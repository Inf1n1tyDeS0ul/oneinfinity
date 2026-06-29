// Package main implements the oi-target-disc gRPC sidecar.
// Provides concurrent TCP port scanning with banner grabbing,
// 500-goroutine pool, semaphore-controlled FD budget, and streaming results.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

func init() {
	// Register JSON codec so stream.RecvMsg/SendMsg use JSON over gRPC framing.
	encoding.RegisterCodec(jsonCodec{})
}

// ---------------------------------------------------------------------------
// Hand-written proto stub for the TargetDisc service
// (new service — no entry in oneinfinity.proto; wire format defined here)
// ---------------------------------------------------------------------------

// TargetDiscRequest is the input message for TargetDisc.Scan.
//
//	service TargetDisc { rpc Scan(TargetDiscRequest) returns (stream OpenPort); }
type TargetDiscRequest struct {
	Target    string  `json:"target"`     // CIDR (e.g. 192.168.1.0/24) or single IP
	ScanID    string  `json:"scan_id"`
	Ports     []int32 `json:"ports"`      // empty → use defaultPorts
	TimeoutMs int32   `json:"timeout_ms"` // per-port dial timeout; 0 → 1000
}

// OpenPort is the streaming response message for TargetDisc.Scan.
type OpenPort struct {
	IP       string `json:"ip"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"` // always "tcp" for now
	Banner   string `json:"banner"`   // first 256 bytes read on connect
	ScanID   string `json:"scan_id"`
}

// HealthCheckRequest mirrors proto HealthCheckRequest.
type HealthCheckRequest struct {
	Service string `json:"service"`
}

// HealthCheckResponse mirrors proto HealthCheckResponse.
type HealthCheckResponse struct {
	Status int32 `json:"status"` // 0=UNKNOWN 1=SERVING 2=NOT_SERVING
}

// ---------------------------------------------------------------------------
// Default port list — common attack-surface ports
// ---------------------------------------------------------------------------

var defaultPorts = []int32{
	// Originally present
	21, 22, 23, 25, 80, 135, 443, 445,
	1433, 1521, 3000, 3306, 3389, 5432,
	5900, 6379, 8080, 8443, 8888, 9200, 27017,
	// Legacy/amplification services
	7, 9, 13, 17, 19, 37, 49,
	// DNS, DHCP, TFTP, finger, POP3, RPC, NNTP, NTP
	53, 67, 69, 79, 110, 111, 119, 123,
	// NetBIOS, IMAP, SNMP, IRC, LDAP, Kerberos, IKE
	137, 138, 139, 143, 161, 194, 389, 464, 500,
	// rexec, rlogin, rsh, LPD, submission, IPP, LDAPS, rsync
	512, 513, 514, 515, 587, 631, 636, 873,
	// VMware, IMAPS, POP3S, SOCKS, RMI, OpenVPN, misc
	902, 993, 995, 1080, 1099, 1194, 1234,
	// iDRAC, MSSQL, Oracle, PPTP, MQTT, NFS
	1311, 1723, 1883, 2049, 2121,
	// Docker API, Oracle RAC
	2375, 2376, 2483,
	// Node/dev, Squid, LDAP-GC, MySQL, RDP, SVN
	3128, 3268, 3690,
	// Angular dev, alt-HTTPS, shells
	4200, 4443, 4444, 4567,
	// GlassFish, Radmin, IPMI
	4848, 4899, 4983,
	// Flask/dev, Windows update, SIP, WinRM/HTTP, WinRM/HTTPS
	5000, 5040, 5060, 5985, 5986,
	// X11, Kubernetes API, BitTorrent
	6000, 6443, 6881,
	// WebLogic, JBoss, alt-HTTPS, Neo4j, smartd
	7001, 7180, 7443, 7474, 7634,
	// HTTP alt, HTTP alt, HTTP alt, AJP
	8000, 8001, 8008, 8009,
	// MQTT-TLS, InfluxDB, alt-HTTP, Puppet, ActiveMQ-console, Solr
	8083, 8086, 8088, 8139, 8140, 8161,
	// Alt-HTTPS, Jupyter, Solr
	8983,
	// SonarQube, Cassandra, Cassandra-Thrift, Elasticsearch, Elasticsearch-cluster
	9000, 9042, 9160, 9300,
	// Git, misc, Webmin
	9418, 9999, 10000,
	// Kubernetes kubelet, Memcached
	10250, 11211,
	// Hadoop/various
	15000, 15672, 16010,
	// MongoDB, RethinkDB
	28015,
	// DB2, Hadoop NameNode/DataNode/SecondaryNameNode
	50000, 50030, 50060, 50070,
	// ActiveMQ
	61616,
}

// ---------------------------------------------------------------------------
// CIDR expansion
// ---------------------------------------------------------------------------

// expandCIDR returns all host IP strings within the given CIDR.
// For a single IP (no /prefix), returns a one-element slice.
func expandCIDR(target string) ([]string, error) {
	// Handle plain IP
	if !strings.Contains(target, "/") {
		if ip := net.ParseIP(target); ip != nil {
			return []string{ip.String()}, nil
		}
		// Treat as hostname
		return []string{target}, nil
	}

	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		ips = append(ips, cur.String())
	}
	// Remove network and broadcast addresses for subnets larger than /31
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 1 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// inc increments an IP address in-place.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Banner grabbing
// ---------------------------------------------------------------------------

const bannerSize = 1024

// grabBanner connects to ip:port with the given deadline and reads up to
// bannerSize bytes. Returns empty string on error (port still counts as open).
func grabBanner(ip string, port int32, deadline time.Time) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))),
		time.Until(deadline))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, bannerSize)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	return strings.TrimSpace(string(buf[:n]))
}

// ---------------------------------------------------------------------------
// Scan implementation
// ---------------------------------------------------------------------------

const (
	maxConcurrency = 2000 // goroutine pool ceiling
	defaultRate    = 1000 // ports/second
)

// scanJob is a single (ip, port) probe unit.
type scanJob struct {
	ip   string
	port int32
}

// runScan performs a concurrent TCP connect scan and sends open ports on out.
// sem limits FD usage to maxConcurrency connections at a time.
// Rate limiting: a token is placed on rateTicker every 1/rate seconds.
func runScan(ctx context.Context, req *TargetDiscRequest, out chan<- *OpenPort) {
	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 1000
	}
	dialTimeout := time.Duration(timeoutMs) * time.Millisecond

	ports := req.Ports
	if len(ports) == 0 {
		ports = defaultPorts
	}

	ips, err := expandCIDR(req.Target)
	if err != nil {
		log.Printf("oi-target-disc: expandCIDR(%q): %v", req.Target, err)
		return
	}

	// Build job list: IPs × ports
	jobs := make([]scanJob, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			jobs = append(jobs, scanJob{ip: ip, port: port})
		}
	}

	// Semaphore for FD budget (max 500 open connections).
	sem := make(chan struct{}, maxConcurrency)

	// Rate limiter: defaultRate tokens/second.
	rateTick := time.NewTicker(time.Second / defaultRate)
	defer rateTick.Stop()

	done := make(chan struct{})
	results := make(chan *OpenPort, 512)

	// Collector goroutine: forward results to caller.
	go func() {
		defer close(done)
		for op := range results {
			select {
			case out <- op:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Worker dispatcher.
	go func() {
		defer close(results)

		pendingWg := make(chan struct{}, len(jobs)+1)
		for i := 0; i < len(jobs); i++ {
			pendingWg <- struct{}{}
		}
		remaining := len(jobs)

		dispatchDone := make(chan struct{})
		go func() {
			defer close(dispatchDone)
		dispatchLoop:
			for _, job := range jobs {
				// Check context cancellation.
				if ctx.Err() != nil {
					break dispatchLoop
				}
				// Consume a rate-limit token.
				select {
				case <-rateTick.C:
				case <-ctx.Done():
					break dispatchLoop
				}
				// Acquire FD slot.
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					break dispatchLoop
				}
				j := job
				go func() {
					defer func() {
						<-sem
						<-pendingWg
					}()
					deadline := time.Now().Add(dialTimeout)
					conn, err := net.DialTimeout("tcp",
						net.JoinHostPort(j.ip, strconv.Itoa(int(j.port))),
						dialTimeout)
					if err != nil {
						return // port closed or filtered
					}
					conn.Close()

					// Grab banner with the remaining timeout budget.
					banner := grabBanner(j.ip, j.port, deadline)

					select {
					case results <- &OpenPort{
						IP:       j.ip,
						Port:     j.port,
						Protocol: "tcp",
						Banner:   banner,
						ScanID:   req.ScanID,
					}:
					case <-ctx.Done():
					}
				}()
			}
		}()

		<-dispatchDone
		// Drain pendingWg: wait for all goroutines to finish.
		for i := 0; i < remaining; i++ {
			<-pendingWg
		}
	}()

	<-done
}

// ---------------------------------------------------------------------------
// gRPC service implementation
// ---------------------------------------------------------------------------

type targetDiscServer struct{}

// ---------------------------------------------------------------------------
// gRPC handlers
// ---------------------------------------------------------------------------

func targetDiscScanHandler(srv interface{}, stream grpc.ServerStream) error {
	req := &TargetDiscRequest{}
	if err := stream.RecvMsg(req); err != nil {
		return err
	}
	if req.ScanID == "" {
		return status.Errorf(codes.InvalidArgument, "scan_id is required")
	}
	if req.Target == "" {
		return status.Errorf(codes.InvalidArgument, "target is required")
	}

	// Warn on very broad CIDRs but do not reject — authorized testers scan full /8 networks.
	if _, ipnet, err := net.ParseCIDR(req.Target); err == nil {
		ones, _ := ipnet.Mask.Size()
		if ones < 16 {
			log.Printf("oi-target-disc: large CIDR /%d requested for target %q — proceeding", ones, req.Target)
		}
	}

	ctx := stream.Context()
	out := make(chan *OpenPort, 256)

	go func() {
		defer close(out)
		runScan(ctx, req, out)
	}()

	for op := range out {
		if err := stream.SendMsg(op); err != nil {
			return err
		}
	}
	return nil
}

func healthHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := &HealthCheckRequest{}
	if err := dec(req); err != nil {
		return nil, err
	}
	resp := &HealthCheckResponse{Status: 1}
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return resp, nil
	}
	if interceptor != nil {
		return interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/oneinfinity.v1.TargetDisc/Health",
		}, handler)
	}
	return handler(ctx, req)
}

// targetDiscServiceDesc is the gRPC service descriptor for TargetDisc.
var targetDiscServiceDesc = grpc.ServiceDesc{
	ServiceName: "oneinfinity.v1.TargetDisc",
	HandlerType: (*targetDiscServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Health",
			Handler:    healthHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Scan",
			Handler:       targetDiscScanHandler,
			ServerStreams: true,
		},
	},
}

// ---------------------------------------------------------------------------
// JSON codec
// ---------------------------------------------------------------------------

type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
func (jsonCodec) Name() string                            { return "proto" }

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// Bind to localhost only — never 0.0.0.0.
	const addr = "127.0.0.1:50059"

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("oi-target-disc: listen %s: %v", addr, err)
	}

	s := grpc.NewServer(
		grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
			return status.Errorf(codes.Unimplemented, "unknown service")
		}),
	)
	s.RegisterService(&targetDiscServiceDesc, &targetDiscServer{})

	log.Printf("oi-target-disc listening on %s (pool=%d goroutines, rate=%d ports/sec)",
		addr, maxConcurrency, defaultRate)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("oi-target-disc: serve: %v", err)
	}
}
