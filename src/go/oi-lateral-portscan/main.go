// oi-lateral-portscan — internal network port scanner for SSRF lateral movement
//
// Input (flags):
//   --targets  comma-separated IPs or CIDRs (e.g. 10.0.1.5,10.0.2.0/24)
//   --ports    comma-separated ports or ranges (e.g. 22,80,443,6379,8080-8090)
//   --timeout  per-connection timeout in ms (default 500)
//   --workers  concurrency (default 200)
//
// Output: NDJSON findings to stdout, one record per open port.
// Each record:
//   {"vuln_type":"lateral_open_port","ip":"10.x","port":6379,"service":"redis","banner":"...","ts":"..."}
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Service fingerprints ─────────────────────────────────────────────────────

var serviceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	2181:  "zookeeper",
	2375:  "docker",
	2376:  "docker-tls",
	3000:  "grafana",
	3306:  "mysql",
	3389:  "rdp",
	4369:  "epmd",
	5432:  "postgresql",
	5672:  "rabbitmq",
	5900:  "vnc",
	6379:  "redis",
	6443:  "k8s-api",
	7001:  "weblogic",
	7474:  "neo4j",
	8080:  "http-alt",
	8443:  "https-alt",
	8500:  "consul",
	9000:  "sonarqube",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch-transport",
	10250: "kubelet",
	10255: "kubelet-readonly",
	11211: "memcached",
	15672: "rabbitmq-mgmt",
	27017: "mongodb",
	50070: "hdfs-namenode",
}

// ─── Finding ─────────────────────────────────────────────────────────────────

type Finding struct {
	VulnType  string `json:"vuln_type"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Service   string `json:"service"`
	Banner    string `json:"banner,omitempty"`
	Evidence  string `json:"evidence"`
	Severity  string `json:"severity"`
	Tool      string `json:"tool"`
	TS        string `json:"ts"`
}

func emitFinding(f Finding) {
	f.Tool = "oi-lateral-portscan"
	f.TS = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(f)
	fmt.Println(string(data))
}

// ─── Banner grab ─────────────────────────────────────────────────────────────

func grabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return ""
	}
	raw := strings.TrimSpace(string(buf[:n]))
	// Strip non-printable
	var sb strings.Builder
	for _, r := range raw {
		if r >= 0x20 && r < 0x7f {
			sb.WriteRune(r)
		}
	}
	result := sb.String()
	if len(result) > 120 {
		return result[:120]
	}
	return result
}

// ─── Port parsing ─────────────────────────────────────────────────────────────

func parsePorts(spec string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				continue
			}
			for p := lo; p <= hi && p <= 65535; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// ─── CIDR expansion ───────────────────────────────────────────────────────────

func expandTargets(spec string) []string {
	var ips []string
	for _, t := range strings.Split(spec, ",") {
		t = strings.TrimSpace(t)
		if strings.Contains(t, "/") {
			// CIDR
			ip, ipnet, err := net.ParseCIDR(t)
			if err != nil {
				continue
			}
			for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); {
				// Skip network and broadcast
				ips = append(ips, cur.String())
				// Increment IP
				for i := len(cur) - 1; i >= 0; i-- {
					cur[i]++
					if cur[i] != 0 {
						break
					}
				}
			}
		} else {
			ips = append(ips, t)
		}
	}
	return ips
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

type scanJob struct {
	ip   string
	port int
}

func scan(targets []string, ports []int, timeoutMs int, workers int) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	jobs := make(chan scanJob, workers*4)

	var wg sync.WaitGroup
	mu := sync.Mutex{} // guard stdout order
	_ = mu

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				conn, err := net.DialTimeout(
					"tcp",
					fmt.Sprintf("%s:%d", job.ip, job.port),
					timeout,
				)
				if err != nil {
					continue
				}
				conn.Close()

				svc, ok := serviceMap[job.port]
				if !ok {
					svc = "unknown"
				}
				banner := grabBanner(job.ip, job.port, timeout)

				severity := "medium"
				highRisk := []string{"redis", "memcached", "docker", "mongodb",
					"elasticsearch", "k8s-api", "kubelet", "kubelet-readonly",
					"zookeeper", "consul", "etcd"}
				for _, h := range highRisk {
					if svc == h {
						severity = "high"
						break
					}
				}

				emitFinding(Finding{
					VulnType: "lateral_open_port",
					IP:       job.ip,
					Port:     job.port,
					Service:  svc,
					Banner:   banner,
					Evidence: fmt.Sprintf(
						"Open port %d (%s) on %s reachable via SSRF lateral movement",
						job.port, svc, job.ip,
					),
					Severity: severity,
				})
			}
		}()
	}

	for _, ip := range targets {
		for _, port := range ports {
			jobs <- scanJob{ip: ip, port: port}
		}
	}
	close(jobs)
	wg.Wait()
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	targetsFlag := flag.String("targets", "", "comma-separated IPs/CIDRs (required)")
	portsFlag := flag.String("ports", "21,22,80,443,445,1433,1521,2375,3306,3389,5432,5900,6379,7001,8080,8443,9200,10250,11211,27017", "comma-separated ports or ranges")
	timeoutMs := flag.Int("timeout", 500, "connection timeout in milliseconds")
	workers := flag.Int("workers", 200, "concurrent workers")
	flag.Parse()

	// Also accept targets from stdin (one IP per line)
	var targets []string
	if *targetsFlag != "" {
		targets = expandTargets(*targetsFlag)
	}

	// Read additional targets from stdin if piped
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, expandTargets(line)...)
			}
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "oi-lateral-portscan: no targets specified (use --targets or stdin)")
		os.Exit(1)
	}

	ports := parsePorts(*portsFlag)
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "oi-lateral-portscan: no valid ports parsed")
		os.Exit(1)
	}

	scan(targets, ports, *timeoutMs, *workers)
}
