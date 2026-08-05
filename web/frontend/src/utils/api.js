import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 15000 })

// Resolve API key: injected by server into window.__OI_API_KEY__ (production),
// or fetched from /api/auth-token (local dev), or read from storage (manual entry).
const _fetchKey = (() => {
  const injected = window.__OI_API_KEY__
  if (injected) {
    api.defaults.headers.common['X-API-Key'] = injected
    return Promise.resolve()
  }
  return axios.get('/api/auth-token').then(r => {
    if (r.data.token) api.defaults.headers.common['X-API-Key'] = r.data.token
  }).catch(() => {
    const stored = sessionStorage.getItem('oneinfinity_api_key')
                || localStorage.getItem('oneinfinity_api_key')
    if (stored) api.defaults.headers.common['X-API-Key'] = stored
  })
})()

// Wait for the key to be resolved before dispatching any request,
// so requests fired during startup don't go out without the header.
api.interceptors.request.use(async config => {
  await _fetchKey
  return config
})

api.interceptors.response.use(
  r => r,
  async err => {
    // On 401, re-fetch the API key and retry the request once.
    if (err.response?.status === 401 && !err.config?._retried) {
      try {
        const r = await axios.get('/api/auth-token')
        const key = r.data.token
        if (key) {
          api.defaults.headers.common['X-API-Key'] = key
          err.config._retried = true
          err.config.headers['X-API-Key'] = key
          return api(err.config)
        }
      } catch (_) {}
    }
    console.error('API error:', err.response?.data || err.message)
    return Promise.reject(err)
  }
)

export default api

export const endpoints = {
  stats:           () => api.get('/stats'),
  targets:         () => api.get('/targets'),
  createTarget:    (data) => api.post('/targets', data),
  deleteTarget:    (id) => api.delete(`/targets/${id}`),
  scans:           () => api.get('/scans'),
  getScan:         (id) => api.get(`/scans/${id}`),
  getScanFindings: (id) => api.get(`/scans/${id}/findings`),
  launchScan:      (data) => api.post('/scans', data),
  startScan:       (data) => api.post('/scans', data),
  simpleScan:      (target) => api.post('/scan', { target }),
  stopScan:        (id) => api.post(`/scans/${id}/stop`),
  deleteScan:      (id) => api.delete(`/scans/${id}`),
  deleteScans:     (ids) => api.delete('/scans', { data: { scan_ids: ids } }),
  vulnerabilities: (params) => api.get('/vulnerabilities', { params }),
  getVuln:         (id) => api.get(`/vulnerabilities/${id}`),
  updateVuln:      (id, data) => api.patch(`/vulnerabilities/${id}`, data),
  findingsStats:   () => api.get('/vulnerabilities/stats'),
  vulnerabilitiesBulkUpdate: (ids, updates) => api.post('/vulnerabilities/bulk-update', { ids, updates }),
  replayVuln:      (id) => api.post(`/vulnerabilities/${id}/replay`),
  mutatePayload:   (id, data) => api.post(`/vulnerabilities/${id}/mutate`, data),
  generateReport:  (id) => api.post(`/vulnerabilities/${id}/report`),
  campaigns:       () => api.get('/ai-campaigns'),
  launchCampaign:  (data) => api.post('/ai-campaigns', data),
  testPrompt:      (data) => api.post('/ai-prompt-test', data),
  attackGraph:     (target) => api.get('/attack-graph', { params: target ? { target } : {} }),
  graphAttackPaths: (target) => api.get(`/graph/${target}/attack-paths`),
  getAttackChains:  (target) => api.get(`/graph/${target}/chains`),
  reports:         () => api.get('/reports'),
  publishReport:   (scanId, sections) => api.post('/reports/publish',
    { scan_id: scanId, sections: sections || null },
    { responseType: 'blob', timeout: 120000 }
  ),
  logs:            (params) => api.get('/logs', { params }),

  // Traffic
  traffic:         (params) => api.get('/traffic', { params }),
  trafficStats:    () => api.get('/traffic/stats'),
  getTrafficReq:   (id) => api.get(`/traffic/${id}`),
  flagTraffic:     (id, reason) => api.post(`/traffic/${id}/flag`, { reason }),
  deleteTraffic:   (id) => api.delete(`/traffic/${id}`),
  replayTraffic:   (id, data) => api.post(`/traffic/${id}/replay`, data),
  fuzzTraffic:     (id, data) => api.post(`/traffic/${id}/fuzz`, data),
  exportTraffic:   (fmt, params) => api.get(`/traffic/export/${fmt}`, { params, responseType: 'blob' }),

  // Proxy
  proxyStatus:     () => api.get('/proxy/status'),
  proxyConfigure:  (data) => api.post('/proxy/configure', data),
  proxyDisable:    () => api.post('/proxy/disable'),
  interceptStatus: () => api.get('/proxy/intercept/requests'),
  interceptToggle: (enabled) => api.post('/proxy/intercept/toggle', { enabled }),
  interceptForward:(id, data) => api.post(`/proxy/intercept/${id}/forward`, data),
  interceptDrop:   (id) => api.post(`/proxy/intercept/${id}/drop`),

  // Attacks
  attacks:         () => api.get('/attacks'),
  registerAttack:  (data) => api.post('/attacks/register', data),
  replayAttack:    (id, data) => api.post(`/attacks/${id}/replay`, data),
  sprayAttack:     (id, data) => api.post(`/attacks/${id}/spray`, data),
  payloadLibrary:  (type) => api.get(`/attacks/payloads/${type}`),

  // Mobile Security
  mobileApps:          () => api.get('/mobile/apps'),
  mobileDevices:       () => api.get('/mobile/devices'),
  devicePackages:      (serial) => api.get(`/mobile/devices/${serial}/packages`),
  packageIngest:       (serial, pkg) => api.post(`/mobile/devices/${serial}/packages/${pkg}/ingest`),
  getMobileApp:        (id) => api.get(`/mobile/apps/${id}`),
  mobileMobsfStatus:   () => api.get('/mobile/mobsf-status'),
  mobileAnalyze:       (id, params) => api.post(`/mobile/apps/${id}/analyze`, null, { params }),
  mobileStatic:        (id) => api.get(`/mobile/apps/${id}/static`),
  mobileSecrets:       (id) => api.get(`/mobile/apps/${id}/secrets`),
  mobileApis:          (id) => api.get(`/mobile/apps/${id}/apis`),
  mobileDynamic:       (id) => api.get(`/mobile/apps/${id}/dynamic`),
  mobileVulns:         (id) => api.get(`/mobile/apps/${id}/vulnerabilities`),
  mobileAIReverse:     (id) => api.get(`/mobile/apps/${id}/ai-reverse`),
  mobileFridaScripts:  (id) => api.get(`/mobile/apps/${id}/frida-scripts`),
  mobileComponents:    (id) => api.get(`/mobile/apps/${id}/components`),
  mobileNetwork:       (id) => api.get(`/mobile/apps/${id}/network`),
  mobileApiAttack:     (id) => api.get(`/mobile/apps/${id}/api-attack`),
  mobileTools:         (id) => api.get(`/mobile/apps/${id}/tools`),
  mobileCommand:       (deviceId, data) => api.post('/mobile/agent/command', data, { params: { device_id: deviceId } }),
  mobileFullReport:    (id) => api.get(`/mobile/apps/${id}/report`),
  forensicSignals:     (id) => api.get(`/mobile/apps/${id}/forensic-signals`),
  forensicAudit:       (id, deviceId) => api.post(`/mobile/apps/${id}/forensic-audit?device_id=${encodeURIComponent(deviceId)}`),
  mobileUpload:        (formData, onProgress) => api.post('/mobile/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000,          // 5 min — APKs can be 50-150 MB
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    onUploadProgress: onProgress,
  }),

  // Week 5 Mobile Enhancements
  mobileInjectFrida:   (id, body) => api.post(`/mobile/apps/${id}/frida`, body),
  mobileGetTraffic:    (id, limit = 100) => api.get(`/mobile/apps/${id}/traffic`, { params: { limit } }),
  mobileBypassSSL:     (id, body) => api.post(`/mobile/apps/${id}/bypass-ssl`, body),

  // Bounty Hunter
  hunterStart:         (config) => api.post('/hunter/start', config),
  hunterScan:          (target, config) => api.post('/hunter/scan', { target, ...(config || {}) }),
  hunterStatus:        (sessionId) => api.get(sessionId ? `/hunter/status/${sessionId}` : '/hunter/status'),
  hunterStats:         () => api.get('/hunter/stats'),
  getHunterConfig:     () => api.get('/hunter/config'),
  updateHunterConfig:  (data) => api.post('/hunter/config', data),
  hunterSessions:      () => api.get('/hunter/sessions'),
  hunterFindings:      (sessionId) => api.get(`/hunter/findings/${sessionId}`),
  hunterReport:        (sessionId, params) => api.post(`/hunter/report/${sessionId}`, params),
  hunterPrograms:      () => api.get('/hunter/programs'),
  hunterStop:          (sessionId) => api.post(`/hunter/stop/${sessionId}`),

  // Attack Graph Core  (/api/graph/{target}/*)
  graphFull:           (target) => api.get(`/graph/${encodeURIComponent(target)}`),
  graphAttackPaths:    (target) => api.get(`/graph/${encodeURIComponent(target)}/attack-paths`),
  graphExploitChains:  (target) => api.get(`/graph/${encodeURIComponent(target)}/exploit-chains`),
  graphRiskReport:     (target) => api.get(`/graph/${encodeURIComponent(target)}/risk-report`),
  graphAttackPlan:     (target) => api.get(`/graph/${encodeURIComponent(target)}/attack-plan`),
  graphUpdate:         (target, data) => api.post(`/graph/${encodeURIComponent(target)}/update`, data),

  // Target Discovery  (/api/discovery/*)
  discoverTargets:     (data) => api.post('/discovery/targets', data),
  discoveryStatus:     (sessionId) => api.get(`/discovery/status/${sessionId}`),
  runOsint:            (target) => api.post('/discovery/osint', { target }),
  correlateAssets:     (target) => api.post('/discovery/correlate', { target }),
  programScope:        (platform, handle) => api.get(`/discovery/scope/${platform}/${handle}`),

  // Business Logic Attacks  (/api/business-logic/*)
  bizLogicGenerate:    (data) => api.post('/business-logic/generate', data),
  bizLogicCategories:  () => api.get('/business-logic/categories'),

  // Swarm Cluster  (/api/swarm/*)
  swarmSubmit:         (data) => api.post('/swarm/submit', data),
  swarmStatus:         (sessionId) => api.get(`/swarm/status/${sessionId}`),
  swarmWorkers:        () => api.get('/swarm/workers'),
  swarmResults:        (sessionId) => api.get(`/swarm/results/${sessionId}`),

  // Intelligence Daemon  (/api/daemon/* and /api/events/*)
  daemonStatus:        () => api.get('/daemon/status'),
  daemonStart:         (data) => api.post('/daemon/start', data),
  daemonStop:          () => api.post('/daemon/stop'),
  daemonAddTarget:     (target) => api.post('/daemon/add-target', { target }),
  daemonRemoveTarget:  (target) => api.post('/daemon/remove-target', { target }),
  daemonWorkers:       () => api.get('/daemon/workers'),
  daemonEnableWorker:  (name) => api.post(`/daemon/workers/${name}/enable`),
  daemonDisableWorker: (name) => api.post(`/daemon/workers/${name}/disable`),
  daemonConfig:        () => api.get('/daemon/config'),
  daemonPatchConfig:   (data) => api.patch('/daemon/config', data),
  eventsRecent:        (params) => api.get('/events/recent', { params }),
  eventsQuery:         (params) => api.get('/events/query', { params }),
  eventsStats:         () => api.get('/events/stats'),
  eventsTypes:         () => api.get('/events/types'),
  eventsDlq:           () => api.get('/events/dlq'),

  // System Evolution  (/api/evolution/*)
  evolutionStatus:      () => api.get('/evolution/status'),
  evolutionEvents:      (params) => api.get('/evolution/events', { params }),
  evolutionInsights:    (params) => api.get('/evolution/insights', { params }),
  evolutionPatterns:    (params) => api.get('/evolution/patterns', { params }),
  evolutionChains:      (params) => api.get('/evolution/chains', { params }),
  evolutionCapabilities:() => api.get('/evolution/capabilities'),
  evolutionChangelog:   (params) => api.get('/evolution/changelog', { params }),
  evolutionSkills:      (params) => api.get('/evolution/skills', { params }),
  evolutionScans:       (params) => api.get('/evolution/scans', { params }),
  evolutionStats:       () => api.get('/evolution/stats'),
  evolutionTopPayloads: (params) => api.get('/evolution/top-payloads', { params }),
  evolutionEmit:        (data) => api.post('/evolution/emit', data),
  evolutionEventTypes:  () => api.get('/evolution/event-types'),

  // Swarm Intelligence  (/api/swarm-intel/*)
  swarmIntelAgents:        () => api.get('/swarm-intel/agents'),
  swarmIntelWorkflows:     () => api.get('/swarm-intel/workflows'),
  swarmIntelSessions:      () => api.get('/swarm-intel/sessions'),
  swarmIntelScan:          (data) => api.post('/swarm-intel/scan', data),
  swarmIntelScanStatus:    (id) => api.get(`/swarm-intel/scan/${id}`),
  swarmIntelScanDelete:    (id) => api.delete(`/swarm-intel/scan/${id}`),
  swarmIntelSimulate:      (data) => api.post('/swarm-intel/simulate', data),
  swarmIntelSimStatus:     (id) => api.get(`/swarm-intel/simulate/${id}`),
  swarmIntelWorkflow:      (data) => api.post('/swarm-intel/workflow', data),
  swarmIntelWorkflowStatus: (id) => api.get(`/swarm-intel/workflow/${id}`),

  // Graph Brain  (/api/brain/*)
  brainStatus:           () => api.get('/brain/status'),
  brainStart:            (data) => api.post('/brain/start', data),
  brainStop:             () => api.post('/brain/stop'),
  brainAddTarget:        (target) => api.post('/brain/add-target', { target }),
  brainQueue:            (limit) => api.get('/brain/queue', { params: { limit } }),
  brainPriorities:       (limit) => api.get('/brain/priorities', { params: { limit } }),
  brainDecisions:        (limit) => api.get('/brain/decisions', { params: { limit } }),
  brainIntegrateNode:    (data) => api.post('/brain/integrate-node', data),
  brainIntegrateFinding: (data) => api.post('/brain/integrate-finding', data),
  brainAttackPaths:      (target) => api.get(`/brain/attack-paths/${encodeURIComponent(target)}`),
  brainRiskReport:       (target) => api.get(`/brain/risk-report/${encodeURIComponent(target)}`),

  // Event-Driven Engine  (/api/ede/*)
  edeStatus:             () => api.get('/ede/status'),
  edeStart:              (data) => api.post('/ede/start', data),
  edeStop:               () => api.post('/ede/stop'),

  // Graph Triggers  (/api/triggers/*)
  triggerRules:          () => api.get('/triggers/rules'),
  triggerEvaluate:       (data) => api.post('/triggers/evaluate', data || {}),
  triggerHistory:        (limit) => api.get('/triggers/history', { params: { limit } }),
  triggerStats:          () => api.get('/triggers/stats'),

  // Decision Engine  (/api/decisions/*)
  decisionPlan:          (target, max) => api.get(`/decisions/plan/${encodeURIComponent(target)}`, { params: { max_decisions: max } }),
  decisionRecent:        (limit) => api.get('/decisions/recent', { params: { limit } }),
  decisionAgentStats:    () => api.get('/decisions/agent-stats'),
  decisionFeedback:      (data) => api.post('/decisions/feedback', data),

  // Agent Fabric  (/api/fabric/*)
  fabricStatus:          () => api.get('/fabric/status'),
  fabricSubmit:          (data) => api.post('/fabric/submit', data),

  // Orchestrator / AI Model Management  (/api/orchestrator/*)
  orchestratorStatus:       () => api.get('/orchestrator/status'),
  orchestratorModels:       (enabledOnly) => api.get(`/orchestrator/models${enabledOnly ? '?enabled_only=true' : ''}`),
  orchestratorHistory:      (limit = 50) => api.get(`/orchestrator/history?limit=${limit}`),
  orchestratorExecute:      (data) => api.post('/orchestrator/execute', data),
  orchestratorClassify:     (data) => api.post('/orchestrator/classify', data),
  orchestratorReload:       () => api.post('/orchestrator/reload', {}),
  orchestratorBudget:       () => api.get('/orchestrator/budget'),
  orchestratorBudgetSummary:(period = 'today') => api.get(`/orchestrator/budget/summary?period=${period}`),
  orchestratorRecords:      (limit = 50) => api.get(`/orchestrator/budget/records?limit=${limit}`),

  // Platform Controls & Telemetry (NEW)
  getSafetyConfig:     () => api.get('/safety'),
  updateSafetyConfig:  (data) => api.post('/safety', data),
  getWafStats:         () => api.get('/waf/stats'),
  getChainContext:     (id) => api.get(`/chains/${id}`),
  runWorkflow:         (data) => api.post('/workflow/run', data),

  // Reports  (/api/reports/*)
  replayFindings:      (data) => api.post('/reports/replay', data),

  // Infrastructure  (/api/infra/*)
  cacheStats:          () => api.get('/cache/stats'),
  cacheSweep:          () => api.post('/cache/sweep'),
  cacheClear:          () => api.post('/cache/clear'),
  cacheInvalidate:     (target) => api.post(`/cache/invalidate/${encodeURIComponent(target)}`),
  distributedScan:     (data) => api.post('/distributed/scan', data),

  // Benchmarks
  benchmark:           (data) => api.post('/benchmark', data),

  // GOD MODE
  godModeRun:          (data) => api.post('/god-mode/run', data),
  authDetect:          (data) => api.post('/auth/detect', data),
  authRecordStart:     (data) => api.post('/auth/record', data),
  authRecordDone:      (recId, data={}) => api.post(`/auth/record/${recId}/done`, data),
  authRecordCancel:    (recId) => api.post(`/auth/record/${recId}/cancel`),
  authLogin:           (data) => api.post('/auth/login', data, { timeout: 60000 }),
  authSaveCookie:      (data) => api.post('/auth/cookie', data),
  authListSessions:    () => api.get('/auth/sessions'),
  authGetSession:      (id) => api.get(`/auth/sessions/${id}`),
  authSessionVerify:   (id) => api.post(`/auth/sessions/${id}/verify`),
  authDeleteSession:   (id) => api.delete(`/auth/sessions/${id}`),
  godModeStatus:       (scanId) => scanId ? api.get(`/god-mode/status/${scanId}`) : api.get('/god-mode/status'),
  godModeSessions:     () => api.get('/god-mode/sessions'),
  godModeStop:         (scanId) => api.post('/god-mode/stop', { scan_id: scanId || null }),
  godModeDelete:       (scanId) => api.delete(`/god-mode/${scanId}`),
  godModeLogs:         (scanId, lines) => api.get(`/god-mode/logs/${scanId}`, { params: { lines: lines || 150 } }),
  godModeApprove:      (data) => api.post('/god-mode/approve', data),

  // HITL Researcher Feedback
  findingFeedback:     (findingId, data) => api.post(`/findings/${findingId}/feedback`, data),
  hitlStats:           () => api.get('/hitl/stats'),

  // Tools & Plugins
  learningStats:       () => api.get('/learning/stats'),
  learningPlan:        (target, tech) => api.post('/learning/plan', { target, tech }),
  toolsStatus:         () => api.get('/tools/status'),
  toolsCapmap:         () => api.get('/tools/capmap'),
  toolsMetrics:        () => api.get('/tools/metrics'),
  toolsHealth:         () => api.get('/tools/health'),
  toolsFailures:       () => api.get('/tools/failures'),

  // Utilities
  utilsCvss:           (vector, describe) => api.post('/utils/cvss', { vector, describe }),
  utilsDedup:          (title) => api.post('/utils/dedup', { title }),
  utilsWafBypass:      (waf, vuln_type) => api.post('/utils/waf-bypass', { waf, vuln_type }),
  utilsMethodology:    (vuln_class) => api.post('/utils/methodology', { vuln_class }),

  // MCP Integration
  mcpStatus:           () => api.get('/mcp/status'),
  mcpManifest:         () => api.get('/mcp/manifest'),
  mcpInvokeTool:       (tool, parameters) => api.post('/mcp/tools/invoke', { tool, parameters }),
  mcpUpdateConfig:     (config) => api.patch('/mcp/config', config),
  mcpCostTracking:     () => api.get('/mcp/cost-tracking'),
  mcpIntegrationStatus: () => api.get('/mcp/integration-status'),

  // AI Red Team
  aiRedteamStart:      (data) => api.post('/ai-redteam/start', data),
  aiRedteamList:       () => api.get('/ai-redteam/campaigns'),
  aiRedteamGet:        (campaignId) => api.get(`/ai-redteam/campaigns/${campaignId}`),
  aiRedteamEngineResults: (campaignId) => api.get(`/ai-redteam/campaigns/${campaignId}/engine-results`),
  aiRedteamProbe:      (data) => api.post('/ai-redteam/probe', data),
  aiRedteamWatchStart: (data) => api.post('/ai-redteam/watch', data),
  aiRedteamWatchStop:  (watchId) => api.delete(`/ai-redteam/watch/${watchId}`),
  aiRedteamSchedules:  () => api.get('/ai-redteam/schedules'),
  aiRedteamBehavior:   (target) => api.get(`/ai-redteam/behavior?target=${encodeURIComponent(target)}`),

  aiPromptTest:        (data) => api.post('/ai-prompt-test', data),

  // AI Security Engine (multi-tool)
  aiSecToolStatus:     () => api.get('/ai-security/tool-status'),
  aiSecScanStart:      (data) => api.post('/ai-security/scan', data),
  aiSecScanList:       () => api.get('/ai-security/scans'),
  aiSecScanGet:        (scanId) => api.get(`/ai-security/scans/${scanId}`),

  // SSO + Endpoint Discovery
  aiSecGetToken:       (data) => api.post('/ai-security/get-token', data),
  aiSecProbeEndpoint:  (data) => api.post('/ai-security/probe-endpoint', data),

  // Custom Tests
  customTestsStart:    (data) => api.post('/custom-tests/start', data),
  customTestsList:     () => api.get('/custom-tests/runs'),
  customTestsGet:      (testId) => api.get(`/custom-tests/runs/${testId}`),

  // AI Agent Test
  aiAgentTestStart:    (data) => api.post('/ai-agent-test/start', data),
  aiAgentTestList:     () => api.get('/ai-agent-test/tests'),
  aiAgentTestGet:      (testId) => api.get(`/ai-agent-test/tests/${testId}`),

  // Configuration / Environment
  getEnvVars:          () => api.get('/config/env'),
  getEnvVar:           (key, reveal) => api.get(`/config/env/${key}${reveal ? '?reveal=true' : ''}`),
  setEnvVars:          (data) => api.post('/config/env', data),
  deleteEnvVar:        (key) => api.delete(`/config/env/${key}`),
  getGithubTokens:     () => api.get('/config/github-tokens'),
  setGithubTokens:     (data) => api.post('/config/github-tokens', data),

  // GitHub Reconnaissance (Unified Scan)
  unifiedScanStart:    (data) => api.post('/github-recon/unified-scan', data),
  unifiedScanList:     () => api.get('/github-recon/unified-scans'),
  unifiedScanGet:      (unifiedId) => api.get(`/github-recon/unified-scan/${unifiedId}`),
  githubRateLimit:     () => api.get('/github-recon/rate-limit'),

  // Advanced Features (New Engines)
  liveExpansion:       (data) => api.post('/scan/live-expansion', data),
  trafficCorrelation:  (data) => api.post('/scan/traffic-correlation', data),
  chainSuggestions:    (data) => api.post('/scan/chain-suggestions', data),
  payloadMutation:     (data) => api.post('/scan/payload-mutation', data),
  zeroDayDetection:    (data) => api.post('/scan/zero-day-detection', data),
  validateFindings:    (data) => api.post('/scan/validate-findings', data),

  // Scan endpoints (singular /scan/* — god-mode, per-scan findings & chains)
  scanGodMode:     (data) => api.post('/scan/god-mode', data),
  scanFindings:    (id) => api.get(`/scan/${id}/findings`),
  scanChains:      (id) => api.get(`/scan/${id}/chains`),

  // AI Council
  councilGet:          (scanId) => api.get(`/council/${scanId}`),
}
