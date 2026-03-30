import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 15000 })

// Auto-fetch session API key from backend and attach to all requests.
// Stored as a Promise so the request interceptor can await it before dispatch.
const _fetchKey = axios.get('/api/auth-token').then(r => {
  api.defaults.headers.common['X-API-Key'] = r.data.token
}).catch(() => {
  // If ONEINFINITY_API_KEY is set in the environment, the user can also set it
  // in localStorage as a fallback.
  const stored = localStorage.getItem('oneinfinity_api_key')
  if (stored) {
    api.defaults.headers.common['X-API-Key'] = stored
  }
})

// Wait for the key to be resolved before dispatching any request,
// so requests fired during startup don't go out without the header.
api.interceptors.request.use(async config => {
  await _fetchKey
  return config
})

api.interceptors.response.use(
  r => r,
  err => {
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
  launchScan:      (data) => api.post('/scans', data),
  startScan:       (data) => api.post('/scans', data),
  simpleScan:      (target) => api.post('/scan', { target }),
  stopScan:        (id) => api.post(`/scans/${id}/stop`),
  deleteScan:      (id) => api.delete(`/scans/${id}`),
  vulnerabilities: (params) => api.get('/vulnerabilities', { params }),
  getVuln:         (id) => api.get(`/vulnerabilities/${id}`),
  updateVuln:      (id, data) => api.patch(`/vulnerabilities/${id}`, data),
  replayVuln:      (id) => api.post(`/vulnerabilities/${id}/replay`),
  mutatePayload:   (id, data) => api.post(`/vulnerabilities/${id}/mutate`, data),
  generateReport:  (id) => api.post(`/vulnerabilities/${id}/report`),
  campaigns:       () => api.get('/ai-campaigns'),
  launchCampaign:  (data) => api.post('/ai-campaigns', data),
  testPrompt:      (data) => api.post('/ai-prompt-test', data),
  attackGraph:     (target) => api.get('/attack-graph', { params: target ? { target } : {} }),
  reports:         () => api.get('/reports'),
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

  // Attacks
  attacks:         () => api.get('/attacks'),
  registerAttack:  (data) => api.post('/attacks/register', data),
  replayAttack:    (id, data) => api.post(`/attacks/${id}/replay`, data),
  sprayAttack:     (id, data) => api.post(`/attacks/${id}/spray`, data),
  payloadLibrary:  (type) => api.get(`/attacks/payloads/${type}`),

  // Mobile Security
  mobileApps:          () => api.get('/mobile/apps'),
  getMobileApp:        (id) => api.get(`/mobile/apps/${id}`),
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
  mobileFullReport:    (id) => api.get(`/mobile/apps/${id}/report`),
  mobileUpload:        (formData) => api.post('/mobile/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),

  // Bounty Hunter
  hunterStart:         (config) => api.post('/hunter/start', config),
  hunterScan:          (target, config) => api.post('/hunter/scan', { target, ...(config || {}) }),
  hunterStatus:        (sessionId) => api.get(sessionId ? `/hunter/status/${sessionId}` : '/hunter/status'),
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

  // Utilities  (/api/utilities/*)
  cvssCalculate:       (data) => api.post('/utilities/cvss', data),
  dedupCheck:          (title) => api.post('/utilities/dedup', { title }),
  methodologyGet:      (vuln_class) => api.get(`/utilities/methodology/${vuln_class}`),
  wafBypassPayloads:   (waf, vuln_type) => api.get(`/utilities/waf-bypass/${waf}/${vuln_type}`),

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
  godModeStatus:       (scanId) => scanId ? api.get(`/god-mode/status/${scanId}`) : api.get('/god-mode/status'),
  godModeSessions:     () => api.get('/god-mode/sessions'),
  godModeStop:         (scanId) => api.post('/god-mode/stop', { scan_id: scanId || null }),
  godModeDelete:       (scanId) => api.delete(`/god-mode/${scanId}`),
  godModeLogs:         (scanId, lines) => api.get(`/god-mode/logs/${scanId}`, { params: { lines: lines || 150 } }),
}
