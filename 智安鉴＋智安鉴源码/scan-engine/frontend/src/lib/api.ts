import axios from 'axios'

// Default to same-origin path so remote users do not call their own localhost.
const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add request interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      try {
        const parsed = JSON.parse(token)
        config.headers.Authorization = `Bearer ${parsed.access_token}`
        console.log('[API] Request with token:', {
          url: config.url,
          method: config.method,
          hasToken: !!parsed.access_token
        })
      } catch (e) {
        console.error('[API] Failed to parse token:', e)
        // Token parsing failed, ignore
      }
    }
    return config
  },
  (error) => {
    console.error('[API] Request error:', error)
    return Promise.reject(error)
  }
)

// Add response interceptor to handle 401 errors
api.interceptors.response.use(
  (response) => {
    console.log('[API] Response success:', {
      url: response.config.url,
      status: response.status,
      dataKeys: Object.keys(response.data || {}).slice(0, 3)
    })
    return response
  },
  (error) => {
    console.error('[API] Response error:', {
      url: error.config?.url,
      status: error.response?.status,
      statusText: error.response?.statusText,
      message: error.message,
      data: error.response?.data
    })

    if (error.response?.status === 401) {
      // Clear auth and redirect to login
      console.error('[API] 401 Unauthorized, clearing auth and redirecting')
      localStorage.removeItem('auth_token')
      localStorage.removeItem('auth_user')
      window.location.href = '/auth'
    }
    return Promise.reject(error)
  }
)

// Types
export interface ScanConfig {
  // 扫描类别开关
  enable_category_network: boolean
  enable_category_vuln: boolean
  enable_category_web: boolean
  enable_category_cred: boolean
  enable_category_post_exploit: boolean

  // 网络扫描与资产识别
  enable_nmap: boolean
  enable_masscan: boolean
  enable_naabu: boolean
  enable_rustscan: boolean
  enable_httpx: boolean
  enable_whatweb: boolean
  enable_katana: boolean

  // 漏洞扫描与组件分析
  enable_nuclei: boolean
  enable_nikto: boolean
  enable_wapiti: boolean
  enable_trivy: boolean
  enable_grype: boolean
  enable_lynis: boolean
  enable_searchsploit: boolean
  enable_yara: boolean

  // Web/API 测试
  enable_sqlmap: boolean
  enable_ffuf: boolean
  enable_dirsearch: boolean
  enable_gobuster: boolean
  enable_feroxbuster: boolean
  enable_wfuzz: boolean
  enable_dalfox: boolean
  enable_xsstrike: boolean
  enable_commix: boolean
  enable_jwt_tool: boolean
  enable_newman: boolean
  enable_sslscan: boolean

  // 凭证与身份验证（默认禁用）
  enable_hydra: boolean
  enable_medusa: boolean
  enable_netexec: boolean
  enable_cewl: boolean
  enable_kerbrute: boolean
  enable_enum4linux: boolean

  // 后渗透与取证辅助（默认禁用）
  enable_gitleaks: boolean
  enable_trufflehog: boolean
  enable_pspy: boolean
  enable_linpeas: boolean
  enable_linenum: boolean
  enable_linux_exploit_suggester: boolean

  // 通用配置
  custom_ports: number[]
  scan_depth: number
  rate_limit: number
  enable_ai_agent?: boolean
  enable_sub_agents?: boolean
  ai_max_iterations?: number  // 0 = unlimited
  ai_custom_prompt?: string
  ai_persona_id?: string | null  // AI 人格 ID
}

export interface SubAgentTask {
  id: string
  name: string
  role: string
  objective: string
  status: 'queued' | 'running' | 'waiting_input' | 'completed' | 'failed' | 'skipped'
  phase: string | null
  progress: number
  started_at: string | null
  completed_at: string | null
  summary: string | null
  findings_count: number
  error: string | null
}

export interface ScanTask {
  id: string
  target: string
  scan_type: string
  status: 'PENDING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
  config: ScanConfig
  started_at: string | null
  completed_at: string | null
  created_at: string
  llm_summary: string | null
  llm_risk_score: number | null
  vulnerability_count: number
  remark?: string | null
  sub_agents: SubAgentTask[]
}

export interface Vulnerability {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string | null
  description: string | null
  evidence: string | null
  location: string | null
  llm_analysis: string | null
  llm_remediation: string | null
  llm_false_positive_score: number | null
  created_at: string
}

// API functions
export async function getScans(params?: { skip?: number; limit?: number; status?: string; search?: string }) {
  const { data } = await api.get<{ total: number; items: ScanTask[] }>('/scans', { params })
  return data
}

export async function getScan(scanId: string) {
  const { data } = await api.get<ScanTask>(`/scans/${scanId}`)
  return data
}

export async function createScan(target: string, scanType: string, config: Partial<ScanConfig>, remark?: string) {
  const { data } = await api.post<ScanTask>('/scans', {
    target,
    scan_type: scanType,
    config,
    remark,
  })
  return data
}

export async function getVulnerabilities(scanId: string, params?: { skip?: number; limit?: number; severity?: string }) {
  const { data } = await api.get<{ total: number; items: Vulnerability[] }>(
    `/scans/${scanId}/vulnerabilities`,
    { params }
  )
  return data
}

export async function cancelScan(scanId: string) {
  const { data } = await api.post(`/scans/${scanId}/cancel`)
  return data
}

export async function deleteScan(scanId: string) {
  const { data } = await api.delete(`/scans/${scanId}`)
  return data
}

export async function batchDeleteScans(scanIds: string[]) {
  const { data } = await api.post('/scans/batch-delete', { scan_ids: scanIds })
  return data
}

export interface ScanProgress {
  scan_id: string
  status: string
  phase: string | null
  message: string | null
  sub_agents: SubAgentTask[]
}

export async function getScanProgress(scanId: string) {
  const { data } = await api.get<ScanProgress>(`/scans/${scanId}/progress`)
  return data
}

export interface ScanLogEntry {
  timestamp: string
  type: 'info' | 'tool' | 'output' | 'llm' | 'error' | 'success'
  message: string
  details: string | null
  tool: string | null
  agent?: string | null
}

export interface ScanLogs {
  scan_id: string
  logs: ScanLogEntry[]
  next_index: number
}

export async function getScanLogs(scanId: string, sinceIndex: number = 0) {
  const { data } = await api.get<ScanLogs>(`/scans/${scanId}/logs`, {
    params: { since_index: sinceIndex }
  })
  return data
}

// ============ Attack Path Analysis ============

export interface AttackPathItem {
  id: string
  name: string
  severity?: string
  details?: string
}

export interface AttackPhase {
  id: string
  name: string
  description: string
  items: AttackPathItem[]
}

export interface AttackChainStep {
  order: number
  action: string
  vulnerability?: string
  result: string
}

export interface AttackChain {
  id: string
  name: string
  description: string
  steps: AttackChainStep[]
  likelihood: string
  impact: string
}

export interface RiskAssessment {
  overall_risk: string
  risk_score: number
  summary: string
  critical_paths: string[]
  recommendations: string[]
}

export interface AttackPathData {
  phases: AttackPhase[]
  attack_chains: AttackChain[]
  risk_assessment: RiskAssessment
}

export interface AttackPathResponse {
  success: boolean
  cached: boolean
  data: AttackPathData
}

export async function getAttackPath(scanId: string, refresh: boolean = false) {
  const { data } = await api.get<AttackPathResponse>(`/scans/${scanId}/attack-path`, {
    params: { refresh }
  })
  return data
}

// ============ Scan Messages ============

export interface ScanMessage {
  id: string
  scan_task_id: string
  role: 'agent' | 'user'
  content: string
  is_processed: boolean
  created_at: string
}

export interface ScanMessageList {
  scan_id: string
  messages: ScanMessage[]
  is_paused: boolean
  pending_question: string | null
}

export async function getScanMessages(scanId: string) {
  const { data } = await api.get<ScanMessageList>(`/scans/${scanId}/messages`)
  return data
}

export async function sendScanMessage(scanId: string, content: string) {
  const { data } = await api.post<ScanMessage>(`/scans/${scanId}/messages`, { content })
  return data
}

// ============ Post-Scan Chat (分析对话) ============

export interface ChatMessage {
  id: string
  scan_id: string
  role: 'user' | 'assistant'
  content: string
  created_at: string
}

export interface ChatHistory {
  scan_id: string
  messages: ChatMessage[]
  can_chat: boolean
}

export async function getScanChatHistory(scanId: string) {
  const { data } = await api.get<ChatHistory>(`/scans/${scanId}/chat`)
  return data
}

export async function sendScanChatMessage(scanId: string, message: string) {
  const { data } = await api.post<ChatMessage>(`/scans/${scanId}/chat`, { message })
  return data
}

export async function getAvailableScanners() {
  const { data } = await api.get<{ available_scanners: string[] }>('/scanners')
  return data.available_scanners
}

// ============ Security Tools / Knowledgebase ============

export interface SecurityTool {
  id: string
  name: string
  description: string | null
  tool_type: 'script' | 'nuclei' | 'wordlist' | 'config' | 'skill' | 'scanner'
  filename: string
  file_size: number | null
  category: string | null
  tags: string[]
  usage_instructions: string | null
  is_enabled: boolean
  is_verified: boolean
  author: string | null
  version: string | null
  created_at: string
  updated_at: string | null
}

export async function getTools(params?: {
  skip?: number
  limit?: number
  tool_type?: string
  category?: string
  enabled_only?: boolean
}) {
  const { data } = await api.get<{ total: number; items: SecurityTool[] }>('/tools', { params })
  return data
}

export async function getTool(toolId: string) {
  const { data } = await api.get<SecurityTool>(`/tools/${toolId}`)
  return data
}

export async function getToolContent(toolId: string) {
  const { data } = await api.get<{ content: string; filename: string }>(`/tools/${toolId}/content`)
  return data
}

export async function uploadTool(formData: FormData) {
  const { data } = await api.post<SecurityTool>('/tools', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return data
}

export async function updateTool(toolId: string, updates: Partial<SecurityTool>) {
  const { data } = await api.patch<SecurityTool>(`/tools/${toolId}`, updates)
  return data
}

export async function deleteTool(toolId: string) {
  const { data } = await api.delete(`/tools/${toolId}`)
  return data
}

export async function getToolCategories() {
  const { data } = await api.get<{ categories: string[]; tool_types: string[] }>('/tools/categories/list')
  return data
}

// ============ Kali Pre-installed Scanners ============

export interface KaliScannerInfo {
  type: string
  name: string
  registered: boolean
}

export interface KaliScannerCategory {
  key: string
  name: string
  description: string
  tools: KaliScannerInfo[]
}

export interface KaliScannerResponse {
  total: number
  categories: KaliScannerCategory[]
}

export async function getKaliScanners() {
  const { data } = await api.get<KaliScannerResponse>('/tools/kali-scanners')
  return data
}

// ============ Nuclei Templates (from Kali container) ============

export interface NucleiTemplate {
  id: string
  name: string
  path: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  file_size: number
  tags: string[]
}

export interface NucleiTemplateListResponse {
  total: number
  items: NucleiTemplate[]
  templates_dir: string
}

export interface NucleiTemplateStats {
  total: number
  categories: Record<string, number>
  severities: Record<string, number>
  templates_dir: string
}

export async function getNucleiTemplates(params?: {
  category?: string
  severity?: string
  search?: string
  skip?: number
  limit?: number
}) {
  const { data } = await api.get<NucleiTemplateListResponse>('/tools/nuclei-templates', { params })
  return data
}

export async function getNucleiTemplateStats() {
  const { data } = await api.get<NucleiTemplateStats>('/tools/nuclei-templates/stats')
  return data
}

export async function getNucleiTemplateContent(path: string) {
  const { data } = await api.get<{ content: string; path: string; size: number }>(
    '/tools/nuclei-templates/content',
    { params: { path } }
  )
  return data
}

// ============ LLM Settings ============

export interface LLMConfig {
  id: string
  name: string
  provider: string
  api_base_url: string | null
  has_api_key: boolean
  model: string
  temperature: number
  max_tokens: number
  active_for_main_agent: boolean
  active_for_sub_agent: boolean
  is_enabled: boolean
  priority: number
  total_requests: number
  failed_requests: number
  last_used_at: string | null
  last_error: string | null
  created_at: string
  updated_at: string | null
}

export interface LLMConfigCreate {
  name: string
  provider: string
  api_base_url?: string
  api_key?: string
  model: string
  temperature?: number
  max_tokens?: number
  active_for_main_agent?: boolean
  active_for_sub_agent?: boolean
  priority?: number
}

export interface SearchSettings {
  enabled: boolean
  provider: string
  api_key: string | null
  max_results: number
}

export async function getLLMConfigs() {
  const { data } = await api.get<{ total: number; items: LLMConfig[] }>('/settings/llm')
  return data
}

export async function createLLMConfig(config: LLMConfigCreate) {
  const { data } = await api.post<LLMConfig>('/settings/llm', config)
  return data
}

export async function updateLLMConfig(id: string, updates: Partial<LLMConfigCreate & { is_enabled?: boolean }>) {
  const { data } = await api.patch<LLMConfig>(`/settings/llm/${id}`, updates)
  return data
}

export async function deleteLLMConfig(id: string) {
  const { data } = await api.delete(`/settings/llm/${id}`)
  return data
}

export async function activateLLMConfig(id: string, role: 'main' | 'sub' = 'main') {
  const { data } = await api.post(`/settings/llm/${id}/activate`, null, { params: { role } })
  return data
}

export async function testLLMConfig(id: string) {
  const { data } = await api.post<{ success: boolean; message: string; response?: string; error?: string }>(
    `/settings/llm/${id}/test`
  )
  return data
}

export interface LLMModel {
  id: string
  owned_by: string
  created?: number
}

export interface FetchModelsResponse {
  success: boolean
  message: string
  models: LLMModel[]
}

export async function fetchLLMModels(apiKey?: string, apiBaseUrl?: string, configId?: string) {
  const { data } = await api.post<FetchModelsResponse>(
    `/settings/llm/fetch-models`,
    {
      api_key: apiKey || null,
      api_base_url: apiBaseUrl || null,
      config_id: configId || null,
    }
  )
  return data
}

export async function getSearchSettings() {
  const { data } = await api.get<SearchSettings>('/settings/search')
  return data
}

export async function updateSearchSettings(settings: SearchSettings) {
  const { data } = await api.put<SearchSettings>('/settings/search', settings)
  return data
}

// ============ AI Personas ============

export interface AIPersona {
  id: string
  name: string
  description: string | null
  system_prompt: string
  is_default: boolean
  is_enabled: boolean
  created_at: string
  updated_at: string | null
}

export interface AIPersonaBrief {
  id: string
  name: string
  description: string | null
  is_default: boolean
}

export interface AIPersonaCreate {
  name: string
  description?: string | null
  system_prompt: string
  is_default?: boolean
}

export interface AIPersonaUpdate {
  name?: string
  description?: string | null
  system_prompt?: string
  is_default?: boolean
  is_enabled?: boolean
}

export async function getPersonas() {
  const { data } = await api.get<{ total: number; items: AIPersona[] }>('/settings/personas')
  return data
}

export async function getPersonasBrief() {
  const { data } = await api.get<AIPersonaBrief[]>('/settings/personas/brief')
  return data
}

export async function getPersona(id: string) {
  const { data } = await api.get<AIPersona>(`/settings/personas/${id}`)
  return data
}

export async function createPersona(persona: AIPersonaCreate) {
  const { data } = await api.post<AIPersona>('/settings/personas', persona)
  return data
}

export async function updatePersona(id: string, updates: AIPersonaUpdate) {
  const { data } = await api.patch<AIPersona>(`/settings/personas/${id}`, updates)
  return data
}

export async function deletePersona(id: string) {
  const { data } = await api.delete(`/settings/personas/${id}`)
  return data
}

export async function setDefaultPersona(id: string) {
  const { data } = await api.post(`/settings/personas/${id}/set-default`)
  return data
}
