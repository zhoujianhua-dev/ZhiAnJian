import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Play, AlertTriangle, Settings, ChevronDown, ChevronUp, Bot, Info, X } from 'lucide-react'
import { createScan, ScanConfig, getPersonasBrief } from '../lib/api'

const scanTypeLabels: Record<string, { name: string; desc: string }> = {
  full: { name: '完整扫描', desc: '包含所有端口的全面扫描' },
  quick: { name: '资产扫描', desc: '仅扫描资产，不进行漏洞检测' },
  custom: { name: '自定义', desc: '手动配置扫描选项' },
}

// 判断目标是否为 URL（带协议）
function isUrl(target: string): boolean {
  return /^https?:\/\//i.test(target.trim())
}

// 从 URL 提取端口信息
function getUrlPort(target: string): string | null {
  try {
    const url = new URL(target.trim())
    if (url.port) {
      return url.port
    }
    // 默认端口
    return url.protocol === 'https:' ? '443' : '80'
  } catch {
    return null
  }
}

export default function NewScan() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [remark, setRemark] = useState('')
  const [scanType, setScanType] = useState('full')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [isUrlTarget, setIsUrlTarget] = useState(false)
  const [detectedPort, setDetectedPort] = useState<string | null>(null)
  const [config, setConfig] = useState<Partial<ScanConfig>>({
    // 类别开关
    enable_category_network: true,
    enable_category_vuln: true,
    enable_category_web: true,
    enable_category_cred: false,
    enable_category_post_exploit: false,
    // 网络扫描
    enable_nmap: true,
    enable_masscan: true,
    enable_naabu: true,
    enable_rustscan: true,
    enable_httpx: true,
    enable_whatweb: true,
    enable_katana: true,
    // 漏洞扫描
    enable_nuclei: true,
    enable_nikto: true,
    enable_wapiti: true,
    enable_trivy: true,
    enable_grype: true,
    enable_lynis: true,
    enable_searchsploit: true,
    enable_yara: true,
    // Web 测试
    enable_sqlmap: true,
    enable_ffuf: true,
    enable_dirsearch: true,
    enable_gobuster: true,
    enable_feroxbuster: true,
    enable_wfuzz: true,
    enable_dalfox: true,
    enable_xsstrike: true,
    enable_commix: true,
    enable_jwt_tool: true,
    enable_newman: true,
    enable_sslscan: true,
    // 凭证测试（默认禁用）
    enable_hydra: false,
    enable_medusa: false,
    enable_netexec: false,
    enable_cewl: false,
    enable_kerbrute: false,
    enable_enum4linux: false,
    // 后渗透（默认禁用）
    enable_gitleaks: false,
    enable_trufflehog: false,
    enable_pspy: false,
    enable_linpeas: false,
    enable_linenum: false,
    enable_linux_exploit_suggester: false,
    // 通用配置
    enable_sub_agents: true,
    scan_depth: 3,
    rate_limit: 10,
    ai_max_iterations: 0,
    ai_custom_prompt: '',
    ai_persona_id: null,
  })

  // 目标历史记录管理
  const [targetHistory, setTargetHistory] = useState<string[]>([])
  const [showHistory, setShowHistory] = useState(false)

  // 从 localStorage 加载历史记录
  useEffect(() => {
    const saved = localStorage.getItem('scanTargetHistory')
    if (saved) {
      try {
        setTargetHistory(JSON.parse(saved))
      } catch (e) {
        console.error('Failed to load target history:', e)
      }
    }
  }, [])

  // 保存历史记录到 localStorage
  const saveTargetHistory = (history: string[]) => {
    setTargetHistory(history)
    localStorage.setItem('scanTargetHistory', JSON.stringify(history))
  }

  // 过滤匹配的历史记录
  const filteredHistory = targetHistory.filter(h =>
    h.toLowerCase().includes(target.toLowerCase()) && h !== target
  )

  // 从历史记录中删除项目
  const removeFromHistory = (item: string) => {
    const updated = targetHistory.filter(h => h !== item)
    saveTargetHistory(updated)
  }

  // 添加到历史记录
  const addToHistory = (value: string) => {
    if (!value.trim()) return
    const updated = [value, ...targetHistory.filter(h => h !== value)].slice(0, 20) // 保留最多20条
    saveTargetHistory(updated)
  }

  // 监听目标变化，自动检测是否为 URL
  useEffect(() => {
    const urlDetected = isUrl(target)
    setIsUrlTarget(urlDetected)

    if (urlDetected) {
      const port = getUrlPort(target)
      setDetectedPort(port)
      // URL 模式下默认禁用端口扫描
      setConfig(prev => ({ ...prev, enable_port_scan: false }))
    } else {
      setDetectedPort(null)
      // IP/域名模式下默认启用端口扫描
      setConfig(prev => ({ ...prev, enable_port_scan: true }))
    }
  }, [target])

  // 获取可用的人格列表
  const { data: personas } = useQuery({
    queryKey: ['personas-brief'],
    queryFn: getPersonasBrief,
  })

  // 在 personas 加载时，自动设置默认人格
  useEffect(() => {
    if (personas && personas.length > 0) {
      const defaultPersona = personas.find(p => p.is_default)
      if (defaultPersona && config.ai_persona_id === null) {
        setConfig(prev => ({ ...prev, ai_persona_id: defaultPersona.id }))
      }
    }
  }, [personas])

  const mutation = useMutation({
    mutationFn: () => createScan(target, scanType, config, remark || undefined),
    onSuccess: (data) => {
      navigate(`/scans/${data.id}`)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    addToHistory(target)
    mutation.mutate()
  }

  const handleSelectHistory = (value: string) => {
    setTarget(value)
    setShowHistory(false)
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">新建扫描</h1>

      {/* Warning */}
      <div className="bg-yellow-100 dark:bg-yellow-900/50 border border-yellow-300 dark:border-yellow-700 rounded-lg p-4 mb-6 flex gap-3">
        <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-500 flex-shrink-0" />
        <div>
          <p className="font-semibold text-yellow-700 dark:text-yellow-500">重要提示</p>
          <p className="text-sm text-yellow-600 dark:text-yellow-200">
            仅扫描您拥有或获得明确授权的目标。未经授权的扫描可能违反法律。
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <div>
          <label className="block text-sm font-medium mb-2">目标 URL 或 IP</label>
          <div className="relative" onBlur={() => setTimeout(() => setShowHistory(false), 100)}>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onFocus={() => setShowHistory(true)}
              placeholder="https://example.com 或 192.168.1.1"
              className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
            {/* History Dropdown */}
            {showHistory && (targetHistory.length > 0 || target) && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-lg z-10 max-h-64 overflow-y-auto">
                {filteredHistory.length > 0 ? (
                  filteredHistory.slice(0, 5).map((item, index) => (
                    <div
                      key={index}
                      className="px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center justify-between group"
                    >
                      <button
                        type="button"
                        onClick={() => handleSelectHistory(item)}
                        className="flex-1 text-left text-gray-700 dark:text-gray-300"
                      >
                        {item}
                      </button>
                      <button
                        type="button"
                        onMouseDown={e => e.preventDefault()}
                        onClick={() => removeFromHistory(item)}
                        className="p-1 opacity-0 group-hover:opacity-100 hover:text-red-500 transition-all"
                        title="删除历史记录"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))
                ) : targetHistory.length > 0 ? (
                  <div className="px-4 py-2 text-gray-500 dark:text-gray-400 text-sm">
                    未找到匹配的历史记录
                  </div>
                ) : null}
              </div>
            )}
          </div>
          {/* URL 检测提示 */}
          {isUrlTarget && (
            <div className="mt-2 flex items-start gap-2 text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 p-2 rounded">
              <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>
                检测到 URL 目标，将仅对端口 {detectedPort} 进行测试，已自动禁用端口扫描。
                如需扫描其他端口，请使用自定义模式手动开启。
              </span>
            </div>
          )}
        </div>

        {/* Remark */}
        <div>
          <label className="block text-sm font-medium mb-2">备注（可选）</label>
          <textarea
            value={remark}
            onChange={e => setRemark(e.target.value)}
            placeholder="为此扫描任务添加备注..."
            className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
            rows={3}
          />
        </div>

        {/* Scan Type */}
        <div>
          <label className="block text-sm font-medium mb-2">扫描类型</label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {Object.entries(scanTypeLabels).map(([type, { name }]) => (
              <button
                key={type}
                type="button"
                onClick={() => setScanType(type)}
                className={`px-4 py-3 rounded-lg border transition-colors ${scanType === type
                  ? 'bg-blue-600 border-blue-500 text-white'
                  : 'bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-600'
                  }`}
              >
                {name}
              </button>
            ))}
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            {scanTypeLabels[scanType]?.desc}
          </p>
        </div>

        {/* Custom Options */}
        {scanType === 'custom' && (
          <div className="space-y-6 p-4 bg-gray-100 dark:bg-gray-800 rounded-lg">
            {/* 网络扫描与资产识别 */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-gray-300 dark:border-gray-600">
                <input
                  type="checkbox"
                  checked={config.enable_category_network}
                  onChange={e => setConfig({ ...config, enable_category_network: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="font-semibold text-blue-700 dark:text-blue-400">🌐 网络扫描与资产识别</span>
                <span className="text-xs text-gray-500 ml-auto">目标发现、端口识别、服务指纹</span>
              </div>
              {config.enable_category_network && (
                <div className="grid grid-cols-2 gap-2 pl-6">
                  {[
                    { key: 'enable_nmap', name: 'Nmap', desc: '端口扫描、服务版本检测' },
                    { key: 'enable_masscan', name: 'Masscan', desc: '超快速端口扫描' },
                    { key: 'enable_naabu', name: 'Naabu', desc: '快速端口发现' },
                    { key: 'enable_rustscan', name: 'RustScan', desc: 'Rust 编写的快速扫描器' },
                    { key: 'enable_httpx', name: 'httpx', desc: 'HTTP 探测与指纹' },
                    { key: 'enable_whatweb', name: 'WhatWeb', desc: 'Web 技术栈识别' },
                    { key: 'enable_katana', name: 'Katana', desc: 'Web 爬虫/URL 发现' },
                  ].map(tool => (
                    <label key={tool.key} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={config[tool.key as keyof ScanConfig] as boolean}
                        onChange={e => setConfig({ ...config, [tool.key]: e.target.checked })}
                        className="w-3.5 h-3.5 mt-0.5"
                      />
                      <span>
                        <span className="font-medium">{tool.name}</span>
                        <span className="block text-xs text-gray-500">{tool.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* 漏洞扫描与组件分析 */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-gray-300 dark:border-gray-600">
                <input
                  type="checkbox"
                  checked={config.enable_category_vuln}
                  onChange={e => setConfig({ ...config, enable_category_vuln: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="font-semibold text-red-700 dark:text-red-400">🛡️ 漏洞扫描与组件分析</span>
                <span className="text-xs text-gray-500 ml-auto">规则扫描、漏洞匹配、组件检查</span>
              </div>
              {config.enable_category_vuln && (
                <div className="grid grid-cols-2 gap-2 pl-6">
                  {[
                    { key: 'enable_nuclei', name: 'Nuclei', desc: '模板化漏洞检测' },
                    { key: 'enable_nikto', name: 'Nikto', desc: 'Web 服务器漏洞扫描' },
                    { key: 'enable_wapiti', name: 'Wapiti', desc: 'Web 应用漏洞扫描' },
                    { key: 'enable_trivy', name: 'Trivy', desc: '容器/依赖漏洞扫描' },
                    { key: 'enable_grype', name: 'Grype', desc: '依赖漏洞扫描' },
                    { key: 'enable_lynis', name: 'Lynis', desc: '系统安全审计' },
                    { key: 'enable_searchsploit', name: 'SearchSploit', desc: '漏洞利用数据库' },
                    { key: 'enable_yara', name: 'YARA', desc: '恶意软件规则匹配' },
                  ].map(tool => (
                    <label key={tool.key} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={config[tool.key as keyof ScanConfig] as boolean}
                        onChange={e => setConfig({ ...config, [tool.key]: e.target.checked })}
                        className="w-3.5 h-3.5 mt-0.5"
                      />
                      <span>
                        <span className="font-medium">{tool.name}</span>
                        <span className="block text-xs text-gray-500">{tool.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Web/API 测试 */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-gray-300 dark:border-gray-600">
                <input
                  type="checkbox"
                  checked={config.enable_category_web}
                  onChange={e => setConfig({ ...config, enable_category_web: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="font-semibold text-purple-700 dark:text-purple-400">💻 Web/API 测试</span>
                <span className="text-xs text-gray-500 ml-auto">Web 枚举、参数变异、API 测试</span>
              </div>
              {config.enable_category_web && (
                <div className="grid grid-cols-2 gap-2 pl-6">
                  {[
                    { key: 'enable_sqlmap', name: 'SQLMap', desc: 'SQL 注入检测' },
                    { key: 'enable_ffuf', name: 'ffuf', desc: 'Web Fuzzer' },
                    { key: 'enable_dirsearch', name: 'Dirsearch', desc: '目录扫描' },
                    { key: 'enable_gobuster', name: 'Gobuster', desc: '目录/文件枚举' },
                    { key: 'enable_feroxbuster', name: 'Feroxbuster', desc: '递归目录扫描' },
                    { key: 'enable_wfuzz', name: 'Wfuzz', desc: 'Web Fuzzer' },
                    { key: 'enable_dalfox', name: 'Dalfox', desc: 'XSS 扫描' },
                    { key: 'enable_xsstrike', name: 'XSStrike', desc: 'XSS 检测' },
                    { key: 'enable_commix', name: 'Commix', desc: '命令注入检测' },
                    { key: 'enable_jwt_tool', name: 'JWT Tool', desc: 'JWT 分析/测试' },
                    { key: 'enable_newman', name: 'Newman', desc: 'Postman 运行器' },
                    { key: 'enable_sslscan', name: 'SSLScan', desc: 'SSL/TLS 分析' },
                  ].map(tool => (
                    <label key={tool.key} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={config[tool.key as keyof ScanConfig] as boolean}
                        onChange={e => setConfig({ ...config, [tool.key]: e.target.checked })}
                        className="w-3.5 h-3.5 mt-0.5"
                      />
                      <span>
                        <span className="font-medium">{tool.name}</span>
                        <span className="block text-xs text-gray-500">{tool.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* 凭证与身份验证 */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-gray-300 dark:border-gray-600">
                <input
                  type="checkbox"
                  checked={config.enable_category_cred}
                  onChange={e => setConfig({ ...config, enable_category_cred: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="font-semibold text-orange-700 dark:text-orange-400">🔑 凭证与身份验证</span>
                <span className="text-xs text-red-500 ml-auto">⚠️ 仅限授权环境</span>
              </div>
              {config.enable_category_cred && (
                <div className="grid grid-cols-2 gap-2 pl-6">
                  {[
                    { key: 'enable_hydra', name: 'Hydra', desc: '暴力破解工具' },
                    { key: 'enable_medusa', name: 'Medusa', desc: '并行暴力破解' },
                    { key: 'enable_netexec', name: 'NetExec', desc: '网络执行工具' },
                    { key: 'enable_cewl', name: 'CeWL', desc: '自定义字典生成' },
                    { key: 'enable_kerbrute', name: 'Kerbrute', desc: 'Kerberos 枚举' },
                    { key: 'enable_enum4linux', name: 'Enum4linux', desc: 'SMB/NetBIOS 枚举' },
                  ].map(tool => (
                    <label key={tool.key} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={config[tool.key as keyof ScanConfig] as boolean}
                        onChange={e => setConfig({ ...config, [tool.key]: e.target.checked })}
                        className="w-3.5 h-3.5 mt-0.5"
                      />
                      <span>
                        <span className="font-medium">{tool.name}</span>
                        <span className="block text-xs text-gray-500">{tool.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* 后渗透与取证辅助 */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-gray-300 dark:border-gray-600">
                <input
                  type="checkbox"
                  checked={config.enable_category_post_exploit}
                  onChange={e => setConfig({ ...config, enable_category_post_exploit: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="font-semibold text-gray-700 dark:text-gray-400">🔍 后渗透与取证辅助</span>
                <span className="text-xs text-red-500 ml-auto">⚠️ 仅限授权环境</span>
              </div>
              {config.enable_category_post_exploit && (
                <div className="grid grid-cols-2 gap-2 pl-6">
                  {[
                    { key: 'enable_gitleaks', name: 'Gitleaks', desc: 'Git 敏感信息扫描' },
                    { key: 'enable_trufflehog', name: 'TruffleHog', desc: '敏感信息扫描' },
                    { key: 'enable_pspy', name: 'pspy', desc: '进程监控' },
                    { key: 'enable_linpeas', name: 'LinPEAS', desc: 'Linux 权限提升检查' },
                    { key: 'enable_linenum', name: 'LinEnum', desc: 'Linux 枚举工具' },
                    { key: 'enable_linux_exploit_suggester', name: 'LES', desc: '内核漏洞建议' },
                  ].map(tool => (
                    <label key={tool.key} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={config[tool.key as keyof ScanConfig] as boolean}
                        onChange={e => setConfig({ ...config, [tool.key]: e.target.checked })}
                        className="w-3.5 h-3.5 mt-0.5"
                      />
                      <span>
                        <span className="font-medium">{tool.name}</span>
                        <span className="block text-xs text-gray-500">{tool.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm mb-1">速率限制 (请求/秒)</label>
              <input
                type="number"
                min="1"
                max="100"
                value={config.rate_limit}
                onChange={e => setConfig({ ...config, rate_limit: parseInt(e.target.value) })}
                className="w-24 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded px-3 py-1"
              />
            </div>
          </div>
        )}

        {/* Advanced AI Options */}
        <div className="border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 flex items-center justify-between hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Settings className="w-5 h-5 text-gray-500" />
              <span className="font-medium">AI 高级选项</span>
            </div>
            {showAdvanced ? (
              <ChevronUp className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            )}
          </button>

          {showAdvanced && (
            <div className="p-4 space-y-4 bg-white dark:bg-gray-900">
              {/* AI Persona Selection */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  <span className="flex items-center gap-2">
                    <Bot className="w-4 h-4 text-purple-500" />
                    AI 人格
                  </span>
                </label>
                <select
                  value={config.ai_persona_id || ''}
                  onChange={e => setConfig({ ...config, ai_persona_id: e.target.value })}
                  className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {personas?.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {p.is_default ? ' (默认)' : ''}
                      {p.description ? ` - ${p.description}` : ''}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  选择 AI Agent 的行为风格，可以在"AI 人格"页面管理
                </p>
              </div>

              {/* AI Custom Prompt */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  自定义 AI 提示词 <span className="text-gray-400 font-normal">(可选)</span>
                </label>
                <textarea
                  value={config.ai_custom_prompt}
                  onChange={e => setConfig({ ...config, ai_custom_prompt: e.target.value })}
                  placeholder="输入额外的指示给 AI 代理，例如：&#10;- 重点测试 SQL 注入漏洞&#10;- 尝试绕过 WAF&#10;- 对登录接口进行暴力破解测试"
                  rows={4}
                  className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  AI 代理会根据这些指示调整测试策略（会追加到人格提示词之后）
                </p>
              </div>

              {/* AI Max Iterations */}
              <label className="flex items-start gap-3 rounded-lg border border-purple-200 dark:border-purple-900/60 bg-purple-50 dark:bg-purple-950/30 p-3">
                <input
                  type="checkbox"
                  checked={config.enable_sub_agents ?? true}
                  onChange={e => setConfig({ ...config, enable_sub_agents: e.target.checked })}
                  className="w-4 h-4 mt-1"
                />
                <span>
                  <span className="block text-sm font-medium">启用子智能体任务编排</span>
                  <span className="block text-xs text-gray-500 dark:text-gray-400 mt-1">
                    主 Agent 会把侦察、漏洞验证、AI 验证、报告生成拆分给多个子智能体，并在扫描详情中展示进度。
                  </span>
                </span>
              </label>

              <div>
                <label className="block text-sm font-medium mb-2">
                  最大迭代次数
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min="0"
                    max="1000"
                    value={config.ai_max_iterations}
                    onChange={e => setConfig({ ...config, ai_max_iterations: parseInt(e.target.value) || 0 })}
                    className="w-24 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {config.ai_max_iterations === 0 ? '无限制' : `最多 ${config.ai_max_iterations} 次`}
                  </span>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  设置为 0 表示无限制，AI 将自行决定何时完成测试
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={mutation.isPending || !target.trim()}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-700 disabled:cursor-not-allowed text-white py-3 rounded-lg font-semibold flex items-center justify-center gap-2"
        >
          {mutation.isPending ? (
            '启动中...'
          ) : (
            <>
              <Play className="w-5 h-5" />
              开始扫描
            </>
          )}
        </button>

        {mutation.error && (
          <p className="text-red-500 text-sm">
            错误: {(mutation.error as Error).message}
          </p>
        )}
      </form>
    </div>
  )
}
