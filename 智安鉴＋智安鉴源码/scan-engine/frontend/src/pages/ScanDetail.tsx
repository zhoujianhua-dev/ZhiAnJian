import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { AlertTriangle, CheckCircle, Brain, Loader2, ChevronDown, ChevronUp, ChevronRight, Terminal, Bot, Wrench, AlertCircle, CheckCircle2, Info, XCircle, Trash2, MessageCircle, Send, Pause, MessageSquare, Server, Eye, Shield, FileText, Route, ShieldCheck, RefreshCw, Download, Key, Settings, ChevronLeft, GitBranch, Network, Sparkles } from 'lucide-react'
import { getScan, getVulnerabilities, getScanProgress, getScanLogs, cancelScan, deleteScan, getScanMessages, sendScanMessage, getScanChatHistory, sendScanChatMessage, getAttackPath, Vulnerability, ScanLogEntry, AttackChain, SubAgentTask } from '../lib/api'
import SeverityBadge from '../components/SeverityBadge'
import { useState, useEffect, useRef, useMemo } from 'react'

const statusLabels: Record<string, string> = {
  PENDING: '等待中',
  RUNNING: '扫描中',
  PAUSED: '等待回复',
  COMPLETED: '已完成',
  FAILED: '失败',
  CANCELLED: '已取消',
}

// Tab 类型定义
type TabType = 'sub-agents' | 'vulnerabilities' | 'attack-dialog' | 'attack-path' | 'report' | 'remediation'

interface TabItem {
  id: TabType
  label: string
  icon: React.ReactNode
}

// Tab 配置
const tabs: TabItem[] = [
  { id: 'sub-agents', label: 'SubAgent 编排', icon: <GitBranch className="w-4 h-4" /> },
  { id: 'vulnerabilities', label: '漏洞信息', icon: <Shield className="w-4 h-4" /> },
  { id: 'attack-dialog', label: '攻击对话', icon: <Terminal className="w-4 h-4" /> },
  { id: 'attack-path', label: '攻击路径', icon: <Route className="w-4 h-4" /> },
  { id: 'report', label: '漏洞报告', icon: <FileText className="w-4 h-4" /> },
  { id: 'remediation', label: '漏洞加固', icon: <ShieldCheck className="w-4 h-4" /> },
]

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<TabType>('vulnerabilities')
  const [showLogs, setShowLogs] = useState(true)
  const [showVulns, setShowVulns] = useState(false) // 默认隐藏，扫描完成后自动展开
  const [logs, setLogs] = useState<ScanLogEntry[]>([])
  const [logIndex, setLogIndex] = useState(0)
  const logsEndRef = useRef<HTMLDivElement>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data
      return data?.status === 'RUNNING' || data?.status === 'PENDING' || data?.status === 'PAUSED' ? 2000 : false
    },
  })

  // 扫描完成后自动展开漏洞列表
  useEffect(() => {
    if (scan?.status === 'COMPLETED' || scan?.status === 'FAILED' || scan?.status === 'CANCELLED') {
      setShowVulns(true)
    }
  }, [scan?.status])

  const { data: progress } = useQuery({
    queryKey: ['scan-progress', scanId],
    queryFn: () => getScanProgress(scanId!),
    enabled: !!scanId && (scan?.status === 'RUNNING' || scan?.status === 'PENDING' || scan?.status === 'PAUSED'),
    refetchInterval: 1500,
  })

  // Fetch logs incrementally
  const { data: logsData } = useQuery({
    queryKey: ['scan-logs', scanId, logIndex],
    queryFn: () => getScanLogs(scanId!, logIndex),
    enabled: !!scanId,
    refetchInterval: () => {
      // Keep polling for logs while scan is running or just completed
      return scan?.status === 'RUNNING' || scan?.status === 'PENDING' ? 1000 : false
    },
  })

  // Append new logs when received
  useEffect(() => {
    if (logsData && logsData.logs.length > 0) {
      setLogs(prev => [...prev, ...logsData.logs])
      setLogIndex(logsData.next_index)
    }
  }, [logsData])

  // Auto-scroll to bottom
  useEffect(() => {
    if (showLogs && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, showLogs])

  // Reset logs when scan changes
  useEffect(() => {
    setLogs([])
    setLogIndex(0)
  }, [scanId])

  const { data: vulns, isLoading: vulnsLoading } = useQuery({
    queryKey: ['vulnerabilities', scanId],
    queryFn: () => getVulnerabilities(scanId!),
    enabled: !!scanId && scan?.status === 'COMPLETED',
  })

  const cancelMutation = useMutation({
    mutationFn: () => cancelScan(scanId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => deleteScan(scanId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      navigate('/')
    },
  })

  const subAgents = useMemo(
    () => getDisplaySubAgents(scan, progress, logs),
    [scan, progress, logs]
  )

  if (scanLoading) {
    return <div className="text-center py-12">加载中...</div>
  }

  if (!scan) {
    return <div className="text-center py-12 text-red-500">扫描任务未找到</div>
  }

  const isActive = scan.status === 'RUNNING' || scan.status === 'PENDING' || scan.status === 'PAUSED'
  const canDelete = scan.status === 'COMPLETED' || scan.status === 'CANCELLED' || scan.status === 'FAILED'
  const displayProgress = getDisplayProgress(progress, subAgents, scan)

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-2">{scan.target}</h1>
          <div className="flex items-center gap-4 text-gray-500 dark:text-gray-400">
            <span className="capitalize">{scan.scan_type} 扫描</span>
            <span>•</span>
            <span>{format(new Date(scan.created_at), 'yyyy-MM-dd HH:mm')}</span>
            <span>•</span>
            <StatusBadge status={scan.status} />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-2">
          {isActive && (
            <button
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50"
            >
              <XCircle className="w-4 h-4" />
              {cancelMutation.isPending ? '取消中...' : '取消扫描'}
            </button>
          )}

          {canDelete && (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
            >
              <Trash2 className="w-4 h-4" />
              删除
            </button>
          )}
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold mb-2">确认删除</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              确定要删除此扫描任务吗？此操作不可恢复，所有相关漏洞数据也将被删除。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg"
              >
                取消
              </button>
              <button
                onClick={() => {
                  deleteMutation.mutate()
                  setShowDeleteConfirm(false)
                }}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
              >
                {deleteMutation.isPending ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Progress (for running/pending scans) */}
      {isActive && scan.status !== 'PAUSED' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
          <div className="flex items-center gap-3">
            <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
            <div>
              <h2 className="font-semibold text-blue-600 dark:text-blue-400">
                {scan.status === 'PENDING' ? '等待执行' : '扫描进行中'}
              </h2>
              <p className="text-gray-500 dark:text-gray-400 text-sm">
                {displayProgress.message}
              </p>
            </div>
          </div>
          {displayProgress.phase && (
            <div className="mt-4">
              <div className="flex gap-2 text-sm">
                <ProgressStep
                  label="初始化"
                  active={displayProgress.phase === 'initializing' || displayProgress.phase === 'queued'}
                  done={['parallel_sub_agents', 'running_nmap', 'running_nuclei', 'ai_agent', 'llm_analysis', 'completed'].includes(displayProgress.phase || '')}
                />
                <ProgressStep
                  label="端口扫描"
                  active={displayProgress.phase === 'running_nmap' || displayProgress.phase === 'parallel_sub_agents'}
                  done={['ai_agent', 'llm_analysis', 'completed'].includes(displayProgress.phase || '') || subAgents.some(agent => agent.id === 'recon-subagent' && agent.status === 'completed')}
                />
                <ProgressStep
                  label="漏洞扫描"
                  active={displayProgress.phase === 'running_nuclei' || displayProgress.phase === 'parallel_sub_agents'}
                  done={['ai_agent', 'llm_analysis', 'completed'].includes(displayProgress.phase || '') || subAgents.some(agent => agent.id === 'vulnerability-subagent' && agent.status === 'completed')}
                />
                <ProgressStep
                  label="AI 测试"
                  active={displayProgress.phase === 'ai_agent'}
                  done={['llm_analysis', 'completed'].includes(displayProgress.phase || '') || subAgents.some(agent => agent.id === 'ai-validation-subagent' && agent.status === 'completed')}
                />
                <ProgressStep
                  label="AI 分析"
                  active={displayProgress.phase === 'llm_analysis'}
                  done={displayProgress.phase === 'completed' || subAgents.some(agent => agent.id === 'reporting-subagent' && agent.status === 'completed')}
                />
              </div>
            </div>
          )}
        </div>
      )}

      <SubAgentOverview subAgents={subAgents} isActive={isActive} />

      {/* Tab Navigation */}
      <div className="mb-6 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
        <nav className="flex space-x-1 min-w-max" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap
                border-b-2 transition-colors duration-200
                ${activeTab === tab.id
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                }
              `}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        {/* Tab 1: 漏洞信息 */}
        {activeTab === 'sub-agents' && (
          <TabSubAgents subAgents={subAgents} scan={scan} />
        )}

        {activeTab === 'vulnerabilities' && (
          <TabVulnerabilities
            scan={scan}
            vulns={vulns}
            vulnsLoading={vulnsLoading}
            showVulns={showVulns}
            setShowVulns={setShowVulns}
          />
        )}

        {/* Tab 2: 攻击对话 */}
        {activeTab === 'attack-dialog' && (
          <TabAttackDialog
            scanId={scanId!}
            scan={scan}
            logs={logs}
            showLogs={showLogs}
            setShowLogs={setShowLogs}
            logsEndRef={logsEndRef}
            isActive={isActive}
            subAgents={subAgents}
          />
        )}

        {/* Tab 3: 攻击路径 */}
        {activeTab === 'attack-path' && (
          <TabAttackPath scan={scan} vulns={vulns} />
        )}

        {/* Tab 4: 漏洞报告 */}
        {activeTab === 'report' && (
          <TabReport scan={scan} vulns={vulns} />
        )}

        {/* Tab 5: 漏洞加固 */}
        {activeTab === 'remediation' && (
          <TabRemediation scanId={scanId!} scan={scan} vulns={vulns} />
        )}
      </div>
    </div>
  )
}

// ============ Tab Content Components ============

const subAgentStatusLabels: Record<string, string> = {
  queued: '排队中',
  running: '执行中',
  waiting_input: '等待输入',
  completed: '已完成',
  failed: '失败',
  skipped: '已跳过',
}

const subAgentStatusStyles: Record<string, string> = {
  queued: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
  running: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  waiting_input: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  skipped: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
}

function getDisplayProgress(progress: any, subAgents: SubAgentTask[], scan: any): { phase: string | null; message: string } {
  const runningAgents = subAgents.filter(agent => agent.status === 'running' || agent.status === 'waiting_input')
  const byId = Object.fromEntries(subAgents.map(agent => [agent.id, agent]))

  if (runningAgents.length > 0) {
    const runningNames = runningAgents.map(agent => agent.name).join('、')
    const hasParallelInitialScan = runningAgents.some(agent => ['recon-subagent', 'vulnerability-subagent'].includes(agent.id))
    return {
      phase: hasParallelInitialScan ? 'parallel_sub_agents' : runningAgents[0].phase || progress?.phase || 'running',
      message: `SubAgent 执行中：${runningNames}`,
    }
  }

  if (byId['reporting-subagent']?.status === 'completed' || scan?.status === 'COMPLETED') {
    return { phase: 'completed', message: 'SubAgent 编排完成' }
  }
  if (byId['ai-validation-subagent']?.status === 'completed') {
    return { phase: 'llm_analysis', message: 'Reporting SubAgent 正在生成报告...' }
  }
  if (byId['vulnerability-subagent']?.status === 'completed') {
    return { phase: 'ai_agent', message: 'AI Validation SubAgent 正在验证发现...' }
  }
  if (byId['recon-subagent']?.status === 'completed') {
    return { phase: 'running_nuclei', message: 'Vulnerability SubAgent 正在验证漏洞...' }
  }

  return {
    phase: progress?.phase || null,
    message: progress?.message || '主 Agent 正在编排 SubAgent...',
  }
}

function getDisplaySubAgents(scan: any, progress: any, logs: ScanLogEntry[]): SubAgentTask[] {
  const fromApi = progress?.sub_agents?.length ? progress.sub_agents : scan?.sub_agents
  const apiLooksStale = fromApi?.length && (
    fromApi.every((agent: SubAgentTask) => agent.status === 'queued' && (agent.progress || 0) === 0)
    || (scan?.status === 'COMPLETED' && fromApi.every((agent: SubAgentTask) => agent.status !== 'completed'))
  )
  if (fromApi?.length && !apiLooksStale) return fromApi

  const hasNmap = logs.some(log => log.tool?.toLowerCase() === 'nmap' || log.message.toLowerCase().includes('nmap'))
  const nmapDone = logs.some(log => log.message.includes('NMAP 扫描完成'))
  const hasNuclei = logs.some(log => log.tool?.toLowerCase() === 'nuclei' || log.message.toLowerCase().includes('nuclei'))
  const nucleiDone = logs.some(log => log.message.includes('NUCLEI 扫描完成'))
  const hasAi = logs.some(log => log.type === 'llm' || log.message.includes('AI Agent') || log.message.includes('迭代'))
  const hasReport = logs.some(log => log.message.includes('AI 开始生成扫描报告') || log.message.includes('扫描任务完成'))

  const statusFromLogs = (started: boolean, done: boolean): SubAgentTask['status'] => {
    if (done) return 'completed'
    if (started) return 'running'
    return 'queued'
  }

  return [
    {
      id: 'recon-subagent',
      name: 'Recon SubAgent',
      role: '资产探测与端口识别',
      objective: '识别目标暴露面、开放端口与基础服务指纹。',
      status: statusFromLogs(hasNmap, nmapDone),
      phase: hasNmap ? 'running_nmap' : null,
      progress: nmapDone ? 100 : hasNmap ? 65 : 0,
      started_at: null,
      completed_at: null,
      summary: hasNmap ? '由现有执行日志推断：主 Agent 已委派 NMAP 侦察任务。' : '等待主 Agent 委派侦察任务。',
      findings_count: logs.filter(log => log.tool?.toLowerCase() === 'nmap' && log.message.includes('发现')).length,
      error: null,
    },
    {
      id: 'vulnerability-subagent',
      name: 'Vulnerability SubAgent',
      role: '模板化漏洞验证',
      objective: '调用漏洞扫描器验证常见 Web 与服务漏洞。',
      status: statusFromLogs(hasNuclei, nucleiDone),
      phase: hasNuclei ? 'running_nuclei' : null,
      progress: nucleiDone ? 100 : hasNuclei ? 65 : 0,
      started_at: null,
      completed_at: null,
      summary: hasNuclei ? '由现有执行日志推断：主 Agent 已委派 NUCLEI 漏洞验证任务。' : '等待侦察结果后启动漏洞验证。',
      findings_count: logs.filter(log => log.tool?.toLowerCase() === 'nuclei' && log.message.includes('发现')).length,
      error: null,
    },
    {
      id: 'ai-validation-subagent',
      name: 'AI Validation SubAgent',
      role: '自主安全测试与发现验证',
      objective: '基于主 Agent 上下文执行补充测试、验证发现并提出下一步判断。',
      status: statusFromLogs(hasAi, (scan?.status === 'COMPLETED' && hasAi) || logs.some(log => log.message.includes('AI Agent 发现') || log.message.includes('AI Validation SubAgent'))),
      phase: hasAi ? 'ai_agent' : null,
      progress: scan?.status === 'COMPLETED' && hasAi ? 100 : hasAi ? 70 : 0,
      started_at: null,
      completed_at: null,
      summary: hasAi ? 'AI Validation SubAgent 正在进行多轮分析、工具调用和结果校验。' : '等待基础扫描结果后启动 AI 验证。',
      findings_count: logs.filter(log => log.type === 'llm' && log.message.includes('发现')).length,
      error: null,
    },
    {
      id: 'reporting-subagent',
      name: 'Reporting SubAgent',
      role: '风险归纳与报告生成',
      objective: '汇总各 SubAgent 输出，生成风险评分、修复建议与攻击路径。',
      status: statusFromLogs(hasReport || scan?.status === 'COMPLETED', scan?.status === 'COMPLETED'),
      phase: hasReport ? 'llm_analysis' : null,
      progress: scan?.status === 'COMPLETED' ? 100 : hasReport ? 60 : 0,
      started_at: null,
      completed_at: null,
      summary: hasReport ? 'Reporting SubAgent 正在整理 SubAgent 输出。' : '等待前置 SubAgent 输出后生成报告。',
      findings_count: scan?.vulnerability_count || 0,
      error: null,
    },
  ]
}

function SubAgentOverview({ subAgents, isActive }: { subAgents: SubAgentTask[]; isActive: boolean }) {
  const running = subAgents.filter(agent => agent.status === 'running' || agent.status === 'waiting_input')
  const completed = subAgents.filter(agent => agent.status === 'completed').length
  const averageProgress = subAgents.length
    ? Math.round(subAgents.reduce((sum, agent) => sum + (agent.progress || 0), 0) / subAgents.length)
    : 0

  return (
    <div className="mb-6 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-gradient-to-r from-purple-50 via-blue-50 to-cyan-50 dark:from-purple-950/40 dark:via-blue-950/30 dark:to-cyan-950/30 p-5 shadow-sm">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-purple-600 text-white shadow">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-lg font-semibold text-purple-900 dark:text-purple-100">主 Agent 正在使用 SubAgent 任务编排</h2>
              {isActive && <span className="px-2 py-0.5 rounded-full text-xs bg-blue-600 text-white animate-pulse">实时编排中</span>}
            </div>
            <p className="text-sm text-purple-700 dark:text-purple-300 mt-1">
              主 Agent 将扫描拆成侦察、漏洞验证、AI 验证、报告生成 4 个 SubAgent，并汇总输出。
            </p>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3 min-w-[280px]">
          <SubAgentMiniStat label="SubAgent" value={subAgents.length} />
          <SubAgentMiniStat label="运行中" value={running.length} color="text-blue-600" />
          <SubAgentMiniStat label="已完成" value={`${completed}/${subAgents.length}`} color="text-green-600" />
        </div>
      </div>
      <div className="mt-4 h-2 bg-white/70 dark:bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full bg-gradient-to-r from-purple-500 via-blue-500 to-cyan-500 transition-all duration-500" style={{ width: `${averageProgress}%` }} />
      </div>
      {running.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {running.map(agent => (
            <span key={agent.id} className="px-2 py-1 rounded-full bg-white/80 dark:bg-gray-800 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-900">
              当前：{agent.name} · {agent.progress}%
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function SubAgentMiniStat({ label, value, color = 'text-purple-700 dark:text-purple-300' }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="rounded-lg bg-white/75 dark:bg-gray-900/60 px-3 py-2 text-center border border-white/70 dark:border-gray-800">
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 dark:text-gray-400">{label}</div>
    </div>
  )
}

function TabSubAgents({ subAgents, scan }: { subAgents: SubAgentTask[]; scan: any }) {
  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow border border-purple-100 dark:border-purple-900/50">
        <div className="flex items-start gap-3 mb-5">
          <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-300">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-semibold">SubAgent 任务编排视图</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              这里展示主 Agent 如何分派子任务、跟踪执行状态，并把各 SubAgent 的输出汇总进扫描结果。
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {subAgents.map((agent, index) => (
            <SubAgentCard key={agent.id} agent={agent} index={index} />
          ))}
        </div>
      </div>

      <div className="bg-gray-950 text-gray-100 rounded-lg p-5 shadow font-mono text-sm overflow-x-auto">
        <div className="flex items-center gap-2 text-purple-300 mb-3">
          <Sparkles className="w-4 h-4" />
          <span>主 Agent 编排链路</span>
        </div>
        <div className="whitespace-nowrap">
          主Agent({scan.target})
          {subAgents.map(agent => `  →  ${agent.name}[${subAgentStatusLabels[agent.status] || agent.status}]`).join('')}
        </div>
      </div>
    </div>
  )
}

function SubAgentCard({ agent, index }: { agent: SubAgentTask; index: number }) {
  const Icon = agent.id.includes('recon') ? Eye : agent.id.includes('vulnerability') ? Shield : agent.id.includes('ai') ? Bot : FileText
  return (
    <div className="relative rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/60 p-4 overflow-hidden">
      <div className="absolute top-3 right-3 text-4xl font-black text-gray-200 dark:text-gray-800">{index + 1}</div>
      <div className="relative">
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="p-2 rounded-lg bg-white dark:bg-gray-800 text-purple-600 dark:text-purple-300 shadow-sm">
            <Icon className="w-5 h-5" />
          </div>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${subAgentStatusStyles[agent.status] || subAgentStatusStyles.queued}`}>
            {subAgentStatusLabels[agent.status] || agent.status}
          </span>
        </div>
        <h3 className="font-semibold text-gray-900 dark:text-gray-100">{agent.name}</h3>
        <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">{agent.role}</p>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-3 min-h-12">{agent.objective}</p>

        <div className="mt-4">
          <div className="flex justify-between text-xs mb-1">
            <span className="text-gray-500">进度</span>
            <span className="font-medium">{agent.progress}%</span>
          </div>
          <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <div className={`h-full transition-all duration-500 ${agent.status === 'failed' ? 'bg-red-500' : agent.status === 'completed' ? 'bg-green-500' : 'bg-blue-500'}`} style={{ width: `${agent.progress}%` }} />
          </div>
        </div>

        <div className="mt-4 rounded-lg bg-white dark:bg-gray-800 p-3 text-xs text-gray-600 dark:text-gray-300 border border-gray-100 dark:border-gray-700">
          {agent.summary || '等待主 Agent 下发任务。'}
          {agent.error && <div className="mt-2 text-red-500">错误：{agent.error}</div>}
        </div>

        <div className="mt-3 flex justify-between text-xs text-gray-500 dark:text-gray-400">
          <span>发现 {agent.findings_count || 0} 项</span>
          <span>{agent.phase || '待调度'}</span>
        </div>
      </div>
    </div>
  )
}

function TabVulnerabilities({
  scan,
  vulns,
  vulnsLoading,
}: {
  scan: any
  vulns: any
  vulnsLoading: boolean
  showVulns?: boolean
  setShowVulns?: (v: boolean) => void
}) {
  const openPorts = vulns?.items.filter((v: Vulnerability) => v.name.startsWith('Open port:')) || []
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []

  if (scan.status !== 'COMPLETED' && scan.status !== 'FAILED' && scan.status !== 'CANCELLED') {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Shield className="w-12 h-12 mx-auto mb-4 text-gray-400" />
        <p className="text-gray-500 dark:text-gray-400">扫描进行中，完成后将在此显示漏洞信息</p>
      </div>
    )
  }

  return (
    <>
      {/* Open Ports Section */}
      {openPorts.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow mb-6">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-500" />
            <h2 className="font-semibold">开放端口</h2>
            <span className="text-sm text-gray-500">({openPorts.length})</span>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {openPorts.map((port: Vulnerability) => (
                <PortCard key={port.id} port={port} />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Stats - only count actual vulnerabilities */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatBox label="漏洞数" value={actualVulns.length} />
        <StatBox
          label="严重"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'critical').length}
          color="text-red-500"
        />
        <StatBox
          label="高危"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'high').length}
          color="text-orange-500"
        />
        <StatBox
          label="中危"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'medium').length}
          color="text-yellow-500"
        />
      </div>

      {/* Vulnerabilities */}
      <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
        <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
          <h2 className="font-semibold">漏洞列表</h2>
        </div>

        {vulnsLoading ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">加载漏洞数据...</div>
        ) : actualVulns.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500" />
            未发现漏洞
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {actualVulns.map((vuln: Vulnerability) => (
              <VulnRow key={vuln.id} vuln={vuln} />
            ))}
          </div>
        )}
      </div>
    </>
  )
}

function TabAttackDialog({
  scanId,
  scan,
  logs,
  showLogs,
  setShowLogs,
  logsEndRef,
  isActive,
  subAgents,
}: {
  scanId: string
  scan: any
  logs: ScanLogEntry[]
  showLogs: boolean
  setShowLogs: (v: boolean) => void
  logsEndRef: React.RefObject<HTMLDivElement>
  isActive: boolean
  subAgents: SubAgentTask[]
}) {
  const activeSubAgents = subAgents.filter(agent => agent.status === 'running' || agent.status === 'waiting_input')

  return (
    <>
      {/* Paused - Agent asking user */}
      {scan.status === 'PAUSED' && (
        <AgentQuestionPanel scanId={scanId} />
      )}

      <div className="bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/60 rounded-lg p-4 mb-4">
        <div className="flex items-center gap-2 mb-3">
          <GitBranch className="w-5 h-5 text-purple-600 dark:text-purple-300" />
          <h2 className="font-semibold text-purple-900 dark:text-purple-100">日志由主 Agent + SubAgent 协作产生</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-sm">
          {subAgents.map(agent => (
            <div key={agent.id} className={`rounded-lg px-3 py-2 border ${agent.status === 'running' || agent.status === 'waiting_input' ? 'bg-white dark:bg-gray-900 border-blue-300 dark:border-blue-800' : 'bg-white/60 dark:bg-gray-900/50 border-purple-100 dark:border-purple-900/50'}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium truncate">{agent.name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${subAgentStatusStyles[agent.status] || subAgentStatusStyles.queued}`}>
                  {subAgentStatusLabels[agent.status] || agent.status}
                </span>
              </div>
              <div className="mt-2 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div className="h-full bg-purple-500 transition-all" style={{ width: `${agent.progress}%` }} />
              </div>
            </div>
          ))}
        </div>
        {activeSubAgents.length > 0 && (
          <p className="mt-3 text-xs text-purple-700 dark:text-purple-300">
            当前活跃 SubAgent：{activeSubAgents.map(agent => `${agent.name}（${agent.progress}%）`).join('、')}
          </p>
        )}
      </div>

      {/* Real-time Logs */}
      {(isActive || logs.length > 0) && (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
          <button
            onClick={() => setShowLogs(!showLogs)}
            className="w-full px-4 py-3 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-green-500" />
              <h2 className="font-semibold">执行日志</h2>
              <span className="text-xs text-gray-500">({logs.length} 条)</span>
            </div>
            {showLogs ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>

          {showLogs && (
            <div className="max-h-[70vh] overflow-y-auto p-4 space-y-2 bg-gray-50 dark:bg-gray-900 font-mono text-sm transition-all duration-300">
              {logs.length === 0 ? (
                <div className="text-gray-500 text-center py-4">等待日志...</div>
              ) : (
                logs.map((log, idx) => (
                  <LogEntry key={idx} log={log} />
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      )}

      {/* 没有日志时的空状态 */}
      {!isActive && logs.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
          <Terminal className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">暂无执行日志</p>
        </div>
      )}
    </>
  )
}

// 攻击阶段定义（本地渲染用）
interface AttackPhaseUI {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  color: string
  bgColor: string
  items: AttackItem[]
}

interface AttackItem {
  id: string
  name: string
  severity?: string
  location?: string
  description?: string
}

// 阶段样式配置
const phaseStyles: Record<string, { icon: React.ReactNode; color: string; bgColor: string }> = {
  recon: {
    icon: <Eye className="w-5 h-5" />,
    color: 'text-blue-600 dark:text-blue-400',
    bgColor: 'bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800',
  },
  vuln: {
    icon: <AlertTriangle className="w-5 h-5" />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-50 dark:bg-orange-900/30 border-orange-200 dark:border-orange-800',
  },
  exploit: {
    icon: <Wrench className="w-5 h-5" />,
    color: 'text-red-600 dark:text-red-400',
    bgColor: 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800',
  },
  impact: {
    icon: <AlertCircle className="w-5 h-5" />,
    color: 'text-purple-600 dark:text-purple-400',
    bgColor: 'bg-purple-50 dark:bg-purple-900/30 border-purple-200 dark:border-purple-800',
  },
}

function TabAttackPath({ scan, vulns }: { scan: any; vulns: any }) {
  const queryClient = useQueryClient()

  // 使用后端 API 获取攻击路径分析
  const { data: attackPathResponse, isLoading, error, refetch } = useQuery({
    queryKey: ['attack-path', scan.id],
    queryFn: () => getAttackPath(scan.id),
    enabled: scan.status === 'COMPLETED' && vulns?.items?.length > 0,
    staleTime: 5 * 60 * 1000, // 5分钟缓存
  })

  const [isRefreshing, setIsRefreshing] = useState(false)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      await getAttackPath(scan.id, true) // 强制刷新
      queryClient.invalidateQueries({ queryKey: ['attack-path', scan.id] })
    } finally {
      setIsRefreshing(false)
    }
  }

  // 加载状态
  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Loader2 className="w-12 h-12 mx-auto mb-4 text-blue-500 animate-spin" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">正在分析攻击路径...</h3>
        <p className="text-gray-500 dark:text-gray-400">AI 正在基于扫描结果生成攻击路径分析</p>
      </div>
    )
  }

  // 扫描未完成
  if (scan.status !== 'COMPLETED') {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Route className="w-16 h-16 mx-auto mb-4 text-gray-400" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">攻击路径分析</h3>
        <p className="text-gray-500 dark:text-gray-400">扫描完成后将自动生成攻击路径分析</p>
      </div>
    )
  }

  // 没有漏洞
  if (!vulns?.items?.length) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-500" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">未发现漏洞</h3>
        <p className="text-gray-500 dark:text-gray-400">扫描未发现安全问题，目标相对安全</p>
      </div>
    )
  }

  // 错误状态
  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <XCircle className="w-16 h-16 mx-auto mb-4 text-red-500" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">分析失败</h3>
        <p className="text-gray-500 dark:text-gray-400 mb-4">无法生成攻击路径分析</p>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          重试
        </button>
      </div>
    )
  }

  const attackPath = attackPathResponse?.data
  if (!attackPath) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Route className="w-16 h-16 mx-auto mb-4 text-gray-400" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">暂无数据</h3>
        <p className="text-gray-500 dark:text-gray-400">攻击路径分析数据不可用</p>
      </div>
    )
  }

  const { phases, attack_chains, risk_assessment } = attackPath

  // 将 API 数据转换为 UI 格式
  const phasesUI: AttackPhaseUI[] = phases.map(phase => ({
    ...phase,
    ...phaseStyles[phase.id] || phaseStyles.vuln,
    items: phase.items.map(item => ({
      id: item.id,
      name: item.name,
      severity: item.severity,
      description: item.details,
    })),
  }))

  // 风险等级配置
  const riskConfig: Record<string, { label: string; color: string; bg: string }> = {
    critical: { label: '极高风险', color: 'text-red-600', bg: 'bg-red-100 dark:bg-red-900/50' },
    high: { label: '高风险', color: 'text-orange-600', bg: 'bg-orange-100 dark:bg-orange-900/50' },
    medium: { label: '中等风险', color: 'text-yellow-600', bg: 'bg-yellow-100 dark:bg-yellow-900/50' },
    low: { label: '低风险', color: 'text-green-600', bg: 'bg-green-100 dark:bg-green-900/50' },
  }

  const riskLevel = risk_assessment.overall_risk || 'low'

  return (
    <div className="space-y-6">
      {/* 风险概览 */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Route className="w-5 h-5 text-blue-500" />
            攻击路径分析
            {attackPathResponse?.cached && (
              <span className="text-xs text-gray-400 font-normal">(缓存)</span>
            )}
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="p-2 text-gray-500 hover:text-blue-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              title="重新分析"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${riskConfig[riskLevel]?.bg || ''} ${riskConfig[riskLevel]?.color || ''}`}>
              {riskConfig[riskLevel]?.label || '未知风险'}
            </div>
          </div>
        </div>

        {/* 风险评分 */}
        <div className="flex items-center gap-4 mb-4">
          <div className="flex-1">
            <div className="flex items-center justify-between text-sm mb-1">
              <span className="text-gray-500">风险评分</span>
              <span className="font-semibold">{risk_assessment.risk_score}/100</span>
            </div>
            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${risk_assessment.risk_score >= 80 ? 'bg-red-500' :
                  risk_assessment.risk_score >= 60 ? 'bg-orange-500' :
                    risk_assessment.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                style={{ width: `${risk_assessment.risk_score}%` }}
              />
            </div>
          </div>
        </div>

        <p className="text-gray-600 dark:text-gray-400 text-sm">
          {risk_assessment.summary}
        </p>
      </div>

      {/* 攻击阶段可视化 */}
      <div className="relative">
        <div className="absolute top-0 bottom-0 left-8 w-0.5 bg-gray-200 dark:bg-gray-700 hidden md:block" />
        <div className="space-y-4">
          {phasesUI.map((phase, index) => (
            <AttackPhaseCard key={phase.id} phase={phase} index={index} />
          ))}
        </div>
      </div>

      {/* 攻击链 */}
      {attack_chains.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            攻击链分析
          </h3>
          <div className="space-y-4">
            {attack_chains.map((chain) => (
              <AttackChainCard key={chain.id} chain={chain} />
            ))}
          </div>
        </div>
      )}

      {/* 安全建议 */}
      {risk_assessment.recommendations.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-green-500" />
            安全建议
          </h3>
          <ul className="space-y-2">
            {risk_assessment.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-300">
                <CheckCircle2 className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// 攻击链卡片组件
function AttackChainCard({ chain }: { chain: AttackChain }) {
  const [expanded, setExpanded] = useState(false)

  const impactColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/50 dark:text-orange-300',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300',
    low: 'bg-green-100 text-green-700 dark:bg-green-900/50 dark:text-green-300',
  }

  const likelihoodLabels: Record<string, string> = {
    high: '高可能性',
    medium: '中可能性',
    low: '低可能性',
  }

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Wrench className="w-5 h-5 text-red-500" />
          <div className="text-left">
            <h4 className="font-medium">{chain.name}</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">{chain.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-1 rounded text-xs ${impactColors[chain.impact] || ''}`}>
            {chain.impact.toUpperCase()}
          </span>
          <span className="text-xs text-gray-500">
            {likelihoodLabels[chain.likelihood] || chain.likelihood}
          </span>
          {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-100 dark:border-gray-700">
          <div className="pt-4 space-y-3">
            {chain.steps.map((step: { order: number; action: string; vulnerability?: string; result?: string }, i: number) => (
              <div key={i} className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 flex items-center justify-center text-xs font-bold shrink-0">
                  {step.order}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm">{step.action}</p>
                  {step.vulnerability && (
                    <p className="text-xs text-orange-600 dark:text-orange-400">利用: {step.vulnerability}</p>
                  )}
                  <p className="text-xs text-gray-500 dark:text-gray-400">{step.result}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// 攻击阶段卡片组件
function AttackPhaseCard({ phase, index }: { phase: AttackPhaseUI; index: number }) {
  const [expanded, setExpanded] = useState(index < 2) // 前两个默认展开

  return (
    <div className={`relative md:ml-12 bg-white dark:bg-gray-800 rounded-lg shadow border ${phase.bgColor}`}>
      {/* 时间线节点 */}
      <div className={`absolute -left-12 top-4 w-6 h-6 rounded-full bg-white dark:bg-gray-800 border-2 items-center justify-center hidden md:flex ${phase.color} border-current`}>
        <span className="text-xs font-bold">{index + 1}</span>
      </div>

      {/* 头部 */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors rounded-t-lg"
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${phase.bgColor} ${phase.color}`}>
            {phase.icon}
          </div>
          <div className="text-left">
            <h3 className="font-semibold">{phase.name}</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">{phase.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
            {phase.items.length} 项
          </span>
          {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {/* 内容 */}
      {expanded && phase.items.length > 0 && (
        <div className="px-4 pb-4 space-y-2">
          {phase.items.slice(0, 10).map((item) => (
            <div
              key={item.id}
              className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex items-start gap-2">
                {item.severity && <SeverityBadge severity={item.severity as any} />}
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm">{item.name}</p>
                  {item.location && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{item.location}</p>
                  )}
                  {item.description && (
                    <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">{item.description}</p>
                  )}
                </div>
              </div>
            </div>
          ))}
          {phase.items.length > 10 && (
            <p className="text-sm text-gray-500 text-center py-2">
              还有 {phase.items.length - 10} 项...
            </p>
          )}
        </div>
      )}

      {expanded && phase.items.length === 0 && (
        <div className="px-4 pb-4">
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
            未发现相关内容
          </p>
        </div>
      )}
    </div>
  )
}

function TabReport({ scan, vulns }: { scan: any; vulns: any }) {
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []
  const [exportFormat, setExportFormat] = useState<string | null>(null)
  const [isExporting, setIsExporting] = useState(false)
  const [exportMenuOpen, setExportMenuOpen] = useState(false)
  const exportMenuRef = useRef<HTMLDivElement>(null)

  // 按严重程度分组
  const criticalVulns = actualVulns.filter((v: Vulnerability) => v.severity === 'critical')
  const highVulns = actualVulns.filter((v: Vulnerability) => v.severity === 'high')
  const mediumVulns = actualVulns.filter((v: Vulnerability) => v.severity === 'medium')
  const lowVulns = actualVulns.filter((v: Vulnerability) => v.severity === 'low')
  const keyVulns = [...criticalVulns, ...highVulns].slice(0, 10)
  const fallbackSummary = actualVulns.length === 0
    ? `已完成对 ${scan.target} 的安全扫描，未发现明显漏洞。`
    : (
      `已完成对 ${scan.target} 的安全扫描，发现 ${actualVulns.length} 个安全问题，`
      + `其中严重 ${criticalVulns.length} 个、高危 ${highVulns.length} 个。`
      + '建议优先处理高风险问题并安排复测。'
    )
  const summaryText: string = (scan.llm_summary?.trim() || fallbackSummary)
    .replace(/^#+\s*/gm, '')
    .replace(/^\s*[-*]\s+/gm, '')
    .replace(/^\s*\d+\.\s+/gm, '')
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/_{1,2}([^_]+)_{1,2}/g, '$1')
    .replace(/\s*\n+\s*/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()

  useEffect(() => {
    if (!exportMenuOpen) return
    const handleClick = (event: MouseEvent) => {
      if (!exportMenuRef.current?.contains(event.target as Node)) {
        setExportMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => {
      document.removeEventListener('mousedown', handleClick)
    }
  }, [exportMenuOpen])

  // 导出报告
  const handleExport = async (format: string) => {
    setExportMenuOpen(false)
    setIsExporting(true)
    setExportFormat(format)

    try {
      const reportData = {
        scan: {
          id: scan.id,
          target: scan.target,
          scan_type: scan.scan_type,
          status: scan.status,
          started_at: scan.started_at,
          completed_at: scan.completed_at,
          risk_score: scan.llm_risk_score,
          summary: scan.llm_summary,
        },
        statistics: {
          total: actualVulns.length,
          critical: criticalVulns.length,
          high: highVulns.length,
          medium: mediumVulns.length,
          low: lowVulns.length,
        },
        vulnerabilities: actualVulns.map((v: Vulnerability) => ({
          name: v.name,
          severity: v.severity,
          category: v.category,
          location: v.location,
          description: v.description,
          evidence: v.evidence,
          analysis: v.llm_analysis,
          remediation: v.llm_remediation,
        })),
      }

      let content = ''
      let filename = `vulnerability-report-${scan.id.slice(0, 8)}`
      let mimeType = 'text/plain'

      switch (format) {
        case 'markdown':
          content = generateMarkdownReport(reportData)
          filename += '.md'
          mimeType = 'text/markdown'
          break
        case 'json':
          content = JSON.stringify(reportData, null, 2)
          filename += '.json'
          mimeType = 'application/json'
          break
        case 'csv':
          content = generateCSVReport(reportData)
          filename += '.csv'
          mimeType = 'text/csv'
          break
        case 'html':
          content = generateHTMLReport(reportData)
          filename += '.html'
          mimeType = 'text/html'
          break
        default:
          content = generateMarkdownReport(reportData)
          filename += '.md'
      }

      // 下载文件
      const blob = new Blob([content], { type: mimeType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } finally {
      setIsExporting(false)
      setExportFormat(null)
    }
  }

  return (
    <>
      {/* 漏洞信息与统计（合并区域） */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
        {/* 头部：风险评分和统计 */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            {/* 风险评分 */}
            {scan.llm_risk_score !== null && scan.llm_risk_score !== undefined && (
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <AlertTriangle className={`w-6 h-6 ${scan.llm_risk_score >= 80 ? 'text-red-500' :
                    scan.llm_risk_score >= 60 ? 'text-orange-500' :
                      scan.llm_risk_score >= 40 ? 'text-yellow-500' : 'text-green-500'
                    }`} />
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">风险评分</p>
                    <p className={`text-2xl font-bold ${scan.llm_risk_score >= 80 ? 'text-red-500' :
                      scan.llm_risk_score >= 60 ? 'text-orange-500' :
                        scan.llm_risk_score >= 40 ? 'text-yellow-500' : 'text-green-500'
                      }`}>{scan.llm_risk_score}/100</p>
                  </div>
                </div>
                <div className="w-32 h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${scan.llm_risk_score >= 80 ? 'bg-red-500' :
                      scan.llm_risk_score >= 60 ? 'bg-orange-500' :
                        scan.llm_risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                    style={{ width: `${scan.llm_risk_score}%` }}
                  />
                </div>
              </div>
            )}

            {/* 漏洞统计 */}
            <div className="flex items-center gap-3">
              <div className="text-center px-3 py-1 bg-gray-100 dark:bg-gray-700 rounded">
                <p className="text-lg font-bold">{actualVulns.length}</p>
                <p className="text-xs text-gray-500">总计</p>
              </div>
              <div className="text-center px-3 py-1 bg-red-100 dark:bg-red-900/30 rounded">
                <p className="text-lg font-bold text-red-600">{criticalVulns.length}</p>
                <p className="text-xs text-red-600">严重</p>
              </div>
              <div className="text-center px-3 py-1 bg-orange-100 dark:bg-orange-900/30 rounded">
                <p className="text-lg font-bold text-orange-600">{highVulns.length}</p>
                <p className="text-xs text-orange-600">高危</p>
              </div>
              <div className="text-center px-3 py-1 bg-yellow-100 dark:bg-yellow-900/30 rounded">
                <p className="text-lg font-bold text-yellow-600">{mediumVulns.length}</p>
                <p className="text-xs text-yellow-600">中危</p>
              </div>
              <div className="text-center px-3 py-1 bg-blue-100 dark:bg-blue-900/30 rounded">
                <p className="text-lg font-bold text-blue-600">{lowVulns.length}</p>
                <p className="text-xs text-blue-600">低危</p>
              </div>
            </div>

            {/* 导出按钮 */}
            <div className="flex items-center gap-2">
              <div className="relative" ref={exportMenuRef}>
                <button
                  type="button"
                  onClick={() => setExportMenuOpen((open) => !open)}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  导出报告
                  <ChevronDown className="w-4 h-4" />
                </button>
                {exportMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-10">
                    {['markdown', 'html', 'json', 'csv'].map(fmt => (
                      <button
                        key={fmt}
                        onClick={() => handleExport(fmt)}
                        disabled={isExporting}
                        className="w-full px-4 py-2 text-left hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2 first:rounded-t-lg last:rounded-b-lg"
                      >
                        <FileText className="w-4 h-4" />
                        {fmt.toUpperCase()}
                        {isExporting && exportFormat === fmt && <Loader2 className="w-4 h-4 animate-spin" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* 报告摘要（可读格式） */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="w-5 h-5 text-purple-500" />
            <h3 className="font-semibold">报告摘要</h3>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-300 leading-relaxed">
            {summaryText}
          </p>
        </div>

        {/* 关键漏洞（简要） */}
        <div className="p-6">
          <h3 className="font-semibold mb-2 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-500" />
            关键漏洞
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            仅展示严重/高危漏洞，完整列表请查看「漏洞信息」。
          </p>
          {keyVulns.length === 0 ? (
            <div className="text-center py-6 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>未发现严重/高危漏洞</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {keyVulns.map((vuln: Vulnerability) => (
                <div key={vuln.id} className="py-3 flex items-start gap-3">
                  <SeverityBadge severity={vuln.severity} />
                  <div className="min-w-0">
                    <p className="font-medium text-sm">{vuln.name}</p>
                    {vuln.location && (
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{vuln.location}</p>
                    )}
                    {vuln.description && (
                      <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">
                        {vuln.description}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 没有报告时的空状态 */}
      {!scan.llm_summary && scan.llm_risk_score === null && actualVulns.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
          <FileText className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">扫描完成后将生成 AI 分析报告</p>
        </div>
      )}
    </>
  )
}

// 生成 Markdown 报告
function generateMarkdownReport(data: any): string {
  let md = `# 漏洞扫描报告

## 扫描信息
- **目标**: ${data.scan.target}
- **扫描类型**: ${data.scan.scan_type}
- **状态**: ${data.scan.status}
- **开始时间**: ${data.scan.started_at || '-'}
- **完成时间**: ${data.scan.completed_at || '-'}
- **风险评分**: ${data.scan.risk_score ?? '-'}/100

## 漏洞统计
| 严重程度 | 数量 |
|---------|------|
| 严重 | ${data.statistics.critical} |
| 高危 | ${data.statistics.high} |
| 中危 | ${data.statistics.medium} |
| 低危 | ${data.statistics.low} |
| **总计** | **${data.statistics.total}** |

## AI 分析摘要
${data.scan.summary || '暂无分析摘要'}

## 漏洞详情
`
  data.vulnerabilities.forEach((v: any, i: number) => {
    md += `
### ${i + 1}. ${v.name}
- **严重程度**: ${v.severity}
- **类型**: ${v.category || '未分类'}
- **位置**: ${v.location || '-'}

**描述**: ${v.description || '-'}

${v.evidence ? `**证据**:\n\`\`\`\n${v.evidence}\n\`\`\`\n` : ''}
${v.analysis ? `**AI 分析**: ${v.analysis}\n` : ''}
${v.remediation ? `**修复建议**: ${v.remediation}\n` : ''}
---
`
  })

  return md
}

// 生成 CSV 报告
function generateCSVReport(data: any): string {
  const headers = ['序号', '漏洞名称', '严重程度', '类型', '位置', '描述', '修复建议']
  const rows = data.vulnerabilities.map((v: any, i: number) => [
    i + 1,
    `"${(v.name || '').replace(/"/g, '""')}"`,
    v.severity,
    v.category || '',
    `"${(v.location || '').replace(/"/g, '""')}"`,
    `"${(v.description || '').replace(/"/g, '""')}"`,
    `"${(v.remediation || '').replace(/"/g, '""')}"`,
  ])

  return [headers.join(','), ...rows.map((r: (string | number)[]) => r.join(','))].join('\n')
}

// 生成 HTML 报告
function generateHTMLReport(data: any): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>漏洞扫描报告 - ${data.scan.target}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1000px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px; }
    h1 { color: #1a1a1a; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }
    h2 { color: #374151; margin-top: 30px; }
    .stats { display: flex; gap: 20px; margin: 20px 0; }
    .stat-box { padding: 15px 25px; border-radius: 8px; text-align: center; }
    .stat-critical { background: #fef2f2; color: #dc2626; }
    .stat-high { background: #fff7ed; color: #ea580c; }
    .stat-medium { background: #fefce8; color: #ca8a04; }
    .stat-low { background: #eff6ff; color: #2563eb; }
    .stat-total { background: #f3f4f6; color: #374151; }
    .stat-box .number { font-size: 24px; font-weight: bold; }
    .stat-box .label { font-size: 12px; margin-top: 5px; }
    .vuln-card { border: 1px solid #e5e7eb; border-radius: 8px; margin: 15px 0; overflow: hidden; }
    .vuln-header { padding: 15px; background: #f9fafb; display: flex; align-items: center; gap: 10px; }
    .severity-badge { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
    .severity-critical { background: #dc2626; color: white; }
    .severity-high { background: #ea580c; color: white; }
    .severity-medium { background: #ca8a04; color: white; }
    .severity-low { background: #2563eb; color: white; }
    .vuln-body { padding: 15px; }
    .vuln-body p { margin: 10px 0; }
    .label { color: #6b7280; font-size: 12px; text-transform: uppercase; }
    pre { background: #f3f4f6; padding: 10px; border-radius: 4px; overflow-x: auto; }
    .remediation { background: #ecfdf5; border: 1px solid #a7f3d0; padding: 15px; border-radius: 8px; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ 漏洞扫描报告</h1>
    
    <h2>扫描信息</h2>
    <p><strong>目标:</strong> ${data.scan.target}</p>
    <p><strong>扫描类型:</strong> ${data.scan.scan_type}</p>
    <p><strong>风险评分:</strong> ${data.scan.risk_score ?? '-'}/100</p>
    
    <h2>漏洞统计</h2>
    <div class="stats">
      <div class="stat-box stat-total"><div class="number">${data.statistics.total}</div><div class="label">总计</div></div>
      <div class="stat-box stat-critical"><div class="number">${data.statistics.critical}</div><div class="label">严重</div></div>
      <div class="stat-box stat-high"><div class="number">${data.statistics.high}</div><div class="label">高危</div></div>
      <div class="stat-box stat-medium"><div class="number">${data.statistics.medium}</div><div class="label">中危</div></div>
      <div class="stat-box stat-low"><div class="number">${data.statistics.low}</div><div class="label">低危</div></div>
    </div>
    
    ${data.scan.summary ? `<h2>AI 分析摘要</h2><p>${data.scan.summary}</p>` : ''}
    
    <h2>漏洞详情</h2>
    ${data.vulnerabilities.map((v: any, i: number) => `
    <div class="vuln-card">
      <div class="vuln-header">
        <span class="severity-badge severity-${v.severity}">${v.severity.toUpperCase()}</span>
        <strong>${i + 1}. ${v.name}</strong>
      </div>
      <div class="vuln-body">
        <p><span class="label">位置:</span> ${v.location || '-'}</p>
        <p><span class="label">描述:</span> ${v.description || '-'}</p>
        ${v.evidence ? `<p><span class="label">证据:</span></p><pre>${v.evidence}</pre>` : ''}
        ${v.remediation ? `<div class="remediation"><strong>🔧 修复建议:</strong><p>${v.remediation}</p></div>` : ''}
      </div>
    </div>
    `).join('')}
  </div>
</body>
</html>`
}

function TabRemediation({ scanId, scan, vulns }: { scanId: string; scan: any; vulns: any }) {
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []
  const vulnsWithRemediation = actualVulns.filter((v: Vulnerability) => v.llm_remediation)

  // 分页状态
  const [currentPage, setCurrentPage] = useState(1)
  const pageSize = 5
  const totalPages = Math.ceil(vulnsWithRemediation.length / pageSize)

  // 当前页的漏洞
  const paginatedVulns = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return vulnsWithRemediation.slice(start, start + pageSize)
  }, [vulnsWithRemediation, currentPage])

  // 认证配置状态
  const [showAuthConfig, setShowAuthConfig] = useState(false)
  const [authConfig, setAuthConfig] = useState({
    host: scan?.target || '',
    username: '',
    password: '',
    port: '22',
    authType: 'password' as 'password' | 'key',
    privateKey: '',
  })

  // 自动修复对话状态
  const [showRemediationChat, setShowRemediationChat] = useState(false)
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)

  const startRemediation = (vuln: Vulnerability) => {
    setSelectedVuln(vuln)
    setShowRemediationChat(true)
  }

  return (
    <>
      {/* 认证配置模态框 */}
      {showAuthConfig && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-blue-500" />
                <h3 className="font-semibold">目标服务器认证配置</h3>
              </div>
              <button onClick={() => setShowAuthConfig(false)} className="text-gray-400 hover:text-gray-600">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">目标主机</label>
                <input
                  type="text"
                  value={authConfig.host}
                  onChange={e => setAuthConfig({ ...authConfig, host: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                  placeholder="例如: 10.0.5.11"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">用户名</label>
                  <input
                    type="text"
                    value={authConfig.username}
                    onChange={e => setAuthConfig({ ...authConfig, username: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                    placeholder="root"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">端口</label>
                  <input
                    type="text"
                    value={authConfig.port}
                    onChange={e => setAuthConfig({ ...authConfig, port: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                    placeholder="22"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">认证方式</label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={authConfig.authType === 'password'}
                      onChange={() => setAuthConfig({ ...authConfig, authType: 'password' })}
                    />
                    <span className="text-sm">密码</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={authConfig.authType === 'key'}
                      onChange={() => setAuthConfig({ ...authConfig, authType: 'key' })}
                    />
                    <span className="text-sm">私钥</span>
                  </label>
                </div>
              </div>
              {authConfig.authType === 'password' ? (
                <div>
                  <label className="block text-sm font-medium mb-1">密码</label>
                  <input
                    type="password"
                    value={authConfig.password}
                    onChange={e => setAuthConfig({ ...authConfig, password: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                    placeholder="••••••••"
                  />
                </div>
              ) : (
                <div>
                  <label className="block text-sm font-medium mb-1">私钥</label>
                  <textarea
                    value={authConfig.privateKey}
                    onChange={e => setAuthConfig({ ...authConfig, privateKey: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono text-xs"
                    rows={5}
                    placeholder="-----BEGIN RSA PRIVATE KEY-----"
                  />
                </div>
              )}
              <div className="flex justify-end gap-2 pt-4">
                <button
                  onClick={() => setShowAuthConfig(false)}
                  className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
                >
                  取消
                </button>
                <button
                  onClick={() => setShowAuthConfig(false)}
                  className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
                >
                  保存配置
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 自动修复对话框 */}
      {showRemediationChat && selectedVuln && (
        <RemediationChatDialog
          scanId={scanId}
          vuln={selectedVuln}
          authConfig={authConfig}
          onClose={() => {
            setShowRemediationChat(false)
            setSelectedVuln(null)
          }}
        />
      )}

      {/* 头部工具栏 */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 mb-6 shadow flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-green-500" />
          <h2 className="font-semibold">漏洞加固</h2>
          <span className="text-sm text-gray-500">({vulnsWithRemediation.length} 条修复建议)</span>
        </div>
        <button
          onClick={() => setShowAuthConfig(true)}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        >
          <Settings className="w-4 h-4" />
          配置目标认证
        </button>
      </div>

      {/* 修复建议列表（分页） */}
      {vulnsWithRemediation.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow mb-6">
          <div className="divide-y divide-gray-200 dark:divide-gray-700 max-h-[500px] overflow-y-auto">
            {paginatedVulns.map((vuln: Vulnerability) => (
              <div key={vuln.id} className="p-4">
                <div className="flex items-start gap-3">
                  <SeverityBadge severity={vuln.severity} />
                  <div className="flex-1">
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="font-medium text-gray-900 dark:text-white">{vuln.name}</h3>
                        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{vuln.location}</p>
                      </div>
                      <button
                        onClick={() => startRemediation(vuln)}
                        className="flex items-center gap-1 px-3 py-1.5 bg-green-500 text-white text-sm rounded-lg hover:bg-green-600 transition-colors"
                      >
                        <Wrench className="w-4 h-4" />
                        自动修复
                      </button>
                    </div>
                    <div className="mt-3 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
                      <div className="flex items-center gap-1 text-green-600 dark:text-green-400 mb-1 text-sm font-medium">
                        <ShieldCheck className="w-4 h-4" />
                        修复建议
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300">{vuln.llm_remediation}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* 分页控件 */}
          {totalPages > 1 && (
            <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <p className="text-sm text-gray-500">
                显示 {(currentPage - 1) * pageSize + 1}-{Math.min(currentPage * pageSize, vulnsWithRemediation.length)} / {vulnsWithRemediation.length}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <span className="text-sm">{currentPage} / {totalPages}</span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 没有修复建议时的空状态 */}
      {vulnsWithRemediation.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow mb-6">
          <ShieldCheck className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">
            {scan.status === 'COMPLETED' ? '暂无修复建议' : '扫描完成后将生成修复建议'}
          </p>
        </div>
      )}

      {/* Post-Scan Chat - 扫描完成后的对话分析 */}
      {(scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'CANCELLED') && (
        <ScanChatPanel scanId={scanId} />
      )}
    </>
  )
}

// 自动修复对话组件
function RemediationChatDialog({
  scanId,
  vuln,
  authConfig,
  onClose,
}: {
  scanId: string
  vuln: Vulnerability
  authConfig: any
  onClose: () => void
}) {
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string }>>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // 初始化修复对话
  useEffect(() => {
    const initMessage = `我需要帮助修复以下漏洞：

**漏洞名称**: ${vuln.name}
**严重程度**: ${vuln.severity}
**位置**: ${vuln.location || '未知'}
**描述**: ${vuln.description || vuln.llm_analysis || '无描述'}

**建议的修复方案**: ${vuln.llm_remediation || '暂无建议'}

目标服务器信息:
- 主机: ${authConfig.host || '未配置'}
- 用户: ${authConfig.username || '未配置'}
- 端口: ${authConfig.port || '22'}

请帮我分析这个漏洞，并提供具体的修复步骤。如果需要执行命令，请先告诉我要执行的命令，我确认后再执行。`

    setMessages([
      { role: 'user', content: initMessage },
      {
        role: 'assistant', content: `正在分析漏洞 "${vuln.name}"...

根据漏洞信息，以下是修复建议：

${vuln.llm_remediation || '暂无自动生成的修复建议，我会根据漏洞特征提供修复方案。'}

**修复步骤**:
1. 首先，建议备份相关配置文件
2. ${vuln.severity === 'critical' || vuln.severity === 'high' ? '由于这是高危漏洞，建议立即进行修复' : '可以按计划安排修复时间'}
3. 修复后需要验证漏洞是否已被修复

请问您想要：
- 查看详细的修复命令
- 让我帮您生成修复脚本
- 直接执行修复操作（需要确认服务器认证）

请告诉我您的选择，或者询问任何其他问题。` },
    ])
  }, [vuln, authConfig])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return

    const userMessage = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: userMessage }])
    setIsLoading(true)

    try {
      // 调用后端 API 进行对话
      const response = await sendScanChatMessage(scanId, userMessage)
      setMessages(prev => [...prev, { role: 'assistant', content: response.content }])
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: '抱歉，处理您的请求时出现错误。请稍后重试。',
      }])
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] flex flex-col">
        {/* 头部 */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-green-500" />
            <h3 className="font-semibold">AI 修复助手</h3>
            <SeverityBadge severity={vuln.severity} />
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        {/* 消息列表 */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-lg px-4 py-2 ${msg.role === 'user'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white'
                  }`}
              >
                <p className="whitespace-pre-wrap text-sm">{msg.content}</p>
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2">
                <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* 输入框 */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && sendMessage()}
              placeholder="输入消息，或询问修复相关问题..."
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
              disabled={isLoading}
            />
            <button
              onClick={sendMessage}
              disabled={isLoading || !input.trim()}
              className="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    PENDING: 'bg-yellow-500',
    RUNNING: 'bg-blue-500',
    PAUSED: 'bg-orange-500',
    COMPLETED: 'bg-green-500',
    FAILED: 'bg-red-500',
    CANCELLED: 'bg-gray-500',
  }

  return (
    <span className={`px-2 py-1 text-xs rounded text-white ${colors[status] || 'bg-gray-500'}`}>
      {statusLabels[status] || status}
    </span>
  )
}

function StatBox({ label, value, color = '' }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 text-center shadow">
      <p className={`text-3xl font-bold ${color || 'text-gray-900 dark:text-white'}`}>{value}</p>
      <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
    </div>
  )
}

function PortCard({ port }: { port: Vulnerability }) {
  // Parse port info from name like "Open port: ssh" and location like "10.0.5.1:22/tcp"
  const serviceName = port.name.replace('Open port: ', '')
  const locationMatch = port.location?.match(/:(\d+)\/(\w+)/)
  const portNum = locationMatch ? locationMatch[1] : ''
  const protocol = locationMatch ? locationMatch[2].toUpperCase() : ''

  return (
    <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600">
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono font-bold text-blue-600 dark:text-blue-400">{portNum}</span>
        <span className="text-xs px-1.5 py-0.5 bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 rounded">
          {protocol}
        </span>
      </div>
      <div className="text-sm font-medium text-gray-700 dark:text-gray-300">{serviceName}</div>
      {port.description && (
        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate" title={port.description}>
          {port.description}
        </div>
      )}
    </div>
  )
}

function VulnRow({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750">
      <div className="flex items-start gap-3">
        <SeverityBadge severity={vuln.severity} />
        <div className="flex-1">
          <h3 className="font-medium">{vuln.name}</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{vuln.location}</p>
          {vuln.description && (
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-2">{vuln.description}</p>
          )}
          {vuln.llm_analysis && (
            <div className="mt-3 p-3 bg-gray-100 dark:bg-gray-700 rounded text-sm">
              <div className="flex items-center gap-1 text-purple-600 dark:text-purple-400 mb-1">
                <Brain className="w-4 h-4" />
                AI 分析
              </div>
              <p className="text-gray-600 dark:text-gray-300">{vuln.llm_analysis}</p>
            </div>
          )}
          {vuln.llm_remediation && (
            <div className="mt-2 text-sm">
              <span className="text-green-600 dark:text-green-400">修复建议: </span>
              <span className="text-gray-600 dark:text-gray-300">{vuln.llm_remediation}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ProgressStep({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <div className={`flex-1 text-center py-2 px-3 rounded ${done ? 'bg-green-100 dark:bg-green-900/50 text-green-600 dark:text-green-400' :
      active ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400' :
        'bg-gray-200 dark:bg-gray-700 text-gray-500'
      }`}>
      {done ? '✓ ' : active ? '● ' : '○ '}{label}
    </div>
  )
}

function LogEntry({ log }: { log: ScanLogEntry }) {
  const [expanded, setExpanded] = useState(false)

  const typeConfig: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
    info: {
      icon: <Info className="w-4 h-4" />,
      color: 'text-blue-600 dark:text-blue-400',
      bg: 'bg-blue-50 dark:bg-blue-900/20'
    },
    tool: {
      icon: <Wrench className="w-4 h-4" />,
      color: 'text-cyan-600 dark:text-cyan-400',
      bg: 'bg-cyan-50 dark:bg-cyan-900/20'
    },
    output: {
      icon: <Terminal className="w-4 h-4" />,
      color: 'text-gray-600 dark:text-gray-400',
      bg: 'bg-gray-100 dark:bg-gray-800'
    },
    llm: {
      icon: <Bot className="w-4 h-4" />,
      color: 'text-purple-600 dark:text-purple-400',
      bg: 'bg-purple-50 dark:bg-purple-900/20'
    },
    error: {
      icon: <AlertCircle className="w-4 h-4" />,
      color: 'text-red-600 dark:text-red-400',
      bg: 'bg-red-50 dark:bg-red-900/20'
    },
    success: {
      icon: <CheckCircle2 className="w-4 h-4" />,
      color: 'text-green-600 dark:text-green-400',
      bg: 'bg-green-50 dark:bg-green-900/20'
    },
  }

  const config = typeConfig[log.type] || typeConfig.info
  const time = new Date(log.timestamp).toLocaleTimeString('zh-CN', { hour12: false })
  const hasDetails = log.details && log.details.length > 0
  const agentLabel = log.agent || inferAgentFromLog(log)

  return (
    <div className={`rounded px-3 py-2 ${config.bg}`}>
      <div
        className={`flex items-start gap-2 ${hasDetails ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetails && setExpanded(!expanded)}
      >
        <span className={`mt-0.5 ${config.color}`}>{config.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-gray-500 text-xs">{time}</span>
            <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${agentLabel === '主 Agent'
              ? 'bg-purple-600 text-white'
              : 'bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300'
              }`}>
              {agentLabel}
            </span>
            {log.tool && (
              <span className="text-xs px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-300">
                {log.tool}
              </span>
            )}
          </div>
          <p className={`${config.color} break-words`}>{log.message}</p>
        </div>
        {hasDetails && (
          <span className="text-gray-500 mt-1">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </span>
        )}
      </div>

      {expanded && log.details && (
        <div className="mt-2 ml-6 p-2 bg-white dark:bg-gray-800 rounded text-gray-600 dark:text-gray-300 text-xs whitespace-pre-wrap overflow-x-auto">
          {log.details}
        </div>
      )}
    </div>
  )
}

function inferAgentFromLog(log: ScanLogEntry): string {
  const tool = log.tool?.toLowerCase()
  const message = log.message.toLowerCase()
  if (message.includes('主 agent')) return '主 Agent'
  if (tool === 'nmap' || message.includes('nmap')) return 'Recon SubAgent'
  if (tool === 'nuclei' || message.includes('nuclei')) return 'Vulnerability SubAgent'
  if (log.type === 'llm' || message.includes('ai agent') || message.includes('迭代') || message.includes('分析')) return 'AI Validation SubAgent'
  if (message.includes('报告') || message.includes('风险评分') || message.includes('攻击路径')) return 'Reporting SubAgent'
  return '主 Agent'
}

function AgentQuestionPanel({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient()
  const [reply, setReply] = useState('')

  const { data: messagesData, isLoading } = useQuery({
    queryKey: ['scan-messages', scanId],
    queryFn: () => getScanMessages(scanId),
    refetchInterval: 2000,
  })

  const sendMutation = useMutation({
    mutationFn: (content: string) => sendScanMessage(scanId, content),
    onSuccess: () => {
      setReply('')
      queryClient.invalidateQueries({ queryKey: ['scan-messages', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (reply.trim()) {
      sendMutation.mutate(reply.trim())
    }
  }

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
        <div className="flex items-center gap-2 text-gray-500">
          <Loader2 className="w-5 h-5 animate-spin" />
          加载中...
        </div>
      </div>
    )
  }

  return (
    <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-6 mb-6">
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center justify-center w-10 h-10 rounded-full bg-orange-100 dark:bg-orange-800">
          <Pause className="w-5 h-5 text-orange-600 dark:text-orange-400" />
        </div>
        <div>
          <h2 className="font-semibold text-orange-700 dark:text-orange-300">AI Agent 等待您的回复</h2>
          <p className="text-sm text-orange-600 dark:text-orange-400">请回答以下问题以继续扫描</p>
        </div>
      </div>

      {/* Message History */}
      {messagesData && messagesData.messages.length > 0 && (
        <div className="space-y-3 mb-4 max-h-64 overflow-y-auto">
          {messagesData.messages.map((msg) => (
            <div
              key={msg.id}
              className={`p-3 rounded-lg ${msg.role === 'agent'
                ? 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700'
                : 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 ml-8'
                }`}
            >
              <div className="flex items-center gap-2 mb-1">
                {msg.role === 'agent' ? (
                  <Bot className="w-4 h-4 text-purple-500" />
                ) : (
                  <MessageCircle className="w-4 h-4 text-blue-500" />
                )}
                <span className="text-xs font-medium text-gray-500">
                  {msg.role === 'agent' ? 'AI Agent' : '您'}
                </span>
                <span className="text-xs text-gray-400">
                  {format(new Date(msg.created_at), 'HH:mm:ss')}
                </span>
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                {msg.content}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Reply Input */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={reply}
          onChange={(e) => setReply(e.target.value)}
          placeholder="输入您的回复..."
          disabled={sendMutation.isPending}
          className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-orange-500 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={!reply.trim() || sendMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Send className="w-4 h-4" />
          {sendMutation.isPending ? '发送中...' : '发送'}
        </button>
      </form>

      {sendMutation.isError && (
        <p className="mt-2 text-sm text-red-500">
          发送失败，请重试
        </p>
      )}
    </div>
  )
}


// ============ Post-Scan Chat Panel ============

function ScanChatPanel({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient()
  const [message, setMessage] = useState('')
  const [isExpanded, setIsExpanded] = useState(true)
  const chatEndRef = useRef<HTMLDivElement>(null)

  const { data: chatData, isLoading } = useQuery({
    queryKey: ['scan-chat', scanId],
    queryFn: () => getScanChatHistory(scanId),
  })

  const sendMutation = useMutation({
    mutationFn: (content: string) => sendScanChatMessage(scanId, content),
    onSuccess: () => {
      setMessage('')
      queryClient.invalidateQueries({ queryKey: ['scan-chat', scanId] })
    },
  })

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current && chatData?.messages.length) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [chatData?.messages])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (message.trim() && !sendMutation.isPending) {
      sendMutation.mutate(message.trim())
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg mt-6 shadow overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-4 py-3 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-purple-500" />
          <h2 className="font-semibold">继续分析</h2>
          <span className="text-xs text-gray-500">
            ({chatData?.messages.length || 0} 条对话)
          </span>
        </div>
        {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
      </button>

      {isExpanded && (
        <div className="p-4">
          {/* Description */}
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            扫描已完成，您可以继续向 AI 提问，对扫描结果进行更深入的分析。例如询问某个漏洞的详细信息、修复建议或攻击场景分析。
          </p>

          {/* Chat History */}
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-gray-500">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              加载中...
            </div>
          ) : chatData?.messages.length ? (
            <div className="space-y-4 mb-4 max-h-96 overflow-y-auto">
              {chatData.messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${msg.role === 'user'
                    ? 'bg-blue-100 dark:bg-blue-900'
                    : 'bg-purple-100 dark:bg-purple-900'
                    }`}>
                    {msg.role === 'user' ? (
                      <MessageCircle className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    ) : (
                      <Brain className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                    )}
                  </div>
                  <div className={`max-w-[80%] p-3 rounded-lg ${msg.role === 'user'
                    ? 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800'
                    : 'bg-gray-100 dark:bg-gray-700'
                    }`}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-medium text-gray-500">
                        {msg.role === 'user' ? '您' : 'AI 分析师'}
                      </span>
                      <span className="text-xs text-gray-400">
                        {format(new Date(msg.created_at), 'HH:mm:ss')}
                      </span>
                    </div>
                    <div className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {msg.content}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
          ) : (
            <div className="text-center py-6 text-gray-500 dark:text-gray-400">
              <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>开始提问，深入分析扫描结果</p>
            </div>
          )}

          {/* Input Form */}
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="例如：这个SQL注入漏洞如何利用？该如何修复？"
              disabled={sendMutation.isPending}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!message.trim() || sendMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {sendMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              {sendMutation.isPending ? '分析中...' : '发送'}
            </button>
          </form>

          {sendMutation.isError && (
            <p className="mt-2 text-sm text-red-500">
              发送失败，请重试
            </p>
          )}

          {/* Example Questions */}
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="text-xs text-gray-500">快捷问题：</span>
            {[
              '总结主要安全风险',
              '最严重的漏洞是什么',
              '如何优先修复这些漏洞',
              '这些漏洞是否可被远程利用'
            ].map((q) => (
              <button
                key={q}
                onClick={() => setMessage(q)}
                disabled={sendMutation.isPending}
                className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded text-gray-600 dark:text-gray-300 disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
