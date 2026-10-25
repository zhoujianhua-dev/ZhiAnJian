import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload, Search, FileCode, Settings,
  Trash2, Eye, EyeOff, X, Check,
  Code, List, Zap, File as FileIcon, ChevronDown, ChevronLeft, ChevronRight, ChevronUp,
  Shield, AlertTriangle
} from 'lucide-react'
import {
  getTools, uploadTool, deleteTool, updateTool, getToolContent, SecurityTool,
  getNucleiTemplates, getNucleiTemplateStats, getNucleiTemplateContent,
  NucleiTemplate, getKaliScanners, KaliScannerCategory,
} from '../lib/api'

const toolTypeIcons: Record<string, React.ReactNode> = {
  script: <FileCode className="w-5 h-5" />,
  nuclei: <Code className="w-5 h-5" />,
  wordlist: <List className="w-5 h-5" />,
  config: <Settings className="w-5 h-5" />,
  skill: <Zap className="w-5 h-5" />,
  scanner: <Search className="w-5 h-5" />,
}

const toolTypeLabels: Record<string, string> = {
  script: '脚本',
  nuclei: 'Nuclei 模板',
  wordlist: '字典',
  config: '配置文件',
  skill: 'AI Skill',
  scanner: '扫描器',
}

export default function Knowledgebase() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(12)
  const [showUpload, setShowUpload] = useState(false)
  const [filterType, setFilterType] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null)
  const [showContent, setShowContent] = useState(false)
  const [nucleiSeverity, setNucleiSeverity] = useState<string>('')
  const [selectedTemplate, setSelectedTemplate] = useState<NucleiTemplate | null>(null)
  const [showTemplateContent, setShowTemplateContent] = useState(false)

  const isNucleiMode = filterType === 'nuclei'

  // 普通工具查询（非 Nuclei 模式时启用）
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['tools', filterType, page, pageSize],
    queryFn: () => getTools({
      skip: (page - 1) * pageSize,
      limit: pageSize,
      tool_type: filterType || undefined,
      enabled_only: false
    }),
    enabled: !isNucleiMode,
  })

  // Nuclei 模板查询（从 Kali 容器获取）
  const nucleiQuery = useQuery({
    queryKey: ['nuclei-templates', page, pageSize, searchQuery, nucleiSeverity],
    queryFn: () => getNucleiTemplates({
      skip: (page - 1) * pageSize,
      limit: pageSize,
      search: searchQuery || undefined,
      severity: nucleiSeverity || undefined,
    }),
    enabled: isNucleiMode,
  })

  // Nuclei 模板统计
  const nucleiStatsQuery = useQuery({
    queryKey: ['nuclei-templates-stats'],
    queryFn: getNucleiTemplateStats,
    enabled: isNucleiMode,
  })

  const toolsErrorMessage = isError
    // @ts-expect-error axios error response
    ? (error?.response?.data?.detail || (error as Error).message)
    : null

  const nucleiErrorMessage = nucleiQuery.isError
    // @ts-expect-error axios error response
    ? (nucleiQuery.error?.response?.data?.detail || (nucleiQuery.error as Error).message)
    : null

  // Kali 预置扫描器查询（始终加载，用于统计计数）
  const kaliScannersQuery = useQuery({
    queryKey: ['kali-scanners'],
    queryFn: getKaliScanners,
    staleTime: 5 * 60 * 1000,
  })
  const kaliScannerTotal = kaliScannersQuery.data?.total ?? 0
  const isScannerMode = filterType === 'scanner'

  const deleteMutation = useMutation({
    mutationFn: deleteTool,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      setSelectedTool(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateTool(id, { is_enabled: enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
    },
  })

  const tools = data?.items || []
  const totalItems = data?.total || 0
  const totalPages = Math.ceil(totalItems / pageSize)

  // 客户端搜索过滤（在当前页内）
  const filteredTools = tools.filter(t =>
    searchQuery === '' ||
    t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.description?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize)
    setPage(1)
  }

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">知识库</h1>
          <p className="text-gray-500 dark:text-gray-400 text-sm">管理安全工具、脚本、模板和扫描器</p>
        </div>
        <button
          onClick={() => setShowUpload(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2"
        >
          <Upload className="w-4 h-4" />
          上传工具
        </button>
      </div>

      {/* Stats */}
      {isNucleiMode ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
          <StatCard label="模板总数" value={nucleiStatsQuery.data?.total ?? nucleiQuery.data?.total ?? 0} />
          <StatCard label="严重" value={nucleiStatsQuery.data?.severities?.critical ?? 0} />
          <StatCard label="高危" value={nucleiStatsQuery.data?.severities?.high ?? 0} />
          <StatCard label="中危" value={nucleiStatsQuery.data?.severities?.medium ?? 0} />
          <StatCard label="低危" value={nucleiStatsQuery.data?.severities?.low ?? 0} />
          <StatCard label="信息" value={nucleiStatsQuery.data?.severities?.info ?? 0} />
        </div>
      ) : (
        <div className="grid grid-cols-6 gap-4 mb-6">
          <StatCard label="总工具数" value={totalItems} />
          <StatCard label="脚本" value={tools.filter(t => t.tool_type === 'script').length} />
          <StatCard label="Nuclei 模板" value={tools.filter(t => t.tool_type === 'nuclei').length} />
          <StatCard label="字典" value={tools.filter(t => t.tool_type === 'wordlist').length} />
          <StatCard label="配置" value={tools.filter(t => t.tool_type === 'config').length} />
          <StatCard label="扫描器" value={tools.filter(t => t.tool_type === 'scanner').length + kaliScannerTotal} />
        </div>
      )}

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 mb-6 shadow">
        <div className="flex gap-4 items-center flex-wrap">
          <div className="flex-1 relative min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder={isNucleiMode ? "搜索模板名称/ID/标签..." : "搜索工具..."}
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => { setFilterType(''); setPage(1); setSearchQuery(''); setNucleiSeverity(''); }}
              className={`px-3 py-2 rounded-lg text-sm ${filterType === '' ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600'}`}
            >
              全部
            </button>
            {Object.entries(toolTypeLabels).map(([type, label]) => (
              <button
                key={type}
                onClick={() => { setFilterType(type); setPage(1); setSearchQuery(''); setNucleiSeverity(''); }}
                className={`px-3 py-2 rounded-lg text-sm flex items-center gap-1 ${filterType === type ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600'}`}
              >
                {toolTypeIcons[type]}
                {label}
              </button>
            ))}
          </div>

          {/* Nuclei 严重级别过滤器 */}
          {isNucleiMode && (
            <div className="flex gap-2 w-full">
              {['', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <button
                  key={sev}
                  onClick={() => { setNucleiSeverity(sev); setPage(1); }}
                  className={`px-2 py-1 rounded text-xs font-medium ${nucleiSeverity === sev
                    ? sev === 'critical' ? 'bg-red-600 text-white'
                      : sev === 'high' ? 'bg-orange-500 text-white'
                        : sev === 'medium' ? 'bg-yellow-500 text-white'
                          : sev === 'low' ? 'bg-blue-500 text-white'
                            : sev === 'info' ? 'bg-gray-500 text-white'
                              : 'bg-blue-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600'
                    }`}
                >
                  {sev === '' ? '全部级别' : sev === 'critical' ? '严重' : sev === 'high' ? '高危' : sev === 'medium' ? '中危' : sev === 'low' ? '低危' : '信息'}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Nuclei 模板列表 */}
      {isNucleiMode ? (
        nucleiQuery.isLoading ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-2"></div>
            正在从 Kali 扫描器加载模板...
          </div>
        ) : nucleiQuery.isError ? (
          <div className="text-center py-12 text-red-500">
            <AlertTriangle className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p>加载 Nuclei 模板失败</p>
            <p className="text-sm mt-1">{nucleiErrorMessage}</p>
            <p className="text-xs mt-2 text-gray-500">请确认 Kali 扫描器容器已启动且 nuclei 模板已下载</p>
          </div>
        ) : (nucleiQuery.data?.items.length ?? 0) === 0 ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            <FileIcon className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p>未找到匹配的模板</p>
            <p className="text-sm">尝试调整搜索条件或严重级别过滤</p>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
              {nucleiQuery.data!.items.map(template => (
                <NucleiTemplateCard
                  key={template.id}
                  template={template}
                  onView={() => { setSelectedTemplate(template); setShowTemplateContent(true); }}
                />
              ))}
            </div>

            {/* Pagination Controls */}
            {(() => {
              const nucleiTotal = nucleiQuery.data?.total ?? 0
              const nucleiTotalPages = Math.ceil(nucleiTotal / pageSize)
              return (
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                  <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      共 {nucleiTotal} 个模板，第 {page} / {nucleiTotalPages || 1} 页
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <label className="text-sm text-gray-600 dark:text-gray-400">每页显示:</label>
                        <select
                          value={pageSize}
                          onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
                          className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                          <option value={12}>12 个</option>
                          <option value={24}>24 个</option>
                          <option value={48}>48 个</option>
                          <option value={100}>100 个</option>
                        </select>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setPage(p => Math.max(1, p - 1))}
                          disabled={page <= 1}
                          className="px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                          <ChevronLeft className="w-4 h-4" />
                        </button>
                        <span className="px-3 py-1.5 text-sm">{page} / {nucleiTotalPages || 1}</span>
                        <button
                          onClick={() => setPage(p => Math.min(nucleiTotalPages, p + 1))}
                          disabled={page >= nucleiTotalPages}
                          className="px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100 dark:hover:bg-gray-700"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })()}
          </>
        )
      ) : (
        /* 普通工具列表 + Kali 扫描器 */
        isLoading ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">加载中...</div>
        ) : isError ? (
          <div className="text-center py-12 text-red-500">
            加载失败: {toolsErrorMessage}
          </div>
        ) : (
          <>
            {/* Kali 预置扫描器区域 - 仅在扫描器标签页显示 */}
            {isScannerMode && (
              <div className="mb-8">
                {kaliScannersQuery.isLoading ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow mb-6">
                    <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-2"></div>
                    <p className="text-gray-500 dark:text-gray-400 text-sm">正在加载系统内置扫描器...</p>
                  </div>
                ) : kaliScannersQuery.isError ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-6 text-center shadow mb-6">
                    <AlertTriangle className="w-10 h-10 mx-auto mb-2 text-yellow-500" />
                    <p className="text-sm text-gray-500 dark:text-gray-400">无法加载系统内置扫描器列表</p>
                    <p className="text-xs text-gray-400 mt-1">请确认后端服务正常运行</p>
                  </div>
                ) : kaliScannersQuery.data ? (
                  <KaliScannersView categories={kaliScannersQuery.data.categories} searchQuery={searchQuery} />
                ) : null}
              </div>
            )}

            {/* 用户上传的工具 */}
            {filteredTools.length === 0 && !isScannerMode ? (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <FileIcon className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>暂无工具</p>
                <p className="text-sm">点击"上传工具"添加您的安全工具</p>
              </div>
            ) : filteredTools.length > 0 ? (
              <>
                {!isScannerMode && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                    {filteredTools.map(tool => (
                      <ToolCard
                        key={tool.id}
                        tool={tool}
                        onView={() => { setSelectedTool(tool); setShowContent(true); }}
                        onToggle={(enabled) => toggleMutation.mutate({ id: tool.id, enabled })}
                        onDelete={() => deleteMutation.mutate(tool.id)}
                      />
                    ))}
                  </div>
                )}
                {isScannerMode && filteredTools.length > 0 && (
                  <>
                    <h3 className="text-sm font-semibold text-gray-500 dark:text-gray-400 mb-3 flex items-center gap-2">
                      <Upload className="w-4 h-4" />
                      已上传的扫描器 ({filteredTools.length})
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                      {filteredTools.map(tool => (
                        <ToolCard
                          key={tool.id}
                          tool={tool}
                          onView={() => { setSelectedTool(tool); setShowContent(true); }}
                          onToggle={(enabled) => toggleMutation.mutate({ id: tool.id, enabled })}
                          onDelete={() => deleteMutation.mutate(tool.id)}
                        />
                      ))}
                    </div>
                  </>
                )}
                {/* 分页 */}
                {totalPages > 1 && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        共 {totalItems} 个工具，第 {page} / {totalPages || 1} 页
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                          <label className="text-sm text-gray-600 dark:text-gray-400">每页显示:</label>
                          <select
                            value={pageSize}
                            onChange={(e) => { handlePageSizeChange(Number(e.target.value)); }}
                            className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                          >
                            <option value={6}>6 个</option>
                            <option value={12}>12 个</option>
                            <option value={24}>24 个</option>
                            <option value={48}>48 个</option>
                          </select>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setPage((p) => Math.max(1, p - 1))}
                            disabled={page <= 1}
                            className="px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                          >
                            <ChevronLeft className="w-4 h-4" />
                          </button>
                          <span className="px-3 py-1.5 text-sm">
                            {page} / {totalPages || 1}
                          </span>
                          <button
                            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                            disabled={page >= totalPages}
                            className="px-3 py-1.5 text-sm rounded-lg border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                          >
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <FileIcon className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>暂无工具</p>
                <p className="text-sm">点击"上传工具"添加您的安全工具</p>
              </div>
            )}
          </>
        )
      )}

      {/* Upload Modal */}
      {showUpload && (
        <UploadModal onClose={() => setShowUpload(false)} />
      )}

      {/* Content Modal */}
      {showContent && selectedTool && (
        <ContentModal tool={selectedTool} onClose={() => setShowContent(false)} />
      )}

      {/* Nuclei Template Content Modal */}
      {showTemplateContent && selectedTemplate && (
        <NucleiTemplateContentModal
          template={selectedTemplate}
          onClose={() => { setShowTemplateContent(false); setSelectedTemplate(null); }}
        />
      )}
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 text-center shadow">
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
    </div>
  )
}

function ToolCard({
  tool,
  onView,
  onToggle,
  onDelete
}: {
  tool: SecurityTool
  onView: () => void
  onToggle: (enabled: boolean) => void
  onDelete: () => void
}) {
  const [showActions, setShowActions] = useState(false)

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg p-4 shadow ${!tool.is_enabled ? 'opacity-60' : ''}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-blue-600 dark:text-blue-400">{toolTypeIcons[tool.tool_type]}</span>
          <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
            {toolTypeLabels[tool.tool_type]}
          </span>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowActions(!showActions)}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
          {showActions && (
            <div className="absolute right-0 top-8 bg-white dark:bg-gray-700 rounded-lg shadow-lg py-1 z-10 min-w-32 border border-gray-200 dark:border-gray-600">
              <button
                onClick={() => { onView(); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2"
              >
                <Eye className="w-4 h-4" /> 查看内容
              </button>
              <button
                onClick={() => { onToggle(!tool.is_enabled); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2"
              >
                {tool.is_enabled ? <EyeOff className="w-4 h-4" /> : <Check className="w-4 h-4" />}
                {tool.is_enabled ? '禁用' : '启用'}
              </button>
              <button
                onClick={() => { onDelete(); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2 text-red-500"
              >
                <Trash2 className="w-4 h-4" /> 删除
              </button>
            </div>
          )}
        </div>
      </div>

      <h3 className="font-semibold mb-1 flex items-center gap-2 flex-wrap">
        {tool.name}
        {tool.tags && tool.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {tool.tags.slice(0, 3).map(tag => (
              <span key={tag} className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded-full">
                {tag}
              </span>
            ))}
            {tool.tags.length > 3 && (
              <span className="text-xs text-gray-500">+{tool.tags.length - 3}</span>
            )}
          </div>
        )}
      </h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
        {tool.description || '暂无描述'}
      </p>

      <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
        <span>{tool.filename}</span>
        <span>•</span>
        <span>{formatFileSize(tool.file_size)}</span>
      </div>
    </div>
  )
}

// Kali 扫描器类别颜色映射
const kaliCategoryStyles: Record<string, { color: string; bg: string; border: string }> = {
  network: { color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/30', border: 'border-blue-200 dark:border-blue-800' },
  vuln: { color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-900/30', border: 'border-orange-200 dark:border-orange-800' },
  web: { color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-900/30', border: 'border-purple-200 dark:border-purple-800' },
  cred: { color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/30', border: 'border-red-200 dark:border-red-800' },
  post_exploit: { color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/30', border: 'border-yellow-200 dark:border-yellow-800' },
}

function KaliScannersView({ categories, searchQuery }: { categories: KaliScannerCategory[]; searchQuery: string }) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())

  // 过滤类别和工具
  const filteredCategories = categories
    .map(cat => ({
      ...cat,
      tools: cat.tools.filter(t =>
        searchQuery === '' ||
        t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.type.toLowerCase().includes(searchQuery.toLowerCase())
      ),
    }))
    .filter(cat => cat.tools.length > 0)

  const totalTools = filteredCategories.reduce((sum, cat) => sum + cat.tools.length, 0)

  return (
    <div className="space-y-4">
      <div className="bg-gradient-to-r from-cyan-50 to-blue-50 dark:from-cyan-950/30 dark:to-blue-950/30 rounded-lg p-4 border border-cyan-200 dark:border-cyan-800">
        <div className="flex items-center gap-2 mb-1">
          <Shield className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
          <h3 className="font-semibold text-cyan-900 dark:text-cyan-100">系统内置的扫描器</h3>
        </div>
        <p className="text-sm text-cyan-700 dark:text-cyan-300">
          已注册 {totalTools} 个扫描器，分为 {filteredCategories.length} 个类别。
          扫描器运行在 Kali 容器中，由主 Agent 编排使用。
        </p>
      </div>

      {filteredCategories.map(cat => {
        const style = kaliCategoryStyles[cat.key] || kaliCategoryStyles.network
        const isExpanded = expandedCategories.has(cat.key)
        return (
          <div key={cat.key} className={`rounded-lg border ${style.border} ${style.bg} overflow-hidden`}>
            <button
              onClick={() => setExpandedCategories(prev => {
                const s = new Set(prev)
                if (s.has(cat.key)) s.delete(cat.key)
                else s.add(cat.key)
                return s
              })}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-white/50 dark:hover:bg-gray-800/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className={`font-semibold ${style.color}`}>{cat.name}</div>
                <span className="text-xs text-gray-500 dark:text-gray-400">{cat.tools.length} 个工具</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">{cat.description}</span>
                {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
              </div>
            </button>
            {isExpanded && (
              <div className="px-4 pb-3 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                {cat.tools.map(tool => (
                  <div key={tool.type} className="bg-white dark:bg-gray-800 rounded-lg px-3 py-2 flex items-center gap-2 shadow-sm">
                    <Search className={`w-4 h-4 ${style.color}`} />
                    <div className="min-w-0">
                      <div className="font-medium text-sm truncate">{tool.name}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{tool.type}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}

      {filteredCategories.length === 0 && (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          <Search className="w-10 h-10 mx-auto mb-2 opacity-40" />
          <p>未找到匹配的扫描器</p>
        </div>
      )}
    </div>
  )
}

function UploadModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    tool_type: 'script',
    description: '',
    category: '',
    tags: '',
    usage_instructions: '',
    author: '',
    version: '',
  })

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('请选择文件')
      const data = new FormData()
      data.append('file', file)
      Object.entries(formData).forEach(([key, value]) => {
        if (value) data.append(key, value)
      })
      return uploadTool(data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      onClose()
    },
  })

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      if (!formData.name) {
        setFormData(prev => ({ ...prev, name: f.name.replace(/\.[^/.]+$/, '') }))
      }
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold">上传安全工具</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); uploadMutation.mutate(); }} className="p-4 space-y-4">
          {/* File Upload */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">文件 *</label>
            <div className="relative border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-4 text-center cursor-pointer hover:border-gray-400 dark:hover:border-gray-500 transition-colors">
              {file ? (
                <div className="flex items-center justify-center gap-2">
                  <FileIcon className="w-5 h-5 text-blue-500" />
                  <span>{file.name}</span>
                  <span className="text-gray-500">({formatFileSize(file.size)})</span>
                </div>
              ) : (
                <div>
                  <Upload className="w-8 h-8 mx-auto mb-2 text-gray-400" />
                  <p className="text-sm text-gray-500 dark:text-gray-400">点击或拖拽文件到此处</p>
                </div>
              )}
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                accept=".py,.sh,.bash,.pl,.rb,.js,.ts,.go,.rs,.ps1,.yaml,.yml,.txt,.lst,.dic,.list,.json,.toml,.ini,.conf,.cfg,.xml,.md,.zip,.tar,.tgz,.tar.gz,.tar.bz2,.7z,.rar,.exe,.dll,.so,.dylib,.bin,.jar,.class,.wasm,.db,.sqlite,.sqlite3,.dat,.csv"
              />
            </div>
          </div>

          {/* Tool Type */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">工具类型 *</label>
            <select
              value={formData.tool_type}
              onChange={(e) => setFormData(prev => ({ ...prev, tool_type: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="script">脚本 (Python/Bash)</option>
              <option value="nuclei">Nuclei 模板</option>
              <option value="wordlist">字典文件</option>
              <option value="config">配置文件</option>
              <option value="skill">AI Skill</option>
              <option value="scanner">扫描器</option>
            </select>
            {formData.tool_type === 'skill' && (
              <div className="mt-2 p-3 bg-blue-50 dark:bg-blue-900/30 rounded-lg text-sm">
                <p className="text-blue-700 dark:text-blue-300 font-medium mb-1">
                  💡 AI Skill 说明
                </p>
                <p className="text-blue-600 dark:text-blue-400 text-xs">
                  支持腾讯 SkillHub 压缩包 (.zip) 或其他 Markdown (.md)、Python (.py) 文件。AI 可自主决定何时调用这些技能。
                </p>
              </div>
            )}
          </div>

          {/* Name */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">名称 *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="工具名称"
              required
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">描述</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
              placeholder="工具描述..."
            />
          </div>

          {/* Category */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">分类</label>
            <select
              value={formData.category}
              onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">选择分类</option>
              <option value="reconnaissance">侦察 (Reconnaissance)</option>
              <option value="vulnerability">漏洞扫描 (Vulnerability)</option>
              <option value="exploitation">利用 (Exploitation)</option>
              <option value="post_exploitation">后渗透 (Post-Exploitation)</option>
              <option value="utility">实用工具 (Utility)</option>
            </select>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">标签 (逗号分隔)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData(prev => ({ ...prev, tags: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="web, sql, xss"
            />
          </div>

          {/* Usage Instructions */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">使用说明</label>
            <textarea
              value={formData.usage_instructions}
              onChange={(e) => setFormData(prev => ({ ...prev, usage_instructions: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
              placeholder="如何使用这个工具..."
            />
          </div>

          {/* Author & Version */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">作者</label>
              <input
                type="text"
                value={formData.author}
                onChange={(e) => setFormData(prev => ({ ...prev, author: e.target.value }))}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">版本</label>
              <input
                type="text"
                value={formData.version}
                onChange={(e) => setFormData(prev => ({ ...prev, version: e.target.value }))}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="1.0.0"
              />
            </div>
          </div>

          {/* Error */}
          {uploadMutation.isError && (
            <div className="text-red-500 text-sm">
              上传失败: {
                // @ts-expect-error axios error response
                uploadMutation.error?.response?.data?.detail ||
                (uploadMutation.error as Error).message
              }
            </div>
          )}

          {/* Submit */}
          <div className="flex justify-end gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={!file || !formData.name || uploadMutation.isPending}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {uploadMutation.isPending ? '上传中...' : '上传'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function severityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'bg-red-600 text-white'
    case 'high': return 'bg-orange-500 text-white'
    case 'medium': return 'bg-yellow-500 text-white'
    case 'low': return 'bg-blue-500 text-white'
    default: return 'bg-gray-500 text-white'
  }
}

function severityLabel(severity: string) {
  switch (severity) {
    case 'critical': return '严重'
    case 'high': return '高危'
    case 'medium': return '中危'
    case 'low': return '低危'
    default: return '信息'
  }
}

function NucleiTemplateCard({
  template,
  onView,
}: {
  template: NucleiTemplate
  onView: () => void
}) {
  return (
    <div
      className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow hover:shadow-md transition-shadow cursor-pointer"
      onClick={onView}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-purple-600 dark:text-purple-400"><Code className="w-5 h-5" /></span>
          <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
            {template.category}
          </span>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded font-medium ${severityColor(template.severity)}`}>
          {severityLabel(template.severity)}
        </span>
      </div>

      <h3 className="font-semibold mb-1 text-sm flex items-center gap-2 flex-wrap">
        {template.name}
      </h3>
      <p className="text-xs text-gray-400 dark:text-gray-500 mb-2 font-mono truncate">
        {template.id}
      </p>

      {template.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {template.tags.slice(0, 5).map(tag => (
            <span key={tag} className="text-xs px-1.5 py-0.5 bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded">
              {tag}
            </span>
          ))}
          {template.tags.length > 5 && (
            <span className="text-xs text-gray-500">+{template.tags.length - 5}</span>
          )}
        </div>
      )}

      <div className="flex items-center gap-2 text-xs text-gray-500">
        <span className="truncate flex-1">{template.path}</span>
        <span>•</span>
        <span>{formatFileSize(template.file_size)}</span>
      </div>
    </div>
  )
}

function NucleiTemplateContentModal({
  template,
  onClose,
}: {
  template: NucleiTemplate
  onClose: () => void
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['nuclei-template-content', template.path],
    queryFn: () => getNucleiTemplateContent(template.path),
  })

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-3">
            <Code className="w-5 h-5 text-purple-600" />
            <div>
              <h2 className="text-lg font-semibold">{template.name}</h2>
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <span className="font-mono">{template.id}</span>
                <span>•</span>
                <span className={`text-xs px-2 py-0.5 rounded ${severityColor(template.severity)}`}>
                  {severityLabel(template.severity)}
                </span>
                <span>•</span>
                <span>{template.category}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tags */}
        {template.tags.length > 0 && (
          <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 flex flex-wrap gap-1">
            <Shield className="w-4 h-4 text-gray-400 mt-0.5" />
            {template.tags.map(tag => (
              <span key={tag} className="text-xs px-2 py-0.5 bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded">
                {tag}
              </span>
            ))}
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-4">
          {isLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">加载中...</div>
          ) : error ? (
            <div className="text-center py-8 text-red-500">无法加载模板内容</div>
          ) : (
            <pre className="bg-gray-100 dark:bg-gray-900 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
              {data?.content}
            </pre>
          )}
        </div>

        <div className="p-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between text-xs text-gray-500">
          <span className="font-mono">{template.path}</span>
          <span>{formatFileSize(template.file_size)}</span>
        </div>
      </div>
    </div>
  )
}

function ContentModal({ tool, onClose }: { tool: SecurityTool; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['tool-content', tool.id],
    queryFn: () => getToolContent(tool.id),
  })

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-lg font-semibold">{tool.name}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{tool.filename}</p>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-hidden flex gap-4 p-4">
          {/* File Content - Left side */}
          <div className="flex-1 overflow-y-auto">
            <div className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-200">文件内容</div>
            {isLoading ? (
              <div className="text-center py-8 text-gray-500 dark:text-gray-400">加载中...</div>
            ) : error ? (
              <div className="text-center py-8 text-red-500">
                无法加载文件内容
              </div>
            ) : (
              <pre className="bg-gray-100 dark:bg-gray-900 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
                {data?.content}
              </pre>
            )}
          </div>

          {/* Usage Instructions - Right side */}
          {tool.usage_instructions && (
            <div className="flex-1 overflow-y-auto border-l border-gray-200 dark:border-gray-700 pl-4">
              <div className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-200">使用说明</div>
              <p className="text-sm text-gray-600 dark:text-gray-300 whitespace-pre-wrap">
                {tool.usage_instructions}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function formatFileSize(bytes: number | null): string {
  if (!bytes) return '未知'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}
