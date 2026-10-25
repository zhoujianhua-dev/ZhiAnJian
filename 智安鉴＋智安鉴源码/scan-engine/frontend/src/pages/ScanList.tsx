import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import {
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  Pause,
  Plus,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Inbox,
  Trash2,
  AlertTriangle,
} from 'lucide-react'
import { getScans, ScanTask, batchDeleteScans } from '../lib/api'

// Status display configuration
const statusIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  PENDING: Clock,
  RUNNING: Activity,
  PAUSED: Pause,
  COMPLETED: CheckCircle,
  FAILED: XCircle,
  CANCELLED: XCircle,
}

const statusColors: Record<string, string> = {
  PENDING: 'text-yellow-500',
  RUNNING: 'text-blue-500',
  PAUSED: 'text-orange-500',
  COMPLETED: 'text-green-500',
  FAILED: 'text-red-500',
  CANCELLED: 'text-gray-500',
}

const statusLabels: Record<string, string> = {
  PENDING: '等待中',
  RUNNING: '扫描中',
  PAUSED: '等待回复',
  COMPLETED: '已完成',
  FAILED: '失败',
  CANCELLED: '已取消',
}

const scanTypeLabels: Record<string, string> = {
  full: '完整扫描',
  quick: '资产扫描',
  custom: '自定义',
}

const statusFilterOptions = [
  { value: '', label: '全部状态' },
  { value: 'PENDING', label: '等待中' },
  { value: 'RUNNING', label: '扫描中' },
  { value: 'COMPLETED', label: '已完成' },
  { value: 'FAILED', label: '失败' },
  { value: 'CANCELLED', label: '已取消' },
]

type SortField = 'created_at' | 'vulnerability_count' | 'llm_risk_score'
type SortOrder = 'asc' | 'desc'

export default function ScanList() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [statusFilter, setStatusFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set())
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const queryClient = useQueryClient()
  const skip = (page - 1) * pageSize

  const { data, isLoading, error } = useQuery({
    queryKey: ['scans', { skip, limit: pageSize, status: statusFilter, search: searchQuery }],
    queryFn: () => getScans({ skip, limit: pageSize, status: statusFilter || undefined, search: searchQuery || undefined }),
    refetchInterval: 5000,
  })

  // Batch delete mutation
  const batchDeleteMutation = useMutation({
    mutationFn: batchDeleteScans,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setSelectedScans(new Set())
      setShowDeleteConfirm(false)
    },
  })

  // Client-side sorting (API may not support sort params)
  const sortedScans = useMemo(() => {
    const items = data?.items || []
    return [...items].sort((a, b) => {
      let aVal: number | string | null
      let bVal: number | string | null

      switch (sortField) {
        case 'created_at':
          aVal = new Date(a.created_at).getTime()
          bVal = new Date(b.created_at).getTime()
          break
        case 'vulnerability_count':
          aVal = a.vulnerability_count
          bVal = b.vulnerability_count
          break
        case 'llm_risk_score':
          aVal = a.llm_risk_score ?? -1
          bVal = b.llm_risk_score ?? -1
          break
        default:
          return 0
      }

      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1
      return 0
    })
  }, [data?.items, sortField, sortOrder])

  const totalPages = Math.ceil((data?.total || 0) / pageSize)

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('desc')
    }
  }

  const handleStatusChange = (newStatus: string) => {
    setStatusFilter(newStatus)
    setPage(1) // Reset to first page when filter changes
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const deletableIds = sortedScans
        .filter(s => !['PENDING', 'RUNNING'].includes(s.status))
        .map(s => s.id)
      setSelectedScans(new Set(deletableIds))
    } else {
      setSelectedScans(new Set())
    }
  }

  const handleSelectScan = (scanId: string, checked: boolean) => {
    const newSelected = new Set(selectedScans)
    if (checked) {
      newSelected.add(scanId)
    } else {
      newSelected.delete(scanId)
    }
    setSelectedScans(newSelected)
  }

  const handleBatchDelete = () => {
    if (selectedScans.size === 0) return
    setShowDeleteConfirm(true)
  }

  const confirmBatchDelete = () => {
    batchDeleteMutation.mutate(Array.from(selectedScans))
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-4 h-4 text-gray-400" />
    }
    return sortOrder === 'asc' ? (
      <ArrowUp className="w-4 h-4" />
    ) : (
      <ArrowDown className="w-4 h-4" />
    )
  }

  if (error) {
    return (
      <div className="text-center py-12 text-red-500">
        加载失败: {(error as Error).message}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <h1 className="text-2xl font-bold">扫描历史</h1>
        <div className="flex items-center gap-3">
          {/* Batch Delete Button */}
          {selectedScans.size > 0 && (
            <button
              onClick={handleBatchDelete}
              disabled={batchDeleteMutation.isPending}
              className="bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              删除选中 ({selectedScans.size})
            </button>
          )}

          {/* Search and Filter */}
          <div className="flex gap-3 items-center flex-wrap">
            <input
              type="text"
              placeholder="搜索目标、备注..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value)
                setPage(1)
              }}
              className="flex-1 min-w-64 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            {/* Status Filter */}
            <div className="relative">
              <select
                value={statusFilter}
                onChange={(e) => handleStatusChange(e.target.value)}
                className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {statusFilterOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
            </div>
          </div>
        </div>
      </div>

      {/* Scan Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[800px]">
            <thead className="bg-gray-100 dark:bg-gray-700">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200 w-12">
                  <input
                    type="checkbox"
                    checked={selectedScans.size > 0 && selectedScans.size === sortedScans.filter(s => !['PENDING', 'RUNNING'].includes(s.status)).length}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200">
                  目标地址
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200">
                  类型
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200">
                  状态
                </th>
                <th
                  className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                  onClick={() => handleSort('vulnerability_count')}
                >
                  <span className="flex items-center gap-1">
                    漏洞数
                    <SortIcon field="vulnerability_count" />
                  </span>
                </th>
                <th
                  className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                  onClick={() => handleSort('llm_risk_score')}
                >
                  <span className="flex items-center gap-1">
                    风险评分
                    <SortIcon field="llm_risk_score" />
                  </span>
                </th>
                <th
                  className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                  onClick={() => handleSort('created_at')}
                >
                  <span className="flex items-center gap-1">
                    创建时间
                    <SortIcon field="created_at" />
                  </span>
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200">
                  备注
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-200">
                  操作
                </th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
                    <div className="flex items-center justify-center gap-2">
                      <Activity className="w-5 h-5 animate-spin" />
                      加载中...
                    </div>
                  </td>
                </tr>
              ) : sortedScans.length > 0 ? (
                sortedScans.map((scan) => (
                  <ScanRow
                    key={scan.id}
                    scan={scan}
                    selected={selectedScans.has(scan.id)}
                    onSelect={handleSelectScan}
                    onDelete={() => {
                      setSelectedScans(new Set([scan.id]))
                      setShowDeleteConfirm(true)
                    }}
                  />
                ))
              ) : (
                <tr>
                  <td colSpan={8}>
                    <EmptyState hasFilter={!!statusFilter} />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {!isLoading && (data?.total || 0) > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-700 gap-4 flex-wrap">
            <div className="text-sm text-gray-500 dark:text-gray-400">
              共 {data?.total || 0} 条记录，第 {page} / {totalPages || 1} 页
            </div>
            <div className="flex items-center gap-4">
              {/* Page Size Selector */}
              <div className="flex items-center gap-2">
                <label className="text-sm text-gray-600 dark:text-gray-400">每页显示:</label>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value))
                    setPage(1)
                  }}
                  className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value={10}>10 条</option>
                  <option value={20}>20 条</option>
                  <option value={50}>50 条</option>
                  <option value={100}>100 条</option>
                </select>
              </div>

              {/* Navigation Buttons */}
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
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <DeleteConfirmModal
          count={selectedScans.size}
          onConfirm={confirmBatchDelete}
          onCancel={() => {
            setShowDeleteConfirm(false)
            setSelectedScans(new Set())
          }}
          isDeleting={batchDeleteMutation.isPending}
        />
      )}
    </div>
  )
}

// ChevronDown icon for select dropdown
function ChevronDown({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  )
}

function ScanRow({
  scan,
  selected,
  onSelect,
  onDelete,
}: {
  scan: ScanTask
  selected: boolean
  onSelect: (scanId: string, checked: boolean) => void
  onDelete: () => void
}) {
  const StatusIcon = statusIcons[scan.status] || Clock
  const canDelete = !['PENDING', 'RUNNING'].includes(scan.status)

  return (
    <tr className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
      <td className="px-4 py-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={(e) => onSelect(scan.id, e.target.checked)}
          disabled={!canDelete}
          className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50"
        />
      </td>
      <td className="px-4 py-3">
        <Link
          to={`/scans/${scan.id}`}
          className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
        >
          {scan.target}
        </Link>
      </td>
      <td className="px-4 py-3 text-gray-600 dark:text-gray-300">
        {scanTypeLabels[scan.scan_type] || scan.scan_type}
      </td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center gap-1.5 ${statusColors[scan.status] || 'text-gray-500'}`}
        >
          <StatusIcon className="w-4 h-4" />
          <span className="text-sm">{statusLabels[scan.status] || scan.status}</span>
        </span>
      </td>
      <td className="px-4 py-3">
        <span
          className={
            scan.vulnerability_count > 0 ? 'font-semibold text-orange-500' : 'text-gray-500'
          }
        >
          {scan.vulnerability_count}
        </span>
      </td>
      <td className="px-4 py-3">
        {scan.llm_risk_score !== null ? <RiskScore score={scan.llm_risk_score} /> : '-'}
      </td>
      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
        {format(new Date(scan.created_at), 'yyyy-MM-dd HH:mm')}
      </td>
      <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300 max-w-xs truncate" title={scan.remark || ''}>
        {scan.remark || '-'}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <Link
            to={`/scans/${scan.id}`}
            className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
          >
            查看
          </Link>
          {canDelete && (
            <>
              <span className="text-gray-300 dark:text-gray-600">|</span>
              <button
                onClick={onDelete}
                className="text-sm text-red-600 dark:text-red-400 hover:underline"
              >
                删除
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  )
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80
      ? 'text-red-500'
      : score >= 60
        ? 'text-orange-500'
        : score >= 40
          ? 'text-yellow-500'
          : 'text-green-500'

  return <span className={`font-semibold ${color}`}>{score}/100</span>
}

function EmptyState({ hasFilter }: { hasFilter: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-gray-500 dark:text-gray-400">
      <Inbox className="w-16 h-16 mb-4 text-gray-300 dark:text-gray-600" />
      <p className="text-lg font-medium mb-2">
        {hasFilter ? '没有符合条件的扫描任务' : '暂无扫描任务'}
      </p>
      <p className="text-sm mb-4">
        {hasFilter ? '尝试调整筛选条件或' : '点击下方按钮开始您的第一次扫描'}
      </p>
      {!hasFilter && (
        <Link
          to="/new-scan"
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          新建扫描
        </Link>
      )}
    </div>
  )
}

function DeleteConfirmModal({
  count,
  onConfirm,
  onCancel,
  isDeleting,
}: {
  count: number
  onConfirm: () => void
  onCancel: () => void
  isDeleting: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6 shadow-xl">
        <div className="flex items-start gap-4 mb-4">
          <div className="flex-shrink-0 w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
              确认删除
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              您确定要删除选中的 <span className="font-semibold text-red-600">{count}</span> 个扫描任务吗？
              此操作不可撤销，将同时删除相关的漏洞记录和日志。
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            disabled={isDeleting}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
          >
            取消
          </button>
          <button
            onClick={onConfirm}
            disabled={isDeleting}
            className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {isDeleting ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                删除中...
              </>
            ) : (
              <>
                <Trash2 className="w-4 h-4" />
                确认删除
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
