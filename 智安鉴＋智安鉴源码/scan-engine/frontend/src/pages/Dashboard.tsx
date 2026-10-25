import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format, parseISO, startOfDay } from 'date-fns'
import { Activity, AlertTriangle, CheckCircle, Clock, XCircle, Pause, PieChart as PieChartIcon, TrendingUp } from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  Sector,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { getScans, ScanTask } from '../lib/api'

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

// Chart color constants
const chartStatusColors: Record<string, string> = {
  PENDING: '#EAB308',
  RUNNING: '#3B82F6',
  PAUSED: '#F97316',
  COMPLETED: '#22C55E',
  FAILED: '#EF4444',
  CANCELLED: '#6B7280',
}

const severityColors: Record<string, string> = {
  critical: '#DC2626',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#6B7280',
}

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const pieTooltipContentStyle = {
  backgroundColor: '#FFFFFF',
  border: '1px solid #E5E7EB',
  borderRadius: '8px',
  color: '#111827',
  boxShadow: '0 8px 20px rgba(15, 23, 42, 0.12)',
}

const pieTooltipTextStyle = {
  color: '#111827',
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans({ limit: 100 }),
    refetchInterval: 5000,
  })

  // Compute chart data
  const { statusData, severityData, trendData, scanTypeData } = useMemo(() => {
    const scans = data?.items || []

    // Task status distribution
    const statusCount: Record<string, number> = {}
    scans.forEach(scan => {
      statusCount[scan.status] = (statusCount[scan.status] || 0) + 1
    })
    const statusData = Object.entries(statusCount).map(([status, count]) => ({
      name: statusLabels[status] || status,
      value: count,
      color: chartStatusColors[status] || '#6B7280',
    }))

    // Vulnerability severity distribution (simulated from risk scores and counts)
    const severityCount: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    scans.forEach(scan => {
      if (scan.vulnerability_count > 0) {
        const score = scan.llm_risk_score || 50
        if (score >= 80) severityCount.critical += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 60) severityCount.high += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 40) severityCount.medium += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 20) severityCount.low += Math.ceil(scan.vulnerability_count * 0.3)
        else severityCount.info += scan.vulnerability_count
      }
    })
    const severityData = Object.entries(severityCount)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => ({
        name: severityLabels[severity] || severity,
        value: count,
        color: severityColors[severity],
      }))

    // Vulnerability trend by date
    const trendMap: Record<string, number> = {}
    scans.forEach(scan => {
      const day = format(startOfDay(parseISO(scan.created_at)), 'MM-dd')
      trendMap[day] = (trendMap[day] || 0) + scan.vulnerability_count
    })
    const trendData = Object.entries(trendMap)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-14) // Last 14 days
      .map(([date, count]) => ({ date, vulnerabilities: count }))

    // Scan type distribution
    const typeCount: Record<string, number> = {}
    scans.forEach(scan => {
      typeCount[scan.scan_type] = (typeCount[scan.scan_type] || 0) + 1
    })
    const typeColors = ['#3B82F6', '#22C55E', '#EAB308', '#F97316', '#8B5CF6', '#EC4899']
    const scanTypeData = Object.entries(typeCount).map(([type, count], index) => ({
      name: scanTypeLabels[type] || type,
      value: count,
      color: typeColors[index % typeColors.length],
    }))

    return { statusData, severityData, trendData, scanTypeData }
  }, [data])

  const scans = data?.items || []
  const layoutRef = useRef<HTMLDivElement | null>(null)
  const leftColumnRef = useRef<HTMLDivElement | null>(null)
  const [showRightAside, setShowRightAside] = useState(false)
  const [syncedRightHeight, setSyncedRightHeight] = useState<number | null>(null)
  const [animateOnLoad, setAnimateOnLoad] = useState(false)
  const [activeStatusIndex, setActiveStatusIndex] = useState<number>(-1)
  const [activeScanTypeIndex, setActiveScanTypeIndex] = useState<number>(-1)
  const [activeSeverityIndex, setActiveSeverityIndex] = useState<number>(-1)

  useEffect(() => {
    setAnimateOnLoad(false)
    const frame = window.requestAnimationFrame(() => {
      setAnimateOnLoad(true)
    })
    const timer = window.setTimeout(() => setAnimateOnLoad(false), 1400)

    return () => {
      window.cancelAnimationFrame(frame)
      window.clearTimeout(timer)
    }
  }, [showRightAside])

  useEffect(() => {
    const container = layoutRef.current
    if (!container) {
      return
    }

    const minLeftWidth = 560
    const minRightWidth = 560
    const columnGap = 24

    const updateLayoutMode = () => {
      const canShowTwoColumns = container.clientWidth >= (minLeftWidth + minRightWidth + columnGap)
      setShowRightAside(canShowTwoColumns)
    }

    updateLayoutMode()

    const observer = new ResizeObserver(updateLayoutMode)
    observer.observe(container)

    return () => {
      observer.disconnect()
    }
  }, [isLoading, error])

  useEffect(() => {
    const leftColumn = leftColumnRef.current
    if (!leftColumn || !showRightAside) {
      setSyncedRightHeight(null)
      return
    }

    const syncHeight = () => {
      const contentHeight = Math.max(leftColumn.scrollHeight, Math.round(leftColumn.getBoundingClientRect().height))
      setSyncedRightHeight(contentHeight)
    }

    syncHeight()

    const observer = new ResizeObserver(syncHeight)
    observer.observe(leftColumn)

    return () => {
      observer.disconnect()
    }
  }, [showRightAside, statusData.length, scanTypeData.length, severityData.length, trendData.length, scans.length])

  const recentScans = scans.slice(0, 15)

  const maxLegendItems = Math.max(statusData.length, scanTypeData.length, severityData.length)
  const estimatedLegendRows = Math.max(1, Math.ceil(maxLegendItems / 2))
  const distributionLegendHeight = estimatedLegendRows * 22 + 8
  const distributionChartHeight = 140 + distributionLegendHeight
  const totalVulnerabilities = scans.reduce((sum, s) => sum + s.vulnerability_count, 0)

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <div className="text-lg font-semibold mb-2">加载中...</div>
        <div className="text-sm text-gray-500">正在获取扫描数据，请稍候</div>
      </div>
    )
  }

  if (error) {
    const errorMsg = error instanceof Error ? error.message : '未知错误'
    console.error('[Dashboard] Error details:', { error, errorMsg })
    return (
      <div className="text-center py-12">
        <div className="text-red-500 font-semibold mb-2">加载失败</div>
        <div className="text-sm text-red-400 mb-4">错误: {errorMsg}</div>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
        >
          重新加载
        </button>
      </div>
    )
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">仪表盘</h1>

      <div
        ref={layoutRef}
        className={`grid grid-cols-1 gap-6 ${showRightAside ? 'grid-cols-[minmax(0,5fr)_minmax(0,5fr)] items-start' : ''}`}
      >
        <div className="self-start">
          <div ref={leftColumnRef} className="space-y-4">
            {/* Left row 1: Summary stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard
                label="总扫描数"
                value={data?.total || 0}
                icon={Activity}
              />
              <StatCard
                label="进行中"
                value={scans.filter(s => s.status === 'RUNNING').length}
                icon={Clock}
                color="text-blue-500"
              />
              <StatCard
                label="已完成"
                value={scans.filter(s => s.status === 'COMPLETED').length}
                icon={CheckCircle}
                color="text-green-500"
              />
              <StatCard
                label="漏洞数"
                value={totalVulnerabilities}
                icon={AlertTriangle}
                color="text-orange-500"
              />
            </div>

            {/* Left row 2: Distribution charts */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <ChartCard title="任务状态分布" icon={PieChartIcon} className="h-full p-3">
                {statusData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={distributionChartHeight}>
                    <PieChart>
                      <Pie
                        data={statusData}
                        cx="50%"
                        cy="46%"
                        innerRadius={30}
                        outerRadius={50}
                        paddingAngle={2}
                        dataKey="value"
                        isAnimationActive={animateOnLoad}
                        animationDuration={900}
                        animationEasing="ease-out"
                        activeIndex={activeStatusIndex}
                        activeShape={renderActivePieShape}
                        onMouseEnter={(_, index) => setActiveStatusIndex(index)}
                        onMouseLeave={() => setActiveStatusIndex(-1)}
                      >
                        {statusData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={pieTooltipContentStyle}
                        labelStyle={pieTooltipTextStyle}
                        itemStyle={pieTooltipTextStyle}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={distributionLegendHeight}
                        wrapperStyle={{ paddingTop: '2px', paddingBottom: '8px' }}
                        formatter={(value) => <span className="text-gray-400 text-xs">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <EmptyChartState message="暂无任务数据" />
                )}
              </ChartCard>

              <ChartCard title="扫描类型分布" icon={PieChartIcon} className="h-full p-3">
                {scanTypeData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={distributionChartHeight}>
                    <PieChart>
                      <Pie
                        data={scanTypeData}
                        cx="50%"
                        cy="46%"
                        innerRadius={30}
                        outerRadius={50}
                        paddingAngle={2}
                        dataKey="value"
                        isAnimationActive={animateOnLoad}
                        animationDuration={900}
                        animationEasing="ease-out"
                        activeIndex={activeScanTypeIndex}
                        activeShape={renderActivePieShape}
                        onMouseEnter={(_, index) => setActiveScanTypeIndex(index)}
                        onMouseLeave={() => setActiveScanTypeIndex(-1)}
                      >
                        {scanTypeData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={pieTooltipContentStyle}
                        labelStyle={pieTooltipTextStyle}
                        itemStyle={pieTooltipTextStyle}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={distributionLegendHeight}
                        wrapperStyle={{ paddingTop: '2px', paddingBottom: '8px' }}
                        formatter={(value) => <span className="text-gray-400 text-xs">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <EmptyChartState message="暂无扫描数据" />
                )}
              </ChartCard>

              <ChartCard title="漏洞等级分布" icon={AlertTriangle} className="h-full p-3">
                {severityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={distributionChartHeight}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="46%"
                        innerRadius={30}
                        outerRadius={50}
                        paddingAngle={2}
                        dataKey="value"
                        isAnimationActive={animateOnLoad}
                        animationDuration={900}
                        animationEasing="ease-out"
                        activeIndex={activeSeverityIndex}
                        activeShape={renderActivePieShape}
                        onMouseEnter={(_, index) => setActiveSeverityIndex(index)}
                        onMouseLeave={() => setActiveSeverityIndex(-1)}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={pieTooltipContentStyle}
                        labelStyle={pieTooltipTextStyle}
                        itemStyle={pieTooltipTextStyle}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={distributionLegendHeight}
                        wrapperStyle={{ paddingTop: '2px', paddingBottom: '8px' }}
                        formatter={(value) => <span className="text-gray-400 text-xs">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <EmptyChartState message="暂无漏洞数据" />
                )}
              </ChartCard>
            </div>

            {/* Left row 3: Vulnerability trend */}
            <ChartCard title="漏洞趋势" icon={TrendingUp}>
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <LineChart data={trendData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#D1D5DB" />
                    <XAxis
                      dataKey="date"
                      stroke="#6B7280"
                      fontSize={12}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="#6B7280"
                      fontSize={12}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#FFFFFF',
                        border: '1px solid #E5E7EB',
                        borderRadius: '8px',
                        color: '#111827',
                      }}
                      formatter={(value: number) => [value, '漏洞数']}
                    />
                    <Line
                      type="monotone"
                      dataKey="vulnerabilities"
                      stroke="#F97316"
                      strokeWidth={2}
                      isAnimationActive={animateOnLoad}
                      animationDuration={1100}
                      animationEasing="ease-out"
                      dot={{ fill: '#F97316', strokeWidth: 2, r: 4 }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <EmptyChartState message="暂无趋势数据" />
              )}
            </ChartCard>
          </div>
        </div>

        {/* Right column: Recent scans auto-fit left column height */}
        <div
          className={showRightAside ? 'h-full self-start' : ''}
          style={showRightAside && syncedRightHeight ? {
            height: `${syncedRightHeight}px`,
            minHeight: `${syncedRightHeight}px`,
            maxHeight: `${syncedRightHeight}px`,
          } : undefined}
        >
          <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow h-full flex flex-col">
            <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h3 className="font-semibold text-gray-700 dark:text-gray-200">最近扫描任务</h3>
              <Link to="/scans" className="text-sm text-blue-500 hover:text-blue-400">
                查看全部 →
              </Link>
            </div>

            <div className="flex-1 overflow-y-auto overflow-x-hidden">
              <table className="w-full">
                <thead className="bg-gray-100 dark:bg-gray-700 sticky top-0 z-10">
                  <tr>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">目标</th>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200 whitespace-nowrap">类型</th>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200 whitespace-nowrap">状态</th>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200 whitespace-nowrap">漏洞</th>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200 whitespace-nowrap">风险评分</th>
                    <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200 whitespace-nowrap">创建时间</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map(scan => (
                    <ScanRow key={scan.id} scan={scan} />
                  ))}
                </tbody>
              </table>

              {scans.length === 0 && (
                <div className="text-center py-12 text-gray-500">
                  暂无扫描记录，点击"新建扫描"开始
                </div>
              )}

            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-gray-400',
}: {
  label: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  color?: string
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
      <div className="flex items-center gap-3">
        <Icon className={`w-8 h-8 ${color}`} />
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
        </div>
      </div>
    </div>
  )
}

function ChartCard({
  title,
  icon: Icon,
  children,
  className = '',
}: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg p-4 shadow ${className}`}>
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-5 h-5 text-gray-400" />
        <h3 className="font-semibold text-gray-700 dark:text-gray-200">{title}</h3>
      </div>
      {children}
    </div>
  )
}

function EmptyChartState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center h-[180px] text-gray-400">
      <div className="text-center">
        <PieChartIcon className="w-12 h-12 mx-auto mb-2 opacity-30" />
        <p className="text-sm">{message}</p>
      </div>
    </div>
  )
}

function ScanRow({ scan }: { scan: ScanTask }) {
  const StatusIcon = statusIcons[scan.status] || Clock

  return (
    <tr className="h-14 border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750">
      <td className="px-4 py-0 align-middle max-w-0">
        <Link
          to={`/scans/${scan.id}`}
          className="block truncate text-blue-600 dark:text-blue-400 hover:underline"
        >
          {scan.target}
        </Link>
      </td>
      <td className="px-4 py-0 align-middle whitespace-nowrap">{scanTypeLabels[scan.scan_type] || scan.scan_type}</td>
      <td className="px-4 py-0 align-middle">
        <span className={`flex items-center gap-2 whitespace-nowrap ${statusColors[scan.status] || 'text-gray-500'}`}>
          <StatusIcon className="w-4 h-4" />
          {statusLabels[scan.status] || scan.status}
        </span>
      </td>
      <td className="px-4 py-0 align-middle whitespace-nowrap">{scan.vulnerability_count}</td>
      <td className="px-4 py-0 align-middle whitespace-nowrap">
        {scan.llm_risk_score !== null ? (
          <RiskScore score={scan.llm_risk_score} />
        ) : (
          '-'
        )}
      </td>
      <td className="px-4 py-0 align-middle text-gray-500 dark:text-gray-400 whitespace-nowrap">
        {format(new Date(scan.created_at), 'MM-dd HH:mm')}
      </td>
    </tr>
  )
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? 'text-red-500' :
      score >= 60 ? 'text-orange-500' :
        score >= 40 ? 'text-yellow-500' :
          'text-green-500'

  return <span className={`font-semibold ${color}`}>{score}/100</span>
}

function renderActivePieShape(props: any) {
  const { outerRadius } = props

  return (
    <Sector
      {...props}
      outerRadius={typeof outerRadius === 'number' ? outerRadius + 8 : 58}
    />
  )
}
