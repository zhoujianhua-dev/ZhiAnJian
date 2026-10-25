import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Bot,
  Copy,
  Database,
  Download,
  FolderOpen,
  Loader2,
  Palette,
  Upload,
  X,
} from 'lucide-react'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { Badge } from '@/components/ui/badge'
import { Tabs } from '@/components/ui/tabs'
import { ErrorBlock, LoadingBlock } from '@/components/ui/states'
import { useConfirm } from '@/components/ui/confirm'
import { useToast } from '@/components/ui/toast'
import { api, downloadFile, pickFile } from '@/lib/api'
import { SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/format'
import { useQuery } from '@/lib/use-query'
import { cn } from '@/lib/cn'
import { useAuth } from '@/store/auth'

/* ---------------- 类型（字段与后端返回一致，后端为 snake_case） ---------------- */

interface AppearanceData {
  app_title: string
  app_subtitle: string
  theme_color: string
  background: string
  background_overlay: number
  background_blur: number
  report_header: string
  export_org: string
  backgrounds: string[]
}

interface AiConfigData {
  base_url: string
  model: string
  api_key: string
  proxy: string
  timeout: number
}

interface AiPingData {
  latency_ms: number
  model_count: number
  models?: string[]
  current_model?: string
  current_online?: boolean
  mock?: boolean
}

interface ShellingBrief {
  id: number | string
  name: string
  model?: string
  provider?: string
  api_base_url?: string
  has_api_key?: boolean
}

interface ShellingStatus {
  reachable: boolean
  error?: string | null
  total: number
  synced: ShellingBrief | null
  active_main: ShellingBrief | null
  active_sub: ShellingBrief | null
}

interface StatsData {
  units: number
  domains: number
  vulns: number
  reports: number
  templates: number
  severity: Record<string, number>
}

/* ---------------- 常量 ---------------- */

const THEME_PRESETS = ['#2563eb', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#0f172a']

const TABS = [
  { key: 'appearance', label: '外观与界面', icon: <Palette size={14} /> },
  { key: 'ai', label: 'AI 接口配置', icon: <Bot size={14} /> },
  { key: 'data', label: '数据管理', icon: <Database size={14} /> },
]

const STAT_ITEMS = [
  { key: 'units', label: '单位' },
  { key: 'domains', label: '域名' },
  { key: 'vulns', label: '漏洞知识' },
  { key: 'reports', label: '漏洞报告' },
  { key: 'templates', label: '报告模板' },
] as const

function bgUrl(name: string) {
  return `/media/backgrounds/${encodeURIComponent(name)}`
}

function Section({ title, hint, children }: { title: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="border-t border-line pt-3.5 first:border-0 first:pt-0">
      <div className="mb-2 flex flex-wrap items-baseline gap-2">
        <h3 className="text-[13px] font-semibold text-slate-800">{title}</h3>
        {hint ? <span className="text-xs text-slate-400">{hint}</span> : null}
      </div>
      {children}
    </div>
  )
}

/* ---------------- 页面 ---------------- */

export function Settings() {
  const toast = useToast()
  const confirm = useConfirm()
  const { refresh: refreshBoot } = useAuth()

  const [tab, setTab] = useState('appearance')

  /* ---------- 外观：表单状态 ---------- */
  const [appTitle, setAppTitle] = useState('')
  const [appSubtitle, setAppSubtitle] = useState('')
  const [themeColor, setThemeColor] = useState(THEME_PRESETS[0])
  const [bgName, setBgName] = useState('')
  const [overlay, setOverlay] = useState(35)
  const [blur, setBlur] = useState(0)
  const [reportHeader, setReportHeader] = useState('')
  const [exportOrg, setExportOrg] = useState('')
  const [savingAppearance, setSavingAppearance] = useState(false)
  const [uploadingBg, setUploadingBg] = useState(false)

  const loadAppearance = useCallback(async () => {
    const res = await api.get<AppearanceData>('/api/settings/appearance')
    return res.data as AppearanceData
  }, [])
  const appearance = useQuery(loadAppearance, [loadAppearance])

  useEffect(() => {
    const d = appearance.data
    if (!d) return
    setAppTitle(d.app_title || '')
    setAppSubtitle(d.app_subtitle || '')
    setThemeColor(d.theme_color || THEME_PRESETS[0])
    setBgName(d.background || '')
    setOverlay(Math.round((d.background_overlay ?? 0.35) * 100))
    setBlur(d.background_blur ?? 0)
    setReportHeader(d.report_header || '')
    setExportOrg(d.export_org || '')
  }, [appearance.data])

  async function saveAppearance() {
    setSavingAppearance(true)
    try {
      const res = await api.post('/api/settings/appearance', {
        app_title: appTitle.trim(),
        app_subtitle: appSubtitle.trim(),
        theme_color: themeColor,
        background: bgName,
        background_overlay: overlay / 100,
        background_blur: blur,
        report_header: reportHeader.trim(),
        export_org: exportOrg.trim(),
      })
      toast.success(res.msg || '外观设置已保存')
      // 主题色 / 标题由 bootstrap 下发，保存后必须刷新才能立即生效
      await refreshBoot()
      await appearance.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSavingAppearance(false)
    }
  }

  async function uploadBg() {
    const files = await pickFile('image/*')
    const file = files?.[0]
    if (!file) return
    setUploadingBg(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await api.upload<{ filename?: string }>('/api/settings/background/upload', fd)
      toast.success(res.msg || '背景图已上传并应用')
      const name = res.data?.filename
      if (name) setBgName(name)
      await appearance.reload()
      await refreshBoot()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '上传失败')
    } finally {
      setUploadingBg(false)
    }
  }

  async function removeBg(name: string) {
    const ok = await confirm({ message: '确定删除该背景图？', confirmText: '删除' })
    if (!ok) return
    try {
      const res = await api.post('/api/settings/background/delete', { name })
      toast.success(res.msg || '已删除')
      if (bgName === name) setBgName('')
      await appearance.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  /* ---------- AI 配置 ---------- */
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [model, setModel] = useState('')
  const [proxy, setProxy] = useState('')
  const [timeout, setTimeoutValue] = useState('120')
  const [manualModel, setManualModel] = useState(false)
  const [modelOptions, setModelOptions] = useState<string[]>([])
  const [modelLoading, setModelLoading] = useState(false)
  const [modelError, setModelError] = useState('')
  const [savingAi, setSavingAi] = useState(false)
  const [testing, setTesting] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [pingInfo, setPingInfo] = useState<{ ok: boolean; text: string } | null>(null)
  const autoFetchedKey = useRef('')
  const fetchModelsRef = useRef<
    ((silent?: boolean, override?: { apiKey?: string; baseUrl?: string; proxy?: string }) => Promise<void>) | null
  >(null)

  const loadAi = useCallback(async () => {
    const res = await api.get<AiConfigData>('/api/settings/ai')
    return res.data as AiConfigData
  }, [])
  const aiQuery = useQuery(loadAi, [loadAi])

  const loadShelling = useCallback(async () => {
    const res = await api.get<ShellingStatus>('/api/settings/ai/shelling')
    return res.data as ShellingStatus
  }, [])
  const shelling = useQuery(loadShelling, [loadShelling])

  const fetchModels = useCallback(
    async (silent = false, override?: { apiKey?: string; baseUrl?: string; proxy?: string }) => {
      const key = (override?.apiKey ?? apiKey).trim()
      if (!key) {
        setModelError('请先填写 API Key')
        if (!silent) toast.error('请先填写 API Key')
        return
      }
      setModelLoading(true)
      setModelError('')
      try {
        const res = await api.post<AiPingData>('/api/ai/ping', {
          api_key: key,
          base_url: (override?.baseUrl ?? baseUrl).trim(),
          proxy: (override?.proxy ?? proxy).trim(),
        })
        const models = Array.isArray(res.data?.models) ? (res.data?.models as string[]) : []
        if (models.length) {
          setModelOptions(models)
          if (!silent) toast.success(`已获取 ${models.length} 个模型，勾选一个即可`)
        } else {
          setModelOptions([])
          setModelError(res.msg || '上游未返回模型列表')
          if (!silent) toast.error(res.msg || '上游未返回模型列表')
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : '请求异常'
        setModelOptions([])
        setModelError(msg)
        if (!silent) toast.error(msg)
      } finally {
        setModelLoading(false)
      }
    },
    [apiKey, baseUrl, proxy, toast],
  )

  // fetchModels 依赖输入框状态，用 ref 转交，避免「填表 → 重跑 → 被服务端数据覆盖」的循环
  useEffect(() => {
    fetchModelsRef.current = fetchModels
  }, [fetchModels])

  useEffect(() => {
    const d = aiQuery.data
    if (!d) return
    setApiKey(d.api_key || '')
    setBaseUrl(d.base_url || '')
    setModel(d.model || '')
    setProxy(d.proxy || '')
    setTimeoutValue(String(d.timeout || 120))
    // 已配置时自动从上游拉一次模型列表，省得每次手点
    const key = `${d.base_url}|${d.api_key}`
    if (d.api_key && d.base_url && autoFetchedKey.current !== key) {
      autoFetchedKey.current = key
      void fetchModelsRef.current?.(true, { apiKey: d.api_key, baseUrl: d.base_url, proxy: d.proxy || '' })
    }
  }, [aiQuery.data])

  const modelList = useMemo(() => {
    const list = modelOptions.slice()
    // 已保存的模型若不在上游列表里，也一并列出并标注，避免配置“凭空消失”
    if (model && !list.includes(model)) list.unshift(model)
    return list
  }, [modelOptions, model])

  function pickModel(name: string, checked: boolean) {
    if (!checked && model === name) {
      setModel('')
      toast.info('已取消选择，保存后将不指定模型')
      return
    }
    if (checked) {
      setModel(name)
      toast.info(`已选用模型：${name} —— 点「保存 AI 配置」生效`)
    }
  }

  function toggleManualModel() {
    const next = !manualModel
    setManualModel(next)
    if (next) toast.info('已解锁输入框，可直接填写模型名')
  }

  async function saveAi() {
    setSavingAi(true)
    try {
      const res = await api.post('/api/settings/ai', {
        api_key: apiKey.trim(),
        base_url: baseUrl.trim(),
        model: model.trim(),
        proxy: proxy.trim(),
        timeout: parseInt(timeout, 10) || 120,
      })
      toast.success(res.msg || 'AI 配置已保存')
      await aiQuery.reload()
      await shelling.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setSavingAi(false)
    }
  }

  async function testAi() {
    const key = apiKey.trim()
    if (!key) {
      toast.error('请先填写 API Key')
      return
    }
    setTesting(true)
    toast.info('正在测试连接...')
    try {
      const res = await api.post<AiPingData>('/api/ai/ping', {
        api_key: key,
        base_url: baseUrl.trim(),
        model: model.trim(),
        proxy: proxy.trim(),
      })
      const d = res.data
      const models = Array.isArray(d?.models) ? (d?.models as string[]) : []
      // 测试连接会一并返回上游模型列表，顺手刷新勾选项
      if (models.length) {
        setModelOptions(models)
        setModelError('')
      }
      const currentModel = d?.current_model || ''
      const modelTip = currentModel
        ? d?.current_online
          ? `，当前模型「${currentModel}」可用 ✔`
          : `，但当前模型「${currentModel}」不在可用列表，请核对模型名`
        : ''
      const text = `连接正常（${d?.latency_ms ?? 0} ms），共 ${d?.model_count ?? 0} 个可用模型${modelTip}`
      setPingInfo({ ok: true, text })
      toast.success(text)
    } catch (e) {
      const msg = e instanceof Error ? e.message : '请求异常'
      setPingInfo({ ok: false, text: `连接失败：${msg}` })
      toast.error(`连接失败：${msg}`)
    } finally {
      setTesting(false)
    }
  }

  async function syncToShelling() {
    const key = apiKey.trim()
    if (!key) {
      toast.error('请先填写 AI API Key —— Shelling 侧需要可用的 Key 才能真正启用 AI 分析')
      return
    }
    setSyncing(true)
    toast.info('正在同步 AI 配置到 Shelling 并实测调用...')
    try {
      const res = await api.post('/api/settings/ai/sync', {
        api_key: key,
        base_url: baseUrl.trim(),
        model: model.trim(),
      })
      toast.success(res.msg || '已同步到 Shelling')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '同步失败')
    } finally {
      setSyncing(false)
      await shelling.reload()
    }
  }

  /* ---------- 数据管理 ---------- */
  const [seeding, setSeeding] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [openingDir, setOpeningDir] = useState(false)

  const loadStats = useCallback(async () => {
    const res = await api.get<StatsData>('/api/settings/stats')
    return res.data as StatsData
  }, [])
  const stats = useQuery(loadStats, [loadStats])

  const loadDataPath = useCallback(async () => {
    const res = await api.get<never>('/api/settings/data-path')
    return typeof res.path === 'string' ? res.path : ''
  }, [])
  const dataPath = useQuery(loadDataPath, [loadDataPath])

  async function seedDemo() {
    const ok = await confirm({
      message: '导入演示数据（测试单位/域名/漏洞）？可随时在设置页清空。',
      confirmText: '导入',
      danger: false,
    })
    if (!ok) return
    setSeeding(true)
    try {
      const res = await api.post('/api/settings/seed-demo')
      toast.success(res.msg || '演示数据导入完成')
      await stats.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导入失败')
    } finally {
      setSeeding(false)
    }
  }

  async function clearData() {
    const ok = await confirm({
      message: '将清空全部单位、域名、漏洞、报告数据！此操作不可恢复，确定继续？',
      confirmText: '清空',
    })
    if (!ok) return
    setClearing(true)
    try {
      const res = await api.post('/api/settings/clear-data')
      toast.success(res.msg || '已清空全部业务数据')
      await stats.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '清空失败')
    } finally {
      setClearing(false)
    }
  }

  async function openDataDir() {
    setOpeningDir(true)
    try {
      const res = await api.post<never>('/api/settings/open-data-dir')
      toast.success(res.msg || '已在文件管理器打开数据目录')
      await dataPath.reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '打开数据目录失败')
    } finally {
      setOpeningDir(false)
    }
  }

  async function copyDataPath() {
    const p = (dataPath.data || '').trim()
    if (!p) {
      toast.error('路径尚未就绪')
      return
    }
    try {
      await navigator.clipboard.writeText(p)
      toast.success('数据目录路径已复制，可粘贴到资源管理器地址栏')
    } catch {
      toast.info(p)
    }
  }

  /* ---------- 渲染 ---------- */

  const configured = !!aiQuery.data?.api_key

  return (
    <div className="flex flex-col gap-4">
      <Tabs items={TABS} value={tab} onChange={setTab} />

      {tab === 'appearance' ? (
        <Card>
          <CardHeader title="外观与界面" description="自定义背景图片 · 主题色 · 标题" />
          {appearance.loading && !appearance.data ? (
            <LoadingBlock />
          ) : appearance.error && !appearance.data ? (
            <ErrorBlock message={appearance.error} onRetry={appearance.reload} />
          ) : (
            <CardBody className="flex flex-col gap-4">
              <Section title="系统标题">
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="主标题">
                    <Input value={appTitle} onChange={(e) => setAppTitle(e.target.value)} placeholder="智安鉴" />
                  </Field>
                  <Field label="副标题">
                    <Input
                      value={appSubtitle}
                      onChange={(e) => setAppSubtitle(e.target.value)}
                      placeholder="智能安全检测与漏洞报告系统"
                    />
                  </Field>
                </div>
              </Section>

              <Section title="主题色" hint="保存后立即生效">
                <div className="flex flex-wrap items-center gap-2">
                  {THEME_PRESETS.map((c) => (
                    <button
                      key={c}
                      type="button"
                      title={c}
                      aria-label={`主题色 ${c}`}
                      onClick={() => setThemeColor(c)}
                      style={{ backgroundColor: c }}
                      className={cn(
                        'h-7 w-7 rounded-md border-2 transition-colors',
                        themeColor === c ? 'border-slate-900' : 'border-transparent',
                      )}
                    />
                  ))}
                  <label className="ml-1 inline-flex items-center gap-1.5 text-xs text-slate-500">
                    <input
                      type="color"
                      value={themeColor}
                      onChange={(e) => setThemeColor(e.target.value)}
                      className="h-7 w-9 cursor-pointer rounded border border-line bg-white p-0.5"
                      aria-label="自定义主题色"
                    />
                    自定义
                  </label>
                  <span className="tnum text-xs text-slate-400">{themeColor}</span>
                </div>
              </Section>

              <Section title="自定义背景图" hint="点击缩略图选中，保存外观设置后生效">
                <div className="flex flex-wrap items-start gap-2">
                  <button
                    type="button"
                    onClick={() => setBgName('')}
                    className={cn(
                      'flex h-[64px] w-[92px] flex-col items-center justify-center rounded-md border-2 bg-slate-100 text-[11px] text-slate-500 transition-colors',
                      bgName ? 'border-line hover:border-primary-line' : 'border-primary',
                    )}
                  >
                    <span>默认</span>
                    <span className="text-[10px] text-slate-400">不使用背景图</span>
                  </button>
                  {(appearance.data?.backgrounds || []).map((name) => (
                    <div key={name} className="relative">
                      <button
                        type="button"
                        onClick={() => setBgName(name)}
                        className={cn(
                          'h-[64px] w-[92px] overflow-hidden rounded-md border-2 bg-slate-100 transition-colors',
                          bgName === name ? 'border-primary' : 'border-line hover:border-primary-line',
                        )}
                      >
                        <img src={bgUrl(name)} alt={name} className="h-full w-full object-cover" />
                      </button>
                      <button
                        type="button"
                        aria-label="删除背景图"
                        onClick={() => removeBg(name)}
                        className="absolute -right-1.5 -top-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-600 text-white hover:bg-red-700"
                      >
                        <X size={10} />
                      </button>
                    </div>
                  ))}
                </div>
                <div className="mt-2.5">
                  <Button variant="primary" size="sm" icon={<Upload size={14} />} loading={uploadingBg} onClick={uploadBg}>
                    上传并应用
                  </Button>
                  <span className="ml-2 text-xs text-slate-400">支持 png / jpg / jpeg / gif / webp</span>
                </div>
              </Section>

              <Section title="背景效果">
                <div className="flex flex-col gap-2.5">
                  <div className="flex items-center gap-3">
                    <span className="w-[70px] shrink-0 text-[13px] text-slate-600">遮罩强度</span>
                    <input
                      type="range"
                      min={0}
                      max={90}
                      value={overlay}
                      onChange={(e) => setOverlay(Number(e.target.value))}
                      className="h-1.5 flex-1 cursor-pointer accent-[color:var(--primary)]"
                      aria-label="遮罩强度"
                    />
                    <span className="tnum w-10 shrink-0 text-right text-xs text-slate-500">
                      {(overlay / 100).toFixed(2)}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-[70px] shrink-0 text-[13px] text-slate-600">背景模糊</span>
                    <input
                      type="range"
                      min={0}
                      max={30}
                      value={blur}
                      onChange={(e) => setBlur(Number(e.target.value))}
                      className="h-1.5 flex-1 cursor-pointer accent-[color:var(--primary)]"
                      aria-label="背景模糊"
                    />
                    <span className="tnum w-10 shrink-0 text-right text-xs text-slate-500">{blur}px</span>
                  </div>
                </div>
              </Section>

              <Section title="报告落款">
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="报告页眉标题">
                    <Input
                      value={reportHeader}
                      onChange={(e) => setReportHeader(e.target.value)}
                      placeholder="网络安全测试报告"
                    />
                  </Field>
                  <Field label="落款单位">
                    <Input
                      value={exportOrg}
                      onChange={(e) => setExportOrg(e.target.value)}
                      placeholder="如：XX 网络安全测评中心"
                    />
                  </Field>
                </div>
              </Section>

              <div>
                <Button variant="primary" loading={savingAppearance} onClick={saveAppearance}>
                  保存外观设置
                </Button>
              </div>
            </CardBody>
          )}
        </Card>
      ) : null}

      {tab === 'ai' ? (
        <Card>
          <CardHeader
            title="AI 接口配置"
            description="智安鉴与 Shelling 共用这一份模型配置"
            actions={<Badge tone={configured ? 'emerald' : 'slate'}>{configured ? '已配置' : '未配置'}</Badge>}
          />
          {aiQuery.loading && !aiQuery.data ? (
            <LoadingBlock />
          ) : aiQuery.error && !aiQuery.data ? (
            <ErrorBlock message={aiQuery.error} onRetry={aiQuery.reload} />
          ) : (
            <CardBody className="flex flex-col gap-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="API Key（仅保存在本机 config.json）" className="sm:col-span-2">
                  <Input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="sk-..."
                    autoComplete="off"
                  />
                </Field>
                <Field label="Base URL">
                  <Input
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    placeholder="https://api.stepfun.com/v1"
                  />
                </Field>
                <Field label="超时（秒）">
                  <Input
                    type="number"
                    value={timeout}
                    onChange={(e) => setTimeoutValue(e.target.value)}
                    placeholder="120"
                  />
                </Field>

                <Field
                  label={
                    <span>
                      模型 <span className="font-normal text-slate-400">从上游获取后勾选，无需手填</span>
                    </span>
                  }
                  className="sm:col-span-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Input
                      value={model}
                      readOnly={!manualModel}
                      onChange={(e) => setModel(e.target.value)}
                      placeholder="点「从上游获取模型」后勾选"
                      className={cn('min-w-[200px] flex-1', !manualModel && 'bg-slate-50')}
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      icon={<Download size={13} />}
                      loading={modelLoading}
                      onClick={() => void fetchModels(false)}
                    >
                      从上游获取模型
                    </Button>
                    <Button size="sm" variant="ghost" onClick={toggleManualModel}>
                      {manualModel ? '改用勾选' : '手动填写'}
                    </Button>
                  </div>
                  {modelList.length ? (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {modelList.map((name) => {
                        const on = name === model
                        const missing = on && !modelOptions.includes(name)
                        return (
                          <label
                            key={name}
                            className={cn(
                              'inline-flex cursor-pointer select-none items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs transition-colors',
                              on
                                ? 'border-primary bg-primary-soft font-semibold text-primary'
                                : 'border-line-strong bg-white text-slate-600 hover:border-primary-line',
                            )}
                          >
                            <input
                              type="checkbox"
                              checked={on}
                              onChange={(e) => pickModel(name, e.target.checked)}
                              className="h-3.5 w-3.5 accent-[color:var(--primary)]"
                            />
                            {name}
                            {missing ? <span className="font-normal text-slate-400">（已保存，上游未返回）</span> : null}
                          </label>
                        )
                      })}
                    </div>
                  ) : null}
                  <p className="mt-1.5 text-xs">
                    {modelLoading ? (
                      <span className="inline-flex items-center gap-1.5 text-slate-500">
                        <Loader2 size={12} className="animate-spin" />
                        正在从上游获取模型列表…
                      </span>
                    ) : modelError ? (
                      <span className="text-red-600">获取失败：{modelError}</span>
                    ) : !modelOptions.length && !model ? (
                      <span className="text-amber-600">
                        尚未获取到模型列表：填好 API Key 与 Base URL 后点「从上游获取模型」
                      </span>
                    ) : !modelOptions.length ? (
                      <span className="text-slate-500">
                        当前模型 <b className="text-slate-700">{model}</b>
                        （上游未返回列表，可点「手动填写」或「从上游获取模型」重试）
                      </span>
                    ) : (
                      <span className="text-slate-500">
                        已从上游获取 <b className="text-slate-700">{modelOptions.length}</b> 个模型
                        {model ? (
                          <>
                            ，当前选用 <b className="text-slate-700">{model}</b>
                          </>
                        ) : (
                          '，请勾选一个'
                        )}
                      </span>
                    )}
                  </p>
                </Field>

                <Field
                  label={
                    <span>
                      网络代理（可选）
                      <span className="ml-1 font-normal text-red-500">
                        校园网/酒店等需网页认证，或接口被网络拦截时填写
                      </span>
                    </span>
                  }
                  className="sm:col-span-2"
                >
                  <Input
                    value={proxy}
                    onChange={(e) => setProxy(e.target.value)}
                    placeholder="留空直连；例如 http://127.0.0.1:7897（Clash）、http://127.0.0.1:7890"
                  />
                </Field>
              </div>

              <div className="text-xs leading-6 text-slate-500">
                常用接入：DeepSeek（api.deepseek.com/v1）、阶跃星辰（api.stepfun.com/v1）、
                通义千问（dashscope.aliyuncs.com/compatible-mode/v1）、OpenAI（api.openai.com/v1）、本地
                Ollama（localhost:11434/v1）。
                <br />
                模型不用记名字：填好 Base URL 与 API Key 后点「从上游获取模型」，在列表里勾选一个即可（打开本页时会自动拉取一次；
                上游返回不了列表时，可点「手动填写」）。
                <br />
                连不上时：①确认当前网络已完成网页认证，或直接换手机热点；②开启本机代理软件后，在上方填写代理地址再“测试连接”。
              </div>

              <Section title="统一 AI 配置" hint="智安鉴与 Shelling 共用这一份模型配置">
                {shelling.loading && !shelling.data ? (
                  <p className="text-xs text-slate-400">读取中…</p>
                ) : shelling.error && !shelling.data ? (
                  <p className="text-xs text-red-600">读取 Shelling 状态失败：{shelling.error}</p>
                ) : shelling.data ? (
                  <ShellingStatusBox status={shelling.data} />
                ) : (
                  <p className="text-xs text-slate-400">读取中…</p>
                )}
                <div className="mt-2.5 flex flex-wrap items-center gap-2">
                  <Button variant="secondary" size="sm" loading={syncing} onClick={syncToShelling}>
                    同步到 Shelling
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => void shelling.reload()}>
                    刷新状态
                  </Button>
                </div>
                <div className="mt-2 text-xs leading-6 text-slate-400">
                  智安鉴的 Base URL / 模型 / API Key 是全系统唯一配置源。保存时自动同步给 Shelling，
                  使 Shelling 扫描同样具备 AI 分析（漏洞摘要、AI 分析、整改建议、误报评分）。
                  <br />
                  注意：上方「网络代理」只对智安鉴生效，Shelling 侧不支持代理。
                </div>
              </Section>

              <div className="flex flex-wrap items-center gap-2">
                <Button variant="primary" loading={savingAi} onClick={saveAi}>
                  保存 AI 配置
                </Button>
                <Button variant="secondary" loading={testing} onClick={testAi}>
                  测试连接
                </Button>
                {pingInfo ? (
                  <span className={cn('text-xs', pingInfo.ok ? 'text-emerald-600' : 'text-red-600')}>
                    {pingInfo.text}
                  </span>
                ) : null}
              </div>
            </CardBody>
          )}
        </Card>
      ) : null}

      {tab === 'data' ? (
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader title="系统统计" description="当前库中的业务数据量" actions={
              <Button variant="ghost" size="sm" onClick={() => void stats.reload()}>
                刷新
              </Button>
            } />
            {stats.loading && !stats.data ? (
              <LoadingBlock />
            ) : stats.error && !stats.data ? (
              <ErrorBlock message={stats.error} onRetry={stats.reload} />
            ) : stats.data ? (
              <CardBody className="flex flex-col gap-3">
                <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
                  {STAT_ITEMS.map((item) => (
                    <div key={item.key} className="rounded-md border border-line bg-slate-50 px-3 py-2.5">
                      <div className="tnum text-[20px] font-semibold leading-tight text-slate-900">
                        {stats.data?.[item.key] ?? 0}
                      </div>
                      <div className="truncate text-xs text-slate-500">{item.label}</div>
                    </div>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-slate-500">报告等级分布：</span>
                  {SEVERITY_ORDER.map((s) => (
                    <span
                      key={s}
                      className="inline-flex items-center gap-1.5 rounded border border-line bg-white px-2 py-0.5 text-xs text-slate-600"
                    >
                      {SEVERITY_LABEL[s]}
                      <span className="tnum font-medium text-slate-800">{stats.data?.severity?.[s] || 0}</span>
                    </span>
                  ))}
                </div>
              </CardBody>
            ) : null}
          </Card>

          <Card>
            <CardHeader title="数据管理" description="本地运行，数据不出本机" />
            <CardBody className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="success" size="sm" loading={seeding} onClick={seedDemo}>
                  导入演示数据
                </Button>
                <Button variant="danger" size="sm" loading={clearing} onClick={clearData}>
                  清空全部业务数据
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<FolderOpen size={14} />}
                  loading={openingDir}
                  onClick={openDataDir}
                >
                  打开数据目录
                </Button>
                <Button variant="ghost" size="sm" icon={<Copy size={14} />} onClick={copyDataPath}>
                  复制路径
                </Button>
              </div>
              <Field
                label="数据目录绝对路径（打不开时可复制，粘贴到任意资源管理器地址栏回车）"
                hint="数据库与导出文件均保存在工具目录 data/ 下，本地运行，数据不出本机。点击“打开数据目录”后若窗口没有弹到最前面，请查看任务栏的文件夹图标。"
              >
                <Input
                  readOnly
                  value={dataPath.data || ''}
                  placeholder="读取中…"
                  className="bg-slate-50 font-mono text-xs"
                  onFocus={(e) => e.currentTarget.select()}
                />
              </Field>
              {dataPath.error ? <p className="text-xs text-red-600">{dataPath.error}</p> : null}
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="内置模板下载" description="系统自带的标准报告模板与占位符说明" />
            <CardBody className="flex flex-col gap-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Download size={14} />}
                  onClick={() => downloadFile('/api/settings/builtin-template/standard')}
                >
                  下载标准报告模板（含占位符）
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<Download size={14} />}
                  onClick={() => downloadFile('/api/settings/builtin-template/guide')}
                >
                  下载占位符说明
                </Button>
              </div>
              <p className="text-xs leading-6 text-slate-500">
                标准模板可直接在 Word 里修改内容与版式后重新上传为自定义模板；占位符说明列出了系统支持的
                全部字段（单位名称、漏洞名称、检测过程、整改建议等）。
              </p>
            </CardBody>
          </Card>
        </div>
      ) : null}
    </div>
  )
}

/* ---------------- Shelling 侧状态展示 ---------------- */

function ShellingStatusBox({ status }: { status: ShellingStatus }) {
  if (!status.reachable) {
    return (
      <div className="text-xs leading-6 text-slate-600">
        <p className="text-amber-600">⚠ 未能连接扫描引擎</p>
        {status.error ? <p className="text-slate-500">{status.error}</p> : null}
        <p className="text-slate-500">
          扫描引擎地址已内置在代码中（http://host.docker.internal:8000），持续失败请检查宿主机 8000 端口。
        </p>
      </div>
    )
  }

  const { synced, active_main: activeMain, active_sub: activeSub } = status
  const total = status.total || 0

  if (synced) {
    const okMain = !!activeMain && activeMain.id === synced.id
    const okSub = !!activeSub && activeSub.id === synced.id
    return (
      <div className="text-xs leading-6 text-slate-600">
        <p>
          Shelling 侧现有 <b className="tnum text-slate-800">{total}</b> 个 LLM 配置。
        </p>
        <p>
          <span className="text-emerald-600">✔ 已统一</span>：配置「{synced.name}」，模型{' '}
          <b className="text-slate-800">{synced.model || '-'}</b>
          {synced.provider ? `（${synced.provider}）` : ''}
          {synced.has_api_key ? null : <span className="text-red-600">，缺少 API Key</span>}
        </p>
        <p>
          主 Agent：{okMain ? '✔ 使用该配置' : `✘ 未生效（当前：${activeMain ? activeMain.name : '无'}）`}
          <span className="mx-2 text-slate-300">|</span>
          子 Agent：{okSub ? '✔ 使用该配置' : `✘ 未生效（当前：${activeSub ? activeSub.name : '无'}）`}
        </p>
      </div>
    )
  }

  if (!total) {
    return (
      <div className="text-xs leading-6 text-slate-600">
        <p>
          Shelling 侧现有 <b className="tnum text-slate-800">0</b> 个 LLM 配置。
        </p>
        <p className="text-amber-600">⚠ Shelling 侧未配置 LLM</p>
        <p className="text-slate-500">
          扫描会跳过 AI 分析（漏洞仍会被扫描出来，但没有 AI 摘要与分析）。
          <br />
          填好上方 API Key 后点「同步到 Shelling」即可统一。
        </p>
      </div>
    )
  }

  const current = activeMain || activeSub
  return (
    <div className="text-xs leading-6 text-slate-600">
      <p>
        Shelling 侧现有 <b className="tnum text-slate-800">{total}</b> 个 LLM 配置。
      </p>
      <p className="text-amber-600">
        ⚠ 尚未统一：Shelling 当前生效的是「{current ? current.name : '未知'}」，与智安鉴不是同一份配置。
      </p>
      <p className="text-slate-500">点「同步到 Shelling」改为统一使用智安鉴的配置。</p>
    </div>
  )
}
