import { useCallback, useEffect, useState } from 'react'
import { Calculator, Copy } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/field'
import { KV } from '@/components/ui/table'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/cvss']

type MetricKey = 'AV' | 'AC' | 'PR' | 'UI' | 'S' | 'C' | 'I' | 'A'

type MetricValues = Record<MetricKey, string>

interface MetricOption {
  value: string
  label: string
}

interface MetricDef {
  key: MetricKey
  name: string
  options: MetricOption[]
}

/** 与 core/cvss.py 的 METRICS 顺序、取值、文案保持一致 */
const METRICS: MetricDef[] = [
  {
    key: 'AV',
    name: '攻击向量',
    options: [
      { value: 'N', label: '网络｜可远程利用·分最高' },
      { value: 'A', label: '邻接｜需同一网段' },
      { value: 'L', label: '本地｜需本机执行/登录' },
      { value: 'P', label: '物理｜需接触设备·分最低' },
    ],
  },
  {
    key: 'AC',
    name: '攻击复杂度',
    options: [
      { value: 'L', label: '低｜条件简单易复现·分高' },
      { value: 'H', label: '高｜条件苛刻难复现·分低' },
    ],
  },
  {
    key: 'PR',
    name: '所需权限',
    options: [
      { value: 'N', label: '无｜未授权匿名可打·分最高' },
      { value: 'L', label: '低｜需普通登录账号' },
      { value: 'H', label: '高｜需管理员权限·分最低' },
    ],
  },
  {
    key: 'UI',
    name: '用户交互',
    options: [
      { value: 'N', label: '无需｜受害者零操作·分高' },
      { value: 'R', label: '需要｜需受害者点击·分低' },
    ],
  },
  {
    key: 'S',
    name: '影响范围',
    options: [
      { value: 'U', label: '不变｜仅影响本组件' },
      { value: 'C', label: '改变｜可越权影响组件外·显著抬分' },
    ],
  },
  {
    key: 'C',
    name: '机密性影响',
    options: [
      { value: 'H', label: '高｜信息完全泄露·分高' },
      { value: 'L', label: '低｜部分泄露' },
      { value: 'N', label: '无｜不影响机密性·分低' },
    ],
  },
  {
    key: 'I',
    name: '完整性影响',
    options: [
      { value: 'H', label: '高｜可完全篡改·分高' },
      { value: 'L', label: '低｜部分篡改' },
      { value: 'N', label: '无｜不影响完整性·分低' },
    ],
  },
  {
    key: 'A',
    name: '可用性影响',
    options: [
      { value: 'H', label: '高｜服务完全瘫痪·分高' },
      { value: 'L', label: '低｜部分受影响' },
      { value: 'N', label: '无｜不影响可用性·分低' },
    ],
  },
]

/** 选中某项时的即时解释（重点标注 PR/AC 等“字面与分数方向相反”的指标） */
const HINTS: Record<MetricKey, Record<string, string>> = {
  AV: {
    N: '攻击者可从互联网远程发起，利用门槛最低，权重最高(0.85)。',
    A: '需与目标处于同一网络（同网段/蓝牙等），权重0.62。',
    L: '需先在目标本机执行代码或本地登录，权重0.55。',
    P: '需物理接触设备才能利用，权重最低(0.20)。',
  },
  AC: {
    L: '攻击条件容易满足、可稳定复现，权重0.77，分更高。',
    H: '需特殊/苛刻条件、依赖竞争或特定配置、难稳定复现，权重0.44，分更低。',
  },
  PR: {
    N: '无需任何登录、未授权即可利用——最危险，权重0.85，分最高。',
    L: '攻击者需先拥有普通账号登录，S不变时权重0.62。',
    H: '指攻击者需先具备管理员等高权限才能利用，门槛最高、能打的人极少，S不变时权重仅0.27，故分更低（这不是说危害小，而是利用前提苛刻，方向并未写反）。',
  },
  UI: {
    N: '无需受害者做任何操作即可触发，权重0.85。',
    R: '需要受害者点击链接/打开文件等配合，权重0.62，分更低。',
  },
  S: {
    U: '漏洞影响仅限脆弱组件自身的安全边界。',
    C: '漏洞可突破边界、影响其他组件/提权到宿主，分数会被显著放大（×1.08，且 PR 改用 0.85/0.68/0.50 权重）。',
  },
  C: {
    H: '可读取大量敏感信息(影响系数0.56)。',
    L: '仅泄露少量/受限信息(0.22)。',
    N: '无机密信息泄露(0)。',
  },
  I: {
    H: '可任意篡改数据/写入(0.56)。',
    L: '仅能有限篡改(0.22)。',
    N: '无完整性影响(0)。',
  },
  A: {
    H: '可导致服务完全中断/崩溃(0.56)。',
    L: '仅造成有限中断或性能下降(0.22)。',
    N: '无可用性影响(0)。',
  },
}

const DEFAULT_VALUES: MetricValues = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }

const PRESET_CRITICAL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const PRESET_MEDIUM = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'

const RATING_BG: Record<string, string> = {
  Critical: 'bg-red-600',
  High: 'bg-orange-600',
  Medium: 'bg-amber-600',
  Low: 'bg-emerald-600',
  None: 'bg-slate-400',
}

const SEVERITY_OF_RATING: Record<string, string> = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  None: 'unknown',
}

/** 与 core/cvss.calculate 返回结构一致 */
interface CvssResult {
  base_score: number
  rating: string
  rating_cn: string
  vector: string
  scope_changed: boolean
  impact_subscore: number
  exploitability_subscore: number
  metrics: Array<{ metric: string; label: string; value: string; value_label: string }>
}

function isMetricKey(key: string): key is MetricKey {
  return METRICS.some((m) => m.key === key)
}

function buildVector(values: MetricValues): string {
  return 'CVSS:3.1/' + METRICS.map((m) => `${m.key}:${values[m.key]}`).join('/')
}

/** 把后端返回的规范向量回填到指标选择器（未识别的指标保留原值） */
function applyVector(vector: string, base: MetricValues): MetricValues {
  const next: MetricValues = { ...base }
  vector.split('/').forEach((part) => {
    const idx = part.indexOf(':')
    if (idx <= 0) return
    const key = part.slice(0, idx).trim().toUpperCase()
    const value = part.slice(idx + 1).trim().toUpperCase()
    if (!isMetricKey(key)) return
    const def = METRICS.find((m) => m.key === key)
    if (def && def.options.some((o) => o.value === value)) next[key] = value
  })
  return next
}

export function ToolCvss() {
  const toast = useToast()

  const [values, setValues] = useState<MetricValues>(DEFAULT_VALUES)
  const [vectorInput, setVectorInput] = useState(() => buildVector(DEFAULT_VALUES))
  const [result, setResult] = useState<CvssResult | null>(null)
  const [loading, setLoading] = useState(false)

  const calculate = useCallback(
    async (vector: string) => {
      setLoading(true)
      try {
        const res = await api.post<CvssResult>('/api/tools/cvss', { vector })
        const data = res.data
        if (!data) {
          toast.error('计算失败：返回数据为空')
          return null
        }
        setResult(data)
        return data
      } catch (e) {
        toast.error(e instanceof Error ? e.message : '计算失败')
        return null
      } finally {
        setLoading(false)
      }
    },
    [toast],
  )

  useEffect(() => {
    void calculate(buildVector(DEFAULT_VALUES))
  }, [calculate])

  function onMetricChange(key: MetricKey, value: string) {
    const next: MetricValues = { ...values, [key]: value }
    setValues(next)
    const vector = buildVector(next)
    setVectorInput(vector)
    void calculate(vector)
  }

  /** 用输入框中的向量计算，并把结果回填到选择器 */
  async function applyInputVector(vector: string) {
    setVectorInput(vector)
    const data = await calculate(vector)
    if (!data) return
    setValues(applyVector(data.vector, values))
    setVectorInput(data.vector)
  }

  async function useInReport() {
    if (!result) {
      toast.error('请先完成评分')
      return
    }
    const sev = SEVERITY_OF_RATING[result.rating] || 'unknown'
    try {
      await navigator.clipboard.writeText(result.vector)
      toast.success(`向量已复制，等级：${result.rating_cn}（可在报告中选用 ${sev}）`)
    } catch {
      toast.info(`等级：${result.rating_cn}`)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="CVSS v3.1 基础评分计算器"
        description="选择 8 项基础指标或直接粘贴向量串，按 FIRST.org 规范计算基础分、等级与子分。"
      />

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <Card>
          <CardHeader
            title="基础指标（Base Metrics）"
            actions={
              <>
                <Button size="sm" variant="ghost" onClick={() => void applyInputVector(PRESET_CRITICAL)}>
                  严重示例
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void applyInputVector(PRESET_MEDIUM)}>
                  中危示例
                </Button>
              </>
            }
          />
          <CardBody className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              {METRICS.map((m) => {
                const hint = HINTS[m.key][values[m.key]] || ''
                const highlight = m.key === 'PR' || m.key === 'AC'
                return (
                  <Field
                    key={m.key}
                    label={`${m.name}（${m.key}）`}
                    hint={
                      hint ? (
                        <span className={highlight ? 'text-amber-600' : undefined}>{hint}</span>
                      ) : undefined
                    }
                  >
                    <Select value={values[m.key]} onChange={(e) => onMetricChange(m.key, e.target.value)}>
                      {m.options.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </Select>
                  </Field>
                )
              })}
            </div>

            <div className="rounded-md border border-line border-l-2 border-l-primary bg-slate-50 px-3.5 py-3 text-[12.5px] leading-6 text-slate-600">
              <b className="text-slate-800">
                指标方向说明（越“容易被利用 / 影响越大”，得分越高，符合 FIRST.org CVSS v3.1 规范）：
              </b>
              <br />
              · 攻击向量 AV：<b>网络(N) &gt; 邻接(A) &gt; 本地(L) &gt; 物理(P)</b>，远程可达分数更高；
              <br />
              · 攻击复杂度 AC：<b>低(L) &gt; 高(H)</b>；用户交互 UI：<b>无需(N) &gt; 需要(R)</b>；
              <br />
              · 所需权限 PR：<b>无(N) &gt; 低(L) &gt; 高(H)</b>。这里“高”指
              <b>攻击者需要具备高权限才能利用</b>，门槛高、更难打，所以分数更低，并非写反；
              <br />
              · 机密性/完整性/可用性影响 C/I/A：<b>高(H) &gt; 低(L) &gt; 无(N)</b>；
              <br />
              · 影响范围 S=改变(C) 且需要权限时，PR 权重按规范取另一套数值（低=0.68 / 高=0.50），属正常现象。
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Input
                value={vectorInput}
                onChange={(e) => setVectorInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void applyInputVector(vectorInput.trim())
                }}
                placeholder={PRESET_CRITICAL}
                className="min-w-[280px] flex-1 font-mono"
              />
              <Button
                variant="primary"
                icon={<Calculator size={14} />}
                loading={loading}
                onClick={() => void applyInputVector(vectorInput.trim())}
              >
                解析向量
              </Button>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="评分结果" />
          <CardBody className="text-center">
            <div
              className={cn(
                'mx-auto mb-3 flex h-[150px] w-[150px] flex-col items-center justify-center rounded-full text-white transition-colors',
                result ? RATING_BG[result.rating] || 'bg-slate-400' : 'bg-slate-400',
              )}
            >
              <div className="tnum text-[40px] font-black leading-none">
                {result ? result.base_score.toFixed(1) : '-'}
              </div>
              <div className="mt-1 text-xs opacity-90">
                {result ? `${result.rating_cn} / ${result.rating}` : '待计算'}
              </div>
            </div>

            <div className="text-left">
              <KV label="向量串">
                <span className="break-all font-mono text-[11px]">{result ? result.vector : '-'}</span>
              </KV>
              <KV label="影响性子分">{result ? result.impact_subscore : '-'}</KV>
              <KV label="可利用性子分">{result ? result.exploitability_subscore : '-'}</KV>
              <KV label="影响范围">
                {result ? (result.scope_changed ? '改变（Changed）' : '不变（Unchanged）') : '-'}
              </KV>
            </div>

            <Button
              variant="success"
              block
              className="mt-3.5"
              icon={<Copy size={14} />}
              onClick={() => void useInReport()}
            >
              将等级用于漏洞报告
            </Button>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
