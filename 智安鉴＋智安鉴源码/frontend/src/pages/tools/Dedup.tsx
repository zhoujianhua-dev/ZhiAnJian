import { useState } from 'react'
import { Copy, Eraser } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Checkbox, Field, Textarea } from '@/components/ui/field'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/dedup']

const PLACEHOLDER = ['example.com', 'example.com', 'www.example.com', '192.168.1.1'].join('\n')

export function ToolDedup() {
  const toast = useToast()

  const [text, setText] = useState('')
  const [caseInsensitive, setCaseInsensitive] = useState(true)
  const [keepOrder, setKeepOrder] = useState(true)
  const [result, setResult] = useState('')
  const [count, setCount] = useState(0)
  const [loading, setLoading] = useState(false)

  async function dedup() {
    setLoading(true)
    try {
      const res = await api.post<string>('/api/tools/dedup', {
        text,
        case_insensitive: caseInsensitive,
        keep_order: keepOrder,
      })
      setResult(res.data || '')
      setCount(res.count || 0)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '去重失败')
    } finally {
      setLoading(false)
    }
  }

  async function copyResult() {
    if (!result) return
    try {
      await navigator.clipboard.writeText(result)
      toast.success('已复制')
    } catch {
      toast.error('复制失败')
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="文本去重"
        description="按行去重，自动忽略空行，可选择忽略大小写与保持原始顺序。"
      />

      <Card>
        <CardHeader title="数据清洗" description="适用于域名、IP、URL 等任意「每行一条」的文本。" />
        <CardBody className="flex flex-col gap-4">
          <Field label="输入文本（每行一条，支持域名/IP/URL 等任意文本）">
            <Textarea
              rows={10}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={PLACEHOLDER}
            />
          </Field>

          <div className="flex flex-wrap items-center gap-4">
            <Button variant="primary" icon={<Eraser size={14} />} loading={loading} onClick={dedup}>
              去重
            </Button>
            <Checkbox
              label="忽略大小写"
              checked={caseInsensitive}
              onChange={(e) => setCaseInsensitive(e.target.checked)}
            />
            <Checkbox
              label="保持原顺序"
              checked={keepOrder}
              onChange={(e) => setKeepOrder(e.target.checked)}
            />
          </div>

          <Field label={`去重结果（${count} 条）`}>
            <Textarea rows={10} value={result} readOnly className="bg-slate-50" />
          </Field>

          <div>
            <Button size="sm" variant="ghost" icon={<Copy size={13} />} onClick={copyResult}>
              复制结果
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}
