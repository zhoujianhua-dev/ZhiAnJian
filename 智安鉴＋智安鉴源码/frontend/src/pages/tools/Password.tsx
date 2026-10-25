import { useState } from 'react'
import { Copy, Play } from 'lucide-react'
import { Card, CardBody, CardHeader, PageIntro } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Checkbox, Field, Input } from '@/components/ui/field'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import { TOOL_ICONS } from '@/layout/nav'

const Icon = TOOL_ICONS['/tools/password']

interface CharTypes {
  uppercase: boolean
  lowercase: boolean
  numbers: boolean
  special: boolean
}

const DEFAULT_TYPES: CharTypes = { uppercase: true, lowercase: true, numbers: true, special: true }

export function ToolPassword() {
  const toast = useToast()

  const [length, setLength] = useState('12')
  const [count, setCount] = useState('10')
  const [types, setTypes] = useState<CharTypes>(DEFAULT_TYPES)
  const [passwords, setPasswords] = useState<string[]>([])
  const [loading, setLoading] = useState(false)

  async function generate() {
    if (!types.uppercase && !types.lowercase && !types.numbers && !types.special) {
      toast.error('请选择至少 1 个字符类型')
      return
    }
    setLoading(true)
    try {
      const res = await api.post<string[]>('/api/tools/password', {
        length: parseInt(length, 10) || 12,
        count: parseInt(count, 10) || 10,
        uppercase: types.uppercase,
        lowercase: types.lowercase,
        numbers: types.numbers,
        special: types.special,
      })
      setPasswords(res.data || [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '生成失败')
    } finally {
      setLoading(false)
    }
  }

  async function copyAll() {
    if (!passwords.length) return
    try {
      await navigator.clipboard.writeText(passwords.join('\n'))
      toast.success('已复制到剪贴板')
    } catch {
      toast.error('复制失败，请手动选择')
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PageIntro
        icon={<Icon size={18} />}
        title="随机密码生成"
        description="按长度与字符类型批量生成随机口令，用于弱口令测试、账号初始化等场景。"
      />

      <Card>
        <CardHeader title="生成参数" description="长度 4-128，数量 1-100，至少选择 1 种字符类型。" />
        <CardBody className="flex flex-col gap-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:max-w-[420px]">
            <Field label="密码长度">
              <Input
                type="number"
                min={4}
                max={128}
                value={length}
                onChange={(e) => setLength(e.target.value)}
              />
            </Field>
            <Field label="生成数量">
              <Input
                type="number"
                min={1}
                max={100}
                value={count}
                onChange={(e) => setCount(e.target.value)}
              />
            </Field>
          </div>

          <Field label="字符类型">
            <div className="flex flex-wrap gap-x-5 gap-y-2 pt-0.5">
              <Checkbox
                label="大写字母 (A-Z)"
                checked={types.uppercase}
                onChange={(e) => setTypes({ ...types, uppercase: e.target.checked })}
              />
              <Checkbox
                label="小写字母 (a-z)"
                checked={types.lowercase}
                onChange={(e) => setTypes({ ...types, lowercase: e.target.checked })}
              />
              <Checkbox
                label="数字 (0-9)"
                checked={types.numbers}
                onChange={(e) => setTypes({ ...types, numbers: e.target.checked })}
              />
              <Checkbox
                label="特殊符号 (!@#...)"
                checked={types.special}
                onChange={(e) => setTypes({ ...types, special: e.target.checked })}
              />
            </div>
          </Field>

          <div>
            <Button variant="primary" icon={<Play size={14} />} loading={loading} onClick={generate}>
              生成密码
            </Button>
          </div>
        </CardBody>

        {passwords.length ? (
          <CardBody className="flex flex-col gap-3 border-t border-line">
            <div className="overflow-hidden rounded-md border border-line">
              <ul className="divide-y divide-line">
                {passwords.map((pwd, i) => (
                  <li key={`${i}-${pwd}`} className="flex items-baseline gap-3 bg-slate-50 px-3 py-1.5">
                    <span className="tnum w-6 shrink-0 text-right text-xs text-slate-400">{i + 1}</span>
                    <code className="min-w-0 break-all font-mono text-[13px] tracking-wide text-slate-800">
                      {pwd}
                    </code>
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button size="sm" variant="ghost" icon={<Copy size={13} />} onClick={copyAll}>
                复制全部
              </Button>
              <span className="text-xs text-slate-400">共 {passwords.length} 条</span>
            </div>
          </CardBody>
        ) : null}
      </Card>
    </div>
  )
}
