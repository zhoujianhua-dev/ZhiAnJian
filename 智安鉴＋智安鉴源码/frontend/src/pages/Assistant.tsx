import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, Loader2, Send, ShieldCheck, Trash2 } from 'lucide-react'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Checkbox, Textarea } from '@/components/ui/field'
import { RichTextView } from '@/components/ui/rich-text'
import { useConfirm } from '@/components/ui/confirm'
import { api, ensureCsrf } from '@/lib/api'
import { useQuery } from '@/lib/use-query'
import { cn } from '@/lib/cn'

/* ---------------- 类型 ---------------- */

interface ChatMsg {
  id: number
  role: 'user' | 'assistant'
  content: string
  /** 正在流式接收 */
  streaming?: boolean
  /** 欢迎语等仅展示、不计入对话历史 */
  transient?: boolean
}

interface ChatHistoryItem {
  role: 'user' | 'assistant'
  content: string
}

interface AiConfigStatus {
  base_url?: string
  model?: string
  api_key_masked?: string
  configured?: boolean
}

interface ChatReplyData {
  reply?: string
  mock?: boolean
}

interface SsePayload {
  delta?: string
  phase?: string
  error?: string
}

/* ---------------- 常量 ---------------- */

const MOCK_KEY = 'sk-test-mock'

const WELCOME =
  '你好，我是智安鉴内置的网络安全专家助手。\n' +
  '可以帮你：分析漏洞原理、设计检测步骤、编写整改建议、生成修复代码、规范报告内容。\n' +
  '直接输入问题开始对话吧。'

const QUICK_QUESTIONS = [
  'SQL 注入怎么检测和修复？',
  '帮我分析一个未授权访问漏洞的整改方案',
  '渗透测试报告的检测过程怎么写才规范？',
  'Fastjson 反序列化漏洞原理与防御',
]

/**
 * 流式对话：直接 fetch 读 ReadableStream（api.post 会 await 整个响应体，无法逐段渲染）。
 * 服务端 SSE 每行形如 `data: {"delta":"..."}` / `{"phase":"thinking"}` / `{"error":"..."}`，以 `data: [DONE]` 结束。
 * 返回累计正文；浏览器不支持流式读取时返回空串，由调用方走非流式回退。
 */
async function streamReply(
  payload: { api_key: string; history: ChatHistoryItem[]; stream: true },
  onText: (text: string) => void,
): Promise<string> {
  const resp = await fetch('/api/ai/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': await ensureCsrf() },
    body: JSON.stringify(payload),
    credentials: 'same-origin',
  })
  if (!resp.ok) {
    const err = (await resp.json().catch(() => null)) as { msg?: string } | null
    throw new Error(err?.msg || `请求失败（${resp.status}）`)
  }
  if (!resp.body) return ''

  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  let full = ''

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    const parts = buf.split('\n\n')
    buf = parts.pop() ?? ''
    for (const part of parts) {
      const line = part.trim()
      if (!line.startsWith('data:')) continue
      const text = line.slice(5).trim()
      if (text === '[DONE]') continue
      let obj: SsePayload
      try {
        obj = JSON.parse(text) as SsePayload
      } catch {
        continue
      }
      // 推理模型先思考后作答：给出等待反馈，避免长时间空白像“卡住”
      if (obj.phase === 'thinking' && !full) onText('🤔 模型正在思考中，请稍候…')
      if (obj.delta) {
        full += obj.delta
        onText(full)
      }
      if (obj.error) {
        full += '\n[错误] ' + obj.error
        onText(full)
      }
    }
  }

  return full
}

/* ---------------- 页面 ---------------- */

export function Assistant() {
  const confirm = useConfirm()
  const [messages, setMessages] = useState<ChatMsg[]>([
    { id: 0, role: 'assistant', content: WELCOME, transient: true },
  ])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [mock, setMock] = useState(false)

  const seq = useRef(0)
  const busy = useRef(false)
  const boxRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  const loadConfig = useCallback(async () => {
    const res = await api.get<AiConfigStatus>('/api/ai/config')
    return res.data as AiConfigStatus
  }, [])
  const config = useQuery(loadConfig, [loadConfig])

  const configured = !!config.data?.configured

  useEffect(() => {
    const el = boxRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages])

  function nextId() {
    seq.current += 1
    return seq.current
  }

  async function send(text?: string) {
    if (sending || busy.current) return
    const q = (text ?? input).trim()
    if (!q) return
    busy.current = true

    setInput('')
    const history: ChatHistoryItem[] = [
      ...messages
        .filter((m) => !m.transient && m.content.trim())
        .map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: q },
    ]

    const userId = nextId()
    const aiId = nextId()
    const update = (content: string) => {
      setMessages((prev) => prev.map((m) => (m.id === aiId ? { ...m, content } : m)))
    }
    setMessages((prev) => [
      ...prev,
      { id: userId, role: 'user', content: q },
      { id: aiId, role: 'assistant', content: '', streaming: true },
    ])
    setSending(true)

    const apiKey = mock ? MOCK_KEY : ''
    let full = ''
    let failure = ''
    try {
      full = await streamReply({ api_key: apiKey, history, stream: true }, update)
      if (!full) {
        // 流式没有正文（浏览器不支持流式读取 / 上游未下发 content）→ 非流式回退一次
        const res = await api.post<ChatReplyData>('/api/ai/chat', { api_key: apiKey, history, stream: false })
        full = res.data?.reply || ''
      }
    } catch (e) {
      failure = e instanceof Error ? e.message : '请求异常'
    }

    if (!full) {
      full = failure ? `请求失败：${failure}（可在系统设置配置 AI，或勾选模拟模式）` : '（无回复）'
    }

    setMessages((prev) => prev.map((m) => (m.id === aiId ? { ...m, content: full, streaming: false } : m)))
    setSending(false)
    busy.current = false
    inputRef.current?.focus()
  }

  async function clearChat() {
    if (sending) return
    const ok = await confirm({ message: '确定清空当前对话？历史消息将不可恢复。', confirmText: '清空' })
    if (!ok) return
    setMessages([{ id: nextId(), role: 'assistant', content: WELCOME, transient: true }])
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-col">
        <CardHeader
          title={
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck size={15} className="text-primary" />
              网络安全专家 Copilot
            </span>
          }
          description="AI / 渗透测试专家 Copilot"
          actions={
            <>
              <Badge tone={mock ? 'amber' : configured ? 'emerald' : 'slate'}>
                {mock ? '模拟模式' : configured ? '已配置' : '未配置'}
              </Badge>
              <Checkbox
                label="模拟模式（无需 Key）"
                checked={mock}
                onChange={(e) => setMock(e.target.checked)}
              />
              <Button
                size="sm"
                variant="ghost"
                icon={<Trash2 size={14} />}
                disabled={sending}
                onClick={() => void clearChat()}
              >
                清空对话
              </Button>
            </>
          }
        />

        <CardBody className="flex flex-col gap-3">
          {!configured && !mock ? (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>
                尚未配置 AI 接口：请到「系统设置 → AI 接口配置」填写 API Key，或勾选右上角「模拟模式（无需
                Key）」先用模拟回复体验。
              </span>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2">
            {QUICK_QUESTIONS.map((q) => (
              <button
                key={q}
                type="button"
                disabled={sending}
                onClick={() => void send(q)}
                className="rounded-full border border-line bg-white px-3 py-1 text-xs text-slate-600 transition-colors hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>

          <div
            ref={boxRef}
            className="flex max-h-[calc(100vh-380px)] min-h-[320px] flex-col gap-3 overflow-y-auto rounded-md border border-line bg-slate-50 p-3"
          >
            {messages.map((m) => (
              <div key={m.id} className={cn('flex gap-2.5', m.role === 'user' && 'flex-row-reverse')}>
                <span
                  className={cn(
                    'flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-[12px] font-bold text-white',
                    m.role === 'user' ? 'bg-sky-600' : 'bg-primary',
                  )}
                >
                  {m.role === 'user' ? '我' : 'AI'}
                </span>
                <div
                  className={cn(
                    'min-w-0 max-w-[82%] rounded-md border px-3 py-2 text-[13.5px] leading-6 text-slate-800',
                    m.role === 'user' ? 'border-sky-200 bg-sky-50' : 'border-line bg-white',
                  )}
                >
                  {m.content ? (
                    m.role === 'assistant' ? (
                      <RichTextView html={m.content} className="whitespace-pre-wrap break-words" />
                    ) : (
                      <p className="whitespace-pre-wrap break-words">{m.content}</p>
                    )
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-slate-400">
                      {m.streaming ? (
                        <>
                          <Loader2 size={13} className="animate-spin" />
                          正在生成…
                        </>
                      ) : (
                        '（无回复）'
                      )}
                    </span>
                  )}
                  {m.streaming && m.content ? (
                    <span className="ml-1 text-primary">▋</span>
                  ) : null}
                </div>
              </div>
            ))}
          </div>

          <div className="flex flex-col gap-2">
            <Textarea
              ref={inputRef}
              rows={3}
              className="resize-none"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  void send()
                }
              }}
              placeholder="输入你的安全问题，Enter 发送 / Shift+Enter 换行"
            />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11.5px] text-slate-400">回答由 AI 生成，仅供授权安全测试与学习参考</span>
              <Button
                size="sm"
                variant="primary"
                icon={<Send size={14} />}
                loading={sending}
                onClick={() => void send()}
              >
                发送
              </Button>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}
