import { useEffect, useRef, useState } from 'react'
import {
  Bold,
  Code2,
  Heading2,
  Image as ImageIcon,
  Italic,
  List,
  ListOrdered,
  Underline,
} from 'lucide-react'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { sanitizeHtml } from '@/lib/sanitize'
import { useToast } from './toast'

interface RichTextEditorProps {
  value: string
  onChange: (html: string) => void
  placeholder?: string
  minHeight?: number
  disabled?: boolean
  className?: string
}

type Cmd = 'bold' | 'italic' | 'underline' | 'h2' | 'ul' | 'ol' | 'code' | 'img'

const TOOLS: Array<{ cmd: Cmd; title: string; icon: React.ReactNode }> = [
  { cmd: 'bold', title: '加粗', icon: <Bold size={13} /> },
  { cmd: 'italic', title: '斜体', icon: <Italic size={13} /> },
  { cmd: 'underline', title: '下划线', icon: <Underline size={13} /> },
  { cmd: 'h2', title: '小标题', icon: <Heading2 size={14} /> },
  { cmd: 'ul', title: '无序列表', icon: <List size={14} /> },
  { cmd: 'ol', title: '有序列表', icon: <ListOrdered size={14} /> },
  { cmd: 'code', title: '代码样式', icon: <Code2 size={14} /> },
  { cmd: 'img', title: '插入图片', icon: <ImageIcon size={14} /> },
]

/** 轻量富文本编辑器：满足检测过程/归属证明的排版与插图需求 */
export function RichTextEditor({
  value,
  onChange,
  placeholder = '支持加粗、列表、代码与插图…',
  minHeight = 140,
  disabled,
  className,
}: RichTextEditorProps) {
  const toast = useToast()
  const ref = useRef<HTMLDivElement>(null)
  const lastHtml = useRef(value)
  const fileRef = useRef<HTMLInputElement>(null)
  const [focused, setFocused] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (value !== lastHtml.current) {
      el.innerHTML = value || ''
      lastHtml.current = value
    }
  }, [value])

  function sync() {
    const el = ref.current
    if (!el) return
    const html = el.innerHTML.replace(/<div><br><\/div>/g, '').replace(/<p><br><\/p>/g, '')
    lastHtml.current = html
    onChange(html)
  }

  function exec(cmd: Cmd) {
    const el = ref.current
    if (!el || disabled) return
    if (cmd === 'img') {
      fileRef.current?.click()
      return
    }
    el.focus()
    if (cmd === 'h2') document.execCommand('formatBlock', false, 'h4')
    else if (cmd === 'ul') document.execCommand('insertUnorderedList')
    else if (cmd === 'ol') document.execCommand('insertOrderedList')
    else if (cmd === 'code') document.execCommand('insertHTML', false, '<code>代码</code>')
    else document.execCommand(cmd)
    sync()
  }

  async function uploadAndInsert(files: File[]) {
    for (const file of files) {
      const fd = new FormData()
      fd.append('file', file)
      try {
        const res = await api.upload<{ location: string }>('/api/upload/image', fd)
        if (res.data?.location) {
          ref.current?.focus()
          document.execCommand('insertHTML', false, `<p><img src="${res.data.location}" style="max-width:100%"></p>`)
          sync()
        } else {
          toast.error(res.msg || '图片上传失败')
        }
      } catch (e) {
        toast.error(e instanceof Error ? e.message : '图片上传失败')
      }
    }
  }

  return (
    <div className={cn('flex flex-col', className)}>
      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={(e) => {
          void uploadAndInsert(Array.from(e.target.files || []))
          e.target.value = ''
        }}
      />
      <div className="flex flex-wrap items-center gap-0.5 rounded-t-md border border-line border-b-0 bg-slate-50 px-1.5 py-1">
        {TOOLS.map((t) => (
          <button
            key={t.cmd}
            type="button"
            title={t.title}
            disabled={disabled}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => exec(t.cmd)}
            className="flex h-7 min-w-7 items-center justify-center rounded px-1.5 text-slate-600 transition-colors hover:bg-slate-200 hover:text-slate-900 disabled:opacity-40"
          >
            {t.icon}
          </button>
        ))}
      </div>
      <div
        ref={ref}
        contentEditable={!disabled}
        role="textbox"
        aria-multiline="true"
        data-placeholder={placeholder}
        onInput={sync}
        onBlur={() => {
          setFocused(false)
          sync()
        }}
        onFocus={() => setFocused(true)}
        style={{ minHeight }}
        className={cn(
          'rich-text overflow-y-auto rounded-b-md border border-line bg-white px-3 py-2.5 text-slate-800 outline-none',
          focused && 'border-primary ring-2 ring-primary-line',
          disabled && 'bg-slate-50 text-slate-500',
        )}
      />
    </div>
  )
}

export function RichTextView({ html, className }: { html?: string | null; className?: string }) {
  const clean = sanitizeHtml(html)
  if (!clean) return <span className="text-slate-400">-</span>
  return <div className={cn('rich-text text-slate-700', className)} dangerouslySetInnerHTML={{ __html: clean }} />
}
