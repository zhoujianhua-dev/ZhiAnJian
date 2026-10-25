import { useRef, useState } from 'react'
import { ImagePlus, Loader2, X } from 'lucide-react'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { useToast } from './toast'

interface ImageZoneProps {
  value: string[]
  onChange: (urls: string[]) => void
  hint?: string
  /** 上传接口，默认 /api/upload/image */
  uploadUrl?: string
  className?: string
}

/**
 * 多图上传区：多选/拖拽上传、点击预览、删除、拖拽排序。
 * 与旧前端 imageZone 行为一致，值统一为 URL 数组。
 */
export function ImageZone({ value, onChange, hint, uploadUrl = '/api/upload/image', className }: ImageZoneProps) {
  const toast = useToast()
  const [uploading, setUploading] = useState(0)
  const [over, setOver] = useState(false)
  const dragIndex = useRef<number | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  async function upload(files: File[]) {
    if (!files.length) return
    setUploading((n) => n + files.length)
    const added: string[] = []
    for (const file of files) {
      const fd = new FormData()
      fd.append('file', file)
      try {
        const res = await api.upload<{ location: string }>(uploadUrl, fd)
        if (res.data?.location) added.push(res.data.location)
        else toast.error(res.msg || `${file.name} 上传失败`)
      } catch (e) {
        toast.error(e instanceof Error ? e.message : '图片上传失败')
      } finally {
        setUploading((n) => n - 1)
      }
    }
    if (added.length) onChange([...value, ...added])
  }

  function move(from: number, to: number) {
    if (from === to) return
    const next = value.slice()
    const [moved] = next.splice(from, 1)
    next.splice(to, 0, moved)
    onChange(next)
  }

  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        multiple
        className="hidden"
        onChange={(e) => {
          void upload(Array.from(e.target.files || []))
          e.target.value = ''
        }}
      />
      <button
        type="button"
        onClick={() => fileRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault()
          setOver(true)
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setOver(false)
          void upload(Array.from(e.dataTransfer.files || []))
        }}
        className={cn(
          'flex items-center gap-2 rounded-md border border-dashed px-3 py-2.5 text-left text-[13px] transition-colors',
          over
            ? 'border-primary bg-primary-soft text-primary'
            : 'border-line-strong bg-slate-50 text-slate-500 hover:border-primary hover:text-primary',
        )}
      >
        {uploading > 0 ? <Loader2 size={15} className="animate-spin" /> : <ImagePlus size={15} />}
        <span className="min-w-0 flex-1 truncate">
          {uploading > 0 ? `正在上传 ${uploading} 张…` : hint || '点击选择或拖拽图片到此处（支持多张）'}
        </span>
        {value.length ? <span className="shrink-0 text-xs text-primary">已上传 {value.length} 张</span> : null}
      </button>

      {value.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {value.map((url, index) => (
            <div
              key={`${url}-${index}`}
              draggable
              onDragStart={() => {
                dragIndex.current = index
              }}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault()
                if (dragIndex.current !== null) move(dragIndex.current, index)
                dragIndex.current = null
              }}
              className="group relative h-[76px] w-[100px] cursor-grab overflow-hidden rounded border border-line bg-white"
            >
              <img
                src={url}
                alt={`图片 ${index + 1}`}
                className="h-full w-full object-cover"
                onClick={() => window.open(url, '_blank', 'noopener')}
              />
              <button
                type="button"
                onClick={() => onChange(value.filter((_, i) => i !== index))}
                className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-slate-900/60 text-white opacity-0 transition-opacity hover:bg-red-600 group-hover:opacity-100"
                aria-label="删除图片"
              >
                <X size={10} />
              </button>
              <span className="absolute bottom-1 left-1 rounded bg-slate-900/60 px-1 text-[10px] text-white">
                {index + 1}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}
