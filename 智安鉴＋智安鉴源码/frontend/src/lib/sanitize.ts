/**
 * 极简 HTML 清洗：报告正文可能来自 AI 返回内容，直接 dangerouslySetInnerHTML 前
 * 必须去掉脚本、内联事件与 javascript: 协议，避免在同源会话下执行任意代码。
 */
const BLOCKED_TAGS = ['script', 'style', 'iframe', 'object', 'embed', 'link', 'meta', 'form', 'base']

export function sanitizeHtml(html?: string | null): string {
  if (!html) return ''
  const doc = new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html')
  const root = doc.getElementById('root')
  if (!root) return ''

  BLOCKED_TAGS.forEach((tag) => {
    root.querySelectorAll(tag).forEach((el) => el.remove())
  })

  root.querySelectorAll<HTMLElement>('*').forEach((el) => {
    Array.from(el.attributes).forEach((attr) => {
      const name = attr.name.toLowerCase()
      const value = attr.value.trim().toLowerCase()
      if (name.startsWith('on')) el.removeAttribute(attr.name)
      else if ((name === 'href' || name === 'src' || name === 'xlink:href') && value.startsWith('javascript:')) {
        el.removeAttribute(attr.name)
      }
    })
  })

  return root.innerHTML
}
