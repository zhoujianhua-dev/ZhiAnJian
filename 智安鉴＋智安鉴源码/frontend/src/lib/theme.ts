/**
 * 主题注入：把「系统设置 → 主题色」的十六进制色换算成整套 CSS 变量。
 * 用纯色派生 hover / soft / line，保证任意主色都能保持扁平风格的层级关系。
 */
function clamp(n: number) {
  return Math.max(0, Math.min(255, Math.round(n)))
}

function parseHex(hex: string): [number, number, number] | null {
  const m = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex.trim())
  if (!m) return null
  let s = m[1]
  if (s.length === 3) s = s.split('').map((c) => c + c).join('')
  return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)]
}

function toHex([r, g, b]: [number, number, number]) {
  return '#' + [r, g, b].map((v) => clamp(v).toString(16).padStart(2, '0')).join('')
}

/** 与白色混合，ratio 为白色占比 */
function tint(rgb: [number, number, number], ratio: number) {
  return toHex(rgb.map((v) => v + (255 - v) * ratio) as [number, number, number])
}

/** 与黑色混合，ratio 为黑色占比 */
function shade(rgb: [number, number, number], ratio: number) {
  return toHex(rgb.map((v) => v * (1 - ratio)) as [number, number, number])
}

export function applyThemeColor(color?: string) {
  const rgb = parseHex(color || '') || [37, 99, 235]
  const root = document.documentElement.style
  root.setProperty('--primary', toHex(rgb))
  root.setProperty('--primary-hover', shade(rgb, 0.16))
  root.setProperty('--primary-soft', tint(rgb, 0.93))
  root.setProperty('--primary-line', tint(rgb, 0.72))
}
