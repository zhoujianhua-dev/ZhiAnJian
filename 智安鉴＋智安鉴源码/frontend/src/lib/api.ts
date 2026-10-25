/**
 * 统一 API 客户端
 * - 自动携带 CSRF Token（POST 时）
 * - 登录失效（401 + need_login）统一跳转登录页，并带上来路
 * - 非 2xx 或业务 code!==0 抛 ApiError，页面只需 catch 后 toast
 */

export interface ApiResp<T = unknown> {
  code: number
  msg?: string
  data?: T
  count?: number
  [key: string]: unknown
}

export class ApiError extends Error {
  status: number
  code: number
  constructor(message: string, status = 0, code = -1) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

let csrfToken: string | null = null
let csrfPending: Promise<string> | null = null

export function ensureCsrf(): Promise<string> {
  if (csrfToken) return Promise.resolve(csrfToken)
  if (!csrfPending) {
    csrfPending = fetch('/api/csrf', { credentials: 'same-origin' })
      .then((r) => r.json())
      .then((j: { token?: string }) => {
        csrfToken = j.token || ''
        return csrfToken
      })
      .catch(() => '')
      .finally(() => {
        csrfPending = null
      })
  }
  return csrfPending
}

export function resetCsrf() {
  csrfToken = null
}

function buildQuery(params?: Record<string, string | number | boolean | null | undefined>) {
  if (!params) return ''
  const sp = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => {
    if (v === null || v === undefined || v === '') return
    sp.append(k, String(v))
  })
  const q = sp.toString()
  return q ? `?${q}` : ''
}

type Method = 'GET' | 'POST'

interface RequestOptions {
  method?: Method
  json?: unknown
  form?: FormData
  query?: Record<string, string | number | boolean | null | undefined>
  /** 登录失效时不跳转（登录页自身使用） */
  noRedirect?: boolean
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<ApiResp<T>> {
  const method: Method = opts.method || (opts.json !== undefined || opts.form ? 'POST' : 'GET')
  const headers: Record<string, string> = {}
  let body: BodyInit | undefined

  if (opts.form) {
    body = opts.form
  } else if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.json)
  }
  if (method === 'POST') {
    // 文件上传同样带 CSRF 头（后端只豁免 /api/upload/ 等少数接口）
    headers['X-CSRF-Token'] = await ensureCsrf()
  }

  let resp: Response
  try {
    resp = await fetch(path + buildQuery(opts.query), {
      method,
      headers,
      body,
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError('网络异常，请检查服务是否在运行', 0, -1)
  }

  const contentType = resp.headers.get('content-type') || ''
  let payload: (ApiResp<T> & { need_login?: boolean }) | null = null
  if (contentType.includes('application/json')) {
    try {
      payload = (await resp.json()) as ApiResp<T> & { need_login?: boolean }
    } catch {
      payload = null
    }
  }

  if (resp.status === 401 && payload?.need_login && !opts.noRedirect) {
    const next = encodeURIComponent(location.pathname + location.search)
    location.replace(`/login?next=${next}`)
    throw new ApiError(payload.msg || '登录已失效', 401, 1)
  }
  if (!resp.ok) {
    throw new ApiError(payload?.msg || `请求失败（${resp.status}）`, resp.status, payload?.code ?? -1)
  }
  if (!payload) {
    throw new ApiError('服务返回了非 JSON 响应', resp.status, -1)
  }
  if (payload.code !== 0) {
    throw new ApiError(payload.msg || '操作失败', resp.status, payload.code)
  }
  return payload
}

export const api = {
  get: <T>(path: string, query?: RequestOptions['query']) => request<T>(path, { method: 'GET', query }),
  post: <T>(path: string, json?: unknown, query?: RequestOptions['query']) =>
    request<T>(path, { method: 'POST', json: json ?? {}, query }),
  upload: <T>(path: string, form: FormData) => request<T>(path, { method: 'POST', form }),
  raw: request,
}

/** 触发浏览器下载（导出报告、模板等） */
export function downloadFile(url: string, filename?: string) {
  const a = document.createElement('a')
  a.href = url
  if (filename) a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
}

/** 文件选择对话框（Promise 版，取消时 resolve(null)） */
export function pickFile(accept?: string, multiple = false): Promise<File[] | null> {
  return new Promise((resolve) => {
    const input = document.createElement('input')
    input.type = 'file'
    if (accept) input.accept = accept
    input.multiple = multiple
    input.style.display = 'none'
    // 必须挂到文档里：部分浏览器对游离节点的 click() 不弹选择框
    document.body.appendChild(input)
    const done = (files: File[] | null) => {
      input.remove()
      resolve(files)
    }
    input.onchange = () => done(input.files ? Array.from(input.files) : null)
    input.addEventListener('cancel', () => done(null))
    input.click()
  })
}
