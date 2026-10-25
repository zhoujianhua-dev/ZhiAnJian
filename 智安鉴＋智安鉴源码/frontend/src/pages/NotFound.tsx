import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-line bg-surface py-24">
      <p className="text-4xl font-semibold text-slate-200">404</p>
      <p className="mt-2 text-[14px] font-medium text-slate-700">页面不存在</p>
      <p className="mt-1 text-[13px] text-slate-500">链接可能已失效，或地址输入有误。</p>
      <Link to="/" className="mt-4">
        <Button variant="primary">返回仪表盘</Button>
      </Link>
    </div>
  )
}
