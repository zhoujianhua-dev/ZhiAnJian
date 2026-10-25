import type { LucideIcon } from 'lucide-react'
import {
  Bot,
  Boxes,
  Building2,
  FileText,
  Gauge,
  Globe,
  KeyRound,
  LayoutGrid,
  ListOrdered,
  Radar,
  ScanSearch,
  Settings,
  ShieldAlert,
  Tags,
  FileDiff,
  Users,
  Wrench,
} from 'lucide-react'

export interface NavChild {
  to: string
  label: string
}

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  adminOnly?: boolean
  children?: NavChild[]
}

export interface NavGroup {
  title?: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    items: [{ to: '/', label: '仪表盘', icon: Gauge }],
  },
  {
    title: '业务管理',
    items: [
      {
        to: '/units',
        label: '单位管理',
        icon: Building2,
        children: [
          { to: '/units', label: '单位列表' },
          { to: '/tags', label: '单位标签' },
        ],
      },
      { to: '/domains', label: '域名资产', icon: Globe },
      { to: '/vulnerabilities', label: '漏洞库', icon: ShieldAlert },
      { to: '/scanner', label: 'AI 漏洞扫描', icon: Radar },
      { to: '/reports', label: '报告管理', icon: FileText },
      { to: '/reports/ai', label: 'AI 智能生成', icon: Boxes },
      { to: '/assistant', label: 'AI 安全助手', icon: Bot },
    ],
  },
  {
    title: '工具箱',
    items: [
      {
        to: '/tools/password',
        label: '工具管理',
        icon: Wrench,
        children: [
          { to: '/tools/password', label: '随机密码生成' },
          { to: '/tools/dedup', label: '文本去重' },
          { to: '/tools/urls', label: '提取域名/IP' },
          { to: '/tools/compare', label: 'A/B 文件对比' },
          { to: '/tools/classify', label: '资产分类' },
          { to: '/tools/cvss', label: 'CVSS 评分计算' },
        ],
      },
    ],
  },
  {
    title: '系统',
    items: [
      { to: '/users', label: '用户管理', icon: Users, adminOnly: true },
      { to: '/settings', label: '系统设置', icon: Settings },
    ],
  },
]

/** 工具页图标（PageIntro 用） */
export const TOOL_ICONS: Record<string, LucideIcon> = {
  '/tools/password': KeyRound,
  '/tools/dedup': ListOrdered,
  '/tools/urls': Globe,
  '/tools/compare': FileDiff,
  '/tools/classify': LayoutGrid,
  '/tools/cvss': ScanSearch,
}

interface Crumb {
  group?: string
  title: string
}

/** 根据路径解析顶栏面包屑（与侧栏高亮同一份配置） */
export function resolveCrumb(pathname: string): Crumb {
  const normalized = pathname.replace(/\/+$/, '') || '/'
  for (const group of NAV_GROUPS) {
    for (const item of group.items) {
      // 先匹配子项：工具的父项本身也是一个子路由（/tools/password），
      // 否则「随机密码生成」会被父级标题「工具管理」覆盖
      const child = item.children?.find((c) => c.to === normalized)
      if (child) return { group: group.title, title: child.label }
      if (item.to === normalized) return { group: group.title, title: item.label }
    }
  }
  if (normalized === '/login') return { title: '登录' }
  return { title: '页面不存在' }
}

export function isItemActive(item: NavItem, pathname: string) {
  const normalized = pathname.replace(/\/+$/, '') || '/'
  if (item.to === normalized) return true
  return !!item.children?.some((c) => c.to === normalized)
}
