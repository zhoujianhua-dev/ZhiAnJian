import clsx, { type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * 合并类名：clsx 负责条件拼接，tailwind-merge 负责消解冲突
 * （例如组件默认 `w-full` 被调用方的 `w-[220px]` 覆盖时，只保留后者）
 */
export function cn(...args: ClassValue[]) {
  return twMerge(clsx(args))
}
