/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // 主色来自「系统设置 → 主题色」，运行时写入 CSS 变量
        primary: {
          DEFAULT: 'var(--primary)',
          hover: 'var(--primary-hover)',
          soft: 'var(--primary-soft)',
          line: 'var(--primary-line)',
        },
        canvas: 'var(--canvas)',
        surface: 'var(--surface)',
        line: 'var(--line)',
        'line-strong': 'var(--line-strong)',
        muted: 'var(--muted)',
      },
      borderRadius: {
        DEFAULT: '6px',
      },
      fontFamily: {
        sans: [
          'system-ui', '-apple-system', '"Segoe UI"', '"PingFang SC"',
          '"Hiragino Sans GB"', '"Microsoft YaHei"', '"Helvetica Neue"', 'Arial', 'sans-serif',
        ],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', '"Courier New"', 'monospace'],
      },
      boxShadow: {
        pop: '0 8px 24px rgba(15, 23, 42, .10)',
        card: '0 1px 2px rgba(15, 23, 42, .04)',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(-4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'fade-in': 'fade-in .15s ease-out',
        'slide-in': 'slide-in .15s ease-out',
      },
    },
  },
  plugins: [],
}
