import React, { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, Radar, ScanSearch, Sparkles, ArrowRight, KeyRound, UserRound, Mail, Lock } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import '../styles/Auth.css'

const highlights = [
  {
    icon: Radar,
    title: '任务态势集中查看',
    description: '扫描进度、风险评分与近期发现统一收敛到同一控制视图。',
  },
  {
    icon: ScanSearch,
    title: '知识与工具联动',
    description: '模板、脚本与扫描器在同一工作流下进行编排与复用。',
  },
  {
    icon: Sparkles,
    title: 'AI 协同分析',
    description: '通过人格配置与子代理策略，形成更可控的安全分析流程。',
  },
]

export const Auth: React.FC = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { login, register } = useAuth()

  const isRegister = searchParams.get('mode') === 'register'
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    password_confirm: '',
  })

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
    setError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    try {
      if (isRegister) {
        if (formData.password !== formData.password_confirm) {
          throw new Error('密码不匹配')
        }
        await register(
          formData.username,
          formData.email,
          formData.password,
          formData.password_confirm
        )
      } else {
        await login(formData.username, formData.password)
      }
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : '发生错误')
    } finally {
      setIsLoading(false)
    }
  }

  const toggleMode = () => {
    const newMode = isRegister ? '' : 'register'
    navigate(newMode ? `?mode=${newMode}` : '/auth')
  }

  return (
    <div className="auth-shell">
      <div className="auth-noise" />

      <div className="auth-layout">
        <section className="auth-hero">
          <div className="auth-hero-topline">
            <div className="auth-hero-badge">
              <Shield className="h-5 w-5" />
              <span>Hack Scan Security Mesh</span>
            </div>
            <div className="auth-hero-status">
              <span className="auth-status-dot" />
              控制台待命中
            </div>
          </div>

          <div className="auth-hero-copy">
            <div className="auth-brand-mark">
              <Shield className="h-9 w-9" />
            </div>
            <p className="auth-kicker">Offensive Control Portal</p>
            <h1 className="auth-title">Hack Scan</h1>
            <p className="auth-description">
              {isRegister
                ? '创建账户后即可进入统一的安全扫描控制台，管理工具、策略与分析流程。'
                : '登录后继续查看任务态势、风险发现与 AI 协同分析结果。'}
            </p>
          </div>

          <div className="auth-highlights">
            {highlights.map(item => {
              const Icon = item.icon
              return (
                <article key={item.title} className="auth-highlight-card">
                  <div className="auth-highlight-icon">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <h3>{item.title}</h3>
                    <p>{item.description}</p>
                  </div>
                </article>
              )
            })}
          </div>
        </section>

        <section className="auth-panel-wrap">
          <div className="auth-panel">
            <div className="auth-panel-header">
              <div>
                <p className="auth-panel-kicker">{isRegister ? 'Create Access' : 'Welcome Back'}</p>
                <h2>{isRegister ? '创建账号' : '登录控制台'}</h2>
                <p className="auth-panel-description">
                  {isRegister
                    ? '填写必要信息，接入 Hack Scan 的扫描与分析工作台。'
                    : '输入您的账户信息，继续之前的扫描与评估工作。'}
                </p>
              </div>
              <div className="auth-panel-chip">
                <KeyRound className="h-4 w-4" />
                安全访问
              </div>
            </div>

            {error && <div className="auth-error">{error}</div>}

            <form onSubmit={handleSubmit} className="auth-form">
              <div className="form-group">
                <label htmlFor="username">用户名</label>
                <div className="input-shell">
                  <UserRound className="h-4 w-4" />
                  <input
                    id="username"
                    type="text"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                    placeholder={isRegister ? '创建用户名' : '用户名或邮箱'}
                    required
                    minLength={3}
                  />
                </div>
              </div>

              {isRegister && (
                <div className="form-group">
                  <label htmlFor="email">邮箱</label>
                  <div className="input-shell">
                    <Mail className="h-4 w-4" />
                    <input
                      id="email"
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      placeholder="邮箱地址"
                      required
                    />
                  </div>
                </div>
              )}

              <div className="form-group">
                <label htmlFor="password">密码</label>
                <div className="input-shell">
                  <Lock className="h-4 w-4" />
                  <input
                    id="password"
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="密码"
                    required
                    minLength={8}
                  />
                </div>
              </div>

              {isRegister && (
                <div className="form-group">
                  <label htmlFor="password_confirm">确认密码</label>
                  <div className="input-shell">
                    <Lock className="h-4 w-4" />
                    <input
                      id="password_confirm"
                      type="password"
                      name="password_confirm"
                      value={formData.password_confirm}
                      onChange={handleChange}
                      placeholder="再次输入密码"
                      required
                      minLength={8}
                    />
                  </div>
                </div>
              )}

              <button type="submit" disabled={isLoading} className="auth-submit">
                <span>{isLoading ? '处理中...' : isRegister ? '创建并进入' : '进入控制台'}</span>
                {!isLoading && <ArrowRight className="h-4 w-4" />}
              </button>
            </form>

            {!isRegister && (
              <div className="auth-inline-actions">
                <button
                  type="button"
                  className="auth-link-button"
                  onClick={() => {
                    window.alert('请联系管理员重置密码')
                  }}
                >
                  忘记密码？
                </button>
              </div>
            )}

            <div className="auth-divider" />

            <button
              type="button"
              onClick={toggleMode}
              className={`auth-toggle-btn ${isRegister ? 'login-btn' : 'register-btn'}`}
            >
              {isRegister ? '已有账户？返回登录' : '没有账户？创建新账户'}
            </button>
          </div>
        </section>
      </div>
    </div>
  )
}
