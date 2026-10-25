import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, Plus, Edit2, Trash2, Star, StarOff, CheckCircle, AlertCircle, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { getPersonas, createPersona, updatePersona, deletePersona, setDefaultPersona, AIPersona, AIPersonaCreate, AIPersonaUpdate } from '../lib/api'

export default function Personas() {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingPersona, setEditingPersona] = useState<AIPersona | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['personas'],
    queryFn: getPersonas,
  })

  const createMutation = useMutation({
    mutationFn: createPersona,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['personas'] })
      setShowForm(false)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, updates }: { id: string; updates: AIPersonaUpdate }) => updatePersona(id, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['personas'] })
      setEditingPersona(null)
      setShowForm(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deletePersona,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['personas'] })
      setDeleteConfirmId(null)
    },
  })

  const setDefaultMutation = useMutation({
    mutationFn: setDefaultPersona,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['personas'] })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12 text-red-500">
        加载失败: {(error as Error).message}
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-6">
        <div>
          <h1 className="text-2xl font-bold">AI 人格</h1>
          <p className="text-gray-500 dark:text-gray-400 text-sm">
            管理 AI Agent 的 System Prompt，自定义扫描时的 AI 行为
          </p>
        </div>
        <button
          onClick={() => {
            setEditingPersona(null)
            setShowForm(true)
          }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
        >
          <Plus className="w-4 h-4" />
          新建人格
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <StatCard label="总数" value={data?.total || 0} icon={Bot} color="text-blue-500" />
        <StatCard
          label="默认人格"
          value={data?.items.find(p => p.is_default)?.name || '未设置'}
          icon={Star}
          color="text-yellow-500"
          isText
        />
        <StatCard
          label="已启用"
          value={data?.items.filter(p => p.is_enabled).length || 0}
          icon={CheckCircle}
          color="text-green-500"
        />
      </div>

      {/* Persona List */}
      {data?.items.length === 0 ? (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center">
          <Bot className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400 mb-4">还没有创建任何 AI 人格</p>
          <button
            onClick={() => setShowForm(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
          >
            创建第一个人格
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {data?.items.map((persona) => (
            <div
              key={persona.id}
              className={`bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden ${
                !persona.is_enabled ? 'opacity-60' : ''
              }`}
            >
              {/* Header Row */}
              <div className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    persona.is_default
                      ? 'bg-yellow-100 dark:bg-yellow-900'
                      : 'bg-gray-100 dark:bg-gray-700'
                  }`}>
                    <Bot className={`w-5 h-5 ${
                      persona.is_default
                        ? 'text-yellow-600 dark:text-yellow-400'
                        : 'text-gray-500'
                    }`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{persona.name}</h3>
                      {persona.is_default && (
                        <span className="px-2 py-0.5 text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 rounded">
                          默认
                        </span>
                      )}
                      {!persona.is_enabled && (
                        <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-500 rounded">
                          已禁用
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {persona.description || '无描述'}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {/* Set Default Button */}
                  {!persona.is_default && persona.is_enabled && (
                    <button
                      onClick={() => setDefaultMutation.mutate(persona.id)}
                      disabled={setDefaultMutation.isPending}
                      className="p-2 text-gray-400 hover:text-yellow-500 transition-colors"
                      title="设为默认"
                    >
                      <StarOff className="w-5 h-5" />
                    </button>
                  )}
                  {persona.is_default && (
                    <span className="p-2 text-yellow-500" title="默认人格">
                      <Star className="w-5 h-5 fill-current" />
                    </span>
                  )}

                  {/* Edit Button */}
                  <button
                    onClick={() => {
                      setEditingPersona(persona)
                      setShowForm(true)
                    }}
                    className="p-2 text-gray-400 hover:text-blue-500 transition-colors"
                    title="编辑"
                  >
                    <Edit2 className="w-5 h-5" />
                  </button>

                  {/* Delete Button */}
                  {!persona.is_default && (
                    <button
                      onClick={() => setDeleteConfirmId(persona.id)}
                      className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                      title="删除"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  )}

                  {/* Expand Button */}
                  <button
                    onClick={() => setExpandedId(expandedId === persona.id ? null : persona.id)}
                    className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                  >
                    {expandedId === persona.id ? (
                      <ChevronUp className="w-5 h-5" />
                    ) : (
                      <ChevronDown className="w-5 h-5" />
                    )}
                  </button>
                </div>
              </div>

              {/* Expanded Content */}
              {expandedId === persona.id && (
                <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-700">
                  <div className="pt-4">
                    <h4 className="text-sm font-medium text-gray-500 mb-2">System Prompt</h4>
                    <pre className="p-3 bg-gray-100 dark:bg-gray-900 rounded-lg text-sm whitespace-pre-wrap font-mono max-h-64 overflow-y-auto">
                      {persona.system_prompt}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create/Edit Form Modal */}
      {showForm && (
        <PersonaFormModal
          persona={editingPersona}
          onClose={() => {
            setShowForm(false)
            setEditingPersona(null)
          }}
          onSubmit={(data) => {
            if (editingPersona) {
              updateMutation.mutate({ id: editingPersona.id, updates: data })
            } else {
              createMutation.mutate(data as AIPersonaCreate)
            }
          }}
          isPending={createMutation.isPending || updateMutation.isPending}
          error={createMutation.error || updateMutation.error}
        />
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold mb-2">确认删除</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              确定要删除此 AI 人格吗？此操作不可恢复。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg"
              >
                取消
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirmId)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
              >
                {deleteMutation.isPending ? '删除中...' : '确认删除'}
              </button>
            </div>
            {deleteMutation.error && (
              <p className="mt-2 text-sm text-red-500">
                {(deleteMutation.error as Error).message}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}


// ============ Sub-components ============

function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-gray-400',
  isText = false,
}: {
  label: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  color?: string
  isText?: boolean
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
      <div className="flex items-center gap-3">
        <Icon className={`w-8 h-8 ${color}`} />
        <div>
          <p className={`${isText ? 'text-base' : 'text-lg'} font-bold`}>{value}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
        </div>
      </div>
    </div>
  )
}


interface PersonaFormModalProps {
  persona: AIPersona | null
  onClose: () => void
  onSubmit: (data: AIPersonaCreate | AIPersonaUpdate) => void
  isPending: boolean
  error: Error | null
}

function PersonaFormModal({ persona, onClose, onSubmit, isPending, error }: PersonaFormModalProps) {
  const [name, setName] = useState(persona?.name || '')
  const [description, setDescription] = useState(persona?.description || '')
  const [systemPrompt, setSystemPrompt] = useState(persona?.system_prompt || '')
  const [isDefault, setIsDefault] = useState(persona?.is_default || false)
  const [isEnabled, setIsEnabled] = useState(persona?.is_enabled ?? true)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      name,
      description: description || null,
      system_prompt: systemPrompt,
      is_default: isDefault,
      is_enabled: isEnabled,
    })
  }

  const isEditing = !!persona

  // 预设模板
  const templates = [
    {
      name: '专业安全研究员',
      prompt: `你是一名专业的安全研究员和渗透测试专家。

你的职责：
1. 系统性地发现目标中的安全漏洞
2. 使用多种工具和技术进行测试
3. 对发现的漏洞进行深入分析
4. 提供专业的修复建议

在测试过程中：
- 优先测试高风险漏洞（SQL注入、RCE、XSS等）
- 注意不要对目标造成破坏
- 详细记录每个测试步骤
- 遇到不确定的情况时询问用户`,
    },
    {
      name: '攻击性渗透测试员',
      prompt: `你是一名经验丰富的攻击性安全测试员（红队成员）。

你的测试风格：
1. 主动尝试绑定WAF和安全设备
2. 使用创造性的攻击向量
3. 尝试链接多个漏洞实现更大影响
4. 模拟真实攻击者的思维方式

注意事项：
- 始终在授权范围内测试
- 记录所有发现供后续报告
- 如果发现严重漏洞立即通知用户`,
    },
    {
      name: '谨慎合规测试员',
      prompt: `你是一名注重合规性的安全测试员。

测试原则：
1. 严格遵循测试范围，不越界
2. 优先使用被动检测方法
3. 避免可能造成服务中断的测试
4. 详细记录所有操作以备审计

在遇到敏感区域时：
- 暂停测试并询问用户是否继续
- 评估测试可能带来的风险
- 建议更安全的替代测试方案`,
    },
  ]

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-hidden shadow-xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold">
            {isEditing ? '编辑 AI 人格' : '新建 AI 人格'}
          </h2>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto max-h-[calc(90vh-130px)]">
          <div className="space-y-4">
            {/* Name */}
            <div>
              <label className="block text-sm font-medium mb-1">名称 *</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如：专业安全研究员"
                required
                maxLength={100}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium mb-1">描述</label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="简短描述此人格的特点"
                maxLength={500}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* System Prompt */}
            <div>
              <label className="block text-sm font-medium mb-1">System Prompt *</label>
              <textarea
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                placeholder="定义 AI Agent 的行为和风格..."
                required
                rows={10}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none font-mono text-sm"
              />
              <p className="text-xs text-gray-500 mt-1">
                这将作为 AI Agent 的系统提示词，定义其行为方式和测试风格
              </p>
            </div>

            {/* Templates */}
            {!isEditing && (
              <div>
                <label className="block text-sm font-medium mb-2">快速模板</label>
                <div className="flex flex-wrap gap-2">
                  {templates.map((t) => (
                    <button
                      key={t.name}
                      type="button"
                      onClick={() => {
                        setName(t.name)
                        setSystemPrompt(t.prompt)
                      }}
                      className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors"
                    >
                      {t.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Options */}
            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={isDefault}
                  onChange={(e) => setIsDefault(e.target.checked)}
                  className="w-4 h-4"
                />
                <span className="text-sm">设为默认人格</span>
              </label>
              
              {isEditing && (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={isEnabled}
                    onChange={(e) => setIsEnabled(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm">启用</span>
                </label>
              )}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-5 h-5" />
              {(error as Error).message}
            </div>
          )}

          {/* Actions */}
          <div className="mt-6 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={isPending || !name.trim() || !systemPrompt.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
            >
              {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              {isPending ? '保存中...' : isEditing ? '保存' : '创建'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
