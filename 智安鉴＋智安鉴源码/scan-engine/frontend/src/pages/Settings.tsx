import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
    AlertCircle,
    Ban,
    CheckCircle,
    Eye,
    EyeOff,
    Globe,
    Key,
    Cpu,
    Plus,
    Trash2,
    Zap,
    Server,
    Thermometer,
    Edit2,
    X,
    Play,
    Loader2,
    RefreshCw,
} from 'lucide-react'
import {
    getSearchSettings,
    updateSearchSettings,
    getLLMConfigs,
    createLLMConfig,
    updateLLMConfig,
    deleteLLMConfig,
    activateLLMConfig,
    testLLMConfig,
    fetchLLMModels,
    type SearchSettings,
    type LLMConfig,
    type LLMConfigCreate,
    type LLMModel,
} from '../lib/api'

// ============ 联网搜索配置 ============

type SearchProviderOption = {
    value: string
    label: string
    detail: string
    needsKey: boolean
}

const searchProviderOptions: SearchProviderOption[] = [
    { value: 'duckduckgo', label: 'DuckDuckGo', detail: '免费，无需 API key', needsKey: false },
    { value: 'tavily', label: 'Tavily', detail: '适合快速摘要与检索', needsKey: true },
    { value: 'serper', label: 'Serper (Google)', detail: 'Google 搜索 API', needsKey: true },
    { value: 'bing', label: 'Bing', detail: 'Microsoft Bing Search API', needsKey: true },
    { value: 'none', label: '关闭', detail: '不使用联网搜索', needsKey: false },
]

// ============ LLM 配置 ============

type LLMProviderOption = {
    value: string
    label: string
    detail: string
    defaultModel: string
    defaultBaseUrl: string
}

const llmProviderOptions: LLMProviderOption[] = [
    { value: 'openai', label: 'OpenAI', detail: 'GPT-4o, GPT-4, GPT-3.5', defaultModel: 'gpt-4o', defaultBaseUrl: '' },
    { value: 'azure', label: 'Azure OpenAI', detail: 'Azure 托管的 OpenAI 模型', defaultModel: 'gpt-4o', defaultBaseUrl: '' },
    { value: 'anthropic', label: 'Anthropic', detail: 'Claude 3.5, Claude 3', defaultModel: 'claude-3-5-sonnet-20241022', defaultBaseUrl: '' },
    { value: 'deepseek', label: 'DeepSeek', detail: 'DeepSeek Chat', defaultModel: 'deepseek-chat', defaultBaseUrl: 'https://api.deepseek.com/v1' },
    { value: 'qwen', label: '通义千问', detail: '阿里云通义千问', defaultModel: 'qwen-max', defaultBaseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
    { value: 'zhipu', label: '智谱 AI', detail: 'GLM-4', defaultModel: 'glm-4', defaultBaseUrl: 'https://open.bigmodel.cn/api/paas/v4' },
    { value: 'moonshot', label: 'Moonshot', detail: 'Kimi', defaultModel: 'moonshot-v1-8k', defaultBaseUrl: 'https://api.moonshot.cn/v1' },
    { value: 'ollama', label: 'Ollama', detail: '本地 Ollama 模型', defaultModel: 'llama3.1', defaultBaseUrl: 'http://localhost:11434/v1' },
    { value: 'custom', label: '自定义', detail: 'OpenAI 兼容 API', defaultModel: '', defaultBaseUrl: '' },
]

interface LLMFormData {
    name: string
    provider: string
    api_base_url: string
    api_key: string
    model: string
    temperature: number
    max_tokens: number
    active_for_main_agent: boolean
    active_for_sub_agent: boolean
    priority: number
}

const defaultLLMFormData: LLMFormData = {
    name: '',
    provider: 'openai',
    api_base_url: '',
    api_key: '',
    model: 'gpt-4o',
    temperature: 10,
    max_tokens: 4096,
    active_for_main_agent: false,
    active_for_sub_agent: false,
    priority: 0,
}

type TabType = 'llm' | 'search'

export default function Settings() {
    const [activeTab, setActiveTab] = useState<TabType>('llm')

    return (
        <div>
            {/* Header */}
            <div className="mb-6">
                <h1 className="text-2xl font-bold">系统设置</h1>
                <p className="text-gray-500 dark:text-gray-400 text-sm">配置 LLM 模型和联网搜索</p>
            </div>

            {/* Tab Navigation */}
            <div className="flex gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-1 mb-6 w-fit">
                <button
                    onClick={() => setActiveTab('llm')}
                    className={clsx(
                        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        activeTab === 'llm'
                            ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow'
                            : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                    )}
                >
                    <Cpu className="w-4 h-4" />
                    LLM 配置
                </button>
                <button
                    onClick={() => setActiveTab('search')}
                    className={clsx(
                        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                        activeTab === 'search'
                            ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow'
                            : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                    )}
                >
                    <Globe className="w-4 h-4" />
                    联网搜索
                </button>
            </div>

            {/* Tab Content */}
            {activeTab === 'llm' ? <LLMSettingsTab /> : <SearchSettingsTab />}
        </div>
    )
}

// ============ LLM 设置 Tab ============

function LLMSettingsTab() {
    const queryClient = useQueryClient()
    const { data, isLoading, error } = useQuery({
        queryKey: ['llm-configs'],
        queryFn: getLLMConfigs,
    })

    const [showForm, setShowForm] = useState(false)
    const [editingId, setEditingId] = useState<string | null>(null)
    const [formData, setFormData] = useState<LLMFormData>(defaultLLMFormData)
    const [showApiKey, setShowApiKey] = useState(false)
    const [testingId, setTestingId] = useState<string | null>(null)
    const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null)
    
    // 模型列表相关状态
    const [availableModels, setAvailableModels] = useState<LLMModel[]>([])
    const [isFetchingModels, setIsFetchingModels] = useState(false)
    const [modelsFetchMessage, setModelsFetchMessage] = useState<string | null>(null)
    const [showModelDropdown, setShowModelDropdown] = useState(false)

    const createMutation = useMutation({
        mutationFn: (data: LLMConfigCreate) => createLLMConfig(data),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] })
            resetForm()
        },
    })

    const updateMutation = useMutation({
        mutationFn: ({ id, data }: { id: string; data: Partial<LLMConfigCreate & { is_enabled?: boolean }> }) =>
            updateLLMConfig(id, data),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] })
            resetForm()
        },
    })

    const deleteMutation = useMutation({
        mutationFn: (id: string) => deleteLLMConfig(id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] })
        },
    })

    const activateMutation = useMutation({
        mutationFn: ({ id, role }: { id: string; role: 'main' | 'sub' }) => activateLLMConfig(id, role),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] })
        },
    })

    const testMutation = useMutation({
        mutationFn: (id: string) => testLLMConfig(id),
        onSuccess: (result, id) => {
            setTestResult({ id, success: result.success, message: result.message })
            setTestingId(null)
        },
        onError: (_, id) => {
            setTestResult({ id, success: false, message: '测试请求失败' })
            setTestingId(null)
        },
    })

    const resetForm = () => {
        setShowForm(false)
        setEditingId(null)
        setFormData(defaultLLMFormData)
        setShowApiKey(false)
        setAvailableModels([])
        setModelsFetchMessage(null)
        setShowModelDropdown(false)
    }
    
    // 获取模型列表
    const handleFetchModels = async () => {
        setIsFetchingModels(true)
        setModelsFetchMessage(null)
        setShowModelDropdown(false)
        
        try {
            const result = await fetchLLMModels(
                formData.api_key || undefined,
                formData.api_base_url || undefined,
                editingId || undefined  // 编辑模式下使用已保存配置的 API key
            )
            
            if (result.success && result.models.length > 0) {
                setAvailableModels(result.models)
                setShowModelDropdown(true)
                setModelsFetchMessage(result.message)
            } else {
                setAvailableModels([])
                setModelsFetchMessage(result.message || '未获取到模型')
            }
        } catch (err) {
            setModelsFetchMessage('获取模型失败')
            setAvailableModels([])
        } finally {
            setIsFetchingModels(false)
        }
    }
    
    const handleSelectModel = (modelId: string) => {
        setFormData((prev) => ({ ...prev, model: modelId }))
        setShowModelDropdown(false)
    }

    const handleProviderChange = (provider: string) => {
        const option = llmProviderOptions.find((o) => o.value === provider)
        setFormData((prev) => ({
            ...prev,
            provider,
            model: option?.defaultModel || prev.model,
            api_base_url: option?.defaultBaseUrl || '',
        }))
    }

    const handleEdit = (config: LLMConfig) => {
        setEditingId(config.id)
        setFormData({
            name: config.name,
            provider: config.provider,
            api_base_url: config.api_base_url || '',
            api_key: '',
            model: config.model,
            temperature: config.temperature,
            max_tokens: config.max_tokens,
            active_for_main_agent: config.active_for_main_agent,
            active_for_sub_agent: config.active_for_sub_agent,
            priority: config.priority,
        })
        setShowForm(true)
    }

    const handleSubmit = (e: FormEvent) => {
        e.preventDefault()
        const payload: LLMConfigCreate = {
            name: formData.name.trim(),
            provider: formData.provider,
            api_base_url: formData.api_base_url.trim() || undefined,
            api_key: formData.api_key.trim() || undefined,
            model: formData.model.trim(),
            temperature: formData.temperature,
            max_tokens: formData.max_tokens,
            active_for_main_agent: formData.active_for_main_agent,
            active_for_sub_agent: formData.active_for_sub_agent,
            priority: formData.priority,
        }

        if (editingId) {
            const updatePayload: Partial<LLMConfigCreate> = { ...payload }
            if (!formData.api_key.trim()) {
                delete updatePayload.api_key
            }
            updateMutation.mutate({ id: editingId, data: updatePayload })
        } else {
            createMutation.mutate(payload)
        }
    }

    const handleTest = (id: string) => {
        setTestingId(id)
        setTestResult(null)
        testMutation.mutate(id)
    }

    const handleDelete = (id: string, name: string) => {
        if (confirm(`确定删除配置 "${name}"？`)) {
            deleteMutation.mutate(id)
        }
    }

    const handleToggleEnabled = (config: LLMConfig) => {
        updateMutation.mutate({ id: config.id, data: { is_enabled: !config.is_enabled } })
    }

    const mainAgentConfig = data?.items.find((c) => c.active_for_main_agent)
    const subAgentConfig = data?.items.find((c) => c.active_for_sub_agent)
    const formatAgentModel = (config?: LLMConfig) => (config ? `${config.name}/${config.model}` : '未配置')
    const isBusy = createMutation.isPending || updateMutation.isPending

    if (isLoading) {
        return <div className="text-center py-12">加载中...</div>
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
            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <StatCard
                    label="主 Agent"
                    value={formatAgentModel(mainAgentConfig)}
                    icon={Zap}
                    color={mainAgentConfig ? 'text-green-500' : 'text-gray-400'}
                />
                <StatCard
                    label="子 Agent"
                    value={formatAgentModel(subAgentConfig)}
                    icon={Key}
                    color={subAgentConfig ? 'text-indigo-500' : 'text-gray-400'}
                />
                <StatCard
                    label="配置数量"
                    value={data?.total.toString() || '0'}
                    icon={Server}
                    color="text-blue-500"
                />
            </div>

            {/* Config List */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                    <h2 className="font-medium text-gray-900 dark:text-gray-100">配置列表</h2>
                    <button
                        onClick={() => {
                            resetForm()
                            setShowForm(true)
                        }}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg flex items-center gap-1.5 text-sm transition-colors"
                    >
                        <Plus className="w-4 h-4" />
                        添加配置
                    </button>
                </div>

                {data?.items.length === 0 ? (
                    <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                        <Server className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>暂无配置，点击上方按钮添加</p>
                    </div>
                ) : (
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {data?.items.map((config) => (
                            <LLMConfigItem
                                key={config.id}
                                config={config}
                                isTesting={testingId === config.id}
                                testResult={testResult?.id === config.id ? testResult : null}
                                onEdit={() => handleEdit(config)}
                                onDelete={() => handleDelete(config.id, config.name)}
                                onActivate={(role) => activateMutation.mutate({ id: config.id, role })}
                                onTest={() => handleTest(config.id)}
                                onToggleEnabled={() => handleToggleEnabled(config)}
                            />
                        ))}
                    </div>
                )}
            </div>

            {/* Add/Edit Form Modal */}
            {showForm && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
                        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                            <h3 className="font-medium text-lg">
                                {editingId ? '编辑配置' : '添加配置'}
                            </h3>
                            <button
                                onClick={resetForm}
                                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleSubmit} className="p-4 space-y-4">
                            {/* Name */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    配置名称 <span className="text-red-500">*</span>
                                </label>
                                <input
                                    type="text"
                                    value={formData.name}
                                    onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                                    placeholder="例如: 主力模型"
                                    required
                                    className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>

                            {/* Provider */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    服务提供商 <span className="text-red-500">*</span>
                                </label>
                                <select
                                    value={formData.provider}
                                    onChange={(e) => handleProviderChange(e.target.value)}
                                    className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    {llmProviderOptions.map((opt) => (
                                        <option key={opt.value} value={opt.value}>
                                            {opt.label}
                                        </option>
                                    ))}
                                </select>
                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                    {llmProviderOptions.find((o) => o.value === formData.provider)?.detail}
                                </p>
                            </div>

                            {/* API Base URL */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    API Base URL
                                    <span className="text-xs font-normal text-gray-400 ml-2">(可选)</span>
                                </label>
                                <input
                                    type="url"
                                    value={formData.api_base_url}
                                    onChange={(e) => setFormData((p) => ({ ...p, api_base_url: e.target.value }))}
                                    placeholder="https://api.openai.com/v1"
                                    className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>

                            {/* API Key */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    API Key
                                    <span className="text-xs font-normal text-gray-400 ml-2">
                                        {editingId ? '(留空保持不变)' : '(本地模型可留空)'}
                                    </span>
                                </label>
                                <div className="relative">
                                    <input
                                        type={showApiKey ? 'text' : 'password'}
                                        value={formData.api_key}
                                        onChange={(e) => setFormData((p) => ({ ...p, api_key: e.target.value }))}
                                        placeholder={editingId ? '••••••••' : '输入 API Key'}
                                        className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowApiKey((prev) => !prev)}
                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                                    >
                                        {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                    </button>
                                </div>
                            </div>

                            {/* Model */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    模型名称 <span className="text-red-500">*</span>
                                </label>
                                <div className="flex gap-2">
                                    <div className="flex-1 relative">
                                        <input
                                            type="text"
                                            value={formData.model}
                                            onChange={(e) => setFormData((p) => ({ ...p, model: e.target.value }))}
                                            placeholder="gpt-4o"
                                            required
                                            className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        {/* 模型下拉列表 */}
                                        {showModelDropdown && availableModels.length > 0 && (
                                            <div className="absolute z-10 w-full mt-1 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                                                {availableModels.map((model) => (
                                                    <button
                                                        key={model.id}
                                                        type="button"
                                                        onClick={() => handleSelectModel(model.id)}
                                                        className={clsx(
                                                            'w-full px-4 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center justify-between',
                                                            formData.model === model.id && 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                                        )}
                                                    >
                                                        <span className="font-medium truncate">{model.id}</span>
                                                        {model.owned_by && (
                                                            <span className="text-xs text-gray-400 ml-2 shrink-0">{model.owned_by}</span>
                                                        )}
                                                    </button>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <button
                                        type="button"
                                        onClick={handleFetchModels}
                                        disabled={isFetchingModels}
                                        title="从 API 获取可用模型列表"
                                        className={clsx(
                                            'px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center gap-1',
                                            isFetchingModels && 'opacity-60 cursor-not-allowed'
                                        )}
                                    >
                                        {isFetchingModels ? (
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <RefreshCw className="w-4 h-4" />
                                        )}
                                        <span className="text-sm">获取</span>
                                    </button>
                                    {showModelDropdown && availableModels.length > 0 && (
                                        <button
                                            type="button"
                                            onClick={() => setShowModelDropdown(false)}
                                            className="px-2 py-2 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700"
                                            title="关闭列表"
                                        >
                                            <X className="w-4 h-4" />
                                        </button>
                                    )}
                                </div>
                                {modelsFetchMessage && (
                                    <p className={clsx(
                                        'mt-1 text-xs',
                                        availableModels.length > 0 ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400'
                                    )}>
                                        {modelsFetchMessage}
                                    </p>
                                )}
                            </div>

                            {/* Temperature & Max Tokens */}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Temperature
                                    </label>
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="range"
                                            min={0}
                                            max={100}
                                            value={formData.temperature}
                                            onChange={(e) =>
                                                setFormData((p) => ({ ...p, temperature: Number(e.target.value) }))
                                            }
                                            className="flex-1 accent-blue-500"
                                        />
                                        <span className="w-12 text-sm text-center">
                                            {(formData.temperature / 100).toFixed(2)}
                                        </span>
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Max Tokens
                                    </label>
                                    <input
                                        type="number"
                                        min={100}
                                        max={128000}
                                        value={formData.max_tokens}
                                        onChange={(e) =>
                                            setFormData((p) => ({ ...p, max_tokens: Number(e.target.value) }))
                                        }
                                        className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>
                            </div>

                            {/* Priority */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    优先级
                                </label>
                                <input
                                    type="number"
                                    min={0}
                                    max={100}
                                    value={formData.priority}
                                    onChange={(e) => setFormData((p) => ({ ...p, priority: Number(e.target.value) }))}
                                    className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>

                            {/* Agent Usage */}
                            <div className="space-y-2 rounded-lg border border-gray-200 dark:border-gray-700 p-3">
                                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Agent 使用范围</p>
                                <label className="flex items-center gap-3 text-sm text-gray-700 dark:text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={formData.active_for_main_agent}
                                        onChange={(e) => setFormData((p) => ({ ...p, active_for_main_agent: e.target.checked }))}
                                        className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                    />
                                    设为主 Agent API
                                </label>
                                <label className="flex items-center gap-3 text-sm text-gray-700 dark:text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={formData.active_for_sub_agent}
                                        onChange={(e) => setFormData((p) => ({ ...p, active_for_sub_agent: e.target.checked }))}
                                        className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                    />
                                    设为子 Agent/API 分析器
                                </label>
                            </div>

                            {/* Submit */}
                            <div className="flex gap-3 pt-2">
                                <button
                                    type="button"
                                    onClick={resetForm}
                                    className="flex-1 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                                >
                                    取消
                                </button>
                                <button
                                    type="submit"
                                    disabled={isBusy || !formData.name.trim() || !formData.model.trim()}
                                    className={clsx(
                                        'flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center justify-center gap-2 transition-colors',
                                        (isBusy || !formData.name.trim() || !formData.model.trim()) &&
                                            'opacity-60 cursor-not-allowed'
                                    )}
                                >
                                    {isBusy ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            保存中...
                                        </>
                                    ) : (
                                        <>
                                            <CheckCircle className="w-4 h-4" />
                                            {editingId ? '更新' : '创建'}
                                        </>
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Tips */}
            <div className="mt-6 bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                <h2 className="font-medium text-gray-900 dark:text-gray-100 mb-3">配置说明</h2>
                <ul className="space-y-2 text-sm text-gray-500 dark:text-gray-400">
                    <li>• 支持 OpenAI 及其兼容 API（DeepSeek、通义千问、Ollama 等）</li>
                    <li>• 可以分别指定主 Agent 和子 Agent/API 分析器使用的配置</li>
                    <li>• 未单独指定时系统会按优先级自动选择可用配置</li>
                    <li>• 本地 Ollama 模型无需 API Key，只需设置正确的 Base URL</li>
                    <li>• Temperature 越低输出越确定，建议扫描分析使用 0.1 左右</li>
                </ul>
            </div>
        </div>
    )
}

function LLMConfigItem({
    config,
    isTesting,
    testResult,
    onEdit,
    onDelete,
    onActivate,
    onTest,
    onToggleEnabled,
}: {
    config: LLMConfig
    isTesting: boolean
    testResult: { success: boolean; message: string } | null
    onEdit: () => void
    onDelete: () => void
    onActivate: (role: 'main' | 'sub') => void
    onTest: () => void
    onToggleEnabled: () => void
}) {
    const provider = llmProviderOptions.find((p) => p.value === config.provider)

    return (
        <div
            className={clsx(
                'p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors',
                !config.is_enabled && 'opacity-50'
            )}
        >
            <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-medium text-gray-900 dark:text-gray-100 truncate">{config.name}</h3>
                        {config.active_for_main_agent && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                                主 Agent
                            </span>
                        )}
                        {config.active_for_sub_agent && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400">
                                子 Agent
                            </span>
                        )}
                        {!config.is_enabled && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">
                                已禁用
                            </span>
                        )}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-500 dark:text-gray-400">
                        <span className="flex items-center gap-1">
                            <Server className="w-3.5 h-3.5" />
                            {provider?.label || config.provider}
                        </span>
                        <span className="flex items-center gap-1">
                               <span className="w-3.5 h-3.5 inline-flex items-center justify-center text-xs">#</span>
                            {config.model}
                        </span>
                        <span className="flex items-center gap-1">
                            <Thermometer className="w-3.5 h-3.5" />
                            {(config.temperature / 100).toFixed(2)}
                        </span>
                        {config.has_api_key && (
                            <span className="text-green-600 dark:text-green-400 text-xs">Key 已配置</span>
                        )}
                    </div>
                    {config.last_error && (
                        <p className="mt-1 text-xs text-red-500 truncate" title={config.last_error}>
                            上次错误: {config.last_error}
                        </p>
                    )}
                    {testResult && (
                        <p
                            className={clsx(
                                'mt-1 text-xs',
                                testResult.success ? 'text-green-600 dark:text-green-400' : 'text-red-500'
                            )}
                        >
                            {testResult.success ? '✓ ' : '✗ '}
                            {testResult.message}
                        </p>
                    )}
                </div>

                <div className="flex items-center gap-1">
                    <button
                        onClick={onTest}
                        disabled={isTesting}
                        className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                        title="测试连接"
                    >
                        {isTesting ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                            <Play className="w-4 h-4" />
                        )}
                    </button>
                    {config.is_enabled && (
                        <button
                            onClick={() => onActivate('main')}
                            className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                            title="设为主 Agent API"
                        >
                            <Zap className="w-4 h-4" />
                        </button>
                    )}
                    {config.is_enabled && (
                        <button
                            onClick={() => onActivate('sub')}
                            className="p-2 text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors"
                            title="设为子 Agent API"
                        >
                            <Cpu className="w-4 h-4" />
                        </button>
                    )}
                    <button
                        onClick={onEdit}
                        className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-lg transition-colors"
                        title="编辑"
                    >
                        <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                        onClick={onToggleEnabled}
                        className={clsx(
                            'p-2 rounded-lg transition-colors',
                            config.is_enabled
                                ? 'text-gray-400 hover:text-yellow-600 dark:hover:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20'
                                : 'text-yellow-600 dark:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20'
                        )}
                        title={config.is_enabled ? '禁用' : '启用'}
                    >
                        {config.is_enabled ? (
                            <Ban className="w-4 h-4" />
                        ) : (
                            <CheckCircle className="w-4 h-4" />
                        )}
                    </button>
                    <button
                        onClick={onDelete}
                        className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                        title="删除"
                    >
                        <Trash2 className="w-4 h-4" />
                    </button>
                </div>
            </div>
        </div>
    )
}

// ============ 联网搜索设置 Tab ============

function SearchSettingsTab() {
    const queryClient = useQueryClient()
    const { data, isLoading, error } = useQuery({
        queryKey: ['search-settings'],
        queryFn: getSearchSettings,
    })

    const [enabled, setEnabled] = useState(true)
    const [provider, setProvider] = useState('duckduckgo')
    const [apiKey, setApiKey] = useState('')
    const [apiKeyMasked, setApiKeyMasked] = useState(false)
    const [apiKeyDirty, setApiKeyDirty] = useState(false)
    const [showApiKey, setShowApiKey] = useState(false)
    const [maxResults, setMaxResults] = useState(5)
    const [saveState, setSaveState] = useState<'idle' | 'success' | 'error'>('idle')

    useEffect(() => {
        if (!data) return

        setEnabled(data.enabled)
        setProvider(data.provider)
        setMaxResults(data.max_results)

        const masked = data.api_key === '***'
        setApiKeyMasked(masked)
        setApiKeyDirty(false)
        setApiKey(masked ? '' : (data.api_key ?? ''))
    }, [data])

    const mutation = useMutation({
        mutationFn: (payload: SearchSettings) => updateSearchSettings(payload),
        onSuccess: (updated) => {
            queryClient.setQueryData(['search-settings'], updated)
            setSaveState('success')
            window.setTimeout(() => setSaveState('idle'), 2200)
            const hasSavedKey = updated.api_key === '***'
            setApiKeyMasked(hasSavedKey)
            setApiKeyDirty(false)
            setApiKey('')
        },
        onError: () => {
            setSaveState('error')
        },
    })

    const selectedProvider = useMemo(
        () => searchProviderOptions.find((option) => option.value === provider) ?? searchProviderOptions[0],
        [provider]
    )

    const isActive = enabled && provider !== 'none'
    const isBusy = isLoading || mutation.isPending

    const handleToggle = () => {
        const next = !enabled
        setEnabled(next)
        if (next && provider === 'none') {
            setProvider('duckduckgo')
        }
    }

    const handleProviderChange = (value: string) => {
        setProvider(value)
        if (value === 'none') {
            setEnabled(false)
        }
    }

    const handleApiKeyChange = (value: string) => {
        setApiKey(value)
        setApiKeyDirty(true)
        setApiKeyMasked(false)
    }

    const handleMaxResultsChange = (value: string) => {
        const parsed = Number(value)
        if (Number.isNaN(parsed)) return
        const clamped = Math.min(20, Math.max(1, parsed))
        setMaxResults(clamped)
    }

    const buildPayload = (): SearchSettings => {
        let api_key: string | null = null

        if (apiKeyDirty) {
            api_key = apiKey.trim() ? apiKey.trim() : null
        } else if (apiKeyMasked) {
            api_key = '***'
        } else {
            api_key = apiKey.trim() ? apiKey.trim() : null
        }

        return {
            enabled,
            provider,
            api_key,
            max_results: maxResults,
        }
    }

    const handleSubmit = (event: FormEvent) => {
        event.preventDefault()
        setSaveState('idle')
        mutation.mutate(buildPayload())
    }

    if (isLoading) {
        return <div className="text-center py-12">加载中...</div>
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
            {/* Stats */}
            <div className="grid grid-cols-3 gap-4 mb-6">
                <StatCard
                    label="搜索提供商"
                    value={selectedProvider.label}
                    icon={Globe}
                    color="text-blue-500"
                />
                <StatCard
                    label="API Key"
                    value={apiKeyMasked && !apiKeyDirty ? '已配置' : apiKey ? '已填写' : '未配置'}
                    icon={Key}
                    color={apiKeyMasked || apiKey ? 'text-green-500' : 'text-gray-400'}
                />
                <StatCard
                    label="最大返回条数"
                    value={maxResults.toString()}
                    icon={Key}
                    color="text-purple-500"
                />
            </div>

            {/* Settings Form */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
                <form onSubmit={handleSubmit}>
                    {/* Toggle Section */}
                    <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="font-medium text-gray-900 dark:text-gray-100">启用联网搜索</p>
                                <p className="text-sm text-gray-500 dark:text-gray-400">
                                    启用后，AI 代理可以在扫描中调用搜索引擎获取漏洞信息
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={handleToggle}
                                disabled={isBusy}
                                className={clsx(
                                    'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                                    isActive ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600',
                                    isBusy && 'opacity-60 cursor-not-allowed'
                                )}
                                aria-pressed={isActive}
                            >
                                <span
                                    className={clsx(
                                        'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform',
                                        isActive ? 'translate-x-6' : 'translate-x-1'
                                    )}
                                />
                            </button>
                        </div>
                    </div>

                    {/* Provider Section */}
                    <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                        <label className="block font-medium text-gray-900 dark:text-gray-100 mb-2">
                            搜索提供商
                        </label>
                        <select
                            value={provider}
                            onChange={(e) => handleProviderChange(e.target.value)}
                            disabled={isBusy}
                            className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            {searchProviderOptions.map((option) => (
                                <option key={option.value} value={option.value}>
                                    {option.label}
                                </option>
                            ))}
                        </select>
                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{selectedProvider.detail}</p>
                    </div>

                    {/* API Key Section */}
                    <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                        <label className="block font-medium text-gray-900 dark:text-gray-100 mb-2">
                            API Key
                            <span className="text-sm font-normal text-gray-400 ml-2">
                                {selectedProvider.needsKey ? '(必填)' : '(可选)'}
                            </span>
                        </label>
                        <div className="relative">
                            <input
                                type={showApiKey ? 'text' : 'password'}
                                value={apiKeyMasked && !apiKeyDirty ? '••••••••••••••••' : apiKey}
                                onChange={(e) => handleApiKeyChange(e.target.value)}
                                onFocus={() => {
                                    if (apiKeyMasked && !apiKeyDirty) {
                                        setApiKey('')
                                    }
                                }}
                                disabled={isBusy}
                                placeholder={apiKeyMasked && !apiKeyDirty ? '已保存，点击修改' : '输入 API key'}
                                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <button
                                type="button"
                                onClick={() => setShowApiKey((prev) => !prev)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                            >
                                {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>

                    {/* Max Results Section */}
                    <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                        <label className="block font-medium text-gray-900 dark:text-gray-100 mb-2">
                            最大返回条数
                        </label>
                        <div className="flex items-center gap-4">
                            <input
                                type="range"
                                min={1}
                                max={20}
                                value={maxResults}
                                onChange={(e) => handleMaxResultsChange(e.target.value)}
                                disabled={isBusy}
                                className="flex-1 accent-blue-500"
                            />
                            <input
                                type="number"
                                min={1}
                                max={20}
                                value={maxResults}
                                onChange={(e) => handleMaxResultsChange(e.target.value)}
                                disabled={isBusy}
                                className="w-20 bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 text-sm text-center focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>
                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">建议 5-10 条以控制 LLM 上下文大小</p>
                    </div>

                    {/* Submit Section */}
                    <div className="p-4 flex items-center gap-4">
                        <button
                            type="submit"
                            disabled={isBusy}
                            className={clsx(
                                'bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors',
                                isBusy && 'opacity-60 cursor-not-allowed'
                            )}
                        >
                            <CheckCircle className="w-4 h-4" />
                            {mutation.isPending ? '保存中...' : '保存设置'}
                        </button>

                        {saveState === 'success' && (
                            <span className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                                <CheckCircle className="w-4 h-4" />
                                设置已保存
                            </span>
                        )}

                        {saveState === 'error' && (
                            <span className="flex items-center gap-2 text-sm text-red-500">
                                <AlertCircle className="w-4 h-4" />
                                保存失败，请重试
                            </span>
                        )}
                    </div>
                </form>
            </div>

            {/* Tips */}
            <div className="mt-6 bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                <h2 className="font-medium text-gray-900 dark:text-gray-100 mb-3">配置提示</h2>
                <ul className="space-y-2 text-sm text-gray-500 dark:text-gray-400">
                    <li>• 使用 Tavily / Serper / Bing 时需要有效的 API key</li>
                    <li>• DuckDuckGo 为免费选项，无需 API key</li>
                    <li>• 关闭联网搜索后，AI 代理只使用本地扫描结果</li>
                    <li>• 如果扫描未启用 AI 代理，联网搜索不会被调用</li>
                </ul>
            </div>
        </div>
    )
}

// ============ 共用组件 ============

function StatCard({
    label,
    value,
    icon: Icon,
    color = 'text-gray-400',
}: {
    label: string
    value: string
    icon: React.ComponentType<{ className?: string }>
    color?: string
}) {
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
            <div className="flex items-center gap-3">
                <Icon className={`w-8 h-8 ${color}`} />
                <div>
                    <p className="text-lg font-bold truncate">{value}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
                </div>
            </div>
        </div>
    )
}
