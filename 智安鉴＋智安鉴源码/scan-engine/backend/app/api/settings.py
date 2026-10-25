"""Settings API endpoints - LLM 和系统配置"""
import uuid
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from loguru import logger

from app.core.database import get_db
from app.models.database import LLMConfig, SystemConfig, AIPersona
from app.schemas.scan import (
    LLMConfigCreate, LLMConfigUpdate, LLMConfigResponse, LLMConfigList,
    SearchSettings, SystemSettings, ScanSettings,
    AIPersonaCreate, AIPersonaUpdate, AIPersonaResponse, AIPersonaList, AIPersonaBrief
)

router = APIRouter(prefix="/settings", tags=["settings"])


# ============ LLM 配置 ============

def _build_llm_response(config: LLMConfig) -> LLMConfigResponse:
    return LLMConfigResponse(
        id=config.id,
        name=config.name,
        provider=config.provider,
        api_base_url=config.api_base_url,
        has_api_key=bool(config.api_key),
        model=config.model,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        active_for_main_agent=config.active_for_main_agent,
        active_for_sub_agent=config.active_for_sub_agent,
        is_enabled=config.is_enabled,
        priority=config.priority,
        total_requests=config.total_requests,
        failed_requests=config.failed_requests,
        last_used_at=config.last_used_at,
        last_error=config.last_error,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


async def _clear_llm_active_flags(db: AsyncSession, role: str, exclude_id: str | None = None):
    conditions = []
    if exclude_id:
        conditions.append(LLMConfig.id != exclude_id)

    stmt = update(LLMConfig)
    if conditions:
        stmt = stmt.where(*conditions)

    values = {}
    if role == "main":
        values["active_for_main_agent"] = False
    if role == "sub":
        values["active_for_sub_agent"] = False

    if values:
        await db.execute(stmt.values(**values))

@router.get("/llm", response_model=LLMConfigList)
async def list_llm_configs(
    db: AsyncSession = Depends(get_db)
):
    """获取所有 LLM 配置"""
    result = await db.execute(
        select(LLMConfig).order_by(LLMConfig.priority.desc(), LLMConfig.created_at.desc())
    )
    configs = result.scalars().all()
    
    return LLMConfigList(total=len(configs), items=[_build_llm_response(c) for c in configs])


@router.post("/llm", response_model=LLMConfigResponse)
async def create_llm_config(
    data: LLMConfigCreate,
    db: AsyncSession = Depends(get_db)
):
    """创建 LLM 配置"""
    config_id = str(uuid.uuid4())
    
    if data.active_for_main_agent:
        await _clear_llm_active_flags(db, "main")
    if data.active_for_sub_agent:
        await _clear_llm_active_flags(db, "sub")
    
    config = LLMConfig(
        id=config_id,
        name=data.name,
        provider=data.provider,
        api_base_url=data.api_base_url,
        api_key=data.api_key,
        model=data.model,
        temperature=data.temperature,
        max_tokens=data.max_tokens,
        is_active=False,
        active_for_main_agent=data.active_for_main_agent,
        active_for_sub_agent=data.active_for_sub_agent,
        is_enabled=True,
        priority=data.priority,
    )
    
    db.add(config)
    await db.commit()
    await db.refresh(config)
    
    logger.info(f"LLM config created: {config.name}")
    
    return _build_llm_response(config)


@router.patch("/llm/{config_id}", response_model=LLMConfigResponse)
async def update_llm_config(
    config_id: str,
    data: LLMConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """更新 LLM 配置"""
    result = await db.execute(
        select(LLMConfig).where(LLMConfig.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="配置不存在")
    
    update_dict = data.model_dump(exclude_unset=True)
    
    if update_dict.get('active_for_main_agent'):
        await _clear_llm_active_flags(db, "main", config_id)
    if update_dict.get('active_for_sub_agent'):
        await _clear_llm_active_flags(db, "sub", config_id)
    
    for key, value in update_dict.items():
        setattr(config, key, value)
    
    await db.commit()
    await db.refresh(config)
    
    return _build_llm_response(config)


@router.delete("/llm/{config_id}")
async def delete_llm_config(
    config_id: str,
    db: AsyncSession = Depends(get_db)
):
    """删除 LLM 配置"""
    result = await db.execute(
        select(LLMConfig).where(LLMConfig.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="配置不存在")
    
    await db.delete(config)
    await db.commit()
    
    logger.info(f"LLM config deleted: {config.name}")
    
    return {"message": "配置已删除", "id": config_id}


@router.post("/llm/{config_id}/activate")
async def activate_llm_config(
    config_id: str,
    role: str = "main",
    db: AsyncSession = Depends(get_db)
):
    """激活指定的 LLM 配置。role=main/sub"""
    if role not in {"main", "sub"}:
        raise HTTPException(status_code=400, detail="role 必须是 main 或 sub")

    result = await db.execute(
        select(LLMConfig).where(LLMConfig.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="配置不存在")
    
    if not config.is_enabled:
        raise HTTPException(status_code=400, detail="不能激活已禁用的配置")

    await _clear_llm_active_flags(db, role)
    
    if role == "main":
        config.active_for_main_agent = True
    else:
        config.active_for_sub_agent = True

    await db.commit()
    
    role_label = {"main": "主 Agent", "sub": "子 Agent"}[role]
    return {"message": f"已设为{role_label}配置: {config.name}", "id": config_id, "role": role}


@router.post("/llm/{config_id}/test")
async def test_llm_config(
    config_id: str,
    db: AsyncSession = Depends(get_db)
):
    """测试 LLM 配置是否可用"""
    result = await db.execute(
        select(LLMConfig).where(LLMConfig.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="配置不存在")
    
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage
        
        llm = ChatOpenAI(
            model=config.model,
            temperature=config.temperature / 100,
            api_key=config.api_key or None,
            base_url=config.api_base_url or None,
            max_tokens=100,
            timeout=30,
        )
        
        response = await llm.ainvoke([HumanMessage(content="Say 'test ok' in two words.")])
        
        return {
            "success": True,
            "message": "连接成功",
            "response": response.content[:200]
        }
        
    except Exception as e:
        logger.error(f"LLM test failed: {e}")
        return {
            "success": False,
            "message": "连接失败",
            "error": str(e)
        }


from pydantic import BaseModel as PydanticBaseModel

class FetchModelsRequest(PydanticBaseModel):
    api_key: str | None = None
    api_base_url: str | None = None
    config_id: str | None = None  # 可选：使用已保存配置的 API key

@router.post("/llm/fetch-models")
async def fetch_llm_models(
    request: FetchModelsRequest,
    db: AsyncSession = Depends(get_db),
):
    """从 LLM 提供商获取可用模型列表 (OpenAI 兼容 API)"""
    import httpx
    
    api_key = request.api_key
    api_base_url = request.api_base_url
    
    # 如果提供了 config_id，从数据库获取配置
    if request.config_id and not api_key:
        result = await db.execute(
            select(LLMConfig).where(LLMConfig.id == request.config_id)
        )
        config = result.scalar_one_or_none()
        if config:
            api_key = config.api_key
            if not api_base_url:
                api_base_url = config.api_base_url
    
    # 确定 API 地址
    base_url = (api_base_url or "https://api.openai.com/v1").rstrip("/")
    models_url = f"{base_url}/models"
    
    headers = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(models_url, headers=headers)
            
            if response.status_code == 401:
                return {
                    "success": False,
                    "message": "API Key 无效或未授权",
                    "models": []
                }
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "message": f"请求失败: HTTP {response.status_code}",
                    "models": []
                }
            
            data = response.json()
            
            # OpenAI 格式: { "object": "list", "data": [{ "id": "model-id", ... }] }
            models = []
            if "data" in data and isinstance(data["data"], list):
                for item in data["data"]:
                    model_id = item.get("id", "")
                    if model_id:
                        models.append({
                            "id": model_id,
                            "owned_by": item.get("owned_by", ""),
                            "created": item.get("created"),
                        })
            
            # 按模型名称排序
            models.sort(key=lambda x: x["id"])
            
            return {
                "success": True,
                "message": f"获取到 {len(models)} 个模型",
                "models": models
            }
            
    except httpx.TimeoutException:
        return {
            "success": False,
            "message": "请求超时，请检查网络或 API 地址",
            "models": []
        }
    except httpx.ConnectError:
        return {
            "success": False,
            "message": "无法连接到服务器，请检查 API 地址",
            "models": []
        }
    except Exception as e:
        logger.error(f"Fetch models failed: {e}")
        return {
            "success": False,
            "message": f"获取失败: {str(e)}",
            "models": []
        }


# ============ 联网搜索配置 ============

@router.get("/search", response_model=SearchSettings)
async def get_search_settings(
    db: AsyncSession = Depends(get_db)
):
    """获取联网搜索设置"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "search_settings")
    )
    config = result.scalar_one_or_none()
    
    if config and config.value:
        try:
            data = json.loads(config.value)
            # 隐藏 API key
            if data.get('api_key'):
                data['api_key'] = '***'
            return SearchSettings(**data)
        except:
            pass
    
    # 返回默认设置
    return SearchSettings()


@router.put("/search", response_model=SearchSettings)
async def update_search_settings(
    settings: SearchSettings,
    db: AsyncSession = Depends(get_db)
):
    """更新联网搜索设置"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "search_settings")
    )
    config = result.scalar_one_or_none()
    
    # 如果是 *** 则保留原有的 key
    if settings.api_key == '***' and config and config.value:
        try:
            old_data = json.loads(config.value)
            settings.api_key = old_data.get('api_key')
        except:
            pass
    
    value = settings.model_dump_json()
    
    if config:
        config.value = value
    else:
        config = SystemConfig(
            key="search_settings",
            value=value,
            description="联网搜索配置"
        )
        db.add(config)
    
    await db.commit()
    
    logger.info(f"Search settings updated: provider={settings.provider}")
    
    # 隐藏返回的 API key
    if settings.api_key:
        settings.api_key = '***'
    
    return settings


# ============ 系统设置 ============

@router.get("/system", response_model=SystemSettings)
async def get_system_settings(
    db: AsyncSession = Depends(get_db)
):
    """获取系统设置"""
    # 获取搜索设置
    search_result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "search_settings")
    )
    search_config = search_result.scalar_one_or_none()
    
    search_settings = SearchSettings()
    if search_config and search_config.value:
        try:
            data = json.loads(search_config.value)
            if data.get('api_key'):
                data['api_key'] = '***'
            search_settings = SearchSettings(**data)
        except:
            pass
    
    # 获取扫描设置
    scan_result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "scan_settings")
    )
    scan_config = scan_result.scalar_one_or_none()
    
    scan_settings = ScanSettings()
    if scan_config and scan_config.value:
        try:
            scan_settings = ScanSettings(**json.loads(scan_config.value))
        except:
            pass
    
    return SystemSettings(
        search=search_settings,
        scan=scan_settings
    )


@router.put("/system", response_model=SystemSettings)
async def update_system_settings(
    settings: SystemSettings,
    db: AsyncSession = Depends(get_db)
):
    """更新系统设置"""
    # 更新搜索设置
    search_result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "search_settings")
    )
    search_config = search_result.scalar_one_or_none()
    
    # 如果是 *** 则保留原有的 key
    if settings.search.api_key == '***' and search_config and search_config.value:
        try:
            old_data = json.loads(search_config.value)
            settings.search.api_key = old_data.get('api_key')
        except:
            pass
    
    search_value = settings.search.model_dump_json()
    
    if search_config:
        search_config.value = search_value
    else:
        search_config = SystemConfig(
            key="search_settings",
            value=search_value,
            description="联网搜索配置"
        )
        db.add(search_config)
    
    # 更新扫描设置
    scan_result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "scan_settings")
    )
    scan_config = scan_result.scalar_one_or_none()
    
    scan_value = settings.scan.model_dump_json()
    
    if scan_config:
        scan_config.value = scan_value
    else:
        scan_config = SystemConfig(
            key="scan_settings",
            value=scan_value,
            description="扫描配置"
        )
        db.add(scan_config)
    
    await db.commit()
    
    logger.info(f"System settings updated")
    
    # 隐藏返回的 API key
    if settings.search.api_key:
        settings.search.api_key = '***'
    
    return settings


async def get_scan_settings_from_db(db: AsyncSession) -> ScanSettings:
    """从数据库获取扫描设置"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "scan_settings")
    )
    config = result.scalar_one_or_none()
    
    if config and config.value:
        try:
            return ScanSettings(**json.loads(config.value))
        except:
            pass
    
    return ScanSettings()


# ============ 获取活跃的 LLM 配置 ============

async def get_active_llm_config(db: AsyncSession, role: str = "main") -> LLMConfig | None:
    """获取当前活跃的 LLM 配置。role=main/sub"""
    if role == "main":
        active_column = LLMConfig.active_for_main_agent
    elif role == "sub":
        active_column = LLMConfig.active_for_sub_agent
    else:
        raise ValueError("role must be 'main' or 'sub'")

    # 首先尝试获取指定用途的配置
    result = await db.execute(
        select(LLMConfig).where(
            active_column == True,
            LLMConfig.is_enabled == True
        )
    )
    config = result.scalar_one_or_none()
    
    if config:
        return config

    # 如果没有，按优先级和成功率选择
    result = await db.execute(
        select(LLMConfig).where(
            LLMConfig.is_enabled == True
        ).order_by(
            LLMConfig.priority.desc(),
            LLMConfig.failed_requests.asc(),
            LLMConfig.created_at.asc()
        ).limit(1)
    )
    
    return result.scalar_one_or_none()


async def get_search_settings_from_db(db: AsyncSession) -> SearchSettings:
    """从数据库获取搜索设置"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == "search_settings")
    )
    config = result.scalar_one_or_none()
    
    if config and config.value:
        try:
            return SearchSettings(**json.loads(config.value))
        except:
            pass
    
    return SearchSettings()


# ============ AI 人格配置 ============

@router.get("/personas", response_model=AIPersonaList)
async def list_personas(
    db: AsyncSession = Depends(get_db)
):
    """获取所有 AI 人格"""
    result = await db.execute(
        select(AIPersona).order_by(AIPersona.is_default.desc(), AIPersona.created_at.desc())
    )
    personas = result.scalars().all()
    
    return AIPersonaList(
        total=len(personas),
        items=[
            AIPersonaResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                system_prompt=p.system_prompt,
                is_default=p.is_default,
                is_enabled=p.is_enabled,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in personas
        ]
    )


@router.get("/personas/brief", response_model=list[AIPersonaBrief])
async def list_personas_brief(
    db: AsyncSession = Depends(get_db)
):
    """获取所有 AI 人格的简要信息（用于下拉选择）"""
    result = await db.execute(
        select(AIPersona)
        .where(AIPersona.is_enabled == True)
        .order_by(AIPersona.is_default.desc(), AIPersona.name.asc())
    )
    personas = result.scalars().all()
    
    return [
        AIPersonaBrief(
            id=p.id,
            name=p.name,
            description=p.description,
            is_default=p.is_default,
        )
        for p in personas
    ]


@router.get("/personas/{persona_id}", response_model=AIPersonaResponse)
async def get_persona(
    persona_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取单个 AI 人格详情"""
    result = await db.execute(
        select(AIPersona).where(AIPersona.id == persona_id)
    )
    persona = result.scalar_one_or_none()
    
    if not persona:
        raise HTTPException(status_code=404, detail="人格不存在")
    
    return AIPersonaResponse(
        id=persona.id,
        name=persona.name,
        description=persona.description,
        system_prompt=persona.system_prompt,
        is_default=persona.is_default,
        is_enabled=persona.is_enabled,
        created_at=persona.created_at,
        updated_at=persona.updated_at,
    )


@router.post("/personas", response_model=AIPersonaResponse)
async def create_persona(
    data: AIPersonaCreate,
    db: AsyncSession = Depends(get_db)
):
    """创建 AI 人格"""
    persona_id = str(uuid.uuid4())
    
    # 如果设置为默认，先取消其他默认人格
    if data.is_default:
        await db.execute(
            update(AIPersona).values(is_default=False)
        )
    
    persona = AIPersona(
        id=persona_id,
        name=data.name,
        description=data.description,
        system_prompt=data.system_prompt,
        is_default=data.is_default,
        is_enabled=True,
    )
    
    db.add(persona)
    await db.commit()
    await db.refresh(persona)
    
    logger.info(f"AI persona created: {persona.name}")
    
    return AIPersonaResponse(
        id=persona.id,
        name=persona.name,
        description=persona.description,
        system_prompt=persona.system_prompt,
        is_default=persona.is_default,
        is_enabled=persona.is_enabled,
        created_at=persona.created_at,
        updated_at=persona.updated_at,
    )


@router.patch("/personas/{persona_id}", response_model=AIPersonaResponse)
async def update_persona(
    persona_id: str,
    data: AIPersonaUpdate,
    db: AsyncSession = Depends(get_db)
):
    """更新 AI 人格"""
    result = await db.execute(
        select(AIPersona).where(AIPersona.id == persona_id)
    )
    persona = result.scalar_one_or_none()
    
    if not persona:
        raise HTTPException(status_code=404, detail="人格不存在")
    
    update_dict = data.model_dump(exclude_unset=True)
    
    # 如果设置为默认，先取消其他默认人格
    if update_dict.get('is_default'):
        await db.execute(
            update(AIPersona).where(AIPersona.id != persona_id).values(is_default=False)
        )
    
    for key, value in update_dict.items():
        setattr(persona, key, value)
    
    await db.commit()
    await db.refresh(persona)
    
    logger.info(f"AI persona updated: {persona.name}")
    
    return AIPersonaResponse(
        id=persona.id,
        name=persona.name,
        description=persona.description,
        system_prompt=persona.system_prompt,
        is_default=persona.is_default,
        is_enabled=persona.is_enabled,
        created_at=persona.created_at,
        updated_at=persona.updated_at,
    )


@router.delete("/personas/{persona_id}")
async def delete_persona(
    persona_id: str,
    db: AsyncSession = Depends(get_db)
):
    """删除 AI 人格"""
    result = await db.execute(
        select(AIPersona).where(AIPersona.id == persona_id)
    )
    persona = result.scalar_one_or_none()
    
    if not persona:
        raise HTTPException(status_code=404, detail="人格不存在")
    
    if persona.is_default:
        raise HTTPException(status_code=400, detail="不能删除默认人格，请先设置其他人格为默认")
    
    await db.delete(persona)
    await db.commit()
    
    logger.info(f"AI persona deleted: {persona.name}")
    
    return {"message": "人格已删除", "id": persona_id}


@router.post("/personas/{persona_id}/set-default")
async def set_default_persona(
    persona_id: str,
    db: AsyncSession = Depends(get_db)
):
    """设置默认 AI 人格"""
    result = await db.execute(
        select(AIPersona).where(AIPersona.id == persona_id)
    )
    persona = result.scalar_one_or_none()
    
    if not persona:
        raise HTTPException(status_code=404, detail="人格不存在")
    
    # 取消所有其他人格的默认状态
    await db.execute(
        update(AIPersona).values(is_default=False)
    )
    
    # 设置当前人格为默认
    persona.is_default = True
    await db.commit()
    
    logger.info(f"AI persona set as default: {persona.name}")
    
    return {"message": f"已设置 {persona.name} 为默认人格", "id": persona_id}


async def get_persona_by_id(db: AsyncSession, persona_id: str | None) -> AIPersona | None:
    """获取指定 ID 的人格，若为空则获取默认人格"""
    if persona_id:
        result = await db.execute(
            select(AIPersona).where(AIPersona.id == persona_id, AIPersona.is_enabled == True)
        )
        persona = result.scalar_one_or_none()
        if persona:
            return persona
    
    # 获取默认人格
    result = await db.execute(
        select(AIPersona).where(AIPersona.is_default == True, AIPersona.is_enabled == True)
    )
    persona = result.scalar_one_or_none()
    
    if persona:
        return persona
    
    # 如果没有默认人格，返回第一个启用的人格
    result = await db.execute(
        select(AIPersona).where(AIPersona.is_enabled == True).order_by(AIPersona.created_at.asc()).limit(1)
    )
    return result.scalar_one_or_none()
