import os
import uuid
import shutil
import aiofiles
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, cast, String, text
from loguru import logger
import httpx

from app.core.database import get_db
from app.core.config import get_settings
from app.models.database import SecurityTool, ToolType
from app.schemas.scan import (
    SecurityToolCreate, SecurityToolUpdate, SecurityToolResponse, SecurityToolList
)

settings = get_settings()
router = APIRouter(prefix="/tools", tags=["tools"])

FALLBACK_TOOLS_DIR = Path("/tmp/shelling_tools")
ALLOWED_EXTENSIONS = {
    "script": [".py", ".sh", ".bash", ".pl", ".rb", ".js", ".ts", ".go", ".rs", ".ps1"],
    "nuclei": [".yaml", ".yml"],
    "wordlist": [".txt", ".lst", ".dic", ".list"],
    "config": [".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg", ".xml"],
    "scanner": [
        # 脚本格式
        ".py", ".sh", ".bash", ".pl", ".rb", ".js", ".ts", ".go", ".rs", ".ps1",
        # 压缩包
        ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".7z", ".rar",
        # 二进制可执行文件
        ".exe", ".dll", ".so", ".dylib", ".bin",
        # 其他二进制格式
        ".jar", ".class", ".wasm",
    ],
    "skill": [
        # 文本格式
        ".py", ".md", ".txt", ".json", ".yaml", ".yml",
        # 脚本文件
        ".sh", ".bash", ".pl", ".rb", ".js", ".ts", ".go", ".rs", ".ps1",
        # 压缩包
        ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".7z", ".rar",
        # 二进制可执行文件
        ".exe", ".dll", ".so", ".dylib", ".bin",
        # 其他二进制格式
        ".jar", ".class", ".pyc", ".wasm",
        # 数据文件
        ".db", ".sqlite", ".sqlite3", ".dat", ".csv", ".xml",
    ],
}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB（从 10MB 增加到 100MB）


def _ensure_tools_dir(base_dir: Path) -> None:
    """确保指定工具目录存在"""
    base_dir.mkdir(parents=True, exist_ok=True)
    for tool_type in ToolType:
        (base_dir / tool_type.value).mkdir(exist_ok=True)


def ensure_tools_dir() -> Path:
    """确保工具目录存在并返回可用路径"""
    configured_dir = Path(settings.tools_dir)
    try:
        _ensure_tools_dir(configured_dir)
        return configured_dir
    except (PermissionError, OSError) as exc:
        logger.warning(f"Tools dir not writable: {configured_dir}. Falling back to {FALLBACK_TOOLS_DIR}. Reason: {exc}")
        try:
            _ensure_tools_dir(FALLBACK_TOOLS_DIR)
            return FALLBACK_TOOLS_DIR
        except (PermissionError, OSError) as fallback_exc:
            logger.error(f"Failed to create tools dir: {FALLBACK_TOOLS_DIR}. Reason: {fallback_exc}")
            raise HTTPException(status_code=500, detail="工具目录不可写，请检查 TOOLS_DIR 配置或目录权限")


async def ensure_tooltype_value(db: AsyncSession, value: str) -> None:
    """确保数据库 enum 包含指定工具类型"""
    enum_value = value.upper()
    await db.execute(
        text(f"""
            DO $$
            DECLARE
                enum_name text;
            BEGIN
                -- Try to detect enum name from security_tools.tool_type
                SELECT t.typname INTO enum_name
                FROM pg_type t
                JOIN pg_attribute a ON a.atttypid = t.oid
                JOIN pg_class c ON c.oid = a.attrelid
                WHERE c.relname = 'security_tools'
                  AND a.attname = 'tool_type'
                  AND t.typtype = 'e'
                LIMIT 1;

                -- Fallback to default enum name
                IF enum_name IS NULL THEN
                    enum_name := 'tooltype';
                END IF;

                IF EXISTS (SELECT 1 FROM pg_type WHERE typname = enum_name) THEN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_enum
                        WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = enum_name)
                        AND enumlabel = '{enum_value}'
                    ) THEN
                        EXECUTE format('ALTER TYPE %I ADD VALUE IF NOT EXISTS %L', enum_name, '{enum_value}');
                    END IF;
                END IF;
            END $$;
        """)
    )
    await db.commit()


def validate_file_extension(filename: str, tool_type: str) -> bool:
    """验证文件扩展名"""
    ext = Path(filename).suffix.lower()
    
    # 对于 skill/scanner 类型，如果没有扩展名，认为是二进制可执行文件
    if tool_type in {"skill", "scanner"} and not ext:
        logger.info(f"File without extension for {tool_type} type: {filename}, treating as binary")
        return True
    
    allowed = ALLOWED_EXTENSIONS.get(tool_type, [])
    return ext in allowed


@router.post("", response_model=SecurityToolResponse)
async def upload_tool(
    file: UploadFile = File(...),
    name: str = Form(...),
    tool_type: str = Form(...),
    description: str = Form(None),
    category: str = Form(None),
    tags: str = Form(""),  # 逗号分隔
    usage_instructions: str = Form(None),
    author: str = Form(None),
    version: str = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """上传安全工具"""
    tools_dir = ensure_tools_dir()
    
    logger.info(f"Upload tool: name={name}, type={tool_type}, file={file.filename}")
    
    # 验证工具类型
    if tool_type not in [t.value for t in ToolType]:
        logger.warning(f"Invalid tool type: {tool_type}")
        raise HTTPException(status_code=400, detail=f"无效的工具类型: {tool_type}")

    if tool_type == "scanner":
        try:
            await ensure_tooltype_value(db, tool_type)
        except Exception as exc:
            logger.error(f"Failed to ensure tooltype enum: {exc}")
            raise HTTPException(status_code=500, detail="初始化数据库工具类型失败，请检查数据库权限")
    
    # 验证文件扩展名
    if not validate_file_extension(file.filename, tool_type):
        allowed = ALLOWED_EXTENSIONS.get(tool_type, [])
        ext = Path(file.filename).suffix.lower() if file.filename else "(无扩展名)"
        logger.warning(f"Invalid file extension: {ext} for type {tool_type}")
        raise HTTPException(
            status_code=400, 
            detail=f"不支持的文件类型 '{ext}'。{tool_type} 类型允许: {', '.join(allowed)}"
        )
    
    # 检查文件大小
    file.file.seek(0, 2)  # 移到文件末尾
    file_size = file.file.tell()
    file.file.seek(0)  # 重置位置
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"文件大小超过限制 ({MAX_FILE_SIZE // 1024 // 1024}MB)")
    
    # 生成安全的文件名
    tool_id = str(uuid.uuid4())
    ext = Path(file.filename).suffix
    
    # 对于没有扩展名的 skill/scanner 文件，添加 .bin 扩展名
    if tool_type in {"skill", "scanner"} and not ext:
        ext = ".bin"
        logger.info(f"No extension for {tool_type} file, using .bin: {file.filename}")
    
    safe_filename = f"{tool_id}{ext}"
    file_path = tools_dir / tool_type / safe_filename
    
    # 保存文件
    try:
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # 为特定类型的文件设置执行权限
        if tool_type in ['skill', 'script', 'scanner']:
            executable_extensions = ['.sh', '.bash', '.pl', '.rb', '.py', '.js', '.bin', '.exe', '']
            file_ext = Path(file_path).suffix
            # 无扩展名或特定扩展名的文件设置为可执行
            if not file_ext or file_ext in executable_extensions:
                os.chmod(file_path, 0o755)
                logger.info(f"Set executable permission for {file_path}")
                
    except Exception as e:
        logger.error(f"Failed to save tool file: {e}")
        raise HTTPException(status_code=500, detail="文件保存失败")
    
    # 解析标签
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    
    # 创建数据库记录
    tool = SecurityTool(
        id=tool_id,
        name=name,
        description=description,
        tool_type=ToolType(tool_type),
        filename=file.filename,
        file_path=str(file_path),
        file_size=file_size,
        category=category,
        tags=tag_list,
        usage_instructions=usage_instructions,
        author=author,
        version=version,
        is_enabled=True,
        is_verified=False,
    )
    
    db.add(tool)
    await db.commit()
    await db.refresh(tool)
    
    logger.info(f"Tool uploaded: {name} ({tool_type})")
    
    return SecurityToolResponse(
        id=tool.id,
        name=tool.name,
        description=tool.description,
        tool_type=tool.tool_type.value,
        filename=tool.filename,
        file_size=tool.file_size,
        category=tool.category,
        tags=tool.tags or [],
        usage_instructions=tool.usage_instructions,
        is_enabled=tool.is_enabled,
        is_verified=tool.is_verified,
        author=tool.author,
        version=tool.version,
        created_at=tool.created_at,
        updated_at=tool.updated_at,
    )


@router.get("", response_model=SecurityToolList)
async def list_tools(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    tool_type: str | None = None,
    category: str | None = None,
    enabled_only: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """获取工具列表"""
    query = select(SecurityTool).order_by(SecurityTool.created_at.desc())
    count_query = select(func.count(SecurityTool.id))
    
    if tool_type:
        if tool_type not in [t.value for t in ToolType]:
            raise HTTPException(status_code=400, detail=f"无效的工具类型: {tool_type}")
        # Compare as text to avoid enum mismatch errors on older schemas
        normalized_type = tool_type.lower()
        query = query.where(func.lower(cast(SecurityTool.tool_type, String)) == normalized_type)
        count_query = count_query.where(func.lower(cast(SecurityTool.tool_type, String)) == normalized_type)
    
    if category:
        query = query.where(SecurityTool.category == category)
        count_query = count_query.where(SecurityTool.category == category)
    
    if enabled_only:
        query = query.where(SecurityTool.is_enabled == True)
        count_query = count_query.where(SecurityTool.is_enabled == True)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    tools = result.scalars().all()
    total = (await db.execute(count_query)).scalar()
    
    return SecurityToolList(
        total=total,
        items=[
            SecurityToolResponse(
                id=t.id,
                name=t.name,
                description=t.description,
                tool_type=t.tool_type.value,
                filename=t.filename,
                file_size=t.file_size,
                category=t.category,
                tags=t.tags or [],
                usage_instructions=t.usage_instructions,
                is_enabled=t.is_enabled,
                is_verified=t.is_verified,
                author=t.author,
                version=t.version,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
            for t in tools
        ]
    )


@router.get("/categories/list")
async def list_categories(
    db: AsyncSession = Depends(get_db)
):
    """获取所有工具分类"""
    result = await db.execute(
        select(SecurityTool.category).where(SecurityTool.category != None).distinct()
    )
    categories = [row[0] for row in result.all()]
    
    return {
        "categories": sorted(set(categories)),
        "tool_types": [t.value for t in ToolType]
    }


@router.get("/kali-scanners")
async def list_kali_scanners():
    """获取 Kali 容器中预置的扫描器列表，按类别分组"""
    from scanners import SCANNER_CATEGORIES, SCANNER_REGISTRY

    categories = []
    for cat_key, cat_config in SCANNER_CATEGORIES.items():
        tools = []
        for scanner_type in cat_config["tools"]:
            scanner_class = SCANNER_REGISTRY.get(scanner_type)
            tools.append({
                "type": scanner_type.value,
                "name": scanner_type.value.upper(),
                "registered": scanner_class is not None,
            })
        categories.append({
            "key": cat_key,
            "name": cat_config["name"],
            "description": cat_config["description"],
            "tools": tools,
        })

    return {
        "total": sum(len(c["tools"]) for c in categories),
        "categories": categories,
    }


@router.get("/skill-template")
async def get_skill_template():
    """获取 Skill 模板示例"""
    template = '''"""
Skill 名称: 描述您的 Skill 功能
"""

# ============ Skill 元数据（必需）============
SKILL_NAME = "my_skill"  # Skill 唯一标识名
SKILL_DESCRIPTION = "描述这个 Skill 的功能"

# 参数定义（JSON Schema 格式）
SKILL_PARAMETERS = {
    "target": {
        "type": "string",
        "description": "目标地址",
        "required": True
    },
    "option": {
        "type": "string",
        "description": "可选参数",
        "required": False
    }
}


# ============ Skill 入口函数（必需）============
async def run(target: str, option: str = None, **kwargs) -> dict:
    """
    执行 Skill
    
    Args:
        target: 目标地址
        option: 可选参数
        
    Returns:
        dict: {"success": bool, "output": str, "error": str | None}
    """
    try:
        # 在这里编写您的逻辑
        result = f"对 {target} 执行了操作"
        
        return {
            "success": True,
            "output": result
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e)
        }
'''
    return {"template": template}


@router.get("/{tool_id}", response_model=SecurityToolResponse)
async def get_tool(
    tool_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取工具详情"""
    result = await db.execute(
        select(SecurityTool).where(SecurityTool.id == tool_id)
    )
    tool = result.scalar_one_or_none()
    
    if not tool:
        raise HTTPException(status_code=404, detail="工具不存在")
    
    return SecurityToolResponse(
        id=tool.id,
        name=tool.name,
        description=tool.description,
        tool_type=tool.tool_type.value,
        filename=tool.filename,
        file_size=tool.file_size,
        category=tool.category,
        tags=tool.tags or [],
        usage_instructions=tool.usage_instructions,
        is_enabled=tool.is_enabled,
        is_verified=tool.is_verified,
        author=tool.author,
        version=tool.version,
        created_at=tool.created_at,
        updated_at=tool.updated_at,
    )


@router.get("/{tool_id}/content")
async def get_tool_content(
    tool_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取工具文件内容（仅文本文件）"""
    result = await db.execute(
        select(SecurityTool).where(SecurityTool.id == tool_id)
    )
    tool = result.scalar_one_or_none()
    
    if not tool:
        raise HTTPException(status_code=404, detail="工具不存在")
    
    file_path = Path(tool.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="文件不存在")
    
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
        return {"content": content, "filename": tool.filename}
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="无法读取二进制文件")


@router.patch("/{tool_id}", response_model=SecurityToolResponse)
async def update_tool(
    tool_id: str,
    update_data: SecurityToolUpdate,
    db: AsyncSession = Depends(get_db)
):
    """更新工具信息"""
    result = await db.execute(
        select(SecurityTool).where(SecurityTool.id == tool_id)
    )
    tool = result.scalar_one_or_none()
    
    if not tool:
        raise HTTPException(status_code=404, detail="工具不存在")
    
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(tool, key, value)
    
    await db.commit()
    await db.refresh(tool)
    
    return SecurityToolResponse(
        id=tool.id,
        name=tool.name,
        description=tool.description,
        tool_type=tool.tool_type.value,
        filename=tool.filename,
        file_size=tool.file_size,
        category=tool.category,
        tags=tool.tags or [],
        usage_instructions=tool.usage_instructions,
        is_enabled=tool.is_enabled,
        is_verified=tool.is_verified,
        author=tool.author,
        version=tool.version,
        created_at=tool.created_at,
        updated_at=tool.updated_at,
    )


@router.delete("/{tool_id}")
async def delete_tool(
    tool_id: str,
    db: AsyncSession = Depends(get_db)
):
    """删除工具"""
    result = await db.execute(
        select(SecurityTool).where(SecurityTool.id == tool_id)
    )
    tool = result.scalar_one_or_none()
    
    if not tool:
        raise HTTPException(status_code=404, detail="工具不存在")
    
    # 删除文件
    file_path = Path(tool.file_path)
    if file_path.exists():
        try:
            file_path.unlink()
        except Exception as e:
            logger.warning(f"Failed to delete tool file: {e}")
    
    # 删除数据库记录
    await db.delete(tool)
    await db.commit()
    
    logger.info(f"Tool deleted: {tool.name}")
    
    return {"message": "工具已删除", "id": tool_id}


# ============= Nuclei 模板代理 =============

@router.get("/nuclei-templates")
async def get_nuclei_templates(
    category: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """从 Kali 容器获取 Nuclei 模板列表"""
    kali_url = settings.kali_scanner_url
    params = {"skip": skip, "limit": limit}
    if category:
        params["category"] = category
    if severity:
        params["severity"] = severity
    if search:
        params["search"] = search

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{kali_url}/nuclei-templates", params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.error("Kali nuclei-templates request timeout")
        raise HTTPException(status_code=504, detail="Kali 扫描器响应超时")
    except httpx.HTTPStatusError as e:
        logger.error(f"Kali nuclei-templates HTTP error: {e.response.status_code}")
        raise HTTPException(status_code=502, detail="Kali 扫描器返回错误")
    except Exception as e:
        logger.error(f"Kali nuclei-templates connection error: {e}")
        raise HTTPException(status_code=502, detail=f"无法连接 Kali 扫描器: {str(e)}")


@router.get("/nuclei-templates/stats")
async def get_nuclei_templates_stats():
    """从 Kali 容器获取 Nuclei 模板统计"""
    kali_url = settings.kali_scanner_url
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{kali_url}/nuclei-templates/stats")
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.error(f"Kali nuclei-templates/stats error: {e}")
        return {"total": 0, "categories": {}, "severities": {}, "templates_dir": ""}


@router.get("/nuclei-templates/content")
async def get_nuclei_template_content(path: str = Query(..., description="模板相对路径")):
    """从 Kali 容器读取 Nuclei 模板内容"""
    kali_url = settings.kali_scanner_url
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{kali_url}/nuclei-templates/content",
                params={"path": path}
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="模板不存在")
        raise HTTPException(status_code=502, detail="Kali 扫描器返回错误")
    except Exception as e:
        logger.error(f"Kali nuclei-templates/content error: {e}")
        raise HTTPException(status_code=502, detail=f"无法连接 Kali 扫描器: {str(e)}")
