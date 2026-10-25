"""Skill Loader - 加载用户上传的 Skill 供 LLM 调用"""
import ast
import asyncio
import sys
import os
import json
import shlex
import zipfile
import importlib.util
from pathlib import Path
from typing import Optional, Callable, Awaitable, Any
from pydantic import BaseModel
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import SecurityTool, ToolType
from app.core.database import AsyncSessionLocal


class SkillInfo(BaseModel):
    """Skill 信息"""
    id: str
    name: str
    description: str
    parameters: dict
    file_path: str
    skill_type: str = "python"  # python, markdown, zip


class SkillResult(BaseModel):
    """Skill 执行结果"""
    success: bool
    output: str
    error: Optional[str] = None


def parse_skill_metadata(file_path: str) -> dict:
    """
    解析 Skill 文件的元数据
    
    Skill 文件格式要求:
    - 必须包含 SKILL_NAME, SKILL_DESCRIPTION 变量
    - 必须包含 SKILL_PARAMETERS 字典定义参数
    - 必须包含 async def run(**kwargs) 函数
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        metadata = {
            'name': None,
            'description': None,
            'parameters': {},
            'has_run_function': False,
        }
        
        for node in ast.walk(tree):
            # 查找变量赋值
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == 'SKILL_NAME' and isinstance(node.value, ast.Constant):
                            metadata['name'] = node.value.value
                        elif target.id == 'SKILL_DESCRIPTION' and isinstance(node.value, ast.Constant):
                            metadata['description'] = node.value.value
                        elif target.id == 'SKILL_PARAMETERS' and isinstance(node.value, ast.Dict):
                            # 简单解析参数字典
                            try:
                                metadata['parameters'] = ast.literal_eval(ast.unparse(node.value))
                            except:
                                pass
            
            # 查找 run 函数
            if isinstance(node, ast.AsyncFunctionDef) and node.name == 'run':
                metadata['has_run_function'] = True
        
        return metadata
    except Exception as e:
        logger.error(f"Failed to parse skill metadata from {file_path}: {e}")
        return {}


def parse_markdown_skill(file_path: str) -> dict:
    """
    解析 Markdown 格式的 Skill
    
    Markdown Skill 是纯描述性的，LLM 可以根据描述自由生成代码执行
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 从 Markdown 中提取标题作为名称
        lines = content.strip().split('\n')
        name = None
        description = content[:500]  # 取前500字符作为描述
        
        for line in lines:
            if line.startswith('# '):
                name = line[2:].strip()
                break
        
        return {
            'name': name,
            'description': description,
            'parameters': {
                'query': {
                    'type': 'string',
                    'description': '要执行的具体任务或查询',
                    'required': True
                }
            },
            'content': content,
            'is_markdown': True,
        }
    except Exception as e:
        logger.error(f"Failed to parse markdown skill from {file_path}: {e}")
        return {}


def parse_zip_skill(file_path: str) -> dict:
    """
    解析 SkillHub 格式的 zip 包
    
    SkillHub zip 包结构:
    - skill.json: 包含 name, description, parameters 等元数据
    - main.py: 主入口文件，包含 run() 函数
    - 或者其他文件结构
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            file_list = zf.namelist()
            
            metadata = {
                'name': None,
                'description': None,
                'parameters': {},
                'has_run_function': False,
                'entry_file': None,
                'is_zip': True,
            }
            
            # 查找 skill.json 或 manifest.json
            for manifest_name in ['skill.json', 'manifest.json', 'package.json']:
                if manifest_name in file_list:
                    manifest_content = zf.read(manifest_name).decode('utf-8')
                    manifest = json.loads(manifest_content)
                    metadata['name'] = manifest.get('name')
                    metadata['description'] = manifest.get('description')
                    metadata['parameters'] = manifest.get('parameters', {})
                    metadata['entry_file'] = manifest.get('entry', manifest.get('main', 'main.py'))
                    break
            
            # 查找入口文件
            entry_candidates = ['main.py', 'index.py', 'skill.py', '__main__.py']
            if metadata['entry_file']:
                entry_candidates.insert(0, metadata['entry_file'])
            
            for entry in entry_candidates:
                # 支持根目录或子目录中的入口文件
                matches = [f for f in file_list if f.endswith(entry)]
                if matches:
                    metadata['entry_file'] = matches[0]
                    # 检查是否有 run 函数
                    try:
                        entry_content = zf.read(matches[0]).decode('utf-8')
                        if 'def run' in entry_content or 'async def run' in entry_content:
                            metadata['has_run_function'] = True
                    except:
                        pass
                    break
            
            # 如果没有找到入口，检查是否有 README.md 作为描述性 skill
            if not metadata['has_run_function']:
                readme_files = [f for f in file_list if f.lower().endswith('readme.md')]
                if readme_files:
                    readme_content = zf.read(readme_files[0]).decode('utf-8')
                    if not metadata['description']:
                        metadata['description'] = readme_content[:500]
                    metadata['is_descriptive'] = True
                    metadata['has_run_function'] = True  # 描述性 skill 视为可用
            
            return metadata
    except Exception as e:
        logger.error(f"Failed to parse zip skill from {file_path}: {e}")
        return {}


async def load_skills_from_db(session_factory=None) -> list[SkillInfo]:
    """从数据库加载所有启用的 Skill
    
    Args:
        session_factory: 数据库会话工厂 (可选，默认使用 AsyncSessionLocal)
    """
    skills = []
    session_factory = session_factory or AsyncSessionLocal
    
    try:
        async with session_factory() as db:
            result = await db.execute(
                select(SecurityTool).where(
                    SecurityTool.tool_type == ToolType.SKILL,
                    SecurityTool.is_enabled == True
                )
            )
            db_skills = result.scalars().all()
            
            for tool in db_skills:
                file_path = Path(tool.file_path)
                if not file_path.exists():
                    logger.warning(f"Skill file not found: {file_path}")
                    continue
                
                suffix = file_path.suffix.lower()
                
                if suffix == '.py':
                    # Python skill
                    metadata = parse_skill_metadata(str(file_path))
                    if not metadata.get('has_run_function'):
                        logger.warning(f"Skill {tool.name} missing run() function")
                        continue
                    skill_type = "python"
                    
                elif suffix == '.md' or suffix == '.txt':
                    # Markdown/文本 skill
                    metadata = parse_markdown_skill(str(file_path))
                    skill_type = "markdown"
                    
                elif suffix in ['.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.7z']:
                    # 压缩包 skill
                    metadata = parse_zip_skill(str(file_path))
                    if not metadata.get('has_run_function') and not metadata.get('is_descriptive'):
                        logger.warning(f"Skill {tool.name} missing run() function or description")
                        continue
                    skill_type = "archive"
                    
                elif suffix in ['.exe', '.bin', '.so', '.dylib', '.dll']:
                    # 二进制可执行文件 skill
                    metadata = {
                        'name': tool.name,
                        'description': tool.description or f"二进制工具: {tool.name}",
                        'parameters': {
                            'args': {
                                'type': 'string',
                                'description': '命令行参数',
                                'required': False
                            }
                        },
                        'is_binary': True,
                    }
                    skill_type = "binary"
                    
                else:
                    # 其他文件类型作为通用数据文件
                    metadata = {
                        'name': tool.name,
                        'description': tool.description or f"数据文件: {tool.name} ({suffix})",
                        'parameters': {
                            'operation': {
                                'type': 'string',
                                'description': '要执行的操作',
                                'required': True
                            }
                        },
                        'is_data_file': True,
                    }
                    skill_type = "data"
                
                skill_info = SkillInfo(
                    id=tool.id,
                    name=metadata.get('name') or tool.name,
                    description=metadata.get('description') or tool.description or "用户自定义 Skill",
                    parameters=metadata.get('parameters', {}),
                    file_path=str(file_path),
                    skill_type=skill_type,
                )
                skills.append(skill_info)
                logger.debug(f"Loaded skill: {skill_info.name} (type: {skill_type})")
                
    except Exception as e:
        logger.error(f"Failed to load skills from database: {e}")
    
    return skills


async def execute_skill(
    skill: SkillInfo,
    kwargs: dict,
    timeout: int = 300,
    log_callback: Callable = None
) -> SkillResult:
    """
    执行 Skill
    
    通过动态导入并调用 skill 的 run() 函数，或直接执行二进制文件
    """
    try:
        if skill.skill_type == "markdown":
            # Markdown skill 返回内容供 LLM 参考
            with open(skill.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return SkillResult(
                success=True,
                output=f"[Skill 参考文档]\n\n{content}\n\n请根据以上文档和用户请求 '{kwargs.get('query', '')}' 生成并执行相应操作。"
            )
        
        elif skill.skill_type == "archive":
            return await _execute_zip_skill(skill, kwargs, timeout)
        
        elif skill.skill_type == "binary":
            return await _execute_binary_skill(skill, kwargs, timeout)
        
        elif skill.skill_type == "data":
            return await _execute_data_file_skill(skill, kwargs, timeout)
        
        else:
            return await _execute_python_skill(skill, kwargs, timeout)
            
    except asyncio.TimeoutError:
        return SkillResult(success=False, output="", error=f"Skill 执行超时 ({timeout}秒)")
    except Exception as e:
        logger.error(f"Skill execution error: {e}")
        return SkillResult(success=False, output="", error=str(e))


async def _execute_python_skill(skill: SkillInfo, kwargs: dict, timeout: int) -> SkillResult:
    """执行 Python Skill"""
    try:
        # 动态加载模块
        spec = importlib.util.spec_from_file_location(f"skill_{skill.id}", skill.file_path)
        if spec is None or spec.loader is None:
            return SkillResult(success=False, output="", error="无法加载 Skill 模块")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"skill_{skill.id}"] = module
        spec.loader.exec_module(module)
        
        # 检查 run 函数
        if not hasattr(module, 'run'):
            return SkillResult(success=False, output="", error="Skill 缺少 run() 函数")
        
        run_func = getattr(module, 'run')
        
        # 执行 skill
        if asyncio.iscoroutinefunction(run_func):
            result = await asyncio.wait_for(run_func(**kwargs), timeout=timeout)
        else:
            # 同步函数在线程池中执行
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: run_func(**kwargs)),
                timeout=timeout
            )
        
        # 处理结果
        if isinstance(result, dict):
            return SkillResult(
                success=result.get('success', True),
                output=result.get('output', str(result)),
                error=result.get('error')
            )
        else:
            return SkillResult(success=True, output=str(result))
            
    finally:
        # 清理模块
        if f"skill_{skill.id}" in sys.modules:
            del sys.modules[f"skill_{skill.id}"]


async def _execute_zip_skill(skill: SkillInfo, kwargs: dict, timeout: int) -> SkillResult:
    """执行 SkillHub zip 包中的 Skill"""
    import tempfile
    import shutil
    
    temp_dir = None
    try:
        # 解压到临时目录
        temp_dir = tempfile.mkdtemp(prefix=f"skill_{skill.id}_")
        
        with zipfile.ZipFile(skill.file_path, 'r') as zf:
            zf.extractall(temp_dir)
            
            # 查找入口文件
            metadata = parse_zip_skill(skill.file_path)
            
            if metadata.get('is_descriptive'):
                # 描述性 skill，返回 README 内容
                readme_files = [f for f in zf.namelist() if f.lower().endswith('readme.md')]
                if readme_files:
                    readme_path = Path(temp_dir) / readme_files[0]
                    with open(readme_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    return SkillResult(
                        success=True,
                        output=f"[Skill 参考文档]\n\n{content}\n\n请根据以上文档和用户请求 '{kwargs.get('query', '')}' 生成并执行相应操作。"
                    )
            
            entry_file = metadata.get('entry_file')
            if not entry_file:
                return SkillResult(success=False, output="", error="找不到 Skill 入口文件")
            
            entry_path = Path(temp_dir) / entry_file
            if not entry_path.exists():
                return SkillResult(success=False, output="", error=f"入口文件不存在: {entry_file}")
        
        # 添加临时目录到 sys.path
        if temp_dir not in sys.path:
            sys.path.insert(0, temp_dir)
        
        # 动态加载模块
        module_name = f"skill_zip_{skill.id}"
        spec = importlib.util.spec_from_file_location(module_name, str(entry_path))
        if spec is None or spec.loader is None:
            return SkillResult(success=False, output="", error="无法加载 Skill 模块")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # 检查 run 函数
        if not hasattr(module, 'run'):
            return SkillResult(success=False, output="", error="Skill 缺少 run() 函数")
        
        run_func = getattr(module, 'run')
        
        # 执行 skill
        if asyncio.iscoroutinefunction(run_func):
            result = await asyncio.wait_for(run_func(**kwargs), timeout=timeout)
        else:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: run_func(**kwargs)),
                timeout=timeout
            )
        
        # 处理结果
        if isinstance(result, dict):
            return SkillResult(
                success=result.get('success', True),
                output=result.get('output', str(result)),
                error=result.get('error')
            )
        else:
            return SkillResult(success=True, output=str(result))
            
    finally:
        # 清理
        if f"skill_zip_{skill.id}" in sys.modules:
            del sys.modules[f"skill_zip_{skill.id}"]
        if temp_dir and temp_dir in sys.path:
            sys.path.remove(temp_dir)
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def get_skills_schema(skills: list[SkillInfo]) -> list[dict]:
    """生成 Skill 的工具 Schema 供 LLM 使用"""
    schemas = []
    
    for skill in skills:
        # 确保参数格式正确
        parameters = skill.parameters or {}
        if not parameters:
            # 默认添加一个通用查询参数
            parameters = {
                'query': {
                    'type': 'string',
                    'description': '要执行的具体任务或查询',
                }
            }
        
        properties = {}
        required = []
        
        for param_name, param_info in parameters.items():
            if isinstance(param_info, dict):
                properties[param_name] = {
                    'type': param_info.get('type', 'string'),
                    'description': param_info.get('description', param_name),
                }
                if param_info.get('required', False):
                    required.append(param_name)
            else:
                properties[param_name] = {
                    'type': 'string',
                    'description': str(param_info),
                }
        
        schema = {
            "name": f"skill_{skill.name}",
            "description": f"[用户 Skill] {skill.description}",
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }
        schemas.append(schema)
    
    return schemas


async def _execute_binary_skill(skill: SkillInfo, kwargs: dict, timeout: int) -> SkillResult:
    """执行二进制可执行文件 Skill - 在 Kali 容器内执行"""
    from scanners.kali_client import KaliClient
    
    try:
        # 构建命令
        cmd_parts = [skill.file_path]
        
        # 添加命令行参数
        args_str = kwargs.get('args', '')
        if args_str:
            cmd_parts.extend(shlex.split(args_str))
        
        # 构建环境变量
        env_vars = {}
        for key, value in kwargs.items():
            if key != 'args':
                env_vars[f'SKILL_{key.upper()}'] = str(value)
        
        # 构建完整的 shell 命令（包含环境变量）
        env_prefix = ' '.join(f'{k}="{v}"' for k, v in env_vars.items())
        cmd_str = ' '.join(shlex.quote(part) for part in cmd_parts)
        
        if env_prefix:
            full_cmd = f"{env_prefix} {cmd_str}"
        else:
            full_cmd = cmd_str
        
        logger.info(f"Executing binary skill in Kali: {full_cmd}")
        
        # 在 Kali 容器内执行
        kali_client = KaliClient()
        result = await kali_client.execute_shell_command(full_cmd, timeout=timeout)
        
        return SkillResult(
            success=result.success,
            output=result.output,
            error=result.error if not result.success else None
        )
            
    except Exception as e:
        logger.error(f"Binary skill execution error: {e}")
        return SkillResult(success=False, output="", error=str(e))


async def _execute_data_file_skill(skill: SkillInfo, kwargs: dict, timeout: int) -> SkillResult:
    """处理数据文件 Skill - 返回文件信息供 AI 参考"""
    try:
        operation = kwargs.get('operation', 'info')
        file_path = Path(skill.file_path)
        
        if operation == 'info':
            # 返回文件信息
            stat = file_path.stat()
            info = f"""数据文件信息:
文件名: {file_path.name}
路径: {skill.file_path}
大小: {stat.st_size} 字节 ({stat.st_size / 1024:.2f} KB)
类型: {file_path.suffix}
修改时间: {stat.st_mtime}

AI 可以：
1. 要求读取文件内容 (operation='read')
2. 要求提取文件的特定部分
3. 根据文件类型使用相应的工具处理
4. 将文件作为工具的输入参数

示例: {{"operation": "read", "max_bytes": 1000}}
"""
            return SkillResult(success=True, output=info)
        
        elif operation == 'read':
            # 读取文件内容
            max_bytes = int(kwargs.get('max_bytes', 10000))
            
            try:
                with open(skill.file_path, 'rb') as f:
                    content = f.read(max_bytes)
                
                # 尝试解码为文本
                try:
                    text = content.decode('utf-8')
                    return SkillResult(success=True, output=f"文件内容 (前 {max_bytes} 字节):\n\n{text}")
                except UnicodeDecodeError:
                    # 二进制文件，返回十六进制
                    hex_dump = content.hex()
                    return SkillResult(
                        success=True, 
                        output=f"二进制文件内容 (十六进制，前 {max_bytes} 字节):\n\n{hex_dump}\n\n文件路径: {skill.file_path}"
                    )
            except Exception as e:
                return SkillResult(success=False, output="", error=f"读取文件失败: {e}")
        
        elif operation == 'path':
            # 返回文件路径供其他工具使用
            return SkillResult(success=True, output=skill.file_path)
        
        else:
            return SkillResult(
                success=False,
                output="",
                error=f"不支持的操作: {operation}。支持的操作: info, read, path"
            )
            
    except Exception as e:
        logger.error(f"Data file skill error: {e}")
        return SkillResult(success=False, output="", error=str(e))
