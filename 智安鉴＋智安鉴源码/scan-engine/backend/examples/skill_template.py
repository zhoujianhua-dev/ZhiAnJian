"""
示例 Skill: 子域名枚举
这是一个用户自定义 Skill 的示例模板

Skill 文件格式要求:
1. 必须定义 SKILL_NAME - Skill 名称
2. 必须定义 SKILL_DESCRIPTION - Skill 描述
3. 必须定义 SKILL_PARAMETERS - 参数定义（JSON Schema 格式）
4. 必须定义 async def run(**kwargs) 函数 - 执行入口
"""
import asyncio
import subprocess

# ============ Skill 元数据 ============
SKILL_NAME = "subdomain_enum"
SKILL_DESCRIPTION = "子域名枚举工具。使用多种方式发现目标的子域名。"

SKILL_PARAMETERS = {
    "domain": {
        "type": "string",
        "description": "目标域名",
        "required": True
    },
    "wordlist": {
        "type": "string",
        "description": "自定义字典路径（可选）",
        "required": False
    }
}


# ============ Skill 实现 ============
async def run(domain: str, wordlist: str = None, **kwargs) -> dict:
    """
    执行子域名枚举
    
    Args:
        domain: 目标域名
        wordlist: 自定义字典路径
        
    Returns:
        dict: {
            "success": bool,
            "output": str,
            "error": str | None
        }
    """
    subdomains = []
    
    try:
        # 方法1: DNS 查询常见子域名
        common_subs = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging"]
        
        for sub in common_subs:
            full_domain = f"{sub}.{domain}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", full_domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if stdout.strip():
                    subdomains.append(f"{full_domain} -> {stdout.decode().strip()}")
            except:
                pass
        
        if subdomains:
            output = f"发现 {len(subdomains)} 个子域名:\n" + "\n".join(subdomains)
            return {"success": True, "output": output}
        else:
            return {"success": True, "output": "未发现子域名"}
            
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}
