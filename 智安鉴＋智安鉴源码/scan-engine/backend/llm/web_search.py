"""Web Search Tool - 联网搜索工具供 LLM Agent 使用"""
import asyncio
import aiohttp
from typing import Optional
from pydantic import BaseModel
from loguru import logger


class SearchResult(BaseModel):
    """搜索结果"""
    title: str
    url: str
    snippet: str


class WebSearchTool:
    """联网搜索工具"""
    
    def __init__(
        self,
        provider: str = "duckduckgo",
        api_key: str = None,
        max_results: int = 5
    ):
        self.provider = provider
        self.api_key = api_key
        self.max_results = max_results
    
    async def search(self, query: str) -> list[SearchResult]:
        """执行搜索"""
        if self.provider == "none":
            return []
        
        try:
            if self.provider == "duckduckgo":
                return await self._search_duckduckgo(query)
            elif self.provider == "tavily":
                return await self._search_tavily(query)
            elif self.provider == "serper":
                return await self._search_serper(query)
            elif self.provider == "bing":
                return await self._search_bing(query)
            else:
                logger.warning(f"Unknown search provider: {self.provider}")
                return []
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    async def _search_duckduckgo(self, query: str) -> list[SearchResult]:
        """使用 DuckDuckGo 搜索（免费）"""
        try:
            from duckduckgo_search import DDGS
            
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                lambda: list(DDGS().text(query, max_results=self.max_results))
            )
            
            return [
                SearchResult(
                    title=r.get('title', ''),
                    url=r.get('href', ''),
                    snippet=r.get('body', '')
                )
                for r in results
            ]
        except ImportError:
            logger.warning("duckduckgo_search not installed, trying alternative...")
            return await self._search_duckduckgo_api(query)
        except Exception as e:
            logger.error(f"DuckDuckGo search error: {e}")
            return []
    
    async def _search_duckduckgo_api(self, query: str) -> list[SearchResult]:
        """DuckDuckGo API 备用方法"""
        url = "https://api.duckduckgo.com/"
        params = {
            "q": query,
            "format": "json",
            "no_html": 1,
            "skip_disambig": 1
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status != 200:
                    return []
                
                data = await resp.json()
                results = []
                
                # 处理相关主题
                for topic in data.get('RelatedTopics', [])[:self.max_results]:
                    if 'Text' in topic:
                        results.append(SearchResult(
                            title=topic.get('Text', '')[:100],
                            url=topic.get('FirstURL', ''),
                            snippet=topic.get('Text', '')
                        ))
                
                return results
    
    async def _search_tavily(self, query: str) -> list[SearchResult]:
        """使用 Tavily API 搜索"""
        if not self.api_key:
            logger.error("Tavily API key not configured")
            return []
        
        url = "https://api.tavily.com/search"
        payload = {
            "api_key": self.api_key,
            "query": query,
            "max_results": self.max_results,
            "search_depth": "basic"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=30) as resp:
                if resp.status != 200:
                    logger.error(f"Tavily API error: {resp.status}")
                    return []
                
                data = await resp.json()
                
                return [
                    SearchResult(
                        title=r.get('title', ''),
                        url=r.get('url', ''),
                        snippet=r.get('content', '')[:500]
                    )
                    for r in data.get('results', [])
                ]
    
    async def _search_serper(self, query: str) -> list[SearchResult]:
        """使用 Serper API 搜索 (Google)"""
        if not self.api_key:
            logger.error("Serper API key not configured")
            return []
        
        url = "https://google.serper.dev/search"
        headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "q": query,
            "num": self.max_results
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    logger.error(f"Serper API error: {resp.status}")
                    return []
                
                data = await resp.json()
                
                return [
                    SearchResult(
                        title=r.get('title', ''),
                        url=r.get('link', ''),
                        snippet=r.get('snippet', '')
                    )
                    for r in data.get('organic', [])
                ]
    
    async def _search_bing(self, query: str) -> list[SearchResult]:
        """使用 Bing Search API"""
        if not self.api_key:
            logger.error("Bing API key not configured")
            return []
        
        url = "https://api.bing.microsoft.com/v7.0/search"
        headers = {
            "Ocp-Apim-Subscription-Key": self.api_key
        }
        params = {
            "q": query,
            "count": self.max_results,
            "responseFilter": "Webpages"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    logger.error(f"Bing API error: {resp.status}")
                    return []
                
                data = await resp.json()
                
                return [
                    SearchResult(
                        title=r.get('name', ''),
                        url=r.get('url', ''),
                        snippet=r.get('snippet', '')
                    )
                    for r in data.get('webPages', {}).get('value', [])
                ]


# 工具 Schema 供 LLM 使用
WEB_SEARCH_SCHEMA = {
    "name": "web_search",
    "description": "联网搜索。用于查找最新的漏洞信息、CVE 详情、安全公告、exploit 代码等。",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "搜索关键词，如 'CVE-2024-1234 exploit' 或 'nginx vulnerability 2024'"
            }
        },
        "required": ["query"]
    }
}
