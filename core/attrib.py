# -*- coding: utf-8 -*-
"""
智安鉴 · 归属证明自动取证
=========================
根据漏洞地址 / 域名，自动完成“资产归属”核验取证，免去手动截图：
  1. 调用本机 Chrome / Edge 无头模式，真实渲染目标站点；
  2. 从渲染后的页面自动识别 ICP 备案号、公网安备号、版权所有 / 主办单位；
  3. 证据图“只截取页面底部的备案公示条”（版权单位 + ICP + 公网安备），
     不截取网站首页大图 / logo / 新闻等无关内容，紧凑、干净，可直接作为归属证明；
  4. 图片存入 data/uploads，导出报告即自动带入“归属证明”图片；并生成核验说明文字。

真实能力边界：
  - 识别与截图均针对“目标站点自身官网页脚公示内容”，政府/高校/企业站普遍公示；
  - 第三方 ICP 查询站有反爬、工信部官网有 JS 挑战，不伪造其结果；官网页脚确无公示时
    如实提示人工补证，绝不编造主体名称或备案号。
"""
import os
import re
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from config import UPLOAD_DIR

_PROV = "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁"

_BROWSER_CANDS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# 用于在页脚定位“备案公示条”的关键词（取最靠上命中行作为裁切上沿）
_FOOTER_KEYS = ("ICP备", "ICP证", "公网安备", "Copyright", "版权所有", "主办单位", "备案号")

_RE_ICP = re.compile(r"[" + _PROV + r"][A-Za-z]?ICP备?\d{4,}号?(?:-?\d+)?")
_RE_POLICE = re.compile(r"[" + _PROV + r"]公网安备\s*\d{6,}号?")
_RE_OWNER = [
    re.compile(r"主办单位(?:名称)?\s*[:：]?\s*([一-龥（）()A-Za-z0-9·\-]{4,40})"),
    re.compile(r"版权所有\s*[:：]?\s*([一-龥（）()A-Za-z0-9·\-]{4,40})"),
    re.compile(r"(?:Copyright\s*)?©\s*\d{4}\s*(?:[-–—]\s*\d{4}\s*)?([一-龥（）()A-Za-z0-9·\-]{4,40})"),
]
_ORG_KW = ("大学", "学院", "学校", "中学", "小学", "幼儿园", "公司", "集团", "有限",
           "人民政府", "政府", "委员会", "管委会", "管理局", "研究院", "研究所", "医院",
           "银行", "报社", "电视台", "办公室", "协会", "基金会", "检察院", "法院",
           "公安局", "气象局", "税务局", "海关", "监督局", "局", "厅", "中心", "站")


def find_browser():
    for p in _BROWSER_CANDS:
        if p and os.path.exists(p):
            return p
    return shutil.which("chrome") or shutil.which("msedge") or None


def normalize_target(target: str):
    t = (target or "").strip()
    if not t:
        return "", ""
    if "://" not in t:
        t = "https://" + t
    u = urlparse(t)
    host = (u.hostname or "").lower()
    url = urlunparse((u.scheme or "https", u.netloc, "/", "", "", ""))
    return url, host


def _run_browser(browser, args, timeout=120):
    cmd = [browser, "--headless=new", "--disable-gpu", "--no-sandbox",
           "--hide-scrollbars", "--disable-dev-shm-usage",
           "--run-all-compositor-stages-before-draw",
           "--user-agent=" + _UA] + args
    return subprocess.run(cmd, capture_output=True, timeout=timeout)


def render_dom(browser, url, budget=15000):
    p = _run_browser(browser, ["--virtual-time-budget=%d" % budget, "--dump-dom", url])
    return p.stdout.decode("utf-8", "ignore") if p.stdout else ""


def render_footer_strip(browser, url, out_path, budget=20000):
    """整页打印 PDF，只把末页“页脚备案公示条”裁成一张宽 1366 的紧凑 PNG。

    用 PDF 文字层定位 ICP / 公网安备 / Copyright 等关键词的纵向位置，
    从最靠上的命中行向上留一行多边距裁到页脚底部——只保留备案条，
    不含首页大图 / logo / 轮播新闻等无关内容。
    """
    tmp_pdf = out_path + ".tmp.pdf"
    for f in (tmp_pdf, out_path):
        if os.path.exists(f):
            os.remove(f)
    try:
        _run_browser(browser, ["--virtual-time-budget=%d" % budget,
                               "--no-pdf-header-footer",
                               "--print-to-pdf=" + tmp_pdf, url])
        if not os.path.exists(tmp_pdf):
            return False
        try:
            import pymupdf as fitz
        except Exception:
            import fitz
        doc = fitz.open(tmp_pdf)
        if doc.page_count == 0:
            return False
        page = doc[doc.page_count - 1]
        W, H = page.rect.width, page.rect.height

        # 定位页脚关键词纵向位置
        top_y = None
        for kw in _FOOTER_KEYS:
            for rct in page.search_for(kw):
                if top_y is None or rct.y0 < top_y:
                    top_y = rct.y0
        if top_y is not None:
            top = max(0.0, top_y - 14.0)     # 仅上移约一行内边距，只保留备案公示行，不带入上方导航
            bottom = min(H, H - 14.0)
        else:
            # 回退：文字层定位不到时，取末页底部 18%
            top, bottom = H * 0.82, H - 14.0
        clip = fitz.Rect(0, top, W, bottom)
        zoom = 1366.0 / W
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), clip=clip, alpha=False)
        pix.save(out_path)
        doc.close()
    except Exception:
        return False
    finally:
        try:
            if os.path.exists(tmp_pdf):
                os.remove(tmp_pdf)
        except Exception:
            pass
    return os.path.exists(out_path) and os.path.getsize(out_path) > 3000


def _clean_owner(name):
    if not name:
        return ""
    name = name.strip(" 　·-—_:：|，,。.;；©®")
    for stop in ("ICP", "公网安备", "All Rights", "all rights", "http", "www.",
                 "版权所有", "主办单位", "Copyright", "©"):
        idx = name.find(stop)
        if idx > 0:
            name = name[:idx]
    name = re.sub(r"(官方)?(门户网站|网站)$", "", name)
    name = name.strip(" 　·-—_:：|，,。.;；")
    if len(name) < 4 or not re.search(r"[一-龥]", name):
        return ""
    return name[:40]


def _owner_from_title(html):
    m = re.search(r"<title[^>]*>([\s\S]*?)</title>", html, re.I)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    cands = []
    for seg in re.split(r"[_\-—–|·,，:：<>《》\[\]【】()（）\s]+", title):
        seg = seg.strip()
        if 2 <= len(seg) <= 30 and re.search(r"[一-龥]", seg) and any(k in seg for k in _ORG_KW):
            cands.append(seg)
    if not cands and 2 <= len(title) <= 30 and any(k in title for k in _ORG_KW):
        cands.append(title)
    if not cands:
        return ""
    cands.sort(key=len, reverse=True)
    return _clean_owner(cands[0])


def extract_attribution(html):
    text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    m = _RE_ICP.search(text)
    icp = m.group(0).replace(" ", "") if m else ""
    m = _RE_POLICE.search(text)
    police = re.sub(r"\s+", "", m.group(0)) if m else ""
    owner = ""
    for rx in _RE_OWNER:
        m = rx.search(text)
        if m:
            owner = _clean_owner(m.group(1))
            if owner:
                break
    if not owner:
        owner = _owner_from_title(html)
    return {"icp": icp, "police": police, "owner": owner}


def fetch_attribution(target: str):
    url, host = normalize_target(target)
    result = {"ok": False, "url": url, "host": host, "image_url": "",
              "icp": "", "police": "", "owner": "", "summary": "", "error": ""}
    if not url or not host:
        result["error"] = "无法解析该地址或域名"
        return result
    browser = find_browser()
    if not browser:
        result["error"] = "未找到本机 Chrome / Edge 浏览器，无法自动截图"
        return result

    try:
        html = render_dom(browser, url)
    except Exception:
        html = ""
    if html:
        result.update(extract_attribution(html))

    date_dir = datetime.now().strftime("%Y%m%d")
    save_dir = os.path.join(str(UPLOAD_DIR), date_dir)
    os.makedirs(save_dir, exist_ok=True)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    fname = "attrib_%s_%d.png" % (safe_host, int(datetime.now().timestamp()))
    disk = os.path.join(save_dir, fname)

    shot_ok = False
    try:
        shot_ok = render_footer_strip(browser, url, disk)
    except Exception:
        shot_ok = False
    if shot_ok:
        result["image_url"] = "/uploads/%s/%s" % (date_dir, fname)

    result["ok"] = bool(shot_ok or result["icp"] or result["police"] or result["owner"])
    result["summary"] = build_summary(result, shot_ok)
    if not result["ok"]:
        result["error"] = "目标站点无法访问或页面未公示归属/备案信息，请手动补充截图"
    return result


def build_summary(info, shot_ok):
    now = datetime.now().strftime("%Y年%m月%d日")
    lines = ["经对目标站点 %s 页脚公示信息进行远程核验：" % info.get("url", "")]
    if info.get("owner"):
        lines.append("版权所有 / 主办单位为“%s”。" % info["owner"])
    if info.get("icp"):
        lines.append("ICP 备案号：%s。" % info["icp"])
    if info.get("police"):
        lines.append("公安备案号：%s。" % info["police"])
    if shot_ok:
        lines.append("核验时间 %s，目标站点页脚备案公示截图见后。" % now)
    if not (info.get("owner") or info.get("icp") or info.get("police")):
        lines.append("目标站点官网页脚未识别到主体名称或备案号，"
                     "请补充工信部 ICP 备案查询截图或其他资产归属证明材料。")
    return "".join(lines)
