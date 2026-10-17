# -*- coding: utf-8 -*-
"""
智安鉴 · PDF 报告导出引擎
==========================
基于 reportlab 生成中文 PDF 报告，支持普通模板 / 网信办公文 / 汇总模板。
自动注册 Windows 中文字体（黑体/仿宋/宋体），跨平台缺失时回退可用字体。
"""
import os
import re
import logging
from io import BytesIO
from datetime import datetime

from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image,
                                Table, TableStyle, PageBreak, KeepTogether)

from config import EXPORT_DIR
from core.helpers import sanitize_filename, now_ts, severity_cn

logger = logging.getLogger(__name__)

# ---------------- 字体注册 ----------------
# 候选字体按顺序探测：Windows 中文字体优先，其次 Linux 常见 CJK 字体（容器/服务器部署）
_LINUX_CJK = [
    ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", 0),
    ("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/truetype/arphic/uming.ttc", 0),
]
_FONT_CANDIDATES = {
    "Song": [(r"C:\Windows\Fonts\simsun.ttc", 0)] + _LINUX_CJK,
    "Hei": [(r"C:\Windows\Fonts\simhei.ttf", None)] + _LINUX_CJK,
    "Fang": [(r"C:\Windows\Fonts\simfang.ttf", None)] + _LINUX_CJK,
}
_registered = {}

for name, cands in _FONT_CANDIDATES.items():
    for path, idx in cands:
        if os.path.exists(path):
            try:
                if idx is not None:
                    pdfmetrics.registerFont(TTFont(name, path, subfontIndex=idx))
                else:
                    pdfmetrics.registerFont(TTFont(name, path))
                _registered[name] = path
                break
            except Exception as e:
                logger.warning("字体注册失败 %s: %s", path, e)

SONG = "Song" if "Song" in _registered else "Helvetica"
HEI = "Hei" if "Hei" in _registered else "Helvetica-Bold"
FANG = "Fang" if "Fang" in _registered else SONG

# ---------------- 样式 ----------------
_styles = getSampleStyleSheet()

def _style(name, **kw):
    base = dict(fontName=SONG, fontSize=12, leading=20, alignment=TA_JUSTIFY,
                firstLineIndent=24, spaceAfter=6, textColor=colors.HexColor("#1e293b"))
    base.update(kw)
    return ParagraphStyle(name, **base)

S_BODY = _style("body")
S_BODY_NI = _style("body_ni", firstLineIndent=0)
S_H1 = _style("h1", fontName=HEI, fontSize=16, leading=26, firstLineIndent=0,
              spaceBefore=10, spaceAfter=8, textColor=colors.HexColor("#0f172a"))
S_H2 = _style("h2", fontName=HEI, fontSize=13, leading=22, firstLineIndent=0,
              spaceBefore=6, spaceAfter=4, textColor=colors.HexColor("#1e293b"))
S_TITLE = _style("title", fontName=HEI, fontSize=22, leading=34, alignment=TA_CENTER,
                 firstLineIndent=0, spaceAfter=18, textColor=colors.HexColor("#0f172a"))
S_CENTER = _style("center", alignment=TA_CENTER, firstLineIndent=0)
S_BOLD = _style("bold", fontName=HEI, firstLineIndent=0)
S_GW_TITLE = _style("gw_title", fontName=FANG, fontSize=20, leading=32, alignment=TA_CENTER,
                    firstLineIndent=0, spaceAfter=16, textColor=colors.HexColor("#b91c1c"))

SEV_COLOR = {
    "critical": colors.HexColor("#dc2626"), "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"), "low": colors.HexColor("#16a34a"),
    "info": colors.HexColor("#0891b2"), "unknown": colors.HexColor("#64748b"),
}


def _esc(text):
    return (str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _resolve_media(src: str) -> str:
    from config import UPLOAD_DIR, BASE_DIR
    src = (src or "").strip()
    for prefix in ("/media/", "/uploads/", "media/", "uploads/"):
        if src.startswith(prefix):
            src = src[len(prefix):]
    for c in (os.path.join(BASE_DIR, "data", src), os.path.join(UPLOAD_DIR, src)):
        if os.path.exists(c):
            return c
    return ""


def _html_to_flowables(html: str, body_style=S_BODY):
    """HTML 富文本（含图片）→ reportlab flowables"""
    out = []
    if not html:
        return out
    soup = BeautifulSoup(html, "html.parser")
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if not src.startswith(("http://", "https://")):
            path = _resolve_media(src)
        else:
            path = src
        try:
            if path.startswith("http"):
                import requests
                resp = requests.get(path, timeout=15)
                if resp.status_code == 200:
                    out.append(Image(BytesIO(resp.content), width=14 * cm, height=8.5 * cm, kind="proportional"))
            elif path and os.path.exists(path):
                out.append(Image(path, width=14 * cm, height=8.5 * cm, kind="proportional"))
        except Exception as e:
            logger.warning("PDF 图片插入失败: %s", e)
        img.extract()
    text = soup.get_text("\n")
    for line in text.split("\n"):
        line = line.strip()
        if line:
            out.append(Paragraph(_esc(line), body_style))
    return out


def _image_field_flowables(value):
    """独立图片字段（JSON 数组）→ PDF 图片 flowable 列表，铺满版心、保持比例。"""
    import json as _json
    out = []
    if not value:
        return out
    if isinstance(value, str):
        try:
            value = _json.loads(value)
        except Exception:
            value = [x.strip() for x in value.replace("\n", ",").split(",") if x.strip()]
    for src in value or []:
        src = str(src).strip()
        if not src:
            continue
        try:
            if src.startswith(("http://", "https://")):
                import requests
                resp = requests.get(src, timeout=15)
                if resp.status_code == 200:
                    out.append(Image(BytesIO(resp.content), width=15 * cm, height=15 * cm, kind="proportional"))
            else:
                path = _resolve_media(src)
                if path and os.path.exists(path):
                    out.append(Image(path, width=15 * cm, height=15 * cm, kind="proportional"))
        except Exception as e:
            logger.warning("PDF 独立图片插入失败: %s", e)
    return out


def _vuln_block(r, story, gw=False):
    bs = S_BODY if not gw else _style("gw_body", fontName=FANG, fontSize=14, leading=24)
    story.append(Paragraph(_esc(f"{r['unit_name']}存在{r['vul_name']}"), S_H2))
    story.append(Paragraph("渗透目标的 IP 地址、URL", S_BOLD))
    for line in (r.get("address") or "-").splitlines() or ["-"]:
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), bs))
    story.append(Spacer(1, 4))
    story.append(Paragraph("漏洞描述", S_BOLD))
    for line in (r.get("description") or "-").splitlines() or ["-"]:
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), bs))
    story.append(Spacer(1, 4))
    story.append(Paragraph("检测过程", S_BOLD))
    fl = _html_to_flowables(r.get("detail", ""), bs)
    story.extend(fl if fl else [Paragraph("-", bs)])
    story.append(Spacer(1, 4))

    sev_text = severity_cn(r.get("severity", "unknown"))
    story.append(Paragraph("漏洞等级", S_BOLD))
    story.append(Paragraph(f'<font color="{SEV_COLOR.get(r.get("severity","unknown"), colors.black).hexval()}">{sev_text}</font>', bs))
    story.append(Spacer(1, 4))

    story.append(Paragraph("漏洞危害", S_BOLD))
    for line in (r.get("harm") or "-").splitlines() or ["-"]:
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), bs))
    story.append(Spacer(1, 4))
    story.append(Paragraph("整改建议", S_BOLD))
    sug_soup = BeautifulSoup(r.get("suggestion") or "-", "html.parser")
    for line in sug_soup.get_text("\n").split("\n"):
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), bs))
    story.append(Spacer(1, 4))
    story.append(Paragraph("归属证明", S_BOLD))
    fl = _html_to_flowables(r.get("prove", ""), bs)
    story.extend(fl if fl else [Paragraph("-", bs)])


# ---------------- 三类模板 ----------------
def _build_normal(records, buf):
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2.2 * cm, bottomMargin=2.2 * cm,
                            leftMargin=2.6 * cm, rightMargin=2.6 * cm,
                            title="网络安全测试报告")
    story = [Paragraph("网络安全测试报告", S_TITLE),
             Paragraph(f"生成日期：{datetime.now().strftime('%Y 年 %m 月 %d 日')}", S_CENTER),
             Spacer(1, 14),
             Paragraph("一、漏洞详情", S_H1)]
    for i, r in enumerate(records, 1):
        _vuln_block(r, story)
        if i < len(records):
            story.append(Spacer(1, 10))
    doc.build(story)


def _build_gongwen(records, buf):
    r = records[0]
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2.4 * cm, bottomMargin=2.4 * cm,
                            leftMargin=2.8 * cm, rightMargin=2.8 * cm,
                            title="网络安全事件隐患通报")
    story = [Paragraph("附件", _style("gw_att", fontName=FANG, fontSize=14, leading=22,
                                      firstLineIndent=0)),
             Paragraph(_esc(f"{r['unit_name']}单位{r.get('system_name') or ''}存在{r['vul_name']}情况报告"),
                       S_GW_TITLE)]
    body = _style("gw_b", fontName=FANG, fontSize=14, leading=26)
    today = datetime.now().strftime("%m月%d日")
    story.append(Paragraph("一、基本信息", S_H2))
    story.append(Paragraph(_esc(
        f"{today}，{r['unit_name']}单位{r.get('system_name') or ''}存在{severity_cn(r.get('severity','unknown'))}漏洞。"), body))
    story.append(Paragraph("二、漏洞详情", S_H2))
    story.append(Paragraph("（一）目标的 IP 地址、URL", S_BOLD))
    for line in (r.get("address") or "-").splitlines() or ["-"]:
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), body))
    story.append(Paragraph("（二）漏洞描述及复现过程", S_BOLD))
    story.extend(_html_to_flowables(r.get("detail", ""), body) or [Paragraph("-", body)])
    story.extend(_image_field_flowables(r.get("detail_images")))
    story.append(Paragraph("漏洞归属：", S_BOLD))
    story.extend(_html_to_flowables(r.get("prove", ""), body) or [Paragraph("-", body)])
    story.extend(_image_field_flowables(r.get("prove_images")))
    story.append(Paragraph("三、整改建议", S_H2))
    sug = BeautifulSoup(r.get("suggestion") or "-", "html.parser").get_text("\n")
    for line in sug.split("\n"):
        if line.strip():
            story.append(Paragraph(_esc(line.strip()), body))
    doc.build(story)


def _build_summary(records, buf):
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2.2 * cm, bottomMargin=2.2 * cm,
                            leftMargin=2.4 * cm, rightMargin=2.4 * cm,
                            title="网络安全漏洞测试汇总报告")
    story = [Paragraph("网络安全漏洞测试汇总报告", S_TITLE),
             Paragraph(f"报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", S_CENTER),
             Paragraph(f"涉及单位：{len(set(r['unit_name'] for r in records))} 家，"
                       f"共发现漏洞 {len(records)} 个", S_CENTER), Spacer(1, 12)]
    data = [["序号", "单位名称", "系统名称", "漏洞名称", "等级"]]
    for i, r in enumerate(records, 1):
        data.append([str(i), _esc(r["unit_name"])[:18], _esc(r.get("system_name") or "")[:14],
                     _esc(r["vul_name"])[:24], severity_cn(r.get("severity", "unknown"))])
    tbl = Table(data, colWidths=[1.2 * cm, 4.2 * cm, 3.2 * cm, 5.2 * cm, 2 * cm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), SONG), ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), HEI),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"), ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(tbl)
    story.append(PageBreak())
    for i, r in enumerate(records, 1):
        story.append(Paragraph(f"{i}. {_esc(r['unit_name'])}：{_esc(r['vul_name'])}", S_H1))
        _vuln_block(r, story)
    doc.build(story)


def export_records_to_pdf(records, template_key="normal", org_footer="") -> str:
    buf = BytesIO()
    if template_key == "gongwen":
        _build_gongwen(records, buf)
        name = f"网络安全事件隐患通报_{records[0]['unit_name']}_{records[0]['vul_name']}"
    elif template_key == "summary":
        _build_summary(records, buf)
        name = f"漏洞测试汇总报告_{len(records)}个漏洞"
    else:
        _build_normal(records, buf)
        unit_names = set(r["unit_name"] for r in records)
        if len(records) == 1:
            r = records[0]
            name = f"{r['unit_name']}{r.get('system_name') or ''}存在{r['vul_name']}"
        elif len(unit_names) == 1:
            name = f"{list(unit_names)[0]}存在{len(records)}个漏洞报告"
        else:
            name = f"多个单位存在{len(records)}个漏洞报告"
    filename = sanitize_filename(name) + f"({now_ts()}).pdf"
    path = os.path.join(str(EXPORT_DIR), filename)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return filename
