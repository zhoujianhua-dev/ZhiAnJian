# -*- coding: utf-8 -*-
"""
智安鉴 · Word 报告导出引擎
===========================
支持三类模板：
  1. 内置普通模板    —— 与原有工具一致的结构化漏洞报告
  2. 内置网信办公文  —— 党政机关公文风格隐患通报
  3. 自定义模板      —— 用户上传 docx 模板，通过 docxtpl 占位符填充
     （占位符：{{单位名称}} {{漏洞名称}} {{系统名称}} {{域名}} {{漏洞地址}}
      {{漏洞描述}} {{检测过程}} {{漏洞等级}} {{漏洞危害}} {{整改建议}}
      {{归属证明}} {{报告日期}} {{单位落款}}）

多记录导出：内置模板直接合并；自定义模板按记录逐一渲染后使用 docxcompose 合并。
"""
import os
import re
import json
import logging
from io import BytesIO
from datetime import datetime

import warnings
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
from docx import Document
from docx.shared import Inches, Pt, Cm, RGBColor
from docx.oxml.ns import qn
from docx.enum.text import WD_ALIGN_PARAGRAPH

from config import EXPORT_DIR, UPLOAD_DIR, BASE_DIR
from core.helpers import sanitize_filename, now_ts, severity_cn

logger = logging.getLogger(__name__)

# 报告图片统一铺满版心宽度（A4 默认页边距下版心约 15.2cm，与送检样例一致）
IMG_WIDTH_CM = 15.2

# AI 生成时模型引用图片用的内部占位符 __AI_IMG_n__；正常会被替换成真实地址，
# 若因历史脏数据残留（模型引用了并不存在的第 n 张图），导出时静默忽略而非报“图片缺失”。
_INTERNAL_IMG_RE = re.compile(r"^__AI_IMG_\d+__$")

# ---------------- 基础样式 ----------------

def _set_run_font(run, size=14, bold=False, italic=False, underline=False,
                  font_cn="宋体", font_en="Times New Roman", color=None):
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.underline = underline
    if color:
        run.font.color.rgb = RGBColor(*color)
    if any('\u4e00' <= ch <= '\u9fff' for ch in run.text):
        run.font.name = font_cn
        run._element.rPr.rFonts.set(qn('w:eastAsia'), font_cn)
    else:
        run.font.name = font_en
        run._element.rPr.rFonts.set(qn('w:eastAsia'), font_en)


def _style_para(para, indent_pt=18, size=14):
    para.paragraph_format.first_line_indent = Pt(indent_pt)
    for run in para.runs:
        _set_run_font(run, size=size)


def _resolve_media_path(img_url: str) -> str:
    """把 /media/... 或 /uploads/... 或相对路径解析为本地磁盘路径"""
    img_url = img_url.strip()
    # 去掉常见前缀
    for prefix in ("/media/", "/uploads/", "media/", "uploads/"):
        if img_url.startswith(prefix):
            img_url = img_url[len(prefix):]
    cands = [
        os.path.join(BASE_DIR, "data", img_url),
        os.path.join(UPLOAD_DIR, img_url),
        os.path.join(BASE_DIR, img_url),
    ]
    if os.path.isabs(img_url) and os.path.exists(img_url):
        return img_url
    for c in cands:
        if os.path.exists(c):
            return c
    return ""


def _load_picture(img_src: str):
    """把任意来源的图片地址统一转换为 python-docx add_picture 可用的对象。
    支持：
      1) data:<mime>;base64,xxxx  —— 富文本内嵌在数据库里的 base64 图片
      2) http(s)://               —— 网络图片
      3) 本地/媒体路径            —— /uploads、/media、绝对路径
    成功返回「文件路径(str) 或 BytesIO」；无法加载返回 None。"""
    import base64
    src = (img_src or "").strip()
    if not src:
        return None
    # 1) base64 data URI
    if src.startswith("data:"):
        m = re.match(r"data:[^;,]*(?:;[^,]*)?;base64,(.*)$", src, re.S | re.I)
        if not m:
            return None
        try:
            raw = base64.b64decode(m.group(1))
            if raw:
                return BytesIO(raw)
        except Exception:
            return None
        return None
    # 2) 网络图片
    if src.startswith(("http://", "https://")):
        try:
            import requests
            resp = requests.get(src, timeout=15)
            if resp.status_code == 200 and resp.content:
                return BytesIO(resp.content)
        except Exception as e:
            logger.warning("下载网络图片失败 %s: %s", src, e)
        return None
    # 3) 本地 / 媒体路径
    path = _resolve_media_path(src)
    if path and os.path.exists(path):
        return path
    if os.path.isabs(src) and os.path.exists(src):
        return src
    return None


def _add_image_to_doc(doc, img_src: str, width_cm=IMG_WIDTH_CM):
    """向 doc 插入一张铺满版心宽、居中的图片（base64 内嵌 / http / 本地路径均支持）。"""
    def _post_format():
        p = doc.paragraphs[-1]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pf = p.paragraph_format
        pf.first_line_indent = Cm(0)
        pf.left_indent = Cm(0)
        pf.space_before = Pt(4)
        pf.space_after = Pt(10)
    pic = _load_picture(img_src)
    if pic is None:
        logger.warning("图片源无法加载：%s", (img_src or "")[:60])
        return False
    try:
        doc.add_picture(pic, width=Cm(width_cm))
        _post_format()
        return True
    except Exception as e:
        logger.warning("插入图片失败 %s: %s", (img_src or "")[:60], e)
        return False


def _append_image_field(doc, value):
    """把独立图片字段（JSON 数组字符串 / URL 列表）逐张插入文档，返回成功张数。"""
    if not value:
        return 0
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            value = [x.strip() for x in value.replace("\n", ",").split(",") if x.strip()]
    n = 0
    for src in value or []:
        if src and _add_image_to_doc(doc, src):
            n += 1
    return n


# ---------------- HTML → Word ----------------

def html_to_plain_text(html: str) -> str:
    """HTML 转纯文本（保留换行）"""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    for p in soup.find_all(["p", "div", "li", "tr"]):
        p.append("\n")
    return re.sub(r"\n{2,}", "\n", soup.get_text())


def _html_to_docx(doc, html: str, font_size=14, width_cm=IMG_WIDTH_CM):
    """把富文本 HTML 内容（含图片）写入 Word"""
    if not html:
        return
    soup = BeautifulSoup(html, "html.parser")

    def handle_text_block(text):
        for seg in text.split("\n"):
            if seg.strip():
                p = doc.add_paragraph()
                r = p.add_run(seg.strip())
                _style_para(p, size=font_size)

    def walk(element):
        if isinstance(element, str):
            handle_text_block(element)
            return
        for child in element.children:
            if isinstance(child, str):
                handle_text_block(child)
            elif child.name == "br":
                pass
            elif child.name == "img":
                src = child.get("src", "")
                # 残留的 AI 内部图片占位符：静默跳过，不产生“图片缺失”字样
                if src and _INTERNAL_IMG_RE.match(src.strip()):
                    continue
                if src and not _add_image_to_doc(doc, src, width_cm):
                    p = doc.add_paragraph("（图片缺失：" + src[:60] + "）")
                    _style_para(p, size=font_size)
            elif child.name in ("b", "strong"):
                p = doc.add_paragraph()
                r = p.add_run(child.get_text())
                _set_run_font(r, size=font_size, bold=True)
                p.paragraph_format.first_line_indent = Pt(18)
            elif child.name in ("i", "em"):
                p = doc.add_paragraph()
                r = p.add_run(child.get_text())
                _set_run_font(r, size=font_size, italic=True)
                p.paragraph_format.first_line_indent = Pt(18)
            elif child.name in ("p", "div", "li"):
                walk(child)
            elif child.name in ("ul", "ol"):
                for li in child.find_all("li"):
                    p = doc.add_paragraph(li.get_text().strip(),
                                          style="List Bullet" if child.name == "ul" else "List Number")
                    _style_para(p, size=font_size)
            elif child.name in ("h1", "h2", "h3", "h4"):
                p = doc.add_paragraph()
                r = p.add_run(child.get_text())
                _set_run_font(r, size=font_size + 2, bold=True)
            elif child.name in ("table",):
                # 简单表格：每行转文本
                for tr in child.find_all("tr"):
                    cells = [td.get_text().strip() for td in tr.find_all(["td", "th"])]
                    p = doc.add_paragraph(" | ".join(cells))
                    _style_para(p, size=font_size)
            else:
                walk(child)

    walk(soup)


# ---------------- 内置模板 1：普通模板 ----------------

def _apply_normal_font(doc, size_pt=14):
    """统一 Normal 样式为宋体 + 指定字号（中文 eastAsia 也设置），保证整文档默认字体一致。"""
    try:
        normal = doc.styles["Normal"]
        normal.font.name = "Times New Roman"
        normal.font.size = Pt(size_pt)
        normal.font.color.rgb = RGBColor(0, 0, 0)
        rpr = normal.element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            from docx.oxml import OxmlElement
            rfonts = OxmlElement("w:rFonts")
            rpr.append(rfonts)
        rfonts.set(qn("w:eastAsia"), "宋体")
    except Exception as e:
        logger.warning("设置默认字体失败: %s", e)


def _black_heading(doc, text, size=16, before=10, after=6, level=None):
    """生成纯黑色宋体加粗标题段落。
    level=1/2 时挂上 Word「标题1/标题2」大纲样式（与送检样例的导航结构一致），
    同时用显式 run 强制覆盖成宋体、加粗、纯黑，避免主题默认的蓝色/Calibri。"""
    p = doc.add_paragraph()
    if level:
        try:
            p.style = doc.styles[f"Heading {level}"]
        except Exception:
            pass
    pf = p.paragraph_format
    pf.first_line_indent = Cm(0)
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    run = p.add_run(text)
    _set_run_font(run, size=size, bold=True, color=(0, 0, 0))
    return p


def build_normal_doc(records) -> Document:
    doc = Document()
    _apply_normal_font(doc, 14)
    _black_heading(doc, "一、漏洞详情", size=16, before=0, after=8, level=1)

    for idx, r in enumerate(records, 1):
        _black_heading(doc, f"{r['unit_name']}存在{r['vul_name']}", size=16, before=8, after=6, level=2)

        p = doc.add_paragraph("渗透目标的IP地址、URL")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True, underline=True)
        for line in (r["address"] or "").splitlines():
            if line.strip():
                para = doc.add_paragraph(line.strip())
                _style_para(para)

        p = doc.add_paragraph("漏洞描述及检测过程")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True, underline=True)
        p = doc.add_paragraph("漏洞描述：")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True)
        for line in (r["description"] or "").splitlines():
            if line.strip():
                para = doc.add_paragraph(line.strip())
                _style_para(para)
        p = doc.add_paragraph("检测过程：")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True)
        _html_to_docx(doc, r.get("detail", ""))
        _append_image_field(doc, r.get("detail_images", ""))

        p = doc.add_paragraph("漏洞等级")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True, underline=True)
        p = doc.add_paragraph(severity_cn(r["severity"]))
        _style_para(p)

        p = doc.add_paragraph("整改建议")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True, underline=True)
        for line in (r["suggestion"] or "").splitlines():
            if line.strip():
                para = doc.add_paragraph(line.strip())
                _style_para(para)

        p = doc.add_paragraph("归属证明")
        for run in p.runs:
            _set_run_font(run, size=14, bold=True, underline=True)
        _html_to_docx(doc, r.get("prove", ""))
        _append_image_field(doc, r.get("prove_images", ""))

    return doc


# ---------------- 内置模板 2：网信办公文 ----------------

def build_gongwen_doc(r: dict) -> Document:
    doc = Document()
    _apply_normal_font(doc, 16)

    p = doc.add_paragraph("附件")
    _set_run_font(p.runs[0], size=16, bold=False, font_cn="黑体")
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT

    title_line = f"{r['unit_name']}存在{r['vul_name']}情况报告"
    p = doc.add_paragraph(title_line.strip())
    _set_run_font(p.runs[0], size=22, bold=False, font_cn="方正小标宋_GBK")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    def h(no, text, font="黑体", size=16):
        p = doc.add_paragraph(f"{no}、{text}")
        _set_run_font(p.runs[0], size=size, bold=False, font_cn=font)
        p.paragraph_format.first_line_indent = Cm(1.48)

    def sub(text):
        p = doc.add_paragraph(text)
        _set_run_font(p.runs[0], size=16, bold=True, font_cn="仿宋_GB2312")
        p.paragraph_format.first_line_indent = Cm(1.48)

    def body(text):
        for line in (text or "").splitlines():
            p = doc.add_paragraph(line.strip())
            _style_para(p, indent_pt=0, size=16)

    h("一", "基本信息")
    today = datetime.now().strftime("%m月%d日")
    p = doc.add_paragraph(f"{today}，{r['unit_name']}存在{severity_cn(r['severity'])}漏洞。")
    _style_para(p, size=16)

    h("二", "漏洞详情")
    sub("2.1 目标的IP地址、URL")
    body(r["address"])

    sub("2.2 漏洞描述及复现过程")
    p = doc.add_paragraph("漏洞描述：")
    _set_run_font(p.runs[0], size=16, bold=True, font_cn="仿宋_GB2312")
    body(r["description"])
    p = doc.add_paragraph("复现过程：")
    _set_run_font(p.runs[0], size=16, bold=True, font_cn="仿宋_GB2312")
    _html_to_docx(doc, r["detail"], font_size=16)
    _append_image_field(doc, r.get("detail_images", ""))

    p = doc.add_paragraph("漏洞归属见下图：")
    _style_para(p, size=16)
    _html_to_docx(doc, r["prove"], font_size=16)
    _append_image_field(doc, r.get("prove_images", ""))

    h("三", "整改建议")
    body(r["suggestion"])

    return doc


# ---------------- 内置模板 3：测试报告（精简，适合多漏洞汇总） ----------------

def build_summary_doc(records) -> Document:
    """汇总式报告：适合快速交付的漏洞清单"""
    doc = Document()
    _apply_normal_font(doc, 14)
    p = doc.add_paragraph("网络安全漏洞测试汇总报告")
    _set_run_font(p.runs[0], size=22, bold=True)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p = doc.add_paragraph(f"报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _style_para(p, indent_pt=0)
    p = doc.add_paragraph(f"涉及单位：{len(set(r['unit_name'] for r in records))} 家，共发现漏洞 {len(records)} 个")
    _style_para(p, indent_pt=0)

    # 汇总表
    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    for i, t in enumerate(["序号", "单位名称", "漏洞名称", "漏洞等级"]):
        hdr[i].text = t
    for idx, r in enumerate(records, 1):
        row = table.add_row().cells
        row[0].text = str(idx)
        row[1].text = r["unit_name"]
        row[2].text = r["vul_name"]
        row[3].text = severity_cn(r["severity"])

    for r in records:
        doc.add_heading(f"{r['unit_name']}：{r['vul_name']}", level=1)
        p = doc.add_paragraph("漏洞地址")
        _set_run_font(p.runs[0], size=14, bold=True)
        for line in (r["address"] or "").splitlines():
            para = doc.add_paragraph(line.strip())
            _style_para(para)
        p = doc.add_paragraph("漏洞描述")
        _set_run_font(p.runs[0], size=14, bold=True)
        for line in (r["description"] or "").splitlines():
            para = doc.add_paragraph(line.strip())
            _style_para(para)
        p = doc.add_paragraph("检测过程")
        _set_run_font(p.runs[0], size=14, bold=True)
        _html_to_docx(doc, r["detail"])
        p = doc.add_paragraph("整改建议")
        _set_run_font(p.runs[0], size=14, bold=True)
        for line in (r["suggestion"] or "").splitlines():
            para = doc.add_paragraph(line.strip())
            _style_para(para)
    return doc


# ---------------- 自定义模板（docxtpl） ----------------

PLACEHOLDER_MAP = {
    "单位名称": "unit_name",
    "漏洞名称": "vul_name",
    "系统名称": "system_name",
    "域名": "domain",
    "漏洞地址": "address",
    "漏洞描述": "description",
    "检测过程": "detail",
    "漏洞等级": "severity_cn",
    "漏洞危害": "harm",
    "整改建议": "suggestion",
    "归属证明": "prove",
    "报告日期": "report_date",
    "单位落款": "org_footer",
}


def _html_with_img_markers(html: str, tag: str = "IMG"):
    """HTML → (纯文本, 图片路径列表)，图片转为 [[{tag}:序号]] 标记。
    tag 用于区分章节（检测过程=DIMG、归属证明=PIMG），避免两组图片互相误替换。"""
    if not html:
        return "", []
    soup = BeautifulSoup(html, "html.parser")
    images = []
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if src.startswith(("data:", "http://", "https://")):
            resolved = src  # base64 data URI / 网络地址原样保留，交给 _load_picture 统一处理
        else:
            resolved = _resolve_media_path(src) or src
        marker = f"[[{tag}:{len(images)}]]"
        images.append(resolved)
        img.replace_with(marker)
    for br in soup.find_all("br"):
        br.replace_with("\n")
    for p in soup.find_all(["p", "div", "li", "tr", "h1", "h2", "h3", "h4"]):
        p.append("\n")
    text = re.sub(r"\n{2,}", "\n", soup.get_text()).strip()
    return text, images


def _inject_images_into_doc(doc, images, tag: str = "IMG"):
    """把 [[{tag}:i]] 标记替换为真实图片（支持段落内混合文本）。
    只处理指定 tag 的标记，因此检测过程(DIMG)与归属证明(PIMG)两组互不干扰：
    文字段保持左对齐，每张图片单独成段并居中，避免“图文同段被整段居中”。"""
    from docx.oxml import OxmlElement
    from docx.text.paragraph import Paragraph
    from copy import deepcopy
    img_pattern = re.compile(rf"\[\[{re.escape(tag)}:(\d+)\]\]")

    def insert_after(anchor_par):
        new_el = OxmlElement("w:p")
        anchor_par._p.addnext(new_el)
        return Paragraph(new_el, anchor_par._parent)

    for para in list(_iter_all_paragraphs(doc)):
        full = para.text
        if not img_pattern.search(full):
            continue
        # 解析成 文本/图片 序列（内部 AI 占位符等无效图片直接丢弃，不生成空图片段）
        # 文本片段按换行拆行后，只保留“非空白行”，避免在图片与图片、文字与图片之间
        # 因标记周围的 \n 生成空段落（即用户看到的“空行”）。
        def _push_text(seg0):
            for ln in seg0.split("\n"):
                if ln.strip():
                    tokens.append(("t", ln))
        tokens, pos = [], 0
        for m in img_pattern.finditer(full):
            idx = int(m.group(1))
            raw_src = (images[idx].strip() if idx < len(images) else "")
            if m.start() > pos:
                _push_text(full[pos:m.start()])
            if raw_src and not _INTERNAL_IMG_RE.match(raw_src):
                tokens.append(("i", idx))
            pos = m.end()
        if pos < len(full):
            _push_text(full[pos:])

        # 原段 pPr 作为新建“文字段”的格式模板
        ppr_el = para._p.find(qn("w:pPr"))
        orig_pPr = deepcopy(ppr_el) if ppr_el is not None else None
        # 清空原段内容（保留 pPr）
        for child in list(para._p):
            if child.tag != qn("w:pPr"):
                para._p.remove(child)

        anchor = para
        started = False  # 原段是否已被用于承载文字
        for kind, val in tokens:
            if kind == "t":
                segs = val.split("\n")
                # 文字 token 的每一行都独立成段，复制锚点 pPr，保证多行缩进/字号一致
                for si, seg in enumerate(segs):
                    if not seg.strip():
                        continue
                    if not started:
                        target, started = para, True
                    else:
                        target = insert_after(anchor)
                        anchor = target
                        if orig_pPr is not None:
                            target._p.insert(0, deepcopy(orig_pPr))
                    # 文字段显式左对齐，杜绝继承到任何居中
                    target.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    if seg:
                        run = target.add_run(seg)
                        _set_run_font(run, size=14)
            else:
                idx = val
                target = insert_after(anchor)
                anchor = target
                # 图片独立成段：居中、取消首行缩进
                target.alignment = WD_ALIGN_PARAGRAPH.CENTER
                try:
                    target.paragraph_format.first_line_indent = Cm(0)
                except Exception:
                    pass
                pf = target.paragraph_format
                pf.space_before = Pt(0)
                pf.space_after = Pt(4)
                if idx < len(images):
                    src = images[idx]
                    pic = _load_picture(src)
                    try:
                        if pic is not None:
                            target.add_run().add_picture(pic, width=Cm(IMG_WIDTH_CM))
                        else:
                            r = target.add_run("（图片缺失）")
                            _set_run_font(r, size=14)
                    except Exception:
                        r = target.add_run("（图片缺失）")
                        _set_run_font(r, size=14)

        # 第一个标记就是图片、原段未承载任何文字时，删除残留空段
        if not started and not para.text.strip():
            para._p.getparent().remove(para._p)


def _iter_all_paragraphs(doc):
    """遍历正文与所有表格（含嵌套）内的段落"""
    from docx.document import Document as _Doc
    from docx.table import Table, _Cell
    from docx.text.paragraph import Paragraph

    def iter_block_items(parent):
        if isinstance(parent, (_Doc, _Cell)):
            parent_elm = parent.element.body if isinstance(parent, _Doc) else parent._tc
        else:
            parent_elm = parent
        for child in parent_elm.iterchildren():
            if child.tag == qn("w:p"):
                yield Paragraph(child, parent)
            elif child.tag == qn("w:tbl"):
                yield Table(child, parent)

    def walk(parent):
        for item in iter_block_items(parent):
            if isinstance(item, Paragraph):
                yield item
            elif isinstance(item, Table):
                for row in item.rows:
                    for cell in row.cells:
                        yield from walk(cell)

    yield from walk(doc)


def _ensure_body_indent(p_el):
    """把段落统一为“首行缩进 2 字符、无左缩进/悬挂”，与模板正文段保持完全一致。
    使用 firstLineChars=200（Word 按本段字号自动折算），不再写死 firstLine 磅值，
    避免不同来源段落出现 18pt/24pt 等深浅不一的缩进。"""
    from docx.oxml import OxmlElement
    ppr = p_el.find(qn("w:pPr"))
    if ppr is None:
        ppr = OxmlElement("w:pPr")
        p_el.insert(0, ppr)
    ind = ppr.find(qn("w:ind"))
    if ind is None:
        ind = OxmlElement("w:ind")
        rpr = ppr.find(qn("w:rPr"))
        if rpr is not None:
            rpr.addprevious(ind)
        else:
            ppr.append(ind)
    for attr in ("left", "start", "leftChars", "startChars", "hanging", "hangingChars", "firstLine"):
        if ind.get(qn("w:" + attr)) is not None:
            del ind.attrib[qn("w:" + attr)]
    ind.set(qn("w:firstLineChars"), "200")


def _expand_newlines(doc):
    """把段落内的换行（<w:br/>、<w:cr/> 或文本中的 \n）拆分为各自独立的 Word 段落。
    直接遍历 run 的 XML 子节点（w:t / w:br / w:cr）重建，不依赖 Run.text 是否转义换行，
    新段深拷贝原段 pPr（对齐/行距）与首个 run 的 rPr（字体字号），并对原本无缩进的正文
    内容段统一补首行缩进 2 字符——整改建议多条、危害/描述多行时每行独立成段、缩进字号一致。"""
    from docx.oxml import OxmlElement
    from copy import deepcopy

    def _lines_of(p_el):
        lines, buf = [], ""
        for r in p_el.findall(qn("w:r")):
            for node in r:
                if node.tag == qn("w:t"):
                    buf += node.text or ""
                elif node.tag in (qn("w:br"), qn("w:cr")):
                    lines.append(buf)
                    buf = ""
            if "\n" in buf:
                ps = buf.split("\n")
                lines.extend(ps[:-1])
                buf = ps[-1]
        lines.append(buf)
        return lines

    def _split_one(p_el, parent):
        has_br = bool(p_el.findall(".//" + qn("w:br")) or p_el.findall(".//" + qn("w:cr")))
        if not has_br and "\n" not in "".join(
                (t.text or "") for t in p_el.findall(".//" + qn("w:t"))):
            return
        tmpl_rpr = None
        for r in p_el.findall(qn("w:r")):
            rpr = r.find(qn("w:rPr"))
            if rpr is not None:
                tmpl_rpr = deepcopy(rpr)
                break
        lines = _lines_of(p_el)
        ppr = p_el.find(qn("w:pPr"))
        for r in p_el.findall(qn("w:r")):
            p_el.remove(r)

        def fill(target_el, text):
            run = OxmlElement("w:r")
            if tmpl_rpr is not None:
                run.append(deepcopy(tmpl_rpr))
            tt = OxmlElement("w:t")
            tt.set(qn("xml:space"), "preserve")
            tt.text = text
            run.append(tt)
            target_el.append(run)

        _ensure_body_indent(p_el)
        fill(p_el, lines[0])
        anchor = p_el
        for ln in lines[1:]:
            newp = OxmlElement("w:p")
            if ppr is not None:
                newp.append(deepcopy(ppr))
            anchor.addnext(newp)
            _ensure_body_indent(newp)
            fill(newp, ln)
            anchor = newp
        _ = parent

    for para in list(_iter_all_paragraphs(doc)):
        _split_one(para._p, para._parent)


def build_custom_doc(records, template_path: str) -> Document:
    """使用用户上传模板渲染报告（支持多记录合并）"""
    from docxtpl import DocxTemplate

    docs = []
    for r in records:
        tpl = DocxTemplate(template_path)
        detail_text, detail_imgs = _html_with_img_markers(r.get("detail", ""), "DIMG")
        prove_text, prove_imgs = _html_with_img_markers(r.get("prove", ""), "PIMG")

        # 独立“检测过程图片 / 归属证明图片”并入对应章节，渲染到模板占位文字之后
        def _extra(field):
            v = r.get(field, "")
            if not v:
                return []
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except Exception:
                    v = [x.strip() for x in v.replace("\n", ",").split(",") if x.strip()]
            paths = []
            for s in v or []:
                s = str(s).strip()
                if not s:
                    continue
                if s.startswith(("data:", "http://", "https://")):
                    paths.append(s)
                else:
                    paths.append(_resolve_media_path(s) or s)
            return paths

        for pth in _extra("detail_images"):
            detail_text += f"\n[[DIMG:{len(detail_imgs)}]]"
            detail_imgs.append(pth)
        for pth in _extra("prove_images"):
            prove_text += f"\n[[PIMG:{len(prove_imgs)}]]"
            prove_imgs.append(pth)

        context = {
            "单位名称": r.get("unit_name", ""),
            "漏洞名称": r.get("vul_name", ""),
            "系统名称": r.get("system_name", ""),
            "域名": r.get("domain", ""),
            "漏洞地址": html_to_plain_text(r.get("address", "")),
            "漏洞描述": html_to_plain_text(r.get("description", "")),
            "检测过程": detail_text,
            "漏洞等级": severity_cn(r.get("severity", "unknown")),
            "漏洞危害": html_to_plain_text(r.get("harm", "")),
            "整改建议": html_to_plain_text(r.get("suggestion", "")),
            "归属证明": prove_text,
            "报告日期": datetime.now().strftime("%Y年%m月%d日"),
            "单位落款": r.get("org_footer", ""),
        }
        out = BytesIO()
        tpl.render(context)
        tpl.save(out)
        out.seek(0)
        sub_doc = Document(out)
        _inject_images_into_doc(sub_doc, detail_imgs, "DIMG")
        _inject_images_into_doc(sub_doc, prove_imgs, "PIMG")
        _expand_newlines(sub_doc)
        docs.append(sub_doc)

    if len(docs) == 1:
        return docs[0]

    # 多记录：docxcompose 合并
    from docxcompose.composer import Composer
    base = docs[0]
    composer = Composer(base)
    for d in docs[1:]:
        composer.append(d)
    return base


# ---------------- 导出调度 ----------------

def export_records_to_docx(records: list, template_key="normal", custom_template_path=None,
                           org_footer="") -> str:
    """
    核心导出函数
    :param records: list[dict] 报告数据
    :param template_key: normal / gongwen / summary / custom
    :param custom_template_path: template_key=custom 时用户模板路径
    :param org_footer: 报告落款单位
    :return: 相对导出目录的文件名
    """
    if org_footer:
        for r in records:
            r["org_footer"] = org_footer

    if template_key == "gongwen":
        doc = build_gongwen_doc(records[0])
        unit = records[0]["unit_name"]
        name = f"网络安全事件隐患通报SXXXX号_{unit}_{records[0]['vul_name']}"
    elif template_key == "summary":
        doc = build_summary_doc(records)
        name = f"漏洞测试汇总报告_{len(records)}个漏洞"
    elif template_key == "custom" and custom_template_path:
        doc = build_custom_doc(records, custom_template_path)
        unit_names = set(r["unit_name"] for r in records)
        name = (list(unit_names)[0] if len(unit_names) == 1 else "多个单位") + f"存在{len(records)}个漏洞报告"
    else:
        doc = build_normal_doc(records)
        unit_names = set(r["unit_name"] for r in records)
        if len(records) == 1:
            r = records[0]
            name = f"{r['unit_name']}存在{r['vul_name']}"
        elif len(unit_names) == 1:
            name = f"{list(unit_names)[0]}存在{len(records)}个漏洞报告"
        else:
            name = f"多个单位存在{len(records)}个漏洞报告"

    safe = sanitize_filename(name)
    filename = f"{safe}({now_ts()}).docx"
    file_path = os.path.join(str(EXPORT_DIR), filename)
    doc.save(file_path)
    return filename


def list_exported_files():
    """列出导出目录中的报告文件（按时间倒序，含 docx/pdf）"""
    files = []
    for f in os.listdir(str(EXPORT_DIR)):
        if f.lower().endswith((".docx", ".pdf")):
            path = os.path.join(str(EXPORT_DIR), f)
            files.append({
                "filename": f,
                "size": os.path.getsize(path),
                "mtime": datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S"),
            })
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return files
