# -*- coding: utf-8 -*-
"""
智安鉴 · 从“成品漏洞报告 docx”反向拆分为可复用模板
==================================================
用户导入一份已经写好的漏洞报告（如单位送检样例），本模块：
  1. parse_report_docx：逐段解析正文（文本 / 标题样式 / 是否含图），并按章节锚点
     规则“猜测”每一段对应哪个字段（漏洞地址 / 描述 / 检测过程 / 等级 / 建议 / 归属…）；
  2. build_template_from_doc：在“保留原文档全部字体字号版式”的前提下，把用户确认映射
     的内容段替换成 {{占位符}}，并剔除成品里的旧证据截图，生成一份下次可直接填充、
     导出与原件一模一样版式的新模板。

全自动识别不可能 100% 准确，因此采用“规则预填 + 界面人工确认/调整”的方式，
映射结果以用户确认为准，不做臆造。
"""
import os
import shutil

from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# 可映射字段（key 与 13 占位符一致）；__TITLE__ 为“单位存在漏洞名”标题的特殊组合
FIELDS = [
    ("unit_name", "单位名称"),
    ("vul_name", "漏洞名称"),
    ("system_name", "系统名称"),
    ("domain", "域名"),
    ("address", "漏洞地址"),
    ("description", "漏洞描述"),
    ("detail", "检测过程"),
    ("severity", "漏洞等级"),
    ("harm", "漏洞危害"),
    ("suggestion", "整改建议"),
    ("prove", "归属证明"),
    ("report_date", "报告日期"),
    ("org_footer", "单位落款"),
]
FIELD_CN = {k: cn for k, cn in FIELDS}
CN_FIELD = {cn: k for k, cn in FIELDS}
TITLE_KEY = "__TITLE__"


def _norm(s: str) -> str:
    return (s or "").replace(" ", "").replace("　", "").replace("\t", "").strip()


def _para_has_image(p) -> bool:
    el = p._p
    return bool(el.findall(".//" + qn("w:drawing")) or el.findall(".//" + qn("w:pict")))


def _is_heading(p) -> bool:
    try:
        return (p.style.name or "").lower().startswith("heading")
    except Exception:
        return False


# 标签词严格判定：去掉结尾标点后必须“恰为”标签词，避免“检测过程是……”这类以标签词
# 开头的正文被误当成标签（会导致区间清扫失效、正文残留）。
_LABEL_ALIAS = {
    "修复建议": "整改建议", "处置建议": "整改建议",
    "复现过程": "检测过程", "漏洞归属": "归属证明",
}


def _field_label(t: str):
    """返回规范中文字段名（漏洞地址/漏洞描述/检测过程/漏洞等级/漏洞危害/整改建议/归属证明），不是标签返回 None。"""
    t = _norm(t)
    if not t:
        return None
    if t.startswith("渗透目标") and ("IP" in t.upper() or "URL" in t.upper() or "地址" in t) and len(t) <= 20:
        return "漏洞地址"
    core = t.rstrip("：:。.、 	")
    words = ("漏洞危害", "整改建议", "修复建议", "处置建议", "归属证明", "漏洞归属",
             "漏洞等级", "检测过程", "复现过程", "漏洞描述")
    for w in words:
        if core == w:
            return _LABEL_ALIAS.get(w, w)
    return None


def parse_report_docx(path: str):
    """解析成品报告，返回段落列表与规则猜测映射。结构对齐 doc.paragraphs 的索引。"""
    doc = Document(path)
    paras = []
    for i, p in enumerate(doc.paragraphs):
        text = p.text.strip()
        paras.append({
            "idx": i,
            "text": text,
            "heading": _is_heading(p),
            "has_image": _para_has_image(p),
            "suggest": "",   # 规则猜测的字段 key
        })

    # ---------- 规则猜测（状态机） ----------
    def is_addr_lbl(t):
        return ("渗透目标" in t) and ("IP" in t.upper() or "URL" in t.upper() or "地址" in t)

    def first_content_after(start):
        """从 start+1 起找第一个“内容段”（有文本且不是标签/不是标题）"""
        j = start + 1
        while j < len(paras):
            t = _norm(paras[j]["text"])
            if t and not _is_label(t) and not paras[j]["heading"]:
                return j
            if _is_label(t):  # 撞到下一个标签就停
                break
            j += 1
        return None

    labels = []  # (idx, kind)
    for i, item in enumerate(paras):
        t = _norm(item["text"])
        if not t:
            continue
        _fl = _field_label(t)
        kind = {"漏洞地址": "address", "漏洞危害": "harm", "整改建议": "suggestion",
                "归属证明": "prove", "漏洞等级": "severity",
                "漏洞描述": "description_lbl", "检测过程": "detail_lbl"}.get(_fl)
        if kind:
            labels.append((i, kind))

    mapping = {}

    def assign(j, key):
        if j is not None and 0 <= j < len(paras) and key not in mapping.values():
            mapping[j] = key

    detail_zone = False
    for (i, kind) in labels:
        if kind == "address":
            assign(first_content_after(i), "address")
        elif kind == "harm":
            assign(first_content_after(i), "harm")
        elif kind == "suggestion":
            assign(first_content_after(i), "suggestion")
        elif kind == "prove":
            j = first_content_after(i)
            if j is None:  # 标签后可能直接是图片
                k = i + 1
                while k < len(paras) and not paras[k]["text"] and not paras[k]["has_image"]:
                    k += 1
                j = k if k < len(paras) and paras[k]["has_image"] else None
            assign(j, "prove")
        elif kind == "severity":
            assign(first_content_after(i), "severity")
        elif kind == "description_lbl":
            assign(first_content_after(i), "description")
        elif kind == "detail_lbl":
            detail_zone = True
            j = first_content_after(i)
            assign(j, "detail")

    # 标签“向后找不到内容”时的紧邻向前兜底：部分成品把正文写在标签正上方
    # （如“该漏洞会导致…”段就在“漏洞危害：”标签的上一行）。自动预猜该紧邻段，
    # 用户仍可在确认界面调整。
    kind_key = {"address": "address", "harm": "harm", "suggestion": "suggestion",
                "severity": "severity", "description_lbl": "description", "detail_lbl": "detail"}
    for (i, kind) in labels:
        key = kind_key.get(kind)
        if not key or key in mapping.values():
            continue
        j = i - 1
        while j >= 0 and not _norm(paras[j]["text"]):
            j -= 1
        if j >= 0:
            tt = _norm(paras[j]["text"])
            if (tt and not _is_label(tt) and not paras[j]["heading"]
                    and j not in mapping and key not in mapping.values()):
                assign(j, key)

    # 图片段：若落在检测过程区 / 归属区且对应字段尚未映射，则归到该字段
    cur = None
    for i, item in enumerate(paras):
        t = _norm(item["text"])
        if t.startswith("检测过程") or t.startswith("复现过程"):
            cur = "detail"
        elif t.startswith("归属证明") or t.startswith("漏洞归属"):
            cur = "prove"
        elif _is_label(t) and not (t.startswith("检测过程") or t.startswith("复现过程")
                                   or t.startswith("归属证明") or t.startswith("漏洞归属")):
            cur = None
        if item["has_image"] and cur and cur not in mapping.values():
            mapping[i] = cur

    # 标题：形如“XX存在XX漏洞”的（标题样式或文本特征）→ 单位+漏洞名组合
    for i, item in enumerate(paras):
        t = _norm(item["text"])
        if item["heading"] and "存在" in t and ("漏洞" in t or "隐患" in t or "风险" in t):
            mapping[i] = TITLE_KEY
            break

    for j, key in mapping.items():
        paras[j]["suggest"] = key

    return {"paragraphs": paras, "mapping": mapping}


def _is_label(t: str) -> bool:
    return _field_label(t) is not None


def _remove_images_in_para(p):
    el = p._p
    for tag in ("w:drawing", "w:pict"):
        for node in el.findall(".//" + qn(tag)):
            parent = node.getparent()
            if parent is not None:
                parent.remove(node)


def _replace_para_text_keep_format(p, new_text: str):
    """保留段落首个 run 的字体格式，将整段文本替换为 new_text；清掉其余 run/超链接文本。"""
    runs = p.runs
    if runs:
        runs[0].text = new_text
        for r in runs[1:]:
            r._element.getparent().remove(r._element)
    else:
        p.add_run(new_text)


def build_template_from_doc(src_path: str, mapping: dict, dst_path: str):
    """
    按 {段落idx: 字段key} 生成模板 docx。
      - 普通字段 → 该段替换为 {{中文名}}；
      - __TITLE__ → {{单位名称}}存在{{漏洞名称}}；
      - 同一字段命中多段：首段写占位符，其余同字段段清空（避免重复填充）；
      - 剔除成品里所有旧证据图片（新报告渲染时自动插新图）。
    返回实际写入的占位符中文名列表。
    """
    shutil.copyfile(src_path, dst_path)
    doc = Document(dst_path)

    # 1) 剔除全文旧图片
    for p in doc.paragraphs:
        _remove_images_in_para(p)
    for tbl in doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    _remove_images_in_para(p)

    # 1.5) 校正“标签型字段”占位符位置：一律放到其标签段正下方。
    # 有的成品报告把内容写在了标签前面（如“该漏洞会导致…”在“漏洞危害：”之上），
    # 逆向时若不校正，填出的报告就会内容在标题前、顺序颠倒。这里把内容段整体移动到
    # 标签段之后（lxml 同树 addnext 为“移动”，完整保留原段字体字号缩进）。
    label_keys = ("address", "harm", "suggestion", "prove", "severity", "detail", "description")

    def _find_label_paras(document):
        res = {}
        for pp in document.paragraphs:
            t = _norm(pp.text)
            if not t:
                continue
            up = t.upper()
            if ("渗透目标" in t) and ("IP" in up or "URL" in up or "地址" in t):
                res.setdefault("address", pp)
            elif t.startswith("漏洞危害") or t == "危害":
                res.setdefault("harm", pp)
            elif t.startswith("整改建议") or t.startswith("修复建议") or t.startswith("处置建议"):
                res.setdefault("suggestion", pp)
            elif t.startswith("归属证明") or t.startswith("漏洞归属") or t == "归属":
                res.setdefault("prove", pp)
            elif t.startswith("漏洞等级") or t == "等级":
                res.setdefault("severity", pp)
            elif t.startswith("检测过程") or t.startswith("复现过程"):
                res.setdefault("detail", pp)
            elif t.startswith("漏洞描述"):
                res.setdefault("description", pp)
        return res

    paras = doc.paragraphs
    label_paras = _find_label_paras(doc)
    body = doc.element.body
    order = {id(el): i for i, el in enumerate(body.iterchildren())}
    key_first_idx = {}
    for idx_str, key in (mapping or {}).items():
        try:
            ii = int(idx_str)
        except Exception:
            continue
        if 0 <= ii < len(paras) and key not in key_first_idx:
            key_first_idx[key] = ii
    for key in label_keys:
        if key not in label_paras or key not in key_first_idx:
            continue
        label_p = label_paras[key]
        content_p = paras[key_first_idx[key]]
        if content_p is label_p:
            continue
        if id(content_p._p) not in order or id(label_p._p) not in order:
            continue
        if order[id(content_p._p)] < order[id(label_p._p)]:
            # 内容段在标签段之前：移动到标签段正下方
            label_p._p.addnext(content_p._p)

    # 2) 替换映射段落（沿用移动前抓取的 paras：段落元素被 addnext 移动后，这些
    #    Paragraph 对象仍指向同一元素；切勿在此重新 doc.paragraphs，否则移动导致的
    #    索引重排会让占位符错写到标签段、并残留成品旧内容）
    used = set()
    written = []
    for idx_str, key in (mapping or {}).items():
        try:
            idx = int(idx_str)
        except Exception:
            continue
        if idx < 0 or idx >= len(paras):
            continue
        p = paras[idx]
        if key == TITLE_KEY:
            token = "{{单位名称}}存在{{漏洞名称}}"
            mark = "标题"
        elif key in FIELD_CN:
            token = "{{" + FIELD_CN[key] + "}}"
            mark = FIELD_CN[key]
        else:
            continue
        if mark in used:
            # 同字段多段：后续段清空，避免重复
            _replace_para_text_keep_format(p, "")
            continue
        used.add(mark)
        _replace_para_text_keep_format(p, token)
        if mark != "标题":
            written.append(mark)

    # 3) 标题兜底：__TITLE__ 未被识别（成品标题未用标题样式）时，按“XX存在XX”文本特征替换
    if "标题" not in used:
        import re as _re
        _kw = ("漏洞", "弱口令", "隐患", "风险", "未授权", "注入", "泄露", "攻击", "上传",
               "绕过", "越权", "执行", "XSS", "CSRF", "SSRF", "MQTT", "默认口令")
        for pp in doc.paragraphs[:12]:
            t = _norm(pp.text)
            if "存在" in t and len(t) <= 40 and any(k in t for k in _kw) and "{{" not in t:
                _replace_para_text_keep_format(pp, "{{单位名称}}存在{{漏洞名称}}")
                used.add("标题")
                break

    # 4) 章节清扫：每个字段标签区间内只保留对应占位符段，清空残留的成品旧正文，
    #    避免用模板导出的每份报告都带着母版里的测试/旧数据文字（图片此前已统一剔除）。
    def _label_of(t):
        return _field_label(t)

    body_paras = doc.paragraphs
    marks = []  # (idx, field)
    for i, pp in enumerate(body_paras):
        f = _label_of(pp.text)
        if f:
            marks.append((i, f))
    for n0, (li, field) in enumerate(marks):
        lj = marks[n0 + 1][0] if n0 + 1 < len(marks) else len(body_paras)
        token = "{{" + field + "}}"
        for k in range(li + 1, lj):
            pp = body_paras[k]
            if _para_has_image(pp):
                continue
            t = pp.text
            if not t.strip():
                continue
            if token in t or "{{" in t:
                continue  # 占位符段保留
            _replace_para_text_keep_format(pp, "")  # 残留旧正文清空（保留段落与格式）

    # 5) 正文排版规范化：删除正文中的多余空段（空行），并把“字段标签段 / 占位符内容段”
    #    统一为相同的“首行缩进 2 字符、无左缩进/悬挂缩进”，解决母版各段缩进深浅不一。
    def _normalize_indent(pp):
        ppr = pp._p.find(qn("w:pPr"))
        if ppr is None:
            ppr = OxmlElement("w:pPr")
            pp._p.insert(0, ppr)
        ind = ppr.find(qn("w:ind"))
        if ind is None:
            ind = OxmlElement("w:ind")
            rpr = ppr.find(qn("w:rPr"))
            if rpr is not None:
                rpr.addprevious(ind)
            else:
                ppr.append(ind)
        # 清掉左缩进/悬挂/固定 firstLine，仅保留“2 字符”首行缩进（随字号自动对齐）
        for attr in ("left", "start", "leftChars", "startChars", "hanging", "hangingChars", "firstLine"):
            if ind.get(qn("w:" + attr)) is not None:
                del ind.attrib[qn("w:" + attr)]
        ind.set(qn("w:firstLineChars"), "200")

    body_paras2 = doc.paragraphs
    first_label_idx = None
    for i, pp in enumerate(body_paras2):
        if _field_label(pp.text):
            first_label_idx = i
            break
    if first_label_idx is not None:
        to_remove = []
        for i in range(first_label_idx, len(body_paras2)):
            pp = body_paras2[i]
            txt = pp.text
            has_img = _para_has_image(pp)
            if not txt.strip() and not has_img:
                to_remove.append(pp)          # 多余空段 -> 删除，消除空行
                continue
            # 字段标签段 或 占位符内容段：统一缩进；大区标题等其它段保持原样
            flabel = _field_label(txt)
            if flabel or "{{" in txt:
                _normalize_indent(pp)
            # 用户要求：漏洞描述 / 漏洞危害 / 检测过程 三个字段名加粗
            if flabel in ("漏洞描述", "漏洞危害", "检测过程"):
                for r in pp.runs:
                    r.font.bold = True
                if not pp.runs and txt:
                    pp.add_run(txt).font.bold = True
        for pp in to_remove:
            par = pp._p.getparent()
            if par is not None:
                par.remove(pp._p)
    doc.save(dst_path)
    return written
