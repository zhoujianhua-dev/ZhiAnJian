# -*- coding: utf-8 -*-
"""AI 智能路由（报告生成 / 分析 / 润色 / 分类 / 摘要）"""
import os
import re
import base64
import uuid
import logging

import json as _json

from flask import Blueprint, request, jsonify, Response, stream_with_context, render_template

import database as db
from config import get_cfg, AI_IMAGE_DIR
from core import exporter
from core.ai_engine import (get_ai_engine, mock_findings, mock_summary,
                            retrieve_similar_vulns, format_knowledge_for_prompt)
from core.helpers import now_display, now_ts, gen_record_id, severity_cn

logger = logging.getLogger(__name__)
bp = Blueprint("ai", __name__)


def _cfg_ai():
    return get_cfg().get("ai", {})


def _parse_body():
    data = request.get_json(silent=True)
    if data is None:
        raw = request.get_data(as_text=True)
        for enc in ("utf-8", "gbk", "gb18030", "latin-1"):
            try:
                return __import__("json").loads(raw.encode(enc, errors="ignore") if enc != "utf-8" else raw)
            except Exception:
                continue
        return None
    return data


def _save_uploaded_images(images):
    """保存 base64 图片到 data/ai_images，返回可访问 URL 列表"""
    if not images:
        return []
    os.makedirs(str(AI_IMAGE_DIR), exist_ok=True)
    urls = []
    ts = now_ts()
    for idx, item in enumerate(images, 1):
        data_url = item.get("base64") if isinstance(item, dict) else item
        if not isinstance(data_url, str) or not data_url:
            continue
        ext = ".jpg"
        m = re.search(r"data:image/([^;]+)", data_url)
        if m:
            ext = "." + m.group(1).split("+")[0]
        fname = f"ai_{ts}_{idx}{ext}"
        path = os.path.join(str(AI_IMAGE_DIR), fname)
        try:
            b64 = data_url.split(",", 1)[1] if data_url.startswith("data:") else data_url
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64))
            urls.append(f"/media/ai_images/{fname}")
        except Exception as e:
            logger.warning("保存图片失败: %s", e)
    return urls


def _ai_request(data, mode):
    """统一 AI 请求：解析参数 → 获取引擎 → 执行"""
    api_key = (data.get("api_key") or _cfg_ai().get("api_key") or "").strip()
    base_url = (data.get("base_url") or _cfg_ai().get("base_url") or "").strip()
    model = (data.get("model") or _cfg_ai().get("model") or "").strip()
    timeout = data.get("timeout") or _cfg_ai().get("timeout") or 120
    if not api_key:
        return None, None, jsonify(code=1, msg="缺少 api_key，请在系统设置中配置 AI 接口"), 400
    # 未填 base_url 时用默认端点；用户显式配置的地址（含阶跃套餐 step_plan 端点）原样使用
    if not base_url:
        base_url = "https://api.stepfun.com/v1"
    base_url = base_url.rstrip("/")
    engine = get_ai_engine(api_key, base_url, model, timeout)
    return engine, api_key, None, None


@bp.get("/assistant")
def assistant_page():
    return render_template("assistant.html")


@bp.get("/api/ai/config")
def ai_config_status():
    cfg = _cfg_ai()
    key = cfg.get("api_key", "")
    masked = (key[:6] + "****" + key[-4:]) if len(key) > 12 else ("已配置" if key else "")
    return jsonify(code=0, data={
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "api_key_masked": masked,
        "configured": bool(key),
    })


@bp.post("/api/ai/ping")
def ai_ping():
    """轻量连接检测：请求兼容 OpenAI 的 GET /models，秒级验证地址与密钥是否有效。"""
    import time as _time
    import requests as _requests
    data = _parse_body() or {}
    cfg = _cfg_ai()
    api_key = (data.get("api_key") or "").strip() or cfg.get("api_key", "")
    if not api_key:
        return jsonify(code=1, msg="未配置 API Key，请先填写后再测试"), 400
    # 模拟模式：不实际请求外部接口，直接返回成功，便于无 Key 联调
    if api_key == "sk-test-mock":
        return jsonify(code=0, msg="当前为模拟模式，未实际请求 AI 接口", data={
            "latency_ms": 0, "model_count": 1, "models": ["mock-model"],
            "current_model": "mock", "current_online": True, "mock": True})
    base_url = (data.get("base_url") or "").strip() or cfg.get("base_url", "")
    model = (data.get("model") or "").strip() or cfg.get("model", "")
    if not base_url:
        return jsonify(code=1, msg="未配置 Base URL"), 400
    url = base_url.rstrip("/") + "/models"
    proxy = (data.get("proxy") or "").strip() or (cfg.get("proxy", "") or "").strip()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    t0 = _time.time()
    try:
        resp = _requests.get(url, headers={"Authorization": "Bearer " + api_key},
                             timeout=20, proxies=proxies)
    except Exception as e:
        tip = "；若处于校园网/酒店等需网页认证的网络，请先完成网页认证或在下方配置代理" if proxy == "" else ""
        return jsonify(code=1, msg=f"无法连接接口地址：{type(e).__name__}（{base_url}）{tip}"), 200
    latency = int((_time.time() - t0) * 1000)
    if resp.status_code != 200:
        snippet = (resp.text or "")[:160].replace("\n", " ")
        return jsonify(code=1, msg=f"接口返回 {resp.status_code}，鉴权或地址有误：{snippet}"), 200
    try:
        body = resp.json()
        models = [m.get("id") for m in body.get("data", [])
                  if isinstance(m, dict) and m.get("id")]
    except Exception:
        models = []
    if not models:
        # 200 但不是模型列表，常见于网络被重定向到网页认证门户 / TLS 被网关劫持
        return jsonify(code=1,
            msg="已连通地址但未返回模型列表，当前网络可能需要网页认证或被网关拦截，请换网络（如手机热点）或配置代理后重试"), 200
    current_online = (not model) or (model in models)
    return jsonify(code=0, data={
        "latency_ms": latency,
        "model_count": len(models),
        "models": models[:30],
        "current_model": model,
        "current_online": current_online,
    })


# ---------------- 仅分析（预览） ----------------
@bp.post("/api/ai/analyze")
def ai_analyze():
    data = _parse_body() or {}
    engine, api_key, err, status = _ai_request(data, "analyze")
    if err is not None:
        return err, status

    asset_info = data.get("asset_info", {})
    raw_findings = data.get("raw_findings", [])
    raw_text = data.get("raw_text", "")
    images = data.get("images", [])
    existing_values = data.get("existing_values", {})
    if not raw_findings and not raw_text and not images:
        return jsonify(code=1, msg="缺少 raw_findings、raw_text 或 images"), 400

    image_urls = _save_uploaded_images(images)

    # 模拟模式
    if api_key == "sk-test-mock":
        findings = mock_findings(asset_info, raw_findings, raw_text)
        for i, img in enumerate(image_urls, 1):
            for f in findings:
                f["detail"] = f["detail"].replace(f"__AI_IMG_{i}__", img)
                f["prove"] = f["prove"].replace(f"__AI_IMG_{i}__", img)
        knowledge = retrieve_similar_vulns(
            " ".join([asset_info.get("system_name", ""), raw_text[:200]] +
                     [str((x.get("data", x) if isinstance(x, dict) else {}).get("title", "")) for x in raw_findings[:5]]))
        return jsonify(code=0, data={"findings": findings, "mock": True,
                                      "knowledge": [{"name": k.get("name"), "severity": k.get("severity")}
                                                    for k in knowledge]})

    try:
        findings = engine.analyze(raw_findings, asset_info, image_urls,
                                  raw_text=raw_text, existing_values=existing_values)
        knowledge = getattr(engine, "last_knowledge", [])
    except Exception as e:
        logger.exception("AI 分析失败")
        return jsonify(code=1, msg=f"AI 分析失败：{e}"), 500
    if not findings:
        return jsonify(code=1, msg="AI 未返回结果，请重试"), 500
    return jsonify(code=0, data={"findings": findings,
                                 "knowledge": [{"name": k.get("name"), "severity": k.get("severity")}
                                               for k in knowledge]})


# ---------------- 分析 + 入库 + 导出 ----------------
@bp.post("/api/ai/generate")
def ai_generate():
    data = _parse_body() or {}
    engine, api_key, err, status = _ai_request(data, "generate")
    if err is not None:
        return err, status

    asset_info = data.get("asset_info", {})
    raw_findings = data.get("raw_findings", [])
    raw_text = data.get("raw_text", "")
    images = data.get("images", [])
    # 页面顶部单独上传的“检测过程图片 / 归属证明图片”（选图即已上传，这里收到的是 URL 列表）
    def _url_list(v):
        return [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) else []
    global_detail_imgs = _url_list(data.get("detail_images", []))
    global_prove_imgs = _url_list(data.get("prove_images", []))
    existing_values = data.get("existing_values", {})
    template_key = data.get("template_key", "normal")
    template_id = data.get("template_id", "")
    org_footer = data.get("org_footer", "")
    if not raw_findings and not raw_text and not images:
        return jsonify(code=1, msg="缺少 raw_findings、raw_text 或 images"), 400

    image_urls = _save_uploaded_images(images)

    if api_key == "sk-test-mock":
        findings = mock_findings(asset_info, raw_findings, raw_text)
        for i, img in enumerate(image_urls, 1):
            for f in findings:
                f["detail"] = f["detail"].replace(f"__AI_IMG_{i}__", img)
                f["prove"] = f["prove"].replace(f"__AI_IMG_{i}__", img)
    else:
        try:
            findings = engine.analyze(raw_findings, asset_info, image_urls,
                                      raw_text=raw_text, existing_values=existing_values)
        except Exception as e:
            logger.exception("AI 分析失败")
            return jsonify(code=1, msg=f"AI 分析失败：{e}"), 500
    if not findings:
        return jsonify(code=1, msg="AI 未返回结果，请重试"), 500

    # 入库
    unit_name = asset_info.get("unit_name", "未知单位")
    records = []
    now = now_display()
    for idx, f in enumerate(findings):
        # 顶部图片默认挂到第一条漏洞；多漏洞请用“分析预览”逐条配图
        d_imgs = global_detail_imgs if idx == 0 else []
        p_imgs = global_prove_imgs if idx == 0 else []
        rid = db.execute(
            """INSERT INTO reports(record_id, unit_name, vul_name, system_name, domain, address,
               description, severity, harm, detail, suggestion, prove, detail_images, prove_images,
               status, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)""",
            (gen_record_id(), unit_name, f.get("vul_name", "未知漏洞"),
             asset_info.get("system_name", ""), asset_info.get("domain", ""), f.get("address", ""),
             f.get("description", ""), f.get("severity", "unknown"), f.get("harm", ""),
             f.get("detail", ""), f.get("suggestion", ""), f.get("prove", ""),
             _json.dumps(d_imgs, ensure_ascii=False), _json.dumps(p_imgs, ensure_ascii=False),
             now, now))
        records.append({"id": rid, **f, "unit_name": unit_name,
                        "vul_name": f.get("vul_name", "未知漏洞"),
                        "system_name": asset_info.get("system_name", ""),
                        "domain": asset_info.get("domain", ""),
                        "detail_images": _json.dumps(d_imgs, ensure_ascii=False),
                        "prove_images": _json.dumps(p_imgs, ensure_ascii=False),
                        "org_footer": org_footer})

    # 导出
    custom_path = None
    if template_key == "custom" and template_id:
        t = db.query_one("SELECT * FROM templates WHERE id=?", (template_id,))
        if t:
            custom_path = os.path.join(str(db_conf_dir()), t["filename"])
    try:
        filename = exporter.export_records_to_docx(
            records, template_key=template_key, custom_template_path=custom_path, org_footer=org_footer)
    except Exception as e:
        # 导出失败则回滚报告
        for r in records:
            db.execute("DELETE FROM reports WHERE id=?", (r["id"],))
        logger.exception("AI 报告导出失败")
        return jsonify(code=1, msg=f"报告导出失败：{e}"), 500

    return jsonify(code=0, msg="AI 报告生成成功", filename=filename,
                   url=f"/api/report/download/{filename}", records_created=len(records))


def db_conf_dir():
    from config import TEMPLATE_DIR
    return TEMPLATE_DIR


# ---------------- AI 润色补全 ----------------
@bp.post("/api/ai/complete")
def ai_complete():
    data = _parse_body() or {}
    engine, api_key, err, status = _ai_request(data, "complete")
    if err is not None:
        return err, status
    asset_info = data.get("asset_info", {})
    existing_values = data.get("existing_values", {})
    if not existing_values.get("vul_name"):
        return jsonify(code=1, msg="请至少填写漏洞名称"), 400
    if api_key == "sk-test-mock":
        return jsonify(code=0, data={
            "description": "（模拟）该接口存在输入校验缺失，攻击者可构造恶意载荷导致 SQL 注入。",
            "harm": "（模拟）可导致敏感数据泄露与未授权访问。",
            "detail": "（模拟）使用载荷验证可稳定复现。",
            "suggestion": "1. 参数化查询；2. 输入白名单；3. 最小权限。",
        })
    try:
        result = engine.complete_text(asset_info, existing_values)
    except Exception as e:
        return jsonify(code=1, msg=f"AI 润色失败：{e}"), 500
    return jsonify(code=0, data=result)


# ---------------- AI 资产分类 ----------------
@bp.post("/api/ai/classify")
def ai_classify():
    data = _parse_body() or {}
    engine, api_key, err, status = _ai_request(data, "classify")
    if err is not None:
        return err, status
    text = data.get("text", "")
    if not text:
        return jsonify(code=1, msg="请输入待分类文本"), 400
    if api_key == "sk-test-mock":
        from core.tools import classify_assets
        return jsonify(code=0, data={"items": classify_assets(text)["items"], "mock": True})
    try:
        items = engine.classify(text)
    except Exception as e:
        return jsonify(code=1, msg=f"AI 分类失败：{e}"), 500
    return jsonify(code=0, data={"items": items})


# ---------------- AI 报告摘要 ----------------
@bp.post("/api/ai/summarize")
def ai_summarize():
    data = _parse_body() or {}
    engine, api_key, err, status = _ai_request(data, "summarize")
    if err is not None:
        return err, status
    findings = data.get("findings", [])
    if not findings:
        return jsonify(code=1, msg="缺少漏洞数据"), 400
    if api_key == "sk-test-mock":
        return jsonify(code=0, data={"summary": mock_summary(findings)})
    try:
        summary = engine.summarize(findings)
    except Exception as e:
        return jsonify(code=1, msg=f"AI 摘要失败：{e}"), 500
    return jsonify(code=0, data={"summary": summary})


# ---------------- 图片保存 ----------------
@bp.post("/api/ai/save-images")
def ai_save_images():
    data = _parse_body() or {}
    images = data.get("images") or []
    urls = _save_uploaded_images(images)
    return jsonify(code=0, urls=urls)


# ---------------- RAG 本地知识检索（不依赖 AI） ----------------
@bp.post("/api/ai/retrieve-knowledge")
def ai_retrieve():
    data = _parse_body() or {}
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify(code=1, msg="缺少检索内容"), 400
    top_k = min(10, max(1, int(data.get("top_k", 3))))
    knowledge = retrieve_similar_vulns(query, top_k=top_k)
    return jsonify(code=0, data=knowledge)


# ---------------- AI 安全专家对话（流式 SSE / 非流式） ----------------
@bp.post("/api/ai/chat")
def ai_chat():
    data = _parse_body() or {}
    api_key = (data.get("api_key") or _cfg_ai().get("api_key") or "").strip()
    base_url = (data.get("base_url") or _cfg_ai().get("base_url") or "").strip() or "https://api.stepfun.com/v1"
    model = (data.get("model") or _cfg_ai().get("model") or "").strip()
    history = data.get("history") or []
    stream = bool(data.get("stream", True))
    if not api_key:
        return jsonify(code=1, msg="缺少 api_key"), 400
    if not history:
        return jsonify(code=1, msg="对话内容为空"), 400

    if api_key == "sk-test-mock":
        q = history[-1].get("content", "")
        reply = ("（模拟安全专家）你可以从以下方向处理该问题：1）明确漏洞入口与参数；"
                 "2）用最小载荷验证并留存证据；3）按最小权限与输入校验原则修复；"
                 "4）修复后回归测试。配置真实 AI Key 后可获得完整分析。\n你刚才的问题：" + q[:200])
        if stream:
            def gen():
                for ch in reply:
                    yield f"data: {_json.dumps({'delta': ch}, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
            return Response(stream_with_context(gen()), mimetype="text/event-stream")
        return jsonify(code=0, data={"reply": reply, "mock": True})

    engine = get_ai_engine(api_key, base_url, model,
                           data.get("timeout") or _cfg_ai().get("timeout") or 120)
    if engine is None:
        return jsonify(code=1, msg="AI 引擎初始化失败"), 500
    try:
        if stream:
            resp = engine.chat_stream(history)

            def sse_gen():
                got_content = False
                thinking_sent = False
                try:
                    for raw_line in resp.iter_lines():
                        if not raw_line:
                            continue
                        line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                        if line.startswith("data:"):
                            payload = line[5:].strip()
                            if payload == "[DONE]":
                                break
                            try:
                                obj = _json.loads(payload)
                                ch = (obj.get("choices") or [{}])[0].get("delta", {})
                                # 只把“最终正文 content”作为回答；reasoning_content 是思考过程，不混入答案
                                content = ch.get("content") or ""
                                reasoning = ch.get("reasoning_content") or ch.get("reasoning") or ""
                                if content:
                                    got_content = True
                                    yield f"data: {_json.dumps({'delta': content}, ensure_ascii=False)}\n\n"
                                elif reasoning and not thinking_sent:
                                    # 推理模型先思考后作答：仅通知前端进入“思考中”，不下发思考原文
                                    thinking_sent = True
                                    yield f"data: {_json.dumps({'phase': 'thinking'}, ensure_ascii=False)}\n\n"
                            except _json.JSONDecodeError:
                                continue
                    # 流式全程没有正文（思考占用过多 token / 部分套餐端点仅回思考）→ 非流式兜底重试一次
                    if not got_content:
                        try:
                            reply = engine.chat(history)
                            if reply:
                                yield f"data: {_json.dumps({'delta': reply}, ensure_ascii=False)}\n\n"
                            else:
                                yield f"data: {_json.dumps({'error': '模型未返回内容，请检查模型名称或套餐额度'}, ensure_ascii=False)}\n\n"
                        except Exception as e2:
                            yield f"data: {_json.dumps({'error': f'流式无正文，兜底请求也失败：{e2}'}, ensure_ascii=False)}\n\n"
                except Exception as e:
                    logger.exception("AI 流式对话异常")
                    yield f"data: {_json.dumps({'error': str(e)}, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"

            return Response(stream_with_context(sse_gen()), mimetype="text/event-stream")
        reply = engine.chat(history)
        if not reply:
            return jsonify(code=1, msg="模型未返回内容，请检查模型名称、Base URL 或套餐额度"), 502
        return jsonify(code=0, data={"reply": reply})
    except Exception as e:
        logger.exception("AI 对话失败")
        return jsonify(code=1, msg=f"AI 对话失败：{e}"), 500


# ---------------- AI 修复方案生成 ----------------
@bp.post("/api/ai/fix-code")
def ai_fix_code():
    data = _parse_body() or {}
    api_key = (data.get("api_key") or _cfg_ai().get("api_key") or "").strip()
    base_url = (data.get("base_url") or _cfg_ai().get("base_url") or "").strip() or "https://api.stepfun.com/v1"
    model = (data.get("model") or _cfg_ai().get("model") or "").strip()
    vul_name = (data.get("vul_name") or "").strip()
    if not vul_name:
        return jsonify(code=1, msg="请提供漏洞名称"), 400
    if not api_key:
        return jsonify(code=1, msg="缺少 api_key"), 400

    if api_key == "sk-test-mock":
        return jsonify(code=0, data={"mock": True, "root_cause": "（模拟）输入未做参数化校验导致注入。",
                                     "fix_plan": ["使用参数化查询", "输入白名单校验", "最小权限配置"],
                                     "code_samples": [{"language": "Python", "title": "参数化查询示例",
                                                       "code": "cursor.execute('SELECT * FROM users WHERE name=%s', (name,))"}],
                                     "verify": "使用原载荷复测应无法绕过",
                                     "defense_in_depth": ["部署 WAF", "开启错误日志告警"]})
    engine = get_ai_engine(api_key, base_url, model)
    try:
        result = engine.fix_code(vul_name, data.get("tech_stack", ""),
                                 data.get("description", ""), data.get("address", ""))
    except Exception as e:
        return jsonify(code=1, msg=f"生成失败：{e}"), 500
    return jsonify(code=0, data=result)


# ---------------- AI 报告评分点评 ----------------
@bp.post("/api/ai/grade")
def ai_grade():
    data = _parse_body() or {}
    rid = data.get("id")
    if not rid:
        return jsonify(code=1, msg="缺少报告 id"), 400
    row = db.query_one("SELECT * FROM reports WHERE id=?", (rid,))
    if not row:
        return jsonify(code=1, msg="报告不存在"), 404
    from core.qa import check_report
    rule = check_report(dict(row))
    api_key = (data.get("api_key") or _cfg_ai().get("api_key") or "").strip()
    if not api_key:
        return jsonify(code=0, data={"rule": rule, "ai": None})
    if api_key == "sk-test-mock":
        return jsonify(code=0, data={"rule": rule, "ai": {"mock": True,
            "score": rule["score"], "highlights": "（模拟）字段完整度较好。",
            "problems": [i["msg"] for i in rule["issues"][:3]],
            "suggestions": ["补充截图证据", "整改建议分条列出"]}})
    base_url = (data.get("base_url") or _cfg_ai().get("base_url") or "").strip() or "https://api.stepfun.com/v1"
    model = (data.get("model") or _cfg_ai().get("model") or "").strip()
    engine = get_ai_engine(api_key, base_url, model)
    try:
        ai = engine.grade_report(dict(row), rule["issues"])
    except Exception as e:
        ai = {"error": str(e)}
    return jsonify(code=0, data={"rule": rule, "ai": ai})
