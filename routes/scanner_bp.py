# -*- coding: utf-8 -*-
"""扫描器结果文件智能解析路由 + 内置漏洞扫描引擎联动路由"""
from flask import Blueprint, request, jsonify, render_template

from core import scanners, shelling_client

bp = Blueprint("scanner", __name__)

# 允许上传的扫描结果文件类型
ALLOWED_EXT = {".json", ".jsonl", ".txt", ".xml", ".log", ".csv"}
MAX_SIZE = 20 * 1024 * 1024  # 20MB

# 智安鉴只发起全量扫描；SCAN_TYPE_CN 保留全部类型，供历史任务回显
SCAN_TYPES = ("full",)
SCAN_TYPE_CN = {"quick": "快速扫描", "full": "全量扫描", "custom": "自定义扫描"}

# 严重等级中文名
_SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
           "info": "信息", "unknown": "未知"}

# 扫描过程日志类型中文名
_LOG_TYPE_CN = {"info": "信息", "tool": "工具", "output": "输出",
                "llm": "AI", "error": "错误", "success": "成功"}

# 攻击链阶段中文名（引擎已给出中文 name，此处仅作兜底）
_PHASE_CN = {"recon": "信息收集", "vuln": "漏洞发现",
             "exploit": "漏洞利用", "impact": "潜在影响"}

# 攻击链可能性 / 影响程度中文名
_LEVEL_CN = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


@bp.post("/api/scanner/parse")
def parse_file():
    f = request.files.get("file")
    if not f:
        return jsonify(code=1, msg="请选择扫描结果文件"), 400
    fname = f.filename or ""
    ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext and ext not in ALLOWED_EXT:
        return jsonify(code=1, msg=f"暂不支持 {ext} 文件，支持 JSON/JSONL/XML/TXT/LOG/CSV"), 400
    content = f.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        return jsonify(code=1, msg="文件过大（限制 20MB）"), 400
    try:
        result = scanners.parse_scanner_content(fname, content)
    except Exception as e:
        return jsonify(code=1, msg=f"解析失败：{e}"), 500
    stats = scanners.summarize_findings(result["findings"])
    return jsonify(code=0, msg="解析成功", data={
        "source": result["source"],
        "source_cn": {"nuclei": "Nuclei", "burp": "Burp Suite", "json": "通用 JSON",
                      "text": "纯文本"}.get(result["source"], result["source"]),
        "count": result["count"],
        "severity_stats": stats,
        "severity_stats_cn": {_SEV_CN.get(k, k): v for k, v in stats.items()},
        "findings": result["findings"],
    })


# ==================== 内置漏洞扫描引擎联动 ====================
@bp.get("/scanner")
def scanner_page():
    """AI 漏洞扫描：调用内置扫描引擎发起扫描、看进度、回收结果"""
    return render_template("scanner.html")


@bp.get("/api/scanner/shelling/options")
def shelling_options():
    """返回可选扫描类型，供前端下拉框渲染"""
    return jsonify(code=0, data={
        "scan_types": [{"value": t, "label": SCAN_TYPE_CN[t]} for t in SCAN_TYPES],
    })


@bp.post("/api/scanner/shelling/start")
def shelling_start():
    """在扫描引擎创建扫描任务，立即返回任务 ID（进度由前端轮询）"""
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify(code=1, msg="请填写扫描目标（域名 / IP / URL）"), 400
    scan_type = (data.get("scan_type") or "full").strip().lower()
    if scan_type not in SCAN_TYPES:
        scan_type = "full"
    remark = (data.get("remark") or "").strip() or "智安鉴发起"
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    try:
        task = shelling_client.get_client().create_scan(
            target, scan_type=scan_type, remark=remark, config=config)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    return jsonify(code=0, msg="扫描任务已提交", data={
        "scan_id": task.get("id"),
        "target": task.get("target") or target,
        "scan_type": task.get("scan_type") or scan_type,
        "scan_type_cn": SCAN_TYPE_CN.get(task.get("scan_type") or scan_type, ""),
        "status": task.get("status"),
        "status_cn": shelling_client.status_cn(task.get("status")),
    })


@bp.get("/api/scanner/shelling/status/<scan_id>")
def shelling_status(scan_id):
    """查询扫描进度（含子 Agent 明细）"""
    try:
        prog = shelling_client.get_client().get_progress(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    status = str(prog.get("status") or "").upper()
    return jsonify(code=0, data={
        "scan_id": prog.get("scan_id") or scan_id,
        "status": status,
        "status_cn": shelling_client.status_cn(status),
        "phase": prog.get("phase") or "",
        "message": prog.get("message") or "",
        "finished": status in shelling_client.FINISHED,
        "ok": status == "COMPLETED",
        "sub_agents": [{
            "name": s.get("name") or "",
            "role": s.get("role") or "",
            "status": s.get("status") or "",
            "progress": s.get("progress") or 0,
            "findings_count": s.get("findings_count") or 0,
            "summary": s.get("summary") or "",
        } for s in (prog.get("sub_agents") or [])],
    })


@bp.get("/api/scanner/shelling/logs/<scan_id>")
def shelling_logs(scan_id):
    """查看某次扫描的过程日志（支持 since_index 增量续拉，便于前端边跑边看）"""
    try:
        since = max(0, int(request.args.get("since_index") or 0))
    except (TypeError, ValueError):
        since = 0
    try:
        data = shelling_client.get_client().get_logs(scan_id, since_index=since)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    logs = []
    for entry in (data.get("logs") or []):
        if not isinstance(entry, dict):
            continue
        ltype = str(entry.get("type") or "info").lower()
        logs.append({
            "timestamp": entry.get("timestamp") or "",
            "type": ltype,
            "type_cn": _LOG_TYPE_CN.get(ltype, ltype),
            "message": entry.get("message") or "",
            "details": entry.get("details") or "",
            "tool": entry.get("tool") or "",
            "agent": entry.get("agent") or "",
        })
    next_index = data.get("next_index")
    if next_index is None:
        next_index = since + len(logs)
    return jsonify(code=0, data={
        "scan_id": data.get("scan_id") or scan_id,
        "logs": logs,
        "next_index": next_index,
        "count": len(logs),
    })


@bp.get("/api/scanner/shelling/result/<scan_id>")
def shelling_result(scan_id):
    """拉取扫描结果并转换为智安鉴统一发现格式（可直接填入 AI 生成流程）"""
    try:
        client = shelling_client.get_client()
        task = client.get_scan(scan_id)
        vulns = client.get_vulnerabilities(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    findings = shelling_client.to_findings(vulns, target=task.get("target") or "")
    stats = scanners.summarize_findings(findings)
    return jsonify(code=0, msg="已获取扫描结果", data={
        "scan_id": scan_id,
        "target": task.get("target") or "",
        "scan_type_cn": SCAN_TYPE_CN.get(task.get("scan_type") or "", task.get("scan_type") or ""),
        "status": task.get("status"),
        "status_cn": shelling_client.status_cn(task.get("status")),
        "llm_summary": task.get("llm_summary") or "",
        "llm_risk_score": task.get("llm_risk_score"),
        "count": len(findings),
        "severity_stats": stats,
        "severity_stats_cn": {_SEV_CN.get(k, k): v for k, v in stats.items()},
        "findings": findings,
    })


@bp.get("/api/scanner/shelling/attack-path/<scan_id>")
def shelling_attack_path(scan_id):
    """获取某次扫描的攻击链分析（阶段 / 攻击链 / 风险评估）；refresh=true 触发 AI 重新分析"""
    refresh = str(request.args.get("refresh") or "").lower() in ("1", "true", "yes")
    try:
        data = shelling_client.get_client().get_attack_path(scan_id, refresh=refresh)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502

    raw = data.get("data") if isinstance(data.get("data"), dict) else {}

    phases = []
    for p in (raw.get("phases") or []):
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or "")
        phases.append({
            "id": pid,
            "name": p.get("name") or _PHASE_CN.get(pid, pid),
            "description": p.get("description") or "",
            "items": [{
                "id": i.get("id") or "",
                "name": i.get("name") or "",
                "severity": str(i.get("severity") or "info").lower(),
                "details": i.get("details") or "",
            } for i in (p.get("items") or []) if isinstance(i, dict)],
        })

    chains = []
    for c in (raw.get("attack_chains") or []):
        if not isinstance(c, dict):
            continue
        like = str(c.get("likelihood") or "").lower()
        impact = str(c.get("impact") or "").lower()
        chains.append({
            "id": c.get("id") or "",
            "name": c.get("name") or "",
            "description": c.get("description") or "",
            "likelihood": like,
            "likelihood_cn": _LEVEL_CN.get(like, ""),
            "impact": impact,
            "impact_cn": _LEVEL_CN.get(impact, ""),
            "steps": [{
                "order": s.get("order") or 0,
                "action": s.get("action") or "",
                "vulnerability": s.get("vulnerability") or "",
                "result": s.get("result") or "",
            } for s in (c.get("steps") or []) if isinstance(s, dict)],
        })

    risk = raw.get("risk_assessment") if isinstance(raw.get("risk_assessment"), dict) else {}
    overall = str(risk.get("overall_risk") or "").lower()
    return jsonify(code=0, data={
        "scan_id": scan_id,
        "cached": bool(data.get("cached")),
        "has_chains": len(chains) > 0,
        "phases": phases,
        "attack_chains": chains,
        "risk_assessment": {
            "overall_risk": overall,
            "overall_risk_cn": _LEVEL_CN.get(overall, ""),
            "risk_score": risk.get("risk_score"),
            "summary": risk.get("summary") or "",
            "critical_paths": risk.get("critical_paths") or [],
            "recommendations": risk.get("recommendations") or [],
        },
    })


@bp.get("/api/scanner/shelling/scans")
def shelling_scans():
    """列出最近扫描任务（供「AI 漏洞扫描」页展示）"""
    try:
        page = max(1, int(request.args.get("page") or 1))
        page_size = max(1, min(int(request.args.get("page_size") or 10), 50))
    except ValueError:
        page, page_size = 1, 10
    try:
        data = shelling_client.get_client().list_scans(page, page_size)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    items = []
    for it in (data.get("items") or []):
        st = it.get("status") or ""
        items.append({
            "scan_id": it.get("id") or "",
            "target": it.get("target") or "",
            "scan_type": it.get("scan_type") or "",
            "scan_type_cn": SCAN_TYPE_CN.get(it.get("scan_type") or "", it.get("scan_type") or ""),
            "status": st,
            "status_cn": shelling_client.status_cn(st),
            "created_at": it.get("created_at") or "",
            "vulnerability_count": it.get("vulnerability_count") or 0,
            "llm_risk_score": it.get("llm_risk_score"),
            "remark": it.get("remark") or "",
        })
    return jsonify(code=0, data={"total": data.get("total") or 0, "items": items,
                                 "page": page, "page_size": page_size})


@bp.post("/api/scanner/shelling/cancel/<scan_id>")
def shelling_cancel(scan_id):
    """请求取消正在进行的扫描"""
    try:
        shelling_client.get_client().cancel_scan(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    return jsonify(code=0, msg="已请求取消扫描")


@bp.post("/api/scanner/shelling/delete/<scan_id>")
def shelling_delete(scan_id):
    """删除某次扫描任务（含其结果与过程记录）；进行中的任务会先取消再删除"""
    client = shelling_client.get_client()
    try:
        client.delete_scan(scan_id)
    except shelling_client.ShellingError as e:
        # 引擎不允许直接删除进行中的任务，先取消再重试一次
        if "Cannot delete running task" not in str(e):
            return jsonify(code=1, msg=str(e)), 502
        try:
            client.cancel_scan(scan_id)
        except shelling_client.ShellingError:
            pass  # 取消接口可能报错，但任务状态通常已置为已取消，继续尝试删除
        try:
            client.delete_scan(scan_id)
        except shelling_client.ShellingError as e2:
            return jsonify(code=1, msg=str(e2)), 502
    return jsonify(code=0, msg="扫描任务已删除")


@bp.post("/api/scanner/shelling/remark/<scan_id>")
def shelling_update_remark(scan_id):
    """修改某次扫描任务的备注（列表内双击编辑）"""
    data = request.get_json(silent=True) or {}
    remark = str(data.get("remark") or "").strip()
    if len(remark) > 200:
        return jsonify(code=1, msg="备注最多 200 个字符"), 400
    try:
        task = shelling_client.get_client().update_scan_remark(scan_id, remark)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    return jsonify(code=0, msg="备注已更新", data={
        "scan_id": scan_id,
        "remark": task.get("remark") or "",
    })
