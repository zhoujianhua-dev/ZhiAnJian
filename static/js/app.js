/* ============================================================
   智安鉴 · 前端公共库
   API 封装（自动带 CSRF）、Toast、模态框、确认框、分页
   ============================================================ */
"use strict";

const ZhiShield = (() => {
  let csrfToken = null;

  async function ensureCsrf() {
    if (csrfToken) return csrfToken;
    try {
      const r = await fetch("/api/csrf");
      const j = await r.json();
      csrfToken = j.token || "";
    } catch (e) { csrfToken = ""; }
    return csrfToken;
  }

  /* 统一 API 请求 */
  async function api(url, options = {}) {
    const opts = { ...options };
    opts.headers = { ...(opts.headers || {}) };
    if (opts.json !== undefined || opts.body === undefined) {
      if (opts.json !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.json);
        delete opts.json;
      }
    }
    const method = (opts.method || (opts.body ? "POST" : "GET")).toUpperCase();
    opts.method = method;
    if (method === "POST" && !(opts.body instanceof FormData)) {
      opts.headers["X-CSRF-Token"] = await ensureCsrf();
    }
    const resp = await fetch(url, opts);
    let data = null;
    try { data = await resp.json(); } catch (e) { data = null; }
    /* 登录失效：整页跳回登录页（带上来路），免得用户对着报错发呆 */
    if (resp.status === 401 && data && data.need_login && !location.pathname.startsWith("/login")) {
      location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
      throw new Error(data.msg || "登录已失效");
    }
    if (!resp.ok && !data) {
      const err = new Error(`请求失败 (${resp.status})`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  /* Toast */
  function toast(msg, type = "success", duration = 2600) {
    let wrap = document.querySelector(".toast-wrap");
    if (!wrap) {
      wrap = document.createElement("div");
      wrap.className = "toast-wrap";
      document.body.appendChild(wrap);
    }
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    const icons = {
      success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6L9 17l-5-5"/></svg>',
      error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M18 6L6 18M6 6l12 12"/></svg>',
      info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 12v4"/></svg>',
      warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 3L2 21h20L12 3z"/><path d="M12 10v4M12 17h.01"/></svg>',
    };
    el.innerHTML = (icons[type] || icons.info) + "<span>" + msg + "</span>";
    wrap.appendChild(el);
    setTimeout(() => {
      el.classList.add("out");
      setTimeout(() => el.remove(), 320);
    }, duration);
  }

  function success(msg) { toast(msg, "success"); }
  function error(msg) { toast(msg, "error"); }
  function info(msg) { toast(msg, "info"); }

  /* 模态框 */
  function openModal({ title, body, footer, size = "" }) {
    closeModal();
    const mask = document.createElement("div");
    mask.className = "modal-mask show";
    mask.innerHTML = `
      <div class="modal ${size}">
        <div class="modal-header">
          <h4>${title || ""}</h4>
          <button class="modal-close" onclick="ZhiShield.closeModal()">×</button>
        </div>
        <div class="modal-body">${body || ""}</div>
        ${footer ? `<div class="modal-footer">${footer}</div>` : ""}
      </div>`;
    mask.addEventListener("click", (e) => { if (e.target === mask) closeModal(); });
    document.body.appendChild(mask);
    document.body.style.overflow = "hidden";
    // 按视口宽度用绝对 px 内联居中，规避 fixed 包含块/缩放/缓存等环境差异
    const modalEl = mask.querySelector(".modal");
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const sizeW = size === "xl" ? 1080 : size === "lg" ? 880 : 640;
    const w = Math.min(sizeW, vw - 32);
    modalEl.style.width = w + "px";
    modalEl.style.maxWidth = (vw - 32) + "px";
    modalEl.style.left = Math.max(8, Math.round((vw - w) / 2)) + "px";
    modalEl.style.transform = "none";
    return modalEl;
  }

  function closeModal() {
    document.querySelectorAll(".modal-mask").forEach(m => m.remove());
    document.body.style.overflow = "";
  }

  /* 确认框 */
  function confirmDialog(msg, onOk, okText = "确定", danger = true) {
    const m = openModal({
      title: "操作确认",
      size: "",
      body: `<div style="display:flex;gap:14px;align-items:flex-start">
        <div style="width:42px;height:42px;border-radius:12px;background:#fef2f2;display:flex;align-items:center;justify-content:center;color:#dc2626;flex-shrink:0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
        </div>
        <div style="font-size:14px;line-height:1.7;padding-top:4px">${msg}</div>
      </div>`,
      footer: `
        <button class="btn btn-ghost" onclick="ZhiShield.closeModal()">取消</button>
        <button class="btn ${danger ? "btn-danger" : "btn-primary"}" id="cfOk">${okText}</button>`,
    });
    m.querySelector("#cfOk").addEventListener("click", () => { closeModal(); onOk && onOk(); });
  }

  /* 分页渲染 */
  function renderPagination(el, page, total, limit, onPage) {
    const pages = Math.max(1, Math.ceil(total / limit));
    const cur = Math.min(page, pages);
    let html = `<button class="pg-btn" data-p="${cur - 1}" ${cur <= 1 ? "disabled" : ""}>‹</button>`;
    const range = [];
    for (let p = 1; p <= pages; p++) {
      if (p === 1 || p === pages || Math.abs(p - cur) <= 2) range.push(p);
      else if (range[range.length - 1] !== "...") range.push("...");
    }
    range.forEach(p => {
      if (p === "...") html += `<span class="pg-btn" style="border:none;background:transparent">…</span>`;
      else html += `<button class="pg-btn ${p === cur ? "active" : ""}" data-p="${p}">${p}</button>`;
    });
    html += `<button class="pg-btn" data-p="${cur + 1}" ${cur >= pages ? "disabled" : ""}>›</button>`;
    html += `<span class="pg-info">共 ${total} 条</span>`;
    el.innerHTML = html;
    el.querySelectorAll(".pg-btn[data-p]").forEach(b => {
      b.addEventListener("click", () => {
        const p = parseInt(b.dataset.p);
        if (p >= 1 && p <= pages && p !== cur) onPage(p);
      });
    });
  }

  /* 严重等级徽章 */
  function sevBadge(s) {
    const map = { critical: ["严重", "badge-critical"], high: ["高危", "badge-high"],
      medium: ["中危", "badge-medium"], low: ["低危", "badge-low"],
      info: ["信息", "badge-info"], unknown: ["未知", "badge-unknown"] };
    const [t, c] = map[s] || map.unknown;
    return `<span class="badge ${c}">${t}</span>`;
  }

  /* HTML 转义 */
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  /* 富文本编辑器 */
  function rteInit(textarea, imgUploadUrl = "/api/upload/image") {
    const ta = textarea;
    ta.style.display = "none";
    const toolbar = document.createElement("div");
    toolbar.className = "rte-toolbar";
    const btns = [
      ["bold", "B", "加粗"], ["italic", "I", "斜体"], ["underline", "U", "下划线"],
      ["|"], ["h2", "H2", "小标题"], ["|"], ["ul", "• 列表", "无序列表"],
      ["ol", "1. 列表", "有序列表"], ["|"], ["img", "🖼 图片", "插入图片"], ["|"],
      ["code", "</>", "代码样式"],
    ];
    btns.forEach(b => {
      if (b[0] === "|") { const s = document.createElement("span"); s.style.width = "1px"; s.style.background = "#e2e8f0"; s.style.margin = "0 3px"; toolbar.appendChild(s); return; }
      const btn = document.createElement("button");
      btn.type = "button"; btn.title = b[2]; btn.innerHTML = b[1];
      btn.dataset.cmd = b[0];
      toolbar.appendChild(btn);
    });
    const body = document.createElement("div");
    body.className = "rte-content";
    body.innerHTML = ta.value || "";
    body.contentEditable = "true";
    ta.parentNode.insertBefore(toolbar, ta);
    ta.parentNode.insertBefore(body, ta);

    toolbar.addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const cmd = btn.dataset.cmd;
      if (cmd === "img") {
        const input = document.createElement("input");
        input.type = "file"; input.accept = "image/*";
        input.onchange = async () => {
          const f = input.files[0];
          if (!f) return;
          const fd = new FormData();
          fd.append("file", f);
          try {
            const r = await api(imgUploadUrl, { method: "POST", body: fd });
            if (r.code === 0) {
              const url = r.data.location;
              body.focus();
              document.execCommand("insertHTML", false, `<p><img src="${url}" style="max-width:100%"></p>`);
            } else toast(r.msg || "上传失败", "error");
          } catch (err) { toast("上传失败: " + err.message, "error"); }
        };
        input.click();
        return;
      }
      body.focus();
      if (cmd === "h2") {
        document.execCommand("formatBlock", false, "h4");
      } else if (cmd === "code") {
        document.execCommand("insertHTML", false, "<code>代码</code>");
      } else {
        document.execCommand(cmd);
      }
      btn.classList.toggle("active", document.queryCommandState(cmd));
    });

    /* 同步回 textarea */
    const sync = () => {
      // 移除编辑器产生的空标签
      let html = body.innerHTML.replace(/<div><br><\/div>/g, "").replace(/<p><br><\/p>/g, "");
      ta.value = html;
    };
    body.addEventListener("input", sync);
    body.addEventListener("blur", sync);
    /* 图片懒清理 */
    const observer = new MutationObserver(sync);
    observer.observe(body, { childList: true, subtree: true, characterData: true });
    return { getValue: () => { sync(); return ta.value; }, setValue: (v) => { body.innerHTML = v || ""; sync(); } };
  }

  /* 从任意漏洞地址提取主机名（与后端 core.asset_sync.extract_host 同口径）
     支持 http/https/mqtt/ftp… 任意协议、裸域名、IP[:端口]、user@host 等 */
  function extractHost(address) {
    if (!address) return "";
    let s = String(address).trim().split(/\r?\n/)[0].trim();
    if (!s) return "";
    s = s.replace(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//, ""); // 去协议
    if (s.includes("@")) s = s.split("@").pop();          // 去用户信息
    const m = s.match(/[/?#\s]/);                         // 去路径/查询/锚点
    if (m) s = s.slice(0, m.index);
    if (!s) return "";
    if (s.startsWith("[")) {                              // IPv6
      const e = s.indexOf("]");
      return e > 0 ? s.slice(1, e) : "";
    }
    if (s.includes(":")) {                                // 去端口（冒号后纯数字）
      const i = s.lastIndexOf(":");
      if (/^\d+$/.test(s.slice(i + 1))) s = s.slice(0, i);
    }
    s = s.replace(/^\.+|\.+$/g, "").trim().toLowerCase();
    if (!s) return "";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) {
      return s.split(".").every(n => +n >= 0 && +n <= 255) ? s : "";
    }
    // 支持带点域名与无点内网主机名（server01、localhost、broker）；纯数字不算
    const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
    if (!s.split(".").every(p => label.test(p))) return "";
    return /[a-z]/.test(s) ? s : "";
  }

  /* 独立多图上传区：多选上传、点击预览、删除、拖拽排序；getValue() 返回图片 URL 数组 */
  function imageZone(container, options = {}) {
    const uploadUrl = options.uploadUrl || "/api/upload/image";
    let urls = Array.isArray(options.value) ? options.value.slice() : [];
    container.innerHTML = "";
    container.classList.add("img-zone");
    const fileInput = document.createElement("input");
    fileInput.type = "file"; fileInput.accept = "image/*"; fileInput.multiple = true;
    fileInput.style.display = "none";
    const drop = document.createElement("div");
    drop.className = "img-zone-drop";
    drop.innerHTML =
      `<span class="img-zone-icon">🖼️</span>
       <span class="img-zone-text">${options.hint || "点击选择或拖拽图片到此处（支持多张）"}</span>
       <span class="img-zone-count"></span>`;
    const thumbs = document.createElement("div");
    thumbs.className = "img-zone-thumbs";
    container.appendChild(drop);
    container.appendChild(thumbs);
    container.appendChild(fileInput);

    function render() {
      thumbs.innerHTML = "";
      urls.forEach((u, idx) => {
        const card = document.createElement("div");
        card.className = "img-card";
        card.draggable = true;
        card.innerHTML =
          `<img src="${esc(u)}" title="点击查看大图，拖动可排序">
           <button type="button" class="img-card-del" title="删除">×</button>
           ${urls.length > 1 ? `<span class="img-card-idx">${idx + 1}</span>` : ""}`;
        card.querySelector("img").onclick = () => window.open(u, "_blank");
        card.querySelector(".img-card-del").onclick = (e) => {
          e.stopPropagation();
          urls.splice(idx, 1); render();
        };
        card.addEventListener("dragstart", (e) => {
          e.dataTransfer.setData("text/idx", String(idx));
          card.classList.add("dragging");
        });
        card.addEventListener("dragend", () => card.classList.remove("dragging"));
        card.addEventListener("dragover", (e) => e.preventDefault());
        card.addEventListener("drop", (e) => {
          e.preventDefault();
          const from = parseInt(e.dataTransfer.getData("text/idx"));
          if (isNaN(from) || from === idx) return;
          const [moved] = urls.splice(from, 1);
          urls.splice(idx, 0, moved);
          render();
        });
        thumbs.appendChild(card);
      });
      drop.querySelector(".img-zone-count").textContent =
        urls.length ? `已上传 ${urls.length} 张，可拖拽调整顺序` : "";
    }

    async function uploadFiles(files) {
      for (const f of files) {
        const fd = new FormData();
        fd.append("file", f);
        try {
          const r = await api(uploadUrl, { method: "POST", body: fd });
          if (r.code === 0 && r.data && r.data.location) {
            urls.push(r.data.location);
          } else {
            toast(r.msg || ("图片 " + f.name + " 上传失败"), "error");
          }
        } catch (err) {
          toast("图片上传失败: " + err.message, "error");
        }
      }
      render();
    }

    drop.onclick = () => fileInput.click();
    fileInput.onchange = () => { uploadFiles(Array.from(fileInput.files)); fileInput.value = ""; };
    ["dragover", "dragenter"].forEach(ev =>
      drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave"].forEach(ev =>
      drop.addEventListener(ev, () => drop.classList.remove("over")));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      if (e.dataTransfer && e.dataTransfer.files.length) {
        uploadFiles(Array.from(e.dataTransfer.files));
      }
    });

    render();
    return {
      getValue: () => urls.slice(),
      setValue: (v) => { urls = Array.isArray(v) ? v.slice() : []; render(); },
      count: () => urls.length,
    };
  }

  /* 隐藏加载（按 data-loading 目标渲染） */
  function showLoading(el, text = "加载中...") {
    el.innerHTML = `<div class="loading-mask"><div class="spinner"></div>${text}</div>`;
  }

  /* 时间格式化 */
  function fmtTime(s) { return s ? String(s).slice(0, 19).replace("T", " ") : ""; }

  /* 扫描引擎返回的时间是 UTC ISO，统一换算为北京时间（UTC+8）后展示 */
  function fmtTimeUtc8(s) {
    if (!s) return "";
    const d = new Date(s);
    if (isNaN(d.getTime())) return fmtTime(s);
    const bj = new Date(d.getTime() + 8 * 3600 * 1000);
    return bj.toISOString().slice(0, 19).replace("T", " ");
  }

  /* 修改自己的登录密码 */
  function changePassword() {
    const m = openModal({
      title: "修改密码",
      body: `<div class="form-item"><label>原密码 <span class="req">*</span></label>
          <input class="input" id="cpOld" type="password" autocomplete="current-password"></div>
        <div class="form-item" style="margin-top:12px"><label>新密码 <span class="req">*</span></label>
          <input class="input" id="cpNew" type="password" autocomplete="new-password" placeholder="至少 6 位"></div>
        <div class="form-item" style="margin-top:12px"><label>确认新密码 <span class="req">*</span></label>
          <input class="input" id="cpNew2" type="password" autocomplete="new-password"></div>
        <div id="cpErr" style="min-height:18px;font-size:13px;color:var(--danger);margin-top:8px"></div>`,
      footer: `<button class="btn btn-ghost" onclick="ZhiShield.closeModal()">取消</button>
               <button class="btn btn-primary" id="cpOk">保存</button>`,
    });
    const val = (id) => m.querySelector(id).value;
    m.querySelector("#cpOk").addEventListener("click", async () => {
      const err = m.querySelector("#cpErr");
      err.textContent = "";
      if (!val("#cpOld") || !val("#cpNew")) { err.textContent = "请填写原密码与新密码"; return; }
      if (val("#cpNew") !== val("#cpNew2")) { err.textContent = "两次输入的新密码不一致"; return; }
      const r = await api("/api/auth/password", {
        json: { old_password: val("#cpOld"), new_password: val("#cpNew") } });
      if (r && r.code === 0) {
        closeModal();
        success(r.msg);
        document.querySelectorAll(".alert-warn").forEach(el => el.remove());
      } else {
        err.textContent = (r && r.msg) || "修改失败";
      }
    });
  }

  /* 退出登录 */
  async function logout() {
    try { await api("/api/auth/logout", { json: {} }); } catch (e) { /* 网络异常也照样回登录页 */ }
    location.href = "/login";
  }

  return {
    api, toast, success, error, info,
    openModal, closeModal, confirmDialog,
    renderPagination, sevBadge, esc, rteInit,
    extractHost, imageZone,
    showLoading, fmtTime, fmtTimeUtc8, ensureCsrf,
    changePassword, logout,
  };
})();

window.ZhiShield = ZhiShield;

/* 侧栏交互 */
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-group > .nav-item").forEach(item => {
    const sub = item.nextElementSibling;
    if (sub && sub.classList.contains("nav-sub")) {
      item.classList.add("has-sub");
      item.addEventListener("click", () => {
        sub.classList.toggle("open");
        item.classList.toggle("open");
      });
    }
  });
  /* 移动端菜单 */
  const menuBtn = document.querySelector(".menu-toggle");
  if (menuBtn) menuBtn.addEventListener("click", () => {
    document.querySelector(".sidebar").classList.toggle("mobile-open");
  });

  /* 右上角账号菜单 */
  const userChip = document.getElementById("userChip");
  const userMenu = document.getElementById("userMenu");
  if (userChip && userMenu) {
    const closeUserMenu = () => {
      userMenu.classList.remove("open");
      userChip.setAttribute("aria-expanded", "false");
    };
    userChip.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = userMenu.classList.toggle("open");
      userChip.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", closeUserMenu);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeUserMenu(); });
  }
});
