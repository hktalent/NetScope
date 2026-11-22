const S = {
  snap: null,
  sortKey: "rate",
  sortDir: -1,
  paused: false,
  search: "",
  onlyAbroad: false,
  onlyRate: false,
  last: [],
};

const $ = (id) => document.getElementById(id);

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
}

// 速率专用：KB 及以上固定保留 2 位小数；不足 1KB 时按整数 B 显示
function fmtRate(n) {
  n = Number(n) || 0;
  if (n < 1024) return n.toFixed(0) + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(2) + " " + u[i];
}

function fmtrate(c) {
  return fmtRate(c.rate);
}

function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function txt(c) {
  const parts = [c.domain, c.ip, c.country, c.app, c.proto, c.appProto, c.url, c.port ? ":" + c.port : ""];
  return parts.join(" ").toLowerCase();
}

function applyFilter(list) {
  const q = S.search.trim().toLowerCase();
  return list.filter((c) => {
    if (S.onlyAbroad) {
      const cc = c.cc || "";
      if (cc === "CN" || cc === "LAN") return false;
    }
    if (S.onlyRate && (c.rate || 0) <= 0) return false;
    if (q && !txt(c).includes(q)) return false;
    return true;
  });
}

function sortList(list) {
  const k = S.sortKey, dir = S.sortDir;
  const val = (c) => {
    if (k === "bytes") return c.bytes || 0;
    if (k === "rate") return c.rate || 0;
    if (k === "country") return c.country || "";
    if (k === "app") return c.app || "";
    if (k === "ip") return c.ip || "";
    if (k === "proto") return c.proto + "/" + c.appProto;
    if (k === "url") return c.url || "";
    return c.domain || "";
  };
  return list.sort((a, b) => {
    const x = val(a), y = val(b);
    if (typeof x === "string" || typeof y === "string") {
      return String(x).localeCompare(String(y)) * dir;
    }
    return (x - y) * dir;
  });
}

const CP_ICON =
  '<svg viewBox="0 0 16 16" class="ico"><rect x="5.2" y="1.6" width="8.6" height="10.6" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.1"/><rect x="2.2" y="4.2" width="8.6" height="10.6" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.1"/></svg>';

// 仅当有数据时返回复制图标
function cpIcon(v, title) {
  if (!v) return "";
  return `<span class="cp" data-copy="${esc(v)}" title="复制${title ? " " + esc(title) : ""}">${CP_ICON}</span>`;
}

function rowHTML(c) {
  const abroad = c.cc && c.cc !== "CN" && c.cc !== "LAN";
  const hot = (c.rate || 0) > 50000 ? " rate-hot" : "";
  const domain = c.domain ? esc(c.domain) : '<span class="dim">-</span>';
  const url = c.url
    ? `<span class="url" data-copy="${esc(c.url)}" title="点击复制">${esc(c.url)}</span>`
    : '<span class="dim">-</span>';
  const cpDomain = cpIcon(c.domain, "域名");
  const cpIp = cpIcon(c.ip, "IP");
  const cpUrl = cpIcon(c.url, "URL");
  const appPath = c.appPath || "";
  // 复制与提示都用完整程序路径；拿不到路径时退化为进程名
  const cpApp = cpIcon(appPath || c.app, "程序路径");
  const app = c.app
    ? `<span class="app">${esc(c.app)}</span>${c.pid ? `<span class="pid">(${c.pid})</span>` : ""}`
    : '<span class="dim">-</span>';
  const ccTxt = c.country ? `<span class="flag">${flag(c.cc)}</span>${esc(c.country)}` : '<span class="dim">-</span>';
  const merged = c.merged > 1 ? `<span class="merge">×${c.merged}</span>` : "";
  const ipTitle = c.merged > 1
    ? `${esc(c.ip)}:${c.port} · 合并 ${c.merged} 条连接`
    : `${esc(c.ip)}:${c.port} (本地 ${esc(c.localIp)}:${c.localPort})`;
  return `<tr class="${abroad ? "tr-abroad" : ""}">
<td class="cell" title="${esc(c.domain)}">${domain}${cpDomain}</td>
<td class="cell mono ip" title="${ipTitle}">${esc(c.ip)}${merged}${cpIp}</td>
<td>${ccTxt}</td>
<td class="cell" title="${esc(appPath || c.app || "")}">${app}${cpApp}</td>
<td class="proto">${esc(c.proto)}/${esc(c.appProto)}</td>
<td class="num" title="↑${fmtBytes(c.bytesUp)} ↓${fmtBytes(c.bytesDown)}">${fmtBytes(c.bytes)}</td>
<td class="num${hot}">${fmtrate(c)}</td>
<td class="cell urlcell" title="${esc(c.url)}">${url}${cpUrl}</td>
</tr>`;
}

function render() {
  if (!S.snap) return;
  const list = sortList(applyFilter(S.snap.conns || []));
  S.last = list;
  const tbody = $("rows");
  tbody.innerHTML = list.slice(0, 500).map(rowHTML).join("");
  $("empty").style.display = list.length ? "none" : "block";
  $("empty").textContent = S.paused ? "已暂停" : "正在收集连接…（3 秒内出现数据）";
}

function renderSummary() {
  if (!S.snap) return;
  const s = S.snap;
  $("iface").textContent = s.iface || "";
  $("rateDown").textContent = fmtRate(s.rateDown);
  $("rateUp").textContent = fmtRate(s.rateUp);
  $("statConns").textContent = s.connCount;
  $("statActive").textContent = s.active;
  $("statApps").textContent = s.apps;
  $("statCountries").textContent = s.countries;
  $("statTotal").textContent = fmtBytes(s.totalBytes);
  drawSpark(s.histDown || [], s.histUp || []);
}

let raf = 0;
function scheduleRender() {
  if (raf) return;
  raf = requestAnimationFrame(() => {
    raf = 0;
    renderSummary();
    if (!S.paused) render();
  });
}

function drawSpark(down, up) {
  const cv = $("spark");
  if (!cv || !cv.getContext) return;
  const ctx = cv.getContext("2d");
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  const n = 60;
  const d = down.slice(-n), u = up.slice(-n);
  const max = Math.max(1024, ...d, ...u);
  const px = (arr, i) => (W * i) / (n - 1);
  const py = (v) => H - 2 - (v / max) * (H - 6);

  if (d.length) {
    ctx.beginPath();
    ctx.moveTo(px(0), H);
    d.forEach((v, i) => ctx.lineTo(px(i), py(v)));
    ctx.lineTo(px(d.length - 1), H);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, "rgba(78,168,255,.45)");
    g.addColorStop(1, "rgba(78,168,255,.03)");
    ctx.fillStyle = g;
    ctx.fill();
    ctx.beginPath();
    d.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.strokeStyle = "#4ea8ff";
    ctx.lineWidth = 1.4;
    ctx.stroke();
  }
  if (u.length) {
    ctx.beginPath();
    u.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.strokeStyle = "rgba(255,169,77,.9)";
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }
}

function connect() {
  const es = new EventSource("/api/stream");
  es.onopen = () => $("live").className = "dot on";
  es.onerror = () => $("live").className = "dot off";
  es.onmessage = (e) => {
    try {
      S.snap = JSON.parse(e.data);
      scheduleRender();
    } catch (_) {}
  };
}

document.querySelectorAll("thead th").forEach((th) => {
  th.addEventListener("click", () => {
    const k = th.dataset.k;
    if (S.sortKey === k) S.sortDir *= -1;
    else { S.sortKey = k; S.sortDir = k === "domain" || k === "country" || k === "app" || k === "ip" || k === "proto" || k === "url" ? 1 : -1; }
    document.querySelectorAll("thead th").forEach((t) => t.classList.remove("sorted"));
    th.classList.add("sorted");
    render();
  });
});

$("search").addEventListener("input", (e) => { S.search = e.target.value; render(); });
$("onlyAbroad").addEventListener("change", (e) => { S.onlyAbroad = e.target.checked; render(); });
$("onlyRate").addEventListener("change", (e) => { S.onlyRate = e.target.checked; render(); });
$("pause").addEventListener("click", (e) => {
  S.paused = !S.paused;
  e.target.textContent = S.paused ? "继续" : "暂停";
  if (!S.paused) render();
});

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 1400);
}

$("rows").addEventListener("click", async (e) => {
  const el = e.target.closest("[data-copy]");
  if (!el) return;
  const text = el.dataset.copy;
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制：" + text);
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast("已复制：" + text);
  }
});

connect();
