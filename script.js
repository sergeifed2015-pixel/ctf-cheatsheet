// Application State
const state = {
  currentCategory: null, // null for main screen, or category ID
  searchQuery: "",
  selectedFrequency: "all" // all, high, medium, low
};

// DOM Elements
const categoryScreen = document.getElementById("category-screen");
const detailScreen = document.getElementById("detail-screen");
const searchInput = document.getElementById("search-input");
const searchClear = document.getElementById("search-clear");
const filterButtons = document.querySelectorAll(".filter-btn");
const backBtn = document.getElementById("back-btn");
const currentCategoryIcon = document.getElementById("current-category-icon");
const currentCategoryTitle = document.getElementById("current-category-title");
const currentCategorySubtitle = document.getElementById("current-category-subtitle");
const commandsContainer = document.getElementById("commands-container");
const emptyState = document.getElementById("empty-state");
const toastContainer = document.getElementById("toast-container");

// Frequency localization mapping
const freqLocal = {
  high: "Часто",
  medium: "Иногда",
  low: "Редко"
};

// SVG icons mapping for backup or helper if needed
const categoryIcons = {};

// Initialize Application
function init() {
  renderCategories();
  setupEventListeners();
  updateView();
}

// Render Category Cards on the Main Screen
function renderCategories() {
  categoryScreen.innerHTML = "";
  
  ctfData.categories.forEach((cat, index) => {
    const card = document.createElement("div");
    card.className = "category-card";
    // Add staggered animation delay
    card.style.animation = `fadeIn 0.4s ease-out ${index * 0.05}s both`;
    card.dataset.id = cat.id;
    
    card.innerHTML = `
      <div class="card-header">
        <div class="category-icon-wrapper">
          ${cat.icon}
        </div>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
      </div>
      <div class="category-details">
        <h2>${cat.title}</h2>
        <div class="cat-sub">${cat.subtitle}</div>
      </div>
      <p class="category-description">${cat.description}</p>
      <div class="card-footer-action">
        <span>Открыть директорию</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="5" y1="12" x2="19" y2="12"></line>
          <polyline points="12 5 19 12 12 19"></polyline>
        </svg>
      </div>
    `;
    
    card.addEventListener("click", () => {
      openCategory(cat.id);
    });
    
    categoryScreen.appendChild(card);
  });
}

// Open Specific Category
function openCategory(categoryId) {
  state.currentCategory = categoryId;
  updateView();
  // Scroll to top
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Go back to Main Screen
function goBack() {
  state.currentCategory = null;
  state.searchQuery = "";
  searchInput.value = "";
  searchClear.style.display = "none";
  updateView();
}

// Update UI elements based on state
function updateView() {
  const isSearchingGlobal = state.searchQuery.length > 0 && state.currentCategory === null;
  
  if (state.currentCategory !== null) {
    // Show Detail Screen, Hide Category Screen
    categoryScreen.style.display = "none";
    detailScreen.style.display = "block";
    
    // Find category info
    const catInfo = ctfData.categories.find(c => c.id === state.currentCategory);
    if (catInfo) {
      currentCategoryIcon.innerHTML = catInfo.icon;
      currentCategoryTitle.textContent = catInfo.title;
      currentCategorySubtitle.textContent = catInfo.subtitle;
      
      // Render recommended software badges
      const softwareContainer = document.getElementById("software-container");
      if (softwareContainer) {
        if (catInfo.programs && catInfo.programs.length > 0) {
          softwareContainer.style.display = "flex";
          softwareContainer.innerHTML = `
            <span class="software-label">Поможет в решении:</span>
            ${catInfo.programs.map(prog => `<span class="software-badge">${prog}</span>`).join("")}
          `;
        } else {
          softwareContainer.style.display = "none";
          softwareContainer.innerHTML = "";
        }
      }
    }
    
    renderCommands();
  } else if (isSearchingGlobal) {
    // If searching globally (no category selected but text entered)
    categoryScreen.style.display = "none";
    detailScreen.style.display = "block";
    
    // Set search visual mode in header
    currentCategoryIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
    currentCategoryTitle.textContent = "Результаты поиска";
    currentCategorySubtitle.textContent = `Поиск по запросу: "${state.searchQuery}"`;
    
    // Hide software container in global search
    const softwareContainer = document.getElementById("software-container");
    if (softwareContainer) {
      softwareContainer.style.display = "none";
      softwareContainer.innerHTML = "";
    }
    
    renderCommands();
  } else {
    // Show Main Category Screen, Hide Details
    categoryScreen.style.display = "grid";
    detailScreen.style.display = "none";
    emptyState.style.display = "none";
    
    // Re-render categories to trigger entrance animations
    renderCategories();
  }
}

// Helper to highlight matching search text
function highlightText(text, query) {
  if (!query) return text;
  
  // Escape regex special characters
  const escapedQuery = query.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
  const regex = new RegExp(`(${escapedQuery})`, 'gi');
  
  return text.replace(regex, '<mark style="background-color: rgba(0, 255, 102, 0.25); color: #fff; border-radius: 2px; padding: 0 2px;">$1</mark>');
}

// Render and Filter Commands List
function renderCommands() {
  commandsContainer.innerHTML = "";
  
  // Filter logic
  const filtered = ctfData.commands.filter(cmd => {
    // Category match
    const categoryMatch = state.currentCategory === null || cmd.categoryId === state.currentCategory;
    
    // Frequency match
    const freqMatch = state.selectedFrequency === "all" || cmd.frequency === state.selectedFrequency;
    
    // Search query match
    let searchMatch = true;
    if (state.searchQuery.trim() !== "") {
      const q = state.searchQuery.toLowerCase();
      const toolMatch = cmd.tool.toLowerCase().includes(q);
      const descMatch = cmd.description.toLowerCase().includes(q);
      const codeMatch = cmd.command.toLowerCase().includes(q);
      const outputMatch = cmd.output ? cmd.output.toLowerCase().includes(q) : false;
      const explanationMatch = cmd.explanation ? cmd.explanation.some(item => item.arg.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q)) : false;
      const importantMatch = cmd.important ? cmd.important.some(item => item.token.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q)) : false;
      searchMatch = toolMatch || descMatch || codeMatch || outputMatch || explanationMatch || importantMatch;
    }
    
    return categoryMatch && freqMatch && searchMatch;
  });
  
  if (filtered.length === 0) {
    emptyState.style.display = "flex";
    commandsContainer.style.display = "none";
  } else {
    emptyState.style.display = "none";
    commandsContainer.style.display = "flex";
    
    filtered.forEach((cmd, index) => {
      const catInfo = ctfData.categories.find(c => c.id === cmd.categoryId);
      const catTitle = catInfo ? catInfo.title : "";
      
      const card = document.createElement("div");
      card.className = "command-card";
      card.style.animation = `fadeIn 0.3s ease-out ${index * 0.04}s both`;
      
      // Highlighting strings
      const highlightedTool = highlightText(cmd.tool, state.searchQuery);
      const highlightedDesc = highlightText(cmd.description, state.searchQuery);
      const highlightedCode = highlightText(cmd.command, state.searchQuery);
      
      // Generate frequency badge
      const badgeClass = `badge-${cmd.frequency}`;
      const badgeText = freqLocal[cmd.frequency];
      
      // Generate argument breakdown HTML
      let explanationHtml = "";
      if (cmd.explanation && cmd.explanation.length > 0) {
        explanationHtml = `
          <div class="command-explanation-box">
            <div class="explanation-title">Разбор команды</div>
            <ul class="explanation-list">
              ${cmd.explanation.map(item => {
                const highlightedArg = highlightText(item.arg, state.searchQuery);
                const highlightedDesc = highlightText(item.desc, state.searchQuery);
                return `
                  <li class="explanation-item">
                    <span class="arg-token">${highlightedArg}</span>
                    <span class="arg-desc">${highlightedDesc}</span>
                  </li>
                `;
              }).join("")}
            </ul>
          </div>
        `;
      }
      
      // Generate output preview HTML
      let outputHtml = "";
      if (cmd.output) {
        const highlightedOutput = highlightText(cmd.output, state.searchQuery);
        
        let importantHtml = "";
        if (cmd.important && cmd.important.length > 0) {
          importantHtml = `
            <div class="output-explanation">
              <div class="output-explanation-title">На что обратить внимание в выводе:</div>
              <ul class="output-explanation-list">
                ${cmd.important.map(item => {
                  const highlightedToken = highlightText(item.token, state.searchQuery);
                  const highlightedDesc = highlightText(item.desc, state.searchQuery);
                  return `
                    <li class="output-explanation-item">
                      <span class="output-token">${highlightedToken}</span>
                      <span class="output-desc">${highlightedDesc}</span>
                    </li>
                  `;
                }).join("")}
              </ul>
            </div>
          `;
        }
        
        outputHtml = `
          <div class="output-block-wrapper">
            <div class="output-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="4 17 10 11 4 5"></polyline>
                <line x1="12" y1="19" x2="20" y2="19"></line>
              </svg>
              Пример вывода утилиты
            </div>
            <pre class="output-block"><code>${highlightedOutput}</code></pre>
          </div>
          ${importantHtml}
        `;
      }
      
      card.innerHTML = `
        <div class="command-card-header">
          <div class="command-card-title">
            <span class="tool-name">${highlightedTool}</span>
            ${state.currentCategory === null ? `<span class="category-tag">${catTitle}</span>` : ""}
          </div>
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="badge ${badgeClass}">${badgeText}</span>
            <div class="window-dots">
              <span class="dot dot-red"></span>
              <span class="dot dot-yellow"></span>
              <span class="dot dot-green"></span>
            </div>
          </div>
        </div>
        <div class="command-card-body">
          <p class="command-description">${highlightedDesc}</p>
          <div class="code-block-wrapper">
            <pre class="code-block"><code>${highlightedCode}</code></pre>
            <button class="copy-btn" data-clipboard-text="${cmd.command.replace(/"/g, '&quot;')}">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
              <span>Copy</span>
            </button>
          </div>
          ${explanationHtml}
          ${outputHtml}
        </div>
      `;
      
      // Setup Copy Click Listener
      const copyBtn = card.querySelector(".copy-btn");
      copyBtn.addEventListener("click", () => {
        copyToClipboard(cmd.command, copyBtn);
      });
      
      commandsContainer.appendChild(card);
    });
  }
}

// Copy Action with Toast Feedback
function copyToClipboard(text, button) {
  // If we have access to navigator.clipboard
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
      .then(() => handleCopySuccess(button))
      .catch(() => fallbackCopy(text, button));
  } else {
    fallbackCopy(text, button);
  }
}

// Fallback for older browsers or non-secure contexts
function fallbackCopy(text, button) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  
  try {
    document.execCommand('copy');
    handleCopySuccess(button);
  } catch (err) {
    console.error('Не удалось скопировать текст: ', err);
    showToast("Ошибка копирования", "error");
  }
  
  document.body.removeChild(textArea);
}

function handleCopySuccess(button) {
  const span = button.querySelector("span");
  const svg = button.querySelector("svg");
  
  button.classList.add("copied");
  span.textContent = "Copied!";
  
  // Save original svg
  const originalSvg = svg.innerHTML;
  // Set checkmark svg
  svg.innerHTML = `<polyline points="20 6 9 17 4 12"></polyline>`;
  
  showToast("Команда успешно скопирована в буфер обмена");
  
  setTimeout(() => {
    button.classList.remove("copied");
    span.textContent = "Copy";
    svg.innerHTML = originalSvg;
  }, 2000);
}

// Custom Toast notification
function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00ff66" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
    <span>${message}</span>
  `;
  
  toastContainer.appendChild(toast);
  
  // Fade out and remove
  setTimeout(() => {
    toast.classList.add("fade-out");
    toast.addEventListener("animationend", () => {
      toast.remove();
    });
  }, 2500);
}

// Setup Event Listeners
function setupEventListeners() {
  // Back button
  backBtn.addEventListener("click", goBack);
  
  // Search input typing
  searchInput.addEventListener("input", (e) => {
    state.searchQuery = e.target.value;
    
    // Show/hide clear button
    if (state.searchQuery.length > 0) {
      searchClear.style.display = "block";
    } else {
      searchClear.style.display = "none";
    }
    
    updateView();
    
    // If searching, trigger render
    if (state.currentCategory !== null || state.searchQuery.length > 0) {
      renderCommands();
    }
  });
  
  // Clear search input
  searchClear.addEventListener("click", () => {
    searchInput.value = "";
    state.searchQuery = "";
    searchClear.style.display = "none";
    searchInput.focus();
    updateView();
  });
  
  // Frequency Filter Buttons
  filterButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      // Remove active from all
      filterButtons.forEach(b => b.classList.remove("active"));
      // Add active to clicked
      btn.classList.add("active");
      
      state.selectedFrequency = btn.dataset.freq;
      
      if (state.currentCategory !== null || state.searchQuery.length > 0) {
        renderCommands();
      }
    });
  });

  // Shortkey to focus search (e.g. '/' or 'Ctrl+/')
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== searchInput) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });
}

// Start app
document.addEventListener("DOMContentLoaded", init);
