(function () {
  "use strict";
  const bootstrap = document.getElementById("workspace-config");
  if (!bootstrap) return;
  const config = JSON.parse(bootstrap.textContent);
  const words = config.labels;
  const query = document.getElementById("workspace-query");
  const project = document.getElementById("workspace-project");
  const protocol = document.getElementById("workspace-protocol");
  const grid = document.getElementById("workspace-grid");
  const status = document.getElementById("workspace-status");
  const feedback = document.getElementById("workspace-feedback");
  const empty = document.getElementById("workspace-empty");
  const more = document.getElementById("workspace-more");
  const count = document.getElementById("workspace-count");
  const views = Array.from(document.querySelectorAll("[data-workspace-view]"));
  const protocolNames = {ssh: "SSH", http: "HTTP", kubernetes: "Kubernetes", postgresql: "PostgreSQL", mysql: "MySQL"};
  const protocolMarks = {ssh: ">_", http: "↗", kubernetes: "⎈", postgresql: "DB", mysql: "DB"};
  const states = new Set(["available", "approval_required", "step_up_required", "maintenance", "denied", "unavailable"]);
  const reasonKeys = {
    "Access is available.": "reason_available", "An administrator must approve this session.": "reason_approval",
    "Fresh authentication is required.": "reason_step_up", "This resource is in maintenance.": "reason_maintenance",
    "A separate connection grant is required.": "reason_denied", "The connection service is not enabled for this resource.": "reason_unavailable"
  };
  const initial = config.initial || {};
  let view = ["all", "favorites", "recent"].includes(initial.view) ? initial.view : "all";
  let favorites = new Set();
  let preferencesReady = false;
  let preferencesBusy = false;
  let nextOffset = null;
  let controller = null;
  let generation = 0;
  let debounce = null;
  let loading = false;
  const seen = new Set();

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function safeHref(value) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\\\x00-\x20\x7f]/.test(value)) return null;
    try {
      const url = new URL(value, window.location.origin);
      return url.origin === window.location.origin ? url.pathname + url.search + url.hash : null;
    } catch (_) { return null; }
  }
  function message(text, action) {
    feedback.replaceChildren(node("span", "", text));
    feedback.hidden = false;
    if (action === "login") {
      const link = node("a", "", words.sign_in);
      link.href = "/login";
      feedback.append(link);
    } else if (action) {
      const retry = node("button", "secondary", words.retry);
      retry.type = "button";
      retry.addEventListener("click", action);
      feedback.append(retry);
    }
  }
  async function responseJSON(response) {
    if (response.status === 401) throw Object.assign(new Error("session"), {status: 401});
    if (response.status === 403) throw Object.assign(new Error("forbidden"), {status: 403});
    if (!response.ok || !(response.headers.get("content-type") || "").includes("application/json")) throw new Error("unavailable");
    return response.json();
  }
  function displayError(error, text, retry) {
    if (error.status === 401) message(words.session_expired, "login");
    else if (error.status === 403) message(words.forbidden);
    else message(text, retry);
  }
  function updateFavoriteButtons() {
    grid.querySelectorAll("[data-resource-favorite]").forEach(button => {
      const selected = favorites.has(button.dataset.resourceFavorite);
      button.textContent = selected ? "★" : "☆";
      button.setAttribute("aria-pressed", String(selected));
      button.setAttribute("aria-label", selected ? words.remove_favorite : words.add_favorite);
      button.title = selected ? words.remove_favorite : words.add_favorite;
      button.disabled = !preferencesReady || preferencesBusy;
    });
  }
  async function loadPreferences() {
    try {
      const payload = await fetch(config.preferences_url, {credentials: "same-origin", cache: "no-store"}).then(responseJSON);
      if (!Array.isArray(payload.favorites)) throw new Error("preferences");
      favorites = new Set(payload.favorites.filter(value => typeof value === "string"));
      preferencesReady = true;
      updateFavoriteButtons();
    } catch (error) { displayError(error, words.preferences_load_error, () => window.location.reload()); }
  }
  async function toggleFavorite(id) {
    if (!preferencesReady || preferencesBusy) return;
    preferencesBusy = true;
    const before = new Set(favorites);
    if (favorites.has(id)) favorites.delete(id); else favorites.add(id);
    updateFavoriteButtons();
    try {
      const payload = await fetch(config.preferences_url, {
        method: "PATCH", credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": config.csrf},
        body: JSON.stringify({favorites: Array.from(favorites)})
      }).then(responseJSON);
      if (!Array.isArray(payload.favorites)) throw new Error("preferences");
      favorites = new Set(payload.favorites);
      if (view === "favorites") await loadResources(false);
    } catch (error) {
      favorites = before;
      displayError(error, words.preferences_error, () => toggleFavorite(id));
    } finally {
      preferencesBusy = false;
      updateFavoriteButtons();
    }
  }
  function actionLabel(access, state) {
    const action = access.next_action && typeof access.next_action === "object" ? access.next_action.type : access.next_action;
    if (words[action]) return words[action];
    if (state === "available") return words.connect;
    if (state === "step_up_required") return words.step_up;
    if (state === "approval_required") return words.request_approval;
    if (state === "denied") return words.request_access;
    return words.view;
  }
  function resourceCard(resource) {
    const id = String(resource.resource_id || "");
    if (!id || !protocolNames[resource.protocol]) return null;
    const article = node("article", "workspace-resource");
    article.tabIndex = 0;
    article.setAttribute("role", "listitem");
    article.setAttribute("aria-label", String(resource.name || resource.host_id) + ", " + protocolNames[resource.protocol]);
    const top = node("div", "workspace-resource-top");
    const badge = node("span", "workspace-protocol");
    const mark = node("span", "workspace-protocol-mark", protocolMarks[resource.protocol]);
    mark.setAttribute("aria-hidden", "true");
    badge.append(mark, node("span", "", protocolNames[resource.protocol]));
    const star = node("button", "workspace-favorite");
    star.type = "button";
    star.dataset.resourceFavorite = id;
    star.addEventListener("click", () => toggleFavorite(id));
    top.append(badge, star);
    article.append(top, node("h2", "", resource.name || resource.host_id), node("div", "workspace-resource-project", resource.project || "—"));
    const metadata = node("dl", "workspace-resource-metadata");
    [[words.owner, resource.owner], [words.environment, resource.environment]].forEach(([label, value]) => {
      metadata.append(node("dt", "", label), node("dd", "", value || "—"));
    });
    article.append(metadata);
    const tags = node("div", "workspace-resource-tags");
    const tagValues = Array.isArray(resource.tags) ? resource.tags : Object.entries(resource.tags || {}).map(([key, value]) => key + ": " + value);
    tagValues.slice(0, 6).forEach(value => tags.append(node("span", "", String(value))));
    article.append(tags);
    const access = resource.access || {};
    const state = states.has(access.state) ? access.state : "unknown";
    const accessNode = node("div", "workspace-access");
    accessNode.dataset.state = state;
    accessNode.append(node("span", "workspace-access-dot"), node("span", "", words[state]));
    article.append(accessNode);
    if (access.reason) article.append(node("p", "workspace-access-reason", words[reasonKeys[access.reason]] || String(access.reason)));
    else article.append(node("p", "workspace-access-reason", ""));
    const actions = node("div", "workspace-resource-actions");
    const detailsURL = safeHref(resource.details_url);
    const nextActionURL = typeof access.next_action === "object" && access.next_action ? access.next_action.url : null;
    const primaryURL = safeHref(access.url || nextActionURL || (state === "available" ? resource.connect_url : null));
    if (primaryURL) {
      const connect = node("a", "workspace-connect", actionLabel(access, state));
      connect.href = primaryURL;
      connect.dataset.workspacePrimary = "true";
      actions.append(connect);
    }
    if (detailsURL) {
      const details = node("a", "", words.details);
      details.href = detailsURL;
      if (!primaryURL) details.dataset.workspacePrimary = "true";
      actions.append(details);
    }
    if (/^[0-9]{1,32}$/.test(String(resource.host_id || ""))) {
      const explain = node("a", "access-explanation-link", words.explain_access || "Why this access?");
      explain.href = "/workspace/access/" + encodeURIComponent(resource.host_id) + "?protocol=" + encodeURIComponent(resource.protocol);
      actions.append(explain);
    }
    article.append(actions);
    return article;
  }
  function renderEmpty() {
    const heading = view === "favorites" ? words.empty_favorites : view === "recent" ? words.empty_recent : words.empty;
    const help = view === "favorites" ? words.favorites_help : view === "recent" ? words.recent_help : words.empty_help;
    const reset = node("button", "secondary", words.reset);
    reset.type = "button";
    reset.addEventListener("click", () => { query.value = ""; project.value = ""; protocol.value = ""; view = "all"; loadResources(false); });
    empty.replaceChildren(node("span", "workspace-empty-mark", view === "favorites" ? "☆" : "⌕"), node("h2", "", heading), node("p", "", help), reset);
    empty.hidden = false;
  }
  function syncFilters() {
    views.forEach(button => button.setAttribute("aria-pressed", String(button.dataset.workspaceView === view)));
    const params = new URLSearchParams();
    if (query.value.trim()) params.set("q", query.value.trim());
    if (project.value.trim()) params.set("project", project.value.trim());
    if (protocol.value) params.set("protocol", protocol.value);
    if (view !== "all") params.set("view", view);
    const current = new URL(window.location.href);
    if (current.searchParams.has("lang")) params.set("lang", current.searchParams.get("lang"));
    window.history.replaceState(null, "", current.pathname + (params.size ? "?" + params.toString() : ""));
    return params;
  }
  async function loadResources(append) {
    if (append && (loading || nextOffset === null)) return;
    if (controller) controller.abort();
    controller = new AbortController();
    const currentGeneration = ++generation;
    loading = true;
    more.hidden = true;
    grid.setAttribute("aria-busy", "true");
    status.textContent = words.loading;
    empty.hidden = true;
    feedback.hidden = true;
    if (!append) { grid.replaceChildren(); seen.clear(); nextOffset = null; count.textContent = ""; }
    const params = syncFilters();
    params.set("limit", "48");
    params.set("offset", append ? String(nextOffset) : "0");
    try {
      const payload = await fetch(config.resources_url + "?" + params.toString(), {credentials: "same-origin", cache: "no-store", signal: controller.signal}).then(responseJSON);
      if (currentGeneration !== generation) return;
      if (!Array.isArray(payload.resources)) throw new Error("resources");
      const fragment = document.createDocumentFragment();
      payload.resources.forEach(resource => {
        if (seen.has(resource.resource_id)) return;
        const card = resourceCard(resource);
        if (card) { seen.add(resource.resource_id); fragment.append(card); }
      });
      grid.append(fragment);
      updateFavoriteButtons();
      nextOffset = Number.isSafeInteger(payload.next_offset) && payload.next_offset > Number(params.get("offset")) ? payload.next_offset : null;
      more.hidden = nextOffset === null;
      count.textContent = String(seen.size) + " " + words.loaded;
      if (!seen.size) renderEmpty();
      status.textContent = "";
    } catch (error) {
      if (error.name === "AbortError" || currentGeneration !== generation) return;
      // A revoked/failed refresh must not leave previously authorized objects on screen.
      grid.replaceChildren(); seen.clear(); nextOffset = null; count.textContent = "";
      status.textContent = "";
      displayError(error, words.error, () => loadResources(false));
    } finally {
      if (currentGeneration === generation) { loading = false; grid.setAttribute("aria-busy", "false"); }
    }
  }
  function scheduleSearch() {
    window.clearTimeout(debounce);
    debounce = window.setTimeout(() => loadResources(false), 180);
  }
  document.getElementById("workspace-filters").addEventListener("submit", event => { event.preventDefault(); window.clearTimeout(debounce); loadResources(false); });
  query.value = initial.q || "";
  project.value = initial.project || "";
  protocol.value = protocolNames[initial.protocol] ? initial.protocol : "";
  query.addEventListener("input", scheduleSearch);
  project.addEventListener("input", scheduleSearch);
  protocol.addEventListener("change", () => loadResources(false));
  views.forEach(button => button.addEventListener("click", () => { view = button.dataset.workspaceView; loadResources(false); }));
  more.addEventListener("click", () => loadResources(true));
  document.addEventListener("keydown", event => {
    const editable = event.target.closest("input, textarea, select, [contenteditable='true']");
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" || event.key === "/" && !editable) {
      event.preventDefault(); query.focus(); query.select();
    }
    if (event.key === "Escape" && event.target === query && query.value) { query.value = ""; loadResources(false); }
    if (event.key === "ArrowDown" && event.target === query) {
      const first = grid.querySelector(".workspace-resource");
      if (first) { event.preventDefault(); first.focus(); }
    }
  });
  grid.addEventListener("keydown", event => {
    const cards = Array.from(grid.querySelectorAll(".workspace-resource"));
    const index = cards.indexOf(event.target);
    if (index < 0) return;
    const columns = Math.max(1, window.getComputedStyle(grid).gridTemplateColumns.split(" ").length);
    let target = index;
    if (event.key === "ArrowRight") target++;
    else if (event.key === "ArrowLeft") target--;
    else if (event.key === "ArrowDown") target += columns;
    else if (event.key === "ArrowUp") target -= columns;
    else if (event.key === "Home") target = 0;
    else if (event.key === "End") target = cards.length - 1;
    else if (event.key === "Enter") {
      const link = cards[index].querySelector("[data-workspace-primary]");
      if (link) { event.preventDefault(); link.click(); }
      return;
    } else return;
    event.preventDefault(); cards[Math.max(0, Math.min(cards.length - 1, target))].focus();
  });
  if (!config.enabled) {
    grid.setAttribute("aria-busy", "false"); status.textContent = ""; message(words.no_api); return;
  }
  loadPreferences();
  loadResources(false);
}());
