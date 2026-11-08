import { Terminal } from '/static/vendor/xterm/xterm.mjs';
import { MAX_TABS, MAX_PANES, MAX_PASTE, terminalPreferences, pasteNeedsConfirmation, websocketEndpoint, findTerminalMatches, inputChunks } from './terminal-workspace-utils.mjs';

const root = document.getElementById('terminal-workspace');
const configuration = document.getElementById('terminal-workspace-config');
if (root && configuration) {
  const config = JSON.parse(configuration.textContent);
  const ru = config.language === 'ru';
  const words = ru ? {
    authorize: 'Проверяем доступ…', waiting: 'Ожидаем согласования…', connected: 'Подключено', closed: 'Соединение закрыто',
    denied: 'Подключение недоступно. Проверьте права или повторите вход.', error: 'Не удалось подключиться к gateway',
    resources: 'Загружаем ресурсы…', noResources: 'Нет доступных SSH-ресурсов по этому запросу.', resourcesFailed: 'Каталог временно недоступен.',
    reconnect: 'Подключиться снова', close: 'Закрыть', tab: 'Терминал', newTab: 'Новая вкладка',
    tabLimit: 'Можно открыть до 8 вкладок. Закройте одну из текущих.', paneLimit: 'Во вкладке можно открыть до 4 терминалов.',
    none: 'Нет совпадений', matches: 'совпадений', pasteLarge: 'Вставка превышает лимит 256 КиБ. Разделите её на части.',
    settingsSaved: 'Настройки сохранены.', settingsLocal: 'Настройки применены. Серверное сохранение временно недоступно.',
    confirmClose: 'Закрыть активное подключение?', login: 'Повторный вход', ended: 'Сессия завершена',
  } : {
    authorize: 'Checking access…', waiting: 'Waiting for approval…', connected: 'Connected', closed: 'Connection closed',
    denied: 'Connection unavailable. Check your access or sign in again.', error: 'Gateway connection failed',
    resources: 'Loading resources…', noResources: 'No authorized SSH resources match.', resourcesFailed: 'Resource catalogue is temporarily unavailable.',
    reconnect: 'Reconnect', close: 'Close', tab: 'Terminal', newTab: 'New tab',
    tabLimit: 'Up to 8 tabs can be open. Close an existing tab first.', paneLimit: 'Up to 4 terminals can be open in a tab.',
    none: 'No matches', matches: 'matches', pasteLarge: 'Paste exceeds 256 KiB. Split it into smaller parts.',
    settingsSaved: 'Settings saved.', settingsLocal: 'Settings applied. Server persistence is temporarily unavailable.',
    confirmClose: 'Close this active connection?', login: 'Sign in again', ended: 'Session ended',
  };
  let settings = terminalPreferences(config.preferences);
  const tabs = [], tabsElement = document.getElementById('tw-tabs'), stage = document.getElementById('tw-stage');
  const empty = stage.firstElementChild;
  const notice = document.getElementById('tw-notice');
  let activeTab = null, activePane = null, sequence = 0, pickerAction = null, resourceCache = [];
  let disposed = false, pendingPaste = null;
  const resourceDialog = document.getElementById('tw-resource-dialog');
  const resourceSearch = document.getElementById('tw-resource-search');
  const settingsDialog = document.getElementById('tw-settings-dialog');
  const pasteDialog = document.getElementById('tw-paste-dialog');
  const searchPanel = document.getElementById('tw-search');
  const searchInput = document.getElementById('tw-search-input');
  const text = (element, value) => { element.textContent = value; };
  const announce = value => { notice.textContent = value; };
  const button = (label, callback, className = '') => {
    const node = document.createElement('button'); node.type = 'button'; node.textContent = label; node.className = className;
    node.addEventListener('click', callback); return node;
  };
  const requestHeaders = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': config.csrf });
  function currentTheme() {
    return settings.theme === 'light' ? { background: '#f8fafc', foreground: '#16243b', cursor: '#087f8c', selectionBackground: '#b5dfe8' }
      : { background: '#0c1423', foreground: '#d7e5f5', cursor: '#68d8cf', selectionBackground: '#314a64' };
  }
  function setState(pane, label, state = 'waiting') {
    pane.state = state; pane.status.textContent = label; pane.element.dataset.state = state;
  }
  function focusPane(pane) {
    if (!pane || pane.closed) return;
    activePane = pane;
    tabs.forEach(tab => tab.panes.forEach(item => item.element.classList.toggle('is-active', item === pane)));
    pane.terminal.focus();
  }
  function activateTab(tab) {
    activeTab = tab;
    for (const item of tabs) {
      const selected = item === tab;
      item.element.hidden = !selected;
      item.tabButton.setAttribute('aria-selected', String(selected));
      item.tabButton.tabIndex = selected ? 0 : -1;
      item.tabNode.classList.toggle('is-selected', selected);
    }
    if (tab?.panes.length) {
      const pane = tab.panes.includes(activePane) ? activePane : tab.panes[0];
      requestAnimationFrame(() => { tab.panes.forEach(resizePane); focusPane(pane); });
    }
  }
  function resizePane(pane) {
    if (pane.closed || !pane.emulator.clientWidth || !pane.emulator.clientHeight) return;
    // A hidden measuring cell uses the chosen real font; no fixed 9px sizing.
    pane.measure.style.fontSize = `${settings.font_size}px`;
    pane.measure.style.fontFamily = `${settings.font_family}, monospace`;
    const bounds = pane.measure.getBoundingClientRect();
    const cols = Math.max(20, Math.min(500, Math.floor((pane.emulator.clientWidth - 16) / Math.max(1, bounds.width / 10))));
    const rows = Math.max(5, Math.min(200, Math.floor((pane.emulator.clientHeight - 8) / Math.max(1, bounds.height))));
    if (cols !== pane.terminal.cols || rows !== pane.terminal.rows) pane.terminal.resize(cols, rows);
    if (pane.state === 'connected' && pane.socket?.readyState === WebSocket.OPEN) pane.socket.send(JSON.stringify({ type: 'resize', cols, rows }));
  }
  function sendInput(pane, data) {
    if (!pane || pane.closed || pane.state !== 'connected' || pane.socket?.readyState !== WebSocket.OPEN) return;
    // Keep each JSON frame below the server bound, including UTF-8 expansion.
    for (const chunk of inputChunks(data)) {
      pane.socket.send(JSON.stringify({ type: 'input', data: chunk }));
    }
  }
  function paste(pane, value) {
    if (!value || pane.closed || pane.state !== 'connected') return;
    if (value.length > MAX_PASTE) { announce(words.pasteLarge); return; }
    if (!pasteNeedsConfirmation(value, settings.paste_threshold)) { pane.terminal.paste(value); return; }
    if (pasteDialog.open) return;
    pendingPaste = { pane, value };
    text(document.getElementById('tw-paste-target'), `${pane.resource.name} · ${pane.resource.project}`);
    document.getElementById('tw-paste-preview').value = value;
    pasteDialog.returnValue = '';
    pasteDialog.showModal();
  }
  pasteDialog.addEventListener('close', () => {
    const pending = pendingPaste; pendingPaste = null;
    document.getElementById('tw-paste-preview').value = '';
    if (pasteDialog.returnValue === 'confirm' && pending && !pending.pane.closed) pending.pane.terminal.paste(pending.value);
    pending?.pane.terminal.focus();
  });
  function disposePane(pane) {
    if (pane.closed) return;
    pane.closed = true; pane.abort?.abort(); pane.socket?.close(1000, 'Client closed terminal');
    pane.observer.disconnect(); pane.terminal.dispose(); pane.element.remove();
    if (pendingPaste?.pane === pane) { pendingPaste = null; pasteDialog.close('cancel'); }
  }
  function closePane(tab, pane) {
    if (pane.state === 'connected' && !window.confirm(words.confirmClose)) return;
    disposePane(pane); tab.panes.splice(tab.panes.indexOf(pane), 1);
    if (!tab.panes.length) removeTab(tab); else { activePane = tab.panes[0]; activateTab(tab); }
  }
  function removeTab(tab) {
    tab.panes.forEach(disposePane); tab.element.remove(); tab.tabNode.remove();
    tabs.splice(tabs.indexOf(tab), 1);
    if (activeTab === tab) activateTab(tabs[tabs.length - 1] || null);
    empty.hidden = tabs.length > 0;
    if (!tabs.length) { activePane = null; activeTab = null; }
  }
  function closeTab(tab) {
    if (tab.panes.some(pane => pane.state === 'connected') && !window.confirm(words.confirmClose)) return;
    removeTab(tab);
  }
  function createTab(resource) {
    if (tabs.length >= MAX_TABS) { announce(words.tabLimit); return; }
    const tab = { id: ++sequence, panes: [] };
    tab.element = document.createElement('div'); tab.element.className = 'tw-pane-grid'; tab.element.id = `tw-tab-panel-${tab.id}`;
    tab.element.setAttribute('role', 'tabpanel'); tab.element.setAttribute('aria-label', resource.name);
    tab.tabNode = document.createElement('div'); tab.tabNode.className = 'tw-tab';
    tab.tabButton = button(resource.name, () => activateTab(tab)); tab.tabButton.setAttribute('role', 'tab');
    tab.tabButton.setAttribute('aria-controls', tab.element.id);
    tab.tabButton.addEventListener('keydown', event => {
      if (!['ArrowRight', 'ArrowLeft'].includes(event.key)) return;
      event.preventDefault(); const direction = event.key === 'ArrowRight' ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + direction + tabs.length) % tabs.length]; activateTab(next); next.tabButton.focus();
    });
    const close = button('×', () => closeTab(tab), 'tw-tab-close'); close.setAttribute('aria-label', `${words.close}: ${resource.name}`);
    tab.tabNode.append(tab.tabButton, close); tabsElement.append(tab.tabNode); stage.append(tab.element); tabs.push(tab);
    empty.hidden = true; createPane(tab, resource); activateTab(tab); return tab;
  }
  function createPane(tab, resource) {
    if (tab.panes.length >= MAX_PANES) { announce(words.paneLimit); return; }
    const pane = { resource, closed: false, state: 'waiting', socket: null, generation: 0, tab };
    pane.element = document.createElement('section'); pane.element.className = 'tw-pane';
    pane.element.setAttribute('aria-label', `${resource.name} · ${resource.project}`);
    const header = document.createElement('header'); header.className = 'tw-pane-header';
    const title = document.createElement('strong'); title.textContent = resource.name;
    pane.status = document.createElement('span'); pane.status.className = 'tw-pane-status'; pane.status.setAttribute('role', 'status');
    const reconnect = button('↻', () => connect(pane)); reconnect.setAttribute('aria-label', words.reconnect); reconnect.title = words.reconnect;
    const close = button('×', () => closePane(tab, pane)); close.setAttribute('aria-label', words.close);
    header.append(title, pane.status, reconnect, close);
    pane.emulator = document.createElement('div'); pane.emulator.className = 'tw-emulator';
    pane.measure = document.createElement('span'); pane.measure.className = 'tw-measure'; pane.measure.textContent = 'MMMMMMMMMM';
    pane.element.append(header, pane.emulator, pane.measure); tab.element.append(pane.element); tab.panes.push(pane);
    pane.terminal = new Terminal({ cursorBlink: true, convertEol: false, scrollback: settings.scrollback, fontSize: settings.font_size,
      fontFamily: `${settings.font_family}, monospace`, theme: currentTheme(), allowProposedApi: false });
    pane.terminal.open(pane.emulator);
    pane.terminal.onData(value => sendInput(pane, value));
    pane.element.addEventListener('pointerdown', () => { activePane = pane; tabs.forEach(item => item.panes.forEach(other => other.element.classList.toggle('is-active', other === pane))); });
    pane.element.addEventListener('focusin', () => { activePane = pane; });
    pane.element.addEventListener('paste', event => {
      const value = event.clipboardData?.getData('text/plain') || '';
      if (pasteNeedsConfirmation(value, settings.paste_threshold) || value.length > MAX_PASTE) {
        event.preventDefault(); event.stopImmediatePropagation(); paste(pane, value);
      }
    }, true);
    pane.observer = new ResizeObserver(() => resizePane(pane)); pane.observer.observe(pane.emulator);
    resizePane(pane); connect(pane); focusPane(pane); return pane;
  }
  async function connect(pane) {
    if (pane.closed || disposed || ['authorizing', 'waiting', 'connected'].includes(pane.state) && pane.abort) return;
    const generation = ++pane.generation;
    pane.abort?.abort(); pane.socket?.close(); pane.abort = new AbortController();
    setState(pane, words.authorize, 'authorizing');
    try {
      const response = await fetch('/api/v1/connections', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: requestHeaders(), body: JSON.stringify({ host_id: pane.resource.id, protocol: 'webssh' }), signal: pane.abort.signal });
      if (!response.ok) throw new Error(words.denied);
      const grant = await response.json();
      if (pane.closed || generation !== pane.generation || disposed) return;
      const endpoint = websocketEndpoint(grant.websocket_url, window.location.href);
      const socket = new WebSocket(endpoint); pane.socket = socket; socket.binaryType = 'arraybuffer';
      setState(pane, words.waiting);
      socket.addEventListener('open', () => {
        if (pane.closed || generation !== pane.generation) { socket.close(); return; }
        socket.send(JSON.stringify({ ticket: grant.ticket, cols: pane.terminal.cols, rows: pane.terminal.rows }));
        delete grant.ticket;
      });
      socket.addEventListener('message', event => {
        if (pane.closed || generation !== pane.generation) return;
        if (event.data instanceof ArrayBuffer) {
          pane.terminal.write(new Uint8Array(event.data), () => {
            pane.outputVersion = (pane.outputVersion || 0) + 1;
            if (activePane === pane && !searchPanel.hidden && searchInput.value) find(0);
          });
          return;
        }
        let value; try { value = JSON.parse(event.data); } catch { return; }
        if (value.type === 'status') {
          setState(pane, value.state === 'connected' ? words.connected : words.waiting, value.state === 'connected' ? 'connected' : 'waiting');
          if (value.state === 'connected') { resizePane(pane); if (activePane === pane) pane.terminal.focus(); }
        } else if (value.type === 'error') { setState(pane, words.denied, 'error'); }
        else if (value.type === 'exit') setState(pane, `${words.ended} (${Number.isInteger(value.code) ? value.code : '?'})`, 'closed');
      });
      socket.addEventListener('error', () => { if (!pane.closed && generation === pane.generation) setState(pane, words.error, 'error'); });
      socket.addEventListener('close', () => { if (!pane.closed && generation === pane.generation && pane.state !== 'error') setState(pane, words.closed, 'closed'); });
    } catch (error) {
      console.warn('Web SSH connection setup failed:', error.name);
      if (!pane.closed && error.name !== 'AbortError' && generation === pane.generation) setState(pane, words.denied, 'error');
    }
  }
  function normalizedResource(row) {
    const id = row.id || row.host_id || row.server_id;
    const metadata = row.metadata || {};
    return /^\d+$/.test(String(id)) ? { id: String(id), name: String(row.name || row.server_name || metadata.name || id),
      project: String(row.project || row.project_name || metadata.project || ''), protocol: row.protocol || 'ssh' } : null;
  }
  function filterResources() {
    const query = resourceSearch.value.toLocaleLowerCase().trim();
    const list = document.getElementById('tw-resource-list'); list.replaceChildren();
    const matching = resourceCache.filter(row => `${row.name} ${row.project} ${row.id}`.toLocaleLowerCase().includes(query)).slice(0, 100);
    matching.forEach(resource => {
      const choice = button('', () => { resourceDialog.close(); pickerAction?.(resource); }, 'tw-resource-choice');
      const name = document.createElement('strong'); name.textContent = resource.name;
      const detail = document.createElement('span'); detail.textContent = `${resource.project || 'SSH'} · #${resource.id}`;
      choice.append(name, detail); choice.setAttribute('role', 'listitem'); list.append(choice);
    });
    text(document.getElementById('tw-resource-state'), matching.length ? '' : words.noResources);
  }
  async function chooseResource(action) {
    pickerAction = action; resourceSearch.value = ''; text(document.getElementById('tw-resource-state'), words.resources);
    document.getElementById('tw-resource-list').replaceChildren(); resourceDialog.showModal(); resourceSearch.focus();
    try {
      const response = await fetch('/api/v1/workspace/resources', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error();
      const data = await response.json();
      resourceCache = (data.resources || []).map(normalizedResource).filter(row => row && ['ssh', 'webssh'].includes(row.protocol));
      filterResources();
    } catch { text(document.getElementById('tw-resource-state'), words.resourcesFailed); }
  }
  resourceSearch.addEventListener('input', filterResources);
  resourceSearch.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown') { event.preventDefault(); document.querySelector('.tw-resource-choice')?.focus(); }
  });
  resourceDialog.addEventListener('keydown', event => {
    if (!['ArrowDown', 'ArrowUp'].includes(event.key) || event.target === resourceSearch) return;
    const choices = Array.from(resourceDialog.querySelectorAll('.tw-resource-choice'));
    if (!choices.length) return;
    event.preventDefault(); const index = choices.indexOf(document.activeElement);
    choices[(index + (event.key === 'ArrowDown' ? 1 : -1) + choices.length) % choices.length].focus();
  });
  function newTab() { if (tabs.length >= MAX_TABS) announce(words.tabLimit); else chooseResource(createTab); }
  function split(direction) {
    if (!activeTab) { newTab(); return; }
    if (activeTab.panes.length >= MAX_PANES) { announce(words.paneLimit); return; }
    const tab = activeTab;
    chooseResource(resource => { if (!tabs.includes(tab)) return; tab.element.dataset.split = direction; createPane(tab, resource); activateTab(tab); });
  }
  function showSearch() { searchPanel.hidden = false; searchInput.focus(); searchInput.select(); }
  let searchTerm = '', searchMatches = [], searchIndex = -1, searchPane = null, searchVersion = -1;
  function find(direction = 1) {
    if (!activePane) return;
    const term = searchInput.value;
    if (term !== searchTerm || activePane !== searchPane || searchVersion !== (activePane.outputVersion || 0)) {
      const previous = term === searchTerm && activePane === searchPane ? searchIndex : -1;
      searchTerm = term; searchPane = activePane; searchVersion = activePane.outputVersion || 0;
      searchMatches = findTerminalMatches(activePane.terminal.buffer.active, term);
      searchIndex = direction === 0 ? Math.min(previous, searchMatches.length - 1) : -1;
    }
    if (!searchMatches.length) { text(document.getElementById('tw-search-count'), words.none); return; }
    searchIndex = direction === 0 ? Math.max(0, searchIndex) : (searchIndex + direction + searchMatches.length) % searchMatches.length;
    const match = searchMatches[searchIndex]; activePane.terminal.select(match.column, match.row, match.length); activePane.terminal.scrollToLine(match.row);
    text(document.getElementById('tw-search-count'), `${searchIndex + 1}/${searchMatches.length}`);
  }
  searchInput.addEventListener('input', () => { searchTerm = ''; find(1); });
  searchInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); find(event.shiftKey ? -1 : 1); } });
  function showSettings() {
    for (const [name, value] of Object.entries(settings)) { const field = document.querySelector(`#tw-settings-form [name="${name}"]`); if (field) field.value = String(value); }
    settingsDialog.showModal();
  }
  document.getElementById('tw-settings-form').addEventListener('submit', async event => {
    event.preventDefault(); const form = new FormData(event.target);
    settings = terminalPreferences({ ...settings, ...Object.fromEntries(form.entries()) });
    tabs.forEach(tab => tab.panes.forEach(pane => {
      pane.terminal.options.fontSize = settings.font_size; pane.terminal.options.fontFamily = `${settings.font_family}, monospace`;
      pane.terminal.options.theme = currentTheme(); pane.terminal.options.scrollback = settings.scrollback; resizePane(pane);
    }));
    settingsDialog.close();
    try {
      const response = await fetch('/api/v1/workspace/preferences', { method: 'PATCH', credentials: 'same-origin', headers: requestHeaders(), body: JSON.stringify({ terminal: settings }) });
      announce(response.ok ? words.settingsSaved : words.settingsLocal);
    } catch { announce(words.settingsLocal); }
  });
  root.querySelectorAll('[data-close-dialog]').forEach(node => node.addEventListener('click', () => node.closest('dialog').close()));
  root.addEventListener('click', event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    ({ 'new-tab': newTab, 'split-columns': () => split('columns'), 'split-rows': () => split('rows'), search: showSearch,
      'hide-search': () => { searchPanel.hidden = true; activePane?.terminal.focus(); }, 'find-next': () => find(1), 'find-previous': () => find(-1),
      settings: showSettings, shortcuts: () => document.getElementById('tw-shortcuts-dialog').showModal() })[action]?.();
  });
  document.addEventListener('keydown', event => {
    if (event.defaultPrevented || event.isComposing) return;
    if (root.querySelector('dialog[open]')) return;
    if ((event.ctrlKey || event.metaKey) && event.shiftKey) {
      const action = { t: newTab, d: () => split('columns'), f: showSearch }[event.key.toLowerCase()];
      if (action) { event.preventDefault(); action(); }
    } else if (event.altKey && /^[1-8]$/.test(event.key)) {
      const tab = tabs[Number(event.key) - 1]; if (tab) { event.preventDefault(); activateTab(tab); }
    } else if (event.key === 'Escape' && !searchPanel.hidden) { searchPanel.hidden = true; activePane?.terminal.focus(); }
  }, true);
  window.addEventListener('pagehide', () => { disposed = true; tabs.forEach(tab => tab.panes.forEach(disposePane)); });
  window.addEventListener('beforeunload', event => { if (tabs.some(tab => tab.panes.some(pane => pane.state === 'connected'))) { event.preventDefault(); event.returnValue = ''; } });
  async function initialize() {
    try {
      const response = await fetch('/api/v1/workspace/preferences', { credentials: 'same-origin', cache: 'no-store' });
      if (response.ok) { const data = await response.json(); settings = terminalPreferences(data.terminal || data.preferences?.terminal); }
    } catch { /* Server preferences are optional; no terminal data is cached. */ }
    if (!disposed && config.initialResource) createTab(config.initialResource);
  }
  initialize();
}
