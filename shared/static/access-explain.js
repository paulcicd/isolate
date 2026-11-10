/* Lazy, text-only access diagnostics. A snapshot never replaces authorization. */
(() => {
  if (window.isolateAccessExplanationInstalled) return;
  window.isolateAccessExplanationInstalled = true;
  document.addEventListener('toggle', async event => {
    const panel = event.target;
    if (!(panel instanceof HTMLDetailsElement) || !panel.matches('[data-access-explanation]') || !panel.open || panel.dataset.loading === 'true') return;
    const target = panel.querySelector('[data-explanation-result]');
    if (!target) return;
    const russian = panel.dataset.language === 'ru';
    const endpoint = panel.dataset.accessExplanation;
    if (!endpoint || !endpoint.startsWith('/api/v1/access/explain/')) return;
    panel.dataset.loading = 'true';
    target.textContent = russian ? 'Проверка доступа…' : 'Checking current access…';
    try {
      const response = await fetch(endpoint, {credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'application/json'}});
      if (!response.ok) throw new Error('explanation unavailable');
      const value = await response.json();
      target.replaceChildren();
      const summary = document.createElement('p'); summary.textContent = value.summary; target.append(summary);
      const selected = value.policy && value.policy.selected_grant;
      if (selected) {
        const rule = document.createElement('p');
        rule.textContent = (russian ? 'Правило: ' : 'Selected rule: ') + (selected.id || 'policy');
        target.append(rule);
      }
      const list = document.createElement('ul');
      for (const check of value.checks || []) {
        const item = document.createElement('li'); item.textContent = check.status + ': ' + check.message; list.append(item);
      }
      target.append(list);
      const precedence = document.createElement('p'); precedence.textContent = value.policy.precedence_note; target.append(precedence);
      if (value.next_action && typeof value.next_action.url === 'string' && value.next_action.url.startsWith('/') && !value.next_action.url.startsWith('//')) {
        const link = document.createElement('a'); link.href = value.next_action.url; link.textContent = value.next_action.label; target.append(link);
      }
      const notice = document.createElement('p'); notice.textContent = value.notice; target.append(notice);
    } catch (_) {
      target.textContent = russian ? 'Объяснение недоступно. Обновите вход или обратитесь к администратору.' : 'Explanation unavailable. Sign in again or ask an administrator.';
    } finally { panel.dataset.loading = 'false'; }
  }, true);
})();
