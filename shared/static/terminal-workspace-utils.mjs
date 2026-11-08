/* Bounded UI helpers shared by the terminal and read-only recording player. */
export const MAX_TABS = 8;
export const MAX_PANES = 4;
export const MAX_PASTE = 262144;
export function terminalPreferences(value = {}) {
  const integer = (key, fallback, low, high) => Number.isInteger(Number(value[key]))
    ? Math.max(low, Math.min(high, Number(value[key]))) : fallback;
  return {
    font_size: integer('font_size', 14, 10, 24),
    font_family: ['ui-monospace', 'monospace', 'Menlo', 'Consolas'].includes(value.font_family) ? value.font_family : 'ui-monospace',
    theme: value.theme === 'light' ? 'light' : 'dark',
    scrollback: integer('scrollback', 5000, 1000, 20000),
    paste_threshold: integer('paste_threshold', 500, 100, 10000),
  };
}
export function pasteNeedsConfirmation(text, threshold = 500) {
  return /[\r\n]/.test(text) || text.length > threshold;
}
export function* inputChunks(value, maximum = 4000) {
  for (let start = 0; start < value.length;) {
    let end = Math.min(value.length, start + maximum);
    // JSON can represent lone surrogates, but the SSH UTF-8 transport cannot.
    const last = value.charCodeAt(end - 1), next = value.charCodeAt(end);
    if (end < value.length && last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) end--;
    yield value.slice(start, end); start = end;
  }
}
export function websocketEndpoint(value, base) {
  const endpoint = new URL(value, base);
  const page = new URL(base);
  if (endpoint.protocol === 'https:') endpoint.protocol = 'wss:';
  if (endpoint.protocol === 'http:') endpoint.protocol = 'ws:';
  if (!['ws:', 'wss:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
      || page.protocol === 'https:' && endpoint.protocol !== 'wss:') throw new Error('Invalid secure WebSocket endpoint');
  return endpoint;
}
export function findTerminalMatches(buffer, query, maximum = 1000) {
  if (!query) return [];
  const needle = query.toLocaleLowerCase();
  const matches = [];
  for (let row = 0; row < buffer.length && matches.length < maximum; row++) {
    const line = buffer.getLine(row);
    const original = line?.translateToString(false) || '';
    const text = original.toLocaleLowerCase();
    const cells = [];
    if (line?.getCell) {
      for (let column = 0; column < line.length; column++) {
        const cell = line.getCell(column), chars = cell?.getChars() || (cell?.getWidth() ? ' ' : '');
        for (let unit = 0; unit < chars.length; unit++) cells.push({ column, width: cell.getWidth() });
      }
    }
    let column = 0;
    while (column <= text.length) {
      const found = text.indexOf(needle, column);
      if (found < 0) break;
      const first = cells[found], last = cells[found + query.length - 1];
      matches.push({ row, column: first ? first.column : found, length: first && last ? last.column + last.width - first.column : query.length });
      if (matches.length >= maximum) break;
      column = found + Math.max(1, needle.length);
    }
  }
  return matches;
}
export function timeLabel(value) {
  const seconds = Math.max(0, Math.floor(Number(value) || 0));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
}
export function chunkIndexAt(chunks, seconds) {
  let low = 0, high = chunks.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (chunks[middle].t <= seconds) low = middle + 1; else high = middle;
  }
  return low;
}
