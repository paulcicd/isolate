/* Run with node tests/js/terminal-workspace.test.mjs (no external packages). */
import assert from 'node:assert/strict';
import { terminalPreferences, pasteNeedsConfirmation, inputChunks, websocketEndpoint,
  findTerminalMatches, timeLabel, chunkIndexAt } from '../../shared/static/terminal-workspace-utils.mjs';

const preferences = terminalPreferences({ font_size: 100, font_family: 'url(javascript:x)', theme: 'untrusted', scrollback: -1, paste_threshold: 1 });
assert.equal(preferences.font_size, 24);
assert.equal(preferences.font_family, 'ui-monospace');
assert.equal(preferences.theme, 'dark');
assert.equal(preferences.scrollback, 1000);
assert.equal(preferences.paste_threshold, 100);
assert.equal(pasteNeedsConfirmation('whoami', 500), false);
assert.equal(pasteNeedsConfirmation('whoami\nid', 500), true);
assert.equal(pasteNeedsConfirmation('x'.repeat(501), 500), true);
assert.equal(pasteNeedsConfirmation('whoami\r', 500), true);
const input = 'x'.repeat(3999) + '😀' + 'next';
const frames = [...inputChunks(input)];
assert.equal(frames.join(''), input);
assert.ok(frames.every(frame => Buffer.from(frame, 'utf8').toString('utf8') === frame));
assert.ok(frames.every(frame => frame.length <= 4000));
assert.equal(websocketEndpoint('https://gateway.example/ssh', 'https://isolate.example/me').href, 'wss://gateway.example/ssh');
for (const endpoint of ['ws://gateway.example/ssh', 'wss://user:secret@gateway.example/ssh', 'wss://gateway.example/ssh?ticket=secret',
  'wss://gateway.example/ssh#token', 'javascript:alert(1)']) {
  assert.throws(() => websocketEndpoint(endpoint, 'https://isolate.example/me'));
}
const lines = ['connected to payments', 'hello HELLO', 'русский текст'];
const buffer = { length: lines.length, getLine: row => ({ translateToString: () => lines[row] }) };
assert.deepEqual(findTerminalMatches(buffer, 'hello'), [{ row: 1, column: 0, length: 5 }, { row: 1, column: 6, length: 5 }]);
assert.equal(findTerminalMatches(buffer, '').length, 0);
assert.equal(findTerminalMatches(buffer, 'hello', 1).length, 1);
assert.equal(findTerminalMatches(buffer, 'РУССКИЙ')[0].row, 2);
const wideCells = [['中', 2], ['', 0], ['a', 1], ['😀', 2], ['', 0]];
const wide = { length: 1, getLine: () => ({ length: wideCells.length, translateToString: () => '中a😀',
  getCell: column => ({ getChars: () => wideCells[column][0], getWidth: () => wideCells[column][1] }) }) };
assert.deepEqual(findTerminalMatches(wide, 'a😀'), [{ row: 0, column: 2, length: 3 }]);
assert.equal(timeLabel(3661.2), '61:01');
assert.equal(timeLabel(-1), '0:00');
const chunks = [{ t: 0 }, { t: 1.5 }, { t: 1.5 }, { t: 10 }];
assert.equal(chunkIndexAt(chunks, -1), 0);
assert.equal(chunkIndexAt(chunks, 1.5), 3);
assert.equal(chunkIndexAt(chunks, 100), 4);
assert.equal(chunkIndexAt([], 0), 0);
console.log('Terminal workspace JavaScript invariants passed');
