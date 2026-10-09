import { describe, expect, it } from 'vitest';
import { ansi, createLogger, kebab, mocha, parse, plain, supportsColor, type Entry } from '../src/logger.js';

describe('unified logger', () => {
  it('renders the lowercase column format', () => {
    const log = createLogger();
    log.title('deobfuscate', '2 passes · 10 bytes');
    log.stage('a · pre-parse');
    log.ok('parsed');
    log.sweep(1, 3);
    log.pass('B05c', 'closed-function-eval', 6, 'calls folded', '2 closed fns');
    log.pass('B01', 'literals', 0);
    log.pass(null, 'junkToken', 0, undefined, 'none detected');
    log.skip('B00c', 'param-locals', 'eval/with');
    log.fail(null, 'vm-eval-hook', 'sandbox exec failed: boom');
    log.warn('parse warnings', '1 browser-tolerant');
    log.note('duplicate declaration of x', '3:1');
    log.sum(6, 'changes');
    log.blank();
    log.done('8 bytes', '20.0% smaller');
    expect(log.lines).toEqual([
      'deobfuscate  2 passes · 10 bytes',
      'stage a · pre-parse',
      '  ok  parsed',
      'sweep 1/3',
      '  b05c  closed-function-eval        6 calls folded  (2 closed fns)',
      '  b01   literals                    0',
      '        junk-token                  0  (none detected)',
      '  b00c  param-locals            skipped · eval/with',
      '        vm-eval-hook            failed · sandbox exec failed: boom',
      '  warn  parse warnings · 1 browser-tolerant',
      '  duplicate declaration of x · 3:1',
      '  → 6 changes',
      '',
      'done  8 bytes · 20.0% smaller',
    ]);
    expect(log.lines.every((l) => l === l.toLowerCase())).toBe(true);
  });

  it('round-trips every entry through its plain line', () => {
    const log = createLogger();
    log.title('deobfuscate', '2 passes');
    log.stage('c · vm eval hook');
    log.sweep(2, 12);
    log.pass('B13c', 'switch-dispatcher', 3);
    log.pass(null, 'base64', 2, 'atob() calls decoded');
    log.pass('B05a', 'closureStr', 0, undefined, '1 factory, no decoders');
    log.skip('B17c', 'dead-stores', 'eval/with');
    log.fail('B05a', 'closureStr', 'vm failed: timeout');
    log.ok('parsed', '2 warning(s)');
    log.warn('continuing with partial ast', 'output may be incomplete');
    log.error('parse errors', '2');
    log.note('ast stable');
    log.sum(0, 'changes');
    log.blank();
    log.done('97821 bytes', '24.9% smaller');
    const inner = log.child('inner');
    inner.sweep(1, 12);
    inner.pass('B04', 'constant-folding', 12);
    inner.add({ kind: 'note', text: 'from a nested run', depth: 0 });
    for (const [i, entry] of log.entries.entries()) {
      const line = log.lines[i];
      expect(plain(entry)).toBe(line);
      expect(parse(line)).toEqual(entry);
    }
    const nested = log.entries.slice(-3);
    expect(nested.map((e) => [e.depth, e.scope])).toEqual([
      [1, 'inner'],
      [1, 'inner'],
      [1, 'inner'],
    ]);
  });

  it('streams entries as they are added', () => {
    const seen: string[] = [];
    const log = createLogger({ onEntry: (_entry, line) => seen.push(line) });
    log.pass('B00', 'strEscape', 165);
    expect(seen).toEqual(['  b00   str-escape                165']);
  });

  it('paints with catppuccin mocha and keeps padding unstyled', () => {
    const entry: Entry = { kind: 'pass', id: 'b00', name: 'str-escape', count: 165, depth: 0 };
    const coloured = ansi(entry);
    const rgb = (hex: string) =>
      hex
        .slice(1)
        .match(/../g)!
        .map((h) => parseInt(h, 16))
        .join(';');
    expect(coloured).toContain(`\x1b[38;2;${rgb(mocha.green)}m  165\x1b[39m`);
    expect(coloured).toContain(`\x1b[38;2;${rgb(mocha.overlay1)}mb00\x1b[39m   `);
    expect(coloured.replace(/\x1b\[[0-9;]*m/g, '')).toBe(plain(entry));
    const zero = ansi({ ...entry, count: 0 });
    expect(zero).toContain(`\x1b[38;2;${rgb(mocha.overlay0)}m    0\x1b[39m`);
  });

  it('names passes in kebab case', () => {
    expect(kebab('closed-function-eval')).toBe('closed-function-eval');
    expect(kebab('jsNice')).toBe('js-nice');
    expect(kebab('str-escape')).toBe('str-escape');
    expect(kebab('B05c')).toBe('b05c');
  });

  it('honours NO_COLOR and FORCE_COLOR before the stream', () => {
    const env = { ...process.env };
    try {
      process.env.NO_COLOR = '1';
      delete process.env.FORCE_COLOR;
      expect(supportsColor({ isTTY: true })).toBe(false);
      delete process.env.NO_COLOR;
      process.env.FORCE_COLOR = '1';
      expect(supportsColor({ isTTY: false })).toBe(true);
      delete process.env.FORCE_COLOR;
      process.env.TERM = 'xterm-256color';
      expect(supportsColor({ isTTY: true })).toBe(true);
      expect(supportsColor({ isTTY: false })).toBe(false);
    } finally {
      process.env = env;
    }
  });
});
