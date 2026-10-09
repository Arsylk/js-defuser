/**
 * unified logger
 *
 * one vocabulary for every message the project emits — the engine's pass log,
 * the cli, the api routes and the browser ui — rendered three ways from the
 * same structured entries:
 *
 *   plain  — what `result.log` holds and what tests assert on
 *   ansi   — 24-bit catppuccin mocha for terminals
 *   spans  — `{ text, tone }` segments for react / `console.log('%c…')`
 *
 * style: lowercase, no boxes, no glyph soup. ids and details dim, counts lit.
 *
 *   deobfuscate  42 passes · 130258 bytes
 *   stage a · pre-parse
 *     parse ok
 *   sweep 1/12
 *     b00   str-escape                 165
 *     b05c  closed-function-eval      2400 calls folded  (2 closed fns, 1 slices evaluated)
 *     b05a  closure-str                  0  (1 factory, no decoders)
 *     b00c  param-locals             skipped · eval/with
 *     → 10933 changes
 *   done  97821 bytes · −24.9%
 */

// ── palette ──────────────────────────────────────────────────────────────────

/** catppuccin mocha, verbatim. */
export const mocha = {
  rosewater: '#f5e0dc',
  flamingo: '#f2cdcd',
  pink: '#f5c2e7',
  mauve: '#cba6f7',
  red: '#f38ba8',
  maroon: '#eba0ac',
  peach: '#fab387',
  yellow: '#f9e2af',
  green: '#a6e3a1',
  teal: '#94e2d5',
  sky: '#89dceb',
  sapphire: '#74c7ec',
  blue: '#89b4fa',
  lavender: '#b4befe',
  text: '#cdd6f4',
  subtext1: '#bac2de',
  subtext0: '#a6adc8',
  overlay2: '#9399b2',
  overlay1: '#7f849c',
  overlay0: '#6c7086',
  surface2: '#585b70',
  surface1: '#45475a',
  surface0: '#313244',
  base: '#1e1e2e',
  mantle: '#181825',
  crust: '#11111b',
} as const;

export type Tone = keyof typeof mocha;

/** what each part of a line means — the palette is applied through this map. */
export const tones = {
  title: 'lavender',
  meta: 'overlay1',
  stage: 'mauve',
  sweep: 'blue',
  id: 'overlay1',
  name: 'text',
  count: 'green',
  zero: 'overlay0',
  unit: 'subtext0',
  detail: 'overlay1',
  skipped: 'yellow',
  failed: 'red',
  note: 'subtext0',
  ok: 'green',
  warn: 'yellow',
  error: 'red',
  sum: 'peach',
  done: 'green',
  scope: 'sapphire',
  raw: 'subtext0',
} as const satisfies Record<string, Tone>;

export type Role = keyof typeof tones;

// ── entries ──────────────────────────────────────────────────────────────────

interface Base {
  /** nesting: one level per recursive run. */
  depth: number;
  /** name of the nested run a line belongs to, e.g. `inner`. */
  scope?: string;
}

/** `Omit` that keeps a union a union. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type Entry = Base &
  (
    | { kind: 'title'; text: string; meta?: string }
    | { kind: 'stage'; text: string }
    | { kind: 'sweep'; index: number; total: number }
    | {
        kind: 'pass';
        id?: string;
        name: string;
        count: number | null;
        unit?: string;
        detail?: string;
        status?: 'skipped' | 'failed';
      }
    | { kind: 'note' | 'ok' | 'warn' | 'error'; text: string; detail?: string }
    | { kind: 'sum'; count: number; text: string }
    | { kind: 'done'; text: string; meta?: string }
    | { kind: 'blank' }
    | { kind: 'raw'; text: string }
  );

export interface Segment {
  text: string;
  role?: Role;
  dim?: boolean;
  bold?: boolean;
}

const ID_WIDTH = 4;
const NAME_WIDTH = 24;
const COUNT_WIDTH = 5;

/** `closedFunctionEval` → `closed-function-eval`; already-kebab names pass through. */
export function kebab(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1-$2')
    .toLowerCase();
}

/** the parts of one entry, in order; join the texts for the plain line. */
export function segments(entry: Entry): Segment[] {
  const out: Segment[] = [];
  const indent = '  '.repeat(entry.depth);
  if (indent) out.push({ text: indent });
  if (entry.scope) out.push({ text: `${entry.scope} · `, role: 'scope' });
  switch (entry.kind) {
    case 'title':
      out.push({ text: entry.text, role: 'title', bold: true });
      if (entry.meta) out.push({ text: `  ${entry.meta}`, role: 'meta' });
      break;
    case 'stage':
      out.push({ text: `stage ${entry.text}`, role: 'stage' });
      break;
    case 'sweep':
      out.push({ text: `sweep ${entry.index}/${entry.total}`, role: 'sweep' });
      break;
    case 'pass': {
      out.push({ text: '  ' });
      const id = entry.id ?? '';
      out.push({ text: id.padEnd(ID_WIDTH), role: 'id' });
      out.push({ text: '  ' });
      out.push({ text: entry.name.padEnd(NAME_WIDTH), role: 'name' });
      if (entry.status) {
        out.push({ text: `${entry.status}`, role: entry.status });
        if (entry.detail) out.push({ text: ` · ${entry.detail}`, role: 'detail' });
      } else {
        const n = entry.count ?? 0;
        out.push({ text: String(n).padStart(COUNT_WIDTH), role: n > 0 ? 'count' : 'zero' });
        if (entry.unit) out.push({ text: ` ${entry.unit}`, role: 'unit' });
        if (entry.detail) out.push({ text: `  (${entry.detail})`, role: 'detail' });
      }
      break;
    }
    case 'note':
      out.push({ text: `  ${entry.text}`, role: 'note' });
      if (entry.detail) out.push({ text: ` · ${entry.detail}`, role: 'detail' });
      break;
    case 'ok':
    case 'warn':
    case 'error':
      out.push({ text: `  ${entry.kind}  `, role: entry.kind, bold: true });
      out.push({ text: entry.text, role: 'note' });
      if (entry.detail) out.push({ text: ` · ${entry.detail}`, role: 'detail' });
      break;
    case 'sum':
      out.push({ text: `  → ${entry.count} ${entry.text}`, role: 'sum' });
      break;
    case 'done':
      out.push({ text: `done  ${entry.text}`, role: 'done', bold: true });
      if (entry.meta) out.push({ text: ` · ${entry.meta}`, role: 'meta' });
      break;
    case 'blank':
      break;
    case 'raw':
      out.push({ text: entry.text, role: 'raw' });
      break;
  }
  return out;
}

// ── renderers ────────────────────────────────────────────────────────────────

export function plain(entry: Entry): string {
  return segments(entry)
    .map((s) => s.text)
    .join('')
    .replace(/\s+$/, '');
}

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function sgr(segment: Segment): [string, string] {
  const open: string[] = [];
  const close: string[] = [];
  if (segment.role) {
    const [r, g, b] = hexToRgb(mocha[tones[segment.role]]);
    open.push(`\x1b[38;2;${r};${g};${b}m`);
    close.unshift('\x1b[39m');
  }
  if (segment.bold) {
    open.push('\x1b[1m');
    close.unshift('\x1b[22m');
  }
  if (segment.dim) {
    open.push('\x1b[2m');
    close.unshift('\x1b[22m');
  }
  return [open.join(''), close.join('')];
}

/** one line with 24-bit colour escapes; trailing padding is kept unstyled. */
export function ansi(entry: Entry): string {
  return segments(entry)
    .map((s) => {
      const trimmed = s.text.replace(/\s+$/, '');
      const pad = s.text.slice(trimmed.length);
      if (!trimmed) return s.text;
      const [open, close] = sgr(s);
      return `${open}${trimmed}${close}${pad}`;
    })
    .join('')
    .replace(/\s+$/, '');
}

/** css for `console.log('%c…')`, one style per segment. */
export function css(segment: Segment): string {
  const parts: string[] = [];
  if (segment.role) parts.push(`color:${mocha[tones[segment.role]]}`);
  if (segment.bold) parts.push('font-weight:600');
  if (segment.dim) parts.push('opacity:.7');
  return parts.join(';');
}

/** honours NO_COLOR / FORCE_COLOR, then asks the stream. */
export function supportsColor(stream?: { isTTY?: boolean }): boolean {
  const env = typeof process !== 'undefined' ? process.env : undefined;
  if (!env) return false;
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return false;
  if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '0') return true;
  if (env.TERM === 'dumb') return false;
  return !!stream?.isTTY;
}

// ── parsing plain lines back (for logs that travelled as strings) ────────────

const RE_SCOPE = /^((?:  )*)([a-z][a-z0-9-]*) · (.*)$/s;
const RE_STAGE = /^stage (.+)$/;
const RE_SWEEP = /^sweep (\d+)\/(\d+)$/;
const RE_PASS_STATUS = /^ {2}(?:([a-z]\d{2}[a-z]?))? +([a-z0-9-]+) +(skipped|failed)(?: · (.*))?$/;
const RE_PASS =
  /^ {2}(?:([a-z]\d{2}[a-z]?))? +([a-z0-9-]+) +(\d+)(?: ([^ ].*?))?(?: {2}\((.*)\))?$/;
const RE_LEVEL = /^ {2}(ok|warn|error) {2}(.*?)(?: · (.*))?$/;
const RE_SUM = /^ {2}→ (\d+) (.*)$/;
const RE_DONE = /^done {2}(.*?)(?: · (.*))?$/;
const RE_TITLE = /^(\S.*?) {2}(.*)$/;

type Body = DistributiveOmit<Entry, 'depth' | 'scope'>;

function parseBody(body: string, top: boolean): Body | null {
  let m: RegExpExecArray | null;
  if (body === '') return { kind: 'blank' };
  if ((m = RE_STAGE.exec(body))) return { kind: 'stage', text: m[1] };
  if ((m = RE_SWEEP.exec(body))) return { kind: 'sweep', index: Number(m[1]), total: Number(m[2]) };
  if ((m = RE_PASS_STATUS.exec(body)))
    return {
      kind: 'pass',
      ...(m[1] ? { id: m[1] } : {}),
      name: m[2],
      count: null,
      status: m[3] as 'skipped' | 'failed',
      ...(m[4] ? { detail: m[4] } : {}),
    };
  if ((m = RE_PASS.exec(body)))
    return {
      kind: 'pass',
      ...(m[1] ? { id: m[1] } : {}),
      name: m[2],
      count: Number(m[3]),
      ...(m[4] ? { unit: m[4] } : {}),
      ...(m[5] ? { detail: m[5] } : {}),
    };
  if ((m = RE_LEVEL.exec(body)))
    return { kind: m[1] as 'ok' | 'warn' | 'error', text: m[2], ...(m[3] ? { detail: m[3] } : {}) };
  if ((m = RE_SUM.exec(body))) return { kind: 'sum', count: Number(m[1]), text: m[2] };
  if ((m = RE_DONE.exec(body)))
    return { kind: 'done', text: m[1], ...(m[2] ? { meta: m[2] } : {}) };
  if (top && (m = RE_TITLE.exec(body))) return { kind: 'title', text: m[1], meta: m[2] };
  return null;
}

function parseLoose(body: string, top: boolean): Body {
  const known = parseBody(body, top);
  if (known) return known;
  const note = /^ {2}(.*?)(?: · (.*))?$/.exec(body);
  if (note) return { kind: 'note', text: note[1], ...(note[2] ? { detail: note[2] } : {}) };
  return { kind: 'raw', text: body };
}

/** a plain line back into its entry; anything unrecognised becomes `raw`. */
export function parse(line: string): Entry {
  const scoped = RE_SCOPE.exec(line);
  if (scoped)
    return {
      depth: scoped[1].length / 2,
      scope: scoped[2],
      ...parseLoose(scoped[3], false),
    } as Entry;
  // nested lines always carry a scope marker, so an unmarked line is top level.
  return { depth: 0, ...parseLoose(line, !line.startsWith(' ')) } as Entry;
}

// ── collecting logger (engine) ───────────────────────────────────────────────

export interface Logger {
  /** structured entries, in order. */
  readonly entries: Entry[];
  /** the same entries as plain lines. */
  readonly lines: string[];
  add(entry: Entry): void;
  title(text: string, meta?: string): void;
  stage(text: string): void;
  sweep(index: number, total: number): void;
  /** `pass('b05c', 'closedFunctionEval', 6, 'calls folded', '2 closed fns')` */
  pass(id: string | null, name: string, count: number, unit?: string, detail?: string): void;
  skip(id: string | null, name: string, reason: string): void;
  fail(id: string | null, name: string, reason: string): void;
  note(text: string, detail?: string): void;
  ok(text: string, detail?: string): void;
  warn(text: string, detail?: string): void;
  error(text: string, detail?: string): void;
  sum(count: number, text: string): void;
  done(text: string, meta?: string): void;
  blank(): void;
  raw(text: string): void;
  /** a logger whose entries land here, one level deeper, tagged with `scope`. */
  child(scope: string): Logger;
}

export interface LoggerOptions {
  /** called for every entry the moment it is added, with its plain line. */
  onEntry?: (entry: Entry, line: string) => void;
  depth?: number;
  scope?: string;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const entries: Entry[] = [];
  const lines: string[] = [];
  const depth = options.depth ?? 0;
  const scope = options.scope;
  // entries arrive relative to the caller (a nested run starts at depth 0);
  // this logger's own depth and scope are applied on the way in.
  const add = (entry: Entry) => {
    const e: Entry = {
      ...entry,
      depth: entry.depth + depth,
      ...(scope && !entry.scope ? { scope } : {}),
    };
    entries.push(e);
    const line = plain(e);
    lines.push(line);
    options.onEntry?.(e, line);
  };
  const mk = (e: Body) => add({ depth: 0, ...e } as Entry);
  const pass = (
    id: string | null,
    name: string,
    count: number | null,
    unit?: string,
    detail?: string,
    status?: 'skipped' | 'failed'
  ) =>
    mk({
      kind: 'pass',
      ...(id ? { id: id.toLowerCase() } : {}),
      name: kebab(name),
      count,
      ...(unit ? { unit } : {}),
      ...(detail ? { detail } : {}),
      ...(status ? { status } : {}),
    });
  const self: Logger = {
    entries,
    lines,
    add,
    title: (text, meta) => mk({ kind: 'title', text, ...(meta ? { meta } : {}) }),
    stage: (text) => mk({ kind: 'stage', text }),
    sweep: (index, total) => mk({ kind: 'sweep', index, total }),
    pass: (id, name, count, unit, detail) => pass(id, name, count, unit, detail),
    skip: (id, name, reason) => pass(id, name, null, undefined, reason, 'skipped'),
    fail: (id, name, reason) => pass(id, name, null, undefined, reason, 'failed'),
    note: (text, detail) => mk({ kind: 'note', text, ...(detail ? { detail } : {}) }),
    ok: (text, detail) => mk({ kind: 'ok', text, ...(detail ? { detail } : {}) }),
    warn: (text, detail) => mk({ kind: 'warn', text, ...(detail ? { detail } : {}) }),
    error: (text, detail) => mk({ kind: 'error', text, ...(detail ? { detail } : {}) }),
    sum: (count, text) => mk({ kind: 'sum', count, text }),
    done: (text, meta) => mk({ kind: 'done', text, ...(meta ? { meta } : {}) }),
    blank: () => mk({ kind: 'blank' }),
    raw: (text) => mk({ kind: 'raw', text }),
    child: (childScope) =>
      createLogger({
        depth: depth + 1,
        scope: childScope,
        onEntry: (entry) => add(entry),
      }),
  };
  return self;
}

// ── console logger (cli, api routes, browser) ────────────────────────────────

export interface ConsoleLogger {
  debug(text: string, ...extra: unknown[]): void;
  info(text: string, ...extra: unknown[]): void;
  ok(text: string, ...extra: unknown[]): void;
  warn(text: string, ...extra: unknown[]): void;
  error(text: string, ...extra: unknown[]): void;
}

function describe(value: unknown): string {
  if (value instanceof Error) return value.stack ?? `${value.name}: ${value.message}`;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * a logger that writes straight out: stderr with ansi in node (colour decided
 * by `supportsColor`), `console` with css in the browser so devtools still
 * show the attached objects. `scope` prefixes every line.
 */
export function createConsoleLogger(
  scope?: string,
  options: { color?: boolean } = {}
): ConsoleLogger {
  const isNode = typeof process !== 'undefined' && !!process.stderr?.write;
  const color = options.color ?? (isNode ? supportsColor(process.stderr) : true);
  const entryOf = (kind: 'note' | 'ok' | 'warn' | 'error', text: string): Entry => ({
    kind,
    text,
    depth: 0,
    ...(scope ? { scope } : {}),
  });
  const emit = (kind: 'note' | 'ok' | 'warn' | 'error', text: string, extra: unknown[]) => {
    const entry = entryOf(kind, text);
    if (isNode) {
      const line = color ? ansi(entry) : plain(entry);
      const tail = extra.map((x) => `\n    ${describe(x).replace(/\n/g, '\n    ')}`).join('');
      process.stderr.write(`${line}${tail}\n`);
      return;
    }
    const segs = segments(entry);
    const method = kind === 'error' ? console.error : kind === 'warn' ? console.warn : console.log;
    if (color) method(segs.map((s) => `%c${s.text}`).join(''), ...segs.map(css), ...extra);
    else method(plain(entry), ...extra);
  };
  return {
    debug: (text, ...extra) => emit('note', text, extra),
    info: (text, ...extra) => emit('note', text, extra),
    ok: (text, ...extra) => emit('ok', text, extra),
    warn: (text, ...extra) => emit('warn', text, extra),
    error: (text, ...extra) => emit('error', text, extra),
  };
}
