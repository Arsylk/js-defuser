// ─────────────────────────────────────────────────────────────────────────────
// JSNice integration (Stage D — optional, network)
//
// Thin client for the jsnice.org "beautify" endpoint (and any API-compatible
// self-hosted Nice2Predict/UnuglifyJS instance). JSNice performs statistical
// identifier renaming and type inference — things the local AST passes
// deliberately do not attempt because the information is lost during
// minification and can only be *guessed*.
//
// This is strictly opt-in: it uploads the source to a third party over plain
// HTTP by default. Every failure mode (disabled, oversized input, network
// error, timeout, non-JSON/error response, empty result) resolves to
// `{ applied: false }` with the original code untouched, so the caller can
// always fall back to the local output.
// ─────────────────────────────────────────────────────────────────────────────

export interface JsNiceOptions {
  /** Master switch. When false, applyJsNice() is a no-op. */
  enabled: boolean;
  /** Endpoint base URL. Defaults to the public jsnice.org beautify endpoint. */
  url?: string;
  /** Rename identifiers (rename=1). Default true. */
  rename?: boolean;
  /** Infer and annotate types (types=1). Default true. */
  types?: boolean;
  /** Pretty-print the result (pretty=1). Default true. */
  pretty?: boolean;
  /** Request name suggestions (suggest=1). Default false. */
  suggest?: boolean;
  /**
   * Transpile the input down to ES5 (via @babel/preset-env) before sending.
   * JSNice's parser is ES5-only and rejects any modern syntax (import/export,
   * arrow functions, const/let, classes, template literals, …), so this is
   * required for it to accept modern bundle output. Default true. The rename /
   * type-inference result comes back as ES5 CommonJS, which is a different
   * representation from the ESM input. Set false when the input is already ES5.
   */
  transpile?: boolean;
  /**
   * Skip inputs larger than this many bytes. This is a latency/cost guard, not a
   * hard service limit — jsnice.org handles multi-megabyte input, but time grows
   * roughly linearly (~7ms/KB) and the ES5 transpile can inflate size further.
   * Default 2 MB, which covers per-route app bundles; raise it for the largest
   * vendor bundles. Measured against the input (pre-transpile).
   */
  maxBytes?: number;
  /** Abort the request after this many milliseconds. Default 60_000. */
  timeoutMs?: number;
}

export interface JsNiceResult {
  /** Renamed code on success; the unmodified input otherwise. */
  code: string;
  /** Whether the service result was accepted. */
  applied: boolean;
  /** Human-readable reason when `applied` is false. */
  reason?: string;
  /** Whether the code was transpiled to ES5 before sending. */
  transpiled?: boolean;
}

const DEFAULT_URL = 'http://jsnice.org/beautify';
const DEFAULT_MAX_BYTES = 2_000_000;
const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Lower modern JS to ES5 CommonJS so JSNice's ES5-only parser accepts it.
 * Loaded lazily so @babel/core / @babel/preset-env are only pulled in when the
 * (opt-in) JSNice stage actually runs.
 */
async function transpileToEs5(code: string): Promise<{ code: string; ok: boolean; error?: string }> {
  try {
    const [core, presetEnvMod] = await Promise.all([
      import('@babel/core'),
      import('@babel/preset-env'),
    ]);
    const transform = core.transformAsync ?? core.default?.transformAsync;
    if (typeof transform !== 'function') return { code, ok: false, error: '@babel/core unavailable' };
    const presetEnv = presetEnvMod.default ?? presetEnvMod;
    const out = await transform(code, {
      babelrc: false,
      configFile: false,
      compact: false,
      comments: false,
      // ES5 target; convert modules so import/export become require/exports,
      // which JSNice's parser accepts.
      presets: [[presetEnv, { targets: { ie: '11' }, modules: 'commonjs', loose: true }]],
    });
    if (!out || typeof out.code !== 'string' || out.code.length === 0) {
      return { code, ok: false, error: 'empty transpile output' };
    }
    return { code: out.code, ok: true };
  } catch (e) {
    return { code, ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export async function applyJsNice(code: string, opts: JsNiceOptions): Promise<JsNiceResult> {
  if (!opts.enabled) return { code, applied: false, reason: 'disabled' };

  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  if (code.length > maxBytes) {
    return {
      code,
      applied: false,
      reason: `input ${code.length}B exceeds jsnice limit ${maxBytes}B`,
    };
  }

  // JSNice is ES5-only; lower modern syntax first unless explicitly disabled.
  let payload = code;
  let transpiled = false;
  if (opts.transpile !== false) {
    const tr = await transpileToEs5(code);
    if (!tr.ok) {
      return { code, applied: false, reason: `transpile failed: ${(tr.error ?? '').slice(0, 100)}` };
    }
    payload = tr.code;
    transpiled = true;
  }

  const params = new URLSearchParams({
    pretty: opts.pretty === false ? '0' : '1',
    rename: opts.rename === false ? '0' : '1',
    types: opts.types === false ? '0' : '1',
    suggest: opts.suggest ? '1' : '0',
  });
  const url = `${opts.url ?? DEFAULT_URL}?${params.toString()}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-requested-with': 'XMLHttpRequest',
        accept: 'application/json, text/javascript, */*; q=0.01',
      },
      body: payload,
      signal: controller.signal,
    });
    if (!res.ok) return { code, applied: false, reason: `HTTP ${res.status}`, transpiled };

    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { code, applied: false, reason: 'non-JSON response', transpiled };
    }
    const obj = parsed as Record<string, unknown>;
    if (typeof obj.error === 'string' && obj.error.length > 0) {
      return { code, applied: false, reason: `service error: ${obj.error.slice(0, 120)}`, transpiled };
    }
    if (typeof obj.js !== 'string' || obj.js.trim().length === 0) {
      return { code, applied: false, reason: 'empty result', transpiled };
    }
    // JSNice reports compile failures by returning the error text *inside* the
    // `js` field rather than an `error` field. Its parser is ES5-oriented, so
    // modern ESM (import/export, arrows, template literals) trips this. Detect
    // the sentinel and surface a clear reason instead of a spurious "applied".
    if (/^Error compiling input:/.test(obj.js.trimStart())) {
      const detail = obj.js.split('\n').find((l) => /Parse error/i.test(l))?.trim();
      return {
        code,
        applied: false,
        reason: `service could not compile input (ES6+ unsupported)${detail ? `: ${detail}` : ''}`,
        transpiled,
      };
    }
    return { code: obj.js, applied: true, transpiled };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { code, applied: false, reason: /abort/i.test(msg) ? 'timeout' : msg, transpiled };
  } finally {
    clearTimeout(timer);
  }
}
