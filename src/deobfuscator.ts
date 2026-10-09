/**
 * JS Deobfuscator Engine v6
 *
 * Pipeline:
 *   Stage A — Pre-parse (raw string transforms, before Babel)
 *     A1. Junk token removal   — safe-zone frequency analysis, strips padded identifiers.
 *                                Includes identifier-collapse guard: if removing a token
 *                                collapses many distinct identifier names into one (e.g.
 *                                hex suffix stripped from _0x1234 → _0), the token is
 *                                the unique disambiguator and is NOT removed.
 *     A2. atob raw decode      — decodes atob("…") literals before AST parse
 *
 *   Stage B — AST passes (multi-sweep, converges to stability)
 *     B00. String escape norm  — \x48\x65 / \u0048 → plain UTF-8 (in-place extra mutation,
 *                                never calls replaceWith to avoid scope-reconciliation crash)
 *     B01. Literal normalise   — 0x hex / octal numeric raw → decimal
 *     B01d. Global obj alias   — var p = window; p.Math.floor(x) → Math.floor(x)
 *     B01b. Native alias       — var s = String.fromCharCode; s(67) → String.fromCharCode(67)
 *     B10b. Pure native calls  — Math.floor(135.61) → 135 (whitelisted pure builtins),
 *                                which unblocks the opaque-predicate arithmetic
 *     B01c. Pure numeric fns   — function ww(A,w){return -6*(A&w)-…} is an algebraic
 *                                identity; ww(113,77) → 77. Unmasks charcodes that
 *                                constantFolding cannot reach through a call.
 *     B02. fromCharCode        — String.fromCharCode(72,101,…) → "Hello"
 *     B03. atob / btoa         — atob("SGVsbG8=") → "Hello" in AST
 *     B03b. Buffer decoding    — Buffer.from("SGVsbG8=", "base64").toString("utf8") → "Hello"
 *     B03c. Function ctor      — Function("p","return p.x")(a) → (function(p){…})(a),
 *                                statically, when no free name of the body would
 *                                capture a local and the surrounding code is sloppy.
 *                                Opens a bundle that is otherwise one string literal.
 *     B03d. Literal eval       — direct eval("<one expression>") → that expression.
 *                                Removes the construct that makes a whole scope chain
 *                                dynamic, so the binding passes below stay enabled.
 *     B03e. RGF embedding      — js-confuser's reduced-global-function: a flag-guarded
 *                                eval wrapper returning a function embedded as source
 *                                (`function F(){…} F;`). When the guard is provably
 *                                truthy and the body reaches only globals, the call
 *                                becomes the function expression and the eval, guard
 *                                and helper are removed.
 *     B04. Constant folding    — arithmetic/logical/ternary, depth-limited, stable inner loop
 *     B05a.Closure string dec  — VM-executes the factory/shuffler/decoder triad used by
 *                                javascript-obfuscator: function _0x212a(){ const arr=[...];
 *                                return (_0x212a=function(){return arr;})(); } + shuffler IIFE
 *                                + self-reassigning decoder. Manual AST walk (no traverse),
 *                                resolves every numeric call site via VM sandbox probing.
 *     B05. String array        — array + rotation IIFE + decoder fn → inline all call sites
 *     B05b. Pool decoder       — pool + *transforming* decoder that B05 cannot match,
 *                                e.g. function D(A){var w=o[A]; return atob(w);} — the
 *                                slice is VM-probed at every literal call index.
 *     B05d. Concealed strings  — js-confuser's `STR(start, len)` → `DEC(POOL.slice(…))`
 *                                with a UTF-8 finisher: VM-probed per literal site
 *     B06. Member simplify     — obj["key"] → obj.key (reserved words too), and
 *                                {"key": v} / class { ["m"]() {} } → plain keys
 *     B07. Dispatch inline     — D.fn(x,y) → inlined expr (block-body + expr-body arrows)
 *     B08. Constant propagation— var K="x"; use(K) → use("x") (write-once literal vars)
 *     B09. Proxy functions     — function a(x){return b(x,"utf8")} → direct call to b
 *     B09b. No-op calls        — `F(a, b, c);` where F has an empty body (or only
 *                                erases itself) → `a; b; c;` (js-confuser AST scrambler)
 *     B11. Opaque predicates   — always-true/false if/ternary/while → removed/inlined;
 *                                `"k" in dummyFn` probes of an untouched empty fn → false
 *     B12. Dead code elim      — if(false)/ternary(bool)/&&/||/?? short-circuit
 *     B13. CF unflatten        — while(true){switch(order[i++]){…}} → flat statements
 *     B14. Self-defending      — debugger stmts, anti-tamper timers, Function("debugger")(),
 *                                and the call-controller probe `X = C(this, fn); X();`
 *                                that regex-searches its own source text
 *     B15. Comma sequence      — (a=1,b=2) at statement level → two statements
 *     B16. typeof simplify     — typeof "x" === "string" → true
 *     B16b. Boolean simplify   — cond ? true : false → !!cond; !!bool → bool
 *     B17. Unused vars         — pure-init vars never read after declaration → removed
 *     B17b. Dead functions     — helpers left behind once B01c/B05b/B09 inlined every
 *                                call site; B17 only prunes literal-init vars
 *     B18. Deduplicate vars    — var x; var x; → var x; (2nd+ → assignment or removal)
 *     B19. Mangled rename      — _0xABCD → v_0, v_1, … (binding-aware, skip prop keys)
 *     B20. Locks               — js-confuser's integrity lock (verified: cyrb53 of the
 *                                function's original text equals the constant) and
 *                                anti-beautify test (`/\n/.test(fn)` on newline-free source)
 *
 *     Binding-aware structural passes (see ./analysis for the shared facts):
 *     B00b. Statement normalise— sequences hoisted out of statement heads,
 *                                `~function(){}()` unwrapped, `x={}; x.k=v` folded,
 *                                loop work moved out of `for(;;a,b){}` updates
 *     B00c. Param locals       — params never read before being overwritten (and
 *                                IIFE params beyond the args) → `var`
 *     B00e. Moved declarations — `function f(a, p){ if(!p) p = function…}` called as `f(x)`
 *                                → the guard is a declaration of p (js-confuser)
 *     B01e. Concealed globals  — js-confuser's global-object probe → `globalThis`, and
 *                                `getGlobal("k")` switch-table lookups → `GV.console`
 *     B00d. Masked variables   — `function f(...S){ S.length=1; S[0]; S[-3]=…; S.k }`
 *                                → named parameters and `var` locals (js-confuser)
 *     B09d. Dispatchers        — js-confuser's `(PAYLOAD=[x], D("k"))` routing through a
 *                                per-block function table → declarations and plain calls
 *     B09c. Flat functions     — `function W(...a){ var o={…}; return F(o, a) }` with
 *                                `function F(o, [x, y]){…}` → `function W(x, y){…}`,
 *                                then the accessor object `o` → the variables it wraps
 *     B05c. Closed fn eval     — self-contained function groups (string table +
 *                                rotation setup + decoder) VM-evaluated in compact
 *                                form (decoders inspect their own source text);
 *                                `const alias = decoder` is a call site, not a
 *                                leak; literal calls folded, dead machinery removed
 *     B04b. Bitwise literals   — `x >>> 6.74` → `x >>> 6`
 *     B07c. Object tables      — frozen, non-escaping object literals: literal props
 *                                and expression-bodied methods inlined (order-safe)
 *     B07d. Literal arrays     — `const K = ["b",0,1,…]` read as `K[13]`: folded to the
 *                                element, for tables nothing visible can mutate
 *     B08b. Binding propagation— write-once aliases / literals → their value, for
 *                                declarators *and* single dominating assignments
 *     B13c. Switch dispatcher  — `for(o=[…],i=0;;) switch(o[i++]){…}` in any spelling
 *     B15b. Conditional stmts  — statement-level `a ? b : c` / `a && b` → if
 *     B17c. Dead stores        — writes to (and declarations of) unread bindings
 *     B17d. Single-use temps   — `x = E; return x;` → `return E;`
 *
 *   Dynamic scope (`eval` / `with`)
 *     A direct `eval` resolves names against its own scope chain, so it can observe
 *     the bindings of the scopes that *enclose* it — and no others. The binding
 *     passes ask `dynamicScopes` that question per binding instead of giving up on
 *     the whole file, which is what lets a bundle with one concealed global still be
 *     recovered everywhere else. Passes that match shapes or rewrite by name without
 *     consulting the scope chain (listed in the orchestrator) stay off in that case.
 *
 *   Stage C — VM eval hooking
 *     Sandboxed execution to intercept eval()/Function() dynamic payloads.
 *     Falls back to IIFE-wrapped execution if duplicate var declarations crash the sandbox.
 *
 *   Logging: every pass reports through the unified logger (`@logger`, at the
 *   repository root) — `log.pass(id, name, count, unit?, detail?)`, `log.skip`,
 *   `log.fail`, `log.note` — which renders the same structured entries as plain
 *   lines (`result.log`), catppuccin-mocha ansi for the cli, and spans for the ui.
 */

import * as parser from '@babel/parser';
import { traverse } from './babel.js';
import type { Binding, NodePath } from '@babel/traverse';
import { generate } from './babel.js';
import * as t from '@babel/types';
import {
  documentOrder,
  walk,
  freeReferences,
  memberRoot,
  getSourceFacts,
  setSourceFacts,
  noteSourceText,
  functionsNewlineFree,
  type SourceFacts,
  freshProgram,
  annexBNames,
  dynamicScopes,
  hasDynamicScope,
  hasSimpleParams,
  instantiateTemplate,
  isInert,
  isInertStatement,
  paramInitialObserved,
  templateFreeNames,
  templateOf,
  usesArguments,
  writeOnceFacts,
  type DynamicScopes,
  type FreeRefs,
  type WriteOnceFact,
} from './analysis.js';
import { applyJsNice, type JsNiceOptions } from './jsnice.js';
import { ownContextSensitive, passCffRecover } from './cff.js';
import * as vm from 'node:vm';
import { createLogger, type Entry, type Logger } from './logger.js';

export type { JsNiceOptions } from './jsnice.js';

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

export interface DeobfuscationOptions {
  enabledPasses: string[];
  lenientMode: boolean;
  autoFix: boolean;
  /**
   * Opt-in Stage D: send the locally-deobfuscated code to a JSNice-compatible
   * service for statistical identifier renaming and type inference. This makes a
   * network request to a third party (jsnice.org over plain HTTP by default), so
   * it is disabled unless explicitly enabled. Failures never abort the run — the
   * local output is kept if the service is unavailable, times out, rejects the
   * input, or returns code that no longer parses.
   */
  jsNice?: JsNiceOptions;
  /**
   * Receives every log line the moment a pass emits it, together with its
   * structured entry (render it with `ansi()` from `@logger` for a terminal),
   * so a caller can show progress while a long run is still going. The
   * complete log is still returned in the result.
   */
  onLog?: (line: string, entry: Entry) => void;
}

export interface ParseError {
  message: string;
  line?: number;
  col?: number;
}

export interface DeobfuscationResult {
  deobfuscatedCode: string;
  passesApplied: string[];
  /** the pass log as plain lines. */
  log: string[];
  /** the same log, structured — see `@logger` for rendering and tones. */
  entries: Entry[];
  parsingErrors: string[];
  parseWarnings: string[];
  structuredParseErrors: ParseError[];
  structuredParseWarnings: ParseError[];
  metadata: Record<string, unknown>;
  success: boolean;
  errors: string[];
}

/**
 * The full, generally safe pass set used by the web UI and command-line tools.
 * Keep opt-in transforms such as junk-token removal and identifier renaming out
 * of this list because they can make valid, non-obfuscated programs less clear.
 */
export const DEFAULT_ENABLED_PASSES = [
  'functionConstructor', // B03c
  'evalLiteral', // B03d
  'rgf', // B03e
  'rgfThunk', // B03f
  'cffRecover', // B13d
  'stringEscapeNorm',
  'hexStringDecoding',
  'globalObjectAlias',
  'nativeAlias',
  'pureNativeCalls',
  'pureNumericFns',
  'fromCharCode',
  'atobDecoding',
  'bufferDecoding',
  'constantFolding',
  'stringDecoding',
  'poolDecoding',
  'concealedStrings', // B05d — js-confuser string pool, per-block decoders
  'statementNormalize', // B00b — hoist sequences / fold `x = {}; x.k = v`
  'dispatchers', // B09d — js-confuser dispatcher tables → declarations and plain calls
  'flatFunctions', // B09c — flattened function bodies back into their wrappers
  'maskedVariables', // B00d — rest-parameter slots → parameters and locals
  'movedDeclarations', // B00e — never-supplied params holding moved declarations
  'paramLocals', // B00c — overwritten-before-read params → var
  'concealedGlobals', // B01e — js-confuser global probe and switch table
  'locks', // B20
  'noopCalls', // B09b — statement-level calls of do-nothing functions → their arguments
  'bindingPropagation', // B08b — write-once aliases & literals
  'objectTables', // B07c — frozen index / proxy-function tables
  'literalArrays', // B07d — frozen literal index tables
  'closedFunctionEval', // B05c — VM-fold self-contained decoder groups
  'bitwiseLiterals', // B04b — fractional bitwise operands
  'memberExpressionSimplification',
  'dispatchTableInlining',
  'identityTable',
  'constantPropagation',
  'proxyFunctionRemoval',
  'functionInlining',
  'opaquePredicateRemoval',
  'scopedConstFold', // B11b — inline single-assignment loop locals into predicates
  'constantFolding', // fold the predicates B11b just made literal
  'deadCodeElimination',
  'controlFlowFlattening',
  'switchDispatcher', // B13c — split-order dispatchers in for/while form
  'stateMachineUnflatten', // B13b — for(;;){switch(state)} → straight-line code
  'selfDefending',
  'commaSequence',
  'conditionalStatements', // B15b — statement-level ?: / && / || → if
  'typeofSimplify',
  'booleanSimplify', // B16b — cond ? true : false → !!cond
  'unusedVars',
  'deadFunctions', // B17b — drop helpers whose call sites were all inlined
  'deadStores', // B17c — writes to bindings nothing reads
  'singleUseTemps', // B17d — `x = E; return x;` → `return E;`
  'iifeFlatten', // B17e
  'declarationTidy', // B17f
  'deduplicateVarDecls',
  'confuserNames', // B19b
  'vmEvalHook',
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Parser — multi-strategy, never throws
// ─────────────────────────────────────────────────────────────────────────────

const BROWSER_TOLERANT_CODES = new Set([
  'VarRedeclaration',
  'DuplicateProto',
  'TrailingCommaAfterRest',
  'LabelRedeclaration',
  'StrictOctalLiteral',
  'StrictOctalNumericLiteral',
  'StrictWith',
  'StrictEvalArguments',
  'StrictDelete',
  'StrictLHSAssignment',
  'StrictPrefixPostfixOperator',
  'StrictForInInitializer',
  'InvalidCoverInitializedName',
  'DuplicateExport',
  'ObsoleteAwaitStar',
  'AwaitOutsideAsync',
]);
const BROWSER_TOLERANT_PATS: RegExp[] = [
  /has already been declared/i,
  /duplicate (key|export|default)/i,
  /octal (literal|escape)/i,
  /'with' statement/i,
  /trailing comma/i,
  /same label was already/i,
  /invalid for-in initializer/i,
  /eval or arguments (can't|cannot)/i,
  /await is not allowed/i,
  /top.level await/i,
];

interface ParseResult {
  ast: t.File;
  warnings: ParseError[];
  hardErrors: ParseError[];
}

function classifyBabelErrors(
  errs: ReadonlyArray<{
    reasonCode?: string;
    message: string;
    loc?: { line: number; column: number } | null;
  }>
): Pick<ParseResult, 'warnings' | 'hardErrors'> {
  const warnings: ParseError[] = [],
    hardErrors: ParseError[] = [];
  for (const err of errs) {
    const pe: ParseError = { message: err.message, line: err.loc?.line, col: err.loc?.column };
    const tolerant =
      (err.reasonCode != null && BROWSER_TOLERANT_CODES.has(err.reasonCode)) ||
      BROWSER_TOLERANT_PATS.some((p) => p.test(err.message));
    if (tolerant) warnings.push(pe);
    else hardErrors.push(pe);
  }
  return { warnings, hardErrors };
}

const PARSE_STRATEGIES: Array<() => Parameters<typeof parser.parse>[1]> = [
  () => ({
    sourceType: 'unambiguous',
    plugins: ['jsx'],
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowUndeclaredExports: true,
    allowSuperOutsideMethod: true,
  }),
  () => ({
    sourceType: 'script',
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowUndeclaredExports: true,
    allowSuperOutsideMethod: true,
  }),
  () => ({
    sourceType: 'module',
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowUndeclaredExports: true,
  }),
  () => ({ sourceType: 'script', errorRecovery: true }),
];

function safeParse(code: string): ParseResult {
  for (const strategy of PARSE_STRATEGIES) {
    try {
      const file = parser.parse(code, strategy());
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawErrors: unknown[] = (file as any).errors ?? [];
      const { warnings, hardErrors } = classifyBabelErrors(
        rawErrors as Parameters<typeof classifyBabelErrors>[0]
      );
      return { ast: file, warnings, hardErrors };
    } catch {
      /* try next */
    }
  }
  try {
    const empty = parser.parse('', { errorRecovery: true });
    return { ast: empty, warnings: [], hardErrors: [{ message: 'All parse strategies failed.' }] };
  } catch {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return {
      ast: {
        type: 'File',
        program: { type: 'Program', body: [], directives: [], sourceType: 'script' },
        comments: [],
      } as any,
      warnings: [],
      hardErrors: [{ message: 'Parser init failed.' }],
    };
  }
}

function genCode(ast: t.File): string {
  return generate(ast, { comments: true, compact: false, jsescOption: { minimal: true } }).code;
}

/**
 * Self-text checks (js-confuser's, see B20) the passes could not settle:
 *   • newline tests — `new RegExp("\n")` / `/\n/` fed to `.test(fn)`: their
 *     answer depends on how the output is *printed*;
 *   • integrity locks — the sensitivity regexp of the text hash: their answer
 *     depends on the function's exact text, which the recovery has changed.
 */
function unsettledSelfChecks(ast: t.File): { newline: number; integrity: number } {
  let newline = 0;
  let integrity = 0;
  const SENSITIVITY = ' |\\n|;|,|\\{|\\}|\\(|\\)|\\.|\\[|\\]';
  t.traverseFast(ast.program, (n) => {
    if (t.isNewExpression(n) && n.arguments.length === 1 && t.isStringLiteral(n.arguments[0], { value: '\n' })) newline++;
    if (t.isRegExpLiteral(n) && n.pattern === '\\n') newline++;
    if (t.isStringLiteral(n, { value: SENSITIVITY }) || (t.isRegExpLiteral(n) && n.pattern === SENSITIVITY)) integrity++;
  });
  return { newline, integrity };
}

/**
 * Source for code that will be *executed* in the VM rather than shown.
 *
 * Obfuscators inspect their own source text at run time: javascript-obfuscator's
 * string-array decoder keeps a sentinel `function(){return'newState';}` and
 * tests `Function.prototype.toString()` of it against
 * `\w+ *\(\) *{\w+ *['|"].+['|"];? *}` — a shape only minified code has. If the
 * sentinel fails, the decoder loops forever (or, in our probe sandbox, throws).
 * Pretty-printing a slice before evaluating it therefore trips the trap; the
 * compact form matches what was deployed and keeps such checks satisfied.
 */
function genVmCode(node: t.Node): string {
  return generate(node, { comments: false, compact: true, jsescOption: { minimal: true } }).code;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core primitives
// ─────────────────────────────────────────────────────────────────────────────

const RESERVED = new Set([
  'break',
  'case',
  'catch',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'finally',
  'for',
  'function',
  'if',
  'in',
  'instanceof',
  'new',
  'return',
  'switch',
  'this',
  'throw',
  'try',
  'typeof',
  'var',
  'void',
  'while',
  'with',
  'class',
  'const',
  'enum',
  'export',
  'extends',
  'import',
  'super',
]);

const MAX_PURE_DEPTH = 40;

function isPurelyLiteral(node: t.Node, depth = 0): boolean {
  if (depth > MAX_PURE_DEPTH) return false;
  if (
    t.isNumericLiteral(node) ||
    t.isBooleanLiteral(node) ||
    t.isStringLiteral(node) ||
    t.isNullLiteral(node)
  )
    return true;
  if (
    t.isIdentifier(node) &&
    (node.name === 'undefined' || node.name === 'Infinity' || node.name === 'NaN')
  )
    return true;
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) return true;
  // `![]` / `!{}` — negating a fresh, effect-free collection is just `false`
  // (the `!![]` spelling of `true` is everywhere in obfuscated loop heads).
  if (
    t.isUnaryExpression(node, { operator: '!' }) &&
    ((t.isArrayExpression(node.argument) &&
      node.argument.elements.every(
        (e) => e !== null && !t.isSpreadElement(e) && isPurelyLiteral(e, depth + 1)
      )) ||
      (t.isObjectExpression(node.argument) && node.argument.properties.length === 0))
  )
    return true;
  if (t.isUnaryExpression(node)) return isPurelyLiteral(node.argument, depth + 1);
  if (t.isBinaryExpression(node))
    return isPurelyLiteral(node.left, depth + 1) && isPurelyLiteral(node.right, depth + 1);
  if (t.isLogicalExpression(node))
    return isPurelyLiteral(node.left, depth + 1) && isPurelyLiteral(node.right, depth + 1);
  if (t.isConditionalExpression(node))
    return (
      isPurelyLiteral(node.test, depth + 1) &&
      isPurelyLiteral(node.consequent, depth + 1) &&
      isPurelyLiteral(node.alternate, depth + 1)
    );
  return false;
}

function evalPure(node: t.Expression): { ok: boolean; value: unknown } {
  if (t.isNumericLiteral(node)) return { ok: true, value: node.value };
  if (t.isStringLiteral(node)) return { ok: true, value: node.value };
  if (t.isBooleanLiteral(node)) return { ok: true, value: node.value };
  if (t.isNullLiteral(node)) return { ok: true, value: null };
  if (t.isIdentifier(node, { name: 'undefined' })) return { ok: true, value: undefined };
  if (t.isIdentifier(node, { name: 'NaN' })) return { ok: true, value: NaN };
  if (t.isIdentifier(node, { name: 'Infinity' })) return { ok: true, value: Infinity };
  if (t.isTemplateLiteral(node) && node.expressions.length === 0 && node.quasis.length === 1)
    return { ok: true, value: node.quasis[0].value.cooked ?? node.quasis[0].value.raw };
  if (!isPurelyLiteral(node)) return { ok: false, value: undefined };
  try {
    // eslint-disable-next-line no-new-func
    return {
      ok: true,
      value: new Function('"use strict"; return (' + generate(node).code + ')')(),
    };
  } catch {
    return { ok: false, value: undefined };
  }
}

function toNode(v: unknown): t.Expression | null {
  if (typeof v === 'number') {
    if (isNaN(v) || !isFinite(v)) return null;
    if (v < 0) return t.unaryExpression('-', t.numericLiteral(-v));
    return t.numericLiteral(v);
  }
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (typeof v === 'string') return t.stringLiteral(v);
  if (v === null) return t.nullLiteral();
  if (v === undefined) return t.identifier('undefined');
  return null;
}

function isAlreadyCanonical(node: t.Expression, v: unknown): boolean {
  if (typeof v === 'number' && !isNaN(v) && isFinite(v)) {
    if (v < 0)
      return (
        t.isUnaryExpression(node, { operator: '-' }) &&
        t.isNumericLiteral(node.argument) &&
        (node.argument as t.NumericLiteral).value === -v
      );
    return t.isNumericLiteral(node) && node.value === v;
  }
  if (typeof v === 'boolean') return t.isBooleanLiteral(node) && node.value === v;
  if (typeof v === 'string') return t.isStringLiteral(node) && node.value === v;
  if (v === null) return t.isNullLiteral(node);
  if (v === undefined) return t.isIdentifier(node, { name: 'undefined' });
  return false;
}

function foldAny(p: { node: t.Expression; replaceWith(n: t.Expression): void }): number {
  if (!isPurelyLiteral(p.node)) return 0;
  const r = evalPure(p.node);
  if (!r.ok) return 0;
  if (isAlreadyCanonical(p.node, r.value)) return 0;
  const repl = toNode(r.value);
  if (!repl) return 0;
  p.replaceWith(repl);
  return 1;
}

function subArgs(expr: t.Expression, m: Map<string, t.Expression>): t.Expression {
  if (
    t.isStringLiteral(expr) ||
    t.isNumericLiteral(expr) ||
    t.isBooleanLiteral(expr) ||
    t.isNullLiteral(expr)
  )
    return expr;
  if (t.isIdentifier(expr)) return m.get(expr.name) ?? expr;
  if (t.isUnaryExpression(expr))
    return t.unaryExpression(expr.operator, subArgs(expr.argument as t.Expression, m), expr.prefix);
  if (t.isBinaryExpression(expr))
    return t.binaryExpression(
      expr.operator,
      subArgs(expr.left as t.Expression, m),
      subArgs(expr.right as t.Expression, m)
    );
  if (t.isLogicalExpression(expr))
    return t.logicalExpression(
      expr.operator,
      subArgs(expr.left as t.Expression, m),
      subArgs(expr.right as t.Expression, m)
    );
  if (t.isConditionalExpression(expr))
    return t.conditionalExpression(
      subArgs(expr.test, m),
      subArgs(expr.consequent, m),
      subArgs(expr.alternate, m)
    );
  if (t.isSequenceExpression(expr))
    return t.sequenceExpression(
      expr.expressions.map((e) => (t.isExpression(e) ? subArgs(e as t.Expression, m) : e))
    );
  if (t.isArrayExpression(expr))
    return t.arrayExpression(
      expr.elements.map((e) => (e && t.isExpression(e) ? subArgs(e as t.Expression, m) : e))
    );
  if (t.isCallExpression(expr)) {
    const nc = t.isExpression(expr.callee) ? subArgs(expr.callee as t.Expression, m) : expr.callee;
    return t.callExpression(
      nc,
      expr.arguments.map((a) => (t.isExpression(a) ? subArgs(a as t.Expression, m) : a))
    );
  }
  if (t.isMemberExpression(expr)) {
    const obj = subArgs(expr.object as t.Expression, m);
    const prop =
      expr.computed && t.isExpression(expr.property)
        ? subArgs(expr.property as t.Expression, m)
        : expr.property;
    return t.memberExpression(obj, prop, expr.computed);
  }
  if (t.isAssignmentExpression(expr))
    return t.assignmentExpression(
      expr.operator,
      expr.left as t.LVal,
      subArgs(expr.right as t.Expression, m)
    );
  return expr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage A — Pre-parse passes
// ─────────────────────────────────────────────────────────────────────────────

function splitSafeZones(code: string): { safe: boolean; text: string }[] {
  const segs: { safe: boolean; text: string }[] = [];
  let i = 0,
    buf = '';
  const flush = (safe: boolean, text: string) => {
    if (text) segs.push({ safe, text });
  };
  while (i < code.length) {
    const ch = code[i];
    if (ch === '/' && code[i + 1] === '/') {
      flush(true, buf);
      buf = '';
      let j = i;
      while (j < code.length && code[j] !== '\n') j++;
      flush(false, code.slice(i, j));
      i = j;
      continue;
    }
    if (ch === '/' && code[i + 1] === '*') {
      flush(true, buf);
      buf = '';
      const end = code.indexOf('*/', i + 2);
      const j = end === -1 ? code.length : end + 2;
      flush(false, code.slice(i, j));
      i = j;
      continue;
    }
    if (ch === '"' || ch === "'") {
      flush(true, buf);
      buf = '';
      let j = i + 1;
      while (j < code.length) {
        if (code[j] === '\\') {
          j += 2;
          continue;
        }
        if (code[j] === ch) {
          j++;
          break;
        }
        j++;
      }
      flush(false, code.slice(i, j));
      i = j;
      continue;
    }
    if (ch === '`') {
      flush(true, buf);
      buf = '';
      let j = i + 1,
        depth = 0;
      while (j < code.length) {
        if (code[j] === '\\') {
          j += 2;
          continue;
        }
        if (code[j] === '$' && code[j + 1] === '{') {
          depth++;
          j += 2;
          continue;
        }
        if (code[j] === '}' && depth > 0) {
          depth--;
          j++;
          continue;
        }
        if (code[j] === '`' && depth === 0) {
          j++;
          break;
        }
        j++;
      }
      flush(false, code.slice(i, j));
      i = j;
      continue;
    }
    buf += ch;
    i++;
  }
  flush(true, buf);
  return segs;
}

function replaceInSafeZones(code: string, token: string): string {
  const re = new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
  return splitSafeZones(code)
    .map((s) => (s.safe ? s.text.replace(re, '') : s.text))
    .join('');
}

/**
 * A1: Junk Token Removal
 *
 * Strips repeating non-semantic substrings from identifier positions only (safe zones).
 *
 * IDENTIFIER-COLLAPSE GUARD (new in v6):
 * Before accepting a removal, counts distinct identifier names before and after.
 * If the removal collapses many distinct names into the same name (e.g. the hex
 * suffix from _0x5843dd, _0x3af988, … being stripped so all become "_0"), the
 * candidate is the unique disambiguator — not junk — and is skipped. This prevents
 * the duplicate-declaration explosion that previously crashed Babel scope APIs and
 * the Stage C VM sandbox.
 */
function prePassJunkTokenRemoval(code: string, log: Logger): string {
  const JS_BUILTINS = new Set([
    'var',
    'let',
    'const',
    'function',
    'return',
    'if',
    'else',
    'for',
    'while',
    'do',
    'switch',
    'case',
    'break',
    'continue',
    'new',
    'delete',
    'typeof',
    'instanceof',
    'void',
    'throw',
    'try',
    'catch',
    'finally',
    'class',
    'extends',
    'import',
    'export',
    'default',
    'this',
    'super',
    'true',
    'false',
    'null',
    'undefined',
    'prototype',
    'constructor',
    'Object',
    'Array',
    'String',
    'Number',
    'Boolean',
    'Buffer',
    'RegExp',
    'Function',
    'Math',
    'JSON',
    'Date',
    'Error',
    'Promise',
    'Symbol',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'Proxy',
    'Reflect',
    'parseInt',
    'parseFloat',
    'isNaN',
    'isFinite',
    'eval',
    'window',
    'document',
    'console',
    'process',
    'require',
    'module',
    'exports',
    'global',
    'self',
    'globalThis',
    'ActiveXObject',
    'WScript',
    'Shell',
    'Application',
    'FileSystemObject',
  ]);

  function countErrors(src: string): number {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (
        (parser.parse(src, { sourceType: 'script', errorRecovery: true }) as any).errors ?? []
      ).length;
    } catch {
      return 9999;
    }
  }

  function uniqueIds(src: string): number {
    return new Set(src.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) ?? []).size;
  }

  const baseline = countErrors(code);
  let cleaned = code,
    totalRemoved = 0;

  for (let round = 0; round < 8; round++) {
    const safeText = splitSafeZones(cleaned)
      .filter((s) => s.safe)
      .map((s) => s.text)
      .join(' ');
    const freq = new Map<string, number>();
    const re = /[a-zA-Z][a-zA-Z0-9]{5,}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(safeText)) !== null) freq.set(m[0], (freq.get(m[0]) ?? 0) + 1);

    let best: string | null = null,
      bestScore = 0;
    for (const [tok, cnt] of freq) {
      if (cnt < 10 || JS_BUILTINS.has(tok)) continue;
      const score = cnt * tok.length;
      if (score > bestScore) {
        bestScore = score;
        best = tok;
      }
    }
    if (!best) break;

    // Safety gate 0: hex-suffix guard.
    // Tokens like "x5843dd", "x3af988", "x1f2915" are the unique hex suffixes of
    // obfuscator-mangled identifiers (_0x5843dd, _0x3af988 …). They appear hundreds
    // of times — making them look like junk to a frequency analyser — but stripping
    // each one in turn causes all the mangled names to collapse into the same short
    // name (_0), creating duplicate declarations that crash Babel scope APIs and the
    // VM sandbox. Pattern: optional leading 'x', then 5+ pure hex digits.
    const HEX_SUFFIX = /^x?[0-9a-fA-F]{5,}$/i;
    if (HEX_SUFFIX.test(best)) {
      log.skip(null, 'junkToken', `"${best}" is a hex identifier suffix (mangled name uniquifier)`);
      break;
    }

    const candidate = replaceInSafeZones(cleaned, best);

    // Safety gate 1: parse errors must not increase
    if (countErrors(candidate) > baseline + 5) {
      log.skip(null, 'junkToken', `"${best}" is structural`);
      break;
    }

    // Safety gate 2: identifier collapse.
    // Stripping a hex suffix like "x5843dd" from "_0x5843dd" causes all mangled
    // identifiers to collapse to "_0", producing duplicate declarations that break
    // Babel scope APIs and the VM sandbox. Reject if > 3% of unique IDs collapsed.
    const beforeU = uniqueIds(cleaned);
    const afterU = uniqueIds(candidate);
    const collapsed = beforeU - afterU;
    if (collapsed > Math.max(4, Math.floor(beforeU * 0.03))) {
      log.skip(
        null,
        'junkToken',
        `"${best}" is an identifier uniquifier (${collapsed} name collisions)`
      );
      break;
    }

    const removed = cleaned.length - candidate.length;
    cleaned = candidate;
    log.pass(
      null,
      'junkToken',
      removed,
      'bytes',
      `removed "${best}" × ${Math.round(removed / best.length)}, safe-zone only`
    );
    totalRemoved += removed;
  }
  if (totalRemoved === 0) log.pass(null, 'junkToken', 0, undefined, 'none detected');
  return cleaned;
}

function prePassBase64(code: string, log: Logger): string {
  let n = 0;
  const out = code.replace(/\batob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)/g, (_m, b64) => {
    try {
      n++;
      return JSON.stringify(Buffer.from(b64, 'base64').toString('utf8'));
    } catch {
      return _m;
    }
  });
  if (n > 0) log.pass(null, 'base64', n, 'atob() calls decoded');
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage B — AST passes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * B00: String escape normalisation
 *
 * Babel decodes \x48 → "H" in StringLiteral.value at parse time, but preserves the
 * raw escaped form in extra.raw. generate() re-emits the raw form by default.
 *
 * FIX: manual recursive walk — completely bypasses Babel's traverse() and scope
 * machinery. Babel's scope.crawl() fires lazily during ANY traverse() call and
 * throws "Duplicate declaration" when duplicate var/function names exist in the AST
 * (even if the visitor itself never calls replaceWith). A plain object-graph walk
 * has zero scope interaction and is immune to this class of crash.
 */
function passStringEscapeNorm(ast: t.File, log: Logger): number {
  let n = 0;
  const SKIP = new Set([
    'start',
    'end',
    'loc',
    'extra',
    'range',
    'leadingComments',
    'trailingComments',
    'innerComments',
  ]);
  function walk(node: unknown): void {
    if (!node || typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;
    if (obj['type'] === 'StringLiteral') {
      const extra = obj['extra'] as Record<string, unknown> | undefined;
      if (extra && typeof extra['raw'] === 'string' && /\\[xXuU0-9'"\\nrtbfv]/.test(extra['raw'])) {
        delete obj['extra'];
        n++;
      }
      return; // no meaningful children on StringLiteral
    }
    for (const key of Object.keys(obj)) {
      if (SKIP.has(key)) continue;
      const child = obj[key];
      if (Array.isArray(child)) {
        for (const item of child) walk(item);
      } else if (child && typeof child === 'object' && 'type' in (child as object)) walk(child);
    }
  }
  walk(ast);
  log.pass('b00', 'strEscape', n);
  return n;
}

function passLiteralNormalise(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    NumericLiteral(p) {
      const raw = p.node.extra?.raw as string | undefined;
      if (raw && !/^\d+(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) {
        p.node.extra = { raw: String(p.node.value), rawValue: p.node.value };
        n++;
      }
    },
  });
  log.pass('b01', 'literals', n);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B01b: Native alias resolution
//
// Obfuscators routinely stash a builtin behind a short local name so that the
// literal-folding passes (which match `String.fromCharCode` / `atob` by name)
// never fire:
//
//   var s = String.fromCharCode, B = atob;
//   var pool = s(100) + s(71) + "cyBo";
//
// A wrapper *function* (`function s(a){ return String.fromCharCode(a) }`) is
// already handled by proxyFunctionRemoval, but a bare reference assignment is
// not: it is a VariableDeclarator whose init is an Identifier/MemberExpression
// rather than a Function, so no proxy is detected. This pass rewrites each
// reference to such an alias back to the canonical builtin, letting the
// downstream literal passes (fromCharCode, atob, bufferDecoding) see through it.
//
// Safety: the alias must be a write-once binding, and the global root it names
// must be unshadowed at the declaration site.
// ─────────────────────────────────────────────────────────────────────────────

// Global roots whose members are side-effect-free and safe to re-resolve.
const ALIASABLE_ROOTS = new Set([
  'String',
  'Number',
  'Boolean',
  'Array',
  'Object',
  'Math',
  'JSON',
  'Date',
  'RegExp',
]);

// Bare globals that are safe to alias by identifier.
const ALIASABLE_GLOBALS = new Set([
  'atob',
  'btoa',
  'parseInt',
  'parseFloat',
  'decodeURIComponent',
  'encodeURIComponent',
  'decodeURI',
  'encodeURI',
  'unescape',
  'escape',
  'isNaN',
  'isFinite',
  'String',
  'Number',
  'Boolean',
  'Array',
  'Object',
  'Math',
  'JSON',
  // The rest of the ECMAScript standard globals, and the host globals every
  // modern engine defines: `globalThis.X` and `X` name the same value.
  'Date',
  'RegExp',
  'Error',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'ReferenceError',
  'EvalError',
  'URIError',
  'Promise',
  'Symbol',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'WeakRef',
  'Reflect',
  'Proxy',
  'BigInt',
  'ArrayBuffer',
  'SharedArrayBuffer',
  'DataView',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int8Array',
  'Uint16Array',
  'Int16Array',
  'Uint32Array',
  'Int32Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array',
  'Intl',
  'Function',
  'console',
  'setTimeout',
  'clearTimeout',
  'setInterval',
  'clearInterval',
  'queueMicrotask',
  'TextDecoder',
  'TextEncoder',
  'URL',
  'URLSearchParams',
  'structuredClone',
]);

// ECMAScript built-ins every engine defines. `G.X` and a bare `X` agree only
// for these: a host API that may be missing (`TextDecoder`, `atob`, `URL`,
// `console`, `SharedArrayBuffer`…) reads as `undefined` through the global
// object but throws a ReferenceError by name.
const GUARANTEED_GLOBALS = new Set([
  'String', 'Number', 'Boolean', 'Array', 'Object', 'Math', 'JSON', 'Date', 'RegExp', 'Function', 'Symbol',
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'EvalError', 'URIError',
  'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Reflect', 'Proxy', 'ArrayBuffer', 'DataView',
  'Uint8Array', 'Uint8ClampedArray', 'Int8Array', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array',
  'Float32Array', 'Float64Array', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
  'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'unescape', 'escape',
]);

// Names that denote the global object itself. Aliasing one (`var p = window`)
// hides every builtin behind a member access (`p.Math.floor`), which defeats
// the name-matching in B02/B03/B10 just as surely as a direct alias does.
const GLOBAL_OBJECT_NAMES = new Set(['window', 'globalThis', 'self', 'global', 'top']);

/** `String.fromCharCode` / `Math.imul` / `atob` → canonical node, else null. */
function asAliasableNative(node: t.Node): t.Expression | null {
  if (t.isIdentifier(node)) return ALIASABLE_GLOBALS.has(node.name) ? (node as t.Expression) : null;
  if (t.isMemberExpression(node) && !node.computed) {
    const { object, property } = node;
    if (!t.isIdentifier(object) || !t.isIdentifier(property)) return null;
    if (!ALIASABLE_ROOTS.has(object.name)) return null;
    return node as t.Expression;
  }
  return null;
}

function passNativeAlias(ast: t.File, log: Logger): number {
  const aliases = new Map<t.Identifier, t.Expression>();
  const aliasNames = new Set<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const declPaths = new Map<t.Identifier, any>();
  // The alias must hold its value at every read: a hoisted function called
  // before `var s = String.fromCharCode` runs sees `undefined` (a `let` throws).
  // writeOnceFacts proves the initialisation dominates every reference.
  const dominated = new Set<t.Identifier>();
  try {
    for (const b of writeOnceFacts(freshProgram(ast), { includeScriptGlobals: true }).keys()) dominated.add(b.identifier);
  } catch {
    /* no facts: nothing is inlined */
  }

  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;

      const target = asAliasableNative(init);
      if (!target) return;

      // The root global must not be shadowed here, or `String.fromCharCode`
      // may not mean what it says.
      const rootName = t.isMemberExpression(target)
        ? (target.object as t.Identifier).name
        : (target as t.Identifier).name;
      try {
        if (p.scope.getBinding(rootName)) return;
      } catch {
        return;
      }

      let binding: { constant?: boolean; identifier?: t.Identifier } | null | undefined;
      try {
        binding = p.scope.getBinding(id.name);
      } catch {
        return;
      }
      // Only inline write-once aliases — a reassigned alias may point elsewhere.
      if (!binding?.constant || !binding.identifier) return;
      if (!dominated.has(binding.identifier)) return;

      aliases.set(binding.identifier, target);
      aliasNames.add(id.name);
      declPaths.set(binding.identifier, p);
    },
  });

  if (aliases.size === 0) {
    log.pass('b01b', 'nativeAlias', 0);
    return 0;
  }

  let n = 0;
  const inlined = new Set<t.Identifier>();
  traverse(ast, {
    Identifier(p) {
      if (!aliasNames.has(p.node.name)) return;
      if (p.parentPath?.isVariableDeclarator() && p.key === 'id') return;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (!(p as any).isReferencedIdentifier()) return;

      let bindingId: t.Identifier | null | undefined;
      try {
        bindingId = p.scope.getBinding(p.node.name)?.identifier;
      } catch {
        return;
      }
      if (!bindingId) return;
      const target = aliases.get(bindingId);
      if (!target) return;

      p.replaceWith(t.cloneNode(target, true));
      inlined.add(bindingId);
      n++;
    },
  });

  // Drop the now-dead alias declarations.
  for (const bindingId of inlined) {
    const declPath = declPaths.get(bindingId);
    if (!declPath) continue;
    try {
      const decl = declPath.parent as t.VariableDeclaration;
      if (decl.declarations.length === 1) declPath.parentPath?.remove();
      else declPath.remove();
    } catch {
      /**/
    }
  }

  log.pass('b01b', 'nativeAlias', n, 'refs', `${inlined.size} aliases removed`);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B01c: Pure numeric function inlining
//
// The bitwise-identity family: dozens of tiny top-level functions whose body is
// a single `return` over pure integer arithmetic on the parameters only —
//
//   function ww(A, w) { return -6*(A&w) - 1*(A&~w) - 6*~(A&w) + 7*~(A&~A) - 1*~(A|w); }
//   function TA(A, w) { return -6*(A&w) - 4*(A&~w) + 4*~(A&w) + 7*~(A&~w)
//                              - 11*~(A|w) - 10*~(A|~w); }
//
// These are algebraic identities: `ww(113, 77) === 77`, `TA(89, 65) === 65`.
// They exist purely to stop constantFolding from seeing the real charcode in
// `s(ww(113, 77))`. Each is referentially transparent, so a call with all-literal
// arguments can be evaluated once and replaced by its result.
//
// Safety: the body must be exactly `return <expr>`, and `<expr>` may only touch
// the declared parameters, numeric literals and the pure arithmetic/bitwise
// operators — no identifiers from an enclosing scope, no calls, no member
// access, no assignment. That makes evaluation total and side-effect-free.
// ─────────────────────────────────────────────────────────────────────────────

const PURE_NUMERIC_BINARY_OPS = new Set([
  '+',
  '-',
  '*',
  '/',
  '%',
  '**',
  '&',
  '|',
  '^',
  '<<',
  '>>',
  '>>>',
  '==',
  '!=',
  '===',
  '!==',
  '<',
  '<=',
  '>',
  '>=',
]);
const PURE_NUMERIC_UNARY_OPS = new Set(['-', '+', '~', '!']);

/** Expression touching only `params`, numeric literals and pure operators. */
function isPureNumericExpr(node: t.Node, params: Set<string>, depth = 0): boolean {
  if (depth > MAX_PURE_DEPTH) return false;
  if (t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return true;
  if (t.isIdentifier(node)) return params.has(node.name);
  if (t.isUnaryExpression(node))
    return (
      PURE_NUMERIC_UNARY_OPS.has(node.operator) &&
      isPureNumericExpr(node.argument, params, depth + 1)
    );
  if (t.isBinaryExpression(node))
    return (
      PURE_NUMERIC_BINARY_OPS.has(node.operator) &&
      t.isExpression(node.left) &&
      isPureNumericExpr(node.left, params, depth + 1) &&
      isPureNumericExpr(node.right, params, depth + 1)
    );
  if (t.isLogicalExpression(node))
    return (
      isPureNumericExpr(node.left, params, depth + 1) &&
      isPureNumericExpr(node.right, params, depth + 1)
    );
  if (t.isConditionalExpression(node))
    return (
      isPureNumericExpr(node.test, params, depth + 1) &&
      isPureNumericExpr(node.consequent, params, depth + 1) &&
      isPureNumericExpr(node.alternate, params, depth + 1)
    );
  return false;
}

function passPureNumericFns(ast: t.File, log: Logger): number {
  type PureFn = { params: string[]; fn: (...args: number[]) => unknown };
  const pureFns = new Map<t.Identifier, PureFn>();
  const pureNames = new Set<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const declPaths = new Map<t.Identifier, any>();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function detect(name: string, node: t.Function, bindingId: t.Identifier, declPath: any) {
    // Params must all be plain identifiers (no defaults, rest or patterns).
    if (!node.params.every((p) => t.isIdentifier(p))) return;
    const paramNames = (node.params as t.Identifier[]).map((p) => p.name);
    // Locals accumulate into the scope as we walk leading declarations, so a
    // later initialiser may legally reference an earlier temporary.
    const scope = new Set(paramNames);

    // Expression-bodied arrow: `(A, w) => A & w`.
    if (!t.isBlockStatement(node.body)) {
      if (!t.isExpression(node.body) || !isPureNumericExpr(node.body, scope)) return;
      compile(name, paramNames, node.body as t.Expression, bindingId, declPath);
      return;
    }

    const stmts = node.body.body.filter((s) => !t.isEmptyStatement(s));
    if (stmts.length === 0) return;

    // Allow leading pure `var C = ~w;` temporaries before the return — the
    // bitwise-identity family often hoists a subexpression:
    //   function Xw(A, w, B) { var C = ~w; return 1*(A&w) + 3*(A&C) - 2*A + …; }
    const prelude: t.VariableDeclaration[] = [];
    for (const stmt of stmts.slice(0, -1)) {
      if (!t.isVariableDeclaration(stmt)) return;
      for (const d of stmt.declarations) {
        if (!t.isIdentifier(d.id)) return;
        // An uninitialised local is `undefined`; only pure initialisers qualify.
        if (d.init && !isPureNumericExpr(d.init, scope)) return;
        scope.add(d.id.name);
      }
      prelude.push(stmt);
    }

    const last = stmts[stmts.length - 1];
    if (!t.isReturnStatement(last) || !last.argument) return;
    if (!isPureNumericExpr(last.argument, scope)) return;

    compile(name, paramNames, last.argument as t.Expression, bindingId, declPath, prelude);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function compile(
    name: string,
    paramNames: string[],
    returnExpr: t.Expression,
    bindingId: t.Identifier,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    declPath: any,
    prelude: t.VariableDeclaration[] = []
  ) {
    // Compile once; the body is closed over its params and its own pure
    // temporaries only, so evaluation is total and side-effect-free.
    let fn: (...args: number[]) => unknown;
    try {
      const preludeSrc = prelude.map((d) => generate(d).code).join('\n');
      // eslint-disable-next-line no-new-func
      fn = new Function(
        ...paramNames,
        `"use strict"; ${preludeSrc} return (${generate(returnExpr).code});`
      ) as (...args: number[]) => unknown;
    } catch {
      return;
    }

    pureFns.set(bindingId, { params: paramNames, fn });
    pureNames.add(name);
    declPaths.set(bindingId, declPath);
  }

  traverse(ast, {
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id) return;
      let bindingId: t.Identifier | null | undefined;
      try {
        const b = p.scope.getBinding(id.name);
        // Reassigned function bindings are not trustworthy.
        if (!b?.constant) return;
        bindingId = b.identifier;
      } catch {
        return;
      }
      if (!bindingId) return;
      detect(id.name, p.node, bindingId, p);
    },
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;
      if (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) return;
      let bindingId: t.Identifier | null | undefined;
      try {
        const b = p.scope.getBinding(id.name);
        if (!b?.constant) return;
        bindingId = b.identifier;
      } catch {
        return;
      }
      if (!bindingId) return;
      detect(id.name, init as t.Function, bindingId, p);
    },
  });

  if (pureFns.size === 0) {
    log.pass('b01c', 'pureNumericFns', 0);
    return 0;
  }

  let n = 0;
  const used = new Set<t.Identifier>();
  traverse(ast, {
    CallExpression: {
      // Exit order so nested calls — s(ww(TA(1,2), 3)) — resolve inside-out.
      exit(p) {
        const callee = p.node.callee;
        if (!t.isIdentifier(callee) || !pureNames.has(callee.name)) return;

        let bindingId: t.Identifier | null | undefined;
        try {
          bindingId = p.scope.getBinding(callee.name)?.identifier;
        } catch {
          return;
        }
        if (!bindingId) return;
        const def = pureFns.get(bindingId);
        if (!def) return;

        // Every argument must be a literal we can evaluate right now.
        const args: unknown[] = [];
        for (const a of p.node.arguments) {
          if (!t.isExpression(a)) return;
          const r = evalPure(a as t.Expression);
          if (!r.ok) return;
          args.push(r.value);
        }
        // Missing trailing args are `undefined` — the identities rely on that
        // (`~(A & ~A)` ignores `w`), so pad rather than bail.
        while (args.length < def.params.length) args.push(undefined);

        let value: unknown;
        try {
          value = def.fn(...(args as number[]));
        } catch {
          return;
        }
        const repl = toNode(value);
        if (!repl) return;

        p.replaceWith(repl);
        used.add(bindingId);
        n++;
      },
    },
  });

  log.pass('b01c', 'pureNumericFns', n, 'calls inlined', `${pureFns.size} fns detected`);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B01d: Global-object prefix removal
//
//   var p = window;
//   var I = p.Math.ceil(287.25), K = p.parseInt("12");
//
// `p.Math.ceil` is `Math.ceil`, but every pass that recognises builtins matches
// on the *name*, so the alias makes all of them miss. Rewriting `p.X` to `X`
// when `p` is a write-once alias of the global object restores those matches
// and, because the global object is the scope root, is semantically a no-op for
// the builtins listed in ALIASABLE_ROOTS / ALIASABLE_GLOBALS.
//
// Only known-safe builtin names are unwrapped; `p.location`, `p.document` and
// friends keep their prefix so nothing environment-bound silently changes shape.
// ─────────────────────────────────────────────────────────────────────────────

function passGlobalObjectAlias(ast: t.File, log: Logger): number {
  const aliasNames = new Set<string>();

  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !t.isIdentifier(init)) return;
      if (!GLOBAL_OBJECT_NAMES.has(init.name)) return;
      // The global name itself must be the real one, not a local shadow.
      try {
        if (p.scope.getBinding(init.name)) return;
      } catch {
        return;
      }
      let binding: { constant?: boolean } | null | undefined;
      try {
        binding = p.scope.getBinding(id.name);
      } catch {
        return;
      }
      if (!binding?.constant) return;
      aliasNames.add(id.name);
    },
  });

  // Rewrite by mutating the parent in place rather than calling replaceWith().
  // replaceWith() requeues the replacement node for traversal and invalidates
  // the surrounding scope, and doing that once per member access on a bundle
  // this size drove Babel into repeated scope rebuilds that never finished.
  // Collect first, mutate after, and consult scope only while collecting.
  const rewrites: Array<{ parent: t.Node; key: string; name: string }> = [];

  traverse(ast, {
    MemberExpression(p) {
      const { object, property, computed } = p.node;
      if (computed || !t.isIdentifier(object) || !t.isIdentifier(property)) return;
      // `globalThis.Math` is `Math` just as a `var p = globalThis` alias is.
      if (!aliasNames.has(object.name) && !(GLOBAL_OBJECT_NAMES.has(object.name) && !p.scope.getBinding(object.name))) return;
      // Only unwrap names we know are plain builtins.
      if (!ALIASABLE_ROOTS.has(property.name) && !ALIASABLE_GLOBALS.has(property.name)) return;
      // A host API may be absent: only `typeof` reads it the same way by name.
      if (!GUARANTEED_GLOBALS.has(property.name) && !p.parentPath.isUnaryExpression({ operator: 'typeof' })) return;
      // Never rewrite the alias in a write position (`p.Math = …`).
      if (p.parentPath?.isAssignmentExpression() && p.key === 'left') return;
      if (p.parentPath?.isUpdateExpression()) return;
      if (p.parentPath?.isUnaryExpression({ operator: 'delete' })) return;
      // Re-binding the builtin name locally would change meaning.
      try {
        if (p.scope.getBinding(property.name)) return;
      } catch {
        return;
      }
      const parent = p.parentPath?.node;
      if (!parent || typeof p.key !== 'string') return;
      rewrites.push({ parent, key: p.key, name: property.name });
    },
  });

  let n = 0;
  for (const { parent, key, name } of rewrites) {
    const holder = parent as unknown as Record<string, unknown>;
    const current = holder[key];
    if (!current || !t.isMemberExpression(current as t.Node)) continue;
    holder[key] = t.identifier(name);
    n++;
  }

  log.pass('b01d', 'globalAlias', n, undefined, `${aliasNames.size} global aliases`);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B10b: Pure native call folding
//
// Once B01b/B01d have restored real builtin names, hundreds of call sites turn
// out to be constants computed at init purely to feed opaque predicates:
//
//   var I = Math.ceil(287.25), K = Math.floor(440.16), r = Number(-115);
//   if (2 * (FA & C) + … < -659) { … }        // ← decided by those constants
//
// Folding them is what lets constantFolding collapse the predicate and deadCode
// delete the dead branch. Restricted to a whitelist of deterministic, pure
// functions over already-literal arguments — `Math.random` is excluded, and any
// result that is not a finite primitive is left alone.
// ── B03c: Function constructor with a literal body ───────────────────────────

/** Free (unbound) identifier names of a parsed program, params excluded. */
function freeNamesOfProgram(body: t.Program, params: string[]): Set<string> {
  const holder = freshProgram(t.file(body));
  const out = new Set(Object.keys(holder.scope.globals));
  for (const p of params) out.delete(p);
  return out;
}

/** Names a program body declares at its own top level (`var` / function). */
function topLevelDeclaredNames(body: t.Program): Set<string> {
  const out = new Set<string>();
  for (const stmt of body.body) {
    if (t.isFunctionDeclaration(stmt) && stmt.id) out.add(stmt.id.name);
    else if (t.isVariableDeclaration(stmt))
      for (const d of stmt.declarations)
        walk(d.id, (x) => {
          if (t.isIdentifier(x)) out.add(x.name);
        });
  }
  return out;
}

/**
 * `Function("a", "b", "<source>")` builds a function at run time out of text,
 * which hides a whole program from every AST pass: such a bundle parses as one
 * string literal, and all of the passes below report zero because there is
 * nothing but that literal to look at. When every argument is a literal the
 * same function can be written out statically, without executing anything:
 *
 *   Function("p", "return p.x")(arg)   →   (function (p) { return p.x })(arg)
 *
 * Scope is what makes this delicate. A `Function` body is compiled in the
 * *global* scope and in sloppy mode, so it cannot see the locals around the
 * call, and its own top-level `var`s land on the global object. The rewrite is
 * therefore taken only when neither difference is observable: no free name of
 * the body may resolve to a binding at the call site (otherwise an inlined name
 * would capture a local the original could not reach), nothing outside may
 * reference a name the body declares at top level (otherwise a global it used
 * to publish would become a local), and the surrounding code must be sloppy.
 */
// ── the original source text ─────────────────────────────────────────────────

// (SourceFacts, noteSourceText: see ./analysis — shared with ./cff)

/** js-confuser's integrity hash (cyrb53), as its integrityTemplate defines it. */
function cyrb53(str: string, seed: number): number {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

// ── B20: js-confuser locks ───────────────────────────────────────────────────

/**
 * Two of js-confuser's protections test the program's own source text, which
 * deobfuscating necessarily changes — left alone, the recovered program would
 * hang where the original did not. Each is resolved only where the original
 * text proves what the test returned:
 *
 *   • anti-beautify: `new RegExp("\n").test(F)` for a function F — the source
 *     F was created from contains no newline (every recorded text is
 *     newline-free), so the original test was `false`.
 *   • integrity: `function L() { if ((L.K || (L.K = HASH(F, SEED))) === C)
 *     { BODY } else { … } }` — F's original text, with js-confuser's
 *     sensitivity characters removed, hashes (cyrb53, SEED) to exactly C, so
 *     the original always took BODY. L becomes BODY; L.K was only ever read
 *     inside L, by the test that is gone. (A different HASH agreeing with
 *     cyrb53 on this one input is a 2^-53 coincidence.)
 */
function passLocks(ast: t.File, log: Logger): number {
  const facts = getSourceFacts();
  if (!facts) {
    log.pass('b20', 'locks', 0, undefined, 'no source record');
    return 0;
  }
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const once = writeOnceFacts(program);
  /** The function a name holds wherever it is read (declaration or write-once expression). */
  const fixedFunction = (b: Binding | undefined): t.Function | null => {
    if (!b || dyn.observesBinding(b)) return null;
    if (b.path.isFunctionDeclaration()) return b.constantViolations.length ? null : b.path.node;
    const v = once.get(b)?.value;
    return t.isFunctionExpression(v) || t.isArrowFunctionExpression(v) ? v : null;
  };
  const regexpCtor = (c: t.Node, scope: NodePath['scope']): boolean =>
    (t.isIdentifier(c, { name: 'RegExp' }) && !scope.getBinding('RegExp')) ||
    (t.isMemberExpression(c) && t.isIdentifier(c.object, { name: 'globalThis' }) && !scope.getBinding('globalThis') && staticMemberKey(c) === 'RegExp');
  let lines = 0;
  let locks = 0;

  // anti-beautify
  if (facts.newlineFree)
    program.traverse({
      CallExpression(p) {
        const c = p.node.callee;
        if (!t.isMemberExpression(c) || staticMemberKey(c) !== 'test' || p.node.arguments.length !== 1) return;
        // the regex in place, or in a variable holding just it (used only here)
        let re: t.Node = c.object;
        if (t.isIdentifier(re)) {
          const rb = p.scope.getBinding(re.name);
          const v = rb && !dyn.observesBinding(rb) && rb.referencePaths.length === 1 ? once.get(rb)?.value : null;
          if (!v) return;
          re = v;
        }
        const lf =
          (t.isNewExpression(re) &&
            regexpCtor(re.callee, p.scope) &&
            re.arguments.length >= 1 &&
            t.isStringLiteral(re.arguments[0]) &&
            (re.arguments[0].value === '\n' || re.arguments[0].value === '\\n') &&
            re.arguments.slice(1).every((a) => t.isStringLiteral(a))) ||
          (t.isRegExpLiteral(re) && re.pattern === '\\n');
        const arg = p.node.arguments[0];
        if (!lf || !t.isIdentifier(arg)) return;
        const b = p.scope.getBinding(arg.name);
        if (!fixedFunction(b)) return;
        // F's own toString must be the built-in one: F is only ever called or
        // tested here, never given properties
        if (!b!.referencePaths.every((r) => r.node === arg || (r.parentPath?.isCallExpression() && r.parentPath.node.callee === r.node))) return;
        p.replaceWith(t.booleanLiteral(false));
        lines++;
      },
    });

  // strict-mode probe (js-confuser's StrictModeTemplate): `delete arr.length`
  // on an array — whose `length` is never configurable — is `false` in sloppy
  // code (it throws only in strict code).
  let probes = 0;
  const strictAt = (q: NodePath): boolean => {
    if (program.node.sourceType === 'module' || program.node.directives.some((d) => d.value.value === 'use strict')) return true;
    for (let x: NodePath | null = q; x; x = x.parentPath) {
      if (x.isClass()) return true;
      if (x.isFunction() && t.isBlockStatement(x.node.body) && x.node.body.directives.some((d) => d.value.value === 'use strict')) return true;
    }
    return false;
  };
  program.traverse({
    UnaryExpression(p) {
      if (p.node.operator !== 'delete' || !t.isMemberExpression(p.node.argument)) return;
      const m = p.node.argument;
      if (staticMemberKey(m) !== 'length' || !t.isIdentifier(m.object) || strictAt(p)) return;
      const b = p.scope.getBinding(m.object.name);
      if (!b || dyn.observesBinding(b) || !t.isArrayExpression(once.get(b)?.value)) return;
      p.replaceWith(t.booleanLiteral(false));
      probes++;
    },
  });

  // integrity
  const parsedTexts = new Map<string, t.File | null>();
  const originalText = (name: string): string | null => {
    let found: string | null = null;
    let count = 0;
    for (const text of facts.texts) {
      if (!text.includes(name)) continue;
      if (!parsedTexts.has(text)) {
        try {
          parsedTexts.set(text, parser.parse(text, { sourceType: 'script', allowReturnOutsideFunction: true }) as unknown as t.File);
        } catch {
          parsedTexts.set(text, null);
        }
      }
      const file = parsedTexts.get(text);
      if (!file) continue;
      // top-level declarations only: F sits at the top of its program (or of
      // the pack wrapper's body); renamed locals elsewhere may share its name
      const tops = file.program.body.flatMap((st) => {
        // the pack wrapper: `(function (G) { … })(…)` as the whole text
        const call = t.isExpressionStatement(st) ? st.expression : null;
        const fn = t.isCallExpression(call) && t.isFunctionExpression(call.callee) ? call.callee : null;
        return fn ? [st, ...fn.body.body] : [st];
      });
      for (const n of tops)
        if (t.isFunctionDeclaration(n) && n.id?.name === name && n.start != null && n.end != null) {
          count++;
          found = text.slice(n.start, n.end);
        }
    }
    return count === 1 ? found : null;
  };
  const SENSITIVITY = / |\n|;|,|\{|\}|\(|\)|\.|\[|\]/g;
  program.traverse({
    FunctionDeclaration(p) {
      const L = p.node;
      if (!L.id || L.async || L.generator) return;
      const lb = p.parentPath.scope.getBinding(L.id.name);
      if (!lb || lb.constantViolations.length || dyn.observesBinding(lb)) return;
      // `var H = <cache>; if (H === C)`, or `if (<cache> === C)`
      let body = L.body.body;
      let cache: t.Node | null = null;
      let hName: string | null = null;
      if (body.length === 2 && t.isVariableDeclaration(body[0]) && body[0].declarations.length === 1 && t.isIdentifier(body[0].declarations[0].id)) {
        cache = body[0].declarations[0].init ?? null;
        hName = body[0].declarations[0].id.name;
        body = body.slice(1);
      }
      if (body.length !== 1 || !t.isIfStatement(body[0]) || !body[0].alternate) return;
      const test = body[0].test;
      if (!t.isBinaryExpression(test) || (test.operator !== '===' && test.operator !== '==')) return;
      const [lhs, rhs] = t.isNumericLiteral(test.right) ? [test.left, test.right] : [test.right, test.left];
      if (!t.isNumericLiteral(rhs)) return;
      if (hName !== null ? !t.isIdentifier(lhs, { name: hName }) : (cache = lhs, false)) return;
      // <cache>: L.K || (L.K = HASH(F, SEED))
      if (!t.isLogicalExpression(cache, { operator: '||' })) return;
      const k1 = cache.left;
      const set = cache.right;
      const selfKey = (m: t.Node): string | null => (t.isMemberExpression(m) && t.isIdentifier(m.object, { name: L.id!.name }) ? staticMemberKey(m) : null);
      const K = selfKey(k1);
      if (K === null || !t.isAssignmentExpression(set, { operator: '=' }) || selfKey(set.left) !== K) return;
      const call = set.right;
      if (!t.isCallExpression(call) || call.arguments.length !== 2 || !t.isIdentifier(call.arguments[0]) || !t.isNumericLiteral(call.arguments[1])) return;
      const F = call.arguments[0].name;
      const seed = call.arguments[1].value;
      const fb = p.scope.getBinding(F);
      if (!fb || !fb.path.isFunctionDeclaration() || fb.constantViolations.length) return;
      const holder = fb.path.parentPath;
      const atTop = holder.isProgram() || (holder.isBlockStatement() && holder.parentPath?.isFunctionExpression() && holder.parentPath.parentPath?.isCallExpression());
      if (!atTop) return;
      // outside L, L is only called (a tagged template calls its tag too):
      // nothing else can read L.K
      if (!lb.referencePaths.every((r) => pathWithin(r, L) || (r.parentPath?.isCallExpression() && r.parentPath.node.callee === r.node) || (r.parentPath?.isTaggedTemplateExpression() && r.parentPath.node.tag === r.node))) return;
      const text = originalText(F);
      if (text === null || cyrb53(text.replace(SENSITIVITY, ''), seed) !== rhs.value) return;
      const taken = body[0].consequent;
      L.body = t.blockStatement(t.isBlockStatement(taken) ? taken.body : [taken], L.body.directives);
      locks++;
    },
  });
  // native-function checks (js-confuser's NativeFunctionTemplate):
  //   function N() { … "{ [native code] }" … getOwnPropertyDescriptor(fn, "toString") …
  //     if (args.length === 1) return check(args[0]);
  //     else if (args.length === 2) { …; return fn.bind(object); } }
  // N(f) is f, and N(o, k) is o[k].bind(o), whenever the function checked is
  // a genuine built-in — the engine assumes the host's built-ins are genuine
  // throughout (it evaluates decoders with them). Calling the bound result
  // calls o[k] on o: `N(o, k)(…)` → `o[k](…)`, reading o, then o[k], then the
  // arguments, in the original order.
  let natives = 0;
  {
    const fresh = locks + lines ? freshProgram(ast) : program;
    fresh.traverse({
      FunctionDeclaration(p) {
        const fn = p.node;
        if (!fn.id || fn.params.length || fn.async || fn.generator) return;
        let marker = false;
        let descriptor = false;
        t.traverseFast(fn.body, (n) => {
          if (t.isStringLiteral(n, { value: '{ [native code] }' })) marker = true;
          if (t.isIdentifier(n, { name: 'getOwnPropertyDescriptor' }) || t.isStringLiteral(n, { value: 'getOwnPropertyDescriptor' })) descriptor = true;
        });
        if (!marker || !descriptor) return;
        const last = fn.body.body[fn.body.body.length - 1];
        const bindsLast =
          t.isIfStatement(last) &&
          t.isIfStatement(last.alternate) &&
          (() => {
            const alt = last.alternate.consequent;
            const r = t.isBlockStatement(alt) ? alt.body[alt.body.length - 1] : alt;
            return t.isReturnStatement(r) && t.isCallExpression(r.argument) && t.isMemberExpression(r.argument.callee) && staticMemberKey(r.argument.callee) === 'bind';
          })();
        if (!bindsLast) return;
        const b = p.parentPath.scope.getBinding(fn.id.name);
        if (!b || b.constantViolations.length || dyn.observesBinding(b)) return;
        const sites = b.referencePaths.map((r) => r.parentPath);
        if (!sites.every((c) => c?.isCallExpression() && t.isIdentifier(c.node.callee, { name: fn.id!.name }) && (c.node.arguments.length === 1 || c.node.arguments.length === 2) && c.node.arguments.every((a) => !t.isSpreadElement(a))))
          return;
        for (const c of sites as NodePath<t.CallExpression>[]) {
          const args = c.node.arguments as t.Expression[];
          if (args.length === 1) {
            c.replaceWith(args[0]);
          } else {
            const [o, k] = args;
            const member = t.memberExpression(o, k, true);
            const outer = c.parentPath;
            if (outer?.isCallExpression() && outer.node.callee === c.node) {
              outer.node.callee = member; // o is still evaluated once
            } else if (t.isIdentifier(o)) {
              // `o[k].bind(o)` reads o twice: only a plain variable reads alike
              c.replaceWith(t.callExpression(t.memberExpression(member, t.identifier('bind')), [t.cloneNode(o, true)]));
            } else continue;
          }
          natives++;
        }
      },
    });
  }
  // What an unlocked lock leaves: `function L() { return F(...arguments); }`.
  // Called plainly, L(a, b) runs F(a, b) with the same arguments, and F is
  // called plainly either way — so each call can name F itself, provided F
  // means the same function at the call site.
  let forwards = 0;
  {
    const fresh = freshProgram(ast);
    fresh.traverse({
      FunctionDeclaration(p) {
        const L = p.node;
        const [st, ...rest] = L.body.body;
        if (!L.id || L.params.length || L.async || L.generator || rest.length || !t.isReturnStatement(st)) return;
        const call = st.argument;
        if (!t.isCallExpression(call) || !t.isIdentifier(call.callee) || call.arguments.length !== 1) return;
        const spread = call.arguments[0];
        if (!t.isSpreadElement(spread) || !t.isIdentifier(spread.argument, { name: 'arguments' })) return;
        const F = call.callee.name;
        const fb = p.scope.getBinding(F);
        const lb = p.parentPath.scope.getBinding(L.id.name);
        if (!fb || !fb.path.isFunctionDeclaration() || fb.constantViolations.length || !lb || lb.constantViolations.length) return;
        if (dyn.observesBinding(lb) || dyn.observesBinding(fb)) return;
        // (a tagged template is a plain call of its tag; its strings object
        // belongs to the site, whichever function is the tag)
        const calls = lb.referencePaths.map((r) => r.parentPath);
        const site = (c: NodePath | null, i: number): boolean =>
          !!c &&
          ((c.isCallExpression() && c.node.callee === lb.referencePaths[i].node) || (c.isTaggedTemplateExpression() && c.node.tag === lb.referencePaths[i].node)) &&
          c.scope.getBinding(F) === fb;
        if (!calls.every(site)) return;
        for (const c of calls as NodePath<t.CallExpression | t.TaggedTemplateExpression>[]) {
          if (c.isCallExpression()) c.node.callee = t.identifier(F);
          else (c.node as t.TaggedTemplateExpression).tag = t.identifier(F);
        }
        p.remove();
        forwards++;
      },
    });
  }
  const total = lines + locks + natives + forwards + probes;
  log.pass('b20', 'locks', total, undefined, `${lines} newline tests · ${locks} integrity locks · ${natives} native checks · ${forwards} forwarders · ${probes} strict probes`);
  return total;
}

function passFunctionConstructor(ast: t.File, log: Logger): number {
  let n = 0;
  let shadowed = 0;
  let strictSkipped = 0;
  let publishes = 0;

  const program = freshProgram(ast);
  const programStrict =
    program.node.sourceType === 'module' ||
    program.node.directives.some((d) => d.value.value === 'use strict');

  /** Is the code around this call strict? Then an inlined body would be too. */
  const inStrictCode = (p: NodePath): boolean => {
    if (programStrict) return true;
    for (let cur: NodePath | null = p; cur; cur = cur.parentPath) {
      const node = cur.node;
      if (t.isFunction(node) && t.isBlockStatement(node.body))
        if (node.body.directives.some((d) => d.value.value === 'use strict')) return true;
      if (t.isClassDeclaration(node) || t.isClassExpression(node)) return true; // class bodies are strict
    }
    return false;
  };

  const candidates: Array<{ path: NodePath; fn: t.FunctionExpression }> = [];

  program.traverse({
    'CallExpression|NewExpression'(p: NodePath) {
      const node = p.node as t.CallExpression | t.NewExpression;
      if (!t.isIdentifier(node.callee, { name: 'Function' })) return;
      if (p.scope.hasBinding('Function', { noGlobals: true })) return;
      const args = node.arguments;
      if (args.length === 0 || !args.every((a) => t.isStringLiteral(a))) return;

      const paramNames = args
        .slice(0, -1)
        .flatMap((a) => (a as t.StringLiteral).value.split(','))
        .map((x) => x.trim())
        .filter((x) => x.length > 0);
      if (!paramNames.every((x) => IDENTIFIER_NAME_RE.test(x) && !RESERVED.has(x))) return;
      if (new Set(paramNames).size !== paramNames.length) return;

      if (inStrictCode(p)) {
        strictSkipped++;
        return;
      }

      let bodyProgram: t.Program;
      try {
        bodyProgram = parser.parse((args[args.length - 1] as t.StringLiteral).value, {
          sourceType: 'script',
          allowReturnOutsideFunction: true,
        }).program;
        noteSourceText((args[args.length - 1] as t.StringLiteral).value);
      } catch {
        return; // not a complete program: leave the literal alone
      }

      const free = freeNamesOfProgram(bodyProgram, paramNames);
      if ([...free].some((name) => p.scope.hasBinding(name, { noGlobals: true }))) {
        shadowed++;
        return;
      }

      // Would a global the body publishes stop being visible outside?
      const declared = topLevelDeclaredNames(bodyProgram);
      if (declared.size > 0) {
        let read = false;
        program.traverse({
          Identifier(ip) {
            if (read || !declared.has(ip.node.name) || !ip.isReferencedIdentifier()) return;
            if (!pathWithin(ip, node)) read = true;
          },
        });
        if (read) {
          publishes++;
          return;
        }
      }

      candidates.push({
        path: p,
        fn: t.functionExpression(
          null,
          paramNames.map((x) => t.identifier(x)),
          t.blockStatement(bodyProgram.body, bodyProgram.directives)
        ),
      });
      p.skip(); // the recovered body is processed by the passes that follow
    },
  });

  for (const { path, fn } of candidates) {
    try {
      path.replaceWith(fn);
      n++;
    } catch {
      /* detached by an earlier replacement */
    }
  }

  const detail = [
    shadowed > 0 ? `${shadowed} would shadow` : null,
    publishes > 0 ? `${publishes} publish globals` : null,
    strictSkipped > 0 ? `${strictSkipped} strict` : null,
  ]
    .filter(Boolean)
    .join(', ');
  log.pass('b03c', 'functionCtor', n, 'unwrapped', detail || undefined);
  return n;
}

// ── B03d: direct eval of a literal expression ────────────────────────────────

/**
 * A direct `eval("<expression>")` is how an obfuscator reaches the real global
 * object (`eval("this")`) or writes a local through a name the AST never shows
 * (`eval("flag = true")`). The call costs far more than it looks: because a
 * direct `eval` resolves names against its own scope chain, every binding of
 * every enclosing scope becomes observable by name, and the binding-aware
 * passes decline to touch any of them.
 *
 * When the argument is a literal that parses to exactly one expression, that
 * expression can replace the call verbatim — a direct `eval` evaluates in the
 * caller's scope with the caller's `this`, and the completion value of a single
 * expression statement is what it returns. Anything else (declarations, several
 * statements) is left alone, since it would publish bindings of its own.
 */
function passEvalLiteral(ast: t.File, log: Logger): number {
  let n = 0;
  let notExpression = 0;
  traverse(ast, {
    CallExpression(p) {
      if (!t.isIdentifier(p.node.callee, { name: 'eval' })) return;
      if (p.scope.hasBinding('eval', { noGlobals: true })) return;
      if (p.node.arguments.length !== 1) return;
      const arg = p.node.arguments[0];
      if (!t.isStringLiteral(arg)) return;

      let body: t.Statement[];
      try {
        body = parser.parse(arg.value, { sourceType: 'script' }).program.body;
        noteSourceText(arg.value);
      } catch {
        return;
      }
      if (body.length !== 1 || !t.isExpressionStatement(body[0])) {
        notExpression++;
        return;
      }
      const expr = body[0].expression;
      // A nested `eval` / `with` would re-introduce exactly what this removes.
      if (hasDynamicScope(expr)) return;
      p.replaceWith(expr);
      n++;
    },
  });
  log.pass(
    'b03d',
    'evalLiteral',
    n,
    'inlined',
    notExpression > 0 ? `${notExpression} not a lone expression` : undefined
  );
  return n;
}

// ── B03e: reduced-global-function (RGF) embedding ────────────────────────────

/**
 * Is `fn` the identity-with-default helper `function (x = <truthy>) { return x }`,
 * so that calling it with no argument yields a statically truthy value?
 */
function returnsTruthyDefault(fn: t.Function): boolean {
  const p0 = fn.params[0];
  if (!t.isAssignmentPattern(p0) || !t.isIdentifier(p0.left)) return false;
  const def = evalPure(p0.right as t.Expression);
  if (!def.ok || !def.value) return false;
  const body = t.isBlockStatement(fn.body)
    ? fn.body.body.filter((s) => !t.isEmptyStatement(s))
    : [t.returnStatement(fn.body)];
  return (
    body.length === 1 &&
    t.isReturnStatement(body[0]) &&
    t.isIdentifier(body[0].argument, { name: p0.left.name })
  );
}

/**
 * js-confuser's RGF transform embeds a function as source text and recovers it
 * at run time through a flag-guarded `eval`:
 *
 *   function flag(x = true) { return x }
 *   var integrity = flag();                         // statically true
 *   var box = [ rgfEval("function F(){ …real body… } F;") ];
 *   function rgfEval(code) { if (integrity) return eval(code); }
 *   (function () { return box[0].apply(this, [box, arguments]); })();
 *
 * `rgfEval(src)` returns `eval(src)`, whose completion value is the function `F`
 * (the trailing `F;` expression). When the guard is provably truthy and the
 * embedded source is `function F(){…} F;` whose body reaches nothing but
 * globals, the call can be written back as the function expression itself —
 * the same value, built in the current scope instead of eval's. No code runs,
 * and the eval, the wrapper and the guard are left for dead-code removal.
 */
function passRgf(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);

  /**
   * Is `name` a binding written exactly once, to a provably truthy value? The
   * value is read straight off the declarator (its initialiser is a call, which
   * writeOnceFacts excludes) — either a truthy literal, or a no-argument call of
   * the identity-with-truthy-default helper.
   */
  const truthyBinding = (name: string, scope: NodePath['scope']): boolean => {
    const binding = scope.getBinding(name);
    if (!binding || binding.constantViolations.length > 0) return false;
    if (!binding.path.isVariableDeclarator()) return false;
    const init = binding.path.node.init;
    if (!init) return false;
    const lit = evalPure(init as t.Expression);
    if (lit.ok) return !!lit.value;
    if (t.isCallExpression(init) && t.isIdentifier(init.callee) && init.arguments.length === 0) {
      const hb = binding.path.scope.getBinding(init.callee.name);
      const hp = hb?.path;
      if (hp?.isFunctionDeclaration() && returnsTruthyDefault(hp.node)) return true;
    }
    return false;
  };

  // ── locate guarded-eval wrappers: function W(code){ if (FLAG) return eval(code); }
  const wrappers = new Set<string>();
  const flagNames = new Set<string>();
  const helperNames = new Set<string>();
  program.traverse({
    FunctionDeclaration(p) {
      const fn = p.node;
      if (!fn.id || fn.params.length !== 1 || !t.isIdentifier(fn.params[0])) return;
      const param = fn.params[0].name;
      const stmts = fn.body.body.filter((s) => !t.isEmptyStatement(s));
      if (stmts.length !== 1 || !t.isIfStatement(stmts[0])) return;
      const iff = stmts[0];
      if (iff.alternate || !t.isIdentifier(iff.test)) return;
      const cons = t.isBlockStatement(iff.consequent)
        ? iff.consequent.body.filter((s) => !t.isEmptyStatement(s))
        : [iff.consequent];
      if (cons.length !== 1 || !t.isReturnStatement(cons[0])) return;
      const ret = cons[0].argument;
      if (
        !t.isCallExpression(ret) ||
        !t.isIdentifier(ret.callee, { name: 'eval' }) ||
        ret.arguments.length !== 1 ||
        !t.isIdentifier(ret.arguments[0], { name: param })
      )
        return;
      if (p.scope.hasBinding('eval', { noGlobals: true })) return;
      if (!truthyBinding(iff.test.name, p.scope)) return;
      const b = p.parentPath.scope.getBinding(fn.id.name);
      if (b && b.path.node === fn) {
        wrappers.add(fn.id.name);
        // The guard binding, and the helper that seeds it, become dead once the
        // wrapper's calls are gone — track them so they can be swept with it.
        flagNames.add(iff.test.name);
        const fb = p.scope.getBinding(iff.test.name);
        const init = fb?.path.isVariableDeclarator() ? fb.path.node.init : null;
        if (init && t.isCallExpression(init) && t.isIdentifier(init.callee))
          helperNames.add(init.callee.name);
      }
    },
  });

  if (wrappers.size === 0) {
    log.pass('b03e', 'rgf', 0, 'embeddings', 'no guarded-eval wrapper');
    return 0;
  }

  // ── rewrite each wrapper call whose literal is a `function F(){…} F;` embedding
  let n = 0;
  let notEmbedding = 0;
  const jobs: Array<{ path: NodePath<t.CallExpression>; fn: t.FunctionExpression }> = [];
  program.traverse({
    CallExpression(p) {
      const callee = p.node.callee;
      if (!t.isIdentifier(callee) || !wrappers.has(callee.name)) return;
      if (p.scope.getBinding(callee.name)?.scope !== program.scope && !wrappers.has(callee.name))
        return;
      if (p.node.arguments.length !== 1 || !t.isStringLiteral(p.node.arguments[0])) return;

      let body: t.Statement[];
      try {
        body = parser.parse(p.node.arguments[0].value, { sourceType: 'script' }).program.body;
        noteSourceText(p.node.arguments[0].value);
      } catch {
        return;
      }
      const decls = body.filter((s) => !t.isEmptyStatement(s));
      // Exactly: one function declaration, then a bare reference to its name.
      if (decls.length !== 2) {
        notEmbedding++;
        return;
      }
      const [decl, tail] = decls;
      if (
        !t.isFunctionDeclaration(decl) ||
        !decl.id ||
        !t.isExpressionStatement(tail) ||
        !t.isIdentifier(tail.expression, { name: decl.id.name })
      ) {
        notEmbedding++;
        return;
      }
      const prog = t.program([decl]);
      const free = freeNamesOfProgram(prog, []);
      // A free name that binds to a local at the call site would be captured.
      if ([...free].some((name) => name !== decl.id!.name && p.scope.hasBinding(name, { noGlobals: true }))) {
        return;
      }
      jobs.push({
        path: p,
        fn: t.functionExpression(decl.id, decl.params, decl.body, decl.generator, decl.async),
      });
      p.skip();
    },
  });

  for (const { path, fn } of jobs) {
    try {
      path.replaceWith(fn);
      n++;
    } catch {
      /* detached by an earlier replacement */
    }
  }

  // Sweep the machinery the rewrites left dead: the wrapper (which still holds
  // the only `eval`, and would otherwise keep every binding pass disabled), the
  // guard binding and the helper that seeded it. Each is removed only once its
  // binding has no remaining references, so nothing live is cut.
  let removed = 0;
  if (n > 0) {
    const dead = new Set([...wrappers, ...flagNames, ...helperNames]);
    // Re-crawl each round: removing one declaration drops the reference that
    // kept the next alive, and binding tables only reflect that after a crawl.
    for (let changed = true; changed; ) {
      changed = false;
      const fresh = freshProgram(ast);
      fresh.traverse({
        'FunctionDeclaration|VariableDeclarator'(dp: NodePath) {
          const id = (dp.node as t.FunctionDeclaration | t.VariableDeclarator).id;
          if (!t.isIdentifier(id) || !dead.has(id.name)) return;
          const b = (dp.isFunctionDeclaration() ? dp.parentPath! : dp).scope.getBinding(id.name);
          if (!b || b.path.node !== dp.node || b.referencePaths.length > 0) return;
          try {
            if (dp.isVariableDeclarator() && (dp.parentPath.node as t.VariableDeclaration).declarations.length === 1)
              dp.parentPath.remove();
            else dp.remove();
            removed++;
            changed = true;
          } catch {
            /**/
          }
        },
      });
    }
  }

  log.pass(
    'b03e',
    'rgf',
    n,
    'embeddings',
    [notEmbedding > 0 ? `${notEmbedding} not F(){}F;` : null, removed > 0 ? `${removed} dead removed` : null]
      .filter(Boolean)
      .join(', ') || undefined
  );
  return n + removed;
}

// ── B03f: RGF thunk calling convention ───────────────────────────────────────

/**
 * The embedding box left by B03e: `var BOX = [function () { var [S, A] =
 * arguments; function REPL(…) {…} return REPL.apply(this, A); }]`. Returns the
 * inner REPL function and the box binding when the node has exactly that shape.
 */
function matchRgfEmbedded(embedded: t.Node | null): t.FunctionDeclaration | null {
  if (!embedded) return null;
  if (!t.isFunctionExpression(embedded) || embedded.params.length !== 0 || embedded.async || embedded.generator)
    return null;
  const body = embedded.body.body.filter((s) => !t.isEmptyStatement(s));
  if (body.length !== 3) return null;
  const [destructure, decl, ret] = body;
  // var [S, A] = arguments;
  if (!t.isVariableDeclaration(destructure) || destructure.declarations.length !== 1) return null;
  const d0 = destructure.declarations[0];
  if (
    !t.isArrayPattern(d0.id) ||
    d0.id.elements.length !== 2 ||
    !d0.id.elements.every((e) => t.isIdentifier(e)) ||
    !t.isIdentifier(d0.init, { name: 'arguments' })
  )
    return null;
  const argsName = (d0.id.elements[1] as t.Identifier).name;
  // function REPL(...) { ... }
  if (!t.isFunctionDeclaration(decl) || !decl.id) return null;
  // return REPL.apply(this, A);
  if (!t.isReturnStatement(ret) || !t.isCallExpression(ret.argument)) return null;
  const call = ret.argument;
  if (
    !t.isMemberExpression(call.callee) ||
    !t.isIdentifier(call.callee.object, { name: decl.id.name }) ||
    !t.isIdentifier(call.callee.property, { name: 'apply' }) ||
    call.arguments.length !== 2 ||
    !t.isThisExpression(call.arguments[0]) ||
    !t.isIdentifier(call.arguments[1], { name: argsName })
  )
    return null;
  // REPL must not refer to its own mangled name (no self-recursion to rewrite),
  // nor to the destructured `self`/`args` of the embedding.
  const banned = new Set([decl.id.name, argsName, (d0.id.elements[0] as t.Identifier).name]);
  let leaks = false;
  walk(decl.body, (node, parent) => {
    if (leaks) return false;
    if (t.isIdentifier(node) && parent && t.isReferenced(node, parent) && banned.has(node.name)) leaks = true;
    return !leaks;
  });
  if (leaks) return null;
  return decl;
}

/**
 * The embedding box B03e leaves: `var BOX = [EMBEDDED0, EMBEDDED1, …]`, a
 * write-once array in which every element is a matching embedded function.
 * js-confuser packs several recovered functions into one shared box, indexed by
 * the thunks that forward to them. Returns the REPL of each element, by index.
 */
function matchRgfBox(binding: Binding | undefined): t.FunctionDeclaration[] | null {
  if (!binding || binding.constantViolations.length > 0) return null;
  if (!binding.path.isVariableDeclarator()) return null;
  const init = binding.path.node.init;
  if (!t.isArrayExpression(init) || init.elements.length === 0) return null;
  const repls: t.FunctionDeclaration[] = [];
  for (const el of init.elements) {
    const repl = matchRgfEmbedded(el);
    if (!repl) return null; // every element must be an embedding, or it is not a box
    repls.push(repl);
  }
  return repls;
}

/**
 * A thunk body is exactly `return BOX[0].apply(this, [BOX, arguments]);`. The
 * thunk forwards its own `this` and `arguments` into the embedded function,
 * which forwards them straight to REPL — so the thunk behaves identically to
 * REPL. Returns the box identifier name when the block has that shape.
 */
function rgfThunkBoxRef(fn: t.Function): { boxName: string; index: number } | null {
  if (t.isArrowFunctionExpression(fn) || !t.isBlockStatement(fn.body)) return null;
  const stmts = fn.body.body.filter((s) => !t.isEmptyStatement(s));
  if (stmts.length !== 1 || !t.isReturnStatement(stmts[0]) || !t.isCallExpression(stmts[0].argument))
    return null;
  const call = stmts[0].argument;
  // callee: BOX[i].apply
  if (!t.isMemberExpression(call.callee) || !t.isIdentifier(call.callee.property, { name: 'apply' }))
    return null;
  const box0 = call.callee.object;
  if (!t.isMemberExpression(box0) || !t.isIdentifier(box0.object) || box0.computed !== true) return null;
  const idx = box0.property;
  if (!t.isNumericLiteral(idx) || !Number.isInteger(idx.value) || idx.value < 0) return null;
  const boxName = box0.object.name;
  // args: (this, [BOX, arguments])
  if (
    call.arguments.length !== 2 ||
    !t.isThisExpression(call.arguments[0]) ||
    !t.isArrayExpression(call.arguments[1]) ||
    call.arguments[1].elements.length !== 2 ||
    !t.isIdentifier(call.arguments[1].elements[0], { name: boxName }) ||
    !t.isIdentifier(call.arguments[1].elements[1], { name: 'arguments' })
  )
    return null;
  return { boxName, index: idx.value };
}

function passRgfThunk(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const boxes = new Map<string, t.FunctionDeclaration[]>(); // box name → REPL per index
  const boxBindings = new Set<string>();

  // Collect qualifying boxes by binding.
  program.traverse({
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const b = p.scope.getBinding(p.node.id.name);
      const m = matchRgfBox(b);
      if (m) {
        boxes.set(p.node.id.name, m);
        boxBindings.add(p.node.id.name);
      }
    },
  });
  if (boxes.size === 0) {
    log.pass('b03f', 'rgfThunk', 0, 'thunks', 'no embedding box');
    return 0;
  }

  let n = 0;
  program.traverse({
    Function(p) {
      const ref = rgfThunkBoxRef(p.node);
      if (!ref) return;
      const repls = boxes.get(ref.boxName);
      if (!repls || ref.index >= repls.length) return;
      // The box name in the thunk must resolve to the collected box binding.
      const b = p.scope.getBinding(ref.boxName);
      if (!b || !t.isIdentifier((b.path.node as t.VariableDeclarator).id, { name: ref.boxName })) return;
      const repl = repls[ref.index];
      const fn = p.node;
      fn.params = repl.params.map((pm) => t.cloneNode(pm, true));
      fn.body = t.cloneNode(repl.body, true);
      n++;
    },
  });

  // Remove boxes no thunk references any more (takes the embedded fn with them).
  let removed = 0;
  if (n > 0) {
    for (let changed = true; changed; ) {
      changed = false;
      const fresh = freshProgram(ast);
      fresh.traverse({
        VariableDeclarator(dp) {
          if (!t.isIdentifier(dp.node.id) || !boxBindings.has(dp.node.id.name)) return;
          const b = dp.scope.getBinding(dp.node.id.name);
          if (!b || b.path.node !== dp.node || b.referencePaths.length > 0) return;
          try {
            if ((dp.parentPath.node as t.VariableDeclaration).declarations.length === 1) dp.parentPath.remove();
            else dp.remove();
            removed++;
            changed = true;
          } catch {
            /**/
          }
        },
      });
    }
  }

  log.pass('b03f', 'rgfThunk', n, 'thunks', removed > 0 ? `${removed} boxes removed` : undefined);
  return n + removed;
}


// ─────────────────────────────────────────────────────────────────────────────

type NativeImpl = (...args: unknown[]) => unknown;

/** Deterministic, side-effect-free builtins safe to evaluate at compile time. */
const PURE_NATIVE_CALLS: Record<string, NativeImpl> = {
  'Math.floor': (a) => Math.floor(a as number),
  'Math.ceil': (a) => Math.ceil(a as number),
  'Math.round': (a) => Math.round(a as number),
  'Math.trunc': (a) => Math.trunc(a as number),
  'Math.abs': (a) => Math.abs(a as number),
  'Math.sign': (a) => Math.sign(a as number),
  'Math.sqrt': (a) => Math.sqrt(a as number),
  'Math.cbrt': (a) => Math.cbrt(a as number),
  'Math.min': (...a) => Math.min(...(a as number[])),
  'Math.max': (...a) => Math.max(...(a as number[])),
  'Math.pow': (a, b) => Math.pow(a as number, b as number),
  'Math.imul': (a, b) => Math.imul(a as number, b as number),
  'Math.log2': (a) => Math.log2(a as number),
  'Math.log10': (a) => Math.log10(a as number),
  'Math.fround': (a) => Math.fround(a as number),
  'Math.clz32': (a) => Math.clz32(a as number),
  Number: (a) => Number(a),
  String: (a) => String(a),
  Boolean: (a) => Boolean(a),
  parseInt: (a, b) => parseInt(String(a), b === undefined ? 10 : (b as number)),
  parseFloat: (a) => parseFloat(String(a)),
  'Number.parseInt': (a, b) => parseInt(String(a), b === undefined ? 10 : (b as number)),
  'Number.parseFloat': (a) => parseFloat(String(a)),
  'Number.isInteger': (a) => Number.isInteger(a),
  'Number.isFinite': (a) => Number.isFinite(a),
  'Number.isNaN': (a) => Number.isNaN(a),
  isNaN: (a) => isNaN(a as number),
  isFinite: (a) => isFinite(a as number),
  'String.fromCharCode': (...a) => String.fromCharCode(...(a as number[])),
};

/** Dotted name for a callee that is a plain builtin reference, else null. */
function nativeCalleeName(callee: t.Node): string | null {
  if (t.isIdentifier(callee)) return callee.name;
  if (t.isMemberExpression(callee) && !callee.computed) {
    const { object, property } = callee;
    if (t.isIdentifier(object) && t.isIdentifier(property))
      return `${object.name}.${property.name}`;
  }
  return null;
}

/**
 * Deterministic String.prototype methods, evaluated when both the receiver and
 * every argument are literals: `"a|b".split("|")`, `"abc".charCodeAt(1)`, ….
 * None of these can observe anything but their (primitive) inputs.
 */
const PURE_STRING_METHODS = new Set([
  'split',
  'charAt',
  'charCodeAt',
  'codePointAt',
  'indexOf',
  'lastIndexOf',
  'includes',
  'startsWith',
  'endsWith',
  'slice',
  'substring',
  'substr',
  'toLowerCase',
  'toUpperCase',
  'trim',
  'trimStart',
  'trimEnd',
  'padStart',
  'padEnd',
  'repeat',
  'concat',
  'at',
]);

/** Fold `"lit".method(lits…)` / `[lits…].join(lit)`; null when not applicable. */
function foldLiteralMethodCall(call: t.CallExpression): t.Expression | null {
  const callee = call.callee;
  if (!t.isMemberExpression(callee)) return null;
  const method = !callee.computed
    ? t.isIdentifier(callee.property)
      ? callee.property.name
      : null
    : t.isStringLiteral(callee.property)
      ? callee.property.value
      : null;
  if (!method) return null;
  const args: unknown[] = [];
  for (const a of call.arguments) {
    if (!t.isExpression(a) || !isPurelyLiteral(a)) return null;
    const r = evalPure(a);
    if (!r.ok) return null;
    args.push(r.value);
  }
  const recv = callee.object;
  if (t.isArrayExpression(recv) && method === 'join') {
    if (
      args.length > 1 ||
      (args.length === 1 && typeof args[0] !== 'string' && args[0] !== undefined)
    )
      return null;
    const vals: unknown[] = [];
    for (const e of recv.elements) {
      if (!e || t.isSpreadElement(e) || !isPurelyLiteral(e)) return null;
      const r = evalPure(e as t.Expression);
      if (!r.ok) return null;
      vals.push(r.value);
    }
    return t.stringLiteral(vals.join(args[0] as string | undefined));
  }
  const recvVal = t.isStringLiteral(recv)
    ? recv.value
    : t.isTemplateLiteral(recv) && recv.expressions.length === 0
      ? (recv.quasis[0].value.cooked ?? null)
      : null;
  if (recvVal === null || !PURE_STRING_METHODS.has(method)) return null;
  // Only primitive arguments: a RegExp or object argument could carry
  // user-defined Symbol.split / toString behaviour.
  if (args.some((a) => a !== null && typeof a === 'object')) return null;
  if (method === 'repeat' && Number(args[0]) * recvVal.length > 10_000) return null;
  let value: unknown;
  try {
    value = (String.prototype as unknown as Record<string, (...x: unknown[]) => unknown>)[
      method
    ].apply(recvVal, args);
  } catch {
    return null;
  }
  if (Array.isArray(value)) {
    if (value.length > 4096 || !value.every((v) => typeof v === 'string')) return null;
    return t.arrayExpression(value.map((v) => t.stringLiteral(v as string)));
  }
  return toNode(value);
}

function passPureNativeCalls(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    MemberExpression: {
      exit(p) {
        // `"literal".length`
        if (!t.isStringLiteral(p.node.object)) return;
        if (staticMemberKey(p.node) !== 'length') return;
        if (
          p.parentPath.isAssignmentExpression({ left: p.node }) ||
          p.parentPath.isUpdateExpression()
        )
          return;
        if (p.parentPath.isCallExpression({ callee: p.node })) return;
        p.replaceWith(t.numericLiteral(p.node.object.value.length));
        n++;
      },
    },
    CallExpression: {
      // Exit order so nested calls fold inside-out.
      exit(p) {
        const literal = foldLiteralMethodCall(p.node);
        if (literal) {
          p.replaceWith(literal);
          n++;
          return;
        }
        const name = nativeCalleeName(p.node.callee);
        if (!name) return;
        const impl = PURE_NATIVE_CALLS[name];
        if (!impl) return;

        // The builtin must not be shadowed by a local binding.
        const rootName = name.split('.')[0];
        try {
          if (p.scope.getBinding(rootName)) return;
        } catch {
          return;
        }

        const args: unknown[] = [];
        for (const a of p.node.arguments) {
          if (!t.isExpression(a)) return;
          const r = evalPure(a as t.Expression);
          if (!r.ok) return;
          args.push(r.value);
        }

        let value: unknown;
        try {
          value = impl(...args);
        } catch {
          return;
        }
        const repl = toNode(value);
        if (!repl) return;
        if (isAlreadyCanonical(p.node as unknown as t.Expression, value)) return;

        p.replaceWith(repl);
        n++;
      },
    },
  });
  log.pass('b10b', 'pureNativeCalls', n);
  return n;
}

function passFromCharCode(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      const callee = p.node.callee;
      const ok =
        t.isIdentifier(callee, { name: 'fromCharCode' }) ||
        (t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object, { name: 'String' }) &&
          t.isIdentifier(callee.property, { name: 'fromCharCode' }));
      if (!ok) return;
      const codes = p.node.arguments.map((a) => (t.isNumericLiteral(a) ? a.value : null));
      if (!codes.length || codes.some((c) => c === null)) return;
      try {
        p.replaceWith(t.stringLiteral(String.fromCharCode(...(codes as number[]))));
        n++;
      } catch {
        /**/
      }
    },
  });
  log.pass('b02', 'fromCharCode', n);
  return n;
}

function passAtob(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      const name = t.isIdentifier(p.node.callee) ? p.node.callee.name : null;
      if (name !== 'atob' && name !== 'btoa') return;
      const arg = p.node.arguments[0];
      if (!t.isStringLiteral(arg)) return;
      try {
        const r =
          name === 'atob'
            ? Buffer.from(arg.value, 'base64').toString('utf8')
            : Buffer.from(arg.value, 'utf8').toString('base64');
        p.replaceWith(t.stringLiteral(r));
        n++;
      } catch {
        /**/
      }
    },
  });
  log.pass('b03', 'atob', n);
  return n;
}

function passBufferDecoding(ast: t.File, log: Logger): number {
  const constStrings = new Map<string, string>();

  type ScopeContext = {
    scope?: {
      getBinding(name: string): { constant?: boolean; path: { node: t.Node } } | null | undefined;
    };
  };

  function stringValue(
    node: t.Node | null | undefined,
    context?: ScopeContext,
    seen = new Set<string>()
  ): string | null {
    if (!node) return null;
    if (t.isStringLiteral(node)) return node.value;
    if (t.isIdentifier(node)) {
      if (seen.has(node.name)) return null;
      try {
        const binding = context?.scope?.getBinding(node.name);
        if (binding) {
          const bindingNode = binding.path.node;
          if (!binding.constant || !t.isVariableDeclarator(bindingNode)) return null;
          const init = bindingNode.init;
          if (!init) return null;
          return stringValue(init, context, new Set([...seen, node.name]));
        }
      } catch {
        /**/
      }
      return constStrings.get(node.name) ?? null;
    }
    if (t.isBinaryExpression(node, { operator: '+' })) {
      const left = stringValue(node.left, context, seen);
      const right = stringValue(node.right, context, seen);
      return left !== null && right !== null ? left + right : null;
    }
    if (t.isTemplateLiteral(node) && node.expressions.length === 0 && node.quasis.length === 1)
      return node.quasis[0].value.cooked ?? node.quasis[0].value.raw;
    if (t.isExpression(node) && isPurelyLiteral(node)) {
      const value = evalPure(node);
      if (value.ok && typeof value.value === 'string') return value.value;
    }
    return null;
  }

  function normalizeEncoding(value: string | null | undefined): BufferEncoding | null {
    if (!value) return null;
    const enc = value.toLowerCase().replace(/[-_\s]/g, '') as BufferEncoding;
    if (enc === 'utf8') return 'utf8';
    if (enc === 'base64') return 'base64';
    if (enc === 'base64url') return 'base64url';
    if (enc === 'hex') return 'hex';
    if (enc === 'ascii') return 'ascii';
    if (enc === 'latin1') return 'latin1';
    return null;
  }

  function decodeBuffer(
    input: string,
    inputEnc: string | null,
    outputEnc: string | null
  ): string | null {
    const fromEnc = normalizeEncoding(inputEnc) ?? 'utf8';
    const toEnc = normalizeEncoding(outputEnc) ?? 'utf8';
    if (!['base64', 'base64url', 'hex'].includes(fromEnc)) return null;
    try {
      return Buffer.from(input, fromEnc).toString(toEnc);
    } catch {
      return null;
    }
  }

  function parseBufferToString(
    expr: t.Expression
  ): { input: t.Expression; inputEnc: t.Expression | null; outputEnc: t.Expression | null } | null {
    if (!t.isCallExpression(expr)) return null;
    if (!t.isMemberExpression(expr.callee)) return null;
    const toStringProp = expr.callee.property;
    const isToString =
      (t.isIdentifier(toStringProp) && toStringProp.name === 'toString') ||
      (t.isStringLiteral(toStringProp) && toStringProp.value === 'toString');
    if (!isToString || expr.arguments.length > 1) return null;

    const source = expr.callee.object;
    if (!t.isCallExpression(source) || !t.isMemberExpression(source.callee)) return null;
    const fromProp = source.callee.property;
    const isFrom =
      (t.isIdentifier(fromProp) && fromProp.name === 'from') ||
      (t.isStringLiteral(fromProp) && fromProp.value === 'from');
    if (!isFrom || !t.isIdentifier(source.callee.object, { name: 'Buffer' })) return null;

    const input = source.arguments[0];
    const inputEnc = source.arguments[1] ?? null;
    const outputEnc = expr.arguments[0] ?? null;
    if (!input || !t.isExpression(input)) return null;
    if (inputEnc && !t.isExpression(inputEnc)) return null;
    if (outputEnc && !t.isExpression(outputEnc)) return null;
    return {
      input,
      inputEnc: (inputEnc as t.Expression | null) ?? null,
      outputEnc: (outputEnc as t.Expression | null) ?? null,
    };
  }

  type Helper = {
    inputEnc: string | null;
    outputEnc: string | null;
    paramName: string;
    sliceStart: number;
  };
  const helpers = new Map<string, Helper>();

  function helperFromFunction(fn: t.Function, context?: ScopeContext): Helper | null {
    if (fn.params.length !== 1 || !t.isIdentifier(fn.params[0])) return null;
    const paramName = fn.params[0].name;
    const expr = t.isBlockStatement(fn.body)
      ? fn.body.body.length === 1 && t.isReturnStatement(fn.body.body[0])
        ? fn.body.body[0].argument
        : null
      : fn.body;
    if (!expr || !t.isExpression(expr)) return null;

    const sequenceAssignments = new Map<string, t.Expression>();
    const target =
      t.isSequenceExpression(expr) && expr.expressions.length > 0
        ? expr.expressions[expr.expressions.length - 1]
        : expr;
    if (t.isSequenceExpression(expr)) {
      for (const part of expr.expressions.slice(0, -1)) {
        if (
          t.isAssignmentExpression(part, { operator: '=' }) &&
          t.isIdentifier(part.left) &&
          t.isExpression(part.right)
        )
          sequenceAssignments.set(part.left.name, part.right);
      }
    }
    if (!t.isExpression(target)) return null;

    const spec = parseBufferToString(target);
    if (!spec) return null;

    let sliceStart = 0;
    let input = spec.input;
    if (t.isIdentifier(input) && sequenceAssignments.has(input.name))
      input = sequenceAssignments.get(input.name)!;
    if (
      t.isCallExpression(input) &&
      t.isMemberExpression(input.callee) &&
      t.isIdentifier(input.callee.object, { name: paramName }) &&
      t.isIdentifier(input.callee.property, { name: 'slice' }) &&
      t.isNumericLiteral(input.arguments[0])
    )
      sliceStart = input.arguments[0].value;
    else if (!t.isIdentifier(input, { name: paramName })) return null;

    return {
      inputEnc: stringValue(spec.inputEnc, context),
      outputEnc: stringValue(spec.outputEnc, context),
      paramName,
      sliceStart,
    };
  }

  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !t.isStringLiteral(p.node.init)) return;
      if (!constStrings.has(p.node.id.name)) constStrings.set(p.node.id.name, p.node.init.value);
    },
  });

  traverse(ast, {
    FunctionDeclaration(p) {
      if (!p.node.id) return;
      const helper = helperFromFunction(p.node, p);
      if (helper) helpers.set(p.node.id.name, helper);
    },
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const init = p.node.init;
      if (!init || (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init))) return;
      const helper = helperFromFunction(init, p);
      if (helper) helpers.set(p.node.id.name, helper);
    },
  });

  let n = 0;
  traverse(ast, {
    CallExpression: {
      exit(p) {
        const direct = parseBufferToString(p.node);
        if (direct) {
          const input = stringValue(direct.input, p);
          const decoded =
            input !== null
              ? decodeBuffer(
                  input,
                  stringValue(direct.inputEnc, p),
                  stringValue(direct.outputEnc, p)
                )
              : null;
          if (decoded !== null) {
            p.replaceWith(t.stringLiteral(decoded));
            n++;
            return;
          }
        }

        if (!t.isIdentifier(p.node.callee) || p.node.arguments.length !== 1) return;
        const helper = helpers.get(p.node.callee.name);
        if (!helper) return;
        const input = stringValue(p.node.arguments[0] as t.Node, p);
        if (input === null) return;
        const decoded = decodeBuffer(
          input.slice(helper.sliceStart),
          helper.inputEnc,
          helper.outputEnc
        );
        if (decoded === null) return;
        p.replaceWith(t.stringLiteral(decoded));
        n++;
      },
    },
  });

  log.pass(
    'b03b',
    'bufferDecode',
    n,
    undefined,
    helpers.size ? `${helpers.size} helper(s)` : undefined
  );
  return n;
}

function passConstantFolding(ast: t.File, log: Logger): number {
  let total = 0;
  for (let round = 0; round < 30; round++) {
    let ch = 0;
    traverse(ast, {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      BinaryExpression: {
        exit(p) {
          ch += foldAny(p as any);
        },
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      UnaryExpression: {
        exit(p) {
          ch += foldAny(p as any);
        },
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      LogicalExpression: {
        exit(p) {
          ch += foldAny(p as any);
        },
      },
      ConditionalExpression: {
        exit(p) {
          if (!isPurelyLiteral(p.node.test)) return;
          const r = evalPure(p.node.test);
          if (!r.ok) return;
          p.replaceWith(r.value ? p.node.consequent : p.node.alternate);
          ch++;
        },
      },
    });
    total += ch;
    if (ch === 0) break;
  }
  log.pass('b04', 'constantFolding', total);
  return total;
}

// ─────────────────────────────────────────────────────────────────────────────
// B05a: Closure string decoder  (self-reassigning factory pattern)
//
// Handles the dominant javascript-obfuscator format:
//
//   function _0x212a() {
//     const arr = ["SGVsbG8=", "d29ybGQ=", ...hundreds of strings...];
//     return (_0x212a = function () { return arr; })();  // ← self-reassigns
//   }
//   (function (_arrParam, _target) {                     // ← shuffler IIFE
//     const arr = _arrParam();
//     while (!![]) {
//       try { if (checksum === _target) break;
//             else arr.push(arr.shift()); }
//       catch { arr.push(arr.shift()); }
//     }
//   }(_0x212a, -0x265bb + ...));
//   function _0x27d2(_a, _b) {                           // ← decoder fn
//     const arr = _0x212a();
//     return (_0x27d2 = function (idx) {
//       idx = idx - BASE;
//       return arr[idx];
//     })(_a, _b);
//   }
//
// Strategy:
//   1. Detect factory/shuffler/decoder nodes via a manual AST walk — never
//      calls traverse() or Babel scope APIs (immune to duplicate-binding crash).
//   2. Generate source for those nodes only and run in a minimal VM sandbox.
//   3. Probe every numeric index seen at decoder call sites.
//   4. Replace all matched CallExpression nodes with the resolved StringLiteral.
// ─────────────────────────────────────────────────────────────────────────────

function passClosureStringDecoder(ast: t.File, log: Logger): number {
  // ── Shared manual walker (never calls traverse / scope APIs) ─────────────
  function walkAst(root: unknown, visit: (node: t.Node) => void): void {
    if (!root || typeof root !== 'object') return;
    const obj = root as Record<string, unknown>;
    if (!('type' in obj) || typeof obj['type'] !== 'string') return;
    visit(obj as unknown as t.Node);
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[obj['type'] as string] ?? [];
    for (const key of keys) {
      const child = obj[key];
      if (!child) continue;
      if (Array.isArray(child)) child.forEach((item) => walkAst(item, visit));
      else walkAst(child, visit);
    }
  }

  // ── Step 1: detect factory functions ─────────────────────────────────────
  // A factory function satisfies ALL of:
  //   a) FunctionDeclaration with an id
  //   b) Body contains a VariableDeclaration with an ArrayExpression of ≥ 10
  //      elements where ≥ 50% are StringLiterals
  //   c) Body contains an AssignmentExpression whose LHS is the function's own name
  const factoryNames = new Set<string>();
  const factoryNodeMap = new Map<string, t.FunctionDeclaration>();

  walkAst(ast, (node) => {
    if (!t.isFunctionDeclaration(node) || !node.id) return;
    const name = node.id.name;

    // (b) has string array
    const hasArr = node.body.body.some((s) => {
      if (!t.isVariableDeclaration(s)) return false;
      return s.declarations.some((d) => {
        if (!t.isArrayExpression(d.init)) return false;
        const elems = d.init.elements;
        const strCount = elems.filter((e) => t.isStringLiteral(e)).length;
        return elems.length >= 10 && strCount / elems.length >= 0.5;
      });
    });
    if (!hasArr) return;

    // (c) self-reassigns
    let selfReassigns = false;
    walkAst(node.body, (inner) => {
      if (selfReassigns) return;
      if (t.isAssignmentExpression(inner) && t.isIdentifier(inner.left, { name }))
        selfReassigns = true;
    });
    if (!selfReassigns) return;

    factoryNames.add(name);
    factoryNodeMap.set(name, node);
  });

  if (factoryNames.size === 0) {
    log.pass('b05a', 'closureStr', 0, undefined, 'no factory');
    return 0;
  }

  // ── Step 2: detect shuffler IIFEs ─────────────────────────────────────────
  // Pattern: ExpressionStatement → CallExpression where callee is a
  // FunctionExpression and args[0] is the factory name identifier.
  const shufflerStmts: t.ExpressionStatement[] = [];
  walkAst(ast, (node) => {
    if (!t.isExpressionStatement(node)) return;
    const expr = node.expression;
    if (!t.isCallExpression(expr)) return;
    if (!t.isFunctionExpression(expr.callee) && !t.isArrowFunctionExpression(expr.callee)) return;
    const firstArg = expr.arguments[0];
    if (!t.isIdentifier(firstArg)) return;
    if (factoryNames.has((firstArg as t.Identifier).name)) shufflerStmts.push(node);
  });

  // ── Step 3: detect decoder functions ─────────────────────────────────────
  // A decoder function:
  //   • calls a factory somewhere in its body
  //   • self-reassigns to a simplified inner form
  const decoderNames = new Set<string>();
  const decoderNodeMap = new Map<string, t.FunctionDeclaration>();

  walkAst(ast, (node) => {
    if (!t.isFunctionDeclaration(node) || !node.id) return;
    const name = node.id.name;
    if (factoryNames.has(name)) return; // skip the factory itself

    let callsFactory = false;
    let selfReassigns = false;
    walkAst(node.body, (inner) => {
      if (
        !callsFactory &&
        t.isCallExpression(inner) &&
        t.isIdentifier(inner.callee) &&
        factoryNames.has((inner.callee as t.Identifier).name)
      )
        callsFactory = true;
      if (!selfReassigns && t.isAssignmentExpression(inner) && t.isIdentifier(inner.left, { name }))
        selfReassigns = true;
    });
    if (callsFactory && selfReassigns) {
      decoderNames.add(name);
      decoderNodeMap.set(name, node);
    }
  });

  if (decoderNames.size === 0) {
    log.pass('b05a', 'closureStr', 0, undefined, `${factoryNames.size} factory, no decoders`);
    return 0;
  }

  // Synchrony resolves decoder references, not only the root decoder. Real
  // javascript-obfuscator output commonly emits dozens of wrappers like:
  //   function a(x, y, z, k) { return root(x - 0x388, k); }
  // and later wrappers can call those wrappers. Include those function
  // declarations in the VM probe set so call sites can be decoded directly.
  const wrapperNodeMap = new Map<string, t.FunctionDeclaration>();
  let wrapperChanged = true;
  while (wrapperChanged) {
    wrapperChanged = false;
    walkAst(ast, (node) => {
      if (!t.isFunctionDeclaration(node) || !node.id) return;
      const name = node.id.name;
      if (factoryNames.has(name) || decoderNames.has(name) || wrapperNodeMap.has(name)) return;
      const stmts = node.body.body.filter((s) => !t.isEmptyStatement(s));
      if (stmts.length !== 1 || !t.isReturnStatement(stmts[0]) || !stmts[0].argument) return;
      const ret = stmts[0].argument;
      if (!t.isCallExpression(ret) || !t.isIdentifier(ret.callee)) return;
      if (!decoderNames.has(ret.callee.name) && !wrapperNodeMap.has(ret.callee.name)) return;
      if (!ret.arguments.every((a) => t.isExpression(a))) return;
      wrapperNodeMap.set(name, node);
      wrapperChanged = true;
    });
  }

  // ── Step 3b: resolve local aliases of decoders/wrappers ───────────────────
  // javascript-obfuscator routinely assigns a decoder to a short-lived local
  // before use, then calls through the alias:
  //   const _0x3fbcf3 = _0x36bb;  ...  _0x3fbcf3(0x1a9)
  // The call sites reference the alias, not the decoder itself, so without this
  // step Step 4 sees "no literal call sites". Resolve every such alias
  // (transitively) to its canonical decoder/wrapper name.
  const aliasToCanonical = new Map<string, string>();
  {
    let aliasChanged = true;
    while (aliasChanged) {
      aliasChanged = false;
      walkAst(ast, (node) => {
        if (!t.isVariableDeclarator(node)) return;
        if (!t.isIdentifier(node.id) || !t.isIdentifier(node.init)) return;
        const aliasName = node.id.name;
        const targetName = node.init.name;
        if (
          aliasToCanonical.has(aliasName) ||
          decoderNames.has(aliasName) ||
          wrapperNodeMap.has(aliasName) ||
          factoryNames.has(aliasName)
        )
          return;
        let canonical: string | null = null;
        if (decoderNames.has(targetName) || wrapperNodeMap.has(targetName)) canonical = targetName;
        else if (aliasToCanonical.has(targetName))
          canonical = aliasToCanonical.get(targetName) ?? null;
        if (!canonical) return;
        aliasToCanonical.set(aliasName, canonical);
        aliasChanged = true;
      });
    }
  }

  // ── Step 4: collect numeric indices from call sites ───────────────────────
  type ProbeSite = { callee: string; args: t.Expression[]; key: string };
  const callableNames = new Set([...decoderNames, ...wrapperNodeMap.keys()]);
  // Resolve an identifier used as a callee to its canonical decoder/wrapper
  // name, following any alias chain; null if it is neither.
  const resolveCallable = (name: string): string | null =>
    callableNames.has(name) ? name : (aliasToCanonical.get(name) ?? null);
  const callSiteIndices = new Set<number>();
  const probeSites = new Map<string, ProbeSite>();

  function addProbe(callee: string, args: t.Expression[]) {
    if (!args.length || !args.every((a) => isPurelyLiteral(a))) return;
    const key = `${callee}(${args.map((a) => generate(a).code).join(',')})`;
    probeSites.set(key, { callee, args, key });
    const first = evalPure(args[0]);
    if (first.ok && typeof first.value === 'number') callSiteIndices.add(first.value);
  }

  walkAst(ast, (node) => {
    if (!t.isCallExpression(node)) return;
    const { callee, arguments: args } = node;
    // Direct: decoder(0x3a8, ...) — or an alias of the decoder
    if (t.isIdentifier(callee)) {
      const canonical = resolveCallable(callee.name);
      if (canonical) {
        const exprArgs = args.filter((a): a is t.Expression => t.isExpression(a));
        if (exprArgs.length === args.length) addProbe(canonical, exprArgs);
      }
    }
    // Member call: decoder.call(ctx, 0x3a8)
    if (
      t.isMemberExpression(callee) &&
      t.isIdentifier((callee as t.MemberExpression).object) &&
      resolveCallable(((callee as t.MemberExpression).object as t.Identifier).name)
    ) {
      const method = t.isIdentifier(callee.property) ? callee.property.name : null;
      const fnName = resolveCallable(
        ((callee as t.MemberExpression).object as t.Identifier).name
      ) as string;
      if (method === 'call') {
        const exprArgs = args.slice(1).filter((a): a is t.Expression => t.isExpression(a));
        if (exprArgs.length === args.length - 1) addProbe(fnName, exprArgs);
      } else if (method === 'apply' && t.isArrayExpression(args[1])) {
        const arrArgs = args[1].elements.filter((a): a is t.Expression => !!a && t.isExpression(a));
        if (arrArgs.length === args[1].elements.length) addProbe(fnName, arrArgs);
      }
    }
  });

  if (probeSites.size === 0 && callSiteIndices.size === 0) {
    log.pass(
      'b05a',
      'closureStr',
      0,
      undefined,
      `${decoderNames.size} decoder(s), ${wrapperNodeMap.size} wrapper(s), no literal call sites`
    );
    return 0;
  }

  // ── Step 5: build & run minimal VM script ────────────────────────────────
  const emitNode = (node: t.Statement) => genVmCode(node);

  const parts: string[] = [];
  for (const [, fn] of factoryNodeMap) parts.push(emitNode(fn));
  for (const stmt of shufflerStmts) parts.push(emitNode(stmt));
  for (const [, fn] of decoderNodeMap) parts.push(emitNode(fn));
  for (const [, fn] of wrapperNodeMap) parts.push(emitNode(fn));

  // Probe direct decoder indices for compatibility with the old lookup path.
  for (const dec of callableNames) {
    parts.push(`var __lut_${dec} = {};`);
    for (const idx of callSiteIndices) {
      parts.push(`try { __lut_${dec}[${idx}] = ${dec}(${idx}); } catch(_e) {}`);
    }
  }
  parts.push('var __probe_lut = {};');
  for (const site of probeSites.values()) {
    const args = site.args.map((a) => generate(a).code).join(',');
    parts.push(
      `try { __probe_lut[${JSON.stringify(site.key)}] = ${site.callee}(${args}); } catch(_e) {}`
    );
  }
  for (const dec of callableNames) {
    parts.push(`globalThis[${JSON.stringify(`__lut_${dec}`)}] = __lut_${dec};`);
  }
  parts.push('globalThis.__probe_lut = __probe_lut;');

  const script = `(function(){\n${parts.join('\n')}\n})();`;

  const lookupMap = new Map<string, Map<number, string>>();
  const probeLookup = new Map<string, string>();
  try {
    const { Script, createContext } = vm;
    const sandbox: Record<string, unknown> = Object.create(null);
    // Provide builtins the shuffler's checksum arithmetic may need
    Object.assign(sandbox, {
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      String,
      Number,
      Boolean,
      Array,
      Object,
      Math,
      JSON,
      RegExp,
      Date,
      Error,
      TypeError,
      RangeError,
      undefined: undefined,
      Symbol: typeof Symbol !== 'undefined' ? Symbol : () => ({}),
      atob: (s: string) => Buffer.from(s, 'base64').toString('utf8'),
      btoa: (s: string) => Buffer.from(s, 'utf8').toString('base64'),
      Buffer,
    });
    for (const dec of callableNames) {
      (sandbox as Record<string, unknown>)[`__lut_${dec}`] = {};
    }
    (sandbox as Record<string, unknown>).__probe_lut = {};
    const ctx = createContext(sandbox);
    new Script(script).runInContext(ctx, { timeout: 10000 });

    for (const dec of callableNames) {
      const raw = (sandbox as Record<string, Record<string, unknown>>)[`__lut_${dec}`];
      const m = new Map<number, string>();
      for (const [k, v] of Object.entries(raw ?? {})) {
        if (typeof v === 'string') m.set(Number(k), v);
      }
      if (m.size > 0) lookupMap.set(dec, m);
    }
    const rawProbe = (sandbox as Record<string, Record<string, unknown>>).__probe_lut;
    for (const [k, v] of Object.entries(rawProbe ?? {})) {
      if (typeof v === 'string') probeLookup.set(k, v);
    }
  } catch (e) {
    log.fail(
      'b05a',
      'closureStr',
      `vm failed: ${(e instanceof Error ? e.message : String(e)).slice(0, 120)}`
    );
    return 0;
  }

  if (lookupMap.size === 0 && probeLookup.size === 0) {
    log.pass(
      'b05a',
      'closureStr',
      0,
      undefined,
      `vm ran but lookup empty; ${wrapperNodeMap.size} wrapper(s) detected`
    );
    return 0;
  }

  // ── Step 6: inline all matched call sites ─────────────────────────────────
  // traverse() is safe here — the factory nodes are still distinct identifiers
  // (hex suffix guard kept them unique), so scope.crawl() won't crash.
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      const { callee, arguments: args } = p.node;
      if (t.isIdentifier(callee) && resolveCallable(callee.name)) {
        const canonical = resolveCallable(callee.name) as string;
        const exprArgs = args.filter((a): a is t.Expression => t.isExpression(a));
        if (exprArgs.length === args.length && exprArgs.every((a) => isPurelyLiteral(a))) {
          const key = `${canonical}(${exprArgs.map((a) => generate(a).code).join(',')})`;
          const str = probeLookup.get(key);
          if (str !== undefined) {
            p.replaceWith(t.stringLiteral(str));
            n++;
            return;
          }
        }
      }

      let decName: string | null = null;
      let idxNode: t.Node | null = null;

      if (t.isIdentifier(callee) && resolveCallable(callee.name)) {
        const canonical = resolveCallable(callee.name) as string;
        if (lookupMap.has(canonical)) {
          decName = canonical;
          idxNode = args[0] ?? null;
        }
      } else if (
        t.isMemberExpression(callee) &&
        t.isIdentifier((callee as t.MemberExpression).object) &&
        resolveCallable(((callee as t.MemberExpression).object as t.Identifier).name) &&
        lookupMap.has(
          resolveCallable(((callee as t.MemberExpression).object as t.Identifier).name) as string
        )
      ) {
        decName = resolveCallable(
          ((callee as t.MemberExpression).object as t.Identifier).name
        ) as string;
        idxNode = args[1] ?? null;
      }

      if (!decName || !idxNode || !t.isExpression(idxNode)) return;
      const idx = evalPure(idxNode);
      if (!idx.ok || typeof idx.value !== 'number') return;
      const str = lookupMap.get(decName)!.get(idx.value);
      if (str === undefined) return;
      p.replaceWith(t.stringLiteral(str));
      n++;
    },
  });

  if (n > 0) {
    const removableNames = new Set([...factoryNames, ...decoderNames, ...wrapperNodeMap.keys()]);
    const aliasNames = new Set(aliasToCanonical.keys());

    // Count references (reads) to a set of names, ignoring identifiers inside the
    // bodies of removable functions and inside the shuffler IIFEs — all of which
    // are being removed together, so their internal cross-references must not
    // keep the group alive. Anything still referenced from surviving code is
    // kept, so removal never leaves a dangling reference.
    const countRefs = (names: Set<string>): Map<string, number> => {
      const counts = new Map<string, number>();
      traverse(ast, {
        FunctionDeclaration(p) {
          if (p.node.id && removableNames.has(p.node.id.name)) p.skip();
        },
        ExpressionStatement(p) {
          if (shufflerStmts.includes(p.node)) p.skip();
        },
        Identifier(p) {
          if (!p.isReferencedIdentifier()) return;
          if (names.has(p.node.name)) counts.set(p.node.name, (counts.get(p.node.name) ?? 0) + 1);
        },
      });
      return counts;
    };

    // 1. Remove the shuffler IIFE(s).
    traverse(ast, {
      ExpressionStatement(p) {
        if (!shufflerStmts.includes(p.node)) return;
        try {
          p.remove();
        } catch {
          /**/
        }
      },
    });

    // 2. Remove dead alias declarations (const ALIAS = decoder;) whose call
    //    sites were all just inlined.
    if (aliasNames.size > 0) {
      const aliasRefs = countRefs(aliasNames);
      traverse(ast, {
        VariableDeclarator(p) {
          const id = p.node.id;
          if (!t.isIdentifier(id) || !aliasNames.has(id.name)) return;
          if (!t.isIdentifier(p.node.init)) return;
          if ((aliasRefs.get(id.name) ?? 0) > 0) return;
          try {
            p.remove();
          } catch {
            /**/
          }
        },
      });
    }

    // 3. Remove factory/decoder/wrapper functions no longer referenced from
    //    surviving code.
    const fnRefs = countRefs(removableNames);
    traverse(ast, {
      FunctionDeclaration(p) {
        if (!p.node.id || !removableNames.has(p.node.id.name)) return;
        if ((fnRefs.get(p.node.id.name) ?? 0) > 0) return;
        try {
          p.remove();
        } catch {
          /**/
        }
      },
    });
  }

  const total = [...lookupMap.values()].reduce((s, m) => s + m.size, 0);
  log.pass(
    'b05a',
    'closureStr',
    n,
    'calls inlined',
    `${lookupMap.size} decoder map(s), ${wrapperNodeMap.size} wrapper(s), ${total + probeLookup.size} strings resolved`
  );
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────

function passStringDecoder(ast: t.File, log: Logger): number {
  // Reuse binding-aware dependency slicing. The former shape matcher indexed
  // pools by name, guessed rotation counts, and folded reads before initialization.
  const changes = passClosedFunctionEval(ast, log);
  log.pass('b05', 'stringDecoder', changes);
  return changes;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared VM-decoder helpers (used by B05b)
// ─────────────────────────────────────────────────────────────────────────────

/** Generic recursive AST walk that never touches Babel scope/traverse. */
function walkNode(root: unknown, visit: (node: t.Node) => void): void {
  if (!root || typeof root !== 'object') return;
  if (Array.isArray(root)) {
    for (const item of root) walkNode(item, visit);
    return;
  }
  const obj = root as Record<string, unknown>;
  if (typeof obj['type'] !== 'string') return;
  visit(obj as unknown as t.Node);
  const keys = (t.VISITOR_KEYS as Record<string, string[]>)[obj['type'] as string] ?? [];
  for (const key of keys) walkNode(obj[key], visit);
}

/**
 * Globals a decoder slice may reference and still be evaluated deterministically.
 * Deliberately excludes anything I/O-, timing- or environment-bound so a probe
 * can never reach the host.
 */
const VM_SAFE_GLOBALS = new Set([
  'String',
  'Number',
  'Boolean',
  'Array',
  'Object',
  'Math',
  'JSON',
  'RegExp',
  'Error',
  'TypeError',
  'RangeError',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite',
  'atob',
  'btoa',
  'decodeURIComponent',
  'encodeURIComponent',
  'decodeURI',
  'encodeURI',
  'unescape',
  'escape',
  'undefined',
  'NaN',
  'Infinity',
]);

/** Minimal sandbox exposing only the VM_SAFE_GLOBALS surface. */
function buildDecoderSandbox(): Record<string, unknown> {
  const sb: Record<string, unknown> = Object.create(null);
  sb['String'] = String;
  sb['Number'] = Number;
  sb['Boolean'] = Boolean;
  sb['Array'] = Array;
  sb['Object'] = Object;
  sb['Math'] = Math;
  sb['JSON'] = JSON;
  sb['RegExp'] = RegExp;
  sb['Error'] = Error;
  sb['TypeError'] = TypeError;
  sb['RangeError'] = RangeError;
  sb['parseInt'] = parseInt;
  sb['parseFloat'] = parseFloat;
  sb['isNaN'] = isNaN;
  sb['isFinite'] = isFinite;
  sb['decodeURIComponent'] = decodeURIComponent;
  sb['encodeURIComponent'] = encodeURIComponent;
  sb['decodeURI'] = decodeURI;
  sb['encodeURI'] = encodeURI;
  sb['unescape'] = unescape;
  sb['escape'] = escape;
  sb['atob'] = (s: string) => Buffer.from(String(s), 'base64').toString('binary');
  sb['btoa'] = (s: string) => Buffer.from(String(s), 'binary').toString('base64');
  return sb;
}

// ─────────────────────────────────────────────────────────────────────────────
// B05b: Transforming pool decoder
//
// Generalises B05 (`return arr[idx]`) to decoders that apply an arbitrary
// *transform* to the pool entry before returning it:
//
//   var o = ["dGhpcyBoYXM…", "T2JqZWN0", …];   // base64 pool
//   function D(A) { var w = o[A]; return atob(w); }
//
//   var c = ["mVgah266", 287.25, …];           // mixed pool
//   function a(A) {
//     var w = c[A];
//     return "string" == typeof w ? function (…) { /* custom base64 */ }(w) : w;
//   }
//
// B05 only recognises a bare member return, so neither of these is matched and
// every `D(0)` / `a(131)` call site survives untouched — which in turn blocks
// memberExpressionSimplification, dispatchTableInlining and renameMangled from
// ever seeing real property names.
//
// Strategy (mirrors B05a): isolate the pool declaration plus the decoder
// function, evaluate that slice in a locked-down VM, then probe it with every
// literal index actually observed at a call site. Only call sites whose probe
// returns a primitive are replaced, so a decoder with side effects or an
// out-of-range index simply yields no replacement.
// ─────────────────────────────────────────────────────────────────────────────

function passPoolDecoder(ast: t.File, log: Logger): number {
  if (hasDynamicScope(ast.program)) return 0;
  const program = freshProgram(ast);
  const poolFacts = writeOnceFacts(program);
  // ── 1. Collect candidate pools: arrays of mostly primitive literals ──────
  const pools = new Map<string, t.ArrayExpression>();
  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !t.isArrayExpression(init)) return;
      const binding = p.scope.getBinding(id.name);
      if (!binding || !poolFacts.has(binding)) return;
      if (init.elements.length < 3) return;
      const primitive = init.elements.filter(
        (e) =>
          e != null &&
          (t.isStringLiteral(e) ||
            t.isNumericLiteral(e) ||
            t.isNullLiteral(e) ||
            t.isBooleanLiteral(e) ||
            (t.isUnaryExpression(e, { operator: '-' }) && t.isNumericLiteral(e.argument)))
      ).length;
      if (primitive / init.elements.length < 0.8) return;
      pools.set(id.name, init);
    },
  });
  if (pools.size === 0) {
    log.pass('b05b', 'poolDecoder', 0, undefined, 'no pool');
    return 0;
  }

  // ── 2. Find decoders: fn(idx) whose body reads pool[idx] and returns ─────
  type Decoder = { poolName: string; src: string; fnName: string };
  const decoders = new Map<t.Identifier, Decoder>();
  const decoderNames = new Set<string>();

  /** The single pool this function body indexes with its own parameter. */
  function poolIndexedBy(node: t.Function, paramName: string): string | null {
    let found: string | null = null;
    let conflict = false;
    walkNode(node.body as t.Node, (n) => {
      if (!t.isMemberExpression(n) || !n.computed) return;
      if (!t.isIdentifier(n.object) || !pools.has(n.object.name)) return;
      if (!t.isIdentifier(n.property) || n.property.name !== paramName) return;
      if (found && found !== n.object.name) conflict = true;
      found = n.object.name;
    });
    return conflict ? null : found;
  }

  /** Free identifiers in `node` that are neither locals nor known globals. */
  /**
   * True when the slice references a binding the sandbox cannot supply.
   *
   * Every name bound anywhere inside the function is in scope for the VM once
   * the slice is evaluated as a unit, so the check is deliberately whole-body
   * rather than per-scope: collect all bindings introduced by the function
   * (params at any depth, every declarator in a `var a, b, c`, function names,
   * catch params), then flag any remaining free identifier that is neither the
   * pool, the decoder itself, nor a VM-safe global.
   */
  function hasUnresolvedRefs(node: t.Function, poolName: string, selfName: string): boolean {
    const locals = new Set<string>();
    const addPattern = (pat: t.Node | null | undefined) => {
      if (!pat) return;
      if (t.isIdentifier(pat)) locals.add(pat.name);
      else if (t.isAssignmentPattern(pat)) addPattern(pat.left);
      else if (t.isRestElement(pat)) addPattern(pat.argument);
      else if (t.isArrayPattern(pat)) for (const el of pat.elements) addPattern(el);
      else if (t.isObjectPattern(pat))
        for (const prop of pat.properties) addPattern(t.isObjectProperty(prop) ? prop.value : prop);
    };

    for (const prm of node.params) addPattern(prm);
    if (t.isFunctionDeclaration(node) || t.isFunctionExpression(node)) {
      if (node.id) locals.add(node.id.name);
    }

    walkNode(node.body as t.Node, (n) => {
      if (t.isVariableDeclarator(n)) addPattern(n.id);
      else if (t.isFunctionDeclaration(n) || t.isFunctionExpression(n)) {
        if (n.id) locals.add(n.id.name);
        for (const prm of n.params) addPattern(prm);
      } else if (t.isArrowFunctionExpression(n)) {
        for (const prm of n.params) addPattern(prm);
      } else if (t.isCatchClause(n)) addPattern(n.param);
      else if (t.isClassDeclaration(n) && n.id) locals.add(n.id.name);
    });

    let unresolved = false;
    const check = (name: string) => {
      if (locals.has(name) || name === poolName || name === selfName) return;
      if (VM_SAFE_GLOBALS.has(name)) return;
      unresolved = true;
    };

    // Walk manually so identifiers in *name* position are never treated as
    // references: `x.foo`, `{foo: 1}`, `var foo`, `break foo`.
    const scan = (n: unknown): void => {
      if (unresolved || !n || typeof n !== 'object') return;
      if (Array.isArray(n)) {
        for (const item of n) scan(item);
        return;
      }
      const node2 = n as t.Node;
      if (typeof (node2 as { type?: unknown }).type !== 'string') return;

      if (t.isIdentifier(node2)) {
        check(node2.name);
        return;
      }
      if (t.isMemberExpression(node2)) {
        scan(node2.object);
        if (node2.computed) scan(node2.property);
        return;
      }
      if (t.isObjectProperty(node2)) {
        if (node2.computed) scan(node2.key);
        scan(node2.value);
        return;
      }
      if (t.isObjectMethod(node2) || t.isClassMethod(node2)) {
        if (node2.computed) scan(node2.key);
        scan(node2.params);
        scan(node2.body);
        return;
      }
      if (t.isVariableDeclarator(node2)) {
        scan(node2.init); // `id` is a binding, not a reference
        return;
      }
      if (t.isLabeledStatement(node2)) {
        scan(node2.body);
        return;
      }
      if (t.isBreakStatement(node2) || t.isContinueStatement(node2)) return;

      const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node2.type] ?? [];
      for (const key of keys) scan((node2 as unknown as Record<string, unknown>)[key]);
    };

    scan(node.body);
    return unresolved;
  }

  /**
   * True when the decoder writes to anything that outlives a single call.
   *
   * Inlining is only sound for a pure lookup: a decoder that bumps a counter or
   * mutates its pool changes observable state, so replacing its call sites both
   * loses that effect and can make later calls return different values. Writes
   * to the function's *own* locals are fine — they die with the call.
   */
  function hasExternalWrites(node: t.Function): boolean {
    const locals = new Set<string>();
    const addPattern = (pat: t.Node | null | undefined) => {
      if (!pat) return;
      if (t.isIdentifier(pat)) locals.add(pat.name);
      else if (t.isAssignmentPattern(pat)) addPattern(pat.left);
      else if (t.isRestElement(pat)) addPattern(pat.argument);
      else if (t.isArrayPattern(pat)) for (const el of pat.elements) addPattern(el);
      else if (t.isObjectPattern(pat))
        for (const prop of pat.properties) addPattern(t.isObjectProperty(prop) ? prop.value : prop);
    };
    for (const prm of node.params) addPattern(prm);
    walkNode(node.body as t.Node, (n) => {
      if (t.isVariableDeclarator(n)) addPattern(n.id);
      else if (t.isFunctionDeclaration(n) || t.isFunctionExpression(n)) {
        if (n.id) locals.add(n.id.name);
        for (const prm of n.params) addPattern(prm);
      } else if (t.isArrowFunctionExpression(n)) for (const prm of n.params) addPattern(prm);
      else if (t.isCatchClause(n)) addPattern(n.param);
    });

    let external = false;
    const targets = (lval: t.Node | null | undefined) => {
      if (!lval || external) return;
      if (t.isIdentifier(lval)) {
        if (!locals.has(lval.name)) external = true;
        return;
      }
      // Any member write (`pool[i] = x`, `obj.k++`) escapes the call.
      if (t.isMemberExpression(lval)) {
        external = true;
        return;
      }
      if (t.isArrayPattern(lval)) for (const el of lval.elements) targets(el);
      else if (t.isObjectPattern(lval))
        for (const prop of lval.properties)
          targets(t.isObjectProperty(prop) ? (prop.value as t.Node) : prop);
      else if (t.isAssignmentPattern(lval)) targets(lval.left);
      else if (t.isRestElement(lval)) targets(lval.argument);
    };

    walkNode(node.body as t.Node, (n) => {
      if (external) return;
      if (t.isAssignmentExpression(n)) targets(n.left);
      else if (t.isUpdateExpression(n)) targets(n.argument);
      else if (t.isForXStatement(n) && !t.isVariableDeclaration(n.left)) targets(n.left);
      // A `delete` is a mutation we cannot model.
      else if (t.isUnaryExpression(n, { operator: 'delete' })) external = true;
      // `pool.push(pool.shift())` rotates shared state just like an assignment.
      else if (t.isCallExpression(n) && t.isMemberExpression(n.callee)) {
        const prop = staticMemberKey(n.callee);
        if (prop !== null && !MUTATING_METHOD_NAMES.has(prop)) return;
        let base: t.Node = n.callee.object;
        while (t.isMemberExpression(base)) base = base.object;
        if (!t.isIdentifier(base) || !locals.has(base.name)) external = true;
      }
    });
    return external;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function detectDecoder(name: string, node: t.Function, bindingId: t.Identifier) {
    if (node.params.length < 1 || !t.isIdentifier(node.params[0])) return;
    const paramName = (node.params[0] as t.Identifier).name;
    const poolName = poolIndexedBy(node, paramName);
    if (!poolName) return;
    if (hasUnresolvedRefs(node, poolName, name)) return;
    // A decoder with observable side effects cannot be inlined away.
    if (hasExternalWrites(node)) return;

    const poolSrc = genVmCode(pools.get(poolName)!);
    const fnSrc = genVmCode(node as unknown as t.Node);
    // A FunctionDeclaration must be emitted as a statement so its own name is
    // bound (self-recursive decoders rely on that); an expression is assigned.
    const src = t.isFunctionDeclaration(node)
      ? `var ${poolName} = ${poolSrc};\n${fnSrc}\nvar __dec = ${name};`
      : `var ${poolName} = ${poolSrc};\nvar __dec = (${fnSrc});`;
    decoders.set(bindingId, { poolName, src, fnName: name });
    decoderNames.add(name);
  }

  traverse(ast, {
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id) return;
      try {
        const b = p.scope.getBinding(id.name);
        if (!b?.constant || !b.identifier) return;
        detectDecoder(id.name, p.node, b.identifier);
      } catch {
        /**/
      }
    },
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;
      if (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) return;
      try {
        const b = p.scope.getBinding(id.name);
        if (!b?.constant || !b.identifier) return;
        detectDecoder(id.name, init as t.Function, b.identifier);
      } catch {
        /**/
      }
    },
  });

  if (decoders.size === 0) {
    log.pass('b05b', 'poolDecoder', 0, undefined, 'no decoder');
    return 0;
  }

  // ── 3. Compile each decoder once in an isolated VM sandbox ───────────────
  // The decoder function object is lifted out of the context a single time and
  // called directly from the host. Compiling a fresh Script per call site would
  // mean thousands of compilations against a pool that can be hundreds of KB.
  const compiled = new Map<t.Identifier, (idx: number) => unknown>();
  for (const [bindingId, def] of decoders) {
    try {
      const { Script, createContext } = vm;
      const ctx = createContext(buildDecoderSandbox());
      const fn = new Script(`${def.src}\n__dec;`).runInContext(ctx, { timeout: 5000 });
      if (typeof fn !== 'function') continue;
      const memo = new Map<number, unknown>();
      compiled.set(bindingId, (idx: number) => {
        if (memo.has(idx)) return memo.get(idx);
        const v = (fn as (i: number) => unknown)(idx);
        memo.set(idx, v);
        return v;
      });
    } catch {
      /**/
    }
  }
  if (compiled.size === 0) {
    log.pass('b05b', 'poolDecoder', 0, undefined, `${decoders.size} decoders, none compiled`);
    return 0;
  }

  // ── 4. Replace every literal-index call site with its decoded value ──────
  let n = 0;
  const resolvedFns = new Set<string>();
  traverse(ast, {
    CallExpression: {
      exit(p) {
        const callee = p.node.callee;
        if (!t.isIdentifier(callee) || !decoderNames.has(callee.name)) return;
        if (p.node.arguments.length !== 1) return;

        const arg = p.node.arguments[0];
        if (!t.isExpression(arg)) return;
        const idx = evalPure(arg as t.Expression);
        if (!idx.ok || typeof idx.value !== 'number' || !Number.isInteger(idx.value)) return;

        let bindingId: t.Identifier | null | undefined;
        try {
          bindingId = p.scope.getBinding(callee.name)?.identifier;
        } catch {
          return;
        }
        if (!bindingId) return;
        const probe = compiled.get(bindingId);
        if (!probe) return;

        let value: unknown;
        try {
          value = probe(idx.value);
        } catch {
          return;
        }
        // Only primitives are safe to inline; anything else may alias state.
        if (value !== null && typeof value === 'object') return;
        if (typeof value === 'function' || typeof value === 'undefined') return;
        const repl = toNode(value);
        if (!repl) return;

        p.replaceWith(repl);
        resolvedFns.add(callee.name);
        n++;
      },
    },
  });

  log.pass(
    'b05b',
    'poolDecoder',
    n,
    'call sites',
    `${resolvedFns.size}/${compiled.size} decoders used`
  );
  return n;
}

const IDENTIFIER_NAME_RE = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;

function passMemberSimplify(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    // obj["key"] → obj.key. Any IdentifierName may follow a dot (ES5), so
    // reserved words such as `catch` and `default` are fine here.
    'MemberExpression|OptionalMemberExpression'(p: NodePath) {
      const node = p.node as t.MemberExpression | t.OptionalMemberExpression;
      if (!node.computed || !t.isStringLiteral(node.property)) return;
      const name = node.property.value;
      if (!IDENTIFIER_NAME_RE.test(name)) return;
      node.property = t.identifier(name);
      node.computed = false;
      n++;
    },
    // { "key": v }, { ["key"]() {} }, class { ["method"]() {} } → plain keys.
    // Non-computed `__proto__` sets the prototype and a class member named
    // `constructor`/`prototype` changes meaning (or is a syntax error), so
    // those keep their spelling.
    'ObjectProperty|ObjectMethod|ClassMethod|ClassProperty|ClassAccessorProperty'(p: NodePath) {
      const node = p.node as
        | t.ObjectProperty
        | t.ObjectMethod
        | t.ClassMethod
        | t.ClassProperty
        | t.ClassAccessorProperty;
      if (!t.isStringLiteral(node.key)) return;
      const name = node.key.value;
      if (!IDENTIFIER_NAME_RE.test(name) || name === '__proto__') return;
      if (
        !t.isObjectProperty(node) &&
        !t.isObjectMethod(node) &&
        (name === 'constructor' || name === 'prototype')
      )
        return;
      node.key = t.identifier(name);
      node.computed = false;
      n++;
    },
  });
  log.pass('b06', 'memberSimplify', n);
  return n;
}

function passDispatchTable(ast: t.File, log: Logger): number {
  // Share the frozen-object and template proofs with assignment-based tables.
  // Name/key heuristics could remove writes to unrelated escaping objects.
  const changes = passObjectTables(ast, log);
  log.pass('b07', 'dispatchTable', changes, 'inlined');
  return changes;
}

// ─────────────────────────────────────────────────────────────────────────────
// B07b: Identity-table state constants
//
// A control-flow-flattening variant that hides its state constants behind a
// self-referential table of array objects instead of plain numbers:
//
//   var L = function (A, w, B, C) {
//     for (C = [], B = 0; B < 128; B++) C[B] = new Array(512);
//     for (w = 0; w < 512; w++)
//       for (A = 0; A < 128; A++) C[A][w] = C[Aw(647, 601, 347, 128, w, 80, A)];
//     return C[80];
//   }();
//   …
//   for (var b = L[349][154];;) { switch (b) { case L[95][365]: … } }
//
// Every cell holds one of the 128 row arrays, so `L[a][b]` is compared by object
// identity — which looks dynamic but is completely determined at build time. The
// table never escapes and is never mutated afterwards, so each `L[a][b]` can be
// replaced by a small integer standing for "which row", preserving every
// equality relation the switch depends on while making the state machine
// readable (and giving controlFlowFlattening real numbers to work with).
//
// Strategy: rebuild the table in a sandbox, assign each distinct row object a
// stable id, then rewrite every literal `alias[a][b]` to that id.
// ─────────────────────────────────────────────────────────────────────────────

function passIdentityTable(ast: t.File, log: Logger): number {
  type TableDef = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    declPath: any;
    resolve: (a: number, b: number) => number | null;
  };
  const tables = new Map<string, TableDef>();

  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;
      // Shape: `var L = (function(){ … })();` — an IIFE returning the table.
      if (!t.isCallExpression(init) || init.arguments.length > 0) return;
      const callee = init.callee;
      if (!t.isFunctionExpression(callee) && !t.isArrowFunctionExpression(callee)) return;

      // The body must be a small, self-contained loop nest: no member calls, no
      // free identifiers other than pure helpers we can pull in with it.
      const src = generate(init).code;
      if (src.length > 4000) return;
      if (!/new Array\(|\[\s*\]/.test(src)) return;

      let binding: { constant?: boolean } | null | undefined;
      try {
        binding = p.scope.getBinding(id.name);
      } catch {
        return;
      }
      if (!binding?.constant) return;

      // Pull in any pure numeric helper the initialiser calls (e.g. `Aw`).
      const helperNames = new Set<string>();
      walkNode(init, (n) => {
        if (t.isCallExpression(n) && t.isIdentifier(n.callee)) helperNames.add(n.callee.name);
      });
      const helpers: string[] = [];
      for (const hName of helperNames) {
        const hBinding = p.scope.getBinding(hName);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const hPath = (hBinding as any)?.path;
        if (!hPath) return; // unknown callee — cannot reproduce the table
        const hNode = hPath.node as t.Node;
        if (t.isFunctionDeclaration(hNode)) helpers.push(generate(hNode).code);
        else if (
          t.isVariableDeclarator(hNode) &&
          hNode.init &&
          (t.isFunctionExpression(hNode.init) || t.isArrowFunctionExpression(hNode.init))
        )
          helpers.push(`var ${hName} = ${generate(hNode.init).code};`);
        else return;
      }

      // Build it in a sandbox and index the distinct row objects.
      try {
        const { Script, createContext } = vm;
        const ctx = createContext(buildDecoderSandbox());
        const built = new Script(
          `${helpers.join('\n')}\nvar __tbl = ${generate(init).code};\n__tbl;`
        ).runInContext(ctx, { timeout: 5000 });
        if (!Array.isArray(built)) return;

        // Assign a stable id per distinct row object reachable as a cell.
        const ids = new Map<unknown, number>();
        const idFor = (obj: unknown): number | null => {
          if (obj === null || typeof obj !== 'object') return null;
          let v = ids.get(obj);
          if (v === undefined) {
            v = ids.size;
            ids.set(obj, v);
          }
          return v;
        };
        const resolve = (a: number, b: number): number | null => {
          const row = (built as unknown[])[a];
          if (!Array.isArray(row)) return null;
          return idFor((row as unknown[])[b]);
        };
        // Require the table to actually collapse into a small identity space —
        // otherwise this is not the construct we are modelling.
        let distinct = 0;
        for (let i = 0; i < Math.min(built.length, 64); i++) {
          const r = resolve(i, 0);
          if (r !== null) distinct = Math.max(distinct, r + 1);
        }
        if (distinct === 0 || distinct > 1024) return;

        tables.set(id.name, { declPath: p, resolve });
      } catch {
        /**/
      }
    },
  });

  if (tables.size === 0) {
    log.pass('b07b', 'identityTable', 0);
    return 0;
  }

  // Rewrite `alias[a][b]` (both indices literal) to the row id.
  const rewrites: Array<{ parent: t.Node; key: string; value: number }> = [];
  traverse(ast, {
    MemberExpression(p) {
      const outer = p.node;
      if (!outer.computed) return;
      const inner = outer.object;
      if (!t.isMemberExpression(inner) || !inner.computed) return;
      if (!t.isIdentifier(inner.object)) return;
      const def = tables.get(inner.object.name);
      if (!def) return;

      const aRes = t.isExpression(inner.property)
        ? evalPure(inner.property)
        : { ok: false, value: 0 };
      const bRes = t.isExpression(outer.property)
        ? evalPure(outer.property)
        : { ok: false, value: 0 };
      if (!aRes.ok || !bRes.ok) return;
      if (typeof aRes.value !== 'number' || typeof bRes.value !== 'number') return;

      const value = def.resolve(aRes.value, bRes.value);
      if (value === null) return;

      const parent = p.parentPath?.node;
      if (!parent || typeof p.key !== 'string') return;
      rewrites.push({ parent, key: p.key, value });
    },
  });

  let n = 0;
  for (const { parent, key, value } of rewrites) {
    const holder = parent as unknown as Record<string, unknown>;
    if (!t.isMemberExpression(holder[key] as t.Node)) continue;
    holder[key] = t.numericLiteral(value);
    n++;
  }

  // The table is dead once every reference is gone; B17b will collect it.
  log.pass('b07b', 'identityTable', n, 'refs', `${tables.size} tables`);
  return n;
}

function passConstantPropagation(ast: t.File, log: Logger): number {
  type BindingKey = t.Identifier;
  type BindingLike = { constant?: boolean; identifier?: t.Identifier };
  const candidates = new Map<BindingKey, t.Expression>();
  const candidateNames = new Set<string>();
  // Only bindings whose declaration dominates every read: a read before
  // `var x = 1` sees undefined, one before `let x = 1` throws.
  const dominated = new Set<t.Identifier>();
  // Bindings a direct `eval` / `with` could read or write by name are left out
  // of the candidate set rather than disabling the pass for the whole program.
  const observed = new Set<t.Identifier>();
  try {
    const program = freshProgram(ast);
    const dyn = dynamicScopes(program);
    for (const b of writeOnceFacts(program, { includeScriptGlobals: true }).keys()) {
      dominated.add(b.identifier);
      if (dyn.observesBinding(b)) observed.add(b.identifier);
    }
  } catch {
    /* fall through with an empty set: nothing is propagated */
  }

  function getBindingKey(
    path: { scope?: { getBinding(name: string): BindingLike | null | undefined } },
    name: string
  ): BindingKey | null {
    try {
      return path.scope?.getBinding(name)?.identifier ?? null;
    } catch {
      return null;
    }
  }

  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;
      let binding: BindingLike | null | undefined;
      try {
        binding = p.scope.getBinding(id.name);
      } catch {
        return;
      }
      if (!binding?.constant || !binding.identifier) return;
      if (!dominated.has(binding.identifier)) return;
      const isLeaf =
        t.isStringLiteral(init) ||
        t.isNumericLiteral(init) ||
        t.isBooleanLiteral(init) ||
        t.isNullLiteral(init) ||
        (t.isUnaryExpression(init, { operator: '-' }) && t.isNumericLiteral(init.argument));
      if (isLeaf) {
        if (observed.has(binding.identifier)) return;
        candidates.set(binding.identifier, init);
        candidateNames.add(id.name);
      }
    },
  });
  if (candidates.size === 0) {
    log.pass('b08', 'constProp', 0);
    return 0;
  }

  let n = 0;
  const inlined = new Set<BindingKey>();
  traverse(ast, {
    Identifier(p) {
      const name = p.node.name;
      if (!candidateNames.has(name)) return;
      if (p.parentPath?.isVariableDeclarator() && p.key === 'id') return;
      if (
        p.parentPath?.isObjectProperty() &&
        p.key === 'key' &&
        !(p.parentPath.node as t.ObjectProperty).computed
      )
        return;
      if (
        p.parentPath?.isMemberExpression() &&
        p.key === 'property' &&
        !(p.parentPath.node as t.MemberExpression).computed
      )
        return;
      if (p.parentPath?.isLabeledStatement() && p.key === 'label') return;
      if (p.parentPath?.isBreakStatement() && p.key === 'label') return;
      if (p.parentPath?.isContinueStatement() && p.key === 'label') return;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (!(p as any).isReferencedIdentifier()) return;
      const bindingKey = getBindingKey(p, name);
      if (!bindingKey) return;
      const candidate = candidates.get(bindingKey);
      if (!candidate) return;
      p.replaceWith(t.cloneNode(candidate, true));
      inlined.add(bindingKey);
      n++;
    },
  });

  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const name = p.node.id.name;
      const bindingKey = getBindingKey(p, name);
      if (!bindingKey || !inlined.has(bindingKey)) return;
      const decl = p.parent as t.VariableDeclaration;
      try {
        if (decl.declarations.length === 1) p.parentPath?.remove();
        else p.remove();
      } catch {
        /**/
      }
    },
  });

  log.pass('b08', 'constProp', n, undefined, `${inlined.size} vars inlined & removed`);
  return n;
}

function passProxyFunctions(ast: t.File, log: Logger): number {
  // The capture check below compares bindings: scope data must be current.
  freshProgram(ast);
  // ...and Babel does not see Annex B's function-scoped copies of block-level
  // function declarations, so a template reading such a name is never moved.
  const annexB = annexBNames(ast);
  // `free`: each name the forwarded callee reads, with the binding it means
  // inside the proxy (null for a global). A call site only gets the callee
  // when every one of those names means the same there — otherwise a local
  // that happens to share the name would capture it.
  type ProxyDef = { targetCallee: t.Expression; extraArgs: t.Expression[]; free: Map<string, Binding | null> };
  const proxies = new Map<string, ProxyDef>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proxyDeclPaths = new Map<string, any>();

  function detect(
    name: string,
    params: t.Function['params'],
    body: t.BlockStatement,
    declPath: any
  ) {
    // eslint-disable-line @typescript-eslint/no-explicit-any
    const stmts = body.body.filter((s) => !t.isEmptyStatement(s));
    if (stmts.length !== 1) return;
    const stmt = stmts[0];
    if (!t.isReturnStatement(stmt) || !stmt.argument || !t.isCallExpression(stmt.argument)) return;
    const call = stmt.argument as t.CallExpression;
    let targetCallee: t.Expression;
    if (t.isIdentifier(call.callee)) {
      if ((call.callee as t.Identifier).name === name) return;
      targetCallee = call.callee;
    } else if (t.isMemberExpression(call.callee)) {
      targetCallee = call.callee;
    } else return;
    const paramNames = params
      .filter((p): p is t.Identifier => t.isIdentifier(p))
      .map((p) => (p as t.Identifier).name);
    const callArgs = call.arguments;
    if (callArgs.length < paramNames.length) return;
    for (let i = 0; i < paramNames.length; i++) {
      const a = callArgs[i];
      if (!t.isIdentifier(a) || (a as t.Identifier).name !== paramNames[i]) return;
    }
    const extraSlice = callArgs.slice(paramNames.length);
    if (!extraSlice.every((a) => t.isExpression(a) && isPurelyLiteral(a as t.Expression))) return;
    const free = new Map<string, Binding | null>();
    let usesParam = false;
    walk(targetCallee, (x, parent) => {
      if (!t.isIdentifier(x) || (parent && !t.isReferenced(x, parent))) return;
      if (paramNames.includes(x.name)) usesParam = true;
      free.set(x.name, declPath.scope.getBinding(x.name) ?? null);
    });
    if (usesParam) return;
    if ([...free.keys()].some((fname) => annexB.has(fname))) return;
    proxies.set(name, { targetCallee, extraArgs: extraSlice as t.Expression[], free });
    proxyDeclPaths.set(name, declPath);
  }

  traverse(ast, {
    FunctionDeclaration(p) {
      if (p.node.id) detect(p.node.id.name, p.node.params, p.node.body, p);
    },
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !init) return;
      if (
        (t.isFunctionExpression(init) || t.isArrowFunctionExpression(init)) &&
        t.isBlockStatement(init.body)
      )
        detect(id.name, init.params, init.body as t.BlockStatement, p);
    },
  });
  if (proxies.size === 0) {
    log.pass('b09', 'proxyFns', 0);
    return 0;
  }

  const inlinedNames = new Set<string>();
  const kept = new Set<string>(); // a call site was left alone: the proxy stays
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      if (!t.isIdentifier(p.node.callee)) return;
      const name = (p.node.callee as t.Identifier).name;
      const def = proxies.get(name);
      if (!def) return;
      for (const [fname, b] of def.free)
        if ((p.scope.getBinding(fname) ?? null) !== b) {
          kept.add(name);
          return;
        }
      p.node.callee = t.cloneNode(def.targetCallee, true);
      if (def.extraArgs.length > 0)
        p.node.arguments.push(...def.extraArgs.map((a) => t.cloneNode(a, true)));
      inlinedNames.add(name);
      n++;
    },
  });

  // Inlining one proxy can create a call of another (`other()` → `get(0, 2)`):
  // remove a declaration only when a fresh crawl finds no reference left.
  const live = new Set<string>();
  {
    const fresh = freshProgram(ast);
    fresh.traverse({
      Identifier(ip) {
        if (inlinedNames.has(ip.node.name) && ip.isReferencedIdentifier()) live.add(ip.node.name);
      },
    });
  }
  for (const name of inlinedNames) {
    if (kept.has(name) || live.has(name)) continue;
    const declPath = proxyDeclPaths.get(name);
    if (!declPath) continue;
    try {
      if (declPath.isFunctionDeclaration()) declPath.remove();
      else if (declPath.isVariableDeclarator()) {
        const parentDecl = declPath.parent as t.VariableDeclaration;
        if (parentDecl.declarations.length === 1) declPath.parentPath?.remove();
        else declPath.remove();
      }
    } catch {
      /**/
    }
  }

  log.pass('b09', 'proxyFns', n, 'calls', `${inlinedNames.size} decls removed`);
  return n;
}

/**
 * `"k" in F` where F is an empty function nothing else touches → `false`.
 *
 * js-confuser's opaque predicates probe a random key against a parameterless,
 * empty function declared for that purpose: `if (!("O9ZPBKy" in dummy))`. The
 * probe is `false` when `k` is not a property of a plain function, and stays
 * `false` as long as nothing can add one. That holds when F is referenced only
 * as the right operand of such probes (so no property is ever written on it),
 * the key is spelled nowhere else in the program, and the program never
 * writes into a prototype object — whether through a member of `.prototype` /
 * `__proto__`, or by handing one to a call such as `Object.defineProperty`.
 * `k in function () {}` is evaluated here to rule out the names every function
 * inherits (`call`, `hasOwnProperty`, …), which are the same in every engine.
 */
function foldFunctionProbes(ast: t.File): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const literalUses = new Map<string, number>();
  // A write through a prototype chain the probed function could share:
  // either a blanket refusal (the key is not static, the object itself is
  // replaced or handed to a call) or the static key it adds. A probe only
  // folds when no such write spells its key — `S.prototype.get = …` from
  // an injected linked-list template cannot make `"soWeC2" in F` true.
  let prototypeWrites = false;
  const protoKeys = new Set<string>();
  const isProtoMember = (node: t.Node): boolean =>
    t.isMemberExpression(node) && ['prototype', '__proto__'].includes(staticMemberKey(node) ?? '');
  /** A function or class created in this program: its `prototype` is its own object. */
  const ownFunction = (node: t.Node, scope: NodePath['scope']): boolean => {
    if (!t.isIdentifier(node)) return false;
    const b = scope.getBinding(node.name);
    if (!b || b.constantViolations.length) return false;
    const d = b.path.node;
    return (
      t.isFunctionDeclaration(d) ||
      t.isClassDeclaration(d) ||
      (t.isVariableDeclarator(d) &&
        (t.isFunctionExpression(d.init) || t.isArrowFunctionExpression(d.init) || t.isClassExpression(d.init)))
    );
  };
  /** `X.prototype` / `X.__proto__` reaching a chain the dummy function could share. */
  const sharedProto = (node: t.Node, scope: NodePath['scope']): boolean =>
    isProtoMember(node) &&
    (staticMemberKey(node as t.MemberExpression) === '__proto__' ||
      !ownFunction((node as t.MemberExpression).object, scope));
  const noteProtoKey = (target: t.MemberExpression): void => {
    const key = staticMemberKey(target);
    if (key === null) prototypeWrites = true;
    else protoKeys.add(key);
  };
  program.traverse({
    StringLiteral(p) {
      literalUses.set(p.node.value, (literalUses.get(p.node.value) ?? 0) + 1);
    },
    AssignmentExpression(p) {
      const target = p.node.left;
      // Replacing a prototype object outright is refused for any function.
      if (isProtoMember(target)) prototypeWrites = true;
      else if (t.isMemberExpression(target) && sharedProto(target.object, p.scope)) noteProtoKey(target);
    },
    UpdateExpression(p) {
      if (t.isMemberExpression(p.node.argument) && sharedProto(p.node.argument.object, p.scope))
        noteProtoKey(p.node.argument);
    },
    CallExpression(p) {
      if (p.node.arguments.some((a) => sharedProto(a, p.scope))) prototypeWrites = true;
      const callee = p.node.callee;
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.property, { name: 'setPrototypeOf' }) &&
        !callee.computed
      )
        prototypeWrites = true;
    },
  });
  if (prototypeWrites) return 0;

  const probe = function () {};
  const usable = new Map<Binding, boolean>();
  let facts: Map<Binding, WriteOnceFact> | null = null;
  /** F holds one plain function wherever it is read: a declaration, or a write-once `var F = function () {…}`. */
  const plainFunction = (b: Binding): boolean => {
    const d = b.path;
    if (d.isFunctionDeclaration()) return !d.node.async && !d.node.generator && b.constantViolations.length === 0;
    facts ??= writeOnceFacts(program);
    const v = facts.get(b)?.value;
    return t.isFunctionExpression(v) && !v.async && !v.generator;
  };
  // F only ever stands right of `in`: nothing can reach it to add a property.
  // (Only probes with a literal key are folded; the others are reads too.)
  const isProbe = (r: NodePath): boolean => {
    const bin = r.parentPath;
    return !!bin && bin.isBinaryExpression({ operator: 'in' }) && bin.node.right === r.node;
  };
  let n = 0;
  program.traverse({
    BinaryExpression(p) {
      if (p.node.operator !== 'in') return;
      if (!t.isStringLiteral(p.node.left) || !t.isIdentifier(p.node.right)) return;
      const binding = p.scope.getBinding(p.node.right.name);
      if (!binding) return;
      let ok = usable.get(binding);
      if (ok === undefined) {
        // Its body is irrelevant: every reference is a probe, so it is never
        // called (other passes may have left a `return;` in it).
        ok =
          plainFunction(binding) &&
          !dyn.observesBinding(binding) &&
          binding.referencePaths.every(isProbe);
        usable.set(binding, ok);
      }
      if (!ok) return;
      const key = p.node.left.value;
      if (key in probe) return; // a name every function has
      if (literalUses.get(key) !== 1) return; // spelled elsewhere: could be a write
      if (protoKeys.has(key)) return; // a shared prototype gains this very name
      p.replaceWith(t.booleanLiteral(false));
      n++;
    },
  });
  return n;
}

/**
 * How many arguments can a call of this function supply? The most any call
 * site passes — when every use of the function is a call: an IIFE; a
 * declaration or write-once variable that is only called; a property of an
 * object literal held in a write-once local that is only ever used to call
 * its members (`T[k](…)`, `T[k].apply(this)`, `T[k].call(this, …)` — the
 * function is reachable through those calls alone). Infinity otherwise: an
 * escaping function may be called with anything.
 */
function knownArity(p: NodePath<t.Function>, dyn: DynamicScopes): number {
  const fn = p.node;
  const parent = p.parentPath;
  if ((t.isFunctionExpression(fn) || t.isArrowFunctionExpression(fn)) && parent.isCallExpression() && parent.node.callee === fn) {
    if (parent.node.arguments.some((a) => t.isSpreadElement(a))) return Infinity;
    if (t.isFunctionExpression(fn) && fn.id && p.scope.getBinding(fn.id.name)?.referenced) return Infinity;
    return parent.node.arguments.length;
  }
  if (parent.isObjectProperty() && parent.node.value === fn) {
    const obj = parent.parentPath;
    const holder = obj.parentPath;
    let ob: Binding | undefined;
    if (holder?.isVariableDeclarator() && t.isIdentifier(holder.node.id) && holder.node.init === obj.node) ob = holder.scope.getBinding(holder.node.id.name);
    else if (holder?.isAssignmentExpression({ operator: '=' }) && t.isIdentifier(holder.node.left) && holder.node.right === obj.node) ob = holder.scope.getBinding(holder.node.left.name);
    if (!ob || dyn.observesBinding(ob)) return Infinity;
    const writes = ob.constantViolations.filter((v) => v.node !== holder!.node).length + (ob.path.isVariableDeclarator() && ob.path.node.init && ob.path.node !== holder!.node ? 1 : 0);
    if (writes) return Infinity;
    if (!(obj.node as t.ObjectExpression).properties.every((pr) => t.isObjectProperty(pr) || t.isObjectMethod(pr))) return Infinity;
    let most = 0;
    for (const r of ob.referencePaths) {
      const m = r.parentPath;
      if (!m?.isMemberExpression() || m.node.object !== r.node) return Infinity;
      const c = m.parentPath;
      if (c?.isCallExpression() && c.node.callee === m.node) {
        if (c.node.arguments.some((a) => t.isSpreadElement(a))) return Infinity;
        most = Math.max(most, c.node.arguments.length);
        continue;
      }
      if (c?.isMemberExpression() && c.node.object === m.node) {
        const key = staticMemberKey(c.node);
        const cc = c.parentPath;
        if (cc?.isCallExpression() && cc.node.callee === c.node && !cc.node.arguments.some((a) => t.isSpreadElement(a))) {
          if (key === 'apply' && cc.node.arguments.length <= 1) continue; // apply(this): no arguments
          if (key === 'call') {
            most = Math.max(most, cc.node.arguments.length - 1);
            continue;
          }
        }
      }
      return Infinity;
    }
    return most;
  }
  const fnBinding = t.isFunctionDeclaration(fn) && fn.id
    ? parent.scope.getBinding(fn.id.name)
    : parent.isVariableDeclarator() && t.isIdentifier(parent.node.id) && parent.node.init === fn
      ? parent.scope.getBinding(parent.node.id.name)
      : null;
  if (!fnBinding || fnBinding.constantViolations.length || dyn.observesBinding(fnBinding)) return Infinity;
  let most = 0;
  for (const r of fnBinding.referencePaths) {
    const call = r.parentPath;
    // `new F(…)` supplies its arguments the same way
    if (!(call?.isCallExpression() || call?.isNewExpression()) || call.node.callee !== r.node) return Infinity; // escapes
    if (call.node.arguments.some((a) => t.isSpreadElement(a))) return Infinity;
    most = Math.max(most, call.node.arguments.length);
  }
  return most;
}

// ── B00e: moved declarations ─────────────────────────────────────────────────

/**
 * `function f(a, p) { if (!p) { p = function () {…} } … }`, called only as
 * `f(x)` → `function f(a, _p) { function p() {…} … }`
 *
 * js-confuser's movedDeclarations turns a function's locals into trailing
 * parameters: a `var` becomes a parameter assigned at the top (B00c handles
 * that), and a nested function declaration becomes a parameter set by
 * `if (!p) p = function …` as one of the leading statements. When every call
 * of f supplies fewer arguments than p's position — all references to f are
 * such calls, or f is an IIFE — p is `undefined` on entry, the guard always
 * fires, and p holds that function before any other statement runs: exactly
 * what a declaration of p in the body means, name and all. The parameter slot
 * stays, under a fresh name nothing reads, so the signature and `f.length`
 * are untouched and the slot's position does not matter.
 */
function passMovedDeclarations(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  let fns = 0;
  let moved = 0;
  type Job = { fn: NodePath<t.Function>; cut: number; slots: number[]; guards: NodePath<t.IfStatement>[]; decls: t.Statement[]; vars: Set<string> };
  const jobs: Job[] = [];
  program.traverse({
    Function(p) {
      const fn = p.node;
      if (!t.isBlockStatement(fn.body)) return;
      if ((t.isObjectMethod(fn) || t.isClassMethod(fn)) && fn.kind !== 'method') return;
      if (dyn.observes(p.scope)) return;
      // `arguments` is no obstacle: a mapped arguments object aliases only the
      // positions a call actually supplied, and a surplus parameter sits past
      // every call's last argument — so `arguments.length` and every
      // `arguments[i]` read the same before and after it becomes a local.
      // How many arguments can a call supply? Unknown (an escaping function) means
      // no parameter is surplus — `var` locals guarded the same way still qualify.
      const arity = (): number => knownArity(p, dyn);
      const maxArgs = fn.params.length ? arity() : Infinity;
      const surplus = new Map<string, number>();
      fn.params.forEach((prm, i) => {
        if (i >= maxArgs && t.isIdentifier(prm)) surplus.set(prm.name, i);
      });
      // A body-level `var` with no value is `undefined` on entry, just like a
      // never-supplied parameter: its guard fires the same way.
      const freshVar = (name: string): boolean => {
        const b = p.scope.getBinding(name);
        return !!b && b.kind === 'var' && b.scope === p.scope && b.path.isVariableDeclarator() && !b.path.node.init;
      };
      const vars = new Set<string>();
      // Leading guards `if (!p) p = <function>` for surplus parameters.
      const guards: NodePath<t.IfStatement>[] = [];
      const decls: t.Statement[] = [];
      const seen = new Set<string>();
      for (const st of (p.get('body') as NodePath<t.BlockStatement>).get('body')) {
        // Bare declarations (B00c's demoted locals, hoisted functions) can sit
        // among the guards: they read nothing on the way.
        if (st.isFunctionDeclaration() || st.isEmptyStatement()) continue;
        if (st.isVariableDeclaration() && st.node.declarations.every((d) => !d.init)) continue;
        if (!st.isIfStatement() || st.node.alternate) break;
        const test = st.node.test;
        if (!t.isUnaryExpression(test, { operator: '!' }) || !t.isIdentifier(test.argument)) break;
        const name = test.argument.name;
        const inner = t.isBlockStatement(st.node.consequent) && st.node.consequent.body.length === 1 ? st.node.consequent.body[0] : st.node.consequent;
        if (!t.isExpressionStatement(inner) || !t.isAssignmentExpression(inner.expression, { operator: '=' }) || !t.isIdentifier(inner.expression.left, { name })) break;
        const value = inner.expression.right;
        const asParam = surplus.has(name);
        const asVar = !asParam && freshVar(name);
        if ((!asParam && !asVar) || seen.has(name) || vars.has(name)) break;
        if (!t.isFunctionExpression(value) && !t.isArrowFunctionExpression(value)) break;
        const binding = p.scope.getBinding(name);
        // p is written here and nowhere else, so it holds this function throughout.
        if (!binding || binding.kind !== (asParam ? 'param' : 'var') || binding.constantViolations.length !== 1) break;
        if (asVar) vars.add(name);
        else seen.add(name);
        guards.push(st);
        decls.push(
          t.isFunctionExpression(value) && !value.id
            ? t.functionDeclaration(t.identifier(name), value.params, value.body, value.generator, value.async)
            : t.variableDeclaration('var', [t.variableDeclarator(t.identifier(name), value)])
        );
      }
      if (guards.length === 0) return;
      // Every reference being a call, nothing reads the arity: a trailing run
      // of guard slots can go outright; slots in the middle are renamed.
      let cut = fn.params.length;
      while (cut > 0 && t.isIdentifier(fn.params[cut - 1]) && seen.has((fn.params[cut - 1] as t.Identifier).name)) cut--;
      jobs.push({ fn: p, cut, slots: [...seen].map((name) => surplus.get(name)!).filter((i) => i < cut), guards, decls, vars });
    },
  });
  for (const job of jobs) {
    try {
      for (const g of job.guards) g.remove();
      const fn = job.fn.node as t.Function & { body: t.BlockStatement };
      for (const i of job.slots) fn.params[i] = job.fn.scope.generateUidIdentifier('unused');
      fn.params = fn.params.slice(0, job.cut);
      // a converted `var` is now declared by its function declaration
      if (job.vars.size)
        fn.body.body = fn.body.body
          .map((st) => {
            if (t.isVariableDeclaration(st) && st.kind === 'var')
              st.declarations = st.declarations.filter((d) => !(t.isIdentifier(d.id) && job.vars.has(d.id.name) && !d.init));
            return st;
          })
          .filter((st) => !(t.isVariableDeclaration(st) && st.declarations.length === 0));
      fn.body.body.unshift(...job.decls);
      fns++;
      moved += job.decls.length;
    } catch {
      /**/
    }
  }
  log.pass('b00e', 'movedDeclarations', moved, 'declarations', `${fns} functions`);
  return moved;
}

/**
 * A top-level `const` array of literals that is only ever read element by
 * element, out of reach of any direct `eval` — duplicateLiteralsRemoval's
 * table. Its entries are constants wherever they are read.
 */
function isImmutableLiteralTable(b: Binding, dyn: DynamicScopes): boolean {
  // Any `const`: none can be rebound, and one inside a function (js-confuser's
  // pack wrapper) is even more private than a script-level one.
  if (b.kind !== 'const' || !b.path.isVariableDeclarator()) return false;
  const init = b.path.node.init;
  if (!t.isArrayExpression(init) || !init.elements.every((e) => !!e && (isCopyableLiteral(e) || t.isIdentifier(e, { name: 'undefined' }))))
    return false;
  if (dyn.observesBinding(b)) return false;
  return b.referencePaths.every((r) => {
    const m = r.parentPath;
    if (!m?.isMemberExpression() || m.node.object !== r.node || !m.node.computed) return false;
    const up = m.parentPath;
    return !((up?.isAssignmentExpression() && up.node.left === m.node) || up?.isUpdateExpression() || up?.isUnaryExpression({ operator: 'delete' }));
  });
}

// ── B01e: concealed globals ──────────────────────────────────────────────────

/**
 * js-confuser's globalConcealing routes every global through a switch table
 * over the global object:
 *
 *   var GV = probe();                      // the getGlobal template → globalThis
 *   function getGlobal(k) { switch (k) { case "x1": return GV["console"]; … } }
 *   getGlobal("x1")["log"](…)
 *
 * The probe tries `globalThis` first and accepts it as soon as it carries
 * `String`, which any ES2020 host guarantees: `probe()` is `globalThis` (and
 * `probe() || {}` too, an object being truthy). A table call with a literal
 * key is the matching case's expression, a property read of GV performed at
 * the same moment, provided GV names the same binding at the call site. B01d
 * then drops the `globalThis.` prefix from the built-ins it knows.
 */
function passConcealedGlobals(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  let probes = 0;
  let lookups = 0;

  const PROBE_GLOBALS = new Set(['globalThis', 'global', 'window', 'self', 'Function', 'Object', 'undefined']);
  const isProbe = (p: NodePath<t.FunctionDeclaration | t.FunctionExpression>): boolean => {
    const fn = p.node;
    if (fn.params.length || fn.async || fn.generator) return false;
    // `var A = [thunks]`, or movedDeclarations' `var A, …; A = [thunks];` —
    // after any number of value-less `var` statements (nothing runs in them)
    const body = fn.body.body;
    let k = 0;
    while (k < body.length && t.isVariableDeclaration(body[k], { kind: 'var' }) && (body[k] as t.VariableDeclaration).declarations.every((d) => !d.init)) k++;
    const s0 = body[k];
    let arr: t.Node | null | undefined = null;
    if (t.isVariableDeclaration(s0) && s0.declarations[0]?.init) arr = s0.declarations[0].init;
    else if (t.isExpressionStatement(s0) && t.isAssignmentExpression(s0.expression, { operator: '=' }) && t.isIdentifier(s0.expression.left)) {
      const b = p.scope.getBinding(s0.expression.left.name);
      if (b && b.scope === p.scope) arr = s0.expression.right;
    }
    if (!t.isArrayExpression(arr) || arr.elements.length < 2) return false;
    const e0 = arr.elements[0];
    if (!t.isFunctionExpression(e0) || e0.body.body.length !== 1) return false;
    const r = e0.body.body[0];
    if (!t.isReturnStatement(r) || !t.isIdentifier(r.argument, { name: 'globalThis' })) return false;
    if (!arr.elements.every((e) => t.isFunctionExpression(e) || t.isArrowFunctionExpression(e))) return false;
    if (p.scope.getBinding('globalThis')) return false;
    // The fallback thunks (elements 1…) only run if `globalThis` fails the
    // probe's check, which an ES2020 host never does — so what they read
    // cannot matter (js-confuser's pack transform has one read its global
    // argument; its controlFlowFlattening fills one with machinery). Every
    // other part of the probe must be closed: no outer writes, and reads only
    // of probe globals or fixed literal tables.
    const fallbacks = new Set<t.Node>(arr.elements.slice(1) as t.Node[]);
    let closed = true;
    const own = (b: Binding): boolean => {
      for (let s: NodePath['scope'] | undefined = b.scope; s; s = s.parent) if (s.path.node === fn) return true;
      return false;
    };
    const check = (q: NodePath, name: string, write: boolean): void => {
      const b = q.scope.getBinding(name);
      if (!b) {
        if (write || !PROBE_GLOBALS.has(name)) closed = false;
      } else if (!own(b) && (write || !isImmutableLiteralTable(b, dyn))) closed = false;
    };
    p.get('body').traverse({
      enter(q) {
        if (fallbacks.has(q.node)) q.skip();
      },
      Identifier(q) {
        if (q.isReferencedIdentifier()) check(q, q.node.name, false);
      },
      AssignmentExpression(q) {
        const left = q.node.left;
        const base = t.isMemberExpression(left) ? memberRoot(left) : null;
        if (base) check(q, base.name, true);
        else if (!t.isMemberExpression(left)) for (const name of Object.keys(t.getBindingIdentifiers(left))) check(q, name, true);
        else closed = false;
      },
      UpdateExpression(q) {
        const arg = q.node.argument;
        const base = t.isIdentifier(arg) ? arg : t.isMemberExpression(arg) ? memberRoot(arg) : null;
        if (base) check(q, base.name, true);
        else closed = false;
      },
      UnaryExpression(q) {
        if (q.node.operator === 'delete') closed = false;
      },
    });
    return closed;
  };

  const probeCalls: NodePath[] = [];
  /** The binding a probe function is stored in: its declaration, or `var X = function …`. */
  const probeBinding = (p: NodePath<t.FunctionDeclaration | t.FunctionExpression>): Binding | null => {
    if (p.isFunctionDeclaration()) {
      const id = p.node.id;
      const b = id ? p.parentPath.scope.getBinding(id.name) : undefined;
      return b && b.path.node === p.node ? b : null;
    }
    const d = p.parentPath;
    if (!d?.isVariableDeclarator() || d.node.init !== p.node || !t.isIdentifier(d.node.id)) return null;
    const b = d.scope.getBinding(d.node.id.name);
    return b && b.path.node === d.node ? b : null;
  };
  const collectProbe = (p: NodePath<t.FunctionDeclaration | t.FunctionExpression>): void => {
    const binding = probeBinding(p);
    if (!binding || binding.constantViolations.length) return;
    if (dyn.observesBinding(binding) || !isProbe(p)) return;
    for (const r of binding.referencePaths) {
      const call = r.parentPath;
      if (call?.isCallExpression() && call.node.callee === r.node && call.node.arguments.length === 0) probeCalls.push(call);
    }
  };
  program.traverse({ FunctionDeclaration: collectProbe, FunctionExpression: collectProbe });
  // The eval spelling of the probe, once its evals are inlined:
  // `function F() { return this; }` (or `const x = this; return x;`). In
  // sloppy code a plain call `F()` runs with `this` = the global object.
  const sloppy = (p: NodePath): boolean => {
    if (program.node.sourceType === 'module') return false;
    if (program.node.directives.some((d) => d.value.value === 'use strict')) return false;
    for (let q: NodePath | null = p; q; q = q.parentPath) {
      if (q.isClass()) return false;
      if (q.isFunction() && t.isBlockStatement(q.node.body) && q.node.body.directives.some((d) => d.value.value === 'use strict')) return false;
    }
    return true;
  };
  const returnsThis = (fn: t.FunctionDeclaration): boolean => {
    const b = fn.body.body;
    if (b.length === 1) return t.isReturnStatement(b[0]) && t.isThisExpression(b[0].argument);
    if (b.length !== 2 || !t.isVariableDeclaration(b[0]) || b[0].declarations.length !== 1) return false;
    const d = b[0].declarations[0];
    return t.isIdentifier(d.id) && t.isThisExpression(d.init) && t.isReturnStatement(b[1]) && t.isIdentifier(b[1].argument, { name: d.id.name });
  };
  program.traverse({
    FunctionDeclaration(p) {
      const fn = p.node;
      if (!fn.id || fn.async || fn.generator || !returnsThis(fn) || !sloppy(p) || p.scope.getBinding('globalThis')) return;
      const b = p.parentPath.scope.getBinding(fn.id.name);
      if (!b || b.path.node !== fn || b.constantViolations.length || dyn.observesBinding(b)) return;
      const calls: NodePath[] = [];
      for (const r of b.referencePaths) {
        const call = r.parentPath;
        if (!call?.isCallExpression() || call.node.callee !== r.node || call.node.arguments.length) return;
        calls.push(call);
      }
      probeCalls.push(...calls);
    },
  });
  for (const call of probeCalls) {
    try {
      const parent = call.parentPath;
      if (parent?.isLogicalExpression({ operator: '||' }) && parent.node.left === call.node && t.isObjectExpression(parent.node.right) && parent.node.right.properties.length === 0)
        parent.replaceWith(t.identifier('globalThis'));
      else call.replaceWith(t.identifier('globalThis'));
      probes++;
    } catch {
      /**/
    }
  }

  // Switch tables.
  type Table = { cases: Map<string, t.Expression>; object: string; scope: NodePath['scope'] };
  const tables = new Map<Binding, Table>();
  const fresh = probes ? freshProgram(ast) : program;
  fresh.traverse({
    FunctionDeclaration(p) {
      const fn = p.node;
      if (!fn.id || fn.params.length !== 1 || !t.isIdentifier(fn.params[0])) return;
      // the switch alone, or followed by a bare `return;` (no case matched)
      const [sw, tail, ...more] = fn.body.body;
      if (more.length || (tail && !(t.isReturnStatement(tail) && !tail.argument))) return;
      if (!t.isSwitchStatement(sw) || !t.isIdentifier(sw.discriminant, { name: fn.params[0].name })) return;
      const cases = new Map<string, t.Expression>();
      let object: string | null = null;
      // an empty case falls through to the next one's return
      let pending: string[] = [];
      for (const c of sw.cases) {
        if (!c.test || !t.isStringLiteral(c.test)) return;
        if (cases.has(c.test.value) || pending.includes(c.test.value)) return;
        if (c.consequent.length === 0) {
          pending.push(c.test.value);
          continue;
        }
        if (c.consequent.length !== 1) return;
        const r = c.consequent[0];
        if (!t.isReturnStatement(r)) return;
        // `GV.X`, or — once B01d has dropped the prefix of a built-in — a bare
        // global name (checked unshadowed at each site below)
        if (t.isIdentifier(r.argument) && !p.scope.getBinding(r.argument.name)) {
          for (const k of [...pending, c.test.value]) cases.set(k, r.argument);
          pending = [];
          continue;
        }
        if (!t.isMemberExpression(r.argument) || !t.isIdentifier(r.argument.object)) return;
        if (staticMemberKey(r.argument) === null) return;
        if (object !== null && object !== r.argument.object.name) return;
        object = r.argument.object.name;
        for (const k of [...pending, c.test.value]) cases.set(k, r.argument);
        pending = [];
      }
      if (pending.length) return; // trailing empty cases fall off: undefined
      if (object === null) object = 'globalThis';
      const scope = p.parentPath.scope;
      const binding = scope.getBinding(fn.id.name);
      if (!binding || binding.path.node !== fn || binding.constantViolations.length || dyn.observesBinding(binding)) return;
      if (p.scope.hasOwnBinding(object)) return; // the table reads an outer GV, not a local
      tables.set(binding, { cases, object, scope });
    },
  });
  for (const [binding, table] of tables) {
    const gv = table.scope.getBinding(table.object);
    for (const r of binding.referencePaths) {
      const call = r.parentPath;
      if (!call?.isCallExpression() || call.node.callee !== r.node || call.node.arguments.length !== 1) continue;
      const arg = call.node.arguments[0];
      if (!t.isStringLiteral(arg)) continue;
      const value = table.cases.get(arg.value);
      if (!value) continue;
      if (call.scope.getBinding(table.object) !== gv) continue;
      if (t.isIdentifier(value) && call.scope.getBinding(value.name)) continue; // a bare global, shadowed here
      try {
        call.replaceWith(t.cloneNode(value, true));
        lookups++;
      } catch {
        /**/
      }
    }
  }
  // The probe and the tables write nothing: once unreferenced they can go.
  let removed = 0;
  if (probes + lookups > 0) {
    const after = freshProgram(ast);
    const doomed = new Set<t.Node>([...tables.keys()].map((b) => b.path.node));
    for (const pc of probeCalls) void pc;
    const drop = (p: NodePath<t.FunctionDeclaration | t.FunctionExpression>): void => {
      const isTable = doomed.has(p.node);
      if (!isTable && !isProbe(p)) return;
      const b = probeBinding(p);
      if (!b || b.referencePaths.length || b.constantViolations.length) return;
      try {
        // a `var X = function …` probe goes with its declarator
        if (p.isFunctionExpression()) {
          const d = p.parentPath as NodePath<t.VariableDeclarator>;
          const vd = d.parentPath as NodePath<t.VariableDeclaration>;
          if (vd.node.declarations.length === 1) vd.remove();
          else d.remove();
        } else p.remove();
        removed++;
      } catch {
        /**/
      }
    };
    after.traverse({ FunctionDeclaration: drop, FunctionExpression: drop });
  }
  log.pass('b01e', 'concealedGlobals', probes + lookups + removed, 'rewrites', `${probes} probes · ${lookups} lookups · ${removed} removed`);
  return probes + lookups + removed;
}

// ── B05d: concealed strings (js-confuser) ────────────────────────────────────

/**
 * js-confuser's string concealing keeps every string in one top-level pool and
 * reads each back through a per-block retriever and decoder:
 *
 *   var POOL = "…decoys…<encoded>…";
 *   function DEC(str) { var table = "…"; … return BTS(bytes); }   // base-91 by default
 *   function STR(start, length) { return DEC(POOL["slice"](start, start + length)); }
 *   … STR(170, 8) …
 *
 * BTS is the template's UTF-8 finisher: TextDecoder when present, otherwise
 * Buffer.from(bytes).toString("utf-8"), otherwise a hand-written decoder —
 * three spellings of one function of the bytes (js-confuser itself verifies
 * each string through the TextDecoder spelling before concealing it). A
 * retriever call with literal arguments is therefore a constant, computed here
 * by running DEC in a sealed VM over the pool slice with BTS standing in as
 * TextDecoder. DEC has to be closed — its free names are deterministic
 * built-ins, BTS, or other closed declarations, and it writes nothing outside
 * itself — the pool has to be a write-once string, and every probe has to give
 * the same string forward and in reverse order. Retrievers, decoders and the
 * pool go once nothing references them, and so does the BTS machinery, whose
 * initialisers only probe the global object and build lookup tables.
 */
function passConcealedStrings(ast: t.File, log: Logger, strict = false): number {
  const program = freshProgram(ast);
  // A direct `eval` whose argument is itself a concealed string — `eval(R(5, 9))`
  // — makes every retriever in its scope chain look observable, yet the string
  // it evaluates is computed before it runs. Unless `strict`, such evals are set
  // aside while probing; every fold is held back until each one's decoded
  // source is shown to reach none of the machinery (below). Only when every
  // eval in the program is of that shape.
  // `D[k]` read from a `const` array of literals that nothing ever
  // writes through (every reference an element read): its value is fixed.
  const tableNames = new Set<string>();
  const tableBindings = new Set<Binding>();
  const tableMemo = new Map<Binding, t.ArrayExpression | null>();
  // Set once the eval analysis below exists; while deciding which evals to set
  // aside, the tables are judged on their own uses alone.
  let dynCheck: ((b: Binding) => boolean) | null = null;
  // The one value a binding holds wherever it is read: a `const`'s
  // initialiser, or a write-once `var` (writeOnceFacts — no read can precede
  // the write).
  let woFacts: Map<Binding, WriteOnceFact> | null = null;
  const fixedValue = (b: Binding): t.Expression | null => {
    const init = b.path.isVariableDeclarator() ? b.path.node.init : null;
    if (b.kind === 'const') return init ?? null;
    if (b.kind !== 'var' && b.kind !== 'let') return null;
    woFacts ??= writeOnceFacts(program);
    return woFacts.get(b)?.value ?? null;
  };
  // Methods that read an array without changing it or exposing it.
  const READ_ONLY_METHODS = new Set(['slice', 'indexOf', 'includes', 'join', 'concat', 'at']);
  /** The literal array a binding holds, if nothing can ever change it. */
  const immutableTable = (b: Binding | undefined): t.ArrayExpression | null => {
    if (!b) return null;
    if (tableMemo.has(b)) return tableMemo.get(b)!;
    let out: t.ArrayExpression | null = null;
    const init = fixedValue(b);
    if (
      t.isArrayExpression(init) &&
      init.elements.every((e) => !!e && (isCopyableLiteral(e) || t.isIdentifier(e, { name: 'undefined' }))) &&
      !(dynCheck?.(b) ?? false) &&
      b.referencePaths.every((r) => {
        const m = r.parentPath;
        if (!m?.isMemberExpression() || m.node.object !== r.node) return false;
        const up = m.parentPath;
        if ((up?.isAssignmentExpression() && up.node.left === m.node) || up?.isUpdateExpression() || up?.isUnaryExpression({ operator: 'delete' })) return false;
        if (m.node.computed) return true; // an element read
        const key = staticMemberKey(m.node);
        if (key === 'length') return true;
        return key !== null && READ_ONLY_METHODS.has(key) && !!up?.isCallExpression() && up.node.callee === m.node;
      })
    )
      out = init;
    tableMemo.set(b, out);
    return out;
  };
  /** A string a binding holds, if nothing can ever change it (a pool). */
  const fixedString = (b: Binding | undefined): t.StringLiteral | null => {
    if (!b || (dynCheck?.(b) ?? false)) return null;
    const v = fixedValue(b);
    return t.isStringLiteral(v) ? v : null;
  };
  const fixedData = (b: Binding | undefined): t.Expression | null => immutableTable(b) ?? fixedString(b);
  const constTableValue = (n: t.Node, scope: NodePath['scope']): { ok: boolean; value?: unknown } => {
    if (!t.isMemberExpression(n) || !n.computed || !t.isIdentifier(n.object) || !t.isNumericLiteral(n.property)) return { ok: false };
    const tb = scope.getBinding(n.object.name);
    const table = immutableTable(tb);
    const el = table?.elements[n.property.value];
    if (!el) return { ok: false };
    tableNames.add(n.object.name);
    tableBindings.add(tb!);
    return evalPure(el as t.Expression);
  };
  const resolveArg = (a: t.Node, scope: NodePath['scope']): { ok: boolean; value?: unknown } =>
    t.isExpression(a) && isPurelyLiteral(a) ? evalPure(a) : constTableValue(a, scope);
  /** A `+` tree of literals, fixed table reads and two-argument calls with resolvable arguments. */
  const evalArgShape = (e: t.Node, scope: NodePath['scope']): boolean => {
    if (t.isStringLiteral(e) || t.isNumericLiteral(e)) return true;
    if (t.isBinaryExpression(e, { operator: '+' })) return evalArgShape(e.left, scope) && evalArgShape(e.right, scope);
    if (t.isMemberExpression(e)) return constTableValue(e, scope).ok;
    return t.isCallExpression(e) && t.isIdentifier(e.callee) && e.arguments.length === 2 && e.arguments.every((x) => resolveArg(x, scope).ok);
  };
  const evalArgSites = new Set<t.Node>();
  const evalArgPaths = new Map<t.Node, NodePath>();
  let otherEvals = false;
  if (!strict)
    program.traverse({
      CallExpression(p) {
        if (!t.isIdentifier(p.node.callee, { name: 'eval' }) || p.scope.hasBinding('eval', { noGlobals: true })) return;
        const a = p.node.arguments[0];
        if (p.node.arguments.length === 1 && a && evalArgShape(a, p.scope)) {
          evalArgSites.add(p.node);
          evalArgPaths.set(p.node, p);
        }
        else otherEvals = true;
      },
      WithStatement() {
        otherEvals = true;
      },
    });
  const loose = !strict && evalArgSites.size > 0 && !otherEvals;
  const dyn = loose ? dynamicScopes(program, { ignore: evalArgSites }) : dynamicScopes(program);
  dynCheck = (b) => dyn.observesBinding(b);
  tableMemo.clear();
  /** Folds held until the end, so a failed eval check leaves the AST untouched. */
  const pendingFolds: Array<{ path: NodePath; value: string }> = [];
  /**
   * The one value a `var` holds: its initialiser, or — js-confuser's
   * movedDeclarations spelling, `var X; … X = v;` — the single assignment to
   * it. With `inertPrefix`, that assignment must sit in its block's inert
   * prefix, so no call (hence no read from a hoisted function) can precede it.
   */
  const singleValue = (b: Binding | undefined, inertPrefix: boolean): t.Expression | null => {
    if (!b || !b.path.isVariableDeclarator() || !t.isIdentifier(b.path.node.id)) return null;
    if (b.path.node.init) return b.constantViolations.length === 0 ? b.path.node.init : null;
    if (b.constantViolations.length !== 1) return null;
    const v = b.constantViolations[0];
    const stmt = v.parentPath;
    if (!v.isAssignmentExpression({ operator: '=' })) return null;
    // Without the inert-prefix demand the write may sit anywhere (a sequence,
    // a call's arguments): the binding is then either still `undefined` or
    // this value — which is all the finisher's `typeof` guards rely on.
    if (!inertPrefix) return v.node.right;
    if (!stmt?.isExpressionStatement()) return null;
    if (inertPrefix) {
      const list = stmt.parentPath;
      if (!list || !(list.isProgram() || list.isBlockStatement())) return null;
      const body = list.node.body as t.Statement[];
      for (const st of body) {
        if (st === stmt.node) break;
        if (!isInertStatement(st)) return null;
      }
      // The prefix must open the binding's own scope (the program, or the
      // function's body block), so nothing in that scope runs before it.
      const owner = b.scope.path;
      const ownBody = owner.isProgram() ? owner.node : owner.isFunction() ? owner.node.body : null;
      if (list.node !== ownBody) return null;
    }
    return v.node.right;
  };

  // ── the UTF-8 finisher ────────────────────────────────────────────────────
  const finishers = new Set<Binding>();
  const machinery = new Set<Binding>();
  // `var A = g.TextDecoder` — or `var A = TextDecoder` once B01d has dropped
  // the global-object prefix from a built-in
  const globalRead = (b: Binding | undefined, key: string): boolean => {
    const v = singleValue(b, false);
    if (!v) return false;
    if (t.isIdentifier(v, { name: key }) && !b!.scope.getBinding(key)) return true;
    return t.isMemberExpression(v) && t.isIdentifier(v.object) && staticMemberKey(v) === key;
  };
  // `"undefined"` — or, after duplicateLiteralsRemoval, a fixed table entry holding it
  const isUndefinedText = (n: t.Node, scope: NodePath['scope']): boolean => {
    if (t.isStringLiteral(n, { value: 'undefined' })) return true;
    const v = constTableValue(n, scope);
    return v.ok && v.value === 'undefined';
  };
  const typeofGuard = (test: t.Node, name: string, scope: NodePath['scope']): boolean =>
    t.isLogicalExpression(test, { operator: '&&' }) &&
    t.isBinaryExpression(test.left, { operator: '!==' }) &&
    t.isUnaryExpression(test.left.left, { operator: 'typeof' }) &&
    t.isIdentifier(test.left.left.argument, { name }) &&
    isUndefinedText(test.left.right, scope) &&
    t.isIdentifier(test.right, { name });
  program.traverse({
    FunctionDeclaration(p) {
      const fn = p.node;
      if (!fn.id || fn.params.length !== 1) return;
      // `function F(buf) { return … }`, or variableMasking's
      // `function F(...J) { J.length = 1; return … J[0] … }` (indices possibly
      // read from a fixed table)
      const p0 = fn.params[0];
      const keyOf = (n: t.Node): unknown => {
        if (t.isNumericLiteral(n) || t.isStringLiteral(n)) return n.value;
        const v = constTableValue(n, p.scope);
        return v.ok ? v.value : undefined;
      };
      let isBuf: (n: t.Node | null | undefined) => boolean;
      let body = fn.body.body;
      if (t.isIdentifier(p0)) {
        isBuf = (n) => t.isIdentifier(n, { name: p0.name });
      } else if (t.isRestElement(p0) && t.isIdentifier(p0.argument)) {
        const J = p0.argument.name;
        const jb = p.scope.getBinding(J);
        if (!jb) return;
        isBuf = (n) => t.isMemberExpression(n) && n.computed && t.isIdentifier(n.object, { name: J }) && keyOf(n.property) === 0;
        // an optional leading `J.length = 1` (reads stay within the one argument)
        const st = body[0];
        if (
          body.length === 2 &&
          t.isExpressionStatement(st) &&
          t.isAssignmentExpression(st.expression, { operator: '=' }) &&
          t.isMemberExpression(st.expression.left) &&
          t.isIdentifier(st.expression.left.object, { name: J }) &&
          (st.expression.left.computed ? keyOf(st.expression.left.property) : staticMemberKey(st.expression.left)) === 'length'
        )
          body = body.slice(1);
        // J is read only as J[0]
        if (!jb.referencePaths.every((r) => isBuf(r.parentPath?.node) || (r.parentPath?.isMemberExpression() && r.parentPath.parentPath?.isAssignmentExpression() && r.parentPath.parentPath.node.left === r.parentPath.node && r.parentPath.parentPath.parentPath?.node === st)))
          return;
      } else return;
      if (body.length !== 1) return;
      const s1 = body[0];
      const ret = (n: t.Node | null | undefined): t.Expression | null => {
        const st = t.isBlockStatement(n) && n.body.length === 1 ? n.body[0] : n;
        return t.isReturnStatement(st) && st.argument ? st.argument : null;
      };
      // `if (a) return x; else if (b) return y; else return z;` — or, minified,
      // `return a ? x : b ? y : z;`
      let test1: t.Node, test2: t.Node, r1: t.Expression | null, r2: t.Expression | null, r3: t.Expression | null;
      if (t.isIfStatement(s1) && t.isIfStatement(s1.alternate)) {
        test1 = s1.test;
        test2 = s1.alternate.test;
        r1 = ret(s1.consequent);
        r2 = ret(s1.alternate.consequent);
        r3 = ret(s1.alternate.alternate);
      } else if (t.isReturnStatement(s1) && t.isConditionalExpression(s1.argument) && t.isConditionalExpression(s1.argument.alternate)) {
        test1 = s1.argument.test;
        test2 = s1.argument.alternate.test;
        r1 = s1.argument.consequent;
        r2 = s1.argument.alternate.consequent;
        r3 = s1.argument.alternate.alternate;
      } else return;
      if (!r1 || !r2 || !r3) return;
      // return new A()["decode"](new B(buffer))
      if (!t.isCallExpression(r1) || !t.isMemberExpression(r1.callee) || staticMemberKey(r1.callee) !== 'decode') return;
      const dec = r1.callee.object;
      if (!t.isNewExpression(dec) || !t.isIdentifier(dec.callee) || dec.arguments.length || r1.arguments.length !== 1) return;
      const bytes = r1.arguments[0];
      if (!t.isNewExpression(bytes) || !t.isIdentifier(bytes.callee) || bytes.arguments.length !== 1 || !isBuf(bytes.arguments[0])) return;
      if (!typeofGuard(test1, dec.callee.name, p.scope)) return;
      // return C["from"](buffer)["toString"]("utf-8")
      if (!t.isCallExpression(r2) || !t.isMemberExpression(r2.callee) || staticMemberKey(r2.callee) !== 'toString') return;
      if (r2.arguments.length !== 1 || !t.isStringLiteral(r2.arguments[0]) || !/^utf-?8$/i.test(r2.arguments[0].value)) return;
      const from = r2.callee.object;
      if (!t.isCallExpression(from) || !t.isMemberExpression(from.callee) || staticMemberKey(from.callee) !== 'from' || !t.isIdentifier(from.callee.object)) return;
      if (from.arguments.length !== 1 || !isBuf(from.arguments[0])) return;
      if (!typeofGuard(test2, from.callee.object.name, p.scope)) return;
      // return F(buffer)
      if (!t.isCallExpression(r3) || !t.isIdentifier(r3.callee) || r3.arguments.length !== 1 || !isBuf(r3.arguments[0])) return;
      const scope = p.parentPath.scope;
      // Each constructor may be reached as a direct global (`TextDecoder`,
      // stringEncoding's spelling) or through an alias var (`var A =
      // g.TextDecoder`, stringConcealing's). `false` means neither; a Binding is
      // an alias to sweep; `null` is a free global with nothing to remove.
      const globalOrAlias = (name: string, expected: string): Binding | null | false => {
        const b = scope.getBinding(name);
        if (!b) return name === expected ? null : false;
        return globalRead(b, expected) ? b : false;
      };
      const A = globalOrAlias(dec.callee.name, 'TextDecoder');
      const B = globalOrAlias(bytes.callee.name, 'Uint8Array');
      const C = globalOrAlias(from.callee.object.name, 'Buffer');
      const F = scope.getBinding(r3.callee.name);
      if (A === false || B === false || C === false || !F) return;
      const self = scope.getBinding(fn.id.name);
      if (!self || self.path.node !== fn || dyn.observesBinding(self)) return;
      if (!self.constantViolations.every((v) => v.node === fn)) return;
      finishers.add(self);
      for (const b of [A, B, C, F]) if (b) machinery.add(b);
    },
  });

  // ── pools and retrievers ──────────────────────────────────────────────────
  // `pool` is null when the pool is written in place (`"…".slice(…)`, once
  // B08b has inlined a single-use pool variable).
  //
  // Retrievers and decoders are fixed functions: a declaration never
  // reassigned, or — js-confuser's spelling once flattening moved them into
  // blocks — a binding holding one anonymous function expression that every
  // read observes (writeOnceFacts), which a call can only find in place.
  type FnDef = { binding: Binding; fn: t.FunctionDeclaration | t.FunctionExpression; path: NodePath<t.FunctionDeclaration | t.FunctionExpression>; name: string };
  const fnDefs = new Map<Binding, FnDef>();
  // (Babel files a block-level function declaration as its own violation.)
  const ownOnly = (b: Binding) => b.constantViolations.every((v) => v.node === b.path.node);
  // js-confuser's no-op: `function N() { N = function () {}; }` — whichever
  // of the two it is when called, it does nothing and returns undefined.
  const noops = new Set<Binding>();
  const isNoop = (fn: t.FunctionDeclaration): boolean => {
    const [st, ...rest] = fn.body.body;
    return (
      !rest.length &&
      !fn.params.length &&
      t.isExpressionStatement(st) &&
      t.isAssignmentExpression(st.expression, { operator: '=' }) &&
      t.isIdentifier(st.expression.left, { name: fn.id?.name }) &&
      t.isFunctionExpression(st.expression.right) &&
      !st.expression.right.params.length &&
      !st.expression.right.body.body.length
    );
  };
  program.traverse({
    FunctionDeclaration(p) {
      const id = p.node.id;
      const b = id ? p.parentPath.scope.getBinding(id.name) : undefined;
      if (!b || !id || b.path.node !== p.node) return;
      if (ownOnly(b)) fnDefs.set(b, { binding: b, fn: p.node, path: p, name: id.name });
      else if (isNoop(p.node) && b.constantViolations.every((v) => v.node === p.node || pathWithin(v, p.node))) {
        fnDefs.set(b, { binding: b, fn: p.node, path: p, name: id.name });
        noops.add(b);
      }
    },
  });
  for (const fact of writeOnceFacts(program).values()) {
    const v = fact.value;
    if (!t.isFunctionExpression(v) || v.id || !['var', 'let', 'const'].includes(fact.binding.kind)) continue;
    const vp = (fact.assignment ? fact.assignment.get('right') : (fact.binding.path as NodePath<t.VariableDeclarator>).get('init')) as NodePath<t.FunctionExpression>;
    fnDefs.set(fact.binding, { binding: fact.binding, fn: v, path: vp, name: fact.binding.identifier.name });
  }
  /** The definition as a declaration, for the sandbox. */
  const asDecl = (d: FnDef): t.FunctionDeclaration =>
    t.isFunctionDeclaration(d.fn) ? d.fn : t.functionDeclaration(t.identifier(d.name), d.fn.params, d.fn.body, d.fn.generator, d.fn.async);
  // `general`: not the template's shape — any closed two-parameter function
  // reading a fixed string pool (a retriever js-confuser went on to flatten,
  // mask or otherwise rewrite). It is its own decoder; the sandbox runs it as
  // it stands, over the pool it reads.
  type Retriever = { binding: Binding; def: FnDef; decoder: Binding; pool: Binding | null; poolValue: t.StringLiteral | null; general?: boolean };
  const retrievers: Retriever[] = [];
  for (const def of fnDefs.values()) {
    (() => {
      const fn = def.fn;
      const p = def.path;
      if (fn.async || fn.generator || fn.params.length !== 2 || fn.body.body.length !== 1) return;
      const [ps, pl] = fn.params;
      if (!t.isIdentifier(ps) || !t.isIdentifier(pl)) return;
      const ret = fn.body.body[0];
      if (!t.isReturnStatement(ret) || !t.isCallExpression(ret.argument) || !t.isIdentifier(ret.argument.callee)) return;
      if (ret.argument.arguments.length !== 1) return;
      const slice = ret.argument.arguments[0];
      if (!t.isCallExpression(slice) || !t.isMemberExpression(slice.callee)) return;
      const sliceKey =
        staticMemberKey(slice.callee) ??
        (() => {
          const v = constTableValue(slice.callee.property, p.scope);
          return v.ok && typeof v.value === 'string' ? v.value : null;
        })();
      if (sliceKey !== 'slice') return;
      const poolNode = slice.callee.object;
      if (!(t.isIdentifier(poolNode) || t.isStringLiteral(poolNode)) || slice.arguments.length !== 2) return;
      const [a0, a1] = slice.arguments;
      if (!t.isIdentifier(a0, { name: ps.name })) return;
      if (!t.isBinaryExpression(a1, { operator: '+' }) || !t.isIdentifier(a1.left, { name: ps.name }) || !t.isIdentifier(a1.right, { name: pl.name })) return;
      // names resolve from inside the retriever (its parameters shadow)
      const scope = p.scope;
      const self = def.binding;
      const decoder = scope.getBinding(ret.argument.callee.name);
      const pool = t.isIdentifier(poolNode) ? scope.getBinding(poolNode.name) : null;
      if (dyn.observesBinding(self)) return;
      if (!decoder || !fnDefs.has(decoder) || dyn.observesBinding(decoder)) return;
      if (t.isStringLiteral(poolNode)) {
        retrievers.push({ binding: self, def, decoder, pool: null, poolValue: poolNode });
        return;
      }
      const poolValue = singleValue(pool ?? undefined, true);
      if (!pool || !poolValue || !t.isStringLiteral(poolValue) || dyn.observesBinding(pool)) return;
      if (!['var', 'let', 'const'].includes(pool.kind)) return;
      retrievers.push({ binding: self, def, decoder, pool, poolValue });
    })();
  }
  // General candidates: two plain parameters, called somewhere with two
  // resolvable arguments. Whether they are closed and read a pool is decided
  // with the decoders below.
  const explicit = new Set(retrievers.map((r) => r.binding));
  for (const def of fnDefs.values()) {
    const fn = def.fn;
    // two plain parameters, or variableMasking's single rest parameter — the
    // sandbox calls it with two arguments either way
    const plain = fn.params.length === 2 && fn.params.every((q) => t.isIdentifier(q));
    const masked = fn.params.length === 1 && t.isRestElement(fn.params[0]) && t.isIdentifier(fn.params[0].argument);
    if (explicit.has(def.binding) || fn.async || fn.generator || !(plain || masked)) continue;
    if (dyn.observesBinding(def.binding)) continue;
    const probed = def.binding.referencePaths.some((ref) => {
      const call = ref.parentPath;
      return call?.isCallExpression() && call.node.callee === ref.node && call.node.arguments.length === 2 && call.node.arguments.every((a) => resolveArg(a, call.scope).ok);
    });
    if (!probed) continue;
    retrievers.push({ binding: def.binding, def, decoder: def.binding, pool: null, poolValue: null, general: true });
  }
  if (retrievers.length === 0) {
    log.pass('b05d', 'concealedStrings', 0, undefined, 'no retrievers');
    return 0;
  }

  // ── closed decoders: deterministic built-ins, the finisher, other closed fns ─
  const refsOf = new Map<Binding, FreeRefs>();
  const closed = new Set<Binding>();
  // freeReferences files a method call on an outer binding under `mutates`
  // when the method is a known mutator — or when it cannot tell, as with a
  // name held in a literals table (`pool[T[36]](…)`). Here the table is
  // readable: a call whose method resolves is judged by its name like any
  // other; one that still does not resolve, an assignment, an update and a
  // delete are real mutations.
  const hardMutates = (def: FnDef): Set<Binding> => {
    const out = new Set<Binding>();
    const outer = (q: NodePath, name: string): Binding | null => {
      const b = q.scope.getBinding(name);
      if (!b) return null;
      for (let sp: NodePath | null = b.scope.path; sp; sp = sp.parentPath) if (sp.node === def.path.node) return null; // local to the definition
      return b;
    };
    def.path.traverse({
      CallExpression(q) {
        const c = q.node.callee;
        if (!t.isMemberExpression(c)) return;
        const root = memberRoot(c);
        if (!root) return;
        const b = outer(q, root.name);
        if (!b) return;
        const key = staticMemberKey(c) ?? (c.computed ? ((): string | null => { const v = constTableValue(c.property, q.scope); return v.ok && typeof v.value === 'string' ? v.value : null; })() : null);
        if (key === null || MUTATING_METHOD_NAMES.has(key)) out.add(b);
      },
      'AssignmentExpression|UpdateExpression'(q) {
        const target = q.isAssignmentExpression() ? q.node.left : (q.node as t.UpdateExpression).argument;
        if (!t.isMemberExpression(target)) return;
        const root = memberRoot(target);
        const b = root ? outer(q, root.name) : null;
        if (b) out.add(b);
      },
      UnaryExpression(q) {
        if (q.node.operator !== 'delete' || !t.isMemberExpression(q.node.argument)) return;
        const root = memberRoot(q.node.argument);
        const b = root ? outer(q, root.name) : null;
        if (b) out.add(b);
      },
    });
    return out;
  };
  const hardMutatesOf = new Map<Binding, Set<Binding>>();
  const consider = (b: Binding): void => {
    if (refsOf.has(b)) return;
    const def = fnDefs.get(b);
    if (!def || dyn.observesBinding(b)) return;
    // the sandbox copy must answer like the original (sandboxSafe)
    if (!sandboxSafe(b)) return;
    const refs = freeReferences(def.path);
    refsOf.set(b, refs);
    closed.add(b);
    for (const x of refs.reads) if (!finishers.has(x) && !fixedData(x)) consider(x);
  };
  for (const r of retrievers) consider(r.decoder);
  for (let changed = true; changed; ) {
    changed = false;
    for (const b of [...closed]) {
      const refs = refsOf.get(b)!;
      const fnNode = fnDefs.get(b)!.fn;
      const selfWrite = noops.has(b) && [...refs.writes].every((x) => x === b);
      if (!hardMutatesOf.has(b)) hardMutatesOf.set(b, hardMutates(fnDefs.get(b)!));
      let ok = !refs.usesThis && (refs.writes.size === 0 || selfWrite) && hardMutatesOf.get(b)!.size === 0 && !usesArguments(fnNode);
      for (const g of refs.globals) if (!SLICE_SAFE_GLOBALS.has(g)) ok = false;
      for (const x of refs.reads) if (!finishers.has(x) && !closed.has(x) && !fixedData(x)) ok = false;
      if (!ok) {
        closed.delete(b);
        changed = true;
      }
    }
  }
  const depsOf = (b: Binding): Binding[] => {
    const out = new Set<Binding>();
    const stack = [b];
    while (stack.length) {
      const x = stack.pop()!;
      if (out.has(x)) continue;
      out.add(x);
      for (const y of refsOf.get(x)?.reads ?? []) if (closed.has(y)) stack.push(y);
    }
    return [...out];
  };
  // A general candidate must be closed and, somewhere in its dependency
  // closure, read a fixed string: that is what makes it a string retriever
  // rather than an arbitrary pure function worth leaving as the author wrote it.
  for (let i = retrievers.length - 1; i >= 0; i--) {
    const r = retrievers[i];
    if (!r.general) continue;
    const readsPool = closed.has(r.decoder) && depsOf(r.decoder).some((d) => [...(refsOf.get(d)?.reads ?? [])].some((x) => !!fixedString(x)));
    if (!readsPool) retrievers.splice(i, 1);
  }
  if (retrievers.length === 0) {
    log.pass('b05d', 'concealedStrings', 0, undefined, 'no retrievers');
    return 0;
  }

  // ── probe and fold ────────────────────────────────────────────────────────
  const { Script, createContext } = vm;
  let folded = 0;
  let evaluated = 0;
  for (const r of retrievers) {
    if (!closed.has(r.decoder)) continue;
    const deps = depsOf(r.decoder);
    const finishersUsed = new Set<Binding>();
    for (const d of deps) for (const x of refsOf.get(d)!.reads) if (finishers.has(x)) finishersUsed.add(x);
    type Site = { path: NodePath<t.CallExpression>; start: number; length: number };
    const sites: Site[] = [];
    for (const ref of r.binding.referencePaths) {
      const call = ref.parentPath;
      if (!call?.isCallExpression() || call.node.callee !== ref.node || call.node.arguments.length !== 2) continue;
      const vals = call.node.arguments.map((a) => {
        const v = resolveArg(a, call.scope);
        return v.ok ? v : null;
      });
      if (!vals.every((v) => v?.ok && typeof v.value === 'number')) continue;
      sites.push({ path: call, start: vals[0]!.value as number, length: vals[1]!.value as number });
    }
    if (sites.length === 0) continue;
    const src: string[] = [];
    if (r.pool && r.poolValue) src.push(`var ${r.pool.identifier.name} = ${genVmCode(r.poolValue)};`);
    // immutable literal tables the decoder or the retriever read (`pool[D[17]]`)
    const tables = new Set<Binding>();
    for (const d of deps) for (const x of refsOf.get(d)!.reads) if (fixedData(x)) tables.add(x);
    for (const x of freeReferences(r.def.path).reads) if (fixedData(x)) tables.add(x);
    for (const tb of tables) {
      if (tb === r.pool) continue; // declared above
      src.push(`var ${tb.identifier.name} = ${genVmCode(fixedData(tb)!)};`);
      tableNames.add(tb.identifier.name);
      tableBindings.add(tb);
    }
    for (const f of finishersUsed) src.push(`function ${f.identifier.name}(bytes) { return __dq_utf8(bytes); }`);
    for (const d of deps) src.push(genVmCode(asDecl(fnDefs.get(d)!)));
    if (!deps.includes(r.binding)) src.push(genVmCode(asDecl(r.def)));
    const run = (order: number[]): Array<string | null> | null => {
      const calls = order.map((i) => `[${i},${sites[i].start},${sites[i].length}]`).join(',');
      const script =
        `(function () {\n${src.join('\n')}\n` +
        `var __dq_out = {}; var __dq_calls = [${calls}];\n` +
        `for (var __dq_i = 0; __dq_i < __dq_calls.length; __dq_i++) { var __dq_c = __dq_calls[__dq_i];\n` +
        `  try { var __dq_v = ${r.binding.identifier.name}(__dq_c[1], __dq_c[2]);\n` +
        `    var __dq_r = typeof __dq_v === 'string' ? __dq_v : null;\n` +
        `    if (__dq_c[0] in __dq_out && __dq_out[__dq_c[0]] !== __dq_r) throw new Error('unstable');\n` +
        `    __dq_out[__dq_c[0]] = __dq_r; } catch (__dq_e) { __dq_out[__dq_c[0]] = null; } }\n` +
        `return JSON.stringify(__dq_out); })()`;
      try {
        const ctx = createContext({
          __dq_utf8: (bytes: number[]) => new TextDecoder().decode(new Uint8Array(bytes)),
        });
        new Script('Math.random = function () { throw new Error("nondeterministic"); };').runInContext(ctx);
        const raw = new Script(script).runInContext(ctx, { timeout: 3000 });
        const parsed = JSON.parse(String(raw)) as Record<string, string | null>;
        return sites.map((_, i) => parsed[i] ?? null);
      } catch {
        return null;
      }
    };
    const idx = sites.map((_, i) => i);
    const forward = run([...idx, ...idx]);
    const backward = run([...idx].reverse());
    evaluated++;
    if (!forward || !backward || JSON.stringify(forward) !== JSON.stringify(backward)) continue;
    sites.forEach((site, i) => {
      const v = forward[i];
      if (v === null) return;
      pendingFolds.push({ path: site.path, value: v });
    });
  }

  // ── the set-aside evals: each must evaluate machinery-free source ────────────
  if (loose) {
    // The machinery as bindings: a name in the eval's source reaches one only
    // if it resolves to it from where the eval runs (another function's local
    // of the same spelling is a different variable).
    const machineryBindings = new Set<Binding>();
    for (const r of retrievers) {
      machineryBindings.add(r.binding);
      if (r.pool) machineryBindings.add(r.pool);
      if (closed.has(r.decoder)) for (const d of depsOf(r.decoder)) machineryBindings.add(d);
      else machineryBindings.add(r.decoder);
    }
    for (const f of finishers) machineryBindings.add(f);
    for (const m of machinery) machineryBindings.add(m);
    for (const b of tableBindings) machineryBindings.add(b);
    const foldOf = new Map(pendingFolds.map((f) => [f.path.node, f.value] as const));
    let currentEval: t.Node | null = null;
    const evalNodeOf = (_e: t.Node): t.Node => currentEval!;
    // Table reads in an eval's argument: fixed values too, folded with the
    // retriever calls so B03d then sees one literal (and the table stops
    // looking reachable from the eval).
    const tableFolds: Array<{ node: t.Node; value: string | number }> = [];
    /** The eval's source, assembled from the folds; null if any part is unknown. */
    const assemble = (e: t.Node): string | null => {
      if (t.isStringLiteral(e)) return e.value;
      if (t.isNumericLiteral(e)) return String(e.value);
      if (t.isMemberExpression(e)) {
        // a fixed table entry, as `+` would stringify it
        const v = constTableValue(e, evalArgPaths.get(evalNodeOf(e))!.scope);
        if (!v.ok || !(typeof v.value === 'string' || typeof v.value === 'number')) return null;
        tableFolds.push({ node: e, value: v.value });
        return String(v.value);
      }
      if (t.isBinaryExpression(e, { operator: '+' })) {
        const l = assemble(e.left);
        const r = assemble(e.right);
        return l === null || r === null ? null : l + r;
      }
      return foldOf.get(e) ?? null;
    };
    for (const ev of evalArgSites) {
      currentEval = ev;
      const source = assemble((ev as t.CallExpression).arguments[0]);
      if (source === null) return passConcealedStrings(ast, log, true); // its source stays unknown
      let parsed: t.File;
      try {
        parsed = parser.parse(source, { sourceType: 'script' }) as unknown as t.File;
      } catch {
        return passConcealedStrings(ast, log, true);
      }
      const evalScope = evalArgPaths.get(ev)!.scope;
      let reaches = false;
      t.traverseFast(parsed.program, (x) => {
        if (t.isIdentifier(x)) {
          if (x.name === 'eval' || x.name === 'Function') reaches = true;
          const b = evalScope.getBinding(x.name);
          if (b && machineryBindings.has(b)) reaches = true;
        }
        if (t.isWithStatement(x)) reaches = true;
      });
      if (reaches) return passConcealedStrings(ast, log, true);
    }
    if (tableFolds.length) {
      const nodes = new Set(tableFolds.map((f) => f.node));
      const valueOf = new Map(tableFolds.map((f) => [f.node, f.value] as const));
      for (const ev of evalArgPaths.values())
        ev.traverse({
          MemberExpression(mp) {
            if (!nodes.has(mp.node)) return;
            const v = valueOf.get(mp.node)!;
            mp.replaceWith(typeof v === 'string' ? t.stringLiteral(v) : t.numericLiteral(v));
            folded++;
          },
        });
    }
  }
  for (const f of pendingFolds) {
    try {
      f.path.replaceWith(t.stringLiteral(f.value));
      folded++;
    } catch {
      /**/
    }
  }

  // ── remove what nothing references any more ───────────────────────────────
  let removed = 0;
  if (folded > 0) {
    for (let round = 0; round < 6; round++) {
      const fresh = freshProgram(ast);
      const gone: NodePath[] = [];
      /**
       * Unread, and written only by its declaration or one plain assignment
       * statement (which goes too). Returns the value expressions it held.
       */
      const unreferenced = (p: NodePath, name: string): NodePath[] | null => {
        const b = p.parentPath?.scope.getBinding(name) ?? p.scope.getBinding(name);
        if (!b || b.referencePaths.length !== 0) return null;
        const values: NodePath[] = [];
        const stmts: NodePath[] = [];
        for (const v of b.constantViolations) {
          if (v.node === p.node) continue;
          const stmt = v.parentPath;
          if (!v.isAssignmentExpression({ operator: '=' }) || !stmt?.isExpressionStatement()) return null;
          values.push(v.get('right') as NodePath);
          stmts.push(stmt);
        }
        const init = p.isVariableDeclarator() && p.node.init ? (p.get('init') as NodePath) : null;
        if (init) values.push(init);
        for (const v of values) {
          const refs = freeReferences(v);
          if (refs.writes.size || refs.mutates.size) return null;
        }
        gone.push(...stmts);
        return values;
      };
      const retrieverNodes = new Set<t.Node>(retrievers.map((r) => r.def.fn));
      const decoderNodes = new Set<t.Node>(retrievers.filter((r) => closed.has(r.decoder)).flatMap((r) => depsOf(r.decoder).map((d) => fnDefs.get(d)!.fn)));
      // function-expression definitions go with their binding's declarator
      const exprDecls = new Set<t.Node>(
        [...retrievers.map((r) => r.binding), ...retrievers.filter((r) => closed.has(r.decoder)).flatMap((r) => depsOf(r.decoder))]
          .filter((b) => t.isFunctionExpression(fnDefs.get(b)?.fn))
          .map((b) => b.path.node)
      );
      const finisherNodes = new Set([...finishers].map((f) => f.path.node));
      const poolNodes = new Set(retrievers.flatMap((r) => (r.pool ? [r.pool.path.node] : [])));
      const machineryNodes = new Set([...machinery].map((m) => m.path.node));
      fresh.traverse({
        FunctionDeclaration(p) {
          const id = p.node.id;
          if (!id) return;
          if (retrieverNodes.has(p.node) || decoderNodes.has(p.node) || finisherNodes.has(p.node)) {
            if (unreferenced(p, id.name)) gone.push(p);
          }
        },
        VariableDeclarator(p) {
          if (!t.isIdentifier(p.node.id)) return;
          if (exprDecls.has(p.node)) {
            if (unreferenced(p, p.node.id.name)) gone.push(p);
            return;
          }
          const isPool = poolNodes.has(p.node);
          const isMachinery = machineryNodes.has(p.node);
          if (!isPool && !isMachinery) return;
          const values = unreferenced(p, p.node.id.name);
          if (!values) return;
          // Machinery values probe the global object and build tables — no
          // writes to program state (checked above) — so dropping an unread one
          // changes nothing. Whatever they read (the probe, the decoder tables)
          // becomes machinery too, once it is unread in turn.
          if (isMachinery) for (const v of values) for (const b of freeReferences(v).reads) machinery.add(b);
          gone.push(p);
        },
      });
      if (gone.length === 0) break;
      for (const p of gone) {
        try {
          if (p.isVariableDeclarator()) {
            const decl = p.parentPath as NodePath<t.VariableDeclaration>;
            if (decl.node.declarations.length === 1) decl.remove();
            else p.remove();
          } else p.remove();
          removed++;
        } catch {
          /**/
        }
      }
      // Functions the machinery read (the global-object probe) go the same way.
      for (const b of [...machinery]) {
        if (b.path.isFunctionDeclaration() && !finishers.has(b)) {
          const refs = freeReferences(b.path);
          if (refs.writes.size === 0 && refs.mutates.size === 0) finishers.add(b); // treated as removable once unread
        }
      }
    }
  }

  log.pass('b05d', 'concealedStrings', folded, 'strings', `${evaluated} retrievers probed · ${removed} declarations removed`);
  return folded + removed;
}

// ── B09d: dispatchers ────────────────────────────────────────────────────────

/**
 * js-confuser's dispatcher collects the function declarations of a block into
 * one table and routes every use of them through a dispatcher function:
 *
 *   var CACHE = Object.create(null); var PAYLOAD;
 *   function D(name, flagArg, returnTypeArg, fnLengths = {}) {
 *     var output;
 *     var fns = { k1: function () { var [a, b] = PAYLOAD; body }, … };
 *     if (flagArg === CLEAR) { PAYLOAD = []; }
 *     if (flagArg === NONCALL) { … output = CACHE[name] || (CACHE[name] = wrapper) }
 *     else { output = fns[name](); }
 *     if (returnTypeArg === ASOBJECT) { return { PROP: output }; } else { return output; }
 *   }
 *   f(x, y)  ⇒  (PAYLOAD = [x, y], D("k1"))   or   …, new D("k1", "…", ASOBJECT)[PROP]
 *   f()      ⇒  D("k1", CLEAR)
 *   f        ⇒  D("k1", NONCALL)             — a cached function forwarding to fns.k1
 *
 * Each table entry becomes a function declaration again, in the dispatcher's
 * block, and each site becomes the plain call or reference it encoded:
 *   • a dispatched call evaluates its arguments, then runs the body with the
 *     block's bindings in scope and `this` unbound — exactly what `f(x, y)` does
 *     once `var [a, b] = PAYLOAD` is the parameter list again;
 *   • `new D(…)` with ASOBJECT returns the wrapper object, so `[PROP]` reads the
 *     same value a plain call would have returned;
 *   • the NONCALL wrapper forwards its arguments and `this` to the body, so a
 *     reference to the declaration behaves the same wherever it is called.
 * The rewrite is all-or-nothing per dispatcher, so that a reference and a call
 * of the same function can never end up naming two different functions. It is
 * refused when an entry uses `arguments` (the wrapper's were empty) or one of
 * the dispatcher's own locals, when D, PAYLOAD or CACHE is used in any other
 * way than the three site shapes with literal keys, or when a NONCALL result is
 * constructed or has a property read (the wrapper's `length`, `name` and
 * `prototype` were its own). After B00b has split a site's sequence into
 * statements, `PAYLOAD = […];` directly before the statement whose first
 * evaluated expression is the dispatcher call is accepted as the same shape.
 */
function passDispatchers(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);

  type Entry = { key: string; fn: t.FunctionExpression; params: t.ArrayPattern['elements']; body: t.Statement[] };
  type Site =
    | { mode: 'call'; node: NodePath; key: string; args: t.ArrayExpression['elements']; payload: NodePath; form: 'seq' | 'stmt' }
    | { mode: 'clear' | 'ref'; node: NodePath; key: string };
  type Job = {
    decl: NodePath<t.FunctionDeclaration>;
    scope: NodePath['scope'];
    entries: Entry[];
    sites: Site[];
    declarators: NodePath[];
    resets: NodePath[];
  };
  const jobs: Job[] = [];

  const lit = (n: t.Node | null | undefined): string | null => (t.isStringLiteral(n) ? n.value : null);
  const eqLit = (n: t.Node | null | undefined, id: string): string | null =>
    t.isBinaryExpression(n, { operator: '===' }) && t.isIdentifier(n.left, { name: id }) ? lit(n.right) : null;
  const blockOf = (n: t.Node | null | undefined): t.Statement[] | null =>
    t.isBlockStatement(n) ? n.body : t.isStatement(n) ? [n] : null;
  const sameId = (n: t.Node | null | undefined, name: string): boolean => t.isIdentifier(n, { name });
  /** The expression a statement evaluates first, when nothing precedes it. */
  const headOf = (stmt: NodePath): t.Node | null => {
    const n = stmt.node;
    if (t.isExpressionStatement(n)) {
      const e = n.expression;
      if (t.isAssignmentExpression(e, { operator: '=' })) {
        if (t.isIdentifier(e.left)) return e.right;
        if (t.isMemberExpression(e.left) && t.isIdentifier(e.left.object) && staticMemberKey(e.left) !== null) return e.right;
        return null;
      }
      return e;
    }
    if (t.isReturnStatement(n) || t.isThrowStatement(n)) return n.argument ?? null;
    if (t.isVariableDeclaration(n) && n.declarations.length === 1 && t.isIdentifier(n.declarations[0].id))
      return n.declarations[0].init ?? null;
    return null;
  };

  program.traverse({
    FunctionDeclaration(p) {
      const fn = p.node;
      if (!fn.id || fn.async || fn.generator || fn.params.length < 4) return;
      const [pName, pFlag, pRet, pLens, ...extras] = fn.params;
      if (!t.isIdentifier(pName) || !t.isIdentifier(pFlag) || !t.isIdentifier(pRet) || !t.isAssignmentPattern(pLens)) return;
      // js-confuser's movedDeclarations turns `var output; var fns = {…}` into
      // trailing parameters assigned at the top: both spellings declare a local.
      if (!extras.every((e) => t.isIdentifier(e))) return;
      const extraNames = new Set(extras.map((e) => (e as t.Identifier).name));
      // Leading locals: `var output; var fns = {…};` in any split of declarators,
      // or assignments to the extra parameters.
      const locals = new Map<string, t.Expression | null>();
      let tableNode: t.Node | null = null;
      const body = fn.body.body;
      // `var a, b; a = …; b = …;` (B00c's demotion of moved parameters, or
      // movedDeclarations directly) declares the same locals as `var a = …`.
      const declaredBare = new Set<string>();
      const assigned = new Set<string>();
      let at = 0;
      for (; at < body.length; at++) {
        const stmt = body[at];
        if (t.isFunctionDeclaration(stmt)) continue; // a block-level helper (B00e's output); hoisted
        if (t.isVariableDeclaration(stmt) && stmt.declarations.every((d) => t.isIdentifier(d.id))) {
          for (const d of stmt.declarations) {
            // `var x = undefined` declares the same as `var x`
            const bare = !d.init || t.isIdentifier(d.init, { name: 'undefined' });
            locals.set((d.id as t.Identifier).name, bare ? null : d.init!);
            if (bare) declaredBare.add((d.id as t.Identifier).name);
            if (t.isObjectExpression(d.init)) tableNode = d;
          }
        } else if (
          t.isExpressionStatement(stmt) &&
          t.isAssignmentExpression(stmt.expression, { operator: '=' }) &&
          t.isIdentifier(stmt.expression.left) &&
          (extraNames.has(stmt.expression.left.name) || (declaredBare.has(stmt.expression.left.name) && !assigned.has(stmt.expression.left.name)))
        ) {
          assigned.add(stmt.expression.left.name);
          locals.set(stmt.expression.left.name, t.isIdentifier(stmt.expression.right, { name: 'undefined' }) ? null : stmt.expression.right);
          if (t.isObjectExpression(stmt.expression.right)) tableNode = stmt.expression;
        } else break;
      }
      if (body.length - at !== 3 || !tableNode) return;
      const [s2, s3, s4] = body.slice(at);
      const tableEntry = [...locals.entries()].find(([, init]) => t.isObjectExpression(init));
      if (!tableEntry) return;
      const fnsName = tableEntry[0];
      const table = tableEntry[1] as t.ObjectExpression;
      // the table is written once — by its declaration or that one assignment
      const fnsBinding = p.scope.getBinding(fnsName);
      if (!fnsBinding || fnsBinding.constantViolations.length > 1) return;
      if (fnsBinding.constantViolations.length === 1 && fnsBinding.constantViolations[0].node !== tableNode) return;
      // output: the bare local the else branch assigns (`else { output = fns[name](); }`)
      const elseHead = t.isIfStatement(s3) ? blockOf(s3.alternate)?.[0] : null;
      if (!t.isExpressionStatement(elseHead) || !t.isAssignmentExpression(elseHead.expression, { operator: '=' }) || !t.isIdentifier(elseHead.expression.left)) return;
      const outputName = elseHead.expression.left.name;
      if (!locals.has(outputName) || locals.get(outputName) !== null) return;
      // if (flagArg === CLEAR) { PAYLOAD = []; }
      if (!t.isIfStatement(s2) || s2.alternate) return;
      const clearKey = eqLit(s2.test, pFlag.name);
      const clearBody = blockOf(s2.consequent);
      if (clearKey === null || !clearBody || clearBody.length > 1) return;
      // An empty clear branch: PAYLOAD itself is gone (B17c drops it when no
      // entry takes parameters) — every entry is then called without any.
      let payloadName: string | null = null;
      let clearExpr: t.Node | null = null;
      if (clearBody.length === 1) {
        const clearStmt = clearBody[0];
        if (!t.isExpressionStatement(clearStmt) || !t.isAssignmentExpression(clearStmt.expression, { operator: '=' }) || !t.isIdentifier(clearStmt.expression.left) || !t.isArrayExpression(clearStmt.expression.right) || clearStmt.expression.right.elements.length) return;
        payloadName = clearStmt.expression.left.name;
        clearExpr = clearStmt.expression;
      }
      // if (flagArg === NONCALL) { function createFunction() {…} output = CACHE[name] || (CACHE[name] = createFunction()); } else { output = fns[name](); }
      if (!t.isIfStatement(s3)) return;
      const nonCallKey = eqLit(s3.test, pFlag.name);
      const ncBody = blockOf(s3.consequent);
      const elseBody = blockOf(s3.alternate);
      if (nonCallKey === null || !ncBody || ncBody.length !== 2 || !elseBody || elseBody.length !== 1) return;
      const [creator, assignWrapper] = ncBody;
      // `function createFunction() {…}`, or (moved by flattening) a bare local
      // `createFunction = function () {…};` used by that one call
      let creatorName: string;
      let creatorBody: t.Statement[];
      if (t.isFunctionDeclaration(creator) && creator.id) {
        creatorName = creator.id.name;
        creatorBody = creator.body.body;
      } else if (
        t.isExpressionStatement(creator) &&
        t.isAssignmentExpression(creator.expression, { operator: '=' }) &&
        t.isIdentifier(creator.expression.left) &&
        locals.get(creator.expression.left.name) === null &&
        creator.expression.left.name !== outputName &&
        t.isFunctionExpression(creator.expression.right) &&
        !creator.expression.right.params.length &&
        !creator.expression.right.async &&
        !creator.expression.right.generator
      ) {
        creatorName = creator.expression.left.name;
        creatorBody = creator.expression.right.body.body;
        const cb = p.scope.getBinding(creatorName);
        if (!cb || cb.referencePaths.length !== 1 || cb.constantViolations.length !== 1) return;
      } else return;
      if (!t.isExpressionStatement(assignWrapper) || !t.isAssignmentExpression(assignWrapper.expression, { operator: '=' }) || !sameId(assignWrapper.expression.left, outputName)) return;
      const orExpr = assignWrapper.expression.right;
      if (!t.isLogicalExpression(orExpr, { operator: '||' }) || !t.isMemberExpression(orExpr.left) || !t.isIdentifier(orExpr.left.object) || !orExpr.left.computed || !sameId(orExpr.left.property, pName.name)) return;
      const cacheName = orExpr.left.object.name;
      // … || (CACHE[name] = createFunction())
      const fill = orExpr.right;
      if (
        !t.isAssignmentExpression(fill, { operator: '=' }) ||
        !t.isMemberExpression(fill.left) ||
        !sameId(fill.left.object, cacheName) ||
        !fill.left.computed ||
        !sameId(fill.left.property, pName.name) ||
        !t.isCallExpression(fill.right) ||
        !sameId(fill.right.callee, creatorName) ||
        fill.right.arguments.length
      )
        return;
      // var fn = function (...args) { PAYLOAD = args; return fns[name].apply(this); };
      // … return fn;
      const wrapperDecl = creatorBody[0];
      if (!t.isVariableDeclaration(wrapperDecl) || !t.isFunctionExpression(wrapperDecl.declarations[0]?.init)) return;
      const creatorTail = creatorBody[creatorBody.length - 1];
      if (!t.isReturnStatement(creatorTail) || !sameId(creatorTail.argument, (wrapperDecl.declarations[0].id as t.Identifier).name)) return;
      const wrapper = wrapperDecl.declarations[0].init;
      // `function (...args) { PAYLOAD = args; return …; }`, or with no PAYLOAD
      // `function () { return …; }`
      let w0: t.Statement | null = null;
      let w1: t.Statement;
      if (payloadName !== null) {
        if (wrapper.params.length !== 1 || !t.isRestElement(wrapper.params[0]) || !t.isIdentifier(wrapper.params[0].argument) || wrapper.body.body.length !== 2) return;
        [w0, w1] = wrapper.body.body;
        if (!t.isExpressionStatement(w0) || !t.isAssignmentExpression(w0.expression, { operator: '=' }) || !sameId(w0.expression.left, payloadName) || !sameId(w0.expression.right, wrapper.params[0].argument.name)) return;
      } else {
        if (wrapper.body.body.length !== 1) return;
        w1 = wrapper.body.body[0];
        // a rest parameter left over from `PAYLOAD = args`, now unread
        const rp = wrapper.params[0];
        if (wrapper.params.length > 1 || (rp && !(t.isRestElement(rp) && t.isIdentifier(rp.argument)))) return;
        if (rp) {
          const name = ((rp as t.RestElement).argument as t.Identifier).name;
          let read = false;
          walk(w1, (n) => {
            if (t.isIdentifier(n, { name })) read = true;
          });
          if (read) return;
        }
      }
      if (!t.isReturnStatement(w1) || !t.isCallExpression(w1.argument) || !t.isMemberExpression(w1.argument.callee) || staticMemberKey(w1.argument.callee) !== 'apply') return;
      const applied = w1.argument.callee.object;
      if (!t.isMemberExpression(applied) || !sameId(applied.object, fnsName) || !applied.computed || !sameId(applied.property, pName.name)) return;
      if (w1.argument.arguments.length !== 1 || !t.isThisExpression(w1.argument.arguments[0])) return;
      // else { output = fns[name](); }
      const el = elseBody[0];
      if (!t.isExpressionStatement(el) || !t.isAssignmentExpression(el.expression, { operator: '=' }) || !sameId(el.expression.left, outputName)) return;
      const direct = el.expression.right;
      if (!t.isCallExpression(direct) || direct.arguments.length || !t.isMemberExpression(direct.callee) || !sameId(direct.callee.object, fnsName) || !direct.callee.computed || !sameId(direct.callee.property, pName.name)) return;
      // if (returnTypeArg === ASOBJECT) { return { PROP: output }; } else { return output; }
      // — or, minified, `return returnTypeArg === ASOBJECT ? { PROP: output } : output;`
      let asObjectKey: string | null;
      let wrapped: t.Node | null | undefined;
      let plain: t.Node | null | undefined;
      if (t.isIfStatement(s4)) {
        asObjectKey = eqLit(s4.test, pRet.name);
        const r1 = blockOf(s4.consequent);
        const r2 = blockOf(s4.alternate);
        if (asObjectKey === null || !r1 || r1.length !== 1 || !r2 || r2.length !== 1) return;
        if (!t.isReturnStatement(r1[0]) || !t.isReturnStatement(r2[0])) return;
        wrapped = r1[0].argument;
        plain = r2[0].argument;
      } else if (t.isReturnStatement(s4) && t.isConditionalExpression(s4.argument)) {
        asObjectKey = eqLit(s4.argument.test, pRet.name);
        if (asObjectKey === null) return;
        wrapped = s4.argument.consequent;
        plain = s4.argument.alternate;
      } else return;
      if (!t.isObjectExpression(wrapped) || wrapped.properties.length !== 1) return;
      const propNode = wrapped.properties[0];
      if (!t.isObjectProperty(propNode) || !sameId(propNode.value, outputName)) return;
      const prop = staticPropKey(propNode);
      if (prop === null) return;
      if (!sameId(plain, outputName)) return;

      // The block that owns D, PAYLOAD and CACHE.
      const scope = p.parentPath.scope;
      const dBinding = scope.getBinding(fn.id.name);
      const payload = payloadName !== null ? scope.getBinding(payloadName) ?? null : null;
      const cache = scope.getBinding(cacheName);
      if (!dBinding || dBinding.path.node !== fn || (payloadName !== null && !payload) || !cache) return;
      if ((payload && payload.kind !== 'var') || cache.kind !== 'var') return;
      if ((payload && !payload.path.isVariableDeclarator()) || !cache.path.isVariableDeclarator()) return;
      if (dBinding.constantViolations.length) return;
      // `var CACHE = Object.create(null)`, or (movedDeclarations) `var CACHE; CACHE = Object.create(null);`
      const cacheInits: NodePath[] = [];
      for (const v of cache.constantViolations) {
        if (!v.isAssignmentExpression({ operator: '=' }) || !v.parentPath.isExpressionStatement() || pathWithin(v, fn)) return;
        if (!isInert(v.node.right) && !(t.isCallExpression(v.node.right) && t.isMemberExpression(v.node.right.callee) && t.isIdentifier(v.node.right.callee.object, { name: 'Object' }) && staticMemberKey(v.node.right.callee) === 'create')) return;
        cacheInits.push(v.parentPath);
      }
      if (dyn.observesBinding(dBinding) || (payload && dyn.observesBinding(payload)) || dyn.observesBinding(cache)) return;
      if (cache.referencePaths.some((r) => !pathWithin(r, fn))) return;
      if (payload && payload.referencePaths.some((r) => !pathWithin(r, fn))) return;
      const machinery = new Set<t.Node>();
      if (clearExpr) machinery.add(clearExpr);
      if (t.isExpressionStatement(w0)) machinery.add(w0.expression);
      // `PAYLOAD = undefined;` (movedDeclarations' spelling of `var PAYLOAD;`) only
      // resets a value no site reads back; it goes with the declaration.
      const resets: NodePath[] = [];
      const payloadWrites = new Set<t.Node>();
      for (const v of payload?.constantViolations ?? []) {
        if (machinery.has(v.node)) continue;
        if (v.isAssignmentExpression({ operator: '=' }) && t.isIdentifier(v.node.right, { name: 'undefined' }) && v.parentPath.isExpressionStatement() && !pathWithin(v, fn)) {
          resets.push(v.parentPath);
          continue;
        }
        payloadWrites.add(v.node);
      }

      // Entries: `key: function (moved…) { var [params] = PAYLOAD; body }` — the
      // entry is always called with no arguments, so a parameter it has (again
      // movedDeclarations) is a local that starts out `undefined`.
      const entries: Entry[] = [];
      const keys = new Set<string>();
      const destructured = new Set<t.Node>();
      let tablePath: NodePath<t.ObjectExpression> | null = null;
      (p.get('body') as NodePath).traverse({
        ObjectExpression(op) {
          if (op.node === table) {
            tablePath = op;
            op.stop();
          }
        },
      });
      if (!tablePath) return;
      const propPaths = (tablePath as NodePath<t.ObjectExpression>).get('properties') as NodePath[];
      for (const propPath of propPaths) {
        const propN = propPath.node;
        // `["4ZXeyZ"]: …` is the same property as `"4ZXeyZ": …` (a key that
        // cannot be spelt as an identifier prints computed)
        if (!t.isObjectProperty(propN) || (propN.computed && !t.isStringLiteral(propN.key)) || !t.isFunctionExpression(propN.value)) return;
        const key = staticPropKey(propN);
        const f = propN.value;
        if (key === null || keys.has(key) || f.async || f.generator || f.id) return;
        // A default always applies (the entry gets no arguments); a literal one
        // — `arr = []`, movedDeclarations' spelling of `var arr = []` — is the
        // same as that declaration at the top of the body.
        const literalDefault = (n: t.Node): boolean =>
          isCopyableLiteral(n) ||
          (t.isArrayExpression(n) && n.elements.every((e) => !!e && isCopyableLiteral(e))) ||
          (t.isObjectExpression(n) && n.properties.length === 0);
        if (!f.params.every((prm) => t.isIdentifier(prm) || (t.isAssignmentPattern(prm) && t.isIdentifier(prm.left) && literalDefault(prm.right)))) return;
        keys.add(key);
        let params: t.ArrayPattern['elements'] = [];
        const stmts = [...f.body.body];
        // `var [params] = PAYLOAD;` — first, or behind inert statements that
        // movedDeclarations put ahead of it (`if (!g) g = function …`): those
        // neither call anything nor touch the names the pattern binds, so the
        // pattern reads the very array the call passed and binding it on entry
        // instead is the same.
        let at = stmts.findIndex(
          (st) =>
            t.isVariableDeclaration(st) &&
            st.declarations.length === 1 &&
            t.isArrayPattern(st.declarations[0].id) &&
            payloadName !== null &&
            sameId(st.declarations[0].init, payloadName)
        );
        // …or, its declaration moved (`var a, b; … [a, b] = PAYLOAD;`): the
        // same binding, provided every name is a local of the entry.
        let payloadRead: t.Node | null = at !== -1 ? (stmts[at] as t.VariableDeclaration).declarations[0].init! : null;
        let pattern: t.ArrayPattern | null = at !== -1 ? ((stmts[at] as t.VariableDeclaration).declarations[0].id as t.ArrayPattern) : null;
        if (at === -1) {
          const fScope = (propPath.get('value') as NodePath).scope;
          at = stmts.findIndex((st) => {
            if (!t.isExpressionStatement(st) || !t.isAssignmentExpression(st.expression, { operator: '=' })) return false;
            const { left, right } = st.expression;
            if (!t.isArrayPattern(left) || payloadName === null || !sameId(right, payloadName)) return false;
            // every name the pattern binds (nested patterns too) is a local of f
            const names = Object.keys(t.getBindingIdentifiers(left));
            return (
              names.length > 0 &&
              left.elements.every((el) => !!el) &&
              names.every((name) => {
                const b = fScope.getBinding(name);
                return !!b && b.scope === fScope && (b.kind === 'var' || b.kind === 'param');
              })
            );
          });
          if (at !== -1) {
            const asg = (stmts[at] as t.ExpressionStatement).expression as t.AssignmentExpression;
            payloadRead = asg.right;
            pattern = asg.left as t.ArrayPattern;
          }
        }
        if (at !== -1 && pattern && payloadRead) {
          params = pattern.elements;
          if (params.some((e) => e === null)) return;
          const bound = new Set<string>();
          walk(pattern, (n) => {
            if (t.isIdentifier(n)) bound.add(n.name);
          });
          const quiet = (st: t.Statement): boolean =>
            isInertStatement(st) ||
            (t.isBlockStatement(st) && st.body.every(quiet)) ||
            (t.isIfStatement(st) &&
              isInert(st.test) &&
              quiet(st.consequent) &&
              (!st.alternate || quiet(st.alternate)));
          for (const st of stmts.slice(0, at)) {
            // a value-less `var` (the moved declaration) does nothing
            if (t.isVariableDeclaration(st, { kind: 'var' }) && st.declarations.every((d) => !d.init && t.isIdentifier(d.id))) continue;
            if (!quiet(st)) return;
            let touches = false;
            walk(st, (n) => {
              if (t.isFunction(n)) return false; // a closure created here runs later
              if (t.isIdentifier(n) && (bound.has(n.name) || n.name === payloadName)) touches = true;
            });
            if (touches) return;
          }
          destructured.add(payloadRead);
          stmts.splice(at, 1);
        }
        if (usesArguments(f)) return;
        // Nothing of the dispatcher's own may be visible from the body.
        const refs = freeReferences(propPath.get('value') as NodePath);
        for (const b of [...refs.reads, ...refs.writes, ...refs.mutates]) if (pathWithin(b.path, fn)) return;
        if (f.params.length)
          stmts.unshift(
            t.variableDeclaration(
              'var',
              f.params.map((prm) =>
                t.isAssignmentPattern(prm)
                  ? t.variableDeclarator(t.identifier((prm.left as t.Identifier).name), prm.right)
                  : t.variableDeclarator(t.identifier((prm as t.Identifier).name))
              )
            )
          );
        entries.push({ key, fn: f, params, body: stmts });
      }

      // Every read of PAYLOAD was one of those patterns.
      if (payload && payload.referencePaths.some((r) => !destructured.has(r.node))) return;

      // Sites.
      const sites: Site[] = [];
      const consumed = new Set<t.Node>();
      for (const r of dBinding.referencePaths) {
        const call = r.parentPath;
        if (!call || !(call.isCallExpression() || call.isNewExpression()) || call.node.callee !== r.node) return;
        const args = call.node.arguments;
        if (args.length < 1 || args.length > 3 || !args.every((a) => t.isStringLiteral(a))) return;
        const [k, flag, ret] = args.map((a) => (a as t.StringLiteral).value);
        if (!keys.has(k)) return;
        let node: NodePath = call;
        if (ret === asObjectKey) {
          const m = call.parentPath;
          if (!m.isMemberExpression() || m.node.object !== call.node || staticMemberKey(m.node) !== prop) return;
          node = m;
        } else if (call.isNewExpression()) return;
        const mode = flag === clearKey ? 'clear' : flag === nonCallKey ? 'ref' : 'call';
        if (mode === 'ref') {
          const use = node.parentPath;
          if (!use) return;
          if (use.isMemberExpression({ object: node.node }) || use.isOptionalMemberExpression({ object: node.node }) || (use.isNewExpression() && use.node.callee === node.node)) return;
          sites.push({ mode, node, key: k });
        } else if (mode === 'clear') sites.push({ mode, node, key: k });
        // without PAYLOAD a plain dispatched call passes nothing: `f()`
        else if (payloadName === null) sites.push({ mode: 'clear', node, key: k });
        else {
          const parent = node.parentPath;
          if (!parent) return;
          let payloadPath: NodePath | null = null;
          let form: 'seq' | 'stmt' = 'seq';
          if (parent.isSequenceExpression()) {
            const idx = parent.node.expressions.indexOf(node.node as t.Expression);
            const prev = idx > 0 ? (parent.get('expressions') as NodePath[])[idx - 1] : null;
            if (prev && payloadWrites.has(prev.node)) payloadPath = prev;
          } else {
            const stmt = node.getStatementParent();
            if (stmt && headOf(stmt) === node.node && Array.isArray(stmt.container) && typeof stmt.key === 'number' && stmt.key > 0) {
              const prev = stmt.getSibling(stmt.key - 1);
              if (prev.isExpressionStatement() && payloadWrites.has(prev.node.expression)) {
                payloadPath = prev.get('expression') as NodePath;
                form = 'stmt';
              }
            }
          }
          if (!payloadPath || !t.isAssignmentExpression(payloadPath.node) || !t.isArrayExpression(payloadPath.node.right)) return;
          const elements = payloadPath.node.right.elements;
          if (elements.some((e) => e === null) || consumed.has(payloadPath.node)) return;
          consumed.add(payloadPath.node);
          sites.push({ mode, node, key: k, args: elements, payload: payloadPath, form });
        }
      }
      if (consumed.size !== payloadWrites.size) return; // a payload write nothing here consumes
      jobs.push({ decl: p, scope, entries, sites, declarators: payload ? [payload.path, cache.path] : [cache.path], resets: [...resets, ...cacheInits] });
    },
  });

  let functions = 0;
  let rewritten = 0;
  const depth = (p: NodePath): number => {
    let d = 0;
    for (let c: NodePath | null = p; c; c = c.parentPath) d++;
    return d;
  };
  for (const job of jobs) {
    // Fresh names in the owning block.
    const used = new Set<string>();
    walk(job.scope.path.node, (n) => {
      if (t.isIdentifier(n)) used.add(n.name);
    });
    const names = new Map<string, string>();
    for (const e of job.entries) {
      let name = t.isValidIdentifier(e.key) ? e.key : `fn_${e.key.replace(/[^A-Za-z0-9_$]/g, '')}`;
      for (let i = 1; !t.isValidIdentifier(name) || used.has(name) || job.scope.hasBinding(name) || job.scope.hasGlobal(name) || job.scope.hasReference(name); i++)
        name = `${e.key}_${i}`;
      used.add(name);
      names.set(e.key, name);
    }
    try {
      // Sites first, innermost first: `f(g(1))` nests one site in the other's payload.
      const ordered = [...job.sites].sort((a, b) => depth(b.node) - depth(a.node));
      for (const site of ordered) {
        const callee = t.identifier(names.get(site.key)!);
        if (site.mode === 'ref') site.node.replaceWith(callee);
        else if (site.mode === 'clear') site.node.replaceWith(t.callExpression(callee, []));
        else if (site.mode === 'call') {
          const call = t.callExpression(callee, site.args as Array<t.Expression | t.SpreadElement>);
          if (site.form === 'seq') {
            const seq = site.node.parentPath as NodePath<t.SequenceExpression>;
            const exprs = seq.node.expressions;
            exprs.splice(exprs.indexOf(site.node.node as t.Expression) - 1, 2, call);
            if (exprs.length === 1) seq.replaceWith(exprs[0]);
          } else {
            site.node.replaceWith(call);
            site.payload.parentPath!.remove();
          }
        }
        rewritten++;
      }
      const decls = job.entries.map((e) =>
        t.functionDeclaration(
          t.identifier(names.get(e.key)!),
          e.params as t.FunctionDeclaration['params'],
          t.blockStatement(e.body, e.fn.body.directives)
        )
      );
      job.decl.replaceWithMultiple(decls);
      for (const r of job.resets) r.remove();
      for (const d of job.declarators) {
        const decl = d.parentPath as NodePath<t.VariableDeclaration>;
        if (decl.node.declarations.length === 1) decl.remove();
        else d.remove();
      }
      functions += decls.length;
    } catch {
      /* a site detached by an earlier rewrite: the next sweep sees a consistent tree */
    }
  }
  log.pass('b09d', 'dispatchers', rewritten, 'sites', `${functions} functions restored`);
  return rewritten;
}

// ── B09c: flattened functions ────────────────────────────────────────────────

/** `this`, `arguments`, `new.target` or `super` of this very function. */
function usesOwnContext(fn: t.Function): boolean {
  let found = false;
  walk(fn.body, (n) => {
    if (found) return false;
    if (t.isFunction(n) && !t.isArrowFunctionExpression(n)) return false;
    if (
      t.isThisExpression(n) ||
      t.isSuper(n) ||
      t.isMetaProperty(n) ||
      t.isIdentifier(n, { name: 'arguments' })
    )
      found = true;
  });
  return found;
}

/**
 * `function W(...args) { var o = {…}; return F(o, args); }` with
 * `function F(o, [a, b]) { body }` → `function W(a, b) { var o = {…}; body }`
 *
 * js-confuser's flatten moves a function's body into a top-level function
 * that receives an object of accessors for the closure variables the body
 * used, plus the arguments as an array. F is called from nowhere else, so its
 * array pattern is exactly W's argument list and becomes W's parameters again.
 * The body moves back when it cannot tell the difference: it uses neither
 * `this`, `arguments`, `new.target` nor `super` (a plain call of F had bound
 * those differently from W), and every free name in it resolves to the same
 * binding from W's position as from the top level, so nothing in W's enclosing
 * scopes captures it. Nested pairs are inlined outermost first, re-crawling in
 * between, so each check sees the position the body will actually land in.
 *
 * Afterwards, while `o` is only ever read, written or called through its keys,
 * each accessor is replaced by the variable it wraps: `o.k` → `v` for
 * `get k() { return v }`, `o.k = x` → `v = x` when `set k(x) { v = x }`
 * exists, `o.t` → `typeof v`, and `o.c(a)` → `v(a)` for
 * `c(...args) { return v(...args) }` — each the very read, write or call the
 * accessor performed, now done in place, provided `v` resolves to the same
 * binding at the use site as at the object literal.
 */
function passFlatFunctions(ast: t.File, log: Logger): number {
  let inlined = 0;
  let accessors = 0;

  // ── phase 1: move bodies back, one nesting layer per round ────────────────
  for (let round = 0; round < 8; round++) {
    const program = freshProgram(ast);
    const dyn = dynamicScopes(program);
    type Pair = {
      flat: NodePath<t.FunctionDeclaration>;
      wrapper: NodePath<t.Function>;
      pattern: t.ArrayPattern;
      objectParam: string;
      objectName: string | null;
      viaArguments: boolean;
      objectExpr: t.ObjectExpression;
    };
    const pairs: Pair[] = [];
    program.traverse({
      Function(wp) {
        const w = wp.node;
        if (w.params.length !== 1 || !t.isRestElement(w.params[0])) return;
        const argsId = w.params[0].argument;
        if (!t.isIdentifier(argsId) || !t.isBlockStatement(w.body) || w.generator) return;
        if ((t.isObjectMethod(w) || t.isClassMethod(w)) && w.kind !== 'method') return;
        if (dyn.observes(wp.scope)) return;
        const stmts = w.body.body;
        if (stmts.length < 1 || stmts.length > 2) return;
        const ret = stmts[stmts.length - 1];
        // `return F(o, args)`, or `F(o, args);` when W's result was always
        // undefined (checked below: F returns no value)
        let call: t.CallExpression;
        let discarded = false;
        if (t.isReturnStatement(ret) && t.isCallExpression(ret.argument)) call = ret.argument;
        else if (t.isExpressionStatement(ret) && t.isCallExpression(ret.expression)) {
          call = ret.expression;
          discarded = true;
        } else return;
        if (!t.isIdentifier(call.callee) || call.arguments.length !== 2) return;
        const [oArg, argsArg] = call.arguments;
        if (!t.isIdentifier(argsArg, { name: argsId.name })) return;
        const argsBinding = wp.scope.getBinding(argsId.name);
        if (!argsBinding || argsBinding.references !== 1 || argsBinding.constantViolations.length)
          return;
        let objectName: string | null = null;
        let objectExpr: t.ObjectExpression;
        if (stmts.length === 2) {
          const d = stmts[0];
          if (!t.isVariableDeclaration(d, { kind: 'var' }) || d.declarations.length !== 1) return;
          const dec = d.declarations[0];
          if (!t.isIdentifier(dec.id) || !t.isObjectExpression(dec.init)) return;
          if (!t.isIdentifier(oArg, { name: dec.id.name })) return;
          const ob = wp.scope.getBinding(dec.id.name);
          if (!ob || ob.references !== 1 || ob.constantViolations.length) return;
          objectName = dec.id.name;
          objectExpr = dec.init;
        } else {
          // `return F({…}, args)`: the object literal was propagated into the call.
          if (!t.isObjectExpression(oArg)) return;
          objectExpr = oArg;
        }
        // F: a top-level declaration whose only reference is this call.
        const fb = wp.scope.getBinding(call.callee.name);
        if (!fb || !fb.path.isFunctionDeclaration() || fb.constantViolations.length) return;
        if (fb.references !== 1 || fb.referencePaths[0].node !== call.callee) return;
        const flat = fb.path;
        // at the top of the program or of a function body (the free-name check
        // below makes the position otherwise irrelevant; a block-level one
        // would carry Annex B semantics)
        const holder = flat.parentPath;
        if (!(holder.isProgram() || (holder.isBlockStatement() && holder.parentPath?.isFunction())) || dyn.observesBinding(fb)) return;
        const f = flat.node;
        if (f.generator || f.async !== w.async) return;
        if (discarded) {
          // W returned undefined after F ran to completion: F's body must
          // return nothing either (and not be async — W did not wait for it)
          if (f.async) return;
          let valued = false;
          walk(f.body, (n) => {
            if (t.isFunction(n)) return false;
            if (t.isReturnStatement(n) && n.argument) valued = true;
          });
          if (valued) return;
        }
        let pattern: t.ArrayPattern | null = null;
        let objectParam: string | null = null;
        let viaArguments = false;
        if (
          f.params.length === 2 &&
          t.isIdentifier(f.params[0]) &&
          t.isArrayPattern(f.params[1])
        ) {
          objectParam = f.params[0].name;
          pattern = f.params[1];
        } else if (f.params.length === 0) {
          // Strict variant: `var [o, [a, b]] = arguments;` as the first statement.
          const first = f.body.body[0];
          const dec =
            t.isVariableDeclaration(first) && first.declarations.length === 1
              ? first.declarations[0]
              : null;
          if (
            dec &&
            t.isArrayPattern(dec.id) &&
            dec.id.elements.length === 2 &&
            t.isIdentifier(dec.id.elements[0]) &&
            t.isArrayPattern(dec.id.elements[1]) &&
            t.isIdentifier(dec.init, { name: 'arguments' })
          ) {
            objectParam = dec.id.elements[0].name;
            pattern = dec.id.elements[1];
            viaArguments = true;
          }
        }
        if (!pattern || objectParam === null) return;
        // F's own `this` / `arguments` / `new.target` / `super` would be bound
        // differently inside W — except the `arguments` the strict variant
        // destructures, which is exactly the parameter list being restored.
        const ownCheck = viaArguments ? t.functionExpression(null, [], t.blockStatement(f.body.body.slice(1))) : f;
        if (usesOwnContext(ownCheck)) return;
        if (pattern.elements.some((e) => e === null)) return;
        const simpleParams = pattern.elements.every((e) => t.isIdentifier(e));
        if (f.body.directives.length && !simpleParams) return; // "use strict" needs simple params
        // Every free name of the body must mean the same thing at W.
        const refs = freeReferences(flat);
        if (refs.usesThis) return;
        for (const b of [...refs.reads, ...refs.writes, ...refs.mutates])
          if (wp.scope.getBinding(b.identifier.name) !== b) return;
        for (const g of refs.globals) if (wp.scope.getBinding(g)) return; // (hasBinding counts built-ins)
        // The object parameter takes W's name for the object, if that is free in F.
        if (objectName !== null && objectName !== objectParam) {
          let clash = false;
          walk(f, (n) => {
            if (t.isIdentifier(n, { name: objectName })) clash = true;
          });
          if (clash) return;
        }
        pairs.push({ flat, wrapper: wp, pattern, objectParam, objectName, viaArguments, objectExpr });
      },
    });
    // Outermost first: a wrapper inside another pair's F waits for the next round.
    const flatNodes = pairs.map((pr) => pr.flat.node);
    const ready = pairs.filter((pr) => !flatNodes.some((fn) => pathWithin(pr.wrapper, fn)));
    if (ready.length === 0) break;
    for (const pr of ready) {
      const f = pr.flat.node;
      const w = pr.wrapper.node as t.Function & { body: t.BlockStatement };
      const body = [...f.body.body];
      if (pr.viaArguments) body.shift();
      const usesObject = pr.flat.scope.getBinding(pr.objectParam)?.referenced ?? false;
      const objectName = pr.objectName ?? pr.objectParam;
      if (pr.objectName !== null && pr.objectName !== pr.objectParam)
        pr.flat.scope.rename(pr.objectParam, pr.objectName);
      const head: t.Statement[] = [];
      if (pr.objectName !== null || usesObject)
        head.push(
          t.variableDeclaration('var', [
            t.variableDeclarator(t.identifier(objectName), pr.objectExpr),
          ])
        );
      w.params = pr.pattern.elements as t.Function['params'];
      // F's "use strict" carries its semantics along — unless W already runs in
      // strict code (a class body, or under an outer directive), where it is a no-op.
      const wStrict =
        !!pr.wrapper.findParent((q) => q.isClass() || (q.isFunction() && t.isBlockStatement(q.node.body) && q.node.body.directives.some((d) => d.value.value === 'use strict'))) ||
        (pr.wrapper.findParent((q) => q.isProgram())?.node as t.Program | undefined)?.sourceType === 'module';
      const moved = wStrict ? f.body.directives.filter((d) => d.value.value !== 'use strict') : f.body.directives;
      w.body = t.blockStatement([...head, ...body], [...w.body.directives, ...moved]);
      try {
        pr.flat.remove();
      } catch {
        /**/
      }
      inlined++;
    }
  }

  // ── phase 2: accessor objects back to the variables they wrap ─────────────
  {
    const program = freshProgram(ast);
    const dyn = dynamicScopes(program);
    type Accessor = { get?: string; typeofOf?: string; set?: string; call?: string };
    const tableOf = (obj: t.ObjectExpression): Map<string, Accessor> | null => {
      const table = new Map<string, Accessor>();
      for (const prop of obj.properties) {
        if (!t.isObjectMethod(prop) || prop.computed || prop.async || prop.generator) return null;
        const key = staticPropKey(prop);
        if (key === null) return null;
        const entry = table.get(key) ?? {};
        const only = prop.body.body.length === 1 ? prop.body.body[0] : null;
        if (prop.kind === 'get' && prop.params.length === 0 && t.isReturnStatement(only)) {
          const a = only.argument;
          if (t.isIdentifier(a)) entry.get = a.name;
          else if (t.isUnaryExpression(a, { operator: 'typeof' }) && t.isIdentifier(a.argument))
            entry.typeofOf = a.argument.name;
          else return null;
        } else if (
          prop.kind === 'set' &&
          prop.params.length === 1 &&
          t.isIdentifier(prop.params[0]) &&
          t.isExpressionStatement(only) &&
          t.isAssignmentExpression(only.expression, { operator: '=' }) &&
          t.isIdentifier(only.expression.left) &&
          t.isIdentifier(only.expression.right, { name: prop.params[0].name })
        ) {
          entry.set = only.expression.left.name;
        } else if (
          prop.kind === 'method' &&
          prop.params.length === 1 &&
          t.isRestElement(prop.params[0]) &&
          t.isIdentifier(prop.params[0].argument) &&
          t.isReturnStatement(only) &&
          t.isCallExpression(only.argument) &&
          t.isIdentifier(only.argument.callee) &&
          only.argument.arguments.length === 1 &&
          t.isSpreadElement(only.argument.arguments[0]) &&
          t.isIdentifier(only.argument.arguments[0].argument, {
            name: prop.params[0].argument.name,
          })
        ) {
          entry.call = only.argument.callee.name;
        } else return null;
        table.set(key, entry);
      }
      return table;
    };
    type Rewrite = () => void;
    const jobs: Array<{ decl: NodePath<t.VariableDeclaration>; rewrites: Rewrite[] }> = [];
    program.traverse({
      VariableDeclarator(dp) {
        const { id, init } = dp.node;
        if (!t.isIdentifier(id) || !t.isObjectExpression(init) || init.properties.length === 0)
          return;
        const decl = dp.parentPath;
        if (!decl.isVariableDeclaration() || decl.node.declarations.length !== 1) return;
        const binding = dp.scope.getBinding(id.name);
        if (!binding || binding.path.node !== dp.node || binding.constantViolations.length) return;
        if (dyn.observesBinding(binding)) return;
        const table = tableOf(init);
        if (!table) return;
        const same = (name: string, at: NodePath): boolean =>
          at.scope.getBinding(name) === dp.scope.getBinding(name);
        const rewrites: Rewrite[] = [];
        for (const r of binding.referencePaths) {
          const member = r.parentPath;
          if (!member?.isMemberExpression() || member.node.object !== r.node || member.node.optional)
            return;
          const key = staticMemberKey(member.node);
          if (key === null) return;
          const acc = table.get(key);
          if (!acc) return;
          const holder = member.parentPath;
          const isWrite =
            (holder.isAssignmentExpression() && holder.node.left === member.node) ||
            holder.isUpdateExpression() ||
            (holder.isForXStatement() && holder.node.left === member.node);
          const isPlainWrite =
            holder.isAssignmentExpression({ operator: '=' }) && holder.node.left === member.node;
          const isCall = holder.isCallExpression() && holder.node.callee === member.node;
          if (holder.isUnaryExpression({ operator: 'delete' })) return;
          if (isCall) {
            if (!acc.call || !same(acc.call, member)) return;
            const name = acc.call;
            rewrites.push(() => {
              (holder.node as t.CallExpression).callee = t.identifier(name);
            });
          } else if (isWrite) {
            // `=` needs the setter; a compound write or update reads first too.
            if (!acc.set || !same(acc.set, member)) return;
            if (!isPlainWrite && acc.get !== acc.set) return;
            const name = acc.set;
            rewrites.push(() => member.replaceWith(t.identifier(name)));
          } else if (acc.get !== undefined) {
            if (!same(acc.get, member)) return;
            const name = acc.get;
            rewrites.push(() => member.replaceWith(t.identifier(name)));
          } else if (acc.typeofOf !== undefined) {
            if (!same(acc.typeofOf, member)) return;
            const name = acc.typeofOf;
            rewrites.push(() =>
              member.replaceWith(t.unaryExpression('typeof', t.identifier(name)))
            );
          } else return;
        }
        jobs.push({ decl, rewrites });
      },
    });
    for (const job of jobs) {
      for (const run of job.rewrites) {
        try {
          run();
          accessors++;
        } catch {
          /**/
        }
      }
      try {
        job.decl.remove();
      } catch {
        /**/
      }
    }
  }

  log.pass('b09c', 'flatFunctions', inlined + accessors, 'rewrites', `${inlined} bodies moved back`);
  return inlined + accessors;
}

// ── B00d: masked variables ───────────────────────────────────────────────────

/**
 * `function f(...S) { S.length = 1; … S[0] … S[-3] = … S.k … }`
 *   → `function f(arg0) { var local_m3, k; … arg0 … local_m3 = … k … }`
 *
 * js-confuser's variable masking turns a function's parameters and locals into
 * slots of its rest parameter: integer slots below the original parameter count
 * hold the arguments, other integers (negative ones too) and string keys hold
 * locals, and `S.length = n` as the first statement discards surplus arguments.
 * The array is private to the function, so once every use of S is a slot read
 * or write under a literal key — never a method call on S, a `length` read, or
 * an escape — the slots are only names:
 *   • slot i < n is the i-th parameter: the same argument, in the same order;
 *   • every other slot starts out `undefined` (the truncation, or the key not
 *     being an array index, guarantees it; keys that `Array.prototype` already
 *     has are refused) and is read and written only here, exactly like a `var`
 *     declared at the top of the body.
 * Without a truncation, n is one more than the largest non-negative slot: a
 * slot below n may then carry a surplus argument, which the parameter keeps.
 * A slot that is *called* would have had S as `this`; the call is rewritten
 * only when every value the slot ever receives is a function that does not
 * use `this`. `arguments` is refused, since it would observe the parameter
 * list, and so is a function whose arity code reads through `.length` /
 * `.bind`, as in B00c.
 */
function passMaskedVariables(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  type Use = { member: NodePath<t.MemberExpression>; key: string };
  type Job = {
    fn: NodePath<t.Function>;
    truncation: NodePath<t.Statement> | null;
    count: number;
    uses: Use[];
  };
  const jobs: Job[] = [];

  const slotKey = (m: t.MemberExpression): string | null => {
    if (!m.computed) return t.isIdentifier(m.property) ? m.property.name : null;
    const prop = m.property;
    if (t.isStringLiteral(prop)) return prop.value;
    if (t.isNumericLiteral(prop)) return String(prop.value);
    if (t.isUnaryExpression(prop, { operator: '-' }) && t.isNumericLiteral(prop.argument))
      return String(-prop.argument.value);
    return null;
  };
  const arrayIndex = (key: string): number | null =>
    /^(0|[1-9]\d*)$/.test(key) ? Number(key) : null;
  /** A function value that never looks at its own `this`. */
  const thisFree = (v: t.Node, scope: NodePath['scope']): boolean => {
    if (t.isArrowFunctionExpression(v)) return true;
    if (t.isFunctionExpression(v)) return !usesOwnContext(v);
    // `Math.max` and friends never consult their receiver.
    if (
      t.isMemberExpression(v) &&
      t.isIdentifier(v.object, { name: 'Math' }) &&
      !scope.getBinding('Math')
    )
      return true;
    if (t.isIdentifier(v)) {
      const b = scope.getBinding(v.name);
      const d = b?.path.node;
      if (!b || b.constantViolations.length) return false;
      if (t.isFunctionDeclaration(d)) return !usesOwnContext(d);
      if (t.isVariableDeclarator(d) && d.init) return thisFree(d.init, b.scope);
    }
    return false;
  };

  program.traverse({
    Function(p) {
      const fn = p.node;
      if (fn.params.length !== 1 || !t.isRestElement(fn.params[0])) return;
      const rest = fn.params[0].argument;
      if (!t.isIdentifier(rest) || !t.isBlockStatement(fn.body)) return;
      if ((t.isObjectMethod(fn) || t.isClassMethod(fn)) && fn.kind !== 'method') return;
      if (dyn.observes(p.scope)) return;
      if (!t.isArrowFunctionExpression(fn) && usesArguments(fn)) return;
      const binding = p.scope.getBinding(rest.name);
      if (!binding || binding.kind !== 'param' || binding.constantViolations.length > 0) return;
      // Like B00c: keep the signature when code observes its arity.
      const parent = p.parentPath;
      const fnBinding =
        t.isFunctionDeclaration(fn) && fn.id
          ? parent.scope.getBinding(fn.id.name)
          : parent.isVariableDeclarator() && t.isIdentifier(parent.node.id)
            ? parent.scope.getBinding(parent.node.id.name)
            : null;
      if (
        fnBinding?.referencePaths.some(
          (r) =>
            r.parentPath?.isMemberExpression() &&
            r.parentPath.node.object === r.node &&
            ['length', 'bind'].includes(staticMemberKey(r.parentPath.node) ?? '')
        )
      )
        return;

      // `S.length = n` is accepted only as the first statement to run —
      // hoisted declarations ahead of it (function declarations, value-less
      // `var`s) run nothing.
      const bodyPaths = (p.get('body') as NodePath<t.BlockStatement>).get('body');
      const firstAt = fn.body.body.findIndex(
        (st) => !(t.isFunctionDeclaration(st) || (t.isVariableDeclaration(st, { kind: 'var' }) && st.declarations.every((d) => !d.init)))
      );
      const first = firstAt >= 0 ? fn.body.body[firstAt] : undefined;
      let truncation: NodePath<t.Statement> | null = null;
      let count = -1;
      let truncationTarget: t.Node | null = null;
      if (
        t.isExpressionStatement(first) &&
        t.isAssignmentExpression(first.expression, { operator: '=' }) &&
        t.isMemberExpression(first.expression.left) &&
        t.isIdentifier(first.expression.left.object, { name: rest.name }) &&
        slotKey(first.expression.left) === 'length' &&
        t.isNumericLiteral(first.expression.right) &&
        Number.isInteger(first.expression.right.value) &&
        first.expression.right.value >= 0
      ) {
        truncation = bodyPaths[firstAt];
        count = first.expression.right.value;
        truncationTarget = first.expression.left;
      }

      // Without a truncation, slots the callers can reach are parameters;
      // when every call is known, that is the most arguments any passes.
      if (count < 0) {
        const arity = knownArity(p, dyn);
        if (Number.isFinite(arity)) count = arity;
      }
      const uses: Use[] = [];
      const writes = new Map<string, t.Node[]>();
      const called = new Set<string>();
      let maxIndex = -1;
      for (const r of binding.referencePaths) {
        const member = r.parentPath;
        if (!member?.isMemberExpression() || member.node.object !== r.node || member.node.optional)
          return;
        if (member.node === truncationTarget) continue;
        const key = slotKey(member.node);
        if (key === null || key === 'length') return;
        const index = arrayIndex(key);
        if (index === null && key in []) return; // `S.map`, `S.at`: not an empty slot
        const holder = member.parentPath;
        if (holder.isUnaryExpression({ operator: 'delete' })) return;
        if (holder.isCallExpression() && holder.node.callee === member.node) called.add(key);
        if (holder.isAssignmentExpression() && holder.node.left === member.node) {
          const list = writes.get(key) ?? [];
          list.push(holder.node.operator === '=' ? holder.node.right : holder.node);
          writes.set(key, list);
        } else if (
          holder.isUpdateExpression() ||
          (holder.isForXStatement() && holder.node.left === member.node) ||
          holder.isArrayPattern() ||
          holder.isObjectProperty({ value: member.node }) ||
          holder.isAssignmentPattern({ left: member.node }) ||
          holder.isRestElement()
        ) {
          const list = writes.get(key) ?? [];
          list.push(holder.node);
          writes.set(key, list);
        }
        if (index !== null) maxIndex = Math.max(maxIndex, index);
        uses.push({ member, key });
      }
      // `S.k[i]` where slot k holds a never-mutated array literal of `this`-free
      // functions: whatever element is read is one of them (or `undefined`,
      // which a call rejects the same way before and after).
      const fromThisFreeTable = (v: t.Node): boolean => {
        if (!t.isMemberExpression(v) || !v.computed) return false;
        const inner = v.object;
        // …or `V[i]` for a local V holding one such array literal, written
        // only by its declaration and otherwise only read element-wise
        if (t.isIdentifier(inner)) {
          const b = p.scope.getBinding(inner.name);
          if (!b || !b.path.isVariableDeclarator() || b.constantViolations.length || dyn.observesBinding(b)) return false;
          const arr = b.path.node.init;
          if (!t.isArrayExpression(arr) || !arr.elements.every((e) => !!e && !t.isSpreadElement(e) && thisFree(e, p.scope))) return false;
          return b.referencePaths.every((r) => {
            const m = r.parentPath;
            if (!m?.isMemberExpression() || m.node.object !== r.node || !m.node.computed) return false;
            const up = m.parentPath;
            return !((up?.isAssignmentExpression() && up.node.left === m.node) || up?.isUpdateExpression() || up?.isUnaryExpression({ operator: 'delete' }) || (up?.isCallExpression() && up.node.callee === m.node));
          });
        }
        if (!t.isMemberExpression(inner) || !t.isIdentifier(inner.object, { name: rest.name })) return false;
        const k = slotKey(inner);
        if (k === null) return false;
        const vals = writes.get(k) ?? [];
        if (vals.length !== 1 || !t.isArrayExpression(vals[0])) return false;
        const table = vals[0];
        if (!table.elements.every((e) => !!e && !t.isSpreadElement(e) && thisFree(e, p.scope))) return false;
        for (const u of uses) {
          if (u.key !== k) continue;
          const h = u.member.parentPath;
          if (h.isAssignmentExpression({ operator: '=' }) && h.node.left === u.member.node && h.node.right === table) continue;
          if (!(h.isMemberExpression() && h.node.object === u.member.node && h.node.computed)) return false;
          const hh = h.parentPath;
          if ((hh?.isAssignmentExpression() && hh.node.left === h.node) || hh?.isUpdateExpression() || hh?.isUnaryExpression({ operator: 'delete' }))
            return false;
        }
        return true;
      };
      // A called slot: every value it receives must be a `this`-free function,
      // or the call's `this` (S itself) might have been observed. One more
      // origin is accepted: a value the slot receives by destructuring
      // (`[S.b, S[2]] = PAYLOAD`, the parameters a dispatcher hands an entry).
      // js-confuser's variableMasking spelt the source's plain call `x(y)` as
      // `S[i](y)` without regard to `this` — handing the callee S instead of
      // `undefined` — so restoring `x(y)` is the source's call; the two differ
      // only for a callee that reads `this`, which the obfuscation had already
      // changed from the source.
      const byDestructuring = (v: t.Node): boolean => t.isArrayPattern(v) || t.isObjectPattern(v) || t.isObjectProperty(v) || t.isRestElement(v);
      for (const key of called) {
        const vals = writes.get(key) ?? [];
        if (vals.length === 0) return;
        if (
          !vals.every(
            (v) => t.isIdentifier(v, { name: 'undefined' }) || thisFree(v, p.scope) || fromThisFreeTable(v) || byDestructuring(v)
          )
        )
          return;
        // A parameter slot also receives the caller's argument.
        if (arrayIndex(key) !== null && (count < 0 || arrayIndex(key)! < count)) return;
      }
      if (count < 0) count = maxIndex + 1;
      jobs.push({ fn: p, truncation, count, uses });
    },
  });

  let fns = 0;
  let slots = 0;
  for (const job of jobs) {
    const fn = job.fn.node as t.Function & { body: t.BlockStatement };
    const used = new Set<string>();
    walk(fn, (n) => {
      if (t.isIdentifier(n)) used.add(n.name);
    });
    const scope = job.fn.scope;
    const fresh = (base: string): string => {
      let name = base;
      for (let i = 1; !t.isValidIdentifier(name) || used.has(name) || scope.hasBinding(name) || scope.hasGlobal(name) || scope.hasReference(name); i++)
        name = `${base}_${i}`;
      used.add(name);
      return name;
    };
    const params: string[] = [];
    for (let i = 0; i < job.count; i++) params.push(fresh(`arg${i}`));
    const locals = new Map<string, string>();
    const nameOf = (key: string): string => {
      const index = arrayIndex(key);
      if (index !== null && index < job.count) return params[index];
      let name = locals.get(key);
      if (name === undefined) {
        const base = index !== null ? `local${index}` : /^-\d+$/.test(key) ? `local_m${key.slice(1)}` : key;
        name = fresh(base);
        locals.set(key, name);
      }
      return name;
    };
    try {
      for (const use of job.uses) use.member.replaceWith(t.identifier(nameOf(use.key)));
      fn.params = params.map((n) => t.identifier(n));
      if (job.truncation) job.truncation.remove();
      if (locals.size)
        fn.body.body.unshift(
          t.variableDeclaration(
            'var',
            [...locals.values()].map((n) => t.variableDeclarator(t.identifier(n)))
          )
        );
      fns++;
      slots += job.uses.length;
    } catch {
      /**/
    }
  }
  log.pass('b00d', 'maskedVariables', slots, 'slots', `${fns} functions`);
  return slots;
}

// ── B09b: no-op calls ────────────────────────────────────────────────────────

/**
 * `F(a, b, c);` where F does nothing → `a; b; c;`
 *
 * js-confuser's AST scrambler packs runs of expression statements into the
 * arguments of one call to a function it appends to the program,
 * `function F() { F = function () {}; }`. A call evaluates its arguments left
 * to right and then runs the body; here the body is empty or only replaces F
 * with another empty function. That write is unobservable when F is referenced
 * solely as the callee of statement-level calls: the binding is never read,
 * compared or passed on, and every later call is a no-op either way. The
 * statement is therefore equivalent to its arguments as statements, in the
 * same order. Spread arguments are left alone, since spreading runs an
 * iterator that the statement form would not.
 */
function passNoopCalls(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const isEmptyFunction = (node: t.Node | null | undefined): boolean =>
    (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) &&
    !node.async &&
    !node.generator &&
    node.params.length === 0 &&
    t.isBlockStatement(node.body) &&
    node.body.body.length === 0;

  let n = 0;
  let fns = 0;
  const work: Array<{ decl: NodePath<t.FunctionDeclaration>; sites: NodePath<t.ExpressionStatement>[] }> =
    [];
  program.traverse({
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id || p.node.async || p.node.generator || p.node.params.length !== 0) return;
      const binding = p.parentPath.scope.getBinding(id.name);
      if (!binding || binding.path.node !== p.node || dyn.observesBinding(binding)) return;
      // The body is empty, or exactly the self-erasure `F = function () {};`.
      const stmts = p.node.body.body.filter((s) => !t.isEmptyStatement(s));
      const erase = stmts.length === 1 ? stmts[0] : null;
      const selfErase =
        !!erase &&
        t.isExpressionStatement(erase) &&
        t.isAssignmentExpression(erase.expression, { operator: '=' }) &&
        t.isIdentifier(erase.expression.left, { name: id.name }) &&
        isEmptyFunction(erase.expression.right);
      if (stmts.length !== 0 && !selfErase) return;
      // No write to F other than that self-erasure.
      if (binding.constantViolations.some((v) => !pathWithin(v, p.node))) return;
      // Every reference is the callee of a statement-level call with plain arguments.
      const sites: NodePath<t.ExpressionStatement>[] = [];
      for (const r of binding.referencePaths) {
        const call = r.parentPath;
        if (!call?.isCallExpression() || call.node.callee !== r.node) return;
        const stmt = call.parentPath;
        if (!stmt?.isExpressionStatement() || stmt.node.expression !== call.node) return;
        if (!call.node.arguments.every((a) => t.isExpression(a))) return;
        sites.push(stmt);
      }
      work.push({ decl: p, sites });
    },
  });
  for (const { decl, sites } of work) {
    fns++;
    for (const stmt of sites) {
      // A bare local or literal among the arguments did nothing either.
      const args = ((stmt.node.expression as t.CallExpression).arguments as t.Expression[]).filter(
        (a) => !isDiscardable(a, stmt.scope)
      );
      try {
        if (args.length === 0) stmt.remove();
        else if (stmt.parentPath.isBlockStatement() || stmt.parentPath.isProgram() || stmt.parentPath.isSwitchCase())
          stmt.replaceWithMultiple(args.map((a) => t.expressionStatement(a)));
        else stmt.replaceWith(t.expressionStatement(args.length === 1 ? args[0] : t.sequenceExpression(args)));
        n++;
      } catch {
        /* detached by an earlier rewrite */
      }
    }
    try {
      decl.remove();
    } catch {
      /**/
    }
  }
  log.pass('b09b', 'noopCalls', n, 'calls', `${fns} functions`);
  return n;
}

function passOpaquePredicates(ast: t.File, log: Logger): number {
  let n = foldFunctionProbes(ast);
  traverse(ast, {
    IfStatement: {
      exit(p) {
        if (!isPurelyLiteral(p.node.test)) return;
        const r = evalPure(p.node.test);
        if (!r.ok) return;
        if (r.value) {
          p.replaceWith(p.node.consequent);
          n++;
        } else if (p.node.alternate) {
          p.replaceWith(p.node.alternate);
          n++;
        } else {
          p.remove();
          n++;
        }
      },
    },
    ConditionalExpression: {
      exit(p) {
        if (!isPurelyLiteral(p.node.test)) return;
        const r = evalPure(p.node.test);
        if (!r.ok) return;
        p.replaceWith(r.value ? p.node.consequent : p.node.alternate);
        n++;
      },
    },
    WhileStatement: {
      exit(p) {
        if (!isPurelyLiteral(p.node.test)) return;
        const r = evalPure(p.node.test);
        if (!r.ok) return;
        if (!r.value) {
          p.remove();
          n++;
        }
      },
    },
    DoWhileStatement: {
      exit(p) {
        if (!isPurelyLiteral(p.node.test)) return;
        const r = evalPure(p.node.test);
        if (!r.ok) return;
        if (!r.value) {
          p.replaceWith(p.node.body);
          n++;
        }
      },
    },
  });
  log.pass('b11', 'opaquePredicates', n);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B11b: Scoped constant folding
//
// The state machines carry their opaque predicates in loop-local scratch vars:
//
//   for (var o = -386, c = 54; true;) {
//     var t = -186;
//     switch (c) {
//       case 54:
//         (-231 < -4*(-31 & t) - 6*(-31 & ~t) + … && 186) ? (i = true, c = 120)
//                                                         : (…, c = 54);
//     }
//   }
//
// `t` is written once with a literal, so the whole test is a constant — but
// constantPropagation (B08) will not inline it: the binding is re-declared on
// every iteration, so Babel does not report it as `constant`, and the folder
// never sees a literal. The predicate therefore survives, and with it a bogus
// `c = 54` self-edge that makes the state graph look cyclic and blocks B13b.
//
// This pass walks each function scope, collects identifiers that are assigned a
// literal exactly once and never mutated anywhere in that scope, and substitutes
// them inside pure arithmetic tests only. Folding is then left to B04.
//
// Restricted to expressions that are already pure arithmetic over literals and
// these single-assignment locals — no calls, no member access, no side effects —
// so substitution cannot change evaluation order or observable behaviour.
// ─────────────────────────────────────────────────────────────────────────────

function passScopedConstFold(ast: t.File, log: Logger): number {
  let n = 0;

  traverse(ast, {
    Function(fnPath) {
      const body = fnPath.node.body;
      if (!t.isBlockStatement(body)) return;

      // Collect candidate literal locals for this function, and count writes.
      const literalOf = new Map<string, number>();
      const writes = new Map<string, number>();

      const note = (name: string) => writes.set(name, (writes.get(name) ?? 0) + 1);

      walkNode(body, (nd) => {
        if (t.isVariableDeclarator(nd) && t.isIdentifier(nd.id)) {
          note(nd.id.name);
          const init = nd.init;
          if (!init) return;
          if (t.isNumericLiteral(init)) literalOf.set(nd.id.name, init.value);
          else if (
            t.isUnaryExpression(init, { operator: '-' }) &&
            t.isNumericLiteral(init.argument)
          )
            literalOf.set(nd.id.name, -init.argument.value);
        } else if (t.isAssignmentExpression(nd) && t.isIdentifier(nd.left)) note(nd.left.name);
        else if (t.isUpdateExpression(nd) && t.isIdentifier(nd.argument)) note(nd.argument.name);
        // A nested function may capture and mutate the name later.
        else if (t.isFunction(nd) && nd !== fnPath.node)
          for (const prm of nd.params) if (t.isIdentifier(prm)) note(prm.name);
      });

      // Keep only names written exactly once, with a literal.
      const env = new Map<string, number>();
      for (const [name, value] of literalOf)
        if ((writes.get(name) ?? 0) === 1) env.set(name, value);
      if (env.size === 0) return;

      /** Pure arithmetic over numeric literals and `env` names only. */
      const isFoldable = (node: t.Node, depth = 0): boolean => {
        if (depth > MAX_PURE_DEPTH) return false;
        if (t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return true;
        if (t.isIdentifier(node)) return env.has(node.name);
        if (t.isUnaryExpression(node))
          return PURE_NUMERIC_UNARY_OPS.has(node.operator) && isFoldable(node.argument, depth + 1);
        if (t.isBinaryExpression(node))
          return (
            PURE_NUMERIC_BINARY_OPS.has(node.operator) &&
            t.isExpression(node.left) &&
            isFoldable(node.left, depth + 1) &&
            isFoldable(node.right, depth + 1)
          );
        if (t.isLogicalExpression(node))
          return isFoldable(node.left, depth + 1) && isFoldable(node.right, depth + 1);
        return false;
      };

      /** Rebuild the expression with env names replaced by their literals. */
      const substitute = (node: t.Expression): t.Expression => {
        if (t.isIdentifier(node) && env.has(node.name)) {
          const v = env.get(node.name) as number;
          return v < 0 ? t.unaryExpression('-', t.numericLiteral(-v)) : t.numericLiteral(v);
        }
        if (t.isUnaryExpression(node))
          return t.unaryExpression(
            node.operator,
            substitute(node.argument as t.Expression),
            node.prefix
          );
        if (t.isBinaryExpression(node))
          return t.binaryExpression(
            node.operator,
            substitute(node.left as t.Expression),
            substitute(node.right as t.Expression)
          );
        if (t.isLogicalExpression(node))
          return t.logicalExpression(
            node.operator,
            substitute(node.left as t.Expression),
            substitute(node.right as t.Expression)
          );
        return node;
      };

      // Only rewrite positions whose value is used as a condition — that is where
      // the opaque predicates live, and it keeps the blast radius small.
      fnPath.traverse({
        ConditionalExpression(p) {
          const test = p.node.test;
          if (!isFoldable(test)) return;
          const folded = evalPure(substitute(test as t.Expression));
          if (!folded.ok) return;
          const repl = toNode(folded.value);
          if (!repl) return;
          p.node.test = repl;
          n++;
        },
        IfStatement(p) {
          const test = p.node.test;
          if (!isFoldable(test)) return;
          const folded = evalPure(substitute(test as t.Expression));
          if (!folded.ok) return;
          const repl = toNode(folded.value);
          if (!repl) return;
          p.node.test = repl;
          n++;
        },
      });
    },
  });

  log.pass('b11b', 'scopedConstFold', n);
  return n;
}

function passDeadCode(ast: t.File, log: Logger): number {
  let n = 0;
  /**
   * Statements after an unconditional jump in the same list never run. Their
   * hoisted parts still exist: a function declaration stays, and a `var`
   * keeps its declaration (minus the initialiser that would never execute).
   */
  // `while (true) {}` (js-confuser's countermeasure) never completes either
  const spinsForever = (st: t.Statement): boolean => {
    const empty = (b: t.Statement) => t.isEmptyStatement(b) || (t.isBlockStatement(b) && b.body.length === 0);
    if (t.isWhileStatement(st)) return (t.isBooleanLiteral(st.test, { value: true }) || (t.isNumericLiteral(st.test) && st.test.value !== 0)) && empty(st.body);
    if (t.isForStatement(st)) return !st.test && !st.update && empty(st.body) && (!st.init || t.isVariableDeclaration(st.init) && st.init.declarations.every((d) => !d.init));
    return false;
  };
  const pruneAfterJump = (list: t.Statement[]): t.Statement[] => {
    const i = list.findIndex((st) => t.isReturnStatement(st) || t.isThrowStatement(st) || t.isBreakStatement(st) || t.isContinueStatement(st) || spinsForever(st));
    if (i < 0 || i === list.length - 1) return list;
    const keep: t.Statement[] = [];
    for (const st of list.slice(i + 1)) {
      if (t.isFunctionDeclaration(st)) keep.push(st);
      else if (t.isVariableDeclaration(st) && st.kind === 'var')
        keep.push(t.variableDeclaration('var', st.declarations.map((d) => t.variableDeclarator(t.cloneNode(d.id, true)))));
    }
    n += list.length - 1 - i - keep.filter((k) => !t.isVariableDeclaration(k)).length;
    return [...list.slice(0, i + 1), ...keep];
  };
  t.traverseFast(ast.program, (x) => {
    if (t.isBlockStatement(x)) x.body = pruneAfterJump(x.body);
    else if (t.isSwitchCase(x)) x.consequent = pruneAfterJump(x.consequent);
  });
  traverse(ast, {
    // A bare block `{ … }` in a statement list, holding no block-scoped
    // declaration (let/const/class, or a function in sloppy code), scopes
    // nothing: its statements can stand in the list themselves.
    BlockStatement: {
      exit(p) {
        if (!p.parentPath.isBlockStatement() && !p.parentPath.isProgram()) return;
        if (!Array.isArray(p.container)) return;
        const scoped = p.node.body.some((st) => (t.isVariableDeclaration(st) && st.kind !== 'var') || t.isClassDeclaration(st) || t.isFunctionDeclaration(st));
        if (scoped || p.node.directives.length) return;
        p.replaceWithMultiple(p.node.body);
        n++;
      },
    },
    // A discarded expression that provably neither throws, loops nor writes
    // anything outside itself (see effectFree) is a no-op.
    ExpressionStatement(p) {
      // A string statement left at the head of a body would print as a
      // directive ("use strict"): never remove one, nor what precedes one.
      if (t.isStringLiteral(p.node.expression)) return;
      const next = p.getSibling((p.key as number) + 1);
      if (typeof p.key === 'number' && next.isExpressionStatement() && t.isStringLiteral(next.node.expression)) return;
      if (!effectFree(p.get('expression'))) return;
      p.remove();
      n++;
    },
    // `try { B } catch …` where nothing in B can throw (every statement
    // effectFree): the handler never runs.
    // `try { B } finally {}`: an empty finally with no catch adds nothing.
    TryStatement: {
      exit(p) {
        const { block, handler, finalizer } = p.node;
        if (handler && !finalizer) {
          const stmts = p.get('block.body') as NodePath[];
          // (an assignment to a declared var or parameter cannot throw either)
          const quietAssign = (e: NodePath): boolean => {
            if (!e.isAssignmentExpression({ operator: '=' }) || !t.isIdentifier(e.node.left)) return false;
            const b = e.scope.getBinding(e.node.left.name);
            return !!b && (b.kind === 'var' || b.kind === 'param') && effectFree(e.get('right') as NodePath);
          };
          const quiet = stmts.every((st) =>
            st.isFunctionDeclaration() // creating a function runs nothing
              ? true
              : st.isExpressionStatement()
                ? effectFree(st.get('expression') as NodePath) || quietAssign(st.get('expression') as NodePath)
                : st.isVariableDeclaration({ kind: 'var' }) &&
                  (st.get('declarations') as NodePath<t.VariableDeclarator>[]).every((d) => t.isIdentifier(d.node.id) && (!d.node.init || effectFree(d.get('init') as NodePath)))
          );
          if (quiet) {
            // a block-level function keeps its block (Annex B semantics)
            if (stmts.some((st) => st.isFunctionDeclaration())) p.replaceWith(block);
            else p.replaceWithMultiple(block.body);
            n++;
            return;
          }
        }
        if (handler || !finalizer || finalizer.body.length) return;
        const scoped = block.body.some((st) => (t.isVariableDeclaration(st) && st.kind !== 'var') || t.isClassDeclaration(st) || t.isFunctionDeclaration(st));
        if (scoped) p.replaceWith(block);
        else p.replaceWithMultiple(block.body);
        n++;
      },
    },
    IfStatement: {
      exit(p) {
        const { test, consequent, alternate } = p.node;
        const isTrue =
          (t.isBooleanLiteral(test) && test.value) ||
          (t.isNumericLiteral(test) && test.value !== 0);
        const isFalse =
          (t.isBooleanLiteral(test) && !test.value) ||
          (t.isNumericLiteral(test) && test.value === 0) ||
          t.isNullLiteral(test) ||
          t.isIdentifier(test, { name: 'undefined' });
        if (isTrue) {
          p.replaceWith(consequent);
          n++;
        } else if (isFalse) {
          if (alternate) p.replaceWith(alternate);
          else p.remove();
          n++;
        }
      },
    },
    ConditionalExpression: {
      exit(p) {
        const { test, consequent, alternate } = p.node;
        if (t.isBooleanLiteral(test)) {
          p.replaceWith(test.value ? consequent : alternate);
          n++;
        } else if (t.isNumericLiteral(test)) {
          p.replaceWith(test.value !== 0 ? consequent : alternate);
          n++;
        }
      },
    },
    LogicalExpression: {
      exit(p) {
        const { left, right, operator } = p.node;
        if (operator === '&&' || operator === '||') {
          // `X || X`, `X && X`: the second read sees what the first did. A
          // binding read has no effect; an unbound name only for a built-in
          // data property (anything else could be a getter, or missing).
          if (
            t.isIdentifier(left) &&
            t.isIdentifier(right, { name: left.name }) &&
            (p.scope.getBinding(left.name) || GUARANTEED_GLOBALS.has(left.name))
          ) {
            p.replaceWith(left);
            n++;
            return;
          }
          if (!t.isBooleanLiteral(left) && !t.isNumericLiteral(left)) return;
          const val = t.isBooleanLiteral(left)
            ? left.value
            : (left as t.NumericLiteral).value !== 0;
          // The short-circuited value is the left operand itself (`0 && x` is 0).
          if (operator === '&&') p.replaceWith(val ? right : left);
          else p.replaceWith(val ? left : right);
          n++;
          return;
        }
        if (operator === '??') {
          if (t.isNullLiteral(left) || t.isIdentifier(left, { name: 'undefined' })) {
            p.replaceWith(right);
            n++;
          } else if (
            t.isBooleanLiteral(left) ||
            t.isNumericLiteral(left) ||
            t.isStringLiteral(left)
          ) {
            p.replaceWith(left);
            n++;
          }
        }
      },
    },
  });
  log.pass('b12', 'deadCode', n);
  return n;
}

function passControlFlowUnflatten(ast: t.File, log: Logger): number {
  const splitMap = new Map<string, string[]>();
  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (t.isIdentifier(id) && t.isArrayExpression(init)) {
        const list = literalStringList(init);
        if (list && list.length > 0) splitMap.set(id.name, list);
        return;
      }
      if (
        !t.isIdentifier(id) ||
        !init ||
        !t.isCallExpression(init) ||
        !t.isMemberExpression(init.callee)
      )
        return;
      if (
        !t.isStringLiteral(init.callee.object) ||
        !t.isIdentifier(init.callee.property, { name: 'split' })
      )
        return;
      if (!init.arguments[0] || !t.isStringLiteral(init.arguments[0])) return;
      splitMap.set(
        id.name,
        (init.callee.object as t.StringLiteral).value.split(
          (init.arguments[0] as t.StringLiteral).value
        )
      );
    },
  });
  let n = 0;
  traverse(ast, {
    WhileStatement(p) {
      const { test, body } = p.node;
      const isInfinite =
        t.isBooleanLiteral(test, { value: true }) || (t.isNumericLiteral(test) && test.value !== 0);
      if (!isInfinite || !t.isBlockStatement(body)) return;
      if (p.parentPath.isLabeledStatement()) return; // jumps may name the loop
      const sw = body.body.find((s) => t.isSwitchStatement(s)) as t.SwitchStatement | undefined;
      if (!sw) return;
      // Besides the switch, the body may hold only hoisted declarations (which
      // keep their block below) and the `break` that ends the loop: any other
      // statement would have run once per iteration.
      const extras = body.body.filter((s) => s !== sw);
      if (
        !extras.every(
          (s) =>
            t.isFunctionDeclaration(s) || (t.isBreakStatement(s) && !s.label) || t.isEmptyStatement(s)
        )
      )
        return;
      const hoisted = extras.filter((s) => t.isFunctionDeclaration(s));
      // A jump nested in a case body targets this loop; flattening would retarget it.
      let jumps = false;
      for (const c of sw.cases)
        for (const st of c.consequent) {
          if (t.isBreakStatement(st) || t.isContinueStatement(st)) continue;
          walk(st, (nd) => {
            if (t.isFunction(nd) || t.isLoop(nd) || t.isSwitchStatement(nd)) return false;
            if (t.isBreakStatement(nd) || t.isContinueStatement(nd)) jumps = true;
          });
        }
      if (jumps) return;
      let order: string[] | null = null;
      if (t.isMemberExpression(sw.discriminant) && t.isIdentifier(sw.discriminant.object))
        order = splitMap.get((sw.discriminant.object as t.Identifier).name) ?? null;
      if (!order && sw.cases.every((c) => c.test && t.isNumericLiteral(c.test))) {
        order = [...sw.cases]
          .filter((c) => c.test)
          .sort((a, b) => (a.test as t.NumericLiteral).value - (b.test as t.NumericLiteral).value)
          .map((c) => String((c.test as t.NumericLiteral).value));
      }
      if (!order) return;
      const caseMap = new Map<string, t.Statement[]>();
      for (const c of sw.cases) {
        if (!c.test) continue;
        const key = t.isStringLiteral(c.test)
          ? c.test.value
          : t.isNumericLiteral(c.test)
            ? String(c.test.value)
            : null;
        if (!key) continue;
        caseMap.set(
          key,
          c.consequent.filter((s) => !t.isBreakStatement(s) && !t.isContinueStatement(s))
        );
      }
      const ordered: t.Statement[] = [];
      for (const k of order) {
        const stmts = caseMap.get(k);
        if (stmts) ordered.push(...stmts);
      }
      if (ordered.length > 0) {
        // Declarations that lived in the loop body keep a block of their own.
        if (hoisted.length) p.replaceWith(t.blockStatement([...hoisted, ...ordered]));
        else p.replaceWithMultiple(ordered);
        n++;
      }
    },
  });
  log.pass('b13', 'cfUnflatten', n);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B13b: State-machine unflattening
//
// Control-flow flattening in its `for`/`switch` form:
//
//   for (var b = 31; true;) {
//     switch (b) {
//       case 8:                       // ← empty fallthrough label
//       case 31: stmtsA; b = 65; continue;
//       case 65:
//       case 8:  stmtsB; b = 55; continue;
//       case 55: stmtsC; break;       // ← no transition: leaves the machine
//     }
//     break;
//   }
//
// When each reachable case assigns the state exactly once and unconditionally,
// the machine is a straight path and the original statement order is recoverable
// by walking it: 31 → 65 → 55 gives `stmtsA; stmtsB; stmtsC;`.
//
// B13 only matched `while (true)` and simply concatenated cases in *numeric*
// order, which is not the execution order — this walks the real transitions.
//
// Deliberately conservative. The rewrite is skipped unless:
//   • the loop is `for (init; ;)` / `for (init; true;)` with a single switch
//   • the discriminant is a local variable initialised to a literal
//   • every case body assigns the state at most once, at the very end, and not
//     inside a nested conditional/loop/function (no branching machines)
//   • the walk terminates without revisiting a state (no loops in the machine)
//   • no case body contains `break` targeting the switch in a way that would
//     resume after the loop, and none declare `var`s that would change scope
// Anything else is left exactly as it was.
// ─────────────────────────────────────────────────────────────────────────────

/** The state assignment `state = <literal>` if it is the statement's whole effect. */
function stateTransitionOf(stmt: t.Statement, stateName: string): number | null {
  if (!t.isExpressionStatement(stmt)) return null;
  const e = stmt.expression;
  if (!t.isAssignmentExpression(e, { operator: '=' })) return null;
  if (!t.isIdentifier(e.left, { name: stateName })) return null;
  const r = evalPure(e.right as t.Expression);
  if (!r.ok || typeof r.value !== 'number') return null;
  return r.value;
}

/** Count assignments to `stateName` anywhere inside `nodes`. */
function countStateAssignments(nodes: t.Node[], stateName: string): number {
  let count = 0;
  for (const node of nodes)
    walkNode(node, (n) => {
      if (t.isAssignmentExpression(n) && t.isIdentifier(n.left, { name: stateName })) count++;
      if (t.isUpdateExpression(n) && t.isIdentifier(n.argument, { name: stateName })) count++;
    });
  return count;
}

/** True if any statement declares a `let`/`const`/class that block scoping would trap. */
function hasBlockScopedDecl(nodes: t.Node[]): boolean {
  let found = false;
  for (const node of nodes)
    walkNode(node, (n) => {
      if (t.isVariableDeclaration(n) && n.kind !== 'var') found = true;
      if (t.isClassDeclaration(n)) found = true;
    });
  return found;
}

/**
 * A trailing `state = test ? <litA> : <litB>` transition, if that is the shape.
 * Returns the test plus both literal successors.
 */
function conditionalTransitionOf(
  stmt: t.Statement,
  stateName: string
): { test: t.Expression; whenTrue: number; whenFalse: number } | null {
  if (!t.isExpressionStatement(stmt)) return null;
  const e = stmt.expression;
  if (!t.isAssignmentExpression(e, { operator: '=' })) return null;
  if (!t.isIdentifier(e.left, { name: stateName })) return null;
  const c = e.right;
  if (!t.isConditionalExpression(c)) return null;
  const a = evalPure(c.consequent as t.Expression);
  const b = evalPure(c.alternate as t.Expression);
  if (!a.ok || !b.ok) return null;
  if (typeof a.value !== 'number' || typeof b.value !== 'number') return null;
  return { test: c.test as t.Expression, whenTrue: a.value, whenFalse: b.value };
}

/**
 * A trailing `if (test) { state = <lit>; continue; } state = <lit>; continue;`
 * — the statement form of the same branch.
 */
function ifTransitionOf(
  stmts: t.Statement[],
  stateName: string
): { test: t.Expression; whenTrue: number; whenFalse: number; consumed: number } | null {
  if (stmts.length < 2) return null;
  const guard = stmts[stmts.length - 2];
  const fallthrough = stmts[stmts.length - 1];
  if (!t.isIfStatement(guard) || guard.alternate) return null;

  const inner = t.isBlockStatement(guard.consequent)
    ? guard.consequent.body.filter((x) => !t.isEmptyStatement(x))
    : [guard.consequent];
  // The guarded branch must be exactly `state = <lit>; continue;`
  if (inner.length !== 2) return null;
  if (!t.isContinueStatement(inner[1]) || inner[1].label) return null;
  const whenTrue = stateTransitionOf(inner[0], stateName);
  if (whenTrue === null) return null;

  const whenFalse = stateTransitionOf(fallthrough, stateName);
  if (whenFalse === null) return null;

  return { test: guard.test, whenTrue, whenFalse, consumed: 2 };
}

/**
 * A trailing `test ? (…, state = <litA>) : (…, state = <litB>)` transition.
 *
 * The obfuscator emits the branch as a bare conditional *expression* whose arms
 * are sequences ending in the state assignment, e.g.
 *
 *   (cond) ? (p.ddResObj.fito = false, o = 2) : (A("18BcfY", cB()), o = 2);
 *
 * Each arm's leading elements are real side effects that must be preserved, so
 * they are returned as statements to emit inside the corresponding branch.
 */
function sequenceTransitionOf(
  stmt: t.Statement,
  stateName: string
): {
  test: t.Expression;
  whenTrue: number;
  whenFalse: number;
  trueEffects: t.Statement[];
  falseEffects: t.Statement[];
} | null {
  if (!t.isExpressionStatement(stmt)) return null;
  const c = stmt.expression;
  if (!t.isConditionalExpression(c)) return null;

  /** Split an arm into (effects, finalStateValue). */
  const armOf = (arm: t.Expression): { effects: t.Statement[]; value: number } | null => {
    const parts = t.isSequenceExpression(arm) ? [...arm.expressions] : [arm];
    const last = parts.pop();
    if (!last) return null;
    if (!t.isAssignmentExpression(last, { operator: '=' })) return null;
    if (!t.isIdentifier(last.left, { name: stateName })) return null;
    const v = evalPure(last.right as t.Expression);
    if (!v.ok || typeof v.value !== 'number') return null;
    // No earlier element may touch the state — that would be a second write.
    for (const part of parts) {
      let touches = false;
      walkNode(part, (nd) => {
        if (t.isAssignmentExpression(nd) && t.isIdentifier(nd.left, { name: stateName }))
          touches = true;
        if (t.isUpdateExpression(nd) && t.isIdentifier(nd.argument, { name: stateName }))
          touches = true;
      });
      if (touches) return null;
    }
    return { effects: parts.map((e) => t.expressionStatement(e as t.Expression)), value: v.value };
  };

  const tArm = armOf(c.consequent as t.Expression);
  const fArm = armOf(c.alternate as t.Expression);
  if (!tArm || !fArm) return null;

  return {
    test: c.test as t.Expression,
    whenTrue: tArm.value,
    whenFalse: fArm.value,
    trueEffects: tArm.effects,
    falseEffects: fArm.effects,
  };
}

function passStateMachineUnflatten(ast: t.File, log: Logger): number {
  let n = 0;

  traverse(ast, {
    ForStatement(p) {
      const { init, test, update, body } = p.node;
      if (update) return;
      const infinite = !test || t.isBooleanLiteral(test, { value: true });
      if (!infinite || !t.isBlockStatement(body)) return;

      // Body must be exactly: [optional var decls], switch, break
      const stmts = body.body.filter((x) => !t.isEmptyStatement(x));
      const swIndex = stmts.findIndex((x) => t.isSwitchStatement(x));
      if (swIndex === -1) return;
      const sw = stmts[swIndex] as t.SwitchStatement;
      // Anything after the switch must be a bare `break` (the machine exit).
      const after = stmts.slice(swIndex + 1);
      if (after.length > 1) return;
      if (after.length === 1 && !(t.isBreakStatement(after[0]) && !after[0].label)) return;

      // Statements before the switch re-run on every iteration, so in general
      // they cannot be hoisted. Bare `var` declarations are the exception the
      // obfuscator actually emits: `var` is function-scoped and hoisted anyway,
      // so re-executing the declaration is a no-op. An initialiser, however,
      // would re-assign each pass — only allow uninitialised declarators.
      const prelude: t.Statement[] = [];
      const preludeRiskyNames: string[] = [];
      for (const pre of stmts.slice(0, swIndex)) {
        if (!t.isVariableDeclaration(pre) || pre.kind !== 'var') return;
        for (const d of pre.declarations) {
          if (!t.isIdentifier(d.id)) return;
          // `var x;` hoists to a no-op and `var x = <literal>;` rewrites the same
          // constant every pass, so both are safe to emit once up front. A
          // non-literal initialiser is only safe if re-running it is unobservable,
          // which we cannot establish here — but the declaration still has to run
          // before the body, so hoist it and forbid the machine from reassigning
          // the name (checked below, once every state body is known).
          if (d.init && !isPurelyLiteral(d.init)) preludeRiskyNames.push(d.id.name);
        }
        prelude.push(pre);
      }

      if (!t.isIdentifier(sw.discriminant)) return;
      const stateName = sw.discriminant.name;

      // The state's literal seed is either the loop's own `init`, or — the shape
      // this obfuscator emits — a `var state = <literal>` immediately preceding
      // the loop. In the latter case that declaration is consumed too, so the
      // seed cannot be observed between the two statements.
      let startRes: { ok: boolean; value: unknown } | null = null;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let seedPath: any = null;
      let keptDecls: t.VariableDeclarator[] = [];

      if (init && t.isExpressionStatement(init as unknown as t.Node)) {
        return; // not a form we model
      } else if (init && !t.isVariableDeclaration(init)) {
        // `for (t = 91; ;)` — the state is seeded by assignment to an outer
        // binding rather than declared here. The assignment is consumed, so the
        // seed value stays unobservable from outside the machine.
        if (!t.isAssignmentExpression(init, { operator: '=' })) return;
        if (!t.isIdentifier(init.left, { name: stateName })) return;
        startRes = evalPure(init.right as t.Expression);
      } else if (init) {
        if (!t.isVariableDeclaration(init)) return;
        // `for (var A, B, v = 73; ;)` — companions must be bare names; they are
        // hoisted anyway, so they survive as a plain declaration in the prelude.
        let seedDecl: t.VariableDeclarator | null = null;
        const companions: t.VariableDeclarator[] = [];
        for (const d of init.declarations) {
          if (!t.isIdentifier(d.id)) return;
          if (d.id.name === stateName) {
            if (!d.init || seedDecl) return;
            seedDecl = d;
          } else {
            // The loop head executes once, so an initialised companion is simply
            // a statement that runs before the machine — hoist it unchanged.
            companions.push(d);
          }
        }
        if (!seedDecl) return;
        if (companions.length > 0)
          prelude.unshift(
            t.variableDeclaration(
              'var',
              companions.map((d) => t.cloneNode(d, true))
            )
          );
        startRes = evalPure(seedDecl.init as t.Expression);
      } else {
        const prev = p.getPrevSibling();
        if (!prev?.node) return;

        // `y = 35; for (; true;) { switch (y) … }` — the state is seeded by a
        // bare assignment to an outer binding just before the loop. Consuming
        // that statement is safe for the same reason as the declaration form:
        // nothing can observe the value between the seed and the switch.
        if (t.isExpressionStatement(prev.node)) {
          const e = prev.node.expression;
          if (!t.isAssignmentExpression(e, { operator: '=' })) return;
          if (!t.isIdentifier(e.left, { name: stateName })) return;
          startRes = evalPure(e.right as t.Expression);
          seedPath = prev;
        } else if (!seedFromDeclaration(prev)) return;
        if (!startRes?.ok || typeof startRes.value !== 'number') return;
      }

      /** Seeds startRes/seedPath/keptDecls from `var … , state = <lit>;`. */
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      function seedFromDeclaration(prev: { node: t.Node } & Record<string, any>): boolean {
        if (!t.isVariableDeclaration(prev.node)) return false;
        const decls: t.VariableDeclarator[] = prev.node.declarations;
        // The seed must be the *last* declarator, so nothing between it and the
        // loop can observe it. Earlier declarators are kept as their own
        // statement rather than dropped.
        const seed = decls[decls.length - 1];
        if (!seed || !t.isIdentifier(seed.id, { name: stateName }) || !seed.init) return false;
        if (decls.some((d) => !t.isIdentifier(d.id))) return false;
        // A companion that also names the state would make the seed ambiguous.
        if (decls.slice(0, -1).some((d) => (d.id as t.Identifier).name === stateName)) return false;
        startRes = evalPure(seed.init as t.Expression);
        seedPath = prev;
        keptDecls = decls.slice(0, -1);
        return true;
      }
      if (!startRes?.ok || typeof startRes.value !== 'number') return;

      // Build state → body. Empty labels fall through to the next non-empty case.
      const bodyFor = new Map<number, t.Statement[]>();
      const labels: Array<{ value: number; index: number }> = [];
      for (let i = 0; i < sw.cases.length; i++) {
        const c = sw.cases[i];
        if (!c.test) return; // a `default` makes the walk ambiguous
        const r = evalPure(c.test as t.Expression);
        if (!r.ok || typeof r.value !== 'number') return;
        labels.push({ value: r.value, index: i });
      }
      // Resolve each state exactly the way `switch` dispatch does: scan the
      // cases in source order and take the FIRST label matching the value, then
      // run from there through any empty fallthrough labels.
      //
      // This obfuscator reuses the same value on several groups as a decoy, so
      // "first match wins" is load-bearing: a later group labelled `case 124:`
      // is unreachable *as 124*, yet the very same group is still reachable via
      // its other label (`case 3:`). Keying bodies by "first occurrence of the
      // value" conflates the two and silently deletes the group's real branch.
      for (let i = 0; i < labels.length; i++) {
        const { value } = labels[i];
        if (bodyFor.has(value)) continue; // already resolved by an earlier label
        // Find the first case group whose label list contains this value.
        const firstIdx = labels.find((l) => l.value === value)?.index;
        if (firstIdx === undefined) continue;
        let collected: t.Statement[] = [];
        for (let j = firstIdx; j < sw.cases.length; j++) {
          const cj = sw.cases[j];
          collected = collected.concat(cj.consequent);
          if (cj.consequent.length > 0) break;
        }
        bodyFor.set(value, collected);
      }

      const startState = startRes.value as number;

      // ── Walk the machine ──────────────────────────────────────────────
      // Straight runs emit in sequence. A conditional transition emits an
      // `if/else`: each side is walked independently until the two paths
      // reconverge, and the shared tail is emitted once after the `if`. States
      // reachable from both sides are found by walking each successor's linear
      // chain and intersecting, so the common suffix is never duplicated.
      const MAX_STATES = 512;
      const reachableTargets = new Set<number>([startState]);
      const visited = new Set<number>();

      type Step =
        | { kind: 'body'; stmts: t.Statement[]; next: number | null }
        | {
            kind: 'branch';
            stmts: t.Statement[];
            test: t.Expression;
            t: number;
            f: number;
            tEffects?: t.Statement[];
            fEffects?: t.Statement[];
          }
        // The state has no matching case: control leaves the switch normally.
        | { kind: 'exit' };

      /** Normalise one state's case body into payload + successor(s). */
      // Returns null only when the body's shape cannot be modelled — callers
      // must abort the whole rewrite in that case rather than stop emitting,
      // otherwise the remainder of the machine is silently deleted.
      const stepOf = (state: number): Step | null => {
        const caseBody = bodyFor.get(state);
        if (caseBody === undefined) return { kind: 'exit' };

        // `case 99: { … }` — obfuscators often wrap the whole body in a block.
        // A bare block introduces no scope for `var`, so when a case is exactly
        // one block we can splice its contents in and analyse them directly.
        // (hasBlockScopedDecl below still rejects let/const/class inside.)
        let caseStmts = caseBody.filter((x) => !t.isEmptyStatement(x));
        while (
          caseStmts.length >= 1 &&
          t.isBlockStatement(caseStmts[0]) &&
          caseStmts.slice(1).every((x) => t.isBreakStatement(x) || t.isContinueStatement(x))
        ) {
          const inner = (caseStmts[0] as t.BlockStatement).body.filter(
            (x) => !t.isEmptyStatement(x)
          );
          caseStmts = [...inner, ...caseStmts.slice(1)];
        }

        const work = caseStmts;
        let tail = work.length;
        let sawContinue = false;
        while (tail > 0) {
          const last = work[tail - 1];
          if (t.isContinueStatement(last) && !last.label) {
            sawContinue = true;
            tail--;
            continue;
          }
          if (t.isBreakStatement(last) && !last.label) {
            tail--;
            continue;
          }
          break;
        }
        const payload = work.slice(0, tail);

        let unsafeJump = false;
        const scanJumps = (node: t.Node, depth: number): void => {
          if (unsafeJump) return;
          const isLoop =
            t.isForStatement(node) ||
            t.isForInStatement(node) ||
            t.isForOfStatement(node) ||
            t.isWhileStatement(node) ||
            t.isDoWhileStatement(node);
          if (
            (t.isBreakStatement(node) || t.isContinueStatement(node)) &&
            !node.label &&
            depth === 0
          ) {
            unsafeJump = true;
            return;
          }
          if (t.isFunction(node)) return;
          const nextDepth = isLoop || t.isSwitchStatement(node) ? depth + 1 : depth;
          const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
          for (const key of keys) {
            const child = (node as unknown as Record<string, unknown>)[key];
            if (Array.isArray(child)) {
              for (const c of child)
                if (c && typeof c === 'object') scanJumps(c as t.Node, nextDepth);
            } else if (child && typeof child === 'object') scanJumps(child as t.Node, nextDepth);
          }
        };

        // A conditional transition owns the trailing `continue` of its own branch,
        // so check for it before the generic jump scan.
        const ifT = ifTransitionOf(payload, stateName);
        if (ifT) {
          const body = payload.slice(0, payload.length - ifT.consumed);
          for (const stmt of body) scanJumps(stmt, 0);
          if (unsafeJump || hasBlockScopedDecl(body)) return null;
          if (countStateAssignments(body, stateName) > 0) return null;
          return { kind: 'branch', stmts: body, test: ifT.test, t: ifT.whenTrue, f: ifT.whenFalse };
        }

        for (const stmt of payload) scanJumps(stmt, 0);
        if (unsafeJump || hasBlockScopedDecl(payload)) return null;

        const lastStmt = payload[payload.length - 1];

        const seqT = lastStmt ? sequenceTransitionOf(lastStmt, stateName) : null;
        if (seqT) {
          const body = payload.slice(0, payload.length - 1);
          if (countStateAssignments(body, stateName) > 0) return null;
          if (!sawContinue) return null;
          return {
            kind: 'branch',
            stmts: body,
            test: seqT.test,
            t: seqT.whenTrue,
            f: seqT.whenFalse,
            tEffects: seqT.trueEffects,
            fEffects: seqT.falseEffects,
          };
        }

        const condT = lastStmt ? conditionalTransitionOf(lastStmt, stateName) : null;
        if (condT) {
          const body = payload.slice(0, payload.length - 1);
          if (countStateAssignments(body, stateName) > 0) return null;
          if (!sawContinue) return null;
          return {
            kind: 'branch',
            stmts: body,
            test: condT.test,
            t: condT.whenTrue,
            f: condT.whenFalse,
          };
        }

        const assigns = countStateAssignments(payload, stateName);
        if (assigns > 1) return null;
        if (assigns === 1) {
          const plain = lastStmt ? stateTransitionOf(lastStmt, stateName) : null;
          if (plain === null) return null;
          if (!sawContinue) return null;
          return { kind: 'body', stmts: payload.slice(0, -1), next: plain };
        }
        return { kind: 'body', stmts: payload, next: null };
      };

      /** Linear successor chain from `state`, stopping at a branch or the end. */
      const chainFrom = (state: number): number[] => {
        const out: number[] = [];
        const guard = new Set<number>();
        let cur: number | null = state;
        while (cur !== null && !guard.has(cur)) {
          guard.add(cur);
          out.push(cur);
          const st = stepOf(cur);
          if (!st || st.kind !== 'body') break;
          cur = st.next;
        }
        return out;
      };

      let bailed = false;

      /** Emit states from `state` until `stopAt` (exclusive) is reached. */
      const emit = (state: number | null, stopAt: Set<number>): t.Statement[] => {
        const out: t.Statement[] = [];
        let cur = state;
        while (cur !== null && !bailed) {
          if (stopAt.has(cur)) break;
          if (visited.has(cur)) {
            bailed = true; // a state reachable twice would be duplicated
            return out;
          }
          visited.add(cur);
          reachableTargets.add(cur);
          if (visited.size > MAX_STATES) {
            bailed = true;
            return out;
          }

          const st = stepOf(cur);
          if (!st) {
            // Unmodellable body — abandon the rewrite entirely.
            bailed = true;
            return out;
          }
          if (st.kind === 'exit') break;

          out.push(...st.stmts);
          if (st.kind === 'body') {
            if (st.next === null) break;
            cur = st.next;
            continue;
          }

          // Branch: find where the two successors reconverge.
          reachableTargets.add(st.t);
          reachableTargets.add(st.f);
          const tChain = chainFrom(st.t);
          const fChain = chainFrom(st.f);
          const fSet = new Set(fChain);
          const join = tChain.find((x) => fSet.has(x));

          // Everything each branch executes before the join must be disjoint,
          // otherwise a shared state would be emitted inside only one arm and
          // silently dropped from the other.
          const tPre = join === undefined ? tChain : tChain.slice(0, tChain.indexOf(join));
          const fPre = join === undefined ? fChain : fChain.slice(0, fChain.indexOf(join));
          if (tPre.some((x) => fPre.includes(x))) {
            bailed = true;
            return out;
          }
          // A branch arm containing a nested branch may reach states outside its
          // linear chain; only accept arms we can fully account for here.
          for (const arm of [tPre, fPre])
            for (const stateId of arm) {
              if (!stepOf(stateId)) {
                bailed = true;
                return out;
              }
            }

          const stop = new Set(stopAt);
          if (join !== undefined) stop.add(join);

          const consequent = [...(st.tEffects ?? []), ...emit(st.t, stop)];
          const alternate = [...(st.fEffects ?? []), ...emit(st.f, stop)];
          if (bailed) return out;

          out.push(
            t.ifStatement(
              st.test,
              t.blockStatement(consequent),
              alternate.length > 0 ? t.blockStatement(alternate) : null
            )
          );
          // Continue with the shared tail, if any.
          cur = join !== undefined && !stopAt.has(join) ? join : null;
        }
        return out;
      };

      const ordered = emit(startState, new Set<number>());
      if (bailed) return;
      // A hoisted non-literal initialiser must not be re-assigned by the machine,
      // or the single hoisted evaluation would no longer match the original.
      if (preludeRiskyNames.length > 0) {
        let clobbered = false;
        for (const stmt of ordered)
          walkNode(stmt, (nd) => {
            if (
              t.isAssignmentExpression(nd) &&
              t.isIdentifier(nd.left) &&
              preludeRiskyNames.includes(nd.left.name)
            )
              clobbered = true;
            if (
              t.isUpdateExpression(nd) &&
              t.isIdentifier(nd.argument) &&
              preludeRiskyNames.includes(nd.argument.name)
            )
              clobbered = true;
          });
        if (clobbered) return;
      }
      const seen = visited;

      if (ordered.length === 0) return;
      // Unvisited labels are expected — the obfuscator emits decoy `case` values
      // that no transition ever targets. Dropping them is safe precisely because
      // nothing reaches them: the start state is a literal and every transition
      // is a literal, so the visited set is the complete reachable set. Guard
      // only against discarding a body that some transition *did* name.
      for (const [stateValue] of bodyFor)
        if (!seen.has(stateValue) && reachableTargets.has(stateValue)) return;

      try {
        const head: t.Statement[] =
          keptDecls.length > 0
            ? [
                t.variableDeclaration(
                  'var',
                  keptDecls.map((d) => t.cloneNode(d, true))
                ),
              ]
            : [];
        p.replaceWithMultiple([...head, ...prelude, ...ordered]);
        if (seedPath) {
          try {
            seedPath.remove();
          } catch {
            /**/
          }
        }
        n++;
      } catch {
        /**/
      }
    },
  });

  log.pass('b13b', 'stateMachine', n);
  return n;
}

function passSelfDefending(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    DebuggerStatement(p) {
      p.remove();
      n++;
    },
    CallExpression(p) {
      const callee = p.node.callee;
      if (t.isCallExpression(callee) || t.isNewExpression(callee)) {
        if (t.isIdentifier(callee.callee, { name: 'Function' })) {
          const arg0 = callee.arguments[0];
          if (t.isStringLiteral(arg0) && arg0.value.trim() === 'debugger') {
            if (p.parentPath?.isExpressionStatement()) {
              p.parentPath.remove();
              n++;
            }
          }
        }
      }
    },
    ExpressionStatement(p) {
      const expr = p.node.expression;
      if (!t.isCallExpression(expr) || !t.isIdentifier(expr.callee)) return;
      if (!['setInterval', 'setTimeout'].includes((expr.callee as t.Identifier).name)) return;
      const fn = expr.arguments[0];
      if (!fn || (!t.isFunctionExpression(fn) && !t.isArrowFunctionExpression(fn))) return;
      const body = t.isBlockStatement(fn.body) ? fn.body.body : [];
      if (body.some((s) => t.isDebuggerStatement(s))) {
        p.remove();
        n++;
      }
    },
  });
  n += removeCallControllerWrappers(ast);
  log.pass('b14', 'selfDefending', n);
  return n;
}

/** Methods a self-defending probe may call on its own source text. */
const SELF_INSPECTION_METHODS = new Set([
  'toString',
  'valueOf',
  'constructor',
  'search',
  'match',
  'test',
  'exec',
  'replace',
  'indexOf',
  'lastIndexOf',
  'includes',
  'startsWith',
  'endsWith',
  'slice',
  'substr',
  'substring',
  'charAt',
  'charCodeAt',
  'split',
  'join',
  'concat',
  'trim',
  'length',
  'source',
]);

/**
 * An expression that only inspects `self` (the function it lives in): literal
 * leaves, `self` itself, string/regexp introspection on those, and `+`.
 * Nothing in it can run user code, so a value computed from it and thrown
 * away is dead — unless it hangs, which is the point of the construct.
 */
function isSelfInspection(node: t.Node, self: string, depth = 0): boolean {
  if (depth > 40) return false;
  if (t.isIdentifier(node)) return node.name === self;
  if (
    t.isStringLiteral(node) ||
    t.isNumericLiteral(node) ||
    t.isRegExpLiteral(node) ||
    t.isBooleanLiteral(node)
  )
    return true;
  if (t.isMemberExpression(node)) {
    const prop = node.computed
      ? t.isStringLiteral(node.property)
        ? node.property.value
        : null
      : t.isIdentifier(node.property)
        ? node.property.name
        : null;
    if (prop === null || !SELF_INSPECTION_METHODS.has(prop)) return false;
    return isSelfInspection(node.object, self, depth + 1);
  }
  if (t.isCallExpression(node)) {
    if (!t.isMemberExpression(node.callee)) return false;
    return (
      isSelfInspection(node.callee, self, depth + 1) &&
      node.arguments.every((a) => t.isExpression(a) && isSelfInspection(a, self, depth + 1))
    );
  }
  if (t.isBinaryExpression(node, { operator: '+' }))
    return (
      t.isExpression(node.left) &&
      isSelfInspection(node.left, self, depth + 1) &&
      isSelfInspection(node.right, self, depth + 1)
    );
  return false;
}

/**
 * javascript-obfuscator's `selfDefending` option emits a *call controller* —
 * an IIFE returning a run-once wrapper — and a probe that inspects its own
 * source with a catastrophic regexp, then invokes it:
 *
 *   const C = function () { let once = true; return function (ctx, fn) { … } }();
 *   const X = C(this, function () {
 *     return X.toString().search("(((.+)+)+)+$").toString().constructor(X).search("(((.+)+)+)+$");
 *   });
 *   X();
 *
 * The probe's result is discarded; its only effect is to hang once the code
 * is reformatted. When the controller is closed (no free references, no
 * globals, no `this`) calling `X` can do nothing but run the inert probe, so
 * the `X()` statements, `X` and an otherwise unused controller are removed.
 */
function removeCallControllerWrappers(ast: t.File): number {
  if (hasDynamicScope(ast.program)) return 0;
  const program = freshProgram(ast);
  let n = 0;
  const pending: Array<() => void> = [];
  const freedControllers = new Map<Binding, number>();

  program.traverse({
    VariableDeclarator(p) {
      const id = p.node.id;
      const init = p.node.init;
      if (!t.isIdentifier(id) || !t.isCallExpression(init) || !t.isIdentifier(init.callee)) return;
      if (init.arguments.length !== 2 || !isInert(init.arguments[0])) return;
      const probe = init.arguments[1];
      if (!t.isFunctionExpression(probe) && !t.isArrowFunctionExpression(probe)) return;
      if (probe.params.length > 0 || probe.async || probe.generator) return;
      const body = t.isBlockStatement(probe.body)
        ? probe.body.body.filter((st) => !t.isEmptyStatement(st))
        : null;
      const returned = body
        ? body.length === 1 && t.isReturnStatement(body[0]) && body[0].argument
          ? body[0].argument
          : null
        : probe.body;
      if (!returned || !isSelfInspection(returned, id.name)) return;
      if (!walkFinds(returned, (x) => t.isIdentifier(x, { name: id.name }))) return;

      const self = p.scope.getBinding(id.name);
      if (!self || self.path.node !== p.node || self.constantViolations.length > 0) return;
      const controller = p.scope.getBinding(init.callee.name);
      if (
        !controller ||
        !controller.path.isVariableDeclarator() ||
        controller.constantViolations.length > 0
      )
        return;
      const cInit = controller.path.get('init');
      if (!cInit.isCallExpression() || cInit.node.arguments.length > 0) return;
      const cFn = cInit.get('callee');
      if (!cFn.isFunctionExpression() && !cFn.isArrowFunctionExpression()) return;
      const refs = freeReferences(cFn);
      if (refs.usesThis || refs.reads.size || refs.writes.size || refs.mutates.size) return;
      // `arguments` inside a function expression is bound by it (or a nested
      // function), never free; an arrow would reach for the enclosing one.
      const ownArguments = cFn.isFunctionExpression();
      if (
        [...refs.globals].some(
          (g) => !SLICE_SAFE_GLOBALS.has(g) && !(ownArguments && g === 'arguments')
        )
      )
        return;

      // Every use of X: the probe's self-reference, or a bare `X();` statement.
      const calls: NodePath[] = [];
      for (const r of self.referencePaths) {
        if (pathWithin(r, probe)) continue;
        const call = r.parentPath;
        const stmt = call?.parentPath;
        if (
          !call?.isCallExpression() ||
          call.node.callee !== r.node ||
          !call.node.arguments.every((a) => isInert(a)) ||
          !stmt?.isExpressionStatement()
        )
          return;
        calls.push(stmt);
      }
      pending.push(() => {
        for (const c of calls) c.remove();
        p.remove();
        n += calls.length + 1;
      });
      freedControllers.set(controller, (freedControllers.get(controller) ?? 0) + 1);
    },
  });
  for (const f of pending) {
    try {
      f();
    } catch {
      /**/
    }
  }
  for (const [controller, freed] of freedControllers) {
    if (controller.referencePaths.length !== freed) continue;
    try {
      controller.path.remove();
      n++;
    } catch {
      /**/
    }
  }
  return n;
}

function walkFinds(root: t.Node, pred: (n: t.Node) => boolean): boolean {
  let found = false;
  walk(root, (x) => {
    if (found) return false;
    if (pred(x)) found = true;
    return !found;
  });
  return found;
}

function passCommaSequence(ast: t.File, log: Logger): number {
  let n = 0;
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  program.traverse({
    ExpressionStatement(p) {
      if (!t.isSequenceExpression(p.node.expression)) return;
      p.replaceWithMultiple(p.node.expression.expressions.map((e) => t.expressionStatement(e)));
      n++;
    },
    // `(0, f)(…)` → `f(…)`: calling a plain variable binds `this` to undefined
    // either way. Not for `eval` (the sequence makes it an indirect eval) nor
    // where a `with` could resolve `f` to a property (and bind `this` to it).
    CallExpression(p) {
      const c = p.node.callee;
      if (!t.isSequenceExpression(c) || c.expressions.length < 2) return;
      const last = c.expressions[c.expressions.length - 1];
      if (!t.isIdentifier(last) || last.name === 'eval') return;
      const lead = c.expressions.slice(0, -1);
      if (!lead.every((e) => t.isNumericLiteral(e) || t.isStringLiteral(e) || t.isBooleanLiteral(e) || t.isNullLiteral(e))) return;
      if (dyn.contains(p) || !dyn.empty) return;
      p.node.callee = last;
      n++;
    },
  });
  log.pass('b15', 'commaSeq', n);
  return n;
}

function passTypeofSimplify(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    BinaryExpression: {
      exit(p) {
        const { left, right, operator } = p.node;
        if (!['===', '!==', '==', '!='].includes(operator)) return;
        if (!t.isUnaryExpression(left, { operator: 'typeof' }) || !t.isStringLiteral(right)) return;
        const arg = left.argument;
        const kt = t.isStringLiteral(arg)
          ? 'string'
          : t.isNumericLiteral(arg)
            ? 'number'
            : t.isBooleanLiteral(arg)
              ? 'boolean'
              : t.isNullLiteral(arg)
                ? 'object'
                : t.isIdentifier(arg, { name: 'undefined' })
                  ? 'undefined'
                  : t.isArrowFunctionExpression(arg) || t.isFunctionExpression(arg)
                    ? 'function'
                    : null;
        if (!kt) return;
        p.replaceWith(
          t.booleanLiteral(
            operator === '===' || operator === '==' ? right.value === kt : right.value !== kt
          )
        );
        n++;
      },
    },
  });
  log.pass('b16', 'typeof', n);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// B17b: Dead function elimination
//
// Passes that inline call sites (B01c pureNumericFns, B05b poolDecoder, B09
// proxyFunctions) leave the *declaration* behind whenever they cannot prove the
// binding is now unused. On this corpus that means ~90 leftover bitwise-identity
// helpers whose only remaining reference is their own name. B17 only prunes
// variables with literal initialisers, so nothing collects them.
//
// Removes function declarations and function-valued `var`s that have zero
// referencing uses. Safety: skip exported//recursive-only bindings is handled by
// counting references excluding the declaration itself, and any function whose
// body references itself keeps a self-reference and so is retained unless that
// self-reference is its only one (a pure self-recursive dead function).
// ─────────────────────────────────────────────────────────────────────────────

function passDeadFunctions(ast: t.File, log: Logger): number {
  // Two phases per round, both over a *fresh* traversal:
  //   1. collect candidate functions and count references from outside each one
  //   2. mark the dead ones by node identity, then delete in one more traversal
  //
  // Removal is done by matching node identity during a new traversal rather than
  // by holding onto NodePaths from phase 1: Babel invalidates and requeues paths
  // as siblings are removed, and reusing a stale path here made the pass spin
  // without ever reaching a fixed point.
  let removed = 0;

  for (let round = 0; round < 4; round++) {
    const owners = new Map<t.Node, string>(); // function node → bound name
    const declOf = new Map<string, t.Node>(); // name → node to delete

    traverse(ast, {
      FunctionDeclaration(p) {
        const id = p.node.id;
        if (!id || p.parentPath?.isExportDeclaration()) return;
        owners.set(p.node, id.name);
        declOf.set(id.name, p.node);
      },
      VariableDeclarator(p) {
        const { id, init } = p.node;
        if (!t.isIdentifier(id) || !init) return;
        if (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) return;
        owners.set(init, id.name);
        declOf.set(id.name, p.node);
      },
    });
    if (declOf.size === 0) break;

    // Count references originating outside the function's own body. The
    // enclosing-owner stack keeps this linear.
    const external = new Map<string, number>();
    for (const name of declOf.keys()) external.set(name, 0);

    const stack: string[] = [];
    traverse(ast, {
      enter(p) {
        const owned = owners.get(p.node);
        if (owned !== undefined) stack.push(owned);
        if (!p.isIdentifier()) return;
        const name = p.node.name;
        if (!external.has(name)) return;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (!(p as any).isReferencedIdentifier()) return;
        if (stack.includes(name)) return; // self-reference only
        external.set(name, (external.get(name) ?? 0) + 1);
      },
      exit(p) {
        if (owners.has(p.node)) stack.pop();
      },
    });

    const doomed = new Set<t.Node>();
    for (const [name, node] of declOf) if ((external.get(name) ?? 1) === 0) doomed.add(node);
    if (doomed.size === 0) break;

    let roundRemoved = 0;
    traverse(ast, {
      FunctionDeclaration(p) {
        if (!doomed.has(p.node)) return;
        try {
          p.remove();
          roundRemoved++;
        } catch {
          /**/
        }
      },
      VariableDeclarator(p) {
        if (!doomed.has(p.node)) return;
        try {
          const decl = p.parent as t.VariableDeclaration;
          if (decl.declarations.length === 1) p.parentPath?.remove();
          else p.remove();
          roundRemoved++;
        } catch {
          /**/
        }
      },
    });

    removed += roundRemoved;
    if (roundRemoved === 0) break;
  }

  log.pass('b17b', 'deadFunctions', removed);
  return removed;
}

// ─────────────────────────────────────────────────────────────────────────────
// B16b: Boolean expression simplification
//
// Cleans up the residue that folding leaves behind:
//   cond ? true : false  →  !!cond      (or `cond` when already boolean)
//   cond ? false : true  →  !cond
//   !!boolean            →  boolean
// ─────────────────────────────────────────────────────────────────────────────

/** True when the expression is guaranteed to evaluate to a boolean. */
function isBooleanValued(node: t.Node): boolean {
  if (t.isBooleanLiteral(node)) return true;
  if (t.isUnaryExpression(node, { operator: '!' })) return true;
  if (t.isBinaryExpression(node))
    return ['==', '!=', '===', '!==', '<', '<=', '>', '>=', 'in', 'instanceof'].includes(
      node.operator
    );
  if (t.isLogicalExpression(node) && node.operator !== '??')
    return isBooleanValued(node.left) && isBooleanValued(node.right);
  return false;
}

function passBooleanSimplify(ast: t.File, log: Logger): number {
  let n = 0;
  traverse(ast, {
    ConditionalExpression: {
      exit(p) {
        const { test, consequent, alternate } = p.node;
        const isTrue = t.isBooleanLiteral(consequent, { value: true });
        const isFalse = t.isBooleanLiteral(consequent, { value: false });
        const altTrue = t.isBooleanLiteral(alternate, { value: true });
        const altFalse = t.isBooleanLiteral(alternate, { value: false });

        if (isTrue && altFalse) {
          // `cond ? true : false` — keep the coercion unless cond is already boolean.
          p.replaceWith(
            isBooleanValued(test) ? test : t.unaryExpression('!', t.unaryExpression('!', test))
          );
          n++;
        } else if (isFalse && altTrue) {
          p.replaceWith(t.unaryExpression('!', test));
          n++;
        }
      },
    },
    UnaryExpression: {
      exit(p) {
        // `!!x` where x is already boolean → x
        if (p.node.operator !== '!') return;
        const inner = p.node.argument;
        if (!t.isUnaryExpression(inner, { operator: '!' })) return;
        if (!isBooleanValued(inner.argument)) return;
        p.replaceWith(inner.argument);
        n++;
      },
    },
  });
  log.pass('b16b', 'booleanSimplify', n);
  return n;
}

function passUnusedVars(ast: t.File, log: Logger): number {
  const readCount = new Map<string, number>();
  const declared = new Set<string>();
  // This pass counts by name rather than by binding, so one declaration a
  // direct `eval` can see blocks every declaration that shares its name.
  const observedNames = new Set<string>();
  const dyn = dynamicScopes(freshProgram(ast));
  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const name = p.node.id.name;
      declared.add(name);
      if (!readCount.has(name)) readCount.set(name, 0);
      const binding = p.scope.getBinding(name);
      if (binding && dyn.observesBinding(binding)) observedNames.add(name);
    },
  });
  traverse(ast, {
    Identifier(p) {
      const name = p.node.name;
      if (!declared.has(name)) return;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ((p as any).isReferencedIdentifier()) readCount.set(name, (readCount.get(name) ?? 0) + 1);
      // A write (`i++`, `i += 1`, `i = …`) still needs the declaration, or it
      // would throw (strict) / create a global (sloppy) once the `var` is gone.
      else if (
        (p.parentPath.isUpdateExpression() && p.key === 'argument') ||
        (p.parentPath.isAssignmentExpression() && p.key === 'left') ||
        (p.parentPath.isForXStatement() && p.key === 'left')
      )
        readCount.set(name, (readCount.get(name) ?? 0) + 1);
    },
  });
  let n = 0;
  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const name = p.node.id.name;
      if (observedNames.has(name)) return;
      if ((readCount.get(name) ?? 1) > 0) return;
      // Literals, and arrays / objects built only of literals (an emptied
      // duplicate-literal table), cost nothing to construct and have no effect;
      // neither does reading the global object by its own unshadowed name.
      const init = p.node.init;
      const globalRef = t.isIdentifier(init) && GLOBAL_OBJECT_NAMES.has(init.name) && !p.scope.getBinding(init.name);
      // a table may hold `undefined` (duplicateLiteralsRemoval keeps it as a slot)
      const inertTable =
        t.isArrayExpression(init) &&
        init.elements.every((e) => !!e && (isCopyableLiteral(e) || t.isIdentifier(e, { name: 'undefined' })));
      if (!init || !(isPurelyLiteral(init) || isDataLiteral(init) || inertTable || globalRef)) return;
      const parent = p.parent as t.VariableDeclaration;
      try {
        if (parent.declarations.length === 1) p.parentPath?.remove();
        else p.remove();
        n++;
      } catch {
        /**/
      }
    },
  });
  log.pass('b17', 'unusedVars', n);
  return n;
}

/**
 * B18: Duplicate `var` declaration resolver
 *
 * Browsers silently allow `var x` to be declared multiple times in the same scope.
 * Babel's scope APIs and strict-mode environments (VM sandbox, TypeScript, bundlers)
 * do NOT — they throw "Identifier 'x' has already been declared".
 *
 * This pass normalises `var` re-declarations within each scope:
 *   var x = 1; … var x = 2;   →  var x = 1; … x = 2;   (2nd+ → assignment)
 *   var x = 1; … var x;       →  var x = 1;              (bare re-decl → removed)
 *
 * Only `var` is affected. `let`/`const` redeclarations are a real syntax error
 * and are deliberately left untouched. Destructuring patterns are skipped.
 *
 * Implementation note: we mutate statement arrays directly rather than using
 * Babel path APIs (which crash on duplicate bindings).
 */
function passDeduplicateVarDecls(ast: t.File, log: Logger): number {
  let n = 0;

  function processScope(stmts: t.Statement[]): void {
    const firstSeen = new Set<string>();

    for (let i = 0; i < stmts.length; i++) {
      const stmt = stmts[i];
      if (!t.isVariableDeclaration(stmt) || stmt.kind !== 'var') continue;

      const keepDeclarators: t.VariableDeclarator[] = [];
      const extraAssignments: t.Statement[] = [];

      for (const decl of stmt.declarations) {
        if (!t.isIdentifier(decl.id)) {
          keepDeclarators.push(decl);
          continue;
        }
        const name = decl.id.name;
        if (firstSeen.has(name)) {
          // Duplicate — convert or drop
          if (decl.init) {
            extraAssignments.push(
              t.expressionStatement(t.assignmentExpression('=', t.identifier(name), decl.init))
            );
          }
          // else: bare `var x;` re-declaration — just drop it
          n++;
        } else {
          firstSeen.add(name);
          keepDeclarators.push(decl);
        }
      }

      // Rebuild the var declaration without duplicates
      stmt.declarations.length = 0;
      stmt.declarations.push(...keepDeclarators);

      // The declaration keeps its place with the surviving declarators and
      // the assignments follow it; one left with no declarator is replaced by
      // its assignments outright (removing it *after* inserting and skipping
      // them would remove the last assignment instead).
      if (stmt.declarations.length === 0) {
        stmts.splice(i, 1, ...extraAssignments);
        i += extraAssignments.length - 1;
      } else if (extraAssignments.length > 0) {
        stmts.splice(i + 1, 0, ...extraAssignments);
        i += extraAssignments.length; // skip over newly inserted statements
      }
    }
  }

  // Process program-level
  processScope(ast.program.body);

  // Process every function body (var is function-scoped, not block-scoped)
  traverse(ast, {
    Function(p) {
      const body = p.node.body;
      if (t.isBlockStatement(body)) processScope(body.body);
    },
  });

  log.pass('b18', 'dedupVars', n);
  return n;
}

/**
 * B19: Mangled identifier rename — _0xABCD / $ABCDE → v_0, v_1, …
 * Binding-aware: skips static property names and object property keys.
 * Also handles destructuring patterns (ObjectPattern, ArrayPattern).
 */
function passRenameMangled(ast: t.File, log: Logger): number {
  const MANGLE = /^_0x[0-9a-fA-F]+$|^\$[0-9a-fA-F]{4,}$/;
  const bindings = new Set<string>();

  traverse(ast, {
    VariableDeclarator(p) {
      if (t.isIdentifier(p.node.id) && MANGLE.test(p.node.id.name)) bindings.add(p.node.id.name);
      if (t.isObjectPattern(p.node.id))
        for (const prop of (p.node.id as t.ObjectPattern).properties) {
          if (
            t.isObjectProperty(prop) &&
            t.isIdentifier(prop.value) &&
            MANGLE.test((prop.value as t.Identifier).name)
          )
            bindings.add((prop.value as t.Identifier).name);
          if (
            t.isRestElement(prop) &&
            t.isIdentifier(prop.argument) &&
            MANGLE.test((prop.argument as t.Identifier).name)
          )
            bindings.add((prop.argument as t.Identifier).name);
        }
      if (t.isArrayPattern(p.node.id))
        for (const el of (p.node.id as t.ArrayPattern).elements) {
          if (el && t.isIdentifier(el) && MANGLE.test(el.name)) bindings.add(el.name);
          if (
            el &&
            t.isRestElement(el) &&
            t.isIdentifier(el.argument) &&
            MANGLE.test((el.argument as t.Identifier).name)
          )
            bindings.add((el.argument as t.Identifier).name);
        }
    },
    FunctionDeclaration(p) {
      if (p.node.id && MANGLE.test(p.node.id.name)) bindings.add(p.node.id.name);
    },
    FunctionExpression(p) {
      if (p.node.id && MANGLE.test(p.node.id.name)) bindings.add(p.node.id.name);
    },
    ClassDeclaration(p) {
      if (p.node.id && MANGLE.test(p.node.id.name)) bindings.add(p.node.id.name);
    },
    Function(p) {
      for (const param of p.node.params) {
        if (t.isIdentifier(param) && MANGLE.test((param as t.Identifier).name))
          bindings.add((param as t.Identifier).name);
        if (
          t.isAssignmentPattern(param) &&
          t.isIdentifier(param.left) &&
          MANGLE.test((param.left as t.Identifier).name)
        )
          bindings.add((param.left as t.Identifier).name);
        if (
          t.isRestElement(param) &&
          t.isIdentifier(param.argument) &&
          MANGLE.test((param.argument as t.Identifier).name)
        )
          bindings.add((param.argument as t.Identifier).name);
      }
    },
  });

  if (bindings.size === 0) {
    log.pass('b19', 'rename', 0);
    return 0;
  }
  let idx = 0;
  const nm = new Map<string, string>();
  for (const s of bindings) nm.set(s, `v_${idx++}`);

  let n = 0;
  traverse(ast, {
    Identifier(p) {
      if (
        p.parentPath?.isMemberExpression() &&
        p.key === 'property' &&
        !(p.parentPath.node as t.MemberExpression).computed
      )
        return;
      if (
        p.parentPath?.isObjectProperty() &&
        p.key === 'key' &&
        !(p.parentPath.node as t.ObjectProperty).computed
      )
        return;
      if (p.parentPath?.isObjectProperty() && p.key === 'key') return;
      const mapped = nm.get(p.node.name);
      if (mapped) {
        p.node.name = mapped;
        n++;
      }
    },
  });
  log.pass('b19', 'rename', bindings.size, 'bindings', `${n} refs`);
  return n;
}

function passCleanup(ast: t.File): void {
  traverse(ast, {
    EmptyStatement(p) {
      p.remove();
    },
    ReturnStatement(p) {
      if (p.node.argument && t.isIdentifier(p.node.argument, { name: 'undefined' }))
        p.node.argument = null;
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Binding-aware structural passes
//
// The passes above recognise obfuscator machinery by its *syntax*: an alias is
// `var a = decoder`, a string table is `var arr = [...]`, a dispatch object is a
// `VariableDeclarator`, a flattened order is `var o = "1|0".split("|")` feeding a
// `while (true)`. An obfuscator that hoists every local into the parameter list
//
//   d.NIEP3 = function (L, K, U, i, uW, uz, ur, mW, o, C, x, P, …) {
//     if ((uW = {L: 602, n: 481, …}), (mW = mM), (o = {Ftsnr: function (a, b) {…}}),
//         K === null || o[mW(uW.L)](K, undefined)) return i;
//
// carries exactly the same facts — `mW` only ever holds the decoder, `uW` is a
// frozen index table, `o` is a proxy table — but in a shape none of those
// matchers accept, so the whole pipeline makes zero progress.
//
// The passes below work from binding facts instead (see ./analysis):
//
//   B00b statementNormalize  — hoist sequences out of statement heads, unwrap
//                              `~function(){}()`, fold `x = {}; x.k = v` into the
//                              literal, move loop work out of `for (…;…; a, b) {}`
//   B00c paramLocals         — parameters whose incoming value is never observed
//                              become `var`s (and IIFE params beyond the args)
//   B08b bindingPropagation  — write-once aliases / literals → their value
//   B07c objectTables        — frozen, non-escaping object literals: inline
//                              literal props and expression-bodied methods
//   B05c closedFunctionEval  — evaluate self-contained function groups (string
//                              table + rotation + decoder) in the VM and fold
//                              every literal-argument call
//   B04b bitwiseLiterals     — `x >>> 6.74` → `x >>> 6` (ToInt32 noise)
//   B13c switchDispatcher    — `for (o = [...], i = 0;;) switch (o[i++]) {…}`
//   B15b conditionalStmts    — statement-level `a ? b : c` / `a && b` → if
//   B17c deadStores          — writes to bindings that are never read
// ─────────────────────────────────────────────────────────────────────────────

/** Methods that mutate their receiver (arrays, typed arrays, maps, sets). */
const MUTATING_METHOD_NAMES = new Set([
  'push',
  'pop',
  'shift',
  'unshift',
  'splice',
  'sort',
  'reverse',
  'fill',
  'copyWithin',
  'set',
  'add',
  'delete',
  'clear',
]);

/** Static property name of `obj.k` / `obj["k"]` / `obj[0]`, else null. */
function staticMemberKey(m: t.MemberExpression | t.OptionalMemberExpression): string | null {
  if (!m.computed) return t.isIdentifier(m.property) ? m.property.name : null;
  if (t.isStringLiteral(m.property)) return m.property.value;
  if (t.isNumericLiteral(m.property)) return String(m.property.value);
  return null;
}

/** Static key of an object-literal member, else null. */
function staticPropKey(prop: t.ObjectProperty | t.ObjectMethod): string | null {
  const k = prop.key;
  if (!prop.computed && t.isIdentifier(k)) return k.name;
  if (t.isStringLiteral(k)) return k.value;
  if (t.isNumericLiteral(k)) return String(k.value);
  return null;
}

/** A literal that can be copied to a use site verbatim. */
function isCopyableLiteral(node: t.Node): boolean {
  return (
    t.isStringLiteral(node) ||
    t.isNumericLiteral(node) ||
    t.isBooleanLiteral(node) ||
    t.isNullLiteral(node) ||
    (t.isUnaryExpression(node, { operator: '-' }) && t.isNumericLiteral(node.argument)) ||
    (t.isUnaryExpression(node, { operator: 'void' }) && t.isNumericLiteral(node.argument)) ||
    (t.isTemplateLiteral(node) && node.expressions.length === 0)
  );
}

/**
 * Can the sandbox's copy of this function stand in for the original? A sandbox
 * runs *regenerated*, compact code, whose functions print differently from the
 * original's. That is invisible when every reference only calls the function.
 * Otherwise its text may be read — and the self-checks obfuscators build on
 * it (javascript-obfuscator's selfDefending, js-confuser's anti-beautify) ask
 * one thing of it: whether it contains a newline. The compact copy has none,
 * so it answers like the original exactly when the original text had none
 * either (sourceFacts.newlineFree).
 */
function sandboxSafe(b: Binding): boolean {
  return (getSourceFacts()?.newlineFree ?? false) || onlyCalled(b);
}

/**
 * Every use of the binding's value is a call (see sandboxSafe) — directly, or
 * after passing through an IIFE parameter or a `const X = f` alias that is
 * itself only called (javascript-obfuscator hands its array function to the
 * rotation IIFE that way).
 */
function onlyCalled(b: Binding, depth = 0): boolean {
  if (depth > 4) return false;
  return b.referencePaths.every((r) => {
    const c = r.parentPath;
    if (!c) return false;
    if ((c.isCallExpression() || c.isNewExpression()) && c.node.callee === r.node) return true;
    // `(function (g) { … g() … })(f)`
    if (c.isCallExpression() && (t.isFunctionExpression(c.node.callee) || t.isArrowFunctionExpression(c.node.callee))) {
      const i = c.node.arguments.indexOf(r.node as t.Expression);
      const param = i >= 0 ? c.node.callee.params[i] : null;
      if (!t.isIdentifier(param)) return false;
      if (t.isFunctionExpression(c.node.callee) && usesArguments(c.node.callee)) return false;
      const pb = (c.get('callee') as NodePath).scope.getBinding(param.name);
      return !!pb && pb.constantViolations.length === 0 && onlyCalled(pb, depth + 1);
    }
    // `const X = f`
    if (c.isVariableDeclarator() && c.node.init === r.node && t.isIdentifier(c.node.id)) {
      const ab = c.scope.getBinding(c.node.id.name);
      return !!ab && ab.constantViolations.length === 0 && onlyCalled(ab, depth + 1);
    }
    return false;
  });
}

/** True when `node` lies inside (or is) `ancestor`. */
function pathWithin(p: NodePath, ancestor: t.Node): boolean {
  let cur: NodePath | null = p;
  while (cur) {
    if (cur.node === ancestor) return true;
    cur = cur.parentPath;
  }
  return false;
}

// ── B00b: statement normalisation ────────────────────────────────────────────

/**
 * Detach the leading expressions of the sequence evaluated *first* inside
 * `holder[key]` and return them, leaving the sequence's last element in place.
 *
 * Only positions evaluated before anything else in the enclosing statement are
 * followed — a binary/logical left operand, a conditional test, an assignment
 * RHS with an identifier target, a member object, a callee, a unary operand —
 * so emitting the detached expressions as preceding statements preserves order.
 * `(0, obj.fn)()` is never touched: dropping the sequence would change `this`.
 */
function peelLeadingSequence(holder: object, key: string): t.Expression[] | null {
  let h = holder as Record<string, unknown>;
  let k = key;
  for (let depth = 0; depth < 64; depth++) {
    const node = h[k] as t.Node | null | undefined;
    if (!node) return null;
    if (t.isSequenceExpression(node)) {
      if (node.expressions.length < 2) return null;
      const last = node.expressions[node.expressions.length - 1];
      // Keep the indirect-call idiom `(0, a.b)()` intact.
      if (
        k === 'callee' &&
        (t.isMemberExpression(last) ||
          t.isOptionalMemberExpression(last) ||
          t.isIdentifier(last, { name: 'eval' }))
      )
        return null;
      h[k] = last;
      // `(1, f)()` leaves a bare `1`: an operand with no effect is dropped
      // rather than emitted as a do-nothing statement.
      return (node.expressions.slice(0, -1) as t.Expression[]).filter(
        (e) =>
          !(
            t.isNumericLiteral(e) ||
            t.isStringLiteral(e) ||
            t.isBooleanLiteral(e) ||
            t.isNullLiteral(e) ||
            t.isIdentifier(e, { name: 'undefined' })
          )
      );
    }
    if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
      if (!t.isExpression(node.left)) return null;
      h = node as unknown as Record<string, unknown>;
      k = 'left';
    } else if (t.isConditionalExpression(node)) {
      h = node as unknown as Record<string, unknown>;
      k = 'test';
    } else if (t.isAssignmentExpression(node) && t.isIdentifier(node.left)) {
      h = node as unknown as Record<string, unknown>;
      k = 'right';
    } else if (t.isMemberExpression(node)) {
      h = node as unknown as Record<string, unknown>;
      k = 'object';
    } else if (t.isCallExpression(node) || t.isNewExpression(node)) {
      if (!t.isExpression(node.callee)) return null;
      h = node as unknown as Record<string, unknown>;
      k = 'callee';
    } else if (t.isUnaryExpression(node) && node.operator !== 'delete') {
      h = node as unknown as Record<string, unknown>;
      k = 'argument';
    } else if (t.isAwaitExpression(node)) {
      h = node as unknown as Record<string, unknown>;
      k = 'argument';
    } else return null;
  }
  return null;
}

/** `x++` / `x--` / `x += lit` — the conventional shape of a loop update. */
function isCounterUpdate(e: t.Expression): boolean {
  if (t.isUpdateExpression(e)) return t.isIdentifier(e.argument);
  return (
    t.isAssignmentExpression(e) &&
    ['+=', '-=', '*=', '<<=', '>>=', '>>>='].includes(e.operator) &&
    t.isIdentifier(e.left)
  );
}

/** Does `loop`'s body contain a `continue` that resumes this loop? */
function hasContinueFor(loop: t.Loop, label: string | null): boolean {
  let found = false;
  const scan = (node: t.Node, depth: number) => {
    if (found) return;
    if (t.isContinueStatement(node)) {
      if (node.label ? node.label.name === label : depth === 0) found = true;
      return;
    }
    if (t.isFunction(node) || t.isClass(node)) return;
    const nested = t.isLoop(node) ? 1 : 0;
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
    for (const key of keys) {
      const child = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const c of child)
          if (c && typeof c.type === 'string') scan(c as t.Node, depth + nested);
      } else if (child && typeof (child as t.Node).type === 'string')
        scan(child as t.Node, depth + nested);
    }
  };
  scan(loop.body, 0);
  return found;
}

/** Does `fn` ever `return <value>` (ignoring nested functions)? */
function returnsValue(fn: t.Function): boolean {
  if (!t.isBlockStatement(fn.body)) return true;
  let found = false;
  walk(fn.body, (n) => {
    if (found || t.isFunction(n) || t.isClass(n)) return false; // nested returns are theirs
    if (t.isReturnStatement(n) && n.argument) found = true;
    return !found;
  });
  return found;
}

/** Identifiers a `for` update steps (`i++`, `i += 2`) — the loop's counters. */
function loopCounters(update: t.Expression | null | undefined): Set<string> {
  const names = new Set<string>();
  for (const e of t.isSequenceExpression(update) ? update.expressions : update ? [update] : []) {
    if (t.isUpdateExpression(e) && t.isIdentifier(e.argument)) names.add(e.argument.name);
    else if (t.isAssignmentExpression(e) && e.operator !== '=' && t.isIdentifier(e.left))
      names.add(e.left.name);
  }
  return names;
}

function passStatementNormalize(ast: t.File, log: Logger): number {
  let n = 0;
  const insertBeforeStmt = (p: NodePath, exprs: t.Expression[]) => {
    const anchor = p.parentPath?.isLabeledStatement() ? p.parentPath : p;
    anchor.insertBefore(exprs.map((e) => t.expressionStatement(e)));
  };

  for (let round = 0; round < 8; round++) {
    let changed = 0;
    traverse(ast, {
      TemplateLiteral(p) {
        if (p.node.expressions.length !== 0) return;
        if (p.parentPath.isTaggedTemplateExpression()) return;
        const cooked = p.node.quasis[0]?.value.cooked;
        if (typeof cooked !== 'string') return;
        p.replaceWith(t.stringLiteral(cooked));
        changed++;
      },
      ExpressionStatement(p) {
        const e = p.node.expression;
        // `~function(){…}()` / `!function(){…}()` — the operator only discards
        // the result. `!` and `void` never call user code; numeric operators
        // could (valueOf), so require a function that returns nothing.
        if (t.isUnaryExpression(e) && ['!', '~', 'void', '+', '-'].includes(e.operator)) {
          const call = e.argument;
          if (t.isCallExpression(call)) {
            const fn = t.isMemberExpression(call.callee) ? call.callee.object : call.callee;
            if (t.isFunctionExpression(fn) || t.isArrowFunctionExpression(fn)) {
              if (e.operator === '!' || e.operator === 'void' || !returnsValue(fn)) {
                p.node.expression = call;
                changed++;
                return;
              }
            }
          }
        }
        if (t.isSequenceExpression(e)) {
          p.replaceWithMultiple(e.expressions.map((x) => t.expressionStatement(x)));
          changed++;
          return;
        }
        const lead = peelLeadingSequence(p.node, 'expression');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      'ReturnStatement|ThrowStatement'(p) {
        const node = p.node as t.ReturnStatement | t.ThrowStatement;
        if (!node.argument) return;
        const lead = peelLeadingSequence(node, 'argument');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      IfStatement(p) {
        const lead = peelLeadingSequence(p.node, 'test');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      SwitchStatement(p) {
        const lead = peelLeadingSequence(p.node, 'discriminant');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      'ForInStatement|ForOfStatement'(p) {
        const lead = peelLeadingSequence(p.node, 'right');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      VariableDeclaration(p) {
        if (p.parentPath.isForStatement() || p.parentPath.isForXStatement()) return;
        if (p.parentPath.isExportDeclaration()) return;
        const first = p.node.declarations[0];
        if (!first?.init) return;
        const lead = peelLeadingSequence(first, 'init');
        if (lead) {
          insertBeforeStmt(p, lead);
          changed++;
        }
      },
      ForStatement(p) {
        const loop = p.node;
        // Loop head: the init runs once, first. Keep what initialises the loop's
        // counters (`for (mj = 0, mG = 0; …; mj++)`), hoist the setup before it.
        if (loop.init) {
          let lead: t.Expression[] | null = null;
          if (t.isVariableDeclaration(loop.init)) {
            const first = loop.init.declarations[0];
            if (first?.init) lead = peelLeadingSequence(first, 'init');
          } else if (t.isSequenceExpression(loop.init)) {
            const exprs = loop.init.expressions;
            const counters = loopCounters(loop.update);
            let keepFrom = exprs.findIndex(
              (e) =>
                t.isAssignmentExpression(e) && t.isIdentifier(e.left) && counters.has(e.left.name)
            );
            if (keepFrom === -1) {
              // No counter to anchor on: keep the trailing run of plain
              // initialisers (`mL = 0, mn = m1.length`), at least the last one.
              const plain = (e: t.Expression) =>
                t.isAssignmentExpression(e, { operator: '=' }) &&
                t.isIdentifier(e.left) &&
                (isCopyableLiteral(e.right) ||
                  (t.isMemberExpression(e.right) &&
                    !e.right.computed &&
                    t.isIdentifier(e.right.object)));
              keepFrom = exprs.length - 1;
              while (keepFrom > 0 && plain(exprs[keepFrom - 1]) && plain(exprs[keepFrom]))
                keepFrom--;
            }
            if (keepFrom > 0) {
              lead = exprs.slice(0, keepFrom);
              const rest = exprs.slice(keepFrom);
              loop.init = rest.length === 1 ? rest[0] : t.sequenceExpression(rest);
            }
          } else lead = peelLeadingSequence(loop, 'init');
          if (lead) {
            insertBeforeStmt(p, lead);
            changed++;
          }
        }
        // `for (…; …; work, i++) {}` — the update is the loop body in disguise.
        if (loop.update && !(t.isVariableDeclaration(loop.init) && loop.init.kind !== 'var')) {
          const parts = t.isSequenceExpression(loop.update)
            ? [...loop.update.expressions]
            : [loop.update];
          const keep = isCounterUpdate(parts[parts.length - 1]) ? parts.pop()! : null;
          if (parts.length > 0) {
            const label = p.parentPath.isLabeledStatement() ? p.parentPath.node.label.name : null;
            const emptyBody =
              t.isEmptyStatement(loop.body) ||
              (t.isBlockStatement(loop.body) && loop.body.body.length === 0);
            if (emptyBody || !hasContinueFor(loop, label)) {
              const moved = parts.map((x) => t.expressionStatement(x));
              const body = t.isBlockStatement(loop.body)
                ? loop.body
                : t.isEmptyStatement(loop.body)
                  ? t.blockStatement([])
                  : t.blockStatement([loop.body]);
              body.body.push(...moved);
              loop.body = body;
              loop.update = keep;
              changed++;
            }
          }
        }
      },
    });

    // `x = {}; x.a = 1; x.b = f;` → `x = {a: 1, b: f};`
    changed += assembleObjectLiterals(ast);
    changed += mergeAdjacentVarDeclarations(ast);
    n += changed;
    if (changed === 0) break;
  }
  log.pass('b00b', 'statementNormalize', n);
  return n;
}

/** `var a, b; var c;` → `var a, b, c;` (adjacent bare `var` statements only). */
function mergeAdjacentVarDeclarations(ast: t.File): number {
  let n = 0;
  walkNode(ast.program, (node) => {
    const list =
      t.isProgram(node) || t.isBlockStatement(node)
        ? node.body
        : t.isSwitchCase(node)
          ? node.consequent
          : null;
    if (!list) return;
    for (let i = list.length - 1; i > 0; i--) {
      const a = list[i - 1];
      const b = list[i];
      // Only bare declarations: merging initialisers would put a write and
      // its reads into one statement, which hides the write's dominance.
      const bare = (d: t.Statement): d is t.VariableDeclaration =>
        t.isVariableDeclaration(d, { kind: 'var' }) && d.declarations.every((x) => !x.init);
      if (bare(a) && bare(b)) {
        a.declarations.push(...b.declarations);
        list.splice(i, 1);
        n++;
      }
    }
  });
  return n;
}

/**
 * Fold consecutive `x.k = v` statements into the object literal just assigned
 * to `x`. Only inert values that do not read `x` themselves are folded: the
 * original evaluates them after `x` is bound, the literal before.
 */
function assembleObjectLiterals(ast: t.File): number {
  let n = 0;
  const lists: t.Statement[][] = [];
  walkNode(ast.program, (node) => {
    if (t.isProgram(node) || t.isBlockStatement(node)) lists.push(node.body);
    else if (t.isSwitchCase(node)) lists.push(node.consequent);
  });

  for (const list of lists) {
    for (let i = 0; i < list.length; i++) {
      const head = list[i];
      let name: string | null = null;
      let obj: t.ObjectExpression | null = null;
      if (
        t.isExpressionStatement(head) &&
        t.isAssignmentExpression(head.expression, { operator: '=' }) &&
        t.isIdentifier(head.expression.left) &&
        t.isObjectExpression(head.expression.right)
      ) {
        name = head.expression.left.name;
        obj = head.expression.right;
      } else if (
        t.isVariableDeclaration(head) &&
        head.declarations.length === 1 &&
        t.isIdentifier(head.declarations[0].id) &&
        t.isObjectExpression(head.declarations[0].init)
      ) {
        name = head.declarations[0].id.name;
        obj = head.declarations[0].init;
      }
      if (!name || !obj) continue;
      if (
        obj.properties.some(
          (p) => t.isSpreadElement(p) || (p.computed && !isCopyableLiteral(p.key))
        )
      )
        continue;

      let j = i + 1;
      while (j < list.length) {
        const s = list[j];
        if (!t.isExpressionStatement(s)) break;
        const e = s.expression;
        if (!t.isAssignmentExpression(e, { operator: '=' })) break;
        if (!t.isMemberExpression(e.left) || !t.isIdentifier(e.left.object, { name })) break;
        const key = staticMemberKey(e.left);
        if (key === null || key === '__proto__') break;
        if (!isInert(e.right)) break;
        let readsSelf = false;
        walkNode(e.right, (nd) => {
          if (t.isIdentifier(nd, { name })) readsSelf = true;
        });
        // A nested function mentioning `x` only reads it later — fine; but
        // walkNode cannot tell, so stay conservative unless the value is a
        // function expression (whose body runs after assembly anyway).
        if (readsSelf && !t.isFunctionExpression(e.right) && !t.isArrowFunctionExpression(e.right))
          break;

        const existing = obj.properties.find(
          (p): p is t.ObjectProperty | t.ObjectMethod =>
            !t.isSpreadElement(p) && staticPropKey(p) === key
        );
        if (existing) {
          if (!t.isObjectProperty(existing)) break; // a method/accessor of that name
          existing.value = e.right;
        } else {
          const keyNode = /^[A-Za-z_$][\w$]*$/.test(key) ? t.identifier(key) : t.stringLiteral(key);
          obj.properties.push(t.objectProperty(keyNode, e.right));
        }
        j++;
      }
      if (j > i + 1) {
        n += j - i - 1;
        list.splice(i + 1, j - i - 1);
      }
    }
  }
  return n;
}

// ── B00c: parameter locals ───────────────────────────────────────────────────

function passParamLocals(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  let underEval = 0;
  type Job = { fn: t.Function; cut: number; declare: string[] };
  const jobs: Job[] = [];

  program.traverse({
    Function(p) {
      const fn = p.node;
      // A direct `eval` below this function can read its parameters by name.
      if (dyn.observes(p.scope)) {
        underEval++;
        return;
      }
      if (!t.isBlockStatement(fn.body) || fn.params.length === 0) return;
      // Only a trailing run of plain parameters can be demoted. In a non-simple
      // list (defaults, patterns, rest) the run must follow every such
      // parameter: `.length` stops at the first default anyway, `arguments` is
      // unmapped, and no default initializer may name a demoted parameter (an
      // earlier one could only reach it by throwing, a later one goes too).
      let firstPlain = fn.params.length;
      while (firstPlain > 0 && t.isIdentifier(fn.params[firstPlain - 1])) firstPlain--;
      if (firstPlain === fn.params.length) return;
      if (firstPlain > 0) {
        const names = new Set((fn.params.slice(firstPlain) as t.Identifier[]).map((x) => x.name));
        let mentioned = false;
        for (const prm of fn.params.slice(0, firstPlain))
          t.traverseFast(prm, (x) => {
            if (t.isIdentifier(x) && names.has(x.name)) mentioned = true;
          });
        if (mentioned) return;
      }
      if ((t.isObjectMethod(fn) || t.isClassMethod(fn)) && fn.kind !== 'method') return;
      if (!t.isArrowFunctionExpression(fn) && usesArguments(fn)) return;

      // An IIFE's parameters beyond its argument list start out `undefined`,
      // exactly like a `var` — no flow analysis needed for those.
      let argCount = Infinity;
      const parent = p.parentPath;
      if (
        (t.isFunctionExpression(fn) || t.isArrowFunctionExpression(fn)) &&
        parent.isCallExpression() &&
        parent.node.callee === fn &&
        !parent.node.arguments.some((a) => t.isSpreadElement(a))
      ) {
        const selfName = t.isFunctionExpression(fn) && fn.id ? fn.id.name : null;
        const selfRef = selfName ? p.scope.getBinding(selfName)?.referenced : false;
        if (!selfRef) argCount = parent.node.arguments.length;
      }

      const params = fn.params as t.Identifier[];
      // Keep the signature when code explicitly observes its arity.
      const fnBinding =
        t.isFunctionDeclaration(fn) && fn.id
          ? p.parentPath.scope.getBinding(fn.id.name)
          : parent.isVariableDeclarator() && t.isIdentifier(parent.node.id)
            ? parent.scope.getBinding(parent.node.id.name)
            : null;
      if (
        fnBinding?.referencePaths.some(
          (r) =>
            r.parentPath?.isMemberExpression() &&
            r.parentPath.node.object === r.node &&
            ['length', 'bind'].includes(staticMemberKey(r.parentPath.node) ?? '')
        )
      )
        return;
      // positions before `firstPlain` are never candidates (and may be patterns)
      const bindings = params.map((prm, i) => (i < firstPlain ? null : p.scope.getBinding(prm.name)));
      if (bindings.some((b, i) => i >= firstPlain && (!b || b.kind !== 'param'))) return;
      const bs = bindings as Binding[];
      const written = bs.map((b) => !!b && b.constantViolations.length > 0);
      // Cheap pre-pass: the trailing run that *could* qualify, and whether it
      // contains anything worth the flow analysis.
      let runStart = params.length;
      for (let i = params.length - 1; i >= firstPlain; i--) {
        if (!(i >= argCount || written[i] || !bs[i].referenced)) break;
        runStart = i;
      }
      const inRun = bs.slice(runStart);
      if (!inRun.some((b, k) => runStart + k >= argCount || written[runStart + k])) return;
      const observed = paramInitialObserved(
        p,
        inRun.filter((_, k) => written[runStart + k] && runStart + k < argCount)
      );

      let cut = params.length;
      let strong = false;
      for (let i = params.length - 1; i >= firstPlain; i--) {
        const b = bs[i];
        const beyondArgs = i >= argCount;
        const overwritten = written[i] && !observed.has(b);
        const unused = !b.referenced && !written[i];
        if (!(beyondArgs || overwritten || unused)) break;
        if (beyondArgs || overwritten) strong = true;
        cut = i;
      }
      // A run of merely-unused trailing params is left alone: arity can be
      // load-bearing (`(err, req, res, next)`), and nothing proves they are
      // obfuscator-made locals.
      if (!strong || cut === params.length) return;
      const declare = params
        .slice(cut)
        .map((prm, k) => ({ name: prm.name, b: bs[cut + k] }))
        .filter(({ b }) => b.referenced || b.constantViolations.length > 0)
        .map(({ name }) => name);
      jobs.push({ fn, cut, declare });
    },
  });

  let n = 0;
  for (const { fn, cut, declare } of jobs) {
    n += fn.params.length - cut;
    fn.params = fn.params.slice(0, cut);
    if (declare.length > 0 && t.isBlockStatement(fn.body))
      fn.body.body.unshift(
        t.variableDeclaration(
          'var',
          declare.map((name) => t.variableDeclarator(t.identifier(name)))
        )
      );
  }
  log.pass(
    'b00c',
    'paramLocals',
    n,
    'params demoted',
    `${jobs.length} fns${underEval > 0 ? `, ${underEval} under eval` : ''}`
  );
  return n;
}

// ── B08b: write-once binding propagation ─────────────────────────────────────

/** Globals whose value is fixed for the lifetime of the page. */
const STABLE_GLOBAL_TARGETS = new Set([
  ...VM_SAFE_GLOBALS,
  ...ALIASABLE_GLOBALS,
  'window',
  'document',
  'globalThis',
]);

type AliasTarget = { name: string; binding: Binding | null };

/**
 * The stable binding an alias fact ultimately names: a never-reassigned
 * function declaration, another write-once binding, or a fixed global.
 * Follows alias chains (`mW = mM`, `mM = Q`) to the root.
 */
function resolveAliasTarget(
  fact: WriteOnceFact,
  facts: Map<Binding, WriteOnceFact>,
  seen = new Set<Binding>()
): AliasTarget | null {
  if (!t.isIdentifier(fact.value)) return null;
  const name = fact.value.name;
  if (seen.has(fact.binding)) return null;
  seen.add(fact.binding);
  const b = fact.statement.scope.getBinding(name);
  if (!b) return STABLE_GLOBAL_TARGETS.has(name) ? { name, binding: null } : null;
  if (b.kind === 'hoisted' && b.path.isFunctionDeclaration() && b.constantViolations.length === 0)
    return { name, binding: b };
  const next = facts.get(b);
  if (!next) return null;
  return resolveAliasTarget(next, facts, seen) ?? { name, binding: b };
}

function passBindingPropagation(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const facts = writeOnceFacts(program);
  let aliases = 0;
  let literals = 0;
  let underEval = 0;

  for (const fact of facts.values()) {
    const refs = fact.binding.referencePaths;
    if (refs.length === 0) continue;
    if (dyn.observesBinding(fact.binding)) {
      underEval++;
      continue;
    }

    let target: AliasTarget | null = null;
    let literal: t.Expression | null = null;
    if (t.isIdentifier(fact.value)) target = resolveAliasTarget(fact, facts);
    else if (isCopyableLiteral(fact.value)) {
      const v = fact.value;
      // Long strings stay named: duplicating them only adds noise.
      if (!(t.isStringLiteral(v) && v.value.length > 20 && refs.length > 1))
        literal = v as t.Expression;
    }
    if (!target && !literal) continue;

    for (const r of refs) {
      if (!r.isIdentifier()) continue;
      const parent = r.parentPath;
      if (!parent || parent.isExportSpecifier() || parent.isUnaryExpression({ operator: 'delete' }))
        continue;
      if (target) {
        let atSite: Binding | undefined;
        try {
          atSite = r.scope.getBinding(target.name);
        } catch {
          continue;
        }
        if ((atSite ?? null) !== target.binding) continue; // shadowed here
        if (parent.isObjectProperty() && parent.node.shorthand && parent.node.value === r.node) {
          parent.node.shorthand = false;
          parent.node.key = t.identifier(r.node.name);
        }
        r.node.name = target.name;
        aliases++;
      } else if (literal) {
        if (parent.isObjectProperty() && parent.node.shorthand && parent.node.value === r.node) {
          parent.node.shorthand = false;
          parent.node.key = t.identifier(r.node.name);
        }
        r.replaceWith(t.cloneNode(literal, true));
        literals++;
      }
    }
  }
  // A `var` that is declared without a value and never written holds
  // `undefined` at every read — hoisting makes the declaration's position
  // irrelevant, and nothing can assign it later. js-confuser leaves these as
  // return flags (`var ret; … if (ret) return result;`) for code that never
  // returns. Restricted to function-scoped `var` (a `let` read before its line
  // throws), outside `for-in/of` heads (those write each iteration), away from
  // script globals and any `eval` that could assign it by name.
  let unset = 0;
  const isModuleSrc = program.node.sourceType === 'module';
  const seenScopes = new Set<unknown>();
  const sweepScope = (scope: NodePath['scope']) => {
    if (seenScopes.has(scope)) return;
    seenScopes.add(scope);
    if (scope.path.isProgram() && !isModuleSrc) return;
    for (const b of Object.values(scope.bindings)) {
      if (b.kind !== 'var' || b.constantViolations.length > 0 || b.referencePaths.length === 0) continue;
      if (dyn.observesBinding(b) || !b.path.isVariableDeclarator() || b.path.node.init) continue;
      const decl = b.path.parentPath;
      if (decl?.parentPath?.isForXStatement() && decl.parentPath.node.left === decl.node) continue;
      // every declarator of this name in the scope must be value-less
      let initialised = false;
      scope.path.traverse({
        VariableDeclarator(dp) {
          if (t.isIdentifier(dp.node.id, { name: b.identifier.name }) && dp.node.init && dp.scope.getBinding(b.identifier.name) === b)
            initialised = true;
        },
      });
      if (initialised) continue;
      for (const r of b.referencePaths) {
        if (!r.isIdentifier()) continue;
        const parent = r.parentPath;
        if (parent?.isObjectProperty() && parent.node.shorthand && parent.node.value === r.node) {
          parent.node.shorthand = false;
          parent.node.key = t.identifier(r.node.name);
        }
        r.replaceWith(r.scope.hasBinding('undefined', { noGlobals: true }) ? t.unaryExpression('void', t.numericLiteral(0)) : t.identifier('undefined'));
        unset++;
      }
    }
  };
  sweepScope(program.scope);
  program.traverse({
    Scopable(p) {
      sweepScope(p.scope);
    },
  });

  log.pass(
    'b08b',
    'bindingPropagation',
    aliases + literals + unset,
    'refs',
    `${aliases} alias, ${literals} literal, ${facts.size} write-once bindings` +
      (unset > 0 ? `, ${unset} never-assigned` : '') +
      (underEval > 0 ? `, ${underEval} under eval` : '')
  );
  return aliases + literals + unset;
}

// ── B07d: frozen literal arrays ──────────────────────────────────────────────

/** Array methods that read the receiver without exposing or mutating it. */
const NON_ESCAPING_ARRAY_METHODS = new Set([
  'slice',
  'indexOf',
  'lastIndexOf',
  'includes',
  'join',
  'at',
  'toString',
]);

/** A literal element that can be copied to a use site verbatim. */
function arrayElementValue(node: t.Node | null | undefined): t.Expression | null {
  if (!node) return null;
  if (isCopyableLiteral(node)) return node as t.Expression;
  if (t.isIdentifier(node, { name: 'undefined' })) return node;
  if (
    t.isUnaryExpression(node) &&
    (node.operator === '-' || node.operator === '+') &&
    t.isNumericLiteral(node.argument)
  )
    return node;
  return null;
}

/**
 * The index table: `const K = ["b", 0, 1, "i", 209, …]` read as `K[13]` from
 * every corner of the program, so that no call site shows what it passes. It is
 * the array counterpart of B07c's frozen object tables, and the same proof
 * applies — a write-once binding whose initialiser is all literals, whose
 * declaration dominates every read, and whose references are only element reads
 * cannot change value, so each read folds to its element.
 *
 * Escape is the whole question. Handing the array to anything that could keep
 * it (a call argument, an assignment, a callback-taking method such as `map`,
 * whose callback receives the array itself) forfeits the proof, so such a table
 * is left alone. Reads through the non-mutating methods above are fine: they
 * copy or search, and never publish the receiver.
 */
function passLiteralArrays(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const facts = writeOnceFacts(program);

  type Fold = { path: NodePath; value: t.Expression };
  const folds: Fold[] = [];
  let tables = 0;

  for (const fact of facts.values()) {
    if (!t.isArrayExpression(fact.value)) continue;
    const binding = fact.binding;
    // the fact's own write (`var K; … K = [...]`) is the one allowed violation
    if (binding.constantViolations.length > (fact.assignment ? 1 : 0)) continue;
    if (dyn.observesBinding(binding)) continue;
    // Program-scope `var` / `let` tables of a classic script are already kept
    // out by `writeOnceFacts`: another script on the page can rebind them. A
    // top-level `const` (js-confuser's duplicate-literal table) cannot be
    // rebound, and its elements are no more exposed than the properties of a
    // `const` object table, which B07c folds under the same conditions.

    const elements = fact.value.elements.map((e) => arrayElementValue(e));
    if (elements.some((e) => e === null)) continue;
    if (elements.length === 0) continue;

    const pending: Fold[] = [];
    let escapes = false;
    for (const ref of binding.referencePaths) {
      const member = ref.parentPath;
      if (
        !member?.isMemberExpression() ||
        member.node.object !== ref.node ||
        member.node.optional === true
      ) {
        escapes = true;
        break;
      }
      // Any write through the table would make its contents unknown.
      const holder = member.parentPath;
      if (
        (holder?.isAssignmentExpression() && holder.node.left === member.node) ||
        holder?.isUpdateExpression() ||
        (holder?.isUnaryExpression({ operator: 'delete' }) ?? false) ||
        (holder?.isForXStatement() && holder.node.left === member.node)
      ) {
        escapes = true;
        break;
      }

      const key = member.node.computed
        ? member.node.property
        : t.isIdentifier(member.node.property)
          ? member.node.property
          : null;

      // `K.length` is fixed for a table nothing can mutate.
      if (!member.node.computed && t.isIdentifier(key, { name: 'length' })) {
        pending.push({ path: member, value: t.numericLiteral(elements.length) });
        continue;
      }
      // A method call that cannot leak the receiver: allowed, never folded.
      if (
        !member.node.computed &&
        t.isIdentifier(key) &&
        NON_ESCAPING_ARRAY_METHODS.has(key.name) &&
        holder?.isCallExpression() &&
        holder.node.callee === member.node
      )
        continue;
      if (!member.node.computed) {
        escapes = true; // some other property or method: unknown behaviour
        break;
      }

      // Computed: fold only an index this table actually has.
      const idx = t.isExpression(member.node.property) ? evalPure(member.node.property) : null;
      if (!idx?.ok || typeof idx.value !== 'number') continue; // dynamic index: leave it
      if (!Number.isInteger(idx.value) || idx.value < 0 || idx.value >= elements.length) continue;
      pending.push({ path: member, value: elements[idx.value]! });
    }
    if (escapes || pending.length === 0) continue;
    tables++;
    folds.push(...pending);
  }

  let n = 0;
  for (const fold of folds) {
    try {
      fold.path.replaceWith(t.cloneNode(fold.value, true));
      n++;
    } catch {
      /* detached by an earlier fold */
    }
  }
  log.pass('b07d', 'literalArrays', n, 'reads folded', `${tables} tables`);
  return n;
}

// ── B07c: frozen object tables ───────────────────────────────────────────────

function passObjectTables(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const facts = writeOnceFacts(program);
  const order = documentOrder(ast);

  type Site = {
    member: NodePath<t.MemberExpression>;
    value: t.Node;
    call: boolean;
    scopeOf: NodePath;
    inTable: boolean;
  };
  const sites: Site[] = [];
  const tableNodes: t.Node[] = [];
  let tables = 0;

  for (const fact of facts.values()) {
    if (!t.isObjectExpression(fact.value)) continue;
    if (dyn.observesBinding(fact.binding)) continue;
    const props = new Map<string, t.Node>();
    let ok = true;
    for (const prop of fact.value.properties) {
      if (t.isSpreadElement(prop)) {
        ok = false;
        break;
      }
      const key = staticPropKey(prop);
      if (key === null || (key === '__proto__' && t.isObjectProperty(prop) && !prop.computed)) {
        ok = false;
        break;
      }
      if (t.isObjectMethod(prop) && prop.kind !== 'method') {
        ok = false; // accessor: reads run code
        break;
      }
      props.set(key, t.isObjectMethod(prop) ? prop : prop.value);
    }
    if (!ok) continue;

    // Every reference must be a property read/call with no way to mutate or
    // leak the object; otherwise its properties are not frozen.
    const local: Site[] = [];
    for (const r of fact.binding.referencePaths) {
      const m = r.parentPath;
      if (!m?.isMemberExpression() || m.node.object !== r.node) {
        ok = false;
        break;
      }
      const gp = m.parentPath;
      const node = m.node;
      const isWrite =
        (gp.isAssignmentExpression() && gp.node.left === node) ||
        gp.isUpdateExpression() ||
        gp.isUnaryExpression({ operator: 'delete' }) ||
        (gp.isForXStatement() && gp.node.left === node) ||
        gp.isArrayPattern() ||
        gp.isRestElement() ||
        (gp.isAssignmentPattern() && gp.node.left === node) ||
        (gp.isObjectProperty() && gp.parentPath?.isObjectPattern());
      if (isWrite || gp.isOptionalCallExpression()) {
        ok = false;
        break;
      }
      const isCall = gp.isCallExpression() && gp.node.callee === node;
      const key = staticMemberKey(node);
      if (key === null) {
        if (isCall) {
          ok = false; // dynamic method call hands the object out as `this`
          break;
        }
        continue; // dynamic read: harmless
      }
      const value = props.get(key);
      if (value === undefined) continue; // inherited / missing
      local.push({ member: m, value, call: isCall, scopeOf: fact.statement, inTable: false });
    }
    if (!ok) continue;
    tables++;
    tableNodes.push(fact.value);
    sites.push(...local);
  }

  for (const s of sites) s.inTable = tableNodes.some((tn) => pathWithin(s.member, tn));
  // Innermost first so nested `T.a(T.b(x))` composes; table bodies before
  // their call sites so instantiated templates are already simplified.
  const enter = (p: NodePath) => order.get(p.node)?.[0] ?? 0;
  sites.sort((a, b) => Number(b.inTable) - Number(a.inTable) || enter(b.member) - enter(a.member));

  let n = 0;
  for (const s of sites) {
    if (!s.member.node || s.member.removed) continue;
    try {
      if (!s.call) {
        if (!isCopyableLiteral(s.value)) continue;
        s.member.replaceWith(t.cloneNode(s.value as t.Expression, true));
        n++;
        continue;
      }
      const tpl = templateOf(s.value);
      if (!tpl) continue;
      // The body's free names must mean the same thing at the call site.
      let sameScope = true;
      for (const name of templateFreeNames(tpl)) {
        if (s.scopeOf.scope.getBinding(name) !== s.member.scope.getBinding(name)) {
          sameScope = false;
          break;
        }
      }
      if (!sameScope) continue;
      const callPath = s.member.parentPath as NodePath<t.CallExpression>;
      const args = callPath.node.arguments;
      if (!args.every((a) => t.isExpression(a))) continue;
      const out = instantiateTemplate(tpl, args as t.Expression[]);
      if (!out) continue;
      callPath.replaceWith(out);
      n++;
    } catch {
      /* stale path after an enclosing rewrite — next sweep */
    }
  }
  log.pass('b07c', 'objectTables', n, 'sites', `${tables} frozen tables`);
  return n;
}

// ── B17c: dead stores ────────────────────────────────────────────────────────

/** Inert expressions whose evaluated names are initialized function/var/parameter bindings. */
// Properties of the global object that are plain data on every host, so
// reading `globalThis.X` runs no getter.
const GLOBAL_DATA_PROPS = new Set([...GUARANTEED_GLOBALS, 'globalThis', 'TextDecoder', 'TextEncoder', 'Buffer', 'console']);

/**
 * Evaluating `e` (whose value is discarded) cannot be observed: it throws on
 * no path, terminates, and writes nothing that outlives it. Accepted:
 *
 *   • literals, `undefined`, function/arrow expressions (creating one runs nothing)
 *   • reads of `var`/param/function bindings (no TDZ), and of unbound
 *     built-ins / `globalThis.X` for X in GLOBAL_DATA_PROPS (data properties)
 *   • array and object literals of the above (no spread, no computed keys)
 *   • `S.k` for a built-in constructor S (static data property, e.g. String.fromCodePoint)
 *   • `new Array(n)` / `new Object()` with a small non-negative integer n
 *   • `&&`, `||`, `??`, `?:`, `,` and `!`/`void`/`typeof` over accepted parts
 *   • a call of a function expression whose parameters are plain or rest
 *     (defaults accepted parts) and whose body is a straight line of
 *     declarations, accepted expression statements, `if` and `return`. Inside,
 *     writes may target the function's own locals, or — by `R[i] = v` /
 *     `R.length = k` — a rest parameter R it never reassigns (always a fresh
 *     array, whose setters are plain). Reads of such an R are `R[i]`, `R.length`.
 *
 * No loops, no other calls, no `this`, no `arguments`: so evaluation terminates.
 */
function effectFree(path: NodePath): boolean {
  let ok = true;
  const restArrays = new Set<Binding>();
  const ownedFns: t.Node[] = [];
  const isOwnLocal = (b: Binding | undefined): boolean => !!b && ownedFns.includes(b.scope.path.node);
  const restOf = (q: NodePath, n: t.Node): Binding | null => {
    if (!t.isIdentifier(n)) return null;
    const b = q.scope.getBinding(n.name);
    return b && restArrays.has(b) ? b : null;
  };
  const restSlot = (q: NodePath, m: t.MemberExpression): boolean =>
    !!restOf(q, m.object) &&
    ((m.computed && t.isNumericLiteral(m.property)) ||
      (m.computed && t.isUnaryExpression(m.property, { operator: '-' }) && t.isNumericLiteral(m.property.argument)) ||
      (!m.computed && t.isIdentifier(m.property, { name: 'length' })));
  const expr = (q: NodePath): void => {
    if (!ok) return;
    const e = q.node;
    if (t.isNumericLiteral(e) || t.isStringLiteral(e) || t.isBooleanLiteral(e) || t.isNullLiteral(e)) return;
    if (t.isFunctionExpression(e) || t.isArrowFunctionExpression(e)) return;
    if (t.isIdentifier(e)) {
      const b = q.scope.getBinding(e.name);
      if (b ? !['var', 'param', 'hoisted'].includes(b.kind) : !(e.name === 'undefined' || GUARANTEED_GLOBALS.has(e.name) || e.name === 'globalThis'))
        ok = false;
      return;
    }
    if (t.isArrayExpression(e)) {
      if (e.elements.some((x) => !x || t.isSpreadElement(x))) ok = false;
      else (q.get('elements') as NodePath[]).forEach(expr);
      return;
    }
    if (t.isObjectExpression(e)) {
      for (const pr of q.get('properties') as NodePath[]) {
        if (pr.isObjectMethod() && !pr.node.computed) continue; // defining a method runs nothing
        if (!pr.isObjectProperty() || (pr.node.computed && !t.isStringLiteral(pr.node.key))) {
          ok = false;
          return;
        }
        expr(pr.get('value') as NodePath);
      }
      return;
    }
    if (t.isMemberExpression(e)) {
      if (restSlot(q, e)) return;
      const key = staticMemberKey(e);
      if (t.isIdentifier(e.object) && !q.scope.getBinding(e.object.name) && key !== null) {
        if (e.object.name === 'globalThis' && GLOBAL_DATA_PROPS.has(key)) return;
        if (GUARANTEED_GLOBALS.has(e.object.name) && /^[A-Z]/.test(e.object.name) && !t.isCallExpression(q.parent)) return;
      }
      ok = false;
      return;
    }
    if (t.isNewExpression(e)) {
      const c = e.callee;
      const small = (a: t.Node) => t.isNumericLiteral(a) && Number.isInteger(a.value) && a.value >= 0 && a.value < 2 ** 16;
      if (t.isIdentifier(c) && !q.scope.getBinding(c.name) && ((c.name === 'Array' && e.arguments.length === 1 && small(e.arguments[0])) || (c.name === 'Object' && e.arguments.length === 0)))
        return;
      // `new RegExp("…", "…")` with a pattern that compiles (checked here)
      if (t.isIdentifier(c, { name: 'RegExp' }) && !q.scope.getBinding('RegExp') && e.arguments.length >= 1 && e.arguments.length <= 2 && e.arguments.every((a) => t.isStringLiteral(a))) {
        try {
          const [pattern, flags] = (e.arguments as t.StringLiteral[]).map((a) => a.value);
          new RegExp(pattern, flags);
          return;
        } catch {
          /* would throw */
        }
      }
      ok = false;
      return;
    }
    if (t.isLogicalExpression(e)) {
      expr(q.get('left') as NodePath);
      expr(q.get('right') as NodePath);
      return;
    }
    if (t.isConditionalExpression(e)) {
      for (const k of ['test', 'consequent', 'alternate'] as const) expr(q.get(k) as NodePath);
      return;
    }
    if (t.isSequenceExpression(e)) {
      (q.get('expressions') as NodePath[]).forEach(expr);
      return;
    }
    if (t.isUnaryExpression(e) && ['!', 'void', 'typeof'].includes(e.operator)) {
      // `typeof x` on an unbound name never throws
      if (e.operator === 'typeof' && t.isIdentifier(e.argument)) return;
      expr(q.get('argument') as NodePath);
      return;
    }
    if (t.isAssignmentExpression(e, { operator: '=' })) {
      const left = e.left;
      if (t.isIdentifier(left)) {
        const b = q.scope.getBinding(left.name);
        if (!isOwnLocal(b) || b!.kind === 'const' || restArrays.has(b!)) ok = false;
      } else if (!(t.isMemberExpression(left) && restSlot(q, left))) ok = false;
      // `R.length = k` needs a valid length
      if (ok && t.isMemberExpression(left) && !left.computed && !(t.isNumericLiteral(e.right) && Number.isInteger(e.right.value) && e.right.value >= 0)) ok = false;
      if (ok) expr(q.get('right') as NodePath);
      return;
    }
    if (t.isCallExpression(e) && (t.isFunctionExpression(e.callee) || t.isArrowFunctionExpression(e.callee))) {
      (q.get('arguments') as NodePath[]).forEach((a) => (a.isSpreadElement() ? (ok = false) : expr(a)));
      if (ok) fnBody(q.get('callee') as NodePath<t.FunctionExpression | t.ArrowFunctionExpression>);
      return;
    }
    ok = false;
  };
  const stmt = (q: NodePath): void => {
    if (!ok) return;
    const s = q.node;
    if (t.isEmptyStatement(s) || t.isFunctionDeclaration(s)) return;
    if (t.isExpressionStatement(s)) return expr(q.get('expression') as NodePath);
    if (t.isReturnStatement(s)) {
      if (s.argument) expr(q.get('argument') as NodePath);
      return;
    }
    if (t.isVariableDeclaration(s, { kind: 'var' })) {
      for (const d of q.get('declarations') as NodePath<t.VariableDeclarator>[]) {
        if (!t.isIdentifier(d.node.id)) ok = false;
        else if (d.node.init) expr(d.get('init') as NodePath);
      }
      return;
    }
    if (t.isBlockStatement(s)) return (q.get('body') as NodePath[]).forEach(stmt);
    if (t.isIfStatement(s)) {
      expr(q.get('test') as NodePath);
      stmt(q.get('consequent') as NodePath);
      if (s.alternate) stmt(q.get('alternate') as NodePath);
      return;
    }
    ok = false;
  };
  const fnBody = (f: NodePath<t.FunctionExpression | t.ArrowFunctionExpression>): void => {
    const fn = f.node;
    if (fn.async || fn.generator || ownedFns.length > 16) {
      ok = false;
      return;
    }
    ownedFns.push(fn);
    let usesCtx = false;
    f.traverse({
      Function(x) {
        if (!x.isArrowFunctionExpression()) x.skip();
      },
      ThisExpression() {
        usesCtx = true;
      },
      Identifier(x) {
        if (x.node.name === 'arguments' && x.isReferencedIdentifier()) usesCtx = true;
      },
    });
    if (usesCtx) {
      ok = false;
      return;
    }
    for (const pm of f.get('params') as NodePath[]) {
      if (pm.isIdentifier()) continue;
      if (pm.isRestElement() && t.isIdentifier(pm.node.argument)) {
        const b = f.scope.getBinding(pm.node.argument.name);
        if (!b || b.constantViolations.length) ok = false;
        else restArrays.add(b);
        continue;
      }
      if (pm.isAssignmentPattern() && t.isIdentifier(pm.node.left)) {
        expr(pm.get('right') as NodePath);
        continue;
      }
      ok = false;
    }
    const body = f.get('body') as NodePath;
    if (body.isBlockStatement()) (body.get('body') as NodePath[]).forEach(stmt);
    else expr(body);
  };
  expr(path);
  return ok;
}

function isDiscardable(node: t.Node, scope: NodePath['scope']): boolean {
  if (!isInert(node)) return false;
  let reads = false;
  walk(node, (n, parent) => {
    if (t.isFunction(n)) return false;
    if (t.isIdentifier(n) && (!parent || t.isReferenced(n, parent))) {
      const binding = scope.getBinding(n.name);
      if (!binding || !['var', 'param', 'hoisted'].includes(binding.kind)) reads = true;
    }
  });
  return !reads;
}

function passDeadStores(ast: t.File, log: Logger): number {
  let total = 0;
  for (let round = 0; round < 6; round++) {
    const program = freshProgram(ast);
    const dyn = dynamicScopes(program);
    const isModule = program.node.sourceType === 'module';
    // Sloppy block-level functions also write a function-scoped var (Annex B
    // B.3.3) that Babel does not model: `typeof f` outside the block reads it.
    const annexB = annexBNames(program.node);
    /**
     * Could anything in the enclosing function F see the var that `b`'s
     * block-level function also writes? A spelling of the name outside the
     * declaration counts when it resolves to nothing (F's var shadows the
     * global), to a binding outside F (shadowed the same way), or to a
     * var/function-level binding of F itself (the very variable the block
     * assigns). A parameter, `let` or `const` of F makes Annex B inapplicable,
     * and a binding inside a nested scope of F shadows the var there — a
     * `let` of the same name in an inner function is not a use.
     */
    const nameUsedAround = (b: Binding): boolean => {
      const ownerPath = b.path.getFunctionParent() ?? program;
      const own = b.path.node;
      const name = b.identifier.name;
      let used = false;
      ownerPath.traverse({
        Identifier(ip) {
          if (used || ip.node.name !== name) return;
          const spelt: NodePath = ip;
          if (!(spelt.isReferencedIdentifier() || spelt.isBindingIdentifier())) return;
          if (ip.findParent((q) => q.node === own)) return;
          const bb = ip.scope.getBinding(name);
          const outsideOwner = bb && bb.scope !== ownerPath.scope && !bb.scope.path.isDescendant(ownerPath);
          if (!bb || bb === b || outsideOwner) {
            used = true;
            return;
          }
          if (bb.scope === ownerPath.scope) used = !['param', 'let', 'const'].includes(bb.kind);
          else if (bb.kind === 'hoisted' && bb.scope.getFunctionParent() === ownerPath.scope) used = true; // another block function writing F's var
        },
      });
      return used;
    };
    const todo: Array<() => void> = [];
    const seen = new Set<unknown>();

    const scan = (scope: NodePath['scope']) => {
      if (seen.has(scope)) return;
      seen.add(scope);
      const atProgram = scope.path.isProgram();
      if (atProgram && !isModule) return; // globals are visible to other scripts
      const fnNode = scope.path.isFunction() ? scope.path.node : null;
      // Sloppy-mode `arguments[i]` aliases parameter i: a write to an "unread"
      // parameter can still be observed through it.
      const paramsAliased =
        !!fnNode && !t.isArrowFunctionExpression(fnNode) && usesArguments(fnNode);
      for (const b of Object.values(scope.bindings)) {
        if (b.referenced) continue;
        // `referenced` only counts references the AST shows; a direct `eval`
        // below this scope can read the binding without one.
        if (dyn.observesBinding(b)) continue;
        if (b.kind === 'param' && paramsAliased) continue;
        // A `let`/`const` nothing reads *or writes* is unobservable; one that is
        // written stays, since the write may throw (TDZ, const) and would
        // become a global store without the declaration.
        const lexicalUnwritten =
          (b.kind === 'let' || b.kind === 'const') && b.constantViolations.length === 0;
        if (b.kind === 'param' || b.kind === 'var' || lexicalUnwritten) {
          let removable = 0;
          for (const v of b.constantViolations) {
            if (!v.isAssignmentExpression({ operator: '=' }) || !t.isIdentifier(v.node.left))
              continue;
            removable++;
            const rhs = v.node.right;
            const stmt = v.parentPath;
            if (stmt?.isExpressionStatement() && isDiscardable(rhs, v.scope))
              todo.push(() => stmt.remove());
            else if (
              stmt?.isSequenceExpression() &&
              isDiscardable(rhs, v.scope) &&
              stmt.node.expressions[stmt.node.expressions.length - 1] !== v.node
            )
              todo.push(() => v.remove()); // value unused: drop the element
            else todo.push(() => v.replaceWith(rhs));
          }
          const others = b.constantViolations.length - removable;
          if (b.kind !== 'param' && others === 0 && b.path.isVariableDeclarator()) {
            const d = b.path as NodePath<t.VariableDeclarator>;
            const decl = d.parentPath;
            if (!decl?.isVariableDeclaration()) continue;
            if (decl.parentPath.isForStatement() || decl.parentPath.isForXStatement()) continue;
            if (!t.isIdentifier(d.node.id)) continue;
            const init = d.node.init;
            // (effectFree: no throw, no call out, no write — e.g. `Math.imul || f`)
            if (!init || isDiscardable(init, d.scope) || effectFree(d.get('init') as NodePath)) todo.push(() => d.remove());
            else if (decl.node.declarations.length === 1 && Array.isArray(decl.container))
              todo.push(() => decl.replaceWith(t.expressionStatement(init)));
            else continue;
          }
        } else if (
          b.kind === 'hoisted' &&
          b.path.isFunctionDeclaration() &&
          b.constantViolations.length === 0 &&
          (!annexB.has(b.identifier.name) || !nameUsedAround(b))
        ) {
          const fp = b.path;
          todo.push(() => fp.remove());
        }
      }
    };
    scan(program.scope);
    program.traverse({
      Scopable(p) {
        scan(p.scope);
      },
    });

    let n = 0;
    for (const f of todo) {
      try {
        f();
        n++;
      } catch {
        /* already detached by an earlier removal */
      }
    }
    total += n;
    if (n === 0) break;
  }
  log.pass('b17c', 'deadStores', total);
  return total;
}

// ── B17d: single-use temporaries ─────────────────────────────────────────────

/**
 * The identifier evaluated *first* in `stmt`, if any — following the same
 * leftmost-evaluation positions as peelLeadingSequence. Callee positions are
 * excluded: substituting `a.b` for `x` in `x()` would change `this`.
 */
function firstEvaluatedIdentifier(stmt: t.Statement): t.Identifier | null {
  let node: t.Node | null | undefined = t.isExpressionStatement(stmt)
    ? stmt.expression
    : t.isReturnStatement(stmt) || t.isThrowStatement(stmt)
      ? stmt.argument
      : t.isIfStatement(stmt)
        ? stmt.test
        : t.isSwitchStatement(stmt)
          ? stmt.discriminant
          : t.isVariableDeclaration(stmt) && stmt.declarations.length === 1
            ? stmt.declarations[0].init
            : null;
  for (let depth = 0; node && depth < 64; depth++) {
    if (t.isIdentifier(node)) return node;
    if (t.isAssignmentExpression(node) && t.isIdentifier(node.left)) node = node.right;
    else if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) node = node.left;
    else if (t.isConditionalExpression(node)) node = node.test;
    else if (t.isMemberExpression(node)) node = node.object;
    else if (t.isUnaryExpression(node) && node.operator !== 'delete' && node.operator !== 'typeof')
      node = node.argument;
    else if (t.isCallExpression(node) || t.isNewExpression(node)) {
      // Arguments run after the callee; only a callee that cannot run code
      // (a plain identifier read) may precede them.
      if (!t.isIdentifier(node.callee) || node.arguments.length === 0) return null;
      node = node.arguments[0];
    } else return null;
  }
  return null;
}

/**
 * `x = E; return x;` → `return E;` — a temporary written once and read once,
 * by the very next statement, before that statement evaluates anything else.
 * Moving `E` to the read keeps every evaluation in its original order.
 */
function passSingleUseTemps(ast: t.File, log: Logger): number {
  let total = 0;
  for (let round = 0; round < 4; round++) {
    const program = freshProgram(ast);
    const dyn = dynamicScopes(program);
    const isModule = program.node.sourceType === 'module';
    type Job = {
      def: NodePath<t.Statement>;
      read: t.Identifier;
      holder: t.Node;
      value: t.Expression;
    };
    const jobs: Job[] = [];
    const claimed = new Set<t.Node>();

    program.traverse({
      'BlockStatement|Program'(p) {
        const stmts = (p.get('body') as NodePath<t.Statement>[]).filter(Boolean);
        for (let i = 0; i + 1 < stmts.length; i++) {
          const def = stmts[i];
          const use = stmts[i + 1];
          let name: string | null = null;
          let value: t.Expression | null = null;
          if (
            def.isExpressionStatement() &&
            t.isAssignmentExpression(def.node.expression, { operator: '=' }) &&
            t.isIdentifier(def.node.expression.left)
          ) {
            name = def.node.expression.left.name;
            value = def.node.expression.right;
          } else if (
            def.isVariableDeclaration() &&
            def.node.declarations.length === 1 &&
            t.isIdentifier(def.node.declarations[0].id) &&
            def.node.declarations[0].init
          ) {
            name = def.node.declarations[0].id.name;
            value = def.node.declarations[0].init;
          }
          if (!name || !value) continue;
          if (claimed.has(def.node) || claimed.has(use.node)) continue;
          const read = firstEvaluatedIdentifier(use.node);
          if (!read || read.name !== name) continue;
          const b = def.scope.getBinding(name);
          if (!b || !['param', 'var', 'let', 'const'].includes(b.kind)) continue;
          if (dyn.observesBinding(b)) continue;
          if (b.scope.path.isProgram() && !isModule) continue;
          if (b.referencePaths.length !== 1 || b.referencePaths[0].node !== read) continue;
          const writes = b.constantViolations;
          if (def.isExpressionStatement()) {
            if (writes.length !== 1 || writes[0].node !== def.node.expression) continue;
          } else if (
            writes.length !== 0 ||
            b.path.node !== (def.node as t.VariableDeclaration).declarations[0]
          )
            continue;
          if (b.kind === 'param') {
            const fn = b.scope.path.node as t.Function;
            if (!t.isArrowFunctionExpression(fn) && usesArguments(fn)) continue;
          }
          // `let`/`const` scoped to the def's block: the use is in the same block.
          claimed.add(def.node);
          claimed.add(use.node);
          jobs.push({ def, read, holder: use.node, value });
        }
      },
    });

    let n = 0;
    for (const job of jobs) {
      let replaced = false;
      const swap = (node: t.Node): void => {
        if (replaced) return;
        const rec = node as unknown as Record<string, unknown>;
        for (const key of (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? []) {
          const child = rec[key];
          if (child === job.read) {
            rec[key] = job.value;
            replaced = true;
            return;
          }
          if (Array.isArray(child)) {
            const idx = child.indexOf(job.read);
            if (idx !== -1) {
              child[idx] = job.value;
              replaced = true;
              return;
            }
            for (const c of child) if (c && typeof c.type === 'string') swap(c as t.Node);
          } else if (child && typeof (child as t.Node).type === 'string') swap(child as t.Node);
          if (replaced) return;
        }
      };
      swap(job.holder);
      if (!replaced) continue;
      try {
        job.def.remove();
        n++;
      } catch {
        /**/
      }
    }
    total += n;
    if (n === 0) break;
  }
  log.pass('b17d', 'singleUseTemps', total);
  return total;
}

// ── B05c: closed function slices evaluated in the VM ─────────────────────────

/** Globals a closed slice may reference: deterministic ECMAScript built-ins. */
const SLICE_SAFE_GLOBALS = new Set([
  ...VM_SAFE_GLOBALS,
  'Symbol',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'ArrayBuffer',
  'DataView',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int8Array',
  'Uint16Array',
  'Int16Array',
  'Uint32Array',
  'Int32Array',
  'Float32Array',
  'Float64Array',
]);

/** Data initialiser that can be copied into the VM verbatim. */
function isDataLiteral(node: t.Node | null | undefined, depth = 0): boolean {
  if (!node || depth > 20) return false;
  if (isCopyableLiteral(node)) return true;
  if (t.isArrayExpression(node))
    return node.elements.every(
      (e) => e !== null && !t.isSpreadElement(e) && isDataLiteral(e, depth + 1)
    );
  if (t.isObjectExpression(node))
    return node.properties.every(
      (p) => t.isObjectProperty(p) && !p.computed && isDataLiteral(p.value, depth + 1)
    );
  if (t.isCallExpression(node) && t.isMemberExpression(node.callee) && !node.callee.computed)
    return (
      isCopyableLiteral(node.callee.object) &&
      t.isIdentifier(node.callee.property, { name: 'split' }) &&
      node.arguments.every((a) => isCopyableLiteral(a))
    );
  return false;
}

/**
 * Generic string-table / decoder resolution by partial evaluation.
 *
 * A *closed* function references nothing but its own locals, other closed
 * functions, literal data bindings and deterministic built-ins, and writes
 * nothing outside itself except its own name (self-memoisation, as in
 * `function m(){ var a = "…".split(";"); m = function(){ return a }; return m() }`).
 * Each function with literal call sites is evaluated in its *slice*: its
 * transitive dependencies, plus the *setup* statements that drive them — e.g.
 * the rotation IIFE
 * `(function(get, target){ … get().push(get().shift()) … })(m, 170357)` —
 * provided they run before anything else in the scope that declares the slice
 * (everything ahead of them is inert), so no call into it can precede them.
 *
 * Each slice is evaluated in a fresh VM context, setup included, and every call
 * into it with literal arguments is probed. A slice is only folded when:
 *   • it is referenced from outside solely through calls (no aliasing/leaks),
 *   • every external call has literal arguments and every successful probe
 *     yields a primitive (no internal object escapes),
 *   • repeated forward and reverse probes agree, in addition to rejecting
 *     writes to shared data. Probes are an extra stability check, not a proof
 *     of purity for arbitrary JavaScript.
 * When nothing outside a slice references it any more, the slice (functions,
 * data and setup) is removed.
 */
function passClosedFunctionEval(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const isModule = program.node.sourceType === 'module';

  type Member =
    | { kind: 'fn'; binding: Binding; path: NodePath<t.FunctionDeclaration>; refs: FreeRefs }
    | { kind: 'data'; binding: Binding; path: NodePath<t.VariableDeclarator> };
  const members = new Map<Binding, Member>();
  const dataFacts = writeOnceFacts(program);

  program.traverse({
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id || p.node.async || p.node.generator) return;
      const b = p.parentPath.scope.getBinding(id.name);
      if (!b || b.path.node !== p.node) return;
      // Self-memoising reassignment inside the body is allowed; anything else is not.
      if (b.constantViolations.some((v) => !pathWithin(v, p.node))) return;
      // A direct `eval` / `with` inside the function, or anywhere that can see
      // its name, puts the slice's state out of reach of static proof.
      if (dyn.observesBinding(b) || dyn.contains(p)) return;
      // Its text could be read (`"" + f`) — see sandboxSafe. (Aliases
      // `const X = f` are only called too: B05c resolves them below.)
      if (!sandboxSafe(b)) return;
      members.set(b, { kind: 'fn', binding: b, path: p, refs: freeReferences(p) });
    },
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !isDataLiteral(p.node.init)) return;
      const b = p.scope.getBinding(p.node.id.name);
      if (!b || b.path.node !== p.node || b.constantViolations.length > 0) return;
      if (!dataFacts.has(b)) return; // initialization must dominate every possible call
      // A classic script's top-level bindings are shared with every other
      // script on the page, which may mutate them: not closed state.
      if (b.scope.path.isProgram() && !isModule) return;
      if (dyn.observesBinding(b)) return;
      members.set(b, { kind: 'data', binding: b, path: p });
    },
  });

  // ── closed set (greatest fixpoint) ─────────────────────────────────────────
  const closed = new Set(members.keys());
  for (let changed = true; changed; ) {
    changed = false;
    for (const b of [...closed]) {
      const m = members.get(b)!;
      if (m.kind === 'data') continue;
      const r = m.refs;
      let ok = !r.usesThis;
      for (const g of r.globals) if (!SLICE_SAFE_GLOBALS.has(g)) ok = false;
      for (const x of r.reads) if (x !== b && !closed.has(x)) ok = false;
      for (const x of r.writes) if (x !== b) ok = false;
      for (const x of r.mutates) if (x !== b && !closed.has(x)) ok = false;
      if (!ok) {
        closed.delete(b);
        changed = true;
      }
    }
  }
  const closedFns = [...closed].filter((b) => members.get(b)!.kind === 'fn');
  if (closedFns.length === 0) {
    log.pass('b05c', 'closedFunctionEval', 0, undefined, 'no closed functions');
    return 0;
  }

  // ── setup statements ──────────────────────────────────────────────────────
  type Setup = { path: NodePath<t.ExpressionStatement>; touches: Set<Binding> };
  const setupsByList = new Map<t.Node, Setup[]>();
  const listsWithMembers = new Map<t.Node, NodePath>();
  for (const b of closedFns) {
    const holder = (members.get(b) as { path: NodePath }).path.parentPath;
    if (holder && (holder.isBlockStatement() || holder.isProgram()))
      listsWithMembers.set(holder.node, holder);
  }
  for (const [listNode, holder] of listsWithMembers) {
    const setups: Setup[] = [];
    const stmts = (holder.get('body') as NodePath[]).filter((s) => s.isStatement());
    for (const s of stmts) {
      if (isInertStatement(s.node as t.Statement)) continue;
      if (!s.isExpressionStatement()) break;
      const refs = freeReferences(s);
      const touches = new Set([...refs.reads, ...refs.mutates].filter((x) => closed.has(x)));
      const ok =
        touches.size > 0 &&
        !refs.usesThis &&
        refs.writes.size === 0 &&
        [...refs.globals].every((g) => SLICE_SAFE_GLOBALS.has(g)) &&
        [...refs.reads].every((x) => closed.has(x)) &&
        [...refs.mutates].every((x) => closed.has(x));
      if (!ok) break;
      setups.push({ path: s, touches });
    }
    if (setups.length) setupsByList.set(listNode, setups);
  }

  // ── slices: dependency closure of each function, plus the setups it needs ─
  // A slice is what *one* function needs to run — not every function that
  // happens to use it. Users of a decoder (`function s(n){ … Q(504) … }`) are
  // closed too, but their own opaque call sites must not veto folding Q.
  const allSetups = [...setupsByList.values()].flat();
  const depMemo = new Map<Binding, Set<Binding>>();
  const depsOf = (b: Binding): Set<Binding> => {
    const hit = depMemo.get(b);
    if (hit) return hit;
    const out = new Set<Binding>();
    const stack = [b];
    while (stack.length) {
      const x = stack.pop()!;
      if (out.has(x)) continue;
      out.add(x);
      const m = members.get(x)!;
      if (m.kind === 'fn')
        for (const y of [...m.refs.reads, ...m.refs.mutates]) if (closed.has(y)) stack.push(y);
    }
    depMemo.set(b, out);
    return out;
  };
  const sliceFor = (f: Binding): { members: Set<Binding>; setups: Setup[] } => {
    const set = new Set(depsOf(f));
    const used = new Set<Setup>();
    for (let changed = true; changed; ) {
      changed = false;
      for (const st of allSetups) {
        if (used.has(st) || ![...st.touches].some((x) => set.has(x))) continue;
        used.add(st);
        for (const x of st.touches) for (const y of depsOf(x)) set.add(y);
        changed = true;
      }
    }
    return { members: set, setups: allSetups.filter((st) => used.has(st)) };
  };

  // ── aliases: `const X = fn;` where X is itself only ever called ───────────
  // javascript-obfuscator binds its decoder to a fresh local in every function
  // body (`const _0x14ecb3 = a1_0x2472;`) and to one top-level alias. Such a
  // declarator is the same reference under another name, not an escape: calls
  // through the alias are call sites of the member, and an alias nobody reads
  // (B08b has usually rewritten its uses already) is inert. Aliases of aliases
  // resolve the same way.
  type Alias = { binding: Binding; path: NodePath<t.VariableDeclarator>; target: Binding };
  const aliasOf = new Map<Binding, Alias>();
  const aliasesOf = new Map<Binding, Alias[]>();
  {
    const queue: Array<{ b: Binding; target: Binding }> = closedFns.map((b) => ({ b, target: b }));
    while (queue.length) {
      const { b, target } = queue.shift()!;
      for (const r of b.referencePaths) {
        const decl = r.parentPath;
        if (
          !decl?.isVariableDeclarator() ||
          decl.node.init !== r.node ||
          !t.isIdentifier(decl.node.id)
        )
          continue;
        if (decl.parentPath.parentPath?.isForXStatement()) continue;
        const ab = decl.scope.getBinding(decl.node.id.name);
        if (
          !ab ||
          ab.path.node !== decl.node ||
          ab.constantViolations.length > 0 ||
          aliasOf.has(ab)
        )
          continue;
        if (members.has(ab)) continue;
        const alias: Alias = { binding: ab, path: decl, target };
        aliasOf.set(ab, alias);
        aliasesOf.set(target, [...(aliasesOf.get(target) ?? []), alias]);
        queue.push({ b: ab, target });
      }
    }
  }
  /** Every reference to `b`, by its own name or through an alias of it. */
  const externalRefs = (b: Binding): NodePath[] => [
    ...b.referencePaths,
    ...(aliasesOf.get(b) ?? []).flatMap((a) => a.binding.referencePaths),
  ];
  const isAliasDeclarator = (r: NodePath): boolean => {
    const decl = r.parentPath;
    if (!decl?.isVariableDeclarator() || decl.node.init !== r.node || !t.isIdentifier(decl.node.id))
      return false;
    const ab = decl.scope.getBinding(decl.node.id.name);
    return !!ab && aliasOf.has(ab) && aliasOf.get(ab)!.path === decl;
  };

  /** External call sites of each closed function, split into literal / opaque. */
  type Site = { path: NodePath<t.CallExpression>; argSrc: string };
  const literalSites = new Map<Binding, Site[]>();
  for (const b of closedFns) {
    const own = (members.get(b) as { path: NodePath }).path.node;
    const sites: Site[] = [];
    for (const r of externalRefs(b)) {
      if (pathWithin(r, own)) continue;
      const call = r.parentPath;
      if (!call?.isCallExpression() || call.node.callee !== r.node) continue;
      const args = call.node.arguments;
      if (args.every((a) => t.isExpression(a) && isPurelyLiteral(a) && evalPure(a).ok))
        sites.push({ path: call, argSrc: `[${args.map((a) => generate(a).code).join(',')}]` });
    }
    if (sites.length) literalSites.set(b, sites);
  }

  const { Script, createContext } = vm;
  let folded = 0;
  let removedGroups = 0;
  let evaluated = 0;
  const foldedSites = new Set<t.Node>();
  const removable: Array<{ members: t.Node[]; setups: t.Node[]; aliases: t.Node[] }> = [];
  const seenSlices = new Set<string>();

  const roots = [...literalSites.keys()].map((b) => ({ b, slice: sliceFor(b) }));
  roots.sort((x, y) => x.slice.members.size - y.slice.members.size);

  for (const { slice } of roots) {
    const sliceMembers = [...slice.members];
    const key =
      sliceMembers
        .map((b) => b.identifier.name)
        .sort()
        .join(',') +
      '|' +
      slice.setups.length;
    if (seenSlices.has(key)) continue;
    seenSlices.add(key);
    const fnMembers = sliceMembers.filter((b) => members.get(b)!.kind === 'fn');
    // Probe order alone cannot prove purity: repeated equal arguments can
    // hide rotations or other writes to shared data.
    if (
      fnMembers.some((b) =>
        [...(members.get(b) as { refs: FreeRefs }).refs.mutates].some((target) => target !== b)
      )
    )
      continue;
    const internalRoots: t.Node[] = [
      ...sliceMembers.map((b) => (members.get(b) as { path: NodePath }).path.node),
      ...slice.setups.map((st) => st.path.node),
    ];
    const isInternal = (p: NodePath) => internalRoots.some((r) => pathWithin(p, r));

    // Setup must precede every possible call: all of the slice's functions are
    // declared in the very list whose inert prefix the setups extend, and any
    // data it touches is initialised before the first setup runs.
    if (slice.setups.length) {
      const list = slice.setups[0].path.parentPath!.node as t.BlockStatement | t.Program;
      if (slice.setups.some((st) => st.path.parentPath!.node !== list)) continue;
      if (
        fnMembers.some((b) => (members.get(b) as { path: NodePath }).path.parentPath?.node !== list)
      )
        continue;
      const firstSetup = list.body.indexOf(slice.setups[0].path.node);
      const dataOk = sliceMembers.every((b) => {
        const m = members.get(b)!;
        if (m.kind !== 'data') return true;
        const declStmt = m.path.parentPath?.node as t.Statement | undefined;
        const at = declStmt ? list.body.indexOf(declStmt) : -1;
        return at !== -1 && at < firstSetup;
      });
      if (!dataOk) continue;
    }
    // Unique names inside the slice.
    const names = sliceMembers.map((b) => b.identifier.name);
    if (new Set(names).size !== names.length) continue;

    // Outside the slice, members may only be *called* — anything else could
    // alias or mutate the state the evaluation captured.
    let leaks = false;
    const opaque = new Set<Binding>();
    for (const b of sliceMembers) {
      for (const r of externalRefs(b)) {
        if (isInternal(r)) continue;
        if (members.get(b)!.kind === 'fn' && isAliasDeclarator(r)) continue; // `const X = fn;`
        const call = r.parentPath;
        if (
          members.get(b)!.kind !== 'fn' ||
          !call?.isCallExpression() ||
          call.node.callee !== r.node
        ) {
          leaks = true;
          break;
        }
        if (!(literalSites.get(b) ?? []).some((st) => st.path === call)) opaque.add(b);
      }
      if (leaks) break;
    }
    if (leaks) continue;

    type Probe = {
      fn: string;
      binding: Binding;
      args: string;
      sites: NodePath<t.CallExpression>[];
    };
    const probes = new Map<string, Probe>();
    for (const b of fnMembers)
      for (const st of literalSites.get(b) ?? []) {
        if (foldedSites.has(st.path.node)) continue;
        // Calls from inside the slice (the decoder reading its pool, the
        // rotation IIFE probing mid-rotation) are the machinery, not uses.
        if (isInternal(st.path)) continue;
        const k = `${b.identifier.name}${st.argSrc}`;
        const pr = probes.get(k) ?? {
          fn: b.identifier.name,
          binding: b,
          args: st.argSrc,
          sites: [],
        };
        pr.sites.push(st.path);
        probes.set(k, pr);
      }
    // Untested arguments could expose internal state even when all literal
    // probes return primitives. Keep slices with opaque external calls.
    if (opaque.size > 0) continue;
    const probeList = [...probes.values()];

    if (probeList.length > 0) {
      const src: string[] = [];
      for (const b of sliceMembers) {
        const m = members.get(b)!;
        if (m.kind === 'data')
          src.push(`var ${b.identifier.name} = ${genVmCode(m.path.node.init!)};`);
      }
      for (const b of fnMembers)
        src.push(genVmCode((members.get(b) as { path: NodePath }).path.node));
      for (const st of slice.setups) src.push(genVmCode(st.path.node));
      // Resolve the live binding each time: a self-memoizing function can
      // replace itself after its first call.
      const fnTable = `{${fnMembers.map((b) => `get ${JSON.stringify(b.identifier.name)}() { return ${b.identifier.name}; }`).join(', ')}}`;

      type Result = { ok: boolean; type?: string; v?: unknown };
      const runProbes = (orderIdx: number[]): Result[] | null => {
        const calls = orderIdx
          .map((i) => `[${i}, ${JSON.stringify(probeList[i].fn)}, ${probeList[i].args}]`)
          .join(',\n');
        const script =
          `(function () {\n${src.join('\n')}\n` +
          `var __dq_fns = ${fnTable}; var __dq_out = {};\n` +
          `var __dq_calls = [${calls}];\n` +
          `for (var __dq_i = 0; __dq_i < __dq_calls.length; __dq_i++) {\n` +
          `  var __dq_c = __dq_calls[__dq_i];\n` +
          `  try { var __dq_v = __dq_fns[__dq_c[1]].apply(void 0, __dq_c[2]);\n` +
          `    var __dq_t = typeof __dq_v;\n` +
          `    var __dq_result = (__dq_v !== null && __dq_t === 'object') || __dq_t === 'function' || __dq_t === 'symbol' || __dq_t === 'bigint'\n` +
          `      ? { ok: true, type: 'object' }\n` +
          `      : { ok: true, type: __dq_t, v: __dq_t === 'number' ? (Object.is(__dq_v, -0) ? '-0' : String(__dq_v)) : __dq_v };\n` +
          `    var __dq_prev = __dq_out[__dq_c[0]];\n` +
          `    if (__dq_prev && JSON.stringify(__dq_prev) !== JSON.stringify(__dq_result)) throw new Error('unstable decoder');\n` +
          `    __dq_out[__dq_c[0]] = __dq_result;\n` +
          `  } catch (__dq_e) { __dq_out[__dq_c[0]] = { ok: false }; }\n` +
          `}\nreturn JSON.stringify(__dq_out);\n})()`;
        try {
          const ctx = createContext({
            __dq_atob: (x: string) => Buffer.from(x, 'base64').toString('binary'),
            __dq_btoa: (x: string) => Buffer.from(x, 'binary').toString('base64'),
          });
          new Script(
            'Math.random = function () { throw new Error("nondeterministic"); };' +
              'var atob = function (s) { return __dq_atob(String(s)); };' +
              'var btoa = function (s) { return __dq_btoa(String(s)); };'
          ).runInContext(ctx);
          const raw = new Script(script).runInContext(ctx, { timeout: 3000 });
          const parsed = JSON.parse(String(raw)) as Record<string, Result>;
          return probeList.map((_, i) => parsed[i] ?? { ok: false });
        } catch {
          return null;
        }
      };

      const indices = probeList.map((_, i) => i);
      const forward = runProbes([...indices, ...indices]);
      const reversed = [...indices].reverse();
      const backward = runProbes([...reversed, ...reversed]);
      evaluated++;
      if (!forward || !backward) continue;
      if (JSON.stringify(forward) !== JSON.stringify(backward)) continue; // hidden state
      if (forward.some((r) => r.ok && r.type === 'object')) continue; // internal object escapes

      probeList.forEach((pr, i) => {
        const r = forward[i];
        if (!r.ok) return;
        let value: unknown;
        if (r.type === 'number') value = r.v === '-0' ? -0 : Number(r.v);
        else if (r.type === 'string' || r.type === 'boolean') value = r.v;
        else if (r.type === 'object' && r.v === null) value = null;
        else return; // undefined / unknown: leave the call
        if (typeof value === 'number' && Object.is(value, -0)) return;
        const node = toNode(value);
        if (!node) return;
        for (const site of pr.sites) {
          try {
            foldedSites.add(site.node);
            site.replaceWith(t.cloneNode(node, true));
            folded++;
          } catch {
            /**/
          }
        }
      });
    }

    const atProgram = sliceMembers.some((b) => b.scope.path.isProgram());
    if (atProgram && !isModule && slice.setups.length === 0) continue; // may be a public global
    removable.push({
      members: sliceMembers.map((b) => (members.get(b) as { path: NodePath }).path.node),
      setups: slice.setups.map((st) => st.path.node),
      aliases: sliceMembers.flatMap((b) => (aliasesOf.get(b) ?? []).map((a) => a.path.node)),
    });
  }

  // ── removal once nothing outside a slice refers to it ─────────────────────
  // Re-crawl: the folds above detached reference paths in place, so the old
  // binding tables can no longer tell live references from replaced ones.
  // Largest slices first, so a dead user takes its decoder with it.
  if (removable.length) {
    removable.sort((a, b) => b.members.length - a.members.length);
    const fresh = freshProgram(ast);
    const pathOf = new Map<t.Node, NodePath>();
    const wanted = new Set(removable.flatMap((g) => [...g.members, ...g.setups, ...g.aliases]));
    fresh.traverse({
      enter(p) {
        if (wanted.has(p.node)) pathOf.set(p.node, p);
      },
    });
    const gone = new Set<t.Node>();
    for (const g of removable) {
      const sliceRoots = [...g.members, ...g.setups];
      if (sliceRoots.some((r) => gone.has(r) || !pathOf.has(r))) continue;
      // An alias declarator goes with its slice once nothing reads the alias
      // (its calls were folded above, or B08b had already rewritten them).
      const deadAliases = new Set<t.Node>();
      for (const node of g.aliases) {
        const ap = pathOf.get(node);
        if (!ap?.isVariableDeclarator() || !t.isIdentifier(ap.node.id)) continue;
        const ab = ap.scope.getBinding(ap.node.id.name);
        if (!ab || ab.path.node !== node || ab.constantViolations.length > 0) continue;
        if (ab.referencePaths.every((r) => deadAliases.has(r.parentPath?.node as t.Node)))
          deadAliases.add(node);
      }
      const withinSlice = (r: NodePath) =>
        sliceRoots.some((root) => pathWithin(r, root)) ||
        deadAliases.has(r.parentPath?.node as t.Node);
      let live = false;
      for (const node of g.members) {
        const mp = pathOf.get(node)!;
        const name = t.isFunctionDeclaration(node)
          ? node.id!.name
          : ((node as t.VariableDeclarator).id as t.Identifier).name;
        const b = (mp.isFunctionDeclaration() ? mp.parentPath! : mp).scope.getBinding(name);
        if (!b || b.path.node !== node) {
          live = true;
          break;
        }
        if (b.referencePaths.some((r) => !withinSlice(r))) {
          live = true;
          break;
        }
      }
      if (live) continue;
      try {
        for (const node of g.setups) pathOf.get(node)!.remove();
        for (const node of g.members) pathOf.get(node)!.remove();
        for (const node of deadAliases) pathOf.get(node)!.remove();
        for (const node of sliceRoots) gone.add(node);
        removedGroups++;
      } catch {
        /**/
      }
    }
  }

  log.pass(
    'b05c',
    'closedFunctionEval',
    folded,
    'calls folded',
    `${closedFns.length} closed fns, ${evaluated} slices evaluated, ${removedGroups} removed`
  );
  return folded + removedGroups;
}

// ── B17e: nested IIFE flattening ─────────────────────────────────────────────

/** A `return` at the function's own level (nested functions excluded). */
function hasOwnReturn(fn: t.Function): boolean {
  let hit = false;
  const v = (x: t.Node): void => {
    if (hit || (t.isFunction(x) && x !== fn)) return;
    if (t.isReturnStatement(x)) {
      hit = true;
      return;
    }
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[x.type] ?? []) {
      const c = (x as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((y) => y && v(y as t.Node));
      else if (c) v(c as t.Node);
    }
  };
  v(fn.body);
  return hit;
}

/**
 * `function () { …; (function () { BODY })(); … }` → `function () { …; BODY; … }`
 *
 * An argument-less IIFE statement directly inside another function's body is
 * a scope with nothing to show for it: control-flow-flattening recovery and
 * wrapper removal leave them nested two or three deep. Inlining BODY is
 * unobservable when BODY does not depend on the inner call's own `this` /
 * `arguments`, its declarations collide with nothing in the enclosing
 * function, it is not in strict mode of its own, and — if it can `return` —
 * it is the last statement of an outer IIFE whose value is discarded (so a
 * return still ends the same work and its value is still thrown away).
 * Program-level IIFEs are left alone: their locals would become globals.
 */
function passIifeFlatten(ast: t.File, log: Logger): number {
  let program = freshProgram(ast);
  let dyn = dynamicScopes(program);
  let n = 0;
  // `var g; g = function () { B }; … return g();` with g used by that one call:
  // nothing else ever sees g, its closure environment is the same wherever the
  // function is created, and the call binds `this` to undefined either way —
  // so the call can create the function itself, as an IIFE the step below
  // then flattens.
  let localised = 0;
  // `(function () { …; return E; })();` — the call's value is thrown away, so
  // the last statement may as well just evaluate E.
  program.traverse({
    ExpressionStatement(p) {
      const call = p.node.expression;
      if (!t.isCallExpression(call) || !t.isFunctionExpression(call.callee) || call.callee.async || call.callee.generator) return;
      const body = call.callee.body.body;
      // A lone `return …` is a forwarding thunk other passes recognise by that
      // shape (RGF, dispatchers); only longer bodies are worth the rewrite.
      if (body.length < 2) return;
      const last = body[body.length - 1];
      if (!t.isReturnStatement(last)) return;
      if (last.argument) body[body.length - 1] = t.expressionStatement(last.argument);
      else body.pop();
      localised++;
    },
  });
  program.traverse({
    CallExpression(p) {
      const c = p.node;
      if (c.arguments.length || !t.isIdentifier(c.callee)) return;
      const st = p.parentPath;
      if (!(st?.isReturnStatement() || st?.isExpressionStatement())) return;
      const b = p.scope.getBinding(c.callee.name);
      if (!b || b.kind !== 'var' || b.referencePaths.length !== 1 || b.referencePaths[0].node !== c.callee) return;
      if (!b.path.isVariableDeclarator() || b.path.node.init || b.constantViolations.length !== 1) return;
      if (dyn.observesBinding(b)) return;
      const asg = b.constantViolations[0];
      if (!asg.isAssignmentExpression({ operator: '=' }) || !asg.parentPath.isExpressionStatement()) return;
      const fe = asg.node.right;
      if (!t.isFunctionExpression(fe) || fe.params.length || fe.async || fe.generator) return;
      if (fe.id && asg.get('right').scope.getBinding(fe.id.name)?.referenced) return;
      // the assignment runs first, in the same block
      if (asg.parentPath.parentPath?.node !== st.parentPath?.node) return;
      const list = (st.parentPath!.node as t.BlockStatement).body;
      if (list.indexOf(asg.parentPath.node as t.Statement) > list.indexOf(st.node as t.Statement)) return;
      c.callee = t.functionExpression(null, [], fe.body);
      asg.parentPath.remove();
      b.path.remove();
      localised++;
    },
  });
  if (localised) {
    program = freshProgram(ast);
    dyn = dynamicScopes(program);
  }
  n += localised;
  program.traverse({
    // `return (function () { BODY })();` as the last statement: BODY's returns
    // now return the same value from here, and falling off its end still
    // yields `undefined`.
    'ExpressionStatement|ReturnStatement'(p: NodePath) {
      const isReturn = p.isReturnStatement();
      const call = isReturn ? (p.node as t.ReturnStatement).argument : (p.node as t.ExpressionStatement).expression;
      if (!t.isCallExpression(call) || call.arguments.length) return;
      const inner = call.callee;
      if (!t.isFunctionExpression(inner) || inner.id || inner.params.length || inner.async || inner.generator) return;
      if (inner.body.directives.length) return;
      const holder = p.parentPath;
      if (!holder?.isBlockStatement()) return;
      const outer = holder.parentPath;
      if (!outer?.isFunction() || outer.isArrowFunctionExpression() || outer.node.body !== holder.node) return;
      if (ownContextSensitive(inner) || dyn.contains(p)) return;
      if (isReturn) {
        const stmts = holder.node.body;
        if (stmts[stmts.length - 1] !== p.node) return;
      } else if (hasOwnReturn(inner)) {
        const stmts = holder.node.body;
        if (stmts[stmts.length - 1] !== p.node) return;
        const outerCall = outer.parentPath;
        if (!(outer.isFunctionExpression() && outerCall?.isCallExpression() && outerCall.node.callee === outer.node && outerCall.parentPath?.isExpressionStatement()))
          return;
      }
      // the inner function's own declarations must not meet anything in the outer one
      const innerScope = (p.get(isReturn ? 'argument.callee' : 'expression.callee') as NodePath).scope;
      for (const name of Object.keys(innerScope.bindings)) {
        if (outer.scope.hasOwnBinding(name)) return;
        let clash = false;
        outer.traverse({
          Identifier(ip) {
            if (clash || ip.node.name !== name) return;
            if (ip.findParent((q) => q.node === inner)) return;
            clash = true;
          },
        });
        if (clash) return;
      }
      p.replaceWithMultiple(inner.body.body);
      n++;
    },
  });
  // `(function (G) { … })({ get X() {…} })` with G never read — js-confuser's
  // pack wrapper once its globals are resolved. An unread parameter receives
  // a value nobody looks at; when its argument is also effectFree, both can
  // go. Not when the function reads `arguments` (it would see the shift) or
  // names itself (its `length` would change).
  let params = 0;
  freshProgram(ast).traverse({
    CallExpression(p) {
      const callee = p.get('callee');
      if (!callee.isFunctionExpression() || callee.node.async || callee.node.generator) return;
      const fn = callee.node;
      if (fn.id || usesArguments(fn) || dyn.contains(p)) return;
      if (p.node.arguments.some((a) => t.isSpreadElement(a))) return;
      for (let i = fn.params.length - 1; i >= 0; i--) {
        const q = fn.params[i];
        if (!t.isIdentifier(q)) break; // a pattern or default reads its slot
        const b = callee.scope.getBinding(q.name);
        if (!b || b.referenced || b.constantViolations.length || dyn.observesBinding(b)) break;
        const args = p.get('arguments') as NodePath[];
        if (i < args.length && !(args.length === i + 1 && effectFree(args[i]))) break;
        fn.params.pop();
        if (i < args.length) p.node.arguments.pop();
        params++;
      }
    },
  });
  n += params;
  log.pass('b17e', 'iifeFlatten', n);
  return n;
}

// ── B19b: js-confuser generated names ────────────────────────────────────────

/**
 * js-confuser names what it generates `__p_<4 random>_<meaning>`: an extracted
 * object property `__p_q8hM_ops_plus`, a masked parameter array
 * `__p_A6bS_varMask`. Once the transform itself is undone, the variable that is
 * left is ordinary code with a noisy name. Renaming it to the meaningful suffix
 * (`ops_plus`) is a pure rename, binding by binding — skipped for anything a
 * direct `eval` can reach, and only to a valid name that appears nowhere else
 * in the program, so no reference can be captured or shadowed. Script globals
 * are renamed too, unlike elsewhere in the engine: a `__p_` name is the
 * obfuscator's own invention, never part of the original program's interface,
 * just as the top-level machinery other passes remove is.
 */
function passConfuserNames(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  const taken = new Set<string>();
  t.traverseFast(ast.program, (x) => {
    if (t.isIdentifier(x)) taken.add(x.name);
    else if (t.isLabeledStatement(x)) taken.add(x.label.name);
  });
  const RE = /^__p_[A-Za-z0-9]{4}_(?:\d+_)?([A-Za-z_$][A-Za-z0-9_$]*)$/;
  let n = 0;
  const seen = new Set<unknown>();
  const visit = (scope: NodePath['scope']) => {
    if (seen.has(scope)) return;
    seen.add(scope);
    for (const [name, b] of Object.entries(scope.bindings)) {
      const m = RE.exec(name);
      if (!m) continue;
      if (dyn.observesBinding(b)) continue;
      const target = m[1];
      if (!t.isValidIdentifier(target) || RESERVED.has(target) || taken.has(target)) continue;
      scope.rename(name, target);
      taken.add(target);
      n++;
    }
  };
  visit(program.scope);
  program.traverse({
    Scopable(p) {
      visit(p.scope);
    },
  });
  log.pass('b19b', 'confuserNames', n, 'renamed');
  return n;
}

// ── B17f: declaration tidy ───────────────────────────────────────────────────

/** A value whose evaluation runs no code: literals, names, function literals, plain literals of those. */
function runsNoCode(e: t.Node | null | undefined): boolean {
  if (!e) return true;
  if (t.isLiteral(e) && !t.isTemplateLiteral(e)) return true;
  if (t.isTemplateLiteral(e)) return e.expressions.length === 0;
  if (t.isIdentifier(e) || t.isFunctionExpression(e) || t.isArrowFunctionExpression(e)) return true;
  if (t.isUnaryExpression(e, { operator: 'void' })) return t.isLiteral(e.argument);
  if (t.isUnaryExpression(e, { operator: '-' })) return t.isNumericLiteral(e.argument);
  if (t.isArrayExpression(e)) return e.elements.every((x) => !x || (!t.isSpreadElement(x) && runsNoCode(x)));
  if (t.isObjectExpression(e))
    return e.properties.every((pr) => (t.isObjectMethod(pr) && !pr.computed) || (t.isObjectProperty(pr) && !pr.computed && runsNoCode(pr.value)));
  return false;
}

/**
 * js-confuser's movedDeclarations, once undone, leaves `var a, b; a = undefined;
 * b = 1;` where the source said `var b = 1;`.
 *
 *   • `x = undefined;` among a function's opening statements, before anything
 *     that could have written x, is a no-op: a `var` already starts undefined.
 *     Only declarations and assignments of values that run no code may come
 *     first. Not at program level, where an earlier script may have set x.
 *   • The first top-level `x = E;` of a `var x` declared without a value can
 *     declare it: `var x = E;`. A `var` is hoisted to the top of its function
 *     (or script) wherever it is written, so the binding and every read of it
 *     are unchanged — only where the declaration is spelt moves.
 */
function passDeclarationTidy(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  let dropped = 0;
  let sunk = 0;
  const tidy = (p: NodePath, body: t.Statement[], atProgram: boolean): t.Statement[] => {
    if (dyn.observes(p.scope)) return body;
    // 1. redundant `x = undefined` in the opening statements
    if (!atProgram && !p.scope.hasBinding('undefined', { noGlobals: true })) {
      const written = new Set<string>();
      const out: t.Statement[] = [];
      let open = true;
      for (const st of body) {
        if (open) {
          if (t.isFunctionDeclaration(st) || (t.isVariableDeclaration(st) && st.kind === 'var' && st.declarations.every((d) => !d.init))) {
            out.push(st);
            continue;
          }
          if (t.isExpressionStatement(st) && t.isAssignmentExpression(st.expression, { operator: '=' }) && t.isIdentifier(st.expression.left)) {
            const name = st.expression.left.name;
            const b = p.scope.getBinding(name);
            const isUndef = t.isIdentifier(st.expression.right, { name: 'undefined' }) || (t.isUnaryExpression(st.expression.right, { operator: 'void' }) && t.isNumericLiteral(st.expression.right.argument));
            if (isUndef && b && b.kind === 'var' && b.scope === p.scope && !written.has(name)) {
              dropped++;
              continue;
            }
            if (runsNoCode(st.expression.right)) {
              written.add(name);
              out.push(st);
              continue;
            }
          }
          open = false;
        }
        out.push(st);
      }
      body = out;
    }
    // 1b. `var p;` naming a parameter redeclares it, which does nothing — with
    // simple parameters (otherwise the body's `var` is a binding of its own)
    // (Destructuring alone is no parameter *expression*; defaults or computed
    // keys are, and give the body its own variable environment.)
    const paramExpressions = (fn: t.Function): boolean => {
      let found = false;
      for (const q of fn.params)
        walk(q, (n) => {
          if (t.isAssignmentPattern(n) || (t.isObjectProperty(n) && n.computed)) found = true;
        });
      return found;
    };
    if (p.isFunction() && !paramExpressions(p.node) && !p.node.params.some((q) => t.isTSParameterProperty(q))) {
      const params = new Set(p.node.params.flatMap((q) => Object.keys(t.getBindingIdentifiers(q))));
      body = body.filter((st) => {
        if (!t.isVariableDeclaration(st, { kind: 'var' })) return true;
        const keep = st.declarations.filter((d) => !(t.isIdentifier(d.id) && !d.init && params.has(d.id.name)));
        if (keep.length === st.declarations.length) return true;
        dropped += st.declarations.length - keep.length;
        st.declarations = keep;
        return keep.length > 0;
      });
    }
    // 2. sink each value-less `var x` into its first top-level `x = E;`
    const declaredAt = new Map<string, t.VariableDeclaration>();
    for (const st of body)
      if (t.isVariableDeclaration(st) && st.kind === 'var')
        for (const d of st.declarations) if (t.isIdentifier(d.id) && !d.init && !declaredAt.has(d.id.name)) declaredAt.set(d.id.name, st);
    const done = new Set<string>();
    const snapshot = body.slice();
    body = body.map((st, k) => {
      if (!t.isExpressionStatement(st) || !t.isAssignmentExpression(st.expression, { operator: '=' }) || !t.isIdentifier(st.expression.left)) return st;
      const name = st.expression.left.name;
      const decl = declaredAt.get(name);
      const b = p.scope.getBinding(name);
      if (!decl || done.has(name) || !b || b.kind !== 'var' || b.scope !== p.scope) return st;
      // Other passes read `var x = E` as "x holds E wherever it is read".
      // Only spell it so when that is true: no read can run before this
      // statement — none in an earlier statement, none in a hoisted function.
      const early = b.referencePaths.some((r) => {
        // a function declaration nested in this body (not the owner itself)
        for (let q = r.parentPath; q && q.node !== p.node; q = q.parentPath) if (q.isFunctionDeclaration()) return true;
        return snapshot.slice(0, k).some((prev) => !!r.findParent((q) => q.node === prev) || r.node === prev);
      });
      if (early) {
        done.add(name);
        return st;
      }
      done.add(name);
      decl.declarations = decl.declarations.filter((d) => !(t.isIdentifier(d.id, { name }) && !d.init));
      sunk++;
      return t.variableDeclaration('var', [t.variableDeclarator(t.identifier(name), st.expression.right)]);
    });
    return body.filter((st) => !(t.isVariableDeclaration(st) && st.declarations.length === 0));
  };
  program.node.body = tidy(program, program.node.body, true);
  program.traverse({
    Function(p) {
      if (t.isBlockStatement(p.node.body)) p.node.body.body = tidy(p, p.node.body.body, false);
    },
  });
  // 3. `var f; … f = function (…) {…};` → `function f(…) {…}` in place. The
  // binding is write-once and no read can run before the write (writeOnceFacts),
  // so hoisting the definition is unobservable; an anonymous function assigned
  // to `f` is named "f" either way; and inside it `f` already named this same
  // binding. Only in a function body (a block-level declaration would bring
  // Annex B semantics), never for arrows (their `this`/`arguments` differ) or
  // for a named expression (its name is a binding of its own).
  let declared = 0;
  {
    const fresh = freshProgram(ast);
    const facts = writeOnceFacts(fresh);
    const freshDyn = dynamicScopes(fresh);
    for (const fact of facts.values()) {
      const fe = fact.value;
      if (!t.isFunctionExpression(fe) || fe.id) continue;
      const b = fact.binding;
      if (b.kind !== 'var' || freshDyn.observesBinding(b)) continue;
      // Only a function that is just called (`f(…)`, `new f(…)`): one whose
      // value escapes keeps the spelling other passes match it by (B09d's thunks).
      if (!b.referencePaths.every((r) => (r.parentPath?.isCallExpression() || r.parentPath?.isNewExpression()) && r.parentPath.node.callee === r.node)) continue;
      const owner = b.scope.path;
      if (!owner.isFunction() || fact.statement.parentPath?.node !== owner.node.body) continue;
      const name = b.identifier.name;
      const decl = t.functionDeclaration(t.identifier(name), fe.params, fe.body, fe.generator, fe.async);
      try {
        if (fact.assignment) {
          fact.statement.replaceWith(decl);
          if (b.path.isVariableDeclarator() && !b.path.node.init) {
            const vd = b.path.parentPath as NodePath<t.VariableDeclaration>;
            if (vd.node.declarations.length === 1) vd.remove();
            else b.path.remove();
          }
        } else {
          const vd = fact.statement as NodePath<t.VariableDeclaration>;
          if (vd.node.declarations.length !== 1) continue;
          vd.replaceWith(decl);
        }
        declared++;
      } catch {
        /* already detached */
      }
    }
  }
  const total = dropped + sunk + declared;
  log.pass(
    'b17f',
    'declarationTidy',
    total,
    'statements',
    total ? `${dropped} redundant, ${sunk} declarations sunk, ${declared} functions declared` : undefined
  );
  return total;
}

// ── B04b: bitwise operand literals ───────────────────────────────────────────

const BITWISE_OPS = new Set(['|', '&', '^', '<<', '>>', '>>>']);
const BITWISE_ASSIGN_OPS = new Set(['|=', '&=', '^=', '<<=', '>>=', '>>>=']);

/**
 * Bitwise operators apply ToInt32/ToUint32 to both operands, so a fractional
 * literal operand (`x >>> 6.74`, `128.26 | y`, `m & 255.04`) is noise: the
 * truncated integer behaves identically.
 */
function passBitwiseLiterals(ast: t.File, log: Logger): number {
  let n = 0;
  const fix = (node: t.Node | null | undefined): t.Expression | null => {
    if (!t.isNumericLiteral(node)) return null;
    const v = node.value;
    if (!Number.isFinite(v) || Number.isInteger(v)) return null;
    const i = v | 0;
    return i < 0 ? t.unaryExpression('-', t.numericLiteral(-i)) : t.numericLiteral(i);
  };
  traverse(ast, {
    BinaryExpression(p) {
      if (!BITWISE_OPS.has(p.node.operator)) return;
      const l = fix(p.node.left);
      if (l) {
        p.node.left = l;
        n++;
      }
      const r = fix(p.node.right);
      if (r) {
        p.node.right = r;
        n++;
      }
    },
    AssignmentExpression(p) {
      if (!BITWISE_ASSIGN_OPS.has(p.node.operator)) return;
      const r = fix(p.node.right);
      if (r) {
        p.node.right = r;
        n++;
      }
    },
  });
  log.pass('b04b', 'bitwiseLiterals', n);
  return n;
}

// ── B13c: switch dispatcher over a literal order ─────────────────────────────

/** `"a|b".split("|")` or `["a", "b"]` → string[]. */
function literalStringList(node: t.Node | null | undefined): string[] | null {
  if (!node) return null;
  if (t.isArrayExpression(node)) {
    const out: string[] = [];
    for (const e of node.elements) {
      if (!t.isStringLiteral(e)) return null;
      out.push(e.value);
    }
    return out;
  }
  if (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    staticMemberKey(node.callee) === 'split' &&
    t.isStringLiteral(node.callee.object) &&
    node.arguments.length === 1 &&
    t.isStringLiteral(node.arguments[0])
  )
    return node.callee.object.value.split(node.arguments[0].value);
  return null;
}

/**
 * `while (true) { switch (order[i++]) { case "0": …; continue; … } break; }`
 * in any of its spellings — `for (o = "2|0|1".split("|"), i = 0; !![];)`, a
 * `var` or assignment seed just before the loop, cases ending in `continue`,
 * `break`, `return` or `throw`, case fall-through, repeated order entries.
 *
 * The dispatch is fully determined by the literal order, so the loop is
 * replaced by the statements it would execute, in order. Bails out whenever a
 * case could jump somewhere this simulation does not model (a nested
 * `break`/`continue` aimed at the dispatcher, block-scoped declarations, a
 * `default` arm) or the order/index bindings are used for anything else.
 */
function passSwitchDispatcher(ast: t.File, log: Logger): number {
  const program = freshProgram(ast);
  const dyn = dynamicScopes(program);
  type Job = { loop: NodePath; out: t.Statement[]; seeds: NodePath[] };
  const jobs: Job[] = [];

  const truthy = (e: t.Expression | null | undefined) => {
    if (!e) return true;
    if (!isPurelyLiteral(e)) return false;
    const r = evalPure(e);
    return r.ok && !!r.value;
  };

  /** Statement-level jump that escapes `stmt` toward the dispatcher. */
  const escapesDispatcher = (stmt: t.Statement): boolean => {
    let bad = false;
    const scan = (node: t.Node, loops: number, switches: number) => {
      if (bad) return;
      if (t.isFunction(node) || t.isClass(node)) return;
      if (t.isBreakStatement(node) && !node.label && loops === 0 && switches === 0) bad = true;
      if (t.isContinueStatement(node) && !node.label && loops === 0) bad = true;
      const l = t.isLoop(node) ? 1 : 0;
      const s = t.isSwitchStatement(node) ? 1 : 0;
      const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
      for (const k of keys) {
        const child = (node as unknown as Record<string, unknown>)[k];
        if (Array.isArray(child)) {
          for (const c of child)
            if (c && typeof c.type === 'string') scan(c as t.Node, loops + l, switches + s);
        } else if (child && typeof (child as t.Node).type === 'string')
          scan(child as t.Node, loops + l, switches + s);
      }
    };
    scan(stmt, 0, 0);
    return bad;
  };

  program.traverse({
    'ForStatement|WhileStatement'(p) {
      const loop = p.node as t.ForStatement | t.WhileStatement;
      if (t.isForStatement(loop) && loop.update) return;
      if (!truthy(loop.test)) return;
      if (p.parentPath?.isLabeledStatement()) return;
      if (!t.isBlockStatement(loop.body)) return;
      const body = loop.body.body.filter((s) => !t.isEmptyStatement(s));
      if (body.length !== 2 || !t.isSwitchStatement(body[0])) return;
      if (!t.isBreakStatement(body[1]) || body[1].label) return;
      const sw = body[0];
      const d = sw.discriminant;
      if (!t.isMemberExpression(d) || !d.computed || !t.isIdentifier(d.object)) return;
      if (!t.isUpdateExpression(d.property, { operator: '++', prefix: false })) return;
      if (!t.isIdentifier(d.property.argument)) return;
      const ordName = d.object.name;
      const idxName = d.property.argument.name;
      if (ordName === idxName) return;

      const ordB = p.scope.getBinding(ordName);
      const idxB = p.scope.getBinding(idxName);
      if (!ordB || !idxB) return;

      // Seeds: in the for-init, or the statements immediately before the loop.
      let order: string[] | null = null;
      let start: number | null = null;
      const seedPaths: NodePath[] = [];
      const seedNodes = new Set<t.Node>();
      const takeSeed = (
        name: string,
        value: t.Expression | null | undefined,
        node: t.Node
      ): boolean => {
        if (name === ordName && order === null) {
          order = literalStringList(value);
          if (order) seedNodes.add(node);
          return order !== null;
        }
        if (name === idxName && start === null) {
          const r = value && isPurelyLiteral(value) ? evalPure(value) : { ok: false, value: 0 };
          if (r.ok && typeof r.value === 'number' && Number.isInteger(r.value) && r.value >= 0) {
            start = r.value;
            seedNodes.add(node);
            return true;
          }
        }
        return false;
      };
      const fromExpr = (e: t.Node | null | undefined, holder: t.Node) => {
        for (const x of t.isSequenceExpression(e) ? e.expressions : e ? [e] : [])
          if (t.isAssignmentExpression(x, { operator: '=' }) && t.isIdentifier(x.left))
            takeSeed(x.left.name, x.right, holder === x ? x : x);
      };
      if (t.isForStatement(loop) && loop.init) {
        if (t.isVariableDeclaration(loop.init)) {
          for (const dcl of loop.init.declarations)
            if (t.isIdentifier(dcl.id)) takeSeed(dcl.id.name, dcl.init, dcl);
        } else fromExpr(loop.init, loop.init);
      }
      // Up to two preceding statements may carry the remaining seeds.
      let prev = p.getPrevSibling();
      for (let k = 0; k < 2 && (order === null || start === null) && prev?.node; k++) {
        const node = prev.node;
        let used = false;
        if (
          t.isExpressionStatement(node) &&
          t.isAssignmentExpression(node.expression, { operator: '=' }) &&
          t.isIdentifier(node.expression.left)
        )
          used = takeSeed(node.expression.left.name, node.expression.right, node.expression);
        else if (t.isVariableDeclaration(node)) {
          // `var order = […], i = 0, out = [];` — take the seed declarators,
          // leave the others where they are.
          const decls = prev.get('declarations') as NodePath<t.VariableDeclarator>[];
          for (const dp of decls)
            if (t.isIdentifier(dp.node.id) && takeSeed(dp.node.id.name, dp.node.init, dp.node)) {
              seedPaths.push(dp);
              used = true;
            }
          if (!used) break;
          prev = prev.getPrevSibling();
          continue;
        }
        if (!used) break;
        seedPaths.push(prev);
        prev = prev.getPrevSibling();
      }
      if (order === null || start === null) return;
      const ord: string[] = order;

      // The order and index must exist only to drive this dispatcher.
      const ordRefs = ordB.referencePaths.filter((r) => r.node !== d.object);
      const idxRefs = idxB.referencePaths.filter(
        (r) => r.node !== (d.property as t.UpdateExpression).argument
      );
      if (ordRefs.length || idxRefs.length) return;
      const okWrite = (v: NodePath) =>
        v.node === d.property ||
        seedNodes.has(v.node) ||
        (v.isVariableDeclarator() && seedNodes.has(v.node));
      if (!ordB.constantViolations.every(okWrite) || !idxB.constantViolations.every(okWrite))
        return;
      if (ordB.kind === 'var' || ordB.kind === 'let' || ordB.kind === 'const')
        if (
          !seedNodes.has(ordB.path.node) &&
          ordB.path.isVariableDeclarator() &&
          ordB.path.node.init
        )
          return;

      // Simulate.
      const caseOf = new Map<string, number>();
      for (let i = 0; i < sw.cases.length; i++) {
        const c = sw.cases[i];
        if (!c.test) return; // `default` would also catch the exhausted order
        if (t.isStringLiteral(c.test)) {
          if (!caseOf.has(c.test.value)) caseOf.set(c.test.value, i);
        } else if (!isPurelyLiteral(c.test)) return; // side-effecting / dynamic test
      }
      for (const c of sw.cases)
        for (const s of c.consequent)
          if (
            (t.isVariableDeclaration(s) && s.kind !== 'var') ||
            t.isClassDeclaration(s) ||
            t.isFunctionDeclaration(s)
          )
            return;

      const out: t.Statement[] = [];
      // Keep unrelated for initializers, in their original order. Replacing
      // the entire loop must not discard work such as `out = []`.
      if (t.isForStatement(loop) && loop.init) {
        if (t.isVariableDeclaration(loop.init)) {
          const rest = loop.init.declarations.filter((decl) => !seedNodes.has(decl));
          if (rest.length)
            out.push(
              t.variableDeclaration(
                loop.init.kind,
                rest.map((decl) => t.cloneNode(decl, true))
              )
            );
        } else {
          const initializers = t.isSequenceExpression(loop.init)
            ? loop.init.expressions
            : [loop.init];
          for (const expr of initializers)
            if (!seedNodes.has(expr)) out.push(t.expressionStatement(t.cloneNode(expr, true)));
        }
      }
      let k = start as number;
      for (let steps = 0; ; steps++) {
        if (steps > 4096) return;
        if (k >= ord.length) break;
        const ci = caseOf.get(ord[k++]);
        if (ci === undefined) break; // no arm: falls to the trailing `break`
        let next: 'continue' | 'stop' | null = null;
        for (let c = ci; c < sw.cases.length && !next; c++) {
          for (const s of sw.cases[c].consequent) {
            if (t.isContinueStatement(s) && !s.label) {
              next = 'continue';
              break;
            }
            if (t.isBreakStatement(s) && !s.label) {
              next = 'stop';
              break;
            }
            if (escapesDispatcher(s)) return;
            out.push(t.cloneNode(s, true));
            if (t.isReturnStatement(s) || t.isThrowStatement(s)) {
              next = 'stop';
              break;
            }
          }
        }
        if (next !== 'continue') break;
      }
      // Reordering is safe, but the seeds are rewritten by name: a direct
      // `eval` in scope could read them mid-dispatch.
      if (dyn.observes(p.scope)) return;
      jobs.push({ loop: p, out, seeds: seedPaths });
    },
  });

  let n = 0;
  for (const job of jobs) {
    try {
      for (const s of job.seeds) s.remove();
      if (job.out.length) job.loop.replaceWithMultiple(job.out);
      else job.loop.remove();
      n++;
    } catch {
      /**/
    }
  }
  log.pass('b13c', 'switchDispatcher', n);
  return n;
}

// ── B15b: statement-level conditionals → if ──────────────────────────────────

/**
 * `a ? b : c;` → `if (a) { b } else { c }`, `a && b;` → `if (a) { b }`,
 * `a || b;` → `if (!a) { b }`, and `if (!!x)` → `if (x)`.
 *
 * A conditional that assigns the enclosing switch's discriminant is a
 * state-machine transition B13b recognises in exactly that form — leave it.
 */
function passConditionalStatements(ast: t.File, log: Logger): number {
  let n = 0;
  const toBlock = (e: t.Expression): t.BlockStatement =>
    t.blockStatement(
      (t.isSequenceExpression(e) ? e.expressions : [e]).map((x) => t.expressionStatement(x))
    );
  const assignsDiscriminant = (p: NodePath, e: t.Node): boolean => {
    const sc = p.findParent((x) => x.isSwitchCase());
    const sw = sc?.parentPath;
    if (!sw?.isSwitchStatement() || !t.isIdentifier(sw.node.discriminant)) return false;
    const name = sw.node.discriminant.name;
    let hit = false;
    walkNode(e, (nd) => {
      if (t.isAssignmentExpression(nd) && t.isIdentifier(nd.left, { name })) hit = true;
    });
    return hit;
  };
  traverse(ast, {
    ExpressionStatement(p) {
      const e = p.node.expression;
      if (t.isConditionalExpression(e)) {
        if (assignsDiscriminant(p, e)) return;
        p.replaceWith(t.ifStatement(e.test, toBlock(e.consequent), toBlock(e.alternate)));
        n++;
      } else if (t.isLogicalExpression(e) && (e.operator === '&&' || e.operator === '||')) {
        if (assignsDiscriminant(p, e)) return;
        const test = e.operator === '&&' ? e.left : t.unaryExpression('!', e.left);
        p.replaceWith(t.ifStatement(test, toBlock(e.right)));
        n++;
      }
    },
    IfStatement(p) {
      const test = p.node.test;
      if (
        t.isUnaryExpression(test, { operator: '!' }) &&
        t.isUnaryExpression(test.argument, { operator: '!' })
      ) {
        p.node.test = test.argument.argument;
        n++;
      }
      // `else { if (…) … }` → `else if (…) …` (a lone `if` declares nothing).
      const alt = p.node.alternate;
      if (t.isBlockStatement(alt) && alt.body.length === 1 && t.isIfStatement(alt.body[0])) {
        p.node.alternate = alt.body[0];
        n++;
      }
    },
  });
  log.pass('b15b', 'conditionalStatements', n);
  return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage C — VM eval hooking
// ─────────────────────────────────────────────────────────────────────────────

// Stage C executes the *whole* program in a sandbox, so a payload that merely
// allocates or spins can stall the run: `Script.runInContext`'s `timeout` only
// preempts between bytecode boundaries and cannot interrupt a VM stuck inside a
// single huge allocation. Two cheap guards keep the stage opportunistic:
// it must plausibly pay off, and it must be small enough to be safe.
const VM_EVAL_MAX_BYTES = 400_000;
const VM_EVAL_TIMEOUT_MS = 5000;

/** Dynamic-eval constructs Stage C could actually capture. */
const VM_EVAL_TRIGGER = /\b(?:eval|Function|setTimeout|setInterval|atob|unescape)\s*\(/;

function vmEvalHook(code: string, log: Logger): string | null {
  // No dynamic-eval construct anywhere → nothing for this stage to capture.
  if (!VM_EVAL_TRIGGER.test(code)) {
    log.skip(null, 'vmEvalHook', 'no dynamic eval constructs');
    return null;
  }
  if (code.length > VM_EVAL_MAX_BYTES) {
    log.skip(
      null,
      'vmEvalHook',
      `${code.length} bytes > ${VM_EVAL_MAX_BYTES} limit, executing a payload this large risks stalling the run`
    );
    return null;
  }

  const captured: string[] = [];
  const artifacts: string[] = [];

  function buildSandbox() {
    const sb: Record<string, unknown> = Object.create(null);
    const captureStr = (src: unknown) => {
      if (typeof src === 'string') captured.push(src);
      return '';
    };
    const captureArtifact = (src: unknown) => {
      if (typeof src === 'string') artifacts.push(src);
      return '';
    };
    const fakeFile = {
      Write: captureArtifact,
      WriteLine: captureArtifact,
      ReadAll: () => '',
      ReadLine: () => '',
      Close: () => {},
    };
    const fakeObject = {
      Run: captureArtifact,
      Exec: captureArtifact,
      ExpandEnvironmentStrings: (s: unknown) => (typeof s === 'string' ? s : ''),
      CreateShortcut: () => ({}),
      OpenTextFile: () => fakeFile,
      CreateTextFile: () => fakeFile,
      GetFile: () => ({}),
      GetFolder: () => ({ Files: [], SubFolders: [] }),
      FileExists: () => false,
      FolderExists: () => false,
      CreateFolder: () => ({}),
      DeleteFile: () => {},
      DeleteFolder: () => {},
      BuildPath: (...parts: unknown[]) => parts.filter((p) => typeof p === 'string').join('/'),
      open: captureArtifact,
      send: captureArtifact,
      setRequestHeader: () => {},
      responseText: '',
      status: 404,
    };
    Object.assign(sb, {
      eval: captureStr,
      Function: function (...args: unknown[]) {
        const body = args[args.length - 1];
        if (typeof body === 'string') captured.push(body);
        return () => undefined;
      },
      setTimeout: (fn: unknown) => {
        if (typeof fn === 'string') captured.push(fn);
        return 0;
      },
      setInterval: (fn: unknown) => {
        if (typeof fn === 'string') captured.push(fn);
        return 0;
      },
      clearTimeout: () => {},
      clearInterval: () => {},
      String,
      Number,
      Boolean,
      Array,
      Object,
      Math,
      JSON,
      RegExp,
      Date,
      Error,
      TypeError,
      RangeError,
      SyntaxError,
      ReferenceError,
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      Symbol: typeof Symbol !== 'undefined' ? Symbol : () => ({}),
      Promise: { resolve: () => ({}), reject: () => ({}), all: () => ({}) },
      Map,
      Set,
      WeakMap,
      WeakSet,
      encodeURIComponent,
      decodeURIComponent,
      encodeURI,
      decodeURI,
      atob: (s: string) => Buffer.from(s, 'base64').toString('utf8'),
      btoa: (s: string) => Buffer.from(s, 'utf8').toString('base64'),
      Buffer,
      console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {} },
      navigator: { userAgent: 'Mozilla/5.0' },
      location: { href: '', hostname: '' },
      WScript: {
        Echo: captureArtifact,
        Quit: () => {},
        Sleep: () => {},
        CreateObject: () => fakeObject,
        Arguments: { length: 0 },
        ScriptFullName: 'sample.js',
        ScriptName: 'sample.js',
      },
      ActiveXObject: function () {
        return fakeObject;
      },
      process: { env: {}, argv: [], exit: () => {} },
      require: () => ({}),
      module: { exports: {} },
      exports: {},
      __dirname: '/',
      __filename: '/script.js',
      undefined: undefined,
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const s = sb as any;
    s.window = sb;
    s.self = sb;
    s.global = sb;
    s.globalThis = sb;
    s.document = Object.create(null);
    return sb;
  }

  try {
    const { Script, createContext } = vm;
    const ctx = createContext(buildSandbox());

    // Primary attempt — run code directly
    // Fallback: if duplicate `var` declarations crash strict-mode VM, wrap in IIFE
    // which creates a function scope where `var` hoisting makes duplicates harmless.
    let ran = false;
    try {
      new Script(code).runInContext(ctx, { timeout: VM_EVAL_TIMEOUT_MS });
      ran = true;
    } catch (e1) {
      const msg1 = e1 instanceof Error ? e1.message : String(e1);
      if (/already been declared/i.test(msg1)) {
        try {
          new Script('(function(){\n' + code + '\n})();').runInContext(ctx, {
            timeout: VM_EVAL_TIMEOUT_MS,
          });
          ran = true;
          log.note('vm-eval-hook: iife fallback succeeded', 'duplicate var declarations');
        } catch {
          /* ignore secondary failure */
        }
      }
      if (!ran) throw e1;
    }

    if (captured.length > 0) {
      log.pass(null, 'vmEvalHook', captured.length, 'eval() payload(s) captured');
      return captured.reduce((a, b) => (a.length >= b.length ? a : b));
    }
    if (artifacts.length > 0) {
      log.pass(null, 'vmEvalHook', artifacts.length, 'wsh/browser artifact string(s) captured');
      return artifacts.join('\n');
    }
    log.pass(null, 'vmEvalHook', 0, 'payloads captured', 'sandbox ran clean');
  } catch (e) {
    log.fail(
      null,
      'vmEvalHook',
      `sandbox exec failed: ${(e instanceof Error ? e.message : String(e)).slice(0, 120)}`
    );
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass registry & sweep order
// ─────────────────────────────────────────────────────────────────────────────

type PassFn = (ast: t.File, log: Logger) => number;

const PASS_FN_MAP: Record<string, PassFn> = {
  stringEscapeNorm: passStringEscapeNorm,
  functionConstructor: passFunctionConstructor, // B03c — Function("…","body") → IIFE
  evalLiteral: passEvalLiteral, // B03d
  rgf: passRgf, // B03e — reduced-global-function (eval-embedded functions)
  rgfThunk: passRgfThunk, // B03f — collapse RGF forwarding thunks into their real fn
  cffRecover: passCffRecover, // B13d — js-confuser control-flow flattening (see ./cff) — eval("<expr>") → <expr>
  hexStringDecoding: passLiteralNormalise,
  nativeAlias: passNativeAlias,
  globalObjectAlias: passGlobalObjectAlias,
  pureNativeCalls: passPureNativeCalls,
  pureNumericFns: passPureNumericFns,
  fromCharCode: passFromCharCode,
  atobDecoding: passAtob,
  bufferDecoding: passBufferDecoding,
  constantFolding: passConstantFolding,
  closureStringDecoding: passClosureStringDecoder, // B05a — closure/factory pattern
  stringDecoding: passStringDecoder,
  poolDecoding: passPoolDecoder,
  memberExpressionSimplification: passMemberSimplify,
  dispatchTableInlining: passDispatchTable,
  identityTable: passIdentityTable,
  constantPropagation: passConstantPropagation,
  proxyFunctionRemoval: passProxyFunctions,
  noopCalls: passNoopCalls, // B09b — `F(a, b);` of a do-nothing F → `a; b;`
  movedDeclarations: passMovedDeclarations, // B00e — `if (!p) p = function…` params → declarations
  concealedGlobals: passConcealedGlobals, // B01e — js-confuser global probe + switch table
  concealedStrings: passConcealedStrings, // B05d — js-confuser string pool + decoder
  dispatchers: passDispatchers, // B09d — dispatcher tables back to declarations and calls
  flatFunctions: passFlatFunctions, // B09c — flattened bodies back into their wrappers
  maskedVariables: passMaskedVariables, // B00d — rest-parameter slots → params and locals
  functionInlining: passPureNativeCalls, // superseded passNumericCoercions (B10b covers B10)
  opaquePredicateRemoval: passOpaquePredicates,
  scopedConstFold: passScopedConstFold,
  deadCodeElimination: passDeadCode,
  controlFlowFlattening: passControlFlowUnflatten,
  stateMachineUnflatten: passStateMachineUnflatten,
  selfDefending: passSelfDefending,
  commaSequence: passCommaSequence,
  typeofSimplify: passTypeofSimplify,
  unusedVars: passUnusedVars,
  deadFunctions: passDeadFunctions,
  booleanSimplify: passBooleanSimplify,
  deduplicateVarDecls: passDeduplicateVarDecls,
  renameMangled: passRenameMangled,
  statementNormalize: passStatementNormalize,
  paramLocals: passParamLocals,
  bindingPropagation: passBindingPropagation,
  objectTables: passObjectTables,
  literalArrays: passLiteralArrays, // B07d — frozen literal index tables
  closedFunctionEval: passClosedFunctionEval,
  bitwiseLiterals: passBitwiseLiterals,
  switchDispatcher: passSwitchDispatcher,
  conditionalStatements: passConditionalStatements,
  deadStores: passDeadStores,
  singleUseTemps: passSingleUseTemps,
  iifeFlatten: passIifeFlatten, // B17e — argument-less IIFE statements inside functions
  declarationTidy: passDeclarationTidy, // B17f — `var x; x = 1;` → `var x = 1;`
  confuserNames: passConfuserNames, // B19b — `__p_XXXX_meaning` → `meaning`
  locks: passLocks, // B20 — js-confuser's self-text checks, resolved from the original text
};

const PASS_ORDER = [
  'functionConstructor', // B03c — expose a program hidden in a Function() string
  'evalLiteral', // B03d — drop literal direct eval so binding passes stay enabled
  'rgf', // B03e — recover functions embedded as eval source behind a guard
  'rgfThunk', // B03f — collapse the forwarding thunks RGF leaves behind
  'cffRecover', // B13d — simulate js-confuser dispatchers, rebuild if/while, lower scope frames
  'stringEscapeNorm',
  'hexStringDecoding',
  'dispatchers', // B09d — before B00b splits `(PAYLOAD = […], D("k"))` into statements
  'statementNormalize', // B00b — sequences out of statement heads, literal assembly
  'flatFunctions', // B09c — `return F(o, args)` wrappers get their bodies back
  'maskedVariables', // B00d — `S[0]`, `S[-3]`, `S.k` slots of a rest param → names
  'movedDeclarations', // B00e — surplus params guarded with `if (!p) p = function…` → declarations
  'paramLocals', // B00c — overwritten-before-read params → var (needs B00b's statements)
  'noopCalls', // B09b — unpack the AST scrambler's `F(a, b, c);` into statements
  'concealedGlobals', // B01e — js-confuser's global probe → globalThis, table lookups → reads
  'locks', // B20 — integrity lock / anti-beautify test settled from the original source text
  'globalObjectAlias', // B01d — `var p = window` → drop the p. prefix first
  'nativeAlias', // B01b — unmask `var s = String.fromCharCode` before B02/B03
  'pureNumericFns', // B01c — collapse bitwise-identity fns hiding charcodes
  'fromCharCode',
  'atobDecoding',
  'bufferDecoding',
  'constantFolding', // round 1 — fold hex/octal numerics first
  'closureStringDecoding', // B05a — run BEFORE constantFolding has destroyed arithmetic
  'stringDecoding', // B05  — simple top-level array pattern (fallback)
  'poolDecoding', // B05b — pool + transforming decoder, e.g. atob(pool[i])
  'concealedStrings', // B05d — js-confuser `STR(start, length)` over one string pool
  'bindingPropagation', // B08b — write-once aliases (`mW = Q`) and literals → value
  'objectTables', // B07c — frozen index/proxy tables: `uW.L` → 602, `o.f(a,b)` → a < b
  'literalArrays', // B07d — `K[13]` → the element, for tables nothing can mutate
  'deadStores', // B17c — drop the alias stores B08b emptied so B05c sees no leaks
  'closedFunctionEval', // B05c — VM-fold calls into self-contained decoder groups
  'pureNumericFns', // B01c again — new literal args exposed by folding
  'fromCharCode', // B02 again — charcodes unmasked by pureNumericFns
  'pureNativeCalls', // B10b — Math.floor(135.61) → 135, feeding the predicates
  'constantFolding', // round 2 — fold after string inlining
  'bitwiseLiterals', // B04b — `x >>> 6.74` → `x >>> 6`
  'closureStringDecoding', // B05a again — picks up any proxy-wrapped call sites
  'evalLiteral', // B03d again — arguments that only became literal after decoding
  'memberExpressionSimplification',
  'objectTables', // B07c again — keys are static now that strings are decoded
  'literalArrays', // B07d again — indices that only became literal after folding
  'dispatchTableInlining',
  'identityTable', // B07b — L[a][b] identity constants → integers
  'constantPropagation', // inline write-once literal vars
  'pureNativeCalls', // B10b again — args now literal after propagation
  'constantFolding', // round 3 — fold expressions using inlined constants
  'pureNumericFns', // B01c — identity fns over now-literal constants
  'proxyFunctionRemoval',
  'functionInlining',
  'opaquePredicateRemoval',
  'scopedConstFold',
  'deadCodeElimination',
  'controlFlowFlattening',
  'switchDispatcher', // B13c — split-order dispatchers in for/while form
  'stateMachineUnflatten',
  'selfDefending',
  'commaSequence',
  'conditionalStatements', // B15b — after B13b, which matches the expression form
  'typeofSimplify',
  'booleanSimplify', // B16b — cond ? true : false → !!cond
  'unusedVars',
  'deadFunctions', // B17b — drop helpers whose call sites were all inlined
  'deadStores', // B17c — stores/declarations nothing reads any more
  'singleUseTemps', // B17d — `x = E; return x;` → `return E;`
  'iifeFlatten', // B17e — `(function(){ … })()` inside a function body → its statements
  'declarationTidy', // B17f — redundant `x = undefined`, declarations sunk into first assignment
  'deduplicateVarDecls', // clean up duplicate var names before rename
  'confuserNames', // B19b — strip js-confuser's generated-name prefix once the transform is undone
  'renameMangled', // rename last — after all structural passes
];

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export async function deobfuscate(
  code: string,
  options: DeobfuscationOptions
): Promise<DeobfuscationResult> {
  const onLog = options.onLog;
  const log = createLogger({ onEntry: onLog ? (entry, line) => onLog(line, entry) : undefined });
  const parsingErrors: string[] = [],
    passesApplied: string[] = [],
    errors: string[] = [];
  let currentCode = code,
    success = true;

  log.title('deobfuscate', `${options.enabledPasses.length} passes · ${code.length} bytes`);
  // The input text, as functions created from it will print themselves.
  const runSourceFacts: SourceFacts = { texts: [code], newlineFree: functionsNewlineFree(code) };

  // ── Stage A ───────────────────────────────────────────────────────────────
  log.stage('a · pre-parse');
  const preEnabled = new Set(options.enabledPasses);

  if (preEnabled.has('junkTokenRemoval')) {
    const before = currentCode.length;
    currentCode = prePassJunkTokenRemoval(currentCode, log);
    if (currentCode.length !== before) passesApplied.push('junkTokenRemoval');
  }
  if (preEnabled.has('atobDecoding') || preEnabled.has('hexStringDecoding')) {
    const before = currentCode.length;
    currentCode = prePassBase64(currentCode, log);
    if (currentCode.length !== before) passesApplied.push('atobDecoding');
  }

  // ── Initial parse ─────────────────────────────────────────────────────────
  let { ast, warnings: parseWarnList, hardErrors: parseHardList } = safeParse(currentCode);
  const structuredParseErrors: ParseError[] = [...parseHardList];
  const structuredParseWarnings: ParseError[] = [...parseWarnList];
  const parseWarnings: string[] = parseWarnList.map((w) => w.message);

  if (parseWarnList.length > 0) {
    log.warn('parse warnings', `${parseWarnList.length} browser-tolerant`);
    for (const w of parseWarnList)
      log.note(w.message.split('\n')[0], w.line ? `${w.line}:${w.col ?? 0}` : undefined);
  }

  if (parseHardList.length > 0) {
    log.error('parse errors', String(parseHardList.length));
    for (const e of parseHardList) {
      log.note(e.message.split('\n')[0], e.line ? `${e.line}:${e.col ?? 0}` : undefined);
      parsingErrors.push(e.message);
    }

    if (options.autoFix) {
      let fixed = currentCode.replace(/^\uFEFF/, '');
      if (parseHardList.some((e) => e.message.includes("'return' outside"))) {
        fixed = `(function(){\n${fixed}\n})();`;
        log.note('auto-fix', 'iife wrap applied');
      }
      const firstErr = parseHardList[0];
      if (firstErr?.line !== undefined && firstErr.line > 1) {
        const truncated = fixed
          .split('\n')
          .slice(0, firstErr.line - 1)
          .join('\n');
        const r = safeParse(truncated);
        if (r.hardErrors.length === 0) {
          ast = r.ast;
          currentCode = truncated;
          structuredParseWarnings.push(...r.warnings);
          parseWarnings.push(...r.warnings.map((w) => w.message));
          structuredParseErrors.length = 0;
          parsingErrors.length = 0;
          log.note('auto-fix', `truncated at line ${firstErr.line - 1}`);
        }
      }
      if (structuredParseErrors.length > 0 && fixed !== currentCode) {
        const r = safeParse(fixed);
        if (r.hardErrors.length < parseHardList.length) {
          ast = r.ast;
          currentCode = fixed;
          structuredParseErrors.length = 0;
          structuredParseErrors.push(...r.hardErrors);
          parsingErrors.length = 0;
          parsingErrors.push(...r.hardErrors.map((e) => e.message));
          structuredParseWarnings.push(...r.warnings);
          parseWarnings.push(...r.warnings.map((w) => w.message));
          log.note('auto-fix', `reduced errors to ${r.hardErrors.length}`);
        }
      }
    }
    if (structuredParseErrors.length > 0)
      log.warn('continuing with partial ast', 'output may be incomplete');
  } else {
    log.ok('parsed', parseWarnList.length ? `${parseWarnList.length} warning(s)` : undefined);
  }

  // ── Stage B ───────────────────────────────────────────────────────────────
  const enabled = new Set(options.enabledPasses);
  // Auto-enable companion passes
  if (enabled.has('stringDecoding')) {
    enabled.add('closureStringDecoding'); // factory/closure pattern — always companion to B05
    enabled.add('fromCharCode');
    enabled.add('atobDecoding');
    enabled.add('bufferDecoding');
  }
  if (enabled.has('atobDecoding')) enabled.add('bufferDecoding');
  if (enabled.has('closureStringDecoding')) {
    enabled.add('stringDecoding');
  }
  if (enabled.has('memberExpressionSimplification')) enabled.add('dispatchTableInlining');
  if (enabled.has('selfDefending')) enabled.add('commaSequence');
  if (enabled.has('proxyFunctionRemoval')) enabled.add('constantPropagation');
  // Always-on passes — prerequisites for correct operation
  enabled.add('stringEscapeNorm');
  enabled.add('deduplicateVarDecls');

  // Direct eval/with can observe bindings absent from the static reference
  // graph. Preserve their declarations, names, and function call boundaries.
  const evalGated = new Set<string>();
  const bindingPasses = [
      'statementNormalize',
      'paramLocals',
      'globalObjectAlias',
      'nativeAlias',
      // Still program-wide in their reasoning: these match shapes or rewrite by
      // name without consulting the scope chain, so one `eval` anywhere can
      // invalidate them. The rest now ask, per binding, whether a direct `eval`
      // is actually in scope, and keep working on the parts of the file it
      // cannot reach — which, in a bundle with one concealed global, is nearly
      // all of it.
      'pureNumericFns',
      'closureStringDecoding',
      'poolDecoding',
      'dispatchTableInlining',
      'identityTable',
      'proxyFunctionRemoval',
      'scopedConstFold',
      'controlFlowFlattening',
      'stateMachineUnflatten',
      // evaluates helpers and literal pools at deobfuscation time; an eval
      // could rewrite either
      'cffRecover',
      'deadFunctions',
      'renameMangled',
  ];
  // Passes switched off while an eval/with is present. Checked again before
  // each such pass runs: an eval can appear mid-run (B03c writing out a
  // `Function("…")` body) as well as go away (B03d inlining a literal one, or
  // B05d decoding a concealed string).
  for (const name of bindingPasses) if (enabled.has(name)) evalGated.add(name);
  let dynamicNow = hasDynamicScope(ast.program);
  if (dynamicNow)
    log.note(
      'binding rewrites limited',
      `${evalGated.size} shape passes off · the rest skip only what an eval can reach`
    );
  const toRunFull = PASS_ORDER.filter((p) => enabled.has(p));

  // Each sweep regenerates the source and re-parses it, so peak memory holds
  // several full ASTs plus Babel's scope tables at once. On a large bundle that
  // is enough to exhaust the heap and have the process killed outright — which
  // surfaces as a silent exit with no output rather than an exception. Large
  // inputs converge in 2–3 sweeps anyway (the bulk of the work lands in the
  // first), so scale the budget down instead of gambling on the allocator.
  const SWEEP_BUDGET_BYTES = 250_000;
  // Small inputs get more sweeps: layered constructs (an alias feeding a table
  // whose keys are decoded strings naming proxy functions that call other proxy
  // tables) peel one layer per sweep, and the loop stops as soon as the output
  // is stable anyway.
  // The budget follows the *current* source: memory scales with the AST being
  // swept, and a large input usually shrinks below the threshold after a sweep
  // or two, from which point it gets the small-input budget.
  const FULL_SWEEPS = 12;
  // Layered inputs (js-confuser's presets stack a dozen transforms, each
  // peeled a sweep or two after the one beneath it) keep shrinking past the
  // usual budget: a sweep that shrank the source earns one more, up to this.
  const HARD_SWEEPS = 48;
  let maxSweeps = currentCode.length > SWEEP_BUDGET_BYTES ? 3 : FULL_SWEEPS;
  if (maxSweeps < FULL_SWEEPS)
    log.note(
      `input is ${currentCode.length} bytes`,
      `limiting to ${maxSweeps} sweeps to bound peak memory`
    );
  for (let sweep = 1; sweep <= maxSweeps; sweep++) {
    let total = 0;
    const sizeBefore = currentCode.length;
    log.sweep(sweep, maxSweeps);
    for (const passName of toRunFull) {
      const fn = PASS_FN_MAP[passName];
      if (!fn) continue;
      if (evalGated.has(passName)) {
        const now = hasDynamicScope(ast.program);
        if (now !== dynamicNow) {
          dynamicNow = now;
          if (now) log.note('binding rewrites limited', 'an eval/with appeared');
          else log.note('binding rewrites restored', 'no eval/with left');
        }
        if (now) continue;
      }
      try {
        setSourceFacts(runSourceFacts);
        // Passes splice statement lists by hand; Babel's cached NodePaths
        // from the previous traversal would then carry stale indices, and a
        // later `traverse` acting on them edits the wrong node.
        traverse.cache.clear();
        const ch = fn(ast, log);
        total += ch;
        if (!passesApplied.includes(passName)) passesApplied.push(passName);
      } catch (err: unknown) {
        const m = err instanceof Error ? err.message : String(err);
        log.fail(null, passName, m);
        errors.push(`${passName}: ${m}`);
      }
    }
    try {
      traverse.cache.clear();
      passCleanup(ast);
    } catch {
      /**/
    }
    log.sum(total, 'changes');
    if (total === 0) {
      log.note('ast stable');
      break;
    }
    // Regenerate after every sweep so `currentCode` always holds the latest good
    // output, then compare against the previous sweep. Some passes report changes
    // idempotently (they re-match a construct without altering the emitted code);
    // once the generated source stops changing, the AST has converged, so stop
    // even though `total > 0`. Beyond avoiding wasted work, this guard is
    // essential on very large inputs: additional sweeps over a deep AST can
    // overflow Babel's native recursion stack and abort the whole process with
    // no output at all.
    // (The last sweep regenerates too: a run that is still shrinking earns
    // another, and a capped one the full budget once it is small enough.)
    {
      let regenerated: string;
      try {
        regenerated = genCode(ast);
      } catch {
        break; // keep the last good currentCode; a failed generate won't improve
      }
      if (regenerated === currentCode) {
        log.note('output stable', 'stopping sweeps');
        break;
      }
      // A sweep whose output does not parse again has a bug in one of its
      // passes. Say so and keep the previous sweep's output: silently going
      // on with the empty program `safeParse` falls back to would present a
      // blank file as the deobfuscation.
      const reparsed = safeParse(regenerated);
      if (reparsed.hardErrors.length) {
        const m = `sweep ${sweep}: regenerated source does not parse (${reparsed.hardErrors[0].message}); keeping sweep ${sweep - 1}'s output`;
        errors.push(m);
        log.note('sweep output unparseable', m);
        ast = safeParse(currentCode).ast;
        break;
      }
      currentCode = regenerated;
      // Shrinking is progress, and the next sweep then works on a smaller AST
      // than one that already went through: one more sweep each time.
      if (maxSweeps < FULL_SWEEPS && currentCode.length <= SWEEP_BUDGET_BYTES) {
        maxSweeps = FULL_SWEEPS;
        log.note(`down to ${currentCode.length} bytes`, `sweep budget raised to ${FULL_SWEEPS}`);
      } else if (sweep === maxSweeps && maxSweeps < HARD_SWEEPS && currentCode.length < sizeBefore) {
        maxSweeps++;
      }
      if (sweep >= maxSweeps) break;
      ast = reparsed.ast;
    }
  }

  let unresolvedEvals = 0;
  try {
    currentCode = genCode(ast);
    // A newline test left unsettled answered "no" in the original (no
    // function text had a newline); pretty-printed, it would answer "yes"
    // and fire its countermeasure. Compact output keeps every answer.
    const left = unsettledSelfChecks(ast);
    if (left.newline && runSourceFacts.newlineFree) {
      currentCode = generate(ast, { comments: true, compact: true, jsescOption: { minimal: true } }).code;
      log.note('self-text checks unsettled', `${left.newline} newline tests · output kept compact`);
    }
    if (left.integrity) {
      const m = `locks: ${left.integrity} integrity lock${left.integrity === 1 ? '' : 's'} unsettled — the output's text no longer hashes to its constant`;
      errors.push(m);
      log.note('self-text checks unsettled', m);
    }
    // A direct eval still fed by computed source means a layer the passes
    // never saw through: whatever it hides (js-confuser's locks included)
    // could not have been settled, so say so.
    t.traverseFast(ast.program, (n) => {
      if (t.isCallExpression(n) && t.isIdentifier(n.callee, { name: 'eval' }) && n.arguments.length === 1 && !t.isStringLiteral(n.arguments[0])) unresolvedEvals++;
    });
    if (unresolvedEvals) log.note('unresolved eval', `${unresolvedEvals} direct eval${unresolvedEvals === 1 ? '' : 's'} with computed source left; the code it hides could not be examined`);
  } catch (e: unknown) {
    errors.push(e instanceof Error ? e.message : String(e));
    success = false;
  }

  // ── Stage C ───────────────────────────────────────────────────────────────
  if (enabled.has('vmEvalHook') || enabled.has('selfDefending')) {
    log.stage('c · vm eval hook');
    const captured = vmEvalHook(currentCode, log);
    if (captured && captured.trim().length > 50) {
      log.note('payload captured', 'recursively deobfuscating');
      const inner = log.child('inner');
      try {
        // Stage C is gated on `vmEvalHook` OR `selfDefending`, so dropping
        // only `vmEvalHook` still re-enters Stage C at the next level and a
        // payload that re-emits itself recurses without bound. Drop both.
        const result = await deobfuscate(captured, {
          ...options,
          enabledPasses: options.enabledPasses.filter(
            (p) => p !== 'vmEvalHook' && p !== 'selfDefending'
          ),
          // The nested run's entries land in our log as they happen, one level
          // deeper and tagged `inner`.
          onLog: (_line, entry) => inner.add(entry),
        });
        currentCode += `\n\n/* === eval() PAYLOAD (recovered) ===\n${result.deobfuscatedCode}\n*/`;
        passesApplied.push('vmEvalHook');
      } catch {
        /**/
      }
    }
  }

  // ── Stage D — JSNice rename / type inference (opt-in, network) ──────────────
  if (options.jsNice?.enabled) {
    log.stage('d · jsnice');
    const before = currentCode;
    const result = await applyJsNice(before, options.jsNice);
    if (result.applied) {
      // Trust nothing: JSNice is ES5-oriented and can mangle modern syntax.
      // Only adopt its output if it still parses; otherwise keep the local code.
      const check = safeParse(result.code);
      if (check.hardErrors.length === 0) {
        currentCode = result.code;
        passesApplied.push('jsNice');
        log.ok(
          'jsnice applied',
          `${before.length} → ${currentCode.length} bytes` +
            `${result.transpiled ? ', via es5 transpile, output is es5 commonjs' : ''}`
        );
      } else {
        log.warn(
          'jsnice result failed to parse',
          `${check.hardErrors.length} error(s), keeping local output`
        );
      }
    } else {
      log.skip(null, 'jsNice', result.reason ?? 'not applied');
    }
  }

  const delta = (1 - currentCode.length / code.length) * 100;
  const red = delta.toFixed(1);
  log.blank();
  log.done(
    `${currentCode.length} bytes`,
    delta >= 0 ? `${delta.toFixed(1)}% smaller` : `${(-delta).toFixed(1)}% larger`
  );
  if (errors.length > 0) log.warn(`${errors.length} non-fatal error(s)`);

  return {
    deobfuscatedCode: currentCode,
    passesApplied,
    log: log.lines,
    entries: log.entries,
    parsingErrors,
    parseWarnings,
    structuredParseErrors,
    structuredParseWarnings,
    metadata: { originalSize: code.length, finalSize: currentCode.length, reductionPercent: red, unresolvedEvals },
    success,
    errors,
  };
}
