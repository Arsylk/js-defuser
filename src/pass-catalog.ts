/**
 * What the engine runs, described for people and user interfaces.
 *
 * `PIPELINE` is the ground truth: the stages in the order `deobfuscate` goes
 * through them, each pass where it first runs within its stage, with the id
 * the pass log prints for it (`b05d`, `b13d`, …), how many times a sweep
 * runs it, and whether the default run includes it. A test keeps stage B in
 * step with the engine's own `PASS_ORDER` and the defaults in step with
 * `DEFAULT_ENABLED_PASSES`. `PASS_CATALOG` is the same list flattened;
 * `BASE_PASSES` / `STRUCTURAL_PASSES` are the older two-group view.
 */
export interface PassInfo {
  id: string;
  name: string;
  description: string;
  enabled_by_default: boolean;
  pass_order: number;
}

export interface PipelineStep extends PassInfo {
  /** the id the pass log prints (`b05d`); `null` for the eval hook, which logs without one */
  logId: string | null;
  /** how many times one sweep runs it (some passes are scheduled again after folding) */
  runs: number;
  stage: 'a' | 'b' | 'c';
}

export interface PipelineStage {
  id: 'a' | 'b' | 'c';
  title: string;
  summary: string;
  steps: PipelineStep[];
}

const DESCRIPTIONS: Record<string, string> = {
  'junk-token-removal':
    'Strip a high-frequency junk token padded into identifiers and strings (frequency analysis on the raw text; opt-in — it can damage ordinary code).',
  'function-constructor': 'Write out Function("args", "body") calls statically, without executing them.',
  'eval-literal': 'Replace direct eval of a literal expression with the expression.',
  'rgf': 'Recover a function embedded as eval source behind a provably-true guard (js-confuser RGF).',
  'rgf-thunk': 'Collapse the forwarding thunk RGF leaves into the real function body.',
  'cff-recover': 'Rebuild code flattened into a js-confuser state-machine dispatcher, including its scope frames.',
  'string-escape-norm': 'Turn \\x48\\x65 and \\u0048 escapes back into plain characters; also decodes raw atob("…") literals before parsing.',
  'hex-string-decoding': 'Normalize hexadecimal and octal numeric literals to decimal.',
  'dispatchers': 'Restore function declarations and calls routed through a js-confuser dispatcher table.',
  'statement-normalize': 'Normalize statement heads, sequence expressions, and loop setup.',
  'flat-functions': 'Move flattened function bodies back into their wrappers and unwrap accessor objects.',
  'masked-variables': 'Recover parameters and locals stored as slots of a rest parameter.',
  'moved-declarations': 'Turn never-supplied parameters guarded by if-not-set assignments back into declarations.',
  'param-locals': 'Recover local variables hidden in overwritten function parameters.',
  'noop-calls': 'Expand statement-level calls of functions that do nothing into their arguments.',
  'concealed-globals': 'Resolve js-confuser global-object probes and switch-table global lookups.',
  'locks': 'Settle js-confuser integrity and anti-beautify checks the original source text decides.',
  'global-object-alias': 'Drop `var w = window` style aliases of the global object from member chains.',
  'native-alias': 'Unmask aliases of native functions such as `var s = String.fromCharCode`.',
  'pure-numeric-fns': 'Collapse bitwise-identity helper functions that hide character codes.',
  'from-char-code': 'Inline literal String.fromCharCode calls.',
  'atob-decoding': 'Decode literal atob/btoa calls (and raw atob("…") literals before parsing).',
  'buffer-decoding': 'Decode literal Buffer.from(...).toString(...) base64 and hex helpers.',
  'constant-folding': 'Fold pure arithmetic, logical, and conditional expressions.',
  'closure-string-decoding':
    'Run the javascript-obfuscator factory/shuffler/decoder triad in a sandbox to resolve string calls (opt-in; the default passes cover it).',
  'string-decoding': 'Decode javascript-obfuscator string arrays and rotating arrays.',
  'pool-decoding': 'Resolve pool decoders that transform entries, such as atob(pool[i]).',
  'concealed-strings': 'Resolve js-confuser string-pool retrievers by evaluating their closed decoders.',
  'binding-propagation': 'Propagate aliases and literals using binding and assignment order.',
  'object-tables': 'Inline frozen proxy tables while preserving argument evaluation.',
  'literal-arrays': 'Fold element reads of write-once literal arrays nothing can mutate.',
  'dead-stores': 'Remove unread local stores while preserving effects and errors.',
  'closed-function-eval': 'Evaluate closed decoder dependencies and their rotation setup in a sandbox.',
  'pure-native-calls': 'Evaluate pure built-in calls on literals, such as Math.floor(135.61).',
  'bitwise-literals': 'Normalize fractional constants used by bitwise operators.',
  'member-expression-simplification': 'Rewrite obj["prop"] as obj.prop where safe.',
  'dispatch-table-inlining': 'Inline object-based control-flow dispatch helpers.',
  'identity-table': 'Replace identity-table lookups L[a][b] by the constants they denote.',
  'constant-propagation': 'Inline write-once literal variables.',
  'proxy-function-removal': 'Remove simple proxy functions and decoder references.',
  'function-inlining': 'Evaluate safe literal coercion functions (the pure-native evaluator once more).',
  'opaque-predicate-removal': 'Remove branches guarded by literal predicates and `"k" in dummy` probes.',
  'scoped-const-fold': 'Inline single-assignment loop locals into the predicates that read them.',
  'dead-code-elimination': 'Simplify dead branches and short-circuit expressions.',
  'control-flow-flattening': 'Deflatten switch/while state-machine control flow.',
  'switch-dispatcher': 'Recover execution order from for/while switch dispatchers.',
  'state-machine-unflatten': 'Recover sequential statements from numeric state-machine loops.',
  'self-defending': 'Remove debugger and anti-tamper timer stubs.',
  'comma-sequence': 'Split statement-level comma sequences.',
  'conditional-statements': 'Expand statement-level conditional and logical expressions.',
  'typeof-simplify': 'Fold typeof comparisons on literal values.',
  'boolean-simplify': 'Rewrite cond ? true : false as !!cond and similar boolean shapes.',
  'unused-vars': 'Remove unused pure literal declarations.',
  'dead-functions': 'Drop helper functions whose call sites were all inlined.',
  'single-use-temps': 'Inline adjacent single-use temporaries without reordering effects.',
  'iife-flatten': 'Inline argument-less IIFE statements nested in a function body.',
  'declaration-tidy': 'Drop redundant undefined initialisations and declare vars at their first assignment.',
  'deduplicate-var-decls': 'Normalize duplicate var declarations before generation.',
  'confuser-names': 'Rename js-confuser generated names (__p_XXXX_meaning) to their meaningful part.',
  'rename-mangled': 'Rename mangled _0x bindings after structural cleanup (opt-in).',
  'vm-eval-hook': 'Run the program in the sandbox with eval/Function/setTimeout hooked, and deobfuscate any payload it hands them.',
};

/** Passes the default run leaves out. */
const OPT_IN = new Set(['junk-token-removal', 'closure-string-decoding', 'rename-mangled']);

/** [name, log id, runs per sweep] in execution order — stage B mirrors the engine's PASS_ORDER. */
const STAGE_B: Array<[string, string, number]> = [
  ['function-constructor', 'b03c', 1],
  ['eval-literal', 'b03d', 2],
  ['rgf', 'b03e', 1],
  ['rgf-thunk', 'b03f', 1],
  ['cff-recover', 'b13d', 1],
  ['string-escape-norm', 'b00', 1],
  ['hex-string-decoding', 'b01', 1],
  ['dispatchers', 'b09d', 1],
  ['statement-normalize', 'b00b', 1],
  ['flat-functions', 'b09c', 1],
  ['masked-variables', 'b00d', 1],
  ['moved-declarations', 'b00e', 1],
  ['param-locals', 'b00c', 1],
  ['noop-calls', 'b09b', 1],
  ['concealed-globals', 'b01e', 1],
  ['locks', 'b20', 1],
  ['global-object-alias', 'b01d', 1],
  ['native-alias', 'b01b', 1],
  ['pure-numeric-fns', 'b01c', 3],
  ['from-char-code', 'b02', 2],
  ['atob-decoding', 'b03', 1],
  ['buffer-decoding', 'b03b', 1],
  ['constant-folding', 'b04', 3],
  ['closure-string-decoding', 'b05a', 2],
  ['string-decoding', 'b05', 1],
  ['pool-decoding', 'b05b', 1],
  ['concealed-strings', 'b05d', 1],
  ['binding-propagation', 'b08b', 1],
  ['object-tables', 'b07c', 2],
  ['literal-arrays', 'b07d', 2],
  ['dead-stores', 'b17c', 2],
  ['closed-function-eval', 'b05c', 1],
  ['pure-native-calls', 'b10b', 2],
  ['bitwise-literals', 'b04b', 1],
  ['member-expression-simplification', 'b06', 1],
  ['dispatch-table-inlining', 'b07', 1],
  ['identity-table', 'b07b', 1],
  ['constant-propagation', 'b08', 1],
  ['proxy-function-removal', 'b09', 1],
  ['function-inlining', 'b10b', 1],
  ['opaque-predicate-removal', 'b11', 1],
  ['scoped-const-fold', 'b11b', 1],
  ['dead-code-elimination', 'b12', 1],
  ['control-flow-flattening', 'b13', 1],
  ['switch-dispatcher', 'b13c', 1],
  ['state-machine-unflatten', 'b13b', 1],
  ['self-defending', 'b14', 1],
  ['comma-sequence', 'b15', 1],
  ['conditional-statements', 'b15b', 1],
  ['typeof-simplify', 'b16', 1],
  ['boolean-simplify', 'b16b', 1],
  ['unused-vars', 'b17', 1],
  ['dead-functions', 'b17b', 1],
  ['single-use-temps', 'b17d', 1],
  ['iife-flatten', 'b17e', 1],
  ['declaration-tidy', 'b17f', 1],
  ['deduplicate-var-decls', 'b18', 1],
  ['confuser-names', 'b19b', 1],
  ['rename-mangled', 'b19', 1],
];

let order = 0;
const step = (stage: 'a' | 'b' | 'c', name: string, logId: string | null, runs: number): PipelineStep => ({
  id: name,
  name,
  description: DESCRIPTIONS[name],
  enabled_by_default: !OPT_IN.has(name),
  pass_order: ++order,
  logId,
  runs,
  stage,
});

export const PIPELINE: PipelineStage[] = [
  {
    id: 'a',
    title: 'pre-parse',
    summary: 'Raw-text transforms before the first parse.',
    steps: [step('a', 'junk-token-removal', 'a1', 1)],
  },
  {
    id: 'b',
    title: 'ast sweeps',
    summary: 'The AST passes, in this order, swept again while the program keeps changing.',
    steps: STAGE_B.map(([name, logId, runs]) => step('b', name, logId, runs)),
  },
  {
    id: 'c',
    title: 'sandbox eval hook',
    summary: 'A last resort for payloads only visible at run time: executed in the sandbox, captured, and deobfuscated in turn.',
    steps: [step('c', 'vm-eval-hook', null, 1)],
  },
];

/** Every pass, in execution order, each once. */
export const PASS_CATALOG: PassInfo[] = PIPELINE.flatMap((s) => s.steps);

// ── the older two-group view, kept for callers that used it ──────────────────
const BASE_NAMES = [
  'string-escape-norm', 'hex-string-decoding', 'global-object-alias', 'native-alias', 'pure-numeric-fns', 'from-char-code', 'atob-decoding',
  'buffer-decoding', 'constant-folding', 'closure-string-decoding', 'string-decoding', 'pool-decoding', 'pure-native-calls',
  'member-expression-simplification', 'dispatch-table-inlining', 'identity-table', 'constant-propagation', 'proxy-function-removal',
  'function-inlining', 'opaque-predicate-removal', 'scoped-const-fold', 'dead-code-elimination', 'control-flow-flattening',
  'state-machine-unflatten', 'self-defending', 'comma-sequence', 'typeof-simplify', 'boolean-simplify', 'unused-vars', 'dead-functions',
  'deduplicate-var-decls', 'rename-mangled', 'vm-eval-hook',
];
const STRUCTURAL_NAMES = [
  'function-constructor', 'eval-literal', 'rgf', 'rgf-thunk', 'cff-recover', 'statement-normalize', 'param-locals', 'moved-declarations',
  'concealed-globals', 'locks', 'concealed-strings', 'dispatchers', 'flat-functions', 'masked-variables', 'noop-calls',
  'binding-propagation', 'object-tables', 'literal-arrays', 'closed-function-eval', 'bitwise-literals', 'switch-dispatcher',
  'conditional-statements', 'dead-stores', 'single-use-temps', 'iife-flatten', 'declaration-tidy', 'confuser-names',
];
const info = (name: string, index: number): PassInfo => ({
  id: name,
  name,
  description: DESCRIPTIONS[name],
  enabled_by_default: !OPT_IN.has(name),
  pass_order: index + 1,
});
export const BASE_PASSES: PassInfo[] = BASE_NAMES.map(info);
/** Structural passes exposed by both the fallback catalog and database-backed UI. */
export const STRUCTURAL_PASSES: PassInfo[] = STRUCTURAL_NAMES.map((n, i) => info(n, BASE_NAMES.length + i));

export function withStructuralPasses<T extends { name: string }>(passes: T[]): Array<T | PassInfo> {
  const names = new Set(passes.map((pass) => pass.name));
  return [...passes, ...STRUCTURAL_PASSES.filter((pass) => !names.has(pass.name))];
}
