/**
 * Every pass a caller can name in `enabledPasses`, with a one-line account of
 * what it does and whether the default run includes it. `BASE_PASSES` are the
 * classic obfuscator.io-era passes in the order a UI lists them; the
 * structural passes (js-confuser's transforms and the general-purpose
 * primitives) follow. `PASS_CATALOG` is both lists together — what the CLI
 * runs is `DEFAULT_ENABLED_PASSES`, which the test suite keeps in step with
 * the `enabled_by_default` flags here.
 */
export interface PassInfo {
  id: string;
  name: string;
  description: string;
  enabled_by_default: boolean;
  pass_order: number;
}

const base: Array<[name: string, description: string, enabledByDefault?: boolean]> = [
  ['stringEscapeNorm', 'Normalize escaped string literals before generation.'],
  ['hexStringDecoding', 'Normalize hexadecimal and octal numeric literals.'],
  ['globalObjectAlias', 'Drop `var w = window` style aliases of the global object from member chains.'],
  ['nativeAlias', 'Unmask aliases of native functions such as `var s = String.fromCharCode`.'],
  ['pureNumericFns', 'Collapse bitwise-identity helper functions that hide character codes.'],
  ['fromCharCode', 'Inline literal String.fromCharCode calls.'],
  ['atobDecoding', 'Decode literal atob/btoa calls.'],
  ['bufferDecoding', 'Decode literal Buffer.from(...).toString(...) base64 and hex helpers.'],
  ['constantFolding', 'Fold pure arithmetic, logical, and conditional expressions.'],
  ['closureStringDecoding', 'Run the javascript-obfuscator factory/shuffler/decoder triad in a sandbox to resolve string calls (opt-in; the default passes cover it).', false],
  ['stringDecoding', 'Decode javascript-obfuscator string arrays and rotating arrays.'],
  ['poolDecoding', 'Resolve pool decoders that transform entries, such as atob(pool[i]).'],
  ['pureNativeCalls', 'Evaluate pure built-in calls on literals, such as Math.floor(135.61).'],
  ['memberExpressionSimplification', 'Rewrite obj["prop"] as obj.prop where safe.'],
  ['dispatchTableInlining', 'Inline object-based control-flow dispatch helpers.'],
  ['identityTable', 'Replace identity-table lookups L[a][b] by the constants they denote.'],
  ['constantPropagation', 'Inline write-once literal variables.'],
  ['proxyFunctionRemoval', 'Remove simple proxy functions and decoder references.'],
  ['functionInlining', 'Evaluate safe literal coercion functions.'],
  ['opaquePredicateRemoval', 'Remove branches guarded by literal predicates.'],
  ['scopedConstFold', 'Inline single-assignment loop locals into the predicates that read them.'],
  ['deadCodeElimination', 'Simplify dead branches and short-circuit expressions.'],
  ['controlFlowFlattening', 'Deflatten switch/while state-machine control flow.'],
  ['stateMachineUnflatten', 'Recover sequential statements from numeric state-machine loops.'],
  ['selfDefending', 'Remove debugger and anti-tamper timer stubs.'],
  ['commaSequence', 'Split statement-level comma sequences.'],
  ['typeofSimplify', 'Fold typeof comparisons on literal values.'],
  ['booleanSimplify', 'Rewrite cond ? true : false as !!cond and similar boolean shapes.'],
  ['unusedVars', 'Remove unused pure literal declarations.'],
  ['deadFunctions', 'Drop helper functions whose call sites were all inlined.'],
  ['deduplicateVarDecls', 'Normalize duplicate var declarations before generation.'],
  ['renameMangled', 'Rename mangled _0x bindings after structural cleanup (opt-in).', false],
  ['vmEvalHook', 'Sandbox and capture eval/Function dynamic payloads.'],
];

export const BASE_PASSES: PassInfo[] = base.map(([name, description, enabledByDefault = true], index) => ({
  id: name,
  name,
  description,
  enabled_by_default: enabledByDefault,
  pass_order: index + 1,
}));

/** Structural passes exposed by both the fallback catalog and database-backed UI. */
export const STRUCTURAL_PASSES: PassInfo[] = [
  ['functionConstructor', 'Write out Function("args","body") calls statically, without executing them.'],
  ['evalLiteral', 'Replace direct eval of a literal expression with the expression.'],
  ['rgf', 'Recover a function embedded as eval source behind a provably-true guard.'],
  ['rgfThunk', 'Collapse the forwarding thunk RGF leaves into the real function body.'],
  ['cffRecover', 'Rebuild code flattened into a js-confuser state-machine dispatcher, including its scope frames.'],
  ['statementNormalize', 'Normalize statement heads, sequence expressions, and loop setup.'],
  ['paramLocals', 'Recover local variables hidden in overwritten function parameters.'],
  ['movedDeclarations', 'Turn never-supplied parameters guarded by if-not-set assignments back into declarations.'],
  ['concealedGlobals', 'Resolve js-confuser global-object probes and switch-table global lookups.'],
  ['locks', 'Settle js-confuser integrity and anti-beautify checks the original source text decides.'],
  ['concealedStrings', 'Resolve js-confuser string-pool retrievers by evaluating their closed decoders.'],
  ['dispatchers', 'Restore function declarations and calls routed through a dispatcher table.'],
  ['flatFunctions', 'Move flattened function bodies back into their wrappers and unwrap accessor objects.'],
  ['maskedVariables', 'Recover parameters and locals stored as slots of a rest parameter.'],
  ['noopCalls', 'Expand statement-level calls of functions that do nothing into their arguments.'],
  ['bindingPropagation', 'Propagate aliases and literals using binding and assignment order.'],
  ['objectTables', 'Inline frozen proxy tables while preserving argument evaluation.'],
  ['literalArrays', 'Fold element reads of write-once literal arrays nothing can mutate.'],
  ['closedFunctionEval', 'Evaluate closed decoder dependencies and their rotation setup.'],
  ['bitwiseLiterals', 'Normalize fractional constants used by bitwise operators.'],
  ['switchDispatcher', 'Recover execution order from for/while switch dispatchers.'],
  ['conditionalStatements', 'Expand statement-level conditional and logical expressions.'],
  ['deadStores', 'Remove unread local stores while preserving effects and errors.'],
  ['singleUseTemps', 'Inline adjacent single-use temporaries without reordering effects.'],
  ['iifeFlatten', 'Inline argument-less IIFE statements nested in a function body.'],
  ['declarationTidy', 'Drop redundant undefined initialisations and declare vars at their first assignment.'],
  ['confuserNames', 'Rename js-confuser generated names (__p_XXXX_meaning) to their meaningful part.'],
].map(([name, description], index) => ({
  id: name,
  name,
  description,
  enabled_by_default: true,
  pass_order: base.length + 1 + index,
}));

export function withStructuralPasses<T extends { name: string }>(passes: T[]): Array<T | PassInfo> {
  const names = new Set(passes.map((pass) => pass.name));
  return [...passes, ...STRUCTURAL_PASSES.filter((pass) => !names.has(pass.name))];
}

/** Every pass, base ones first, each once. */
export const PASS_CATALOG: PassInfo[] = withStructuralPasses(BASE_PASSES) as PassInfo[];
