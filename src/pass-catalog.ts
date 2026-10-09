/** Structural passes exposed by both the fallback catalog and database-backed UI. */
export const STRUCTURAL_PASSES = [
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
  pass_order: 23 + index,
}));

export function withStructuralPasses<T extends Record<string, unknown>>(passes: T[]) {
  const names = new Set(passes.map((pass) => pass.name));
  return [...passes, ...STRUCTURAL_PASSES.filter((pass) => !names.has(pass.name))];
}
