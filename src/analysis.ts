/**
 * Binding-level analysis primitives shared by the structural passes.
 *
 * The original passes recognise obfuscator constructs by *shape* — an alias is a
 * `VariableDeclarator`, a string table is `var arr = [...]`, a dispatcher's
 * order is `var o = "1|0".split("|")`. Obfuscators that hoist every local into
 * the parameter list (`function (a, b, uW, mW, o) { uW = {…}, mW = Q, … }`) or
 * build tables through assignments defeat all of those matchers at once even
 * though the underlying facts are identical.
 *
 * This module answers the questions those passes actually need, independent of
 * how the binding was introduced:
 *
 *   • writeOnceFacts       — which bindings hold exactly one value at every
 *                            point they are read (declarator, `var` + one
 *                            assignment, or a parameter overwritten up front)
 *   • paramInitialObserved — definite-assignment analysis: may a parameter's
 *                            incoming value ever be read?
 *   • instantiateTemplate  — evaluation-order-safe inlining of an expression-
 *                            bodied function at a call site
 *   • freeReferences       — free variables / writes of a subtree, for slicing
 *                            self-contained code out to the VM
 *
 * Everything here is read-only over the AST; passes own all mutation.
 */

import { traverse } from './babel.js';
import type { Binding, NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { parse as babelParse } from '@babel/parser';

// ─────────────────────────────────────────────────────────────────────────────
// Scope freshness & program-wide guards
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Program path with freshly crawled scopes.
 *
 * Passes mutate the AST in place without keeping Babel's binding tables in
 * sync, and Babel caches scopes per node, so a later traverse() happily serves
 * stale `referencePaths` / `constantViolations`. Any analysis that trusts those
 * tables must start from a fresh crawl.
 */
export function freshProgram(ast: t.File): NodePath<t.Program> {
  traverse.cache.clear();
  let out: NodePath<t.Program> | null = null;
  traverse(ast, {
    Program(p) {
      out = p;
      p.stop();
    },
  });
  if (!out) throw new Error('freshProgram: no Program node');
  return out;
}

/**
 * True when some binding may be read or written by name at runtime — a direct
 * `eval(…)` or a `with` block. Binding-based rewrites are unsound there.
 */
export function hasDynamicScope(root: t.Node): boolean {
  let found = false;
  walk(root, (n) => {
    if (found) return false;
    if (t.isWithStatement(n)) found = true;
    else if (t.isCallExpression(n) && t.isIdentifier(n.callee, { name: 'eval' })) found = true;
    return !found;
  });
  return found;
}

/**
 * Which scopes a direct `eval` or a `with` block can actually reach.
 *
 * `hasDynamicScope` answers the question for a whole program, which costs every
 * binding in every function as soon as one line anywhere calls `eval`. The real
 * reach is narrower: a direct `eval(…)` resolves names against its own scope
 * chain, so it can observe the bindings of the scopes that *enclose* it and
 * nothing else. A function that merely sits beside the `eval` is untouched, and
 * most of a protected bundle is exactly that.
 *
 * `with (o) { … }` is treated the same way: inside its body a property of `o`
 * can shadow any enclosing binding, so the enclosing scopes are observable too.
 *
 * Both are conservative in the same direction as before — a scope that encloses
 * one of them is never rewritten — and `empty` reports the common case where the
 * program has neither, so callers can take their fast path.
 */
export interface DynamicScopes {
  /** No direct `eval` and no `with` anywhere: every binding is statically known. */
  readonly empty: boolean;
  /** Can a direct `eval` / `with` observe the bindings declared by this scope? */
  observes(scope: NodePath['scope']): boolean;
  /** Can a direct `eval` / `with` observe this binding by name? */
  observesBinding(binding: Binding): boolean;
  /** Does this subtree *contain* a direct `eval` / `with`? (slice safety) */
  contains(path: NodePath): boolean;
}

export function dynamicScopes(program: NodePath<t.Program>, opts: { ignore?: Set<t.Node> } = {}): DynamicScopes {
  // Every node on the path from the program down to a dynamic construct. A
  // scope whose node is in here has the construct somewhere inside it.
  const enclosing = new Set<t.Node>();
  const sites: t.Node[] = [];

  const mark = (p: NodePath) => {
    sites.push(p.node);
    for (let cur: NodePath | null = p; cur; cur = cur.parentPath) enclosing.add(cur.node);
  };

  program.traverse({
    WithStatement(p) {
      mark(p);
    },
    CallExpression(p) {
      if (!t.isIdentifier(p.node.callee, { name: 'eval' })) return;
      // A caller that has verified what this eval can reach may set it aside.
      if (opts.ignore?.has(p.node)) return;
      // A local binding named `eval` is an ordinary function: an indirect call
      // gets the global scope, not this one, so it observes nothing here.
      if (p.scope.hasBinding('eval', { noGlobals: true })) return;
      mark(p);
    },
  });

  const empty = sites.length === 0;
  // `enclosing` holds each site and all of its ancestors, so membership answers
  // both questions: a scope observes a site below it, and a subtree contains one.
  return {
    empty,
    observes: (scope) => !empty && enclosing.has(scope.path.node),
    observesBinding: (binding) => !empty && enclosing.has(binding.scope.path.node),
    contains: (path) => !empty && enclosing.has(path.node),
  };
}

/**
 * Names of function declarations nested in blocks of sloppy code. Annex B
 * (B.3.3) gives each of them a second, `var`-like binding in the enclosing
 * function, assigned when the block runs — a binding Babel's scope model does
 * not record. Any rewrite that relies on `scope.getBinding(name)` to prove a
 * name means the same thing in two places must also stay clear of these.
 */
export function annexBNames(root: t.Node): Set<string> {
  const out = new Set<string>();
  const visit = (n: t.Node, strict: boolean, inBlock: boolean): void => {
    if (t.isFunctionDeclaration(n) && inBlock && !strict && n.id) out.add(n.id.name);
    if (t.isFunction(n)) {
      const body = n.body;
      const s = strict || (t.isBlockStatement(body) && body.directives.some((d) => d.value.value === 'use strict'));
      if (t.isBlockStatement(body)) for (const st of body.body) visit(st, s, false);
      return;
    }
    if (t.isClass(n)) {
      for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[n.type] ?? []) {
        const c = (n as unknown as Record<string, unknown>)[k];
        if (Array.isArray(c)) c.forEach((x) => x && visit(x as t.Node, true, inBlock));
        else if (c) visit(c as t.Node, true, inBlock);
      }
      return;
    }
    const nested = t.isBlockStatement(n) || t.isSwitchCase(n);
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[n.type] ?? []) {
      const c = (n as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((x) => x && visit(x as t.Node, strict, inBlock || nested));
      else if (c) visit(c as t.Node, strict, inBlock || nested);
    }
  };
  const prog = t.isFile(root) ? root.program : root;
  const strict = t.isProgram(prog) && (prog.sourceType === 'module' || prog.directives.some((d) => d.value.value === 'use strict'));
  if (t.isProgram(prog)) for (const st of prog.body) visit(st, strict, false);
  else visit(prog, strict, false);
  return out;
}

/** Pre-order walk over VISITOR_KEYS; `visit` returning false skips children. */
export function walk(root: t.Node | null | undefined, visit: (n: t.Node, parent: t.Node | null) => boolean | void): void {
  if (!root) return;
  const stack: Array<[t.Node, t.Node | null]> = [[root, null]];
  while (stack.length) {
    const [node, parent] = stack.pop()!;
    if (visit(node, parent) === false) continue;
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
    for (let k = keys.length - 1; k >= 0; k--) {
      const child = (node as unknown as Record<string, unknown>)[keys[k]];
      if (Array.isArray(child)) {
        for (let i = child.length - 1; i >= 0; i--) {
          const c = child[i];
          if (c && typeof (c as t.Node).type === 'string') stack.push([c as t.Node, node]);
        }
      } else if (child && typeof (child as t.Node).type === 'string') stack.push([child as t.Node, node]);
    }
  }
}

/** Pre-order [enter, exit] index of every node; `a` follows `b` iff enter(a) > exit(b). */
export function documentOrder(root: t.Node): WeakMap<t.Node, [number, number]> {
  const order = new WeakMap<t.Node, [number, number]>();
  let counter = 0;
  const stack: Array<{ node: t.Node; done: boolean }> = [{ node: root, done: false }];
  while (stack.length) {
    const top = stack.pop()!;
    if (top.done) {
      const entry = order.get(top.node);
      if (entry) entry[1] = counter - 1;
      continue;
    }
    order.set(top.node, [counter++, -1]);
    stack.push({ node: top.node, done: true });
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[top.node.type] ?? [];
    for (let k = keys.length - 1; k >= 0; k--) {
      const child = (top.node as unknown as Record<string, unknown>)[keys[k]];
      if (Array.isArray(child)) {
        for (let i = child.length - 1; i >= 0; i--) {
          const c = child[i];
          if (c && typeof (c as t.Node).type === 'string') stack.push({ node: c as t.Node, done: false });
        }
      } else if (child && typeof (child as t.Node).type === 'string')
        stack.push({ node: child as t.Node, done: false });
    }
  }
  return order;
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression classification
// ─────────────────────────────────────────────────────────────────────────────

function isPrimitiveLiteral(node: t.Node): boolean {
  return (
    t.isStringLiteral(node) ||
    t.isNumericLiteral(node) ||
    t.isBooleanLiteral(node) ||
    t.isNullLiteral(node) ||
    t.isBigIntLiteral(node) ||
    (t.isTemplateLiteral(node) && node.expressions.length === 0) ||
    (t.isUnaryExpression(node) &&
      ['-', '+', '!', '~', 'void'].includes(node.operator) &&
      isPrimitiveLiteral(node.argument))
  );
}

/**
 * Evaluating `node` cannot run user code and has no observable effect.
 *
 * Deliberately excludes member access (getters) and arithmetic on anything but
 * literals (`valueOf`). Function/arrow expressions only *create* a closure.
 */
export function isInert(node: t.Node | null | undefined, depth = 0): boolean {
  if (!node) return true;
  if (depth > 40) return false;
  if (isPrimitiveLiteral(node) || t.isRegExpLiteral(node)) return true;
  if (t.isIdentifier(node) || t.isThisExpression(node)) return true;
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) return true;
  if (t.isTemplateLiteral(node)) return node.expressions.every((e) => isInert(e, depth + 1) && !t.isIdentifier(e));
  if (t.isArrayExpression(node))
    return node.elements.every((e) => e === null || (!t.isSpreadElement(e) && isInert(e, depth + 1)));
  if (t.isObjectExpression(node))
    return node.properties.every((p) => {
      if (t.isSpreadElement(p)) return false;
      if (p.computed && !isPrimitiveLiteral(p.key)) return false;
      if (t.isObjectMethod(p)) return true;
      return isInert(p.value, depth + 1);
    });
  if (t.isUnaryExpression(node)) {
    if (node.operator === '!' || node.operator === 'typeof' || node.operator === 'void')
      return isInert(node.argument, depth + 1);
    return false;
  }
  if (t.isBinaryExpression(node)) {
    if (node.operator === '===' || node.operator === '!==')
      return t.isExpression(node.left) && isInert(node.left, depth + 1) && isInert(node.right, depth + 1);
    return isPrimitiveLiteral(node.left) && isPrimitiveLiteral(node.right);
  }
  if (t.isLogicalExpression(node)) return isInert(node.left, depth + 1) && isInert(node.right, depth + 1);
  if (t.isConditionalExpression(node))
    return isInert(node.test, depth + 1) && isInert(node.consequent, depth + 1) && isInert(node.alternate, depth + 1);
  if (t.isSequenceExpression(node)) return node.expressions.every((e) => isInert(e, depth + 1));
  return false;
}

/** A statement whose execution cannot run user code (declarations, inert writes). */
export function isInertStatement(stmt: t.Statement): boolean {
  if (t.isFunctionDeclaration(stmt) || t.isEmptyStatement(stmt)) return true;
  if (t.isVariableDeclaration(stmt))
    return stmt.declarations.every((d) => t.isIdentifier(d.id) && isInert(d.init));
  if (t.isExpressionStatement(stmt)) {
    const e = stmt.expression;
    if (t.isAssignmentExpression(e, { operator: '=' }) && t.isIdentifier(e.left)) return isInert(e.right);
    return isInert(e);
  }
  return false;
}

/**
 * Argument classes for call-site inlining:
 *   const  — a value with no identity or state dependence (literals)
 *   read   — side-effect free but depends on state (identifiers, member reads)
 *   impure — may run code / write state
 */
export type ArgKind = 'const' | 'read' | 'impure';

export function classifyArg(node: t.Node, depth = 0): ArgKind {
  if (depth > 40) return 'impure';
  if (isPrimitiveLiteral(node)) return 'const';
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) return 'const';
  if (t.isIdentifier(node) || t.isThisExpression(node)) return 'read';
  const worst = (kinds: ArgKind[]): ArgKind =>
    kinds.includes('impure') ? 'impure' : kinds.includes('read') ? 'read' : 'const';
  // A member read may hit a getter: it can run code, so it is ordered like
  // any other effect.
  if (t.isMemberExpression(node)) return 'impure';
  if (t.isUnaryExpression(node)) {
    if (node.operator === 'delete') return 'impure';
    return worst([classifyArg(node.argument, depth + 1), 'read']);
  }
  if (t.isBinaryExpression(node)) {
    if (node.operator === 'in' || node.operator === 'instanceof') return 'impure';
    if (!t.isExpression(node.left)) return 'impure';
    return worst([classifyArg(node.left, depth + 1), classifyArg(node.right, depth + 1), 'read']);
  }
  if (t.isLogicalExpression(node))
    return worst([classifyArg(node.left, depth + 1), classifyArg(node.right, depth + 1), 'read']);
  if (t.isConditionalExpression(node))
    return worst([
      classifyArg(node.test, depth + 1),
      classifyArg(node.consequent, depth + 1),
      classifyArg(node.alternate, depth + 1),
      'read',
    ]);
  if (t.isTemplateLiteral(node)) return worst([...node.expressions.map((e) => classifyArg(e, depth + 1)), 'read']);
  return 'impure';
}

/** Small enough and identity-free, so copying it to several use sites is harmless. */
export function isDuplicable(node: t.Node): boolean {
  if (t.isIdentifier(node) || t.isThisExpression(node)) return true;
  if (t.isStringLiteral(node)) return node.value.length <= 64;
  return isPrimitiveLiteral(node);
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression-template inlining
// ─────────────────────────────────────────────────────────────────────────────

export interface Template {
  params: string[];
  body: t.Expression;
}

/**
 * The single-expression body of a function, usable as an inlining template.
 *
 * Accepts `function (a, b) { return expr; }`, `(a, b) => expr`, and object
 * methods of the same shape. Rejects anything whose meaning depends on the call
 * itself (`this`, `arguments`, `new.target`, `super`), closures (a nested
 * function would capture the parameters), and writes.
 */
export function templateOf(fn: t.Node): Template | null {
  if (!t.isFunctionExpression(fn) && !t.isArrowFunctionExpression(fn) && !t.isObjectMethod(fn)) return null;
  if (fn.async || fn.generator) return null;
  if (t.isObjectMethod(fn) && fn.kind !== 'method') return null;
  if (!fn.params.every((p) => t.isIdentifier(p))) return null;
  const params = (fn.params as t.Identifier[]).map((p) => p.name);
  if (new Set(params).size !== params.length) return null;

  let body: t.Expression;
  if (t.isBlockStatement(fn.body)) {
    if (fn.body.directives.length) return null;
    const stmts = fn.body.body.filter((s) => !t.isEmptyStatement(s));
    if (stmts.length === 0) body = t.unaryExpression('void', t.numericLiteral(0));
    else if (stmts.length === 1 && t.isReturnStatement(stmts[0]))
      body = stmts[0].argument ?? t.unaryExpression('void', t.numericLiteral(0));
    else return null;
  } else body = fn.body as t.Expression;

  let ok = true;
  walk(body, (n) => {
    if (!ok) return false;
    if (
      t.isFunction(n) ||
      t.isClass(n) ||
      t.isThisExpression(n) ||
      t.isSuper(n) ||
      t.isMetaProperty(n) ||
      t.isYieldExpression(n) ||
      t.isAwaitExpression(n) ||
      t.isAssignmentExpression(n) ||
      t.isUpdateExpression(n) ||
      t.isUnaryExpression(n, { operator: 'delete' }) ||
      t.isIdentifier(n, { name: 'arguments' })
    )
      ok = false;
    return ok;
  });
  return ok ? { params, body } : null;
}

type TemplateEvent = { k: 'param'; i: number; cond: boolean } | { k: 'read' } | { k: 'effect' };

/** Events of evaluating `node`, in evaluation order. Returns false for unmodelled syntax. */
function templateEvents(
  node: t.Node,
  params: Map<string, number>,
  cond: boolean,
  out: TemplateEvent[]
): boolean {
  const rec = (n: t.Node, c = cond) => templateEvents(n, params, c, out);
  if (isPrimitiveLiteral(node) || t.isRegExpLiteral(node)) return true;
  if (t.isIdentifier(node)) {
    const i = params.get(node.name);
    out.push(i === undefined ? { k: 'read' } : { k: 'param', i, cond });
    return true;
  }
  if (t.isTemplateLiteral(node)) {
    for (const e of node.expressions) {
      if (!rec(e)) return false;
      out.push({ k: 'effect' }); // ToString can invoke user code.
    }
    return true;
  }
  if (t.isUnaryExpression(node)) {
    if (!rec(node.argument)) return false;
    if (['+', '-', '~'].includes(node.operator)) out.push({ k: 'effect' });
    return true;
  }
  if (t.isBinaryExpression(node)) {
    if (!rec(node.left) || !rec(node.right)) return false;
    if (!['===', '!=='].includes(node.operator)) out.push({ k: 'effect' });
    return true;
  }
  if (t.isLogicalExpression(node)) return rec(node.left) && rec(node.right, true);
  if (t.isConditionalExpression(node))
    return rec(node.test) && rec(node.consequent, true) && rec(node.alternate, true);
  if (t.isMemberExpression(node)) {
    if (!rec(node.object)) return false;
    if (node.computed && !rec(node.property)) return false;
    out.push({ k: 'effect' }); // A getter can mutate later argument reads.
    return true;
  }
  if (t.isCallExpression(node) || t.isNewExpression(node)) {
    if (!t.isExpression(node.callee) || !rec(node.callee)) return false;
    for (const a of node.arguments) if (!t.isExpression(a) || !rec(a)) return false;
    out.push({ k: 'effect' });
    return true;
  }
  if (t.isSequenceExpression(node)) return node.expressions.every((e) => rec(e));
  if (t.isArrayExpression(node))
    return node.elements.every((e) => e === null || (t.isExpression(e) && rec(e)));
  if (t.isObjectExpression(node))
    return node.properties.every((p) => {
      if (!t.isObjectProperty(p)) return false;
      if (p.computed && !rec(p.key)) return false;
      return t.isExpression(p.value) && rec(p.value);
    });
  return false;
}

/** Replace parameter references in a cloned template body. */
function substituteParams(body: t.Expression, params: Map<string, number>, args: t.Expression[]): t.Expression {
  const replace = (node: t.Node, parent: t.Node | null, key: string): t.Node => {
    const valueCall = t.isCallExpression(node) && t.isIdentifier(node.callee) && params.has(node.callee.name);
    if (t.isIdentifier(node) && params.has(node.name) && (!parent || t.isReferenced(node, parent))) {
      const arg = args[params.get(node.name)!];
      return arg ? t.cloneNode(arg, true) : t.unaryExpression('void', t.numericLiteral(0));
    }
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
    for (const k of keys) {
      const rec = node as unknown as Record<string, unknown>;
      const child = rec[k];
      if (Array.isArray(child))
        rec[k] = child.map((c) => (c && typeof c.type === 'string' ? replace(c as t.Node, node, k) : c));
      else if (child && typeof (child as t.Node).type === 'string') rec[k] = replace(child as t.Node, node, k);
    }
    if (valueCall && t.isCallExpression(node) &&
        (t.isMemberExpression(node.callee) || t.isIdentifier(node.callee, { name: 'eval' }))) {
      node.callee = t.sequenceExpression([t.numericLiteral(0), node.callee]);
    }
    void key;
    return node;
  };
  return replace(t.cloneNode(body, true), null, '') as t.Expression;
}

/**
 * Inline `fn(args…)` given the function's template, or null when doing so could
 * change behaviour.
 *
 * Arguments are evaluated once, left to right, before the body. The inlined
 * expression instead evaluates each argument where its parameter appears. That
 * is equivalent exactly when:
 *   • an impure argument is used once, unconditionally, and is not reordered
 *     relative to any other state-dependent argument;
 *   • no state-dependent argument is evaluated after a side effect of the body
 *     (it would observe that effect), nor after one of the body's own free
 *     reads when an impure argument could have changed what that read sees;
 *   • an argument used more than once is a duplicable leaf;
 *   • dropped arguments (unused params, extra args) are effect-free.
 */
export function instantiateTemplate(tpl: Template, args: t.Expression[]): t.Expression | null {
  const params = new Map(tpl.params.map((p, i) => [p, i] as const));
  const events: TemplateEvent[] = [];
  if (!templateEvents(tpl.body, params, false, events)) return null;

  const kinds: ArgKind[] = tpl.params.map((_, i) => (args[i] ? classifyArg(args[i]) : 'const'));
  for (let i = tpl.params.length; i < args.length; i++) if (classifyArg(args[i]) !== 'const') return null;

  const positions: number[][] = tpl.params.map(() => []);
  events.forEach((e, k) => {
    if (e.k === 'param') positions[e.i].push(k);
  });
  const firstEffect = events.findIndex((e) => e.k === 'effect');
  const effectAt = firstEffect === -1 ? Infinity : firstEffect;

  for (let i = 0; i < tpl.params.length; i++) {
    const uses = positions[i];
    const kind = kinds[i];
    if (!args[i]) continue;
    if (kind !== 'const' && (uses.length === 0 || uses.some((k) =>
      (events[k] as { cond: boolean }).cond))) return null;
    if (uses.length > 1 && !isDuplicable(args[i])) return null;
    if (kind === 'impure') {
      if (uses.length !== 1) return null;
      if ((events[uses[0]] as { cond: boolean }).cond) return null;
    }
    if (kind !== 'const' && uses.some((k) => k > effectAt)) return null;
  }

  const impure = kinds.map((k, i) => (k === 'impure' ? i : -1)).filter((i) => i >= 0);
  if (impure.length) {
    const lastImpure = Math.max(...impure.map((i) => positions[i][0]));
    // Free reads of the body happen after every argument in the original.
    if (events.some((e, k) => e.k === 'read' && k < lastImpure)) return null;
    for (const i of impure) {
      const at = positions[i][0];
      for (let j = 0; j < tpl.params.length; j++) {
        if (j === i || kinds[j] === 'const') continue;
        if (j < i && positions[j].some((k) => k > at)) return null;
        if (j > i && positions[j].some((k) => k < at)) return null;
      }
    }
  }

  return substituteParams(tpl.body, params, args);
}

/** Free identifier names of a template body (excluding its parameters). */
export function templateFreeNames(tpl: Template): Set<string> {
  const names = new Set<string>();
  const params = new Set(tpl.params);
  walk(tpl.body, (n, parent) => {
    if (t.isIdentifier(n) && !params.has(n.name) && (!parent || t.isReferenced(n, parent))) names.add(n.name);
  });
  return names;
}

// ─────────────────────────────────────────────────────────────────────────────
// Function-level helpers
// ─────────────────────────────────────────────────────────────────────────────

/** The function (or program) whose scope owns `binding`'s declarations. */
function ownerBody(binding: Binding): t.BlockStatement | t.Program | null {
  const sp = binding.scope.path;
  if (sp.isProgram()) return sp.node;
  if (sp.isFunction()) {
    const body = sp.node.body;
    return t.isBlockStatement(body) ? body : null;
  }
  return null;
}

/** True when the function body mentions `arguments` (incl. in nested arrows). */
export function usesArguments(fn: t.Function): boolean {
  let found = false;
  walk(fn.body, (n) => {
    if (found) return false;
    if ((t.isFunctionDeclaration(n) || t.isFunctionExpression(n) || t.isObjectMethod(n) || t.isClassMethod(n)) && n !== fn)
      return false;
    if (t.isIdentifier(n, { name: 'arguments' })) found = true;
    return !found;
  });
  return found;
}

/** Simple parameter list: identifiers only, no duplicates. */
export function hasSimpleParams(fn: t.Function): boolean {
  if (!fn.params.every((p) => t.isIdentifier(p))) return false;
  const names = (fn.params as t.Identifier[]).map((p) => p.name);
  return new Set(names).size === names.length;
}

function isInside(node: t.Node, ancestor: t.Node, order: WeakMap<t.Node, [number, number]>): boolean {
  const a = order.get(node);
  const b = order.get(ancestor);
  if (!a || !b) return false;
  return a[0] >= b[0] && a[0] <= b[1];
}

function isAfter(node: t.Node, ref: t.Node, order: WeakMap<t.Node, [number, number]>): boolean {
  const a = order.get(node);
  const b = order.get(ref);
  if (!a || !b) return false;
  return a[0] > b[1];
}

/**
 * True when `p` sits inside a function that is *hoisted into* `owner` — i.e. the
 * outermost function between `p` and `owner` is a declaration. Such code can run
 * as soon as `owner` starts, regardless of where it appears in the source.
 * Functions nested inside a function *expression* are only callable once that
 * expression has been evaluated, so their position in the source is what counts.
 */
function readsViaHoistedFunction(p: NodePath, owner: t.Node): boolean {
  let outermost: NodePath | null = null;
  let cur: NodePath | null = p.parentPath;
  while (cur && cur.node !== owner) {
    if (cur.isFunction()) outermost = cur;
    cur = cur.parentPath;
  }
  return !!outermost && outermost.isFunctionDeclaration();
}

// ─────────────────────────────────────────────────────────────────────────────
// Write-once facts
// ─────────────────────────────────────────────────────────────────────────────

export interface WriteOnceFact {
  binding: Binding;
  /** The value every read of the binding observes. */
  value: t.Expression;
  /** The statement performing the write (ExpressionStatement or VariableDeclaration). */
  statement: NodePath<t.Statement>;
  /** For assignment facts, the AssignmentExpression path. */
  assignment: NodePath<t.AssignmentExpression> | null;
}

/**
 * Bindings that hold exactly one value wherever they are read.
 *
 * A binding qualifies when it has a single syntactic write S — a declarator
 * initialiser with no reassignment, or one `x = v` assignment to a parameter /
 * uninitialised `var` — and S *dominates* every read:
 *
 *   • S is a statement directly in a block (or the program/function body) B;
 *   • every read lies inside B, after S in source order;
 *   • reads inside a hoisted function declaration may run before S, so they
 *     are only accepted when S sits in the owning function's *inert prefix*
 *     (nothing before S, nor S's own value, can call out).
 *
 * Under those conditions no read can observe the binding's incoming value (the
 * parameter argument, `undefined`, a previous loop iteration's value differs
 * only by object identity), so substituting `v` for a read, or inlining a
 * literal property of an object `v`, is behaviour preserving.
 *
 * Program-scope `var`/function bindings of a classic script are global object
 * properties visible to other scripts, so they are left alone.
 */
export function writeOnceFacts(
  program: NodePath<t.Program>,
  opts: { includeScriptGlobals?: boolean } = {}
): Map<Binding, WriteOnceFact> {
  const facts = new Map<Binding, WriteOnceFact>();
  const order = documentOrder(program.node);
  const isModule = program.node.sourceType === 'module';
  const argUse = new WeakMap<t.Node, boolean>();
  const inertPrefixCache = new WeakMap<t.Node, Set<t.Node>>();
  // An eval or with could call any function by name, at any time.
  const anyDynamic = hasDynamicScope(program.node);

  /** Statements of `body` lying in its inert prefix (incl. the first non-inert write's RHS check). */
  const inertPrefix = (body: t.BlockStatement | t.Program): Set<t.Node> => {
    let s = inertPrefixCache.get(body);
    if (s) return s;
    s = new Set();
    for (const stmt of body.body) {
      if (!isInertStatement(stmt)) break;
      s.add(stmt);
    }
    inertPrefixCache.set(body, s);
    return s;
  };

  const seenScopes = new Set<unknown>();
  program.traverse({
    Scopable(p) {
      const scope = p.scope;
      if (seenScopes.has(scope)) return;
      seenScopes.add(scope);
      for (const binding of Object.values(scope.bindings)) {
        try {
          const fact = factFor(binding);
          if (fact) facts.set(binding, fact);
        } catch {
          /* malformed binding tables — skip */
        }
      }
    },
  });
  // The program scope itself is not visited by the Scopable visitor above.
  for (const binding of Object.values(program.scope.bindings)) {
    try {
      const fact = factFor(binding);
      if (fact) facts.set(binding, fact);
    } catch {
      /**/
    }
  }
  return facts;

  function factFor(binding: Binding): WriteOnceFact | null {
    const scopePath = binding.scope.path;
    const atProgram = scopePath.isProgram();
    if (atProgram && !isModule && binding.kind !== 'const' && !opts.includeScriptGlobals) return null;

    let value: t.Expression;
    let statement: NodePath<t.Statement>;
    let assignment: NodePath<t.AssignmentExpression> | null = null;
    // The node every read must follow: the declarator for `var a = 1, b = a`
    // (later declarators run after earlier ones), else the whole statement.
    let writeNode: t.Node;

    if (binding.kind === 'var' || binding.kind === 'let' || binding.kind === 'const') {
      const declPath = binding.path;
      if (!declPath.isVariableDeclarator() || !t.isIdentifier(declPath.node.id)) return null;
      const declStmt = declPath.parentPath;
      if (!declStmt?.isVariableDeclaration()) return null;
      if (declPath.node.init) {
        if (binding.constantViolations.length !== 0) return null;
        value = declPath.node.init;
        statement = declStmt as NodePath<t.Statement>;
        writeNode = declPath.node;
      } else {
        if (binding.kind === 'const') return null;
        const v = singleAssignment(binding);
        if (!v) return null;
        value = v.node.right;
        statement = v.parentPath as NodePath<t.Statement>;
        assignment = v;
        writeNode = statement.node;
      }
    } else if (binding.kind === 'param') {
      const fnPath = scopePath;
      if (!fnPath.isFunction()) return null;
      const fn = fnPath.node;
      if (!hasSimpleParams(fn)) return null;
      if (!argUse.has(fn)) argUse.set(fn, usesArguments(fn));
      if (argUse.get(fn) && !t.isArrowFunctionExpression(fn)) return null;
      const v = singleAssignment(binding);
      if (!v) return null;
      value = v.node.right;
      statement = v.parentPath as NodePath<t.Statement>;
      assignment = v;
      writeNode = statement.node;
    } else return null;

    // S must sit directly in a block / function body / program.
    const block = statement.parentPath;
    if (!block || !(block.isBlockStatement() || block.isProgram())) return null;
    if (statement.isVariableDeclaration() && statement.node.kind !== 'var') {
      // let/const: same dominance argument (reads before S would throw TDZ).
    }

    // The write must not read the binding itself (`x = x + 1`) — except from
    // inside a function value: creating `function () { … x … }` runs none of
    // its body, which can only run once called, after the write.
    const valueNode = value;
    const fnValue = t.isFunctionExpression(value) || t.isArrowFunctionExpression(value);
    const inValueBody = (r: NodePath): boolean => fnValue && isInside(r.node, valueNode, order);
    for (const r of binding.referencePaths) if (isInside(r.node, valueNode, order) && !inValueBody(r)) return null;

    const owner = ownerBody(binding);
    /** `r` sits in a function nested inside the binding's scope. */
    const inNestedFunction = (r: NodePath): boolean => {
      for (let q = r.parentPath; q && q.node !== scopePath.node; q = q.parentPath) if (q.isFunction()) return true;
      return false;
    };
    /**
     * Does `p` only ever run after S? Directly in S's block: when it follows S.
     * Inside a function: when every run of that function starts after S —
     * an IIFE where it stands, a named function (one value, never escaping)
     * at each of its call sites, recursively. A function's calls of itself
     * run only once it is already running, so they add no entry; any other
     * cycle is refused. A function used other than by calling it could be
     * run by anyone, at any time: refused.
     */
    const fnMemo = new Map<t.Node, boolean>();
    const runsAfter = (p: NodePath): boolean => {
      // The outermost function below the binding's scope: anything nested in
      // it is created, and so can run, only once it runs.
      let fnPath: NodePath | null = null;
      for (let q = p.parentPath; q && q.node !== scopePath.node; q = q.parentPath) if (q.isFunction()) fnPath = q;
      if (!fnPath) return isInside(p.node, block.node, order) && isAfter(p.node, writeNode, order) && !isInside(p.node, valueNode, order);
      return fnRunsAfter(fnPath);
    };
    const fnRunsAfter = (f: NodePath): boolean => {
      const memo = fnMemo.get(f.node);
      if (memo !== undefined) return memo;
      fnMemo.set(f.node, false); // in progress: a cycle back here is refused
      const res = ((): boolean => {
        const parent = f.parentPath;
        if ((parent?.isCallExpression() || parent?.isNewExpression()) && parent.node.callee === f.node) return runsAfter(parent);
        let b: Binding | undefined;
        if (f.isFunctionDeclaration() && f.node.id) {
          // a block-level declaration is also an Annex B var: keep to bodies
          const holder = f.parentPath;
          if (!(holder.isProgram() || (holder.isBlockStatement() && holder.parentPath?.isFunction()))) return false;
          b = holder.scope.getBinding(f.node.id.name);
        } else if (parent?.isVariableDeclarator() && parent.node.init === f.node && t.isIdentifier(parent.node.id))
          b = parent.scope.getBinding(parent.node.id.name);
        else if (parent?.isAssignmentExpression({ operator: '=' }) && parent.node.right === f.node && t.isIdentifier(parent.node.left))
          b = parent.scope.getBinding(parent.node.left.name);
        if (!b) return false;
        // a script global can be called by other scripts
        if (b.scope.path.isProgram() && !isModule) return false;
        // the binding holds this function and nothing else
        if (b.constantViolations.some((v) => v.node !== parent?.node && v.node !== f.node)) return false;
        return b.referencePaths.every((ref) => {
          if (isInside(ref.node, f.node, order)) return true; // f calling itself
          const c = ref.parentPath;
          if (!(c?.isCallExpression() || c?.isNewExpression()) || c.node.callee !== ref.node) return false;
          return runsAfter(c);
        });
      })();
      fnMemo.set(f.node, res);
      return res;
    };
    for (const r of binding.referencePaths) {
      if (!isInside(r.node, block.node, order)) return null;
      if (inValueBody(r)) continue;
      const prefixed = !!owner && block.node === owner && inertPrefix(owner).has(statement.node);
      if (!isAfter(r.node, writeNode, order)) {
        // A closure created before S (`var f = function () { … x … }; x = v;`)
        // can only run once something calls it; if nothing up to and
        // including S can call out, that is after S — or if each of its
        // calls is shown to come after S.
        if (inNestedFunction(r) && prefixed) continue;
        if (!anyDynamic && inNestedFunction(r) && runsAfter(r)) continue;
        return null;
      }
      if (readsViaHoistedFunction(r, scopePath.node)) {
        // Callable before S unless nothing up to and including S can call
        // out, or unless every call is shown to come after S.
        if (prefixed) continue;
        if (!anyDynamic && runsAfter(r)) continue;
        return null;
      }
    }
    return { binding, value, statement, assignment };
  }

  function singleAssignment(binding: Binding): NodePath<t.AssignmentExpression> | null {
    if (binding.constantViolations.length !== 1) return null;
    const v = binding.constantViolations[0];
    if (!v.isAssignmentExpression({ operator: '=' })) return null;
    if (!t.isIdentifier(v.node.left)) return null;
    if (!v.parentPath?.isExpressionStatement()) return null;
    return v;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Definite assignment — may a parameter's incoming value be observed?
// ─────────────────────────────────────────────────────────────────────────────

/**
 * For the candidate parameter bindings of `fnPath`, return those whose initial
 * (argument) value may be read. A parameter that is always overwritten before
 * any read is an obfuscator-introduced local and can be demoted to `var`.
 *
 * Classic forward definite-assignment over the function body, conservative at
 * every merge: branches intersect, loop bodies are analysed from the state at
 * loop entry and contribute nothing afterwards, `try` handlers start from the
 * state before the `try`. Nested closures are treated as reading every
 * candidate they (transitively) mention at the point they are created — or,
 * for hoisted declarations, at each point their name is referenced.
 */
export function paramInitialObserved(fnPath: NodePath<t.Function>, candidates: Binding[]): Set<Binding> {
  const observed = new Set<Binding>();
  if (candidates.length === 0) return observed;
  const fn = fnPath.node;
  if (!t.isBlockStatement(fn.body)) return new Set(candidates);
  const cand = new Set(candidates);

  // identifier node → candidate binding it reads
  const readOf = new Map<t.Node, Binding>();
  // write site node → candidate binding it writes
  const writeOf = new Map<t.Node, Binding>();
  for (const b of candidates) {
    for (const r of b.referencePaths) readOf.set(r.node, b);
    for (const v of b.constantViolations) writeOf.set(v.node, b);
  }

  // Closures: the candidates each nested function/class reads, transitively.
  // Built from the candidates' own reference lists (walking up to `fn`), so the
  // cost is proportional to references × nesting, not to the body size.
  const closureReads = new Map<t.Node, Set<Binding>>();
  const addRead = (owner: t.Node, b: Binding) => {
    let set = closureReads.get(owner);
    if (!set) closureReads.set(owner, (set = new Set()));
    set.add(b);
  };
  const enclosingClosures = (p: NodePath): t.Node[] => {
    const out: t.Node[] = [];
    let cur: NodePath | null = p.parentPath;
    while (cur && cur.node !== fn) {
      if (cur.isFunction() || cur.isClass()) out.push(cur.node);
      cur = cur.parentPath;
    }
    return out;
  };
  for (const b of candidates) {
    for (const r of b.referencePaths) for (const c of enclosingClosures(r)) addRead(c, b);
    for (const v of b.constantViolations)
      if (!v.isAssignmentExpression({ operator: '=' }) && !v.isVariableDeclarator())
        for (const c of enclosingClosures(v)) addRead(c, b);
  }

  // Function declarations hoisted to the top of `fn`'s body run whenever their
  // name is used: map each such use to the declaration, and record which other
  // closures name them (a call from inside a closure happens when it runs).
  const hoistedByIdent = new Map<t.Node, t.Node>();
  const directRefs = new Map<t.Node, Set<t.Node>>();
  for (const stmt of fn.body.body) {
    if (!t.isFunctionDeclaration(stmt) || !stmt.id) continue;
    const b = fnPath.scope.getBinding(stmt.id.name);
    if (!b || b.path.node !== stmt) continue;
    for (const r of b.referencePaths) {
      const closures = enclosingClosures(r);
      if (closures.length === 0) hoistedByIdent.set(r.node, stmt);
      for (const c of closures) {
        if (c === stmt) continue;
        let set = directRefs.get(c);
        if (!set) directRefs.set(c, (set = new Set()));
        set.add(stmt);
      }
    }
  }
  for (let changed = true, guard = 0; changed && guard < 64; guard++) {
    changed = false;
    for (const [node, refs] of directRefs) {
      for (const r of refs) {
        for (const b of closureReads.get(r) ?? []) {
          let set = closureReads.get(node);
          if (!set) closureReads.set(node, (set = new Set()));
          if (!set.has(b)) {
            set.add(b);
            changed = true;
          }
        }
      }
    }
  }

  type State = Set<Binding> | null; // null = unreachable
  const copy = (s: Set<Binding>) => new Set(s);
  const meet = (a: State, b: State): State => {
    if (a === null) return b === null ? null : copy(b);
    if (b === null) return copy(a);
    return new Set([...a].filter((x) => b.has(x)));
  };
  const checkClosure = (node: t.Node, s: Set<Binding>) => {
    for (const b of closureReads.get(node) ?? []) if (!s.has(b)) observed.add(b);
  };
  const giveUp = () => {
    for (const b of cand) observed.add(b);
  };

  const expr = (node: t.Node | null | undefined, s: Set<Binding>): Set<Binding> => {
    if (!node) return s;
    if (t.isIdentifier(node)) {
      const b = readOf.get(node);
      if (b && !s.has(b)) observed.add(b);
      const decl = hoistedByIdent.get(node);
      if (decl) checkClosure(decl, s);
      return s;
    }
    if (t.isFunction(node) || t.isClass(node)) {
      checkClosure(node, s);
      return s;
    }
    if (t.isAssignmentExpression(node)) {
      const b = writeOf.get(node);
      if (t.isIdentifier(node.left)) {
        if (node.operator !== '=') {
          if (b && !s.has(b)) observed.add(b);
          const lb = readOf.get(node.left);
          if (lb && !s.has(lb)) observed.add(lb);
        }
        s = expr(node.right, s);
        if (b) s.add(b);
        return s;
      }
      if (t.isMemberExpression(node.left)) {
        s = expr(node.left.object, s);
        if (node.left.computed) s = expr(node.left.property, s);
        return expr(node.right, s);
      }
      // destructuring: defaults are conditional — check reads, record no writes
      s = expr(node.right, s);
      expr(node.left, copy(s));
      if (b) s.add(b);
      return s;
    }
    if (t.isUpdateExpression(node)) {
      const b = writeOf.get(node);
      if (b && !s.has(b)) observed.add(b);
      if (!t.isIdentifier(node.argument)) return expr(node.argument, s);
      return s;
    }
    if (t.isLogicalExpression(node)) {
      s = expr(node.left, s);
      expr(node.right, copy(s));
      return s;
    }
    if (t.isConditionalExpression(node)) {
      s = expr(node.test, s);
      const a = expr(node.consequent, copy(s));
      const b = expr(node.alternate, copy(s));
      return meet(a, b) ?? s;
    }
    if (t.isOptionalMemberExpression(node) || t.isOptionalCallExpression(node)) {
      // Everything after `?.` is conditional: check reads, drop writes.
      expr2Generic(node, copy(s));
      return s;
    }
    if (t.isMemberExpression(node)) {
      s = expr(node.object, s);
      if (node.computed) s = expr(node.property, s);
      return s;
    }
    if (t.isObjectProperty(node)) {
      if (node.computed) s = expr(node.key, s);
      return expr(node.value, s);
    }
    if (t.isObjectMethod(node)) {
      checkClosure(node, s);
      return s;
    }
    return expr2Generic(node, s);
  };
  const expr2Generic = (node: t.Node, s: Set<Binding>): Set<Binding> => {
    const keys = (t.VISITOR_KEYS as Record<string, string[]>)[node.type] ?? [];
    for (const k of keys) {
      const child = (node as unknown as Record<string, unknown>)[k];
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c.type === 'string') s = expr(c as t.Node, s);
      } else if (child && typeof (child as t.Node).type === 'string') s = expr(child as t.Node, s);
    }
    return s;
  };

  const stmt = (node: t.Statement, s: Set<Binding>): State => {
    if (t.isExpressionStatement(node)) return expr(node.expression, s);
    if (t.isVariableDeclaration(node)) {
      for (const d of node.declarations) {
        s = expr(d.init, s);
        const b = writeOf.get(d);
        if (b && d.init) s.add(b);
      }
      return s;
    }
    if (t.isFunctionDeclaration(node) || t.isEmptyStatement(node) || t.isDebuggerStatement(node)) return s;
    if (t.isClassDeclaration(node)) {
      checkClosure(node, s);
      return s;
    }
    if (t.isReturnStatement(node) || t.isThrowStatement(node)) {
      expr(node.argument, s);
      return null;
    }
    if (t.isBreakStatement(node) || t.isContinueStatement(node)) return null;
    if (t.isBlockStatement(node)) return block(node.body, s);
    if (t.isIfStatement(node)) {
      s = expr(node.test, s);
      const a = stmt(node.consequent, copy(s));
      const b = node.alternate ? stmt(node.alternate, copy(s)) : copy(s);
      return meet(a, b);
    }
    if (t.isForStatement(node)) {
      if (node.init) s = t.isVariableDeclaration(node.init) ? (stmt(node.init, s) as Set<Binding>) : expr(node.init, s);
      s = expr(node.test, s);
      stmt(node.body, copy(s));
      expr(node.update, copy(s));
      return s;
    }
    if (t.isWhileStatement(node)) {
      s = expr(node.test, s);
      stmt(node.body, copy(s));
      return s;
    }
    if (t.isDoWhileStatement(node)) {
      stmt(node.body, copy(s));
      expr(node.test, copy(s));
      return s;
    }
    if (t.isForInStatement(node) || t.isForOfStatement(node)) {
      s = expr(node.right, s);
      const inner = copy(s);
      const b = writeOf.get(node);
      if (b) inner.add(b);
      if (!t.isVariableDeclaration(node.left) && !t.isIdentifier(node.left)) expr(node.left, inner);
      stmt(node.body, inner);
      return s;
    }
    if (t.isSwitchStatement(node)) {
      s = expr(node.discriminant, s);
      for (const c of node.cases) {
        const inner = copy(s);
        expr(c.test, inner);
        block(c.consequent, inner);
      }
      return s;
    }
    if (t.isTryStatement(node)) {
      const before = copy(s);
      const tryOut = stmt(node.block, copy(before));
      let base: State = tryOut;
      if (node.handler) base = meet(tryOut, stmt(node.handler.body, copy(before)));
      if (node.finalizer) {
        const fin = stmt(node.finalizer, copy(before));
        if (fin === null || base === null) return null;
        for (const b of fin) base.add(b);
      }
      return base;
    }
    if (t.isLabeledStatement(node)) {
      const before = copy(s);
      return meet(stmt(node.body, s), before);
    }
    giveUp();
    return s;
  };
  const block = (stmts: t.Statement[], s: Set<Binding>, top = false): State => {
    // A function declared inside a nested block is callable from the moment the
    // block is entered (and, in sloppy mode, afterwards through its var binding):
    // check it against the block-entry state. Top-level declarations are
    // handled precisely, at each use of their name.
    if (!top)
      for (const st of stmts) if (t.isFunctionDeclaration(st)) checkClosure(st, s);
    let cur: State = s;
    for (const st of stmts) {
      if (cur === null) break; // unreachable remainder
      cur = stmt(st, cur);
    }
    return cur;
  };

  block(fn.body.body, new Set(), true);
  return observed;
}

// ─────────────────────────────────────────────────────────────────────────────
// Free references of a subtree (for VM slicing)
// ─────────────────────────────────────────────────────────────────────────────

export interface FreeRefs {
  /** Unbound names (globals). */
  globals: Set<string>;
  /** Bindings declared outside the subtree that it reads. */
  reads: Set<Binding>;
  /** Bindings declared outside the subtree that it writes. */
  writes: Set<Binding>;
  /** Member writes / mutating calls whose base is an outside binding. */
  mutates: Set<Binding>;
  /** `this` used at the subtree's own function level. */
  usesThis: boolean;
}

const MUTATING_METHODS = new Set([
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

/** Root identifier of a member chain `a.b[c].d` → `a`. */
export function memberRoot(node: t.Node): t.Identifier | null {
  let cur: t.Node = node;
  while (t.isMemberExpression(cur) || t.isOptionalMemberExpression(cur)) cur = cur.object;
  return t.isIdentifier(cur) ? cur : null;
}

export function freeReferences(path: NodePath): FreeRefs {
  const out: FreeRefs = {
    globals: new Set(),
    reads: new Set(),
    writes: new Set(),
    mutates: new Set(),
    usesThis: false,
  };
  const root = path.node;
  const outside = (b: Binding) => {
    let cur: NodePath | null = b.scope.path;
    while (cur) {
      if (cur.node === root) return false;
      cur = cur.parentPath;
    }
    return true;
  };
  const resolve = (p: NodePath, name: string): Binding | 'global' | 'local' => {
    const b = p.scope.getBinding(name);
    if (!b) return 'global';
    return outside(b) ? b : 'local';
  };
  const visitor = {
    Identifier(ip: NodePath<t.Identifier>) {
      if (!ip.isReferencedIdentifier()) return;
      const r = resolve(ip, ip.node.name);
      if (r === 'global') out.globals.add(ip.node.name);
      else if (r !== 'local') out.reads.add(r);
    },
    AssignmentExpression(ap: NodePath<t.AssignmentExpression>) {
      const left = ap.node.left;
      if (t.isIdentifier(left)) {
        const r = resolve(ap, left.name);
        if (r === 'global') out.globals.add(left.name);
        else if (r !== 'local') out.writes.add(r);
      } else if (t.isMemberExpression(left)) {
        const base = memberRoot(left);
        if (base) {
          const r = resolve(ap, base.name);
          if (r !== 'local' && r !== 'global') out.mutates.add(r);
          else if (r === 'global') out.globals.add(base.name);
        }
      } else {
        for (const name of Object.keys(t.getBindingIdentifiers(left))) {
          const r = resolve(ap, name);
          if (r === 'global') out.globals.add(name);
          else if (r !== 'local') out.writes.add(r);
        }
      }
    },
    UpdateExpression(up: NodePath<t.UpdateExpression>) {
      const arg = up.node.argument;
      const base = t.isIdentifier(arg) ? arg : memberRoot(arg);
      if (!base) return;
      const r = resolve(up, base.name);
      if (r === 'global') out.globals.add(base.name);
      else if (r !== 'local') (t.isIdentifier(arg) ? out.writes : out.mutates).add(r);
    },
    UnaryExpression(up: NodePath<t.UnaryExpression>) {
      if (up.node.operator !== 'delete') return;
      const base = memberRoot(up.node.argument);
      if (!base) return;
      const r = resolve(up, base.name);
      if (r !== 'local' && r !== 'global') out.mutates.add(r);
    },
    CallExpression(cp: NodePath<t.CallExpression>) {
      const callee = cp.node.callee;
      if (!t.isMemberExpression(callee)) return;
      const prop = callee.computed
        ? t.isStringLiteral(callee.property)
          ? callee.property.value
          : null
        : t.isIdentifier(callee.property)
          ? callee.property.name
          : null;
      if (prop !== null && !MUTATING_METHODS.has(prop)) return;
      const base = memberRoot(callee.object);
      if (!base) return;
      const r = resolve(cp, base.name);
      if (r !== 'local' && r !== 'global') out.mutates.add(r);
    },
    ThisExpression(tp: NodePath<t.ThisExpression>) {
      // `this` is bound by the nearest non-arrow function; if that is the root
      // (or lies outside it) the subtree depends on how it is invoked.
      let cur: NodePath | null = tp.parentPath;
      while (cur && cur.node !== root) {
        if (cur.isFunction() && !cur.isArrowFunctionExpression()) return;
        cur = cur.parentPath;
      }
      out.usesThis = true;
    },
  };
  // path.traverse() visits descendants only, which is every identifier that
  // can occur below a statement or function root.
  path.traverse(visitor);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// The original source text
// ─────────────────────────────────────────────────────────────────────────────

/**
 * What a function's `toString()` returns at run time is a slice of the text it
 * was created from: the input file, or a string a `Function(…)` / `eval(…)`
 * turned into code. The passes that write such strings out as code record
 * them here (noteSourceText). The orchestrator sets the current run's record
 * before every pass, so concurrent runs never see each other's.
 */
export type SourceFacts = { texts: string[]; newlineFree: boolean };
let currentSourceFacts: SourceFacts | null = null;
export function setSourceFacts(facts: SourceFacts | null): void {
  currentSourceFacts = facts;
}
export function getSourceFacts(): SourceFacts | null {
  return currentSourceFacts;
}
export function noteSourceText(text: string): void {
  const facts = currentSourceFacts;
  if (!facts || facts.texts.includes(text)) return;
  facts.texts.push(text);
  if (!functionsNewlineFree(text)) facts.newlineFree = false;
}

/**
 * No function in `text` spans a newline — what its `toString()` would show.
 * (Comments and formatting between functions never reach a function's text.)
 * Unparseable text: judged as a whole.
 */
export function functionsNewlineFree(text: string): boolean {
  if (!text.includes('\n')) return true;
  let file: t.File;
  try {
    file = babelParse(text, { sourceType: 'script', allowReturnOutsideFunction: true, errorRecovery: true }) as unknown as t.File;
  } catch {
    return false;
  }
  let free = true;
  t.traverseFast(file.program, (n) => {
    if (!free || !t.isFunction(n) || n.start == null || n.end == null) return;
    if (text.slice(n.start, n.end).includes('\n')) free = false;
  });
  return free;
}

