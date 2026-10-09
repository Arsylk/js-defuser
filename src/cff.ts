/**
 * js-confuser control-flow flattening (CFF) recovery.
 *
 * js-confuser rewrites a program into one *dispatcher*:
 *
 *   function main(states, scope = { ["K"]: {} }, runtime, arg) {
 *     while (sum(states) !== TERM) switch (sum(states)) {
 *       case states[32] - 26:  …real code…;  states[5] += states[10] - -437, …;  break;
 *       case 771: if (states[states[47] + 471] != -(states[3] + 1194)) { …; break; } …; break;
 *     }
 *   }
 *   main([...slice(0, 5), -587, ...]);
 *
 * with three supporting ideas:
 *
 *   • Control state lives in the `states` array, and every write to it is
 *     affine — `states[i] += states[j] - C`. Program data never flows into it,
 *     so the next case is a pure function of the array.
 *   • Strings and numbers are hidden behind that state: `xor(states[27] + 849217,
 *     2, 7)` decodes a property name, `states[68] + -506` is the number 4. With
 *     the array known, both are constants.
 *   • Variables live in *scope frames*: `scope["K"]["v"]`. Each invocation of a
 *     flattened function creates its own frame (`{["K"]: {}}`) and receives its
 *     parents' frames by reference — exactly JS closure semantics, spelt out.
 *
 * Recovery, in order:
 *
 *   1. Closed helpers. The sum / slice / xor / hash helpers and their literal
 *      pools are pure; they are loaded into a sandbox so any expression over a
 *      concrete state array can be evaluated.
 *   2. Specialisation. Every call `main(<static array>, …)` is replaced by an
 *      IIFE holding the dispatcher's recovered body for that entry state.
 *   3. Simulation → CFG → structure. The dispatcher is run on the concrete
 *      array: opaque predicates (which read only the array) are evaluated,
 *      affine updates applied, real statements recorded with every state-derived
 *      subexpression replaced by its value. A condition that reads program data
 *      is a real branch of the original program: the simulation forks there.
 *      States are memoised, so merges and loops become a graph, which is then
 *      structured back into `if` / `while` / `break` / `continue`.
 *   4. Frames. `scope["K"]["v"]` becomes a variable, declared in the function
 *      that owns frame K. Children reach it by closure, as they did by
 *      reference before.
 *   5. Nested dispatchers. A flattened inner function takes its state array as
 *      its first argument; once every call is shown to pass the same static
 *      array, its loop is linearised in place. Steps 4–5 repeat to a fixpoint.
 *
 * Every step bails out (leaving the code as it was) on anything it cannot
 * prove: a write to the state array that is not affine, a recorded statement
 * that still reads it, a jump that leaves a recorded statement, an irreducible
 * graph, a frame used other than as `frame["K"]["v"]`, a direct call of a frame
 * variable (which would change `this`), or a closure that escapes.
 */

import * as parser from '@babel/parser';
import { traverse } from './babel.js';
import type { Binding, NodePath } from '@babel/traverse';
import { generate } from './babel.js';
import * as t from '@babel/types';
import type { Logger } from './logger.js';
import { getSourceFacts } from './analysis.js';

import * as vm from 'node:vm';

class Abort extends Error {}

/** Deterministic globals a helper may reference. */
const SAFE = new Set([
  'String', 'Number', 'Boolean', 'Array', 'Object', 'Math', 'JSON', 'RegExp', 'Error', 'TypeError',
  'RangeError', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'undefined', 'NaN', 'Infinity',
  'decodeURIComponent', 'encodeURIComponent', 'Symbol', 'Map', 'Set', 'Uint8Array', 'Int32Array',
  'Uint32Array', 'Uint16Array', 'Int16Array', 'Int8Array', 'Float64Array', 'Float32Array',
]);
const RESERVED = new Set(
  ('break case catch class const continue debugger default delete do else enum export extends false finally for ' +
    'function if implements import in instanceof interface let new null package private protected public return ' +
    'static super switch this throw true try typeof var void while with yield await arguments eval undefined NaN Infinity')
    .split(' ')
);
const ID_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

const reparse = (ast: t.File): t.File =>
  parser.parse(generate(ast).code, { sourceType: ast.program.sourceType, allowReturnOutsideFunction: true }) as unknown as t.File;

// ── 1. closed helpers ────────────────────────────────────────────────────────

type Helpers = { fns: Map<string, t.FunctionDeclaration>; data: Map<string, t.Expression>; closed: Set<string>; rebound: Set<string> };

function isLiteralData(n: t.Node | null | undefined): boolean {
  if (!n) return false;
  if (t.isNumericLiteral(n) || t.isStringLiteral(n) || t.isBooleanLiteral(n) || t.isNullLiteral(n)) return true;
  if (t.isUnaryExpression(n, { operator: '-' }) && t.isNumericLiteral(n.argument)) return true;
  return t.isArrayExpression(n) && n.elements.every((e) => isLiteralData(e as t.Node));
}

/**
 * Where the helpers live: the program, or — js-confuser's `pack` spelling,
 * `(function (G) { … })({ get …() {} })` as the whole program — that wrapper's
 * body. Its scope plays the program's part: the helpers and pools are its
 * direct children, and a free name is one bound there or nowhere.
 */
type Root = { body: t.Statement[]; block: t.Node; scope: t.Node };
function helperRoot(ast: t.File): Root {
  const prog = ast.program;
  const only = prog.body.length === 1 ? prog.body[0] : null;
  const call = t.isExpressionStatement(only) ? only.expression : null;
  const fn = t.isCallExpression(call) ? call.callee : null;
  if (t.isFunctionExpression(fn) && !fn.async && !fn.generator && !fn.id)
    return { body: fn.body.body, block: fn.body, scope: fn };
  return { body: prog.body, block: prog, scope: prog };
}

/**
 * renameVariables reuses names freely, so a helper's or pool's name (or a safe
 * global's) is often also a local somewhere. Expressions are judged by
 * spelling (pureOver), so give every such local — never a script-level
 * binding, which other scripts can see — a fresh name first. Renaming a
 * non-global binding together with all its references changes nothing (the
 * pass does not run where an eval or with could look names up).
 */
function uniquifyHelperNames(ast: t.File): number {
  const root = helperRoot(ast);
  const names = new Set<string>(SAFE);
  for (const s of root.body) {
    if (t.isFunctionDeclaration(s) && s.id) names.add(s.id.name);
    if (t.isVariableDeclaration(s)) for (const d of s.declarations) if (t.isIdentifier(d.id)) names.add(d.id.name);
  }
  const todo: Array<{ scope: NodePath['scope']; name: string }> = [];
  traverse(ast, {
    Scopable(p) {
      // (a function body block shares its function's scope)
      if (p.scope.path.isProgram() || p.scope.path.node === root.scope) return;
      for (const name of Object.keys(p.scope.bindings)) {
        if (!names.has(name) || p.scope.bindings[name].scope !== p.scope) continue;
        if (!todo.some((x) => x.scope === p.scope && x.name === name)) todo.push({ scope: p.scope, name });
      }
    },
  });
  for (const { scope, name } of todo) scope.rename(name, scope.generateUid(name));
  return todo.length;
}

/** Top-level functions whose free names are only each other, literal data and safe globals. */
function closedHelpers(ast: t.File): Helpers {
  const fns = new Map<string, t.FunctionDeclaration>();
  const data = new Map<string, t.Expression>();
  const root = helperRoot(ast);
  // Data is evaluated as initialised, so its declaration must run before any
  // code can read it: it has to sit in the root's inert prefix (declarations
  // and literal writes only — nothing that can call a function).
  let inert = true;
  for (const s of root.body) {
    if (t.isFunctionDeclaration(s) && s.id && !s.async && !s.generator) fns.set(s.id.name, s);
    if (t.isVariableDeclaration(s) && inert)
      for (const d of s.declarations) if (t.isIdentifier(d.id) && isLiteralData(d.init)) data.set(d.id.name, d.init!);
    if (!t.isFunctionDeclaration(s) && !(t.isVariableDeclaration(s) && s.declarations.every((d) => !d.init || isLiteralData(d.init))))
      inert = false;
  }
  // Expressions are judged by spelling (pureOver): a helper, pool or safe
  // global is only recognised by name if no other binding anywhere reuses it.
  const bindingsOf = new Map<string, Set<Binding>>();
  traverse(ast, {
    Scopable(p) {
      for (const [name, b] of Object.entries(p.scope.bindings)) {
        if (!bindingsOf.has(name)) bindingsOf.set(name, new Set());
        bindingsOf.get(name)!.add(b);
      }
    },
  });
  const rebound = new Set<string>();
  for (const [name, bs] of bindingsOf) if (bs.size > 1 || SAFE.has(name)) rebound.add(name);
  for (const name of rebound) {
    fns.delete(name);
    data.delete(name);
  }
  const atRoot = (p: NodePath): boolean => p.parentPath?.node === root.block;
  const rootScoped = (b: Binding): boolean => b.scope.path.node === root.scope || b.scope.path.isProgram();
  const free = new Map<string, Set<string>>();
  traverse(ast, {
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id || !fns.has(id.name) || !atRoot(p)) return;
      const names = new Set<string>();
      p.traverse({
        Identifier(ip) {
          if (!ip.isReferencedIdentifier()) return;
          const b = ip.scope.getBinding(ip.node.name);
          if (!b || rootScoped(b)) names.add(ip.node.name);
        },
        ThisExpression() {
          names.add('this');
        },
      });
      free.set(id.name, names);
      p.skip();
    },
  });
  const closed = new Set(fns.keys());
  for (let ch = true; ch; ) {
    ch = false;
    for (const f of [...closed]) {
      for (const n of free.get(f) ?? []) {
        if (n === f || closed.has(n) || data.has(n) || SAFE.has(n)) continue;
        closed.delete(f);
        ch = true;
        break;
      }
    }
  }
  // Closed is not enough: a helper is only evaluated at deobfuscation time if
  // it cannot change anything — it writes nothing but its own locals and calls
  // nothing that mutates. Otherwise folding its call would drop the effect.
  const pure = new Set<string>();
  traverse(ast, {
    FunctionDeclaration(p) {
      const id = p.node.id;
      if (!id || !closed.has(id.name) || !atRoot(p)) return;
      let ok = true;
      p.traverse({
        Function(q) {
          ok = false;
          q.stop();
        },
        'AssignmentExpression|UpdateExpression'(q) {
          const target = q.isAssignmentExpression() ? q.node.left : (q.node as t.UpdateExpression).argument;
          if (!t.isIdentifier(target)) {
            ok = false;
            return;
          }
          // only the helper's own parameters and locals may be written
          const b = q.scope.getBinding(target.name);
          const ownScope = !!b && (b.scope.path.node === p.node || !!b.scope.path.findParent((x) => x.node === p.node));
          if (!ownScope) ok = false;
        },
        UnaryExpression(q) {
          if (q.node.operator === 'delete') ok = false;
        },
        CallExpression(q) {
          const c = q.node.callee;
          if (t.isMemberExpression(c)) {
            const key = !c.computed && t.isIdentifier(c.property) ? c.property.name : t.isStringLiteral(c.property) ? c.property.value : null;
            if (key === null || MUTATING.has(key)) ok = false;
          } else if (!t.isIdentifier(c)) ok = false;
        },
        NewExpression(q) {
          if (!t.isIdentifier(q.node.callee) || !SAFE.has(q.node.callee.name)) ok = false;
        },
      });
      // The sandbox runs regenerated, compact code: a helper whose text could
      // be read (used as a value, not only called) prints differently — which
      // only newline self-checks look at, and they answer alike when the
      // original text had no newline either (see sandboxSafe in ../deobfuscator).
      const b = p.parentPath.scope.getBinding(id.name);
      const onlyCalled = !!b && b.referencePaths.every((r) => r.parentPath?.isCallExpression() && r.parentPath.node.callee === r.node);
      if (!b || (!onlyCalled && !(getSourceFacts()?.newlineFree ?? false))) ok = false;
      if (ok) pure.add(id.name);
      p.skip();
    },
  });
  for (let ch = true; ch; ) {
    ch = false;
    for (const f of [...pure])
      for (const n of free.get(f) ?? [])
        if (fns.has(n) && n !== f && !pure.has(n)) {
          pure.delete(f);
          ch = true;
          break;
        }
  }
  // Data is only read at deobfuscation time if nothing can change it at run
  // time: every reference is inside a pure helper, or a read-only member use.
  const immutable = new Set<string>();
  traverse(ast, {
    enter(p) {
      if (p.node !== root.scope) return;
      for (const [name] of data) {
        const b = p.scope.getBinding(name);
        if (!b || b.constantViolations.length) continue;
        let ok = true;
        for (const r of b.referencePaths) {
          const host = r.findParent((x) => x.isFunctionDeclaration() && atRoot(x));
          if (host && pure.has(((host.node as t.FunctionDeclaration).id as t.Identifier).name)) continue;
          const m = r.parentPath;
          if (!m?.isMemberExpression() || m.node.object !== r.node) {
            ok = false;
            break;
          }
          const up = m.parentPath;
          if ((up?.isAssignmentExpression() && up.node.left === m.node) || up?.isUpdateExpression() || up?.isUnaryExpression({ operator: 'delete' })) {
            ok = false;
            break;
          }
          const key = !m.node.computed && t.isIdentifier(m.node.property) ? m.node.property.name : null;
          if (up?.isCallExpression() && up.node.callee === m.node && (key === null || MUTATING.has(key))) {
            ok = false;
            break;
          }
        }
        if (ok) immutable.add(name);
      }
      p.stop();
    },
  });
  const pureData = new Map([...data].filter(([n]) => immutable.has(n)));
  return { fns, data: pureData, closed: pure, rebound };
}

/** Methods that change their receiver. */
const MUTATING = new Set(['push', 'pop', 'shift', 'unshift', 'splice', 'sort', 'reverse', 'fill', 'copyWithin', 'set', 'add', 'delete', 'clear']);

function makeSandbox(h: Helpers): import('vm').Context {
  const src: string[] = [];
  for (const [n, v] of h.data) src.push(`var ${n} = ${generate(v).code};`);
  for (const f of h.closed) src.push(generate(h.fns.get(f)!).code);
  const ctx = vm.createContext({});
  new vm.Script('Math.random = function () { throw new Error("nondeterministic"); };\n' + src.join('\n')).runInContext(
    ctx,
    { timeout: 2000 }
  );
  return ctx;
}

/** Pure in the state arrays `xs`, literals, closed helpers and safe globals — no effects. */
function pureOver(e: t.Node, xs: Set<string>, h: Helpers): boolean {
  let ok = true;
  const visit = (n: t.Node, parent: t.Node | null): void => {
    if (!ok) return;
    if (
      t.isAssignmentExpression(n) || t.isUpdateExpression(n) || t.isFunction(n) || t.isNewExpression(n) ||
      t.isThisExpression(n) || t.isAwaitExpression(n) || t.isYieldExpression(n) || t.isClass(n)
    ) {
      ok = false;
      return;
    }
    // `D.slice(a, b)` on an immutable literal pool copies part of it — the
    // entry-state spelling `[...D.slice(0, 3), -8198, …]`
    const poolSlice = (c: t.Node): boolean =>
      t.isMemberExpression(c) && !c.computed && t.isIdentifier(c.object) && h.data.has(c.object.name) && t.isIdentifier(c.property, { name: 'slice' });
    if (t.isCallExpression(n) && poolSlice(n.callee)) {
      n.arguments.forEach((a) => visit(a, n));
      return;
    }
    if (t.isCallExpression(n) && (!t.isIdentifier(n.callee) || !h.closed.has(n.callee.name))) {
      ok = false;
      return;
    }
    if (t.isIdentifier(n) && (!parent || t.isReferenced(n, parent))) {
      const asCallee = !!parent && t.isCallExpression(parent) && parent.callee === n;
      const known = xs.has(n.name) || h.data.has(n.name) || (SAFE.has(n.name) && !h.rebound.has(n.name)) || (asCallee && h.closed.has(n.name));
      if (!known) {
        ok = false;
        return;
      }
    }
    if (t.isMemberExpression(n) && !n.computed) {
      visit(n.object, n);
      return;
    }
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[n.type] ?? []) {
      const c = (n as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((x) => x && visit(x as t.Node, n));
      else if (c) visit(c as t.Node, n);
    }
  };
  visit(e, null);
  return ok;
}

function evalIn(ctx: import('vm').Context, e: t.Node, env: Record<string, number[]>): unknown {
  const params = Object.keys(env);
  const fn = new vm.Script(`(function (${params.join(',')}) { return (${generate(e).code}); })`).runInContext(ctx, {
    timeout: 1000,
  }) as (...a: unknown[]) => unknown;
  return fn(...params.map((p) => env[p].slice()));
}

function toLiteral(v: unknown): t.Expression | null {
  if (typeof v === 'number') {
    if (!Number.isFinite(v) || Object.is(v, -0)) return null;
    return v < 0 ? t.unaryExpression('-', t.numericLiteral(-v)) : t.numericLiteral(v);
  }
  if (typeof v === 'string') return t.stringLiteral(v);
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (v === undefined) return t.identifier('undefined');
  if (v === null) return t.nullLiteral();
  return null;
}

/**
 * Does `fn` rebind `name` for its whole body — as a parameter, its own name,
 * or a function-scoped declaration (`var`, nested function declaration)? Then
 * `name` inside it is a different variable. Block-scoped `let`/`const` shadow
 * only part of the body, so they do not count.
 */
function rebinds(fn: t.Function, name: string): boolean {
  // (a declaration's own name binds in the enclosing scope, an expression's inside)
  if (t.isFunctionExpression(fn) && fn.id?.name === name) return true;
  for (const pm of fn.params) if (name in t.getBindingIdentifiers(pm)) return true;
  let found = false;
  const v = (x: t.Node): void => {
    if (found) return;
    if (t.isVariableDeclaration(x, { kind: 'var' })) for (const d of x.declarations) if (name in t.getBindingIdentifiers(d.id)) found = true;
    if (t.isFunctionDeclaration(x)) {
      if (x.id?.name === name) found = true;
      return;
    }
    if (t.isFunction(x) || t.isClass(x)) return;
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[x.type] ?? []) {
      const c = (x as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((y) => y && v(y as t.Node));
      else if (c) v(c as t.Node);
    }
  };
  if (t.isBlockStatement(fn.body)) v(fn.body);
  return found;
}

/** Visit the nodes of `n` where `name` still means the outer variable. */
function walkUnshadowed(n: t.Node, name: string, f: (x: t.Node) => void): void {
  const v = (x: t.Node): void => {
    if (t.isFunction(x) && rebinds(x, name)) return;
    f(x);
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[x.type] ?? []) {
      const c = (x as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((y) => y && v(y as t.Node));
      else if (c) v(c as t.Node);
    }
  };
  v(n);
}

const mentions = (n: t.Node, name: string): boolean => {
  let r = false;
  walkUnshadowed(n, name, (x) => {
    if (t.isIdentifier(x, { name })) r = true;
  });
  return r;
};

/**
 * Clone `stmt`, replacing each maximal subexpression that is pure in the state
 * array and mentions it with its value. Nested functions are left alone: they
 * run later, when the array may hold something else.
 */
function concretize(stmt: t.Statement, X: string, arr: number[], ctx: import('vm').Context, h: Helpers): t.Statement {
  const xs = new Set([X]);
  const file = t.file(t.program([t.cloneNode(stmt, true)]));
  traverse(file, {
    Function(p) {
      p.skip();
    },
    Class(p) {
      p.skip();
    },
    enter(p) {
      if (!p.isExpression() || p.isLiteral()) return;
      const n = p.node;
      if (!mentions(n, X)) return;
      if (p.parentPath?.isAssignmentExpression() && p.parentPath.node.left === n) return;
      if (!pureOver(n, xs, h)) return;
      let v: unknown;
      try {
        v = evalIn(ctx, n, { [X]: arr });
      } catch {
        return;
      }
      const lit = toLiteral(v);
      if (!lit) return;
      p.replaceWith(lit);
      p.skip();
    },
  });
  return file.program.body[0];
}

// ── affine control updates ───────────────────────────────────────────────────

type Affine = { i: number; j: number; c: number; op: '+=' | '-=' };

/** `X[i] += X[j] - C` (or a sequence of them); null if anything else. */
function affineOps(e: t.Expression, X: string): Affine[] | null {
  const parts = t.isSequenceExpression(e) ? e.expressions : [e];
  const out: Affine[] = [];
  for (const a of parts) {
    if (!t.isAssignmentExpression(a) || (a.operator !== '+=' && a.operator !== '-=')) return null;
    const l = a.left;
    if (!t.isMemberExpression(l) || !t.isIdentifier(l.object, { name: X }) || !t.isNumericLiteral(l.property)) return null;
    const r = a.right;
    if (!t.isBinaryExpression(r) || (r.operator !== '-' && r.operator !== '+')) return null;
    if (!t.isMemberExpression(r.left) || !t.isIdentifier(r.left.object, { name: X }) || !t.isNumericLiteral(r.left.property))
      return null;
    let c: number;
    if (t.isNumericLiteral(r.right)) c = r.right.value;
    else if (t.isUnaryExpression(r.right, { operator: '-' }) && t.isNumericLiteral(r.right.argument)) c = -r.right.argument.value;
    else return null;
    out.push({ i: l.property.value, j: r.left.property.value, c: r.operator === '-' ? -c : c, op: a.operator });
  }
  return out;
}

/** `while (true) {}` / `for (;;) {}` — js-confuser's countermeasure: the path never completes. */
function spinsForever(st: t.Statement): boolean {
  const empty = (b: t.Statement) => t.isEmptyStatement(b) || (t.isBlockStatement(b) && b.body.length === 0);
  if (t.isWhileStatement(st)) return (t.isBooleanLiteral(st.test, { value: true }) || (t.isNumericLiteral(st.test) && st.test.value !== 0)) && empty(st.body);
  if (t.isForStatement(st)) return !st.init && !st.test && !st.update && empty(st.body);
  return false;
}
const spinNode = (nid: () => number): Node => ({
  id: nid(),
  kind: 'block',
  stmts: [t.whileStatement(t.booleanLiteral(true), t.blockStatement([]))],
  next: { id: nid(), kind: 'ret' },
});

function applyAffine(arr: number[], ops: Affine[]): void {
  for (const o of ops) {
    const d = arr[o.j] + o.c;
    arr[o.i] = o.op === '+=' ? arr[o.i] + d : arr[o.i] - d;
  }
}

function writesState(n: t.Node, X: string): boolean {
  let w = false;
  walkUnshadowed(n, X, (x) => {
    if (
      (t.isAssignmentExpression(x) && t.isMemberExpression(x.left) && t.isIdentifier(x.left.object, { name: X })) ||
      (t.isUpdateExpression(x) && t.isMemberExpression(x.argument) && t.isIdentifier(x.argument.object, { name: X }))
    )
      w = true;
  });
  return w;
}

/** A break/continue that leaves `n` toward the dispatcher (labels declared inside `n` are fine). */
function jumpsOut(n: t.Node): boolean {
  let j = false;
  const v = (x: t.Node, loops: number, sw: number, labels: Set<string>): void => {
    if (j || t.isFunction(x)) return;
    if (t.isBreakStatement(x) || t.isContinueStatement(x)) {
      if (x.label) {
        if (!labels.has(x.label.name)) j = true;
      } else if (t.isBreakStatement(x) ? loops === 0 && sw === 0 : loops === 0) j = true;
      return;
    }
    const L = t.isLoop(x) ? 1 : 0;
    const S = t.isSwitchStatement(x) ? 1 : 0;
    const lb = t.isLabeledStatement(x) ? new Set([...labels, x.label.name]) : labels;
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[x.type] ?? []) {
      const c = (x as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((y) => y && v(y as t.Node, loops + L, sw + S, lb));
      else if (c) v(c as t.Node, loops + L, sw + S, lb);
    }
  };
  v(n, 0, 0, new Set());
  return j;
}

// ── 3. simulation → control-flow graph ───────────────────────────────────────

type Node =
  | { id: number; kind: 'block'; stmts: t.Statement[]; next: Node | null }
  | { id: number; kind: 'cond'; test: t.Expression; then: Node; else: Node }
  | { id: number; kind: 'end' }
  | { id: number; kind: 'ret' };

/** `while (SUM(X) !== T) switch (SUM(X)) { … }` → [X, SUM, switch] or null. */
function dispatcherShape(loop: t.WhileStatement): { X: string; sum: string; sw: t.SwitchStatement } | null {
  const tst = loop.test;
  if (!t.isBinaryExpression(tst, { operator: '!==' }) || !t.isCallExpression(tst.left) || !t.isIdentifier(tst.left.callee))
    return null;
  if (tst.left.arguments.length !== 1 || !t.isIdentifier(tst.left.arguments[0])) return null;
  const body = t.isBlockStatement(loop.body) ? loop.body.body : [loop.body];
  if (body.length !== 1 || !t.isSwitchStatement(body[0])) return null;
  const sw = body[0];
  const d = sw.discriminant;
  if (!t.isCallExpression(d) || !t.isIdentifier(d.callee, { name: tst.left.callee.name })) return null;
  if (d.arguments.length !== 1 || !t.isIdentifier(d.arguments[0], { name: tst.left.arguments[0].name })) return null;
  return { X: tst.left.arguments[0].name, sum: tst.left.callee.name, sw };
}

function buildCfg(loop: t.WhileStatement, init: number[], ctx: import('vm').Context, h: Helpers): Node {
  const shape = dispatcherShape(loop);
  if (!shape) throw new Abort('loop shape');
  const { X, sum, sw } = shape;
  if (!h.closed.has(sum)) throw new Abort('sum helper not closed');
  // the summing helper must actually sum
  if (evalIn(ctx, t.callExpression(t.identifier(sum), [t.arrayExpression([t.numericLiteral(2), t.numericLiteral(5)])]), {}) !== 7)
    throw new Abort('sum helper');
  const term = evalIn(ctx, (loop.test as t.BinaryExpression).right, {});
  if (typeof term !== 'number') throw new Abort('terminal');
  const xs = new Set([X]);
  let nid = 0;
  let budget = 400_000;
  const heads = new Map<string, Node>();

  const head = (arr: number[]): Node => {
    const key = arr.join(',');
    const hit = heads.get(key);
    if (hit) return hit;
    if (heads.size >= 5000) throw new Abort('too many states');
    const stub: Node = { id: nid++, kind: 'block', stmts: [], next: null };
    heads.set(key, stub);
    const s = arr.reduce((a, b) => a + b, 0);
    let res: Node;
    if (s === term) res = { id: nid++, kind: 'end' };
    else {
      let idx = -1;
      for (let k = 0; k < sw.cases.length; k++) {
        const cs = sw.cases[k];
        if (!cs.test) continue;
        if (!pureOver(cs.test, xs, h)) throw new Abort('case label');
        if (evalIn(ctx, cs.test, { [X]: arr }) === s) {
          idx = k;
          break;
        }
      }
      if (idx < 0) idx = sw.cases.findIndex((c) => !c.test);
      if (idx < 0) {
        // No label matches and nothing changes the state: the loop re-tests
        // the same sum forever. Such a state is only reached down a path the
        // original never takes (a countermeasure's `while (true) {}` case
        // falls through into updates), and spinning is what it would do.
        res = spinNode(() => nid++);
      } else {
        const flat: t.Statement[] = [];
        for (let k = idx; k < sw.cases.length; k++) flat.push(...sw.cases[k].consequent);
        // falling off the last case re-enters the loop
        res = execList(flat, 0, arr.slice(), (a) => head(a));
      }
    }
    stub.next = res;
    return stub;
  };

  const execList = (stmts: t.Statement[], i: number, arr: number[], k: (a: number[]) => Node): Node => {
    for (; i < stmts.length; i++) {
      if (--budget < 0) throw new Abort('budget');
      const s = stmts[i];
      if (t.isEmptyStatement(s)) continue;
      if ((t.isBreakStatement(s) || t.isContinueStatement(s)) && !s.label) return head(arr);
      // the path ends here; what follows (more updates, a fall-through) never runs
      if (spinsForever(s)) return spinNode(() => nid++);
      if (t.isBlockStatement(s)) {
        const rest = i + 1;
        return execList(s.body, 0, arr, (a) => execList(stmts, rest, a, k));
      }
      if (t.isExpressionStatement(s)) {
        const ops = affineOps(s.expression, X);
        if (ops) {
          applyAffine(arr, ops);
          continue;
        }
      }
      if (t.isIfStatement(s)) {
        const rest = i + 1;
        const after = (a: number[]) => execList(stmts, rest, a, k);
        const branch = (b: t.Statement | null | undefined, a: number[]) => (b ? execList([b], 0, a, after) : after(a));
        if (pureOver(s.test, xs, h)) return evalIn(ctx, s.test, { [X]: arr }) ? branch(s.consequent, arr) : branch(s.alternate, arr);
        // a condition on program data: a real branch of the original program
        if (writesState(s.test, X)) throw new Abort('condition writes state');
        const c = concretize(t.expressionStatement(s.test), X, arr, ctx, h) as t.ExpressionStatement;
        if (mentions(c, X)) throw new Abort('condition still reads state');
        return { id: nid++, kind: 'cond', test: c.expression, then: branch(s.consequent, arr.slice()), else: branch(s.alternate, arr.slice()) };
      }
      if (writesState(s, X)) throw new Abort('statement writes state');
      if (jumpsOut(s)) throw new Abort('statement jumps out');
      const c = concretize(s, X, arr, ctx, h);
      if (mentions(c, X)) throw new Abort('statement still reads state');
      if (t.isReturnStatement(s)) return { id: nid++, kind: 'block', stmts: [c], next: { id: nid++, kind: 'ret' } };
      const rest = i + 1;
      return { id: nid++, kind: 'block', stmts: [c], next: execList(stmts, rest, arr.slice(), k) };
    }
    return k(arr);
  };

  return head(init.slice());
}

// ── 3b. structuring ──────────────────────────────────────────────────────────

const successors = (n: Node): Node[] => (n.kind === 'block' ? (n.next ? [n.next] : []) : n.kind === 'cond' ? [n.then, n.else] : []);

function structure(entry: Node): t.Statement[] {
  // collapse empty forwarding blocks so a node is a code location
  const real = (n: Node | null): Node | null => {
    const seen = new Set<Node>();
    while (n && n.kind === 'block' && n.stmts.length === 0 && n.next && !seen.has(n)) {
      seen.add(n);
      n = n.next;
    }
    return n;
  };
  const all = new Set<Node>();
  for (const st = [entry]; st.length; ) {
    const x = st.pop()!;
    if (all.has(x)) continue;
    all.add(x);
    st.push(...successors(x));
  }
  for (const n of all) {
    if (n.kind === 'block') n.next = real(n.next);
    if (n.kind === 'cond') {
      n.then = real(n.then)!;
      n.else = real(n.else)!;
    }
  }
  const start = real(entry)!;

  // DFS: back-edges and reverse postorder
  const back = new Set<string>();
  const onStack = new Set<Node>();
  const seen = new Set<Node>();
  const post: Node[] = [];
  const key = (u: Node, v: Node) => `${u.id}>${v.id}`;
  const dfs = (u: Node): void => {
    seen.add(u);
    onStack.add(u);
    for (const v of successors(u)) {
      if (onStack.has(v)) back.add(key(u, v));
      else if (!seen.has(v)) dfs(v);
    }
    onStack.delete(u);
    post.push(u);
  };
  dfs(start);
  const order = post.reverse();
  const rpo = new Map<Node, number>();
  order.forEach((n, i) => rpo.set(n, i));
  const byId = new Map<number, Node>(order.map((n) => [n.id, n]));
  const dagSucc = (n: Node) => successors(n).filter((v) => !back.has(key(n, v)));

  // dominators, to reject irreducible graphs
  const preds = new Map<Node, Node[]>();
  for (const n of order) preds.set(n, []);
  for (const n of order) for (const v of successors(n)) preds.get(v)?.push(n);
  const idom = new Map<Node, Node>([[start, start]]);
  const intersect = (a: Node, b: Node): Node => {
    while (a !== b) {
      while (rpo.get(a)! > rpo.get(b)!) a = idom.get(a)!;
      while (rpo.get(b)! > rpo.get(a)!) b = idom.get(b)!;
    }
    return a;
  };
  for (let ch = true; ch; ) {
    ch = false;
    for (const n of order) {
      if (n === start) continue;
      const ps = preds.get(n)!.filter((p) => idom.has(p));
      if (!ps.length) continue;
      let d = ps[0];
      for (const p of ps.slice(1)) d = intersect(p, d);
      if (idom.get(n) !== d) {
        idom.set(n, d);
        ch = true;
      }
    }
  }
  const dominates = (a: Node, b: Node): boolean => {
    for (let x: Node | undefined = b; x; ) {
      if (x === a) return true;
      const nx = idom.get(x);
      if (!nx || nx === x) return false;
      x = nx;
    }
    return false;
  };

  // natural loops
  type Loop = { header: Node; body: Set<Node>; follow: Node | null; label: string };
  const loops = new Map<Node, Loop>();
  const existing = new Set<string>();
  for (const n of order)
    if (n.kind === 'block')
      for (const st of n.stmts)
        t.traverseFast(st, (x) => {
          if (t.isLabeledStatement(x)) existing.add(x.label.name);
        });
  const generated = new Set<string>();
  let lbl = 0;
  for (const e of back) {
    const [u, v] = e.split('>').map(Number);
    const U = byId.get(u)!;
    const Hd = byId.get(v)!;
    if (!dominates(Hd, U)) throw new Abort('irreducible');
    let L = loops.get(Hd);
    if (!L) {
      let name: string;
      do name = `loop${++lbl}`;
      while (existing.has(name));
      generated.add(name);
      L = { header: Hd, body: new Set([Hd]), follow: null, label: name };
      loops.set(Hd, L);
    }
    for (const st = [U]; st.length; ) {
      const x = st.pop()!;
      if (L.body.has(x)) continue;
      L.body.add(x);
      st.push(...(preds.get(x) ?? []));
    }
  }
  const sink = (n: Node) => n.kind === 'end' || n.kind === 'ret';
  for (const L of loops.values()) {
    const exits = new Set<Node>();
    for (const b of L.body) for (const v of successors(b)) if (!L.body.has(v) && !sink(v)) exits.add(v);
    if (exits.size > 1) throw new Abort('loop with several exits');
    L.follow = exits.size ? [...exits][0] : null;
  }

  // if/else merge: the earliest node both arms reach in the acyclic graph
  const reachMemo = new Map<Node, Set<Node>>();
  const reach = (n: Node): Set<Node> => {
    const hit = reachMemo.get(n);
    if (hit) return hit;
    const out = new Set<Node>();
    for (const st = [n]; st.length; ) {
      const x = st.pop()!;
      if (out.has(x)) continue;
      out.add(x);
      st.push(...dagSucc(x));
    }
    reachMemo.set(n, out);
    return out;
  };
  const mergeOf = (c: Extract<Node, { kind: 'cond' }>, inLoop: Loop | null): Node | null => {
    const a = reach(c.then);
    const b = reach(c.else);
    let best: Node | null = null;
    for (const x of a)
      if (b.has(x) && (!inLoop || inLoop.body.has(x) || x === inLoop.follow))
        if (!best || rpo.get(x)! < rpo.get(best)!) best = x;
    return best;
  };

  const used = new Set<string>();
  const emitted = new Set<Node>();
  type Ctx = { stop: Node | null; loops: Loop[]; atHeader: Loop | null };
  const jump = (kind: 'break' | 'continue', L: Loop, ctx: Ctx): t.Statement => {
    const label = ctx.loops[ctx.loops.length - 1] === L ? null : t.identifier(L.label);
    if (label) used.add(L.label);
    return kind === 'break' ? t.breakStatement(label) : t.continueStatement(label);
  };
  const emit = (n0: Node | null, ctx: Ctx): t.Statement[] => {
    const out: t.Statement[] = [];
    let n = n0;
    let first = true;
    while (n) {
      if (n === ctx.stop) break;
      let jumped = false;
      for (let i = ctx.loops.length - 1; i >= 0 && !jumped; i--) {
        const L = ctx.loops[i];
        if (n === L.header && !(first && ctx.atHeader === L)) {
          out.push(jump('continue', L, ctx));
          jumped = true;
        } else if (n === L.follow) {
          out.push(jump('break', L, ctx));
          jumped = true;
        }
      }
      if (jumped) break;
      first = false;
      const L = loops.get(n);
      if (L && !ctx.loops.includes(L)) {
        const body = emit(n, { stop: null, loops: [...ctx.loops, L], atHeader: L });
        const last = body[body.length - 1];
        if (last && t.isContinueStatement(last) && !last.label) body.pop();
        out.push(t.labeledStatement(t.identifier(L.label), t.whileStatement(t.booleanLiteral(true), t.blockStatement(body))));
        n = L.follow;
        continue;
      }
      if (emitted.has(n) && !sink(n)) throw new Abort('node emitted twice');
      emitted.add(n);
      if (n.kind === 'block') {
        out.push(...n.stmts);
        n = n.next;
        continue;
      }
      if (n.kind === 'ret') break;
      if (n.kind === 'end') {
        if (ctx.loops.length || ctx.stop) out.push(t.returnStatement());
        break;
      }
      const inLoop = ctx.loops[ctx.loops.length - 1] ?? null;
      const m = mergeOf(n, inLoop);
      const thenS = emit(n.then, { stop: m, loops: ctx.loops, atHeader: null });
      const elseS = emit(n.else, { stop: m, loops: ctx.loops, atHeader: null });
      out.push(t.ifStatement(n.test, t.blockStatement(thenS), elseS.length ? t.blockStatement(elseS) : null));
      n = m;
    }
    return out;
  };
  const stmts = emit(start, { stop: null, loops: [], atHeader: null });

  // labels we generated and nothing jumps to
  const dead = (y: t.Node | null | undefined): y is t.LabeledStatement =>
    !!y && t.isLabeledStatement(y) && generated.has(y.label.name) && !used.has(y.label.name);
  const unlabel = (s: t.Statement): t.Statement => {
    const top = dead(s) ? s.body : s;
    t.traverseFast(top, (x) => {
      const rec = x as unknown as Record<string, unknown>;
      for (const k of ['body', 'consequent', 'alternate']) {
        const v = rec[k];
        if (Array.isArray(v)) rec[k] = v.map((y) => (dead(y as t.Node) ? (y as t.LabeledStatement).body : y));
        else if (dead(v as t.Node)) rec[k] = (v as t.LabeledStatement).body;
      }
    });
    return top;
  };
  return stmts.map(unlabel);
}

// ── 2. specialising the dispatcher function per entry ────────────────────────

type Dispatcher = { fn: t.FunctionDeclaration; loop: t.WhileStatement };

/** Function declarations (any depth) whose body is exactly a dispatcher loop over their first param. */
function findDispatchers(ast: t.File): Map<t.FunctionDeclaration, Dispatcher> {
  const out = new Map<t.FunctionDeclaration, Dispatcher>();
  traverse(ast, {
    FunctionDeclaration(p) {
      const s = p.node;
      if (!s.id || !t.isIdentifier(s.params[0]) || s.async || s.generator) return;
      // the loop alone, or followed by a bare `return;` (falling off the end
      // does the same)
      const [loop, tail, ...more] = s.body.body;
      if (!t.isWhileStatement(loop) || more.length || (tail && !(t.isReturnStatement(tail) && !tail.argument))) return;
      const shape = dispatcherShape(loop);
      if (!shape || shape.X !== (s.params[0] as t.Identifier).name) return;
      out.set(s, { fn: s, loop });
    },
  });
  return out;
}

function staticArray(e: t.Node | undefined, ctx: import('vm').Context, h: Helpers): number[] | null {
  if (!e || !t.isArrayExpression(e)) return null;
  for (const el of e.elements) {
    if (!el) return null;
    if (!pureOver(t.isSpreadElement(el) ? el.argument : el, new Set(), h)) return null;
  }
  try {
    const v = evalIn(ctx, e, {});
    return Array.isArray(v) && v.every((x) => typeof x === 'number') ? (v as number[]) : null;
  } catch {
    return null;
  }
}

function expandDispatchers(ast: t.File, ctx: import('vm').Context, h: Helpers, why: string[]): { ast: t.File; n: number } {
  let n = 0;
  for (let round = 0; round < 50; round++) {
    const disp = findDispatchers(ast);
    if (disp.size === 0) break;
    let changed = false;
    traverse(ast, {
      CallExpression(p) {
        if (!t.isIdentifier(p.node.callee)) return;
        const decl = p.scope.getBinding(p.node.callee.name)?.path.node;
        if (!decl || !t.isFunctionDeclaration(decl) || !disp.has(decl)) return;
        // calls inside a dispatcher are the machinery being replaced
        if (p.findParent((q) => q.isFunctionDeclaration() && disp.has(q.node as t.FunctionDeclaration))) return;
        const d = disp.get(decl)!;
        const init = staticArray(p.node.arguments[0], ctx, h);
        if (!init) {
          why.push('non-static entry state');
          return;
        }
        let body: t.Statement[];
        try {
          body = structure(buildCfg(d.loop, init, ctx, h));
        } catch (e) {
          if (e instanceof Abort) {
            why.push(e.message);
            return;
          }
          throw e;
        }
        const params = d.fn.params.slice(1).map((pm) => t.cloneNode(pm, true)) as t.FunctionExpression['params'];
        p.replaceWith(t.callExpression(t.functionExpression(null, params, t.blockStatement(body)), p.node.arguments.slice(1)));
        p.skip();
        n++;
        changed = true;
      },
    });
    ast = reparse(ast);
    if (!changed) break;
  }
  // dispatchers nothing outside their own body references any more
  for (let round = 0; round < 5; round++) {
    let removed = false;
    const disp = findDispatchers(ast);
    traverse(ast, {
      FunctionDeclaration(p) {
        if (!disp.has(p.node)) return;
        const b = p.parentPath.scope.getBinding(p.node.id!.name);
        if (!b || b.path.node !== p.node) return;
        if (b.referencePaths.some((r) => !r.findParent((q) => q.node === p.node))) return;
        p.remove();
        removed = true;
      },
    });
    ast = reparse(ast);
    if (!removed) break;
  }
  return { ast, n };
}

/**
 * `xor(264483, 971, 7)` — a closed pure helper called with literal arguments,
 * anywhere (also in closures the simulation leaves alone): its value does not
 * depend on any state, so it is the constant the sandbox computes. The callee
 * must be the root helper itself (names are unique, see uniquifyHelperNames).
 */
function foldHelperCalls(ast: t.File, ctx: import('vm').Context, h: Helpers): number {
  let n = 0;
  const literal = (a: t.Node): boolean =>
    t.isNumericLiteral(a) || t.isStringLiteral(a) || (t.isUnaryExpression(a, { operator: '-' }) && t.isNumericLiteral(a.argument));
  traverse(ast, {
    CallExpression(p) {
      const c = p.node.callee;
      if (!t.isIdentifier(c) || !h.closed.has(c.name) || h.rebound.has(c.name)) return;
      if (!p.node.arguments.every(literal)) return;
      let v: unknown;
      try {
        v = evalIn(ctx, p.node, {});
      } catch {
        return;
      }
      const lit = toLiteral(v);
      if (!lit) return;
      p.replaceWith(lit);
      p.skip();
      n++;
    },
  });
  return n;
}

/**
 * `f([...POOL.slice(0, 3), 391, …])` where f no longer takes that parameter
 * (its state array, after linearisation): an argument beyond f's parameters
 * is never bound, so if f cannot see it through `arguments` and evaluating it
 * has no effect (pureOver: literals, immutable pools, pure helpers), it can go.
 * f must be a function declaration nothing reassigns.
 */
function dropSurplusArgs(ast: t.File, h: Helpers): number {
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      const c = p.node.callee;
      if (!t.isIdentifier(c)) return;
      const b = p.scope.getBinding(c.name);
      if (!b || !b.path.isFunctionDeclaration() || b.constantViolations.some((v) => v.node !== b.path.node)) return;
      const fn = b.path.node;
      if (fn.params.some((pm) => t.isRestElement(pm)) || p.node.arguments.length <= fn.params.length) return;
      if (ownContextSensitive(fn)) return;
      const extra = p.node.arguments.slice(fn.params.length);
      if (!extra.every((a) => !t.isSpreadElement(a) && pureOver(a, new Set(), h))) return;
      p.node.arguments = p.node.arguments.slice(0, fn.params.length);
      n++;
    },
  });
  return n;
}

// ── 4. scope frames → variables ──────────────────────────────────────────────

// `S["K"]` and `S.K` are one access; later passes turn the first into the
// second, so a sweep can hand either spelling to this pass.
const strKey = (m: t.Node): string | null =>
  !t.isMemberExpression(m) ? null : m.computed ? (t.isStringLiteral(m.property) ? m.property.value : null) : t.isIdentifier(m.property) ? m.property.name : null;
/** The key of `{ ["K"]: … }`, `{ K: … }` or `{ "K": … }`. */
const propKey = (pr: t.Node): string | null =>
  !t.isObjectProperty(pr)
    ? null
    : t.isStringLiteral(pr.key)
      ? pr.key.value
      : !pr.computed && t.isIdentifier(pr.key)
        ? pr.key.name
        : null;
const isFrameLiteral = (n: t.Node | null | undefined): n is t.ObjectExpression =>
  t.isObjectExpression(n) &&
  n.properties.length > 0 &&
  n.properties.every((pr) => propKey(pr) !== null && t.isObjectExpression((pr as t.ObjectProperty).value) && ((pr as t.ObjectProperty).value as t.ObjectExpression).properties.length === 0);

type Frame = {
  call: NodePath<t.CallExpression> | null; // a param frame's IIFE call
  fn: NodePath<t.Function>; // where its variables are declared
  P: Binding; // the binding holding the scope object
  owned: string[];
  keys: string[]; // every frame key reachable through P here (owned and inherited)
  usesArguments: boolean;
  local: NodePath<t.Statement> | null; // a local frame's single assignment
  member?: boolean; // `P.K = {}` adding frame K to frame object P
};

function lowerFrames(ast: t.File, why: string[]): number {
  const frames: Frame[] = [];
  // param frames: (function (scope = {…}, …) { … })({…}, …)
  traverse(ast, {
    CallExpression(p) {
      const callee = p.get('callee');
      if (!callee.isFunctionExpression()) return;
      const p0 = callee.node.params[0];
      let name: string | null = null;
      let def: t.Expression | null = null;
      if (t.isIdentifier(p0)) name = p0.name;
      else if (t.isAssignmentPattern(p0) && t.isIdentifier(p0.left)) {
        name = p0.left.name;
        def = p0.right;
      }
      if (!name) return;
      const a0 = p.node.arguments[0];
      const obj = a0 && !t.isIdentifier(a0, { name: 'undefined' }) ? a0 : def;
      if (!t.isObjectExpression(obj) || obj.properties.length === 0) return;
      const owned: string[] = [];
      const keys: string[] = [];
      for (const pr of obj.properties) {
        const key = propKey(pr);
        if (key === null) return;
        const value = (pr as t.ObjectProperty).value;
        if (t.isObjectExpression(value) && value.properties.length === 0) owned.push(key);
        else if (!(t.isMemberExpression(value) && t.isIdentifier(value.object) && strKey(value) === key)) return;
        keys.push(key);
      }
      const P = callee.scope.getBinding(name);
      if (!P || P.kind !== 'param' || P.constantViolations.length) return;
      let usesArgs = false;
      callee.traverse({
        Function(q) {
          if (!q.isArrowFunctionExpression()) q.skip();
        },
        Identifier(q) {
          if (q.node.name === 'arguments' && q.isReferencedIdentifier()) usesArgs = true;
        },
      });
      frames.push({ call: p, fn: callee, P, owned, keys, usesArguments: usesArgs, local: null });
    },
  });
  // local frames: `B = { ["K"]: {} }` assigned once at the top level of the declaring function
  traverse(ast, {
    AssignmentExpression(p) {
      if (p.node.operator !== '=' || !t.isIdentifier(p.node.left) || !isFrameLiteral(p.node.right)) return;
      const stmt = p.parentPath;
      if (!stmt?.isExpressionStatement()) return;
      const B = p.scope.getBinding(p.node.left.name);
      if (!B || B.kind === 'param' || B.constantViolations.length !== 1 || B.constantViolations[0].node !== p.node) return;
      if (B.path.isVariableDeclarator() && B.path.node.init) return;
      const fn = stmt.getFunctionParent();
      if (!fn || B.scope.path.node !== fn.node || stmt.parentPath?.node !== fn.node.body) return;
      const owned = (p.node.right as t.ObjectExpression).properties.map((pr) => propKey(pr)!);
      frames.push({ call: null, fn, P: B, owned, keys: owned, usesArguments: false, local: stmt });
    },
  });
  // member frames: `P.K = {}` on a frame object P, in P's own function — the
  // frame of a block-scoped declaration, created when its block runs. As a
  // `var` in that function it is the same variable provided the statement
  // runs at most once per activation (no loop around it, so no earlier
  // object a closure could still hold) and every access to K follows it in
  // the same statement list (so none can run while P.K is still missing).
  const memberOf = new Map<string, NodePath<t.ExpressionStatement>>();
  {
    const byBinding = new Map(frames.map((f) => [f.P, f] as const));
    traverse(ast, {
      AssignmentExpression(p) {
        const { left, right } = p.node;
        if (p.node.operator !== '=' || !t.isMemberExpression(left) || !t.isIdentifier(left.object)) return;
        const K = strKey(left);
        if (K === null || !t.isObjectExpression(right) || right.properties.length) return;
        const stmt = p.parentPath;
        if (!stmt?.isExpressionStatement() || !Array.isArray(stmt.container)) return;
        const P = p.scope.getBinding(left.object.name);
        const pf = P ? byBinding.get(P) : undefined;
        if (!pf || pf.member || stmt.getFunctionParent()?.node !== pf.fn.node) return;
        for (let q: NodePath | null = stmt.parentPath; q && q.node !== pf.fn.node; q = q.parentPath) if (q.isLoop()) return;
        if (memberOf.has(K)) {
          why.push('member frame created twice');
          return;
        }
        memberOf.set(K, stmt);
        frames.push({ call: null, fn: pf.fn, P: pf.P, owned: [K], keys: [K], usesArguments: false, local: stmt, member: true });
      },
    });
  }
  /** `a` lies in a statement after member frame K's creation, in the same list. */
  const afterCreation = (a: NodePath, K: string): boolean => {
    const cs = memberOf.get(K);
    if (!cs) return true;
    for (let q: NodePath | null = a; q; q = q.parentPath)
      if (q.container === cs.container && typeof q.key === 'number') return q.key > (cs.key as number);
    return false;
  };
  if (frames.length === 0) return 0;

  // Each frame key is judged on its own: a key whose object can be reached
  // other than through the accesses below (it is passed to a call nobody
  // here expands, deleted, created twice, …) stays an object, while every
  // other key still becomes variables. Keys are program-wide names: a frame
  // inheriting K hands on the very object its parent holds under K.
  const bad = new Set<string>();
  const keysOf = new Map<Binding, Set<string>>();
  for (const f of frames) {
    const set = keysOf.get(f.P) ?? new Set<string>();
    for (const k of f.keys) set.add(k);
    keysOf.set(f.P, set);
  }
  const owner = new Map<string, Frame>();
  for (const f of frames)
    for (const k of f.owned) {
      if (owner.has(k)) {
        why.push(`frame ${k} owned twice`);
        bad.add(k);
      }
      owner.set(k, f);
    }
  // `{ K: {} }` anywhere else (a dispatcher call left unexpanded still creates
  // frames): K's object exists outside this analysis, so a frame reading it
  // is neither lowered nor treated as missing.
  const createdElsewhere = new Set<string>();
  {
    const ownLiterals = new Set<t.Node>();
    for (const f of frames) {
      if (f.call) {
        // the argument, and a default the argument makes dead
        const a0 = f.call.node.arguments[0];
        if (a0) ownLiterals.add(a0);
        const p0 = f.fn.node.params[0];
        if (t.isAssignmentPattern(p0)) ownLiterals.add(p0.right);
      } else if (f.member) ownLiterals.add((f.local!.node as t.ExpressionStatement).expression);
      else ownLiterals.add(((f.local!.node as t.ExpressionStatement).expression as t.AssignmentExpression).right);
    }
    traverse(ast, {
      ObjectProperty(p) {
        const k = propKey(p.node);
        if (k === null || !t.isObjectExpression(p.node.value) || p.node.value.properties.length) return;
        if (!ownLiterals.has(p.parent)) createdElsewhere.add(k);
      },
      AssignmentExpression(p) {
        const { left, right } = p.node;
        const k = t.isMemberExpression(left) ? strKey(left) : null;
        if (k === null || !t.isObjectExpression(right) || right.properties.length || ownLiterals.has(p.node)) return;
        createdElsewhere.add(k);
      },
    });
    for (const k of createdElsewhere) {
      if (!owner.has(k)) continue;
      why.push(`frame ${k} created elsewhere`);
      bad.add(k);
    }
  }

  type Access = { path: NodePath; k: string; v: string };
  const accesses: Access[] = [];
  // `{ K: P.K }` handing K on to a child frame: dead once K is variables
  const inherited: { prop: NodePath; k: string }[] = [];
  // `S.K.v` for a K no frame object has (js-confuser's junk updates in dead
  // branches): `S.K` is undefined, so the access throws a TypeError on
  // reading `v` — exactly what `(void 0).v` does.
  const missing: NodePath[] = [];
  for (const f of frames) {
    if (f.member) continue; // its references are P's, visited with P's frame
    for (const r of f.P.referencePaths) {
      const m1 = r.parentPath;
      const k = m1 && (m1.node as t.MemberExpression).object === r.node ? strKey(m1.node) : null;
      if (!m1 || k === null) {
        why.push(`frame object ${f.P.identifier.name} used directly`);
        for (const key of keysOf.get(f.P)!) bad.add(key);
        continue;
      }
      const m2 = m1.parentPath!;
      // the creation `P.K = {}` itself
      if (memberOf.get(k)?.node.expression === m2.node && (m2.node as t.AssignmentExpression).left === m1.node) continue;
      if (!afterCreation(m1, k)) {
        why.push(`member frame ${k} used before creation`);
        bad.add(k);
        continue;
      }
      const v = (m2.node as t.MemberExpression).object === m1.node ? strKey(m2.node) : null;
      if (v !== null) {
        const up = m2.parentPath;
        // `delete S.K.v` removes the variable; a variable cannot be removed.
        // (`x in S.K.v` only reads v's value; testing the frame itself,
        // `"v" in S.K`, is an escape of S.K and refused below.)
        if (up?.isUnaryExpression({ operator: 'delete' })) {
          why.push(`frame variable ${k}.${v} deleted`);
          bad.add(k);
          continue;
        }
        // a direct call would see the frame as `this`; a variable call would not
        if (up?.isCallExpression() && up.node.callee === m2.node) {
          why.push(`frame variable ${k}.${v} called directly`);
          bad.add(k);
          continue;
        }
        if (!owner.has(k)) {
          if (!createdElsewhere.has(k)) missing.push(m1);
          continue;
        }
        accesses.push({ path: m2, k, v });
        continue;
      }
      // inheritance: `{ ["K"]: P["K"] }` as the scope argument of a child frame call
      const prop = m1.parentPath;
      const obj = prop?.parentPath;
      const call = obj?.parentPath;
      const inherits =
        prop?.isObjectProperty() &&
        prop.node.value === m1.node &&
        propKey(prop.node) === k &&
        call?.isCallExpression() &&
        call.node.arguments[0] === obj!.node &&
        frames.some((g) => g.call !== null && g.call.node === call.node);
      if (!inherits) {
        why.push(`frame ${f.P.identifier.name}.${k} escapes`);
        bad.add(k);
        continue;
      }
      inherited.push({ prop: prop!, k });
    }
  }
  const lowered = accesses.filter((a) => !bad.has(a.k));
  if (lowered.length === 0) return 0;
  /** Some key reachable through P stays an object: P must stay. */
  const keepsObject = (f: Frame): boolean => [...keysOf.get(f.P)!].some((k) => bad.has(k));

  // one identifier per (frame, variable), unique program-wide
  const taken = new Set<string>();
  traverse(ast, {
    Identifier(p) {
      taken.add(p.node.name);
    },
  });
  const frameCount = new Map<string, Set<string>>();
  for (const a of lowered) {
    if (!frameCount.has(a.v)) frameCount.set(a.v, new Set());
    frameCount.get(a.v)!.add(a.k);
  }
  const fresh = (base: string): string => {
    let n = base;
    for (let i = 2; taken.has(n) || RESERVED.has(n); i++) n = `${base}_${i}`;
    taken.add(n);
    return n;
  };
  const names = new Map<string, string>();
  const nameOf = (k: string, v: string): string => {
    const key = `${k}\u0000${v}`;
    let n = names.get(key);
    if (!n) {
      const sane = (s: string) => s.replace(/[^A-Za-z0-9_$]/g, '_') || 'v';
      let base = ID_RE.test(v) && frameCount.get(v)!.size === 1 ? v : `${sane(v)}_${sane(k)}`;
      if (/^[0-9]/.test(base)) base = `_${base}`;
      n = fresh(base);
      names.set(key, n);
    }
    return n;
  };
  const declared = new Map<Frame, string[]>();
  for (const a of lowered) {
    const n = nameOf(a.k, a.v);
    const f = owner.get(a.k)!;
    const list = declared.get(f) ?? [];
    if (!list.includes(n)) list.push(n);
    declared.set(f, list);
  }
  for (const a of lowered) a.path.replaceWith(t.identifier(nameOf(a.k, a.v)));
  for (const m of missing) m.replaceWith(t.unaryExpression('void', t.numericLiteral(0)));
  for (const { prop, k } of inherited) {
    if (bad.has(k)) continue;
    try {
      prop.remove();
    } catch {
      /* already detached */
    }
  }
  for (const [f, list] of declared)
    (f.fn.node.body as t.BlockStatement).body.unshift(t.variableDeclaration('var', list.map((n) => t.variableDeclarator(t.identifier(n)))));
  // creations of the frames that are variables now (a local frame object
  // also carries its member frames: it stays while any of those does)
  for (const f of frames) {
    if (!f.local || (f.member ? bad.has(f.owned[0]) : keepsObject(f))) continue;
    try {
      f.local.remove();
    } catch {
      /* already detached */
    }
    if (f.member) continue; // P itself stays: it is another frame's object
    if (f.P.path.isVariableDeclarator()) {
      try {
        f.P.path.remove();
      } catch {
        /* already detached */
      }
    }
  }
  // a frame object that stays sheds the keys that are variables now: nothing
  // reads them through it any more
  const pruneLiteral = (obj: NodePath | null | undefined): void => {
    if (!obj?.isObjectExpression()) return;
    for (const pr of obj.get('properties')) {
      const k = propKey(pr.node);
      if (k !== null && owner.has(k) && !bad.has(k)) pr.remove();
    }
  };
  for (const f of frames) {
    if (f.call && keepsObject(f)) {
      pruneLiteral(f.call.get('arguments.0') as NodePath);
      pruneLiteral(f.fn.get('params.0.right') as NodePath);
    } else if (f.local && !f.member && keepsObject(f)) pruneLiteral(f.local.get('expression.right') as NodePath);
  }
  // the scope parameter and its argument go too, unless `arguments` could see
  // them or a key of theirs stays an object
  if (!frames.some((f) => f.usesArguments))
    for (const f of frames) {
      if (!f.call || keepsObject(f)) continue;
      f.fn.node.params.shift();
      if (f.call.node.arguments.length > 0) f.call.node.arguments.shift();
    }
  return lowered.length;
}

// ── 5. nested dispatchers ────────────────────────────────────────────────────

/** Callee of `V(…)` or `(0|1, V)(…)`. */
const calleeName = (c: t.CallExpression): t.Identifier | null => {
  if (t.isIdentifier(c.callee)) return c.callee;
  const s = c.callee;
  if (t.isSequenceExpression(s) && s.expressions.length === 2 && t.isNumericLiteral(s.expressions[0]) && t.isIdentifier(s.expressions[1]))
    return s.expressions[1];
  return null;
};

/**
 * `V = function (...A) { return (function (R, ARG) { var S, SC, RT; [S, SC = {…}, RT] = ARG;
 *  while (SUM(S) !== T) … })(R0, A); }` — a flattened inner function whose state array is its
 * first argument. When every call of V passes the same static array, linearise in place.
 */
function linearizeNested(ast: t.File, ctx: import('vm').Context, h: Helpers, why: string[]): number {
  let n = 0;
  traverse(ast, {
    WhileStatement(lp) {
      const loop = lp.node;
      const shape = dispatcherShape(loop);
      if (!shape || !h.closed.has(shape.sum)) return;
      const S = shape.X;
      try {
        const block = lp.parentPath;
        if (!block?.isBlockStatement()) throw new Abort('loop not in a block');
        const iife = block.parentPath;
        if (!iife?.isFunctionExpression()) throw new Abort('loop not in a function');
        const stmts = block.node.body;
        const li = stmts.indexOf(loop);
        let di = -1;
        let pat: t.ArrayPattern | null = null;
        let argName: string | null = null;
        for (let i = 0; i < li; i++) {
          const s = stmts[i];
          if (
            t.isExpressionStatement(s) &&
            t.isAssignmentExpression(s.expression, { operator: '=' }) &&
            t.isArrayPattern(s.expression.left) &&
            t.isIdentifier(s.expression.left.elements[0], { name: S }) &&
            t.isIdentifier(s.expression.right)
          ) {
            di = i;
            pat = s.expression.left;
            argName = s.expression.right.name;
          }
        }
        if (di < 0 || !pat || !argName) throw new Abort('no seed');
        const pIdx = iife.node.params.findIndex((p) => t.isIdentifier(p, { name: argName! }));
        if (pIdx < 0) throw new Abort('seed is not a parameter');
        const call = iife.parentPath;
        if (!call?.isCallExpression() || call.node.callee !== iife.node) throw new Abort('not an IIFE');
        const ret = call.parentPath;
        if (!ret?.isReturnStatement()) throw new Abort('IIFE not returned');
        const vfn = ret.parentPath?.parentPath;
        if (!(vfn?.isFunctionExpression() || vfn?.isFunctionDeclaration()) || vfn.node.body.body.length !== 1) throw new Abort('no closure');
        const rest = vfn.node.params[0];
        if (vfn.node.params.length !== 1 || !t.isRestElement(rest) || !t.isIdentifier(rest.argument)) throw new Abort('closure params');
        if (!t.isIdentifier(call.node.arguments[pIdx], { name: rest.argument.name })) throw new Abort('arguments not forwarded');
        const store = vfn.parentPath;
        let vName: string | null = null;
        if (vfn.isFunctionDeclaration() && vfn.node.id) vName = vfn.node.id.name;
        else if (store?.isAssignmentExpression({ operator: '=' }) && t.isIdentifier(store.node.left) && store.node.right === vfn.node)
          vName = store.node.left.name;
        else if (store?.isVariableDeclarator() && t.isIdentifier(store.node.id) && store.node.init === vfn.node) vName = store.node.id.name;
        if (!vName) throw new Abort('closure not stored');
        const vb = store!.scope.getBinding(vName);
        if (!vb) throw new Abort('no binding');
        // a declaration is its own one write
        const writes = vfn.isFunctionDeclaration()
          ? vb.path.node === vfn.node && vb.constantViolations.every((v) => v.node === vfn.node)
            ? 1
            : 2
          : vb.constantViolations.length + (vb.path.isVariableDeclarator() && vb.path.node.init ? 1 : 0);
        if (writes !== 1) throw new Abort('closure written twice');
        let init: number[] | null = null;
        let maxArgs = 0;
        for (const r of vb.referencePaths) {
          let cp: NodePath | null = r.parentPath;
          if (cp?.isSequenceExpression()) cp = cp.parentPath;
          if (!cp?.isCallExpression() || calleeName(cp.node) !== r.node) throw new Abort('closure escapes');
          const a = staticArray(cp.node.arguments[0], ctx, h);
          if (!a) throw new Abort('non-static state argument');
          if (init && init.join(',') !== a.join(',')) throw new Abort('state argument differs between calls');
          init = a;
          maxArgs = Math.max(maxArgs, cp.node.arguments.length);
        }
        if (!init) throw new Abort('closure never called');
        const sb = lp.scope.getBinding(S);
        if (!sb) throw new Abort('no state binding');
        for (const r of [...sb.referencePaths, ...sb.constantViolations])
          if (!r.findParent((q) => q.node === loop) && !r.findParent((q) => q.node === stmts[di]))
            throw new Abort('state used outside the loop');

        const out = structure(buildCfg(loop, init, ctx, h));
        // the seed no longer binds S; frame defaults every call takes become plain assignments
        pat.elements[0] = null;
        const extra: t.Statement[] = [];
        for (let i = 1; i < pat.elements.length; i++) {
          const el = pat.elements[i];
          if (t.isAssignmentPattern(el) && t.isIdentifier(el.left) && isFrameLiteral(el.right) && maxArgs <= i) {
            extra.push(t.expressionStatement(t.assignmentExpression('=', t.identifier(el.left.name), el.right)));
            pat.elements[i] = null;
          }
        }
        for (const s of stmts) if (t.isVariableDeclaration(s)) s.declarations = s.declarations.filter((d) => !t.isIdentifier(d.id, { name: S }));
        const seed = stmts[di];
        while (pat.elements.length && pat.elements[pat.elements.length - 1] === null) pat.elements.pop();
        block.node.body = [
          ...stmts.slice(0, di).filter((s) => !(t.isVariableDeclaration(s) && s.declarations.length === 0)),
          ...(pat.elements.length ? [seed] : []),
          ...extra,
          ...stmts.slice(di + 1, li),
          ...out,
          ...stmts.slice(li + 1),
        ];
        n++;
        lp.skip();
      } catch (e) {
        if (e instanceof Abort) {
          why.push(e.message);
          return;
        }
        throw e;
      }
    },
  });
  return n;
}

// ── 6. calling convention ────────────────────────────────────────────────────

/** Uses `this` / `arguments` / `super` / `new.target` at the function's own level. */
export function ownContextSensitive(fn: t.Function): boolean {
  let hit = false;
  const v = (x: t.Node, top: boolean): void => {
    if (hit) return;
    if (!top && t.isFunction(x) && !t.isArrowFunctionExpression(x)) return;
    if (t.isThisExpression(x) || t.isSuper(x) || t.isIdentifier(x, { name: 'arguments' }) || t.isMetaProperty(x)) {
      hit = true;
      return;
    }
    for (const k of (t.VISITOR_KEYS as Record<string, string[]>)[x.type] ?? []) {
      const c = (x as unknown as Record<string, unknown>)[k];
      if (Array.isArray(c)) c.forEach((y) => y && v(y as t.Node, false));
      else if (c) v(c as t.Node, false);
    }
  };
  for (const st of (fn.body as t.BlockStatement).body) v(st, false);
  return hit;
}

/**
 * An argument whose evaluation has no effect and cannot throw, so dropping it
 * is unobservable: literals (signed numbers included), bound identifiers, and
 * arrays of those — spreads only of calls to pure helpers (the state pools).
 */
let pureHelpers: Set<string> = new Set();
/** Immutable literal pools (Helpers.data): `POOL.slice(a, b)` copies part of one. */
let pureData: Set<string> = new Set();
const pureArg = (e: t.Node | undefined, scope?: NodePath['scope']): boolean => {
  if (!e) return true;
  if (t.isLiteral(e) && !t.isTemplateLiteral(e)) return true;
  // reading an undeclared name throws: only bound names and standard globals
  if (t.isIdentifier(e)) return SAFE.has(e.name) || (!!scope && !!scope.getBinding(e.name));
  if (t.isUnaryExpression(e) && ['-', '+', '!', 'void'].includes(e.operator)) return pureArg(e.argument, scope);
  if (t.isArrayExpression(e))
    return e.elements.every((x) => {
      if (!x) return true;
      if (!t.isSpreadElement(x)) return pureArg(x, scope);
      const c = x.argument;
      if (!t.isCallExpression(c) || !c.arguments.every((a) => pureArg(a, scope))) return false;
      if (t.isIdentifier(c.callee)) return pureHelpers.has(c.callee.name);
      const m = c.callee;
      return t.isMemberExpression(m) && !m.computed && t.isIdentifier(m.object) && pureData.has(m.object.name) && t.isIdentifier(m.property, { name: 'slice' });
    });
  return false;
};

/**
 * `function (...A) { return (function (R, ARG) { var a, b; [a, b] = ARG; BODY })(R0, A); }`
 *   → `function (a, b) { BODY }`
 *
 * The thunk forwards every argument as the array ARG, and BODY reads them back
 * by destructuring — exactly what a parameter list does. Sound when BODY does
 * not depend on the inner call's own `this` / `arguments`, the other inner
 * parameters are unused, and the destructuring is the first effect in BODY.
 */
function collapseCallingConvention(ast: t.File, why: string[]): number {
  let n = 0;
  // Pass 1: rewrite each thunk in place; remember leading holes per stored function.
  const holes = new Map<t.Function, number>();
  traverse(ast, {
    'FunctionExpression|FunctionDeclaration'(path) {
      const p = path as NodePath<t.FunctionExpression | t.FunctionDeclaration>;
      const fn = p.node;
      if (fn.async || fn.generator || fn.params.length !== 1 || !t.isRestElement(fn.params[0])) return;
      // Named parameters change `length`: a declaration is only rewritten when
      // nothing but calls can see it.
      if (p.isFunctionDeclaration()) {
        const b = fn.id ? p.parentPath.scope.getBinding(fn.id.name) : undefined;
        if (!b || !b.referencePaths.every((r) => r.parentPath?.isCallExpression() && r.parentPath.node.callee === r.node)) return;
      }
      const A = (fn.params[0] as t.RestElement).argument;
      if (!t.isIdentifier(A) || fn.body.body.length !== 1) return;
      const ret = fn.body.body[0];
      if (!t.isReturnStatement(ret) || !t.isCallExpression(ret.argument)) return;
      const call = ret.argument;
      const inner = call.callee;
      if (!t.isFunctionExpression(inner) || inner.id || inner.async || inner.generator) return;
      if (!inner.params.every((q) => t.isIdentifier(q))) return;
      if (call.arguments.some((a) => t.isSpreadElement(a))) return;
      const k = call.arguments.findIndex((a) => t.isIdentifier(a, { name: A.name }));
      // The rest array may only be forwarded as that one argument: a body
      // that reaches it by closure would lose it with the parameter.
      const Ab = p.scope.getBinding(A.name);
      if (!Ab || Ab.constantViolations.length || !Ab.referencePaths.every((r) => k >= 0 && r.node === call.arguments[k])) {
        why.push('thunk array used beyond forwarding');
        return;
      }
      if (ownContextSensitive(inner)) {
        why.push('thunk body uses this/arguments');
        return;
      }
      if (inner.body.directives.some((d) => d.value.value === 'use strict')) return;
      const innerPath = (p.get('body.body.0.argument.callee') as NodePath<t.FunctionExpression>);
      const paramBinding = (name: string) => innerPath.scope.getBinding(name);
      // other parameters: unused, with pure arguments
      for (let i = 0; i < inner.params.length; i++) {
        if (i === k) continue;
        const b = paramBinding((inner.params[i] as t.Identifier).name);
        if (!b || b.referenced || b.constantViolations.length) return;
        if (!pureArg(call.arguments[i], p.scope)) return;
      }
      const body = inner.body.body;
      let pattern: t.ArrayPattern | null = null;
      let di = -1;
      if (k >= 0 && k < inner.params.length) {
        const ARG = (inner.params[k] as t.Identifier).name;
        const ab = paramBinding(ARG);
        if (!ab || ab.constantViolations.length) return;
        if (ab.referencePaths.length > 1) return;
        if (ab.referencePaths.length === 1) {
          const r = ab.referencePaths[0];
          const asg = r.parentPath;
          if (!asg?.isAssignmentExpression({ operator: '=' }) || asg.node.right !== r.node || !t.isArrayPattern(asg.node.left)) return;
          const st = asg.parentPath;
          if (!st?.isExpressionStatement() || st.parentPath?.node !== inner.body) return;
          di = body.indexOf(st.node);
          for (let i = 0; i < di; i++) {
            const b0 = body[i];
            if (!(t.isVariableDeclaration(b0) && b0.kind === 'var' && b0.declarations.every((d) => !d.init))) return;
          }
          pattern = asg.node.left;
        }
      } else if (k >= 0) return;
      // the destructured names become parameters: each must be a body-level `var`
      const declared = new Set<string>();
      for (const st of body) if (t.isVariableDeclaration(st) && st.kind === 'var') for (const d of st.declarations) if (t.isIdentifier(d.id) && !d.init) declared.add(d.id.name);
      const params: (t.Identifier | t.AssignmentPattern | t.RestElement | null)[] = [];
      if (pattern) {
        for (const el of pattern.elements) {
          if (el === null) {
            params.push(null);
            continue;
          }
          const id = t.isIdentifier(el) ? el : t.isAssignmentPattern(el) && t.isIdentifier(el.left) ? el.left : t.isRestElement(el) && t.isIdentifier(el.argument) ? el.argument : null;
          if (!id || !declared.has(id.name)) return;
          if (t.isAssignmentPattern(el)) {
            // a default runs in the parameter scope: it must not see the body
            let local = false;
            t.traverseFast(el.right, (x) => {
              if (t.isIdentifier(x) && declared.has(x.name)) local = true;
            });
            if (local || (!pureArg(el.right, innerPath.scope) && !t.isObjectExpression(el.right))) return;
          }
          const b = innerPath.scope.getBinding(id.name);
          const unused = !!b && !b.referenced && b.constantViolations.length === 1 && !t.isAssignmentPattern(el);
          params.push(unused ? null : (el as t.Identifier | t.AssignmentPattern | t.RestElement));
        }
      }
      while (params.length && params[params.length - 1] === null) params.pop();
      const lead = params.findIndex((q) => q !== null);
      const leading = lead < 0 ? 0 : lead;
      // rewrite
      const names = new Set(params.filter(Boolean).map((q) => (t.isIdentifier(q) ? q.name : t.isAssignmentPattern(q) ? (q.left as t.Identifier).name : ((q as t.RestElement).argument as t.Identifier).name)));
      const newBody = body.filter((_, i) => i !== di).map((st) => {
        if (t.isVariableDeclaration(st) && st.kind === 'var')
          st.declarations = st.declarations.filter((d) => !(t.isIdentifier(d.id) && (names.has(d.id.name) || (pattern?.elements.some((e) => t.isIdentifier(e, { name: (d.id as t.Identifier).name })) ?? false))));
        return st;
      }).filter((st) => !(t.isVariableDeclaration(st) && st.declarations.length === 0));
      fn.params = params.map((q, i) => q ?? t.identifier(`_${i}`)) as t.FunctionExpression['params'];
      fn.body = t.blockStatement(newBody, inner.body.directives);
      holes.set(fn, leading);
      n++;
    },
  });
  // Pass 2: drop leading placeholder parameters when every call is known and their arguments are pure.
  if (holes.size)
    traverse(ast, {
      'FunctionExpression|FunctionDeclaration'(path) {
        const p = path as NodePath<t.FunctionExpression | t.FunctionDeclaration>;
        const lead = holes.get(p.node);
        if (lead === undefined) return;
        const store = p.parentPath;
        let name: string | null = null;
        if (p.isFunctionDeclaration() && p.node.id) name = p.node.id.name;
        else if (store?.isAssignmentExpression({ operator: '=' }) && t.isIdentifier(store.node.left)) name = store.node.left.name;
        else if (store?.isVariableDeclarator() && t.isIdentifier(store.node.id)) name = store.node.id.name;
        if (!name) return;
        const b = store!.scope.getBinding(name);
        if (!b) return;
        const writes = p.isFunctionDeclaration()
          ? b.path.node === p.node && b.constantViolations.every((v) => v.node === p.node)
            ? 1
            : 2
          : b.constantViolations.length + (b.path.isVariableDeclarator() && b.path.node.init ? 1 : 0);
        if (writes !== 1) return;
        const calls: t.CallExpression[] = [];
        for (const r of b.referencePaths) {
          let cp: NodePath | null = r.parentPath;
          if (cp?.isSequenceExpression()) cp = cp.parentPath;
          if (!cp?.isCallExpression() || calleeName(cp.node) !== r.node) return;
          if (cp.node.arguments.some((a) => t.isSpreadElement(a))) return;
          if (cp.node.arguments.slice(0, lead).some((a) => !pureArg(a, cp!.scope))) return;
          calls.push(cp.node);
        }
        p.node.params.splice(0, lead);
        // the collapsed body never reads `arguments`: arguments past the last
        // parameter are discarded, so pure ones can go
        const hasRest = p.node.params.some((q) => t.isRestElement(q));
        for (const c of calls) {
          c.arguments.splice(0, lead);
          if (!hasRest) while (c.arguments.length > p.node.params.length && pureArg(c.arguments[c.arguments.length - 1], p.scope)) c.arguments.pop();
        }
      },
    });
  return n;
}

/** `(function (a, b) { … })(x, y)` with `a` unused and `x` pure: drop both. */
function dropUnusedIifeParams(ast: t.File): number {
  let n = 0;
  traverse(ast, {
    CallExpression(p) {
      const callee = p.get('callee');
      if (!callee.isFunctionExpression() || callee.node.async || callee.node.generator) return;
      const fn = callee.node;
      if (ownContextSensitive(fn) && (() => { let a = false; t.traverseFast(fn.body, (x) => { if (t.isIdentifier(x, { name: 'arguments' })) a = true; }); return a; })()) return;
      if (p.node.arguments.some((a) => t.isSpreadElement(a))) return;
      for (let i = fn.params.length - 1; i >= 0; i--) {
        const q = fn.params[i];
        if (!t.isIdentifier(q)) continue;
        const b = callee.scope.getBinding(q.name);
        if (!b || b.referenced || b.constantViolations.length) continue;
        const a = p.node.arguments[i];
        if (a && !pureArg(a, p.scope)) continue;
        // later params keep their positions only if their arguments shift with them
        fn.params.splice(i, 1);
        if (i < p.node.arguments.length) p.node.arguments.splice(i, 1);
        n++;
      }
    },
  });
  return n;
}

// ── 7. tidying what the recovery leaves behind ───────────────────────────────

const isUndefinedValue = (e: t.Node | null | undefined): boolean =>
  t.isIdentifier(e, { name: 'undefined' }) || (t.isUnaryExpression(e, { operator: 'void' }) && t.isNumericLiteral(e.argument));

/** Statements after an unconditional jump in the same list never run (hoisted declarations excepted). */
function dropUnreachable(ast: t.File): number {
  let n = 0;
  const prune = (list: t.Statement[]): t.Statement[] => {
    const i = list.findIndex((s) => t.isReturnStatement(s) || t.isThrowStatement(s) || t.isBreakStatement(s) || t.isContinueStatement(s));
    if (i < 0 || i === list.length - 1) return list;
    // hoisted parts survive: function declarations, and each `var` (its
    // initialiser would never run, but the binding exists)
    const keep: t.Statement[] = [];
    for (const s of list.slice(i + 1)) {
      if (t.isFunctionDeclaration(s)) keep.push(s);
      else if (t.isVariableDeclaration(s) && s.kind === 'var')
        keep.push(t.variableDeclaration('var', s.declarations.map((d) => t.variableDeclarator(t.cloneNode(d.id, true)))));
    }
    n += list.length - 1 - i - keep.length;
    return [...list.slice(0, i + 1), ...keep];
  };
  t.traverseFast(ast.program, (x) => {
    if (t.isBlockStatement(x)) x.body = prune(x.body);
    else if (t.isSwitchCase(x)) x.consequent = prune(x.consequent);
  });
  return n;
}

/** `var x; …; x = undefined;` at the top of a function, before anything can run: a no-op. */
function dropRedundantUndefined(ast: t.File): number {
  let n = 0;
  traverse(ast, {
    Function(p) {
      const body = p.node.body;
      if (!t.isBlockStatement(body)) return;
      const out: t.Statement[] = [];
      let open = true;
      for (const st of body.body) {
        if (open) {
          if (t.isFunctionDeclaration(st) || (t.isVariableDeclaration(st) && st.kind === 'var' && st.declarations.every((d) => !d.init))) {
            out.push(st);
            continue;
          }
          if (
            t.isExpressionStatement(st) &&
            t.isAssignmentExpression(st.expression, { operator: '=' }) &&
            t.isIdentifier(st.expression.left) &&
            isUndefinedValue(st.expression.right)
          ) {
            const b = p.scope.getBinding(st.expression.left.name);
            if (b && b.kind === 'var' && b.scope === p.scope && b.path.isVariableDeclarator() && !b.path.node.init && !p.scope.hasBinding('undefined', { noGlobals: true })) {
              n++;
              continue;
            }
          }
          open = false;
        }
        out.push(st);
      }
      body.body = out;
    },
  });
  return n;
}

/** `1;`, `true;`, `null;`, `undefined;` — expression statements that do nothing. */
function dropNoopStatements(ast: t.File): number {
  let n = 0;
  const keep = (s: t.Statement) => {
    const e = t.isExpressionStatement(s) ? s.expression : null;
    const noop = !!e && (t.isNumericLiteral(e) || t.isBooleanLiteral(e) || t.isNullLiteral(e) || isUndefinedValue(e));
    if (noop) n++;
    return !noop;
  };
  t.traverseFast(ast.program, (x) => {
    if (t.isBlockStatement(x) || t.isProgram(x)) x.body = x.body.filter(keep);
    else if (t.isSwitchCase(x)) x.consequent = x.consequent.filter(keep);
  });
  return n;
}

/**
 * js-confuser's return flag:
 *
 *   flag = undefined; r = g(…); if (flag) { return r; } else { return; }
 *
 * where g, a local function called only here, sets `flag = true` on every
 * return and cannot fall off its end. Then `flag` is true whenever g returns,
 * so the whole thing is `return g(…)`.
 */
function collapseReturnFlags(ast: t.File): number {
  let n = 0;
  traverse(ast, {
    IfStatement(p) {
      const s = p.node;
      if (!t.isIdentifier(s.test)) return;
      const F = s.test.name;
      const thenB = t.isBlockStatement(s.consequent) ? s.consequent.body : [s.consequent];
      if (thenB.length !== 1 || !t.isReturnStatement(thenB[0]) || !t.isIdentifier(thenB[0].argument)) return;
      const R = thenB[0].argument.name;
      if (s.alternate) {
        const elseB = t.isBlockStatement(s.alternate) ? s.alternate.body : [s.alternate];
        if (elseB.length !== 1 || !t.isReturnStatement(elseB[0]) || (elseB[0].argument && !isUndefinedValue(elseB[0].argument))) return;
      }
      const list = p.parentPath;
      if (!list?.isBlockStatement()) return;
      const stmts = list.node.body;
      const at = stmts.indexOf(s);
      // `r = g(…)` or `var r = g(…)`, with g a stored function or an inline IIFE
      const prev = stmts[at - 1];
      let callE: t.Node | null | undefined = null;
      if (t.isExpressionStatement(prev) && t.isAssignmentExpression(prev.expression, { operator: '=' }) && t.isIdentifier(prev.expression.left, { name: R }))
        callE = prev.expression.right;
      else if (t.isVariableDeclaration(prev) && prev.declarations.length === 1 && t.isIdentifier(prev.declarations[0].id, { name: R }))
        callE = prev.declarations[0].init;
      if (!t.isCallExpression(callE)) return;
      const fb = p.scope.getBinding(F);
      const rb = p.scope.getBinding(R);
      if (!fb || !rb || fb.kind !== 'var' || rb.kind !== 'var') return;
      let g: t.FunctionExpression;
      if (t.isFunctionExpression(callE.callee) && callE.arguments.length === 0 && !callE.callee.id) {
        g = callE.callee; // an IIFE: used here and nowhere else by construction
      } else {
        const G = calleeName(callE);
        if (!G) return;
        const gb = p.scope.getBinding(G.name);
        if (!gb) return;
        // g: one function value, called only here
        const gWrites = gb.constantViolations;
        if (gWrites.length !== 1 || !(gb.path.isVariableDeclarator() && !gb.path.node.init)) return;
        const gAsg = gWrites[0];
        if (!gAsg.isAssignmentExpression({ operator: '=' }) || !t.isFunctionExpression(gAsg.node.right)) return;
        if (gb.referencePaths.length !== 1) return;
        g = gAsg.node.right;
      }
      if (g.async || g.generator) return;
      const gBody = g.body.body;
      if (!gBody.length) return;
      // If g can fall off its end (R = undefined, flag unset), the original
      // goes on past the `if`; `return R` would return undefined instead. That
      // is the same only when nothing follows: an `else return;`, or the `if`
      // ending a function body.
      if (!t.isReturnStatement(gBody[gBody.length - 1])) {
        const endsFn = at === stmts.length - 1 && !!list.parentPath?.isFunction();
        if (!s.alternate && !endsFn) return;
      }
      // every return of g (outside nested functions) sets the flag just before
      // it; nothing else in g touches it
      let ok = true;
      const setsFlag = (e: t.Node | null | undefined) =>
        t.isAssignmentExpression(e, { operator: '=' }) && t.isIdentifier(e.left, { name: F }) && t.isBooleanLiteral(e.right, { value: true });
      const hasReturn = (x: t.Node): boolean => {
        let r = false;
        const v = (y: t.Node): void => {
          if (r || t.isFunction(y)) return;
          if (t.isReturnStatement(y)) r = true;
          for (const key of (t.VISITOR_KEYS as Record<string, string[]>)[y.type] ?? []) {
            const c = (y as unknown as Record<string, unknown>)[key];
            if (Array.isArray(c)) c.forEach((z) => z && v(z as t.Node));
            else if (c) v(c as t.Node);
          }
        };
        v(x);
        return r;
      };
      const asList = (x: t.Statement): t.Statement[] => (t.isBlockStatement(x) ? x.body : [x]);
      const visit = (list2: t.Statement[]): void => {
        list2.forEach((st, i) => {
          if (!ok) return;
          if (t.isReturnStatement(st)) {
            const viaSeq = t.isSequenceExpression(st.argument) && setsFlag(st.argument.expressions[0]);
            const viaPrev = i > 0 && t.isExpressionStatement(list2[i - 1]) && setsFlag((list2[i - 1] as t.ExpressionStatement).expression);
            if (!viaSeq && !viaPrev) ok = false;
            return;
          }
          if (t.isFunctionDeclaration(st) || !hasReturn(st)) return;
          // statements whose nested statement lists we follow; a return under
          // anything else (try/finally can override it, `with`) is not modelled
          if (t.isBlockStatement(st)) visit(st.body);
          else if (t.isIfStatement(st)) {
            visit(asList(st.consequent));
            if (st.alternate) visit(asList(st.alternate));
          } else if (t.isSwitchStatement(st)) st.cases.forEach((c) => visit(c.consequent));
          else if (t.isLabeledStatement(st) || t.isWhileStatement(st) || t.isDoWhileStatement(st) || t.isForStatement(st) || t.isForInStatement(st) || t.isForOfStatement(st))
            visit(asList(st.body));
          else ok = false;
        });
      };
      visit(gBody);
      if (!ok) return;
      // the flag: written only as `= undefined` here and `= true` inside g, read only by this test
      for (const w of fb.constantViolations) {
        const inG = !!w.findParent((q) => q.node === g);
        const ok2 = w.isAssignmentExpression({ operator: '=' }) && ((inG && t.isBooleanLiteral(w.node.right, { value: true })) || (!inG && isUndefinedValue(w.node.right)));
        if (!ok2) return;
      }
      if (fb.referencePaths.length !== 1 || fb.referencePaths[0].node !== s.test) return;
      // rewrite: drop the flag everywhere, return the call's value
      for (const w of fb.constantViolations) {
        const st = w.parentPath;
        if (st?.isExpressionStatement()) st.remove();
        else if (st?.isSequenceExpression()) {
          const seq = st.node;
          seq.expressions = seq.expressions.filter((x) => x !== w.node);
          if (seq.expressions.length === 1) st.replaceWith(seq.expressions[0]);
        }
      }
      p.replaceWith(t.returnStatement(t.identifier(R)));
      n++;
    },
  });
  return n;
}

/** The cff machinery (pools and helpers the dispatchers used) once nothing references it. */
function dropDeadMachinery(ast: t.File, machinery: Set<string>): number {
  let n = 0;
  for (let round = 0; round < 6; round++) {
    let removed = false;
    traverse(ast, {
      Program(p) {
        for (const st of p.get('body')) {
          const names: string[] = [];
          if (st.isFunctionDeclaration() && st.node.id) names.push(st.node.id.name);
          else if (st.isVariableDeclaration()) for (const d of st.node.declarations) if (t.isIdentifier(d.id)) names.push(d.id.name);
          if (!names.length || !names.every((nm) => machinery.has(nm))) continue;
          if (st.isVariableDeclaration() && !st.node.declarations.every((d) => isLiteralData(d.init))) continue;
          if (names.some((nm) => (p.scope.getBinding(nm)?.referencePaths ?? []).some((r) => !r.findParent((q) => q.node === st.node)))) continue;
          st.remove();
          n++;
          removed = true;
        }
        p.stop();
      },
    });
    ast.program = reparse(ast).program;
    if (!removed) break;
  }
  return n;
}

// ── the pass ─────────────────────────────────────────────────────────────────

/** Has the program a dispatcher loop at all? Cheap test before building a sandbox. */
function hasDispatcherLoop(ast: t.File): boolean {
  let found = false;
  t.traverseFast(ast.program, (n) => {
    if (!found && t.isWhileStatement(n) && dispatcherShape(n)) found = true;
  });
  return found;
}

export function passCffRecover(ast: t.File, log: Logger): number {
  if (!hasDispatcherLoop(ast)) {
    // Frames can outlive their dispatchers by a sweep (recovered, then a later
    // pass respelt `S["K"]` as `S.K`); lowering them needs no helpers.
    const why: string[] = [];
    let work = reparse(ast);
    let lowered = 0;
    for (let round = 0; round < 8; round++) {
      const l = lowerFrames(work, why);
      work = reparse(work);
      lowered += l;
      if (!l) break;
    }
    // likewise the return-flag convention, once other passes have reshaped it
    const flags = collapseReturnFlags(work);
    if (flags) work = reparse(work);
    // and state arrays still passed to linearised functions
    let surplus = 0;
    try {
      if (uniquifyHelperNames(work)) work = reparse(work);
      const h = closedHelpers(work);
      pureHelpers = h.closed;
      pureData = new Set(h.data.keys());
      surplus = dropSurplusArgs(work, h);
      if (surplus) work = reparse(work);
      // and calling-convention thunks other passes have since reshaped
      for (let round = 0; round < 4; round++) {
        const c = collapseCallingConvention(work, why);
        if (!c) break;
        work = reparse(work);
        surplus += c;
        const f = collapseReturnFlags(work);
        if (f) work = reparse(work);
        surplus += f;
      }
    } catch {
      surplus = 0;
    }
    if (lowered || flags || surplus) ast.program = work.program;
    const note = [lowered ? `${lowered} frame refs lowered` : null, flags ? `${flags} return flags collapsed` : null, surplus ? `${surplus} state arguments dropped` : null]
      .filter(Boolean)
      .join(', ');
    log.pass('b13d', 'cffRecover', 0, 'dispatchers', note || 'none');
    return lowered + flags + surplus ? 1 : 0;
  }
  const why: string[] = [];
  let work = reparse(ast);
  if (uniquifyHelperNames(work)) work = reparse(work);
  let helpers: Helpers;
  let ctx: import('vm').Context;
  try {
    helpers = closedHelpers(work);
    pureHelpers = helpers.closed;
    pureData = new Set(helpers.data.keys());
    ctx = makeSandbox(helpers);
  } catch (e) {
    log.skip('b13d', 'cffRecover', `helpers: ${(e instanceof Error ? e.message : String(e)).slice(0, 80)}`);
    return 0;
  }
  // the machinery: closed helpers and pools the dispatcher loops reach
  const machinery = new Set<string>();
  t.traverseFast(work.program, (x) => {
    if (t.isIdentifier(x) && (helpers.closed.has(x.name) || helpers.data.has(x.name))) machinery.add(x.name);
  });
  for (let ch = true; ch; ) {
    ch = false;
    for (const m of [...machinery]) {
      const fn = helpers.fns.get(m);
      if (!fn) continue;
      t.traverseFast(fn, (x) => {
        if (t.isIdentifier(x) && (helpers.closed.has(x.name) || helpers.data.has(x.name)) && !machinery.has(x.name)) {
          machinery.add(x.name);
          ch = true;
        }
      });
    }
  }
  const expanded = expandDispatchers(work, ctx, helpers, why);
  work = expanded.ast;
  if (expanded.n && foldHelperCalls(work, ctx, helpers)) work = reparse(work);
  if (expanded.n && dropSurplusArgs(work, helpers)) work = reparse(work);
  let lowered = 0;
  let nested = 0;
  for (let round = 0; round < 8; round++) {
    const l = lowerFrames(work, why);
    work = reparse(work);
    const k = linearizeNested(work, ctx, helpers, why);
    work = reparse(work);
    lowered += l;
    nested += k;
    if (!l && !k) break;
  }
  let thunks = 0;
  if (expanded.n + nested > 0) {
    for (let round = 0; round < 4; round++) {
      const c = collapseCallingConvention(work, why);
      work = reparse(work);
      const d = dropUnusedIifeParams(work);
      work = reparse(work);
      thunks += c + d;
      if (!c && !d) break;
    }
  }
  let tidied = 0;
  if (expanded.n + nested > 0) {
    for (let round = 0; round < 4; round++) {
      let k = dropUnreachable(work);
      work = reparse(work);
      k += collapseReturnFlags(work);
      work = reparse(work);
      k += dropRedundantUndefined(work);
      k += dropNoopStatements(work);
      work = reparse(work);
      k += collapseCallingConvention(work, why);
      work = reparse(work);
      tidied += k;
      if (!k) break;
    }
    tidied += dropDeadMachinery(work, machinery);
  }
  const changes = expanded.n + nested + (lowered > 0 ? 1 : 0) + thunks + tidied;
  if (changes > 0) ast.program = work.program;
  const reasons = [...new Set(why)].slice(0, 3).join('; ');
  log.pass(
    'b13d',
    'cffRecover',
    expanded.n + nested,
    'dispatchers',
    [lowered ? `${lowered} frame refs lowered` : null, thunks ? `${thunks} call shims removed` : null, reasons ? `kept: ${reasons}` : null]
      .filter(Boolean)
      .join(', ') || undefined
  );
  return changes;
}
