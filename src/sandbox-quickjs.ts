/**
 * A sandbox on QuickJS compiled to WebAssembly (quickjs-emscripten): a real
 * separate JavaScript engine with its own heap, its own builtins and an
 * interrupt handler for the time budget — nothing the evaluated slice does
 * can reach the page, and a loop that never ends is stopped at the deadline.
 *
 * Values cross the boundary as JSON produced by a marshalling helper that is
 * installed in every context: shared references come back shared (the
 * identity-table pass relies on it), functions come back as host wrappers
 * that call into the context, and host hooks go in as native functions.
 */
import type { QuickJSContext, QuickJSHandle, QuickJSWASMModule } from 'quickjs-emscripten-core';
import { shouldInterruptAfterDeadline } from 'quickjs-emscripten-core';
import type { SandboxContext, SandboxFactory, SandboxGlobals } from './sandbox.js';

const MARSHAL = `(function () {
  var fns = [];
  Object.defineProperty(globalThis, '__dq_fns', { value: fns, enumerable: false });
  Object.defineProperty(globalThis, '__dq_marshal', { enumerable: false, value: function (v) {
    var ids = new Map(), n = 0;
    function walk(x) {
      var t = typeof x;
      if (x === null || t === 'string' || t === 'boolean') return x;
      if (t === 'number') {
        if (x !== x) return { $n: 'NaN' };
        if (x === Infinity) return { $n: 'Infinity' };
        if (x === -Infinity) return { $n: '-Infinity' };
        if (x === 0 && 1 / x < 0) return { $n: '-0' };
        return x;
      }
      if (t === 'undefined') return { $u: 1 };
      if (t === 'function') { fns.push(x); return { $fn: fns.length - 1 }; }
      if (t === 'bigint') return { $big: String(x) };
      if (t === 'symbol') return { $sym: String(x) };
      if (ids.has(x)) return { $ref: ids.get(x) };
      var id = n++;
      ids.set(x, id);
      if (Array.isArray(x)) { var a = []; for (var i = 0; i < x.length; i++) a.push(walk(x[i])); return { $id: id, $a: a }; }
      if (x instanceof Error) return { $id: id, $err: { name: String(x.name), message: String(x.message) } };
      var o = {}, keys = Object.keys(x);
      for (var k = 0; k < keys.length; k++) { try { o[keys[k]] = walk(x[keys[k]]); } catch (e) { o[keys[k]] = { $u: 1 }; } }
      return { $id: id, $o: o };
    }
    return JSON.stringify(walk(v));
  } });
})();`;

type Tagged =
  | { $n: string }
  | { $u: 1 }
  | { $fn: number }
  | { $big: string }
  | { $sym: string }
  | { $ref: number }
  | { $id: number; $a: unknown[] }
  | { $id: number; $o: Record<string, unknown> }
  | { $id: number; $err: { name: string; message: string } };

export function createQuickJSSandboxFactory(module: QuickJSWASMModule, options: { memoryLimitBytes?: number; maxLive?: number } = {}): SandboxFactory {
  const runtime = module.newRuntime();
  runtime.setMemoryLimit(options.memoryLimitBytes ?? 256 * 1024 * 1024);
  runtime.setMaxStackSize(1024 * 1024);
  const maxLive = options.maxLive ?? 64;
  const live: QuickJSSandbox[] = [];

  class QuickJSSandbox implements SandboxContext {
    private readonly vm: QuickJSContext;
    private disposed = false;

    constructor(globals: SandboxGlobals) {
      this.vm = runtime.newContext();
      this.unwrap(this.vm.evalCode(MARSHAL, 'marshal.js', { type: 'global' })).dispose();
      const seen = new Map<unknown, QuickJSHandle>();
      seen.set(globals, this.vm.global);
      for (const [name, value] of Object.entries(globals)) {
        // The host's own builtins (`String`, `Math`, `JSON`, …) are handed to a
        // Node context because it starts empty; this engine has its own.
        if (value === undefined || value === (globalThis as Record<string, unknown>)[name]) continue;
        const h = this.toGuest(value, seen);
        this.vm.setProp(this.vm.global, name, h);
        h.dispose();
      }
      live.push(this);
      while (live.length > maxLive) live.shift()!.dispose();
    }

    run(code: string, timeoutMs?: number): unknown {
      this.check();
      return this.withDeadline(timeoutMs, () => {
        const h = this.unwrap(this.vm.evalCode(code, 'sandbox.js', { type: 'global' }));
        return this.fromGuest(h);
      });
    }

    get(name: string): unknown {
      this.check();
      const h = this.vm.getProp(this.vm.global, name);
      return this.fromGuest(h);
    }

    dispose(): void {
      if (this.disposed) return;
      this.disposed = true;
      const i = live.indexOf(this);
      if (i >= 0) live.splice(i, 1);
      this.vm.dispose();
    }

    private check(): void {
      if (this.disposed) throw new Error('sandbox disposed');
    }

    private withDeadline<T>(timeoutMs: number | undefined, f: () => T): T {
      if (!timeoutMs) return f();
      runtime.setInterruptHandler(shouldInterruptAfterDeadline(Date.now() + timeoutMs));
      try {
        return f();
      } finally {
        runtime.removeInterruptHandler();
      }
    }

    /** A call result's value, or the error it carries as a host Error. */
    private unwrap(result: { value: QuickJSHandle } | { error: QuickJSHandle }): QuickJSHandle {
      if ('error' in result) {
        const e = this.vm.dump(result.error) as { name?: string; message?: string } | string;
        result.error.dispose();
        const err = new Error(typeof e === 'object' && e !== null ? String(e.message ?? e.name ?? 'error') : String(e));
        if (typeof e === 'object' && e !== null && e.name) err.name = String(e.name);
        throw err;
      }
      return result.value;
    }

    /** Marshal a guest value out through `__dq_marshal`, consuming the handle. */
    private fromGuest(handle: QuickJSHandle): unknown {
      const marshal = this.vm.getProp(this.vm.global, '__dq_marshal');
      try {
        const out = this.unwrap(this.vm.callFunction(marshal, this.vm.undefined, handle));
        const json = this.vm.getString(out);
        out.dispose();
        return this.revive(JSON.parse(json));
      } finally {
        marshal.dispose();
        handle.dispose();
      }
    }

    private revive(data: unknown): unknown {
      const byId = new Map<number, unknown>();
      const walk = (x: unknown): unknown => {
        if (x === null || typeof x !== 'object') return x;
        const tag = x as Tagged;
        if ('$n' in tag) return Number(tag.$n);
        if ('$u' in tag) return undefined;
        if ('$fn' in tag) return this.guestFunction(tag.$fn);
        if ('$big' in tag) return BigInt(tag.$big);
        if ('$sym' in tag) return Symbol(tag.$sym);
        if ('$ref' in tag) return byId.get(tag.$ref);
        if ('$a' in tag) {
          const a: unknown[] = [];
          byId.set(tag.$id, a);
          for (const el of tag.$a) a.push(walk(el));
          return a;
        }
        if ('$err' in tag) {
          const e = new Error(tag.$err.message);
          e.name = tag.$err.name;
          byId.set(tag.$id, e);
          return e;
        }
        const o: Record<string, unknown> = {};
        byId.set(tag.$id, o);
        for (const [k, v] of Object.entries(tag.$o)) o[k] = walk(v);
        return o;
      };
      return walk(data);
    }

    /** A host function that calls guest function #id with marshalled arguments. */
    private guestFunction(id: number): (...args: unknown[]) => unknown {
      return (...args: unknown[]) => {
        this.check();
        const fns = this.vm.getProp(this.vm.global, '__dq_fns');
        const fn = this.vm.getProp(fns, id);
        fns.dispose();
        const seen = new Map<unknown, QuickJSHandle>();
        const handles = args.map((a) => this.toGuest(a, seen));
        try {
          return this.withDeadline(5000, () => this.fromGuest(this.unwrap(this.vm.callFunction(fn, this.vm.undefined, ...handles))));
        } finally {
          for (const h of handles) h.dispose();
          fn.dispose();
        }
      };
    }

    /** A guest handle for a host value; `seen` keeps shared and cyclic references shared. */
    private toGuest(value: unknown, seen: Map<unknown, QuickJSHandle>): QuickJSHandle {
      const vm = this.vm;
      switch (typeof value) {
        case 'string':
          return vm.newString(value);
        case 'number':
          return vm.newNumber(value);
        case 'boolean':
          return value ? vm.true : vm.false;
        case 'undefined':
          return vm.undefined;
        case 'bigint':
          return this.unwrap(vm.evalCode(`${value}n`));
        case 'symbol':
          return vm.undefined;
        case 'function': {
          const hook = value as (...a: unknown[]) => unknown;
          return vm.newFunction(hook.name || 'hook', (...handles) => {
            const args = handles.map((h) => vm.dump(h));
            const r = hook(...args);
            const out = this.toGuest(r, new Map());
            return out;
          });
        }
        case 'object': {
          if (value === null) return vm.null;
          const known = seen.get(value);
          if (known) return known.dup();
          if (Array.isArray(value)) {
            const arr = vm.newArray();
            seen.set(value, arr);
            value.forEach((el, i) => {
              const h = this.toGuest(el, seen);
              vm.setProp(arr, i, h);
              h.dispose();
            });
            return arr;
          }
          if (value instanceof Error) return this.unwrap(vm.evalCode(`new Error(${JSON.stringify(value.message)})`));
          const obj = vm.newObject();
          seen.set(value, obj);
          for (const key of Object.keys(value)) {
            const h = this.toGuest((value as Record<string, unknown>)[key], seen);
            vm.setProp(obj, key, h);
            h.dispose();
          }
          return obj;
        }
        default:
          return vm.undefined;
      }
    }
  }

  return (globals) => new QuickJSSandbox(globals);
}
