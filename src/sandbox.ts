/**
 * The engine evaluates only closed, proven-pure slices of a program — string
 * decoders with their pools, state-array helpers, global lookup tables — and
 * it does so inside an isolated context with a time budget. This is the one
 * interface those evaluations go through, so the same engine runs on Node
 * (`node:vm`, see sandbox-node.ts) and in a browser (QuickJS compiled to
 * WebAssembly, see sandbox-quickjs.ts).
 *
 * Values cross the boundary in a deliberately small vocabulary: primitives,
 * arrays and plain objects (with shared references kept shared), and
 * functions — a function coming out of a sandbox is callable from the host
 * and runs inside the sandbox; a function going in is a host hook the
 * sandboxed code can call with values of the same vocabulary.
 */
export interface SandboxContext {
  /**
   * Run `code` as a sloppy-mode script in this context and return its
   * completion value. `var` declarations become globals of the context, as
   * they would in a script. Throws when the code throws, fails to parse, or
   * runs past `timeoutMs`.
   */
  run(code: string, timeoutMs?: number): unknown;
  /** The current value of a global of this context. */
  get(name: string): unknown;
  /** Release the context. Using it afterwards is an error. */
  dispose(): void;
}

/** What a sandbox starts out with as globals. */
export type SandboxGlobals = Record<string, unknown>;

export type SandboxFactory = (globals: SandboxGlobals) => SandboxContext;

let factory: SandboxFactory | null = null;

/** Choose the sandbox implementation; `js-defuser` (Node) and `js-defuser/browser` each register theirs. */
export function setSandboxFactory(f: SandboxFactory | null): void {
  factory = f;
}

export function createSandbox(globals: SandboxGlobals = {}): SandboxContext {
  if (!factory) {
    // Imported straight from the engine module on Node (the test suite does):
    // Node ≥ 20.16 hands out its builtins synchronously without a static
    // import that a browser bundler would then try to resolve.
    const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
    const vm = proc?.getBuiltinModule?.('node:vm') as typeof import('node:vm') | undefined;
    if (!vm) throw new Error('no sandbox available: import "js-defuser" (Node) or prepare "js-defuser/browser" first');
    factory = nodeSandboxFactory(vm);
  }
  return factory(globals);
}

/** The Node implementation: a `node:vm` context whose global object is the globals record itself. */
export function nodeSandboxFactory(vm: typeof import('node:vm')): SandboxFactory {
  return (globals) => {
    const sandbox: Record<string, unknown> = globals;
    const ctx = vm.createContext(sandbox);
    return {
      run(code, timeoutMs) {
        return new vm.Script(code).runInContext(ctx, timeoutMs ? { timeout: timeoutMs } : undefined);
      },
      get(name) {
        return sandbox[name];
      },
      dispose() {
        /* nothing to release: the context is garbage */
      },
    };
  };
}
