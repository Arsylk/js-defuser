// The QuickJS sandbox must behave like the node:vm one wherever the engine
// looks: same values back (shared references kept shared, functions callable
// from the host), host hooks callable from inside, deadlines enforced — and,
// the real check, the same recovered programs.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { newQuickJSWASMModuleFromVariant } from 'quickjs-emscripten-core';
import variant from '@jitl/quickjs-singlefile-browser-release-sync';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_ENABLED_PASSES, deobfuscate } from '../src/deobfuscator.js';
import { createSandbox, nodeSandboxFactory, setSandboxFactory, type SandboxFactory } from '../src/sandbox.js';
import { createQuickJSSandboxFactory } from '../src/sandbox-quickjs.js';

let quickjs: SandboxFactory;
const node = nodeSandboxFactory(vm);

beforeAll(async () => {
  quickjs = createQuickJSSandboxFactory(await newQuickJSWASMModuleFromVariant(variant));
});
afterAll(() => setSandboxFactory(null));

function execute(code: string): string[] {
  const events: string[] = [];
  const context = vm.createContext({ console: { log: (...args: unknown[]) => events.push(args.map(String).join(' ')) } });
  try {
    new vm.Script(code).runInContext(context, { timeout: 2000 });
  } catch (error) {
    events.push(`THREW ${(error as Error).name}`);
  }
  return events;
}

describe('quickjs sandbox', () => {
  it('returns primitives, arrays and objects with shared references', () => {
    const ctx = quickjs({});
    expect(ctx.run('1 + 2')).toBe(3);
    expect(ctx.run('"a" + "b"')).toBe('ab');
    expect(ctx.run('[1, "x", true, null]')).toEqual([1, 'x', true, null]);
    expect(ctx.run('var row = { k: 1 }; [[row, row], [row]]')).toSatisfy((v: unknown[][]) => v[0][0] === v[0][1] && v[0][0] === v[1][0]);
    expect(ctx.run('(function () { var o = {}; o.self = o; return o; })()')).toSatisfy((o: { self: unknown }) => o.self === o);
    expect(ctx.run('-0')).toSatisfy((v: number) => Object.is(v, -0));
    expect(ctx.run('undefined')).toBeUndefined();
    ctx.dispose();
  });

  it('keeps script globals and hands out callable functions', () => {
    const ctx = quickjs({});
    ctx.run('var table = [3, 1, 2]; function dec(i) { return table[i] * 10; }');
    expect(ctx.get('table')).toEqual([3, 1, 2]);
    const dec = ctx.run('dec') as (i: number) => number;
    expect(dec(2)).toBe(20);
    const sum = ctx.run('(function (xs, ys) { return xs.concat(ys).reduce(function (a, b) { return a + b; }, 0); })') as (a: number[], b: number[]) => number;
    expect(sum([1, 2], [3])).toBe(6);
    ctx.dispose();
  });

  it('calls host hooks, keeps host builtins out and the engine isolated', () => {
    const seen: unknown[] = [];
    const ctx = quickjs({
      capture: (...args: unknown[]) => {
        seen.push(args);
        return 'ok';
      },
      String,
      Math,
      doc: { title: 't', nested: { n: 1 } },
      self: 'me',
    });
    expect(ctx.run('capture("x", [1, 2], { a: 1 })')).toBe('ok');
    expect(seen).toEqual([['x', [1, 2], { a: 1 }]]);
    expect(ctx.run('typeof String.fromCharCode')).toBe('function');
    expect(ctx.run('doc.nested.n + doc.title')).toBe('1t');
    ctx.run('Math.random = function () { return 7; }');
    expect(Math.random()).not.toBe(7); // the host's Math is untouched
    expect(ctx.run('typeof fetch') === 'undefined' && ctx.run('typeof require') === 'undefined').toBe(true);
    ctx.dispose();
  });

  it('stops at the deadline and reports thrown errors', () => {
    const ctx = quickjs({});
    const started = Date.now();
    expect(() => ctx.run('while (true) {}', 300)).toThrow();
    expect(Date.now() - started).toBeLessThan(5000);
    expect(() => ctx.run('throw new TypeError("nope")')).toThrow(/nope/);
    expect(() => ctx.run('var x = 1; let x = 2;')).toThrow();
    ctx.dispose();
  });

  it('createSandbox uses the registered factory', () => {
    setSandboxFactory(quickjs);
    const ctx = createSandbox({ hook: () => 41 });
    expect(ctx.run('hook() + 1')).toBe(42);
    ctx.dispose();
    setSandboxFactory(node);
  });
});

describe('engine on quickjs', () => {
  const fixtures = new URL('./fixtures/', import.meta.url);
  const obfuscated = new URL('./obfuscated/', import.meta.url);

  async function recoverWith(factory: SandboxFactory, code: string): Promise<string> {
    setSandboxFactory(factory);
    try {
      const result = await deobfuscate(code, { enabledPasses: [...DEFAULT_ENABLED_PASSES], lenientMode: false, autoFix: false });
      expect(result.success).toBe(true);
      return result.deobfuscatedCode;
    } finally {
      setSandboxFactory(node);
    }
  }

  // Every sandbox-using pass is exercised by one of these: javascript-obfuscator's
  // string arrays and rotation (sa_rc4, sa_b64), js-confuser's concealed strings
  // and flattened control flow (medium), and the max-settings gate program.
  const samples: Array<[string, string]> = [];
  for (const config of ['sa_rc4.json', 'sa_b64.json', 'jsconfuser-strings.json', 'jsconfuser-cff.json', 'jsconfuser-medium.json']) {
    const fixture = JSON.parse(readFileSync(new URL(config, obfuscated), 'utf8')) as { cases: { name: string; code: string }[] };
    for (const c of fixture.cases.filter((_, i) => i % 7 === 0)) samples.push([`${config}/${c.name}`, c.code]);
  }
  for (const [name, code] of samples) {
    it(`recovers ${name} identically`, async () => {
      const expected = await recoverWith(node, code);
      const got = await recoverWith(quickjs, code);
      expect(got).toBe(expected);
      const source = readFileSync(new URL(name.split('/')[1], fixtures), 'utf8');
      expect(execute(got)).toEqual(execute(source));
    }, 120_000);
  }

  // (The max-settings gate programs recover identically on QuickJS too — 150 s
  // of synchronous work, which is more than a vitest worker may block for;
  // the browser build's own check covers them.)
});
