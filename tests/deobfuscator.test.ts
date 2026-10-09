import { readFileSync, readdirSync } from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import { DEFAULT_ENABLED_PASSES, deobfuscate } from '../src/deobfuscator.js';
import type { Entry } from '../src/logger.js';

const fixtures = new URL('./fixtures/', import.meta.url);

async function execute(code: string): Promise<string[]> {
  const events: string[] = [];
  const context = vm.createContext({
    console: { log: (...args: unknown[]) => events.push(args.map(String).join(' ')) },
  });
  try {
    new vm.Script(code).runInContext(context, { timeout: 1000 });
  } catch (error) {
    events.push(`THREW ${(error as Error).name}`);
  }
  // Drain Promise continuations from the async/generator fixtures.
  for (let i = 0; i < 5; i++) await new Promise<void>((resolve) => setImmediate(resolve));
  return events;
}

/** every count a named pass reported, in order. */
function passCounts(result: { entries: Entry[] }, name: string): number[] {
  return result.entries.flatMap((e) =>
    e.kind === 'pass' && e.name === name && e.count !== null ? [e.count] : []
  );
}

async function recover(code: string, passes: readonly string[] = DEFAULT_ENABLED_PASSES) {
  const result = await deobfuscate(code, {
    enabledPasses: [...passes],
    lenientMode: false,
    autoFix: false,
  });
  expect(result.success).toBe(true);
  expect(result.errors).toEqual([]);
  expect(result.parsingErrors).toEqual([]);
  new vm.Script(result.deobfuscatedCode);
  return result;
}

describe('semantics corpus', () => {
  for (const name of readdirSync(fixtures)
    .filter((name) => name.endsWith('.js'))
    .sort()) {
    it(name, async () => {
      const source = readFileSync(new URL(name, fixtures), 'utf8');
      const result = await recover(source);
      expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    });
  }
});

describe('obfuscated corpus', () => {
  const directory = new URL('./obfuscated/', import.meta.url);
  for (const config of readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort()) {
    const fixture = JSON.parse(readFileSync(new URL(config, directory), 'utf8')) as {
      cases: { name: string; code: string }[];
    };
    for (const { name, code } of fixture.cases) {
      it(`${config}/${name}`, async () => {
        const source = readFileSync(new URL(name, fixtures), 'utf8');
        const expected = await execute(source);
        // Verify the generated fixture itself before blaming recovery.
        expect(await execute(code)).toEqual(expected);
        const result = await recover(code);
        expect(await execute(result.deobfuscatedCode)).toEqual(expected);
        // The per-transform js-confuser corpus is fully recovered: none of the
        // obfuscator's generated `__p_XXXX` names survives.
        if (config.startsWith('jsconfuser-') && config !== 'jsconfuser-medium.json')
          expect(result.deobfuscatedCode).not.toMatch(/__p_[A-Za-z0-9]{4}/);
        // preset fixtures stack every transform: up to ~20 s each on their own
      }, config === 'jsconfuser-medium.json' ? 120_000 : 30_000);
    }
  }
});

describe('structural primitives', () => {
  const cases: Record<string, string> = {
    'proxy folding keeps escaped property descriptors': `(function () {
      var table = { abc: function (a, b) { return a + b; } };
      var descriptor = {}, obj = {};
      descriptor.get = function () { return 42; };
      console.log(table.abc(1, 2));
      Object.defineProperty(obj, 'v', descriptor);
      console.log(obj.v);
    })();`,
    'self-replacement changes later results': `(function () {
      function fn(i) { fn = function () { return 2; }; return 1; }
      console.log(fn(0), fn(0));
    })();`,
    'eval observes helper declarations and aliases': `(function () {
      function helper() { return 7; }
      var alias = Math.max;
      console.log(eval('helper() + alias(1, 2)'));
    })();`,
    'unused arguments still throw': `(function () {
      var table = { abc: function (a) { return 1; } };
      try { console.log(table.abc(missing)); } catch (e) { console.log(e.name); }
    })();`,
    'conditional arguments still throw': `(function () {
      var table = { abc: function (a, b) { return a && b; } };
      try { console.log(table.abc(false, missing)); } catch (e) { console.log(e.name); }
    })();`,
    'member arguments retain value-call receivers': `(function () {
      var obj = { method: function () { return this === obj; } };
      var table = { abc: function (fn) { return fn(); } };
      console.log(table.abc(obj.method));
    })();`,
    'member calls in templates keep their receivers': `(function () {
      var obj = { method: function () { return this === obj; } };
      var table = { abc: function (x) { return x.method(); } };
      console.log(table.abc(obj));
    })();`,
    'repeated stateful decoder calls': `(function () {
      var pool = ['a', 'b', 'c'];
      function rot(i) { pool.push(pool.shift()); return pool[i]; }
      console.log(rot(0), rot(0), rot(0));
    })();`,
    'getter argument order': `(function () {
      var log = [], x = { get v() { log.push('getter'); return log.length; } };
      var table = { abc: function (a, b) { return b - a; } };
      console.log(table.abc(x.v, (log.push('arg'), 10)), log.join(','));
    })();`,
    'coercion before a later argument': `(function () {
      var x = 0, obj = { valueOf: function () { x++; return 2; } };
      var table = { abc: function (a, b) { return +a + b; } };
      console.log(table.abc(obj, x), x);
    })();`,
    'indirect eval stays indirect': `(function () {
      var hidden = 3;
      var table = { abc: function (fn, arg) { return fn(arg); } };
      console.log(table.abc(eval, 'typeof hidden'));
    })();`,
    'dead initializer still throws': `(function () {
      try { var unused = missing; } catch (e) { console.log(e.name); }
    })();`,
    'TDZ dead assignment still throws': `(function () {
      try { x = 1; } catch (e) { console.log(e.name); }
      let x;
    })();`,
    'object assembly preserves earlier effects': `(function () {
      var log = [], obj = { a: (log.push('init'), 1) };
      obj.a = 2;
      console.log(obj.a, log.join(','));
    })();`,
    'loop update preserves per-iteration let': `(function () {
      var out = [];
      for (let i = 0; i < 3; out.push(function () { return i; }), i++) {}
      console.log(out.map(function (fn) { return fn(); }).join(','));
    })();`,
    'decoder data initialized after a call': `(function () {
      try { console.log(decode(0)); } catch (e) { console.log(e.name); }
      var pool = ['a', 'b', 'c'];
      function decode(i) { return pool[i]; }
      console.log(decode(0));
    })();`,
    'parameter arity is observed': `(function () {
      function fn(x) { x = 1; return x; }
      console.log(fn.length, fn(9));
    })();`,
    'branch assignment does not dominate a read': `(function () {
      var x;
      if (false) { x = 3; }
      console.log(x);
    })();`,
    'dispatcher with unrelated initializer': `(function () {
      var order, i, out;
      for (order = ['1', '0'], i = 0, out = []; true;) {
        switch (order[i++]) {
          case '0': out.push('zero'); continue;
          case '1': out.push('one'); continue;
        }
        break;
      }
      console.log(out.join(','));
    })();`,
  };
  for (const [name, source] of Object.entries(cases)) {
    it(name, async () => {
      const result = await recover(source);
      expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    });
  }

  it('normalizes split pools and assignment-based proxy tables', async () => {
    const source = `(function (table, order, i) {
      table = { abc: function (a, b) { return a + b; } };
      var out = [];
      for (order = '1|0'.split('|'), i = 0; true;) {
        switch (order[i++]) {
          case '0': out.push(table.abc(2, 3)); continue;
          case '1': out.push(table.abc(4, 5)); continue;
        }
        break;
      }
      console.log(out.join(','));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['9,5']);
    expect(result.deobfuscatedCode).not.toMatch(/switch|table\.abc|\.split\(/);
  });

  it('defeats source-text traps: self-defending decoder, aliases and call controller', async () => {
    const source = readFileSync(new URL('./obfuscated/self-defending.js', import.meta.url), 'utf8');
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['Hello name World!name greet shout']);
    expect(passCounts(result, 'closed-function-eval')).toContain(6);
    expect(passCounts(result, 'self-defending')).toContain(3);
    // the plain log says the same thing, in the unified lowercase format
    expect(result.log.join('\n')).toMatch(/b05c {2}closed-function-eval +6 calls folded/);
    const code = result.deobfuscatedCode.replace(/^\/\/.*$/gm, ''); // the fixture's header comment survives
    // Decoder, rotation IIFE, both aliases, the probe and its controller are gone.
    expect(code).not.toMatch(/newState|\.search\(|parseInt|function [fdc]\b|\bconst [zpq] =/);
    // Property keys lost their quotes and brackets, reserved words included.
    expect(code).toMatch(/\bgreet\(n\)/);
    expect(code).toMatch(/static shout\(n\)/);
    expect(code).not.toMatch(/\[['"]/);
  });

  it('recovers an RGF function from guarded eval source and removes the eval', async () => {
    // js-confuser's reduced-global-function shape: a flag-guarded eval wrapper
    // returns a function embedded as source text (`function F(){…} F;`).
    const source = `function flag(x = true) { return x; }
      var integrity = flag();
      var box = [rgfEval("function embedded(){ return 6 * 7; } embedded;")];
      function rgfEval(code) { if (integrity) return eval(code); }
      console.log(box[0]());`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['42']);
    // The eval, the guard and the helper are all gone.
    expect(result.deobfuscatedCode).not.toContain('eval');
    expect(result.deobfuscatedCode).not.toContain('integrity');
    expect(result.deobfuscatedCode).not.toContain('rgfEval');
    expect(result.log.join('\n')).toContain('b03e');
  });

  it('collapses RGF forwarding thunks, including a shared multi-function box', async () => {
    // Two functions packed into one eval-embedded box, each reached by a thunk
    // that forwards this/arguments. After recovery both thunks are their real
    // bodies and nothing obfuscated is left.
    const source = `function flag(x = true) { return x; }
      var integrity = flag();
      function rgfEval(code) { if (integrity) return eval(code); }
      var box = [
        rgfEval("function e0(){ var[s,a]=arguments; function R(n){ return n + 1; } return R.apply(this,a); } e0;"),
        rgfEval("function e1(){ var[s,a]=arguments; function R(n){ return n * 2; } return R.apply(this,a); } e1;")
      ];
      function inc() { return box[0].apply(this, [box, arguments]); }
      function dbl() { return box[1].apply(this, [box, arguments]); }
      console.log(inc(4), dbl(4));`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['5 8']);
    const code = result.deobfuscatedCode;
    expect(code).not.toContain('eval');
    expect(code).not.toContain('box');
    expect(code).not.toContain('.apply');
    expect(result.log.join('\n')).toContain('b03f');
  });

  it('leaves an RGF wrapper whose guard is not provably true', async () => {
    const source = `var integrity = Math.random() > 2;
      var box = [rgfEval("function embedded(){ return 1; } embedded;")];
      function rgfEval(code) { if (integrity) return eval(code); }
      console.log(typeof box[0]);`;
    const result = await recover(source);
    // A guard we cannot prove truthy must keep the eval: the value could be
    // undefined, and folding would change behaviour.
    expect(result.deobfuscatedCode).toContain('eval');
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
  });

  it('leaves an RGF embedding whose body would capture a local', async () => {
    const source = `(function () {
      var captured = 'outer';
      var box = [rgfEval("function embedded(){ return typeof captured; } embedded;")];
      function rgfEval(code) { if (true) return eval(code); }
      console.log(box[0](), captured);
    })();`;
    const result = await recover(source);
    // The embedded body resolves \`captured\` globally; inlining it beside the
    // local would capture the wrong binding, so the eval stays.
    expect(result.deobfuscatedCode).toContain('eval');
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
  });

  it('decodes the combined string transforms, incl. a direct-global UTF-8 finisher', async () => {
    // js-confuser `strings` preset = concealing + encoding + splitting + dup
    // literals. stringEncoding emits a bufferToString finisher that reaches
    // TextDecoder/Uint8Array as *direct globals*, not aliases; B05d must still
    // recognise it and evaluate the per-block retrievers.
    const dir = new URL('./obfuscated/jsconfuser-strings.json', import.meta.url);
    const fixture = JSON.parse(readFileSync(dir, 'utf8')) as { cases: { name: string; code: string }[] };
    const greet = fixture.cases.find((c) => c.name === '29-greet.js');
    expect(greet).toBeDefined();
    const result = await recover(greet!.code);
    expect(result.deobfuscatedCode).toContain('Hello ');
    // No per-block retriever or decoder left behind.
    expect(result.deobfuscatedCode).not.toMatch(/_STR(_|\d)|_decode\b/);
    expect(result.log.join('\n')).toContain('b05d');
  });

  it('writes out a program hidden in a Function() string', async () => {
    const source = `var out = Function("p", "var seen = p * 2; return seen + 1;")(20);
      console.log(out);`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['41']);
    expect(result.log.join('\n')).toContain('function-ctor');
    expect(result.deobfuscatedCode).not.toContain('Function(');
  });

  it('leaves a Function() body whose free name would capture a local', async () => {
    // A parameter cannot be propagated away, so the binding is still there
    // when the unwrap is considered.
    const source = `(function (hidden) {
      var fn = Function("return typeof hidden;");
      console.log(fn(), hidden);
    })('local');`;
    const result = await recover(source);
    // The body resolves `hidden` globally; inlining would bind it to the local.
    expect(result.deobfuscatedCode).toContain('Function(');
    expect(await execute(result.deobfuscatedCode)).toEqual(['undefined local']);
  });

  it('inlines a literal direct eval and keeps a declaring one', async () => {
    const source = `(function () {
      var flag = false;
      eval("flag = true");
      var self = eval("this");
      eval("var introduced = 3");
      console.log(flag, self === undefined, typeof introduced);
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    const code = result.deobfuscatedCode;
    expect(code).not.toContain('eval("flag = true")');
    expect(code).not.toContain('eval("this")');
    expect(code).toContain('eval("var introduced = 3")');
  });

  it('folds reads of a frozen literal array and keeps escaping ones', async () => {
    const source = `(function () {
      var keep = ['x', 'y'];
      function sink(a) { a[0] = 'mutated'; return a[0]; }
      var table = ['log', 2, 'ok', -1];
      console.log(table[0], table[1], table[2], table[3], table.length, sink(keep), keep[0]);
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    const log = result.log.join('\n');
    expect(log).toContain('literal-arrays');
    // `keep` is handed to a function that writes it: its reads must stay reads.
    expect(result.deobfuscatedCode).toContain('keep[0]');
  });

  it('confines a direct eval to the scopes that enclose it', async () => {
    const source = `(function () {
      function reachable() {
        var dead = 'unused';
        var table = ['a', 'b'];
        return table[1];
      }
      function dynamic() {
        var watched = 'kept';
        // A runtime value: the engine cannot turn this call into a literal, so
        // the eval stays and keeps this scope dynamic.
        var key = console.log.name;
        return eval(key.length > 0 ? 'watched' : 'watched');
      }
      console.log(reachable(), dynamic());
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['b kept']);
    // The eval-free sibling is cleaned up …
    expect(result.deobfuscatedCode).not.toContain("'unused'");
    // … while the binding the eval can read by name is left alone.
    expect(result.deobfuscatedCode).toContain('watched');
  });

  it('never inlines a proxy whose target a local or an Annex B function would capture', async () => {
    // `get` forwards to the top-level `pool.slice`. Inside `user`, a block-level
    // function named `pool` (sloppy mode) shadows the pool for the whole
    // function: inlining `pool.slice` there would call the wrong thing.
    const source = `var pool = [1, 2, 3, 4];
      function get(a, b) { return pool.slice(a, b); }
      function user(flag) {
        var out = get(1, 3).join(',');
        if (flag) { function pool() { return 'fn'; } }
        return out + ':' + typeof pool;
      }
      function other() { var pool = { slice: function () { return 'local'; } }; return get(0, 2); }
      console.log(user(true), other().join(','));`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
  });

  it('does not inline a native alias read before its declaration runs', async () => {
    const source = `(function () {
      function early() { return typeof alias; }
      var first = early();
      var alias = Math.max;
      console.log(first, early(), alias(1, 2));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['undefined function 2']);
  });

  it('keeps the global-object prefix on host APIs that may be missing', async () => {
    // \`g.TextDecoder\` is undefined on a host without it; a bare
    // \`TextDecoder\` would throw a ReferenceError instead.
    const source = `var g = globalThis;
      var TD = g.TextDecoder;
      console.log(typeof TD, g.Math.max(1, 2));`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['undefined 2']);
    expect(result.deobfuscatedCode).not.toMatch(/=\s*TextDecoder\b/);
  });

  it('treats a value as fixed only where every read provably follows the write', async () => {
    // `dec` is assigned after `get` is declared. The first `get()` runs before
    // the assignment and must still see `undefined`; the later call is free to
    // use the value. A closure that escapes (`keep`) could run at any time.
    const source = `(function () {
      var dec;
      function get() { return typeof dec; }
      var keep = function () { return typeof dec; };
      var early = get();
      var held = [keep];
      dec = function (x) { return x + 1; };
      console.log(early, get(), held[0](), dec(1));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['undefined function function 2']);
  });

  it('keeps the short-circuited operand itself, not a boolean', async () => {
    const source = `console.log(0 && f(), 1 || f(), String(0 && 'x'), typeof (1 || 'x'));`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    expect(result.deobfuscatedCode).not.toMatch(/\bfalse\b|\btrue\b/);
  });

  it('drops only discarded expressions that have no effect', async () => {
    // The first IIFE writes nothing outside its own rest array; the second
    // writes a captured variable, and the third calls out.
    const source = `(function () {
      var seen = 0;
      [1, 2, undefined];
      (function (...r) { r.length = 0; r[3] = new Array(4); return function () { return r; }; })();
      (function () { seen = 1; })();
      (function () { console.log('called'); })();
      console.log(seen);
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['called', '1']);
    expect(result.deobfuscatedCode).not.toContain('new Array(4)');
    expect(result.deobfuscatedCode).not.toContain('[1, 2, undefined]');
  });

  it('declares a called-only function variable, and leaves an escaping one alone', async () => {
    // helper is only called, so a declaration names and behaves the same;
    // shared is stored, so its identity and spelling stay as they were.
    const source = `(function () {
      var helper, shared;
      helper = function (x) { console.log('h', x); };
      shared = function () { return 1; };
      var list = [shared];
      helper(3);
      helper(4);
      console.log(list[0] === shared, shared.name);
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['h 3', 'h 4', 'true shared']);
    expect(result.deobfuscatedCode).toMatch(/function helper\(/);
    expect(result.deobfuscatedCode).not.toMatch(/function shared\(/);
  });

  it('keeps eval-sensitive passes off when an eval only appears after a Function() unwrap', async () => {
    // `p` is reached only through the eval: removing it as a forwarded proxy
    // would turn the eval's call into a ReferenceError.
    const source = `Function("function p(a){ return q(a); } function q(a){ return a + 1; } var k = typeof window === 'undefined' ? 'p' : 'p'; console.log(eval(k + '(1)'), q(5));")();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['2 6']);
  });

  it('removes an integrity lock only when the original text proves it passes', async () => {
    // js-confuser's lock: cyrb53 of the function's text, sensitivity characters
    // stripped, compared with a constant fixed at obfuscation time.
    const cyrb53 = (str: string, seed: number): number => {
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
    };
    const target = 'function F(x){var y=x*2;return y+1}';
    const strip = / |\n|;|,|\{|\}|\(|\)|\.|\[|\]/g;
    const hashFn = `function H(fn,seed){var s=fn.toString().replace(/ |\\n|;|,|\\{|\\}|\\(|\\)|\\.|\\[|\\]/g,"");var h1=3735928559^seed,h2=1103547991^seed;for(var i=0;i<s.length;i++){var ch=s.charCodeAt(i);h1=Math.imul(h1^ch,2654435761);h2=Math.imul(h2^ch,1597334677)}h1=Math.imul(h1^h1>>>16,2246822507)^Math.imul(h2^h2>>>13,3266489909);h2=Math.imul(h2^h2>>>16,2246822507)^Math.imul(h1^h1>>>13,3266489909);return 4294967296*(2097151&h2)+(h1>>>0)}`;
    const lock = (c: number) =>
      `(function(){${hashFn}${target}function L(){if((L.k||(L.k=H(F,77)))===${c}){return F(...arguments)}else{while(true){}}}console.log(L(20))})();`;
    const good = lock(cyrb53(target.replace(strip, ''), 77));
    expect(await execute(good)).toEqual(['41']);
    const unlocked = await recover(good);
    expect(await execute(unlocked.deobfuscatedCode)).toEqual(['41']);
    expect(unlocked.deobfuscatedCode).not.toMatch(/while \(true\)/);
    // a constant the text does not hash to: the original hangs — keep the
    // lock, and say so: the recovered text cannot hash to it either
    const bad = await deobfuscate(lock(12345), { enabledPasses: [...DEFAULT_ENABLED_PASSES], lenientMode: false, autoFix: false });
    expect(bad.deobfuscatedCode).toMatch(/while \(true\)/);
    expect(bad.errors.join('\n')).toMatch(/integrity lock/);
  });

  it('settles a newline self-test only for newline-free source', async () => {
    const flat = `(function(){function g(){return 1}function chk(){return new RegExp("\\n").test(g)}if(chk()){while(true){}}console.log(g())})();`;
    const result = await recover(flat);
    expect(await execute(result.deobfuscatedCode)).toEqual(['1']);
    expect(result.deobfuscatedCode).not.toMatch(/RegExp|while \(true\)/);
    // with a newline in the original, g's own text matches: left alone
    const tall = `(function(){function g(){\nreturn 1}function chk(){return new RegExp("\\n").test(g)}if(chk()){while(true){}}console.log(g())})();`;
    expect((await recover(tall)).deobfuscatedCode).toMatch(/RegExp/);
  });

  it('recovers greet from the medium and locks presets to a few lines', async () => {
    // Every js-confuser layer at once (cff, dispatcher, strings, globals,
    // masking, pack) and the self-text locks: the result is the program itself.
    for (const config of ['jsconfuser-medium.json', 'jsconfuser-locks.json']) {
      const { cases } = JSON.parse(readFileSync(new URL(`./obfuscated/${config}`, import.meta.url), 'utf8')) as {
        cases: { name: string; code: string }[];
      };
      const greet = cases.find((c) => c.name === '29-greet.js')!;
      const result = await recover(greet.code);
      expect(await execute(result.deobfuscatedCode)).toEqual(['Hello Internet User!']);
      expect(result.deobfuscatedCode).toMatch(/"Hello " \+ \w+ \+ "!"/);
      expect(result.deobfuscatedCode.length).toBeLessThan(600);
    }
  }, 120_000);

  it('simulates a flattened function past a dead countermeasure case', async () => {
    // A real predicate (`out.length > 5`) forks the state walk. One fork is a
    // path the original never takes: it reaches the `while (true) {}` case
    // and would fall through into updates for which no label exists. Both
    // are "this path never completes" — not a reason to give up on the loop.
    const source = `function sum(a) { var s = 0; for (var i = 0; i < a.length; i++) s += a[i]; return s; }
      function main(S, out) {
        while (sum(S) !== 50) switch (sum(S)) {
          case 10:
            out.push('a');
            if (out.length > 5) { S[0] += S[1] + 5; break; }
            S[0] += S[1] + 0;
            break;
          case 15:
            out.push('b');
            S[0] += S[1] + 30;
            break;
          case 20:
            while (true) {}
          case 999:
            S[0] += S[1] + 31;
            break;
        }
      }
      var o = []; main([5, 5], o); console.log(o.join(','));`;
    expect(await execute(source)).toEqual(['a,b']);
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['a,b']);
    expect(result.deobfuscatedCode).not.toMatch(/switch|sum\(/);
  });

  it('lowers masked slots when a hoisted declaration precedes the truncation', async () => {
    const source = `(function (...S) {
      function read() { return S.a + S[1]; }
      S.length = 0;
      S.a = 7;
      S[1] = 5;
      console.log(read());
    })(1, 2);`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['12']);
    expect(result.deobfuscatedCode).not.toMatch(/\.length = 0|\.a\b|S\[1\]/);
  });

  it('keeps the output compact when a newline self-test cannot be settled', async () => {
    // `probe` escapes into an object, so B20 cannot prove what `.test(probe)`
    // returns at every use; the original (one line) answered "no". Pretty
    // printing would make it "yes" and hang: the output stays on one line.
    const source = `(function(){function probe(){return 1}var keep={p:probe};function chk(){return new RegExp("\\n").test(keep.p)}if(chk()){while(true){}}console.log(keep.p())})();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['1']);
    expect(result.deobfuscatedCode.trim()).not.toMatch(/\n/);
  });

  it('folds function probes beside prototype methods that spell other names', async () => {
    // js-confuser's dead-code templates install methods on prototypes of
    // objects nobody can name (`frame.a.List.prototype.get = …`); that adds
    // `get`, never the random probe key, so `"soWeC2" in dummy` is still false.
    // A write that spells the probed key itself keeps the probe.
    const source = `(function () {
      var frame = { a: { List: function () {} } };
      frame.a.List.prototype.get = function () { return 1; };
      function dummy() {}
      function grab() { const self = this; return !("soWeC2" in dummy) ? self : "junk"; }
      var G = grab();
      console.log(typeof G.Math, typeof new frame.a.List().get);
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['object function']);
    expect(result.deobfuscatedCode).not.toMatch(/soWeC2|dummy/);
    const spelled = `(function () {
      var frame = { a: { List: function () {} } };
      function dummy() {}
      frame.a.List.prototype.soWeC2 = 1;
      console.log("soWeC2" in dummy);
    })();`;
    const kept = await recover(spelled);
    expect(await execute(kept.deobfuscatedCode)).toEqual(['false']);
    expect(kept.deobfuscatedCode).toMatch(/in dummy/);
  });

  it('lowers the frames it can prove while another frame still escapes', async () => {
    // Frame A is handed to `keep`, which nothing here expands: A stays an
    // object. Frame B is only ever read and written through `S.B.y`, so it
    // becomes a variable regardless.
    const source = `(function () {
      function keep(o) { o.A.x += 10; return o.A.x; }
      var r = (function (S = { A: {}, B: {} }) {
        S.A.x = 1;
        S.B.y = 2;
        var k = keep({ A: S.A });
        return k + S.A.x + S.B.y;
      })({ A: {}, B: {} });
      console.log(r);
    })();`;
    expect(await execute(source)).toEqual(['24']);
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['24']);
    expect(result.deobfuscatedCode).toMatch(/\.A\b/);
    expect(result.deobfuscatedCode).not.toMatch(/\.B\b|B:/);
  });

  it('drops an unused block function whose name only recurs as a nested let', async () => {
    // Sloppy block functions also write a function-scoped var (Annex B). The
    // `let late` inside the inner function shadows that var, so nothing reads
    // it and the dead template declaration can go.
    const source = `(function () {
      function run(mode) {
        var show = function () {
          var r = [];
          try { r.push(late); } catch (e) { r.push(e.name); }
          let late = "late";
          r.push(late);
          return r.join(",");
        };
        if (mode === "x") { function late() { return "template"; } }
        return show();
      }
      console.log(run("y"), run("x"));
    })();`;
    expect(await execute(source)).toEqual(['ReferenceError,late ReferenceError,late']);
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['ReferenceError,late ReferenceError,late']);
    expect(result.deobfuscatedCode).not.toMatch(/template/);
    // The same declaration stays when the function reads the var it writes.
    const read = `(function () {
      function run(mode) {
        if (mode === "x") { function late() { return "template"; } }
        return typeof late;
      }
      console.log(run("y"), run("x"));
    })();`;
    const kept = await recover(read);
    expect(await execute(kept.deobfuscatedCode)).toEqual(['undefined function']);
  });

  it('bounds a table member function by its call sites and restores its moved declaration', async () => {
    // js-confuser's dispatcher table: every member is only ever called with
    // no arguments, so the guarded parameter is a moved local.
    const source = `(function () {
      var fns = {
        a: function (helper) {
          if (!helper) { helper = function (x) { return x + 1; }; }
          return helper(41);
        },
        b: function () { return fns.a.apply(this); }
      };
      console.log(fns.a(), fns['b'](), fns.a.call(this));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['42 42 42']);
    expect(result.deobfuscatedCode).not.toMatch(/if \(!helper\)/);
  });

  it('unwraps a bare block that scopes nothing', async () => {
    const source = `function f(a) { var x = a + 1; { return x * 2; } }
      function g(a) { { let y = a; { console.log(y, typeof h); } } { function h() { return a; } console.log(h()); } }
      console.log(f(2)); g(3);`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['6', '3 undefined', '3']);
    // the declaration-free blocks are gone (f folds away entirely); the
    // `let` block and the sloppy block function keep theirs
    expect(result.deobfuscatedCode).toMatch(/console\.log\(6\)/);
    expect(result.deobfuscatedCode).toMatch(/let y = a;\s*console\.log\(y, typeof h\);/);
    expect(result.deobfuscatedCode).toMatch(/\{\s*function h\(\)/);
  });

  it('settles an eval whose source mixes retriever calls with fixed table reads', async () => {
    // The eval reads the table it sits beside (`T[0]`); its source is still
    // fixed, so the eval can be written out and the table folded with it.
    const source = `(function () {
      const T = ["e", 1];
      var P = " = tru";
      function DEC(s) { return s; }
      function R(a, b) { return DEC(P.slice(a, a + b)); }
      var flag = false;
      eval("flag" + (R(0, 6) + T[0]));
      if (!flag) { while (true) {} }
      console.log(flag, R(3, 3));
    })();`;
    expect(await execute(source)).toEqual(['true tru']);
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['true tru']);
    expect(result.deobfuscatedCode).not.toMatch(/\beval\b|T\[0\]/);
    expect(result.deobfuscatedCode).toMatch(/flag = true;/);
  });

  it('turns a duplicate var declaration with a value into an assignment', async () => {
    // The second declaration has nothing to keep but a value: it becomes the
    // assignment itself (not an empty `var ;` with the value lost).
    const source = `function f(a, b) { var r; var q = a; var r = a + b; return r + q; }
      console.log(f(1, 2));`;
    const result = await recover(source, ['deduplicateVarDecls']);
    expect(await execute(result.deobfuscatedCode)).toEqual(['4']);
    expect(result.deobfuscatedCode).toMatch(/r = a \+ b;/);
    expect(result.deobfuscatedCode).not.toMatch(/var ;/);
  });

  it('declares a write-once function variable that is also constructed with new', async () => {
    // (every use is a call or a `new`; a property access would keep the var)
    const source = `(function () {
      var D;
      D = function (k) { this.k = k; };
      console.log(new D(3).k, D(4));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['3 undefined']);
    expect(result.deobfuscatedCode).toMatch(/function D\(k\)/);
  });

  it('unmasks a called slot fed from a local array of this-free functions', async () => {
    const source = `(function (...S) {
      S.length = 0;
      var fns = [function (x) { return x + 1; }, function (x) { return x * 2; }];
      S[3] = [];
      for (S[7] = 0; S[7] < 2; S[7]++) { S.d = fns[S[7]]; S[3].push(S.d(10)); }
      console.log(S[3].join(','));
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['11,20']);
    expect(result.deobfuscatedCode).not.toMatch(/\.\.\.S\b|S\[/);
  });

  it('keeps a thunk parameter the forwarded body reaches by closure', async () => {
    // js-confuser's calling-convention thunk forwards its rest array as an
    // argument; here the inner body reads the array itself instead, so the
    // parameter must survive whatever the thunk collapse does.
    const source = `function sum(a) { var s = 0; for (var i = 0; i < a.length; i++) s += a[i]; return s; }
      var out = (function (...S) {
        return (function (frame = { K: {} }) {
          S.length = 0;
          S.a = 5;
          frame.K.v = S.a + 1;
          while (sum([1, 2]) !== 3) switch (sum([1, 2])) { case 9: break; }
          return frame.K.v;
        })({ K: {} });
      })(7, 8);
      console.log(out);`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['6']);
  });

  it('probes a masked retriever whose keys come from a literals table', async () => {
    // variableMasking + duplicateLiteralsRemoval on the retriever: no
    // parameters to match, `length` and `slice` spelt as table entries. The
    // sandbox runs it as it stands, so the eval it feeds still gets settled.
    const source = `(function () {
      const T = ["length", 2, "slice", 0, 1];
      var P;
      function DEC(s) { return s; }
      function R(...S) { S[T[0]] = T[1]; return DEC(P[T[2]](S[T[3]], S[T[3]] + S[T[4]])); }
      P = "flag = true;tru";
      var flag = false;
      eval(R(0, 12));
      if (!flag) { while (true) {} }
      console.log(flag, R(12, 3));
    })();`;
    expect(await execute(source)).toEqual(['true tru']);
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(['true tru']);
    expect(result.deobfuscatedCode).not.toMatch(/\beval\b|\bR\(/);
  });

  it('keeps reserved-word members and class constructor keys meaningful', async () => {
    const source = `(function () {
      class K { ['constructor']() { return 'method'; } static ['prototype2']() { return 'ok'; } }
      const o = { ['__proto__']: 1, 'catch': 2 };
      console.log(new K().constructor === K, K.prototype2(), o.catch, Object.keys(o).join(','));
      Promise.resolve(1)['catch'](function () {}).then(function (v) { console.log(v); });
    })();`;
    const result = await recover(source);
    expect(await execute(result.deobfuscatedCode)).toEqual(await execute(source));
    expect(result.deobfuscatedCode).toContain('.catch(');
    expect(result.deobfuscatedCode).toContain("['constructor']");
    expect(result.deobfuscatedCode).toContain("['__proto__']");
  });
});
