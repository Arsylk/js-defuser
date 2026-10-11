# js-defuser

Sound, fully automatic JavaScript deobfuscation. Give it a file that went through
[js-confuser](https://github.com/MichaelXF/js-confuser) at its **maximum settings** —
control-flow flattening, dispatchers, flattening, variable masking, string concealing,
global concealing, RGF, pack, opaque predicates, dead code, plus the integrity /
self-defending / tamper-protection locks — and it comes back as the program you
wrote. [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
(obfuscator.io) output is recovered the same way.

```
$ js-defuser -f sample.max.js -o sample.js -v
deobfuscate  42 passes · 959628 bytes
stage a · pre-parse
  parse ok
sweep 1/12
  b03c  function-ctor                1 unwrapped
  b13d  cff-recover                101 dispatchers  (8294 frame refs lowered, 115 call shims removed)
  b05d  concealed-strings          245 strings  (35 retrievers probed · 60 declarations removed)
  …
done  145 bytes · 100.0% smaller

$ cat sample.js
(function () {
  function greet(name) {
    var output = "Hello " + name + "!";
    globalThis.console.log(output);
  }
  greet("Internet User");
})();
```

The input of that run is js-confuser's own editor demo at max settings; it is checked
in as a release gate (`tests/gates/`) so the result can never silently regress.

## Install

```sh
npm install js-defuser        # library + `js-defuser` command
npx js-defuser -f in.js -o out.js
```

Node 20 or newer. No network access, no native modules; the only runtime
dependencies are the Babel parser/traverser/generator. For browsers see below.

## Command line

```
js-defuser [-f input.js] [-o output.js] [--verbose]

  -f, --file <path>    read obfuscated JavaScript from a file (default: stdin)
  -o, --output <path>  write the result (default: input.deobf.js, or stdout for stdin)
  -v, --verbose        stream the pass log to stderr while it runs
      --jsnice …       opt-in post-processing through a JSNice-compatible service
                       (sends your code to a third party; off unless asked for)
```

Exit code 1 means the run finished but some pass reported an error (the output is
still the best sound result); 2 means the input could not be processed at all.

A pretty-printed input is taken for the compact program the obfuscator emitted:
obfuscators decide things from their own text (js-confuser's anti-beautify lock hangs
a formatted copy on purpose), so the engine answers those checks for the compact
original and says so in the log. `--strict-source` (`assumeCompactSource: false`)
analyses the text exactly as given.

## Library

```ts
import { deobfuscate, DEFAULT_ENABLED_PASSES, ansi } from 'js-defuser';

const result = await deobfuscate(source, {
  enabledPasses: [...DEFAULT_ENABLED_PASSES],
  lenientMode: false,
  autoFix: true,
  onLog: (_line, entry) => process.stderr.write(ansi(entry) + '\n'), // optional, live progress
});

result.deobfuscatedCode;   // the recovered program
result.success;            // false when a pass reported an error
result.errors;             // those errors, e.g. an integrity lock the source text does not settle
result.log / result.entries; // the pass log, plain lines and structured
result.metadata;           // sizes, reduction, unresolved evals, …
```

`PASS_CATALOG` describes every pass with a one-line explanation; pass names in
`enabledPasses` select which ones run. The defaults are the full safe set.

### In the browser

```ts
import { deobfuscate, prepare } from 'js-defuser/browser';
await prepare(); // loads the WebAssembly sandbox once (~1 MB)
```

The same engine, with its sandboxed evaluations running on QuickJS compiled to
WebAssembly instead of `node:vm` — a separate JavaScript engine with its own heap and
an interrupt-based time budget, so nothing the evaluated slices do can reach the page.
Needs the optional peer dependencies `quickjs-emscripten-core` and
`@jitl/quickjs-singlefile-browser-release-sync`; run it in a Web Worker, the engine is
synchronous while it works. `js-defuser/logger` exports the log renderers and the
palette without the engine. A test keeps the two sandboxes producing byte-identical
recoveries; the live demo is [arsylk.github.io/js-defuse-web](https://arsylk.github.io/js-defuse-web/).

## What it recovers

**js-confuser 2.1.3**, every transform, including the combinations the presets stack
and the locks the presets add:

| corpus (29 semantics fixtures each) | result |
| --- | --- |
| every single-transform configuration (21 configs) | all cases recovered |
| `controlFlowFlattening` on its own | 28/28 |
| `low` preset | 27/27 |
| `medium` preset | 26/26 |
| `low` + integrity + selfDefending + tamperProtection | 27/27 |
| `high` preset + `pack` + all locks (the maximum) | 26/26 |

"Recovered" means the output behaves exactly like the original in a differential VM run
and, except for names, is structurally the original program — the control-flow
state machines, dispatcher tables, scope frames, string pools, global lookups and
dead-code templates are all gone. (Cases the obfuscator itself miscompiles are
listed in the fixtures as `skipped`.)

**javascript-obfuscator** (obfuscator.io) **4.2.2 and 5.9**: string arrays with rotation,
index shift and RC4/base64 decoders, variable and function wrappers (chained), calls
transform, control-flow flattening and its storage objects, dead code injection,
self-defending, debug protection, transformed object keys, numbers-to-expressions,
split strings, unicode escapes, mangled and renamed globals:

| corpus (29 semantics fixtures each) | result |
| --- | --- |
| 5.9 `high-obfuscation` preset | 29/29 |
| 5.9 high preset with every other option turned up (rc4 + base64, calls transform, unicode escapes, mangled names, `renameGlobals`) | 27/27 |

Everything else that is common: `eval`/`Function` wrappers, proxy functions, opaque
predicates, bracket-notation members, hex/unicode/`fromCharCode`/`atob` strings,
constant folding, sequence expressions, dead stores and temporaries.

**Dean Edwards' packer** (`eval(function(p,a,c,k,e,d){…}('…',N,M,'…'.split('|'),0,{}))`)
and **JSFuck** (`[][…]["constructor"](<[]()!+ source>)()`) are recovered back to the
original program. Both ship the real source behind a decoder that is a closed, pure
string transform, so the engine evaluates *only that slice* — in a sandbox with no
reachable `eval` or `Function` — reads back the source it builds, and splices it in.
The payload is never run; a decoder that tried to execute its own result throws
instead. The rewrite is taken per call only where it is provably behaviour-preserving
(a sloppy caller, no name the payload introduces clashing or escaping its scope).

**Not (yet) recovered**, though the output still behaves like the input: bytecode-VM
obfuscators (Obscura, MeowShield's JSVMP levels). When the engine cannot settle a
self-check that reads the program's own text, it keeps the output on one line rather
than risk changing what the check sees. One known exception: MeowShield's self-defending
VM level verifies its own text from inside the bytecode, where the engine cannot see the
check, and rejects any reprint at all.

## How it works — and what "sound" means here

The engine is a pipeline of ~45 Babel AST passes that sweep until nothing changes.
Each pass rewrites only when it can prove the rewrite preserves behaviour, and the
proof is written next to the code: a comment states why the transformation is
unobservable, and a test shows the case where it must *not* fire.

- **The payload is never executed.** Obfuscated programs carry locks that hang the
  process, check their own source text, or probe for tampering. The engine runs only
  *closed slices* it has proven pure — a string decoder and the pool it reads, a
  state-array helper, a global-lookup table — inside a `node:vm` context with a time
  budget and no host objects. Everything else is static.
- **Locks are decided by facts about the original text.** js-confuser's integrity
  lock hashes a function's own source; the engine computes that hash from the input
  it was given and removes the lock only when the numbers match. The anti-beautify
  check (`RegExp("\n").test(fn)`) is answered from whether the original functions
  contained newlines. When a lock cannot be settled, the output is kept compact and
  the lock is reported — it is never guessed.
- **Per-item refusal, never per-file.** Where a pass cannot prove one dispatcher,
  one scope frame or one probe, it leaves exactly that item alone and continues with
  the rest. The maximum-settings corpus is what exposed every whole-file bail-out in
  earlier versions.
- **Binding-aware, not name-based.** Every decision about a variable goes through
  Babel's scope analysis (plus the engine's own facts for `var`/Annex B hoisting,
  write-once bindings, `eval`/`with` reach and `arguments` aliasing).

Dynamic scopes (`eval`, `with`) switch the binding-based passes off for the scopes
they can see, until an earlier pass has removed the construct.

## Tests

```sh
npm test            # 970+ behavioural tests: fixtures × every obfuscator configuration, ~15 min
npm run test:gates  # the two max-settings release gates, ~3 min
```

Every test runs the original and the recovered program in separate VM contexts and
compares what they print; a recovery that behaves differently fails, whatever it
looks like. The fixture JSONs record the exact obfuscator version and options they
were generated with and can be regenerated from an installed obfuscator (see
`tests/README.md`); the tests themselves need no obfuscator and no network.

## Prior art

General-purpose deobfuscators (webcrack, synchrony, REstringer) target obfuscator.io;
js-confuser's changelog lists the release that stopped each of them. The two public
js-confuser-specific tools either stop at nested control-flow flattening or execute
the sample to unpack it. js-defuser's results above are, as far as we know, the first
automatic, non-executing recovery of js-confuser at maximum settings with the locks
on — and the gates in this repository are there to keep it that way.

## License

MIT © Krzysztof Iwaniuk (Arsylk)
