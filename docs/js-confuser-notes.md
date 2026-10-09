> **Note.** These are the working notes from the js-confuser recovery effort, kept verbatim.
> They were written inside the original monorepo: `apps/web/src/app/api/deobfuscator/engine/`
> is `src/` here, `engine/__tests__/` is `tests/`, `bun run test:engine` is `npm test`,
> `bun run test:gates` is `npm run test:gates`, and `deobfuscate-js` is the `js-defuser` CLI.
> Scratchpad corpora (`high`, `max`) are generated locally with the scripts in `tests/`.

# Handoff: JS-Confuser support

Context for a new session picking up JS-Confuser recovery in this engine.

## Where the sample came from

`~/marsbahis/helloworld.js` (about 960 KB) is **js-confuser's own editor demo**, obfuscated at
https://js-confuser.com/editor with a heavy preset. js-confuser is version 2.1.3. The original source
is the editor's default example:

```js
function greet(name) {
  var output = 'Hello ' + name + '!';
  console.log(output);
}

greet('Internet User');
```

The bulk of the file comes from stacked transforms and the preset's protection options. It is a test
input, not a third-party payload.

## How to work this time

The previous session worked directly on the max-preset file. That stalled. Use **fixtures built one
option at a time** instead, the way `engine/__tests__/obfuscated/*.json` were built from
javascript-obfuscator 4.2.2:

1. Install js-confuser locally at a pinned version, `npm i js-confuser@2.1.3` in a scratch directory.
   Do not add it to the repo's dependencies.
2. Take the small programs in `engine/__tests__/fixtures/*.js` as inputs, plus the `greet` program above.
3. Obfuscate each with **a single option enabled**, then with small combinations. Check the option
   names against the installed version's docs. Likely candidates:
   - `stringConcealing`, `stringEncoding`, `stringSplitting`
   - `controlFlowFlattening`, `dispatcher`, `opaquePredicates`, `deadCode`
   - `globalConcealing`, `calculator`, `objectExtraction`, `flatten`
   - `duplicateLiteralsRemoval`, `movedDeclarations`, `renameVariables`
4. Save the outputs as a new `engine/__tests__/obfuscated/jsconfuser-*.json`, with the generation
   options recorded in each file like the existing ones. Add a small regenerate script next to
   `regenerate-fixtures.cjs`.
5. The existing `obfuscated corpus` test already runs every JSON in that folder and checks that the
   recovered code behaves like the original. Start there and see which configurations fail.
6. Fix one transform at a time, smallest failing fixture first. Add a structural assertion per fix,
   for example "no decoder call left", next to the behavioural check.

Leave the protection-style options out of scope. That means integrity checks, locks, anti-debug and
anti-tooling. Focus on recovering readable code from the obfuscating transforms.

## What already exists (done 2026-10-08, all tested)

These live in `apps/web/src/app/api/deobfuscator/engine/deobfuscator.ts` and `analysis.ts`:

- **B03c `functionCtor`** writes out a `Function("args", "body")` call statically, with no execution.
  It is refused when a free name of the body would capture a local, or when the surrounding code is
  strict.
- **B03d `evalLiteral`** replaces a direct `eval("<one expression>")` with the expression.
- **`dynamicScopes`** in `analysis.ts` provides per-binding `eval`/`with` gating. A direct `eval`
  only blocks the bindings of the scopes that enclose it. The orchestrator now turns off 11
  shape-matching passes when one is present, instead of 20.
- **B07d `literalArrays`** folds `K[13]` reads from write-once literal arrays that nothing can mutate
  or escape with.

On the demo file these unwrap the `Function` layer and land about 49k changes. Literal-array folding
does not reach the main index table there, because two non-literal `eval` calls keep its scope
dynamic.

Gaps that per-option fixtures will likely surface:

- Decoder calls with two arguments where the second is a table read, `dec(3923, K[32])`, plus
  rest-parameter wrappers around them.
- Flattened control flow that dispatches on a value computed from a state *array* that each case
  mutates. B13, B13b and B13c only model a scalar state or a split-string order.
- Decoders that finish through `TextDecoder` or `Buffer`, which are not in `SLICE_SAFE_GLOBALS`.

## Project conventions

- Run the suite from the repo root with `bun run test:engine`. It must stay green: 288 tests at handoff.
- Typecheck in `apps/web` with `bunx tsc --noEmit -p tsconfig.json`.
- Passes log through the unified logger, `log.pass(id, name, count, unit?, detail?)`, `log.skip` and
  `log.note`. Never use `log.push` or `console.*`. Message text is lowercase.
- A new pass needs four things: an entry in `PASS_FN_MAP`, a position in `PASS_ORDER`, membership in
  `DEFAULT_ENABLED_PASSES`, and a line in `pass-catalog.ts`. Also update the hard-coded count in
  `__tests__/pass-catalog.test.ts`, currently 13.
- Document each pass in the header comment at the top of `deobfuscator.ts`.
- Soundness is a stated value here. Every rewrite says in a comment why it cannot change behaviour,
  and tests compare execution of the original and recovered code in a VM.
- VM evaluation is only for small closed slices with a timeout and a safe-globals allowlist. Do not
  raise the Stage C size limit to execute whole inputs.

## Useful commands

```sh
# run the CLI with a streamed pass log
bun ./deobfuscate-js -f input.js -o out.js -v

# engine tests
bun run test:engine
```

## State after 2026-10-08 (fixture-driven session)

- Fixtures: `engine/__tests__/obfuscated/jsconfuser-*.json` (21 configs), generator
  `regenerate-jsconfuser-fixtures.cjs <js-confuser-2.1.3 dir>`; cases js-confuser miscompiles are
  listed under `skipped`. The medium/high presets are too large to check in; generate ad hoc.
- New passes: noopCalls (B09b), flatFunctions (B09c), maskedVariables (B00d), dispatchers (B09d),
  concealedStrings (B05d), movedDeclarations (B00e), concealedGlobals (B01e). B11 folds
  `"k" in dummyFn`; B07d/B17 accept top-level `const` tables; B13 now keeps loop-body declarations
  (it used to drop them — a soundness fix).
- Clean on the single-option fixtures: rename, string-encoding, string-splitting, calculator, pack,
  moved-declarations, ast-scrambler, opaque-predicates, dispatcher, duplicate-literals; 28/29 for
  string-concealing, dead-code, global-concealing; 27/28 flatten; 26/28 variable-masking.
  Combinations: strings 28/29, structure 21/28, low preset 17/27.
- Open: controlFlowFlattening (state array, `sum(states)` discriminant, affine updates, xor strings
  keyed by states, scope object), rgf (`eval("function E(){…}E;")` behind an integrity flag — design:
  parse payloads, inline the embedded function into each `RGF[i].apply(this,[RGF,arguments])`
  wrapper, then re-check `hasDynamicScope` per sweep in the orchestrator so the shape passes come
  back once the eval is gone), and B00e when the original body's first statement precedes the guards.
- Still missing from this session: structural assertions in `deobfuscator.test.ts` for the new
  passes, and a README line for the js-confuser corpus.

## State after 2026-10-08 (second session: cff, medium and high presets)

- Fixtures: 21 per-option/combination configs plus `jsconfuser-medium.json` (preset `medium`,
  checked in; 10-eval, 17-class-getters and 23-tdz are js-confuser miscompiles under `skipped`).
  The `high` preset (16 MB) is generated ad hoc and scored with the scratchpad scoreboard.
- Every per-option config scores clean; `cff` is 28/28. `low` is 27/27. `medium` is 18/26 clean
  with 0 behaviour differences; the other 8 are structurally the original program and only fail the
  size-ratio heuristic because of the leftover IIFE wrapper on tiny programs.
- Medium 29-greet now recovers to the original `greet` function inside a bare IIFE.
- Main additions this session (all with soundness comments, all in `deobfuscator.ts`, `analysis.ts`,
  `cff.ts`):
  - cff (B13d): helpers may live inside the `pack` wrapper IIFE (`helperRoot`); locals that reuse a
    helper's name are renamed first (`uniquifyHelperNames`) because `pureOver` judges by spelling;
    entry states `[...POOL.slice(a, b), …]`; frames spelt `S.K.v` as well as `S["K"]["v"]`;
    member frames `S.K = {}` (block-scoped declarations); literal helper calls folded anywhere;
    surplus state arguments dropped; generalised return-flag collapse; frame lowering and flag
    collapse also run once no dispatcher loop is left. cff is now eval-gated.
  - `writeOnceFacts`: closures created before the write are fine when nothing before it can call
    out, or when every call site of the enclosing function provably runs after it (`runsAfter`,
    outermost function, self-recursion allowed, escaping functions refused); function-valued
    writes may reference themselves.
  - B05d: pools assigned after a hoisted `var`, pools inlined as literals, retrievers/decoders that
    are function-expression bindings (via write-once facts).
  - B01e: probes stored as `var X = function NAME() {…}` and in movedDeclarations form, fallback
    thunks ignored (they never run); switch tables with trailing `return;` and fall-through cases.
  - B09d: creator as an assignment, output found from the else branch, payload-less dispatchers,
    `var a; [a] = PAYLOAD;` entries, and `CACHE[name] = creator()` is now actually validated.
  - B12 `effectFree` statement removal (discarded IIFEs that only touch their own rest array, global
    data reads, literal tables); fixed `0 && x` / `1 || x` folding to booleans; `X || X` → `X`.
  - B17e drops unused trailing IIFE params with effect-free args (the pack wrapper's getter object).
  - B17f turns called-only write-once `var f = function () {}` into declarations, drops
    `var p;` redeclaring a simple parameter, and no longer treats the owner function as a nested one.
  - B07d folds tables written by one assignment; B11's `"k" in dummy` accepts any body and
    var-held dummies; B17c keeps Annex B block functions; B09 removes a proxy only once unreferenced.
- Next: the `high` preset (and then helloworld.js itself, statically). High case 11 already
  recovers fully in ~7 s.

## State after 2026-10-08 (third session: helloworld.js and the locks)

- **`~/marsbahis/helloworld.js` now deobfuscates completely** (960 KB → ~150 bytes, ~90 s) to the
  editor's `greet('Internet User')` program. Run only the CLI on it, never the file itself.
- The `Leave the protection-style options out of scope` note above no longer holds for js-confuser's
  self-text protections: a recovered program *must* settle them, because every rewrite changes the
  text they test. New pass **B20 `locks`** does so, each only where the original proves the answer:
  - integrity: removed when cyrb53 of the protected function's *original* text (stripped of
    js-confuser's sensitivity characters) equals the lock's constant;
  - anti-beautify `new RegExp("\n").test(fn)` → `false` when no original function text had a newline;
  - native-function check `N(o, k)(…)` → `o[k](…)` (assumes genuine host built-ins, as the engine
    does everywhere it evaluates code);
  - strict-mode probe `delete arr.length` → `false` in sloppy code;
  - the `L() { return F(...arguments) }` forwarder an unlocked lock leaves → calls of F.
- Original texts: `SourceFacts` in `analysis.ts` (input text plus every string B03c/B03d/B03e turn into
  code), set by the orchestrator before each pass. Sandboxed evaluation (B05c, B05d, cff helpers) only
  admits functions used as values when no original function text has a newline (`sandboxSafe`) —
  the sandbox's regenerated code prints differently, and newline self-checks are the one property it
  shares with a minified original.
- Soundness fixes found on the way: eval-sensitive passes are gated per pass (an eval can appear after
  B03c), B05c no longer evaluates text-dependent code for multi-line sources, B09d now validates the
  `CACHE[name] = creator()` half of its match, B12 no longer folds `0 && x` to `false`.
- New fixture `jsconfuser-locks.json` (low preset + integrity/selfDefending/tamperProtection): 27 cases,
  all behaviour-preserving. Suite: 957 tests.


## Release gate (2026-10-09)

`engine/__tests__/gates.test.ts` + `engine/__tests__/gates/jsconfuser-editor-max.js` (the js-confuser
editor demo at max settings, i.e. `~/marsbahis/helloworld.js`). It must recover, automatically, to the
original `greet` program: same output (`Hello Internet User!`), the `"Hello " + name + "!"` function,
under 300 bytes, no eval/Function/RegExp/`while (true)` machinery left. Runs in `bun run test:engine`
and on its own via `bun run test:gates` (~90 s; the CLI runs in a child process). Never weaken it.
The VM gives `console.log` as a *bound* function so js-confuser's native-function lock accepts it.

Resolved the same day: a freshly generated sample (high preset + pack + every lock) recovers to the
greet program too (2.2 MB → 145 bytes). What blocked it: the cff state walk forks on a real
predicate (the tamper check), and the fork the original never takes lands in a countermeasure
`while (true) {}` case, falling through into updates for which no label exists — the walk gave
up on the whole loop. `cff.ts` now models both an empty infinite loop and "no label matches" as a
path that never completes (`spinNode`), which is exactly what the original does there; later
passes settle the predicate and drop the dead branch. Also: B00d accepts `S.length = n` behind
hoisted declarations, and the orchestrator keeps sweeping (up to 48) while the source still shrinks.
Every remaining js-confuser option was tried on greet (antiDebug, date/domain locks,
hexadecimalNumbers+minify, renameLabels, the identifierGenerator variants, preserveFunctionLength,
customStringEncodings): all recover; date/domain locks stay, as they must (environment-dependent).

## 2026-10-09: towards every program at max settings

A scratchpad corpus of all 29 semantics fixtures at max settings (high preset + pack + integrity +
selfDefending + tamperProtection; 26 valid cases, 1–2 MB each) drove the rest of the work. The
scoreboard VM for it hands the program a *bound* `console.log` and a 20 s budget — the tamper lock
hangs on a hooked `console.log`, original and recovery alike.

Engine fixes, all with tests:
- cff: `while (true) {}` cases and "no label matches" are path-ending spin nodes (dead forks of the
  tamper-check predicate used to abort the whole loop).
- B05d loose mode: fixed table reads inside eval arguments are accepted and folded with the
  retriever calls, so B03d then sees one literal.
- `knownArity` (shared by B00e/B00d): a function's arity is bounded by its call sites also when it is
  a property of an object literal used only through `T[k](…)` / `.apply(this)` / `.call(this, …)`.
- B00d: `S.length = n` may follow hoisted declarations; called slots may be fed by destructuring
  (variableMasking spelt the source's `x(y)` as `S[i](y)`, already changing `this` — restoring
  `x(y)` is the source) or by elements of a never-mutated local array of `this`-free functions.
- B17f declares called-only function variables also when a use is `new f(…)`.
- B12 unwraps bare blocks that scope nothing.
- B18 **soundness bug fixed**: a duplicate `var x = v` whose declaration ended up empty had its
  assignment removed instead of the empty declaration (`var ;`, value lost).
- Orchestrator: sweeps continue while the source shrinks (hard cap 48); Babel's traversal cache is
  cleared before every pass; a sweep whose regenerated text does not parse is reported in `errors`
  and the previous sweep's output kept (it used to carry on with an empty program and emit a blank
  file); an unsettled newline self-test keeps the final output compact; an unsettled integrity lock
  is reported in `errors`.

State: high preset 02/04/05/12/15/19/22/24 recover fully; the max corpus score is being measured
(scratchpad `score_max.txt`). Every js-confuser option has been tried on greet and recovers; date and
domain locks stay, as they must.

Later on 2026-10-09 (max corpus, second round):
- The max corpus initially scored 3/26 with 23 *behaviour differences*. Two causes: (1) cff's
  calling-convention collapse dropped a thunk's rest parameter although the inner body reached it
  by closure (ReferenceError) — fixed, `thunk array used beyond forwarding`; (2) retrievers that
  js-confuser also flattened/masked, with `length`/`slice` spelt as literals-table entries, never
  matched B05d's template shape, so the eval gate never lifted and the hidden locks fired.
- B05d now also takes *general* candidates: any closed function with two plain parameters or one
  rest parameter, called somewhere with two resolvable arguments, whose dependency closure reads a
  fixed string. Closedness classifies member calls on outer bindings by their resolved method name
  (`hardMutates`: literals-table keys resolved, mutating names from MUTATING_METHOD_NAMES, an
  unresolved key counts as a mutation). A first version treated every method outside a short
  read-only list as a mutation and silently broke the editor-sample gate (`charCodeAt` on the xor
  pool) — the gate caught it within the hour. Keep running `bun run test:gates` after B05d changes.
- Unresolved computed-source evals are reported in `metadata.unresolvedEvals` and the log, not in
  `errors` (several fixtures leave an eval on purpose).

## 2026-10-09, third round: the max corpus is 26/26

Final score (scratchpad `scoreboard3.ts max max`, every case run alone on the final engine):
**26/26 behaviour-preserving, 0 pass errors, 23/26 under the size heuristic**; 05/09/14/26 are
structurally the original program (only the IIFE wrapper and `globalThis.` prefixes inflate the
ratio). Pure calls with literal arguments get constant-folded (21-bitwise ends as
`console.log(1335831723, …)`), which is sound. Gate green, 973/973 tests green.

The three universality bugs the corpus exposed — none of them visible on a single example:
- **B11 refused every `"rnd" in dummy` probe whenever the program wrote any shared prototype.**
  js-confuser's `deadCode` injects real-looking templates (SHA-256, a utf8 codec, a linked list
  doing `X.prototype.get = …`) as `if ("rnd" in dummy) { template() }`, so with dead code on the
  blanket guard fired in every file and the global-object probe (`const s = this; return !("k" in
  dummy) ? s : "junk"`) never became `globalThis`, which left every `new G.RegExp("\n")` newline
  test unsettled (max 15: 1 MB → 400 KB). The guard is now key-aware: a prototype write with a
  static key only blocks probes of that key; a computed key, `__proto__`, replacing a prototype or
  passing one to a call still blocks everything.
- **cff `lowerFrames` was all-or-nothing for the whole file.** A dead-code template's own cff
  dispatcher aborted ("node emitted twice"), its calls stayed, the frames they inherit "escaped",
  and `lowerFrames` returned 0 for every frame in the program (max 21: 1 MB → 600 KB, the global
  lookup function stayed masked). Lowering is now per key: a key whose object escapes, is deleted,
  owned twice, used before creation, or is also created by a literal outside the frame set stays
  an object (its frame parameter and creation stay, the kept literal sheds the lowered keys), while
  every other key becomes variables. `kept:` reasons now name the frame key.
- **B17c's Annex B guard was name-based.** A block-level template function `function late(){…}`
  was kept because a nested payload function declared `let late` — the guard counted any spelling
  of the name in the enclosing function. It is now binding-aware: a spelling counts when it resolves
  to nothing, to a binding outside the function, to the function's own var/function-level binding,
  or to another block function of that function; a parameter/let/const of the function or any
  binding in a nested scope is not a use (max 23: dispatcher kept → the original program).

Operational lesson: four engine processes at once (two scorers, the suite, a case) got the
background jobs killed for memory on the 16 GB machine. Run one or two heavy jobs at a time, in the
foreground, and chunk the suite with `-t` filters (`"^(?!obfuscated corpus)"`, `"obfuscated corpus
jsconfuser-medium"`, `"obfuscated corpus jsconfuser-(cff|strings|low)\.json"`,
`"obfuscated corpus jsconfuser-(?!(medium|locks|cff|strings|low)\.json)"`, `"obfuscated corpus
(?!jsconfuser-)"`); each chunk stays under ten minutes.

Second gate: `engine/__tests__/gates/jsconfuser-max-bitwise.js` (fixture 21-bitwise at the same max
settings, 1.9 MB) is now part of `bun run test:gates` (two tests, ~3 min). It is the case that needs
all three fixes above; a whole-file refusal creeping back into B11, B17c or cff fails it.

Open items: nothing known to fail. The `high` and `max` corpora should still be re-scored after any
change to B11, B17c or cff.ts (the gate covers one program, the corpus covers 26).

