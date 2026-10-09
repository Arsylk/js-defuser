// Release gates: whole-program recoveries the engine must never lose.
//
// gates/jsconfuser-editor-max.js is js-confuser 2.1.3's own editor demo
// (https://js-confuser.com/editor, default example `greet('Internet User')`)
// obfuscated at its maximum settings: every transform (cff, dispatcher, flatten,
// string concealing, globals, masking, RGF, pack, …) plus the self-text locks
// (integrity, selfDefending, tamperProtection). The engine recovers it, fully
// automatically, to the original program. Any change that breaks that fails here.
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import vm from 'node:vm';
import { expect, it } from 'vitest';

// The full pipeline takes minutes on this input; run it through the built CLI
// (`npm run build` first — `npm run test:gates` does) in a child process so
// the test worker stays responsive meanwhile. That also exercises the
// published entry point exactly as a user would.
const cli = new URL('../dist/cli.js', import.meta.url).pathname;
async function recover(file: string): Promise<string> {
  const out = join(mkdtempSync(join(tmpdir(), 'js-defuser-gate-')), 'out.js');
  await promisify(execFile)(process.execPath, [cli, '-f', file, '-o', out], { maxBuffer: 64 * 1024 * 1024, timeout: 840_000 });
  return readFileSync(out, 'utf8');
}

/**
 * Console output of `code`. The log function is a bound one so it prints as
 * `[native code]`, like a real host's: js-confuser's tamper protection hangs on
 * a hooked console.log, original and recovery alike.
 */
function execute(code: string): string[] {
  const events: string[] = [];
  const log = ((...args: unknown[]) => {
    events.push(args.map(String).join(' '));
  }).bind(null);
  const context = vm.createContext({ console: { log } });
  try {
    new vm.Script(code).runInContext(context, { timeout: 20_000 });
  } catch (error) {
    events.push(`THREW ${(error as Error).name}`);
  }
  return events;
}

it('recovers js-confuser max settings on its editor example back to the source', async () => {
  const file = new URL('./gates/jsconfuser-editor-max.js', import.meta.url).pathname;
  expect(execute(readFileSync(file, 'utf8'))).toEqual(['Hello Internet User!']);

  const out = await recover(file);
  expect(execute(out)).toEqual(['Hello Internet User!']);

  // The original program, give or take names:
  //   function greet(name) { var output = 'Hello ' + name + '!'; console.log(output); }
  //   greet('Internet User');
  expect(out).toMatch(/function (\w+)\((\w+)\) \{\s*var (\w+) = "Hello " \+ \2 \+ "!";\s*(globalThis\.)?console\.log\(\3\);\s*\}/);
  expect(out).toMatch(/\w+\("Internet User"\);/);
  expect(out.length).toBeLessThan(300);
  // no machinery left
  expect(out).not.toMatch(/\beval\b|\bFunction\(|while \(true\)|RegExp|native code|switch \(/);
}, 900_000);

// gates/jsconfuser-max-bitwise.js is the semantics fixture 21-bitwise.js (two
// pure top-level functions and one console.log) at the same maximum settings,
// generated locally from js-confuser 2.1.3. Its dead-code templates carry a
// cff dispatcher the engine cannot expand and prototype writes on nameless
// objects: it is the case that needs frame lowering to work per key, the
// function-probe guard to be key-aware and the Annex B guard to be
// binding-aware. Any whole-file refusal creeping back into those fails here.
it('recovers a max-settings program whose dead-code templates resist analysis', async () => {
  const file = new URL('./gates/jsconfuser-max-bitwise.js', import.meta.url).pathname;
  const expected = ['1335831723 3336926330 255 15 3'];
  expect(execute(readFileSync(file, 'utf8'))).toEqual(expected);

  const out = await recover(file);
  expect(execute(out)).toEqual(expected);

  // The whole program folds to its one console.log (the functions are pure
  // and called with literals); nothing of the obfuscation survives.
  expect(out).toMatch(/console\.log\(1335831723, 3336926330, 255, 15, 3\);/);
  expect(out.length).toBeLessThan(200);
  expect(out).not.toMatch(/\beval\b|\bFunction\(|while \(true\)|RegExp|native code|switch \(|prototype/);
}, 900_000);
