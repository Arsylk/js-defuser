// A pretty-printed copy of an obfuscated program must recover like the
// compact original: obfuscators read their own text (anti-beautify locks,
// self-inspecting decoders), and by default the engine answers those checks
// for the compact form the obfuscator emitted. `assumeCompactSource: false`
// is the literal reading, kept for analysts who want exactly what was given.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { parse } from '@babel/parser';
import { describe, expect, it } from 'vitest';
import { generate } from '../src/babel.js';
import { DEFAULT_ENABLED_PASSES, deobfuscate } from '../src/deobfuscator.js';

const obfuscated = new URL('./obfuscated/', import.meta.url);
const fixtures = new URL('./fixtures/', import.meta.url);

function caseCode(config: string, name: string): string {
  const fixture = JSON.parse(readFileSync(new URL(config, obfuscated), 'utf8')) as { cases: { name: string; code: string }[] };
  return fixture.cases.find((c) => c.name === name)!.code;
}

/** What a devtools "pretty print" does: same tokens, newlines and indentation everywhere. */
function prettyPrint(code: string): string {
  const ast = parse(code, { sourceType: 'script', errorRecovery: true, allowReturnOutsideFunction: true });
  return generate(ast, { compact: false }).code + '\n';
}

async function recover(code: string, assumeCompactSource?: boolean) {
  return deobfuscate(code, { enabledPasses: [...DEFAULT_ENABLED_PASSES], lenientMode: false, autoFix: false, assumeCompactSource });
}

async function execute(code: string): Promise<string[]> {
  const events: string[] = [];
  const context = vm.createContext({ console: { log: (...args: unknown[]) => events.push(args.map(String).join(' ')) } });
  try {
    new vm.Script(code).runInContext(context, { timeout: 3000 });
  } catch (error) {
    events.push(`THREW ${(error as Error).name}`);
  }
  for (let i = 0; i < 5; i++) await new Promise<void>((resolve) => setImmediate(resolve));
  return events;
}

describe('pretty-printed input', () => {
  const samples: Array<[string, string, string]> = [
    ['sa_rc4.json', '14-closures-counter.js', 'javascript-obfuscator rc4 string array'],
    ['jsconfuser-locks.json', '29-greet.js', 'js-confuser low + locks'],
    ['jsconfuser-strings.json', '29-greet.js', 'js-confuser string concealing'],
    ['jsconfuser-cff.json', '14-closures-counter.js', 'js-confuser control-flow flattening'],
  ];
  for (const [config, name, label] of samples) {
    it(`recovers ${label} like the compact original`, async () => {
      const compact = caseCode(config, name);
      const formatted = prettyPrint(compact);
      expect(formatted).not.toBe(compact);
      expect(formatted.split('\n').length).toBeGreaterThan(20);
      const a = await recover(compact);
      const b = await recover(formatted);
      expect(b.deobfuscatedCode).toBe(a.deobfuscatedCode);
      expect(b.errors).toEqual([]);
      expect(await execute(b.deobfuscatedCode)).toEqual(await execute(readFileSync(new URL(name, fixtures), 'utf8')));
      expect(b.log.some((l) => /pretty-printed/.test(l))).toBe(true);
      expect(a.log.some((l) => /pretty-printed/.test(l))).toBe(false);
    }, 120_000);
  }

  it('reads the text literally when asked to', async () => {
    // Formatted, js-confuser's anti-beautify test is true: the program hangs
    // by design. The literal reading keeps that test (it cannot be settled
    // from a text that has newlines), the default reading removes it.
    const formatted = prettyPrint(caseCode('jsconfuser-locks.json', '29-greet.js'));
    const literal = await recover(formatted, false);
    const assumed = await recover(formatted);
    expect(literal.deobfuscatedCode).toMatch(/RegExp|\\n/);
    expect(assumed.deobfuscatedCode).not.toMatch(/RegExp/);
    expect(assumed.deobfuscatedCode).toMatch(/"Internet User"/);
  }, 120_000);
});
