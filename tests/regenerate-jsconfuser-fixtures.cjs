// Optional fixture generator for the js-confuser corpus; runtime tests use only the checked-in JSON.
// Each configuration enables one js-confuser transform (or one small combination) so that a failing
// case points at a single transform. The `locks` configuration adds the self-text protections
// (integrity, selfDefending, tamperProtection) that B20 settles from the original source. A case whose obfuscated form no longer behaves like the original (js-confuser 2.1.3 breaks
// a few of the semantics fixtures) is listed under `skipped` instead of `cases`.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const moduleDirectory = process.argv[2];
if (!moduleDirectory) throw new Error('Supply the installed js-confuser package directory.');
const directory = path.resolve(moduleDirectory);
const version = require(path.join(directory, 'package.json')).version;
if (version !== '2.1.3') throw new Error(`Expected js-confuser 2.1.3; found ${version}.`);
const { obfuscate } = require(directory);
const only = process.argv.slice(3);
const sourceDirectory = path.join(__dirname, 'fixtures');
const outputDirectory = path.join(__dirname, 'obfuscated');

const base = { target: 'node', compact: true };
/** file stem → js-confuser options; every file is `jsconfuser-<stem>.json`. */
const configurations = {
  rename: { renameVariables: true, renameGlobals: true, identifierGenerator: 'mangled' },
  'string-concealing': { stringConcealing: true },
  'string-encoding': { stringEncoding: true },
  'string-splitting': { stringSplitting: true },
  'duplicate-literals': { duplicateLiteralsRemoval: true },
  'moved-declarations': { movedDeclarations: true },
  calculator: { calculator: true },
  'object-extraction': { objectExtraction: true },
  flatten: { flatten: true },
  dispatcher: { dispatcher: true },
  'opaque-predicates': { opaquePredicates: true },
  'dead-code': { deadCode: true },
  'global-concealing': { globalConcealing: true },
  cff: { controlFlowFlattening: true },
  'variable-masking': { variableMasking: true },
  'ast-scrambler': { astScrambler: true },
  pack: { pack: true },
  rgf: { rgf: true },
  // Small combinations: the strings layer, the structure layer, then the smallest preset.
  // (The high preset produces a ~16 MB fixture; generate it ad hoc. medium is checked in.)
  strings: { stringConcealing: true, stringEncoding: true, stringSplitting: true, duplicateLiteralsRemoval: true },
  structure: { dispatcher: true, flatten: true, objectExtraction: true, movedDeclarations: true, calculator: true },
  low: { preset: 'low' },
  // every transform at once
  medium: { preset: 'medium' },
  // the protections that test the program's own source text (B20), on the low preset
  locks: { preset: 'low', lock: { selfDefending: true, integrity: true, tamperProtection: true } },
};

// Same observation as the test harness: console output, plus a drained microtask queue.
async function execute(code) {
  const events = [];
  const context = vm.createContext({ console: { log: (...args) => events.push(args.map(String).join(' ')) } });
  try {
    new vm.Script(code).runInContext(context, { timeout: 1000 });
  } catch (error) {
    events.push(`THREW ${error.name}`);
  }
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
  return events;
}

async function main() {
  const names = fs.readdirSync(sourceDirectory).filter((name) => name.endsWith('.js')).sort();
  for (const [stem, extra] of Object.entries(configurations)) {
    if (only.length && !only.includes(stem)) continue;
    const options = { ...base, ...extra };
    const cases = [];
    const skipped = [];
    for (const name of names) {
      const source = fs.readFileSync(path.join(sourceDirectory, name), 'utf8');
      const expected = JSON.stringify(await execute(source));
      let code = null;
      // The output is randomised; a transform that only sometimes breaks a program gets a few tries.
      for (let attempt = 0; attempt < 3 && code === null; attempt++) {
        const candidate = (await obfuscate(source, { ...options })).code;
        if (JSON.stringify(await execute(candidate)) === expected) code = candidate;
      }
      if (code === null) skipped.push({ name, reason: 'js-confuser output does not behave like the original' });
      else cases.push({ name, code });
    }
    const target = path.join(outputDirectory, `jsconfuser-${stem}.json`);
    fs.writeFileSync(
      target,
      JSON.stringify({ generator: `js-confuser ${version}`, options, cases, skipped }, null, 2) + '\n'
    );
    console.log(`jsconfuser-${stem}.json: ${cases.length} cases, ${skipped.length} skipped`);
  }
}
main().catch((error) => {
  console.error(error);
  process.exit(1);
});
