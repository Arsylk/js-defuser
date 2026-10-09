// Optional fixture generator; runtime tests use only the checked-in JSON.
const fs = require('node:fs');
const path = require('node:path');
const moduleDirectory = process.argv[2];
if (!moduleDirectory) throw new Error('Supply the installed javascript-obfuscator package directory.');
const directory = path.resolve(moduleDirectory);
const version = require(path.join(directory, 'package.json')).version;
if (version !== '4.2.2') throw new Error(`Expected javascript-obfuscator 4.2.2; found ${version}.`);
const obfuscator = require(directory);
const sourceDirectory = path.join(__dirname, 'fixtures');
const outputDirectory = path.join(__dirname, 'obfuscated');
for (const file of fs.readdirSync(outputDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const target = path.join(outputDirectory, file);
  const { options } = JSON.parse(fs.readFileSync(target, 'utf8'));
  const cases = fs.readdirSync(sourceDirectory).filter((name) => name.endsWith('.js')).sort().map((name) => ({
    name,
    code: obfuscator.obfuscate(fs.readFileSync(path.join(sourceDirectory, name), 'utf8'), options).getObfuscatedCode(),
  }));
  fs.writeFileSync(target, JSON.stringify({ generator: version, options, cases }, null, 2) + '\n');
  console.log(`${file}: ${cases.length} cases`);
}
