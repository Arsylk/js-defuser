#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join } from 'node:path';
import { parseArgs } from 'node:util';
import './sandbox-node.js';
import { DEFAULT_ENABLED_PASSES, deobfuscate } from './deobfuscator.js';
import { ansi, createConsoleLogger, plain, supportsColor } from './logger.js';

const USAGE = `Usage: js-defuser [-f input.js] [-o output.js] [--verbose]

Input and output:
  -f, --file <path>    Read obfuscated JavaScript from a file
  -o, --output <path>  Write deobfuscated JavaScript to a file

If -f is supplied without -o, input.js becomes input.deobf.js.
Without -f, input is read from stdin and output defaults to stdout.
Use "-" as either path to explicitly select stdin or stdout.

Options:
  -v, --verbose        Stream the pass log to stderr as passes run, in colour
                       when stderr is a terminal (NO_COLOR / FORCE_COLOR apply)
      --strict-source  Analyse the text exactly as given. By default a
                       pretty-printed input is taken for the compact program
                       the obfuscator emitted, so its self-text checks
                       (anti-beautify locks, self-inspecting decoders) answer
                       as they would for that original.
      --jsnice         Post-process with JSNice (rename identifiers + infer
                       types). Sends the deobfuscated code to a third-party
                       service (jsnice.org over HTTP) — off by default.
      --jsnice-url <u> Use a custom JSNice-compatible endpoint instead of
                       jsnice.org (implies --jsnice).
      --jsnice-no-transpile
                       Skip the ES5 transpile step. By default --jsnice lowers
                       the code to ES5 (JSNice cannot parse modern syntax), so
                       its renamed output comes back as ES5 CommonJS. Use this
                       only when the input is already ES5.
      --jsnice-max-bytes <n>
                       Skip files whose input exceeds n bytes (default
                       2000000). Larger inputs still work but are slower.
      --jsnice-timeout <ms>
                       Abort a JSNice request after ms milliseconds (default
                       60000). Large, complex bundles may need more; on timeout
                       the local output is kept.
  -h, --help           Show this help`;

function defaultOutputPath(inputPath: string): string {
  const extension = extname(inputPath);
  const inputName = basename(inputPath, extension);
  return join(dirname(inputPath), `${inputName}.deobf.js`);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      file: { type: 'string', short: 'f' },
      output: { type: 'string', short: 'o' },
      verbose: { type: 'boolean', short: 'v', default: false },
      'strict-source': { type: 'boolean', default: false },
      jsnice: { type: 'boolean', default: false },
      'jsnice-url': { type: 'string' },
      'jsnice-no-transpile': { type: 'boolean', default: false },
      'jsnice-max-bytes': { type: 'string' },
      'jsnice-timeout': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  });

  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  const readsStdin = values.file == null || values.file === '-';
  if (readsStdin && process.stdin.isTTY) {
    throw new Error(`No input provided.\n\n${USAGE}`);
  }

  const source = readsStdin ? await readStdin() : await readFile(values.file!, 'utf8');
  const color = supportsColor(process.stderr);
  const useJsNice = values.jsnice || values['jsnice-url'] != null;
  const result = await deobfuscate(source, {
    enabledPasses: [...DEFAULT_ENABLED_PASSES],
    lenientMode: false,
    autoFix: true,
    assumeCompactSource: !values['strict-source'],
    // Stream the pass log as it is produced instead of dumping it at the end.
    onLog: values.verbose
      ? (_line, entry) => process.stderr.write(`${color ? ansi(entry) : plain(entry)}\n`)
      : undefined,
    jsNice: useJsNice
      ? {
          enabled: true,
          url: values['jsnice-url'],
          transpile: !values['jsnice-no-transpile'],
          maxBytes: values['jsnice-max-bytes'] != null ? Number(values['jsnice-max-bytes']) : undefined,
          timeoutMs: values['jsnice-timeout'] != null ? Number(values['jsnice-timeout']) : undefined,
        }
      : undefined,
  });

  const outputPath = values.output ?? (readsStdin ? '-' : defaultOutputPath(values.file!));
  const output = result.deobfuscatedCode.endsWith('\n') ? result.deobfuscatedCode : `${result.deobfuscatedCode}\n`;

  if (outputPath === '-') {
    process.stdout.write(output);
  } else {
    await writeFile(outputPath, output, 'utf8');
  }

  if (result.errors.length > 0) {
    createConsoleLogger('js-defuser').warn(`completed with ${result.errors.length} non-fatal error(s)`);
  }
  if (!result.success) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  createConsoleLogger('js-defuser').error(message);
  process.exitCode = 2;
});
