/**
 * js-defuser for browsers: the same engine, with its sandboxed evaluations
 * running on QuickJS compiled to WebAssembly instead of `node:vm`.
 *
 *   import { deobfuscate, DEFAULT_ENABLED_PASSES } from 'js-defuser/browser';
 *   const result = await deobfuscate(code, { enabledPasses: [...DEFAULT_ENABLED_PASSES], lenientMode: false, autoFix: true });
 *
 * The first call loads the WebAssembly module (about 1 MB, bundled); call
 * `prepare()` early to have it ready. Run it in a Web Worker: a large input
 * takes minutes, and the engine is synchronous while it works.
 */
import { newQuickJSWASMModuleFromVariant } from 'quickjs-emscripten-core';
import variant from '@jitl/quickjs-singlefile-browser-release-sync';
import { setSandboxFactory } from './sandbox.js';
import { createQuickJSSandboxFactory } from './sandbox-quickjs.js';
import { deobfuscate as runEngine, type DeobfuscationOptions, type DeobfuscationResult } from './deobfuscator.js';

let ready: Promise<void> | null = null;

/** Load the sandbox engine once; resolves when `deobfuscate` can run without waiting. */
export function prepare(): Promise<void> {
  ready ??= newQuickJSWASMModuleFromVariant(variant).then((module) => {
    setSandboxFactory(createQuickJSSandboxFactory(module));
  });
  return ready;
}

export async function deobfuscate(code: string, options: DeobfuscationOptions): Promise<DeobfuscationResult> {
  await prepare();
  return runEngine(code, options);
}

export { DEFAULT_ENABLED_PASSES, PASS_ORDER } from './deobfuscator.js';
export type { DeobfuscationOptions, DeobfuscationResult, ParseError } from './deobfuscator.js';
export { BASE_PASSES, PASS_CATALOG, PIPELINE, STRUCTURAL_PASSES, withStructuralPasses } from './pass-catalog.js';
export type { PassInfo, PipelineStage, PipelineStep } from './pass-catalog.js';
export { ansi, createConsoleLogger, createLogger, kebab, mocha, parse, plain, segments, supportsColor, tones } from './logger.js';
export type { Entry, Logger } from './logger.js';
