/**
 * js-defuser — sound, fully automatic JavaScript deobfuscation.
 *
 *   import { deobfuscate, DEFAULT_ENABLED_PASSES } from 'js-defuser';
 *   const result = await deobfuscate(code, { enabledPasses: [...DEFAULT_ENABLED_PASSES], lenientMode: false, autoFix: true });
 *   console.log(result.deobfuscatedCode);
 */
export { deobfuscate, DEFAULT_ENABLED_PASSES } from './deobfuscator.js';
export type { DeobfuscationOptions, DeobfuscationResult, ParseError, JsNiceOptions } from './deobfuscator.js';
export { STRUCTURAL_PASSES, withStructuralPasses } from './pass-catalog.js';
export { applyJsNice } from './jsnice.js';
export type { JsNiceResult } from './jsnice.js';
export { ansi, createConsoleLogger, createLogger, kebab, mocha, parse, plain, segments, supportsColor, tones } from './logger.js';
export type { Entry, Logger } from './logger.js';
