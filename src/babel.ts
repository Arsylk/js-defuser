// @babel/traverse and @babel/generator are CommonJS modules whose main export
// lives on `exports.default`. Node's ESM loader hands an importer the whole
// `module.exports` object as the default import, while bundlers and bun unwrap
// it — so the engine takes both through this one shim and sees the function
// either way.
import traverseModule from '@babel/traverse';
import generateModule from '@babel/generator';

type TraverseFn = typeof import('@babel/traverse').default;
type GenerateFn = typeof import('@babel/generator').default;

const unwrap = <T>(mod: unknown): T => {
  const m = mod as { default?: T } | T;
  return (typeof m === 'object' && m !== null && 'default' in m && (m as { default?: T }).default) || (m as T);
};

export const traverse: TraverseFn = unwrap<TraverseFn>(traverseModule);
export const generate: GenerateFn = unwrap<GenerateFn>(generateModule);
