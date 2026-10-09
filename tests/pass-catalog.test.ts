import { expect, it } from 'vitest';
import { DEFAULT_ENABLED_PASSES } from '../src/deobfuscator.js';
import { STRUCTURAL_PASSES, withStructuralPasses } from '../src/pass-catalog.js';

it('exposes every structural primitive with the engine default', () => {
  expect(STRUCTURAL_PASSES).toHaveLength(27);
  for (const pass of STRUCTURAL_PASSES) {
    expect(DEFAULT_ENABLED_PASSES).toContain(pass.name);
    expect(pass.enabled_by_default).toBe(true);
  }
});

it('adds new passes without duplicating or changing saved settings', () => {
  const saved = { name: 'objectTables', enabled_by_default: false, id: 42 };
  const passes = withStructuralPasses([saved]);
  expect(passes).toHaveLength(27);
  expect(passes[0]).toBe(saved);
  expect(new Set(passes.map((pass) => pass.name)).size).toBe(passes.length);
});
