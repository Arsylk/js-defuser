import { expect, it } from 'vitest';
import { DEFAULT_ENABLED_PASSES } from '../src/deobfuscator.js';
import { PASS_CATALOG, STRUCTURAL_PASSES, withStructuralPasses } from '../src/pass-catalog.js';

it('flags every catalogued pass exactly as the default run treats it', () => {
  const names = PASS_CATALOG.map((p) => p.name);
  expect(new Set(names).size).toBe(names.length);
  const defaults: readonly string[] = DEFAULT_ENABLED_PASSES;
  for (const pass of PASS_CATALOG) expect([pass.name, pass.enabled_by_default]).toEqual([pass.name, defaults.includes(pass.name)]);
  const orders = PASS_CATALOG.map((p) => p.pass_order);
  expect([...orders].sort((a, b) => a - b)).toEqual(orders);
});

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
