import { expect, it } from 'vitest';
import { DEFAULT_ENABLED_PASSES, PASS_ORDER } from '../src/deobfuscator.js';
import { BASE_PASSES, PASS_CATALOG, PIPELINE, STRUCTURAL_PASSES, withStructuralPasses } from '../src/pass-catalog.js';

it('describes stage b exactly as the engine schedules it', () => {
  const b = PIPELINE.find((s) => s.id === 'b')!;
  const firstSeen: string[] = [];
  const runs = new Map<string, number>();
  for (const name of PASS_ORDER) {
    if (!runs.has(name)) firstSeen.push(name);
    runs.set(name, (runs.get(name) ?? 0) + 1);
  }
  expect(b.steps.map((s) => s.name)).toEqual(firstSeen);
  for (const s of b.steps) expect([s.name, s.runs]).toEqual([s.name, runs.get(s.name)]);
  for (const s of PIPELINE.flatMap((st) => st.steps)) {
    expect(s.description, s.name).toBeTruthy();
    if (s.stage === 'b') expect(s.logId, s.name).toMatch(/^b\d\d[a-z]?$/);
  }
});

it('flags every catalogued pass exactly as the default run treats it', () => {
  const names = PASS_CATALOG.map((p) => p.name);
  expect(new Set(names).size).toBe(names.length);
  const defaults: readonly string[] = DEFAULT_ENABLED_PASSES;
  for (const pass of PASS_CATALOG) expect([pass.name, pass.enabled_by_default]).toEqual([pass.name, defaults.includes(pass.name)]);
  const orders = PASS_CATALOG.map((p) => p.pass_order);
  expect([...orders].sort((a, b) => a - b)).toEqual(orders);
  // the older two-group view names the same passes
  const grouped = new Set([...BASE_PASSES, ...STRUCTURAL_PASSES].map((p) => p.name));
  expect([...grouped].sort()).toEqual([...names].filter((n) => n !== 'junk-token-removal').sort());
});

it('exposes every structural primitive with the engine default', () => {
  expect(STRUCTURAL_PASSES).toHaveLength(27);
  for (const pass of STRUCTURAL_PASSES) {
    expect(DEFAULT_ENABLED_PASSES).toContain(pass.name);
    expect(pass.enabled_by_default).toBe(true);
  }
});

it('adds the structural passes to a catalog that lacks them', () => {
  const passes = withStructuralPasses([{ name: 'string-escape-norm' }]);
  expect(passes).toHaveLength(28);
  expect(passes.filter((p) => p.name === 'string-escape-norm')).toHaveLength(1);
});
