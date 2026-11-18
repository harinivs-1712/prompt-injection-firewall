import { describe, it, expect } from 'vitest';
import reasonCodes from '../data/reason_codes.generated.json';
import { REASON_CODE_METADATA, REASON_CODE_CATEGORIES, getReasonCodeMeta } from '../data/reasonCodeDescriptions';

describe('Reason code coverage', () => {
  it('every generated reason code has metadata (or logs missing ones)', () => {
    const missing = (reasonCodes as string[]).filter(
      (code) => !(code in REASON_CODE_METADATA)
    );
    if (missing.length > 0) {
      console.warn('[reasonCodeCoverage] Missing metadata for:', missing.join(', '));
    }
    // Allow at most 2 codes without metadata (future upstream additions)
    expect(missing.length).toBeLessThanOrEqual(2);
  });

  it('metadata has valid typicalAction values', () => {
    const valid = new Set(['ALLOW', 'ASK', 'BLOCK', 'MIXED']);
    for (const [code, meta] of Object.entries(REASON_CODE_METADATA)) {
      expect(valid.has(meta.typicalAction), `${code}.typicalAction='${meta.typicalAction}' is not in [ALLOW,ASK,BLOCK,MIXED]`).toBe(true);
    }
  });

  it('metadata has non-empty descriptions (>10 chars)', () => {
    for (const [code, meta] of Object.entries(REASON_CODE_METADATA)) {
      expect(meta.plainDescription.length, `${code} plainDescription is too short`).toBeGreaterThan(10);
    }
  });

  it('metadata has non-empty category', () => {
    for (const [code, meta] of Object.entries(REASON_CODE_METADATA)) {
      expect(meta.category.length, `${code} category is empty`).toBeGreaterThan(0);
    }
  });

  it('metadata categories are from the known category list', () => {
    const knownCategories = new Set([...REASON_CODE_CATEGORIES, 'Uncategorized']);
    for (const [code, meta] of Object.entries(REASON_CODE_METADATA)) {
      expect(knownCategories.has(meta.category), `${code}.category='${meta.category}' is not in REASON_CODE_CATEGORIES`).toBe(true);
    }
  });

  it('getReasonCodeMeta returns fallback for unknown code', () => {
    const meta = getReasonCodeMeta('TOTALLY_UNKNOWN_CODE_XYZ');
    expect(meta.code).toBe('TOTALLY_UNKNOWN_CODE_XYZ');
    expect(meta.category).toBe('Uncategorized');
  });

  it('metadata count is close to generated count', () => {
    const generated = (reasonCodes as string[]).length;
    const described = Object.keys(REASON_CODE_METADATA).length;
    // Allow +/- 2 discrepancy for version drift
    expect(Math.abs(generated - described)).toBeLessThanOrEqual(2);
  });
});
