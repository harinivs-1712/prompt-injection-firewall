import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'fs';
import { resolve, join, extname } from 'path';

const SRC_DIR = resolve(__dirname, '..');

function getAllSourceFiles(dir: string, skip: string[] = []): string[] {
  const results: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (skip.includes(name)) continue;
      results.push(...getAllSourceFiles(full, skip));
    } else if (['.ts', '.tsx'].includes(extname(name))) {
      results.push(full);
    }
  }
  return results;
}

function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');
}

// Source files only (not tests themselves)
const SOURCE_FILES = getAllSourceFiles(SRC_DIR, ['__tests__', 'node_modules']);

describe('Source code security audit', () => {
  it('no dangerouslySetInnerHTML in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (src.includes('dangerouslySetInnerHTML')) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found dangerouslySetInnerHTML in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no direct .innerHTML assignment in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/\.innerHTML\s*=/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found innerHTML= in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no eval() calls in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      // Matches eval( but not "evaluate(" or "unevaluated"
      if (/(?<![A-Za-z])eval\s*\(/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found eval() in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no localStorage usage in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/\blocalStorage\b/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found localStorage in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no sessionStorage usage in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/\bsessionStorage\b/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found sessionStorage in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('fetch() only used in api/client.ts', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      if (file.endsWith('client.ts')) continue;
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/(?<![A-Za-z])fetch\s*\(/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found fetch() outside client.ts in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no document.write() in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/document\.write\s*\(/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found document.write() in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no new Function() in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/new\s+Function\s*\(/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found new Function() in: ${violations.join(', ')}`).toHaveLength(0);
  });

  it('no outerHTML= assignment in source files', () => {
    const violations: string[] = [];
    for (const file of SOURCE_FILES) {
      const src = stripComments(readFileSync(file, 'utf-8'));
      if (/\.outerHTML\s*=/.test(src)) {
        violations.push(file.replace(SRC_DIR, ''));
      }
    }
    expect(violations, `Found outerHTML= in: ${violations.join(', ')}`).toHaveLength(0);
  });
});
