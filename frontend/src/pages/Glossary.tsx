import { useMemo, useState } from 'react';
import { REASON_CODE_METADATA, REASON_CODE_CATEGORIES, getReasonCodeMeta } from '../data/reasonCodeDescriptions';
import reasonCodes from '../data/reason_codes.generated.json';
import { ActionBadge } from '../components/ActionBadge';

const ACTION_LABEL_MAP: Record<string, string> = {
  ALLOW: 'allow',
  ASK: 'ask',
  BLOCK: 'block',
  MIXED: 'block',
};

export function Glossary() {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  const allCodes: string[] = useMemo(() => {
    // Ensure generated codes list is exhaustive
    const known = new Set(reasonCodes as string[]);
    const fromMetadata = new Set(Object.keys(REASON_CODE_METADATA));
    const union = new Set([...known, ...fromMetadata]);
    return [...union].sort();
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return allCodes
      .map((code) => getReasonCodeMeta(code))
      .filter((meta) => {
        const matchesSearch = !q ||
          meta.code.toLowerCase().includes(q) ||
          meta.plainDescription.toLowerCase().includes(q) ||
          meta.category.toLowerCase().includes(q);
        const matchesCategory = !categoryFilter || meta.category === categoryFilter;
        return matchesSearch && matchesCategory;
      });
  }, [allCodes, search, categoryFilter]);

  return (
    <main className="glossary-page" aria-labelledby="glossary-heading">
      <h1 id="glossary-heading">Reason Code Glossary</h1>
      <p className="glossary-page__count">{allCodes.length} codes defined</p>

      <div className="glossary-controls" role="search" aria-label="Filter reason codes">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search codes or descriptions…"
          aria-label="Search reason codes"
          className="glossary-controls__search"
        />
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          aria-label="Filter by category"
          className="glossary-controls__category"
        >
          <option value="">All categories</option>
          {REASON_CODE_CATEGORIES.map((cat) => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
        </select>
      </div>

      {filtered.length === 0 && (
        <p className="empty-state">No matching reason codes.</p>
      )}

      <dl className="glossary-list">
        {filtered.map((meta) => (
          <div key={meta.code} className="glossary-item" id={`code-${meta.code}`}>
            <dt className="glossary-item__term">
              <code className="glossary-item__code">{meta.code}</code>
              <span className="glossary-item__category">{meta.category}</span>
              <ActionBadge action={ACTION_LABEL_MAP[meta.typicalAction] ?? meta.typicalAction.toLowerCase()} className="glossary-item__action" />
            </dt>
            <dd className="glossary-item__desc">{meta.plainDescription}</dd>
          </div>
        ))}
      </dl>
    </main>
  );
}
