import { useMemo, useState } from 'react';
import {
  REASON_CODE_METADATA,
  REASON_CODE_CATEGORIES,
  getReasonCodeMeta,
} from '../data/reasonCodeDescriptions';
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
        const matchesSearch =
          !q ||
          meta.code.toLowerCase().includes(q) ||
          meta.plainDescription.toLowerCase().includes(q) ||
          meta.category.toLowerCase().includes(q);
        const matchesCategory = !categoryFilter || meta.category === categoryFilter;
        return matchesSearch && matchesCategory;
      });
  }, [allCodes, search, categoryFilter]);

  return (
    <main className="glossary-page" aria-labelledby="glossary-heading">
      <div className="page-header">
        <div>
          <h1 id="glossary-heading" className="page-title">
            Reason Code Glossary
          </h1>
          <p className="page-subtitle">
            Comprehensive reference of all 49 firewall decision codes and mitigation semantics
          </p>
        </div>
        <div className="page-header__badge">
          <span>{filtered.length} of {allCodes.length} codes</span>
        </div>
      </div>

      <div className="glossary-controls" role="search" aria-label="Filter reason codes">
        <div className="glossary-search-wrap">
          <span className="search-icon" aria-hidden="true">🔎</span>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search code name, category, or description…"
            aria-label="Search reason codes"
            className="glossary-controls__search"
          />
        </div>

        <div className="glossary-category-wrap">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            aria-label="Filter by category"
            className="glossary-controls__category"
          >
            <option value="">All Categories ({REASON_CODE_CATEGORIES.length})</option>
            {REASON_CODE_CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state-box">
          <span className="empty-icon" aria-hidden="true">🔍</span>
          <p className="empty-state">No matching reason codes found for "{search}".</p>
        </div>
      ) : (
        <div className="glossary-grid" role="list">
          {filtered.map((meta) => (
            <article
              key={meta.code}
              className={`glossary-card glossary-card--${meta.typicalAction.toLowerCase()}`}
              id={`code-${meta.code}`}
              role="listitem"
            >
              <div className="glossary-card__header">
                <code className="glossary-card__code">{meta.code}</code>
                <ActionBadge
                  action={
                    ACTION_LABEL_MAP[meta.typicalAction] ?? meta.typicalAction.toLowerCase()
                  }
                  className="glossary-card__action"
                />
              </div>
              <div className="glossary-card__category-wrap">
                <span className="glossary-card__category">{meta.category}</span>
              </div>
              <p className="glossary-card__desc">{meta.plainDescription}</p>
            </article>
          ))}
        </div>
      )}
    </main>
  );
}
