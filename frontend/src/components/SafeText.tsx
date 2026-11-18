/**
 * SafeText – renders any string from the API as plain text only.
 * Strips/replaces hostile Unicode: control chars, bidi overrides, zero-width chars.
 */
import { useState } from 'react';

const TRUNCATE_AT = 500;

// Ranges to replace with markers:
// C0/C1 control chars (except \n \t), bidi overrides/isolates, zero-width chars, BOM
const HOSTILE_CHAR_RE =
  /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/gu;

function sanitize(raw: string): string {
  return raw.replace(HOSTILE_CHAR_RE, (ch) => {
    const cp = ch.codePointAt(0)!;
    return `\u27E6U+${cp.toString(16).toUpperCase().padStart(4, '0')}\u27E7`;
  });
}

interface SafeTextProps {
  value: unknown;
  truncate?: boolean;
  className?: string;
}

export function SafeText({ value, truncate = true, className }: SafeTextProps) {
  const [expanded, setExpanded] = useState(false);

  if (value === null || value === undefined) {
    return <span className={`safe-text safe-text--null ${className ?? ''}`}>—</span>;
  }

  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  const sanitized = sanitize(raw);

  const shouldTruncate = truncate && sanitized.length > TRUNCATE_AT && !expanded;
  const display = shouldTruncate ? sanitized.slice(0, TRUNCATE_AT) + '…' : sanitized;

  return (
    <span
      className={`safe-text ${className ?? ''}`}
      style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', unicodeBidi: 'isolate' }}
    >
      {display}
      {shouldTruncate && (
        <button
          className="safe-text__show-more"
          onClick={() => setExpanded(true)}
          aria-label="Show full text"
        >
          {' '}show more
        </button>
      )}
    </span>
  );
}
