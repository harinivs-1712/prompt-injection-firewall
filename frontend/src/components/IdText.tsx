/**
 * IdText – displays an ID with middle truncation, full ID in title,
 * and a quiet clipboard copy button.
 */
import React, { useState } from 'react';

interface IdTextProps {
  id: string;
  maxLen?: number;
  className?: string;
}

function middleTruncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  const half = Math.floor((maxLen - 1) / 2);
  return s.slice(0, half) + '…' + s.slice(s.length - half);
}

export function IdText({ id, maxLen = 20, className }: IdTextProps) {
  const [copied, setCopied] = useState(false);

  if (!id) {
    return <span className={`id-text ${className ?? ''}`}>—</span>;
  }

  const display = middleTruncate(id, maxLen);

  const handleCopy = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard may be unavailable in some environments
    }
  };

  return (
    <span className={`id-text ${className ?? ''}`} title={id}>
      <code className="id-text__code">{display}</code>
      <button
        className="id-text__copy"
        onClick={handleCopy}
        aria-label={`Copy full ID: ${id}`}
        title={copied ? 'Copied!' : 'Copy ID'}
      >
        {copied ? '✓' : '⎘'}
      </button>
    </span>
  );
}
