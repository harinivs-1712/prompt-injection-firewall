/**
 * ActionBadge – renders firewall action with symbol + text.
 * Always shows both so it doesn't rely on colour alone (accessibility).
 */
interface ActionBadgeProps {
  action: string | null | undefined;
  className?: string;
}

type BadgeVariant = 'allow' | 'block' | 'ask' | 'denied' | 'hold' | 'pass' | 'mask' | 'unknown';

const BADGE_MAP: Record<string, { symbol: string; label: string; variant: BadgeVariant }> = {
  allow: { symbol: '✓', label: 'ALLOW', variant: 'allow' },
  ALLOW: { symbol: '✓', label: 'ALLOW', variant: 'allow' },
  block: { symbol: '✕', label: 'BLOCK', variant: 'block' },
  BLOCK: { symbol: '✕', label: 'BLOCK', variant: 'block' },
  ask: { symbol: '?', label: 'ASK', variant: 'ask' },
  ASK: { symbol: '?', label: 'ASK', variant: 'ask' },
  denied: { symbol: '⊘', label: 'DENIED', variant: 'denied' },
  DENIED: { symbol: '⊘', label: 'DENIED', variant: 'denied' },
  hold: { symbol: '⏸', label: 'HOLD', variant: 'hold' },
  HOLD: { symbol: '⏸', label: 'HOLD', variant: 'hold' },
  pass: { symbol: '↗', label: 'PASS', variant: 'pass' },
  PASS: { symbol: '↗', label: 'PASS', variant: 'pass' },
  mask: { symbol: '▓', label: 'MASK', variant: 'mask' },
  MASK: { symbol: '▓', label: 'MASK', variant: 'mask' },
};

export function ActionBadge({ action, className }: ActionBadgeProps) {
  if (!action) {
    return null;
  }

  const entry = BADGE_MAP[action] ?? { symbol: '·', label: action.toUpperCase(), variant: 'unknown' as BadgeVariant };

  return (
    <span
      className={`action-badge action-badge--${entry.variant} ${className ?? ''}`}
      aria-label={`Action: ${entry.label}`}
      title={`Action: ${entry.label}`}
    >
      <span className="action-badge__symbol" aria-hidden="true">{entry.symbol}</span>
      <span className="action-badge__label">{entry.label}</span>
    </span>
  );
}
