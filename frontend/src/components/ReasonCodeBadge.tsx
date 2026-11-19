/**
 * ReasonCodeBadge – renders a single reason code as a badge with tooltip.
 */
import { getReasonCodeMeta } from '../data/reasonCodeDescriptions';

interface ReasonCodeBadgeProps {
  code: string;
  className?: string;
}

export function ReasonCodeBadge({ code, className }: ReasonCodeBadgeProps) {
  const meta = getReasonCodeMeta(code);

  return (
    <span
      className={`reason-badge reason-badge--${meta.typicalAction.toLowerCase()} ${className ?? ''}`}
      title={meta.plainDescription}
      aria-label={`Reason: ${code} – ${meta.plainDescription}`}
    >
      {code}
    </span>
  );
}
