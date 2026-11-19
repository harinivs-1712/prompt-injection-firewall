import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../api/client';
import type { SummaryResponse, AuditVerifyResponse } from '../api/types';
import { SafeText } from '../components/SafeText';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';
import { ErrorBanner } from '../components/ErrorBanner';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ActionBadge } from '../components/ActionBadge';

type VerifyState = 'idle' | 'loading' | 'done';

export function Overview() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [verifyState, setVerifyState] = useState<VerifyState>('idle');
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getSummary()
      .then((data) => {
        if (!cancelled) {
          setSummary(data);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError && err.status === 401 ? 'Please sign in.' : 'Cannot reach the server.');
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, []);

  const handleVerify = useCallback(async () => {
    setVerifyState('loading');
    setVerifyError(null);
    setVerifyResult(null);
    try {
      const result = await api.verifyAudit();
      setVerifyResult(result);
      setVerifyState('done');
    } catch (err: unknown) {
      setVerifyError(err instanceof ApiError && err.status === 401 ? 'Please sign in.' : 'Cannot reach the server.');
      setVerifyState('idle');
    }
  }, []);

  if (loading) return <LoadingSpinner label="Loading overview…" />;
  if (error) return <ErrorBanner message={error} />;
  if (!summary) return null;

  return (
    <main className="overview-page" aria-labelledby="overview-heading">
      <h1 id="overview-heading">Overview</h1>

      <section className="stats-grid" aria-label="Summary statistics">
        <article className="stat-card">
          <span className="stat-card__value">{summary.sessions}</span>
          <span className="stat-card__label">Sessions</span>
        </article>
        <article className="stat-card">
          <span className="stat-card__value">{summary.events}</span>
          <span className="stat-card__label">Events</span>
        </article>
        <article className="stat-card">
          <span className="stat-card__value">{summary.held_outputs}</span>
          <span className="stat-card__label">Held Outputs</span>
        </article>
        <article className="stat-card">
          <span className="stat-card__value">{summary.halts}</span>
          <span className="stat-card__label">Session Halts</span>
        </article>
        <article className="stat-card">
          <span className="stat-card__value">{summary.rejected_audit_events}</span>
          <span className="stat-card__label">Rejected Events</span>
        </article>
      </section>

      <section className="overview-section" aria-label="Decisions by action">
        <h2>Decisions by Action</h2>
        <ul className="action-breakdown">
          {Object.entries(summary.decisions_by_action).map(([action, count]) => (
            <li key={action} className="action-breakdown__item">
              <ActionBadge action={action} />
              <span className="action-breakdown__count">{count}</span>
            </li>
          ))}
          {Object.keys(summary.decisions_by_action).length === 0 && (
            <li className="empty-state">No decisions recorded.</li>
          )}
        </ul>
      </section>

      <section className="overview-section" aria-label="Top reason codes">
        <h2>Top Reason Codes</h2>
        <ol className="reason-code-list">
          {summary.top_reason_codes.map(([code, count]) => (
            <li key={code} className="reason-code-list__item">
              <ReasonCodeBadge code={code} />
              <span className="reason-code-list__count">{count}</span>
            </li>
          ))}
          {summary.top_reason_codes.length === 0 && (
            <li className="empty-state">No reason codes recorded.</li>
          )}
        </ol>
      </section>

      <section className="overview-section" aria-label="Approval outcomes">
        <h2>Approval Outcomes</h2>
        <ul className="action-breakdown">
          {Object.entries(summary.approval_outcomes).map(([outcome, count]) => (
            <li key={outcome} className="action-breakdown__item">
              <SafeText value={outcome} truncate={false} />
              <span className="action-breakdown__count">{count}</span>
            </li>
          ))}
          {Object.keys(summary.approval_outcomes).length === 0 && (
            <li className="empty-state">No approvals recorded.</li>
          )}
        </ul>
      </section>

      <section className="overview-section overview-section--verify" aria-label="Audit chain verification">
        <h2>Audit Chain</h2>
        <button
          className="verify-btn"
          onClick={handleVerify}
          disabled={verifyState === 'loading'}
          aria-busy={verifyState === 'loading'}
        >
          {verifyState === 'loading' ? <LoadingSpinner label="Verifying…" /> : 'Verify Audit Chain'}
        </button>
        {verifyError && <ErrorBanner message={verifyError} />}
        {verifyResult && (
          <div
            className={`verify-result verify-result--${verifyResult.ok ? 'ok' : 'fail'}`}
            role="status"
          >
            <span className="verify-result__icon">{verifyResult.ok ? '✓' : '✕'}</span>
            <span className="verify-result__message"><SafeText value={verifyResult.message} /></span>
            <span className="verify-result__detail">({verifyResult.checked} rows checked)</span>
          </div>
        )}
      </section>
    </main>
  );
}
