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
          setError(
            err instanceof ApiError && err.status === 401
              ? 'Please sign in.'
              : 'Cannot reach the server.'
          );
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
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
      setVerifyError(
        err instanceof ApiError && err.status === 401
          ? 'Please sign in.'
          : 'Cannot reach the server.'
      );
      setVerifyState('idle');
    }
  }, []);

  if (loading) return <LoadingSpinner label="Loading telemetry overview…" />;
  if (error) return <ErrorBanner message={error} />;
  if (!summary) return null;

  return (
    <main className="overview-page" aria-labelledby="overview-heading">
      <div className="page-header">
        <div>
          <h1 id="overview-heading" className="page-title">
            Security Overview
          </h1>
          <p className="page-subtitle">
            Real-time prompt-injection telemetry and policy enforcement metrics
          </p>
        </div>
        <div className="page-header__badge">
          <span className="live-dot" aria-hidden="true" />
          <span>TELEMETRY ACTIVE</span>
        </div>
      </div>

      <section className="stats-grid" aria-label="Summary statistics">
        <article className="stat-card stat-card--sessions">
          <div className="stat-card__top">
            <span className="stat-card__icon" aria-hidden="true">📊</span>
            <span className="stat-card__tag">TOTAL RUNS</span>
          </div>
          <span className="stat-card__value">{summary.sessions}</span>
          <span className="stat-card__label">Recorded Sessions</span>
        </article>

        <article className="stat-card stat-card--events">
          <div className="stat-card__top">
            <span className="stat-card__icon" aria-hidden="true">⚡</span>
            <span className="stat-card__tag">AUDIT LOG</span>
          </div>
          <span className="stat-card__value">{summary.events}</span>
          <span className="stat-card__label">Logged Events</span>
        </article>

        <article className="stat-card stat-card--held">
          <div className="stat-card__top">
            <span className="stat-card__icon" aria-hidden="true">⏸</span>
            <span className="stat-card__tag">TAINT DETECTED</span>
          </div>
          <span className="stat-card__value">{summary.held_outputs}</span>
          <span className="stat-card__label">Outputs Held</span>
        </article>

        <article className="stat-card stat-card--halts">
          <div className="stat-card__top">
            <span className="stat-card__icon" aria-hidden="true">🚨</span>
            <span className="stat-card__tag">FAIL-CLOSED</span>
          </div>
          <span className="stat-card__value">{summary.halts}</span>
          <span className="stat-card__label">Session Halts</span>
        </article>

        <article className="stat-card stat-card--rejected">
          <div className="stat-card__top">
            <span className="stat-card__icon" aria-hidden="true">🛡️</span>
            <span className="stat-card__tag">INTEGRITY</span>
          </div>
          <span className="stat-card__value">{summary.rejected_audit_events}</span>
          <span className="stat-card__label">Rejected Events</span>
        </article>
      </section>

      <div className="overview-grid">
        <section className="dashboard-panel" aria-label="Decisions by action">
          <div className="panel-header">
            <h2 className="panel-title">Decisions by Action</h2>
            <span className="panel-tag">L2 Core Policy</span>
          </div>
          <ul className="action-breakdown">
            {Object.entries(summary.decisions_by_action).map(([action, count]) => (
              <li key={action} className="action-breakdown__item">
                <ActionBadge action={action} />
                <div className="action-breakdown__bar-track" aria-hidden="true">
                  <div
                    className={`action-breakdown__bar action-breakdown__bar--${action.toLowerCase()}`}
                    style={{
                      width: `${summary.events > 0 ? Math.min(100, Math.round((count / summary.events) * 100)) : 0}%`,
                    }}
                  />
                </div>
                <span className="action-breakdown__count">{count}</span>
              </li>
            ))}
            {Object.keys(summary.decisions_by_action).length === 0 && (
              <li className="empty-state">No policy decisions recorded yet.</li>
            )}
          </ul>
        </section>

        <section className="dashboard-panel" aria-label="Top reason codes">
          <div className="panel-header">
            <h2 className="panel-title">Top Reason Codes</h2>
            <span className="panel-tag">Trigger Frequency</span>
          </div>
          <ol className="reason-code-list">
            {summary.top_reason_codes.map(([code, count], idx) => (
              <li key={code} className="reason-code-list__item">
                <span className="reason-code-rank" aria-hidden="true">
                  {String(idx + 1).padStart(2, '0')}
                </span>
                <ReasonCodeBadge code={code} />
                <span className="reason-code-list__count">{count}</span>
              </li>
            ))}
            {summary.top_reason_codes.length === 0 && (
              <li className="empty-state">No reason codes recorded.</li>
            )}
          </ol>
        </section>
      </div>

      <div className="overview-grid overview-grid--sub">
        <section className="dashboard-panel" aria-label="Approval outcomes">
          <div className="panel-header">
            <h2 className="panel-title">Approval Outcomes</h2>
            <span className="panel-tag">Human in the Loop</span>
          </div>
          <ul className="action-breakdown">
            {Object.entries(summary.approval_outcomes).map(([outcome, count]) => (
              <li key={outcome} className="action-breakdown__item">
                <span className="outcome-pill">
                  <SafeText value={outcome} truncate={false} />
                </span>
                <span className="action-breakdown__count">{count}</span>
              </li>
            ))}
            {Object.keys(summary.approval_outcomes).length === 0 && (
              <li className="empty-state">No human review outcomes recorded yet.</li>
            )}
          </ul>
        </section>

        <section className="dashboard-panel dashboard-panel--verify" aria-label="Audit chain verification">
          <div className="panel-header">
            <h2 className="panel-title">Cryptographic Audit Chain</h2>
            <span className="panel-tag">SHA-256 Ledger</span>
          </div>
          <p className="verify-description">
            Validates cryptographic hash continuity for every event row in SQLite to detect tampering.
          </p>

          <div className="verify-action-area">
            <button
              className="verify-btn"
              onClick={handleVerify}
              disabled={verifyState === 'loading'}
              aria-busy={verifyState === 'loading'}
            >
              {verifyState === 'loading' ? (
                <LoadingSpinner label="Hashing rows…" />
              ) : (
                <>
                  <span className="verify-btn__icon" aria-hidden="true">🔒</span>
                  <span>Verify Hash Chain</span>
                </>
              )}
            </button>

            {verifyError && <ErrorBanner message={verifyError} />}

            {verifyResult && (
              <div
                className={`verify-result verify-result--${verifyResult.ok ? 'ok' : 'fail'}`}
                role="status"
              >
                <div className="verify-result__header">
                  <span className="verify-result__icon" aria-hidden="true">
                    {verifyResult.ok ? '✓' : '✕'}
                  </span>
                  <span className="verify-result__title">
                    {verifyResult.ok ? 'Chain Verified Intact' : 'Integrity Mismatch Detected'}
                  </span>
                </div>
                <div className="verify-result__meta">
                  <span className="verify-result__detail">
                    Checked {verifyResult.checked.toLocaleString()} rows against root ledger
                  </span>
                  <span className="verify-result__message">{verifyResult.message}</span>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </main>
  );
}
