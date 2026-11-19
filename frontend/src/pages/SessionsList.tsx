import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { SessionItem, SessionsListResponse } from '../api/types';
import { IdText } from '../components/IdText';
import { SafeText } from '../components/SafeText';
import { ErrorBanner } from '../components/ErrorBanner';
import { LoadingSpinner } from '../components/LoadingSpinner';

const PAGE_SIZE = 50;

export function SessionsList() {
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getSessions(PAGE_SIZE, 0)
      .then((data: SessionsListResponse) => {
        if (!cancelled) {
          setSessions(data.items);
          setTotal(data.total);
          setOffset(data.items.length);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError && err.status === 401
              ? 'Please sign in.'
              : 'Failed to load sessions.'
          );
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLoadMore = async () => {
    setLoadingMore(true);
    try {
      const data = await api.getSessions(PAGE_SIZE, offset);
      setSessions((prev) => [...prev, ...data.items]);
      setTotal(data.total);
      setOffset((prev) => prev + data.items.length);
    } catch (err: unknown) {
      setError(
        err instanceof ApiError && err.status === 401
          ? 'Please sign in.'
          : 'Failed to load more sessions.'
      );
    } finally {
      setLoadingMore(false);
    }
  };

  if (loading) return <LoadingSpinner label="Loading sessions…" />;

  return (
    <main className="sessions-page" aria-labelledby="sessions-heading">
      <div className="page-header">
        <div>
          <h1 id="sessions-heading" className="page-title">
            Agent Sessions
          </h1>
          <p className="page-subtitle">
            Monitored AI agent runs with full audit history
          </p>
        </div>
        <div className="page-header__badge">
          <span>{sessions.length} of {total} sessions</span>
        </div>
      </div>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {sessions.length === 0 ? (
        <div className="empty-state-box">
          <span className="empty-icon" aria-hidden="true">📭</span>
          <p className="empty-state">No agent sessions recorded in the audit database.</p>
        </div>
      ) : (
        <div className="table-wrapper" role="region" aria-label="Sessions table" tabIndex={0}>
          <table className="sessions-table">
            <thead>
              <tr>
                <th scope="col">Session Identifier</th>
                <th scope="col">Started Timestamp</th>
                <th scope="col">Agent Harness</th>
                <th scope="col">Policy Config</th>
                <th scope="col">Task Payload</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id}>
                  <td className="session-id-cell">
                    <Link
                      to={`/sessions/${encodeURIComponent(s.session_id)}`}
                      className="session-link"
                    >
                      <IdText id={s.session_id} maxLen={22} />
                    </Link>
                  </td>
                  <td className="timestamp-cell">
                    <time dateTime={s.started_at} title={s.started_at}>
                      {s.started_at
                        ? new Date(s.started_at).toLocaleString(undefined, {
                            dateStyle: 'medium',
                            timeStyle: 'medium',
                          })
                        : '—'}
                    </time>
                  </td>
                  <td>
                    <span className="agent-tag">
                      <SafeText value={s.agent_name} />
                    </span>
                  </td>
                  <td>
                    <span className="policy-tag">
                      <SafeText value={s.policy_version} />
                    </span>
                  </td>
                  <td>
                    <span className="length-tag">
                      {s.user_task_length != null ? `${s.user_task_length} chars` : '—'}
                    </span>
                  </td>
                  <td>
                    <Link
                      to={`/sessions/${encodeURIComponent(s.session_id)}`}
                      className="view-btn"
                      aria-label={`View session ${s.session_id}`}
                    >
                      <span>Timeline</span>
                      <span aria-hidden="true">→</span>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sessions.length < total && (
        <div className="load-more-wrap">
          <button
            className="load-more-btn"
            onClick={handleLoadMore}
            disabled={loadingMore}
            aria-busy={loadingMore}
          >
            {loadingMore ? (
              <LoadingSpinner label="Fetching more sessions…" />
            ) : (
              <>
                <span>Load More Sessions</span>
                <span className="load-more-count">({total - sessions.length} remaining)</span>
              </>
            )}
          </button>
        </div>
      )}
    </main>
  );
}
