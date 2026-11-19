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
          setError(err instanceof ApiError && err.status === 401 ? 'Please sign in.' : 'Cannot reach the server.');
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, []);

  const handleLoadMore = async () => {
    setLoadingMore(true);
    try {
      const data = await api.getSessions(PAGE_SIZE, offset);
      setSessions((prev) => [...prev, ...data.items]);
      setTotal(data.total);
      setOffset((prev) => prev + data.items.length);
    } catch (err: unknown) {
      setError(err instanceof ApiError && err.status === 401 ? 'Please sign in.' : 'Cannot reach the server.');
    } finally {
      setLoadingMore(false);
    }
  };

  if (loading) return <LoadingSpinner label="Loading sessions…" />;

  return (
    <main className="sessions-page" aria-labelledby="sessions-heading">
      <h1 id="sessions-heading">Sessions</h1>
      <p className="sessions-page__count">
        Showing {sessions.length} of {total} sessions
      </p>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {sessions.length === 0 ? (
        <p className="empty-state">No sessions found.</p>
      ) : (
        <div className="table-wrapper" role="region" aria-label="Sessions table" tabIndex={0}>
          <table className="sessions-table">
            <thead>
              <tr>
                <th scope="col">Session ID</th>
                <th scope="col">Started At</th>
                <th scope="col">Agent</th>
                <th scope="col">Policy</th>
                <th scope="col">Task Len</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id}>
                  <td>
                    <Link to={`/sessions/${encodeURIComponent(s.session_id)}`} className="session-link">
                      <IdText id={s.session_id} maxLen={22} />
                    </Link>
                  </td>
                  <td>
                    <time
                      dateTime={s.started_at}
                      title={s.started_at}
                    >
                      {s.started_at
                        ? new Date(s.started_at).toLocaleString(undefined, {
                            dateStyle: 'short',
                            timeStyle: 'medium',
                          })
                        : '—'}
                    </time>
                  </td>
                  <td><SafeText value={s.agent_name} /></td>
                  <td><SafeText value={s.policy_version} /></td>
                  <td>{s.user_task_length ?? '—'}</td>
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
            {loadingMore ? <LoadingSpinner label="Loading…" /> : `Load more (${total - sessions.length} remaining)`}
          </button>
        </div>
      )}
    </main>
  );
}
