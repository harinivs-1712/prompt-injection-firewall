import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { SessionDetailResponse, AuditEventItem, SessionEventsResponse } from '../api/types';
import { IdText } from '../components/IdText';
import { SafeText } from '../components/SafeText';
import { ActionBadge } from '../components/ActionBadge';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';
import { ErrorBanner } from '../components/ErrorBanner';
import { LoadingSpinner } from '../components/LoadingSpinner';

const SAFE_EVENT_TYPES = [
  'session_started',
  'tool_check',
  'tool_authorized',
  'approval_requested',
  'approval_outcome',
  'output_inspected',
  'tool_output_inspection',
  'loop_guard_triggered',
  'session_halted',
  'session_resumed',
  'audit_event_rejected',
];
const SAFE_ACTIONS = [
  'allow',
  'ask',
  'block',
  'denied',
  'pass',
  'mask',
  'hold',
  'ALLOW',
  'BLOCK',
  'DENIED',
  'PASS',
  'MASK',
  'HOLD',
];

const PAGE_SIZE = 50;

export function SessionDetail() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [detail, setDetail] = useState<SessionDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterEventType, setFilterEventType] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterTool, setFilterTool] = useState('');

  // Paginated events
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsOffset, setEventsOffset] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    let cancelled = false;
    setLoading(true);
    api
      .getSession(sessionId)
      .then((data) => {
        if (!cancelled) {
          setDetail(data);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError && err.status === 401
              ? 'Please sign in.'
              : 'Failed to load session.'
          );
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const loadEvents = useCallback(
    async (eventType: string, action: string, tool: string, offset: number, replace: boolean) => {
      if (!sessionId) return;
      setEventsLoading(true);
      setEventsError(null);
      try {
        const params: Parameters<typeof api.getSessionEvents>[1] = { limit: PAGE_SIZE, offset };
        if (eventType) params.event_type = eventType;
        if (action) params.action = action;
        if (tool) params.tool = tool;
        const data: SessionEventsResponse = await api.getSessionEvents(sessionId, params);
        setEvents((prev) => (replace ? data.items : [...prev, ...data.items]));
        setEventsTotal(data.total);
        setEventsOffset(offset + data.items.length);
      } catch (err: unknown) {
        setEventsError(
          err instanceof ApiError && err.status === 401
            ? 'Please sign in.'
            : 'Failed to load events.'
        );
      } finally {
        setEventsLoading(false);
      }
    },
    [sessionId]
  );

  // Initial event load after session detail loads
  useEffect(() => {
    if (detail) {
      setEvents([]);
      setEventsOffset(0);
      loadEvents(filterEventType, filterAction, filterTool, 0, true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail]);

  const handleFilterApply = () => {
    setEvents([]);
    setEventsOffset(0);
    loadEvents(filterEventType, filterAction, filterTool, 0, true);
  };

  const handleLoadMoreEvents = () => {
    loadEvents(filterEventType, filterAction, filterTool, eventsOffset, false);
  };

  if (loading) return <LoadingSpinner label="Loading session telemetry…" />;
  if (error) return <ErrorBanner message={error} />;
  if (!detail) return null;

  const { session } = detail;

  return (
    <main className="session-detail-page" aria-labelledby="session-detail-heading">
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/sessions" className="breadcrumb__link">
          <span aria-hidden="true">←</span> Back to Sessions
        </Link>
      </nav>

      <div className="page-header">
        <div>
          <h1 id="session-detail-heading" className="page-title">
            Session <IdText id={session.session_id} maxLen={28} />
          </h1>
          <p className="page-subtitle">
            Timeline of monitored actions, tool calls, and firewall verdicts
          </p>
        </div>
        <div className="page-header__badge">
          <span>{detail.event_count} total events</span>
        </div>
      </div>

      <section className="session-meta-panel" aria-label="Session metadata">
        <div className="meta-grid">
          <div className="meta-item">
            <span className="meta-label">Agent Harness</span>
            <span className="meta-value">
              <SafeText value={session.agent_name} />
            </span>
          </div>

          <div className="meta-item">
            <span className="meta-label">Policy Specification</span>
            <span className="meta-value">
              <SafeText value={session.policy_version} />
            </span>
          </div>

          <div className="meta-item">
            <span className="meta-label">Execution Started</span>
            <span className="meta-value">
              <time dateTime={session.started_at} title={session.started_at}>
                {session.started_at
                  ? new Date(session.started_at).toLocaleString(undefined, {
                      dateStyle: 'medium',
                      timeStyle: 'medium',
                    })
                  : '—'}
              </time>
            </span>
          </div>

          <div className="meta-item">
            <span className="meta-label">User Task Length</span>
            <span className="meta-value">
              {session.user_task_length != null ? `${session.user_task_length} characters` : '—'}
            </span>
          </div>
        </div>
      </section>

      <section className="events-section" aria-label="Events">
        <div className="events-header">
          <div>
            <h2 className="events-title">Audit Event Stream</h2>
            <p className="events-subtitle">Sequential record of evaluated tool interactions</p>
          </div>
        </div>

        <div className="event-filters" role="search" aria-label="Filter events">
          <div className="filter-field">
            <label htmlFor="filter-event-type" className="filter-label">Event Type</label>
            <select
              id="filter-event-type"
              value={filterEventType}
              onChange={(e) => setFilterEventType(e.target.value)}
              aria-label="Filter by event type"
              className="filter-select"
            >
              <option value="">All Event Types</option>
              {SAFE_EVENT_TYPES.map((et) => (
                <option key={et} value={et}>
                  {et}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-field">
            <label htmlFor="filter-action" className="filter-label">Action Outcome</label>
            <select
              id="filter-action"
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              aria-label="Filter by action"
              className="filter-select"
            >
              <option value="">All Actions</option>
              {[...new Set(SAFE_ACTIONS.map((a) => a.toLowerCase()))].map((a) => (
                <option key={a} value={a}>
                  {a.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-field filter-field--grow">
            <label htmlFor="filter-tool" className="filter-label">Tool Name</label>
            <input
              id="filter-tool"
              type="text"
              value={filterTool}
              onChange={(e) => setFilterTool(e.target.value.slice(0, 200))}
              placeholder="e.g. send_email, bash, sql"
              aria-label="Filter by tool name"
              className="event-filters__tool-input"
            />
          </div>

          <button
            onClick={handleFilterApply}
            className="event-filters__apply"
            disabled={eventsLoading}
          >
            Filter
          </button>
        </div>

        {eventsError && <ErrorBanner message={eventsError} onDismiss={() => setEventsError(null)} />}
        {eventsLoading && events.length === 0 && <LoadingSpinner label="Querying event log…" />}

        <div className="timeline" role="list" aria-label="Event timeline">
          {events.map((event, idx) => (
            <EventCard key={event.id} event={event} index={idx + 1} />
          ))}
          {events.length === 0 && !eventsLoading && (
            <div className="empty-state-box">
              <span className="empty-icon" aria-hidden="true">🔍</span>
              <p className="empty-state">No audit events match the current filter criteria.</p>
            </div>
          )}
        </div>

        {events.length < eventsTotal && (
          <div className="load-more-wrap">
            <button
              className="load-more-btn"
              onClick={handleLoadMoreEvents}
              disabled={eventsLoading}
              aria-busy={eventsLoading}
            >
              {eventsLoading ? (
                <LoadingSpinner label="Fetching events…" />
              ) : (
                <>
                  <span>Load More Events</span>
                  <span className="load-more-count">({eventsTotal - events.length} remaining)</span>
                </>
              )}
            </button>
          </div>
        )}
      </section>
    </main>
  );
}

function EventCard({ event, index }: { event: AuditEventItem; index: number }) {
  const isUnknownType = ![
    'session_started',
    'tool_check',
    'tool_authorized',
    'approval_requested',
    'approval_outcome',
    'output_inspected',
    'tool_output_inspection',
    'loop_guard_triggered',
    'session_halted',
    'session_resumed',
    'audit_event_rejected',
  ].includes(event.event_type);

  return (
    <article
      className={`event-card event-card--${event.event_type.replace(/_/g, '-')}`}
      role="listitem"
      aria-label={`Event ${event.event_type} at ${event.ts}`}
    >
      <div className="event-card__node" aria-hidden="true">
        <span className="event-card__index">{index}</span>
      </div>

      <div className="event-card__body">
        <div className="event-card__header">
          <div className="event-card__type-wrap">
            <span className="event-card__type">
              <SafeText value={event.event_type} truncate={false} />
            </span>
            {event.action && <ActionBadge action={event.action} />}
          </div>
          <time className="event-card__ts" dateTime={event.ts} title={event.ts}>
            {event.ts ? new Date(event.ts).toLocaleTimeString() : '—'}
          </time>
        </div>

        {event.tool && (
          <div className="event-card__tool">
            <span className="tool-label">TOOL:</span>
            <code className="tool-name">
              <SafeText value={event.tool} truncate={false} />
            </code>
          </div>
        )}

        {event.reason_codes && event.reason_codes.length > 0 && (
          <div className="event-card__reasons" aria-label="Reason codes">
            {event.reason_codes.map((code) => (
              <ReasonCodeBadge key={code} code={code} />
            ))}
          </div>
        )}

        {event.evidence && event.evidence.length > 0 && (
          <div className="event-card__evidence">
            <span className="evidence-label">EVIDENCE:</span>
            <span className="evidence-content">
              <SafeText value={event.evidence} />
            </span>
          </div>
        )}

        {isUnknownType && (
          <details className="event-card__raw">
            <summary>Raw Audit Payload</summary>
            <pre>{JSON.stringify(event, null, 2)}</pre>
          </details>
        )}
      </div>
    </article>
  );
}
