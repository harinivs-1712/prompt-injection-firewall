import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { SessionDetailResponse, AuditEventItem, SessionEventsResponse, SecurityTraceResponse } from '../api/types';
import { IdText } from '../components/IdText';
import { SafeText } from '../components/SafeText';
import { ActionBadge } from '../components/ActionBadge';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';
import { ErrorBanner } from '../components/ErrorBanner';
import { LoadingSpinner } from '../components/LoadingSpinner';

const SAFE_EVENT_TYPES = [
  'session_started', 'tool_check', 'tool_authorized', 'approval_requested',
  'approval_outcome', 'output_inspected', 'tool_output_inspection',
  'loop_guard_triggered', 'session_halted', 'session_resumed', 'audit_event_rejected',
];
const SAFE_ACTIONS = [
  'allow', 'ask', 'block', 'denied', 'pass', 'mask', 'hold',
  'ALLOW', 'BLOCK', 'DENIED', 'PASS', 'MASK', 'HOLD',
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
  const [trace, setTrace] = useState<SecurityTraceResponse | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    let cancelled = false;
    setLoading(true);
    api
      .getSession(sessionId)
      .then((data) => {
        if (!cancelled) {
          setDetail(data);
          api.getSecurityTrace(sessionId).then(setTrace).catch(() => setTrace(null));
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
        setEvents((prev) => replace ? data.items : [...prev, ...data.items]);
        setEventsTotal(data.total);
        setEventsOffset(offset + data.items.length);
      } catch (err: unknown) {
        setEventsError(err instanceof ApiError && err.status === 401 ? 'Please sign in.' : 'Cannot reach the server.');
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

  if (loading) return <LoadingSpinner label="Loading session…" />;
  if (error) return <ErrorBanner message={error} />;
  if (!detail) return null;

  const { session } = detail;

  return (
    <main className="session-detail-page" aria-labelledby="session-detail-heading">
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/sessions">← Sessions</Link>
      </nav>

      <h1 id="session-detail-heading">
        Session <IdText id={session.session_id} maxLen={30} />
      </h1>

      <section className="session-meta" aria-label="Session metadata">
        <dl className="meta-list">
          <dt>Agent</dt>
          <dd><SafeText value={session.agent_name} /></dd>
          <dt>Policy</dt>
          <dd><SafeText value={session.policy_version} /></dd>
          <dt>Started At</dt>
          <dd>
            <time dateTime={session.started_at} title={session.started_at}>
              {session.started_at ? new Date(session.started_at).toLocaleString() : '—'}
            </time>
          </dd>
          <dt>Task Length</dt>
          <dd>{session.user_task_length ?? '—'}</dd>
          <dt>Total Events</dt>
          <dd>{detail.event_count}</dd>
        </dl>
      </section>

      <section className="events-section" aria-label="Security scan trace">
        <h2>Security Scan Trace</h2>
        {!trace && <p className="empty-state">No Layer 1 scan record is available for this session.</p>}
        {trace?.scans.map((scan) => (
          <details key={scan.id} className="event-card" open>
            <summary><SafeText value={`${scan.source_type}: ${scan.doc_id} (${scan.segment_count} segments)`} /></summary>
            {trace.text_stored && scan.original_text !== null ? <SafeText value={scan.original_text} /> : <p>Original text was not stored.</p>}
            <div className="table-wrapper"><table className="sessions-table"><thead><tr><th>Segment</th><th>Text</th><th>Instruction</th><th>PIGuard</th><th>Gemini judge</th><th>Final level</th></tr></thead><tbody>
              {scan.segments.map((segment) => <tr key={segment.segment_id}>
                <td><IdText id={segment.segment_id} /></td>
                <td>{scan.original_text !== null ? <SafeText value={scan.original_text.slice(segment.start, segment.end)} /> : <span>Stored text disabled</span>}</td>
                <td><SafeText value={segment.instruction_detected ? `Yes — ${segment.instruction_reasons.join(', ') || 'rule matched'}` : 'No'} /></td>
                <td><SafeText value={segment.piguard_score === null ? 'Not available' : `${segment.piguard_label ?? 'unknown'} (${segment.piguard_score.toFixed(4)})`} /></td>
                <td><SafeText value={!segment.judge_ran ? 'Not judged' : segment.judge_flag ? `Flagged — ${segment.judge_reason ?? ''}` : `Not flagged — ${segment.judge_reason ?? ''}`} /></td>
                <td><SafeText value={segment.suspicion_level} /></td>
              </tr>)}
            </tbody></table></div>
          </details>
        ))}
        {trace && <><h3>Tool decisions</h3><div className="table-wrapper"><table className="sessions-table"><thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Reason codes</th><th>Linked segments</th></tr></thead><tbody>
          {trace.tool_decisions.map((event) => <tr key={event.id}><td><SafeText value={event.ts} /></td><td><SafeText value={event.tool} /></td><td><ActionBadge action={event.action ?? 'unknown'} /></td><td><SafeText value={event.reason_codes.join(', ')} /></td><td><SafeText value={(event.evidence as Array<{segment_id?: string}>).map((x) => x.segment_id).filter(Boolean).join(', ') || '—'} /></td></tr>)}
        </tbody></table></div></>}
      </section>

      <section className="events-section" aria-label="Events">
        <h2>Events</h2>

        <div className="event-filters" role="search" aria-label="Filter events">
          <select
            value={filterEventType}
            onChange={(e) => setFilterEventType(e.target.value)}
            aria-label="Filter by event type"
          >
            <option value="">All event types</option>
            {SAFE_EVENT_TYPES.map((et) => (
              <option key={et} value={et}>{et}</option>
            ))}
          </select>

          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            aria-label="Filter by action"
          >
            <option value="">All actions</option>
            {[...new Set(SAFE_ACTIONS.map(a => a.toLowerCase()))].map((a) => (
              <option key={a} value={a}>{a.toUpperCase()}</option>
            ))}
          </select>

          <input
            type="text"
            value={filterTool}
            onChange={(e) => setFilterTool(e.target.value.slice(0, 200))}
            placeholder="Filter by tool name"
            aria-label="Filter by tool name"
            className="event-filters__tool-input"
          />

          <button
            onClick={handleFilterApply}
            className="event-filters__apply"
            disabled={eventsLoading}
          >
            Apply
          </button>
        </div>

        {eventsError && <ErrorBanner message={eventsError} onDismiss={() => setEventsError(null)} />}
        {eventsLoading && events.length === 0 && <LoadingSpinner label="Loading events…" />}

        <div className="timeline" role="list" aria-label="Event timeline">
          {events.map((event) => (
            <EventCard key={event.id} event={event} />
          ))}
          {events.length === 0 && !eventsLoading && (
            <p className="empty-state">No events match the current filters.</p>
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
              {eventsLoading
                ? <LoadingSpinner label="Loading…" />
                : `Load more events (${eventsTotal - events.length} remaining)`}
            </button>
          </div>
        )}
      </section>
    </main>
  );
}

function EventCard({ event }: { event: AuditEventItem }) {
  const isUnknownType = ![
    'session_started', 'tool_check', 'tool_authorized', 'approval_requested',
    'approval_outcome', 'output_inspected', 'tool_output_inspection',
    'loop_guard_triggered', 'session_halted', 'session_resumed', 'audit_event_rejected',
  ].includes(event.event_type);

  return (
    <article
      className="event-card"
      role="listitem"
      aria-label={`Event ${event.event_type} at ${event.ts}`}
    >
      <div className="event-card__header">
        <span className="event-card__type">
          <SafeText value={event.event_type} truncate={false} />
        </span>
        <time className="event-card__ts" dateTime={event.ts} title={event.ts}>
          {event.ts ? new Date(event.ts).toLocaleString() : '—'}
        </time>
        {event.action && <ActionBadge action={event.action} />}
      </div>

      {event.tool && (
        <div className="event-card__tool">
          Tool: <SafeText value={event.tool} truncate={false} />
        </div>
      )}

      {event.reason_codes && event.reason_codes.length > 0 && (
        <div className="event-card__reasons" aria-label="Reason codes">
          {event.reason_codes.map((code) => (
            <ReasonCodeBadge key={code} code={code} />
          ))}
        </div>
      )}

      {isUnknownType && (
        <details className="event-card__raw">
          <summary>Raw event data</summary>
          <pre><SafeText value={event} truncate={false} /></pre>
        </details>
      )}
    </article>
  );
}
