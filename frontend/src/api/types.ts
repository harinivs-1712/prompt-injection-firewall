/**
 * Strict TypeScript interfaces and runtime validation keys for the Firewall API.
 */

export interface HealthResponse {
  status: string;
  version: string;
}

export const HEALTH_KEYS: (keyof HealthResponse)[] = ['status', 'version'];

export interface SummaryResponse {
  sessions: number;
  events: number;
  decisions_by_action: Record<string, number>;
  top_reason_codes: [string, number][];
  approval_outcomes: Record<string, number>;
  held_outputs: number;
  halts: number;
  rejected_audit_events: number;
}

export const SUMMARY_KEYS: (keyof SummaryResponse)[] = [
  'sessions',
  'events',
  'decisions_by_action',
  'top_reason_codes',
  'approval_outcomes',
  'held_outputs',
  'halts',
  'rejected_audit_events',
];

export interface SessionItem {
  session_id: string;
  started_at: string;
  agent_name: string;
  policy_version: string;
  user_task_length: number;
}

export const SESSION_ITEM_KEYS: (keyof SessionItem)[] = [
  'session_id',
  'started_at',
  'agent_name',
  'policy_version',
  'user_task_length',
];

export interface SessionsListResponse {
  items: SessionItem[];
  limit: number;
  offset: number;
  total: number;
}

export const SESSIONS_LIST_KEYS: (keyof SessionsListResponse)[] = ['items', 'limit', 'offset', 'total'];

export interface TimelineEvent {
  id: number;
  ts: string;
  event_type: string;
  action: string | null;
  tool: string | null;
  reason_codes: string[];
}

export const TIMELINE_EVENT_KEYS: (keyof TimelineEvent)[] = [
  'id',
  'ts',
  'event_type',
  'action',
  'tool',
  'reason_codes',
];

export interface SessionDetailResponse {
  session: SessionItem;
  timeline: TimelineEvent[];
  event_count: number;
}

export const SESSION_DETAIL_KEYS: (keyof SessionDetailResponse)[] = ['session', 'timeline', 'event_count'];

export interface AuditEventItem {
  id: number;
  ts: string;
  session_id: string;
  event_type: string;
  tool: string | null;
  action: string | null;
  reason_codes: string[];
  rule_ids: string[];
  link_level: string | null;
  evidence: unknown[];
  approval_outcome: string | null;
  output_id: string | null;
  max_level: string | null;
  counts: Record<string, unknown>;
  prev_hash: string;
  row_hash: string;
}

export const AUDIT_EVENT_KEYS: (keyof AuditEventItem)[] = [
  'id',
  'ts',
  'session_id',
  'event_type',
  'tool',
  'action',
  'reason_codes',
  'rule_ids',
  'prev_hash',
  'row_hash',
];

export interface SessionEventsResponse {
  items: AuditEventItem[];
  limit: number;
  offset: number;
  total: number;
}

export const SESSION_EVENTS_KEYS: (keyof SessionEventsResponse)[] = ['items', 'limit', 'offset', 'total'];

export interface AuditVerifyResponse {
  ok: boolean;
  checked: number;
  first_bad_id: number | null;
  message: string;
}

export const AUDIT_VERIFY_KEYS: (keyof AuditVerifyResponse)[] = ['ok', 'checked', 'first_bad_id', 'message'];

export interface ScanSegment {
  segment_id: string; start: number; end: number; suspicion_level: string;
  instruction_detected: boolean; instruction_reasons: string[];
  piguard_label: string | null; piguard_score: number | null; piguard_flag: boolean | null;
  judge_ran: boolean; judge_is_instruction: boolean | null; judge_needed_for_task: boolean | null;
  judge_flag: boolean | null; judge_reason: string | null; judge_coverage_reason: string | null;
}
export interface ScanTrace { id: string; source_type: string; doc_id: string; segment_count: number; judge_calls_made: number; coverage_fraction: number; original_text: string | null; text_truncated: boolean; segments: ScanSegment[]; }
export interface SecurityTraceResponse { scans: ScanTrace[]; tool_decisions: AuditEventItem[]; text_stored: boolean; }
export const SECURITY_TRACE_KEYS: (keyof SecurityTraceResponse)[] = ['scans', 'tool_decisions', 'text_stored'];

export interface ApiErrorResponse {
  error: string;
  code: string;
}
