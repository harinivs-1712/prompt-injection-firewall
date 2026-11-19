/**
 * Hardened API client for the Firewall Review API.
 * Single choke point for all network requests.
 */

import {
  HealthResponse,
  HEALTH_KEYS,
  SummaryResponse,
  SUMMARY_KEYS,
  SessionsListResponse,
  SESSIONS_LIST_KEYS,
  SessionDetailResponse,
  SESSION_DETAIL_KEYS,
  SessionEventsResponse,
  SESSION_EVENTS_KEYS,
  AuditVerifyResponse,
  AUDIT_VERIFY_KEYS,
  ApiErrorResponse,
} from './types';
import { getToken, clearToken, resetIdleTimer } from './token';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB

let apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export function setApiBaseUrl(url: string): void {
  // Validate base URL
  const parsed = new URL(url);
  validateHost(parsed.hostname);
  apiBaseUrl = url.replace(/\/+$/, '');
}

export function getApiBaseUrl(): string {
  return apiBaseUrl;
}

export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === '127.0.0.1' ||
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname === '[::1]'
  );
}

function validateHost(hostname: string): void {
  const allowRemote =
    typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_ALLOW_REMOTE_API === '1';

  if (!allowRemote && !isLoopbackHost(hostname)) {
    throw new Error('A non-loopback API URL is not permitted.');
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(message: string, status: number, code: string = 'API_ERROR', requestId: string | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

function validateShape<T extends object>(data: unknown, requiredKeys: (keyof T)[], context: string): T {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new ApiError(`Invalid ${context} response.`, 502, 'INVALID_SHAPE');
  }
  for (const key of requiredKeys) {
    if (!(String(key) in data)) {
      throw new ApiError(
        `Invalid ${context} response.`,
        502,
        'INVALID_SHAPE'
      );
    }
  }
  return data as T;
}

interface RequestOptions {
  authRequired?: boolean;
  timeoutMs?: number;
}

async function request<T>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  const { authRequired = true, timeoutMs = DEFAULT_TIMEOUT_MS } = options;

  // Construct and validate target URL
  const fullUrl = new URL(path, apiBaseUrl);
  validateHost(fullUrl.hostname);

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (authRequired) {
    const token = getToken();
    if (!token) {
      throw new ApiError('No authentication token available.', 401, 'UNAUTHORIZED');
    }
    headers['Authorization'] = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(fullUrl.toString(), {
      method: 'GET',
      headers,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new ApiError('Request timed out.', 504, 'TIMEOUT');
    }
    throw new ApiError('Cannot reach the server.', 503, 'NETWORK_ERROR');
  } finally {
    clearTimeout(timer);
  }

  // Update activity on successful network roundtrip
  resetIdleTimer();

  const requestId = response.headers.get('x-request-id');

  // Handle 401 Unauthorized immediately
  if (response.status === 401) {
    clearToken();
    throw new ApiError('Session expired or invalid token.', 401, 'UNAUTHORIZED', requestId);
  }

  // Check content length header
  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    throw new ApiError(
      `Response body exceeds maximum permitted size of ${MAX_BODY_BYTES} bytes.`,
      502,
      'RESPONSE_TOO_LARGE',
      requestId
    );
  }

  if (!(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) {
    throw new ApiError('Server returned an invalid response.', 502, 'INVALID_CONTENT_TYPE', requestId);
  }

  // Read response text and check size
  const rawText = await response.text();
  if (rawText.length > MAX_BODY_BYTES) {
    throw new ApiError(
      `Response body exceeds maximum permitted size of ${MAX_BODY_BYTES} bytes.`,
      502,
      'RESPONSE_TOO_LARGE',
      requestId
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(rawText);
  } catch {
    throw new ApiError('Failed to parse response as JSON.', 502, 'INVALID_JSON', requestId);
  }

  if (!response.ok) {
    const errorBody = json as Partial<ApiErrorResponse>;
    const message = errorBody?.error || `HTTP error ${response.status}: ${response.statusText}`;
    const code = errorBody?.code || `HTTP_${response.status}`;
    throw new ApiError(message, response.status, code, requestId);
  }

  return json as T;
}

export const api = {
  async getHealth(): Promise<HealthResponse> {
    const raw = await request<HealthResponse>('/health', { authRequired: false });
    return validateShape<HealthResponse>(raw, HEALTH_KEYS, 'health');
  },

  async getSummary(): Promise<SummaryResponse> {
    const raw = await request<SummaryResponse>('/api/v1/summary');
    return validateShape<SummaryResponse>(raw, SUMMARY_KEYS, 'summary');
  },

  async getSessions(limit: number = 50, offset: number = 0): Promise<SessionsListResponse> {
    const params = new URLSearchParams({
      limit: Math.min(Math.max(limit, 1), 200).toString(),
      offset: Math.max(offset, 0).toString(),
    });
    const raw = await request<SessionsListResponse>(`/api/v1/sessions?${params.toString()}`);
    return validateShape<SessionsListResponse>(raw, SESSIONS_LIST_KEYS, 'sessions list');
  },

  async getSession(sessionId: string): Promise<SessionDetailResponse> {
    if (!sessionId || typeof sessionId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(sessionId)) {
      throw new ApiError('Invalid session ID parameter.', 400, 'BAD_PARAM');
    }
    const safeId = encodeURIComponent(sessionId.trim());
    const raw = await request<SessionDetailResponse>(`/api/v1/sessions/${safeId}`);
    return validateShape<SessionDetailResponse>(raw, SESSION_DETAIL_KEYS, 'session detail');
  },

  async getSessionEvents(
    sessionId: string,
    params?: {
      event_type?: string;
      action?: string;
      tool?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<SessionEventsResponse> {
    if (!sessionId || typeof sessionId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(sessionId)) {
      throw new ApiError('Invalid session ID parameter.', 400, 'BAD_PARAM');
    }
    const safeId = encodeURIComponent(sessionId.trim());
    const searchParams = new URLSearchParams();
    const validEvents = new Set(['session_started', 'tool_check', 'tool_authorized', 'approval_requested', 'approval_outcome', 'output_inspected', 'tool_output_inspection', 'loop_guard_triggered', 'session_halted', 'session_resumed', 'audit_event_rejected']);
    const validActions = new Set(['allow', 'ask', 'block', 'denied', 'pass', 'mask', 'hold', 'ALLOW', 'BLOCK', 'DENIED', 'PASS', 'MASK', 'HOLD']);
    if (params?.event_type && !validEvents.has(params.event_type)) throw new ApiError('Invalid request parameters.', 400, 'BAD_PARAM');
    if (params?.action && !validActions.has(params.action)) throw new ApiError('Invalid request parameters.', 400, 'BAD_PARAM');
    if (params?.tool && !/^[A-Za-z0-9_.-]{1,64}$/.test(params.tool)) throw new ApiError('Invalid request parameters.', 400, 'BAD_PARAM');
    if (params?.event_type) searchParams.set('event_type', params.event_type);
    if (params?.action) searchParams.set('action', params.action);
    if (params?.tool) searchParams.set('tool', params.tool);
    if (params?.limit !== undefined) {
      searchParams.set('limit', Math.min(Math.max(params.limit, 1), 200).toString());
    }
    if (params?.offset !== undefined) {
      searchParams.set('offset', Math.max(params.offset, 0).toString());
    }

    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    const raw = await request<SessionEventsResponse>(`/api/v1/sessions/${safeId}/events${query}`);
    return validateShape<SessionEventsResponse>(raw, SESSION_EVENTS_KEYS, 'session events');
  },

  async verifyAudit(maxRows: number = 100_000): Promise<AuditVerifyResponse> {
    const params = new URLSearchParams({
      max_rows: Math.min(Math.max(maxRows, 1), 1_000_000).toString(),
    });
    const raw = await request<AuditVerifyResponse>(`/api/v1/audit/verify?${params.toString()}`);
    return validateShape<AuditVerifyResponse>(raw, AUDIT_VERIFY_KEYS, 'audit verify');
  },
};
