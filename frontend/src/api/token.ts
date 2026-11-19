/**
 * In-memory token management with 15-minute idle timeout.
 * NEVER writes to browser web storage or cookies.
 */

const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

let inMemoryToken: string | null = null;
let lastActivityTime: number = Date.now();
let idleTimerId: ReturnType<typeof setTimeout> | null = null;
let idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;

type LogoutListener = () => void;
const logoutListeners: Set<LogoutListener> = new Set();

export function onTokenCleared(listener: LogoutListener): () => void {
  logoutListeners.add(listener);
  return () => {
    logoutListeners.delete(listener);
  };
}

function notifyLogout(): void {
  for (const listener of logoutListeners) {
    try {
      listener();
    } catch {
      // quiet listener error
    }
  }
}

export function resetIdleTimer(): void {
  lastActivityTime = Date.now();
  if (idleTimerId !== null) {
    clearTimeout(idleTimerId);
  }
  if (inMemoryToken !== null) {
    idleTimerId = setTimeout(() => {
      const elapsed = Date.now() - lastActivityTime;
      if (elapsed >= idleTimeoutMs) {
        clearToken();
      } else {
        // reschedule remaining
        resetIdleTimer();
      }
    }, idleTimeoutMs);
  }
}

export function setIdleTimeoutMsForTesting(ms: number): void {
  idleTimeoutMs = ms;
  resetIdleTimer();
}

export function setToken(token: string): void {
  // Validate token: non-empty string, no CRLF injection
  if (!token || typeof token !== 'string') {
    throw new Error('Invalid token');
  }
  if (/[\r\n]/.test(token)) {
    throw new Error('Token contains forbidden newline characters');
  }
  inMemoryToken = token.trim();
  resetIdleTimer();
}

export function getToken(): string | null {
  if (inMemoryToken === null) {
    return null;
  }
  // Check if timed out
  if (Date.now() - lastActivityTime >= idleTimeoutMs) {
    clearToken();
    return null;
  }
  return inMemoryToken;
}

export function hasToken(): boolean {
  return getToken() !== null;
}

export function clearToken(): void {
  const hadToken = inMemoryToken !== null;
  inMemoryToken = null;
  if (idleTimerId !== null) {
    clearTimeout(idleTimerId);
    idleTimerId = null;
  }
  if (hadToken) {
    notifyLogout();
  }
}

/**
 * Initialize user activity tracking to keep the token active while user is interacting.
 */
let activityTrackingInitialized = false;
export function initActivityTracking(): void {
  if (activityTrackingInitialized || typeof window === 'undefined') {
    return;
  }
  activityTrackingInitialized = true;

  const handleActivity = () => {
    if (inMemoryToken !== null) {
      resetIdleTimer();
    }
  };

  window.addEventListener('mousemove', handleActivity, { passive: true });
  window.addEventListener('keydown', handleActivity, { passive: true });
  window.addEventListener('click', handleActivity, { passive: true });
  window.addEventListener('scroll', handleActivity, { passive: true });
}
