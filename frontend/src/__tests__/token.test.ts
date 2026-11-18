import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Import after clearing module cache to ensure fresh state
let tokenModule: typeof import('../api/token');

describe('token (memory-only storage)', () => {
  beforeEach(async () => {
    // Re-import fresh module state for isolation
    tokenModule = await import('../api/token');
    tokenModule.clearToken();
    tokenModule.setIdleTimeoutMsForTesting(15 * 60 * 1000);
  });

  afterEach(() => {
    tokenModule.clearToken();
    vi.useRealTimers();
  });

  it('stores and retrieves a token', () => {
    tokenModule.setToken('my-secret-token');
    expect(tokenModule.getToken()).toBe('my-secret-token');
    expect(tokenModule.hasToken()).toBe(true);
  });

  it('clears the token', () => {
    tokenModule.setToken('tok');
    tokenModule.clearToken();
    expect(tokenModule.getToken()).toBeNull();
    expect(tokenModule.hasToken()).toBe(false);
  });

  it('rejects tokens with CRLF injection', () => {
    expect(() => tokenModule.setToken('tok\r\nX-Injected: header')).toThrow();
    expect(() => tokenModule.setToken('tok\nX-Injected: header')).toThrow();
  });

  it('rejects empty string tokens', () => {
    expect(() => tokenModule.setToken('')).toThrow();
  });

  it('never touches localStorage or sessionStorage', () => {
    tokenModule.setToken('test-token-abc');
    const lsKeys = Object.keys(localStorage);
    const ssKeys = Object.keys(sessionStorage);
    expect(lsKeys.filter(k => k.toLowerCase().includes('token'))).toHaveLength(0);
    expect(ssKeys.filter(k => k.toLowerCase().includes('token'))).toHaveLength(0);
    tokenModule.clearToken();
  });

  it('expires token after idle timeout using fake timers', () => {
    vi.useFakeTimers();
    tokenModule.setIdleTimeoutMsForTesting(100);
    tokenModule.setToken('expire-me');
    expect(tokenModule.hasToken()).toBe(true);
    vi.advanceTimersByTime(200);
    // getToken() checks elapsed time, should return null
    expect(tokenModule.getToken()).toBeNull();
  });

  it('calls logout listeners on clearToken', () => {
    const listener = vi.fn();
    const unsubscribe = tokenModule.onTokenCleared(listener);
    tokenModule.setToken('tok');
    tokenModule.clearToken();
    expect(listener).toHaveBeenCalledOnce();
    unsubscribe();
  });

  it('logout listener is not called when token was already cleared', () => {
    const listener = vi.fn();
    const unsubscribe = tokenModule.onTokenCleared(listener);
    tokenModule.clearToken(); // already clear
    expect(listener).not.toHaveBeenCalled();
    unsubscribe();
  });

  it('trims whitespace from token', () => {
    tokenModule.setToken('  valid-token  ');
    expect(tokenModule.getToken()).toBe('valid-token');
  });
});
