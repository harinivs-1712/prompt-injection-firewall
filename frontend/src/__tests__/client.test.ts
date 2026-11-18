import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { setApiBaseUrl, isLoopbackHost, ApiError, getApiBaseUrl } from '../api/client';
import { clearToken, setToken } from '../api/token';

describe('API client security', () => {
  beforeEach(() => {
    clearToken();
    setApiBaseUrl('http://127.0.0.1:8000');
  });

  afterEach(() => {
    clearToken();
    setApiBaseUrl('http://127.0.0.1:8000');
    vi.restoreAllMocks();
  });

  describe('isLoopbackHost()', () => {
    it('recognises 127.0.0.1', () => {
      expect(isLoopbackHost('127.0.0.1')).toBe(true);
    });
    it('recognises localhost', () => {
      expect(isLoopbackHost('localhost')).toBe(true);
    });
    it('recognises ::1', () => {
      expect(isLoopbackHost('::1')).toBe(true);
    });
    it('recognises [::1]', () => {
      expect(isLoopbackHost('[::1]')).toBe(true);
    });
    it('rejects example.com', () => {
      expect(isLoopbackHost('example.com')).toBe(false);
    });
    it('rejects 0.0.0.0', () => {
      expect(isLoopbackHost('0.0.0.0')).toBe(false);
    });
  });

  describe('setApiBaseUrl()', () => {
    it('accepts loopback URL', () => {
      expect(() => setApiBaseUrl('http://127.0.0.1:8000')).not.toThrow();
      expect(getApiBaseUrl()).toBe('http://127.0.0.1:8000');
    });

    it('rejects non-loopback host by default', () => {
      expect(() => setApiBaseUrl('http://example.com')).toThrow(/non-loopback/i);
    });

    it('strips trailing slash', () => {
      setApiBaseUrl('http://127.0.0.1:8000/');
      expect(getApiBaseUrl()).toBe('http://127.0.0.1:8000');
    });
  });

  describe('api() without token', () => {
    it('throws ApiError with 401 when no token', async () => {
      clearToken();
      const { api } = await import('../api/client');
      let err: unknown;
      try {
        await api.getSummary();
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(401);
      expect((err as ApiError).code).toBe('UNAUTHORIZED');
    });
  });

  describe('ApiError shape', () => {
    it('has name, status, code, requestId properties', () => {
      const e = new ApiError('oops', 500, 'INTERNAL', 'req-123');
      expect(e.name).toBe('ApiError');
      expect(e.status).toBe(500);
      expect(e.code).toBe('INTERNAL');
      expect(e.requestId).toBe('req-123');
      expect(e.message).toBe('oops');
    });

    it('defaults requestId to null', () => {
      const e = new ApiError('oops', 404, 'NOT_FOUND');
      expect(e.requestId).toBeNull();
    });
  });

  describe('request hardening', () => {
    it('fetch is called with credentials omit and cache no-store', async () => {
      setToken('valid-token-12345');
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(JSON.stringify({ status: 'ok', version: '0.1.0' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const { api } = await import('../api/client');
      await api.getHealth();

      expect(fetchSpy).toHaveBeenCalledOnce();
      const [, options] = fetchSpy.mock.calls[0];
      expect((options as RequestInit).credentials).toBe('omit');
      expect((options as RequestInit).cache).toBe('no-store');
      expect((options as RequestInit).referrerPolicy).toBe('no-referrer');
    });
  });
});
