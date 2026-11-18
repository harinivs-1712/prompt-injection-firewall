import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { clearToken, hasToken, onTokenCleared, setToken, initActivityTracking } from '../api/token';
import { api } from '../api/client';
import { setApiBaseUrl } from '../api/client';

interface AuthContextValue {
  isAuthenticated: boolean;
  baseUrl: string;
  login: (token: string, baseUrl: string) => Promise<void>;
  logout: () => void;
  loginError: string | null;
  loginPending: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(hasToken);
  const [baseUrl, setBaseUrl] = useState<string>('http://127.0.0.1:8000');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginPending, setLoginPending] = useState<boolean>(false);

  useEffect(() => {
    initActivityTracking();
    const unsubscribe = onTokenCleared(() => {
      setIsAuthenticated(false);
    });
    return unsubscribe;
  }, []);

  const login = useCallback(async (token: string, url: string) => {
    setLoginError(null);
    setLoginPending(true);
    try {
      setApiBaseUrl(url);
      setToken(token);
      // Verify the token works by hitting /health (no auth) then /api/v1/summary (auth)
      await api.getSummary();
      setBaseUrl(url);
      setIsAuthenticated(true);
    } catch (err: unknown) {
      clearToken();
      const message = err instanceof Error ? err.message : 'Connection failed.';
      setLoginError(message);
      setIsAuthenticated(false);
    } finally {
      setLoginPending(false);
    }
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setIsAuthenticated(false);
    setLoginError(null);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, baseUrl, login, logout, loginError, loginPending }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
