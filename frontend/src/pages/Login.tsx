import { FormEvent, useRef, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner } from '../components/ErrorBanner';
import { LoadingSpinner } from '../components/LoadingSpinner';

export function Login() {
  const { login, loginError, loginPending } = useAuth();
  const tokenRef = useRef<HTMLInputElement>(null);
  const [url, setUrl] = useState('http://127.0.0.1:8000');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const token = tokenRef.current?.value ?? '';
    await login(token.trim(), url.trim());
    if (tokenRef.current) tokenRef.current.value = '';
  };

  return (
    <main className="login-page" aria-labelledby="login-heading">
      <div className="login-card">
        <div className="login-card__header">
          <div className="login-card__icon-wrap">
            <svg
              className="login-card__icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M12 8v4" />
              <path d="M12 16h.01" />
            </svg>
          </div>
          <h1 id="login-heading" className="login-card__title">
            Firewall Control Plane
          </h1>
          <p className="login-card__subtitle">
            Prompt-Injection Defense Telemetry & Review Console
          </p>
        </div>

        {loginError && <ErrorBanner message={loginError} />}

        <form onSubmit={handleSubmit} className="login-form" noValidate>
          <div className="login-form__field">
            <label htmlFor="login-url" className="login-form__label">
              <span>Server Endpoint</span>
              <span className="login-form__tag">Loopback Only</span>
            </label>
            <div className="input-group">
              <span className="input-group__icon" aria-hidden="true">🌐</span>
              <input
                id="login-url"
                type="url"
                className="login-form__input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                autoComplete="off"
                required
                placeholder="http://127.0.0.1:8000"
              />
            </div>
          </div>

          <div className="login-form__field">
            <label htmlFor="login-token" className="login-form__label">
              <span>Bearer Token</span>
              <span className="login-form__tag">Viewer / Reviewer</span>
            </label>
            <div className="input-group">
              <span className="input-group__icon" aria-hidden="true">🔑</span>
              <input
                id="login-token"
                type="password"
                className="login-form__input"
                ref={tokenRef}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                required
                placeholder="Paste your 24+ character token"
                aria-describedby="login-token-hint"
              />
            </div>
            <div id="login-token-hint" className="login-form__hint-box">
              <span className="hint-icon" aria-hidden="true">🛡️</span>
              <span>
                <strong>In-Memory Isolation:</strong> Token is never written to disk, cookies, or browser storage. It auto-expires after 15 minutes of inactivity.
              </span>
            </div>
          </div>

          <button
            type="submit"
            className="login-form__submit"
            disabled={loginPending}
            aria-busy={loginPending}
          >
            {loginPending ? (
              <LoadingSpinner label="Authenticating session…" />
            ) : (
              <>
                <span>Connect Console</span>
                <span className="btn-arrow" aria-hidden="true">→</span>
              </>
            )}
          </button>
        </form>
      </div>
    </main>
  );
}
