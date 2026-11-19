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
    // Clear the input field regardless of outcome
    if (tokenRef.current) tokenRef.current.value = '';
  };

  return (
    <main className="login-page" aria-labelledby="login-heading">
      <div className="login-card">
        <h1 id="login-heading" className="login-card__title">
          Firewall Dashboard
        </h1>
        <p className="login-card__subtitle">Enter your viewer token to connect.</p>

        {loginError && <ErrorBanner message={loginError} />}

        <form onSubmit={handleSubmit} className="login-form" noValidate>
          <div className="login-form__field">
            <label htmlFor="login-url" className="login-form__label">
              Server URL
            </label>
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

          <div className="login-form__field">
            <label htmlFor="login-token" className="login-form__label">
              Bearer Token
            </label>
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
              placeholder="Token (never stored)"
              aria-describedby="login-token-hint"
            />
            <span id="login-token-hint" className="login-form__hint">
              Token is held in memory only and cleared after 15 minutes of inactivity.
            </span>
          </div>

          <button
            type="submit"
            className="login-form__submit"
            disabled={loginPending}
            aria-busy={loginPending}
          >
            {loginPending ? <LoadingSpinner label="Connecting…" /> : 'Connect'}
          </button>
        </form>
      </div>
    </main>
  );
}
