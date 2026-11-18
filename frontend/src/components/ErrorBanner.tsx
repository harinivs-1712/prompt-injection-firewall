interface ErrorBannerProps {
  message: string;
  code?: string;
  onDismiss?: () => void;
}

export function ErrorBanner({ message, code, onDismiss }: ErrorBannerProps) {
  return (
    <div className="error-banner" role="alert" aria-live="polite">
      <span className="error-banner__icon" aria-hidden="true">⚠</span>
      <span className="error-banner__message">
        {message}
        {code && <span className="error-banner__code"> [{code}]</span>}
      </span>
      {onDismiss && (
        <button className="error-banner__dismiss" onClick={onDismiss} aria-label="Dismiss error">
          ✕
        </button>
      )}
    </div>
  );
}
