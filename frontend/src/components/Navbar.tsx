import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function Navbar() {
  const { logout, baseUrl } = useAuth();

  return (
    <header className="navbar" aria-label="Main navigation">
      <div className="navbar__brand">
        <div className="navbar__logo">
          <svg
            className="navbar__logo-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </div>
        <div className="navbar__brand-text">
          <span className="navbar__title">FIREWALL</span>
          <span className="navbar__subtitle">CONTROL PLANE</span>
        </div>
        <div className="navbar__status" title={`Connected to ${baseUrl}`}>
          <span className="navbar__status-dot" aria-hidden="true" />
          <span className="navbar__status-text">AUDIT ACTIVE</span>
        </div>
      </div>

      <nav className="navbar__nav">
        <ul className="navbar__links" role="list">
          <li>
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                isActive ? 'navbar__link navbar__link--active' : 'navbar__link'
              }
            >
              <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <rect x="3" y="3" width="7" height="9" />
                <rect x="14" y="3" width="7" height="5" />
                <rect x="14" y="12" width="7" height="9" />
                <rect x="3" y="16" width="7" height="5" />
              </svg>
              <span>Overview</span>
            </NavLink>
          </li>
          <li>
            <NavLink
              to="/sessions"
              className={({ isActive }) =>
                isActive ? 'navbar__link navbar__link--active' : 'navbar__link'
              }
            >
              <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <polyline points="10 9 9 9 8 9" />
              </svg>
              <span>Sessions</span>
            </NavLink>
          </li>
          <li>
            <NavLink
              to="/glossary"
              className={({ isActive }) =>
                isActive ? 'navbar__link navbar__link--active' : 'navbar__link'
              }
            >
              <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
              </svg>
              <span>Glossary</span>
            </NavLink>
          </li>
        </ul>
      </nav>

      <div className="navbar__actions">
        <button className="navbar__logout" onClick={logout} aria-label="Log out and clear token">
          <svg className="logout-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          <span>Disconnect</span>
        </button>
      </div>
    </header>
  );
}
