import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function Navbar() {
  const { logout } = useAuth();

  return (
    <nav className="navbar" aria-label="Main navigation">
      <div className="navbar__brand">
        <span className="navbar__title">Firewall Dashboard</span>
      </div>
      <ul className="navbar__links" role="list">
        <li>
          <NavLink to="/" end className={({ isActive }) => isActive ? 'navbar__link navbar__link--active' : 'navbar__link'}>
            Overview
          </NavLink>
        </li>
        <li>
          <NavLink to="/sessions" className={({ isActive }) => isActive ? 'navbar__link navbar__link--active' : 'navbar__link'}>
            Sessions
          </NavLink>
        </li>
        <li>
          <NavLink to="/glossary" className={({ isActive }) => isActive ? 'navbar__link navbar__link--active' : 'navbar__link'}>
            Glossary
          </NavLink>
        </li>
      </ul>
      <button className="navbar__logout" onClick={logout} aria-label="Log out and clear token">
        Log out
      </button>
    </nav>
  );
}
