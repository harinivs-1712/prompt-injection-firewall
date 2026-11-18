import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { SessionsList } from './pages/SessionsList';
import { SessionDetail } from './pages/SessionDetail';
import { Glossary } from './pages/Glossary';
import { Navbar } from './components/Navbar';

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <div className="app-layout">
      <Navbar />
      <div className="app-content">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/sessions" element={<SessionsList />} />
          <Route path="/sessions/:sessionId" element={<SessionDetail />} />
          <Route path="/glossary" element={<Glossary />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}
