import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Landing from './components/Landing';
import Dashboard from './components/Dashboard';
import AttackerTerminal from './components/AttackerTerminal';
import Sessions from './components/Sessions';

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/dashboard/:sessionId" element={<Dashboard />} />
        <Route path="/attacker" element={<AttackerTerminal />} />
      </Routes>
    </Router>
  );
}