import { useState, FormEvent } from 'react';
import { analyzeHeaders, type SecurityAnalysisReport } from './utils/security';
import './index.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  const [headers, setHeaders] = useState<string>('');
  const [report, setReport] = useState<SecurityAnalysisReport | null>(null);

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    if (username.toLowerCase() !== 'vedantpatil') {
      setLoginError('Invalid credentials');
      return;
    }

    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Target Hash for the requested password (we never store plaintext)
      if (hashHex === 'ff43f674a8d1d838705c70f5dd43a868ea52c208d9b55853d14478d0b2a6a3e2') {
        setIsAuthenticated(true);
        setLoginError('');
      } else {
        setLoginError('Invalid credentials');
      }
    } catch (err) {
      setLoginError('Crypto error, please use a modern browser.');
    }
  };

  const handleAnalyze = () => {
    if (!headers.trim()) return;
    const analysis = analyzeHeaders(headers);
    setReport(analysis);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'secure': return 'var(--success)';
      case 'warning': return 'var(--warning)';
      case 'missing': return 'var(--danger)';
      case 'insecure': return 'var(--danger)';
      default: return 'var(--info)';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'secure': return <span className="badge badge-success">Secure</span>;
      case 'warning': return <span className="badge badge-warning">Warning</span>;
      case 'missing': return <span className="badge badge-danger">Missing</span>;
      case 'insecure': return <span className="badge badge-danger">Insecure</span>;
      default: return <span className="badge badge-info">Info</span>;
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="login-container">
        <div className="login-box glass-panel fade-in">
          <div className="logo-glow login-glow"></div>
          <h2>Header Shield Access</h2>
          <p className="subtitle">Please authenticate to continue</p>
          
          <form onSubmit={handleLogin} className="login-form">
            {loginError && <p className="login-error">{loginError}</p>}
            <div className="form-group">
              <label>Username</label>
              <input 
                type="text" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                required 
              />
            </div>
            <button type="submit" className="analyze-btn login-btn">Login</button>
          </form>
        </div>
        <footer className="copyright">© Copyright to Vedant Patil</footer>
      </div>
    );
  }

  return (
    <div className="app-container">
      <header className="header-section">
        <div className="logo-glow"></div>
        <h1>Header Shield</h1>
        <p>Advanced HTTP Header Security Analyzer</p>
        <button className="logout-button" onClick={() => setIsAuthenticated(false)}>Logout</button>
      </header>

      <main className="main-content">
        <section className="input-section glass-panel fade-in">
          <h2>Paste Headers</h2>
          <p className="subtitle">Copy and paste raw HTTP headers from your browser, burp suite, or curl</p>
          <textarea 
            className="header-input"
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder={"HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000; includeSubDomains"}
          />
          <button className="analyze-btn" onClick={handleAnalyze}>
            Analyze Security
          </button>
        </section>

        {report && (
          <section className="results-section glass-panel fade-in">
            <div className="score-header">
              <div className="score-label">
                <h2>Security Score</h2>
                <p>Based on modern web security best practices</p>
              </div>
              <div 
                className="score-circle"
                style={{
                  borderColor: report.score > 80 ? 'var(--success)' : report.score > 50 ? 'var(--warning)' : 'var(--danger)',
                  color: report.score > 80 ? 'var(--success)' : report.score > 50 ? 'var(--warning)' : 'var(--danger)',
                  boxShadow: `0 0 20px ${report.score > 80 ? 'var(--success-bg)' : report.score > 50 ? 'var(--warning-bg)' : 'var(--danger-bg)'}`
                }}
              >
                {report.score}
              </div>
            </div>

            <div className="results-list">
              {report.results.map((result, idx) => (
                <div key={idx} className="result-card" style={{ borderLeftColor: getStatusColor(result.status) }}>
                  <div className="card-header">
                    <h3 className="header-name">{result.name}</h3>
                    {getStatusBadge(result.status)}
                  </div>
                  <p className="description">{result.description}</p>
                  
                  {result.value && (
                    <div className="value-box">
                      <strong>Current Value:</strong> <code>{result.value}</code>
                    </div>
                  )}
                  
                  {result.recommendation && (
                    <div className="recommendation-box">
                      <strong>Recommendation:</strong> {result.recommendation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </main>

      <footer className="copyright">© Copyright to Vedant Patil</footer>
    </div>
  );
}

export default App;
