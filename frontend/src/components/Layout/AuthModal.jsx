import React, { useEffect, useRef, useState } from 'react';
import { useThreatSentinel } from '../../context/ThreatSentinelContext';

// Minimal API token prompt. The token stays in sessionStorage for this tab
// only; it never goes into a URL or localStorage.
const AuthModal = () => {
  const { authModalOpen, closeAuthModal, authRequired, hasToken, signIn, signOut } = useThreatSentinel();
  const [token, setToken] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    if (authModalOpen) {
      setToken('');
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [authModalOpen]);

  useEffect(() => {
    if (!authModalOpen) return undefined;
    const onKey = (e) => e.key === 'Escape' && closeAuthModal();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [authModalOpen, closeAuthModal]);

  if (!authModalOpen) return null;

  const submit = (e) => {
    e.preventDefault();
    if (token.trim()) signIn(token);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 px-4" role="dialog" aria-modal="true" aria-labelledby="auth-title">
      <form onSubmit={submit} className="panel w-full max-w-md">
        <div className="panel-head">
          <h2 id="auth-title" className="label">Session / API token</h2>
          <button type="button" onClick={closeAuthModal} className="font-mono text-xs text-muted hover:text-ink" aria-label="Close">ESC</button>
        </div>
        <div className="px-4 py-4 space-y-4">
          {authRequired && (
            <p className="border border-high/40 bg-high/10 px-3 py-2 font-mono text-xs text-high">
              The API answered 401. Enter the server's SECRET_KEY to continue.
            </p>
          )}
          <p className="text-sm text-inksoft">
            The token is kept in this tab's session storage and sent as a Bearer header.
            It is cleared when the tab closes or you sign out. With <span className="num">DEBUG=true</span> on the
            server, REST calls work without a token; the live metrics WebSocket always needs one.
          </p>
          <label className="block">
            <span className="label block mb-1.5">API token</span>
            <input
              ref={inputRef}
              type="password"
              autoComplete="off"
              spellCheck={false}
              className="input-field w-full"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="SECRET_KEY"
            />
          </label>
          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            {hasToken ? (
              <button type="button" className="btn-danger" onClick={signOut}>Sign out</button>
            ) : <span />}
            <div className="flex gap-2">
              <button type="button" className="btn-secondary" onClick={closeAuthModal}>Cancel</button>
              <button type="submit" className="btn-primary" disabled={!token.trim()}>Use token</button>
            </div>
          </div>
        </div>
      </form>
    </div>
  );
};

export default AuthModal;
