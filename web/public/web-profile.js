'use strict';

// Resolve identity before the workbench reads browser preferences. Desktop keeps its existing storage keys.
(() => {
  const profile = { web: false, user: null, role: 'administrator', permissions: { read: true, review: true, manageFindings: true, manageSettings: true, manageMembers: true }, ready: null };
  let identityResolved = false;
  function storageKey(key) {
    if (!identityResolved) throw new Error('Profile is still loading.');
    return profile.web ? `threatlint.profile.${profile.user.id}.${key}` : key;
  }
  const scoped = storageName => ({
    getItem(key) { return window[storageName].getItem(storageKey(key)); },
    setItem(key, value) { window[storageName].setItem(storageKey(key), value); },
    removeItem(key) { window[storageName].removeItem(storageKey(key)); },
  });
  profile.storage = scoped('localStorage');
  profile.sessionStorage = scoped('sessionStorage');
  profile.url = url => {
    if (!profile.web || !identityResolved) return url;
    let target;
    try { target = new URL(String(url), location.href); } catch { return url; }
    if (target.origin !== location.origin || !target.pathname.startsWith('/api/')) return url;
    target.searchParams.set('_profile', profile.user.id);
    return `${target.pathname}${target.search}${target.hash}`;
  };
  profile.fetch = async (url, options = {}) => {
    if (!profile.web || !identityResolved) return fetch(url, options);
    let target;
    try { target = new URL(typeof url === 'string' ? url : url?.url || String(url), location.href); }
    catch { return fetch(url, options); }
    const protectedRequest = target.origin === location.origin && (target.pathname.startsWith('/api/') || target.pathname === '/auth/logout');
    if (!protectedRequest) return fetch(url, options);
    const headers = new Headers(options.headers || url?.headers);
    headers.set('X-Threatlint-Profile', profile.user.id);
    const response = await fetch(url, { ...options, headers });
    if (response.status === 409) profile.check().catch(() => {});
    return response;
  };
  function loginPath() {
    const company = profile.user?.company?.slug || /^\/c\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])(?:\/|$)/.exec(location.pathname || '/')?.[1];
    return company ? `/c/${company}/login` : '/login';
  }
  profile.loginPath = loginPath;
  const redirect = () => { location.replace(loginPath()); };
  let channel;
  try { channel = new BroadcastChannel('threatlint-auth'); } catch { /* older browsers still recheck on focus */ }
  channel?.addEventListener('message', () => { if (profile.web) location.reload(); });
  profile.check = async () => {
    if (!profile.web) return true;
    const response = await fetch('/auth/session', { cache: 'no-store', credentials: 'same-origin' });
    if (response.status === 401) { redirect(); return false; }
    if (!response.ok) return false;
    const current = await response.json();
    if (current.user?.id !== profile.user.id) { location.reload(); return false; }
    if (current.user.company?.slug !== profile.user.company?.slug) {
      profile.user = current.user;
      const slug = current.user.company?.slug;
      const canonical = typeof slug === 'string' && /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(slug) ? `/c/${slug}/` : '/';
      location.replace(`${canonical}${location.hash || ''}`);
      return false;
    }
    if (current.role && current.role !== profile.role) { location.reload(); return false; }
    if (current.user.company?.name !== profile.user.company?.name) { profile.user = current.user; location.reload(); return false; }
    return true;
  };
  function showIdentity() {
    if (!profile.web || !profile.user) return;
    document.body.classList.add('web-workbench');
    const setCopy = (id, text) => { const node = document.getElementById(id); if (node) node.textContent = text; };
    setCopy('settings-description', 'Choose your models, connect the tools your organization uses, and manage access. Organization integrations are shared with your company; model and scanner preferences stay in your profile. Saved secrets are never shown again.');
    setCopy('settings-provider-note', 'Choose a provider and model ID. Use a session key or a credential configured in your personal profile runtime.');
    setCopy('settings-model-privacy', 'Model API keys entered here remain in memory for this session. Non-secret model preferences and report history are saved to your profile on the server. Integration credentials saved in the connection sections are also kept in your profile. A remote model provider receives prompts and the source inspected by its agents.');
    setCopy('model-server-note', 'This URL is reached from your profile runtime on the server. Loopback refers to that runtime, so it cannot reach a model running only on your laptop. Use an accessible HTTPS model server.');
    setCopy('github-private-key-note', 'Use a private key file provisioned inside your profile runtime. Only its path is saved; the key stays in that file. This server cannot read a path on your laptop. Leave fields blank to keep saved values.');
    setCopy('repository-description', 'Open source already available in your personal profile runtime, or check out a repository from Connect source. This browser cannot browse folders on your laptop.');
    setCopy('repo-path-label', 'Profile folder');
    setCopy('repository-history-note', 'Report history is saved to your profile on the server.');
    setCopy('runtime-auth-storage-note', 'Auth material is sent to your profile runtime on the server for this scan and is not persisted by this interface. Imported browser state replays cookies only. Sanitized evidence can be shared with specialists.');
    const repoDescription = document.getElementById('onboarding-repo-description');
    if (repoDescription?.firstChild) repoDescription.firstChild.textContent = 'A profile folder, or ';
    const browserButton = document.getElementById('browse-repository');
    if (browserButton) browserButton.textContent = 'Browse profile…';
    const repoPath = document.getElementById('repo-path');
    if (repoPath) repoPath.placeholder = '/home/threatlint/path/to/repository';
    const metricsExport = document.getElementById('metrics-export');
    if (metricsExport) metricsExport.href = profile.url(metricsExport.href);
    const account = document.getElementById('web-profile');
    const name = document.getElementById('web-profile-name');
    const signout = document.getElementById('web-signout');
    if (!account || !name || !signout) return;
    account.hidden = false;
    name.textContent = `${profile.user.company ? `${profile.user.company.name} · ` : ''}${profile.user.displayName || profile.user.email}`;
    name.title = `${profile.user.email}${profile.user.company ? ` · ${profile.user.company.name} (${profile.user.company.slug})` : ''}`;
    const avatar = document.getElementById('profile-avatar');
    if (avatar) { avatar.textContent = (profile.user.displayName || profile.user.email).slice(0, 2).toUpperCase(); avatar.setAttribute('aria-label', profile.user.email); }
    signout.addEventListener('click', async () => {
      signout.disabled = true;
      let sessionRevoked = false;
      try {
        const response = await profile.fetch('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', credentials: 'same-origin' });
        if (!response.ok && response.status !== 401) throw new Error('Sign out could not complete. Please try again.');
        sessionRevoked = true;
        channel?.postMessage({ type: 'session-changed' });
        await window.ThreatlintAuth.logout();
      } catch (error) {
        if (sessionRevoked) { location.replace(`${loginPath()}?notice=provider-logout`); return; }
        signout.disabled = false; document.getElementById('web-profile-error').textContent = error.message;
      }
    });
  }
  profile.ready = (async () => {
    // Native desktop is an individual local application, even when no network is available.
    if (window.threatlintDesktop) { identityResolved = true; return; }
    // The Electron/local server has no auth endpoint and serves its app HTML instead.
    const response = await fetch('/auth/session', { cache: 'no-store', credentials: 'same-origin' });
    if (response.status === 401) { redirect(); throw new Error('Sign in to continue.'); }
    if (response.status === 404 || !response.headers.get('content-type')?.includes('application/json')) { identityResolved = true; return; }
    if (!response.ok) throw new Error('Your profile could not be loaded. Reload to try again.');
    const data = await response.json();
    if (!data.web || !data.user?.id) throw new Error('Your profile could not be loaded. Reload to try again.');
    profile.web = true; profile.user = data.user;
    profile.role = data.role || 'viewer';
    profile.permissions = data.permissions || { read: true, review: false, manageFindings: false, manageSettings: false, manageMembers: false };
    identityResolved = true;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', showIdentity, { once: true });
    else showIdentity();
    window.addEventListener('focus', () => profile.check().catch(() => {}));
    document.addEventListener('visibilitychange', () => { if (!document.hidden) profile.check().catch(() => {}); });
    setInterval(() => profile.check().catch(() => {}), 60_000);
  })();
  // app.js handles a failed identity lookup without using unscoped browser data.
  profile.ready.catch(() => {});
  window.ThreatlintProfile = profile;
})();
