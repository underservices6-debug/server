let currentTab = 'users';
let currentPage = 1;
const pageLimit = 25;
let currentStatus = '';
let currentSearch = '';
let selectedKeyId = null;

// api helper with csrf header
async function apiCall(url, options = {}) {
  options.headers = options.headers || {};
  options.headers['X-Requested-With'] = 'XMLHttpRequest';

  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = '/login';
    return null;
  }
  return res;
}

// verify auth on startup
async function checkAuth() {
  const res = await apiCall('/api/v1/admin/me');
  if (!res) return;

  const data = await res.json();
  if (data.must_change_password) {
    window.location.href = '/login';
    return;
  }

  switchTab('users');
}

function timeAgo(dateString) {
  if (!dateString) return '-';
  const now = Date.now();
  const past = new Date(dateString).getTime();
  const diffSec = Math.floor((now - past) / 1000);

  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function timeUntil(dateString) {
  if (!dateString) return '-';
  const now = Date.now();
  const target = new Date(dateString).getTime();
  const diffSec = Math.floor((target - now) / 1000);

  if (diffSec <= 0) return 'expired';
  if (diffSec < 3600) return `in ${Math.floor(diffSec / 60)}m`;
  if (diffSec < 86400) return `in ${Math.floor(diffSec / 3600)}h`;
  return `in ${Math.floor(diffSec / 86400)}d`;
}

function formatDate(dateString) {
  if (!dateString) return '-';
  const d = new Date(dateString);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function getAvatarColor(name) {
  const n = (name || '').toLowerCase();
  if (n.startsWith('z')) return 'avatar-purple';
  if (n.startsWith('p')) return 'avatar-magenta';
  if (n.startsWith('s')) return 'avatar-blue';
  if (n.startsWith('l')) return 'avatar-lime';
  if (n.startsWith('v')) return 'avatar-amber';
  const colors = ['avatar-pink', 'avatar-magenta', 'avatar-blue', 'avatar-lime', 'avatar-amber', 'avatar-purple'];
  let hash = 0;
  for (let i = 0; i < n.length; i++) {
    hash = n.charCodeAt(i) + ((hash << 5) - hash);
  }
  return colors[Math.abs(hash) % colors.length];
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, function (m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
  });
}

// view tab router
function switchTab(tab) {
  currentTab = tab;

  document.querySelectorAll('.sidebar-link').forEach((link) => {
    if (link.getAttribute('data-nav') === tab) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  document.querySelectorAll('.tab-view').forEach((v) => v.classList.add('hidden'));
  const targetView = document.getElementById(`view-${tab}`);
  if (targetView) targetView.classList.remove('hidden');

  const titleEl = document.getElementById('view-title');
  const subEl = document.getElementById('view-subtitle');
  const searchBox = document.getElementById('top-search-container');
  const exportBtn = document.getElementById('btn-export');
  const createBtn = document.getElementById('btn-open-create');
  const createBtnText = document.getElementById('btn-open-create-text');

  if (tab === 'users') {
    titleEl.textContent = 'Users';
    subEl.textContent = 'Registered user labels, customer records and assigned licenses';
    searchBox.style.display = 'flex';
    exportBtn.style.display = 'flex';
    createBtn.style.display = 'flex';
    createBtnText.textContent = 'New user';
    loadUsersView();
  } else if (tab === 'keys') {
    titleEl.textContent = 'License Keys';
    subEl.textContent = 'Manage 24-hour activation keys, validity windows, and activation states';
    searchBox.style.display = 'flex';
    exportBtn.style.display = 'flex';
    createBtn.style.display = 'flex';
    createBtnText.textContent = 'New key';
    loadKeysView();
  } else if (tab === 'devices') {
    titleEl.textContent = 'Active Devices';
    subEl.textContent = 'Hardware IDs (HWID) currently bound to activated client sessions';
    searchBox.style.display = 'flex';
    exportBtn.style.display = 'flex';
    createBtn.style.display = 'none';
    loadDevicesView();
  } else if (tab === 'logs') {
    titleEl.textContent = 'Security & Audit Logs';
    subEl.textContent = 'Real-time audit trail of activations, device resets, and admin actions';
    searchBox.style.display = 'flex';
    exportBtn.style.display = 'none';
    createBtn.style.display = 'none';
    loadLogsView();
  } else if (tab === 'settings') {
    titleEl.textContent = 'Settings & Administration';
    subEl.textContent = 'Manage administrator credentials, database backups, and system status';
    searchBox.style.display = 'none';
    exportBtn.style.display = 'none';
    createBtn.style.display = 'none';
    loadSettingsView();
  }
}

// users view loader
async function loadUsersView() {
  const tbody = document.getElementById('users-table-body');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:32px; color:var(--text-dim);">Loading users...</td></tr>';

  const res = await apiCall('/api/v1/admin/users-summary');
  if (!res || !res.ok) return;

  const data = await res.json();
  const users = data.users || [];

  document.getElementById('nav-count').textContent = users.length;

  const filtered = currentSearch
    ? users.filter((u) => u.username.toLowerCase().includes(currentSearch.toLowerCase()))
    : users;

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:32px; color:var(--text-dim);">No users found.</td></tr>';
    return;
  }

  filtered.forEach((u) => {
    const tr = document.createElement('tr');
    const avatarClass = getAvatarColor(u.username);
    const initial = (u.username || 'U').charAt(0).toUpperCase();

    tr.innerHTML = `
      <td>
        <div class="user-cell">
          <div class="avatar ${avatarClass}">${initial}</div>
          <div class="user-info">
            <span class="user-name">${escapeHtml(u.username)}</span>
            <span class="user-subtext">${u.active_keys > 0 ? 'Active customer' : 'Inactive'}</span>
          </div>
        </div>
      </td>
      <td>
        <span class="badge-mono">${u.total_keys} keys</span>
      </td>
      <td>
        <div class="status-indicator ${u.active_keys > 0 ? 'status-active' : 'status-unused'}">
          <span class="status-dot"></span>
          <span>${u.active_keys} active</span>
        </div>
      </td>
      <td>
        <span class="badge-mono" style="color:${u.active_devices > 0 ? '#10b981' : 'var(--text-dim)'};">
          ${u.active_devices} bound
        </span>
      </td>
      <td>
        <div class="date-cell">
          <span class="date-primary">${u.last_created ? formatDate(u.last_created) : '-'}</span>
          <span class="date-secondary">${u.last_created ? timeAgo(u.last_created) : ''}</span>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function openCreateForUser(username) {
  document.getElementById('create-username').value = username === 'Unassigned' ? '' : username;
  document.getElementById('create-note').value = '';
  document.getElementById('create-result').classList.add('hidden');
  document.getElementById('modal-create').classList.remove('hidden');
}

function filterKeysByUser(username) {
  currentSearch = username === 'Unassigned' ? '' : username;
  document.getElementById('search-input').value = currentSearch;
  switchTab('keys');
}

// keys view loader
async function loadKeysView() {
  const url = `/api/v1/admin/keys?page=${currentPage}&limit=${pageLimit}&status=${encodeURIComponent(currentStatus)}&search=${encodeURIComponent(currentSearch)}`;
  const res = await apiCall(url);
  if (!res) return;

  const data = await res.json();
  updateMetrics(data.stats);
  renderKeysTable(data.keys);
  renderPagination(data.total, data.page, data.limit);
}

function updateMetrics(stats) {
  if (!stats) return;

  document.getElementById('stat-total').textContent = stats.total || 0;
  document.getElementById('stat-sub-unused').textContent = `${stats.unused || 0} keys not yet redeemed`;

  document.getElementById('stat-active').textContent = stats.active || 0;
  const pct = stats.total ? Math.round(((stats.active || 0) / stats.total) * 100) : 0;
  document.getElementById('stat-sub-active').textContent = `${pct}% of all keys`;

  document.getElementById('stat-expiring').textContent = stats.expiring_soon || 0;
  document.getElementById('stat-unbound').textContent = stats.unbound || 0;

  // pill counters
  document.getElementById('pill-all-count').textContent = stats.total || 0;
  document.getElementById('pill-active-count').textContent = stats.active || 0;
  document.getElementById('pill-unused-count').textContent = stats.unused || 0;
  document.getElementById('pill-expired-count').textContent = stats.expired || 0;
  document.getElementById('pill-banned-count').textContent = stats.revoked || 0;
}

function renderKeysTable(keys) {
  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '';

  if (!keys || keys.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:36px; color:var(--text-dim);">No matching license keys found.</td></tr>';
    return;
  }

  keys.forEach((item) => {
    const tr = document.createElement('tr');

    let userName = 'unassigned';
    let userSub = 'Key #' + item.id;
    if (item.user_note) {
      const parts = item.user_note.split('|');
      userName = parts[0].trim();
      if (parts[1]) userSub = parts[1].trim();
    }

    const initial = userName.charAt(0).toUpperCase();
    const avatarClass = getAvatarColor(userName);
    const masked = item.masked_key;

    let hwidDisplay = '<span style="color:var(--text-dim);">Unbound</span>';
    if (item.device_id) {
      const head = item.device_id.slice(0, 8).toUpperCase();
      const tail = item.device_id.slice(-4).toUpperCase();
      hwidDisplay = `${head}..${tail}`;
    }

    const activatedMain = item.activated_at ? formatDate(item.activated_at) : '-';
    const activatedSub = item.activated_at ? timeAgo(item.activated_at) : '';

    let expiresMain = '-';
    let expiresSub = '';
    let progressBar = '';

    if (item.duration_seconds >= 365 * 86400 || item.duration_seconds === -1) {
      expiresMain = `<div class="lifetime-badge"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.178 8c5.096 0 5.096 8 0 8-5.095 0-7.133-8-12.739-8-4.585 0-4.585 8 0 8 5.606 0 7.644-8 12.74-8z"></path></svg> <span>Lifetime</span></div>`;
    } else if (item.expires_at) {
      expiresMain = formatDate(item.expires_at);
      const isPast = new Date(item.expires_at).getTime() <= Date.now();
      if (isPast) {
        expiresSub = timeAgo(item.expires_at);
        progressBar = `<div class="progress-bar-wrap"><div class="progress-bar-fill progress-bar-muted" style="width:100%;"></div></div>`;
      } else {
        expiresSub = timeUntil(item.expires_at);
        const totalDuration = (item.duration_seconds || 86400) * 1000;
        const remaining = new Date(item.expires_at).getTime() - Date.now();
        const pctLeft = Math.max(0, Math.min(100, Math.round((remaining / totalDuration) * 100)));
        progressBar = `<div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:${pctLeft}%;"></div></div>`;
      }
    }

    let statusClass = 'status-unused';
    let statusText = 'Unused';
    if (item.effective_status === 'ACTIVE') {
      statusClass = 'status-active';
      statusText = 'Active';
    } else if (item.effective_status === 'REVOKED') {
      statusClass = 'status-banned';
      statusText = 'Banned';
    } else if (item.effective_status === 'EXPIRED') {
      statusClass = 'status-expired';
      statusText = 'Expired';
    }

    tr.innerHTML = `
      <td>
        <div class="user-cell">
          <div class="avatar ${avatarClass}">${initial}</div>
          <div class="user-info">
            <span class="user-name">${escapeHtml(userName)}</span>
            <span class="user-subtext">${escapeHtml(userSub)}</span>
          </div>
        </div>
      </td>
      <td>
        <div class="badge-mono">
          <span>${masked}</span>
          <button class="badge-btn" onclick="copyText('${masked}', this)" title="Copy Masked Key">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>
      </td>
      <td>
        <div class="badge-mono">
          <span>${hwidDisplay}</span>
          ${item.device_id ? `
            <button class="badge-btn" onclick="copyText('${item.device_id}', this)" title="Copy Full HWID">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
            <button class="badge-btn" onclick="quickResetHWID(${item.id})" title="Reset HWID">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path>
              </svg>
            </button>
          ` : ''}
        </div>
      </td>
      <td>
        <div class="date-cell">
          <span class="date-primary">${activatedMain}</span>
          <span class="date-secondary">${activatedSub}</span>
        </div>
      </td>
      <td>
        <div class="date-cell">
          <span class="date-primary">${expiresMain}</span>
          <span class="date-secondary">${expiresSub}</span>
          ${progressBar}
        </div>
      </td>
      <td>
        <div class="status-indicator ${statusClass}">
          <span class="status-dot"></span>
          <span>${statusText}</span>
        </div>
      </td>
      <td>
        <button class="action-menu-btn" onclick="openMenu(event, ${item.id}, '${item.effective_status}')">&hellip;</button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

// devices view loader
async function loadDevicesView() {
  const tbody = document.getElementById('devices-table-body');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-dim);">Loading bound devices...</td></tr>';

  const res = await apiCall('/api/v1/admin/devices');
  if (!res || !res.ok) return;

  const data = await res.json();
  const devices = data.devices || [];

  const filtered = currentSearch
    ? devices.filter((d) =>
        (d.device_id && d.device_id.toLowerCase().includes(currentSearch.toLowerCase())) ||
        (d.username && d.username.toLowerCase().includes(currentSearch.toLowerCase())) ||
        (d.masked_key && d.masked_key.toLowerCase().includes(currentSearch.toLowerCase()))
      )
    : devices;

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-dim);">No active device bindings found.</td></tr>';
    return;
  }

  filtered.forEach((d) => {
    const tr = document.createElement('tr');
    const avatarClass = getAvatarColor(d.username);
    const initial = (d.username || 'U').charAt(0).toUpperCase();

    const shortHwid = `${d.device_id.slice(0, 8)}..${d.device_id.slice(-6)}`.toUpperCase();
    const isPast = d.expires_at ? new Date(d.expires_at).getTime() <= Date.now() : false;
    const expiresText = d.expires_at ? (isPast ? 'Expired' : timeUntil(d.expires_at)) : 'Lifetime';

    tr.innerHTML = `
      <td>
        <div class="badge-mono">
          <span>${shortHwid}</span>
          <button class="badge-btn" onclick="copyText('${d.device_id}', this)" title="Copy Full HWID">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>
      </td>
      <td>
        <div class="user-cell">
          <div class="avatar ${avatarClass}">${initial}</div>
          <div class="user-info">
            <span class="user-name">${escapeHtml(d.username)}</span>
          </div>
        </div>
      </td>
      <td>
        <div class="badge-mono">
          <span>${d.masked_key}</span>
        </div>
      </td>
      <td>
        <span style="font-size:12px; color:var(--text-muted); font-family:monospace;">${escapeHtml(d.ip_address || 'local')}</span>
      </td>
      <td>
        <div class="date-cell">
          <span class="date-primary">${d.activated_at ? formatDate(d.activated_at) : '-'}</span>
          <span class="date-secondary">${d.activated_at ? timeAgo(d.activated_at) : ''}</span>
        </div>
      </td>
      <td>
        <div class="date-cell">
          <span class="date-primary">${d.expires_at ? formatDate(d.expires_at) : '-'}</span>
          <span class="date-secondary">${expiresText}</span>
        </div>
      </td>
      <td>
        <div class="status-indicator ${d.effective_status === 'ACTIVE' ? 'status-active' : 'status-expired'}">
          <span class="status-dot"></span>
          <span>${d.effective_status === 'ACTIVE' ? 'Active' : 'Expired'}</span>
        </div>
      </td>
      <td style="text-align:right;">
        <button class="btn-secondary" onclick="quickResetHWID(${d.license_id})" title="Clear HWID binding">Reset HWID</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// logs view loader
async function loadLogsView() {
  const tbody = document.getElementById('logs-table-body');
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:32px; color:var(--text-dim);">Loading audit logs...</td></tr>';

  const res = await apiCall('/api/v1/admin/audit-logs?limit=100');
  if (!res || !res.ok) return;

  const data = await res.json();
  const logs = data.logs || [];

  const filtered = currentSearch
    ? logs.filter((l) =>
        (l.event_type && l.event_type.toLowerCase().includes(currentSearch.toLowerCase())) ||
        (l.actor && l.actor.toLowerCase().includes(currentSearch.toLowerCase())) ||
        (l.details && l.details.toLowerCase().includes(currentSearch.toLowerCase()))
      )
    : logs;

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:32px; color:var(--text-dim);">No audit logs recorded yet.</td></tr>';
    return;
  }

  filtered.forEach((log) => {
    const tr = document.createElement('tr');
    let eventClass = 'event-key-activated';
    const ev = (log.event_type || '').toUpperCase();
    if (ev.includes('VALIDAT')) eventClass = 'event-session-validated';
    else if (ev.includes('RESET')) eventClass = 'event-device-reset';
    else if (ev.includes('REVOKE')) eventClass = 'event-key-revoked';
    else if (ev.includes('DELETE')) eventClass = 'event-key-deleted';
    else if (ev.includes('LOGIN') || ev.includes('PASS')) eventClass = 'event-login';
    else if (ev.includes('GENERATE')) eventClass = 'event-key-generated';

    tr.innerHTML = `
      <td style="font-size:11px; color:var(--text-dim); white-space:nowrap;">
        <div>${formatDate(log.created_at)}</div>
        <div style="color:var(--text-dim); font-size:10px;">${timeAgo(log.created_at)}</div>
      </td>
      <td>
        <span class="badge-event ${eventClass}">${escapeHtml(log.event_type)}</span>
      </td>
      <td style="font-size:12px;">
        <span style="font-weight:600;">${escapeHtml(log.actor)}</span>
        <span style="color:var(--text-dim); font-size:11px;">(${escapeHtml(log.ip_address || 'local')})</span>
      </td>
      <td class="badge-mono" style="font-size:11px; word-break:break-all;">
        ${escapeHtml(log.details || '-')}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// settings view loader
async function loadSettingsView() {
  const meRes = await apiCall('/api/v1/admin/me');
  if (meRes && meRes.ok) {
    const me = await meRes.json();
    document.getElementById('settings-admin-username').textContent = me.username || 'admin';
  }

  const sysRes = await apiCall('/api/v1/admin/system-info');
  if (sysRes && sysRes.ok) {
    const sys = await sysRes.json();
    document.getElementById('settings-db-keys').textContent = sys.total_keys;
    document.getElementById('settings-db-sessions').textContent = sys.active_sessions;
    document.getElementById('settings-node-ver').textContent = sys.node_version;
    document.getElementById('settings-platform').textContent = sys.platform;
    const upHours = Math.floor(sys.uptime_seconds / 3600);
    const upMins = Math.floor((sys.uptime_seconds % 3600) / 60);
    document.getElementById('settings-uptime').textContent = `${upHours}h ${upMins}m`;
    document.getElementById('settings-audit-count').textContent = sys.total_audit_logs;
  }
}

// quick reset hwid helper
async function quickResetHWID(id) {
  if (!confirm(`Reset bound hardware ID for license #${id}?`)) return;
  const res = await apiCall(`/api/v1/admin/keys/${id}/reset-device`, { method: 'POST' });
  if (res && res.ok) {
    if (currentTab === 'devices') loadDevicesView();
    else if (currentTab === 'users') loadUsersView();
    else loadKeysView();
  } else {
    alert('Failed to reset HWID.');
  }
}

// clipboard copy
function copyText(text, btn) {
  navigator.clipboard.writeText(text);
  const orig = btn.innerHTML;
  btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
  setTimeout(() => {
    btn.innerHTML = orig;
  }, 1200);
}

// context action menu
function openMenu(e, id, status) {
  e.stopPropagation();
  selectedKeyId = id;
  const menu = document.getElementById('row-menu');
  menu.classList.remove('hidden');

  const rect = e.target.getBoundingClientRect();
  menu.style.top = `${rect.bottom + window.scrollY + 4}px`;
  menu.style.left = `${rect.left + window.scrollX - 120}px`;
}

document.addEventListener('click', () => {
  document.getElementById('row-menu').classList.add('hidden');
});

document.getElementById('row-menu').addEventListener('click', (e) => {
  e.stopPropagation();
});

document.getElementById('menu-act-reset').addEventListener('click', () => {
  const id = selectedKeyId;
  document.getElementById('row-menu').classList.add('hidden');
  if (id) quickResetHWID(id);
});

document.getElementById('menu-act-revoke').addEventListener('click', async () => {
  const id = selectedKeyId;
  document.getElementById('row-menu').classList.add('hidden');
  if (!id) return;
  if (!confirm(`Are you sure you want to ban / revoke license #${id}?`)) return;
  const res = await apiCall(`/api/v1/admin/keys/${id}/revoke`, { method: 'POST' });
  if (res && res.ok) {
    loadKeysView();
  } else {
    alert('Failed to revoke license.');
  }
});

document.getElementById('menu-act-delete').addEventListener('click', async () => {
  const id = selectedKeyId;
  document.getElementById('row-menu').classList.add('hidden');
  if (!id) return;
  if (!confirm(`Are you sure you want to permanently delete license #${id}? This cannot be undone.`)) return;
  const res = await apiCall(`/api/v1/admin/keys/${id}`, { method: 'DELETE' });
  if (res && res.ok) {
    loadKeysView();
  } else {
    alert('Failed to delete license.');
  }
});

// filter pills click
document.querySelectorAll('.pills-bar .pill').forEach((pill) => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.pills-bar .pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    currentStatus = pill.getAttribute('data-status');
    currentPage = 1;
    loadKeysView();
  });
});

// search input live filter
const searchInput = document.getElementById('search-input');
searchInput.addEventListener('input', () => {
  currentSearch = searchInput.value.trim();
  currentPage = 1;
  if (currentTab === 'users') loadUsersView();
  else if (currentTab === 'keys') loadKeysView();
  else if (currentTab === 'devices') loadDevicesView();
  else if (currentTab === 'logs') loadLogsView();
});

// '/' keyboard shortcut to search
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== searchInput) {
    e.preventDefault();
    searchInput.focus();
  }
});

// pagination
document.getElementById('btn-prev').addEventListener('click', () => {
  if (currentPage > 1) {
    currentPage--;
    loadKeysView();
  }
});

document.getElementById('btn-next').addEventListener('click', () => {
  currentPage++;
  loadKeysView();
});

function renderPagination(total, page, limit) {
  const totalPages = Math.ceil(total / limit) || 1;
  const start = total === 0 ? 0 : (page - 1) * limit + 1;
  const end = Math.min(page * limit, total);
  document.getElementById('page-indicator').textContent = `Showing ${start}-${end} of ${total}`;
  document.getElementById('btn-prev').disabled = page <= 1;
  document.getElementById('btn-next').disabled = page >= totalPages;
}

// export csv
document.getElementById('btn-export').addEventListener('click', () => {
  window.location.href = '/api/v1/admin/export.csv';
});

// modal generate key
document.getElementById('btn-open-create').addEventListener('click', () => {
  document.getElementById('create-result').classList.add('hidden');
  document.getElementById('form-create').reset();
  document.getElementById('modal-create').classList.remove('hidden');
});

document.querySelectorAll('[data-modal]').forEach((btn) => {
  btn.addEventListener('click', (e) => {
    const modalId = btn.getAttribute('data-modal');
    document.getElementById(modalId).classList.add('hidden');
    if (currentTab === 'users') loadUsersView();
    else loadKeysView();
  });
});

document.getElementById('form-create').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('create-username').value.trim();
  const note = document.getElementById('create-note').value.trim();
  const duration = parseInt(document.getElementById('create-duration').value, 10);
  const count = 1;
  const prefix = '';

  const combinedNote = note ? `${username} | ${note}` : username;

  const res = await apiCall('/api/v1/admin/keys/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ count, prefix, user_note: combinedNote, duration_seconds: duration })
  });

  if (!res || !res.ok) {
    alert('Failed to generate key.');
    return;
  }

  const data = await res.json();
  const outputBox = document.getElementById('output-keys');
  outputBox.value = data.keys.join('\n');
  document.getElementById('create-result').classList.remove('hidden');
});

document.getElementById('btn-copy-generated').addEventListener('click', () => {
  const box = document.getElementById('output-keys');
  box.select();
  navigator.clipboard.writeText(box.value);
  alert('Copied to clipboard.');
});

// sidebar link click events
document.querySelectorAll('.sidebar-link').forEach((link) => {
  link.addEventListener('click', (e) => {
    const nav = link.getAttribute('data-nav');
    if (nav) switchTab(nav);
  });
});

// refresh logs button
document.getElementById('btn-refresh-logs').addEventListener('click', () => {
  loadLogsView();
});

// change password form
document.getElementById('form-change-password').addEventListener('submit', async (e) => {
  e.preventDefault();
  const currentPass = document.getElementById('input-current-pass').value;
  const newPass = document.getElementById('input-new-pass').value;
  const confirmPass = document.getElementById('input-confirm-pass').value;
  const statusEl = document.getElementById('password-status');

  if (newPass !== confirmPass) {
    statusEl.style.color = '#ef4444';
    statusEl.textContent = 'New passwords do not match.';
    return;
  }

  statusEl.style.color = 'var(--text-muted)';
  statusEl.textContent = 'Updating password...';

  const res = await apiCall('/api/v1/admin/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPass, new_password: newPass })
  });

  if (res && res.ok) {
    statusEl.style.color = '#10b981';
    statusEl.textContent = 'Password updated successfully.';
    document.getElementById('form-change-password').reset();
  } else {
    const err = await res.json().catch(() => ({}));
    statusEl.style.color = '#ef4444';
    statusEl.textContent = err.error || 'Failed to update password.';
  }
});

// create hot backup button
document.getElementById('btn-create-backup').addEventListener('click', async () => {
  const statusEl = document.getElementById('backup-status');
  statusEl.style.color = 'var(--text-muted)';
  statusEl.textContent = 'Creating hot database snapshot...';

  const res = await apiCall('/api/v1/admin/backup', { method: 'POST' });
  if (res && res.ok) {
    const data = await res.json();
    statusEl.style.color = '#10b981';
    statusEl.textContent = `Backup created: ${data.filename}`;
  } else {
    statusEl.style.color = '#ef4444';
    statusEl.textContent = 'Backup failed.';
  }
});

// settings explicit logout button
document.getElementById('btn-settings-logout').addEventListener('click', async () => {
  if (confirm('Log out of KeyVault administrator session?')) {
    await apiCall('/api/v1/admin/logout', { method: 'POST' });
    window.location.href = '/login';
  }
});

// toggle sidebar for mobile
document.getElementById('btn-toggle-sidebar').addEventListener('click', () => {
  const sidebar = document.querySelector('.sidebar');
  if (sidebar.style.display === 'flex') {
    sidebar.style.display = '';
  } else {
    sidebar.style.display = 'flex';
  }
});

// start application
checkAuth();
