/* ============================================================
   ExpoVote Live – Admin Panel JavaScript
   ============================================================ */

const socket = io();

// ── State ──────────────────────────────────────────────────
let adminToken = sessionStorage.getItem('expovote_admin_token') || null;
let dashboardData = { projects: [], settings: {}, totalVotes: 0, uniqueIPs: 0 };

// ── Toast ────────────────────────────────────────────────
function showToast(msg, type = 'info', dur = 3000) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = `toast ${type} show`;
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.className = 'toast'; }, dur);
}

// ── API Helper ────────────────────────────────────────────
async function api(method, path, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json', 'x-admin-token': adminToken || '' }
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
}

// ── Auth ──────────────────────────────────────────────────
async function checkAuth() {
    if (!adminToken) { showLoginOverlay(); return; }
    try {
        await api('GET', '/api/admin/dashboard');
        showAdminLayout();
        loadDashboard();
    } catch {
        adminToken = null;
        sessionStorage.removeItem('expovote_admin_token');
        showLoginOverlay();
    }
}

function showLoginOverlay() {
    document.getElementById('loginOverlay').style.display = 'flex';
    document.getElementById('adminLayout').style.display = 'none';
}
function showAdminLayout() {
    document.getElementById('loginOverlay').style.display = 'none';
    document.getElementById('adminLayout').style.display = 'flex';
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const btn = document.getElementById('loginBtn');
    const errEl = document.getElementById('loginError');
    errEl.style.display = 'none';
    btn.disabled = true; btn.textContent = 'Logging in…';

    try {
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.token) {
            adminToken = data.token;
            sessionStorage.setItem('expovote_admin_token', adminToken);
            showAdminLayout();
            loadDashboard();
        } else {
            errEl.textContent = data.error || 'Login failed.';
            errEl.style.display = 'block';
        }
    } catch {
        errEl.textContent = 'Server error. Is the server running?';
        errEl.style.display = 'block';
    } finally {
        btn.disabled = false; btn.textContent = 'Login →';
    }
});

async function adminLogout() {
    try { await api('POST', '/api/admin/logout'); } catch { }
    adminToken = null;
    sessionStorage.removeItem('expovote_admin_token');
    showLoginOverlay();
}

// ── Tab Navigation ────────────────────────────────────────
function showTab(tabName) {
    ['dashboard', 'projects', 'voting', 'settings'].forEach(t => {
        document.getElementById(`tab${capitalize(t)}`).style.display = t === tabName ? 'block' : 'none';
        document.getElementById(`nav${capitalize(t)}`).classList.toggle('active', t === tabName);
    });
    if (tabName === 'projects') renderProjectsAdmin();
    if (tabName === 'settings') loadSettings();
}

function capitalize(str) { return str.charAt(0).toUpperCase() + str.slice(1); }

// ── Load Dashboard ────────────────────────────────────────
async function loadDashboard() {
    try {
        dashboardData = await api('GET', '/api/admin/dashboard');
        updateDashboardUI();
        updateVotingStatusUI();
    } catch (err) {
        showToast('Failed to load dashboard: ' + err.message, 'error');
    }
}

function updateDashboardUI() {
    const { projects, totalVotes, uniqueIPs } = dashboardData;
    document.getElementById('statTotalVotes').textContent = totalVotes;
    document.getElementById('statProjects').textContent = projects.length;
    document.getElementById('statUniqueIPs').textContent = uniqueIPs;

    const leader = [...projects].sort((a, b) => b.voteCount - a.voteCount)[0];
    document.getElementById('statLeader').textContent = leader ? leader.name : '—';

    // Mini leaderboard
    const sorted = [...projects].sort((a, b) => b.voteCount - a.voteCount);
    const MEDALS = ['🥇', '🥈', '🥉'];
    document.getElementById('miniLeaderboard').innerHTML = sorted.length === 0
        ? '<div style="color:var(--text-muted);padding:1rem;text-align:center">No projects yet.</div>'
        : sorted.map((p, i) => `
        <div class="mini-lb-row">
          <span class="mini-lb-rank">${MEDALS[i] || (i + 1)}</span>
          <span class="mini-lb-name">${escHtml(p.name)}</span>
          <span class="mini-lb-votes">${p.voteCount} votes</span>
        </div>`).join('');
}

function updateVotingStatusUI() {
    const { settings } = dashboardData;
    const vcStatus = document.getElementById('vcStatus');
    const statusDot = document.getElementById('statusDot');

    if (vcStatus) {
        if (settings.winnerDeclared) {
            vcStatus.textContent = '🏆 Winner Declared – Voting Locked';
        } else if (settings.votingActive) {
            vcStatus.textContent = '✅ Voting is LIVE';
        } else {
            vcStatus.textContent = '⏸ Voting is PAUSED';
        }
    }
}

// ── Voting Controls ───────────────────────────────────────
async function toggleVoting(active) {
    try {
        await api('POST', '/api/admin/settings', { votingActive: active });
        dashboardData.settings.votingActive = active;
        showToast(active ? '✅ Voting started!' : '⏹ Voting stopped.', 'success');
        updateVotingStatusUI();
    } catch (err) {
        showToast('Error: ' + err.message, 'error');
    }
}

async function declareWinner() {
    showConfirm(
        '🏆', 'Declare Winner?',
        'This will lock voting, show the winner on the leaderboard, and trigger confetti! This cannot be undone easily.',
        async () => {
            try {
                const data = await api('POST', '/api/admin/declare-winner');
                showToast(`🏆 Winner declared: ${data.winner.name}!`, 'success', 5000);
                loadDashboard();
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }
    );
}

async function resetVoting() {
    showConfirm(
        '⚠️', 'Reset All Votes?',
        'This will permanently delete ALL vote records and reset all project vote counts to 0. This cannot be undone!',
        async () => {
            try {
                await api('POST', '/api/admin/reset');
                showToast('✅ System reset complete.', 'success');
                loadDashboard();
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        },
        'Reset'
    );
}

// ── Projects Admin ────────────────────────────────────────
function renderProjectsAdmin() {
    const list = document.getElementById('projectsAdminList');
    const { projects } = dashboardData;
    if (projects.length === 0) {
        list.innerHTML = `<div style="text-align:center;padding:3rem;color:var(--text-muted)">
      No projects yet. Click <strong>+ Add Project</strong> to get started.
    </div>`;
        return;
    }
    list.innerHTML = projects.map(p => `
    <div class="project-admin-row" id="par-${p.id}">
      <div class="par-info">
        <div class="par-name">${escHtml(p.name)}</div>
        <div class="par-team">👥 ${escHtml(p.team)} · <em>${escHtml(p.category || 'General')}</em></div>
      </div>
      <div class="par-votes">🗳️ ${p.voteCount}</div>
      <div class="par-actions">
        <button class="btn-icon btn-icon-edit" title="Edit" onclick="openEditProjectModal('${p.id}')">✏️</button>
        <button class="btn-icon btn-icon-del" title="Delete" onclick="deleteProject('${p.id}', '${escHtml(p.name)}')">🗑️</button>
      </div>
    </div>`).join('');
}

// ── Project Modal ─────────────────────────────────────────
function openAddProjectModal() {
    document.getElementById('projectModalTitle').textContent = 'Add New Project';
    document.getElementById('projectSubmitBtn').textContent = 'Add Project';
    document.getElementById('projectEditId').value = '';
    document.getElementById('projectForm').reset();
    document.getElementById('projectModal').style.display = 'flex';
}

function openEditProjectModal(id) {
    const p = dashboardData.projects.find(x => x.id === id);
    if (!p) return;
    document.getElementById('projectModalTitle').textContent = 'Edit Project';
    document.getElementById('projectSubmitBtn').textContent = 'Save Changes';
    document.getElementById('projectEditId').value = id;
    document.getElementById('projectName').value = p.name;
    document.getElementById('projectTeam').value = p.team;
    document.getElementById('projectCategory').value = p.category || '';
    document.getElementById('projectDesc').value = p.description || '';
    document.getElementById('projectModal').style.display = 'flex';
}

function closeProjectModal() {
    document.getElementById('projectModal').style.display = 'none';
}

document.getElementById('projectForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('projectEditId').value;
    const payload = {
        name: document.getElementById('projectName').value.trim(),
        team: document.getElementById('projectTeam').value.trim(),
        category: document.getElementById('projectCategory').value.trim(),
        description: document.getElementById('projectDesc').value.trim()
    };
    const btn = document.getElementById('projectSubmitBtn');
    btn.disabled = true; btn.textContent = 'Saving…';

    try {
        if (id) {
            await api('PUT', `/api/admin/projects/${id}`, payload);
            showToast('✅ Project updated!', 'success');
        } else {
            await api('POST', '/api/admin/projects', payload);
            showToast('✅ Project added!', 'success');
        }
        closeProjectModal();
        await loadDashboard();
        renderProjectsAdmin();
    } catch (err) {
        showToast('Error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = id ? 'Save Changes' : 'Add Project';
    }
});

async function deleteProject(id, name) {
    showConfirm('🗑️', `Delete "${name}"?`, 'This will also remove all votes for this project.', async () => {
        try {
            await api('DELETE', `/api/admin/projects/${id}`);
            showToast('✅ Project deleted.', 'success');
            await loadDashboard();
            renderProjectsAdmin();
        } catch (err) {
            showToast('Error: ' + err.message, 'error');
        }
    });
}

// ── Settings Tab ──────────────────────────────────────────
function loadSettings() {
    const { settings } = dashboardData;
    document.getElementById('settingEventName').value = settings.eventName || '';
    document.getElementById('settingMaxVotes').value = settings.maxVotesPerIP || 3;
}

async function saveSettings() {
    const eventName = document.getElementById('settingEventName').value.trim();
    const maxVotesPerIP = parseInt(document.getElementById('settingMaxVotes').value);
    try {
        await api('POST', '/api/admin/settings', { eventName, maxVotesPerIP });
        dashboardData.settings.eventName = eventName;
        dashboardData.settings.maxVotesPerIP = maxVotesPerIP;
        showToast('✅ Settings saved!', 'success');
    } catch (err) {
        showToast('Error: ' + err.message, 'error');
    }
}

// ── Confirm Modal ─────────────────────────────────────────
let _confirmCallback = null;
function showConfirm(emoji, title, msg, onConfirm, btnLabel = 'Confirm') {
    _confirmCallback = onConfirm;
    document.getElementById('confirmEmoji').textContent = emoji;
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMsg').textContent = msg;
    document.getElementById('confirmOkBtn').textContent = btnLabel;
    document.getElementById('confirmModal').style.display = 'flex';
}
function closeConfirm() {
    document.getElementById('confirmModal').style.display = 'none';
    _confirmCallback = null;
}
document.getElementById('confirmOkBtn').addEventListener('click', async () => {
    if (_confirmCallback) { await _confirmCallback(); }
    closeConfirm();
});

// ── Socket real-time ──────────────────────────────────────
socket.on('leaderboard-update', (data) => {
    dashboardData.projects = data.leaderboard;
    dashboardData.settings = data.settings;
    dashboardData.totalVotes = data.totalVotes;
    updateDashboardUI();
    updateVotingStatusUI();
});

socket.on('winner-declared', (data) => {
    dashboardData.settings.winnerDeclared = true;
    dashboardData.settings.votingActive = false;
    updateVotingStatusUI();
    showToast(`🏆 Winner: ${data.winner.name}`, 'success', 5000);
});

socket.on('system-reset', (data) => {
    dashboardData.settings.winnerDeclared = false;
    dashboardData.settings.votingActive = false;
    dashboardData.totalVotes = 0;
    dashboardData.projects.forEach(p => { p.voteCount = 0; });
    updateDashboardUI();
    updateVotingStatusUI();
});

// ─── Utility ──────────────────────────────────────────────
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── Boot ──────────────────────────────────────────────────
checkAuth();
