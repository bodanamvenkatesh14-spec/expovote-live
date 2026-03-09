/* ============================================================
   ExpoVote Live – Voter Page JavaScript
   ============================================================ */

const socket = io();

// ── State ──────────────────────────────────────────────────
let state = {
    projects: [],
    settings: {},
    usedVotes: 0,
    maxVotes: 3,
    remaining: 3,
    votedProjectIds: [],
    votingInFlight: false
};

// ── localStorage helpers ─────────────────────────────────
// Used as a secondary layer (in addition to server IP tracking)
function lsGetVotes() {
    try { return JSON.parse(localStorage.getItem('expovote_votes') || '[]'); }
    catch { return []; }
}
function lsAddVote(projectId) {
    const v = lsGetVotes();
    v.push({ projectId, ts: Date.now() });
    localStorage.setItem('expovote_votes', JSON.stringify(v));
}
function lsClear() { localStorage.removeItem('expovote_votes'); }

// ── Particles ────────────────────────────────────────────
function spawnParticles() {
    const container = document.getElementById('bgParticles');
    for (let i = 0; i < 18; i++) {
        const el = document.createElement('div');
        el.className = 'particle';
        const size = 80 + Math.random() * 160;
        el.style.cssText = `
      width:${size}px; height:${size}px;
      left:${Math.random() * 100}%;
      animation-duration:${12 + Math.random() * 16}s;
      animation-delay:${-Math.random() * 20}s;
    `;
        container.appendChild(el);
    }
}

// ── Toast ────────────────────────────────────────────────
function showToast(msg, type = 'info', dur = 3000) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = `toast ${type} show`;
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.className = 'toast'; }, dur);
}

// ── Modal ────────────────────────────────────────────────
function showSuccessModal(projectName, remaining) {
    document.getElementById('successEmoji').textContent = remaining > 0 ? '🎉' : '🏁';
    document.getElementById('successTitle').textContent = 'Vote Registered!';
    document.getElementById('successMsg').textContent = `Your vote for "${projectName}" has been counted.`;
    document.getElementById('remainingVotesDisplay').textContent =
        remaining > 0
            ? `You have ${remaining} vote${remaining !== 1 ? 's' : ''} remaining.`
            : '🏁 You have used all your votes. Thank you!';
    document.getElementById('successModal').style.display = 'flex';
}
function closeModal() {
    document.getElementById('successModal').style.display = 'none';
    // If no votes remain, show final message
    if (state.remaining <= 0) {
        document.getElementById('voteStatusText').textContent =
            '✅ You have used all your votes. Thanks for participating!';
    }
}

// ── Vote Status UI ───────────────────────────────────────
function updateVoteStatusUI() {
    const { usedVotes, maxVotes, remaining } = state;
    const bar = document.getElementById('voteStatusText');
    const dots = document.getElementById('voteDots');
    document.getElementById('maxVotesDisplay').textContent = maxVotes;

    if (remaining <= 0) {
        bar.textContent = '🏁 All votes used. Thank you for participating!';
    } else {
        bar.textContent = `You have used ${usedVotes} of ${maxVotes} votes. ${remaining} remaining.`;
    }

    dots.innerHTML = '';
    for (let i = 0; i < maxVotes; i++) {
        const d = document.createElement('div');
        d.className = `vote-dot ${i < usedVotes ? 'used' : 'available'}`;
        dots.appendChild(d);
    }
}

// ── Render Projects Grid ─────────────────────────────────
function renderProjects() {
    const grid = document.getElementById('projectsGrid');
    const { projects, settings, votedProjectIds, remaining } = state;
    const votingOpen = settings.votingActive && !settings.winnerDeclared;

    if (projects.length === 0) {
        grid.innerHTML = `<div class="loading-placeholder"><p style="font-size:1.2rem">🗂️ No projects registered yet.</p></div>`;
        return;
    }

    grid.innerHTML = projects.map((p, idx) => {
        const alreadyVoted = votedProjectIds.includes(p.id);
        const canVote = votingOpen && !alreadyVoted && remaining > 0;
        const isVoted = alreadyVoted;

        let btnLabel = '🗳️ Cast Vote';
        let btnClass = 'vote-btn';
        let btnDisabled = '';
        if (!votingOpen) { btnLabel = '⏸️ Voting Closed'; btnDisabled = 'disabled'; }
        else if (alreadyVoted) { btnLabel = '✓ Voted'; btnClass += ' voted-state'; btnDisabled = 'disabled'; }
        else if (remaining <= 0) { btnLabel = '🚫 No Votes Left'; btnDisabled = 'disabled'; }

        return `
      <div class="project-card${isVoted ? ' voted-card' : ''}" id="card-${p.id}">
        <div class="project-number">Project #${String(idx + 1).padStart(2, '0')}</div>
        <div class="project-name">${escHtml(p.name)}</div>
        <div class="project-team">👥 ${escHtml(p.team)}</div>
        <span class="project-category">${escHtml(p.category || 'General')}</span>
        ${p.description ? `<div class="project-desc">${escHtml(p.description)}</div>` : ''}
        <button class="${btnClass}" ${btnDisabled}
          id="voteBtn-${p.id}"
          onclick="castVote('${p.id}', '${escHtml(p.name)}')">
          ${btnLabel}
        </button>
      </div>`;
    }).join('');
}

// ── Casting a Vote ────────────────────────────────────────
async function castVote(projectId, projectName) {
    if (state.votingInFlight) return;
    state.votingInFlight = true;

    const btn = document.getElementById(`voteBtn-${projectId}`);
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Submitting…'; }

    try {
        const res = await fetch('/api/vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ projectId })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            lsAddVote(projectId);
            state.votedProjectIds.push(projectId);
            state.usedVotes += 1;
            state.remaining = data.remaining;
            updateVoteStatusUI();
            renderProjects();
            showSuccessModal(projectName, data.remaining);
        } else {
            showToast(data.error || 'Vote failed. Please try again.', 'error');
            if (btn) { btn.disabled = false; btn.textContent = '🗳️ Cast Vote'; }
        }
    } catch (err) {
        showToast('Network error. Please check your connection.', 'error');
        if (btn) { btn.disabled = false; btn.textContent = '🗳️ Cast Vote'; }
    } finally {
        state.votingInFlight = false;
    }
}

// ── Fetch initial data ────────────────────────────────────
async function loadInitialData() {
    try {
        const [projRes, statusRes] = await Promise.all([
            fetch('/api/projects'),
            fetch('/api/vote-status')
        ]);
        const projData = await projRes.json();
        const statusData = await statusRes.json();

        state.projects = projData.projects;
        state.settings = projData.settings;
        state.usedVotes = statusData.usedVotes;
        state.maxVotes = statusData.maxVotes;
        state.remaining = statusData.remaining;
        state.votedProjectIds = statusData.votedProjectIds;

        // Cross-reference with localStorage (hybrid protection)
        const lsVotes = lsGetVotes();
        lsVotes.forEach(v => {
            if (!state.votedProjectIds.includes(v.projectId)) {
                state.votedProjectIds.push(v.projectId);
            }
        });

        document.getElementById('eventName').textContent = state.settings.eventName || 'TECH FORGE 2k26';
        updateVoteStatusUI();
        renderProjects();
        updateClosedBanner();
    } catch (e) {
        document.getElementById('projectsGrid').innerHTML = `
      <div class="loading-placeholder" style="color:#ff8888">
        <p>⚠️ Failed to load projects. Is the server running?</p>
      </div>`;
    }
}

function updateClosedBanner() {
    const banner = document.getElementById('closedBanner');
    const isOpen = state.settings.votingActive && !state.settings.winnerDeclared;
    banner.style.display = isOpen ? 'none' : 'block';
    if (state.settings.winnerDeclared) {
        banner.innerHTML = '<span>🏆 Voting has ended! <a href="/leaderboard" style="color:var(--gold);font-weight:700">View the Winner →</a></span>';
    } else {
        banner.innerHTML = '<span>⏸️ Voting is currently <strong>paused</strong>. Check back soon!</span>';
    }
}

// ── Socket events ─────────────────────────────────────────
socket.on('leaderboard-update', (data) => {
    state.settings = data.settings;
    // Refresh vote buttons without losing local vote state
    state.projects = data.leaderboard.map(lb => {
        const existing = state.projects.find(p => p.id === lb.id);
        return { ...lb, voteCount: lb.voteCount };
    });
    renderProjects();
    updateClosedBanner();
});

socket.on('settings-update', (settings) => {
    state.settings = settings;
    updateClosedBanner();
    renderProjects();
});

socket.on('winner-declared', (data) => {
    state.settings.votingActive = false;
    state.settings.winnerDeclared = true;
    updateClosedBanner();
    renderProjects();
    showToast(`🏆 Winner declared: ${data.winner.name}! Check the leaderboard!`, 'info', 6000);
});

socket.on('system-reset', () => {
    state.votedProjectIds = [];
    state.usedVotes = 0;
    state.remaining = state.maxVotes;
    lsClear();
    loadInitialData();
    showToast('System has been reset by admin.', 'info');
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
spawnParticles();
loadInitialData();
