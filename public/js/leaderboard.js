/* ============================================================
   ExpoVote Live – Live Leaderboard JavaScript (List Layout)
   ============================================================ */

const socket = io();

let state = {
    leaderboard: [],
    settings: {},
    totalVotes: 0,
    previousOrder: [],
    winnerDeclared: false
};

// ── Confetti ──────────────────────────────────────────────
function launchConfetti() {
    const duration = 5000;
    const animationEnd = Date.now() + duration;
    const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 9999 };
    const randomInRange = (min, max) => Math.random() * (max - min) + min;
    const interval = setInterval(() => {
        const timeLeft = animationEnd - Date.now();
        if (timeLeft <= 0) { clearInterval(interval); return; }
        const count = 50 * (timeLeft / duration);
        confetti({ ...defaults, count, origin: { x: randomInRange(0.1, 0.4), y: Math.random() - 0.2 } });
        confetti({ ...defaults, count, origin: { x: randomInRange(0.6, 0.9), y: Math.random() - 0.2 } });
    }, 250);
}

// ── Fullscreen ────────────────────────────────────────────
document.getElementById('fullscreenBtn').addEventListener('click', () => {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => { });
        document.getElementById('fullscreenBtn').textContent = '✕';
    } else {
        document.exitFullscreen();
        document.getElementById('fullscreenBtn').textContent = '⛶';
    }
});
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        document.getElementById('fullscreenBtn').textContent = '⛶';
    }
});

// ── Medal / rank configs ──────────────────────────────────
const RANK_META = [
    { label: '1st', color: 'var(--gold)', glow: 'var(--gold-glow)', icon: '🥇', cls: 'rank-1' },
    { label: '2nd', color: 'var(--silver)', glow: 'var(--silver-glow)', icon: '🥈', cls: 'rank-2' },
    { label: '3rd', color: 'var(--bronze)', glow: 'var(--bronze-glow)', icon: '🥉', cls: 'rank-3' },
];

// ── Rankings List ─────────────────────────────────────────
function renderRankings(sorted) {
    const list = document.getElementById('rankingsList');
    if (sorted.length === 0) {
        list.innerHTML = `<div class="lb-empty">🗂️ No projects registered yet.</div>`;
        return;
    }

    const maxVotes = sorted[0]?.voteCount || 1;

    // Detect "trending" – biggest rank climb since last update
    let trendingId = null;
    if (state.previousOrder.length > 0) {
        let bestGain = 0;
        sorted.forEach((p, newIdx) => {
            const oldIdx = state.previousOrder.indexOf(p.id);
            if (oldIdx !== -1 && (oldIdx - newIdx) > bestGain) {
                bestGain = oldIdx - newIdx;
                trendingId = p.id;
            }
        });
    }

    list.innerHTML = sorted.map((p, idx) => {
        const pct = maxVotes > 0 ? (p.voteCount / maxVotes) * 100 : 0;
        const isWinner = state.winnerDeclared && idx === 0;
        const isTrending = trendingId === p.id && p.voteCount > 0;
        const meta = RANK_META[idx];   // undefined for idx >= 3

        const rankBadgeStyle = meta
            ? `color:${meta.color}; text-shadow: 0 0 12px ${meta.glow};`
            : `color: var(--text-muted);`;

        const rowExtra = meta
            ? `lb-rank-row--${meta.cls}${isWinner ? ' lb-rank-row--winner' : ''}`
            : '';

        const rankLabel = meta
            ? `<span class="lb-rank-icon">${meta.icon}</span><span class="lb-rank-label">${meta.label}</span>`
            : `<span class="lb-rank-num">${idx + 1}</span>`;

        return `
      <div class="lb-rank-row ${rowExtra}" id="rankrow-${p.id}" style="animation-delay:${idx * 0.06}s">

        <!-- Rank Badge -->
        <div class="lb-col-rank" style="${rankBadgeStyle}">
          ${rankLabel}
        </div>

        <!-- Project Info -->
        <div class="lb-col-info">
          <div class="lb-proj-name">
            ${escHtml(p.name)}
            ${isTrending ? '<span class="lb-badge lb-badge--fire">🔥 Rising</span>' : ''}
            ${isWinner ? '<span class="lb-badge lb-badge--winner">👑 Winner</span>' : ''}
          </div>
          <div class="lb-proj-team">👥 ${escHtml(p.team)}<span class="lb-proj-cat">${escHtml(p.category || '')}</span></div>
        </div>

        <!-- Progress Bar -->
        <div class="lb-col-bar">
          <div class="lb-bar-bg">
            <div class="lb-bar-fill ${meta ? `lb-bar--${meta.cls}` : ''}"
                 id="bar-${p.id}" style="width:0%"></div>
          </div>
          <span class="lb-pct">${Math.round(pct)}%</span>
        </div>

        <!-- Vote Count -->
        <div class="lb-col-votes" style="${meta ? `color:${meta.color};` : ''}">
          <span class="lb-votes-num">${p.voteCount}</span>
          <span class="lb-votes-label">votes</span>
        </div>

      </div>`;
    }).join('');

    // Animate bars after DOM insert
    requestAnimationFrame(() => {
        sorted.forEach(p => {
            const pct = maxVotes > 0 ? (p.voteCount / maxVotes) * 100 : 0;
            const bar = document.getElementById(`bar-${p.id}`);
            if (bar) setTimeout(() => { bar.style.width = `${pct}%`; }, 80);
        });
    });

    state.previousOrder = sorted.map(p => p.id);
}

// ── Winner Banner ─────────────────────────────────────────
function showWinnerBanner(winner) {
    const banner = document.getElementById('winnerBanner');
    document.getElementById('winnerName').textContent = winner.name;
    document.getElementById('winnerTeam').textContent = winner.team;
    document.getElementById('winnerVotes').textContent = `${winner.voteCount} votes`;
    banner.style.display = 'block';
    banner.classList.add('winner-zoom');
}

// ── Full Render ───────────────────────────────────────────
function renderAll() {
    const { leaderboard, settings, totalVotes } = state;
    const sorted = [...leaderboard].sort((a, b) => b.voteCount - a.voteCount);

    document.getElementById('lbEventName').textContent = settings.eventName || 'TECH FORGE 2k26';
    document.getElementById('totalVotesCount').textContent = totalVotes;

    const dot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    if (settings.winnerDeclared) {
        dot.className = 'status-dot closed'; statusText.textContent = '🏆 Winner Declared';
    } else if (settings.votingActive) {
        dot.className = 'status-dot active'; statusText.textContent = '● Voting LIVE';
    } else {
        dot.className = 'status-dot'; statusText.textContent = '⏸ Voting Paused';
    }

    document.getElementById('lastUpdated').textContent =
        `Last updated: ${new Date().toLocaleTimeString()}`;

    renderRankings(sorted);
}

// ── Socket Events ─────────────────────────────────────────
socket.on('leaderboard-update', (data) => {
    state.leaderboard = data.leaderboard;
    state.settings = data.settings;
    state.totalVotes = data.totalVotes;
    renderAll();
});
socket.on('settings-update', (settings) => {
    state.settings = settings;
    renderAll();
});
socket.on('winner-declared', (data) => {
    state.settings.winnerDeclared = true;
    state.settings.votingActive = false;
    state.winnerDeclared = true;
    state.leaderboard = data.leaderboard.leaderboard;
    state.totalVotes = data.leaderboard.totalVotes;
    renderAll();
    showWinnerBanner(data.winner);
    launchConfetti();
});
socket.on('system-reset', (data) => {
    state.winnerDeclared = false;
    state.leaderboard = data.leaderboard;
    state.settings = data.settings;
    state.totalVotes = data.totalVotes;
    state.previousOrder = [];
    document.getElementById('winnerBanner').style.display = 'none';
    renderAll();
});
socket.on('connect', () => { document.getElementById('statusText').textContent = 'Connected'; });
socket.on('disconnect', () => {
    document.getElementById('statusDot').className = 'status-dot closed';
    document.getElementById('statusText').textContent = 'Disconnected – reconnecting…';
});

// ─── Utility ──────────────────────────────────────────────
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
