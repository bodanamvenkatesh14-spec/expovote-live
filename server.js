/**
 * ExpoVote Live – Main Server v2 (NeDB, Judges Support)
 * Score = (Votes/TotalVotes)*30 + (AvgJudgeMarks/100)*70
 */
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Datastore = require('@seald-io/nedb');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'expovote_secret_2024';
const JUDGE_SECRET = process.env.JUDGE_SECRET || 'judge_secret_2024';
const DATA_DIR = path.join(__dirname, 'data');
const MAX_VOTES_PER_IP = 3;

// — Databases —
const db = {
  admins: new Datastore({ filename: path.join(DATA_DIR, 'admins.db'), autoload: true }),
  judges: new Datastore({ filename: path.join(DATA_DIR, 'judges.db'), autoload: true }),
  projects: new Datastore({ filename: path.join(DATA_DIR, 'projects.db'), autoload: true }),
  votes: new Datastore({ filename: path.join(DATA_DIR, 'votes.db'), autoload: true }),
  judgeScores: new Datastore({ filename: path.join(DATA_DIR, 'judgeScores.db'), autoload: true }),
  settings: new Datastore({ filename: path.join(DATA_DIR, 'settings.db'), autoload: true }),
};

db.votes.ensureIndex({ fieldName: 'ip_address' });
db.settings.ensureIndex({ fieldName: 'key', unique: true });
db.judgeScores.ensureIndex({ fieldName: 'judge_id' });
db.judgeScores.ensureIndex({ fieldName: 'project_id' });

// — DB Helpers —
const dbFind = (s, q) => new Promise((r, j) => s.find(q, (e, d) => e ? j(e) : r(d)));
const dbFindOne = (s, q) => new Promise((r, j) => s.findOne(q, (e, d) => e ? j(e) : r(d)));
const dbInsert = (s, d) => new Promise((r, j) => s.insert(d, (e, doc) => e ? j(e) : r(doc)));
const dbUpdate = (s, q, u, o) => new Promise((r, j) => s.update(q, u, o || {}, (e, n) => e ? j(e) : r(n)));
const dbRemove = (s, q, o) => new Promise((r, j) => s.remove(q, o || {}, (e, n) => e ? j(e) : r(n)));
const dbCount = (s, q) => new Promise((r, j) => s.count(q, (e, n) => e ? j(e) : r(n)));
const dbFindSorted = (s, q, sort, limit) => new Promise((r, j) => {
  let c = s.find(q).sort(sort);
  if (limit) c = c.limit(limit);
  c.exec((e, d) => e ? j(e) : r(d));
});

// — Seed —
async function seed() {
  // Admin
  if (!await dbFindOne(db.admins, { username: 'admin' })) {
    const hash = await bcrypt.hash('admin123', 12);
    await dbInsert(db.admins, { username: 'admin', password: hash, role: 'admin' });
  }
  // Default judges
  const defaultJudges = [
    { username: 'judge1', password: 'judge123', name: 'Judge 1' },
    { username: 'judge2', password: 'judge456', name: 'Judge 2' },
    { username: 'judge3', password: 'judge789', name: 'Judge 3' },
  ];
  for (const j of defaultJudges) {
    if (!await dbFindOne(db.judges, { username: j.username })) {
      const hash = await bcrypt.hash(j.password, 12);
      await dbInsert(db.judges, { username: j.username, password: hash, name: j.name });
    }
  }
  // Settings
  for (const [k, v] of [
    ['voting_active', false],
    ['winner_declared', false],
    ['final_scores', null],
  ]) {
    if (!await dbFindOne(db.settings, { key: k })) await dbInsert(db.settings, { key: k, value: v });
  }
}

async function setSetting(key, value) {
  if (await dbFindOne(db.settings, { key })) await dbUpdate(db.settings, { key }, { $set: { value } });
  else await dbInsert(db.settings, { key, value });
}

function getIP(req) {
  return ((req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket?.remoteAddress || '127.0.0.1';
}

// — Middleware —
function adminAuthMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized.' });
  try {
    const decoded = jwt.verify(h.split(' ')[1], JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ success: false, message: 'Forbidden.' });
    req.admin = decoded;
    next();
  } catch { res.status(401).json({ success: false, message: 'Invalid token.' }); }
}

function judgeAuthMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized.' });
  try {
    const decoded = jwt.verify(h.split(' ')[1], JUDGE_SECRET);
    if (decoded.role !== 'judge') return res.status(403).json({ success: false, message: 'Forbidden.' });
    req.judge = decoded;
    next();
  } catch { res.status(401).json({ success: false, message: 'Invalid judge token.' }); }
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);

// =========================================================
// AUTH – Admin
// =========================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await dbFindOne(db.admins, { username });
    if (!admin || !await bcrypt.compare(password, admin.password))
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const token = jwt.sign({ id: admin._id, username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, username });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/auth/verify', (req, res) => {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false });
    const decoded = jwt.verify(h.split(' ')[1], JWT_SECRET);
    res.json({ success: true, username: decoded.username, role: decoded.role });
  } catch { res.status(401).json({ success: false, message: 'Invalid token.' }); }
});

// =========================================================
// AUTH – Judge
// =========================================================
app.post('/api/judge/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const judge = await dbFindOne(db.judges, { username });
    if (!judge || !await bcrypt.compare(password, judge.password))
      return res.status(401).json({ success: false, message: 'Invalid judge credentials.' });
    const token = jwt.sign({ id: judge._id, username, name: judge.name, role: 'judge' }, JUDGE_SECRET, { expiresIn: '12h' });
    res.json({ success: true, token, username, name: judge.name });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/judge/verify', (req, res) => {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false });
    const decoded = jwt.verify(h.split(' ')[1], JUDGE_SECRET);
    res.json({ success: true, username: decoded.username, name: decoded.name, id: decoded.id });
  } catch { res.status(401).json({ success: false, message: 'Invalid token.' }); }
});

// =========================================================
// PROJECTS (Public read, Admin write)
// =========================================================
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await dbFindSorted(db.projects, {}, { created_at: 1 });
    // Never expose vote_count on public endpoint (hide from voting page)
    // but admin needs it — controlled per-route
    const safe = projects.map(p => ({
      _id: p._id, project_name: p.project_name, team_name: p.team_name,
      description: p.description, category: p.category, is_winner: p.is_winner,
      created_at: p.created_at, final_score: p.final_score
    }));
    res.json({ success: true, projects: safe });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// Admin-only: includes vote counts
app.get('/api/admin/projects', adminAuthMW, async (req, res) => {
  try {
    const projects = await dbFindSorted(db.projects, {}, { created_at: 1 });
    res.json({ success: true, projects });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/projects', adminAuthMW, async (req, res) => {
  try {
    const { project_name, team_name, description, category } = req.body;
    if (!project_name || !team_name || !description)
      return res.status(400).json({ success: false, message: 'All fields required.' });
    const project = await dbInsert(db.projects, {
      project_name, team_name, description,
      category: category || 'General',
      vote_count: 0, is_winner: false,
      final_score: null, created_at: new Date()
    });
    io.emit('project_added', { _id: project._id, project_name, team_name, category, description });
    res.status(201).json({ success: true, project });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.put('/api/projects/:id', adminAuthMW, async (req, res) => {
  try {
    const { project_name, team_name, description, category } = req.body;
    await dbUpdate(db.projects, { _id: req.params.id }, { $set: { project_name, team_name, description, category } });
    const project = await dbFindOne(db.projects, { _id: req.params.id });
    io.emit('project_updated', { _id: project._id, project_name, team_name, category, description });
    res.json({ success: true, project });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.delete('/api/projects/:id', adminAuthMW, async (req, res) => {
  try {
    await dbRemove(db.projects, { _id: req.params.id });
    await dbRemove(db.votes, { project_id: req.params.id }, { multi: true });
    await dbRemove(db.judgeScores, { project_id: req.params.id }, { multi: true });
    io.emit('project_deleted', { id: req.params.id });
    res.json({ success: true, message: 'Deleted.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// VOTES (Public)
// =========================================================
const voteLimiter = rateLimit({ windowMs: 60000, max: 10 });

app.post('/api/votes', voteLimiter, async (req, res) => {
  try {
    const { project_id, fingerprint } = req.body;
    const ip = getIP(req);
    if (!project_id) return res.status(400).json({ success: false, message: 'Project ID required.' });

    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    if (!vs?.value) return res.status(403).json({ success: false, message: 'Voting is currently closed.' });

    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    if (wd?.value) return res.status(403).json({ success: false, message: 'Voting has ended.' });

    const project = await dbFindOne(db.projects, { _id: project_id });
    if (!project) return res.status(404).json({ success: false, message: 'Project not found.' });

    // Check IP limit
    const ipCount = await dbCount(db.votes, { ip_address: ip });
    if (ipCount >= MAX_VOTES_PER_IP)
      return res.status(429).json({ success: false, message: `You have reached the maximum ${MAX_VOTES_PER_IP} votes limit.`, votes_used: ipCount, votes_remaining: 0 });

    // Check fingerprint limit
    if (fingerprint && await dbCount(db.votes, { fingerprint }) >= MAX_VOTES_PER_IP)
      return res.status(429).json({ success: false, message: 'Vote limit reached on this device.', votes_used: MAX_VOTES_PER_IP, votes_remaining: 0 });

    // Check duplicate vote for same project from same IP
    const dupVote = await dbFindOne(db.votes, { ip_address: ip, project_id });
    if (dupVote)
      return res.status(409).json({ success: false, message: 'You have already voted for this project.' });

    // Check duplicate fingerprint for same project
    if (fingerprint) {
      const dupFp = await dbFindOne(db.votes, { fingerprint, project_id });
      if (dupFp)
        return res.status(409).json({ success: false, message: 'You have already voted for this project.' });
    }

    await dbInsert(db.votes, { project_id, ip_address: ip, fingerprint: fingerprint || null, timestamp: new Date() });
    await dbUpdate(db.projects, { _id: project_id }, { $inc: { vote_count: 1 } });

    const newCount = await dbCount(db.votes, { ip_address: ip });
    io.emit('vote_cast', { project_id, project_name: project.project_name });

    res.json({
      success: true,
      message: 'Vote recorded successfully!',
      votes_used: newCount,
      votes_remaining: MAX_VOTES_PER_IP - newCount,
    });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/votes/status', async (req, res) => {
  try {
    const ip = getIP(req);
    const { fingerprint } = req.query;
    const ipCount = await dbCount(db.votes, { ip_address: ip });
    const fpCount = fingerprint ? await dbCount(db.votes, { fingerprint }) : 0;
    const effective = Math.max(ipCount, fpCount);

    // Which projects did this user vote for?
    const myVotes = await dbFind(db.votes, { ip_address: ip });
    const votedProjects = myVotes.map(v => v.project_id);

    res.json({
      success: true,
      votes_used: effective,
      votes_remaining: Math.max(0, MAX_VOTES_PER_IP - effective),
      max_votes: MAX_VOTES_PER_IP,
      can_vote: effective < MAX_VOTES_PER_IP,
      voted_projects: votedProjects
    });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// JUDGE SCORES
// =========================================================
app.post('/api/judge/scores', judgeAuthMW, async (req, res) => {
  try {
    const {
      project_id,
      problem, innovation, technical, functionality, impact, ui, presentation, communication
    } = req.body;
    const judge_id = req.judge.id;

    if (!project_id) return res.status(400).json({ success: false, message: 'Project ID required.' });

    const problem_s = Math.min(10, Math.max(0, Number(problem) || 0));
    const innovation_s = Math.min(20, Math.max(0, Number(innovation) || 0));
    const technical_s = Math.min(20, Math.max(0, Number(technical) || 0));
    const functionality_s = Math.min(15, Math.max(0, Number(functionality) || 0));
    const impact_s = Math.min(10, Math.max(0, Number(impact) || 0));
    const ui_s = Math.min(5, Math.max(0, Number(ui) || 0));
    const presentation_s = Math.min(10, Math.max(0, Number(presentation) || 0));
    const communication_s = Math.min(10, Math.max(0, Number(communication) || 0));

    const total = problem_s + innovation_s + technical_s + functionality_s + impact_s + ui_s + presentation_s + communication_s;

    const existing = await dbFindOne(db.judgeScores, { judge_id, project_id });
    if (existing) {
      await dbUpdate(db.judgeScores, { _id: existing._id }, {
        $set: {
          problem: problem_s, innovation: innovation_s, technical: technical_s,
          functionality: functionality_s, impact: impact_s, ui: ui_s,
          presentation: presentation_s, communication: communication_s,
          total, updated_at: new Date()
        }
      });
    } else {
      await dbInsert(db.judgeScores, {
        judge_id, project_id,
        judge_name: req.judge.name,
        problem: problem_s, innovation: innovation_s, technical: technical_s,
        functionality: functionality_s, impact: impact_s, ui: ui_s,
        presentation: presentation_s, communication: communication_s,
        total, created_at: new Date(), updated_at: new Date()
      });
    }

    io.emit('judge_score_submitted', { judge_id, project_id });
    res.json({ success: true, message: 'Score submitted successfully!', total });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Server error.' }); }
});

// Judge gets their own scores for all projects
app.get('/api/judge/my-scores', judgeAuthMW, async (req, res) => {
  try {
    const scores = await dbFind(db.judgeScores, { judge_id: req.judge.id });
    const scoreMap = {};
    scores.forEach(s => { scoreMap[s.project_id] = s; });
    res.json({ success: true, scores: scoreMap });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// Admin: view all judge scores summary
app.get('/api/admin/judge-scores', adminAuthMW, async (req, res) => {
  try {
    const allScores = await dbFind(db.judgeScores, {});
    const judges = await dbFind(db.judges, {});
    const projects = await dbFind(db.projects, {});

    // Group by project
    const byProject = {};
    allScores.forEach(s => {
      if (!byProject[s.project_id]) byProject[s.project_id] = [];
      byProject[s.project_id].push(s);
    });

    // Summary per project
    const summary = projects.map(p => {
      const scores = byProject[p._id] || [];
      const avgTotal = scores.length > 0 ? Math.round(scores.reduce((a, s) => a + s.total, 0) / scores.length) : null;
      return {
        project_id: p._id,
        project_name: p.project_name,
        team_name: p.team_name,
        judges_scored: scores.length,
        total_judges: judges.length,
        avg_judge_score: avgTotal,
        scores
      };
    });

    res.json({ success: true, summary, total_judges: judges.length });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// ADMIN – Status & Controls
// =========================================================
app.get('/api/admin/status', async (req, res) => {
  try {
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    const fs = await dbFindOne(db.settings, { key: 'final_scores' });
    res.json({
      success: true,
      voting_active: vs?.value || false,
      winner_declared: wd?.value || false,
      final_scores: fs?.value || null,
    });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/admin/stats', adminAuthMW, async (req, res) => {
  try {
    const totalVotes = await dbCount(db.votes, {});
    const allVotes = await dbFind(db.votes, {});
    const uniqueIPs = new Set(allVotes.map(v => v.ip_address)).size;
    const projects = await dbFindSorted(db.projects, {}, { vote_count: -1 });
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    const judgeScoresData = await dbFind(db.judgeScores, {});

    const recentVotes = await dbFindSorted(db.votes, {}, { timestamp: -1 }, 20);
    const enriched = await Promise.all(recentVotes.map(async v => {
      const p = await dbFindOne(db.projects, { _id: v.project_id });
      return { ...v, project_name: p?.project_name || 'Unknown', team_name: p?.team_name || '' };
    }));

    res.json({
      success: true,
      total_votes: totalVotes,
      unique_voters: uniqueIPs,
      projects,
      recent_votes: enriched,
      voting_active: vs?.value || false,
      winner_declared: wd?.value || false,
      judge_scores_submitted: judgeScoresData.length,
    });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/voting/start', adminAuthMW, async (req, res) => {
  try {
    await setSetting('voting_active', true);
    await setSetting('winner_declared', false);
    await setSetting('final_scores', null);
    await dbUpdate(db.projects, {}, { $set: { is_winner: false, final_score: null } }, { multi: true });
    io.emit('voting_started');
    res.json({ success: true, message: 'Voting started!' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/voting/stop', adminAuthMW, async (req, res) => {
  try {
    await setSetting('voting_active', false);
    io.emit('voting_stopped');
    res.json({ success: true, message: 'Voting stopped.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// LIVE VOTING RANKINGS (Public) - Obfuscated counts
// =========================================================
app.get('/api/voting-rankings', async (req, res) => {
  try {
    const projects = await dbFind(db.projects, {});
    const allVotes = await dbFind(db.votes, {});
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });

    // Calculate final score per project
    const scored = projects.map(p => {
      const projectVotes = allVotes.filter(v => v.project_id === p._id).length;
      return { ...p, vote_count: projectVotes };
    });

    // Sort by votes descending
    scored.sort((a, b) => b.vote_count - a.vote_count);

    // Filter to only safe data (no actual vote counts to obey rule 3)
    const rankings = scored.map((p, i) => ({
      rank: i + 1,
      project_name: p.project_name,
      team_name: p.team_name,
    }));

    res.json({
      success: true,
      rankings,
      voting_active: vs?.value || false,
      winner_declared: wd?.value || false
    });
  } catch (e) { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// DECLARE WINNER – Final score calculation
// Formula: voteScore = (projectVotes/totalVotes)*30
//          judgeScore = (avgJudgeMarks/100)*70
//          finalScore = voteScore + judgeScore
// =========================================================
app.post('/api/admin/voting/declare-winner', adminAuthMW, async (req, res) => {
  try {
    await setSetting('voting_active', false);

    const projects = await dbFind(db.projects, {});
    const allVotes = await dbFind(db.votes, {});
    const allJudgeScores = await dbFind(db.judgeScores, {});

    const totalVotes = allVotes.length;

    // Calculate final score per project
    const scored = projects.map(p => {
      // Vote Score: (project's votes / total votes) * 30
      const projectVotes = allVotes.filter(v => v.project_id === p._id).length;
      const voteScore = totalVotes > 0 ? (projectVotes / totalVotes) * 30 : 0;

      // Judge Score: (avg judge marks / 100) * 70
      const projScores = allJudgeScores.filter(s => s.project_id === p._id);
      const avgJudgeMarks = projScores.length > 0
        ? projScores.reduce((acc, s) => acc + s.total, 0) / projScores.length
        : 0;
      const judgeScore = (avgJudgeMarks / 100) * 70;

      const finalScore = Math.round((voteScore + judgeScore) * 100) / 100;

      return {
        ...p,
        project_votes: projectVotes,
        vote_score: Math.round(voteScore * 100) / 100,
        judge_score: Math.round(judgeScore * 100) / 100,
        avg_judge_marks: Math.round(avgJudgeMarks * 100) / 100,
        final_score: finalScore,
        judges_scored: projScores.length,
      };
    });

    // Sort by final score descending
    scored.sort((a, b) => b.final_score - a.final_score);

    // Store final scores in settings (for leaderboard)
    const finalScoresList = scored.map((p, i) => ({
      rank: i + 1,
      _id: p._id,
      project_name: p.project_name,
      team_name: p.team_name,
      category: p.category,
      final_score: p.final_score,
      is_winner: i === 0,
    }));
    await setSetting('final_scores', finalScoresList);
    await setSetting('winner_declared', true);

    // Update each project's final score and winner flag
    for (const p of scored) {
      await dbUpdate(db.projects, { _id: p._id }, {
        $set: { final_score: p.final_score, is_winner: p === scored[0] }
      });
    }

    const winner = scored[0];
    io.emit('winner_declared', { winner: finalScoresList[0], leaderboard: finalScoresList });
    res.json({ success: true, message: 'Winner declared! Leaderboard published.', winner, leaderboard: finalScoresList });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Server error.' }); }
});

// Admin: manage judges
app.get('/api/admin/judges', adminAuthMW, async (req, res) => {
  try {
    const judges = await dbFind(db.judges, {});
    res.json({ success: true, judges: judges.map(j => ({ _id: j._id, username: j.username, name: j.name })) });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/judges', adminAuthMW, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password || !name) return res.status(400).json({ success: false, message: 'All fields required.' });
    if (await dbFindOne(db.judges, { username })) return res.status(409).json({ success: false, message: 'Username already exists.' });
    const hash = await bcrypt.hash(password, 12);
    const judge = await dbInsert(db.judges, { username, password: hash, name });
    res.status(201).json({ success: true, judge: { _id: judge._id, username, name } });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.delete('/api/admin/judges/:id', adminAuthMW, async (req, res) => {
  try {
    await dbRemove(db.judges, { _id: req.params.id });
    await dbRemove(db.judgeScores, { judge_id: req.params.id }, { multi: true });
    res.json({ success: true, message: 'Judge removed.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/reset', adminAuthMW, async (req, res) => {
  try {
    await dbRemove(db.votes, {}, { multi: true });
    await dbRemove(db.judgeScores, {}, { multi: true });
    await dbUpdate(db.projects, {}, { $set: { vote_count: 0, is_winner: false, final_score: null } }, { multi: true });
    await setSetting('voting_active', false);
    await setSetting('winner_declared', false);
    await setSetting('final_scores', null);
    io.emit('system_reset');
    res.json({ success: true, message: 'System reset. All votes and scores cleared.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// =========================================================
// PAGES
// =========================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vote.html')));
app.get('/vote', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vote.html')));
app.get('/voting-leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'voting-leaderboard.html')));
app.get('/leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'leaderboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/judge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'judge-login.html')));
app.get('/judge/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'judge-dashboard.html')));

// =========================================================
// SOCKET.IO
// =========================================================
io.on('connection', (socket) => {
  socket.on('request_leaderboard', async () => {
    try {
      const vs = await dbFindOne(db.settings, { key: 'voting_active' });
      const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
      const fs = await dbFindOne(db.settings, { key: 'final_scores' });
      socket.emit('leaderboard_data', {
        voting_active: vs?.value || false,
        winner_declared: wd?.value || false,
        final_scores: fs?.value || null,
      });
    } catch { }
  });
});

(async () => {
  await seed();
  server.listen(PORT, () => {
    console.log('\n========================================');
    console.log('  ExpoVote Live v2 is RUNNING!');
    console.log('  http://localhost:' + PORT);
    console.log('  Admin:  admin / admin123');
    console.log('  Judge1: judge1 / judge123');
    console.log('  Judge2: judge2 / judge456');
    console.log('  Judge3: judge3 / judge789');
    console.log('  Voting Page:     http://localhost:' + PORT + '/vote');
    console.log('  Judge Page:      http://localhost:' + PORT + '/judge');
    console.log('  Leaderboard:     http://localhost:' + PORT + '/leaderboard');
    console.log('  Admin Dashboard: http://localhost:' + PORT + '/admin');
    console.log('========================================\n');
  });
})();
