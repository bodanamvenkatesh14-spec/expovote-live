const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const Project = require('../models/Project');
const Vote = require('../models/Vote');
const Setting = require('../models/Setting');
const authMiddleware = require('../middleware/auth');

const MAX_VOTES_PER_IP = 3;

// Rate limiter: max 10 vote attempts per minute per IP
const voteLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Helper to get real IP
function getClientIp(req) {
    return (
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.headers['x-real-ip'] ||
        req.connection?.remoteAddress ||
        req.socket?.remoteAddress ||
        'unknown'
    );
}

// POST /api/votes - Submit a vote (public)
router.post('/', voteLimiter, async (req, res) => {
    try {
        const { project_id, fingerprint } = req.body;
        const ip = getClientIp(req);

        if (!project_id) {
            return res.status(400).json({ success: false, message: 'Project ID is required.' });
        }

        // Check if voting is active
        const votingStatus = await Setting.findOne({ key: 'voting_active' });
        if (!votingStatus || !votingStatus.value) {
            return res.status(403).json({ success: false, message: 'Voting is currently closed.' });
        }

        // Check if winner has been declared
        const winnerDeclared = await Setting.findOne({ key: 'winner_declared' });
        if (winnerDeclared && winnerDeclared.value) {
            return res.status(403).json({ success: false, message: 'Voting has ended. A winner has been declared.' });
        }

        // Check project exists
        const project = await Project.findById(project_id);
        if (!project) {
            return res.status(404).json({ success: false, message: 'Project not found.' });
        }

        // Count votes from this IP
        const ipVoteCount = await Vote.countDocuments({ ip_address: ip });
        if (ipVoteCount >= MAX_VOTES_PER_IP) {
            return res.status(429).json({
                success: false,
                message: `❌ You have reached the maximum ${MAX_VOTES_PER_IP} votes limit from this network.`,
                votes_used: ipVoteCount,
                votes_remaining: 0,
            });
        }

        // Check fingerprint-based vote limit (browser identity)
        if (fingerprint) {
            const fpVoteCount = await Vote.countDocuments({ fingerprint });
            if (fpVoteCount >= MAX_VOTES_PER_IP) {
                return res.status(429).json({
                    success: false,
                    message: `❌ You have reached the maximum ${MAX_VOTES_PER_IP} votes limit from this device.`,
                    votes_used: fpVoteCount,
                    votes_remaining: 0,
                });
            }
        }

        // Record vote
        const vote = new Vote({ project_id, ip_address: ip, fingerprint: fingerprint || null });
        await vote.save();

        // Increment project vote count
        const updatedProject = await Project.findByIdAndUpdate(
            project_id,
            { $inc: { vote_count: 1 } },
            { new: true }
        );

        // Get remaining votes for this IP
        const newIpCount = await Vote.countDocuments({ ip_address: ip });
        const remaining = MAX_VOTES_PER_IP - newIpCount;

        // Emit real-time update
        const io = req.app.get('io');
        const allProjects = await Project.find().sort({ vote_count: -1 });
        io.emit('vote_update', { projects: allProjects, updated_project: updatedProject });

        res.json({
            success: true,
            message: '✅ Vote recorded successfully!',
            votes_used: newIpCount,
            votes_remaining: remaining,
            project: updatedProject,
        });
    } catch (err) {
        console.error('Vote error:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// GET /api/votes/status - Get vote status for the current IP (public)
router.get('/status', async (req, res) => {
    try {
        const ip = getClientIp(req);
        const { fingerprint } = req.query;

        const ipVoteCount = await Vote.countDocuments({ ip_address: ip });
        let fpVoteCount = 0;
        if (fingerprint) {
            fpVoteCount = await Vote.countDocuments({ fingerprint });
        }

        const effectiveCount = Math.max(ipVoteCount, fpVoteCount);
        const remaining = Math.max(0, MAX_VOTES_PER_IP - effectiveCount);

        res.json({
            success: true,
            votes_used: effectiveCount,
            votes_remaining: remaining,
            max_votes: MAX_VOTES_PER_IP,
            can_vote: remaining > 0,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// GET /api/votes/stats - Get detailed vote stats (admin only)
router.get('/stats', authMiddleware, async (req, res) => {
    try {
        const totalVotes = await Vote.countDocuments();
        const uniqueIPs = await Vote.distinct('ip_address');
        const projects = await Project.find().sort({ vote_count: -1 });
        const winnerDeclared = await Setting.findOne({ key: 'winner_declared' });
        const votingStatus = await Setting.findOne({ key: 'voting_active' });

        // Votes over time (last 20)
        const recentVotes = await Vote.find().sort({ timestamp: -1 }).limit(20).populate('project_id', 'project_name team_name');

        res.json({
            success: true,
            total_votes: totalVotes,
            unique_voters: uniqueIPs.length,
            projects,
            recent_votes: recentVotes,
            voting_active: votingStatus ? votingStatus.value : false,
            winner_declared: winnerDeclared ? winnerDeclared.value : false,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
