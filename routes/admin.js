const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const Vote = require('../models/Vote');
const Setting = require('../models/Setting');
const authMiddleware = require('../middleware/auth');

// Helper to upsert a setting
async function setSetting(key, value) {
    return Setting.findOneAndUpdate({ key }, { value }, { upsert: true, new: true });
}

// GET /api/admin/status - Get current voting status (public read)
router.get('/status', async (req, res) => {
    try {
        const votingStatus = await Setting.findOne({ key: 'voting_active' });
        const winnerStatus = await Setting.findOne({ key: 'winner_declared' });
        const winnerProject = await Setting.findOne({ key: 'winner_project_id' });

        let winnerData = null;
        if (winnerProject && winnerProject.value) {
            winnerData = await Project.findById(winnerProject.value);
        }

        res.json({
            success: true,
            voting_active: votingStatus ? votingStatus.value : false,
            winner_declared: winnerStatus ? winnerStatus.value : false,
            winner: winnerData,
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// POST /api/admin/voting/start - Start voting (admin only)
router.post('/voting/start', authMiddleware, async (req, res) => {
    try {
        await setSetting('voting_active', true);
        await setSetting('winner_declared', false);
        await setSetting('winner_project_id', null);

        // Clear winner flags from all projects
        await Project.updateMany({}, { is_winner: false });

        const io = req.app.get('io');
        io.emit('voting_started');

        res.json({ success: true, message: 'Voting started!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// POST /api/admin/voting/stop - Stop voting (admin only)
router.post('/voting/stop', authMiddleware, async (req, res) => {
    try {
        await setSetting('voting_active', false);

        const io = req.app.get('io');
        io.emit('voting_stopped');

        res.json({ success: true, message: 'Voting stopped.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// POST /api/admin/voting/declare-winner - Declare winner (admin only)
router.post('/voting/declare-winner', authMiddleware, async (req, res) => {
    try {
        // Stop voting first
        await setSetting('voting_active', false);
        await setSetting('winner_declared', true);

        // Find project with most votes
        const winner = await Project.findOne().sort({ vote_count: -1 });
        if (!winner) {
            return res.status(400).json({ success: false, message: 'No projects found.' });
        }

        await Project.findByIdAndUpdate(winner._id, { is_winner: true });
        await setSetting('winner_project_id', winner._id.toString());

        const io = req.app.get('io');
        io.emit('winner_declared', { winner });

        res.json({ success: true, message: 'Winner declared!', winner });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// POST /api/admin/reset - Reset entire voting system (admin only)
router.post('/reset', authMiddleware, async (req, res) => {
    try {
        await Vote.deleteMany({});
        await Project.updateMany({}, { vote_count: 0, is_winner: false });
        await setSetting('voting_active', false);
        await setSetting('winner_declared', false);
        await setSetting('winner_project_id', null);

        const io = req.app.get('io');
        const projects = await Project.find().sort({ vote_count: -1 });
        io.emit('system_reset', { projects });

        res.json({ success: true, message: 'System reset successfully. All votes cleared.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
