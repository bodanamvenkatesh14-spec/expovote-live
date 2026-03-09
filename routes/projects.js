const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const Vote = require('../models/Vote');
const Setting = require('../models/Setting');
const authMiddleware = require('../middleware/auth');

// GET /api/projects - Get all projects (public)
router.get('/', async (req, res) => {
    try {
        const projects = await Project.find().sort({ vote_count: -1 });
        res.json({ success: true, projects });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// GET /api/projects/:id - Get a single project (public)
router.get('/:id', async (req, res) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) return res.status(404).json({ success: false, message: 'Project not found.' });
        res.json({ success: true, project });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// POST /api/projects - Add new project (admin only)
router.post('/', authMiddleware, async (req, res) => {
    try {
        const { project_name, team_name, description, category } = req.body;
        if (!project_name || !team_name || !description) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        const project = new Project({ project_name, team_name, description, category: category || 'General' });
        await project.save();

        // Emit to socket
        const io = req.app.get('io');
        io.emit('project_added', project);

        res.status(201).json({ success: true, project });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// PUT /api/projects/:id - Update project (admin only)
router.put('/:id', authMiddleware, async (req, res) => {
    try {
        const { project_name, team_name, description, category } = req.body;
        const project = await Project.findByIdAndUpdate(
            req.params.id,
            { project_name, team_name, description, category },
            { new: true, runValidators: true }
        );
        if (!project) return res.status(404).json({ success: false, message: 'Project not found.' });

        const io = req.app.get('io');
        io.emit('project_updated', project);

        res.json({ success: true, project });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// DELETE /api/projects/:id - Delete project (admin only)
router.delete('/:id', authMiddleware, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (!project) return res.status(404).json({ success: false, message: 'Project not found.' });

        // Also remove associated votes
        await Vote.deleteMany({ project_id: req.params.id });

        const io = req.app.get('io');
        io.emit('project_deleted', { id: req.params.id });

        res.json({ success: true, message: 'Project deleted.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
