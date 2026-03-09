const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
    project_name: { type: String, required: true, trim: true },
    team_name: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    category: { type: String, default: 'General', trim: true },
    vote_count: { type: Number, default: 0 },
    is_winner: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
}, { timestamps: true });

module.exports = mongoose.model('Project', projectSchema);
