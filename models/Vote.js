const mongoose = require('mongoose');

const voteSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
    ip_address: { type: String, required: true },
    fingerprint: { type: String, default: null },
    timestamp: { type: Date, default: Date.now },
}, { timestamps: true });

voteSchema.index({ ip_address: 1 });
voteSchema.index({ project_id: 1, ip_address: 1 });

module.exports = mongoose.model('Vote', voteSchema);
