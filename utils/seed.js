const mongoose = require('mongoose');
const Admin = require('../models/Admin');
const Setting = require('../models/Setting');

async function seed(mongoUri) {
    try {
        await mongoose.connect(mongoUri);
        console.log('🌱 Seeding database...');

        // Seed admin
        const existingAdmin = await Admin.findOne({ username: process.env.ADMIN_USERNAME || 'admin' });
        if (!existingAdmin) {
            const admin = new Admin({
                username: process.env.ADMIN_USERNAME || 'admin',
                password: process.env.ADMIN_PASSWORD || 'admin123',
            });
            await admin.save();
            console.log('✅ Admin created: admin / admin123');
        } else {
            console.log('ℹ️  Admin already exists.');
        }

        // Seed default settings
        const defaults = [
            { key: 'voting_active', value: false },
            { key: 'winner_declared', value: false },
            { key: 'winner_project_id', value: null },
        ];

        for (const setting of defaults) {
            await Setting.findOneAndUpdate({ key: setting.key }, { value: setting.value }, { upsert: true });
        }
        console.log('✅ Default settings initialized.');
        console.log('🌱 Seeding complete!');
    } catch (err) {
        console.error('Seed error:', err);
    }
}

module.exports = seed;
