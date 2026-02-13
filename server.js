// server.js

const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const WebSocket = require('ws');
const path = require('path');
require('dotenv').config();

const { User, Session, License, Activity, Config, Macro } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';

// Middleware
app.use(cors({
    origin: ['https://asceac.vercel.app', 'https://asceac.vercel.app/'],
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

mongoose.connect(process.env.MONGODB_URI)
.then(async () => {
    console.log('Connected to MongoDB');
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// JWT verification
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Admin check
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Session helpers
async function createSession(userId, token, hwid = null) {
    await Session.create({ userId, token, hwid });
}

async function validateSession(token) {
    const session = await Session.findOne({ token });
    if (!session) return null;
    
    const user = await User.findById(session.userId);
    return user;
}

async function deleteSession(token) {
    await Session.deleteOne({ token });
}

// Log activity
async function logActivity(userId, username, action, details = '', ipAddress = null) {
    try {
        await Activity.create({
            userId,
            username,
            action,
            details,
            ipAddress
        });
    } catch (error) {
        console.error('Activity log error:', error);
    }
}

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, isFirstAdmin } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }

        if (isFirstAdmin) {
            const userCount = await User.countDocuments();
            if (userCount > 0) {
                return res.status(403).json({ error: 'Admin account already exists' });
            }
        }

        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            username,
            email,
            password: hashedPassword,
            role: isFirstAdmin ? 'admin' : 'user',
            needsActivation: !isFirstAdmin
        });

        await logActivity(user._id, username, 'USER_REGISTERED', '', req.ip);

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                needsActivation: user.needsActivation
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Check if admin exists
app.get('/api/auth/admin-exists', async (req, res) => {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        res.json({ exists: !!adminExists });
    } catch (error) {
        console.error('Admin check error:', error);
        res.status(500).json({ error: 'Failed to check admin status' });
    }
});

// Login (web dashboard - no HWID)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        if (user.status === 'banned') {
            return res.status(403).json({ error: 'Account has been banned' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        user.lastSeen = new Date();
        await user.save();

        await logActivity(user._id, user.username, 'USER_LOGIN', '', req.ip);

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        let licenseInfo = null;
        if (user.licenseKey) {
            const license = await License.findOne({ key: user.licenseKey });
            if (license) {
                if (license.status === 'revoked' || license.status === 'expired') {
                    user.needsActivation = true;
                    user.licenseKey = null;
                    await user.save();
                } else {
                    licenseInfo = {
                        type: license.type,
                        expiresAt: license.expiresAt,
                        status: license.status
                    };
                }
            }
        }

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                totalClicks: user.totalClicks,
                needsActivation: user.needsActivation,
                license: licenseInfo
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Login with HWID (C++ client)
app.post('/api/auth/login-hwid', async (req, res) => {
    try {
        const { username, password, hwid } = req.body;

        if (!username || !password || !hwid) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.status === 'banned') {
            return res.status(403).json({ error: 'Account has been banned' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Parse HWID (handle both string and object)
        let clientHWID;
        if (typeof hwid === 'string') {
            try {
                clientHWID = JSON.parse(hwid);
            } catch (e) {
                console.error('[HWID] Failed to parse HWID string:', e);
                return res.status(400).json({ error: 'Invalid HWID format (parse error)' });
            }
        } else if (typeof hwid === 'object') {
            clientHWID = hwid;
        } else {
            return res.status(400).json({ error: 'Invalid HWID format (wrong type)' });
        }

        // Validate required fields
        if (!clientHWID.cpuID || !clientHWID.motherboardID || !clientHWID.volumeSerial) {
            console.error('[HWID] Missing required fields:', clientHWID);
            return res.status(400).json({ error: 'Invalid HWID format (missing fields)' });
        }

        const hwidJSON = JSON.stringify(clientHWID);

        // HWID Verification
        if (!user.firstLoginCompleted) {
            // FIRST LOGIN - Store HWID
            user.hwid = hwidJSON;
            user.hwidFingerprint = clientHWID.fingerprint || 'no-fingerprint';
            user.firstLoginCompleted = true;
            user.hwidLocked = true;
            await user.save();

            console.log(`[SECURITY] HWID registered for ${username}`);
            await logActivity(user._id, username, 'HWID_REGISTERED', clientHWID.fingerprint || 'unknown', req.ip);

        } else {
            // SUBSEQUENT LOGIN - Verify HWID
            let storedHWID;
            try {
                storedHWID = JSON.parse(user.hwid);
            } catch (e) {
                console.error('[HWID] Failed to parse stored HWID:', e);
                // Corrupted HWID - re-register
                user.hwid = hwidJSON;
                user.hwidFingerprint = clientHWID.fingerprint || 'no-fingerprint';
                await user.save();
                console.log(`[SECURITY] HWID re-registered for ${username} (corrupted data)`);
            }

            if (storedHWID) {
                // Core component check
                const coreMatch = 
                    clientHWID.cpuID === storedHWID.cpuID &&
                    clientHWID.motherboardID === storedHWID.motherboardID &&
                    clientHWID.volumeSerial === storedHWID.volumeSerial;

                if (!coreMatch) {
                    // HWID MISMATCH - BAN IMMEDIATELY
                    user.status = 'banned';
                    await user.save();

                    console.log(`[SECURITY] HWID mismatch for ${username} - ACCOUNT BANNED`);
                    console.log(`  Expected CPU: ${storedHWID.cpuID}, Got: ${clientHWID.cpuID}`);
                    console.log(`  Expected MB: ${storedHWID.motherboardID}, Got: ${clientHWID.motherboardID}`);
                    console.log(`  Expected VS: ${storedHWID.volumeSerial}, Got: ${clientHWID.volumeSerial}`);
                    
                    await logActivity(user._id, username, 'HWID_VIOLATION', 
                        `Expected: ${storedHWID.fingerprint}, Got: ${clientHWID.fingerprint}`, req.ip);

                    return res.status(403).json({ 
                        error: 'HWID mismatch detected. Account has been terminated for security reasons.',
                        banned: true
                    });
                }

                console.log(`[SECURITY] HWID verified for ${username}`);
            }
        }

        user.lastSeen = new Date();
        await user.save();

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        let licenseInfo = null;
        if (user.licenseKey) {
            const license = await License.findOne({ key: user.licenseKey });
            if (license && license.status === 'active') {
                licenseInfo = {
                    type: license.type,
                    expiresAt: license.expiresAt,
                    status: license.status
                };
            }
        }

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                totalClicks: user.totalClicks,
                needsActivation: user.needsActivation,
                license: licenseInfo,
                firstLogin: !user.firstLoginCompleted
            }
        });

    } catch (error) {
        console.error('Login HWID error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Activate account with license
app.post('/api/auth/activate', authenticateToken, async (req, res) => {
    try {
        const { licenseKey } = req.body;

        if (!licenseKey) {
            return res.status(400).json({ error: 'License key required' });
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.needsActivation) {
            return res.status(400).json({ error: 'Account already activated' });
        }

        const license = await License.findOne({ key: licenseKey });
        
        if (!license) {
            return res.status(400).json({ error: 'Invalid license key' });
        }

        if (license.status === 'expired' || license.status === 'revoked') {
            return res.status(400).json({ error: 'License key is no longer valid' });
        }

        if (license.currentUses >= license.maxUses) {
            return res.status(400).json({ error: 'License key has reached maximum uses' });
        }

        if (license.expiresAt && license.expiresAt < new Date()) {
            license.status = 'expired';
            await license.save();
            return res.status(400).json({ error: 'License key has expired' });
        }

        user.licenseKey = licenseKey;
        user.needsActivation = false;
        await user.save();

        await License.findOneAndUpdate(
            { key: licenseKey },
            { 
                $set: { 
                    status: 'active',
                    usedBy: user._id
                },
                $inc: { currentUses: 1 }
            }
        );

        await logActivity(user._id, user.username, 'ACCOUNT_ACTIVATED', licenseKey, req.ip);

        res.json({
            success: true,
            license: {
                type: license.type,
                expiresAt: license.expiresAt,
                status: license.status
            }
        });
    } catch (error) {
        console.error('Activation error:', error);
        res.status(500).json({ error: 'Activation failed' });
    }
});

// Verify token
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        
        let licenseInfo = null;
        if (user.licenseKey) {
            const license = await License.findOne({ key: user.licenseKey });
            if (license) {
                if (license.status === 'revoked' || license.status === 'expired') {
                    user.needsActivation = true;
                    user.licenseKey = null;
                    await user.save();
                } else {
                    licenseInfo = {
                        type: license.type,
                        expiresAt: license.expiresAt,
                        status: license.status
                    };
                }
            }
        }

        res.json({ 
            user: {
                ...user.toObject(),
                license: licenseInfo
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (token) {
            await deleteSession(token);
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

const fs = require('fs');
const pathModule = require('path');

app.get('/api/download/client', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // Check if user has active license
        if (!user || user.needsActivation) {
            return res.status(403).json({ error: 'Active license required' });
        }
        
        const filename = req.query.filename || 'asce';
        
        // Path to your EXE file
        const exePath = pathModule.join(__dirname, 'client', 'asce.exe');
        
        // Check if file exists
        if (!fs.existsSync(exePath)) {
            console.error('Client EXE not found at:', exePath);
            return res.status(404).json({ error: 'Client file not found' });
        }
        
        // Log download
        await logActivity(user._id, user.username, 'CLIENT_DOWNLOADED', filename, req.ip);
        
        // Set headers for download
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}.exe"`);
        
        // Stream the file
        const fileStream = fs.createReadStream(exePath);
        fileStream.pipe(res);
        
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// Get stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const onlineUsers = await User.countDocuments({
            lastSeen: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
        });
        const activeLicenses = await License.countDocuments({ status: 'active' });
        
        const clicksResult = await User.aggregate([
            { $group: { _id: null, total: { $sum: '$totalClicks' } } }
        ]);
        const totalClicks = clicksResult[0]?.total || 0;

        res.json({
            totalUsers,
            onlineUsers,
            activeLicenses,
            totalClicks
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Get all users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Create user
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            username,
            email,
            password: hashedPassword,
            role: role || 'user',
            needsActivation: role !== 'admin'
        });

        await logActivity(req.user.id, req.user.username, 'ADMIN_CREATE_USER', username, req.ip);

        res.json({
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role
        });
    } catch (error) {
        console.error('User creation error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        await logActivity(req.user.id, req.user.username, 'ADMIN_DELETE_USER', user.username, req.ip);
        res.json({ success: true });
    } catch (error) {
        console.error('User deletion error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Ban/unban user
app.patch('/api/admin/users/:id/ban', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { banned } = req.body;
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { status: banned ? 'banned' : 'active' },
            { new: true }
        ).select('-password');

        await logActivity(
            req.user.id, 
            req.user.username, 
            banned ? 'ADMIN_BAN_USER' : 'ADMIN_UNBAN_USER', 
            user.username, 
            req.ip
        );

        res.json(user);
    } catch (error) {
        console.error('Ban error:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

// Get activity logs
app.get('/api/admin/activity', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const totalActivities = await Activity.countDocuments();
        const totalPages = Math.ceil(totalActivities / limit);

        const activities = await Activity.find()
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit);

        res.json({
            activities,
            pagination: {
                currentPage: page,
                totalPages,
                totalActivities,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error('Activity fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch activity' });
    }
});

// Get licenses
app.get('/api/admin/licenses', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const licenses = await License.find()
            .populate('usedBy', 'username')
            .sort({ createdAt: -1 });

        res.json(licenses);
    } catch (error) {
        console.error('Licenses fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch licenses' });
    }
});

// Generate license
app.post('/api/admin/licenses/generate', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, maxUses } = req.body;
        const key = generateLicenseKey();
        
        let expiresAt = null;
        if (type === 'week') {
            expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        } else if (type === 'month') {
            expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        }

        const license = await License.create({
            key,
            type: type || 'month',
            expiresAt,
            maxUses: maxUses || 1
        });

        await logActivity(req.user.id, req.user.username, 'ADMIN_GENERATE_LICENSE', `${key} (${type})`, req.ip);

        res.json(license);
    } catch (error) {
        console.error('License generation error:', error);
        res.status(500).json({ error: 'Failed to generate license' });
    }
});

// Revoke license
app.patch('/api/admin/licenses/:id/revoke', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const license = await License.findByIdAndUpdate(
            req.params.id,
            { status: 'revoked' },
            { new: true }
        );

        if (license.usedBy) {
            await User.findByIdAndUpdate(
                license.usedBy,
                { 
                    needsActivation: true,
                    licenseKey: null
                }
            );
        }

        await logActivity(req.user.id, req.user.username, 'ADMIN_REVOKE_LICENSE', license.key, req.ip);

        res.json(license);
    } catch (error) {
        console.error('License revoke error:', error);
        res.status(500).json({ error: 'Failed to revoke license' });
    }
});

// View user HWID
app.get('/api/admin/users/:id/hwid', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('hwid hwidFingerprint hwidLocked');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        let hwidData = null;
        if (user.hwid) {
            try {
                hwidData = JSON.parse(user.hwid);
            } catch (e) {
                hwidData = { error: 'Corrupted HWID data' };
            }
        }

        res.json({
            hwid: hwidData,
            fingerprint: user.hwidFingerprint,
            locked: user.hwidLocked
        });
    } catch (error) {
        console.error('HWID fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch HWID' });
    }
});

// Reset user HWID
app.post('/api/admin/users/:id/reset-hwid', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.hwid = null;
        user.hwidFingerprint = null;
        user.firstLoginCompleted = false;
        user.hwidLocked = false;
        await user.save();

        await logActivity(req.user.id, req.user.username, 'ADMIN_RESET_HWID', user.username, req.ip);

        res.json({ success: true, message: 'HWID reset successfully' });
    } catch (error) {
        console.error('HWID reset error:', error);
        res.status(500).json({ error: 'Failed to reset HWID' });
    }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        
        let licenseInfo = null;
        if (user.licenseKey) {
            const license = await License.findOne({ key: user.licenseKey });
            if (license) {
                if (license.status === 'revoked' || license.status === 'expired') {
                    user.needsActivation = true;
                    user.licenseKey = null;
                    await user.save();
                } else {
                    let timeRemaining = null;
                    if (license.expiresAt) {
                        const now = new Date();
                        const diff = license.expiresAt - now;
                        const daysLeft = Math.ceil(diff / (1000 * 60 * 60 * 24));
                        timeRemaining = daysLeft > 0 ? `${daysLeft} days` : 'Expired';
                    } else {
                        timeRemaining = 'Lifetime';
                    }

                    licenseInfo = {
                        type: license.type,
                        expiresAt: license.expiresAt,
                        status: license.status,
                        timeRemaining
                    };
                }
            }
        }

        res.json({
            ...user.toObject(),
            license: licenseInfo
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update user profile
app.patch('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { email, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (email && email !== user.email) {
            const emailExists = await User.findOne({ email, _id: { $ne: user._id } });
            if (emailExists) {
                return res.status(400).json({ error: 'Email already in use' });
            }
            user.email = email;
        }

        if (currentPassword && newPassword) {
            const validPassword = await bcrypt.compare(currentPassword, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }
            user.password = await bcrypt.hash(newPassword, 10);
        }

        await user.save();
        await logActivity(user._id, user.username, 'USER_UPDATE_PROFILE', '', req.ip);

        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Get user configs
app.get('/api/configs', authenticateToken, async (req, res) => {
    try {
        const configs = await Config.find({ userId: req.user.id })
            .sort({ createdAt: -1 });
        res.json(configs);
    } catch (error) {
        console.error('Configs fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch configs' });
    }
});

// Save config
app.post('/api/configs', authenticateToken, async (req, res) => {
    try {
        const { name, settings } = req.body;

        const config = await Config.create({
            userId: req.user.id,
            name,
            settings
        });

        res.json(config);
    } catch (error) {
        console.error('Config save error:', error);
        res.status(500).json({ error: 'Failed to save config' });
    }
});

// Delete config
app.delete('/api/configs/:id', authenticateToken, async (req, res) => {
    try {
        await Config.findOneAndDelete({
            _id: req.params.id,
            userId: req.user.id
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Config delete error:', error);
        res.status(500).json({ error: 'Failed to delete config' });
    }
});

// Get user macros
app.get('/api/macros', authenticateToken, async (req, res) => {
    try {
        const macros = await Macro.find({ userId: req.user.id })
            .sort({ createdAt: -1 });
        res.json(macros);
    } catch (error) {
        console.error('Macros fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch macros' });
    }
});

// Save macro
app.post('/api/macros', authenticateToken, async (req, res) => {
    try {
        const { name, intervals, cps } = req.body;

        const macro = await Macro.create({
            userId: req.user.id,
            name,
            intervals,
            cps
        });

        res.json(macro);
    } catch (error) {
        console.error('Macro save error:', error);
        res.status(500).json({ error: 'Failed to save macro' });
    }
});

// Update total clicks
app.post('/api/user/clicks', authenticateToken, async (req, res) => {
    try {
        const { count } = req.body;
        
        await User.findByIdAndUpdate(
            req.user.id,
            { $inc: { totalClicks: count } }
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Click update error:', error);
        res.status(500).json({ error: 'Failed to update clicks' });
    }
});

// Agent validation
app.get('/api/agent/validate', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.status === 'banned') {
            return res.status(403).json({ error: 'Account banned' });
        }

        if (user.needsActivation) {
            return res.status(403).json({ error: 'Account needs activation' });
        }

        res.json({ 
            valid: true, 
            userId: user._id,
            username: user.username
        });
    } catch (error) {
        console.error('Agent validation error:', error);
        res.status(500).json({ error: 'Validation failed' });
    }
});

// Get agent settings
app.get('/api/agent/settings', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        if (!user || user.needsActivation) {
            return res.status(403).json({ error: 'Account not activated' });
        }

        let config = await Config.findOne({ userId: req.user.id, name: 'default' });

        if (!config) {
            config = await Config.create({
                userId: req.user.id,
                name: 'default'
            });
        }

        console.log('[AGENT] Settings fetched for', user.username);

        res.json({
    // Basic clicker settings
    enabled: config.enabled,
    cps: config.cps,
    leftClick: config.leftClick,
    blatantMode: config.blatantMode,
    holdToClick: config.holdToClick,
    hotkeyCode: config.hotkeyCode,
    useMacro: config.useMacro,
    macroIntervals: config.macroIntervals || [],
    
    // Randomization settings
    enableRandomization: config.enableRandomization,
    randomizationAmount: config.randomizationAmount,
    
    // Exhaust settings
    exhaustMode: config.exhaustMode,
    exhaustDropCps: config.exhaustDropCps,
    exhaustChance: config.exhaustChance,
    
    // Spike settings
    spikeMode: config.spikeMode,
    spikeIncreaseCps: config.spikeIncreaseCps,
    spikeChance: config.spikeChance,
    
    // Blockhit settings
    blockhitEnabled: config.blockhitEnabled,
    blockChance: config.blockChance,
    holdLengthMin: config.holdLengthMin,
    holdLengthMax: config.holdLengthMax,
    delayMin: config.delayMin,
    delayMax: config.delayMax,
    onlyWhileClicking: config.onlyWhileClicking,
    
    // Throw Pot settings
    throwPotEnabled: config.throwPotEnabled,
    throwPotHotkey: config.throwPotHotkey,
    throwPotWeaponSlot: config.throwPotWeaponSlot,
    throwPotSlots: config.throwPotSlots,
    throwPotSlotDelay: config.throwPotSlotDelay,
    throwPotThrowDelay: config.throwPotThrowDelay,
    throwPotReturnDelay: config.throwPotReturnDelay,
    
    // Loader settings
    hideLoader: config.hideLoader,
});
    } catch (error) {
        console.error('Settings fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update agent settings
app.post('/api/agent/settings', authenticateToken, async (req, res) => {
    try {
        const updates = req.body;

        console.log('[AGENT] Settings update for', req.user.username, ':', Object.keys(updates));

        const config = await Config.findOneAndUpdate(
            { userId: req.user.id, name: 'default' },
            { 
                $set: updates,
                updatedAt: new Date()
            },
            { upsert: true, new: true }
        );

        const userWs = connectedClients.get(req.user.id);
        if (userWs && userWs.readyState === WebSocket.OPEN) {
            userWs.send(JSON.stringify({
                type: 'settings_updated',
                settings: updates
            }));
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Settings update error:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// Agent heartbeat
app.post('/api/agent/heartbeat', authenticateToken, async (req, res) => {
    try {
        const { clickerEnabled, actualCps, totalClicks } = req.body;

        await User.findByIdAndUpdate(req.user.id, { lastSeen: new Date() });

        const userWs = connectedClients.get(req.user.id);
        if (userWs && userWs.readyState === WebSocket.OPEN) {
            userWs.send(JSON.stringify({
                type: 'agent_heartbeat',
                data: { clickerEnabled, actualCps, totalClicks }
            }));
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Heartbeat error:', error);
        res.status(500).json({ error: 'Heartbeat failed' });
    }
});

// Update click count
app.post('/api/agent/clicks', authenticateToken, async (req, res) => {
    try {
        const { count } = req.body;
        
        await User.findByIdAndUpdate(
            req.user.id,
            { $inc: { totalClicks: count } }
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Click update error:', error);
        res.status(500).json({ error: 'Failed to update clicks' });
    }
});

// Get macros
app.get('/api/agent/macros', authenticateToken, async (req, res) => {
    try {
        const macros = await Macro.find({ userId: req.user.id })
            .sort({ createdAt: -1 });
        
        res.json(macros);
    } catch (error) {
        console.error('Macros fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch macros' });
    }
});

// Log agent activity
app.post('/api/agent/log', authenticateToken, async (req, res) => {
    try {
        const { action, details } = req.body;
        
        await logActivity(req.user.id, req.user.username, action, details || '', req.ip);

        res.json({ success: true });
    } catch (error) {
        console.error('Log error:', error);
        res.status(500).json({ error: 'Failed to log activity' });
    }
});

// Create HTTP server from Express app
const server = http.createServer(app);

// Start HTTP server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

// Create WebSocket server using the HTTP server
const wss = new WebSocket.Server({ server });
const connectedClients = new Map();

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) {
        ws.close();
        return;
    }

    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) {
            ws.close();
            return;
        }

        connectedClients.set(user.id, ws);
        console.log(`[WS] User ${user.username} connected`);

        await User.findByIdAndUpdate(user.id, { lastSeen: new Date() });

        ws.send(JSON.stringify({ type: 'connected', message: 'WebSocket connected' }));

        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message);
                await handleWebSocketMessage(user, data, ws);
            } catch (error) {
                console.error('[WS] Message error:', error);
            }
        });

        ws.on('close', () => {
            connectedClients.delete(user.id);
            console.log(`[WS] User ${user.username} disconnected`);
        });
    });
});

async function handleWebSocketMessage(user, data, ws) {
    switch(data.type) {
        case 'heartbeat':
            await User.findByIdAndUpdate(user.id, { lastSeen: new Date() });
            ws.send(JSON.stringify({ type: 'heartbeat_ack' }));
            break;

        case 'update_clicks':
            await User.findByIdAndUpdate(
                user.id,
                { $inc: { totalClicks: data.count || 1 } }
            );
            break;

        case 'clicker_state':
            ws.send(JSON.stringify({ 
                type: 'state_update', 
                state: data.state 
            }));
            break;

        case 'license_revoked':
            ws.send(JSON.stringify({ 
                type: 'license_revoked',
                message: 'Your license has been revoked. Please activate with a new license key.'
            }));
            break;
    }
}

function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 20; i++) {
        if (i > 0 && i % 5 === 0) key += '-';
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

module.exports = app;
