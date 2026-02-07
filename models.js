const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    status: {
        type: String,
        enum: ['active', 'banned'],
        default: 'active'
    },
    licenseKey: {
        type: String,
        default: null
    },
    needsActivation: {
        type: Boolean,
        default: true
    },
    totalClicks: {
        type: Number,
        default: 0
    },

    hwid: {
        type: String,  // Stored as JSON string
        default: null
    },
    hwidFingerprint: {
        type: String,  // Quick lookup hash
        default: null
    },
    firstLoginCompleted: {
        type: Boolean,
        default: false
    },
    hwidLocked: {
        type: Boolean,
        default: false  // If true, HWID cannot be changed
    },

    lastSeen: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Session Schema (replaces token.txt file)
const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    hwid: {
        type: String,
        default: null  // Hardware ID for security
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600 // Auto-delete after 1 hour
    }
});

// License Schema
const licenseSchema = new mongoose.Schema({
    key: {
        type: String,
        required: true,
        unique: true
    },
    type: {
        type: String,
        enum: ['week', 'month', 'lifetime'],
        default: 'month'
    },
    status: {
        type: String,
        enum: ['unused', 'active', 'expired', 'revoked'],
        default: 'unused'
    },
    maxUses: {
        type: Number,
        default: 1
    },
    currentUses: {
        type: Number,
        default: 0
    },
    usedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    expiresAt: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Activity Schema
const activitySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    username: {
        type: String,
        required: true
    },
    action: {
        type: String,
        required: true
    },
    details: {
        type: String,
        default: ''
    },
    ipAddress: {
        type: String,
        default: null
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

// Config Schema - Updated to store actual module settings
const configSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    name: {
        type: String,
        required: true,
        default: 'default'
    },
    // Clicker settings
    enabled: { type: Boolean, default: false },
    cps: { type: Number, default: 10.0 },
    leftClick: { type: Boolean, default: true },
    blatantMode: { type: Boolean, default: false },
    exhaustMode: { type: Boolean, default: false },
    exhaustAmount: { type: Number, default: 20 },
    holdToClick: { type: Boolean, default: true },
    hotkeyCode: { type: Number, default: 117 },
    useMacro: { type: Boolean, default: false },
    macroIntervals: { type: [Number], default: [] },
    
    // Overlay settings
    overlayEnabled: { type: Boolean, default: true },
    overlayScale: { type: Number, default: 100 },
    overlayTextColorR: { type: Number, default: 255 },
    overlayTextColorG: { type: Number, default: 255 },
    overlayTextColorB: { type: Number, default: 255 },
    overlayBackground: { type: Boolean, default: true },
    overlayLowercase: { type: Boolean, default: true },
    overlayColorbar: { type: Boolean, default: false },
    overlaySuffix: { type: Boolean, default: true },
    overlayShadow: { type: Boolean, default: true },
    overlayRainbow: { type: Boolean, default: false },
    overlayWatermark: { type: Boolean, default: true },
    overlayBgColorR: { type: Number, default: 0 },
    overlayBgColorG: { type: Number, default: 0 },
    overlayBgColorB: { type: Number, default: 0 },
    overlayBgOpacity: { type: Number, default: 47 },
    
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Update timestamp on save
configSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

// Macro Schema
const macroSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    name: {
        type: String,
        required: true
    },
    intervals: {
        type: [Number],
        required: true
    },
    cps: {
        type: Number,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const License = mongoose.model('License', licenseSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Config = mongoose.model('Config', configSchema);
const Macro = mongoose.model('Macro', macroSchema);

module.exports = {
    User,
    Session,
    License,
    Activity,
    Config,
    Macro
};