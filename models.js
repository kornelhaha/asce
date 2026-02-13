// models.js - Updated with randomization, throwpot, and loader settings

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
        type: String,
        default: null
    },
    hwidFingerprint: {
        type: String,
        default: null
    },
    firstLoginCompleted: {
        type: Boolean,
        default: false
    },
    hwidLocked: {
        type: Boolean,
        default: false
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

// Session Schema
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
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600
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

// Config Schema - UPDATED with all new features
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
    
    // ===== CLICKER SETTINGS =====
    enabled: { type: Boolean, default: false },
    cps: { type: Number, default: 10.0 },
    leftClick: { type: Boolean, default: true },
    blatantMode: { type: Boolean, default: false },
    holdToClick: { type: Boolean, default: true },
    hotkeyCode: { type: Number, default: 117 },  // F6
    
    // ===== RANDOMIZATION SETTINGS =====
    enableRandomization: { type: Boolean, default: false },
    randomizationAmount: { type: Number, default: 1.0, min: 0.1, max: 5.0 },
    
    // ===== EXHAUST MODE SETTINGS =====
    exhaustMode: { type: Boolean, default: false },
    exhaustDropCps: { type: Number, default: 3.0 },
    exhaustChance: { type: Number, default: 50 },
    
    // ===== SPIKE MODE SETTINGS =====
    spikeMode: { type: Boolean, default: false },
    spikeIncreaseCps: { type: Number, default: 5.0 },
    spikeChance: { type: Number, default: 30 },
    
    // ===== BLOCKHIT SETTINGS =====
    blockhitEnabled: { type: Boolean, default: false },
    blockChance: { type: Number, default: 50 },
    holdLengthMin: { type: Number, default: 50 },
    holdLengthMax: { type: Number, default: 150 },
    delayMin: { type: Number, default: 100 },
    delayMax: { type: Number, default: 300 },
    onlyWhileClicking: { type: Boolean, default: true },
    
    // ===== THROW POT SETTINGS =====
    throwPotEnabled: { type: Boolean, default: false },
    throwPotHotkey: { type: Number, default: 0x52 },  // R key
    throwPotWeaponSlot: { type: Number, default: 1 },
    throwPotSlots: { type: String, default: "011000000" },  // Slots 2 and 3 enabled
    throwPotSlotDelay: { type: Number, default: 50 },
    throwPotThrowDelay: { type: Number, default: 100 },
    throwPotReturnDelay: { type: Number, default: 50 },
    
    // ===== LOADER SETTINGS =====
    hideLoader: { type: Boolean, default: false },
    
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

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const License = mongoose.model('License', licenseSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Config = mongoose.model('Config', configSchema);

module.exports = {
    User,
    Session,
    License,
    Activity,
    Config
};
