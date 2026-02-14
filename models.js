// models.js - Updated with Right Clicker and Config Manager

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

// Config Schema - User's default settings
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
    
    // ===== LEFT CLICKER SETTINGS =====
    enabled: { type: Boolean, default: false },
    cps: { type: Number, default: 10.0 },
    leftClick: { type: Boolean, default: true },
    blatantMode: { type: Boolean, default: false },
    holdToClick: { type: Boolean, default: true },
    hotkeyCode: { type: Number, default: 117 },  // F6
    
    // ===== LEFT CLICKER RANDOMIZATION =====
    enableRandomization: { type: Boolean, default: false },
    randomizationAmount: { type: Number, default: 1.0, min: 0.1, max: 5.0 },
    
    // ===== LEFT CLICKER EXHAUST MODE =====
    exhaustMode: { type: Boolean, default: false },
    exhaustDropCps: { type: Number, default: 3.0 },
    exhaustChance: { type: Number, default: 50 },
    
    // ===== LEFT CLICKER SPIKE MODE =====
    spikeMode: { type: Boolean, default: false },
    spikeIncreaseCps: { type: Number, default: 5.0 },
    spikeChance: { type: Number, default: 30 },
    
    // ===== RIGHT CLICKER SETTINGS =====
    rightEnabled: { type: Boolean, default: false },
    rightCps: { type: Number, default: 10.0 },
    rightBlatantMode: { type: Boolean, default: false },
    rightHoldToClick: { type: Boolean, default: true },
    rightHotkeyCode: { type: Number, default: 118 },  // F7
    rightEnableRandomization: { type: Boolean, default: false },
    rightRandomizationAmount: { type: Number, default: 1.0, min: 0.1, max: 5.0 },
    
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
    throwPotSlots: { type: String, default: "011000000" },
    throwPotSlotDelay: { type: Number, default: 50 },
    throwPotThrowDelay: { type: Number, default: 100 },
    throwPotReturnDelay: { type: Number, default: 50 },
    throwPotWeaponKeybinds: { 
        type: String, 
        default: JSON.stringify([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]) 
    },
    throwPotPotionKeybinds: { 
        type: String, 
        default: JSON.stringify([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]) 
    },
    
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

// Saved Config Schema - User's saved configurations
const savedConfigSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    settings: {
        type: Object,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Update timestamp on save
configSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

// Index for faster queries
savedConfigSchema.index({ userId: 1, createdAt: -1 });

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const License = mongoose.model('License', licenseSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Config = mongoose.model('Config', configSchema);
const SavedConfig = mongoose.model('SavedConfig', savedConfigSchema);

module.exports = {
    User,
    Session,
    License,
    Activity,
    Config,
    SavedConfig
};
