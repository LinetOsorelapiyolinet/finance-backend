const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const validator = require('validator');

dotenv.config();

const prisma = new PrismaClient();

const validatePassword = (password) => {
  const errors = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character (!@#$%^&*)');
  }
  
  const weakPasswords = [
    'password', 'password123', '12345678', 'qwerty123', 
    'admin123', 'letmein', 'welcome123', 'password1',
    '123456789', 'qwertyuiop', '1234567890'
  ];
  if (weakPasswords.includes(password.toLowerCase())) {
    errors.push('Password is too common. Please choose a stronger password');
  }
  
  return errors;
};

async function initializeDatabase() {
    try {
        const roleCount = await prisma.role.count();
        
        if (roleCount === 0) {
            await prisma.role.createMany({
                data: [
                    { id: 1, name: 'admin', description: 'Full access to all features including user management' },
                    { id: 2, name: 'analyst', description: 'Can view records and access insights' },
                    { id: 3, name: 'viewer', description: 'Can only view dashboard data' }
                ]
            });
            console.log('Default roles created');
        }
        
        const adminExists = await prisma.user.findUnique({
            where: { email: 'admin@finance.com' }
        });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('Admin@123', 10);
            const admin = await prisma.user.create({
                data: {
                    email: 'admin@finance.com',
                    password: hashedPassword,
                    name: 'System Admin',
                    roleId: 1,
                    status: 'active'
                }
            });
            
            await prisma.subscription.create({
                data: {
                    userId: admin.id,
                    plan: 'enterprise',
                    status: 'active',
                    endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
                    amount: 0
                }
            });
            
            console.log('Admin user created');
        }
        
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error.message);
    }
}

const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }
    next();
};

const protect = async (req, res, next) => {
    try {
        let token;
        
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Not authorized, no token provided' 
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        
        const user = await prisma.user.findUnique({
            where: { id: decoded.id },
            include: {
                role: true,
                subscription: true
            }
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        if (user.status !== 'active') {
            return res.status(401).json({ 
                success: false, 
                message: 'Account is inactive' 
            });
        }
        
        req.user = {
            id: user.id,
            email: user.email,
            name: user.name,
            roleId: user.roleId,
            roleName: user.role.name,
            status: user.status,
            subscription: user.subscription
        };
        next();
    } catch (error) {
        res.status(401).json({ 
            success: false, 
            message: 'Not authorized' 
        });
    }
};

const requireSubscription = (requiredPlan) => {
    return async (req, res, next) => {
        try {
            const user = await prisma.user.findUnique({
                where: { id: req.user.id },
                include: { subscription: true }
            });
            
            if (!user.subscription) {
                return res.status(403).json({
                    success: false,
                    message: 'No active subscription found. Please subscribe to access this feature.'
                });
            }
            
            if (user.subscription.status !== 'active') {
                return res.status(403).json({
                    success: false,
                    message: 'Your subscription is ' + user.subscription.status + '. Please renew to access this feature.'
                });
            }
            
            if (new Date(user.subscription.endDate) < new Date()) {
                await prisma.subscription.update({
                    where: { userId: user.id },
                    data: { status: 'expired' }
                });
                return res.status(403).json({
                    success: false,
                    message: 'Your subscription has expired. Please renew to continue.'
                });
            }
            
            const planLevels = {
                free: 0,
                basic: 1,
                premium: 2,
                enterprise: 3
            };
            
            if (planLevels[user.subscription.plan] < planLevels[requiredPlan]) {
                return res.status(403).json({
                    success: false,
                    message: 'Your current plan (' + user.subscription.plan + ') does not have access to this feature. Please upgrade to ' + requiredPlan + '.'
                });
            }
            
            next();
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    };
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.roleName)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Role ' + req.user.roleName + ' is not authorized' 
            });
        }
        next();
    };
};

const checkPermission = (resource, action) => {
    const permissions = {
        user: {
            create: ['admin'],
            read: ['admin', 'analyst', 'viewer'],
            update: ['admin'],
            delete: ['admin']
        },
        transaction: {
            create: ['admin', 'analyst'],
            read: ['admin', 'analyst', 'viewer'],
            update: ['admin', 'analyst'],
            delete: ['admin']
        },
        dashboard: {
            read: ['admin', 'analyst', 'viewer']
        },
        account: {
            create: ['admin', 'analyst'],
            read: ['admin', 'analyst', 'viewer'],
            update: ['admin', 'analyst'],
            delete: ['admin']
        }
    };
    
    return (req, res, next) => {
        const allowedRoles = permissions[resource]?.[action] || [];
        
        if (!allowedRoles.includes(req.user.roleName)) {
            return res.status(403).json({ 
                success: false, 
                message: 'You don\'t have permission to ' + action + ' ' + resource 
            });
        }
        next();
    };
};

const errorHandler = (err, req, res, next) => {
    console.error(err);
    
    if (err.code === 'P2002') {
        return res.status(400).json({ 
            success: false, 
            message: 'Duplicate entry value' 
        });
    }
    
    if (err.code === 'P2025') {
        return res.status(404).json({ 
            success: false, 
            message: 'Record not found' 
        });
    }
    
    res.status(500).json({
        success: false,
        message: err.message || 'Server Error'
    });
};

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET || 'your-secret-key', {
        expiresIn: process.env.JWT_EXPIRE || '7d'
    });
};

// ===== REGISTER - NOW ALLOWS FREE SIGNUP =====
const register = async (req, res) => {
    try {
        const { email, password, name, role_id = 3 } = req.body;
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please provide a valid email address' 
            });
        }
        
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password validation failed',
                errors: passwordErrors 
            });
        }
        
        const existingUser = await prisma.user.findUnique({
            where: { email }
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }
        
        const roleId = parseInt(role_id);
        if (roleId === 1) {
            return res.status(403).json({ 
                success: false, 
                message: 'You cannot register as an admin.' 
            });
        }
        
        const role = await prisma.role.findUnique({
            where: { id: roleId }
        });
        
        if (!role) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid role' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                roleId: roleId,
                status: 'active'
            },
            include: {
                role: true
            }
        });
        
        await prisma.subscription.create({
            data: {
                userId: user.id,
                plan: 'free',
                status: 'active',
                endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
                amount: 0
            }
        });
        
        await prisma.userSettings.create({
            data: {
                userId: user.id
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: user.id,
                action: 'REGISTER',
                details: 'New user registered: ' + email,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            }
        });
        
        res.status(201).json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role.name,
                token: generateToken(user.id)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== LOGIN - ALLOWS ADMIN & NON-SUBSCRIBERS =====
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                role: true,
                subscription: true
            }
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        if (user.status !== 'active') {
            return res.status(401).json({ 
                success: false, 
                message: 'Account is inactive' 
            });
        }
        
        let subscriptionStatus = 'none';
        if (user.subscription) {
            subscriptionStatus = user.subscription.status;
            if (new Date(user.subscription.endDate) < new Date()) {
                await prisma.subscription.update({
                    where: { userId: user.id },
                    data: { status: 'expired' }
                });
                subscriptionStatus = 'expired';
            }
        }
        
        await prisma.auditLog.create({
            data: {
                userId: user.id,
                action: 'LOGIN',
                details: 'User logged in',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            }
        });
        
        res.json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role.name,
                subscription: user.subscription ? {
                    plan: user.subscription.plan,
                    status: subscriptionStatus,
                    endDate: user.subscription.endDate
                } : null,
                token: generateToken(user.id)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== GET SUBSCRIPTION INFO =====
const getSubscription = async (req, res) => {
    try {
        const subscription = await prisma.subscription.findUnique({
            where: { userId: req.user.id }
        });
        
        if (!subscription) {
            return res.status(404).json({
                success: false,
                message: 'No subscription found'
            });
        }
        
        res.json({
            success: true,
            data: subscription
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== RENEW SUBSCRIPTION =====
const renewSubscription = async (req, res) => {
    try {
        const { paymentId, plan } = req.body;
        
        const subscription = await prisma.subscription.findUnique({
            where: { userId: req.user.id }
        });
        
        if (!subscription) {
            return res.status(404).json({
                success: false,
                message: 'No subscription found'
            });
        }
        
        const planPrices = {
            basic: 9.99,
            premium: 29.99,
            enterprise: 99.99
        };
        
        const updatedSubscription = await prisma.subscription.update({
            where: { userId: req.user.id },
            data: {
                plan: plan || subscription.plan,
                status: 'active',
                endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                paymentId: paymentId || subscription.paymentId,
                amount: planPrices[plan] || subscription.amount
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'RENEW_SUBSCRIPTION',
                details: 'Renewed subscription to ' + (plan || subscription.plan) + ' plan'
            }
        });
        
        res.json({
            success: true,
            message: 'Subscription renewed successfully!',
            data: updatedSubscription
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== ACCOUNT CRUD OPERATIONS =====
const getAccounts = async (req, res) => {
    try {
        const accounts = await prisma.account.findMany({
            where: { 
                userId: req.user.id,
                isActive: true
            }
        });
        res.json({ success: true, data: accounts });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getAccount = async (req, res) => {
    try {
        const account = await prisma.account.findFirst({
            where: {
                id: parseInt(req.params.id),
                userId: req.user.id
            }
        });
        
        if (!account) {
            return res.status(404).json({ success: false, message: 'Account not found' });
        }
        
        res.json({ success: true, data: account });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const createAccount = async (req, res) => {
    try {
        const { name, type, balance = 0 } = req.body;
        
        const account = await prisma.account.create({
            data: {
                userId: req.user.id,
                name,
                type,
                balance: parseFloat(balance)
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'CREATE_ACCOUNT',
                details: 'Created account: ' + name + ' (' + type + ')'
            }
        });
        
        res.status(201).json({ success: true, data: account });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const updateAccount = async (req, res) => {
    try {
        const { name, type, balance, isActive } = req.body;
        
        const account = await prisma.account.update({
            where: {
                id: parseInt(req.params.id)
            },
            data: {
                ...(name && { name }),
                ...(type && { type }),
                ...(balance !== undefined && { balance: parseFloat(balance) }),
                ...(isActive !== undefined && { isActive })
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'UPDATE_ACCOUNT',
                details: 'Updated account: ' + account.name
            }
        });
        
        res.json({ success: true, data: account });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'Account not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
};

const deleteAccount = async (req, res) => {
    try {
        await prisma.account.update({
            where: {
                id: parseInt(req.params.id)
            },
            data: {
                isActive: false
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'DELETE_ACCOUNT',
                details: 'Deleted account ID: ' + req.params.id
            }
        });
        
        res.json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'Account not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== OTHER ROUTES (GET USERS, TRANSACTIONS, ETC.) =====
const getUsers = async (req, res) => {
    try {
        const { status, role_id } = req.query;
        
        const where = {};
        if (status) where.status = status;
        if (role_id) where.roleId = parseInt(role_id);
        
        const users = await prisma.user.findMany({
            where,
            select: {
                id: true,
                email: true,
                name: true,
                status: true,
                roleId: true,
                role: {
                    select: {
                        name: true
                    }
                },
                subscription: {
                    select: {
                        plan: true,
                        status: true,
                        endDate: true
                    }
                },
                createdAt: true
            },
            orderBy: {
                createdAt: 'desc'
            }
        });
        
        const formattedUsers = users.map(user => ({
            id: user.id,
            email: user.email,
            name: user.name,
            status: user.status,
            role_id: user.roleId,
            role_name: user.role.name,
            subscription: user.subscription,
            created_at: user.createdAt
        }));
        
        res.json({ success: true, count: formattedUsers.length, data: formattedUsers });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getUser = async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: parseInt(req.params.id) },
            select: {
                id: true,
                email: true,
                name: true,
                status: true,
                roleId: true,
                role: {
                    select: {
                        name: true
                    }
                },
                subscription: {
                    select: {
                        plan: true,
                        status: true,
                        endDate: true
                    }
                },
                createdAt: true
            }
        });
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ 
            success: true, 
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                status: user.status,
                role_id: user.roleId,
                role_name: user.role.name,
                subscription: user.subscription,
                created_at: user.createdAt
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const createUser = async (req, res) => {
    try {
        const { email, password, name, role_id } = req.body;
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please provide a valid email address' 
            });
        }
        
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password validation failed',
                errors: passwordErrors 
            });
        }
        
        const existingUser = await prisma.user.findUnique({
            where: { email }
        });
        
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                roleId: role_id,
                status: 'active'
            },
            include: {
                role: true
            }
        });
        
        await prisma.userSettings.create({
            data: {
                userId: user.id
            }
        });
        
        await prisma.subscription.create({
            data: {
                userId: user.id,
                plan: 'free',
                status: 'active',
                endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
                amount: 0
            }
        });
        
        res.status(201).json({ 
            success: true, 
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                status: user.status,
                role_id: user.roleId,
                role_name: user.role.name
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const updateUser = async (req, res) => {
    try {
        const { name, role_id, status } = req.body;
        
        const user = await prisma.user.update({
            where: { id: parseInt(req.params.id) },
            data: {
                ...(name && { name }),
                ...(role_id && { roleId: role_id }),
                ...(status && { status })
            },
            include: {
                role: true
            }
        });
        
        res.json({ 
            success: true, 
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                status: user.status,
                role_id: user.roleId,
                role_name: user.role.name
            }
        });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
};

const deleteUser = async (req, res) => {
    try {
        await prisma.user.delete({
            where: { id: parseInt(req.params.id) }
        });
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== TRANSACTION ROUTES =====
const getTransactions = async (req, res) => {
    try {
        const { type, category, startDate, endDate, limit, offset } = req.query;
        
        const where = {
            userId: req.user.id
        };
        
        if (type) where.type = type;
        if (category) where.category = category;
        if (startDate || endDate) {
            where.date = {};
            if (startDate) where.date.gte = new Date(startDate);
            if (endDate) where.date.lte = new Date(endDate);
        }
        
        const transactions = await prisma.transaction.findMany({
            where,
            orderBy: {
                date: 'desc'
            },
            take: limit ? parseInt(limit) : undefined,
            skip: offset ? parseInt(offset) : undefined
        });
        
        res.json({ success: true, count: transactions.length, data: transactions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getTransaction = async (req, res) => {
    try {
        const transaction = await prisma.transaction.findFirst({
            where: {
                id: parseInt(req.params.id),
                userId: req.user.id
            }
        });
        
        if (!transaction) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        res.json({ success: true, data: transaction });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const createTransaction = async (req, res) => {
    try {
        const { amount, type, category, date, description, accountId } = req.body;
        
        const transaction = await prisma.transaction.create({
            data: {
                userId: req.user.id,
                amount,
                type,
                category,
                date: new Date(date),
                description
            }
        });
        
        if (accountId) {
            const account = await prisma.account.findFirst({
                where: {
                    id: parseInt(accountId),
                    userId: req.user.id
                }
            });
            
            if (account) {
                const newBalance = type === 'income' 
                    ? account.balance + parseFloat(amount)
                    : account.balance - parseFloat(amount);
                    
                await prisma.account.update({
                    where: { id: parseInt(accountId) },
                    data: { balance: newBalance }
                });
            }
        }
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'CREATE_TRANSACTION',
                details: 'Created transaction: ' + category + ' - $' + amount
            }
        });
        
        res.status(201).json({ success: true, data: transaction });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const updateTransaction = async (req, res) => {
    try {
        const { amount, type, category, date, description } = req.body;
        
        const transaction = await prisma.transaction.updateMany({
            where: {
                id: parseInt(req.params.id),
                userId: req.user.id
            },
            data: {
                ...(amount && { amount }),
                ...(type && { type }),
                ...(category && { category }),
                ...(date && { date: new Date(date) }),
                ...(description !== undefined && { description })
            }
        });
        
        if (transaction.count === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        const updatedTransaction = await prisma.transaction.findFirst({
            where: { id: parseInt(req.params.id) }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'UPDATE_TRANSACTION',
                details: 'Updated transaction ID: ' + req.params.id
            }
        });
        
        res.json({ success: true, data: updatedTransaction });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const deleteTransaction = async (req, res) => {
    try {
        const result = await prisma.transaction.deleteMany({
            where: {
                id: parseInt(req.params.id),
                userId: req.user.id
            }
        });
        
        if (result.count === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'DELETE_TRANSACTION',
                details: 'Deleted transaction ID: ' + req.params.id
            }
        });
        
        res.json({ success: true, message: 'Transaction deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== DASHBOARD ROUTES =====
const getDashboardSummary = async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        const where = {
            userId: req.user.id
        };
        
        if (startDate || endDate) {
            where.date = {};
            if (startDate) where.date.gte = new Date(startDate);
            if (endDate) where.date.lte = new Date(endDate);
        }
        
        const transactions = await prisma.transaction.findMany({
            where,
            select: {
                amount: true,
                type: true
            }
        });
        
        let totalIncome = 0;
        let totalExpenses = 0;
        
        transactions.forEach(transaction => {
            if (transaction.type === 'income') {
                totalIncome += parseFloat(transaction.amount);
            } else {
                totalExpenses += parseFloat(transaction.amount);
            }
        });
        
        res.json({
            success: true,
            data: {
                total_income: totalIncome,
                total_expenses: totalExpenses,
                net_balance: totalIncome - totalExpenses,
                total_transactions: transactions.length
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getCategoryWiseTotals = async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        const where = {
            userId: req.user.id
        };
        
        if (startDate || endDate) {
            where.date = {};
            if (startDate) where.date.gte = new Date(startDate);
            if (endDate) where.date.lte = new Date(endDate);
        }
        
        const transactions = await prisma.transaction.findMany({
            where,
            select: {
                category: true,
                type: true,
                amount: true
            }
        });
        
        const categoryMap = new Map();
        
        transactions.forEach(transaction => {
            if (!categoryMap.has(transaction.category)) {
                categoryMap.set(transaction.category, {
                    category: transaction.category,
                    total_income: 0,
                    total_expenses: 0
                });
            }
            
            const categoryData = categoryMap.get(transaction.category);
            if (transaction.type === 'income') {
                categoryData.total_income += parseFloat(transaction.amount);
            } else {
                categoryData.total_expenses += parseFloat(transaction.amount);
            }
        });
        
        res.json({ success: true, data: Array.from(categoryMap.values()) });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getMonthlyTrends = async (req, res) => {
    try {
        const year = req.query.year || new Date().getFullYear();
        
        const transactions = await prisma.transaction.findMany({
            where: {
                userId: req.user.id,
                date: {
                    gte: new Date(year + '-01-01'),
                    lte: new Date(year + '-12-31')
                }
            },
            select: {
                amount: true,
                type: true,
                date: true
            }
        });
        
        const monthlyData = Array(12).fill().map((_, i) => ({
            month: i + 1,
            month_name: new Date(2000, i, 1).toLocaleString('default', { month: 'long' }),
            total_income: 0,
            total_expenses: 0
        }));
        
        transactions.forEach(transaction => {
            const month = new Date(transaction.date).getMonth();
            if (transaction.type === 'income') {
                monthlyData[month].total_income += parseFloat(transaction.amount);
            } else {
                monthlyData[month].total_expenses += parseFloat(transaction.amount);
            }
        });
        
        res.json({ success: true, data: monthlyData });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getRecentActivity = async (req, res) => {
    try {
        const limit = req.query.limit || 10;
        
        const transactions = await prisma.transaction.findMany({
            where: {
                userId: req.user.id
            },
            orderBy: {
                date: 'desc'
            },
            take: parseInt(limit)
        });
        
        res.json({ success: true, data: transactions });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getCompleteDashboard = async (req, res) => {
    try {
        const { startDate, endDate, year } = req.query;
        
        const where = {
            userId: req.user.id
        };
        
        if (startDate || endDate) {
            where.date = {};
            if (startDate) where.date.gte = new Date(startDate);
            if (endDate) where.date.lte = new Date(endDate);
        }
        
        const allTransactions = await prisma.transaction.findMany({
            where,
            select: {
                amount: true,
                type: true
            }
        });
        
        let totalIncome = 0;
        let totalExpenses = 0;
        
        allTransactions.forEach(transaction => {
            if (transaction.type === 'income') {
                totalIncome += parseFloat(transaction.amount);
            } else {
                totalExpenses += parseFloat(transaction.amount);
            }
        });
        
        const categoryTransactions = await prisma.transaction.findMany({
            where,
            select: {
                category: true,
                type: true,
                amount: true
            }
        });
        
        const categoryMap = new Map();
        categoryTransactions.forEach(transaction => {
            if (!categoryMap.has(transaction.category)) {
                categoryMap.set(transaction.category, {
                    category: transaction.category,
                    total_income: 0,
                    total_expenses: 0
                });
            }
            
            const categoryData = categoryMap.get(transaction.category);
            if (transaction.type === 'income') {
                categoryData.total_income += parseFloat(transaction.amount);
            } else {
                categoryData.total_expenses += parseFloat(transaction.amount);
            }
        });
        
        const targetYear = year || new Date().getFullYear();
        const yearlyTransactions = await prisma.transaction.findMany({
            where: {
                userId: req.user.id,
                date: {
                    gte: new Date(targetYear + '-01-01'),
                    lte: new Date(targetYear + '-12-31')
                }
            },
            select: {
                amount: true,
                type: true,
                date: true
            }
        });
        
        const monthlyData = Array(12).fill().map((_, i) => ({
            month: i + 1,
            month_name: new Date(2000, i, 1).toLocaleString('default', { month: 'long' }),
            total_income: 0,
            total_expenses: 0
        }));
        
        yearlyTransactions.forEach(transaction => {
            const month = new Date(transaction.date).getMonth();
            if (transaction.type === 'income') {
                monthlyData[month].total_income += parseFloat(transaction.amount);
            } else {
                monthlyData[month].total_expenses += parseFloat(transaction.amount);
            }
        });
        
        const recentTransactions = await prisma.transaction.findMany({
            where: {
                userId: req.user.id
            },
            orderBy: {
                date: 'desc'
            },
            take: 10
        });
        
        const accounts = await prisma.account.findMany({
            where: {
                userId: req.user.id,
                isActive: true
            }
        });
        
        res.json({
            success: true,
            data: {
                summary: {
                    total_income: totalIncome,
                    total_expenses: totalExpenses,
                    net_balance: totalIncome - totalExpenses,
                    total_transactions: allTransactions.length
                },
                category_breakdown: Array.from(categoryMap.values()),
                monthly_trends: monthlyData,
                recent_transactions: recentTransactions,
                accounts: accounts
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ===== SETTINGS ROUTES =====
const getSettings = async (req, res) => {
    try {
        let settings = await prisma.userSettings.findUnique({
            where: { userId: req.user.id }
        });
        
        if (!settings) {
            settings = await prisma.userSettings.create({
                data: {
                    userId: req.user.id
                }
            });
        }
        
        res.json({ success: true, data: settings });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const updateSettings = async (req, res) => {
    try {
        const {
            emailNotifications,
            pushNotifications,
            weeklyReports,
            monthlyReports,
            theme,
            accentColor,
            fontSize,
            compactView,
            twoFactorAuth,
            sessionTimeout,
            shareAnalytics,
            publicProfile
        } = req.body;
        
        const settings = await prisma.userSettings.upsert({
            where: { userId: req.user.id },
            update: {
                emailNotifications: emailNotifications !== undefined ? emailNotifications : true,
                pushNotifications: pushNotifications !== undefined ? pushNotifications : true,
                weeklyReports: weeklyReports !== undefined ? weeklyReports : true,
                monthlyReports: monthlyReports !== undefined ? monthlyReports : true,
                theme: theme || 'dark',
                accentColor: accentColor || 'cyan',
                fontSize: fontSize || 'medium',
                compactView: compactView !== undefined ? compactView : false,
                twoFactorAuth: twoFactorAuth !== undefined ? twoFactorAuth : false,
                sessionTimeout: sessionTimeout || 30,
                shareAnalytics: shareAnalytics !== undefined ? shareAnalytics : false,
                publicProfile: publicProfile !== undefined ? publicProfile : false
            },
            create: {
                userId: req.user.id,
                emailNotifications: emailNotifications !== undefined ? emailNotifications : true,
                pushNotifications: pushNotifications !== undefined ? pushNotifications : true,
                weeklyReports: weeklyReports !== undefined ? weeklyReports : true,
                monthlyReports: monthlyReports !== undefined ? monthlyReports : true,
                theme: theme || 'dark',
                accentColor: accentColor || 'cyan',
                fontSize: fontSize || 'medium',
                compactView: compactView !== undefined ? compactView : false,
                twoFactorAuth: twoFactorAuth !== undefined ? twoFactorAuth : false,
                sessionTimeout: sessionTimeout || 30,
                shareAnalytics: shareAnalytics !== undefined ? shareAnalytics : false,
                publicProfile: publicProfile !== undefined ? publicProfile : false
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'UPDATE_SETTINGS',
                details: 'User updated their settings'
            }
        });
        
        res.json({ success: true, data: settings });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const getAuditLogs = async (req, res) => {
    try {
        const logs = await prisma.auditLog.findMany({
            where: { userId: req.user.id },
            orderBy: { createdAt: 'desc' },
            take: 50
        });
        res.json({ success: true, data: logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const createAuditLog = async (req, res) => {
    try {
        const { action, details } = req.body;
        const log = await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action,
                details,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            }
        });
        res.json({ success: true, data: log });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// ==============================================
// APP SETUP
// ==============================================

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

const registerValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('name').notEmpty().trim(),
    body('role_id').optional().isInt()
];

const loginValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
];

const transactionCreateValidation = [
    body('amount').isFloat({ min: 0.01 }),
    body('type').isIn(['income', 'expense']),
    body('category').notEmpty().trim(),
    body('date').isISO8601().toDate(),
    body('description').optional().trim(),
    body('accountId').optional().isInt()
];

const transactionUpdateValidation = [
    body('amount').optional().isFloat({ min: 0.01 }),
    body('type').optional().isIn(['income', 'expense']),
    body('category').optional().trim(),
    body('date').optional().isISO8601().toDate(),
    body('description').optional().trim()
];

const userUpdateValidation = [
    body('name').optional().trim(),
    body('role_id').optional().isInt(),
    body('status').optional().isIn(['active', 'inactive'])
];

const accountCreateValidation = [
    body('name').notEmpty().trim(),
    body('type').notEmpty().trim(),
    body('balance').optional().isFloat({ min: 0 })
];

const accountUpdateValidation = [
    body('name').optional().trim(),
    body('type').optional().trim(),
    body('balance').optional().isFloat({ min: 0 }),
    body('isActive').optional().isBoolean()
];

app.use(passport.initialize());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'https://finance-backend-api-74z9.onrender.com/auth/google/callback',
    passReqToCallback: true
  },
  async function(req, accessToken, refreshToken, profile, done) {
    try {
      let user = await prisma.user.findUnique({
        where: { email: profile.emails[0].value }
      });
      
      if (!user) {
        user = await prisma.user.create({
          data: {
            email: profile.emails[0].value,
            name: profile.displayName || profile.name.givenName || 'Google User',
            password: '',
            roleId: 3,
            status: 'active'
          }
        });
        
        await prisma.userSettings.create({
          data: {
            userId: user.id
          }
        });
        
        await prisma.subscription.create({
          data: {
            userId: user.id,
            plan: 'free',
            status: 'active',
            endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            amount: 0
          }
        });
        
        console.log('New Google user created:', user.email);
      } else {
        console.log('Existing user logged in via Google:', user.email);
      }
      
      return done(null, user);
    } catch (error) {
      console.error('Google OAuth error:', error);
      return done(error, null);
    }
  }
));

app.get('/auth/google',
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: process.env.FRONTEND_URL + '?error=google_failed' || 'https://finance-dashboard-ashy-six.vercel.app?error=google_failed',
    session: false
  }),
  function(req, res) {
    try {
      const token = jwt.sign(
        { 
          id: req.user.id, 
          email: req.user.email,
          name: req.user.name,
          role: req.user.role
        },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '30d' }
      );
      
      const frontendUrl = process.env.FRONTEND_URL || 'https://finance-dashboard-ashy-six.vercel.app';
      res.redirect(frontendUrl + '?token=' + token);
    } catch (error) {
      console.error('Token generation error:', error);
      const frontendUrl = process.env.FRONTEND_URL || 'https://finance-dashboard-ashy-six.vercel.app';
      res.redirect(frontendUrl + '?error=token_failed');
    }
  }
);

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ==============================================
// AUTH ROUTES
// ==============================================
app.post('/api/auth/register', registerValidation, validateRequest, register);
app.post('/api/auth/login', loginValidation, validateRequest, login);
app.get('/api/auth/me', protect, async (req, res) => {
    res.json({ success: true, data: req.user });
});

// ==============================================
// SUBSCRIPTION ROUTES
// ==============================================
app.get('/api/subscription', protect, getSubscription);
app.post('/api/subscription/renew', protect, renewSubscription);

// ==============================================
// USER ROUTES
// ==============================================
app.get('/api/users', protect, authorize('admin'), getUsers);
app.get('/api/users/:id', protect, authorize('admin'), getUser);
app.post('/api/users', protect, authorize('admin'), registerValidation, validateRequest, createUser);
app.put('/api/users/:id', protect, authorize('admin'), userUpdateValidation, validateRequest, updateUser);
app.delete('/api/users/:id', protect, authorize('admin'), deleteUser);

// ==============================================
// ADMIN PORTAL ROUTES
// ==============================================
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                role: true,
                subscription: true
            }
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        if (user.role.name !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin privileges required.' 
            });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        if (user.status !== 'active') {
            return res.status(401).json({ 
                success: false, 
                message: 'Account is inactive' 
            });
        }
        
        await prisma.auditLog.create({
            data: {
                userId: user.id,
                action: 'ADMIN_LOGIN',
                details: 'Admin user logged in via admin portal',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            }
        });
        
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email,
                name: user.name,
                role: user.role.name,
                isAdmin: true
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '1d' }
        );
        
        res.json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role.name,
                isAdmin: true,
                token: token
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/users', protect, authorize('admin'), async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                status: true,
                roleId: true,
                role: {
                    select: {
                        name: true
                    }
                },
                subscription: {
                    select: {
                        plan: true,
                        status: true,
                        endDate: true
                    }
                },
                createdAt: true
            },
            orderBy: {
                createdAt: 'desc'
            }
        });
        
        res.json({ success: true, data: users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/users/:id', protect, authorize('admin'), async (req, res) => {
    try {
        const { status, roleId } = req.body;
        const userId = parseInt(req.params.id);
        
        const user = await prisma.user.update({
            where: { id: userId },
            data: {
                ...(status && { status }),
                ...(roleId && { roleId: parseInt(roleId) })
            },
            include: {
                role: true
            }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'ADMIN_UPDATE_USER',
                details: 'Admin updated user: ' + user.email
            }
        });
        
        res.json({ 
            success: true, 
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                status: user.status,
                role: user.role.name
            }
        });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/users/:id', protect, authorize('admin'), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (userId === req.user.id) {
            return res.status(403).json({ 
                success: false, 
                message: 'You cannot delete your own admin account.' 
            });
        }
        
        await prisma.user.delete({
            where: { id: userId }
        });
        
        await prisma.auditLog.create({
            data: {
                userId: req.user.id,
                action: 'ADMIN_DELETE_USER',
                details: 'Admin deleted user ID: ' + userId
            }
        });
        
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        if (error.code === 'P2025') {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==============================================
// ACCOUNT ROUTES
// ==============================================
app.get('/api/accounts', protect, getAccounts);
app.get('/api/accounts/:id', protect, getAccount);
app.post('/api/accounts', protect, accountCreateValidation, validateRequest, createAccount);
app.put('/api/accounts/:id', protect, accountUpdateValidation, validateRequest, updateAccount);
app.delete('/api/accounts/:id', protect, deleteAccount);

// ==============================================
// TRANSACTION ROUTES
// ==============================================
app.get('/api/transactions', protect, checkPermission('transaction', 'read'), getTransactions);
app.get('/api/transactions/:id', protect, checkPermission('transaction', 'read'), getTransaction);
app.post('/api/transactions', protect, checkPermission('transaction', 'create'), transactionCreateValidation, validateRequest, createTransaction);
app.put('/api/transactions/:id', protect, checkPermission('transaction', 'update'), transactionUpdateValidation, validateRequest, updateTransaction);
app.delete('/api/transactions/:id', protect, checkPermission('transaction', 'delete'), deleteTransaction);

// ==============================================
// DASHBOARD ROUTES
// ==============================================
app.get('/api/dashboard/summary', protect, checkPermission('dashboard', 'read'), getDashboardSummary);
app.get('/api/dashboard/category-totals', protect, checkPermission('dashboard', 'read'), getCategoryWiseTotals);
app.get('/api/dashboard/monthly-trends', protect, checkPermission('dashboard', 'read'), getMonthlyTrends);
app.get('/api/dashboard/recent-activity', protect, checkPermission('dashboard', 'read'), getRecentActivity);
app.get('/api/dashboard/complete', protect, checkPermission('dashboard', 'read'), getCompleteDashboard);

// ==============================================
// SETTINGS ROUTES
// ==============================================
app.get('/api/settings', protect, getSettings);
app.put('/api/settings', protect, updateSettings);
app.get('/api/audit-logs', protect, getAuditLogs);
app.post('/api/audit-log', protect, createAuditLog);

app.use(errorHandler);

async function startServer() {
    try {
        await initializeDatabase();
        app.listen(PORT, () => {
            console.log('\n=================================');
            console.log('🚀 Server running on port ' + PORT);
            console.log('📍 API URL: http://localhost:' + PORT);
            console.log('=================================');
            console.log('\n📝 Test Credentials:');
            console.log('   Email: admin@finance.com');
            console.log('   Password: Admin@123');
            console.log('=================================\n');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

process.on('SIGINT', async () => {
    await prisma.$disconnect();
    console.log('Disconnected from database');
    process.exit(0);
});
