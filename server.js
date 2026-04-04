const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

dotenv.config();

const prisma = new PrismaClient();

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
            await prisma.user.create({
                data: {
                    email: 'admin@finance.com',
                    password: hashedPassword,
                    name: 'System Admin',
                    roleId: 1,
                    status: 'active'
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
                role: true
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
            status: user.status
        };
        next();
    } catch (error) {
        res.status(401).json({ 
            success: false, 
            message: 'Not authorized' 
        });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.roleName)) {
            return res.status(403).json({ 
                success: false, 
                message: `Role ${req.user.roleName} is not authorized` 
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
        }
    };
    
    return (req, res, next) => {
        const allowedRoles = permissions[resource]?.[action] || [];
        
        if (!allowedRoles.includes(req.user.roleName)) {
            return res.status(403).json({ 
                success: false, 
                message: `You don't have permission to ${action} ${resource}` 
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

const register = async (req, res) => {
    try {
        const { email, password, name, role_id = 3 } = req.body;
        
        const existingUser = await prisma.user.findUnique({
            where: { email }
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }
        
        const role = await prisma.role.findUnique({
            where: { id: role_id }
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
                roleId: role_id,
                status: 'active'
            },
            include: {
                role: true
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

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                role: true
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
        
        res.json({
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
        const { amount, type, category, date, description } = req.body;
        
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
        
        res.json({ success: true, message: 'Transaction deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

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
                    gte: new Date(`${year}-01-01`),
                    lte: new Date(`${year}-12-31`)
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
                    gte: new Date(`${targetYear}-01-01`),
                    lte: new Date(`${targetYear}-12-31`)
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
                recent_transactions: recentTransactions
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

const registerValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
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
    body('description').optional().trim()
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

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/api/auth/register', registerValidation, validateRequest, register);
app.post('/api/auth/login', loginValidation, validateRequest, login);
app.get('/api/auth/me', protect, async (req, res) => {
    res.json({ success: true, data: req.user });
});

app.get('/api/users', protect, authorize('admin'), getUsers);
app.get('/api/users/:id', protect, authorize('admin'), getUser);
app.post('/api/users', protect, authorize('admin'), registerValidation, validateRequest, createUser);
app.put('/api/users/:id', protect, authorize('admin'), userUpdateValidation, validateRequest, updateUser);
app.delete('/api/users/:id', protect, authorize('admin'), deleteUser);

app.get('/api/transactions', protect, checkPermission('transaction', 'read'), getTransactions);
app.get('/api/transactions/:id', protect, checkPermission('transaction', 'read'), getTransaction);
app.post('/api/transactions', protect, checkPermission('transaction', 'create'), transactionCreateValidation, validateRequest, createTransaction);
app.put('/api/transactions/:id', protect, checkPermission('transaction', 'update'), transactionUpdateValidation, validateRequest, updateTransaction);
app.delete('/api/transactions/:id', protect, checkPermission('transaction', 'delete'), deleteTransaction);

app.get('/api/dashboard/summary', protect, checkPermission('dashboard', 'read'), getDashboardSummary);
app.get('/api/dashboard/category-totals', protect, checkPermission('dashboard', 'read'), getCategoryWiseTotals);
app.get('/api/dashboard/monthly-trends', protect, checkPermission('dashboard', 'read'), getMonthlyTrends);
app.get('/api/dashboard/recent-activity', protect, checkPermission('dashboard', 'read'), getRecentActivity);
app.get('/api/dashboard/complete', protect, checkPermission('dashboard', 'read'), getCompleteDashboard);

app.use(errorHandler);

async function startServer() {
    try {
        await initializeDatabase();
        app.listen(PORT, () => {
            console.log(`\n=================================`);
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📍 API URL: http://localhost:${PORT}`);
            console.log(`=================================`);
            console.log(`\n📝 Test Credentials:`);
            console.log(`   Email: admin@finance.com`);
            console.log(`   Password: Admin@123`);
            console.log(`=================================\n`);
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