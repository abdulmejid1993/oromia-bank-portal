require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, 'oromia_bank.db');
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const REGISTRATION_OTP_TTL_MS = 5 * 60 * 1000;
const REGISTRATION_OTP_COOLDOWN_MS = 60 * 1000;
const MAX_REGISTRATION_OTP_ATTEMPTS = 5;
const OTP_HASH_SECRET = process.env.OTP_SECRET || crypto.randomBytes(32).toString('hex');
const DEMO_OTP_ENABLED = process.env.DEMO_OTP_MODE === 'true' && process.env.NODE_ENV !== 'production';

if (process.env.NODE_ENV === 'production') {
    const adminPasswords = ['ADMIN_PASSWORD', 'MANAGER_PASSWORD', 'CASHIER_PASSWORD']
        .map((key) => process.env[key]);
    if (adminPasswords.some((password) => !password || password.length < 16)
        || new Set(adminPasswords).size !== adminPasswords.length) {
        throw new Error('Production requires unique admin passwords of at least 16 characters.');
    }
}

const ADMIN_ACCOUNTS = {
    admin: { username: process.env.ADMIN_USERNAME || 'admin', password: process.env.ADMIN_PASSWORD || 'admin123' },
    manager: { username: process.env.MANAGER_USERNAME || 'manager', password: process.env.MANAGER_PASSWORD || 'manager123' },
    cashier: { username: process.env.CASHIER_USERNAME || 'cashier', password: process.env.CASHIER_PASSWORD || 'cashier123' }
};

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Could not open database:', err.message);
        process.exit(1);
    }
    console.log('Connected to SQLite database.');
});

function hashPassword(password) {
    return crypto.pbkdf2Sync(password, 'oromia-bank-salt', 100000, 64, 'sha256').toString('hex');
}

function createToken() {
    return crypto.randomBytes(32).toString('hex');
}

function createOtp() {
    return String(crypto.randomInt(100000, 1000000));
}

function hashOtp(code) {
    return crypto.createHmac('sha256', OTP_HASH_SECRET).update(code).digest('hex');
}

function isSmsConfigured() {
    return Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER);
}

function normalizeSmsPhone(phone) {
    const normalized = String(phone || '').trim().replace(/[\s()-]/g, '');
    if (/^0[79]\d{8}$/.test(normalized)) return `+251${normalized.slice(1)}`;
    if (/^\+251[79]\d{8}$/.test(normalized)) return normalized;
    if (/^\+[1-9]\d{7,14}$/.test(normalized)) return normalized;
    throw new Error('The phone number is not in a supported international format.');
}

async function sendSms(phone, message) {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_FROM_NUMBER;
    const body = new URLSearchParams({
        To: normalizeSmsPhone(phone),
        From: fromNumber,
        Body: message,
    });
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, {
        method: 'POST',
        headers: {
            Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString('base64')}`,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
        signal: AbortSignal.timeout(8000),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(result.message || `SMS provider returned status ${response.status}.`);
    }
}

async function deliverRegistrationOtp(phone, code) {
    if (isSmsConfigured()) {
        await sendSms(phone, `Oromia Bank: Your customer registration verification code is ${code}. It expires in 5 minutes. Do not share it with anyone.`);
        return 'sms';
    }
    if (DEMO_OTP_ENABLED) return 'demo';
    throw new Error('SMS verification is not configured. Please contact the administrator.');
}

function logDemoOtp(phone, code) {
    console.log(`Demo registration OTP for ${phone}: ${code}`);
}

function runSql(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve({ id: this.lastID, changes: this.changes });
        });
    });
}

function getSql(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) return reject(err);
            resolve(row);
        });
    });
}

function allSql(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });
}

async function notifyThirdInQueue() {
    if (!isSmsConfigured()) return 0;

    const waitingTickets = await allSql(
        `SELECT id, ticket_number, phone_number, queue_alert_eligible, queue_alert_status
         FROM tickets WHERE branch_code = ? AND status = 'WAITING' ORDER BY created_at ASC, id ASC`,
        ['ORB-BAB01']
    );
    let sentCount = 0;

    for (const [index, ticket] of waitingTickets.slice(0, 3).entries()) {
        if (!ticket.queue_alert_eligible || ticket.queue_alert_status !== 'PENDING') continue;

        const claim = await runSql(
            "UPDATE tickets SET queue_alert_status = 'SENDING' WHERE id = ? AND queue_alert_status = 'PENDING'",
            [ticket.id]
        );
        if (!claim.changes) continue;

        try {
            const position = index + 1;
            await sendSms(
                ticket.phone_number,
                `Oromia Bank: Ticket ${ticket.ticket_number} is now ${position}${position === 1 ? 'st' : position === 2 ? 'nd' : 'rd'} in the Babile queue. Please be ready for service.`
            );
            await runSql("UPDATE tickets SET queue_alert_status = 'SENT' WHERE id = ?", [ticket.id]);
            sentCount += 1;
        } catch (error) {
            await runSql("UPDATE tickets SET queue_alert_status = 'PENDING' WHERE id = ?", [ticket.id]);
            console.error(`SMS alert failed for ticket ${ticket.ticket_number}:`, error.message);
        }
    }

    return sentCount;
}

function authAdmin(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Authentication required.' });
    }

    getSql(
        `SELECT s.token, s.admin_id, s.expires_at, a.username, a.role
     FROM admin_sessions s
     INNER JOIN admins a ON a.id = s.admin_id
     WHERE s.token = ? AND s.expires_at > ?`,
        [token, Date.now()]
    )
        .then((row) => {
            if (!row) {
                return res.status(401).json({ success: false, message: 'Session expired or invalid.' });
            }

            req.admin = {
                id: row.admin_id,
                username: row.username,
                role: row.role,
            };
            next();
        })
        .catch((err) => {
            res.status(500).json({ success: false, message: err.message });
        });
}

function authCustomer(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Customer ') ? authHeader.slice(9) : null;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Customer login required.' });
    }

    getSql(
        `SELECT s.token, s.customer_id, s.expires_at, c.full_name, c.phone
         FROM customer_sessions s
         INNER JOIN customers c ON c.id = s.customer_id
         WHERE s.token = ? AND s.expires_at > ?`,
        [token, Date.now()]
    )
        .then((row) => {
            if (!row) return res.status(401).json({ success: false, message: 'Customer session expired or invalid.' });
            req.customer = { id: row.customer_id, fullName: row.full_name, phone: row.phone };
            next();
        })
        .catch((err) => res.status(500).json({ success: false, message: err.message }));
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({ success: false, message: 'Authentication required.' });
        }

        if (!allowedRoles.includes(req.admin.role)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. This action requires one of: ${allowedRoles.join(', ')}`
            });
        }

        next();
    };
}

async function recordAudit(admin, action, entityType, entityId, details = '') {
    await runSql(
        'INSERT INTO audit_logs (admin_id, username, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?, ?)',
        [admin.id, admin.username, action, entityType, entityId || null, details]
    );
}

function initializeDatabase() {
    db.serialize(() => {
        db.run(`
      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

        db.run(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(admin_id) REFERENCES admins(id)
      )
    `);

        db.run(`
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS customer_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS customer_registration_otps (
                phone TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_sent_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
                        CREATE TABLE IF NOT EXISTS contact_messages (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT NOT NULL,
                                contact TEXT NOT NULL DEFAULT '',
                                message TEXT NOT NULL,
                                read_at TEXT,
                                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                `);

        db.run(`
      CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        branch_code TEXT NOT NULL UNIQUE,
        branch_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ONLINE',
        avg_wait_minutes INTEGER NOT NULL DEFAULT 12,
        active_counters TEXT NOT NULL DEFAULT 'Counter 1 & 2',
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

        db.run(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        ticket_number TEXT NOT NULL UNIQUE,
        branch_code TEXT NOT NULL,
        customer_name TEXT NOT NULL,
        phone_number TEXT NOT NULL,
        bank_account_number TEXT NOT NULL DEFAULT '',
        service_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'WAITING',
                queue_alert_eligible INTEGER NOT NULL DEFAULT 0,
                queue_alert_status TEXT NOT NULL DEFAULT 'NOT_ELIGIBLE',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

        db.run(`
      CREATE TABLE IF NOT EXISTS loan_prescreenings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        applicant_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        loan_type TEXT NOT NULL,
        asset_value REAL NOT NULL,
        estimated_loan REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

        db.run('ALTER TABLE tickets ADD COLUMN customer_id INTEGER', () => { });
        db.run("ALTER TABLE tickets ADD COLUMN bank_account_number TEXT NOT NULL DEFAULT ''", () => { });
        db.run('ALTER TABLE tickets ADD COLUMN queue_alert_eligible INTEGER NOT NULL DEFAULT 0', () => { });
        db.run("ALTER TABLE tickets ADD COLUMN queue_alert_status TEXT NOT NULL DEFAULT 'NOT_ELIGIBLE'", () => { });
        db.run("DELETE FROM tickets WHERE status = 'SERVED'", function (err) {
            if (err) {
                console.error('Could not remove previously served tickets:', err.message);
            } else if (this.changes > 0) {
                console.log(`Removed ${this.changes} previously served ticket(s).`);
            }
        });
        db.run("UPDATE tickets SET queue_alert_status = 'PENDING' WHERE queue_alert_status = 'SENDING'");
        db.run('ALTER TABLE loan_prescreenings ADD COLUMN customer_id INTEGER', () => { });

        Object.entries(ADMIN_ACCOUNTS).forEach(([role, account]) => {
            db.run(
                `INSERT OR IGNORE INTO admins (username, password_hash, role) VALUES (?, ?, ?)`,
                [account.username, hashPassword(account.password), role]
            );
        });

        db.run(
            `INSERT OR IGNORE INTO branches (branch_code, branch_name, status, avg_wait_minutes, active_counters)
       VALUES (?, ?, 'ONLINE', 12, 'Counter 1 & 2')`,
            ['ORB-BAB01', 'Babile Main Branch']
        );
    });
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/branch/status', async (req, res) => {
    try {
        const branch = await getSql('SELECT * FROM branches WHERE branch_code = ?', ['ORB-BAB01']);
        if (!branch) {
            return res.status(404).json({ success: false, message: 'Branch not found.' });
        }
        res.json({ success: true, branch });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    try {
        const attempt = await getSql('SELECT * FROM login_attempts WHERE username = ?', [username]);
        if (attempt && attempt.locked_until > Date.now()) {
            return res.status(429).json({ success: false, message: 'Too many failed attempts. Try again later.' });
        }

        const admin = await getSql(
            'SELECT * FROM admins WHERE username = ? AND password_hash = ?',
            [username, hashPassword(password)]
        );

        if (!admin) {
            const attempts = (attempt?.attempts || 0) + 1;
            const lockedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? Date.now() + LOGIN_LOCKOUT_MS : 0;
            await runSql(
                `INSERT INTO login_attempts (username, attempts, locked_until) VALUES (?, ?, ?)
                 ON CONFLICT(username) DO UPDATE SET attempts = excluded.attempts, locked_until = excluded.locked_until`,
                [username, attempts, lockedUntil]
            );
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

        await runSql('DELETE FROM login_attempts WHERE username = ?', [username]);

        const token = createToken();
        const expiresAt = Date.now() + SESSION_TTL_MS;

        await runSql(
            'INSERT INTO admin_sessions (admin_id, token, expires_at) VALUES (?, ?, ?)',
            [admin.id, token, expiresAt]
        );

        res.json({
            success: true,
            token,
            admin: {
                id: admin.id,
                username: admin.username,
                role: admin.role,
            },
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/admin/logout', authAdmin, async (req, res) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    try {
        await runSql('DELETE FROM admin_sessions WHERE token = ?', [token]);
        res.json({ success: true, message: 'Logged out successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/me', authAdmin, async (req, res) => {
    res.json({ success: true, admin: req.admin });
});

app.post('/api/customer/register', async (req, res) => {
    const { fullName, phone, password } = req.body || {};
    const cleanName = String(fullName || '').trim();
    if (!cleanName || cleanName.length > 100 || !phone || typeof password !== 'string' || password.length < 8 || password.length > 128) {
        return res.status(400).json({ success: false, message: 'Full name, a valid phone number, and a password of 8 to 128 characters are required.' });
    }

    let normalizedPhone;
    try {
        normalizedPhone = normalizeSmsPhone(phone);
        const enteredPhone = String(phone).trim();
        await runSql('DELETE FROM customer_registration_otps WHERE expires_at <= ?', [Date.now()]);
        const existingCustomer = await getSql(
            'SELECT id, full_name, phone, password_hash FROM customers WHERE phone IN (?, ?)',
            [normalizedPhone, enteredPhone]
        );
        const passwordHash = hashPassword(password);
        if (existingCustomer && existingCustomer.password_hash !== passwordHash) {
            return res.status(409).json({ success: false, message: 'An account with this phone number already exists.' });
        }

        const pendingRegistration = await getSql('SELECT attempts, last_sent_at, expires_at FROM customer_registration_otps WHERE phone = ?', [normalizedPhone]);
        if (pendingRegistration?.attempts >= MAX_REGISTRATION_OTP_ATTEMPTS) {
            return res.status(429).json({ success: false, message: 'Too many incorrect codes. Please wait for the code to expire before registering again.' });
        }
        if (pendingRegistration && Date.now() - pendingRegistration.last_sent_at < REGISTRATION_OTP_COOLDOWN_MS) {
            return res.status(429).json({ success: false, message: 'Please wait one minute before requesting another verification code.' });
        }

        if (!isSmsConfigured() && !DEMO_OTP_ENABLED) {
            return res.status(503).json({ success: false, message: 'SMS verification is not configured. Please contact the administrator.' });
        }
        const code = createOtp();
        const delivery = await deliverRegistrationOtp(normalizedPhone, code);
        await runSql(
            `INSERT INTO customer_registration_otps (phone, full_name, password_hash, otp_hash, expires_at, attempts, last_sent_at)
             VALUES (?, ?, ?, ?, ?, 0, ?)
             ON CONFLICT(phone) DO UPDATE SET
                full_name = excluded.full_name,
                password_hash = excluded.password_hash,
                otp_hash = excluded.otp_hash,
                expires_at = excluded.expires_at,
                attempts = 0,
                last_sent_at = excluded.last_sent_at`,
            [
                normalizedPhone,
                existingCustomer ? existingCustomer.full_name : cleanName,
                passwordHash,
                hashOtp(code),
                Date.now() + REGISTRATION_OTP_TTL_MS,
                Date.now()
            ]
        );
        if (delivery === 'demo') logDemoOtp(normalizedPhone, code);
        res.status(202).json({
            success: true,
            pending: true,
            phone: normalizedPhone,
            delivery,
            message: 'A verification code has been sent to the phone number you entered.'
        });
    } catch (err) {
        const duplicate = String(err.message).includes('UNIQUE');
        const phoneError = String(err.message).includes('supported international format');
        res.status(duplicate ? 409 : phoneError ? 400 : 502).json({
            success: false,
            message: duplicate ? 'An account with this phone number already exists.' : err.message
        });
    }
});

app.post('/api/customer/register/resend-otp', async (req, res) => {
    let phone;
    try {
        phone = normalizeSmsPhone(req.body?.phone);
        const pending = await getSql('SELECT attempts, expires_at, last_sent_at FROM customer_registration_otps WHERE phone = ?', [phone]);
        if (!pending) return res.status(404).json({ success: false, message: 'No pending registration was found. Please register again.' });
        if (pending.expires_at <= Date.now()) {
            await runSql('DELETE FROM customer_registration_otps WHERE phone = ?', [phone]);
            return res.status(410).json({ success: false, message: 'The verification code expired. Please register again.' });
        }
        if (pending.attempts >= MAX_REGISTRATION_OTP_ATTEMPTS) {
            return res.status(429).json({ success: false, message: 'Too many incorrect codes. Please wait for the code to expire before trying again.' });
        }
        if (Date.now() - pending.last_sent_at < REGISTRATION_OTP_COOLDOWN_MS) {
            return res.status(429).json({ success: false, message: 'Please wait one minute before requesting another verification code.' });
        }
        if (!isSmsConfigured() && !DEMO_OTP_ENABLED) {
            return res.status(503).json({ success: false, message: 'SMS verification is not configured. Please contact the administrator.' });
        }

        const code = createOtp();
        const delivery = await deliverRegistrationOtp(phone, code);
        await runSql(
            'UPDATE customer_registration_otps SET otp_hash = ?, expires_at = ?, attempts = 0, last_sent_at = ? WHERE phone = ?',
            [hashOtp(code), Date.now() + REGISTRATION_OTP_TTL_MS, Date.now(), phone]
        );
        if (delivery === 'demo') logDemoOtp(phone, code);
        res.json({ success: true, delivery, message: 'A new verification code has been sent to your phone.' });
    } catch (err) {
        const phoneError = String(err.message).includes('supported international format');
        res.status(phoneError ? 400 : 502).json({ success: false, message: err.message });
    }
});

app.post('/api/customer/register/verify', async (req, res) => {
    const { code } = req.body || {};
    let phone;
    try {
        const enteredPhone = String(req.body?.phone || '').trim();
        phone = normalizeSmsPhone(enteredPhone);
        const pending = await getSql('SELECT * FROM customer_registration_otps WHERE phone = ?', [phone]);
        if (!pending) return res.status(404).json({ success: false, message: 'No pending registration was found. Please register again.' });
        if (pending.expires_at <= Date.now()) {
            await runSql('DELETE FROM customer_registration_otps WHERE phone = ?', [phone]);
            return res.status(410).json({ success: false, message: 'The verification code expired. Please register again.' });
        }
        if (pending.attempts >= MAX_REGISTRATION_OTP_ATTEMPTS) {
            return res.status(429).json({ success: false, message: 'Too many incorrect codes. Please wait for the code to expire before trying again.' });
        }

        const submittedCode = String(code || '').trim();
        const validCode = /^\d{6}$/.test(submittedCode)
            && crypto.timingSafeEqual(Buffer.from(hashOtp(submittedCode), 'hex'), Buffer.from(pending.otp_hash, 'hex'));
        if (!validCode) {
            const attempts = pending.attempts + 1;
            await runSql('UPDATE customer_registration_otps SET attempts = ? WHERE phone = ?', [attempts, phone]);
            return res.status(attempts >= MAX_REGISTRATION_OTP_ATTEMPTS ? 429 : 400).json({
                success: false,
                message: attempts >= MAX_REGISTRATION_OTP_ATTEMPTS
                    ? 'Too many incorrect codes. Please wait for the code to expire before trying again.'
                    : 'The verification code is invalid.'
            });
        }

        const existingCustomer = await getSql(
            'SELECT id, full_name, phone, password_hash FROM customers WHERE phone IN (?, ?)',
            [phone, enteredPhone]
        );
        if (existingCustomer && existingCustomer.password_hash !== pending.password_hash) {
            await runSql('DELETE FROM customer_registration_otps WHERE phone = ?', [phone]);
            return res.status(409).json({ success: false, message: 'The registration details do not match this phone number. Please try again.' });
        }
        const customer = existingCustomer || {
            id: (await runSql(
                'INSERT INTO customers (full_name, phone, password_hash) VALUES (?, ?, ?)',
                [pending.full_name, phone, pending.password_hash]
            )).id,
            full_name: pending.full_name,
            phone
        };
        await runSql('DELETE FROM customer_registration_otps WHERE phone = ?', [phone]);
        const token = createToken();
        await runSql(
            'INSERT INTO customer_sessions (customer_id, token, expires_at) VALUES (?, ?, ?)',
            [customer.id, token, Date.now() + SESSION_TTL_MS]
        );
        res.status(201).json({
            success: true,
            token,
            customer: { id: customer.id, fullName: customer.full_name, phone: customer.phone }
        });
    } catch (err) {
        const duplicate = String(err.message).includes('UNIQUE');
        const phoneError = String(err.message).includes('supported international format');
        res.status(duplicate ? 409 : phoneError ? 400 : 500).json({
            success: false,
            message: duplicate ? 'An account with this phone number already exists.' : err.message
        });
    }
});

app.post('/api/customer/login', async (req, res) => {
    const { phone, password } = req.body || {};
    if (!phone || !password) return res.status(400).json({ success: false, message: 'Phone and password are required.' });
    try {
        let normalizedPhone;
        try {
            normalizedPhone = normalizeSmsPhone(phone);
        } catch {
            return res.status(400).json({ success: false, message: 'Enter a valid phone number.' });
        }
        const enteredPhone = String(phone).trim();
        const customer = await getSql(
            'SELECT * FROM customers WHERE phone IN (?, ?) AND password_hash = ? ORDER BY CASE WHEN phone = ? THEN 0 ELSE 1 END LIMIT 1',
            [normalizedPhone, enteredPhone, hashPassword(password), normalizedPhone]
        );
        if (!customer) return res.status(401).json({ success: false, message: 'Invalid phone number or password.' });
        const token = createToken();
        await runSql('INSERT INTO customer_sessions (customer_id, token, expires_at) VALUES (?, ?, ?)', [customer.id, token, Date.now() + SESSION_TTL_MS]);
        res.json({ success: true, token, customer: { id: customer.id, fullName: customer.full_name, phone: customer.phone } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/customer/logout', authCustomer, async (req, res) => {
    const token = (req.headers.authorization || '').slice(9);
    await runSql('DELETE FROM customer_sessions WHERE token = ?', [token]);
    res.json({ success: true, message: 'Customer logged out.' });
});

app.get('/api/customer/me', authCustomer, (req, res) => {
    res.json({ success: true, customer: req.customer });
});

app.get('/api/admin/dashboard', authAdmin, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    try {
        const search = String(req.query.search || '').trim();
        const status = String(req.query.status || '').trim().toUpperCase();
        const pattern = `%${search}%`;
        const ticketConditions = [];
        if (search) ticketConditions.push('(customer_name LIKE ? OR phone_number LIKE ? OR ticket_number LIKE ?)');
        if (status) {
            ticketConditions.push('status = ?');
        } else {
            ticketConditions.push("status = 'WAITING'");
        }
        const ticketWhere = ticketConditions.length ? `WHERE ${ticketConditions.join(' AND ')}` : '';
        const ticketParams = [
            ...(search ? [pattern, pattern, pattern] : []),
            ...(status ? [status] : [])
        ];
        const queueOrder = status === 'SERVED' ? 'created_at DESC, id DESC' : 'created_at ASC, id ASC';
        const [queue, loans, branch, ticketTotals, waitingTotals, serviceBreakdown, dailyTickets, approvals] = await Promise.all([
            allSql(
                `SELECT tickets.*,
                    CASE WHEN status = 'WAITING' THEN (
                        SELECT COUNT(*) + 1 FROM tickets ahead
                        WHERE ahead.branch_code = tickets.branch_code AND ahead.status = 'WAITING'
                        AND (ahead.created_at < tickets.created_at OR (ahead.created_at = tickets.created_at AND ahead.id < tickets.id))
                    ) ELSE NULL END AS queue_position
                 FROM tickets ${ticketWhere} ORDER BY ${queueOrder} LIMIT 50`,
                ticketParams
            ),
            allSql(`SELECT * FROM loan_prescreenings ${search ? 'WHERE applicant_name LIKE ? OR phone LIKE ?' : ''} ORDER BY created_at DESC LIMIT 50`, search ? [pattern, pattern] : []),
            getSql('SELECT * FROM branches WHERE branch_code = ?', ['ORB-BAB01']),
            getSql('SELECT COUNT(*) AS total FROM tickets'),
            getSql('SELECT COUNT(*) AS total FROM tickets WHERE status = ?', ['WAITING']),
            allSql('SELECT service_type, COUNT(*) AS value FROM tickets GROUP BY service_type ORDER BY value DESC LIMIT 5'),
            allSql(`SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total FROM tickets GROUP BY day ORDER BY day DESC LIMIT 7`),
            getSql('SELECT COUNT(*) AS total FROM loan_prescreenings WHERE status = ?', ['APPROVED'])
        ]);

        const pendingCount = queue.filter((item) => item.status === 'WAITING').length;
        const analytics = {
            totalTickets: Number(ticketTotals?.total || 0),
            waitingTickets: Number(waitingTotals?.total || 0),
            avgWaitMinutes: Number(branch?.avg_wait_minutes || 0),
            branchStatus: branch?.status || 'ONLINE',
            serviceBreakdown: serviceBreakdown.map((item) => ({
                label: item.service_type,
                value: Number(item.value || 0),
            })),
            trend: dailyTickets.map((item) => ({
                day: item.day,
                total: Number(item.total || 0),
                served: Number(item.served || 0),
            })),
            approvedLoanCount: Number(approvals?.total || 0),
        };

        res.json({
            success: true,
            admin: req.admin,
            waitingCount: pendingCount,
            loanCount: loans.length,
            branch,
            dailyTickets,
            audit: await allSql('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20'),
            analytics,
            queue: queue.map((item) => ({
                id: item.id,
                name: item.customer_name,
                phone: item.phone_number,
                service: item.service_type,
                status: item.status === 'WAITING' ? 'Waiting' : 'Served',
                position: item.queue_position,
            })),
            loans: loans.map((item) => ({
                id: item.id,
                name: item.applicant_name,
                phone: item.phone,
                amount: Number(item.estimated_loan),
                status: item.status === 'APPROVED' ? 'Approved' : 'Review',
            })),
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.patch('/api/admin/tickets/:id/status', authAdmin, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body || {};

    if (!status) {
        return res.status(400).json({ success: false, message: 'Status is required.' });
    }

    const normalized = status.toUpperCase();

    if (req.admin.role === 'cashier' && normalized !== 'SERVED') {
        return res.status(403).json({
            success: false,
            message: 'Cashiers can only mark tickets as served.'
        });
    }

    try {
        if (normalized === 'SERVED') {
            const deletedTicket = await runSql('DELETE FROM tickets WHERE id = ?', [id]);
            if (!deletedTicket.changes) {
                return res.status(404).json({ success: false, message: 'Ticket not found.' });
            }
            await recordAudit(req.admin, 'DELETE_SERVED_TICKET', 'ticket', id, 'Served ticket permanently removed.');
        } else {
            const updatedTicket = await runSql('UPDATE tickets SET status = ? WHERE id = ?', [normalized, id]);
            if (!updatedTicket.changes) {
                return res.status(404).json({ success: false, message: 'Ticket not found.' });
            }
            await recordAudit(req.admin, 'UPDATE_STATUS', 'ticket', id, `Status changed to ${normalized}`);
        }

        let smsNotificationsSent = 0;
        if (normalized === 'SERVED') {
            try {
                smsNotificationsSent = await notifyThirdInQueue();
            } catch (error) {
                console.error('Could not check queue SMS alerts:', error.message);
            }
        }
        res.json({
            success: true,
            message: normalized === 'SERVED' ? 'Ticket served and permanently removed.' : 'Ticket status updated.',
            smsNotificationsSent
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.patch('/api/admin/loans/:id/status', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body || {};

    if (!status) {
        return res.status(400).json({ success: false, message: 'Status is required.' });
    }

    try {
        await runSql('UPDATE loan_prescreenings SET status = ? WHERE id = ?', [status.toUpperCase(), id]);
        await recordAudit(req.admin, 'UPDATE_STATUS', 'loan', id, `Status changed to ${status.toUpperCase()}`);
        res.json({ success: true, message: 'Loan status updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

function csvEscape(value) {
    const stringValue = String(value ?? '');
    return `"${stringValue.replace(/"/g, '""')}"`;
}

app.get('/api/admin/export/tickets', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const rows = await allSql('SELECT ticket_number, customer_name, phone_number, bank_account_number, service_type, status, created_at FROM tickets ORDER BY created_at DESC');
        const header = ['ticket_number', 'customer_name', 'phone_number', 'bank_account_number', 'service_type', 'status', 'created_at'];
        const csvRows = [header.join(',')].concat(rows.map((row) => header.map((key) => csvEscape(row[key])).join(',')));
        const csv = csvRows.join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="oromia-ticket-export.csv"');
        res.send(csv);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/export/loan-approvals', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const rows = await allSql(
            'SELECT applicant_name, phone, loan_type, asset_value, estimated_loan, status, created_at FROM loan_prescreenings WHERE status = ? ORDER BY created_at DESC',
            ['APPROVED']
        );
        const header = ['applicant_name', 'phone', 'loan_type', 'asset_value', 'estimated_loan', 'status', 'created_at'];
        const csvRows = [header.join(',')].concat(rows.map((row) => header.map((key) => csvEscape(row[key])).join(',')));
        const csv = csvRows.join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="oromia-loan-approvals.csv"');
        res.send(csv);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/tickets/issue', authCustomer, async (req, res) => {
    const { name, phone, accountNumber, serviceType } = req.body || {};
    const normalizedName = String(name || '').trim();
    const normalizedPhone = String(phone || '').trim();
    const normalizedAccountNumber = String(accountNumber || '').trim();
    const normalizedServiceType = String(serviceType || '').trim();

    if (!normalizedName || !normalizedPhone || !normalizedAccountNumber || !normalizedServiceType) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    try {
        const ticketNumber = 'BBL-' + Math.floor(1000 + Math.random() * 9000);

        const ticket = {
            ticket_number: ticketNumber,
            branch_code: 'ORB-BAB01',
            customer_name: normalizedName,
            phone_number: normalizedPhone,
            service_type: normalizedServiceType,
            status: 'WAITING',
        };

        const result = await runSql(
            `INSERT INTO tickets (
                customer_id, ticket_number, branch_code, customer_name, phone_number, bank_account_number, service_type, status,
                queue_alert_eligible, queue_alert_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'WAITING',
                CASE WHEN (SELECT COUNT(*) FROM tickets WHERE branch_code = ? AND status = 'WAITING') >= 5 THEN 1 ELSE 0 END,
                CASE WHEN (SELECT COUNT(*) FROM tickets WHERE branch_code = ? AND status = 'WAITING') >= 5 THEN 'PENDING' ELSE 'NOT_ELIGIBLE' END
            )`,
            [req.customer.id, ticket.ticket_number, ticket.branch_code, ticket.customer_name, ticket.phone_number, normalizedAccountNumber, ticket.service_type, ticket.branch_code, ticket.branch_code]
        );

        const savedTicket = await getSql('SELECT queue_alert_eligible FROM tickets WHERE id = ?', [result.id]);
        res.json({
            success: true,
            ticket: {
                ...ticket,
                id: result.id,
                queue_alert_eligible: Boolean(savedTicket?.queue_alert_eligible),
                sms_configured: isSmsConfigured(),
            },
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/loans/prescreen', authCustomer, async (req, res) => {
    const { name, phone, loanType, assetValue } = req.body || {};

    if (!name || !phone || !loanType || !assetValue) {
        return res.status(400).json({ success: false, message: 'Missing parameters.' });
    }

    try {
        const estimatedLoan = Number(assetValue) * 0.60;
        const result = await runSql(
            'INSERT INTO loan_prescreenings (customer_id, applicant_name, phone, loan_type, asset_value, estimated_loan, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [req.customer.id, name, phone, loanType, Number(assetValue), estimatedLoan, 'PENDING']
        );

        res.json({
            success: true,
            result: {
                id: result.id,
                applicant_name: name,
                phone,
                loan_type: loanType,
                asset_value: Number(assetValue),
                estimated_loan: estimatedLoan,
                status: 'PENDING',
            },
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

initializeDatabase();

app.listen(PORT, () => {
    console.log(`Oromia Bank Backend running on port ${PORT}`);
});

app.post('/api/admin/password', authAdmin, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword || newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'Current password and a new password of at least 8 characters are required.' });
    }

    try {
        const admin = await getSql('SELECT password_hash FROM admins WHERE id = ?', [req.admin.id]);
        if (!admin || admin.password_hash !== hashPassword(currentPassword)) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
        }
        await runSql('UPDATE admins SET password_hash = ? WHERE id = ?', [hashPassword(newPassword), req.admin.id]);
        await recordAudit(req.admin, 'CHANGE_PASSWORD', 'admin', req.admin.id);
        res.json({ success: true, message: 'Password changed successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/audit', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    try {
        res.json({ success: true, audit: await allSql('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100') });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/contact-messages', async (req, res) => {
    const name = String(req.body?.name || '').trim();
    const contact = String(req.body?.contact || '').trim();
    const message = String(req.body?.message || '').trim();
    if (!name || name.length > 100 || contact.length > 120 || !message || message.length > 2000) {
        return res.status(400).json({ success: false, message: 'Please provide a name and a message under 2,000 characters.' });
    }

    try {
        const result = await runSql(
            'INSERT INTO contact_messages (name, contact, message) VALUES (?, ?, ?)',
            [name, contact, message]
        );
        res.status(201).json({ success: true, id: result.id, message: 'Your message was sent to the branch manager.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/contact-messages', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const messages = await allSql(
            'SELECT id, name, contact, message, read_at, created_at FROM contact_messages ORDER BY read_at IS NULL DESC, created_at DESC LIMIT 200'
        );
        res.json({ success: true, messages });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.patch('/api/admin/contact-messages/:id/read', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ success: false, message: 'A valid message ID is required.' });
    }

    try {
        const result = await runSql(
            'UPDATE contact_messages SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND read_at IS NULL',
            [id]
        );
        if (!result.changes) {
            const existing = await getSql('SELECT id FROM contact_messages WHERE id = ?', [id]);
            if (!existing) return res.status(404).json({ success: false, message: 'Message not found.' });
        } else {
            await recordAudit(req.admin, 'READ_CONTACT_MESSAGE', 'contact_message', id);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.patch('/api/admin/branch', authAdmin, requireRole('admin', 'manager'), async (req, res) => {
    const { status, avgWaitMinutes, activeCounters } = req.body || {};
    if (!status || !Number.isInteger(Number(avgWaitMinutes)) || !activeCounters) {
        return res.status(400).json({ success: false, message: 'Branch status, wait time, and active counters are required.' });
    }
    try {
        await runSql(
            'UPDATE branches SET status = ?, avg_wait_minutes = ?, active_counters = ?, updated_at = CURRENT_TIMESTAMP WHERE branch_code = ?',
            [status.toUpperCase(), Number(avgWaitMinutes), activeCounters, 'ORB-BAB01']
        );
        await recordAudit(req.admin, 'UPDATE_BRANCH', 'branch', 1, `${status}, ${avgWaitMinutes} minutes, ${activeCounters}`);
        res.json({ success: true, message: 'Branch settings saved.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/tickets/live', async (req, res) => {
    try {
        const tickets = await allSql(
            `SELECT tickets.ticket_number, tickets.service_type, tickets.status,
                (SELECT COUNT(*) + 1 FROM tickets ahead
                 WHERE ahead.branch_code = tickets.branch_code AND ahead.status = 'WAITING'
                 AND (ahead.created_at < tickets.created_at OR (ahead.created_at = tickets.created_at AND ahead.id < tickets.id))
                ) AS position
             FROM tickets WHERE tickets.status = 'WAITING'
             ORDER BY tickets.created_at ASC, tickets.id ASC LIMIT 25`
        );
        res.json({ success: true, tickets });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/tickets/lookup', authCustomer, async (req, res) => {
    const ticketNumber = String(req.query.ticket || '').trim();
    if (!ticketNumber) return res.status(400).json({ success: false, message: 'Ticket number is required.' });
    try {
        const ticket = await getSql(
            `SELECT t.ticket_number, t.customer_name, t.service_type, t.status, t.created_at,
                CASE WHEN t.status = 'WAITING' THEN (
                    SELECT COUNT(*) FROM tickets ahead
                    WHERE ahead.branch_code = t.branch_code AND ahead.status = 'WAITING'
                    AND (ahead.created_at < t.created_at OR (ahead.created_at = t.created_at AND ahead.id < t.id))
                ) ELSE 0 END AS customers_ahead
            FROM tickets t WHERE t.ticket_number = ? AND t.customer_id = ?`,
            [ticketNumber, req.customer.id]
        );
        if (!ticket) return res.status(404).json({ success: false, message: 'Ticket not found.' });
        res.json({ success: true, ticket });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/loans/lookup', authCustomer, async (req, res) => {
    const id = Number(req.query.id);
    const phone = String(req.query.phone || '').trim();
    if (!id && !phone) return res.status(400).json({ success: false, message: 'Application ID or phone number is required.' });
    try {
        const loan = await getSql(
            `SELECT id, applicant_name, phone, loan_type, estimated_loan, status, created_at
            FROM loan_prescreenings WHERE customer_id = ? AND ${id ? 'id = ?' : 'phone = ?'} ORDER BY created_at DESC LIMIT 1`,
            [req.customer.id, id || phone]
        );
        if (!loan) return res.status(404).json({ success: false, message: 'Loan application not found.' });
        res.json({ success: true, loan });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});