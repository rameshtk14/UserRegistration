const sqlite3 = require('sqlite3').verbose();
//const db = new sqlite3.Database(':memory:');
const { db,initializeDatabase } = require('./db');
const PasswordReset = require('./passwordReset');


// Initialize the table
// db.serialize(() => {
//     db.run(`
//         CREATE TABLE IF NOT EXISTS users (
//             id INTEGER PRIMARY KEY AUTOINCREMENT,
//             username TEXT NOT NULL UNIQUE,
//             password TEXT NOT NULL,
//             type TEXT NOT NULL CHECK(type IN ('Admin', 'User')),
//             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//             reset_token TEXT,
//             reset_token_expiry DATETIME
//         )
//     `);
//     // Create a default Admin user
//     const bcrypt = require('bcrypt');
//     const adminPassword = bcrypt.hashSync('admin123', 10); // hash the password
//     db.run(`INSERT INTO users (username, password, type) VALUES ('admin', ?, 'Admin')`, [adminPassword]);
// });
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = "your_secret_key"; // Replace with a strong secret

// Middleware for authentication
const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log("Authorization Header:", authHeader);

    if (!authHeader) {
        console.log("No Authorization header provided.");
        return res.status(403).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    console.log("Extracted Token:", token);

    if (!token) {
        console.log("No token found in Authorization header.");
        return res.status(403).json({ error: 'No token provided' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.error("Token verification failed:", err.message);
            return res.status(403).json({ error: 'Failed to authenticate token' });
        }
        console.log("Decoded Token Payload:", decoded);
        req.user = decoded;
        next();
    });
};

// Middleware for Admin-only access
const isAdmin = (req, res, next) => {
    if (req.user.type !== 'Admin') {
        return res.status(403).json({ error: 'Only Admin users can perform this action' });
    }
    next();
};

// Login API
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const passwordValid = bcrypt.compareSync(password, user.password);
        if (!passwordValid) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, username: user.username, type: user.type }, SECRET_KEY, {
            expiresIn: '1h',
        });
        res.json({ token });
    });
});

app.post('/users', authenticate, isAdmin, (req, res) => {
    const { username, password, type } = req.body;

    console.log("Request to create user:", { username, type });

    // Validate input
    if (!username || !password || !['Admin', 'User'].includes(type)) {
        console.log("Invalid input provided:", { username, password, type });
        return res.status(400).json({ error: 'Invalid input' });
    }

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert the new user
    db.run(
        `INSERT INTO users (username, password, type) VALUES (?, ?, ?)`,
        [username, hashedPassword, type],
        function (err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    console.log("Username already exists:", username);
                    return res.status(409).json({ error: 'Username already exists' });
                }
                console.error("Database error:", err.message);
                return res.status(500).json({ error: 'Internal server error' });
            }
            console.log("User created successfully:", { userId: this.lastID, username, type });
            res.status(201).json({ message: 'User created successfully', userId: this.lastID });
        }
    );
});

// Forgot Password Route
app.post('/forgot-password', (req, res) => {
    const { username } = req.body;
    PasswordReset.forgotPassword(username, res);  // Call the static method
});

// Reset Password Route
app.post('/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
    console.log("Received Token:", token); // Debugging
    console.log("Received New Password:", newPassword); // Debugging
    if (!token || !newPassword) {
        return res.status(400).json({ error: "Token and newPassword are required" });
    }
    PasswordReset.resetPassword(token, newPassword, res);  // Call the static method
});
// Start Server
const PORT = 3000;
console.log("SinitializeDatabasetarting server...");
initializeDatabase();
console.log("Ended server...");
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
   
});
