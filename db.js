const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Open the database file (users.db)
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the users.db SQLite database.');
    }
});

// Initialize the table
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('Admin', 'User')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_token TEXT,
            reset_token_expiry DATETIME
        )
    `);
    // Create a default Admin user
    const bcrypt = require('bcrypt');
    const adminPassword = bcrypt.hashSync('admin123', 10); // hash the password
    db.run(`INSERT INTO users (username, password, type) VALUES ('admin', ?, 'Admin')`, [adminPassword]);
});

const initializeDatabase = () => {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            type TEXT,
            reset_token TEXT,
            reset_token_expiry INTEGER
        );
    `;

    db.run(createUsersTable, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table created or already exists.');

            // Check if the admin user already exists
            db.get(`SELECT username FROM users WHERE username = ?`, ['admin'], (err, row) => {
                if (err) {
                    console.error('Error checking for admin user:', err.message);
                } else if (!row) {
                    // If admin user does not exist, insert it
                    const bcrypt = require('bcryptjs');
                    const hashedPassword = bcrypt.hashSync('adminpassword', 10);

                    const insertAdminUser = `
                        INSERT INTO users (username, password, type)
                        VALUES (?, ?, 'Admin');
                    `;

                    db.run(insertAdminUser, ['admin', hashedPassword], (err) => {
                        if (err) {
                            console.error('Error inserting default admin user:', err.message);
                        } else {
                            console.log('Default admin user created.');
                        }
                    });
                } else {
                    console.log('Admin user already exists. Skipping creation.');
                }
            });
        }
    });
};

module.exports = { db, initializeDatabase };
