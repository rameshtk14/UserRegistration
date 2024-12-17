// const sqlite3 = require('sqlite3').verbose();
// const path = require('path');
// const bcrypt = require('bcryptjs');

// const dbPath = path.join(__dirname, 'users.db');
// const db = new sqlite3.Database(dbPath);

// const initializeDatabase = () => {
//     db.serialize(() => {
//         const createUsersTable = `
//             CREATE TABLE IF NOT EXISTS users (
//                 id INTEGER PRIMARY KEY AUTOINCREMENT,
//                 username TEXT NOT NULL UNIQUE,
//                 password TEXT NOT NULL,
//                 type TEXT NOT NULL CHECK(type IN ('Admin', 'User')),
//                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//                 reset_token TEXT,
//                 reset_token_expiry DATETIME
//             );
//         `;
//         console.log('Creating users table...');
//         db.run(createUsersTable, (err) => {
//             if (err) {
//                 console.error('Error creating users table:', err.message);
//             } else {
//                 console.log('Users table created or already exists.');

//                 // Check if the admin user already exists
//                 db.get(`SELECT username FROM users WHERE username = ?`, ['admin'], (err, row) => {
//                     if (err) {
//                         console.error('Error checking for admin user:', err.message);
//                     } else {
//                         console.log('Admin user check result:', row);
//                         if (!row) {
//                             // If admin user does not exist, insert it
//                             const hashedPassword = bcrypt.hashSync('admin123', 10);

//                             const insertAdminUser = `
//                                 INSERT INTO users (username, password, type)
//                                 VALUES (?, ?, 'Admin');
//                             `;

//                             db.run(insertAdminUser, ['admin', hashedPassword], (err) => {
//                                 if (err) {
//                                     console.error('Error inserting default admin user:', err.message);
//                                 } else {
//                                     console.log('Default admin user created.');
//                                 }
//                             });
//                         } else {
//                             console.log('Admin user already exists. Skipping creation.');
//                         }
//                     }
//                 });
//             }
//         });
//         console.log('Users table creation complete.');
//     });
// };
// module.exports = {
//     initializeDatabase,
//     db
// };

const bcrypt = require('bcryptjs'); // Ensure bcrypt is required
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the users.db SQLite database.');
    }
});

const initializeDatabase = () => {
    db.serialize(() => {
        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('Admin', 'User')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_token_expiry DATETIME
            );
        `;
        console.log('Creating users table...');

        db.run(createUsersTable, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
                return;
            }

            console.log('Users table created or already exists.');

            // Check for the admin user
            const checkAdminQuery = `SELECT username FROM users WHERE username = ?`;
            db.get(checkAdminQuery, ['admin'], (err, row) => {
                if (err) {
                    console.error('Error checking for admin user:', err.message);
                    return;
                }

                if (!row) {
                    console.log('Admin user does not exist. Creating default admin user...');

                    const hashedPassword = bcrypt.hashSync('admin123', 10);
                    const insertAdminUser = `
                        INSERT INTO users (username, password, type)
                        VALUES (?, ?, 'Admin');
                    `;

                    db.run(insertAdminUser, ['admin', hashedPassword], (err) => {
                        if (err) {
                            console.error('Error inserting default admin user:', err.message);
                        } else {
                            console.log('Default admin user created successfully.');
                        }
                    });
                } else {
                    console.log('Admin user already exists. No action taken.');
                }
            });
        });
    });
};

module.exports = { db, initializeDatabase };
