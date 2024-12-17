const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db, initializeDatabase } = require('./db');



//const transporter = nodemailer.createTransport({
//     service: 'gmail', // Replace with your email service
//     auth: {
//         user: 'your-email@gmail.com',  // Replace with your email
//         pass: 'your-email-password'    // Replace with your email password or app password
//     }
// });

//const nodemailer = require('nodemailer');

const Nodemailer = require("nodemailer");
const { MailtrapTransport } = require("mailtrap");

const TOKEN = "8a068d990126c4e27bad05e57c94db76";

const transporter = Nodemailer.createTransport(
  MailtrapTransport({
    token: TOKEN,
    testInboxId: 3323781,
  })
);

// Create a transporter using Mailtrap's SMTP credentials
// const transporter = nodemailer.createTransport({
//   //host: 'sandbox.smtp.mailtrap.io',
//   host: 'smtp.mailtrap.io',
//   port: 587,
//   auth: {
//     user: '1df0af70b628ef',  // Replace with your Mailtrap username
//     pass: '7b82c16c25b631'   // Replace with your Mailtrap password
//   }
// });

const TOKEN_EXPIRE_TIME =  1000*60*60;

class PasswordReset {
    // Method to handle Forgot Password
    static async forgotPassword(username, res) {
        try {
            // Check if the user exists
            console.log(username);
            db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
                if (err) {
                    console.error("Database error:", err.message);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (!row) {
                    return res.status(404).json({ error: 'User not found' });
                }

                // Generate a secure reset token
                const resetToken = crypto.randomBytes(20).toString('hex');
                const resetTokenExpiry = Date.now() + TOKEN_EXPIRE_TIME;  // Token expires in 1 hour

                console.error("resetToken",resetToken);
                console.error("resetTokenExpiry",resetTokenExpiry);

                // Store the token and expiry time in the database
                db.run(
                    `UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE username = ?`,
                    [resetToken, resetTokenExpiry, username],
                    (err) => {
                        if (err) {
                            console.error("Error updating reset token:", err.message);
                            return res.status(500).json({ error: 'Internal server error' });
                        }

                        // Send the reset email to the user
                        const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
                        const sender = {
                            address: "hello@example.com",
                            name: "Mailtrap Test",
                          };
                        const mailOptions = {
                            //from: 'your-email@gmail.com',
                            from:sender,
                            to: row.username, // User's email (replace as needed)
                            subject: 'Password Reset Request',
                            text: `Please click the following link to reset your password: ${resetUrl}`,
                            category: "Integration Test",
                            sandbox: true,
                        };
                        console.error("Mail Options", mailOptions);
                        transporter.sendMail(mailOptions, (err, info) => {
                            if (err) {
                                console.error("Error sending email:", err.message);
                                return res.status(500).json({ error: 'Error sending email' });
                            }

                            res.status(200).json({ message: 'Password reset email sent' });
                        });
                    }
                );
            });
        } catch (error) {
            console.error("Error:", error.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    // Method to handle Reset Password
    static async resetPassword(token, newPassword, res) {
        try {
            // Find the user by reset token
            console.error("UserToken :",token);
            db.get(`SELECT * FROM users WHERE reset_token = ?`, [token], (err, row) => {
                if (err) {
                    console.error("Database error:", err.message);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (!row) {
                    return res.status(400).json({ error: 'Invalid or expired token' });
                }

                // Check if the token has expired
                if (Date.now() > row.reset_token_expiry) {
                    return res.status(400).json({ error: 'Token has expired' });
                }

                // Hash the new password
                const hashedPassword = bcrypt.hashSync(newPassword, 10);

                // Update the user's password and clear the reset token
                db.run(
                    `UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = ?`,
                    [hashedPassword, token],
                    (err) => {
                        if (err) {
                            console.error("Error updating password:", err.message);
                            return res.status(500).json({ error: 'Internal server error' });
                        }

                        res.status(200).json({ message: 'Password updated successfully' });
                    }
                );
            });
        } catch (error) {
            console.error("Error:", error.message);
            return res.status(500).json({ error: 'Internal server error *** *' });
        }
    }
}

module.exports = PasswordReset;
