const nodemailer = require('nodemailer');
const { MailtrapTransport } = require('mailtrap');

// Define the MailTrapService class
class MailTrapService {
  constructor() {
    // Initialize Mailtrap transporter with token and inbox ID
    const TOKEN = '8a068d990126c4e27bad05e57c94db76'; // Your Mailtrap API token
    this.transport = nodemailer.createTransport(
      MailtrapTransport({
        token: TOKEN,
        testInboxId: 3323781, // Your Mailtrap inbox ID
      })
    );
  }

  // Method to send email via Mailtrap
  sendEmail(sender, recipients, subject, text, category = 'Integration Test') {
    return this.transport
      .sendMail({
        from: sender,      // Sender info
        to: recipients,    // Recipients list
        subject: subject,  // Subject of the email
        text: text,        // Email body text
        category: category, // Email category for Mailtrap
        sandbox: true,     // Enable Mailtrap sandbox for testing
      })
      .then((info) => {
        console.log('Email sent:', info);
        return info;
      })
      .catch((error) => {
        console.error('Error sending email:', error);
        throw error;
      });
  }
}

// Export the class to use in other parts of the app
module.exports = MailTrapService;
