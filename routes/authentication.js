const express = require('express');
const router = express.Router(); // Creates a mini Express App (with this I can define the necessary routes)
const bycrypt = require('bcrypt');
const crypto = require('crypto'); // Cryptography Module (Generates secure random tokens for 2FA): https://nodejs.org/api/crypto.html#crypto
// https://www.w3schools.com/nodejs/nodejs_email.asp
const nodemailer = require('nodemailer');  // Sends EMAILS from server (signup, login 2FA links, notifications to roles): https://www.nodemailer.com/
// Importing the model exported from the userModel.js
const UserSOBIE = require('../models/userModel');

// GMAIL 2FA Setup through App Password (Google Security)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

`
Get Section
`

// Login Page
router.get('/login', (req, res) => {
    res.render('login');
});

// Signup Page
router.get('/signup', (req, res) => {
    res.render('signup');
});

// 2FA Verification Page
router.get('/verify', (req, req) => {
    res.render('verify');
});

// User Dashboard
router.get('/dashbaord', async (req, res) => {
    // Checks if the userId is stored in the session, if not authenticated go back to login page.
    if (!req.session.userId) return res.redirect('/login');
    // Fetches the user's data from db and if user not found display prompt
    const user = await UserSOBIE.findById(req.session.userId);
    if (!user) return res.send('User Does Not Exist')
    res.render('dashboard', { user });

});

// Admin Dashboard (security issue, fix later!)
router.get('admin-dashboard', async (req, res) => {
    res.render('admin-dashboard');
});

// Edit Profile
router.get('/profile', async (req, res) => {
    // Checks/Fetches userId and data
    if (!req.session.userId) return res.redirect('/login');
    const user = await UserSOBIE.findById(req.session.userId);
    if (!user) return res.send("User Does Not Exist");
    res.render('profile', { user });

})

// Research Form Submission
router.get('/submit-research', async (req, res) => {
    // Checks/Fetches userId and data
    if (!req.session.userId) return res.redirect('/login');
    const user = await UserSOBIE.findById(req.session.userId);
    res.render('submit-research', { user });
});

`
Post Section
`

// SignUp Route
router.post('/signup', async (req, res) => {
    // extracts user data by retrieving from request body
    const { email, username, password, role } = req.body;
    const passwordHash = await bycrypt.hash(password, 10); // password hashing
    const tokenVerify = crypto.randomBytes(20).toString('hex'); // generates unique token (email)

    // creates a User Record (stores new user to db with hashed pw and veritifcation token).
    await UserSOBIE.create({
        email,
        username,
        passwordHash,
        role,
        tokenVerify
    });

    // verification link 
    const link = `${req.protocol}://${req.get('host')}/verify?token=${tokenVerify}`;

    // sends the link to the user's email (nodemailer)
    transporter.sendMail({
        to: email,
        subject: 'SOBIE Email Verification',
        text: 'Click this link to verifiy your account:\n\n${link}'
    });

    // storing user's email in the session (tempUserId) 
    req.session.tempUserId = email;
    res.redirect('/verify'); // redirects user to verification page for email prompt
});

// Login Route
router.post('/login', async (req, res) => {
    // extracts user data by retrieving from request body
    const { email, password } = req.body;
    const user = await UserSOBIE.findOne({ email }); // Searches for the user in the db (email)

    // verifies password by comparing the provided pw with the stored hashed pw
    if (!user || !(await bycrypt.compare(password, user.passwordHash))) {
        return res.send("Invalid Email or Password");
    }
    // genereates new verification token for login
    const verifyToken = crypto.randomBytes(20).toString('hex');
    user.tokenVerify = tokenVerify; 
    // puts the new token to user record
    await user.save();

    // verification link 
    const link = `${req.protocol}://${req.get('host')}/verify?token=${verifyToken}`;

    // sends the link to the user's email (nodemailer)
    transporter.sendMail({
        to: email,
        subject: 'SOBIE Email Verification',
        text: 'Click this link to log in (securely):\n\n${link}'
    });
    // Storing user's email in the session (tempUserId)
    req.session.tempUserId = user._id;
    res.redirect('/verify');
});

// Email Route
router.get('/verify', async (req, res) => {
    // extracts token by retrieving the verification token from req.query
    const { token } = req.query;
    // searches for the user with the matching token 
    const user = await UserSOBIE.findOne({ tokenVerify: token});
    if (!user) return res.send('Invalid Link'); // if not found then prompt
   
    user.tokenVerify = null; // removes
    await user.save(); 
    req.sessionID.userId = user._id; // stores user ID in session
    // redirects to appropriate role
    return res.redirect(user.role === 'admin' ? '/admin-dashboard' : '/user-dashboard');
});

// Update Profile Route
router.post('/profile', async (req, res) => {
    // check to make sure that user is logged in by session
    if (!req.session.userId) return res.redirect('/login');
    const { username } = req.body; // retrieves updated username
    // updates user'susername in db
    await UserSOBIE.findByIdAndUpdate(req.session.userId, { username });
    // redirects back to profile
    res.redirect('/profile');
});

// Research Submission Route
router.post('/submit-research', async (req, res) => {
    // makes sure user is logged in by checking sesssion
    if (!req.session.userId) return res.redirect('/login');
    // extracting the research data
    const {
        researchTitle,
        researchAbstract,
        sessionPreference,
        coAuthorsRawInput
    } = req.body; // retrieving research details 

    // convert the raw input of comma separated strings into an array
    const coAuthors = coAuthorsRawInput
        ? coAuthorsRawInput.split(',').map(name => name.trim()).filter(Boolean) 
        : [];
    
    // saves details of research to the user record in db
    try {
        await UserSOBIE.findByIdAndUpdate(req.session.userId, {
            hasResearch: true,
            researchTitle,
            researchAbstract,
            sessionPreference,
            coAuthors
        });
        // confirmation of sucess
        res.send("Research Submitted Successfully.");
    // handles error 
    } catch (err) {
        console.error('Error | Submission Failed:', err);
        res.status(500).send('Server Side Error | Problem Occured during Submission');
    }
});

// exports the router object (can be imported) for usage in other parts of app
module.exports = router;
