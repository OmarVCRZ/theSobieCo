const mongoose = require('mongoose'); 
const bycrypt = require('bcrypt'); // Password Hashing: https://www.npmjs.com/package/bcrypt

// Mongoose Schematics: https://mongoosejs.com/docs/guide.html
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    passwordHash: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['attendee', 'researcher', 'admin'],
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true // this has to be unique so there's no duplicates on accounts
    },
    // Email Verification Code
    tokenVerify: {
        type: String, // this is for email verification
        default: null // stores null in db if tokenVerify is not set manually (nothing was given)
    },
    // Does the User have Research they will present in SOBIE.
    hasResearch: {
        type: Boolean,
        default: false
    },
    researchTitle: String,
    researchAbstract: String,
    coAuthors: [String], // Could be multiple (Array)
    sessionPreference: String // Do you want to attend a student, faculty, or no preference?
});
// Validation on password by comparing input to hashsed password
userSchema.methods.validatePW = function (password) {
    return bycrypt.compare(password, this.passwordHash);
};

// Exporting the Model: https://www.freecodecamp.org/news/module-exports-how-to-export-in-node-js-and-javascript/
module.exports = mongooose.model('UserSOBIE', userSchema);
