// Means if we're in development server
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// Used to get express
const express = require('express');
const app = express();
// Used for encrypting and decrypting passwords
const bcrypt = require('bcrypt');
// Used for authentication
const passport = require('passport')
// For displaying messages in case we fail to login
const flash = require('express-flash')
// In order to store and persist our user across different pages
const session = require('express-session')
// delete is not supported by forms and we can only use post, 
// so for implementing delete, we need this library
const methodOverride = require('method-override');

const initializePassport = require('./passport-config');
initializePassport(
    passport, 
    // Function for finding the user based on the email
    email => users.find(user => user.email === email),
    // Function for finding the user based on the id
    id => users.find(user => user.id === id)
);

// Local storage for users instead of a database
// This will get erased on each initialization of the server or on every refresh
const users = [];

// Telling our server that we are using ejs
app.set('view-engine', 'ejs');

// We want to take values from our form and we should be able to
// access them inside our request variable inside of our post method
app.use(express.urlencoded({ extended: false }));

// Our server should know how to use passport
app.use(flash())
app.use(session({
    // Essentially a key that we want to keep secret which is going to encrypt
    // all of our information for us
    secret: process.env.SESSION_SECRET,
    // Should we resave our session variables if nothing has changed
    resave: false,
    // Should we save an empty value in the session if there is no value
    saveUninitialized: false
}))
// Initialize some of the basics for us in passport
app.use(passport.initialize())
// Since we want to persist our variables across the entire session our user has
app.use(passport.session())

app.use(methodOverride('_method'));

// Home page route
app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', {name: req.user.name});
})

// Login page Route
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
})

// POST Request for login
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true  // Message in case failure to login
}))

// Register page Route
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

// POST Request for registering a user
// In HTML, whatever corresponds to name, we can use it in req.body.<var>
app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
        });
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
})

// For logging out
app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})

// To protect our functions from unauthenticated users
// Middleware function
// next: The function to be called once we are done authenticating
function checkAuthenticated(req, res, next) {
    if(req.isAuthenticated()) {
        return next();
    }

    res.redirect('/login');
}

// We don't want to go back to login page if we are already authenticated
function checkNotAuthenticated(req, res, next) {
    if(req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();    
}

// Start listening to port 4000
app.listen(4000)