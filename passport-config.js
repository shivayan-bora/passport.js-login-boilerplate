// Using a local strategy since we are persisting users locally and would be doing local authentication
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize(passport, getUserByEmail, getUserById) {
    // Function to authenticate
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email);
        if(user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        try {
            if(await bcrypt.compare(password, user.password)) {
                return done(null, user)

            } else {
                return done(null, false, { message: 'Password Incorrect' })
 
            }

        } catch(e) { 
            return done(e);
        }
    }

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    
    // Function to serialize our user
    passport.serializeUser((user, done) => done(null, user.id));
    // Function to deserialize our user
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    });
}

module.exports = initialize;