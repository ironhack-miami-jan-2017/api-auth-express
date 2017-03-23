const LocalStrategy = require('passport-local').Strategy;
const bcrypt        = require('bcrypt');

const User          = require('../models/user-model');


module.exports = function (passport) {
  passport.use(new LocalStrategy((username, password, next) => {
    User.findOne({ username }, (err, foundUser) => {
      if (err) {
        next(err);
        return;
      }

      if (!foundUser) {
        next(null, false, { message: 'Incorrect username' });
        return;
      }

      const didPasswordMatch = bcrypt.compareSync(password, foundUser.encryptedPassword);

      if (!didPasswordMatch) {
        next(null, false, { message: 'Incorrect password' });
        return;
      }

      next(null, foundUser);
    });
  }));


  passport.serializeUser((loggedInUser, cb) => {
    cb(null, loggedInUser._id);
  });


  passport.deserializeUser((userIdFromSession, cb) => {
    User.findById(userIdFromSession, (err, userDocument) => {
      if (err) {
        cb(err);
        return;
      }

      cb(null, userDocument);
    });
  });
};
