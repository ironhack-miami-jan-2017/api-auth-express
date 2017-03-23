const express  = require('express');
const passport = require('passport');
const bcrypt   = require('bcrypt');

const User     = require('../models/user-model');

const authRoutes = express.Router();


authRoutes.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const nickname = req.body.nickname;
  const password = req.body.password;

  if (!username || !password) {
    res.status(400).json({ message: 'Provide username and password.' });
    return;
  }

  User.findOne({ username }, '_id', (err, foundUser) => {
    if (err) {
      res.status(500).json({ message: 'Something went wrong.' });
      return;
    }

    if (foundUser) {
      res.status(400).json({ message: 'The username already exists.' });
      return;
    }

    const salt     = bcrypt.genSaltSync(10);
    const hashPass = bcrypt.hashSync(password, salt);

    const theUser  = new User({
      username,
      nickname,
      encryptedPassword: hashPass,
    });

    theUser.save((err) => {
      if (err) {
        res.status(500).json({ message: 'Something went wrong.' });
        return;
      }

      req.login(theUser, (err) => {
        if (err) {
          res.status(500).json({ message: 'Something went wrong.' });
          return;
        }

        res.status(200).json(req.user);
      });
    });
  });
});

// ------------ LOGIN OPTION A ------------
authRoutes.post('/login', (req, res, next) => {
  const passportFunction = passport.authenticate('local',
    (err, theUser, failureDetails) => {
      if (err) {
        res.status(500).json({ message: 'Something went wrong.' });
        return;
      }

      if (!theUser) {
        res.status(401).json(failureDetails);
        return;
      }

      req.login(theUser, (err) => {
        if (err) {
          res.status(500).json({ message: 'Something went wrong.' });
          return;
        }

        res.status(200).json(req.user);
      });
    }
  );

  passportFunction(req, res, next);
});

// ------------ LOGIN OPTION B ------------
// authRoutes.post('/login', (req, res, next) => {
//   passport.authenticate('local', (err, theUser, failureDetails) => {
//     if (err) {
//       res.status(500).json({ message: 'Something went wrong.' });
//       return;
//     }
//
//     if (!theUser) {
//       res.status(401).json(failureDetails);
//       return;
//     }
//
//     req.login(theUser, (err) => {
//       if (err) {
//         res.status(500).json({ message: 'Something went wrong.' });
//         return;
//       }
//
//       res.status(200).json(req.user);
//     });
//   })(req, res, next);
// });


module.exports = authRoutes;
