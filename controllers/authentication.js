const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res) {
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ email: email }, function(err, existing) {
    if (err) { next(err); };

    if (existing) {
      return res.status(422).send({ error: 'Email is already in use' });
    }

    const user = new User({ email: email, password: password });

    user.save(function(err, created) {
      if (err) { next(err) };

      res.send({ token: tokenForUser(user) });
    });
  });
}
