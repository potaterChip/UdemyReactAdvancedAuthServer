const Authentication = require('./controllers/Authentication');
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireLocalAuth = passport.authenticate('local', { session: false });


module.exports = function(app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ hi: 'there' });
  });

  app.post('/signin', requireLocalAuth, Authentication.signin);

  app.post('/signup', Authentication.signup);
}
