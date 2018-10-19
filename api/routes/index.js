var express = require('express');
var router = express.Router();
var jwt = require('express-jwt');
var auth = jwt({
  secret: 'MY_SECRET',
  userProperty: 'payload'
});

var ctrlProfile = require('../controllers/profile');
var ctrlAuth = require('../controllers/authentication');

// profile
router.get('/profile', auth, ctrlProfile.profileRead);

router.get('/profiletest', auth, ctrlProfile.profileRead);

router.get('/.well-known/acme-challenge/a-string', function(req, res, next) {
  console.log('Test');
  res.render('Express Test a-string');
});

// authentication
router.post('/register', ctrlAuth.register);
router.post('/login', ctrlAuth.login);

module.exports = router;
