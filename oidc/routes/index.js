var express = require('express');
var router_oidc = express.Router();
/* var jwt = require('express-jwt');
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
router.post('/login', ctrlAuth.login); */

router_oidc.get('/test', function(req, res, next) {
    console.log('oidc Test');
    // res.render('oidc Test');
   res.render('index', { title: 'oidcTest' });
   })
router_oidc.get('/rendertest', function(req, res, next) {
   console.log('RenderTest');
   res.render('index', { title: 'RenderTest'});
})

module.exports = router_oidc;