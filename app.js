/*

  There are some minor modifications to the default Express setup
  Each is commented and marked with [SH] to make them easy to find

 */

var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var cors = require('cors');
// [SH] Require Passport
var passport = require('passport');
// https://www.npmjs.com/package/dotenv -> see ./api/models/db.js -> dbURI
var dotenv = require('dotenv').config('.env');
if (dotenv.error) {
    throw dotenv.error
  };

// [SH] Bring in the data model
require('./api/models/db');
// [SH] Bring in the Passport config after model is defined
require('./api/config/passport');


// [SH] Bring in the routes for the API (delete the default routes)
var routesApi = require('./api/routes/index');
// var routesOIDC = require('./oidc/routes/index');

var app = express();
// change from seperated apps (ports) to supApps
var labRouter = express.Router();
var clientApp = require("./client");
var authorizationServerApp = require("./authorizationServer");
var protectedResourceApp = require("./protectedResource");

// für 
app.use(express.static('static'));

  

// view engine setup
app.set('views', path.join(__dirname, 'views'));
// app.set('view engine', 'jade');
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
//app.use(logger('dev'));
app.use(logger('short'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cors());

// [SH] Initialise Passport before using the route middleware
app.use(passport.initialize());

// no stores configured, all in-memory (dev only)
// oidc.initialize({ clients });

// [SH] Use the API routes when path starts with /api
app.use('/api', routesApi);
// app.use('/oidc', routesOIDC);

// change from seperated apps (ports) to supApps
app.use('/labClient', clientApp);
app.use('/labAuthorizationServer', authorizationServerApp);
app.post('/labAuthorizationServer/token', function(req,res) {
  console.log("oh je");
  res.send("oh je");
});
app.use('/labProtectedResource', protectedResourceApp);
labRouter.all('/labClient/*', clientApp);
labRouter.all('/labAuthorizationServer/*', authorizationServerApp);
labRouter.all('/labProtectedResource/*', protectedResourceApp);
/* app
 .use('/labClient', clientApp)
 .use('/labAuthorizationServer', authorizationServerApp)
 .use('/labProtectedResource', protectedResourceApp)
//app.use('/labClient', clientApp); */
// app.use('/labAuthorizationServer', authorizationServerApp);
//app.use('/labAuthorizationServer', AuthorizationServerRouter);
//app.post('/labAuthorizationServer/token', authorizationServerApp)
//app.use('/labAuthorizationServer/token', authorizationServerApp)
//labRouter.get('/labAuthorizationServer/authorize', authorizationServerApp);
//labRouter.post('/labAuthorizationServer', authorizationServerApp);
//app.use('/labProtectedResource', protectedResourceApp);
/* app.route('/labAuthorizationServer')
  .get(authorizationServerApp)
  .post(authorizationServerApp) */

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// [SH] Catch unauthorised errors
app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    res.status(401);
    res.json({"message" : err.name + ": " + err.message});
  }
});

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

/* app.get('/rendertest', function (req, res) {
    console.log('RenderTest');
    res.render('index', { title: 'RenderTest'});
  }); */

// no stores configured, all in-memory (dev only)


module.exports = app;
