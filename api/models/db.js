var mongoose = require('mongoose');
var gracefulShutdown;
// https://www.npmjs.com/package/dotenv
const db_host = process.env.DB_HOST;
const dbuser = process.env.DB_USER;
const dbpassword = process.env.DB_PASSWORD;

const dbURI = "mongodb://" + dbuser + ":" + dbpassword + db_host;

/* if (process.env.NODE_ENV === 'production') {
  dbURI = process.env.MONGOLAB_URI;
} */

mongoose.connect(dbURI, {useNewUrlParser: true });

// CONNECTION EVENTS
mongoose.connection.on('error', console.error.bind(console, 'connection error:'));
mongoose.connection.on('connected', function() {
  console.log('Mongoose connected to ' + dbURI);
});
mongoose.connection.once('open', function() {
    console.log(JSON.stringify("we're connected!" + " user: " + dbuser + " pw: " + dbpassword))
  });
  
  // mongoose.disconnect();

  mongoose.connection.on('disconnected', function() {
    console.log('Mongoose disconnected');
  });


  // CAPTURE APP TERMINATION / RESTART EVENTS
// To be called when process is restarted or terminated
gracefulShutdown = function(msg, callback) {
  mongoose.connection.close(function() {
    console.log('Mongoose disconnected through ' + msg);
    callback();
  });
};
// For nodemon restarts
process.once('SIGUSR2', function() {
  gracefulShutdown('nodemon restart', function() {
    process.kill(process.pid, 'SIGUSR2');
  });
});
// For app termination
process.on('SIGINT', function() {
  gracefulShutdown('app termination', function() {
    process.exit(0);
  });
});
// For Heroku app termination
process.on('SIGTERM', function() {
  gracefulShutdown('Heroku app termination', function() {
    process.exit(0);
  });
});

  // BRING IN YOUR SCHEMAS & MODELS
require('./users');

  // mongoose.connection.close;