var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
var jose = require('jsrsasign');
var cors = require('cors');

// in oidcApp.js, authorizationServer.js, client.js, protectedResource.js vor dem Hochladen anpassen
// in files/client/index.html Zeile 48 bis 60 facebook, google, oidc -> switch local/azure -> redirect
// in files/client/oidc.html Zeile 61 bis 64 switch local/azure -> redirect


serverURL = 'www.innoedu.ch';
var http_or_https = 'https://';
var port_9000_or_9010 = ':9000';
var port_9001_or_9011 = ':9001';
var port_9002_or_9012 = ':9002';

/*
serverURL = 'localhost';
var http_or_https = 'http://';
var port_9000_or_9010 = ':9010';
var port_9001_or_9011 = ':9011';
var port_9002_or_9012 = ':9012'; 
*/

var protectedResource = {
	protectedResourceEndpoint: http_or_https + serverURL + port_9002_or_9012 +'/resource',
	userInfoEndpoint: http_or_https + serverURL + port_9002_or_9012 +'/userinfo'
};

var protectedResourceApp = express();

protectedResourceApp.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

protectedResourceApp.engine('html', cons.underscore);
protectedResourceApp.set('view engine', 'html');
protectedResourceApp.set('views', 'files/protectedResource');
protectedResourceApp.set('json spaces', 4);

protectedResourceApp.use('/', express.static('files/protectedResource'));
protectedResourceApp.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var resource_student = {
	"name": "Protected Resource Student",
	"description": "This data has been protected by OAuth 2.0 for the permission 'student'"
};

var resource_teacher = {
	"name": "Protected Resource Teacher",
	"description": "This data has been protected by OAuth 2.0 for the permission 'teacher'"
};

var resource_school_administrator = {
	"name": "Protected Resource School Administrator",
	"description": "This data has been protected by OAuth 2.0 for the permission 'school-administrator'"
};

var resource_government_administrator = {
	"name": "Protected Resource Government Administrator",
	"description": "This data has been protected by OAuth 2.0 for the permission 'government-administrator'"
};

var resource_malicious_attacker = {
	"name": "Protected Resource Malicious Attacker",
	"description": "This data has been protected by OAuth 2.0 for the permission 'malicious-attacker'"
};

var resource_with_access_token = {
	"name": "Protected Resource anonymous Access",
	"description": "This data has been protected by OAuth 2.0 for access with Access Token but No ID Token"
};

var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var permission = req.headers.permission;
	req.permission = permission;
	var fetch_resource_with_access_token = req.headers.fetch_resource_with_access_token;
	req.fetch_resource_with_access_token = fetch_resource_with_access_token;
	console.log('req.fetch_resource_with_access_token: %s', req.fetch_resource_with_access_token);
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);
	console.log('req.body.fetch_resource_with_access_token: ', req.body.fetch_resource_with_access_token)
	console.log('req.access_token: %s', req.access_token);
	console.log('permission: %s', permission);
	console.log('res.fetch_resource_with_access_token: %s', req.fetch_resource_with_access_token);


		/*
	-> Funktioniert mit aktuellem node.js nicht mehr
	-> "nosql": "^6.1.0", aktualisiert
	-> siehe auch: https://forums.manning.com/posts/list/44617.page;jsessionid=97EEFD6985B87DA757E58C67A00E5838
	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
			console.log("We found a matching token: %s", inToken);
		} else {
			console.log('No matching token was found.');
		}
		req.access_token = token;
		next();
		return;
	});
	*/

	nosql.find().make(function(filter) {
		filter.where('access_token', inToken);
        filter.callback(function(err, DbFiltered) {
			console.log("Error: ", err,  "DbFiltered: ", DbFiltered);
			token = DbFiltered[0];
			console.log("Error: ", err,  "Found a token: ", token);
			req.access_token = token;
            next();
        }); 
	});

};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

protectedResourceApp.options('/resource', cors());

protectedResourceApp.post("/resource", cors(), getAccessToken, function(req, res){
	console.log(req.access_token);
	if (req.access_token) {
		// res.json(resource);
		if (req.fetch_resource_with_access_token == 'true') {
			res.json(resource_with_access_token);
				}
		else if (req.permission == 'student') {
		res.json(resource_student);
		}
		else if (req.permission == 'teacher') {
			res.json(resource_teacher);
			}
		else if (req.permission == 'school-administrator') {
			res.json(resource_school_administrator);
			}
		else if (req.permission == 'government-administrator') {
			res.json(resource_government_administrator);
			}
		else if (req.permission == 'malicious-attacker') {
			res.json(resource_malicious_attacker);
			}
				else {
			res.status(401).end();
		};
	} else {
		res.status(401).end();
	}
	
});

var userInfoEndpoint = function(req, res) {
	
	if (!__.contains(req.access_token.scope, 'openid')) {
		res.status(403).end();
		return;
	}
	
	var user = req.access_token.user;
	if (!user) {
		res.status(404).end();
		return;
	}
	
	var out = {};
	__.each(req.access_token.scope, function (scope) {
		if (scope == 'openid') {
			__.each(['sub'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'profile') {
			__.each(['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'email') {
			__.each(['email', 'email_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'address') {
			__.each(['address'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'phone') {
			__.each(['phone_number', 'phone_number_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'permissiongroupe') {
			__.each(['permissiongroupe'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'credentials') {
			__.each(['credentials'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'permission') {
			__.each(['permission'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		}
	});
	
	res.status(200).json(out);
	return;
};

protectedResourceApp.get('/info', function(req, res) {
	res.render('info', {protectedResource: protectedResource});
});

protectedResourceApp.get('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);
protectedResourceApp.post('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);

protectedResourceApp.use('/', express.static('files/protectedResource'));

module.exports = protectedResourceApp;