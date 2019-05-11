var express = require("express");
var session = require('express-session');
var url = require("url");
var bodyParser = require('body-parser');
var request_auth = require("request");
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
var jose = require('jsrsasign');
var md5 = require('md5');

// in oidcApp.js, authorizationServer.js, client.js, protectedResource.js vor dem Hochladen anpassen
// in files/client/index.html Zeile 48 bis 60 facebook, google, oidc -> switch local/azure -> redirect
// in files/client/oidc.html Zeile 61 bis 64 switch local/azure -> redirect

/*
serverURL = 'www.innoedu.ch';
var http_or_https = 'https://';
var port_9000_or_9010 = ':9000';
var port_9001_or_9011 = ':9001';
var port_9002_or_9012 = ':9002';
*/

/*
serverURL = 'localhost';
var http_or_https = 'http://';
var port_9000_or_9010 = ':9010';
var port_9001_or_9011 = ':9011';
var port_9002_or_9012 = ':9012';
*/

// change from seperated apps (ports) to supApps
serverURL = 'localhost';
var http_or_https = 'http://';
var port_9000_or_9010 = '/labClient';
var port_9001_or_9011 = '/labAuthorizationServer';
var port_9002_or_9012 = '/labProtectedResource';


var authorizationServerApp = express();


authorizationServerApp.use(bodyParser.json());
authorizationServerApp.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

authorizationServerApp.engine('html', cons.underscore);
authorizationServerApp.set('view engine', 'html');
authorizationServerApp.set('views', 'files/authorizationServer');
authorizationServerApp.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: http_or_https + serverURL + port_9001_or_9011 +'/authorize',
	tokenEndpoint: http_or_https + serverURL + port_9001_or_9011 +'/token'
};

// client information
var clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": [http_or_https + serverURL + port_9000_or_9010 +"/callback_code"],
		"scope": "openid profile email permission credentials "
	}
];

var rsaKey = {
  "alg": "RS256",
  "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

var userInfo = {
	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"profile":  {
			"favourite_colour": "blue",
			"favourite_animal": "cat" 
		},
		"email": "alice.student@example.com",
		"email_verified": true,
		"permission_groupe": "student",
		"credentials":  {
			"password": "Lp21:DIeuv", 
			"salt": "salt1",
			"hash": "084973670e2913b1500a30c7b7343a0b"
		},
		"permission": "student"
	},
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"profile":  {
			"favourite_colour": "red",
			"favourite_animal": "dog" 
		},
		"email": "bob.teacher@example.net",
		"email_verified": true,
		"permission_groupe": "teacher",
		"credentials":  {
			"password": "Lp21:DIeuv", 
			"salt": "salt2",
			"hash": "0da7baa58ec080fd0b67057f97f5e7f5"
		},
		"permission": "teacher"
	},
	"carol": {
		"sub": "K95E-8UF1-7453C",
		"preferred_username": "carol",
		"name": "Carol",
		"profile":  {
			"favourite_colour": "green",
			"favourite_animal": "cow" 
		},
		"email": "carol.school-administrator@example.net",
		"email_verified": true,
		"permission_groupe": "school-administrator",
		"credentials":  {
			"password": "Lp21:DIeuv", 
			"salt": "salt3",
			"hash": "dffb8c1df66c57b67c6f8600d4337c65"
		},
		"permission": "school-administrator"
	},
	"dave": {
		"sub": "G6R2-G6E1-7352D",
		"preferred_username": "dave",
		"name": "Dave",
		"profile":  {
			"favourite_colour": "pink",
			"favourite_animal": "hamster" 
		},
		"email": "dave.government-administrator@example.net",
		"email_verified": true,
		"permission_groupe": "government-administrator",
		"credentials":  {
			"password": "Lp21:DIeuv", 
			"salt": "salt4",
			"hash": "4beb0e02dd728806d0e9482baa8462ed"
		},
		"permission": "government-administrator"
	},
	"mallory": {
		"sub": "H6R3-J8Z5-5897M",
		"preferred_username": "mallory",
		"name": "Mallory",
		"profile":  {
			"favourite_colour": "black",
			"favourite_animal": "tiger" 
		},
		"email": "mallory.malicious-attacker.@example.net",
		"email_verified": false,
		"permission_groupe": "malicious-attacker",
		"credentials":  {
			"password": "Lp21:DIeuv", 
			"salt": "salt5",
			"hash": "df5936712c7e37d7b79b2d8c7d506cd1"
		},
		"permission": "malicious-attacker"
	}
};

var getUser = function(username) {
	return userInfo[username];
};


// https://www.npmjs.com/package/md5
// https://hashgenerator.de/
// https://de.wikipedia.org/wiki/Bcrypt
// https://www.abeautifulsite.net/hashing-passwords-with-nodejs-and-bcrypt
// https://www.npmjs.com/package/bcrypt

var getCredentials = function(username) {
	return getUser(username).credentials;
};

var getHash = function(username) {
	return getUser(username).credentials.hash;
};

var getSalt = function(username) {
	return getUser(username).credentials.salt;
};

var getPassword = function(username) {
	return getUser(username).credentials.password;
};

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

var getProtectedResource = function(resourceId) {
	return __.find(protectedResources, function(resource) { return resource.resource_id == resourceId; });
};

authorizationServerApp.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer, redirect_uri: http_or_https + serverURL + port_9000_or_9010 +'/callback_code'});
});

authorizationServerApp.get("/authorize", function(req, res){
	console.log("/authorize wurde mit authorizationServerApp.get aufgerufen");
	
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
		var reqid = randomstring.generate(8);
		
		requests[reqid] = req.query;
		
		res.render('approve_user_pw', {client: client, reqid: reqid, scope: rscope});
		// res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

authorizationServerApp.post('/approve', function(req, res) {
	console.log("/approve wurde mit authorizationServerApp.post aufgerufen");

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}

	console.log('input user: ', req.body.user );
	console.log('getUser: ', getUser(req.body.user));
	
	if (!getUser(req.body.user)){
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'user not found'
		});
		res.redirect(urlParsed);
		return;	
	}
	console.log('getHash: ', getHash(req.body.user));
	console.log('getSalt: ', getSalt(req.body.user));
	console.log('built hash: ', md5(req.body.password + getSalt(req.body.user)));

	if (md5(req.body.password + getSalt(req.body.user)) != getHash(req.body.user)){
		var urlParsed = buildUrl(query.redirect_uri, {
			error: "password doesn't match"
		});
		res.redirect(urlParsed);
		return;	
	}


	
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access
			var code = randomstring.generate(8);
			
			var user = getUser(req.body.user);

			

			var scope = getScopesFromForm(req.body);

			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}


			

			// save the code and request for later
			codes[code] = { request: query, scope: scope, user: user };
		
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

authorizationServerApp.get('/testMethodGet', function(req, res) {
	console.log("/test Routing Test for http://localhost/labAuthorizationServer/testMethodGet");
	res.send("/test Routing Test for http://localhost/labAuthorizationServer/testMethodGet");
});

authorizationServerApp.post('/testMethodPost', function(req, res) {
	console.log("/test Routing Test for http://localhost/labAuthorizationServer/testMethodPost");
	res.send("/test Routing Test for  http://localhost/labAuthorizationServer/testMethodPost");
});

authorizationServerApp.post("/token", function(req, res, next){
	console.log("Zeile 357: /token wurde mit authorizationServerApp.post aufgerufen");
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId, scope: code.scope, user: code.user });

				console.log('Issuing access token %s', access_token);
				console.log('with scope %s', code.scope);

				var cscope = null;
				if (code.scope) {
					cscope = code.scope.join(' ');
				}

				var token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope };

				if (__.contains(code.scope, 'openid') && code.user) {
					var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };

					var ipayload = {
						iss: http_or_https + serverURL + port_9001_or_9011 +'/',
						sub: code.user.sub,
						aud: client.client_id,
						iat: Math.floor(Date.now() / 1000),
						exp: Math.floor(Date.now() / 1000) + (5 * 60)	
					};
					if (code.request.nonce) {
						ipayload.nonce = code.request.nonce;
					}

					var privateKey = jose.KEYUTIL.getKey(rsaKey);
					var id_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(ipayload), privateKey);

					console.log('Issuing ID token %s', id_token);

					token_response.id_token = id_token;
				}

				// res.status(200).json(token_response);
				console.log('Zeile 436 Issued tokens for code %s', req.body.code);
				// var callback_response = request_auth.post({url: 'http://localhost/labClient/callback_get_access_token', body: token_response});
				// console.log("callback_response.status: " + callback_response.status);
				console.log('Zeile 439');
				console.log('JSON.token_response: ' + JSON.stringify(token_response));
				// session.token_response = token_response;
				
				request_auth.post({
					// url: 'http://localhost/labClient/callback_get_access_token',
					url: http_or_https + serverURL + port_9000_or_9010 + '/callback_get_access_token',
					body: token_response,
					json: true
				  }, function(error, response, body){
				  console.log('Zeile 450: request_auth.post token_response: ' + body);
				  res.status(200).send(body);
				}); 
				// res.status(200).send(token_response);
				console.log("Ende: authorizationServerApp.post('/token'");
				return;
				
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

authorizationServerApp.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

module.exports = authorizationServerApp;