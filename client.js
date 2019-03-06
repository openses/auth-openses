var express = require("express");
var session = require('express-session');
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');
var __ = require('underscore');
__.string = require('underscore.string');
const http = require('http');
var outputClient = "";

var serverURL;

// in oidcApp.js, authorizationServer.js, client.js vor dem Hochladen anpassen
// client/index.html -> Zeile 97 
// authorizationServer/error.html -> Zeile 32
// serverURL = 'localhost';
serverURL = 'auth-openses.westeurope.azurecontainer.io';



var clientApp = express();

clientApp.use(session({secret: "xcerats24srw"}));


clientApp.use(bodyParser.json());
clientApp.use(bodyParser.urlencoded({ extended: true }));

clientApp.engine('html', cons.underscore);
clientApp.set('view engine', 'html');
clientApp.set('views', 'files/client');

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://" + serverURL + ":9000/callback"],
	"scope": "openid profile email phone address password salt hash"
};

outputClient = outputClient + "client_id: " + "oauth-client-1" + "<br>";;
outputClient = outputClient + "client_secret: " + "oauth-client-secret-1" + "<br>";
outputClient = outputClient + "\ redirect_uris: " + "http://" + serverURL + ":9000/callback" + "<br>";
outputClient = outputClient + "client_id: " + "openid profile email phone address" + "<br>";

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://' + serverURL + ':9001/authorize',
	tokenEndpoint: 'http://' + serverURL + ':9001/token',
	userInfoEndpoint: 'http://' + serverURL + ':9002/userinfo'
};

outputClient = outputClient + "authorizationEndpoint: " + authServer.authorizationEndpoint + "<br>";
outputClient = outputClient + "tokenEndpoint: " + "http://" + authServer.tokenEndpoint + "<br>";
outputClient = outputClient + "userInfoEndpoint: " + "http://" + authServer.userInfoEndpoint + "<br>";

var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

var protectedResource = 'http://' + serverURL + ':9002/resource';

var state = null;
// var render_code = null;
// var access_token = null;
// var refresh_token = null;
// var scope = null;
// var id_token = null;
// var userInfo = null;
// var sub = null;
// var iss = null;
// var body_id_token = null;
// var protectedResourceVar = null;



clientApp.get('/', function (req, res, next) {
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource: req.session.protectedResourceVar, profile: req.session.profile});
});

clientApp.get('/authorize', function(req, res){

	var access_token = null;
	req.session.access_token = access_token;
	var refresh_token = null;
	var scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});

	req.session.scope = scope;
	
	console.log("redirect", authorizeUrl);
	// outputClient = "Test";
	outputClient = outputClient + "redirect: " + authorizeUrl + "<br>";
	res.redirect(authorizeUrl);
});

clientApp.get("/callback", function(req, res){

	if (req.query.error) {
		// it's an error response, act accordingly
		var access_token = null;
		var refresh_token = null;
		var scope = null;
		render_code = null;
		var body_id_token = null;
		var id_token = null;
		var sub = null;
		var iss = null;
		var userInfo = null;
		var protectedResourceVar = null;
		res.render('error', {error: req.query.error});
		req.session.destroy();
		return;
	}
	
	var resState = req.query.state;
	if (resState == state) {
		console.log('State value matches: expected %s got %s', state, resState);
		outputClient = outputClient + "State value matches: expected %s got %s: " + state + " " + resState + "<br>";
	} else {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		outputClient = outputClient + "St'State DOES NOT MATCH: expected %s got %s: " + state + " " + resState + "<br>";
		res.render('error', {error: 'State value did not match'});
		outputClient = outputClient + "error: " + "State value did not match" + "<br>";
		return;
	}

	var code = req.query.code;
	req.session.render_code = code;
	

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uris[0]
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);
	outputClient = outputClient + "code: " + code  + "<br>";
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		req.session.access_token = access_token;
		console.log('Got access token: %s', access_token);
		outputClient = outputClient + "access token: %s" + access_token  + "<br>";
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			req.session.refresh_token = refresh_token;
			console.log('Got refresh token: %s', refresh_token);
			outputClient = outputClient + "refresh token: %s" + refresh_token  + "<br>";
		}
		
		scope = body.scope;
		req.session.scope = scope;
		console.log('Got scope: %s', scope);
		outputClient = outputClient + "scope: %s" + scope  + "<br>";

		if (body.id_token) {
			userInfo = null;
			id_token = null;

			console.log('Got ID token: %s', body.id_token);
			outputClient = outputClient + "ID token: %s" + body.id_token  + "<br>";
			body_id_token = body.id_token;
			req.session.body_id_token = body_id_token;
			// check the id token
			var pubKey = jose.KEYUTIL.getKey(rsaKey);
			var tokenParts = body.id_token.split('.');
			var payload = JSON.parse(base64url.decode(tokenParts[1]));
			console.log('Payload', payload);
			if (jose.jws.JWS.verify(body.id_token, pubKey, [rsaKey.alg])) {
				console.log('Signature validated.');
				if (payload.iss == 'http://' + serverURL + ':9001/') {
					console.log('issuer OK');
					if ((Array.isArray(payload.aud) && __.contains(payload.aud, client.client_id)) || 
						payload.aud == client.client_id) {
						console.log('Audience OK');
		
						var now = Math.floor(Date.now() / 1000);
		
						if (payload.iat <= now) {
							console.log('issued-at OK');
							if (payload.exp >= now) {
								console.log('expiration OK');
				
								console.log('Token valid!');

								// save just the payload, not the container (which has been validated)
								id_token = payload;
								
				
							}
						}
					}
				}
			}
			req.session.userInfo = userInfo;
			sub = payload.sub;
			req.session.sub = sub;
			iss = payload.iss;
			req.session.iss = iss;
			
			// res.render('userinfo', {userInfo: userInfo, id_token: id_token});
			res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource: req.session.protectedResourceVar, profile: req.session.profile});
			return;
		}
		
		// res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource: req.session.protectedResourceVar, profile: req.session.profile});
		return;

	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
		return;
	}
});

clientApp.get('/fetch_resource', function(req, res) {

	var access_token = req.session.access_token;

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		protectedResourceVar = body;
		req.session.protectedResourceVar = protectedResourceVar;
		// res.render('data', {resource: body});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource: req.session.protectedResourceVar, profile: req.session.profile});
		return;
	} else {
		access_token = null;
		req.session.access_token = access_token;
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

clientApp.get('/userinfo', function(req, res) {
	
	var access_token = req.session.access_token;
	var id_token = req.session.id_token
	// var profile = null;
	

	var headers = {
		'Authorization': 'Bearer ' + access_token
	};
	
	var resource = request('GET', authServer.userInfoEndpoint,
		{headers: headers}
	);
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('Got data: ', body);
		// protectedResource = resource;
	
		userInfo = body;
		req.session.userInfo = userInfo;
		req.session.profile = body.profile;
		console.log('profile: ', body.profile);
		console.log('salt: ', body.salt);
		
	
		// res.render('userinfo', {userInfo:  userInfo, id_token: id_token});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource: req.session.protectedResourceVar, profile: req.session.profile});
		return;
	} else {
		res.render('error', {error: 'Unable to fetch user information'});
		return;
	}
	
});

clientApp.use('/', express.static('files/client'));

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
	
	return url.format(newUrl);s
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

function clearOutputClient(){
	outputClient = "";

}

clientApp.get('/outputClient', function(req, res,) {
	res.render('outputClient', {outputClient: outputClient});
	return;	
});

const clientHttpServer = http.createServer(clientApp);

clientHttpServer.listen(9000, () => {
	console.log('client Http Server running on port 9000');
});

/* var server = clientApp.listen(9000, serverURL  , function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});  */


// module.exports = clientApp;s