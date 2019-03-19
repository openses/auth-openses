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
const https = require('https'), fs = require('fs') /* , helmet = require('helmet') */ ;
var jwtDecode = require('jwt-decode');

const credentials = {
  key: fs.readFileSync('./bin/privkey.pem', 'utf8'),
  cert: fs.readFileSync('./bin/fullchain.pem', 'utf8'),
  };


// in oidcApp.js, authorizationServer.js, client.js, protectedResource.js vor dem Hochladen anpassen
// in files/client/index.html Zeile 45 redirect_uri=https://localhost:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 45 redirect_uri=https://www.innoedu.ch:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 52 redirect_uri=https://localhost:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 52 redirect_uri=https://www.innoedu.ch:9000/callback_facebook_token&state='123'"

// in client.js Zeile 300  var token = request('GET', 'https://graph.facebook.com/v3.2/oauth/access_token?client_id=326817281370555&redirect_uri=https://localhost:9000/callback_facebook_token&client_secret=5ced210c64d794c7590084a1d2e1bff5&code=' + code,
// in client.jsZeile 300 var token = request('GET', 'https://graph.facebook.com/v3.2/oauth/access_token?client_id=326817281370555&redirect_uri=https://www.innoedu.ch:9000/callback_facebook_token&client_secret=5ced210c64d794c7590084a1d2e1bff5&code=' + code,


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
	// "redirect_uris": ["https://" + serverURL + ":9000/callback"],
	"redirect_uris": [http_or_https + serverURL + port_9000_or_9010 + "/callback_code"],
	"scope": "openid profile email permission credentials"
};

// authorization server information
var authServer = {
	authorizationEndpoint: http_or_https + serverURL + port_9001_or_9011 +'/authorize',
	tokenEndpoint: http_or_https + serverURL + port_9001_or_9011 + '/token',
	userInfoEndpoint: http_or_https + serverURL + port_9002_or_9012 +'/userinfo'
};

var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

var protectedResource = http_or_https + serverURL + port_9002_or_9012 + '/resource';

var state = null;

clientApp.get('/', function (req, res, next) {
	res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
});

clientApp.get('/authorize', function(req, res){

	// req.session.oidcflow= 'start';

	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	req.session.oidcflow = req.session.oidcflow.concat('a');

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

clientApp.get('/oidcdemoauth', function(req, res){
	//post redirect nach  http://auth-openses.westeurope.azurecontainer.io:3000/oidc/auth
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
		
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
		
	
		access_token = body.access_token;
		req.session.access_token = access_token;
		console.log('Got access token: %s', access_token);
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
				if (payload.iss == http_or_https + serverURL + port_9001_or_9011 +'/') {
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
			res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
			return;
		}
		
		// res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;

	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
		return;
	}
});

clientApp.get("/callback_code", function(req, res){

	// req.session.oidcflow = 'code';
	if (!req.session.oidcflow) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('a')) {
	req.session.oidcflow = req.session.oidcflow.concat('b');
	};

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		req.session.destroy();
		return;
	}
	
	var resState = req.query.state;
	req.session.resState = resState;
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
	res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
	return;
});

clientApp.get("/callback_facebook_code", function(req, res){
	var facebook_oauth =request("GET", "https://www.facebook.com/v3.2/dialog/oauth?client_id=326817281370555&scope=email&response_type=code&response_mode=query&redirect_uri=https://localhost:9000/callback_facebook_token&state='123'");
});

clientApp.get("/callback_facebook_token", function(req, res){
	var facebook_code = req.query.code;
	console.log('code : ',  facebook_code)
	req.session.facebook_code = facebook_code;
	// var facebook_token = request('GET', 'https://graph.facebook.com/v3.2/oauth/access_token?client_id=326817281370555&redirect_uri=https://localhost:9000/callback_facebook_token&client_secret=5ced210c64d794c7590084a1d2e1bff5&code=' + facebook_code,
	var facebook_token = request('GET', 'https://graph.facebook.com/v3.2/oauth/access_token?client_id=326817281370555&redirect_uri=https://' + serverURL + ':9000/callback_facebook_token&client_secret=5ced210c64d794c7590084a1d2e1bff5&code=' + facebook_code,
	req.body
	);
	console.log("token.req.body", facebook_token.body);
	// req.session.facebook_access_token = token.body.toString('utf8');
	req.session.facebook_access_token = JSON.parse(facebook_token.body);
	req.session.facebook_access_token = req.session.facebook_access_token.access_token;
	console.log("req.session.facebook_access_token", req.session.facebook_access_token); 
	// res.render('facebook', {access_token: req.session.facebook_access_token, facebook_userInfo: req.session.facebook_userInfo, data: null });
	var facebook_userInfo = request('GET', 'https://graph.facebook.com/me?fields=id,name,email&access_token=' + req.session.facebook_access_token,
	req.body
	);
	var json_fb_body = JSON.parse(facebook_userInfo.body)
	var json_fb_body_name = json_fb_body.name;
	req.session.facebook_userInfo = facebook_userInfo.body.toString('utf8');
	req.session.facebook_userInfo = facebook_userInfo.body.toString('utf8');
	console.log("userInfo.body", req.session.facebook_userInfo);
	res.render('facebook_continue', {fb_name: json_fb_body_name});
});

 clientApp.post("/callback_oidc_token", function(req, res){
	 // var body = req.body.toString('utf8');
	 var body = req.body;
	 console.log('body: ', body);
	 console.log('body.code: ', body.code);
	 req.session.oidc_code = body.code;
	 console.log('body.token: ', body.access_token);
	 req.session.oidc_access_token = body.access_token;
	 console.log('body.token_id: ', body.id_token);
	//  body = JSON.parse(body);
	//  console.log('jsonbody: ', body);
	var jwt = jwtDecode(body.id_token);
	console.log('jwt: ', jwt);
	req.session.oidc_jwt_payload = jwt;
	console.log('jwt.sub: ', jwt.sub);
	req.session.oidc_jwt_sub = jwt.sub;
	res.render('oidc_continue', {jwt_sub: req.session.oidc_jwt_sub});
	 });


clientApp.get("/callback_facebook_continue", function(req, res){
	res.render('facebook', {code: req.session.facebook_code, access_token: req.session.facebook_access_token, facebook_userInfo: req.session.facebook_userInfo, data: null });
});

clientApp.get("/callback_oidc_continue", function(req, res){
	res.render('oidc', {code: req.session.oidc_code, access_token: req.session.oidc_access_token, oidc_jwt_sub: req.session.oidc_jwt_sub, data: null });
});

clientApp.get("/get_fb_userInfo", function(req, res){
	var userInfo = request('GET', 'https://graph.facebook.com/me?fields=id,name,email&access_token=' + req.session.facebook_access_token,
	req.body
	);
	req.session.facebook_userInfo = userInfo.body.toString('utf8');
	console.log("serInfo.body.toString('utf8')", req.session.facebook_userInfo); 
	res.render('facebook', {code: req.session.facebook_code, access_token: req.session.facebook_access_token, facebook_userInfo: req.session.facebook_userInfo, data: null });
});

clientApp.get("/fetch_resource_fb", function(req, res){
	// this is only fake, it should be a request to protectedResource.js
	var userInfoJSON = JSON.parse(req.session.facebook_userInfo);
	console.log("userInfoJSON", userInfoJSON);
	var resourseDataBasedOnFacebookID = 'Resource Data.... ( Resource Owner: ' + userInfoJSON.name + ')';
	res.render('facebook', {code: req.session.facebook_code, access_token: req.session.facebook_access_token, facebook_userInfo: '{ id: ' + userInfoJSON.id + ' ,name: ' + userInfoJSON.name + ' ,email: '+userInfoJSON.email+'}',  data: resourseDataBasedOnFacebookID});
});

clientApp.get("/fetch_resource_oidc", function(req, res){
	// this is only fake, it should be a request to protectedResource.js
	var resourseDataBasedOnOidcID = 'Resource Data.... ( Resource Owner: ' + req.session.oidc_jwt_sub + ')';
	res.render('oidc', {code: req.session.oidc_code, access_token: req.session.oidc_access_token, oidc_jwt_sub: req.session.oidc_jwt_sub, data: resourseDataBasedOnOidcID});
});


clientApp.get("/sign_in_with_google_under_construction", function(req, res){
	res.render('google');
});

clientApp.get("/sign_in_with_oidc_under_construction", function(req, res){
	res.render('oidc');
});

clientApp.get("/get_tokens", function(req, res){

	// req.session.oidcflow = 'tokens';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('b')) {
		req.session.oidcflow = req.session.oidcflow.concat('c');
		};
	
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

	var resState = req.session.resState;
	var code = req.session.render_code;

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
		
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
		req.session.body = body;
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


		body = req.session.body;
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
				if (payload.iss == http_or_https + serverURL + port_9001_or_9011 + '/') {
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
			sub = null;
			req.session.sub = payload.sub;
			iss = null;
			req.session.iss = payload.iss;
			
			// res.render('userinfo', {userInfo: userInfo, id_token: id_token});
			res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
			return;
		}
		
		// res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;

	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
		return;
	}
});

clientApp.get("/get_access_token", function(req, res){

	// req.session.oidcflow = 'tokens';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('b')) {
		req.session.oidcflow = req.session.oidcflow.concat('c');
		};
	
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

	var resState = req.session.resState;
	var code = req.session.render_code;

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
		
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
		req.session.body = body;
		access_token = body.access_token;
		req.session.access_token = access_token;
		console.log('Got access token: %s', access_token);
		outputClient = outputClient + "access token: %s" + access_token  + "<br>";
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			req.session.refresh_token = refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}

		scope = body.scope;
		req.session.scope = scope;
		console.log('Got scope: %s', scope);
		outputClient = outputClient + "scope: %s" + scope  + "<br>";
		
		// res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;

	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
		return;
	}
});

clientApp.get('/fetch_resource_with_access_token', function(req, res) {

	// req.session.oidcflow = 'protectedResource';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('c')) {
		req.session.oidcflow = req.session.oidcflow.concat('x');
		};

	var access_token = req.session.access_token;

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded',
		'fetch_resource_with_access_token': 'true'
	};
	

	console.log('headers %s', headers.fetch_resource_with_access_token);
	var resource = request('POST', protectedResource,
		{headers: headers, 'fetch_resource_with_access_token': 'true'}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		protectedResourceVar_with_access_token = body;
		console.log('protectedResourceVar_with_access_token %s', protectedResourceVar_with_access_token);
		req.session.protectedResourceVar_with_access_token = protectedResourceVar_with_access_token;
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;
	} else {
		access_token = null;
		req.session.access_token = access_token;
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

clientApp.get("/get_id_token", function(req, res){

	// req.session.oidcflow = 'tokens';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('c')) {
		req.session.oidcflow = req.session.oidcflow.concat('d');
		};
	
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

	var resState = req.session.resState;
	var code = req.session.render_code;

		body = req.session.body;
		/* scope = body.scope;
		req.session.scope = scope;
		console.log('Got scope: %s', scope);
		outputClient = outputClient + "scope: %s" + scope  + "<br>"; */

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
				if (payload.iss == http_or_https + serverURL + port_9001_or_9011 +'/') {
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
			sub = null;
			req.session.sub = payload.sub;
			iss = null;
			req.session.iss = payload.iss;
			
			// res.render('userinfo', {userInfo: userInfo, id_token: id_token});
			res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
			return;
		}
		
		// res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;	
});

clientApp.get('/decode_jwt', function(req, res) {
	// req.session.oidcflow = 'decode_jwt';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('d')) {
		req.session.oidcflow = req.session.oidcflow.concat('e');
		};
	iss = req.session.iss;
	sub = req.session.sub;
	res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
});

clientApp.get('/userinfo', function(req, res) {
	// req.session.oidcflow = 'userInfo';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	}; 
	if (req.session.oidcflow.includes('e')) {
		req.session.oidcflow = req.session.oidcflow.concat('f');
		};
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
		req.session.credentials = body.credentials;
		req.session.permission = body.permission;
		console.log('profile: ', body.profile);
		console.log('req.session.permission: ', req.session.permission);
		console.log('req.session.credentials: ', req.session.credentials);
	
		// res.render('userinfo', {userInfo:  userInfo, id_token: id_token});
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;
	} else {
		res.render('error', {error: 'Unable to fetch user information'});
		return;
	}
});

clientApp.get('/fetch_resource', function(req, res) {

	// req.session.oidcflow = 'protectedResource';
	if (!req.session.oidcflow ) {
		req.session.oidcflow = 'z';
	};
	if (req.session.oidcflow.includes('f')) {
		req.session.oidcflow = req.session.oidcflow.concat('g');
		};

	var access_token = req.session.access_token;

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded',
		'permission': req.session.permission
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		protectedResourceVar = body;
		req.session.protectedResourceVar = protectedResourceVar;
		res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		return;
	} else {
		access_token = null;
		req.session.access_token = access_token;
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

clientApp.get("/sign_out_destroy_session", function(req, res){
	res.render('index', {render_code: req.session.render_code, access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope, id_token: req.session.body_id_token, sub: req.session.sub, iss: req.session.iss, userInfo: req.session.userInfo, resource_with_access_token: req.session.protectedResourceVar_with_access_token, resource: req.session.protectedResourceVar, profile: req.session.profile, permission: req.session.permission, credentials: req.session.credentials, oidcflow: req.session.oidcflow});
		req.session.destroy();
		return;
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

const clientHttpServer = http.createServer(clientApp);
const clientHttpsServer = https.createServer(credentials, clientApp);

clientHttpsServer.listen(9000, () => {
	console.log('client Https Server running on port 9000');
});

clientHttpServer.listen(9010, () => {
	console.log('client Http Server running on port 9010');
});

/* var server = clientApp.listen(9000, serverURL  , function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});  */


// module.exports = clientApp;s