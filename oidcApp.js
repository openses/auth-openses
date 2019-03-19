const express = require('express');
const Provider = require('oidc-provider');

// in oidcApp.js, authorizationServer.js, client.js, protectedResource.js vor dem Hochladen anpassen
// in files/client/index.html Zeile 45 redirect_uri=https://localhost:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 45 redirect_uri=https://www.innoedu.ch:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 52 redirect_uri=https://localhost:9000/callback_facebook_token&state='123'"
// in files/client/index.html Zeile 52 redirect_uri=https://www.innoedu.ch:9000/callback_facebook_token&state='123'"


 
serverURL = 'www.innoedu.ch';
ClientserverURL = 'www.innoedu.ch';
var http_or_https = 'http://'; //https
var port_3000_or_3010 = ':3000'; 

/*
serverURL = '127.0.0.1';
var http_or_https = 'http://';
var port_3000_or_3010 = ':3000'; //3010
*/





const oidcApp = express();

const clients = [
    // token id_token code
    {client_id: 'eidlab_token_id_token_code',
    client_secret: 'super_secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token id_token code'],
    redirect_uris: ['https://' + serverURL + ':9000/callback_oidc_token'],
    token_endpoint_auth_method: 'none'},


    {client_id: 'token_id_token_code',
    client_secret: 'super_secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token id_token code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // local -> token id_token code
    {client_id: 'local_test_oidcdebugger_com_token_id_token_code',
    client_secret: 'super_secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token id_token code'],
    // redirect_uris: ['https://oidcdebugger.com/debug'],
    redirect_uris: ['https://127.0.0.1:3001/callback'],
    token_endpoint_auth_method: 'none'},
    // token code
    {client_id: 'test_oidcdebugger_com_token_code',
    client_secret: 'client_secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // code id_token 
    {client_id: 'test_oidcdebugger_com_code_id_token',
    client_secret: 'client_secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['code id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'}, 
    // token id_token
    {client_id: 'test_oidcdebugger_com_token_id_token',
    client_secret: 'client_secret',
    grant_types: ['implicit'],
    response_types: ['token id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // code
    {client_id: 'code',
    client_secret: 'client_secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    {client_id: 'code_eidlab',
    client_secret: 'client_secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://localhost:9000/callback_oidc_token'],
    token_endpoint_auth_method: 'none'},
    // token
    {client_id: 'token',
    client_secret: 'client_secret',
    grant_types: ['implicit'],
    response_types: ['token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // id_token
    {client_id: 'id_token',
    client_secret: 'client_secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    
    {
    client_id: 'test_oauth_app',
    client_secret: 'client_secret',
    client_secret: 'super_secret',
    grant_types: ['client_credentials'],
    redirect_uris: [],
    response_types: [],
}];

const oidc = new Provider(http_or_https + serverURL + port_3000_or_3010, {
    claims: {
        address: ['address'],
        email: ['email', 'email_verified'],
        phone: ['phone_number', 'phone_number_verified'],
        profile: ['birthdate', 'family_name', 'gender', 'given_name', 'locale', 'middle_name', 'name',
            'nickname', 'picture', 'preferred_username', 'profile', 'updated_at', 'website', 'zoneinfo']
    },
    scopes: ['api1'],
    features: {
        clientCredentials: true,
        introspection: true,
        sessionManagement: true
    },
    async findById(ctx, id) {
        return {
            accountId: id,
            async claims() { return { sub: id }; },
        };
    }
});

// no stores configured, all in-memory (dev only)
oidc.initialize({ clients }).then(function () {
    oidcApp.use('/oidc', oidc.callback);
   // oidcApp.listen(3000);
    });

module.exports = oidcApp;