const express = require('express');
const Provider = require('oidc-provider');

const oidcApp = express();

const clients = [
    // token id_token code
    {client_id: 'test_oidcdebugger_com_token_id_token_code',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token id_token code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // token code
    {client_id: 'test_oidcdebugger_com_token_code',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['token code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // code id_token 
    {client_id: 'test_oidcdebugger_com_code_id_token',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['code id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'}, 
    // token id_token
    {client_id: 'test_oidcdebugger_com_token_id_token',
    grant_types: ['implicit'],
    response_types: ['token id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // code
    {client_id: 'test_oidcdebugger_com_code',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // token
    {client_id: 'test_oidcdebugger_com_token',
    grant_types: ['implicit'],
    response_types: ['token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    // id_token
    {client_id: 'test_oidcdebugger_com_id_token',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://oidcdebugger.com/debug'],
    token_endpoint_auth_method: 'none'},
    
    {
    client_id: 'test_oauth_app',
    client_secret: 'super_secret',
    grant_types: ['client_credentials'],
    redirect_uris: [],
    response_types: [],
}];

const oidc = new Provider('http://auth-openses.westeurope.azurecontainer.io:3000', {
// const oidc = new Provider('http://localhost:3000', {
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