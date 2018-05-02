const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const OIDC = require('./oic/init');
const StateInterface = require('./nodeOIDCService/SRC/OIDCClient/src/state').StateInterface;
const addPath = require('./nodeOIDCService/SRC/OIDCClient/src/util').addPath;
const oauth2 = require('./nodeOIDCService/src/OIDCClient/src/oauth2/service/service');
const oidc = require('./nodeOIDCService/src/OIDCClient/src/oic/service/service');
const crypto = require('crypto');
const adapter = new FileSync('clientsDb.json');
const CLIENT_AUTHN_METHOD = require('./nodeOIDCService/src/OIDCClient/src/clientAuth/privateKeyJWT').CLIENT_AUTHN_METHOD;
const db = low(adapter);
const all = require('./provider/init').all;
const linkedInProviders = require('./provider/linkedin');
const githubProviders = require('./provider/github');
const AuthorizationResponse = require('./nodeOIDCMsg/src/oicMsg/oic/responses').AuthorizationResponse;
const AuthorizationRequest = require('./nodeOIDCMsg/src/oicMsg/oic/requests').AuthorizationRequest;
const OpenIDSchema = require('./nodeOIDCMsg/src/oicMsg/oic/init').OpenIDSchema

db.defaults({posts: [], user: {}, count: 0}).write();

let SERVICE_NAME = "OIC";
let CLIENT_CONFIG = {};

/**
 * @fileoverview
 * RPHandler
 * Implements a service within the web service that handles user authentication 
 * and access authorization on behalf of the web service.
 */

 /**
  * InMemoryStateDataBase
  * @class
  * @constructor
  */
class InMemoryStateDataBase{
    constructor(){
        this.db = {};
    }

    set(key, value){
        this.db[key] = value;
    }

    get(key){
        try{
            return this.db[key];
        }catch(err){
            return null;
        }
    }
}

/**
 * Get a class instance of a Service subclass specific to a specified service provider.
 * @param {string} serviceProvider The name of the service provider
 * @param {string} service The name of the service
 * @param {Object<string, string>} params Arguments provided when initiating the class
 * @return An initiated subclass of Service or None if the service or the service provider could 
 * not be found.
 */
function getProviderSpecificService(serviceProvider, service, params){
    let cls = null
    if (all.indexOf(serviceProvider)!== -1){
        if (serviceProvider == 'linkedin'){
            cls = linkedInProviders[service];
        }else{
            cls = githubProviders[service];
        }
        return new cls(params);
    }
    return cls;
}

/**
 * A factory which given a service name will return a Service instance if a service matching the 
 * name could be found. 
 * @param {string} serviceName Could be either of the format group.name or name
 * @param {ServiceContext} serviceContext A ServiceContext instance 
 * @param {DB} stateDb DB class instance
 * @param {string} clientAuthnMethod One of the six client authentication methods : bearer_body, bearer_header, client_secret_basic, 
   * client_secret_jwt, client_secret_post, private_key_jwt 
 * @param {Object<string, string>} serviceConfiguration Client configuration that contains information such as client Metadata
 */
function factory(serviceName, serviceContext, stateDb, clientAuthnMethod, serviceConfiguration) {
    if (serviceName.indexOf('.') !== -1){
        let pair = serviceName.split('.');
        let group = pair[0];
        let name = pair[1];
        if (group == 'oauth2'){
            oauth2.factory(serviceName[1], serviceContext, stateDb, clientAuthnMethod, serviceConfiguration);
        }else if (group == 'oidc'){
            oidc.OicFactory(serviceName[1], serviceContext, stateDb, clientAuthnMethod, serviceConfiguration);
        }else{
            return getProviderSpecificService(group, name, {serviceContext: serviceContext, stateDb: stateDb, clientAuthnMethod: clientAuthnMethod, conf: serviceConfiguration});
        }
    }else{
        return oidc.OicFactory(serviceName, serviceContext, stateDb, clientAuthnMethod, serviceConfiguration);
    }
}

/**
 * RPHandler
 * @class
 * @constructor
 */
class RPHandler{
    /**
     * @param {string} baseUrl There are several places in the code where urls are dynamically built. What normally happens when creating this new url, is that a path is added to baseUrl.
     * @param {int} hasSeed Used when dynamically creating redirect_uris. Just to make it imposible for outsiders to guess what redirect_uris would be created for which OPs/ASs. Look at create_callbacks()
     * @param {KeyJar} keyJar A keyjar instance
     * @param {bool} verifySsl Whether the SSL certificate should be verified
     * @param {Array<string>} services A list of service definitions
     * @param {function} serviceFactory A factory to use when building the service instances
     * @param {Object<string, string>} clientConfigs Configuration information passed on to the Service context initialization
     * @param {string} clientAuthnMethod Methods that this client can use to authenticate itself. Its a dictionary with method names as keys and method classes as values.
     * @param {Array<string>} clientCls Certificates used by the HTTP client
     */
    constructor({baseUrl='', hashSeed="", keyJar=null, verifySsl=true,
    services=null, serviceFactory=null, clientConfigs=null,
    clientAuthnMethod=CLIENT_AUTHN_METHOD, clientCls=null, stateDb=null, params}){
        this.baseUrl = baseUrl;
        this.hashSeed = hashSeed;
        this.verifySsl = verifySsl;
        this.keyJar = keyJar; 

        if (stateDb){
            this.stateDb = stateDb;
        }else{
            this.stateDb = new InMemoryStateDataBase();
        }

        this.sessionInterface = new StateInterface(this.stateDb);
        if (params){
            this.jwksUri = addPath(baseUrl, params['jwks_path']);
        }

        this.extra = params;
        this.clientCls = clientCls || OIDC.RP;
        this.services = services;
        this.serviceFactory = serviceFactory || factory;
        this.clientAuthnMethod = clientAuthnMethod;
        this.clientConfigs = clientConfigs;

        this.issuer2rp = {};
        this.hash2issuer =  {};
    };

    /**
     * WebFinger is only used when you don't know which OP/AS to talk to until
     * a user gives you some information you can base a search on.
     * 
     * @return True if WebFinger is among the services supported.
     */
    supportsWebfinger(){
        let _cnf = this.pickConfig('');
        if (Object.keys(_cnf['services']).indexOf('WebFinger') !== -1){
            return true;
        }else{
            return false;
        }
    }

    /**
     * Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.
     * @param {State} state The state value
     * @return An issuer id
     */
    state2Issuer(state){
        return this.sessionInterface.getIss(state);
    }

    /**
     * From the set of client configurations pick one based on the issuer ID.
     * Will raise a KeyError if issuer is unknown.
     * @param {string} issuer Issuer ID
     * @return A client configuration
     */
    pickConfig(issuer){
        return this.clientConfigs[issuer];
    }

    /**
     *  This is the second of the methods users of this class should know about.
     * It will return the complete session information as an State instance
     * @param {*} key The session key (state)
     * @return A state instance
     */
    getSessionInformation(key){
        return this.sessionInterface.getState(key);
    }

    /**
     * Initiate a Client instance. Specifically which client class is used is decided by configuration.
     * @param {string} issuer An issuer id
     * @return A client instance
     */
    initClient(issuer){
        let _cnf = this.pickConfig(issuer);
        let _services = null;
        if (_cnf['services']){
            _services = _cnf['services'];
        }else{
            _services = this.services;
        }
        let client = null
        try{
            client = new this.clientCls({stateDb:this.stateDb, clientAuthnMethod:this.clientAuthnMethod, verifySsl:this.verifySsl, services:_services, serviceFactory:this.serviceFactory, config:_cnf});
        }catch(err){
            console.log(err);
        }
        client.serviceContext.baseUrl = this.baseUrl;
        return client;
    }

    /**
     * If the client has been  statically registered that information must
     * be provided during the configuration. If expected to be done 
     * dynamically, this method will do dynamic client registration.
     * @param {Client} client OIC Client instance
     */
    loadRegistrationResponse(client){
        let clientReg = null;
        if (client.serviceContext.config['registration_response']){
            let clientReg = client.serviceContext.config['registration_response'];
        }else{
            try{
                let response = client.doRequest('registration');
                if (response.isErrorMessage()){
                    throw new JSError(response['error'], OIDCServiceError);
                }
                client.serviceContext.registrationInfo = clientReg;
            }catch(err){
                console.log('No registration info');
            }
        }
    }

    /**
     * To mitigate some security issues the redirect_uris should be OP/AS specific. 
     * This method creates a set of redirect_uris unique to the OP/AS.
     * @param {string} issuer Issuer ID
     * @return A set of redirect_uris
     */
    createCallbacks(issuer){
        var hmac = crypto.createHmac('sha256', '');
        hmac.update(this.hashSeed);
        hmac.update(issuer);
        let hex = hmac.digest('hex');
        this.hash2issuer[hex] = issuer;
        return {'code':this.baseUrl+ '/authz_cb/' + hex, 
                'implicit': this.baseUrl + '/authz_im_cb/' + hex,
                'form_post': this.baseUrl + '/authz_fp_cb/' + hex
            };
    }

    registerClient(client=null, stateKey=''){
        if (!client){
            if (stateKey){
                client = this.getClientFromSessionKey(stateKey);
            }else{
                console.log()
            }
        }

        let callbacks = null;
        let iss = client.serviceContext.issuer;
        if (!client.serviceContext.redirectUris){
            callbacks = this.createCallbacks(iss);
            client.serviceContext.redirectUris = callbacks;
            client.serviceContext.callbacks = callbacks;
        }else{
            this.hash2issuer[iss] = iss;
        }

        try{
            client.serviceCOntext.postLogoutRedirectUris;
        }catch(err){
            client.serviceContext.postLogoutRedirectUris = [this.baseUrl];
        }

        if (!client.serviceContext.clientId){
            this.loadRegistrationResponse(client);
        }
    }

    /**
     * Given the response returned to the redirect_uri, parse and verify it.
     * @param {Client} client A client instance
     * @param {string} issuer An issuer ID
     * @param {AuthorizationResponse} response The authorization response as a dictionary
     * @return An auth2 or OIC authorizationResponse instance
     */
    finalizeAuth(client, issuer, response){
        let authorizationResponse = null
        let srv = client.service['authorization'];
        try{
            authorizationResponse = srv.parseResponse(response, 'dict');
        }catch(err){
            console.log(err);
        }

        if (authorizationResponse.isErrorMessage()){
            return authorizationResponse;
        }
        let iss = '';

        try{
            iss = this.sessionInterface.getIssuer(authorizationResponse.claims['state']);
        }catch(err){
            console.log(err);
        }

        if (iss !== issuer){
            console.log('Issuer problem', iss);
        }

        srv.updateServiceContext(authorizationResponse, authorizationResponse.claims['state']);
        return authorizationResponse;
    }

    clientSetUp(issuer='', user=''){
        let temporaryClient = null;
        if (!issuer){
            if (!user){
                console.log('Need issuer or user');
            }

            temporaryClient = this.initClient('');
            temporaryClient.doRequest('webfinger', user);
            issuer = temporaryClient.serviceContext.issuer;
        }else{
            temporaryClient = null;
        }

        let client = null;

        if (this.issuer2rp[issuer]){
            client = this.issuer2rp[issuer];
            return client;
        }else{
            if (temporaryClient){
                client = temporaryClient;
            }else{
                client = this.initClient(issuer);
            }
        }

        issuer = this.doProviderInfo(client);
        this.registerClient(client);
        this.issuer2rp[issuer] = client;
        return client;
    }

    /**
     * Constructs the URL that will redirect the user to the authorization
     * endpoint of the OP/AS.
     * @param {Client} client A client instance
     * @param {string} stateKey The key corresponding to a state
     * @param {Object<string, string>} reqArgs Non default request arguments
     * @return A dictionary with 2 keys : url - The authorization redirect URL and 
     * state key - the key to the session information in the state data store.
     */
    initAuthorization(client=null, stateKey='', reqArgs=null){
        if (!client){
            if (stateKey){
                client = this.getClientFromSessionKey(stateKey);
            }else{
                // throw new JSError('Missing state/session key', ValueError);
                console.log('Missing state/session key');
            }
        }

        let serviceContext = client.serviceContext;

        let nonce = Math.random();
        let requestArgs = {
            'redirect_uri': serviceContext.redirectUris[0],
            'scope': serviceContext.behavior['scope'],
            'response_type': serviceContext.behavior['response_types'][0],
            'nonce': nonce
        }

        if (reqArgs){
            requestArgs = Object.assign(requestArgs, reqArgs);
        }

        let state = this.sessionInterface.createState(serviceContext.issuer);
        requestArgs['state'] = state;
        this.sessionInterface.storeNonce2State(nonce, state);

        let srv = client.service['authorization'];
        let info = srv.getRequestParameters({requestArgs:requestArgs});
        return {'url': info['url'], 'state_key':state};
    }

    /**
     * If the providerInfo is statically provided not much has to be done. 
     * If its expected to be gotten dynamically Provider Info discovery 
     * has to be performed.
     * @param {Client} client OIC Client instance 
     * @param {string} issuer Issuer
     */
    loadProviderInfo(client, issuer){
    }

    /**
     * This is about performing dynamic Provider Info discovery
     * @param {Client} client Client instance
     */
    dynamicProviderInfoDiscovery(client){
        try{
            client.service['provider_info'];
            try{
                client.serviceContext.issuer = client.serviceContext.config['srv_discovery_url'];
            }catch(err){
                console.log(err);
            }
            let response = client.doRequest('provider_info');
            if (response.isErrorMessage()){
                throw new JSError(response['error'], OIDCServiceError);
            }
        }catch(err){
            console.log('Cannot do dynamic provider info discovery');
        }
    }

    /**
     * Fetch the client based on the issuer,services fetched from the 
     * config, etc..
     * @param {*} issuer 
     * @return Client
     */
    getClient(issuer){
    }

    /**
     * Either get the provider info from configuration or from dynamic 
     * discovery by calling loadProviderInfo and updates endpoint
     * @param {Client} client OIC client instance
     * @param {string} issuer 
     * @return Issuer 
     */
    doProviderInfo(client, issuer){
        if (!client){
            if (stateKey){
                client = this.getClientFromSessionKey(stateKey);
            }else{
                //throw JSError('Missing state/session key', ValueError);
                console.log('Missing state/session key');
            }
        }

        let _pi = null;
        if (!client.serviceContext.provider_info){
            dynamicProviderInfoDiscovery(client);
            return client.serviceContext.providerInfo['issuer'];
        }else{
            _pi = client.serviceContext.provider_info;
            let endpoints = ['authorizationEndpoint', 'token_endpoint',
            'userinfo_endpoint'];
            for (var i = 0; i < endpoints.length; i++){
                let endp = endpoints[i];
                if (Object.keys(_pi).indexOf(endp) !== -1){
                    let length = Object.keys(client.service).length;
                    for (var i = 0; i < length; i++){
                        let key = Object.keys(client.service)[i];
                        let srv = client.service[key];
                        if (srv.endpointName == endp){
                            srv.endpoint = _pi[endp];
                        }
                    }
                }
            }
           if (client.serviceContext.provider_info['issuer']){
                return client.serviceContext.provider_info['issuer'];
            }else{
                return client.serviceContext.issuer;
            }
        }
    }



    /**
     * Prepare for and do client registration if configured to do or so 
     * by calling loadRegistration and checks for redirectUris
     * @param {Client} client Client instance
     * @param {string} issuer The issuer ID
     */
    doClientInfo(client, issuer){
    }

    /**
     * Prepare for and do client registration if configured to do or so 
     * by calling loadRegistration and checks for redirectUris
     * @param {string} issuer The issuer ID.
     * @return Client instance
     */
    setUp(issuer){
    }

    /**
     * Fetches the response type a specific client wants to use
     * @param {Client} client A client instance
     * @return The response type
     */
    getResponseType(client, issuer){
        return client.serviceContext.behavior['response_types'][0];
    }

    /**
     * Return the client authentication method a client wants to use a specific endpoint
     * @param {Client} client A client instance
     * @param {string} endpoint The endpoint at which the client has to authenticate 
     * @return The client authentication method
     */
    getClientAuthnMethod(client, endpoint){
        if (endpoint == 'token_endpoint'){
            try{
                let am = client.serviceContext.behavior['token_endpoint_auth_method'];
                if (typeof am == 'string'){
                    return am;
                }else{
                    return am[0];
                }
            }catch(err){
                return ''
            }
        }
    }

    /**
     * This is the first of the three high level mthods that most users of this library should
     * confine themselves to use. If will use client_setup to product a Client instance ready
     * to be used against the OP/AS the user wants to use. Once it has the client it will 
     * construct an Authorization Request.
     * @param {string} issuer Issuer ID
     * @param {string} userId A user identifier
     * @return A dictionary containing url the URL that will redirect the user to 
     * the OP/AS and state key, thes session key will allow higher level code to access
     * session information. 
     */
    begin(issuerId='', userId=''){
        let client = this.clientSetUp(issuerId, userId);
        try{
            let res = this.initAuthorization(client);
            return res;
        }catch(err){
            console.log(err);
        }
    }

    /**
     * Use the 'accesstoken' service to get an access token from the OP/AS.
     * @param {string} state_key The state key (the state parameter in the authorization request)
     * @param {Client} client A client instance
     * @return An AccessTokenResponse or AuthorizationResponse
     */
    getAccessToken(stateKey, client){
        if (!client){
            client = this.getClientFromSessionKey(stateKey);
        }

        let authorizationResponse = this.sessionInterface.getItem(AuthorizationResponse, 'auth_response', stateKey);
        let authorizationRequest = this.sessionInterface.getItem(AuthorizationRequest, 'auth_request', stateKey);

        let reqArgs = {
            'code': authorizationResponse.claims['code'],
            'state': stateKey,
            'redirect_uri': authorizationRequest.claims['redirect_uri'],
            'grant_type': 'authorization_code',
            'client_id': client.serviceContext.client_id,
            'client_secret': client.serviceContext.client_secret
        }

        //try{
                                              
            let tokenResp = client.doRequest('accessToken', null, reqArgs, {authnMethod:this.getClientAuthnMethod(client, 'token_endpoint'), state:stateKey});
            if (tokenResp && tokenResp.isErrorMessage()){
                throw new JSError('OIDCServiceError', tokenResp['error']);
            }
            return tokenResp;
        /*}catch(err){
            console.log(err);
        }*/
    }

    /**
     * Refresh an access token using a refresh token. When asking for a new access token the RP
     * can ask for another scope for the new token. 
     * @param {string} stateKey The state key (the state parameter in the authorization request)
     * @param {Client} client A client instance
     * @param {string} scope What the returned token should be valid for.
     * @return An AccessTokenResponse instance
     */
    refreshAccessToken(stateKey, client=null, scope=''){
        let reqArgs = {};
        if (scope){
            reqArgs = {'scope': scope};
        }
        
        if (!client){
            client = this.getClientFromSessionKey(stateKey);
        }

        try{
            let tokenResp = client.doRequest('refresh_token', this.getClientAuthnMethod(client, 'token_endpoint'), reqArgs, stateKey);
            if (tokenResp.isErrorMessage()){
                console.log(err);
            }
            return tokenResp;
        }catch(err){
            console.log(err);
        }
    }

    /**
     * Use the access token previously acquired to get some user info
     * @param {string} stateKey The state value, this is the key into the session data store
     * @param {Client} client A client instance
     * @param {string} accessToken An access token
     * @param {Object<string, string>} params Other attributes that might be necessary
     * @return An OpenIdSchema song instance
     */
    getUserInfo(stateKey, client=null, access_token='', params){
        if (!access_token){
            this.sessionInterface.multipleExtendRequestArgs({}, stateKey, ['access_token'], ['auth_response', 'token_response', 'refresh_token_response']);
        }
        let requestArgs = {'access_token': access_token};
        if (!client){
            client = this.getClientFromSessionKey(stateKey);
        }
        if (!params){
            params = {};
        }
        params = Object.assign(params, {state: stateKey});
        let resp = client.doRequest('userinfo', 'json', requestArgs, params);

        if (resp.isErrorMessage()){
            throw new JSError(resp['error'], OIDCServiceError);
        }
        return resp;
    }

    /**
     * Given an verified id token return all claims that may been user information
     * @param {BasicIdToken} idToken An IDToken instance
     * @return A dictionary with user information
     */
    userInfoInIdToken(idToken){
        let dict = {}; 
        let openIdSchema = new OpenIDSchema();    
        for (var i = 0; i < Object.keys(openIdSchema.cParam).length; i++){
            let k = Object.keys(openIdSchema.cParam)[i];
            if (Object.keys(idToken.claims).indexOf(k) !== -1){
                dict[k] = idToken.claims[k]
                //dict = Object.assign(dict, idToken.claims);
            }
        }
        return dict;
    }

    /**
     * There are a number of services where access tokens and ID Tokens can occur in the response. 
     * This method goes through the possiblee places based on the response type the client uses.
     * @param {AuthorizationResponse} authorizationResponse The authorization response
     * @param {string} stateKey The state key (the state parameter in the authorization request)
     * @param {Client} client Client instance
     * @return A dictionary with 2 keys: access token with the access token as value and id token 
     * with a verified id token if one was returned otherwise none.
     */
    getAccessAndIdToken(authorizationResponse=null, stateKey='', client=null){
        if (authorizationResponse == null){
            if (stateKey){
                authorizationResponse = this.sessionInterface.getItem(AuthorizationResponse, 'auth_response', stateKey);
            }else{
                console.log('One of authorization respone or state must be provided');
            }
        }

        if (!stateKey){
            stateKey = authorizationResponse.claims['state'];
        }

        let authReq = this.sessionInterface.getItem(AuthorizationRequest, 'auth_request', stateKey);
        let respType = [authReq.claims['response_type']];

        let accessToken = null;
        let idToken = null;
        let respTypes = [['id_token'], ['id_token', 'token'],
        ['code', 'id_token', 'token']];
        if (respTypes.indexOf(respType) !== -1){
            idToken = authorizationResponse['verified_id_token'];
        }
        respTypes =[['token'], ['id_token', 'token'], ['code', 'token'],
        ['code', 'id_token', 'token']];

        let respTypes2 = [['code'], ['code', 'id_token']];
        
        let inRespType = false;
        for (var i = 0; i < respTypes.length; i++){
            var currType = respTypes[i];
            if (currType.toString() === respType.toString()){
                accessToken = authorizationResponse.claims['access_token'];
                inRespType = true;
            }
        }

        if (! inRespType){
            for (var i = 0; i < respTypes2.length; i++){
                let currType2 = respTypes2[i];
                if (currType2.toString() === respType.toString()){
                    if (!client){
                        let client = this.getClientFromSessionKey(stateKey);
                    }
        
                    let tokenResp = this.getAccessToken(stateKey, client);
                    if (tokenResp && tokenResp.isErrorMessage()){
                        return false;
                    }
                    try{
                        accessToken = tokenResp.claims['access_token'];                        
                        idToken = tokenResp.claims['verified_id_token'];
                    }catch(err){
                        return;
                    }
                }
            }
        }
        return {'access_token': accessToken, 'id_token': idToken};
    }

    /**
     * The third of the high level methods that a user of this class should know about.
     * Once the consumer has redirected the user back to the callback url there might be a number
     * of services that hte client should use. Which one those are defined by the client configuration.
     * @param {string} issuer Who sent the response
     * @param {Object<string, string>} response A dictionary with two claims: 
     *      stateKey - the key under which the session information is stored in the data store and 
     *      error - encountered error or 
     *      userinfo - the collected user information
     */
    finalize(issuer, response){
        let client = this.issuer2rp[issuer];

        authorizationResponse = this.finalizeAuth(client, issuer, response);
        if (authorizationResponse.isErrorMessage()){
            return {'state_key': authorizationResponse['state'], 'error': authorizationResponse['error']};
        }

        let state = authorizationResponse['state'];
        let token = this.getAccessAndIdToken(authorizationResponse, state, client);

        if (Object.keys(client.service).indexOf('userinfo') !== -1 && token['access_token']){
            let infoResp = this.getUserInfo(authorizationResponse['state'], client, token['access_token']);
            if (typeof resp == ResponseMessage){
                return {
                    'error': "Invalid response %s." % infoResp["error"],
                    'state_key': state};
            }
        }else if (token['id_token']){
            infoResp = this.userInfoInIdToken(token['id_token']);
        }else{
            infoResp = {};
        }

        return {'userinfo': inforesp,
        'state_key': authorizationResponse['state']};
    }
}

module.exports.RPHandler = RPHandler;
module.exports.factory = factory;