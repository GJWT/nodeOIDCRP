let KeyJar = require('../nodeOIDCService/src/OIDCClient/nodeOIDCMsg/src/oicMsg/keystore/keyJar').KeyJar;
const ServiceContext = require('../../oidcRp/nodeOIDCService/src/OIDCClient/src/serviceContext.js').ServiceContext;
const caFactory = require('../nodeOIDCService/src/OIDCClient/src/clientAuth/privateKeyJWT').clientAuthFactory;
let service = require('../nodeOIDCService/src/OIDCClient/src/oauth2/service/service');
let buildServices = require('../nodeOIDCService/src/OIDCClient/src/service').buildServices;
let http = require('../http').HttpRequest;
let util = require('../util').Util;
let httpServer = require('http');
const port = 3000

const DEFAULT_SERVICES = {'Authorization' : {}, 'AccessToken': {}, 'RefreshAccessToken': {}, 'ProviderInfoDiscovery': {}};

const SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

const SPECIAL_ARGS = ['authn_endpoint', 'algs']

const REQUEST_INFO = 'Doing request with: URL:{}, method:{}, data:{}, https_args:{}'

/**
 * Client
 * @class
 * @constructor
 */
class Client {
    /**
     * @param {Object} caCerts Certificates used to verify HTTPS certificates
     * @param {function} clientAuthnFactory Methods that this client can use to
     *       authenticate itself. It's a dictionary with method names as
     *       keys and method classes as values.
     * @param {KeyJar} keyjar A KeyJar class instance
     * @param {bool} verifySsl Whether the SSL certificate should be verified.
     * @param {Object<string, string>} config Configuration information passed on to the 
     * ServiceContext initialization
     * @param {Object} clientCert Certificate used by the HTTP client
     * @param {HttpLib} httpLib A HTTP client to use 
     * @param {Array<string>} services A list of service definitions
     * @param {function} serviceFactory A factory to use when building the Service instances
     * @param {string} jwksUri A jwksUri
     * @return Client instance
     */
    constructor({stateDb, caCerts, clientAuthnFactory=null, keyJar=null, 
        verifySsl=true, config=null, clientCert = null, httpLib = null, services = null,
        serviceFactory=null, jwksUri=''}){
        this.stateDb = stateDb;
        this.url = '';

      if (!keyJar) {
        let keyJar = new KeyJar();
      }
      
      verifySsl = verifySsl || true;
      
      this.events = null;
      this.serviceContext = new ServiceContext(keyJar, config, jwksUri);

      if (this.serviceContext.clientId){
          this.clientId = this.serviceContext.clientId;
      }

      let cam = clientAuthnFactory || caFactory;
      this.serviceFactory = serviceFactory || service.Factory;
      let _srvs = services || DEFAULT_SERVICES;

      this.service = buildServices(_srvs, this.serviceFactory, this.serviceContext, stateDb, cam);

      this.serviceContext.service = this.service;

      this.verifySsl = verifySsl;
    }
  
    construct(requestType, requestArgs=null, extraArgs=null, params) {
      try {
        this.service[requestType];
      } catch (err) {
        console.log(err);
      }
      let met = this['construct_' + requestType + '_request'];
      return met(this.serviceContext, requestArgs, extraArgs, params);
    }

    doRequest(
        requestType, responseBodyType='', requestArgs=null, params) {
            
      let srv = this.service[requestType];
      
      let info = srv.getRequestParameters({requestArgs: requestArgs, params: params});
      
      if (!responseBodyType) {
        responseBodyType = srv.responseBodyType;
      }
      
      let state = null;
      try{
          state = params['state'];
      }catch(err){
          state = '';
      }
      return this.serviceRequest(srv, responseBodyType, state, info, params.response);
    }
    
    setClientId(clientId) {
      this.clientId = clientId;
      this.clientInfo.clientId = clientId;
    }

    /**
    * The method that sends the request and handles the response returned.
    * This assumes a synchronous request-response exchange.
    * @param {string} reqresp The HTTP request response
    * @param {string} responseBodyType If response in body one of 'json', 'jwt' or
    *      'urlencoded'
    * @param {State} state Session identifier
    * @return Returns a request response
    */
    serviceRequest(service, responseBodyType='', state, params, resp) {
        let body = params.body;
        let headers = params.headers;
        let url = service.endpoint;
        let method = params.method || 'GET';
        if (headers == null) {
            headers = {};
        }
        
        /*
        try {
            function callback(response){
                resp = response;
            }
            http.prototype.httpGetAsync(url, callback, {body: body, headers: headers});
        } catch (err) {
            console.log('Exception on request');
        }*/
        if (params && Object.keys(params).indexOf('keyjar') === -1 && this.service.serviceContext) {
            params['keyjar'] = this.service.serviceContext.keyJar;
        }
        if (!responseBodyType) {
            responseBodyType = service.responseBodyType;
        }
        
        let response = this.parseRequestResponse(service, resp, responseBodyType, state, params);
        
        if (response && !response.isErrorMessage()){
           response.verify();
           service.updateServiceContext(response, state, params); 
        }
        return response;
    }

    /**
     * Deal with a request response. The response are expected to follow a special pattern, having the 
     * attributes : 
     *      - headers (list of tuples with headers attributes and their values)
     *      - status_code (integer)
     *      - text (The text version of the response)
     *      - url (The calling URL)
     * @param {Service} service A Service instance
     * @param {string} reqresp The HTTP request response
     * @param {string} responseBodyType If response in body one of 'json', 'jwt' or
     *      'urlencoded'
     * @param {State} state Session identifier 
     * @param {Object<string, string>} params Other attributes that might be needed
     * @return response type such as an ErrorResponse 
     */
    parseRequestResponse(service, reqresp, responseBodyType='', state='', params) {
        let statusCodeArr = [302, 303];
        if (reqresp && SUCCESSFUL.indexOf(reqresp.status) !== -1) {
            let deserMethod = util.prototype.getDeserializationMethod(reqresp);
            if (deserMethod !== responseBodyType){
                console.log('Not the body type I expected');
            }
            let methods = ['json', 'jwt', 'urlencoded'];
            let valueType = 'json';
            if (methods.indexOf(deserMethod) !== -1){
                valueType = deserMethod;
            }else{
                valueType = responseBodyType;
            }
            try{
                return service.parseResponse(reqresp.text, valueType, state, params);
            }catch(err){
                console.log(err)
            }
        }else if (reqresp && statusCodeArr.indexOf(reqresp.status) !== -1) {
                return reqresp;
        } else if (reqresp && reqresp.status === 500) {
            console.log('Something went wrong');
        } else if (reqresp && 400 <= reqresp.status < 500) {
            let deserMethod = util.prototype.getDeserializationMethod(reqresp);
            if (!deserMethod){
                deserMethod = 'json';
            }
            try{
                errResp = service.parseResponse(reqresp.text, _deser_method);
            }catch(err){
                if (deserMethod !== responseBodyType){
                    try{
                        errResp = service.parseResponse(reqresp.text, responseBodyType);
                    }catch(err){
                        console.log('HTTP ERROR');
                    }
                }else{
                    console.log('HTTP ERROR');
                }
            }
            return errResp;
        } else {
            console.log('Error response');
        }
    }
  
    getDefaultServices() {
      return DEFAULT_SERVICES;
    }
  }

  module.exports.Client = Client;