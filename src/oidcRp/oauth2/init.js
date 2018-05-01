let KeyJar = require('../nodeoiDCMsg/src/oicMsg/keystore/keyJar')
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
     * @param {*} caCerts Certificates used to verify HTTPS certificates
     * @param {*} clientAuthnMethod Methods that this client can use to
            authenticate itself. It's a dictionary with method names as
            keys and method classes as values.
     * @param {*} verifySsl Whether the SSL certificate should be verified.
     */
    constructor({stateDb, caCerts, clientAuthnFactory=null, keyJar=null, 
        verifySsl=true, config=null, clientCert = null, httpLib = null, services = null,
        serviceFactory=null, jwksUri=''}){
        this.stateDb = stateDb;
        this.url = '';

        //this.http = httpLib || new HTTPLib(caCerts, verifySsl, clientCert, keyJar);
            
        /**http.createServer(function(request, response){
          response.writeHead(200, {'Content-type':'text/plan'});
          response.write('Hello Node JS Server Response');
          response.end();
        }).listen(7000);**/

        /*var server=httpServer.createServer(function(req,res){
            res.end('{"access_token": "accessTok", "id_token": "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI1VFRLOUpaMFh5Z1p5d0t4UWRqNE5zalAiLCAic3ViIjogIkVuZFVzZXJTdWJqZWN0IiwgImlzcyI6ICJodHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplIiwgImF1ZCI6IFsiZWVlZWVlZWVlIl0sICJpYXQiOiAxNTI0NzY0MDA4LCAiZXhwIjogMTUyNDc2NDMwOH0.R0hFumtBNd9WDEl0yJSOe57gC9C6afDHIO9aYffS2lQ", "token_type": "Bearer", "expires_in": 3600}');
        });
        
        server.on('listening',function(){
            console.log('ok, server is running');
            this.url = 'http://localhost:3000/'
        });
        
        server.listen(3000);*/
        
        /*
        const requestHandler = (request, response) => {
          console.log(request.url)
          this.url = request.url;
          response.end('Hello Node.js Server!')
        }
        
        const server = httpServer.createServer(requestHandler)
        
        server.listen(port, (err) => {
          if (err) {
            return console.log('something bad happened', err)
          }
        
          console.log(`server is listening on ${port}`)
        })
        */

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
      return this.serviceRequest(srv, responseBodyType, state, info);
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
    serviceRequest(service, responseBodyType='', state, params) {
        let body = params.body;
        let headers = params.headers;
        let url = service.endpoint;
        let method = params.method || 'GET';
        if (headers == null) {
            headers = {};
        }
        let resp = null;
        try {
            function callback(response){
                resp = response;
            }
            http.prototype.httpGetAsync(url, callback, {body: body, headers: headers});
        } catch (err) {
            console.log('Exception on request');
        }
        if (params && Object.keys(params).indexOf('keyjar') === -1 && this.service.serviceContext) {
            params['keyjar'] = this.service.serviceContext.keyJar;
        }
        if (!responseBodyType) {
            responseBodyType = service.responseBodyType;
        }

        let response = this.parseRequestResponse(service, resp, responseBodyType, state, params);

        if (response && !response.isErrorMessage()){
            service.updateServiceContext(response, params);
        }
        return response;
    }

    /**
     * Deal with a request response
     * @param {string} reqresp The HTTP request response
     * @param {ClientInfo} clientInfo Information about the client/server session
     * @param {string} responseBodyType If response in body one of 'json', 'jwt' or
     *      'urlencoded'
     * @param {State} state Session identifier
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
                return service.parseResponse(reqresp.responseText, valueType, state, params);
            }catch(err){
                console.log(err)
            }
        }else if (reqresp && statusCodeArr.indexOf(reqresp.status) !== -1) {
                return reqresp;
        } else if (reqresp && reqresp.status === 500) {
            console.log('Something went wrong');
        } else if (reqresp && 400 <= reqresp.status < 500) {
            let deserMethod = util.prototype.getDeserializationMethod(reqResp);
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