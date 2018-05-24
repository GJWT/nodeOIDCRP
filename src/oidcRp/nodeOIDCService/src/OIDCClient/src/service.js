const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const ErrorResponse = require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').ErrorResponse;
const HttpLib = require('./http');
const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init.js').AuthorizationResponse;
const util = require('./util').Util;
const urlParse = require('url-parse');
const Util = require('./util').Util;
const StateInterface = require('./state').StateInterface;
const URINormalizer = require('./webFinger/uriNormalizer').URINormalizer;
const URL_ENCODED = require('./util').URL_ENCODED;
const JSON_ENCODED = require('./util').JSON_ENCODED;
const getHttpBody = require('./util').getHttpBody;
//const caFactory = require('../src/clientAuth/clientAuth').ClientAuthnMethod;
const caFactory = require('../src/clientAuth/privateKeyJWT').clientAuthFactory;

/**
 * @fileoverview Method call structure for Services
 * do_request_init
 *  - request_info
 *  - construct
 *      - pre_construct (*)
 *      - parse_args
 *      - post_construct (*)
 *  - init_authentication_method
 *  - uri_and_body
 *      - _endpoint
 *  - update_http_args
 *
 * service_request
 *   - parse_request_response
 *      - parse_response
 *         - get_urlinfo
 *              - post_parse_response (*)
 *      - parse_error_mesg
 *
 * The methods marked with (*) are where service specific
 * behaviour is implemented.
 */

let SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206];
let SPECIAL_ARGS = ['authn_endpoint', 'algs'];
let REQUEST_INFO =
    'Doing request with: URL:{}, method:{}, data:{}, https_args:{}';
let rt2gt = {
  'code': ['authorization_code'],
  'id_token': ['implicit'],
  'id_token token': ['implicit'],
  'code id_token': ['authorization_code', 'implicit'],
  'code token': ['authorization_code', 'implicit'],
  'code id_token token': ['authorization_code', 'implicit']
};

/**
 * Service
 * @class
 * @constructor
 */
class Service extends StateInterface{
  /**
   * 
   * @param {ServiceContext} serviceContext Contains information that a client needs to be able to talk to a server
   * @param {DB} stateDb DB class instance
   * @param {string} clientAuthnMethod One of the six client authentication methods : bearer_body, bearer_header, client_secret_basic, client_secret_jwt, client_secret_post, private_key_jwt 
   * @param {Object.<string, string>} conf Client configuration that contains information such as client Metadata
   */
  constructor(serviceContext, stateDb, clientAuthnMethod, conf) {
    super(stateDb);
    if (stateDb){
      this.stateDb = stateDb;
    }
    /** 
     * The message subclass that describes the request. Default is Message 
     * @type {Message} 
     */ 
    this.msgType = Message;

    /** 
     * The message subclass that describes the response. Default is Message 
     * @type {Message}
     */
    this.responseCls = Message;

    /** The message subclass that describes an error response. Default is oauth2 ErrorResponse
     * @type {ErrorResponse}
     */
    this.errorMsg = ErrorResponse;

    /** The name of the endpoint on the server that the request should be sent to. No default 
     * @type {string}
     */
    this.endpointName = '';

    /** 
     * True if the response will be returned as a direct response to the request. The only exception 
     * right now to this is the Authorization request where the response is delivered to the client 
     * at some later date. Default is True 
     * @type {bool}
     */
    this.synchronous = true;

    /** 
     * A name of the service. Later when a RP/client is implemented instances of different services are found by using this name. No default 
     * @type {string}
     */
    this.request = '';

    /** 
     * The client authentication method to use if nothing else is specified. Default is ‘’ which means none. 
     * @type {string}
     */
    this.defaultAuthMethod = '';

    /** Which HTTP method to use when sending the request. Default is GET 
     * @type {string}
     */
    this.httpMethod = 'GET';

    /** The serialization method to be used for the request Default is urlencoded 
     * @type {string}
     */
    this.bodyType = 'urlEncoded';

    /** The deserialization method to use on the response Default is json 
     * @type {string}
     */
    this.responseBodyType = 'json';

    this.serviceContext = serviceContext;
    this.events = null;
    this.endpoint = '';
    this.defaultRequestArgs = {};

    this.clientAuthMethod = clientAuthnMethod || caFactory;

    if (conf){
      this.conf = conf;
      let params = ['msg_type', 'response_cls', 'error_msg',
      'default_authn_method', 'http_method', 'body_type',
      'response_body_type'];
      for (var i = 0; i < params; i++){
        let param = list[i];
        this[param] = conf[param];
      }
    } else {
      this.conf = {};
    }

    // pull in all the modifiers
    this.preConstruct = [];
    this.postConstruct = [];
}

  /**
   * Go through the attributes that the message class can contain and
   * add values if they are missing and exists in the client info or
   * when there are default values.
   *
   * @param {serviceContext} serviceContext Client info
   * @return Object<string, Object> 
   */

  parseArgs(serviceContext, params) {
    let arArgs = params;
    let self = this;
    for (let i = 0; i < Object.keys(this.msgType.cParam).length;
         i++) {
      let prop = Object.keys(this.msgType.cParam)[i];
      if (Object.keys(arArgs).indexOf(prop) !== -1) {
        continue;
      } else {
        if (serviceContext[prop]) {
          arArgs[prop] = serviceContext[prop];
        } else if (this.defaultRequestArgs[prop]) {
          arArgs[prop] = this.defaultRequestArgs[prop];
        }
      }
    }
    return arArgs;
  }

  /**
   * Will run the pre_construct methods one at the time in order. Updates 
   * the arguments in the method call with preconfigure argument from the 
   * client configuration. Then it will run the list of pre_construct methods
   * one by one in the order they appear in the list.
   * 
   * The call API that all the pre_construct methods must adhere to is:
   *    meth(cli_info, request_args, **_args)
   * 
   * 
   * @param {serviceContext} serviceContext Client Information as a Client instance.
   * @param {Object<string, string>} requestArgs Request arguments
   * @return Array consisting of request arguments and post arguments
   */
  doPreConstruct(requestArgs, params) {
    let args = this.methodArgs('pre_construct', params);
    let postArgs = {};
    let pair = null;
    for (let i = 0; i < this.preConstruct.length; i++) {
      let meth = this.preConstruct[i];
      pair = meth(requestArgs, this, args);
    }
    if (!pair){
      pair = [requestArgs, postArgs];
    }
    return pair;
  }

  /**
   * Has a number of sources where it can get request arguments from. 
   * In priority order:
   * -  Arguments to the method call
   * -  Information kept in the client information instance
   * -  Information in the client configuration targeted for this method.
   * -  Standard protocol defaults.
   * 
   * It will go through the list of possible (required/optional) attributes 
   * as specified in the oicmsg.message.Message class that is defined to be 
   * used for this request and add values to the attributes if any can be 
   * found.
   * 
   * @param {serviceContext} serviceContext contains client information
   * @return Object<string, Object> that contains request arguments such as
   * redirectUri 
   */
  gatherRequestArgs(attrs, req) {
    if (!req){
      req = this;
    }
    let arArgs = attrs;
    /*try{
    req.msgType = new req.msgType();
    }catch(err){
      console.log(err);
    }*/
    for (var i = 0; i < Object.keys(req.msgType.cParam).length; i++){
      let prop = Object.keys(req.msgType.cParam)[i];
      if (Object.keys(attrs).indexOf(prop) !== -1){
        continue;
      }else{
        if (req.serviceContext && req.serviceContext[prop] ){
          arArgs[prop] = req.serviceContext[prop];
        } else if (req.conf['request_args'] && req.conf['request_args'][prop]){
          arArgs[prop] = req.conf['request_args'][prop];
        } else if (req.defaultRequestArgs[prop]){
          arArgs[prop] = req.defaultRequestArgs[prop];
        }
      }
    }
    return arArgs;
  }

  methodArgs(context, extra){
    let args;
    if (this.conf[context]){
      args = this.conf[context];
      args = Object.assign(args, extra);
    } else {
      args = extra;
    }
    return args;
  }

  /**
   * Has a number of sources where it can get request arguments from. In 
   * priority order:
   * -  Arguments to the method call
   * -  Information kept in the client information instance
   * -  Information in the client configuration targeted for this method.
   * -  Standard protocol defaults.
   * 
   * It will go through the list of possible (required/optional) attributes 
   * as specified in the oicmsg.message.Message class that is defined to be 
   * used for this request and add values to the attributes if any can be 
   * found.
   * 
   * @param {serviceContext} serviceContext Client Information as a oiccli Client instance
   * @param {Object<string, string>} requestArgs Request arguments
   * @param {Object<string, string>} postArgs Arguments used by the 
   * postConstruct method
   * @return Possible modified set of request arguments.
   */
  doPostConstruct(requestArgs, params) {
    let args = this.methodArgs('post_construct', params);
    let pair = null;
    for (let i = 0; i < this.postConstruct.length; i++) {
      let meth = this.postConstruct[i];
      requestArgs = meth(requestArgs, this, args);
    }
    return requestArgs;
  }

  /**
   * A method run after the response has been parsed and verified.
   * Runs the list of post_parse_response methods in the order they appear 
   * in the list.
   * 
   * @param {Message} resp The response as a Message instance
   * @param {serviceContext} serviceContext Client Information as a Client instance.
   * @param {State} state State value
   */
  doPostParseResponse(resp, serviceContext, state, params) {
    state = state || '';
    if (this.postParseResponse){
      for (let i = 0; i < this.postParseResponse.length; i++) {
        let meth = this.postParseResponse[i];
        if (meth){
          meth(resp, serviceContext, state, params);
        }
      }
    }
  }

  setUp() {
    console.log('Unsupported');
  }

  /**
   * Instantiate the request as a message class instance with
   * attribute values gathered in a preConstruct method or in the
   * gatherRequestArgs method and possibly modified by a postConstruct method.
   * 
   * @param {serviceContext} serviceContext Information about the client
   * @param {Object<string, string>}requestArgs Request arguments
   * @return Message class instance 
   */ 
  construct(requestArgs, params) {
    if (requestArgs == null) {
      requestArgs = {};
    }
    let pair = this.doPreConstruct(requestArgs, params);
    requestArgs = pair[0];
    let postArgs = pair[1];
    try{
      this.msgType = new this.msgType();
    }catch(err){
      //console.log(err);
    }
    
    /*
    if (this.msgType && this.msgType.cParam && 
        Object.keys(this.msgType.cParam).indexOf('state') === -1) {
      if (params && params['state']) {
        delete params['state'];
      }
    }*/
    let args = null;

    //try {
    args = this.gatherRequestArgs(requestArgs);
    /*} catch (err) {
      args = this.parseArgs(serviceContext, requestArgs);
    }*/
    this.msgType.claims = Object.assign(this.msgType.claims, args);
    //args = new this.msgType(args);
    params = postArgs;
    return this.doPostConstruct(this.msgType, postArgs);
  }
  
  /**
   *  Find out which endpoint the request should be sent to
   *  Picks the endpoint (URL) to which the request will be sent.
   * @return The endpoint URI to which the request will be sent
   */
  getEndpoint(params) {
    return this.endpoint;
    
    /*let uri = '';
    if (params) {
      uri = params['endpoint'];
      if (uri){
        delete params['endpoint'];
      }
    }
    if (!uri) {
      try {
        uri = this.endpoint;
      } catch (err) {
        console.log('No endpoint specified');
        throw new Error(err);        
      }
    }
    return uri;*/
  }
  
  /**
   * Based on the HTTP method place the protocol message in the right place.
   * Depending on where the request are to be placed in the request (part of 
   * the URL or as a POST body) and the serialization used the request in 
   * it’s proper form will be constructed and tagged with destination.
   * 
   * uriAndBody will return a dictionary that a HTTP client library can use 
   * to send the request.
   * 
   * @param {ResourceRequest} request The request as a Message class instance
   * @param {string} method HTTP method
   */
  uriAndBody(request, method, params) {
    method = method || 'POST';
    let resp = {};
    let uri = this.getEndpoint(params);
    if (params && params['headers']){
      resp['hArgs'] = {'headers': params['headers']};
    }
    resp = Object.assign(resp, util.prototype.getOrPost(uri, method, request, null, null, params));
    resp['request'] = request;
    return resp;
  }

  /**
   *  Will run the proper client authentication method.
   *  Each such method will place the necessary information in the necessary
   *  place. A method may modify the request.
   *  Supports 6 different client authentication/authorization methods
   * -  bearerBody
   * -  bearerHeader
   * -  clientSecretBasic
   * -  clientSecretJwt
   * -  clientSecretPost
   * -  privateKeyJwt
   * depending on which of these, if any, is supposed to be used different 
   * things has to happen. Thos things will happen when this method is called.
   * 
   * @param {ResourceRequest} request The request as a Message class instance
   * @param {serviceContext} serviceContext serviceContext instance
   * @param {string} authMethod Type of authentication method
   * @param {Object<string, string>} requestArgs Request args
   * @param {Object<string, string>} httpArgs HTTP header arguments
   * @return Object<string, Object> containing Http arguments 
   */
  initAuthenticationMethod(
      request, authMethod, httpArgs, params) {
    if (httpArgs == null) {
      httpArgs = {};
    }
    if (authMethod) {
      /*return this.clientAuthMethod[authMethod].prototype.construct(
        request, this, httpArgs, params);*/
      return this.clientAuthMethod(authMethod).prototype.construct(
          request, this, httpArgs, params);
    } else {
      return httpArgs;
    }
  }

  /**
   * @param {*} request 
   * @param {*} authMethod 
   * @param {*} httpArgs 
   * @param {*} params 
   */
  getAuthHeader(request, authnMethod, params){
    let headers = {};
    // If I should deal with client authentication
    if (authnMethod){
      let hArg = this.initAuthenticationMethod(request, authnMethod, null, params);
      if (hArg['headers']){
        headers = hArg['headers'];
      }
    }
    return headers;
  }

  /**
   * The method where everything is setup for sending the request.
   * The request information is gathered and the where and how of sending the
   * request is decided.
   * 
   * - Remove request arguments that is know at this point should not appear in
   *   the request
   * - Construct the request
   * - Do the client authentication setup if necessary
   * - Set the necessary HTTP headers
   * 
   * @param {serviceContext} serviceContext Client information as a oicCli Client instance
   * @param {string} method The HTTP method to be used
   * @param {Object<string, string>} requestArgs Request Arguments
   * @param {string} bodyType If the request is sent in the HTTP body this 
   * decides the encoding of the request
   * @param {string} authnMethod The client authentication method
   * @param {bool} lax If it should be allowed to send a request that doesn't 
   * completely conform to the standard
   * @return A dictionary with the keys 'uri' and possibly 'body', 'params',
   * 'request' and 'ht_args'
   */
  requestInfo(serviceContext, method, requestArgs, bodyType, authMethod, lax, params) {
    if (!method) {
      method = this.httpMethod;
    }

    if (requestArgs == null) {
      requestArgs = {};
    }

    var paramsArr = [];
    if (params){
      paramsArr = Object.keys(params);      
    }

    let args = {};
    for (let i = 0; i < paramsArr.length; i++) {
      let k = paramsArr[i];
      let v = params[k];
      if (SPECIAL_ARGS.indexOf(v) == -1 && SPECIAL_ARGS.indexOf(k) == -1) {
        args[k] = v;
      }
    }

    let request = this.construct(serviceContext, requestArgs, args);

    if (this.events) {
      this.events.store('Protocol request', request);
    }

    if (request && lax) {
      request.lax = lax;
    }

    let hArg = null;

    if (authMethod) {
      hArg =
          this.initAuthenticationMethod(request, serviceContext, authMethod, null, params);
    }

    if (hArg) {
      if (params.headers) {
        params['headers'] = Object.assign(hArg['headers'], params['headers']);
      } else {
        params['headers'] = hArg['headers'];
      }
    }

    if (bodyType == 'json') {
      params['contentType'] = JSON;
    }

    return this.uriAndBody(request, method, params);
  }

  /**
   * Extending the header with information gathered during the request setup.
   * Will add the HTTP header arguments that has been added while the request
   * has been travelling through the pipe line to a possible starting set.
   * @param {Object<string, string>} httpArgs Original HTTP header arguments
   * @param {Object} info Request info
   */
  updateHttpArgs(httpArgs, info) {
    let hArgs = null;
    if (info['hArgs']){
      hArgs = info['hArgs'];
    } else {
      hArgs = {};
    }

    if (httpArgs == null) {
      httpArgs = hArgs;
    } else {
      httpArgs = info['hArgs'];
    }

    if (info['params'] && info['params']['headers']){
      const headers = info['params']['headers'];
      httpArgs = {'headers': headers}
    }

    info['httpArgs'] = httpArgs;
    return info;
  }

  /**
   *  Builds the request message and constructs the HTTP headers.
   *  This is the starting pont for a pipeline that will:
   *    - construct the request message
   *    - add/remove information to/from the request message in the way a
   *      specific client authentication method requires.
   *    - gather a set of HTTP headers like Content-type and Authorization.
   *    - serialize the request message into the necessary format (JSON, 
   *      urlencoded, signed JWT)
   * 
   * @param {serviceContext} serviceContext Client information
   * @param {string} bodyType Which serialization to use for the HTTP body
   * @param {string} method HTTP method used
   * @param {string} authMethod One of the six client authentication methods
   * @param {Object<string, string>} requestArgs Message arguments
   * @param {Object<string, object>} httpArgs Initial HTTP header arguments
   * @return Object<string, Object> contains difference information such as 
   * the uri, body, and httpArgs based on the service
   */
  doRequestInit(
      serviceContext, bodyType, method, authMethod, requestArgs, httpArgs, params) {
    if (!method) {
      method = this.httpMethod;
    }
    if (!authMethod) {
      authMethod = this.defaultAuthnMethod;
    }
    if (!bodyType) {
      bodyType = this.bodyType;
    }

    /*
    let request = this.constructRequest(requestArgs, params)

    let info = {'method':method};
    let args = params;
    if (this.serviceContext.issuer){
      args['iss'] = this.serviceContext.issuer;
    }
    let headers = this.getAuthnHeader(request, authMethod, args);

    let endpointUrl = '';
    if (params['endpoint']){
      endpointUrl = params['endpoint']
    }else{
      endpointUrl = this.getEndpoint();
    }

    info['url'] = getHttpUrl(endpointUrl, request, method);
    */

    let info = this.requestInfo(
        serviceContext, method, requestArgs, bodyType, authMethod, httpArgs, params);
    return this.updateHttpArgs(httpArgs, info);
  }

  /************************ RESPONSE HANDLING *************************/

  /**
   *  Pick out the fragment or query part from a URL.
   *  @param info A URL possibly containing a query or a fragment part
   *  @return the query/fragment part
   */
  getUrlInfo(info) {
    let parts = null;
    if (typeof info == 'string'){
      if (info.indexOf('?') !== -1 || info.indexOf('#') !== -1) {
        parts = urlParse(info);
        let query = parts.query;
        let fragment = parts.fragment;
        if (query) {
          info = query.substring(1);
        } else {
          info = fragment;
        }
      }
    }
    return info;
  }

  urlUnsplit(dict){
    var str = [];
    for (var i = 0; i < Object.keys(dict).length; i++){
      var key = Object.keys(dict)[i];
      var val = dict[key];
      str.push(encodeURIComponent(key) + "=" + encodeURIComponent(val));
      
    }
    return str.join("&");
  }

  getHttpUrl(url, req, method='GET'){
    let methods = ["GET", "DELETE"];
    if (methods.indexOf(method) !== -1){
      if (Object.keys(req.claims).length > 0){
        let comp = urlParse(url);
        if (comp.query){
          req = Object.assign(parse_qs(comp.query));
        }
        
        let parts = urlParse(url);
        let scheme = parts[0];
        let netloc = parts[1];
        let path = parts[2];
        let params = parts[3];
        let query = parts[4];
        let fragment = parts[5];
        //let comp = urlSplit(uri.toString());
        if (query) {
          req = this.parseQs(query);
        }
        query = encodeURIComponent(req.claims);
        return url + '?' + this.urlUnsplit(req.claims);
      }else{
        return url;
      }
    }else{
      return url;
    }
  }

  /**
   * Builds the request message and constructs the HTTP headers. This is the starting point for a pipeline that will: 
   * construct the request message 
   * add/remove information to/from the request message in the way a specific client authentication method requires. 
   * gather a set of HTTP headers like Content-type and Authorization. 
   * serialize the request message into the necessary format (JSON, urlencoded, signed JWT)
   * @param {string} bodyType Which serialization to use for the HTTP body
   * @param {string} method HTTP method used
   * @param {string} authnMethod One of the six client authentication methods : bearer_body, bearer_header, client_secret_basic, client_secret_jwt, client_secret_post, private_key_jwt 
   * @param {Object.<string, string>} requestArgs Message arguments
   * @param {Object.<string, string>} httpArgs Initial HTTP header arguments
   * @param {Object.<string, string>} params Other attributes that might be needed
   * @return Object<string, Object> contains difference information such as the uri, body, and httpArgs based on the service
   */
  getRequestParameters({bodyType, method, authnMethod, requestArgs, httpArgs, params}= {bodyType:'', method:'', authnMethod:'', requestArgs:null, httpArgs:null}){

    if (!method){
      method = this.httpMethod;
    }
    if (!authnMethod){
      authnMethod = this.defaultAuthnMethod;
    }
    if (!bodyType){
      bodyType = this.bodyType;
    }
    
    let request = this.constructRequest(requestArgs, params);
    
    let info = {'method': method};
    let args = {};
    if (this.serviceContext && this.serviceContext.issuer){
      args['iss'] = this.serviceContext.issuer;
    }
    let contentType = null;
    
    if (bodyType == 'urlEncoded'){
      contentType = URL_ENCODED;
    }else{
      contentType = JSON_ENCODED;
    }
    
    let _headers = this.getAuthHeader(request, authnMethod, params);

    let endpointUrl = this.getEndpoint(args);
    info['url'] = this.getHttpUrl(endpointUrl, request, method);

    let methods = ['POST', 'PUT'];
    if (methods.indexOf(method) !== -1){
      info['body'] = getHttpBody(request, contentType);  
      _headers = Object.assign(_headers, {'Content-Type': contentType});
    } 
    
    if (_headers && Object.keys(_headers).length){
      info['headers'] = _headers;
    }

    return info
  }

  query(resource, rel) {
    rel = rel || null;
    let uriNormalizer = new URINormalizer();
    resource = uriNormalizer.normalize(resource);
    let info = {};
    info['resource'] = resource;
    if (rel == null) {
      if (this.defaultRel) {
        info['rel'] = this.defaultRel;
      }
    } else if (rel instanceof String) {
      info['rel'] = rel;
    } else {
      for (let i = 0; i < rel.length; i++) {
        let val = rel[i];
        if (info['rel']) {
          info['rel'].push(val);
        } else {
          info['rel'] = [val];
        }
      }
    }
    if (resource.startsWith('http')) {
      let part = urlParse(resource);
      var host = part.hostName;
      if (part.port !== null) {
        host += ':' + str(part.port);
      }
    } else if (resource.startsWith('acct:')) {
      let list = resource.split('@');
      host = list[list.length - 1];
      host = host.replace('/', '#').replace('?', '#').split('#')[0];
    } else if (resource.startsWith('device:')) {
      host = resource.split(':')[1];
    } else {
      console.log('Unknown schema');
    }
    return WF_URL.replace('%s', host) + '?' + this.urlEncode(info);
  }

  /**
   * This the start of a pipeline that will:
   *  - Deserializes a response into it's response message class.
   *    Or oauth2 ErrorResponse if it's an error message
   *  - verifies the correctness of the response by running the verify 
   *    method belonging to the message class used.
   *  - runs the doPostParseResponse method iff the response was not
   *    an error response.
   * 
   * @param {Object<string, string>} info The response, can be either in a JSON or an urlencoded format
   * @param {string} sformat Which serialization that was used
   * @param {State} state The state
   * @param {Object<string, string>} params Other attributes that might be needed
   * @return Response instance such as an ErrorResponse
   */
  parseResponse(info, sformat, state, params) {
    if (!sformat){
      sformat = this.responseBodyType;
    }
    if (sformat == 'urlencoded') {
      info = this.getUrlInfo(info);
    }

    if (this.events) {
      this.events.store('Response', info);
    }

    let resp = null;
    let responseObj = this.responseCls;    
    try {
      if (sformat === 'urlencoded') {
        resp = responseObj.fromUrlEncoded(info);
      }else if (sformat === 'json'){
        resp = responseObj.fromJSON(info);
      }else if (sformat == 'dict'){
        resp = new responseObj(info);
      }
    } catch (err) {
      console.log('Error while deserializing');
    }

    let msg = 'Initial response parsing';

    if (this.events) {
      this.events.store('Protocol Response', resp);
    }
    let errMsgs = null;
    if (resp && Object.keys(resp).indexOf('error') !== -1 &&
        !(resp instanceof ErrorResponse)) {
      resp = null;
      try {
        errMsgs = [this.errorMsg];
        if (errMsgs.indexOf(ErrorResponse) !== -1) {
          errMsgs.push(ErrorResponse);
        }
      } catch (err) {
        errMsgs = [ErrorResponse];
      }

      try {
        for (let i = 0; i < errMsgs.length; i++) {
          var errMsg = errMsgs[i];
          try {
            if (sformat === 'urlencoded') {
              resp = errMsg.fromUrlEncoded(info);
              break;
            }
          } catch (err) {
            resp = null;
          }
        }
      } catch (err) {
        console.log(err);
      }
    } else {
      if (!params) {
        params = {};
      }
      params['client_id'] = this.serviceContext.client_id;
      params['iss'] = this.serviceContext.issuer;

      if (Object.keys(params).indexOf('key') !== -1 &&
          Object.keys(params).indexOf('keyjar') !== -1) {
        params['keyjar'] = this.serviceContext.keyjar;
      }

      if (this.conf['verify']){
        params = Object.assign(this.conf['verify'], params);
      }

      try {
        let responseObj = this.responseCls;
      } catch (err) {
        console.log(err);
      }

      if (resp && Object.keys(resp).indexOf('scope') !== -1) {
        if (params['scope']){
          resp['scope'] = params['scope'];
        }
      }
    }
    if (!resp) {
      console.log('Missing or faulty response');
    }

    try {
      this.doPostParseResponse(resp, state);
    } catch (err) {
      console.log(err);
    }
    return resp;
  }

  /**
   * Deal with a request response
   * @param {string} reqresp The HTTP request response
   * @param {string} bodyType How the body is encoded
   * @return ErrorMessage class instance
   */
  parseErrorMessage(reqresp, bodyType) {
    if (bodyType == 'txt'){
      bodyType = 'urlencoded';
    }else{
      bodyType = bodyType;
    }
    let err;
    if (bodyType === 'urlencoded'){
      err = new this.errorMsg().fromUrlEncoded(reqresp.text)
    }else if (bodyType === 'json'){
      err = new this.errorMsg().fromJSON(reqresp.text)
    }
    return err;
  }

  /**
   * Get the encoding of the response
   * @param {string} reqresp The response
   * @param {string} bodyType Assumed body type
   * @return String with the encoding type
   */
  getValueType(reqresp, bodyType){
    if (bodyType) {
      return Util.prototype.verifyHeader(reqresp, bodyType);
    } else {
      return 'urlencoded';
    }
  }

  /**
   * Deal with a request response
   * @param {string} reqresp The HTTP request response
   * @param {serviceContext} serviceContext Information about the client/server session
   * @param {string} responseBodyType If response in body one of 'json', 'jwt' or
   *      'urlencoded'
   * @param {State} state Session identifier
   * @return response type such as an ErrorResponse
   */
  parseRequestResponse(reqresp, serviceContext, responseBodyType, state, params) {
    responseBodyType = responseBodyType || '';
    state = state || '';
    let statusCodeArr = [302, 303];

    if (SUCCESSFUL.indexOf(reqresp.statusCode) !== -1) {
      /*
      var type;
      var valueType;
      try{
        type = Util.prototype.getResponseBodyType(reqresp);
      }catch(err){
        valueType = responseBodyType;
      }
      if (type != responseBodyType){
        console.log('Not the expected body type. Expected : ' + type);
      }
      var typeArr = ['json', 'jwt', 'urlencoded'];
      var valueType;
      if (typeArr.indexOf(type) !== -1){
        valueType = type;
      }else{
        valueType = responseBodyType;
      } */
      
      let valueType = this.getValueType(reqresp, responseBodyType);

      try {
        return this.parseResponse(
            reqresp.text, serviceContext, valueType, state, params);
      } catch (err) {
        console.log(err);
      }
    } else if (statusCodeArr.indexOf(reqresp.statusCode) !== -1) {
      return reqresp;
    } else if (reqresp.statusCode === 500) {
      console.log('Something went wrong');
    } else if (400 <= reqresp.statusCode < 500) {
      let valueType = this.getValueType(reqresp, responseBodyType);
      let errResp = null;
      try {
        errResp = this.parseErrorMessage(reqresp, valueType);
      } catch (err) {
        return reqresp.text;
      }
      return errResp;
    } else {
      console.log('Error response');
    }
  }

  /**
  * The method that sends the request and handles the response returned.
  * This assumes a synchronous request-response exchange.
  * @param {string} reqresp The HTTP request response
  * @param {serviceContext} serviceContext Information about the client/server session
  * @param {string} responseBodyType If response in body one of 'json', 'jwt' or
  *      'urlencoded'
  * @param {State} state Session identifier
  * @return Returns a request response
  */ 
  serviceRequest(reqresp, serviceContext, responseBodyType, state, params) {
    if (httpArgs == null) {
      httpArgs = {};
    }
    try {
      resp = this.httpLib(url, method, data, httpArgs);
      data = data || body;
    } catch (err) {
      console.log('Exception on request');
    }
    if (params.indexOf('keyjar') === -1) {
      params['keyjar'] = this.keyjar;
    }
    if (!responseBodyType) {
      responseBodyType = this.responseBodyType;
    }
    return this.parseRequestResponse(
        resp, serviceContext, responseBodyType, params);
  }

  /**
   * A method run after the response has been parsed and verified.
   * @param {Object<string, string>} resp The response, can be either in a JSON or an urlencoded format
   * @param {State} state The state
   * @param {Object<string, string>} params Other attributes that might be needed
   */
  updateServiceContext(resp, state, params){
    this.storeItem(resp, this.request, state);
  }

  /**
   *  The method where everything is setup for sending the request.
   *  The request information is gathered and the where and how of sending the
   *  request is decided.
   * @param {*} requestArgs 
   * @param {*} params 
   */
  constructRequest(requestArgs, params){
    if (!requestArgs){
      requestArgs = {};
    }
    return this.construct(requestArgs, params);
  }


addRedirectUris(requestArgs, service, params){
  let context = service.serviceContext;
  if (Object.keys(requestArgs).indexOf('redirect_uris') === -1){
    if (context.callback){
      requestArgs['redirect_uris'] = context.callback.values();
    }else{
      requestArgs['redirect_uris'] = context.redirectUris;
    }
  }
  let list = [requestArgs, {}]
  return list;
}

addRequestUri(requestArgs=null, service=null, params){
  let context = service.serviceContext;
  if (context.request_dir){
    try{
      if (context.providerInfo['require_request_uri_registration']){
        requestArgs['request_uris'] = context.generateRequestUris(context.request_dir);
      }
    }catch(err){
      console.log(err);
    }
  }
  let list = [requestArgs, {}];
  return list;
}

addPostLogoutRequestUris(requestArgs=null, service=null, params){
  let uris = [];
  if (Object.keys(requestArgs).indexOf('post_logout_redirect_uris') === -1){
    try{
      uris = service.serviceContext.post_logout_redirect_uris;
    }catch(err){
      console.log(err);
    }
    if (uris){
      requestArgs['post_logout_redirect_uris'] = uris;
    }
  }
  let list = [requestArgs, {}];
  return list;
}

addJwksUriOrJwks(requestArgs=null, service=null, params){
  if (Object.keys(requestArgs).indexOf('jwks_uri') !== -1){
    if (Object.keys(requestArgs).indexOf('jwks') !== -1){
      delete requestArgs['jwks'];
    }
    let list = [requestArgs, {}];
    return list;
  }else if (Object.keys(requestArgs).indexOf('jwks') !== -1){
    let list = [requestArgs, {}];
    return list;
  }

  let jwksList = ['jwks_uri', 'jwks'];
  for (var i = 0; i < jwksList.length; i++){
    let attr = jwksList[i];
    let val = service.serviceContext[attr];
    if (val){
      requestArgs[attr] = val;
      break;
    }else{
      try{
        val = service.serviceContext.config[attr];
      }catch(err){
        return
      }
      if (val){
        requestArgs[attr] = val;
      }
      break;
    }
  }
  let list = [requestArgs, {}];
  return list;
}

responseTypesToGrantTypes(responseTypes){
  let gt = []
  for (var i = 0; i < responseTypes.length; i++){
    let responseType = responseTypes[i];
    try{
      gt = rt2gt[responseType];
    }catch(err){
      console.log(err);
    }
    return gt;
  }
}
}

function addJwksUriOrJwks(requestArgs=null, service=null, params){
  if (Object.keys(requestArgs).indexOf('jwks_uri') !== -1){
    if (Object.keys(requestArgs).indexOf('jwks') !== -1){
      delete requestArgs['jwks'];
    }
    let list = [requestArgs, {}];
    return list;
  }else if (Object.keys(requestArgs).indexOf('jwks') !== -1){
    let list = [requestArgs, {}];
    return list;
  }

  let jwksList = ['jwks_uri', 'jwks'];
  for (var i = 0; i < jwksList.length; i++){
    let attr = jwksList[i];
    let val = service.serviceContext[attr];
    if (val){
      requestArgs[attr] = val;
      break;
    }else{
      try{
        val = service.serviceContext.config[attr];
      }catch(err){
        return
      }
      if (val){
        requestArgs[attr] = val;
      break;
      }
    }
  }
  let list = [requestArgs, {}];
  return list;
}

/** 
 * Takes a dictionary with a reference to which service subclass that should be 
 * instantiated as key and specific service configuration for that instance as 
 * value.
 * @param {Object<string, object>} serviceDefinitions Service subclass as key and configuration as value
 * @param {function} serviceFactory OIC/ OAuth2 factory method 
 * @param {ServiceContext} serviceContext Contains information that a client needs to be able to talk to a server
 * @param {string} clientAuthnMethod One of the six client authentication methods : bearer_body, bearer_header, client_secret_basic, client_secret_jwt, client_secret_post, private_key_jwt 
 * @return A dictionary containing the necessary services and their instances
 */
function buildServices(serviceDefinitions, serviceFactory, serviceContext, stateDb, clientAuthnMethod) {
  //let http = params['httpLib'];
  //let keyJar = params['keyJar'];
  //let clientAuthnMethod = params['clientAuthnMethod'];
  let service = {};
  for (let i = 0; i < Object.keys(serviceDefinitions).length; i++) {
    let serviceName = Object.keys(serviceDefinitions)[i];
    let serviceConfiguration = serviceDefinitions[serviceName]
    let srv = serviceFactory(serviceName, serviceContext, stateDb, clientAuthnMethod, serviceConfiguration); 
    service[srv.request] = srv;
    //service['any'] = new Service(serviceContext, stateDb, clientAuthnMethod);
  }
  return service;
}

module.exports.Service = Service;
module.exports.addJwksUriOrJwks = addJwksUriOrJwks;
module.exports.buildServices = buildServices;