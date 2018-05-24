const OAuth2Authorization =
    require('../../oauth2/service/authorization').Authorization;
const State = require('../../state.js').State;
const serviceContext= require('../../serviceContext').ServiceContext;
const AuthorizationRequest = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;

function pickRedirectUris(requestArgs, service, params){
  let context = service.serviceContext;
  if (Object.keys(requestArgs).indexOf('redirect_uri') !== -1){
    return;
  }else if (context.callback){
    if (requestArgs['response_type']){
      _responseType = requestArgs['response_type'];
    }else if (context.behavior['response_types'][0]){
      _responseType = context.behavior['response_types'][0];
      requestArgs['response_type'] = _responseType;
    }
    if (requestArgs['response_mode']){
      responseMode = requestArgs['response_mode'];
    }else{
      _responseMode = '';
    }

    if (_responseMode == 'form_post'){
      requestArgs['redirect_uri'] = context.callback['form_post'];
    }else if (_responseType == 'code'){
      requestArgs['redirect_uri'] = context.callback['code'];
    }else{
      requestArgs['redirect_uri'] = context.callback['implicit'];
    }
  }else if (context.redirectUris){
    requestArgs['redirect_uri'] = context.redirectUris[0];
  }
  let list = [requestArgs, {}];
  return list;
}

/**
 * Authorization
 * @class
 * @constructor
 * @extends OAuth2Authorization
 */
class Authorization extends OAuth2Authorization {
  /**
   * @param {ResourceRequest} request Request class instance
   * @param {Object<string, string>} requestArgs Request arguments
   * @param {Object<string, object>} httpArgs HTTP arguments
   */
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null){
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = AuthorizationRequest;
    this.defaultRequestArgs = {'scope': ['openid']};
    this.preConstruct = [this.setState, pickRedirectUris, this.oicPreConstruct];
    this.postConstruct = [this.oicPostConstruct];
    this.endpoint = 'https://example.org/op/authorization';
  }

  setState(requestArgs, req, params){
    let _state;
    if (params && params['state']){
      _state = params['state'];
    }else if (requestArgs && requestArgs['state']){
      _state = requestArgs['state'];
    }else{
      _state = Math.random(24);
    }
    requestArgs['state'] = _state;
    //let _item = new State({iss: req.serviceContext.issuer});
    let _item = State;
    req.stateDb.set(_state, _item.toJSON({iss: req.serviceContext.issuer}));
    //req.stateDb.set(_state, _item.toJSON());
    let list = [requestArgs, {}];
    return list;
  }

  updateServiceContext(resp, state='', params){
    this.storeItem(resp, 'auth_response', state);
  }

  oicPreConstruct(requestArgs, req, params) {
    if (requestArgs == null){
      requestArgs = {};
    }

    let _rt;
    if (requestArgs['response_type']){
      _rt = requestArgs['response_type'];
    }else if (req.serviceContext.behavior && req.serviceContext.behavior['response_types']){
      _rt = req.serviceContext.behavior['response_types'][0];
      requestArgs['response_type'] = _rt;
    }

    // For OIDC 'openId' is required in scope
    if (Object.keys(requestArgs).indexOf('scope') === -1){
      requestArgs['scope'] = ['openid']; 
    }else if (requestArgs['scope'].indexOf('openid') === -1){
      requestArgs['scope'].push('openid');
    }

    //'code' or 'id_token' in response_type means an ID token
    // will eventually be returned, hence the need for a nonce
    if (_rt && (_rt.includes('code') || _rt.includes('id_token'))){
      if (Object.keys(requestArgs).indexOf('nonce') === -1){
        requestArgs['nonce'] = Math.random(32);
      }
    }

    let postArgs = {};
    let algs = ["request_object_signing_alg", "algorithm", 'sig_kid'];
    for (var i = 0; i < algs.length; i++){
      let attr = algs[i];
      if (params && params[attr]){
        postArgs[attr] = params[attr];
        delete params[attr];
      }
    }

    let rt = null;
    if (requestArgs != null) {
      rt = requestArgs['response_type'];
      if (rt =='token' || rt == 'idToken') {
        if (Object.keys(requestArgs).indexOf('nonce') !== -1) {
          requestArgs['nonce'] = Math.random().toString(36).substring(32);
        }
      }
    } else {
      requestArgs = {'nonce': Math.random().toString(36).substring(32)};
    }

    let attributes = ['request_object_signing_alg', 'algorithm', 'sig_kid'];
    for (let i = 0; i < attributes.length; i++) {
      let attr = attributes[i];
      try {
        postArgs[attr] = params[attr];
      } catch (err) {
      }
      if (params && params[attr]) {
        delete params[attr];
      }
    }

    if (params && Object.keys(params).indexOf('requestMethod') !== -1) {
      if (params['requestMethod'] == 'reference') {
        postArgs['requestParam'] = 'requestUri';
      } else {
        postArgs['requestParam'] = 'request';
      }
      delete params['requestMethod'];
    }

    let list = [requestArgs, postArgs];
    return list;
  }

  oicPostConstruct(req, request, params) {
    let _nonce;
    if (req.claims['scope'] && req.claims['scope'][0] == 'openid') {
      if (req.claims['response_type']){
        let responseType = req.claims['response_type'][0];
        if (responseType.indexOf('id_token') !== -1 ||
            responseType.indexOf('code') !== -1) {
          if (Object.keys(req.claims).indexOf('nonce') === -1) {
            _nonce = Math.random().toString(36).substring(2);
            req.claims['nonce'] = nonce;
          }
          this.storeNonce2State(_nonce, req.claims['state']);
        }
      }
    }

    let requestMethod = null;
    if (params && params['request_method']){
      let requestMethod = params['request_method'];
      delete params['request_method'];
    }
    
    let alg = 'RS256';
    let args = ['request_object_signing_alg', 'algorithm'];
    for (let i = 0; i < args.length; i++) {
      let arg = args[i];
      try {
        alg = params[arg];
      } catch (err) {
        console.log(err);
      }
    }

    if (!alg) {
      try {
        alg = request.serviceContext.behavior['request_object_signing_alg'];
      } catch (err) {
        alg = 'RS256';
      }
    }

    if (params){
      params['request_object_signing_alg'] = alg;      
    }

    if (params && Object.keys(params).indexOf('keys') === -1 && alg && alg !== null) {
      // TODO
      //kty = jws.alg2keyType(alg);
      try {
        kid = params['sigKid'];
      } catch (err) {
        if (request.serviceContext && request.serviceContext.kid && request.serviceContext.kid['sig']){
          kid = request.serviceContext.kid['sig'].get(kty, null);
        }
      }

      if (serviceContext.keyJar){
        params['keys'] = request.serviceContext.keyJar.getSigningKey(kty, kid);
      }
    }

    //TODO
    //_req = makeOpenIdRequest(req, params);

    // _req = requestObjectEncryption(_req, this.serviceContext, params);
    let _webname = null;
    if (requestMethod === 'request'){
      req.claims['request'] = _req;
    }else if (request.serviceContext){
      try{
        _webname = request.serviceContext.registrationResponse['request_uris'][0];
        filename = request.serviceContext.filenameFromWebname(_webname);
      }catch(err){
        //TODO
        /*let pair = constructRequestUri(params);
        let filename = pair[0];
        let webName = pair[1];*/
      }
    }
    /*
      fid = open(filename, mode="w")
      fid.write(_req)
      fid.close()
    */
    if (_webname){
      req.claims['request_uri'] = _webname;
    }
    //TODO
    request.storeItem(req, 'auth_request', req.claims['state']);
    return req;
  }
}

module.exports.Authorization = Authorization;