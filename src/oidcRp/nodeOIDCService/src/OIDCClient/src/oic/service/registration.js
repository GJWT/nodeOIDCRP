const Service = require('../../service').Service;
const OIDCRequests = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests');
const OIDCResponses = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses');

let rt2gt = {
  'code': ['authorization_code'],
  'id_token': ['implicit'],
  'id_token token': ['implicit'],
  'code id_token': ['authorization_code', 'implicit'],
  'code token': ['authorization_code', 'implicit'],
  'code id_token token': ['authorization_code', 'implicit']
};

/**
 * Registration
 * @class
 * @constructor
 * @extends Service
 */
class Registration extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    let service = super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = OIDCRequests.RegistrationRequest;
    this.responseCls = OIDCResponses.RegistrationResponse;
    this.errorMsg =  OIDCResponses.ResponseMessage;
    this.endpointName = 'registrationEndpoint';
    this.synchronous = true;
    this.request = 'registration';
    this.bodyType = 'json';
    this.httpMethod = 'POST';
    let addRedirectUris = this.addRedirectUris;
    let addRequestUri = this.addRequestUri;
    let addJwksUriOrJwks = this.addJwksUriOrJwks;
    this.endpoint = 'https://example.org/op/registration';
    //    this.postParseResponse = [this.addClientBehavior, this.addRedirectUris, this.addRequestUr, this.addPostLogoutRedirectUris, this.addJwksUriOrJwks];
    //this.postParseResponse = [this.oicPostParseResponse];
    this.preConstruct = [this.addClientBehavior, this.addRedirectUris, this.addRequestUri, this.addPostLogoutRequestUris, this.addJwksUriOrJwks]   
    this.postConstruct = [this.oidcPostConstruct];
    return this;
  }

  addClientBehavior(requestArgs=null, request, params){
    request.msgType = new request.msgType();
    for (var i = 0; i < Object.keys(request.msgType.cParam).length; i++){
      let prop = Object.keys(request.msgType.cParam)[i];
      if (Object.keys(requestArgs).indexOf(prop) !== -1){
        continue;
      }
      try{
        if (request.serviceContext.behavior[prop]){
          requestArgs[prop] = request.serviceContext.behavior[prop];
        }
      }catch(err){
        pass;
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

  oidcPostConstruct(requestArgs=null, params){
    try{
      let responseTypes = requestArgs.claims['response_types'];
      let gt = []
      for (var i = 0; i < responseTypes.length; i++){
        let responseType = responseTypes[i];
        try{
          gt = rt2gt[responseType];
        }catch(err){
          console.log(err);
        }
      }

      requestArgs.claims['grant_types'] = gt;
    }catch(err){
      console.log(err);
    }
    return requestArgs;
  }

  updateServiceContext(resp, state='', params){
    this.serviceContext.registrationResponse = resp;
    if (Object.keys(this.serviceContext.registrationResponse).indexOf('token_endpoint_auth_method') == -1){
      this.serviceContext.registrationResponse['token_endpoint_auth_method'] = 'client_secret_basic';
    }
    this.serviceContext['client_id'] = resp['client_id'];

    if (resp['client_secret']){
      this.serviceContext['client_secret'] = resp['client_secret'];
    }else if (resp.claims['client_secret_expires_at']){
      this.serviceContext['client_secret_expires_at'] = resp['client_secret_expires_at'];
    }
    this.serviceContext['registration_access_token'] = resp['registration_access_token'];
  }

  /*
  addRedirectUris(requestArgs, serviceContext, params){
    let context = service.serviceContext;
    if (Object.keys(requestArgs).indexOf('redirect_uris') === -1){
      if (context.callback){
        requestArgs['redirect_uris'] = context.callback.values();
      }else{
        requestArgs['redirect_uris'] = context.redirect_uris;
      }
    }
    let list = [requestArgs, {}]
    return list;
  }
  
  addRequestUris(requestArgs=null, service=null, params){
    let context = service.serviceContext;
    if (context.requestDir){
      try{
        if (context.providerInfo['require_request_uri_registration']){
          requestArgs['request_uris'] = context.generateRequestUris(context.requestDir);
        }
      }catch(err){
        console.log(err);
      }
    }
    let list = [requestArgs, {}];
    return list;
  }
  
  function addPostLogoutRequestUris(requestArgs=null, service=null, params){
    let uris = [];
    if (Object.keys(requestArgs).indexOf('post_logout_redirect_uris') === -1){
      try{
        uris = service.serviceContext.post_logout_redirect_uris;
      }catch(err){
        console.log(err);
      }
      requestArgs['post_logout_redirect_uris'] = uris;
    }
    let list = [requestArgs, {}];
    return list;
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
    for (var i = 0; i < jwksList; i++){
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
        requestArgs[attr] = val;
        break;
      }
    }
    let list = [requestArgs, {}];
    return list;
  }
  */
}

module.exports.Registration = Registration;