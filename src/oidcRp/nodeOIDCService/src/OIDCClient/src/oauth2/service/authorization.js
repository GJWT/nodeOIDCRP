const oauth2 = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/init.js');
const Service = require('../../service.js').Service;
const oauth2Service = require('./service');
const requests = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/requests');
const responses = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/responses');

function getStateParameter(requestArgs, params){
  let _state;
  if (params && params['state']){
    _state = params['state'];
  }else if (requestArgs['state']){
    _state = requestArgs['state'];
  }else{
    //throw new JSError('state', 'MissingParameter');
  }
  return _state;
}

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
  }else{
    requestArgs['redirect_uri'] = context.redirectUris[0];
  }
  let list = [requestArgs, {}];
  return list;
}

function setStateParameter(requestArgs=null, req, params){
  requestArgs['state'] = getStateParameter(requestArgs, params);
  let list = [requestArgs, {'state': requestArgs['state']}];
  return list;
}

/**
 * Authorization
 * @class
 * @constructor
 * @extends Service
 */
class Authorization extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod, conf) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = requests.AuthorizationRequest;
    this.responseCls = responses.AuthorizationResponse;
    this.errorMsg = responses.AuthorizationErrorResponse;
    this.endpointName = 'authorization_endpoint';
    this.synchronous = false;
    this.request = 'authorization';
    //this.preConstruct = [this.oauthPreConstruct];
    //this.postParseResponse.push(oauth2Service.postXParseResponse);
    this.preConstruct = [pickRedirectUris, setStateParameter];
    this.postConstruct.push(this.storeAuthRequest);
    this.responseBodyType = 'urlencoded';
  }

  updateServiceContext(resp, state='', params){
    this.storeItem(resp, 'auth_response', state);
  }

  storeAuthRequest(requestArgs, req, params){
    let key = oauth2Service.getState(requestArgs, params);
    req.storeItem(requestArgs, 'auth_request', key);
    return requestArgs;
  }

  gatherRequestArgs(params){
    let arArgs = Service.prototype.gatherRequestArgs(params, this);
    if (Object.keys(arArgs).indexOf('redirect_uri')){
      try{
        arArgs['redirect_uri'] = this.serviceContext.redirectUris[0];
      }catch(err){
        //throw new JSError('redirect_uri', 'MissingParameter');
      }
    }
    return arArgs;
  }
}

module.exports.Authorization = Authorization;