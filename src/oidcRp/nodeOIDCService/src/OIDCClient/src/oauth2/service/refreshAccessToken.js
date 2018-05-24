const oauth2 = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/responses');
const Service = require('../../service.js').Service;
const oauth2Service = require('./service');
const requests = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/requests');
const responses = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/responses');
const serviceContext = require('../../serviceContext');

/**
 * RefreshAccessToken
 * @class 
 * @constructor
 * @extends Service
 */
class RefreshAccessToken extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.preConstruct = [this.oauthPreConstruct];
    this.msgType = requests.RefreshAccessTokenRequest;
    this.responseCls = responses.AccessTokenResponse;
    this.errorMsg = responses.TokenErrorResponse;
    this.endpointName = 'token_endpoint';
    this.synchronous = true;
    this.request = 'refresh_token';
    this.defaultAuthnMethod = 'bearer_header';
    this.httpMethod = 'POST';
  }

  updateServiceContext(resp, key='', params){
    this.storeItem(resp, 'token_response', key);
  }
  
  oauthPreConstruct(requestArgs, request, params) {
    let req = new request.msgType();
    let _state = oauth2Service.getState(requestArgs, params);
    let parameters = Object.keys(req.cParam);
    let _args = request.extendRequestArgs({}, oauth2.AuthorizationResponse, 'auth_response', _state, parameters);
    _args = request.extendRequestArgs(_args, oauth2.AccessTokenResponse, 'token_response', _state, parameters);
    if (requestArgs == null){
      requestArgs = _args;
    }else{
      _args = Object.assign(requestArgs, _args);
      requestArgs = _args;
    }
    let list = [requestArgs, {}];
    return list
  }
}

module.exports.RefreshAccessToken = RefreshAccessToken;