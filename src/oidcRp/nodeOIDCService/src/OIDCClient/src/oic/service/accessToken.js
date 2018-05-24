const OAuth2AccessToken =
    require('../../oauth2/service/accessToken').AccessToken;
const OIDCRequests = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests');
const OIDCResponses = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses');

/**
 * AccessToken
 * @class
 * @constructor
 * @extends OAuth2AccessToken
 */
class AccessToken extends OAuth2AccessToken {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = OIDCRequests.AccessTokenRequest;
    this.responseCls = OIDCResponses.AccessTokenResponse;
    this.errorMsg = OIDCResponses.ResponseMessage;
    this.endpoint = 'https://example.org/op/token';
  }
  
  updateServiceContext(resp, state='', params){
    if (resp['verified_id_token']){
    let _idt = resp['verified_id_token'];
    let nonceState = null;
    try{
      nonceState = this.getStateByNonce(_idt['nonce'])
    }catch(err){
      //throw new Error('Unknown nonce value');
      //throw new JSError('Unknown nonce value', 'ValueError');      
    }
    if (nonceState != state){
      //throw new Error('Someone has messed with nonce');
      //throw new JSError('Someone has messed with nonce', 'ParameterError');
    }
  }
    this.storeItem(resp, 'token_response', state);    
  }
}

module.exports.AccessToken = AccessToken;