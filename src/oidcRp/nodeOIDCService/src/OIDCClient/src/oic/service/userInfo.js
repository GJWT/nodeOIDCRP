const Service = require('../../service').Service;
const Message = require('../../../nodeOIDCMsg/src/oicMsg/message');
const OpenIDSchema = require('../../../nodeOIDCMsg/src/oicMsg/oic/init').OpenIDSchema;
const OIDCResponses = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses');

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

function carryState(requestArgs, req, params){
  let list = [requestArgs, {state: getStateParameter(requestArgs, params)}];
  return list;
}

/**
 * UserInfo
 * @class
 * @constructor
 */
class UserInfo extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod, conf) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = Message;
    this.responseCls = OpenIDSchema;
    this.errorMsg = OIDCResponses.ResponseMessage;
    this.endpointName = 'userinfo_endpoint';
    this.synchronous = true;
    this.request = 'userinfo';
    this.defaultAuthnMethod = 'bearer_header';
    this.httpMethod = 'GET';
    this.preConstruct = [this.oicPreConstruct, carryState];
    this.endpoint = 'https://example.org/op/userInfo';
  }
  
  oicPreConstruct(requestArgs, service, params) {
    if (requestArgs === null) {
      requestArgs = {};
    }

    if (Object.keys(requestArgs).indexOf('access_token') !== -1) {
      return;
    } else {
      requestArgs = service.multipleExtendRequestArgs(requestArgs, params['state'], ['access_token'], ['auth_response', 'token_response', 'refresh_token_response']);
    }
    let list = [requestArgs, {}];
    return list;
  }

  postParseResponse(response, params){
    _args = this.multipleExtendRequestArgs({}, params['state'], ['verified_id_token'], ['auth_response', 'token_response', 'refresh_token_response']);
    try{
      _sub = _args['verified_id_token']['sub'];
      if (response['sub'] !== _sub){
        //throw new JSError('Incorrect sub value', 'ValueError');
      }
    }catch(err){
      //throw new JSError('Can not verify value on sub', 'KeyError');
    }

    _csrc = response['_claim_sources'];
    for (var i = 0; i < Object.keys(_csrc).length; i++){
      let _csrcKey = Object.keys(_csrc)[i];
      let spec = _csrc[_csrcKey];
      if (Object.keys(spec).indexOf('JWT')){
        let values = [];
        let aggregatedClaims = new Message().fromJWT(spec['JWT'].encode('utf-8'), this.serviceContext.keyJar);
        for (var i = 0; i < Object.keys(response['_claim_names']).length; i++){
          let value = Object.keys(response['_claim_names'])[i];
          let src = response['_claim_names'][value];
          if (src === csrc){
            values.push(value);
          }
        }

        for (var i = 0; i < Object.keys(claims).length; i++){
          let key = Object.keys(claims)[i];
          response[key] = aggregatedClaims[key];
        }
      }
    }

    this.storeItem(response, 'user_info', params['state']);
    return response;
  }
}

module.exports.UserInfo = UserInfo;