const Service = require('../../service').Service;
const Message = require('../../../nodeOIDCMsg/src/oicMsg/message');
const ErrorResponse = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/responses').ErrorResponse;
const CheckIdRequest = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests').CheckIdRequest;

/**
 * CheckID
 * @class
 * @constructor
 * @extends Service
 */
class CheckID extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = CheckIdRequest;
    this.responseCls = Message;
    this.errorMsg = ErrorResponse;
    this.endpointName = '';
    this.synchronous = true;
    this.request = 'checkId';
    this.preConstruct = [this.oicPreConstruct];
  }

  oicPreConstruct(requestArgs, request, params) {
    requestArgs = request.multipleExtendRequestArgs(requestArgs, params['state'], ['id_token'], ['auth_response', 'token_response', 'refresh_token_response']);
    let list = [requestArgs, {}];
    return list;
  }
}

module.exports.CheckID = CheckID;