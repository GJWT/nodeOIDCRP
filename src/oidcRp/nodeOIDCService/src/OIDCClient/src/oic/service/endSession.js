const Service = require('../../service').Service;
const Message = require('../../../nodeOIDCMsg/src/oicMsg/message');
const ErrorResponse = require('../../../nodeOIDCMsg/src/oicMsg/oauth2/responses').ErrorResponse;
const EndSessionRequest = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests').EndSessionRequest;

/**
 * End Session
 * @class
 * @constructor
 * @extends Service
 */
class EndSession extends Service {
  constructor(serviceContext, stateDb, clientAuthnMethod) {
    super(serviceContext, stateDb, clientAuthnMethod);
    this.msgType = EndSessionRequest;
    this.responseCls = Message;
    this.errorMsg = ErrorResponse;
    this.endpointName = 'endSessionEndpoint';
    this.synchronous = true;
    this.request = 'endSession';
    this.preConstruct = [this.oicPreConstruct];
  }

  oicPreConstruct(requestArgs, request, params) {
    requestArgs = request.multipleExtendRequestArgs(requestArgs, params['state'], ['id_token'], ['auth_response', 'token_response', 'refresh_token_response']);
    let list = [requestArgs, {}];
    return list;
  }
}

module.exports.EndSession = EndSession;