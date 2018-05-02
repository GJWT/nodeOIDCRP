const OAuth2RefreshAccessToken =
    require('../../oauth2/service/refreshAccessToken').RefreshAccessToken;
const oicMsgOic = require('../../../nodeOIDCMsg/src/oicMsg/oic/init');
const RefreshAccessTokenRequest = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests').RefreshAccessTokenRequest;
const AccessTokenResponse = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses').AccessTokenResponse;
const TokenErrorResponse = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses').TokenErrorResponse;

/**
 * RefreshAccessToken
 * @class
 * @constructor
 * @extends OAuth2RefreshAccessToken
 */
class RefreshAccessToken extends OAuth2RefreshAccessToken {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = RefreshAccessTokenRequest;
    this.responseCls = AccessTokenResponse;
    this.errorMsg = TokenErrorResponse;
  }
}

module.exports.RefreshAccessToken = RefreshAccessToken;