const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const OAuth2ServiceAccessToken = require('../nodeOIDCService/src/OIDCClient/src/oauth2/service/accessToken').AccessToken;
const OICServiceUserInfo = require('../nodeOIDCService/src/OIDCClient/src/oic/service/userInfo').UserInfo;

/**
 * AccessTokenResponse
 * @class
 * @constructor
 * @extends Message
 */
class AccessTokenResponse extends Message {
    constructor(args) {
      super();
      this.cParam = {
        'access_token': SINGLE_REQUIRED_STRING,
        'token_type': SINGLE_REQUIRED_STRING,
        'scope': SINGLE_OPTIONAL_STRING
      };
      return args;
    }
  }

/**
 * AccessToken
 * @class
 * @constructor
 * @extends Service
 */
class AccessToken extends OAuth2ServiceAccessToken {
    constructor() {
      super();
      this.msgType = AccessTokenRequest;
      this.responseCls = AccessTokenResponse;
      this.errorMsg = TokenErrorResponse;
      this.responseBodyType = 'urlEncoded';
    }
}

/**
 * UserInfo
 * @class
 * @constructor
 */
class UserInfo extends OICServiceUserInfo {
    constructor() {
      super();
      this.responseCls = Message;
      this.errorMsg = ErrorResponse;
      this.defaultAuthnMethod = '';
      this.httpMethod = 'GET';
    }
}

module.exports.UserInfo = UserInfo;
module.exports.AccessToken = AccessToken;
module.exports.AccessTokenResponse = AccessTokenResponse;