const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const OAuth2ServiceAccessToken = require('../nodeOIDCService/src/OIDCClient/src/oauth2/service/accessToken').AccessToken;
const OICServiceUserInfo = require('../nodeOIDCService/src/OIDCClient/src/oic/service/userInfo').UserInfo;
const AccessTokenRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const TokenErrorResponse = require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').TokenErrorResponse;

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
        'expires_in': SINGLE_REQUIRED_INT
      };
      return args;
    }
  }

/**
 * UserSchema
 * @class
 * @constructor
 * @extends Message
 */
class UserSchema extends Message{
    constructor(){
        super();
        this.cParam = {
            firstName: SINGLE_OPTIONAL_STRING,
            headline: SINGLE_OPTIONAL_STRING,
            id: SINGLE_REQUIRED_STRING,
            lastName: SINGLE_OPTIONAL_STRING,
            siteStandardProfileRequest: SINGLE_OPTIONAL_JSON};
    }
}

/**
 * AccessToken
 * @class
 * @constructor
 * @extends Service
 */
class AccessToken extends OAuth2ServiceAccessToken {
    constructor({serviceContext, stateDb, clientAuthnMethod, conf}) {
      super({serviceContext, stateDb, clientAuthnMethod, conf});
      this.msgType = AccessTokenRequest;
      this.responseCls = AccessTokenResponse;
      this.errorMsg = TokenErrorResponse;
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
      this.responseCls = UserSchema;
    }
}

module.exports.UserInfo = UserInfo;
module.exports.AccessToken = AccessToken;
module.exports.AccessTokenResponse = AccessTokenResponse;
module.exports.UserSchema = UserSchema;