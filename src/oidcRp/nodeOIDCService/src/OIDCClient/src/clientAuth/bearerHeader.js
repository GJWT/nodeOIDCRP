/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds the request access token
 * information to the request header
 */

const ClientAuthnMethod = require('./clientAuth').ClientAuthnMethod;
const SINGLE_OPTIONAL_STRING = (String, false, null, null, false);

function findToken(request, tokenType, service, params){
  let token;
  if (request !== null){
    if (request.claims[tokenType]){
      token = request.claims[tokenType];
      delete request.claims[tokenType];
      request.cParam[tokenType] = SINGLE_OPTIONAL_STRING;
      return token;
    }
  }

  if (params){
    if (params['access_token']){
      return params['access_token'];
    }else{
      let arg = service.multipleExtendRequestArgs({}, params['state'], ['access_token'], ['auth_response', 'token_response', 'refresh_token_response']);
      return arg['access_token'];
    }
  }
}

/**
 * BearerHeader
 * @class
 * @constructor
 * @extends ClientAuthnMethod
 */
class BearerHeader extends ClientAuthnMethod {
  constructor() {
    super();
  }

  /**
   * Constructing the Authorization header. The value of
   * the Authorization header is "Bearer <access_token>".
   *
   * @param {?ResourceRequest} request Request class instance
   * @param {?serviceContext} serviceContext Client information
   * @param {?Object<string, string>} httpArgs HTTP header arguments
   * @return {!Object<string, string>} HTTP header arguments
   */
  construct(request = null, service = null, httpArgs = null, params) {
    let _accToken = '';
    let tokens = ['access_token', 'refresh_token'];
    for (var i = 0; i < tokens.length; i++){
      let _tokenType = tokens[i];
      _accToken = findToken(request, _tokenType, service, params);
      if (!_accToken){
        //throw new JSError('No access or refresh token available', 'KeyError');
      }

      const bearer = 'Bearer ' + _accToken;
      httpArgs = httpArgs || {};
      httpArgs.headers = httpArgs.headers || {};
      httpArgs.headers['Authorization'] = bearer;
      return httpArgs;
    }
  }
}

module.exports.BearerHeader = BearerHeader;