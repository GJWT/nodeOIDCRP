/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds access token information to the request 
 * body.
 */

const ClientAuthnMethod = require('./clientAuth').ClientAuthnMethod;

const SINGLE_OPTIONAL_STRING = (String, false, null, null, false);

function findToken(request, tokenType, service, params){
  let token;
  if (Object.keys(request.claims).length != 0){
    if (request.claims[tokenType]){
      token = request.claims[tokenType];
      delete request.claims[tokenType];
      request.cParam[tokenType] = SINGLE_OPTIONAL_STRING;
      return token;
    }
  }

  if (params && params['access_token']){
    return params['access_token'];
  }else{
    let arg = service.multipleExtendRequestArgs({}, params['state'], ['access_token'], ['auth_response', 'token_response', 'refresh_token_response']);
    return arg['access_token'];
  }
}

/**
 * BearerBody
 * @class
 * @constructor
 * @extends ClientAuthnMethod
 */
class BearerBody extends ClientAuthnMethod {
  constructor() {
    super();
  }

  /**
   * Will add access_token to the request if not present
   *
   * @param {?ResourceRequest} request Request class instance
   * @param {?serviceContext} serviceContext Client information
   * @param {?Object.<string, string>} requestArgs Request arguments
   * @param {?Object.<string, string>} httpArgs HTTP header arguments
   */
  construct(request, service, httpArgs, params) {
    let _accToken = '';
    let tokens = ['access_token', 'refresh_token'];
    for (var i = 0; i < tokens.length; i++){
      let _tokenType = tokens[i];
      _accToken = findToken(request, _tokenType, service, params);
      if (_accToken){
        break;
      }
    }
    if (!_accToken){
      console.log('No access or refresh token available', 'KeyError');
    }else{
      request['access_token'] = _accToken;
    }

    const list = [httpArgs, request];
    return list;
  }

  /**
   * Pick out the access token, either in HTTP_Authorization header 
   * or in request body.
   * 
   * @param {*} req The request
   * @param {*} authn The value of the Authorization header
   * @return An access token
   */
  bearerAuth(req, authn) {
    try {
      return req.access_token;
    } catch (err) {
      if (!authn.startsWith('Bearer ')){
        console.log('Not a bearer token', 'ValueError');
      }
      return authn.substring(7, authn.length - 1);
    }
  }
}

module.exports.BearerBody = BearerBody;