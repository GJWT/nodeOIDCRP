var base64url = require('base64url');

/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds confidential client authentication
 * information to the request header such as a username and password.
 */

const ClientAuthnMethod = require('./clientAuth').ClientAuthnMethod;

/**
 * Clients that have received a client_secret value from the Authorization
 * Server, may authenticate with the Authorization Server in accordance with
 * Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
 * 
 * The upshot of this is to construct an Authorization header that has the
 * value 'Basic <token>' where <token> is username and password concatenated
 * together with a ':' in between and then URL safe base64 encoded.
 * 
 * @class
 * @constructor
 * @extends ClientAuthnMethod
 */
class ClientSecretBasic extends ClientAuthnMethod {
  constructor() {
    super();
  }

  /**
   * @param {?ResourceRequest} request Request class instance
   * @param {?serviceContext} serviceContext Client information
   * @param {?Object<string, string>} requestArgs Request arguments
   * @param {?Object<string, string>} httpArgs HTTP header arguments
   * @return {!Object<string, string>} HTTP header arguments
   */
  construct(request, service = null, httpArgs = {}, params) {
    httpArgs = httpArgs || {};
    httpArgs.headers = httpArgs.headers || {};
  
    let passwd = null;
    if (params && params.password) {
      passwd = params.password;
    } else {
      passwd = request && request.claims['client_secret'] ? request.claims['client_secret'] :
      service.serviceContext.clientId;
    }

    const user = params && params.user ? params.user : service.serviceContext.client_id;
    
    const credentials = {};
    credentials[user] = passwd;
    httpArgs.headers = httpArgs.headers || {};
    httpArgs.headers['Authorization'] = credentials
    
    if (request.claims && request.claims['client_secret'] ) {
      delete request.claims['client_secret'] ;
    }
    if (request.claims && request.claims['grant_type'] === 'authorization_code') {
      if (!request.claims['client_id']) {
        if (serviceContext.client_id) {
          request.client_id = serviceContext.client_id;
        } else {
          return;
        }
      }
    } else {
      const req = request.claims && request.claims['client_id'] ? request.claims['client_id'] : false
      if (!req && request.claims && request.claims['client_id']) {
        delete request.claims['client_id'];
      }
    }
    return httpArgs;
  }
}

module.exports.ClientSecretBasic = ClientSecretBasic;