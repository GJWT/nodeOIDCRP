/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds the corresponding authentication
 * information to the request.  * Clients that have received a client_secret value from the Authorization
  * Server, authenticate with the Authorization Server in accordance with
  * Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
  * the request body.
  *
  * These means putting both client_secret and client_id in the request body.
 */

 /**
  * ClientSecretPost
  * @class
  * @constructor
  */
const ClientSecretBasic = require('./clientSecretBasic').ClientSecretBasic;

/**
 * ClientSecretPost
 * @class
 * @constructor
 * @extends ClientSecretBasic
 */
class ClientSecretPost extends ClientSecretBasic {
  constructor() {
    super();
  }

  /** 
   * I MUST have a client_secret, there are 3 possible places
   * where I can find it. In the request, as an argument in http_args
   * or among the client information.
   * @param {*} request Request class instance
   * @param {*} requestArgs: Request arguments
   * @param {*} httpArgs: HTTP arguments
   */
  construct(request, service, httpArgs, params) {
    let serviceContext = service.serviceContext;
    if (Object.keys(request).indexOf('client_secret')) {
      try {
        request['client_secret'] = params['client_secret'];
        if (httpArgs && httpArgs['client_secret']){
          delete httpArgs['client_secret'];
        }
      } catch (err) {
        if (serviceContext.client_secret) {
          request['client_secret'] = serviceContext.client_secret;
        } else {
          console.log('Missing client secret');
        }
      }
    }

    request['client_id'] = serviceContext.client_id;
    let list = [httpArgs, request];
    return list;
  }
}

module.exports.ClientSecretPost = ClientSecretPost;