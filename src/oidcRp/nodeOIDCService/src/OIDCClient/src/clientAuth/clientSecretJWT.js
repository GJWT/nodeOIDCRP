/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds the corresponding authentication
 * information to the request. Clients that have received a client_secret value from the Authorization
 * Server can create a signed JWT using an HMAC SHA algorithm, such as
 * HMAC SHA-256.
 * 
 * The HMAC (Hash-based Message Authentication Code) is calculated using the
 * bytes of the UTF-8 representation of the client_secret as the shared key.
 */

const JWSAuthnMethod = require('./jwsAuth').JWSAuthnMethod;

/**
 * ClientSecretJWT
 * @class
 * @constructor
 * @extends JWSAuthnMethod
 */
class ClientSecretJWT extends JWSAuthnMethod {
  constructor() {
    super();
  }

  /**
   * @param {string} entity Class instance name
   */
  chooseAlgorithm(entity, params) {
    entity = entity || 'clientSecretJwt';
    return JWSAuthnMethod.chooseAlgorithm(entity, params);
  }

  /**
   * Fetch key for signing
   * @param {string} algorithm Type of algorithm
   * @param {serviceContext} serviceContext Type of serviceContext
   */
  getSigningKey(algorithm, serviceContext) {
    alg = alg || algorithm;
    return serviceContext.keyjar.getSigningKey(alg2keyType(algorithm), '', alg);
  }
}

module.exports.ClientSecretJWT = ClientSecretJWT;