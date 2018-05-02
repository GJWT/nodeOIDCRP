/**
 * @fileoverview One of the six different client authentication / authorization
 * methods supported by OICCli that adds the corresponding authentication
 * information to the request.Clients that have registered a public key can 
 * sign a JWT using that key.
 */

const BearerBody = require('./bearerBody').BearerBody;
const BearerHeader = require('./bearerHeader').BearerHeader;
const ClientSecretBasic = require('./clientSecretBasic').ClientSecretBasic;
const ClientSecretJWT = require('./clientSecretJWT').ClientSecretJWT;
const ClientSecretPost = require('./clientSecretPost').ClientSecretPost;
const JWSAuthnMethod = require('./jwsAuth').JWSAuthnMethod;
const JWT_BEARER = require('../init.js').OICCli.JWT_BEARER;

/**
 * PrivateKeyJWT
 * @class
 * @private
 * @extends JWSAuthnMethod
 * Clients that have registered a public key can sign a JWT using that key.
 */
class PrivateKeyJWT extends JWSAuthnMethod {
  constructor() {
    super();
  }

  /**
   * @param {*} request Request class instance
   * @param {*} ci Client information
   * @param {*} requestArgs Request arguments
   * @param {*} httpArgs HTTP header arguments
   */
  chooseAlgorithm(entity, params) {
    entity = entity || 'privateKeyJwt';
    return JWSAuthnMethod.chooseAlgorithm(entity, params);
  }

  getSigningKey(algorithm, serviceContext) {
    serviceContext = serviceContext || null;
    alg = alg || algorithm;
    return serviceContext.keyjar.getSigningKey(alg2keyType(algorithm), '', alg);
  }
}

let CLIENT_AUTHN_METHOD = {
  'client_secret_basic': ClientSecretBasic,
  'client_secret_post': ClientSecretPost,
  'bearer_header': BearerHeader,
  'bearer_body': BearerBody,
  'client_secret_jwt': ClientSecretJWT,
  'private_key_jwt': PrivateKeyJWT,
};


function clientAuthFactory(authnMethod){
  try{
    return CLIENT_AUTHN_METHOD[authnMethod];
  }catch(err){
    console.log(err);
  }
}

let TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)];

module.exports.PrivateKeyJWT = PrivateKeyJWT;
module.exports.CLIENT_AUTHN_METHOD = CLIENT_AUTHN_METHOD;
module.exports.clientAuthFactory = clientAuthFactory;