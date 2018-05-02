
const ClientAuthnMethod = require('./clientAuth').ClientAuthnMethod;

/**
 * @fileoverview Base class for client authentication methods that uses signed Json
 * Web Tokens.
 */

/**
 * JWSAuthnMethod
 * @class
 * @constructor
 * @extends ClientAuthnMethod
 * Base class for client authentication methods that uses signed Json
 * Web Tokens.
 */
class JWSAuthnMethod extends ClientAuthnMethod {
  constructor() {
    super();
  }

  /**
   * Pick signing algorithm
   * 
   * @param {string} entity Signing context
   * @return Name of a signing algorithm
   */
  chooseAlgorithm(entity, params) {
    try {
      algorithm = params['algorithm'];
    } catch (err) {
      algorithm = DEF_SIGN_ALG[entity];
    }

    if (!algorithm) {
      console.log('Missing algorithm specification');
    }
    return algorithm;
  }

  /**
   * Pick signing key based on signing algorithm to be used
   * 
   * @param {string} algorithm Signing algorithm
   * @param {serviceContext} serviceContext serviceContext instance
   * @return A key
   */
  getSigningKey(algorithm, serviceContext) {
    alg = alg || algorithm;
    return serviceContext.keyjar.getSigningKey(alg2keyType(algorithm), alg);
  }

  /**
   * Pick a key that matches a given key ID and signing algorithm.
   * 
   * @param {string} kid KeyID
   * @param {string} algorithm Signing algorithm
   * @param {serviceContext} serviceContext serviceContext instance
   * @return A matching key
   */
  getKeyByKid(kid, algorithm, serviceContext) {
    let key = serviceContext.keyjar.getKeyByKid(kid);
    if (key) {
      ktype = alg2keyType(algorithm);
      try {
        assert.deepEqual(key.kty, ktype);
      } catch (err) {
        console.log('Wrong key type');
        //throw new JSError('Wrong key type', 'NoMatchingKey');
      }
      return key;
    } else {
      console.log('No key with kid');
      //throw new JSError('No key with kid: ' + kid);
    }
  }

  /**
   * Constructs a client assertion and signs it with a key.
   * The request is modified as a side effect.
   * 
   * @param {ResourceRequest} request The request
   * @param {serviceContext} serviceContext serviceContext instance
   * @param {Object<string, string>} httpArgs HTTP arguments
   * @return Constructed HTTP arguments, in this cases none
   */
  construct(request, service, httpArgs, params) {
    if (params.indexOf('clientAssertion') !== -1) {
      request['clientAssertionType'] = params['clientAssertion'];
      if (params.indexOf('clientAssertionType') !== -1) {
        request['clientAssertionType'] = params['clientAssertionType'];
      } else {
        request['clientAssertionType'] = JWTBEARER;
      }
    } else if (request.indexOf('clientAssertion') !== -1) {
      if (request.indexOf('clientAssertionType') !== -1) {
        request['clientAssertionType'] = JWT_BEARER;
      }
    } else {
      algorithm = null;
      let serviceContext = service.serviceContext;
      let tokenInfo = ['token', 'refresh'];
      if (tokenInfo.indexOf(params['authEndpoint'])) {
        try {
          algorithm = serviceContext.registrationInfo['tokenEndpointAuthSigningAlg'];
        } catch (err) {
          return;
        }
        audience = serviceContext.providerInfo['tokenEndpoint'];
      } else {
        audience = serviceContext.providerInfo['issuer'];
      }

      if (!algorithm) {
        algorithm = this.chooseAlgorithm(params);
      }
      ktype = alg2keyType(algorithm);
      let signingKey = null;
      try {
        if (params.indexOf('kid')) {
          signingKey = [this.getKeyByKid(params['kid'], algorithm, serviceContext)];
        } else if (serviceContext.kid['sig'].indexOf(ktype)) {
          try {
            signingKey =
                this.getKeyByKid(serviceContext.kid['sig'][ktype], algorithm, serviceContext);
          } catch (err) {
            signingKey = this.getSigningKey(algorithm, serviceContext);
          }
        } else {
          signingKey = this.getSigningKey(algorithm, serviceContext);
        }
      } catch (err) {
        console.log('No Matching Key');
      }

      try {
        args = {'lifetime': params['lifetime']};
      } catch (err) {
        args = {};
      }
      request['clientAssertion'] =
          assertionJwt(serviceContext.clientId, signingKey, audience, algorithm, args);
      request['clientAssertionType'] = JWTBEARER;
    }
    try {
      delete request['clientSecret'];
    } catch (err) {
      console.log('KeyError');
    }
    if (!request.cParam['clientId'][VREQUIRED]) {
      try {
        delete request['clientId'];
      } catch (err) {
        console.log('KeyError');
      }
    }
    return {};
  }
}

module.exports.JWSAuthnMethod = JWSAuthnMethod;