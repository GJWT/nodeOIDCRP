const crypto = require('crypto');
crypto.createHmac('sha256', '');
/**
 * OICCli
 * @class
 * @constructor
 */
class OICCli {
  constructor() {
    this.OIDCONF_PATTERN = '%s/.well-known/openid-configuration';

    this.CC_METHOD = {
      'S256': crypto.createHmac('sha256', ''),
      'S384': crypto.createHmac('sha256', ''),
      'S512': crypto.createHmac('sha256', ''),
    }

                     this.DEF_SIGN_ALG = {
      'id_token': 'RS256',
      'userinfo': 'RS256',
      'request_object': 'RS256',
      'client_secret_jwt': 'HS256',
      'private_key_jwt': 'RS256'
    }

                                         this.HTTP_ARGS =
        ['headers', 'redirections', 'connection_type'];

    this.JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    this.SAML2_BEARER_GRANT_TYPE =
        'urn:ietf:params:oauth:grant-type:saml2-bearer';
  }

  /**
   * Returns a string of random ascii characters or digits
   * @param {int} size The length of the string
   */
  rndStr(size) {
    return Math.random().toString(36).substring(size);
  }

  /**
   * Returns a string of random ascii characters, digits and unreserved
   * characters
   * @param {int} size The length of the string
   */
  unreserved() {};

  sanitize(str) {
    return str;
  }
}

module.exports.OICCli = OICCli;