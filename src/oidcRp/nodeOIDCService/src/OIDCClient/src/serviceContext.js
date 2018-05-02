const State = require('./state.js').State;
const crypto = require('crypto');
const KeyJar = require('../nodeOIDCMsg/src/oicMsg/keystore/KeyJar');
const assert = require('chai').assert;

/**
 * @fileoverview This class keeps information that a client needs to be
 * able to talk to a server. Some of this information comes from 
 * configuration and some from dynamic provider info discovery or client
 * registration. But information is also picked up during the 
 * conversation with a server.
 */

/** 
 * serviceContext
 * @class
 * @constructor
 */
class ServiceContext {
  /**
   * This class keeps information that a client needs to be able to talk
   * to a server. Some of this information comes from configuration and some
   * from dynamic provider info discovery or client registration.
   * But information is also picked up during the conversation with a server.
   * @param {KeyJar} keyjar OIDCMsg KeyJar instance that contains the RP signing and encyrpting keys
   * @param {Object<string, string>} config Client configuration
   * @param {Object<string, string>} params Other attributes that might be needed
   */
  constructor(keyjar, config, params) {
    this.clientSecret = [this.getClientSecret, this.setClientSecret];
    keyjar = keyjar || null;
    config = config || null;
    this.keyjar = keyjar || new KeyJar();
    this.providerInfo = {};
    this.registrationResponse = {};
    this.kid = {'sig': {}, 'enc': {}};

    this.config = config || {};

    this.baseUrl = '';
    this.requestDir = '';
    this.allow = {};
    this.behavior = {};
    this.clientPreferences = {};
    this.cId = '';
    this.cSecret = '';
    this.issuer = '';

    let serviceContext = ['client_id', 'issuer', 'client_secret', 'base_url', 'requests_dir'];
    let defaultVal = '';

    if (params){
      for (var i = 0; i < Object.keys(params).length; i++){
        let key = Object.keys(params)[i];
        let val = params[key];
        this[key] = val;
      }
    }

    for (let i = 0; i < serviceContext.length; i++) {
      let attr = serviceContext[i];
      if (attr === 'client_id') {
        this.client_id = this.config[attr] || defaultVal;
      } else if (attr === 'issuer') {
        this.issuer = this.config[attr] || defaultVal;
      } else if (attr === 'client_secret') {
        this.client_secret = this.config[attr] || defaultVal;
      } else if (attr === 'base_url') {
        this.base_url = this.config[attr] || defaultVal;
      } else if (attr === 'requests_dir') {
        this.request_dir = this.config[attr] || defaultVal;
      }
    };

    let providerInfo = ['allow', 'client_preferences', 'behaviour', 'provider_info'];
    defaultVal = {};
    for (let i = 0; i < providerInfo.length; i++) {
      let attr = providerInfo[i];
      if (attr === 'allow') {
        this.allow = this.config[attr] || defaultVal;
      } else if (attr === 'client_preferences') {
        this.client_prefs = this.config[attr] || defaultVal;
      } else if (attr === 'behaviour') {
        this.behavior = this.config[attr] || defaultVal;
      } else if (attr === 'provider_info') {
        this.provider_info = this.config[attr] || defaultVal;
      }
    };

    // TODO: Make sure the requests_dir path exists. if not, then make it

    try {
      this.redirectUris = this.config['redirect_uris'];
    } catch (err) {
      this.redirectUris = [null];
    }

    try {
      this.callback = this.config['callback'];
    } catch (err) {
      this.callback = {}
    }

    if (config && Object.keys(config).indexOf('keydefs') !== -1) {
      this.keyjar = this.buildKeyJar(config['keydefs'], this.keyjar)[1];
    }

    return this;
  }

  getClientSecret() {
    return this.client_secret;
  }

  setClientSecret(val) {
    if (!val) {
      this.client_secret;
    } else {
      this.client_secret = val;
      // client uses it for signing
      // Server might also use it for signing which means the
      // client uses it for verifying server signatures
      if (this.keyjar == null) {
        this.keyjar = new KeyJar();
      }
      this.keyjar.addSymmetric('', val.toString());
    }
  }

  /**
   *  Need to generate a redirect_uri path that is unique for a OP/RP combo
      This is to counter the mix-up attack.
   * @param {string} path Leading path
   * @return A list of one unique URL
   */
  generateRequestUris(path) {
    let m = crypto.createHmac('sha256', '');
    try {
      m.update(this.providerInfo['issuer']);
    } catch (error) {
      m.update(this.issuer);
    }
    m.update(this.baseUrl);
    if (!path.startsWith('/')){
      return [this.baseUrl + '/' + path+ '/' +  m.digest('hex')];
    }else{
      return [this.baseUrl + path + '/' + m.digest('hex')];
    }
  }

  /**
   *  A 1<->1 map is maintained between a URL pointing to a file and
   * the name of the file in the file system.
   * 
   * As an example if the base_url is 'https://example.com' and a jwks_uri
   * is 'https://example.com/jwks_uri.json' then the filename of the
   * corresponding file on the local filesystem would be 'jwks_uri'.
   * Relative to the directory from which the RP instance is run.
   * 
   * @param {*} webName 
   */
  filenameFromWebName(webName) {
    if (webName.startsWith(this.baseUrl) == false){
      //throw new Error('', 'ValueError');

    }
    let name = webName.substring(this.baseUrl.length, webName.length);
    if (name.startsWith('/')) {
      return name.substring(1, name.length);
    } else {
      let splitName = name.split('/');
      return splitName[splitName.length - 1];
    }
  }
}

module.exports.ServiceContext = ServiceContext;