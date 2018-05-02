const OAuth2ProviderInfoDiscovery =
    require('../../oauth2/service/providerInfoDiscovery').ProviderInfoDiscovery;
//const ProviderConfigurationResponse =
//    require('../../oauth2/service/service').ProviderConfigurationResponse;
const ProviderConfigurationResponse =
    require('../../../nodeOIDCMsg/src/oicMsg/oic/responses').ProviderConfigurationResponse;
const Message = require('../../../nodeOIDCMsg/src/oicMsg/message');
const ResponseMessage = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses').ResponseMessage;
const OIDCResponses = require('../../../nodeOIDCMsg/src/oicMsg/oic/responses');
const OIDC_CONF_PATTERN = '/.well-known/openid-configuration';
const RegistrationRequest = require('../../../nodeOIDCMsg/src/oicMsg/oic/requests').RegistrationRequest;
//const PREFERENCE2PROVIDER = require('../../../src/oic/service/service').PREFERENCE2PROVIDER;

const PREFERENCE2PROVIDER = {
  'require_signed_request_object': 'request_object_algs_supported',
  'request_object_signing_alg': 'request_object_signing_alg_values_supported',
  'request_object_encryption_alg':
      'request_object_encryption_alg_values_supported',
  'request_object_encryption_enc':
      'request_object_encryption_enc_values_supported',
  'userinfo_signed_response_alg': 'userinfo_signing_alg_values_supported',
  'userinfo_encrypted_response_alg': 'userinfo_encryption_alg_values_supported',
  'userinfo_encrypted_response_enc': 'userinfo_encryption_enc_values_supported',
  'id_token_signed_response_alg': 'id_token_signing_alg_values_supported',
  'id_token_encrypted_response_alg': 'id_token_encryption_alg_values_supported',
  'id_token_encrypted_response_enc': 'id_token_encryption_enc_values_supported',
  'default_acr_values': 'acr_values_supported',
  'subject_type': 'subject_types_supported',
  'token_endpoint_auth_method': 'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg':
      'token_endpoint_auth_signing_alg_values_supported',
  'response_types': 'response_types_supported',
  'grant_types': 'grant_types_supported'
};

const PROVIDER_DEFAULT = {
  "token_endpoint_auth_method": "client_secret_basic",
  "id_token_signed_response_alg": "RS256",
}

/**
 * ProviderInfoDiscovery
 * @class
 * @constructor
 * @extends OAuth2ProviderInfoDiscovery
 */
class ProviderInfoDiscovery extends OAuth2ProviderInfoDiscovery {
  constructor(serviceContext, stateDb, clientAuthnMethod=null, conf=null) {
    super(serviceContext, stateDb, clientAuthnMethod, conf);
    this.msgType = Message;
    this.responseCls = ProviderConfigurationResponse;
    this.errorMsg = OIDCResponses.ResponseMessage;
  }

  updateServiceContextProviderInfo(resp, params){
    this.updateServiceContext(resp, params);
    this.matchPreferences(resp, this.serviceContext.issuer);
    if (Object.keys(this.conf).indexOf('pre_load_keys') && this.conf['pre_load_keys']){
      let jwks = this.serviceContext.keyJar.exportJwksAsJSON({issuer:resp['issuer']});
    }
  }

  getEndpoint(params){
    let iss = null;
    if (this.serviceContext && this.serviceContext.issuer){
      iss = this.serviceContext.issuer;
    }else{
      iss = this.endpoint;
    }
    if (iss.endsWith('/')){
      let splitIssuer = issu.split('');
      let reversedIssuer = splitIssuer.reverse();
      let issuer = reversedIssuer.join('');
      return issuer + OIDC_CONF_PATTERN;
    }else{
      return iss + OIDC_CONF_PATTERN;
    }
  }

  /**
   * Match the clients preferences against what the provider can do.
   * This is to prepare for later client registration and or what 
   * functionality the client actually will use. In the client 
   * configuration the client preferences are expressed. These are
   * then compared with the Provider Configuration information. If 
   * the Provider has left some claims out, defaults specified in the
   * standard will be used.
   * 
   * @param {*} resp Provider configuration response if available
   * @param {serviceContext} serviceContext 'serviceContext' instance
   * @param {*} state State information
   */
  matchPreferences(pcr=null, issuer=null) {
    if (!pcr) {
      pcr = this.serviceContext.providerInfo;
    }

    let regreq = new RegistrationRequest();

    let vals = null;
    for (let i = 0; i < Object.keys(PREFERENCE2PROVIDER).length; i++) {
      let pref = Object.keys(PREFERENCE2PROVIDER)[i];
      let prov = PREFERENCE2PROVIDER[pref];
      if (this.serviceContext.client_prefs[pref]){
        vals = this.serviceContext.client_prefs[pref];
      } else {
        continue;
      }
      let pVals = null;
      try {
        pVals = pcr.claims[prov];
      } catch (err) {
        try {
          pVals = PROVIDER_DEFAULT[pref];
        } catch (err) {
          console.log('No info from provider');

          if (this.serviceContext.strictOnPreferences) {
            console.log('OP couldnt match preference');
          } else {
            pVals = vals;
          }
        }
      }

      if (vals instanceof String) {
        if (pvals.indexOf(vals) !== -1) {
          this.serviceContext.behavior[pref] = vals;
        }
      } else {
        let vTyp = regreq.cParam[pref];

        if (vTyp[0] instanceof Array) {
          this.serviceContext.behavior[pref] = [];
          for (let i = 0; i < vals.length; i++) {
            let val = vals[i];
            if (pVals.indexOf(val) !== -1) {
              this.serviceContext.behavior[pref].push(val);
            }
          }
        } else {
          for (let i = 0; i < vals.length; i++) {
            let val = vals[i];
            if (pVals.indexOf(val) !== -1) {
              this.serviceContext.behavior[pref] = val;
              break;
            }
          }
        }
      }

      if (Object.keys(this.serviceContext.behavior).indexOf(pref) === -1) {
        console.log('OP couldnt match preference');
      }
    }

    for (let i = 0; i < Object.keys(this.serviceContext.client_prefs).length; i++) {
      let key = Object.keys(this.serviceContext.client_prefs)[i];
      let val = this.serviceContext.client_prefs[key];
      if (Object.keys(this.serviceContext.behavior).indexOf(key) !== -1) {
        continue;
      }

      try {
        let vTyp = regreq.cParam[key];
        if (vTyp[0] instanceof Array) {
          console.log('pass')
        } else if (val instanceof Array && !(val instanceof String)) {
          val = val[0];
        }
      } catch (err) {
        console.log(err);
      }

      if (Object.keys(PREFERENCE2PROVIDER).indexOf(key) === -1) {
        this.serviceContext.behavior[key] = val;
      }
    }
  }
}

module.exports.ProviderInfoDiscovery = ProviderInfoDiscovery;