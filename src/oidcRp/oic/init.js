const OAuth2Client = require('../oauth2/init').Client;
let service = require('../nodeOIDCService/src/OIDCClient/src/oic/service/service');

const DEFAULT_SERVICES = {
    'Authorization':{}, 'AccessToken':{}, 'RefreshAccessToken':{}, 'ProviderInfoDiscovery':{},
    'UserInfo':{}, 'Registration':{}
};

const MAX_AUTHENTICATION_AGE = 86400;

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

let PROVIDER2PREFERENCE = {};

for (let i = 0; i < Object.keys(PREFERENCE2PROVIDER).length; i++) {
  let k = Object.keys(PREFERENCE2PROVIDER)[i];
  let v = PREFERENCE2PROVIDER[k];
  PROVIDER2PREFERENCE[k] = v;
};

const PROVIDER_DEFAULT = {
  'token_endpoint_auth_method': 'client_secret_basic',
  'id_token_signed_response_alg': 'RS256',
};

/**
 * Client
 * @class
 * @constructor
 * @extends OAuth2Client
 */
class RP extends OAuth2Client {
  /**
   * @param {DB} stateDb A DB class instance
   * @param {Object} caCerts Certificates used to verify HTTPS certificates
   * @param {function} clientAuthnFactory A factory function
   * @param {KeyJar} keyJar KeyJar class instance
   * @param {bool} verifySsl True or false
   * @param {Object<string, string>} config Configuration information passed on to the 
   * ServiceContext initialization
   * @param {Object} clientCert Client certificate
   * @param {HttpLib} httpLib An httpLib class instance
   * @param {Object<string, Object>} services A dictionary mapping from service names to instances
   * @param {function} serviceFactory An oidc or oauth2 factory function 
   */
  constructor({stateDb, caCerts=null, clientAuthnFactory=null, keyJar=null, verifySsl=true, config=null, clientCert=null,
      httpLib=null, services=null, serviceFactory=null}) {
    let srvs = services || DEFAULT_SERVICES;
    serviceFactory = serviceFactory || service.OicFactory    
    super({stateDb:stateDb, caCerts:caCerts, clientAuthnFactory:clientAuthnFactory, keyJar:keyJar, verifySsl:verifySsl, config:config, clientCert:clientCert, httpLib:httpLib, services:srvs, serviceFactory:serviceFactory});
  }

  /**
   * @param {Message} userInfo A Message sub class instance
   * @param {UserInfo} service Possibly an instance of the ServiceUserInfo class
   * @param {function} callback A callback function that can be used to fetch things
   * @return Updated user info instance
   */
  fetchDistributedClaims(userInfo, service, callback){
      try{
        let csrc = userinfo['_claims_sources'];
      }catch(err){
        console.log(err);
      }
      for (var i = 0; i < Object.keys(csrc).length; i++){
        var csrcKey = Object.keys(csrc)[i];
        var val = csrc[csrcKey];

        if (spec.indexOf('access_token') !== -1){
          let uInfo = this.serviceRequest(service, spec['endpoint'], 'GET', spec['access_token']);
        }else{
          if (callback){
            uInfo = this.serviceRequest(service, spec['endpoint', 'GET', callback(spec['endpoint'])]);
          }else{
            uInfo = this.serviceRequest(service, spec['endpoint'], 'GET');
          }
        }

        let claims = []
        for (var i = 0; i < Object.keys(userInfo['_claim_names']).length; i++){
          if (src === csrc){
          claims.push(value);
          }
        }

        if (claims != Object.keys(uinfo)){
          console.log("Claims from claim source doesn't match what's in the userinfo");
        }

        for (var i = 0; i < Object.keys(info); i++){
          let key = Object.keys(info)[i];
          let val = info[key];
          userInfo[key] = val;
        }
        
      }
      return userInfo;
  }

  static getProviderDefault() {
    return PROVIDER_DEFAULT;
  }
}

module.exports.RP = RP;