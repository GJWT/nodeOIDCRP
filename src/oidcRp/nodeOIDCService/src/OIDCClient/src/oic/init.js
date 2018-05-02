const OAuth2Client = require('../oauth2/init').Client;
const OicFactory = require('../oic/service/service').OicFactory;

const DEFAULT_SERVICES = {
  'Authorization':{},
  'AccessToken':{},
  'RefreshAccessToken':{},
  'ProviderInfoDiscovery':{},
  'UserInfo':{},
  'Registration':{}
};

let WF_URL = "https://%s/.well-known/webfinger";
let OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";

module.exports.DEFAULT_SERVICES = DEFAULT_SERVICES;
module.exports.WF_URL = WF_URL;
module.exports.OIC_ISSUER = OIC_ISSUER;