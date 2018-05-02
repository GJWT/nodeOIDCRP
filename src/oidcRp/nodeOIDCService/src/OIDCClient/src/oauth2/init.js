const CLIENT_AUTHN_METHOD =
    require('../clientAuth/privateKeyJWT').CLIENT_AUTHN_METHOD;
const serviceContext = require('../serviceContext.js');
const Factory = require('../oauth2/service/service').Factory;
const HTTPLib = require('../http').HTTPLib;
const KeyJar = require('../../nodeOIDCMsg/src/oicMsg/keystore/KeyJar');
const OicCliError = require('../exception').OicCliError;
const Service = require('../service');

const DEFAULT_SERVICES = {
  'Authorization':{},
  'AccessToken':{},
  'RefreshAccessToken':{},
  'ProviderInfoDiscovery':{}
};

module.exports.DEFAULT_SERVICES = DEFAULT_SERVICES;