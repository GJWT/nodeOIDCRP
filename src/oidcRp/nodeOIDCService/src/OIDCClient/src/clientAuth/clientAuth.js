/**
 * @fileoverview Adds authentication information to a request and validates
 * client info.
 */

const OICCli = require('../init.js').OICCli;
const utf8 = require('utf8');
const base64url = require('base64url');

/**
 * ClientAuthnMethod
 * Basic Client Authentication Method class.
 * @class 
 * @constructor
 */
class ClientAuthnMethod {
  constructor() {}

  construct(params) {
    throw new Error('Unsupported Operation Exception');
  }
}

function validServiceContext(serviceContext, when) {
  let eta = serviceContext['client_secret_expires_at'] || 0;
  let now = when || Date.now();
  if (eta !== 0 && eta < now) {
    return false;
  }
  return true;
}

module.exports.ClientAuthnMethod = ClientAuthnMethod;
module.exports.validServiceContext = validServiceContext;