const base64url = require('base64url');
const crypto = require('crypto');
const Message = require('../../nodeOIDCMsg/src/oicMsg/message');

function addCodeChallenge(requestArgs, service, params) {
  let cvLen = null;
  let serviceContext = service.serviceContext;
  try {
    cvLen = serviceContext.config['code_challenge']['length'];
  } catch (err) {
    cvLen = 64;
  }

  let codeVerifier = unreserved(cvLen);
  let cv = encode(codeVerifier);

  let method = null;
  try {
    method = serviceContext.config['code_challenge']['method'];
  } catch (err) {
    method = 'sha256';
  }
  try {
    let m = crypto.createHmac(method, '');
    m.update(cv);
    let hv = m.digest('hex');
    var codeChallenge = decode(base64url.encode(encode(hv)));
  } catch (err) {
    throw new Error('PKCE Transformation method:{}');
  }

  let item = new Message({codeVerifier:codeVerifier, codeChallengeMethod: method});
  service.storeItem(item, 'pkce', requestArgs.state);

  requestArgs = Object.assign(requestArgs, {"code_challenge": codeChallenge,
  "code_challenge_method": method});

  return requestArgs;
}

function addCodeVerifier(requestArgs, service, params){
  let item = service.getItem(Message, 'pkce', params.state);
  requestArgs = Object.assign(requestArgs, {'code_verifier': item.claims['codeVerifier']});
  return requestArgs.code_verifier;
}

function putStateInPostArgs(requestArgs, params){
  let state = getStateParameter(requestArgs, params);
  let list = [requestArgs, {'state': state}];
  return list;
}

function unreserved(len) {
  let rdmString = '';
  for (; rdmString.length < len;
       rdmString += Math.random().toString(36).substr(2))
    ;
  return rdmString.substr(0, len);
}

function encode(str) {
  return 'b\'' + str;
}

function decode(str) {
  return str.substring(2);
}

module.exports.addCodeChallenge = addCodeChallenge;
module.exports.addCodeVerifier = addCodeVerifier;