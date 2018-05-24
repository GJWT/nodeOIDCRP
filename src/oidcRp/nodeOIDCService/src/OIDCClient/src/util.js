const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const urlParse = require('url-parse');

const JSON_ENCODED = 'application/json';
const URL_ENCODED = 'application/x-www-form-urlencoded';
const DEFAULT_POST_CONTENT_TYPE = URL_ENCODED;

const PAIRS = {
  'port': 'port_specified',
  'domain': 'domain_specified',
  'path': 'path_specified'
};

const ATTRS = {
  'version': null,
  'name': '',
  'value': null,
  'port': null,
  'port_specified': false,
  'domain': '',
  'domain_specified': false,
  'domain_initial_dot': false,
  'path': '',
  'path_specified': false,
  'secure': false,
  'expires': null,
  'discard': true,
  'comment': null,
  'comment_url': null,
  'rest': '',
  'rfc2109': true
};

const SORT_ORDER = {
  'RS': 0,
  'ES': 1,
  'HS': 2,
  'PS': 3,
  'no': 4
};

/**
 * Util
 * @class
 * @constructor
 */
class Util {
  constructor() {}

  /**
   * Create the information pieces necessary for sending a request.
   * Depending on whether the request is done using GET or POST the request
   * is placed in different places and serialized into different formats.
   * @param {string} uri The URL pointing to where the request should be sent
   * @param {string} method Which method that should be used to send the request
   * @param {Message} req The request as a :py:class:`oicmsg.message.Message` instance
   * @param {string} contentType Which content type to use for the body
   * @param {bool} accept Whether an Accept header should be added to the HTTP request
   */
  getOrPost(uri, method, req, contentType, accept, params) {
    contentType = contentType || DEFAULT_POST_CONTENT_TYPE;
    accept = accept || null;
    let resp = {};
    let reqActions = ['GET', 'DELETE'];
    let respActions = ['POST', 'PUT'];
    if (reqActions.indexOf(method) !== -1) {
      if (Object.keys(req).length != 0) {
        let reqCpy = req;
        let parts = urlParse(uri);
        let scheme = parts[0];
        let netloc = parts[1];
        let path = parts[2];
        let params = parts[3];
        let query = parts[4];
        let fragment = parts[5];
        //let comp = urlSplit(uri.toString());
        if (query) {
          reqCpy = this.parseQs(query);
        }
        query = encodeURIComponent(reqCpy);
        resp['uri'] = uri + '?' + this.urlUnsplit(reqCpy);
      } else {
        resp['uri'] = uri;
      }
    } else if (respActions.indexOf(method) !== -1) {
      resp['uri'] = uri;
      if (contentType === URL_ENCODED) {
        resp['body'] = new Message().toUrlEncoded(req);
      } else if (contentType === JSON_ENCODED) {
        resp['body'] = req;
      } else {
        console.log('Unsupported content type');
      }

      let headerExt = {'Content-Type': contentType};
      if (accept) {
        let headerExt = {'Accept': accept};
      }
      if (Object.keys(params).indexOf('headers') !== -1) {
        params['headers'] = Object.assign(headerExt, params['headers']);
      } else {
        params['headers'] = headerExt;
      }
      params['headers'] = headerExt;

      resp['params'] = params;
    } else {
      throw new Error('Unsupported HTTP Method')
    }
    return resp;
  }

  urlUnsplit(dict){
    var str = [];
    for (var i = 0; i < Object.keys(dict).length; i++){
      var key = Object.keys(dict)[i];
      var val = dict[key];
      str.push(encodeURIComponent(key) + "=" + encodeURIComponent(val));
      
    }
    return str.join("&");
  }

  /**
   * PLaces a cookie (a cookielib.Cookie based on a set-cookie header
   * line) in the cookie jar.
   * Always chose the shortest expires time.
   * @param cookiejar
   * @param kaka Cookie
   */
  setCookie(cookieJar, kaka) {
    for (let i = 0; i < Object.keys(kaka); i++) {
      let cookieName = Object.keys(kaka)[i];
      let morsel = kaka[cookieName];
      let stdAttr = ATTR.copy();
      stdAttr['name'] = cookieName;
      tmp = morsel.codedValue;
      if (temp.startsWith('') && tmp.endsWith('')) {
        stdAttr['value'] = tmp.substring(1, -1);
      } else {
        stdAttr['value'] = tmp;
      }

      stdAttr['version'] = 0;
      attr = '';
      // Copy attributes that have values
      try {
        for (let i = 0; i < Object.keys(morsel).length; i++) {
          if (ATTRS.indexOf(attr) !== -1) {
            if (morsel[attr]) {
              if (attr === 'expires') {
                stdAttr[attr] = this.getOrPost.http2Time(morsel[attr]);
              } else {
                stdAttr[attr] = morsel[attr];
              }
            }
          } else if (attr === 'maxAge') {
            if (morsel[attr]) {
              stdAttr['expires'] = this.http2Time(morsel[attr]);
            }
          }
        }
      } catch (err) {
        console.log(err);
        continue;
      }

      for (let i = 0; i < Object.keys(PAIRS); i++) {
        if (stdAttr[att]) {
          stdAttr[spec] = true;
        }
      }

      if (stdAttr['domain'] && stdAttr['domain'].startsWith('.')) {
        stdAttr['domainInitialDot'] = true;
      }

      if (morsel['max-age'] === 0) {
        try {
          this.cookieJar.clear(
              std_attr['domain'], std_attr['path'], std_attr['name']);
        } catch (err) {
          console.log(err);
        }
      } else {
        if (stdAttr.indexOf('version') !== -1) {
          try {
            stdAttr['version'] = stdAttr['version'].split(',')[0];
          } catch (err) {
            console.log(err);
          }
        }
        let newCookie = new Cookie(stdAttr);
        this.cookieJar.setCookie(newCookie);
      }
    }
  }

  getResponseBodyType(response){
    if (response.headers['content-type']){
      var cType = response.headers['content-type'];
    }

    var bodyType = '';
    if (this.matchTo("application/json", cType) || this.matchTo("application/jrd+json", cType)){
      bodyType = 'json';
    }else if (this.matchTo("application/jwt", cType)){
      bodyType = 'jwt';
    }else if (this.matchTo(URL_ENCODED, cType)){
      bodyType = 'urlencoded';
    }
    return bodyType;
  }

  matchTo(val, vlist) {
    if (typeof vlist == 'string') {
      if (vlist.startsWith(val)) {
        return true;
      }
    } else {
      for (let i = 0; i < vlist.length; i++) {
        let v = vlist[i];
        if (v.startsWith(val)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * @param {Object<string, object>} reqresp Class instance with attributes: ['status', 'text',
       'headers', 'url']
   * @param {string} bodyType If information returned in the body part
   */
  verifyHeader(reqResp, bodyType) {
    let cType;
    if (reqResp.headers['content-type']){
      cType = reqResp.headers['content-type'];
    }else{
      if (bodyType) {
        return bodyType;
      } else {
        return 'txt';
      }
    }

    if (bodyType === '') {
      if (this.matchTo('application/json', cType)) {
        bodyType = 'json';
      } else if (this.matchTo('application/jwt', cType)) {
        bodyType = 'jwt';
      } else if (this.matchTo(URL_ENCODED, cType)) {
        bodyType = 'urlEncoded';
      } else {
        bodyType = 'txt';
      }
    } else if (bodyType === 'json') {
      if (this.matchTo('application/json', cType)) {
        bodyType = 'jwt';
      } else if (this.matchTo('application/jwt', cType)) {
        bodyType = 'jwt';
      } else {
        console.log('Wrong Content Type');
      }
    } else if (bodyType === 'jwt') {
      if (!(this.matchTo('application/jwt', cType))) {
        console.log('Wrong Content Type');
      }
    } else if (bodyType === 'urlEncoded') {
      if (!(this.matchTo(DEFAULT_POST_CONTENT_TYPE, _ctype))) {
        if (!(this.matchTo('text/plain', cType))) {
          console.log('Wrong Content Type');
        }
      }
    } else {
      console.log('Unknown return format ' + bodyType);
    }
    console.log('Got body type: ' + bodyType);
    return bodyType;
  };

  sortSignAlg(alg1, alg2) {
    if (SORT_ORDER(alg1.substring(0, 2)) < SORT_ORDER[alg2.substring(0, 2)]) {
      return -1;
    } else if (
        SORT_ORDER(alg1.substring(0, 2)) < SORT_ORDER[alg2.substring(0, 2)]) {
      return 1;
    } else {
      if (alg1 < alg2) {
        return -1;
      } else if (alg1 > alg2) {
        return 1;
      } else {
        return 0;
      }
    }
  }
}

function getHttpBody(req, contentType){
  let resp = {}
  if (contentType === URL_ENCODED) {
    //return req.toUrlEncoded(req.claims);
    return req.claims;
  } else if (contentType === JSON_ENCODED) {
    return req.claims;
    //return req.toJSON(req.claims);
  } else {
    console.log('Unsupported content type');
  }
}

function parseQs(dict){
  var keys = Object.keys(dict);
  var parsedDict = {};
  for (var i = 0; i < keys.length; i++){
    var key = Object.keys(dict)[i];
    var val = dict[key];
    parsedDict[key] = [val]
  }
  return parsedDict;
}

function addPath(url, path){
  if (url.endsWith('/')){
    if (path.startsWith('/')){
      return url + path.substring(1, path.length);
    }else{
      return url + path;
    }
  }else{
    if (path.startsWith('/')){
      return url + path;
    }else{
      return url + "/" + path;
    }
  }
}

module.exports.Util = Util;
module.exports.URL_ENCODED = URL_ENCODED;
module.exports.JSON_ENCODED = JSON_ENCODED;
module.exports.getHttpBody = getHttpBody;
module.exports.parseQs = parseQs;
module.exports.addPath = addPath;