const assert = require('chai').assert;
const AuthorizationRequest =
require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse =
require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
let urlParse = require('url-parse');
let util = require('../src/util').Util;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const JSON_ENCODED = 'application/json';
var AccessTokenRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;

function queryStringCompare(queryStr1, queryStr2){
  return new Message().fromUrlEncoded(queryStr1) == new Message().fromUrlEncoded(queryStr2);
}

function urlCompare(firstUrl, secondUrl){
  const url1 = urlParse(firstUrl);
  const url2 = urlParse(secondUrl);

  if (url1.scheme !== url2.scheme){
    return false;
  }
  if (url1.netloc !== url2.netloc){
    return false;
  }
  if (url1.path !== url2.path){
    return false;
  }
  if (!queryStringCompare(url1.query, url2.query)){
    return false;
  }
  if (!queryStringCompare(url1.fragment, url2.fragment)){
    return false;
  }
  return true;
}

describe('Test get', function() {
  it('should work', function() {
    let uri = 'https://localhost:8092/authorization';
    let method = 'GET';
    let values = {'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
      'redirect_uri':
                  'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
      'response_type': 'code',
      'client_id': 'u\'ok8tx7ulVlNV',
      'scope': 'openid profile email address phone'};
    let request = new AuthorizationRequest(values);
    let resp = util.prototype.getOrPost(uri, method, request);
    assert.deepEqual(Object.keys(resp), ['uri']);
    urlCompare(resp['uri'], 'https://localhost:8092/authorization?state=urn%3Auuid%3A92d81fb3-72e8-4e6c-9173-c360b782148a&redirect_uri=https%3A%2F%2Flocalhost%3A8666%2F919D3F697FDAAF138124B83E09ECB0B7&response_type=code&client_id=ok8tx7ulVlNV&scope=openid+profile+email+address+phone');    
  });
});

describe('Test method post', function() {
  it('should work', function() {
    let uri = 'https://localhost:8092/token';
    let method = 'POST';
    let values = {
      'redirect_uri':
            'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
      'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl',
      'grant_type': 'authorization_code'};
    let request = new AccessTokenRequest(values);
    let params = {'scope': '',
      'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
      'authn_method': 'client_secret_basic', 'key': [],
      'headers': {'Authorization': 'Basic aGVqOmhvcHA='}};

    let resp = util.prototype.getOrPost(uri, method, request, JSON_ENCODED, null, params);
    assert.deepEqual(Object.keys(resp), ['uri', 'body', 'params']);
    assert.deepEqual(resp['body'], request);
    assert.deepEqual(resp['params'], {
      'scope': '',
      'state':
            'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
      'authn_method': 'client_secret_basic', 'key': [],
      'headers': {'Content-Type':'application/json',
        'Authorization': 'Basic aGVqOmhvcHA='}});
  });
});

describe('Test match to', function() {
  let str0 = 'abc';
  let str1 = '123';
  let str2 = 'a1b2c3';
  it('should work', function() {
    let testString = str0 + str1 + str2;
    assert.isTrue(util.prototype.matchTo(str0, testString));
    assert.isFalse(util.prototype.matchTo(str2, testString));

    let lstStr = ['test_0', testString, 'test_1', str1];
    assert.isTrue(util.prototype.matchTo(str0, lstStr));
    assert.isTrue(util.prototype.matchTo(str1, lstStr));
    assert.isFalse(util.prototype.matchTo(str2, lstStr));
  });
});

describe('Test Unsupported', function() {
  it('should work', function() {
    let uri = 'https://localhost:8092/token';
    let method = 'UNSUPPORTED';
    let values = {
      'redirect_uri':
                'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
      'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl/YLBBZDB9wefNExQlLDUIIDM2rT2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
      'grant_type': 'authorization_code'};
    let request = new AccessTokenRequest(values);
    let params = {'scope': '',
      'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
      'authn_method': 'client_secret_basic', 'key': [],
      'headers': {
        'Authorization': 'Basic b2s4dHg3dWxWbE5WOjdlNzUyZDU1MTc0NzA0NzQzYjZiZWJkYjU4ZjU5YWU3MmFlMGM5NDM4YTY1ZmU0N2IxMDA3OTM1'}
    };
    try{
      let resp = util.prototype.getOrPost(uri, method, request, JSON_ENCODED, null, params);
      console.log(resp);
      console.log('RESPRESRSERSERSERSERSERSERSERSERSRRESRRESRRESRRESP');
    }catch(err){
      assert.isNotNull(err);
      console.log(err);
      console.log('ERRRERERERERERERERERERERERRERERER');
    }
  });
});