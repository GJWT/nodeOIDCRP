var expect = require('chai').expect;
var atob = require('atob');
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('encoding', function() {
  var clockTimestamp = 1000000000;

  function b64_to_utf8(str) {
    return decodeURIComponent(escape(atob(str)));
  }

  it('should properly encode the token (utf8)', function() {
    var expected = 'José';

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'name': expected,
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('shhhh')
        .then(function(signedJWT) {
          var decoded_name =
              JSON.parse(b64_to_utf8(signedJWT.split('.')[1])).name;
          expect(decoded_name).to.equal(expected);
        });
  });

  it('should properly encode the token (binary)', function() {
    var expected = 'José';

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims(
        {
          'name': expected,
          'aud': 'audience',
          'nbf': clockTimestamp + 2,
          'exp': clockTimestamp + 3
        },
        {encoding: 'binary'});
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('shhhh', {encoding: 'binary'})
        .then(function(signedJWT) {
          var decoded_name = JSON.parse(atob(signedJWT.split('.')[1])).name;
          expect(decoded_name).to.equal(expected);
        });
  });

  it('should return the same result when decoding', function() {
    var username = '測試';

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'username': username,
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });

    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('shhhh')
        .then(function(signedJWT) {
          var payload = basicIdToken.fromJWT(
              signedJWT, 'shhhh', {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp});
          expect(payload.username).to.equal(username);
        });

  });

});