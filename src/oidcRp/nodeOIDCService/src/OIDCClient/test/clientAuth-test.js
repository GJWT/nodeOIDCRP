const assert = require('chai').assert;
const validServiceContext = require('../src/clientAuth/clientAuth').validServiceContext;

describe('Test valid client info', function() {
  let now = 123456;

  it('test valid client info works', function() {
    assert.isTrue(validServiceContext({}, now));
    assert.isTrue(
      validServiceContext({'client_id': 'test', 'client_secret': 'secret'}, now));
    assert.isTrue(validServiceContext({'client_secret_expires_at': 0}, now));
    assert.isTrue(validServiceContext({'client_secret_expires_at': 123460}, now));
    assert.isTrue(validServiceContext(
      {'client_id': 'test', 'client_secret_expires_at': 123460}, now));
    assert.isFalse(validServiceContext({'client_secret_expires_at': 1}, now));
    assert.isFalse(validServiceContext(
      {'client_id': 'test', 'client_secret_expires_at': 123455}, now));
  });
});