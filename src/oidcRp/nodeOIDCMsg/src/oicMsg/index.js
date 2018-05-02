
module.exports = {
  verify: require('./verify'),
  sign: require('./sign'),
  JsonWebTokenError: require('../../lib/JsonWebTokenError'),
  NotBeforeError: require('../../lib/NotBeforeError'),
  TokenExpiredError: require('../../lib/TokenExpiredError'),
};