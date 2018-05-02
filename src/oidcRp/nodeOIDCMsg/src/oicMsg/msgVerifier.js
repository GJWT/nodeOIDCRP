const JsonWebTokenError = require('./lib/JsonWebTokenError');
const NotBeforeError = require('./lib/NotBeforeError');
const TokenExpiredError = require('./lib/TokenExpiredError');
const timespan = require('./lib/timespan');
const xtend = require('xtend');

/**
 * @fileoverview Handles the common verification functionality for all message
 * protocols
 */

/**
 * MessageVerifier
 * @class
 * @constructor
 */
class MessageVerifier {
  constructor() {}

  /**
   * Check message signature and other option values
   *
   * @param jwtString The signed Jwt string
   * @param secretOrPublicKey A string or buffer containing either the secret
   for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param options Other inputs that are not part of the payload, for ex :
   'algorithm'
   * @param callback If a callback is supplied, function acts asynchronously.
   The callback is called with the decoded payload if the signature is valid and
   optional expiration, audience, or issuer are valid. If not, it will be called
   with the error.
   * @throws JsonWebToken error if options does not match expected claims
   * @memberof MessageVerifier.prototype
   */
  verifyOptions(jwtString, secretOrPublicKey, options, callback) {
    if ((typeof options === 'function') && !callback) {
      callback = options;
      options = {};
    }

    if (!options) {
      options = {};
    }

    // clone this object since we are going to mutate it.
    options = xtend(options);
    let done;

    if (callback) {
      done = callback;
    } else {
      done = (err, data) => {
        if (err) throw err;
        return data;
      };
    }

    if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
      return done(new JsonWebTokenError('clockTimestamp must be a number'));
    }

    const clockTimestamp =
        options.clockTimestamp || Math.floor(Date.now() / 1000);

    if (!jwtString) {
      return done(new JsonWebTokenError('jwt must be provided'));
    }

    if (typeof jwtString !== 'string') {
      return done(new JsonWebTokenError('jwt must be a string'));
    }

    const parts = jwtString.split('.');

    if (parts.length !== 3) {
      return done(new JsonWebTokenError('jwt malformed'));
    }

    const hasSignature = parts[2].trim() !== '';


    if (!hasSignature && secretOrPublicKey) {
      return done(new JsonWebTokenError('jwt signature is required'));
    }

    if (hasSignature && !secretOrPublicKey) {
      return done(
          new JsonWebTokenError('secret or public key must be provided'));
    }

    if (options && !hasSignature && !options.algorithms) {
      options.algorithms = ['none'];
    }

    if (options && !options.algorithms) {
      options.algorithms =
          ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
              ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY') ?
          ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'] :
          ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY') ?
          ['RS256', 'RS384', 'RS512'] :
          ['HS256', 'HS384', 'HS512'];
    }
    return done(null);
  }

  /**
   * Verify if payload options matches the expected claim values
   * @param payload Could be an object literal, buffer or string, containing
   claims. Please note that exp is only set if the payload is an object literal.
   * @param tokenProfile Contains the token properties, required, optional and
   verification claims
   * @param callback If a callback is supplied, function acts asynchronously.
   The callback is called with the decoded payload if the signature is valid and
   optional expiration, audience, or issuer are valid. If not, it will be called
   with the error.
   * @throws JsonWebToken error if options does not match expected claims
   * @memberof MessageVerifier.prototype
   */
  verifyPayload(payload, tokenProfile, otherOptions, callback) {
    const options = tokenProfile.getVerificationClaims();
    let done;

    if (callback) {
      done = callback;
    } else {
      done = (err, data) => {
        if (err) throw err;
        return data;
      };
    }

    if (!otherOptions) {
      otherOptions = {};
    }
    const clockTimestamp =
        otherOptions.clockTimestamp || Math.floor(Date.now() / 1000);

    if (typeof payload.nbf !== 'undefined' && !otherOptions.ignoreNotBefore) {
      if (typeof payload.nbf !== 'number') {
        return done(new JsonWebTokenError('invalid nbf value'));
      }
      if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
        return done(
            new NotBeforeError('jwt not active', new Date(payload.nbf * 1000)));
      }
    }

    if (typeof payload.exp !== 'undefined' && !otherOptions.ignoreExpiration) {
      if (typeof payload.exp !== 'number') {
        return done(new JsonWebTokenError('invalid exp value'));
      }
      if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
        return done(
            new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
      }
    }

    Object.keys(tokenProfile.claimsForVerification).forEach(key => {
      const claim = tokenProfile.claimsForVerification[key];
      if (options[key] && key != 'maxAge' && key != 'clockTolerance' &&
          key != 'aud') {
        if (payload[claim] != options[key]) {
          return done(new JsonWebTokenError(
              `jwt option invalid. expected: ${options[key]}`));
        }
      }
    });

    if (options && options.aud) {
      const audiences =
          Array.isArray(options.audience) ? options.aud : [options.aud];
      const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

      const match = target.some(
          targetAudience => audiences.some(
              audience => audience instanceof RegExp ?
                  audience.test(targetAudience) :
                  audience === targetAudience));

      if (!match)
        return done(new JsonWebTokenError(
            `jwt audience invalid. expected: ${audiences.join(' or ')}`));
    }

    /*
    if (otherOptions.issuer) {
      const invalid_issuer =
          (typeof otherOptions.issuer === 'string' && payload.iss !==
    otherOptions.issuer) || (Array.isArray(otherOptions.issuer) &&
    otherOptions.issuer.indexOf(payload.iss) === -1);

      if (invalid_issuer) {
        return done(new JsonWebTokenError('jwt issuer invalid. expected: ' +
    otherOptions.issuer));
      }
    }

    if (otherOptions.subject) {
      if (payload.sub !== otherOptions.subject) {
        return done(new JsonWebTokenError('jwt subject invalid. expected: ' +
    otherOptions.subject));
      }
    }*/


    if (otherOptions && otherOptions.jwtid) {
      if (payload.jti !== otherOptions.jwtid) {
        return done(new JsonWebTokenError(
            `jwt jwtid invalid. expected: ${otherOptions.jwtid}`));
      }
    }

    if (options && options.maxAge) {
      if (typeof payload.iat !== 'number') {
        return done(
            new JsonWebTokenError('iat required when maxAge is specified'));
      }

      const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
      if (typeof maxAgeTimestamp === 'undefined') {
        return done(new JsonWebTokenError(
            '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
      if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError(
            'maxAge exceeded', new Date(maxAgeTimestamp * 1000)));
      }
    }
    return payload;
  }
}

module.exports = MessageVerifier;