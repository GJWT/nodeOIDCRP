const WF_URL = 'https://%s/.well-known/webfinger';
const OIC_ISSUER = 'http://openid.net/specs/connect/1.0/issuer';

/**
** @fileoverview * A string of any other type is interpreted as a URI either the form of scheme
* "://" authority path-abempty [ "?" query ] [ "*" fragment ] or authority
* path-abempty [ "?" query ] [ "*" fragment ] per RFC 3986 [RFC3986] and is
* normalized according to the following rules:
*
* If the user input Identifier does not have an RFC 3986 [RFC3986] scheme
* portion, the string is interpreted as [userinfo "@"] host [":" port]
* path-abempty [ "?" query ] [ "*" fragment ] per RFC 3986 [RFC3986].
* If the userinfo component is present and all of the path component, query
* component, and port component are empty, the acct scheme is assumed. In this
* case, the normalized URI is formed by prefixing acct: to the string as the
* scheme. Per the 'acct' URI Scheme [I‑D.ietf‑appsawg‑acct‑uri], if there is an
* at-sign character ('@') in the userinfo component, it needs to be
* percent-encoded as described in RFC 3986 [RFC3986].
* For all other inputs without a scheme portion, the https scheme is assumed,
* and the normalized URI is formed by prefixing https:// to the string as the
* scheme.
* If the resulting URI contains a fragment portion, it MUST be stripped off
* together with the fragment delimiter character "*".
* The WebFinger [I‑D.ietf‑appsawg‑webfinger] Resource in this case is the
* resulting URI, and the WebFinger Host is the authority component.
*
* Note: Since the definition of authority in RFC 3986 [RFC3986] is
* [ userinfo "@" ] host [ ":" port ], it is legal to have a user input
* identifier like userinfo@host:port, e.g., alice@example.com:8080.
 */

/**
 * URINormalizer
 * @class
 * @constructor
 */
class URINormalizer {
  constructor() {}

  hasScheme(inp) {
    if (inp && inp.indexOf('://') !== -1) {
      return true;
    } else if (inp){
      let authority = inp.replace('/', '*').replace('?', '*').split('*')[0];

      if (authority.indexOf(':') !== -1) {
        let hostOrPort = authority.split(':')[1];
        if (hostOrPort.match(/^\d+$/)) {
          return false;
        }
      } else {
        return false;
      }
    }
    return true;
  }

  acctSchemeAssumed(inp) {
    if (inp.indexOf('@') !== -1) {
      let list = inp.split('@');
      let host = list[list.length - 1];
      return !(
          (host.indexOf(':') !== -1) || (host.indexOf('/') !== -1) ||
          (host.indexOf('?') !== -1));
    } else {
      return false;
    }
  }

  normalize(inp) {
    if (this.hasScheme(inp)) {
    } else if (this.acctSchemeAssumed(inp)) {
      inp = 'acct:' + inp;
    } else {
      inp = 'https://' + inp;
    }
    return inp.split('#')[0];
  }
}

module.exports.URINormalizer = URINormalizer;
module.exports.OIC_ISSUER = OIC_ISSUER;