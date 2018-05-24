const assert = require('chai').assert;
const WebFinger = require('../src/webFinger/webFinger').WebFinger;
const OIC_ISSUER = require('../src/webFinger/uriNormalizer').OIC_ISSUER;
const URINormalizer = require('../src/webFinger/uriNormalizer').URINormalizer;
const LINK = require('../src/webFinger/link').LINK;
const JRD = require('../src/webFinger/link').JRD;

const EXAMPLE = {
  'example.com': 'https://example.com',
  'example.com:8080': 'https://example.com:8080',
  'example.com/path': 'https://example.com/path',
  'example.com?query': 'https://example.com?query',
  'example.com#fragment': 'https://example.com',
  'example.com:8080/path?query#fragment': 'https://example.com:8080/path?query',
  'http://example.com': 'http://example.com',
  'http://example.com:8080': 'http://example.com:8080',
  'http://example.com/path': 'http://example.com/path',
  'http://example.com?query': 'http://example.com?query',
  'http://example.com#fragment': 'http://example.com',
  'http://example.com:8080/path?query#fragment':
      'http://example.com:8080/path?query',
  'nov@example.com': 'acct:nov@example.com',
  'nov@example.com:8080': 'https://nov@example.com:8080',
  'nov@example.com/path': 'https://nov@example.com/path',
  'nov@example.com?query': 'https://nov@example.com?query',
  'nov@example.com#fragment': 'acct:nov@example.com',
  'nov@example.com:8080/path?query#fragment':
      'https://nov@example.com:8080/path?query',
  'acct:nov@matake.jp': 'acct:nov@matake.jp',
  'acct:nov@example.com:8080': 'acct:nov@example.com:8080',
  'acct:nov@example.com/path': 'acct:nov@example.com/path',
  'acct:nov@example.com?query': 'acct:nov@example.com?query',
  'acct:nov@example.com#fragment': 'acct:nov@example.com',
  'acct:nov@example.com:8080/path?query#fragment':
      'acct:nov@example.com:8080/path?query',
  'mailto:nov@matake.jp': 'mailto:nov@matake.jp',
  'mailto:nov@example.com:8080': 'mailto:nov@example.com:8080',
  'mailto:nov@example.com/path': 'mailto:nov@example.com/path',
  'mailto:nov@example.com?query': 'mailto:nov@example.com?query',
  'mailto:nov@example.com#fragment': 'mailto:nov@example.com',
  'mailto:nov@example.com:8080/path?query#fragment':
      'mailto:nov@example.com:8080/path?query',
  'localhost': 'https://localhost',
  'localhost:8080': 'https://localhost:8080',
  'localhost/path': 'https://localhost/path',
  'localhost?query': 'https://localhost?query',
  'localhost#fragment': 'https://localhost',
  'localhost/path?query#fragment': 'https://localhost/path?query',
  'nov@localhost': 'acct:nov@localhost',
  'nov@localhost:8080': 'https://nov@localhost:8080',
  'nov@localhost/path': 'https://nov@localhost/path',
  'nov@localhost?query': 'https://nov@localhost?query',
  'nov@localhost#fragment': 'acct:nov@localhost',
  'nov@localhost/path?query#fragment': 'https://nov@localhost/path?query',
  'tel:+810312345678': 'tel:+810312345678',
  'device:192.168.2.1': 'device:192.168.2.1',
  'device:192.168.2.1:8080': 'device:192.168.2.1:8080',
  'device:192.168.2.1/path': 'device:192.168.2.1/path',
  'device:192.168.2.1?query': 'device:192.168.2.1?query',
  'device:192.168.2.1#fragment': 'device:192.168.2.1',
  'device:192.168.2.1/path?query#fragment': 'device:192.168.2.1/path?query',
};

describe('URINormalizer test', function() {
  it('Test normalize', function() {
    for (let i = 0; i < Object.keys(EXAMPLE).length; i++) {
      let key = Object.keys(EXAMPLE)[i];
      let val = EXAMPLE[key];
      let uriNormalizer = new URINormalizer();
      let res = uriNormalizer.normalize(key);
      assert.deepEqual(res, val);
    }
  });
});

describe('LINK tests', function() {
  it('Test link1', function() {
    let link = new LINK({
      'rel': 'http://webfinger.net/rel/avatar',
      'type': 'image/jpeg',
      'href': 'http://www.example.com/~bob/bob.jpg'
    });
    assert.deepEqual(link['rel'], 'http://webfinger.net/rel/avatar');
    assert.deepEqual(link['type'], 'image/jpeg');
    assert.deepEqual(link['href'], 'http://www.example.com/~bob/bob.jpg');
  });

  it('Test link2', function() {
    let link = new LINK({
      'rel': 'blog',
      'type': 'text/html',
      'href': 'http://blogs.example.com/bob/',
      'titles': {
        'en-us': 'The Magical World of Bob',
        'fr': 'Le monde magique de Bob'
      }
    });
    assert.deepEqual(link['rel'], 'blog');
    assert.deepEqual(link['type'], 'text/html');
    assert.deepEqual(link['href'], 'http://blogs.example.com/bob/');
    assert.deepEqual(Object.keys(link['titles']).length, 2);
  });

  it('Test link2', function() {
    let link = new LINK({
      'rel': 'http://webfinger.net/rel/profile-page',
      'href': 'http://www.example.com/~bob/'
    });
    assert.deepEqual(link['rel'], 'http://webfinger.net/rel/profile-page');
    assert.deepEqual(link['href'], 'http://www.example.com/~bob/');
    assert.deepEqual(Object.keys(link).length, 2);
  });
});

describe('JRD tests', function() {
  it('Test jrd', function() {
    let link = new JRD({
      'subject': 'acct:bob@example.com',
      'aliases': ['http://www.example.com/~bob/'],
      'properties': {'http://example.com/ns/role/': 'employee'},
      'links': [
        new LINK({
          'rel': 'http://webfinger.net/rel/avatar',
          'type': 'image/jpeg',
          'href': 'http://www.example.com/~bob/bob.jpg'
        }),
        new LINK({
          'rel': 'http://webfinger.net/rel/profile-page',
          'href': 'http://www.example.com/~bob/'
        })
      ]
    });
    assert.deepEqual(
      Object.keys(link), ['subject', 'aliases', 'properties', 'links']);
  });

  it('Test jrd2', function() {
    let ex0 = {
      'subject': 'acct:bob@example.com',
      'aliases': ['http://www.example.com/~bob/'],
      'properties': {'http://example.com/ns/role/': 'employee'},
      'links': [
        {
          'rel': 'http://webfinger.net/rel/avatar',
          'type': 'image/jpeg',
          'href': 'http://www.example.com/~bob/bob.jpg'
        },
        {
          'rel': 'http://webfinger.net/rel/profile-page',
          'href': 'http://www.example.com/~bob/'
        },
        {
          'rel': 'blog',
          'type': 'text/html',
          'href': 'http://blogs.example.com/bob/',
          'titles': {
            'en-us': 'The Magical World of Bob',
            'fr': 'Le monde magique de Bob'
          }
        },
        {'rel': 'vcard', 'href': 'https://www.example.com/~bob/bob.vcf'}
      ]
    };

    let jrd = new JRD();
    let jrd0 = JRD.fromJSON(JSON.stringify(ex0));
    for (let i = 0; i < jrd0['links'].length; i++) {
      let link = jrd0['links'][i];
      if (link['rel'] == 'blog') {
        assert.deepEqual(link['href'], 'http://blogs.example.com/bob/');
        break;
      }
    }
  });

  it('Test extra member response', function() {
    let ex = {
      'subject': 'acct:bob@example.com',
      'aliases': ['http://www.example.com/~bob/'],
      'properties': {'http://example.com/ns/role/': 'employee'},
      'dummy': 'foo',
      'links': [{
        'rel': 'http://webfinger.net/rel/avatar',
        'type': 'image/jpeg',
        'href': 'http://www.example.com/~bob/bob.jpg'
      }]
    };

    let resp = JRD.fromJSON(JSON.stringify(ex));
    assert.deepEqual(resp['dummy'], 'foo');
  });
});

describe('webfinger tests', function() {
  let wf;
  beforeEach(function() {
    wf = new WebFinger();
  });

  it('Test query device', function() {
    let query = wf.query('device:p1.example.com');
    assert.deepEqual(
      query,
      'https://p1.example.com/.well-known/webfinger?resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');
  });

  it('Test query device', function() {
    let query = wf.query(
      'acct:bob@example.com',
      ['http://webfinger.net/rel/profile-page', 'vcard']);
    assert.deepEqual(
      query,
      'https://example.com/.well-known/webfinger?resource=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard');
  });

  it('Test query acct', function() {
    wf.init(OIC_ISSUER);
    let query = wf.query('acct:carol@example.com');
    assert.deepEqual(
      query,
      'https://example.com/.well-known/webfinger?resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');
  });
});