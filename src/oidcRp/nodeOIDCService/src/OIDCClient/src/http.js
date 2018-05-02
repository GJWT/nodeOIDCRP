class HTTPLib {
  constructor() {}

  init(caCerts, verifySsl, keyJar, clientCert) {
    this.keyJar = keyJar || new KeyJar(verifySsl);
    this.requestArgs = {'allowRedirects': false};
    this.cookieJar = FileCookieJar();
    this.caCerts = caCerts;

    if (caCerts) {
      if (verifySsl == false) {
        console.log('Conflict : caCerts defined, but verifySsl is False');
      }
      this.requestArgs['verify'] = caCerts;
    } else if (verifySsl) {
      this.reuestArgs['verify'] = true;
    } else {
      this.requestArgs['verify'] = false;
    }

    this.events = null;
    this.reqCallback = null;
    if (clientCert) {
      this.requestArgs['cert'] = clientCert;
    }
  }

  cookies() {
    let cookiesDict = {};
    for (let i = 0; i < this.cookieJar.cookies.items().length; i++) {
      let a = this.cookieJar.cookies.items()[i];
      for (let j = 0; j < a.items.length; i++) {
        let b = a.items[j];
        for (let i = 0; i < b.values().length; i++) {
          let cookie = b.values()[i];
          cookieDict[cookie.name] = cookie.value;
        }
      }
    }
    return cookieDict;
  }

  call(url, method, params) {
    method = method || 'GET';
    var params = copy.copy(this.requestArgs);
    if (params) {
      params.update(params);
    }
    if (this.cookieJar) {
      params['cookies'] = this.cookies();
    }
    if (this.reqCallback != null) {
      params = this.reqCallback(method, url, params);
    }
    try {
      r = requests.request(method, url, params);
    } catch (err) {
      console.log('Http request failed');
    }

    if (this.events != null) {
      this.events.store('HTTP response', r, url);
    }

    try {
      let cookie = r.headers['setCookie'];
      try {
        this.setCookie(this.cookieJar, SimpleCookie(cookie));
      } catch (err) {
        console.log(err);
      }
    } catch (err) {
      console.log(err);
    }
    return r;
  }

  send(url, method, params) {
    return this(url, method, params);
  }

  loadCookiesFromFile(fileName, ignoreDiscard, ignoreExpires) {
    ignoreDiscard = ignoreDiscard || false;
    ignoreExpires = ignoreExpires || false;
    this.cookiesJar.load(fileName, ignoreDiscard, ignoreExpires);
  }

  saveCookiesToFile(fileName, ignoreDiscard, ignoreExpires) {
    ignoreDiscard = ignoreDiscard || false;
    ignoreExpires = ignoreExpires || false;
    this.cookieJar.save(fileName, ignoreDiscard, ignoreExpires);
  }
}

module.exports.HTTPLib = HTTPLib;