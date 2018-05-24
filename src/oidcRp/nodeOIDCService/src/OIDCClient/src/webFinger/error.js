// OAuth2 - init

class ExpiredToken extends OicCliError {
  constructor() {
    super();
  }
}

// Oiccli src - Error
class Exception {}

class AuthenticationFailure extends Exception {
  constructor() {
    super();
  }
}

class NoMatchingKey extends Exception {
  constructor() {
    super();
  }
}

class UnknownAuthnMethod extends Exception {
  constructor() {
    super();
  }
}

module.exports.ExpiredToken = ExpiredToken;
module.exports.AuthenticationFailure = AuthenticationFailure;
module.exports.NoMatchingKey = NoMatchingKey;
module.exports.UnknownAuthnMethod = UnknownAuthnMethod;