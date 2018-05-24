const assert = require('chai').assert;
const SINGLE_REQUIRED_STRING =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_REQUIRED_STRING;
const SINGLE_OPTIONAL_DICT =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_DICT;
const SINGLE_OPTIONAL_INT =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_INT;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const Service = require('../src/service.js').Service;
var ServiceContext = require('../src/ServiceContext.js').ServiceContext;
const SINGLE_OPTIONAL_STRING =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_STRING;
var ErrorResponse = require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').ErrorResponse;
const State = require('../src/state').State;


class DummyMessage extends Message {
  constructor() {
    super();
    this.cParam = {
      'req_str': SINGLE_REQUIRED_STRING,
      'opt_str': SINGLE_OPTIONAL_STRING,
      'opt_int': SINGLE_OPTIONAL_INT,
    };
  }
}

class Response {
  constructor(statusCode, text, headers) {
    headers = headers || null;
    this.statusCode = statusCode;
    this.text = text;
    this.headers = headers || {'content-type': 'text/plain'};
    return this;
  }
}

class DummyService extends Service {
  constructor() {
    super();
    this.msgType = DummyMessage;
  }
}

class DB{
  constructor(){
    this.db = {};
  }

  set(key, value){
    this.db[key] = value;
  }

  get(item){
    return this.db[item];
  }
}

describe('Test Dummy Service', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    service = new DummyService();

    serviceContext = new ServiceContext(null, null,
      {'clientId': 'client_id', 'issuer': 'https://www.example.org/as'});
    let db = new DB();
    //db.set('state', new State({iss:'Issuer'}).toJSON());
    db.set('state', State.toJSON({iss:'Issuer'}));
    service = new DummyService(serviceContext, db);
  });
  it('Test construct', function() {
    let reqArgs = {'foo': 'bar'};
    let req = service.construct(reqArgs);
    assert.deepEqual(Object.keys(req.claims), ['foo']);
  });
  it('Test request cli info', function() {
    let reqArgs = {'foo': 'bar', 'req_str': 'some string'};
    let req = service.construct(reqArgs);
    assert.deepEqual(Object.keys(req.claims), ['foo', 'req_str']);
  });
  it('Test request info', function() {
    let reqArgs = {'foo': 'bar', 'req_str': 'some string'};
    service.endpoint = 'https://example.com/authorize';
    info = service.getRequestParameters({requestArgs: reqArgs});
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    let msg =
        DummyMessage.fromUrlEncoded(service.getUrlInfo(info['url']));
    assert.deepEqual(msg,{'foo': 'bar', 'req_str': 'some string'});
  });
  it('Test request init', function() {
    let reqArgs = {'foo': 'bar', 'req_str': 'some string'};
    service.endpoint = 'https://example.com/authorize';
    info = service.getRequestParameters({requestArgs: reqArgs});
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    let msg =
        DummyMessage.fromUrlEncoded(service.getUrlInfo(info['url']));
    assert.deepEqual(msg, {'foo': 'bar', 'req_str': 'some string'});
  });
});

describe('Test Request', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    service = new Service();
    serviceContext = new ServiceContext(null);
  });
  it('Test parse request response json', function() {
    var reqArgs = {'foo': 'bar'};
    var req = service.construct(reqArgs);
    assert.deepEqual(Object.keys(req.claims), ['foo']);
  });
});