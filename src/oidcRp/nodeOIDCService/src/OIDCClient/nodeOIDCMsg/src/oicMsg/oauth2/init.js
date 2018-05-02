var Message = require('../message');
var AccessToken = require('../tokenProfiles/accessToken');

var dict = {};
var SINGLE_REQUIRED_STRING = [String, true, null, null, false];
var SINGLE_OPTIONAL_STRING = [String, false, null, null, false];
var SINGLE_OPTIONAL_INT = [Number, false, null, null, false];
var SINGLE_REQUIRED_INT = [Number, true, null, null, false];
var OPTIONAL_LIST_OF_STRINGS =
    [[String], false, this.listSerializer, this.listDeserializer, false];
var REQUIRED_LIST_OF_STRINGS =
    [[String], true, this.listSerializer, this.listDeserializer, false];
var OPTIONAL_LIST_OF_SP_SEP_STRINGS = [
  [String], false, this.spSepListSerializer, this.spSepListDeserializer, false
];

var REQUIRED_LIST_OF_SP_SEP_STRINGS = [
  [String], true, this.spSepListSerializer, this.spSepListDeserializer, false
];

var SINGLE_OPTIONAL_JSON =
    [dict, false, this.jsonSerializer, this.jsonDeserializer, false];

var REQUIRED = [
  SINGLE_REQUIRED_STRING, REQUIRED_LIST_OF_STRINGS,
  REQUIRED_LIST_OF_SP_SEP_STRINGS
];

var OPTIONAL_MESSAGE = [Message, false, this.msgSer, this.msgDeser, false];
var REQUIRED_MESSAGE = [Message, true, this.msgSer, this.msgDeser, false];

var OPTIONAL_LIST_OF_MESSAGES =
    [[Message], false, this.msgListSer, this.msgListDeser, false];

var SINGLE_OPTIONAL_DICT =
    (Object, false, this.jsonSerializer, this.jsonDeserializer, false)

        var VTYPE = 0;
var VREQUIRED = 1;
var VSER = 2;
var VDESER = 3;
var VNULLALLOWED = 4;

function factory(msgtype, params) {
  for (var i = 0; i < inspect.getMembers(sys.modules[_name_]).length; i++) {
    if (inspect.isclass(obj) && obj instanceof Message) {
      try {
        if (obj.name == msgType) {
          return obj(params);
        }
      } catch (err) {
        return;
      }
    }
  }
}

module.exports.SINGLE_OPTIONAL_STRING = SINGLE_OPTIONAL_STRING;
module.exports.OPTIONAL_LIST_OF_STRINGS = OPTIONAL_LIST_OF_STRINGS;
module.exports.SINGLE_OPTIONAL_DICT = SINGLE_OPTIONAL_DICT;
module.exports.SINGLE_OPTIONAL_INT = SINGLE_OPTIONAL_INT;
module.exports.SINGLE_REQUIRED_STRING = SINGLE_REQUIRED_STRING;