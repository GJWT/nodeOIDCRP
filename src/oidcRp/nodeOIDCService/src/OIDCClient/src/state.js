const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/init.js').AuthorizationResponse;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const SINGLE_REQUIRED_STRING = require('../nodeOIDCMsg/src/oicMsg/message').SINGLE_REQUIRED_STRING;
const SINGLE_OPTIONAL_JSON = require('../nodeOIDCMsg/src/oicMsg/message').SINGLE_OPTIONAL_JSON;

/** 
 * StateJWT
 * @class
 * @constructor
 * @extends Message
 */
class State extends Message{
  constructor(claims) {
    super();
    if (claims){
      this.claims = claims;
    }else{
      this.claims = {};
    }
    this.cParam = {
      iss: SINGLE_REQUIRED_STRING,
      auth_request: SINGLE_OPTIONAL_JSON,
      auth_response: SINGLE_OPTIONAL_JSON,
      token_response: SINGLE_OPTIONAL_JSON,
      refresh_token_request: SINGLE_OPTIONAL_JSON,
      refresh_token_response: SINGLE_OPTIONAL_JSON,
      user_info: SINGLE_OPTIONAL_JSON
    };
  }
}

/**
 * State
 * Given state I need to be able to find valid access token and id_token
 * and to whom it was sent.
 * @class
 * @constructor
 */
class StateInterface {

  constructor(stateDb){
    this.stateDb = stateDb;
  };

  /**
   * Get the state connected to a given key.
   * 
   * @param {Key} key Key into the state database
   * @return State instance
   */
  getState(key){
    const _data = this.stateDb.get(key);
    if (!_data){
      //throw new JSError(key, 'KeyError');
    }else{
      return State.fromJSON(_data);
    }
  }

  /**
   * Store a service response.
   * @param {Message} item The item as a Message
            subclass instance or a JSON document.
   * @param {string} itemType The type of request or response
   * @param {Key} key The key under which the information should be stored in
            the state database
   */
  storeItem(item, itemType, key){
    let _state = State;
    if (this.getState(key)){
      _state.claims = this.getState(key)
    }else if (!(this.getState(key))){
      _state.claims = {};
    }

    try{
      _state.claims[itemType] = item.toJSON(item.claims);
      item.fromJSON(item.claims);
    }catch(err){
      if (item.claims){
        _state.claims[itemType] = item.claims;
      }else{
        _state.claims[itemType] = item;
      }
    }
    this.stateDb.set(key, _state.toJSON(_state.claims));
  }

  /** 
   * Get the Issuer ID
   * @param {Key} key Key to the information in the state database
   * @return The issuer ID
   */
  getIssuer(key){
    let _state = this.stateDb.get(key);
    if (!_state){
      //throw new JSError(key, 'KeyError');
    }
    
    if (typeof _state == 'string'){
      _state = JSON.parse(_state)
    }
    return _state.iss;
  }

  /**
   * Get a piece of information (a request or a response) from the state database.
   * @param {Message} itemCls Message subclass that described the item.
   * @param {string} itemType Which request/response that is wanted
   * @param {Key} key The key to the information in the state database
   * @return A Message instance
   */
  getItem(itemCls, itemType, key){
    let claims = this.getState(key);
    if (claims && typeof claims[itemType] == 'string'){
      return itemCls.fromJSON(claims[itemType]);
    }else if (claims[itemType]){
      itemCls.claims = claims[itemType];
      return itemCls.claims;
    }
  }

  /**
   *  Add a set of parameters and their value to a set of request arguments.
   * @param {Object} args A dictionary
   * @param {Message} itemCls The Message subclass that describes the item
   * @param {string} itemType The type of item, this is one of the parameter
            names in the Service state class.
   * @param {Key} key The key to the information in the database
   * @param {Array<string>} parameters A list of parameters who's values this method
            will return.
   * @return A dictionary with keys from the list of parameters and
            values being the values of those parameters in the item.
            If the parameter does not a appear in the item it will not appear
            in the returned dictionary.
   */
  extendRequestArgs(args, itemCls, itemType, key, parameters){
    let claims = this.getItem(itemCls, itemType, key);
    for (var i = 0; i < parameters.length; i++){
      var parameter = parameters[i];
      if (claims && claims[parameter]){
        args[parameter] = claims[parameter];
      }
    }
    return args;
  }

  /**
   * Go through a set of items (by their type) and add the attribute-value
   * that match the list of parameters to the arguments
   * If the same parameter occurs in 2 different items then the value in
   * the later one will be the one used.
   * 
   * @param {Object} args Initial set of arguments
   * @param {Key} key Key to the State information in the state database
   * @param {Array<string>} parameters A list of parameters that we're looking for
   * @param {Array<string>} itemTypes A list of item_type specifying which items we
            are interested in.
   * @return A possibly augmented set of arguments
   */
  multipleExtendRequestArgs(args, key, parameters, itemTypes){
    let claims = this.getState(key);
    for (var i = 0; i < itemTypes.length; i++){
      let typ = itemTypes[i];
      let _item = new Message(claims[typ]);
      for (var j = 0; j < parameters.length; j++){
        let parameter = parameters[j];
        if (Object.keys(_item.claims).length !== 0){
          if (_item.claims[parameter]){
            args[parameter] = _item.claims[parameter];
          }else{
            console.log(_item.claims);
            console.log("************************")
            try{
            args[parameter] = JSON.parse(_item.claims)[parameter];
            }catch(err){
              console.log('parameter does not exist');
            }
          }
        }
      }
    }
    return args;
  }

  /**
   * Store the connection between a nonce value and a state value.
   * This allows us later in the game to find the state if we have the nonce.
   * @param {int} nonce 
   * @param {State} state 
   */
  storeNonce2State(nonce, state){
    this.stateDb.set('_' + nonce + '_', state);
  }

  /**
   * Find the state value by providing the nonce value.
   * Will raise an exception if the nonce value is absent 
   * from the state data base.
   * @param {*} nonce 
   */
  getStateByNonce(nonce){
    _state = this.stateDb.get('_nonce_', state);
    if (_state){
      return _state;
    }else{
      throw new Error(nonce, 'KeyError');
    }
  }

  /**
   *Find the state value by providing the nonce value.
   * Will raise an exception if the nonce value is absent from the state data base.
   * @param {*} nonce 
   */
  getStateByNonce(nonce){
    let _state = this.stateDb.get('_' + nonce + '_'); 
    if (_state){
      return _state;
    }else{
      throw new Error('_nonce_', 'KeyError');
    }
  }
  
  /**
   * Create state
   * @param {string} iss Issuer
   */
  createState(iss){
    let key = Math.random(32);
    let _state = new State({iss:iss});
    this.stateDb.set(key, _state);
    return key;
  }
}

module.exports.State = State;
module.exports.StateInterface = StateInterface;