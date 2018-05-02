// api.js
var API = require('api-stub');
var config = [{path: '/status', data: {status: true}}] var server =
    new API(config);
server.start(3000);
// then run the script `node api.js`