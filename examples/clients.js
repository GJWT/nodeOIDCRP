const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync('clientsDb.json');
const db = low(adapter);

db.defaults({posts: [], user: {}, count: 0}).write();

// Get registered client by issuer
const get = async (iss) => {
  const client = await db.get({iss});
  if (client) return client;

  console.log(
      'No client found.  Returning null to initiate dynamic registration'
  );
  return null;
};

// Store registered client in db
const register = async ({iss, clientId, clientSecret}) => {
  // ... TODO
};

module.exports = {get, register};
