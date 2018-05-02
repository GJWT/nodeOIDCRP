const fs = require('fs');
const shell = require('shelljs');

function requestObjectEncryption(msg, serviceContext, params) {
  let encalg = null;
  try {
    encalg = params['request_object_encryption_alg'];
  } catch (err) {
    try {
      encalg = serviceContext.behavior['request_object_encryption_alg'];
    } catch (err) {
      return msg;
    }
  }
  let encenc = null;
  try {
    encenc = params['request_object_encryption_enc'];
  } catch (err) {
    try {
      encenc = serviceContext.behavior['request_object_encryption_enc'];
    } catch (err) {
      //throw new JSError('No request object encryption enc specified', MissingRequiredAttribute);
    }
  }

  let kid = null;
  try {
    kid = params['enc_kid'];
  } catch (err) {
    kid = '';
  }

  if (params.indexOf('target') === -1) {
    throw new Error('Missing Required Attribute - No target specified');
  }

  if (kid) {
    keys = serviceContext.keyJar.getEncyptKey(kty, params['target'], kid);
    jwe['kid'] = kid;
  } else {
    keys = serviceContext.keyJar.getEncryptKey(kty, params['target']);
  }
  return jwe.encrypt(keys);
}

function constructRequestUri(localDir, basePath) {
  let fileDir = localDir;

  if (!fs.existsSync(fileDir)) {
    shell.mkdir('-p', fileDir);
  }

  let webPath = basePath;
  let name = rndStr(10) + '.jwt';
  let fileName = fileDir + '/' + name;
  while (!fs.lstatSync(fileName).isFile()) {
    name = rndStr(10);
    fileName = os.path.join(fileDir, name);
  }
  let webName = webPath + name;
  let pair = [fileName, webName];
}