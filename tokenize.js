var crypto = require('crypto');

// TODO: the vector is used to encrypt the server key & the rest of the data
var crypto_vector = 'qwertyuiop[]'; 

// TODO: key will be encrypted and sended to the client 
var server_key = 'unacadenamuyperoquemuylargo';

/**
 * This method create a hash from a text
 * @param text {String} string to be encoded
 * @param method {String} hashing method to be used
 * @return {string}
 */
function hashify(text, method){
  //TODO: here check is method is a know hashing method
  return crypto.createHash(method).update(text + server_key).digest('hex');
}

/**
 * this take a json session object encryot it 
 * and send it to the user, the token itself contains
 * all the information required
 * {userId, created, forever, etc[object]}
 * @param sessionObj json session data to be included in the jwt
 * @return {String}
 */
var tokenize = function(sessionObj){
  //TODO: implement here  
  if(! typeof(sessionObj) == 'object'){
    throw Error('sessionObj must be an object');
  }
  var header = {
    'algo': 'sha256',
    'type': 'jwt',
    'created': Date.now()
  }; 
  // convierrto los objetos json en cadenas
  var jheader = JSON.stringify(header);
  var jdata = JSON.stringify(sessionObj);
  
  //codifico los datos con algoritmo base64
  var subkey = new Buffer(jheader).toString('base64')+'.'+new Buffer(jdata).toString('base64');
  
  var signature = hashify(subkey, 'sha256');
  
  return subkey + '.' + signature;
};

/**
 * This takes one token key and split it
 * @param token {string}  raw token string to be processed
 * @return array || null
 */
function split(token){
  //TODO: implement here
  var subelements = token.split('.');
  if(subelements.length !== 3){
    return null; // this token is not valid
  }
  return subelements;
};

/**
 * Check if a token is valid
 * @param token raw jwt to be validate
 * @return {Object || null}
 */
var validate = function(token){
  //TODO: implement here
  if(!'string' === typeof token){
    throw Error('The token is not a string');
  }
  var subitems = split(token);
  if(subitems === null){
    throw Error('The token is not valid.');
  }
  var subheader = subitems[0],
      subdata = subitems[1],
      signature = subitems[2]
    ;

  // antes que nada
  // compruebo que la firma del token sea valida, 
  // para evitar tokens manipulados
  if (signature !== hashify(subheader+'.'+subdata, 'sha256')){
    console.log('Que no cojones...');
    throw Error('Token signature is not valid');
  }
  
  jheader = new Buffer(subheader, 'base64').toString('ascii');
  jdata = new Buffer(subdata, 'base64').toString('ascii');
  return JSON.parse(jdata);
  
};

exports.tokenize = tokenize;
exports.validate = validate;
