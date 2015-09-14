/* global Buffer */
/**
 * This modules if for using JSON web tokens within the application
 * @author Osmay Y. Cruz Alvarez <osmay.cruz@gmail.com>
 * @source https://github.com/osmay88/tokenize
 * 
 */

/**
 * TODO: Implementar persistencia antes que el servidor se reinicie
 * 
 **/

'use strict';

var crypto = require('crypto');

var server_key  = '',    //server_key is used to generate the token signature
    method 	= 'sha256',  // hashing method used to generate the signature
    blacklist	= {}, //list containing the blacklisted objects
    token_life = 5*1000*60
  ;

/**
 * Initialize the tokenize middleware
 * 
 * @param key {string}  key used to generate the signature
 * @param hasher {string} hashing algorithm used to generate the signature
 */
exports.init=module.exports.init=function(key, hasher, token_time){
  if((key !== null) && (key !== ''))
    server_key = key;
  if((hasher !== null) && (hasher !== ''))
    method = hasher;
  if(token_time !== null)
    token_life = token_time
};

/**
 * This method create a hash from a text.
 * 
 * @param text {String} string to be encoded
 * @param method {String} hashing method to be used
 * @return {string}
 */
function hashify(text, method){
  //TODO: here check is method is a know hashing method
  if(! method in crypto.getHashes()){
    throw Error('Invalid hashing method');
  }
  return crypto.createHash(method).update(text + server_key).digest('hex');
}

/**
 * Add the user to the blacklist
 * @param userId {string} user id to add to the blacklist
 * @param reason {string} Reason why the user is banned
 * @param beforethan {date} all the tokens issued before this date should be banned
 */
var addToBlackList = function(userId, reason, beforethan){
  if(is_blacklisted(userId)){
    //the user is already in the black list, just update the fields
    blacklist[userId].reason = reason;
    blacklist[userId].beforethan = beforethan;
    return true;
  }else{
    blacklist[userId] = {
      reason:reason || null,
      beforethan:beforethan || null
      
    };
  }
};

/**
 * Remove the username from the blacklist
 * 
 * @param userId {string} User id to be removed
 */
var remove_blacklist = function(userId){
  if(is_blacklisted(userId))  {
    delete blacklist[userId];
    return true;
  }
  return false;
};

/**
 * Check if the user is in the blacklist
 * 
 * @param userId {string}
 * @return {boolean}
 */
var is_blacklisted = function(userId){
  return blacklist.hasOwnProperty(userId) ? true : false;
};

/**
 * Create a JSON web token
 * 
 * @param sessionObj {object} json session data to be included in the jwt
 * @param expireon {number} Define for how long this token will be valid(in ms).
 *                          If no value is provided, then the module setting will be used.
 * @return {string} JSON string token
 */
var create = function(sessionObj, expireon){
  //console.log('server_key:' + server_key);
  if('object' !== typeof(sessionObj)){
    throw Error('sessionObj must be an object');
  }
  var header = {
    'algo': method,
    'type': 'jwt',
    'created': Date.now(),
    'expireon': expireon || token_life
  }; 
  // convierto los objetos json en cadenas
  var jheader = JSON.stringify(header);
  var jdata = JSON.stringify(sessionObj);
  
  //codifico los datos con algoritmo base64
  var subkey = new Buffer(jheader).toString('base64')+'.'+new Buffer(jdata).toString('base64');
  
  var signature = hashify(subkey, 'sha256');
  
  return subkey + '.' + signature;
};

/**
 * Create a new token from a previous valid token
 * This method doesnt validate the token..
 * @param token {string} old token to be updated
 */
var update = function(token){
  //TODO: la validacion del token debe ser comprobada por el usuario
  var extracted = extract(token);
  var strdata = new Buffer(extracted['data'], 'base64').toString('ascii');

  return create(JSON.parse(strdata), extracted.header.expireon); //creo el nuevo token


};

/**
 * This takes one token key and split it
 * 
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
}

/**
 * Extract the json object whithout validate
 * 
 * @param token {string} raw JSON web token
 * @return Object object containing the json data {header, data, signature}
 */
var extract = function(token){
  if('string' !== typeof token)
    throw Error('The token object should be a string');
  var subelements = split(token);
  var header = subelements[0]
    , data   = subelements[1]
    , signature = subelements[2]
    ;
  return {'header':header, 'data':data, 'signature':signature}
  
};

/**
 * Check the validity of the token
 * 
 * @param token {string} raw JSON token to be validate
 * @return {Object || null}
 */
var validate = function(token){
  if('string' !== typeof token){
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
    throw Error('Token signature is not valid');
  }
  
  //  jheader = new Buffer(subheader, 'base64').toString('ascii');
  var jdata = new Buffer(subdata, 'base64').toString('ascii');
  return JSON.parse(jdata);
  
};

exports.create = create;
exports.validate = validate;
exports.extract = extract;
exports.is_blacklisted = is_blacklisted;
exports.remove_blacklist = remove_blacklist;
exports.blacklist = addToBlackList;
exports.update = update;
