var tokenize = require('./tokenize.js');
//var create = require('./tokenize.js').create;
//var validate = require('./tokenize.js').validate;
console.log('testing\n');

tokenize.init('abcdefghijk', 'sha256');

var session = {
  'userId':'OsmayYoander',
  'created':'201509090958',
  'expire':'201509091045'
};

console.log('Session object:');
console.log(session);
console.log('\n');

console.log('Generate token string:')
var token = tokenize.create(session);
//token += 'inject_some_nasty_code'
console.log(token);
console.log('\n');

console.log('Recovered session info from token');
var rsession = tokenize.validate(token);
console.log(rsession);
console.log('\n');