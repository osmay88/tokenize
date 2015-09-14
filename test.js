var tokenize = require('./tokenize.js');
//var create = require('./tokenize.js').create;
//var validate = require('./tokenize.js').validate;
console.log('testing\n');

tokenize.init('abcdefghijk', 'sha256');

var session = {
  'userId':'OsmayYoander',
  'created':'201509090958',
  'scope': 'mis copes',
  'permission': '[leer, escribir, cantar, bailar]',
  'expire':'201509091045'
};

console.log('\033[31m Session object: \033[0m ');
console.log(session);
console.log('\n');

console.log('\033[31m Generate token string:\033[0m ');
var token = tokenize.create(session);
//token += 'inject_some_nasty_code'
console.log(token);
console.log('\n');

console.log('\033[31m Recovered session info from token \033[0m ');
var rsession = tokenize.validate(token);
console.log(rsession);
console.log('\n');

console.log('Updating the current token');
var newtoken = tokenize.update(token);
console.log(newtoken);

console.log('\033[31m Recovered session info from updated token \033[0m ');
rsession = tokenize.validate(newtoken);
console.log(rsession);
console.log('\n');