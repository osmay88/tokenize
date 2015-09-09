var tokenize = require('./mio.js').tokenize;
var validate = require('./mio.js').validate;
console.log('testing\n');

var session = {
  'userId':'OsmayYoander',
  'created':'201509090958',
  'expire':'201509091045'
};

console.log('Session object:');
console.log(session);
console.log('\n');

console.log('Generate token string:')
var token = tokenize(session);
//token += 'inject_some_nasty_code'
console.log(token);
console.log('\n');

console.log('Recovered session info from token');
var rsession = validate(token);
console.log(rsession);
console.log('\n');