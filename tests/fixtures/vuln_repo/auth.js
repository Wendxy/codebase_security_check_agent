const jwt = require('jsonwebtoken');

function parseToken(token, secret) {
  return jwt.verify(token, secret, { ignoreExpiration: true });
}

module.exports = { parseToken };
