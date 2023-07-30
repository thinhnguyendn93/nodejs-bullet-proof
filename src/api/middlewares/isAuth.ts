import { expressjwt } from 'express-jwt';
import * as jwt from 'jsonwebtoken';
import config from 'config';

const getTokenFromHeader = (req) => {
  const { authorization } = req.headers;
  if (
    (authorization && authorization.split(' ')[0] === 'Token') ||
    (authorization && authorization.split(' ')[0] === 'Bearer')
  ) {
    return authorization.split(' ')[1];
  }
  return null;
};

const isAuth = expressjwt({
  secret: config.jwtSecret,
  algorithms: [config.jwtAlgorithm] as jwt.Algorithm[],
  getToken: getTokenFromHeader,
});

export default isAuth;
