import serverless =  require('serverless-http');
import * as express from 'express';
// source-map support
import 'source-map-support/register';
// lambda logic imports
import pwnedLambda from './src/pwned-or-not';

const app = express();

// endpoints
app
  .get('/', pwnedLambda)
;

module.exports.handler = serverless(app);