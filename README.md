# pwned-or-not

To periodically see if your credentials have been compromised

## Local development

Run env with `npm start`. To start local dynamodb, run `docker run -p 8000:8000 amazon/dynamodb-local`

There's `http://localhost:8000/shell/` browser shell to get started with local dynamodb.
Also it's possible to use aws-cli, e.g. like this: `aws dynamodb list-tables --endpoint-url http:localhost:8000`