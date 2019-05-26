// Import aws modules with XRay tracing capabilities
import * as awsXRay from 'aws-xray-sdk';
const { SES } = awsXRay.captureAWS(require('aws-sdk'));

import * as rp from "request-promise";
import { RequestPromiseOptions } from "request-promise";
import { SHA256 } from 'crypto-js';

interface IBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
}

interface IBreachData {
  account: string;
  data: IBreach[];
}

const pwnedLambda = async (req: any, res: any) => {

  const ses = new SES({
    region: "eu-west-1",
  });

  // comma separated list of accounts to check
  // Accounts need to be URL encoded
  const promises: Promise<IBreachData | void>[] = (process.env.ACCOUNTS_TO_BE_CHECKED as string)
    .split(",")
    .map(account => account.trim())
    .map(account => encodeURIComponent(account))
    .map(account => {
      const uri = `https://haveibeenpwned.com/api/v2/breachedaccount/${account}`;
      const options: RequestPromiseOptions = {
        headers: {
          "User-Agent": "pwned-checker-api",
        },
      };

      const decodedAccount = decodeURIComponent(account);

      return rp(uri, options)
        .then((data) => ({
          account: decodedAccount,
          data: JSON.parse(data),
        }))
        // handle error independently, so it won't stop promise.all process
        .catch((err) => {
          console.error("Error happened with account: " + decodedAccount, err);
        })
      ;
    })
  ;

  const data = await Promise.all(promises) || [];

  // const options: { endpoint?: string; } = {};
  // if (process.env.IS_OFFLINE) {
  //   options.endpoint = 'http://localhost:8000';
  // }

  // const dynamodbClient = new DynamoDB.DocumentClient(options);


  // if there are breaches, check if the notifications are already sent to that account
  // if there are not sent notifications, sum them up and send an email
  await data
    // remove empty results
    .filter(breachData => breachData && breachData.data && breachData.data.length)
    // TODO check which results are already sent from dynamodb
    // .map(breachData => {
      // const accountHash = breachData && SHA256(breachData.account).toString() || null;
      // console.log(accountHash)
    // })
    .map(({ account, data: bdata }: IBreachData) => {
      console.log(account, typeof bdata)
      // use SES to send email notification
      const descriptions = bdata
        .map(({ Description, Title }) => {
          return `
            Title: ${Title}
            Description: ${Description}
          `;
        })
        .join("\n\n")
      ;

      const params = {
        Destination: {
          ToAddresses: [
            account,
          ]
        },
        Message: {
          Body: {
            Html: {
              Charset: "UTF-8",
              Data: descriptions,
            },
            Text: {
              Charset: "UTF-8",
              Data: descriptions
            }
          },
          Subject: {
            Charset: "UTF-8",
            Data: "You have been powned"
          },
        },
        Source: process.env.SES_EMAIL_SENDER,
      };

      console.log("Going to send email with content", params);

      return ses.sendEmail(params)
        .promise()
        .then(res => {
          console.log("res", res)
        })
        .catch((err) => {
          console.error("Error happened on .sendEmail", err);
        })
      ;

    })
  ;



  res.send("Hello there!");
};

export default pwnedLambda;