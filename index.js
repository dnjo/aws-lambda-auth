const https = require('https');
const jose = require('node-jose');

const region = process.env['AWS_REGION'];
const userpool_id = process.env['USERPOOL_ID'];
const app_client_id = process.env['APP_CLIENT_ID'];
const keys_url = 'https://cognito-idp.' + region + '.amazonaws.com/' + userpool_id + '/.well-known/jwks.json';

const getJwk = () => {
    return new Promise((resolve, reject) => {
        https.get(keys_url, (response) => {
            if (response.statusCode === 200) {
                response.on('data', body => resolve(body));
            } else {
                reject('Invalid response code');
            }

            response.on('error', error => reject(error));
        })
    })
};

const verifyJwt = (token, kid, jwkBody) => {
    return new Promise((resolve, reject) => {
        const keys = JSON.parse(jwkBody)['keys'];
        // search for the kid in the downloaded public keys
        let key_index = -1;
        for (let i = 0; i < keys.length; i++) {
            if (kid === keys[i].kid) {
                key_index = i;
                break;
            }
        }
        if (key_index === -1) {
            console.log('Public key not found in jwks.json');
            reject('Public key not found in jwks.json');
        }
        // construct the public key
        jose.JWK.asKey(keys[key_index])
          .then(result => jose.JWS.createVerify(result).verify(token))
          .then(result => {
              // now we can use the claims
              const claims = JSON.parse(result.payload);
              // additionally we can verify the token expiration
              const current_ts = Math.floor(new Date() / 1000);
              if (current_ts > claims.exp) {
                  reject('Token is expired');
              }
              // and the Audience (use claims.client_id if verifying an access token)
              if (claims.aud !== app_client_id) {
                  reject('Token was not issued for this audience');
              }
              resolve(claims);
          })
          .catch(error => reject(error));
    });
};

const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
};

exports.handler = (event, context, callback) => {
    const token = event.authorizationToken;
    const sections = token.split('.');
    // get the kid from the headers prior to verification
    const header = JSON.parse(jose.util.base64url.decode(sections[0]));
    getJwk()
      .then(jwkBody => verifyJwt(token, header.kid, jwkBody))
      .then(claims => {
        const policyResponse = generatePolicy(claims.sub, 'Allow', event.methodArn);
        callback(null, policyResponse);
      })
      .catch(callback('Invalid token'));
};
