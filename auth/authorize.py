import jwt
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def jwt_verify(auth_token):
    with open("mykey.pub", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    payload = jwt.decode(auth_token, key=public_key, algorithm='RS256')
    print("keshar>>>>", payload)
    return payload['Item']['id']


def generate_policy(principal_id, effect, resource):
    return {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }


def handler(event, context):
    token = event.get('authorizationToken')
    print(token)
    if not token:
        raise Exception('Unauthorized')
    methodArn = event['methodArn']
    print("keshar>>>>", type(methodArn))
    print("keshar>>>>", methodArn)
    try:
        a_token = str.encode(token, "utf-8")
        principle_id = jwt_verify(a_token)
        policy = generate_policy(principle_id, 'Allow', methodArn)
        return policy
    except Exception as e:
        print(f"Exception>>>> {e}")
        raise Exception("Unauthorized")
