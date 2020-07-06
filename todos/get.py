import os
import json
import jwt
import boto3

from todos import decimalencoder
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

dynamodb = boto3.resource('dynamodb')


def get(event, context):
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    # fetch todo from the database
    result = table.get_item(
        Key={
            'id': event['pathParameters']['id']
        }
    )
    token = signToken(result)
    data = {key: value for key, value in result['Item'].items()}
    data["token"] = token
    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(data, cls=decimalencoder.DecimalEncoder)
    }
    return response


def signToken(result):
    try:
        with open("mykey.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return jwt.encode(result, key=private_key, algorithm='RS256').decode("utf-8")
    except Exception as e:
        print("Keshae>>>>>", e)
        raise Exception(e)


def iterable(obj):
    try:
        iter(obj)
    except Exception:
        return False
    else:
        return True
