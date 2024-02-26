# for test:
# {"userID": "1000", "passwd:12345"}
# string for md5: secret_string

import json
import boto3
import hashlib


def calculate_md5(string):
    md5_hash = hashlib.md5()
    md5_hash.update(string.encode('utf-8'))
    return md5_hash.hexdigest()


def lambda_handler(event, context):

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('growUp_auth')
    body = json.loads(event.get('body', ''))    # JSON to python-format

    # get password from body

    user_id = body.get('userID')
    passwd_before_hash = body.get('password') + 'secret_string'

    # make md5 hash

    md5_password = calculate_md5(passwd_before_hash)

    # get password from database

    projection_expression = 'passwd'

    response = table.query(
        Select='SPECIFIC_ATTRIBUTES',
        ProjectionExpression=projection_expression,
        KeyConditionExpression='userID = :uid',
        ExpressionAttributeValues={':uid': str(user_id)})

    passwd_from_db = response['Items'][0].get(
        'passwd') if 'Items' in response else 'wrong password'

    # check the correctness of the password and login
    isPasswdCorrect = True if passwd_from_db == md5_password else False

    # give a token
    token_for_auth = 'aB3dE7fG2hI9jK4l'

    statusCode = 404
    responseBody = {'message': 'Item not found'}

    if isPasswdCorrect:
        statusCode = 200
        responseBody = {'token': token_for_auth}

    return {
        'statusCode': statusCode,
        'body': json.dumps(responseBody)
    }

# DynamoDB item
# {
#  "userID": "1000",
#  "objID": "1",
#  "keyResults": [
#   {
#    "description": "learn python",
#    "idDone": false,
#    "number": 1,
#    "progress": 80
#   },
#   {
#    "description": "learn js",
#    "isDone": false,
#    "number": 2,
#    "progress": 10
#   }
#  ]
# }
# {
#  "userID": "1000",
#  "objID": "2",
#  "keyResults": [
#   {
#    "description": "learn python",
#    "idDone": false,
#    "number": 1,
#    "progress": 80
#   },
#   {
#    "description": "learn nodejs",
#    "isDone": false,
#    "number": 2,
#    "progress": 10
#   }
#  ]
# }
# {
#  "userID": "1001",
#  "objID": "1",
#  "keyResults": [
#   {
#    "description": "learn scrum",
#    "idDone": false,
#    "number": 1,
#    "progress": 80
#   },
#   {
#    "description": "learn js",
#    "isDone": false,
#    "number": 2,
#    "progress": 10
#   }
#  ]
# }
