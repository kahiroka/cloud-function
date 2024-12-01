is_aws = False
is_gcp = False
is_azure = False
try:
    import functions_framework
    is_gcp = True
except ImportError:
    pass
try:
    import azure.functions as func
    is_azure = True
except ImportError:
    pass
if not is_gcp and not is_azure:
    is_aws = True
import json
import base64
import hashlib
import hmac
import os
import urllib.request

# LINE parroting bot
def common_function(headers, body):
    if 'x-line-signature' in headers:
        sig1 = headers['x-line-signature']
    else:
        return 400
    channel_secret = os.environ['CHANNEL_SECRET']
    channel_access_token = os.environ['CHANNEL_ACCESS_TOKEN']
    hash = hmac.new(channel_secret.encode('utf-8'),
        body.encode('utf-8'), hashlib.sha256).digest()
    sig2 = base64.b64encode(hash).decode()
    if sig1 != sig2:
        return 401
    else:
        b = json.loads(body)
        if not 'events' in b:
            return 400
        else:
            for e in b['events']:
                if 'message' in e and e['message']['type'] == 'text':
                    text = e['message']['text']
                    if 'source' in e and 'userId' in e['source']:
                        userId = e['source']['userId']
                        msg_body = json.dumps({
                            "to": userId,
                            "messages": [{
                                "type": "text",
                                "text": text
                            }]
                        })
                        request = urllib.request.Request('https://api.line.me/v2/bot/message/push',
                            data=msg_body.encode('utf-8'),
                            headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + channel_access_token,
                            },
                            method='POST')
                        with urllib.request.urlopen(request) as response:
                            data = response.read().decode('utf-8')
                            status = response.status
        return 200

# aws
def lambda_handler(event, context):
    headers = event['headers']
    body = event['body']

    status = common_function(headers, body)

    if status == 400:
        return {
            'statusCode': 400,
            'body': 'Bad Request'
        }
    elif status == 401:
        return {
            'statusCode': 401,
            'body': 'Unauthorized'
        }
    else:
        return {
            'statusCode': 200,
            'body': 'OK'
        }

# gcp
if not is_gcp:
    class functions_framework:
        def http(request):
            pass
@functions_framework.http
def hello_http(request):
    headers = request.headers
    body = request.get_data().decode()

    status = common_function(headers, body)

    if status == 400:
        return 'Bad Request'
    elif status == 401:
        return 'Unauthorized'
    else:
        return 'OK'

# azure
if not is_azure:
    class func:
        def FunctionApp(http_auth_level):
            pass
        class AuthLevel:
            ANONYMOUS = 0
        class HttpRequest:
            pass
        class HttpResponse:
            pass
    class app:
        def route(route):
            def func(req):
                pass
            return func
if is_azure:
    app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
@app.route(route="http_trigger")
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    headers = req.headers
    body = req.get_body().decode()

    status = common_function(headers, body)

    if status == 400:
        return func.HttpResponse(
            "Bad Request",
            status_code=400
        )
    elif status == 401:
        return func.HttpResponse(
            "Unauthorized",
            status_code=401
        )
    else:
        return func.HttpResponse(
            "OK",
            status_code=200
        )
