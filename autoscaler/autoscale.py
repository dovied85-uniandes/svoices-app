from apscheduler.schedulers.blocking import BlockingScheduler
import requests
import json
import os
import boto3

APP = os.environ["HEROKU_APP_NAME"]
KEY = os.environ["HEROKU_API_TOKEN"]
PROCESS = "worker"
HEADERS = {
    "Accept": "application/vnd.heroku+json; version=3",
    "Authorization": "Bearer " + KEY
}
URL = "https://api.heroku.com/apps/" + APP + "/formation/" + PROCESS

sqs_queue_region = os.environ["AWS_SQS_REGION"]
sqs_queue_access_key_id = os.environ["AWS_SQS_ACCESS_KEY_ID"]
sqs_queue_access_key_secret = os.environ["AWS_SQS_ACCESS_KEY_SECRET"]
sqs_queue_name = os.environ["AWS_SQS_QUEUE_NAME"]

queue = boto3.resource('sqs', region_name=sqs_queue_region, aws_access_key_id=sqs_queue_access_key_id, aws_secret_access_key=sqs_queue_access_key_secret)\
    .get_queue_by_name(QueueName=sqs_queue_name)

MAX_WORKERS = 4

def update_dyno_qty(size):
    json_payload = json.dumps({'quantity': size})
    try:
        result = requests.patch(URL, headers=HEADERS, data=json_payload)
    except:
        print("Heroku API error")
        return None
    if result.status_code == 200:
        return f"Successfully updated dyno quantity for process: {PROCESS}; new quantity: {size}"
    else:
        return f"Failure to update dyno quantity for process: {PROCESS}"

def get_current_dyno_qty():
    try:
        result = requests.get(URL, headers=HEADERS)
        current_quantity = json.loads(result.text)["quantity"]
        return current_quantity
    except:
        return None

def get_queue_size():
    queue.reload()
    return int(queue.attributes.get('ApproximateNumberOfMessages')) + int(queue.attributes.get('ApproximateNumberOfMessagesNotVisible'))

sched = BlockingScheduler()

@sched.scheduled_job('interval', seconds=int(os.environ["AUTOSCALING_INTERVAL"]))
def job():
    queue_size = get_queue_size()

    current_dynos = get_current_dyno_qty()
    if queue_size == 0:
        target_dynos = 0
    elif queue_size < 100:
        target_dynos = 1
    elif queue_size < 300:
        target_dynos = 2
    elif queue_size < 600:
        target_dynos = 3
    else:
        target_dynos = MAX_WORKERS

    if current_dynos != target_dynos:
        res = update_dyno_qty(target_dynos)
        print(res)
    else:
        print("No update needed to number of dynos")

sched.start()
