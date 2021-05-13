from celery import Celery
from celery.utils.log import get_task_logger

from dotenv import load_dotenv

from batch.emails import get_email_client

from batch.utils import get_from_env

import boto3
import json
import os
import subprocess

root_dir = get_from_env(envvar="AUDIO_FOLDER", default="var/svoice/media/audios")

sqs_queue_region = os.environ["AWS_SQS_REGION"]
sqs_queue_access_key_id = os.environ["AWS_SQS_ACCESS_KEY_ID"]
sqs_queue_access_key_secret = os.environ["AWS_SQS_ACCESS_KEY_SECRET"]
sqs_queue_name = os.environ["AWS_SQS_QUEUE_NAME"]

queue = boto3.resource('sqs', region_name=sqs_queue_region, aws_access_key_id=sqs_queue_access_key_id, aws_secret_access_key=sqs_queue_access_key_secret)\
    .get_queue_by_name(QueueName=sqs_queue_name)

s3_bucket_region = os.environ["AWS_S3_REGION"]
s3_access_key_id = os.environ["AWS_S3_ACCESS_KEY_ID"]
s3_access_key_secret = os.environ["AWS_S3_ACCESS_KEY_SECRET"]
s3_bucket_name = os.environ["AWS_S3_BUCKET_NAME"]

s3resource = boto3.resource('s3', region_name=s3_bucket_region,
    aws_access_key_id=s3_access_key_id, aws_secret_access_key=s3_access_key_secret)

dynamodb_table_region = os.environ["AWS_DYNAMODB_REGION"]
dynamodb_access_key_id = os.environ["AWS_DYNAMODB_ACCESS_KEY_ID"]
dynamodb_access_key_secret = os.environ["AWS_DYNAMODB_ACCESS_KEY_SECRET"]
dynamodb_table_name = os.environ["AWS_DYNAMODB_TABLE_NAME"]

table = boto3.resource('dynamodb', region_name=dynamodb_table_region,
    aws_access_key_id=dynamodb_access_key_id, aws_secret_access_key=dynamodb_access_key_secret).Table(dynamodb_table_name)

def create_batch():
    global BATCH_SIZE
    BATCH_SIZE = get_from_env(envvar="BATCH_SIZE", default=30)
    batch_name = get_from_env(envvar="BATCH_NAME", default="transcoder")
    broker_url = get_from_env(envvar="TASK_BROKER", desc="No se pudo configurar el broker de mensajería")
    return Celery(batch_name , broker = broker_url)

def query_voices_to_process():
    logger.info(f"Fetching the next batch of {BATCH_SIZE} audios to process")

    messages = queue.receive_messages(MessageAttributeNames=['All'], MaxNumberOfMessages=int(BATCH_SIZE))
    logger.info(f"Found {len(messages)} to convert")
    return messages

def transcode_voice(voice, media_dir):
    voice = json.loads(voice.body)
    rel_source_path = voice['rel_source_path']
    rel_target_path = voice['rel_target_path']
    abs_source_path = os.path.join(media_dir, rel_source_path)
    abs_target_path = os.path.join(media_dir, rel_target_path)

    logger.info(f"Convirtiendo archivo '{abs_source_path}' a: {abs_target_path}")

    # convert:
    error_message = f"No se pudo convertir el archivo: {abs_source_path}"

    s3resource.meta.client.download_file(s3_bucket_name, abs_source_path, 'audio_original')

    try:
        result = subprocess.run(["ffmpeg", "-y", "-i", 'audio_original', "-f", "mp3", 'audio_convertido'])
        if result.returncode == 0:
            s3resource.meta.client.upload_file('audio_convertido', s3_bucket_name, abs_target_path)
            return voice
    except Exception as e:
        error_message = f"{error_message}: {str(e)}"

    logger.error(f"No se pudo convertir el archivo: {abs_source_path}")
    return None

def transcode_voices(voices_to_process):
    voices_processed = map(lambda voice: transcode_voice(voice, root_dir), voices_to_process)
    voices_to_update = filter(lambda voice: voice is not None, voices_processed)
    return list(voices_to_update)
    
def mark_converted(converted_voices):
    num_converted = len(converted_voices)
    if num_converted == 0:
        logger.info("Ninguna voz fue convertida en esta iteración.")
        return 0

    logger.info(f"{num_converted} voces fueron convertidas. Actualizando su estado en la base de datos.")
    # update status
    with table.batch_writer() as batch:
        for converted_voice in converted_voices:
            table.update_item(Key={'pk': converted_voice['pk'], 'sk': converted_voice['sk']}, AttributeUpdates={'status': {'Value': 'Convertida', 'Action': 'PUT'}})

    return num_converted

def notify_authors(converted_voices):
    logger.info(f"Notifying voice authors that their voices were converted.")
    smtp_client = get_email_client(connect=True, logger=logger)
    
    for voice in converted_voices:
        author_email = voice['author_email']
        author_first_name = voice['author_first_name']
        author_last_name = voice['author_last_name']
        voice_file_name = voice['rel_source_path'].rsplit("/", 1)[1]
        msg_text = f"Concursante {author_first_name} {author_last_name}:\n Queremos avisarle que su audio {voice_file_name} ya ha sido convertido."
        try:
            smtp_client.send_email(author_email, "Audio convertido", msg_text)
        except Exception as e:
            logger.error(f"Unable to send notification to '{author_email}': {e}")

    smtp_client.disconnect()

load_dotenv()
app = create_batch()
logger = get_task_logger(__name__)

task_period = float(get_from_env(envvar="TASK_PERIOD", default=60))
app.conf.beat_schedule = {
    "Convert-audio-files": {
        "task": "batch.transcoder.convert_audios",
        "schedule": task_period
    }
}

@app.task
def convert_audios():
    try:
        voices_to_process = query_voices_to_process()
        transcoded_voices = transcode_voices(voices_to_process)
        voices_updated = mark_converted(transcoded_voices)

        if voices_updated > 0:
            if os.environ["NOTIFY_AUTHORS"] == "TRUE":
                notify_authors(transcoded_voices)
            entries = [{'Id': str(ind), 'ReceiptHandle': msg.receipt_handle} for ind, msg in enumerate(voices_to_process) if json.loads(msg.body)['id'] in [v['id'] for v in transcoded_voices]]
            queue.delete_messages(Entries=entries)

        return "DONE with SUCCESS"
    except Exception as e:
        logger.error(f"Ocurrió un error durante la ejecución de la tarea: {str(e)}")
        return "DONE with ERRORS"
