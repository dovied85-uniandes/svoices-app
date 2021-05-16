#from dotenv import load_dotenv
#load_dotenv()   # in local: .env need to load before any of our modules

from celery import Celery
from celery.utils.log import get_task_logger

from batch.emails import get_email_client

from batch.utils import get_from_env

import boto3
import json
import math
import os
import subprocess
import time

audios_dir = get_from_env(envvar="AUDIO_FOLDER", default="var/svoice/media/audios")

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
    batch_name = get_from_env(envvar="BATCH_NAME", default="transcoder")
    sqs_queue_region = get_from_env(envvar="AWS_SQS_REGION", desc="Debe especificar la cola de trabajo")
    sqs_polling_interval = int(get_from_env(envvar="AWS_SQS_POLLING_INTERVAL", default="60"))
    sqs_long_polling = int(get_from_env(envvar="AWS_SQS_LONG_POLLING", default="20"))
    sqs_visibility_timeout = int(get_from_env(envvar="AWS_SQS_VISIBILITY", default="60"))
    sqs_queue_url = get_from_env(envvar="AWS_SQS_QUEUE_URL", desc="Debe especificar la url de la cola de trabajo")
    sqs_access_key_id = get_from_env(envvar="AWS_SQS_ACCESS_KEY_ID", desc="Debe especificar el id de la llave para conectarse a la cola de trabajo")
    sqs_access_key_secret = get_from_env(envvar="AWS_SQS_ACCESS_KEY_SECRET", desc="Debe especificar el secreto de la llave para conectarse a la cola de trabajo")
    broker_url = f"sqs://{sqs_access_key_id}:{sqs_access_key_secret}@"

    app = Celery(batch_name, broker = broker_url)
    app.conf.update(
        broker_transport_options = {
            "region": sqs_queue_region,
            "polling_interval": sqs_polling_interval,
            "wait_time_seconds": sqs_long_polling,
            "visibility_timeout": sqs_visibility_timeout,
            "predefined_queues": {
                "celery": {
                    "url": sqs_queue_url,
                    "access_key_id": sqs_access_key_id,
                    "secret_access_key": sqs_access_key_secret
                }
            }
        }
    )
    return app

def transcode_voice(voice, media_dir):
    # Desgargar el archivo de s3
    logger.debug("Descargando archivo de audio")
    rel_source_path = voice["rel_source_path"]
    abs_source_path = os.path.join(media_dir, rel_source_path)
    s3resource.meta.client.download_file(s3_bucket_name, abs_source_path, 'audio_original')
    
    # Convertir el archivo descargado:
    error_message = f"No se pudo convertir el archivo: {abs_source_path}"
    try:
        rel_target_path = voice["rel_target_path"]
        abs_target_path = os.path.join(media_dir, rel_target_path)
        logger.info(f"Convirtiendo archivo '{abs_source_path}' a: {abs_target_path}")
        result = subprocess.run(["ffmpeg", "-y", "-i", 'audio_original', "-f", "mp3", voice.get("file_name", 'audio_convertido'))
        if result.returncode == 0:
            s3resource.meta.client.upload_file("audio_convertido", s3_bucket_name, abs_target_path)
            return voice
    except Exception as e:
        error_message = f"{error_message}: {str(e)}"

    logger.error(error_message)
    os.remove(voice.get("file_name", 'audio_convertido'))
    return None
    
def mark_converted(converted_voice):
    if converted_voice is None:
        return False

    logger.info("Marcando como 'convertida' la voz en la base de datos.")
    with table.batch_writer() as batch:
        voice_key = {"pk": converted_voice["pk"], "sk": converted_voice["sk"]}
        status_attr = {"status": {"Value": "Convertida", "Action": "PUT"}}
        table.update_item(Key=voice_key, AttributeUpdates=status_attr)
    return True

def notify_author(voice):
    logger.info("Enviando correo de notificación de voz convertida.")
    smtp_client = get_email_client(connect=True, logger=logger)
    
    author_email = voice['author_email']
    author_first_name = voice['author_first_name']
    author_last_name = voice['author_last_name']
    voice_file_name = voice['rel_source_path'].rsplit("/", 1)[1]
    msg_text = f"Concursante {author_first_name} {author_last_name}:\n Queremos avisarle que su audio {voice_file_name} ya ha sido convertido."
    try:
        smtp_client.send_email(author_email, "Audio convertido", msg_text)
    except Exception as e:
        logger.error(f"No se pudo enviar correo de notificación a '{author_email}': {e}")

    smtp_client.disconnect()

app = create_batch()
logger = get_task_logger(__name__)

def handle_error(error, start_time):
    """
    This method favors consistency over throughput and will wailt until current_time - start_time > visibility
    to give a chance to other workers to pickup the failed voice.
    """
    current_time = time.time()
    elapsed_time = math.floor(current_time - start_time)
    visibility_timeout = int(get_from_env(envvar="AWS_SQS_VISIBILITY", default="60"))
    diff_time = visibility_timeout - elapsed_time
    if diff_time > 0:
        logger.warn(f"Sleeping for {diff_time} seconds to avoid celery acknowledging this failed task")
        time.sleep(diff_time)

@app.task()
def convert_audio(voice):
    """
    This task may complete successfully even if no convertion can be performed, so check the
    logs if you see tasks completing successfully but no voice files being converted.
    @param voice a dictionary containing the properties of the voice to be configured.
    @return "DONE with SUCCESS" when the task completes without errors and "DONE with
    ERRORS" otherwise.
    """
    start_time = time.time()
    try:
        converted_voice = transcode_voice(voice, audios_dir)
        voice_updated = mark_converted(converted_voice)

        if voice_updated and get_from_env(envvar="NOTIFY_AUTHORS", default="FALSE") == "TRUE":
            notify_author(converted_voice)
        return "DONE with SUCCESS"
    except Exception as e:
        logger.error(f"Error inesperado durante la ejecución de la tarea: {str(e)}")
        handle_error(e, start_time)
        return "DONE with ERRORS"
