from flask import current_app
from werkzeug.utils import secure_filename

import boto3
import os

ALLOWED_IMAGE_TYPES = {"png", "jpg", "jpeg", "gif"}
ALLOWED_AUDIO_TYPES = {"wav", "wma", "mp3", "ogg", "flac", "aac", "aiff", "m4a"}

s3_bucket_region = os.environ["AWS_S3_REGION"]
s3_access_key_id = os.environ["AWS_S3_ACCESS_KEY_ID"]
s3_access_key_secret = os.environ["AWS_S3_ACCESS_KEY_SECRET"]
s3_bucket_name = os.environ["AWS_S3_BUCKET_NAME"]

s3client = boto3.client('s3', region_name=s3_bucket_region,
    aws_access_key_id=s3_access_key_id, aws_secret_access_key=s3_access_key_secret)
s3resource = boto3.resource('s3', region_name=s3_bucket_region,
    aws_access_key_id=s3_access_key_id, aws_secret_access_key=s3_access_key_secret)

def create_media_dirs(flask_app):
    root_dir = os.environ["UPLOAD_FOLDER"]
    global AUDIO_DIR
    global IMAGE_DIR
    
    # Media folder should already exist in the bucket (but it really doesn't have to)
    AUDIO_DIR = os.path.join(root_dir, "audios")
    IMAGE_DIR = os.path.join(root_dir, "images")

def store_media_file(media_storage, relative_path, root_media_dir):
    path_tokens = relative_path.rsplit(os.path.sep, 1)
    relative_dir = path_tokens[0]
    filename = path_tokens[1]
    contest_dir = os.path.join(root_media_dir, relative_dir)
    absolute_path = os.path.join(contest_dir, filename)

    current_app.logger.debug(f"Storing media file: {absolute_path}")
    s3client.upload_fileobj(media_storage, s3_bucket_name, absolute_path, ExtraArgs={'Metadata': {'Content-Disposition': 'attachment'}})
    media_storage.close()

def remove_media_file(relative_path, get_abs_media_path):
    absolute_path = get_abs_media_path(relative_path)
    current_app.logger.warn(f"Removing media: {absolute_path}")
    s3client.delete_object(Bucket=s3_bucket_name, Key=absolute_path)

def allowed_image(filename):
    return _allowed_file(filename, ALLOWED_IMAGE_TYPES)

def get_supported_images():
    return str(ALLOWED_IMAGE_TYPES)

def get_rel_image_path(contest_id, image_filename):
    sanitized_filename = secure_filename(image_filename)
    return os.path.join(contest_id, sanitized_filename)

def get_abs_image_path(relative_path):
    return os.path.join(IMAGE_DIR, relative_path)

def store_image_file(image_storage, relative_path):
    absolute_path = get_abs_image_path(relative_path)
    s3client.upload_fileobj(image_storage, s3_bucket_name, absolute_path, ExtraArgs={'Metadata': {'Content-Disposition': 'attachment'}})
    image_storage.close()

def remove_image_file(relative_path):
    remove_media_file(relative_path, get_abs_image_path)

def remove_audio_file(relative_path):
    remove_media_file(relative_path, get_abs_audio_path)

def remove_image_subdir(subdir_name):
    absolute_path = get_abs_image_path(subdir_name)
    s3resource.Bucket(s3_bucket_name).objects.filter(Prefix=absolute_path).delete()

def allowed_audio(filename):
    return _allowed_file(filename, ALLOWED_AUDIO_TYPES)

def get_supported_audios():
    return str(ALLOWED_AUDIO_TYPES)

def get_abs_audio_path(relative_path):
    return os.path.join(AUDIO_DIR, relative_path)

def get_rel_audio_path(contest_id, author_email, audio_filename):
    sanitized_email = _cleanup_email(author_email)
    sanitized_filename = secure_filename(audio_filename)
    composed_filename = f"{sanitized_email}_{sanitized_filename}"
    return os.path.join(contest_id, composed_filename)

def store_audio_file(audio_storage, relative_path):
    store_media_file(audio_storage, relative_path, AUDIO_DIR)

def remove_audio_subdir(subdir_name):
    absolute_path = get_abs_audio_path(subdir_name)
    s3resource.Bucket(s3_bucket_name).objects.filter(Prefix=absolute_path).delete()

def _cleanup_email(raw_email):
    """ TODO: replace with a more elaborate & performant scheme if time allows """
    return raw_email.replace("@", ".")

def _get_audio_path(contest_id, author_email, audio_filename):
    sanitized_filename = secure_filename(audio_filename)
    composed_name = f"{author_email}_{sanitized_filename}"
    return os.path.join(AUDIO_DIR, contest_id, composed_name)

def _allowed_file(filename, allowed_set):
    return '.' in filename and \
        filename.rsplit(".", 1)[1].lower() in allowed_set
