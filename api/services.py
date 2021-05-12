from boto3.dynamodb.conditions import Key, Attr

from datetime import timedelta

from api.db import Contest, User, Voice, table, Page

from dotenv import load_dotenv

from api.error import CustomValidationError

from flask import Flask, abort, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

import boto3
import api.files
import json
import os

sqs_queue_region = os.environ["AWS_SQS_REGION"]
sqs_queue_access_key_id = os.environ["AWS_SQS_ACCESS_KEY_ID"]
sqs_queue_access_key_secret = os.environ["AWS_SQS_ACCESS_KEY_SECRET"]
sqs_queue_name = os.environ["AWS_SQS_QUEUE_NAME"]

queue = boto3.resource('sqs', region_name=sqs_queue_region, aws_access_key_id=sqs_queue_access_key_id, aws_secret_access_key=sqs_queue_access_key_secret)\
    .get_queue_by_name(QueueName=sqs_queue_name)

def get_bool_envvar(varname, default_value):
    if varname in os.environ:
        return os.environ[varname].lower in {"1", "true"}
    else:
        return default_value

def _create_flask_app(name):
    app = Flask(name)
    CORS(app)

    # Our default error handler
    @app.errorhandler(CustomValidationError) 
    def handler_validation_error(e):
        return _handle_error_as_json(e, str(e), e.status)

    @app.errorhandler(404)
    def handler_not_found(e):
        return _handle_error_as_json(e, "Entidad no encontrada", 404)

    def _handle_error_as_json(exception, error_msg, status):
        app.logger.error(f"An error occurred: {exception}")
        response = jsonify(message=error_msg)
        response.status_code = status
        response.content_type = "application/json"
        return response

    # Map env vars to the correct python type
    if "MAX_CONTENT_LENGTH" in os.environ:
        app.config["MAX_CONTENT_LENGTH"] = int(os.environ["MAX_CONTENT_LENGTH"])
    app.config["JSON_AS_ASCII"] = get_bool_envvar("JSON_AS_ASCII", False)
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = get_bool_envvar("JSONIFY_PRETTYPRINT_REGULAR", False)
    app.config["JSON_SORT_KEYS"] = get_bool_envvar("JSON_SORT_KEYS", False)

    return app

def config_jwt(flask_app):
    # Configure token seeds
    if "JWT_SECRET_KEY" not in os.environ or len(os.environ["JWT_SECRET_KEY"].strip()) == 0:
        raise ValueError("Please configure the JWT secret key for jwt token generation")
    else:
        flask_app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"].strip()

    # Configure token duration
    if  "JWT_ACCESS_TOKEN_EXPIRES" not in flask_app.config:
        if "JWT_ACCESS_TOKEN_EXPIRES" in os.environ:
            flask_app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.environ["JWT_ACCESS_TOKEN_EXPIRES"])
        else:
            flask_app.logger.info("Token duration not found. Using defaults.")
            flask_app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 86400    # value must be in seconds

    return JWTManager(flask_app)

def config_bcrypt(flask_app):
    return Bcrypt(flask_app)

def _get_credential(request_payload, credential_type, error_message):
    credential = request_payload.get(credential_type, "").strip()
    if len(credential) == 0:
        raise CustomValidationError(error_message)
    return credential

def _get_login(request_credentials):
    return _get_credential(request_credentials, "email", "Debe especificar el login")
        
def _get_secret(request_credentials):
    return _get_credential(request_credentials, "secret", "Debe especificar la contraseña")

# Init flask + extensions + application setup
load_dotenv()
app = _create_flask_app(__name__)
jwt = config_jwt(app)
bcrypt = config_bcrypt(app)

files.create_media_dirs(app)

@app.route("/api/v1/users", methods=["POST"])
def register():
    model_user = User.from_dict(request.json)
    model_user.hash_secret()

    user_to_return = model_user.to_json_obj()
    user_json = dict(user_to_return)
    user_json.update({'pk': 'USER#' + model_user.email, 'sk': 'PROFILE', 'secret': model_user.secret, 'type': 'user'})
    table.put_item(Item=user_json)

    return user_to_return

@app.route("/api/v1/users/<string:email>/token", methods=["POST"])
def login(email):
    secret = _get_secret(request.json) # Check secret was specified before going to the DB

    # Fetch user:
    model_user = table.get_item(Key={'pk': 'USER#' + email, 'sk': 'PROFILE'}, AttributesToGet=['email', 'secret', 'first_name', 'last_name']).get('Item')
    if model_user is None:
        raise CustomValidationError("Usuario no existe", 404)

    # Validate provided secret
    model_user = User.from_dict(model_user)
    authorized = model_user.check_secret(secret)
    if not authorized:
        raise CustomValidationError("Credenciales inválidas", 401)

    # Generate & return authorization token
    access_token = create_access_token(identity=str(model_user.email))
    return {"access_token": access_token}

@app.route("/api/v2/contests")
@jwt_required()
def get_contests_v2():
    email = get_jwt_identity()
    return get_contests(email)

@app.route("/api/v1/users/<string:email>/contests")
def get_contests(email):
    app.logger.debug(f"Retrieving contests for user: {email}")

    # Get pagination details
    page = Page.from_http_request(request)
    return Contest.get_contests_by_user(email, page)

@app.route("/api/v2/contests", methods=["POST"])
@jwt_required()
def create_contest_v2():
    email = get_jwt_identity()
    return create_contest(email)

@app.route("/api/v1/users/<string:email>/contests", methods=["POST"])
def create_contest(email):
    # Create the contest entity, which will first validate the supplied attributes
    try:
        model_contest = Contest.from_api(request, email)
    except OSError as ose:
        error_msg = str(ose)
        raise CustomValidationError(error_msg)

    # If we made it here, contest img is in DB. Try to store the entity
    # and delete the image from the filesystem if there was a DB error
    contest_to_return = model_contest.to_json_obj()
    contest_json = dict(contest_to_return)
    path = contest_json["image_path"]
    del contest_json["image_path"]
    contest_json["rel_image_path"] = path
    contest_json.update({'pk': 'USER#' + email, 'sk': 'CONTEST#' + model_contest.id, 'type': 'contest'})
    table.put_item(Item=contest_json)

    return contest_to_return

@app.route("/api/v2/contests/<string:contest_id>", methods=["PUT"])
@jwt_required()
def update_contest_v2(contest_id):
    email = get_jwt_identity()
    return update_contest(email, contest_id)

@app.route("/api/v1/users/<string:email>/contests/<string:contest_id>", methods=["PUT"])
def update_contest(email, contest_id):
    # Check if the contest we want to update exists and is owned by the calling admin
    model_contest = Contest.find_by_id_and_email(contest_id, email)
    if model_contest is None:
        raise CustomValidationError("Concurso no existe", 404)

    model_contest = Contest(id=model_contest.get("id", ""),
            name=model_contest.get("name", ""),
            rel_image_path=model_contest.get("rel_image_path", ""),
            url=model_contest.get("url", ""),
            start_date=model_contest.get("start_date", ""),
            end_date=model_contest.get("end_date", ""),
            pay=model_contest.get("pay", ""),
            script=model_contest.get("script", ""),
            recommendations=model_contest.get("recommendations", ""),
            user_ref=model_contest.get("user_ref", ""))

    # Let the entity validate & update its attributes from the request data
    old_image_path = model_contest.update_from_api(request)
    
    # Try to update the entity
    # and delete the previous image if successful
    # TODO if dynamo update fails, remove the new image from s3
    table.update_item(Key={'pk': 'USER#' + email, 'sk': 'CONTEST#' + model_contest.id}, AttributeUpdates={
        'name': {'Value': model_contest.name, 'Action': 'PUT'},
        'rel_image_path': {'Value': model_contest.rel_image_path, 'Action': 'PUT'},
        'url': {'Value': model_contest.url, 'Action': 'PUT'},
        'start_date': {'Value': model_contest.start_date.strftime("%Y-%m-%d"), 'Action': 'PUT'},
        'end_date': {'Value': model_contest.end_date.strftime("%Y-%m-%d"), 'Action': 'PUT'},
        'pay': {'Value': model_contest.pay, 'Action': 'PUT'},
        'script': {'Value': model_contest.script, 'Action': 'PUT'},
        'recommendations': {'Value': model_contest.recommendations, 'Action': 'PUT'},
        'user_ref': {'Value': model_contest.user_ref, 'Action': 'PUT'}
        }
    )

    if old_image_path is not None:  # this means a new image was uploaded & stored
        model_contest.remove_image(old_image_path)

    return model_contest.to_json_obj()

@app.route("/api/v2/contests/<string:contest_id>", methods=["DELETE"])
@jwt_required()
def delete_contest_v2(contest_id):
    email = get_jwt_identity()
    return delete_contest(email, contest_id)

@app.route("/api/v1/users/<string:email>/contests/<string:contest_id>", methods=["DELETE"])
def delete_contest(email, contest_id):
    model_contest = Contest.find_by_id_and_email(contest_id, email)
    if model_contest is None:
        raise CustomValidationError("Concurso no existe", 404)

    model_contest = Contest(id=model_contest.get("id", ""),
            name=model_contest.get("name", ""),
            rel_image_path=model_contest.get("rel_image_path", ""),
            url=model_contest.get("url", ""),
            start_date=model_contest.get("start_date", ""),
            end_date=model_contest.get("end_date", ""),
            pay=model_contest.get("pay", ""),
            script=model_contest.get("script", ""),
            recommendations=model_contest.get("recommendations", ""),
            user_ref=model_contest.get("user_ref", ""))

    # delete contest (from user)
    table.delete_item(Key={'pk': 'USER#' + email, 'sk': 'CONTEST#' + contest_id})

    # delete voices in contest (first query voices, then delete them)
    contest_voices = table.query(KeyConditionExpression=Key('pk').eq('CONTEST#' + contest_id))['Items']
    for contest_voice in contest_voices:
        table.delete_item(Key={'pk': contest_voice['pk'], 'sk': contest_voice['sk']})

    model_contest.delete_media()    # Only delete if commit succeeded
    return model_contest.to_json_obj()

@app.route("/api/v1/contests/<path:friendly_url>")
def get_contest(friendly_url):
    model_contests = Contest.find_by_url('/' + friendly_url)
    if len(model_contests) == 0:
        raise CustomValidationError("Concurso no existe", 404)

    model_contest = model_contests[0]
    model_contest = Contest(id=model_contest.get("id", ""),
            name=model_contest.get("name", ""),
            rel_image_path=model_contest.get("rel_image_path", ""),
            url=model_contest.get("url", ""),
            start_date=model_contest.get("start_date", ""),
            end_date=model_contest.get("end_date", ""),
            pay=model_contest.get("pay", ""),
            script=model_contest.get("script", ""),
            recommendations=model_contest.get("recommendations", ""),
            user_ref=model_contest.get("user_ref", ""))
    return model_contest.to_json_obj()

@app.route("/api/v1/users/<string:email>/contests/<string:contest_id>/voices")
def get_public_contest_voices(email, contest_id):
    # Perform the paginated query
    page = Page.from_http_request(request)
    return Voice.get_voices_by_contest_and_admin(email=email, contest_id=contest_id, page=page)

@app.route("/api/v2/contests/<string:contest_id>/voices")
@jwt_required()
def get_admin_contest_voices_v2(contest_id):
    email = get_jwt_identity()
    return get_admin_contest_voices(email, contest_id)

@app.route("/api/v1/admin/<string:email>/contests/<string:contest_id>/voices")
def get_admin_contest_voices(email, contest_id):
    # Perform the paginated query
    page = Page.from_http_request(request)
    return Voice.get_voices_by_contest_and_admin(email, contest_id, page, True)

@app.route("/api/v1/users/<string:email>/contests/<string:contest_id>/voices", methods=["POST"])
def create_contest_voice(email, contest_id):
    # Create the voice entity, which will validate the supplied attributes
    try:
        model_voice = Voice.from_api(request, contest_id, email)
    except OSError as ose:
        error_msg = str(ose)
        raise CustomValidationError(error_msg)

    voice_json = dict(model_voice.to_json_obj())
    path = voice_json['source_path']
    del voice_json['source_path']
    voice_json['rel_source_path'] = path
    path = voice_json['target_path']
    del voice_json['target_path']
    voice_json['rel_target_path'] = path

    # TODO call "model_voice.remove_audio()" if dynamo operation fails
    voice_json.update({'pk': 'CONTEST#' + contest_id, 'sk': 'VOICE#' + model_voice.id, 'type': 'voice'})
    table.put_item(Item=voice_json)

    # send message to the queue:
    queue.send_message(MessageBody=json.dumps(voice_json))

    return model_voice.to_json_obj()
