from datetime import date, datetime, timedelta

from api.error import CustomValidationError

from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

import enum
import api.files as files
import os
import uuid

import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb_table_region = os.environ["AWS_DYNAMODB_REGION"]
dynamodb_access_key_id = os.environ["AWS_DYNAMODB_ACCESS_KEY_ID"]
dynamodb_access_key_secret = os.environ["AWS_DYNAMODB_ACCESS_KEY_SECRET"]
dynamodb_table_name = os.environ["AWS_DYNAMODB_TABLE_NAME"]

table = boto3.resource('dynamodb', region_name=dynamodb_table_region,
    aws_access_key_id=dynamodb_access_key_id, aws_secret_access_key=dynamodb_access_key_secret).Table(dynamodb_table_name)

def sanitize_str_repr(value, length):
    sanitized_value = value
    if len(sanitized_value) > length:
        sanitized_value = f"{value[0:length]}..."
    return sanitized_value

def validate_required_string(value, error_message):
    sanitized_value = value.strip()
    if len(sanitized_value) == 0:
        raise CustomValidationError(error_message)
    return sanitized_value

def validate_media(http_request, allowed_media_validator, get_allowed_media, error_message):
    request_files = http_request.files
    if "file" not in request_files:
        raise CustomValidationError(error_message)

    media_filename = validate_required_string(request_files["file"].filename, error_message)
    if not allowed_media_validator(media_filename):
        raise CustomValidationError(f"Archivo '{media_filename}' debe ser de tipo: {get_allowed_media()}")

    return request_files["file"]

def generate_id():
    raw_id = uuid.uuid4()
    return str(raw_id)

"""
    Enumeration of possible status a voice can be in.
"""
class VoiceStatus(enum.Enum):
    RECEIVED = "Recibida"
    IN_PROGRESS = "En proceso"
    CONVERTED = "Convertida"

    @staticmethod
    def get_possible_statuses():
        return list(map(lambda status: status.name, list(VoiceStatus)))

class User:
    """ An admin in our system. """
    def __init__(self, email="", secret="", first_name="", last_name=""):
        self.email = self.validate_email("email", email)
        self.secret = self.validate_secret("secret", secret)
        self.first_name = self.validate_names("first_name", first_name)
        self.last_name = self.validate_names("last_name", last_name)

    def __repr__(self):
        return f"<User: email={self.email},\
            first_name={self.first_name},\
            last_name={self.last_name}>"

    def validate_email(self, key, value):
        sanitized_address = value.strip()
        if len(sanitized_address) == 0:
            raise CustomValidationError("Debe proporcionar su login")
        return sanitized_address
    
    def validate_secret(self, key, value):
        santized_secret = value.strip()
        if len(santized_secret) == 0:
            raise CustomValidationError("Debe proporcionar su contraseña")
        return santized_secret

    def validate_names(self, name_type, value):
        sanitized_name = value.strip()
        if len(sanitized_name) == 0:
            field_name = "nombre"
            if name_type == "last_name":
                field_name = "apellido"
            raise CustomValidationError(f"Debe proporcionar su {field_name}")
        return sanitized_name

    def hash_secret(self):
        hashed_secret = generate_password_hash(self.secret).decode('utf8')
        self.secret = hashed_secret

    def check_secret(self, other_secret):
        return check_password_hash(self.secret, other_secret)

    def to_json_obj(self):
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name
        }

    @staticmethod
    def from_dict(api_user):
        model_user = User(email=api_user.get("email", ""),
            secret=api_user.get("secret", ""),
            first_name=api_user.get("first_name", ""),
            last_name=api_user.get("last_name", ""))
        return model_user

class Contest:
    """ An contest in our system. """
    def __init__(self, **kwargs):
        # If start date was provided, (1) check if it is a string that can be parsed to a date and parse it,
        # or check if it is already a date.
        if "start_date" in kwargs:
            raw_start_date = kwargs.get("start_date", "")
            start_date = Contest._get_required_date(raw_start_date, "fecha inicio")
            kwargs["start_date"] = start_date 
        else:
            start_date = None

        # If end date was provided, (1) check if it is a string that can be parsed to a date and parse it,
        # or check if it is already a date.
        if "end_date" in kwargs:
            raw_end_date = kwargs.get("end_date", "")
            end_date = Contest._get_required_date(raw_end_date, "fecha fin")
            kwargs["end_date"] = end_date
        else:
            end_date = None
        
        # Check that start & end dates define a valid date range
        if start_date is not None and end_date is not None:
            Contest._validate_date_range(start_date, end_date)

        # If "id" is not present, this is a creation. Generate the UUID and update the dict so it gets saved to the DB.
        if "id" not in kwargs:
            id = generate_id()
            kwargs["id"] = id

        # Update/initialize "rel_image_path" if "image_storage" is present.
        if "image_storage" in kwargs:
            image_storage = kwargs["image_storage"]
            del kwargs["image_storage"]
            kwargs["rel_image_path"] = files.get_rel_image_path(id, image_storage.filename)
        else:
            image_storage = None

        self.id = kwargs["id"]
        self.name = self.validate_strings("name", kwargs.get("name", ""))

        if "rel_image_path" in kwargs:
            self.rel_image_path = kwargs["rel_image_path"]

        self.url = self.validate_url("url", kwargs.get("url", ""))

        if "start_date" in kwargs:
            self.start_date = kwargs["start_date"]
        if "end_date" in kwargs:
            self.end_date = kwargs["end_date"]

        self.pay = self.validate_pay("pay", kwargs.get("pay", ""))
        self.script = self.validate_strings("script", kwargs.get("script", ""))

        if "recommendations" in kwargs:
            self.recommendations = kwargs["recommendations"]

        self.user_ref = self.validate_strings("user_ref", kwargs.get("user_ref", ""))

        if image_storage is not None:
            self._store_image(image_storage)    # We'll need to undo this if DB operation fails

    def __repr__(self):
        return f"<Contest: id={self.id},\
          name={self.name},\
          rel_image_path={self.rel_image_path},\
          url={self.url},\
          start_date={self.start_date},\
          end_date={self.end_date},\
          pay={self.pay},\
          script={sanitize_str_repr(self.script, 10)},\
          recommendations={sanitize_str_repr(self.recommendations, 10)},\
          admin_email={self.user_ref}>"

    def validate_url(self, key, value):
        sanitized_url = validate_required_string(value, "Debe enviar la url del concurso")
        
        if sanitized_url == "/":
            raise CustomValidationError("La url del evento no puede ser la raíz '/'")
        return sanitized_url

    def validate_strings(self, key, value):
        if key == "name":
            label = "el nombre"
        elif key == "user_ref":
            label = "el correo del administrador"
        else:
            label = "el guión"
        return validate_required_string(value, f"Debe enviar {label} del concurso")

    def validate_pay(self, key, value):
        error_message = f"El pago es requerido y debe ser un entero no negativo: '{value}'"
        try:
            pay = int(value)
        except ValueError:
            raise CustomValidationError(error_message)

        if pay < 0:
            raise CustomValidationError(error_message)
        return value

    def update_from_api(self, http_request):
        # Validate only if provided
        if "name" in http_request.form:
            new_name = self.validate_strings("name", http_request.form["name"])
            self.name = new_name
        
        # Validate only if provided
        if "url" in http_request.form:
            new_url = self.validate_url("url", http_request.form["url"])
            self.url = new_url

        # Validate only if provided
        check_range = False
        if "start_date" in http_request.form:
            new_date = Contest._get_required_date(http_request.form["start_date"], "fecha inicio")
            self.start_date = new_date
            check_range = True
        
        # Validate only if provided
        if "end_date" in http_request.form:
            new_date = Contest._get_required_date(http_request.form["end_date"], "fecha fin")
            self.end_date = new_date
            check_range = True

        # Validate date range if either start or end date was provided
        if check_range:
            Contest._validate_date_range(self.start_date, self.end_date)

        # Validate only if provided
        if "pay" in http_request.form:
            new_pay = self.validate_pay("pay", http_request.form["pay"])
            self.pay = new_pay

        # Validate only if provided
        if "script" in http_request.form:
            new_script = self.validate_strings("script", http_request.form["script"])
            self.script = new_script

        # Update if supplied, no need to validate
        if "recommendations" in http_request.form:
            self.recommendations = http_request.form["recommendations"]

        # Leave this one for last: if new image was provided, store the new image in file system.
        # If a DB error occurs when updating, we need to remove this new image from the file system;
        # if DB operation is successful, we need to remove the old image from the file system (if the
        # image was updated).
        if "file" in http_request.files:
            new_image_storage = Contest._validate_image(http_request)
            old_image_path = self.rel_image_path
            new_image_path = files.get_rel_image_path(self.id, new_image_storage.filename)

            if old_image_path != new_image_path:
                self.rel_image_path = new_image_path
                self._store_image(new_image_storage)
                return old_image_path
        return None # Signal that image wasn't updated

    def remove_image(self, image_path=None):
        if image_path is None:
            image_path = self.rel_image_path
        files.remove_image_file(image_path)

    def to_json_obj(self):
        return {
            "id": self.id,
            "name": self.name,
            "image_path": self.rel_image_path,
            "url": self.url,
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "pay": int(self.pay),
            "script": self.script,
            "recommendations": self.recommendations,
            "user_ref": self.user_ref
        }

    def _store_image(self, image_storage):
        files.store_image_file(image_storage, self.rel_image_path)

    def delete_media(self):
        files.remove_image_subdir(self.id)
        files.remove_audio_subdir(self.id)

    @staticmethod
    def _get_required_date(value, date_label):
        if isinstance(value, date):
            return value

        sanitized_value = value.strip()
        if len(sanitized_value) == 0:
            raise CustomValidationError(f"Debe proporcionar la {date_label}")

        try:
            parsed_date = datetime.strptime(sanitized_value, "%Y-%m-%d").date()
        except ValueError:
            raise CustomValidationError(f"El formato de {date_label} debe ser: 'YYYY-MM-DD'")
        return parsed_date

    @staticmethod
    def _validate_date_range(start_date, end_date):
        if start_date > end_date:
            raise CustomValidationError("Fecha de inicio no puede ser mayor o igual que la fecha final")

    @staticmethod
    def _validate_image(http_request):
        request_files = http_request.files
        if "file" not in request_files:
            raise CustomValidationError("Debe enviar el archivo con la imagen del concurso")

        image_filename = validate_required_string(request_files["file"].filename, "Debe enviar el nombre del archivo de la imagen del concurso")
        if not files.allowed_image(image_filename):
            raise CustomValidationError(f"Archivo de imagen '{image_filename}' debe ser de tipo: f{files.get_supported_images()}")

        return request_files["file"]

    @staticmethod
    def from_api(http_request, owning_admin):
        image_storage = Contest._validate_image(http_request)
        model_contest = Contest(name=http_request.form.get("name", ""),
            image_storage=image_storage,
            url=http_request.form.get("url", ""),
            start_date=http_request.form.get("start_date", ""),
            end_date=http_request.form.get("end_date", ""),
            pay=http_request.form.get("pay", ""),
            script=http_request.form.get("script", ""),
            recommendations=http_request.form.get("recommendations", ""),
            user_ref=owning_admin)
        return model_contest

    @staticmethod
    def get_contests_by_user(email, page):
        response = table.query(KeyConditionExpression=Key('pk').eq('USER#' + email), FilterExpression=Attr('type').eq('contest'))
        contest_list = response['Items']
        contest_list.sort(key=lambda x: x['start_date'])

        for c in contest_list:
            path = c["rel_image_path"]
            del c["rel_image_path"]
            c["image_path"] = path

        contest_qty = response['Count']

        # TODO paginate with "Limit" + "LastEvaluatedKey"
        if (page.offset - 1) * page.limit < contest_qty:
            contest_list = contest_list[(page.offset - 1) * page.limit : min(page.offset * page.limit, contest_qty)]
        else:
            contest_list = []
        return {'total': contest_qty, 'items': contest_list}

    @staticmethod
    def find_by_id_and_email(id, email):
        return table.get_item(Key={'pk': 'USER#' + email, 'sk': 'CONTEST#' + id}).get('Item')

    @staticmethod
    def find_by_url(url):
        return table.scan(FilterExpression=Attr('url').eq(url))['Items']

class Page:
    def __init__(self, offset=1, limit=10):
        if offset < 1:
            self.offset = 1
        else:
            self.offset = offset
        
        if limit < 10:
            self.limit = 10
        else:
            self.limit = limit

    @staticmethod
    def from_http_request(http_request):
        offset = int(http_request.args.get("offset", "1"))
        limit = int(http_request.args.get("limit", "10"))
        return Page(offset, limit)

class PagedResult:
    def __init__(self, pagination, json_mapper):
        self.total = int(pagination.total)
        self.has_more = pagination.has_next
        self.items = list(map(json_mapper, pagination.items))

    def to_json_obj(self):
        return {
            "total": self.total,
            "has_more": self.has_more,
            "items": self.items
        }

    @staticmethod
    def _get_pagination(pagination):
        if pagination is None:
            raise CustomValidationError("No se puede construir resultado paginado sin el objeto de paginación", 500)
        return pagination
    
    @staticmethod
    def _get_json_mapper(json_mapper):
        if json_mapper is None or not callable(json_mapper):
            raise CustomValidationError("El mapeador a json debe ser una función que se pueda ejecutar", 500)
        return json_mapper

    @staticmethod
    def build(pagination, json_mapper):
        mapper = PagedResult._get_json_mapper(json_mapper)
        paginated_query = PagedResult._get_pagination(pagination)
        return PagedResult(paginated_query, mapper)

class Voice:
    """ Represents a contest voice """
    def __init__(self, **kwargs):
        # If "id" is not present, this is a creation. Generate the UUID and update the dict so it gets saved to the DB.
        if "id" not in kwargs:
            id = generate_id()
            kwargs["id"] = id

        # Need to validate "contest_ref" here and not in a @validates method, since we need its value for the source
        # and target relative path names
        contest_ref = validate_required_string(kwargs.get("contest_ref", ""), "Debe enviar el identificador del concurso de la voz")
        kwargs["contest_ref"] = contest_ref

        # Need to validate "author_email" here and not in a @validates method, since we need its value for th source
        # and target relative path names
        author_email = validate_required_string(kwargs.get("author_email", ""), "Debe enviar el correo del autor de la voz")
        kwargs["author_email"] = author_email

        # Update/initialize "rel_source_path" and "rel_target_path" if "audio_storage" is present.
        if "audio_storage" in kwargs:
            audio_storage = kwargs["audio_storage"]
            del kwargs["audio_storage"]

            kwargs["rel_source_path"] = files.get_rel_audio_path(contest_ref, author_email, audio_storage.filename)
            kwargs["rel_target_path"] = kwargs["rel_source_path"].rsplit(".", 1)[0] + ".mp3"    # just replacing the original extension
        else:
            audio_storage = None

        self.id = kwargs["id"]
        self.author_first_name = self.validate_strings("author_first_name", kwargs.get("author_first_name", ""))
        self.author_last_name = self.validate_strings("author_last_name", kwargs.get("author_last_name", ""))
        self.author_email = kwargs["author_email"]

        if "rel_source_path" in kwargs:
            self.rel_source_path = kwargs["rel_source_path"]

        if "rel_target_path" in kwargs:
            self.rel_target_path = kwargs["rel_target_path"]

        if "observations" in kwargs:
            self.observations = kwargs["observations"]

        self.status = self.validate_status("status", kwargs.get("status", ""))
        self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conversion_started = kwargs.get("conversion_started", "")

        if "contest_ref" in kwargs:
            self.contest_ref = kwargs["contest_ref"]

        self.user_ref = self.validate_strings("user_ref", kwargs.get("user_ref", ""))

        if audio_storage is not None:
            self._store_source_audio(audio_storage)    # We'll need to delete it if there's a DB error when creating/updating this entity

    def __repr__(self):
        return f"<Voice: id={self.id},\
            author_first_name={self.author_first_name},\
            author_last_name={self.author_last_name},\
            author_email={self.author_email},\
            source_path={self.rel_source_path},\
            target_path={self.rel_target_path},\
            observations={sanitize_str_repr(self.observations, 10)},\
            status={self.status},\
            created_at={self.created_at},\
            contest_ref={self.contest_ref},\
            user_ref={self.user_ref}>"

    def to_json_obj(self):
        return {
            "id": self.id,
            "author_first_name": self.author_first_name,
            "author_last_name": self.author_last_name,
            "author_email": self.author_email,
            "source_path": self.rel_source_path,
            "target_path": self.rel_target_path,
            "observations": self.observations,
            "status": self.status,
            "created_at": self.created_at
        }

    def remove_audio(self):
        files.remove_audio_file(self.rel_source_path)

    def _store_source_audio(self, audio_storage):
        files.store_audio_file(audio_storage, self.rel_source_path)

    def validate_strings(self, key, value):
        if key == "author_first_name":
            label = "el nombre del autor"
        elif key == "author_last_name":
            label = "el apellido del autor"
        else:
            label = "el correo del administrador"
        return validate_required_string(value, f"Debe enviar {label} de la voz")

    def validate_status(self, key, value):
        sanitized_status = value.strip()
        try:
            VoiceStatus(sanitized_status)
        except ValueError:
            accepted_statuses = VoiceStatus.get_possible_statuses()
            raise CustomValidationError(f"Debe proporcionar un estado válido: {accepted_statuses}")    
        return sanitized_status

    @staticmethod
    def _validate_audio(http_request):
        return validate_media(http_request, files.allowed_audio, files.get_supported_audios, "Debe enviar el archivo de voz y este debe tener un nombre no vacío")

    @staticmethod
    def from_api(http_request, contest_id, owning_admin):
        audio_storage = Voice._validate_audio(http_request)
        model_voice = Voice(author_first_name=http_request.form.get("author_first_name", ""),
            author_last_name=http_request.form.get("author_last_name", ""),
            author_email=http_request.form.get("author_email", ""),
            audio_storage=audio_storage,
            observations=http_request.form.get("observations", ""),
            status=VoiceStatus.RECEIVED.value,
            contest_ref=contest_id,
            user_ref=owning_admin)
        return model_voice

    @staticmethod
    def get_voices_by_contest_and_admin(email, contest_id, page, all=False):
        if all:
            response = table.query(KeyConditionExpression=Key('pk').eq('CONTEST#' + contest_id))
        else:
            response = table.query(KeyConditionExpression=Key('pk').eq('CONTEST#' + contest_id), FilterExpression=Attr('status').eq('Convertida'))

        voice_list = response['Items']
        voice_list.sort(key=lambda x: x['created_at'], reverse=True)
        voice_qty = response['Count']

        for v in voice_list:
            path = v["rel_source_path"]
            del v["rel_source_path"]
            v["source_path"] = path
            path = v["rel_target_path"]
            del v["rel_target_path"]
            v["target_path"] = path

        # TODO paginate with "Limit" + "LastEvaluatedKey"
        if all:
            return {'total': voice_qty, 'items': voice_list}

        if (page.offset - 1) * page.limit < voice_qty:
            voice_list = voice_list[(page.offset - 1) * page.limit : min(page.offset * page.limit, voice_qty)]
        else:
            voice_list = []
        return {'total': voice_qty, 'items': voice_list}
