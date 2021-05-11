from smtplib import SMTP, SMTPServerDisconnected

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To, Subject, Content, SendGridException

from utils import get_from_env

import sendgrid

def _log_error(logger, error_message):
    if logger is not None:
        logger.error(error_message)
    else:
        print(error_message)

def _log_warning(logger, warn_message):
    if logger is not None:
        logger.warn(warn_message)
    else:
        print(warn_message)

def _load_email_type():
    email_type = get_from_env(envvar="EMAIL_TYPE", default="SMTP")
    if email_type != "SMTP" and email_type != "SGRID":
        raise ValueError(f"Tipo de cliente de correo no soportado: {email_type}")
    return email_type

EMAIL_TYPE = _load_email_type()

def get_email_client(connect=False, logger=None):
    if EMAIL_TYPE == "SMTP":
        return SMTPClient(connect=connect, logger=logger)
    else:
        return SendGridClient(logger=logger)

class SMTPClient:
    def __init__(self, connect=False, logger=None):
        self._load_config()
        self._logger = logger
        self._smtp_client = None

        if connect:
            self.connect()

    def connect(self):
        try:
            if not self._config_loaded:
                self._load_config()

            # Either create the server intance or connect to the remote SMTP
            if self._smtp_client is None:
                self._smtp_client = SMTP(self._server, self._port)
            else:
                self._smtp_client.connect(self._server, self._port)
            
            # Start conversation with remote SMTP server and login using the configured credentials
            self._smtp_client.ehlo()
            self._smtp_client.starttls()
            self._smtp_client.ehlo()
            self._smtp_client.login(self._sender_account_user, self._sender_account_pwd)

            return True # signal that connection was successfully established
        except Exception as e:
            _log_error(self._logger, f"Unable to connect to SMTP Server: {e}")
            return False    # signal that we could not connect to SMTP server

    def send_email(self, target_account, message_subject, message_text):
        smtp_message = f"From: {self._sender_account_email}\nTo: {target_account}\nSubject: {message_subject}\n\n{message_text}\n\r\n"
        do_send = lambda client: client.sendmail(self._sender_account_email, [target_account], smtp_message)
        error_message = lambda e: f"Unable to send email: {e}"

        try:
            do_send(self._smtp_client)
            return True
        except SMTPServerDisconnected:
            self.connect()
            try:
                do_send(self._smtp_client)
                return True
            except Exception as inner_e:
                _log_error(self._logger, error_message(inner_e))
        except Exception as outer_e:
            _log_error(self._logger, error_message(outer_e))

        return False

    def disconnect(self):
        if self._smtp_client is not None:
            try:
                self._smtp_client.quit()
            except SMTPServerDisconnected:
                _log_warning(self._logger, "SMTP client already disconnected")
        else:
            _log_warning(self._logger, "Calling 'disconnect' on non-existing SMTP client")

    def _load_config(self):
        self._server = get_from_env("SMTP_SERVER", "servidor SMTP")
 
        port = get_from_env("SMTP_PORT", "puerto SMTP")
        try:
            self._port = int(port)
        except ValueError:
            raise ValueError(f"El puerto debe ser numérico: {port}")
        if self._port <= 0:
            raise ValueError(f"El puerto debe ser un valor positivo: {self._port}")

        self._sender_account_email = get_from_env("SMTP_SENDER_EMAIL", "cuenta de correo para el envío")
        self._sender_account_user = get_from_env("SMTP_SENDER_USER", "usuario de cuenta de correo para envío")
        self._sender_account_pwd = get_from_env("SMTP_SENDER_PWD", "contraseña de cuenta de correo para el envío")
        self._config_loaded = True

class SendGridClient:
    def __init__(self, logger=None):
        self._load_config()
        self._logger = logger
        self._smtp_client = sendgrid.SendGridAPIClient(api_key=self._api_key)

    def connect(self):
        pass

    def send_email(self, target_account, message_subject, message_text):
        from_email = From(self._sender_account)
        to_email = To(target_account)
        subject = message_subject
        content = Content("text/plain", message_text)
        mail = Mail(from_email, to_email, subject, content)

        try:
            self._smtp_client.client.mail.send.post(request_body=mail.get())
        except SendGridException as e:
            _log_error(self._logger, f"Unable to send email: {e}")

    def disconnect(self):
        pass

    def _load_config(self):
        self._sender_account = get_from_env("SMTP_SENDER", "cuenta de correo para el envvío")
        self._api_key = get_from_env("SMTP_SENDER_KEY", "api key de SendGrid para el envío")
        self._config_loaded = True
    