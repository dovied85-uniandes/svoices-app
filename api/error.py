from marshmallow.exceptions import ValidationError

class CustomValidationError(ValidationError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self._status = status

    @property
    def status(self):
        return self._status