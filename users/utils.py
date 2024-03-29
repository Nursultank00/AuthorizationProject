import re

from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.utils.translation import gettext as _
from django.template.loader import render_to_string
from decouple import config



char_validator = RegexValidator(r'^[a-zA-Z]+$', 'Only characters are allowed.')

# Send email util
class EmailUtil:
    @staticmethod
    def send_email(data):
        # email = EmailMessage(subject=data['email_subject'],
        #                      body=data['email_body'],
        #                      to = [data['to_email']])
        
        # link = "https://neobis-front-auth-five.vercel.app/confirm?token="+data['token']
        context ={
            'link_app': config('EMAIL_LINK')+data['token'],
            'user_username' : data['username']
        }
        html_content = render_to_string(
            'email.html', context=context
        )
        email = EmailMultiAlternatives(subject = data['email_subject'], to = [data['to_email']])
        email.attach_alternative(html_content, "text/html")
        email.send()


# Password Validators
class LengthValidator:
    def __init__(self, min_length=8, max_length=15):
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(
                _("This password must contain at least %(min_length)d characters."),
                code="password_too_short",
                params={"min_length": self.min_length},
            )
        if len(password) > self.max_length:
            raise ValidationError(
                _("This password's length must be lower than %(max_length)d characters."),
                code="password_too_long",
                params={"max_length": self.max_length+1},
            )

    def get_help_text(self):
        return _(
            "Your password must contain at least %(min_length)d characters and lower than %(max_length)d characters."
            % {"min_length": self.min_length,
               "max_length": self.max_length+1}
        )

class DigitValidator:
    def __init__(self):
        pass

    def validate(self, password, user=None):
        if not any(char.isdigit() for char in password):
            raise ValidationError(
                _("This password must contain at least 1 numeric character."),
                code="no numeric character"
            )

    def get_help_text(self):
        return _(
            "Your password must contain numeric character."
        )
    
class UpperLowerValidator:
    def __init__(self):
        pass

    def validate(self, password, user=None):
        if not any(char.isupper() for char in password):
            raise ValidationError(
                _("This password must contain at least 1 upper case character."),
                code="no upper case character"
            )
        if not any(char.islower() for char in password):
            raise ValidationError(
                _("This password must contain at least 1 lower case characters."),
                code="no lower case character"
            )

    def get_help_text(self):
        return _(
            "Your password must contain upper case and lower case characters."
        )
    
class SpecialCharacterValidator:
    def __init__(self):
        pass

    def validate(self, password, user=None):
        if not re.search(r'[-_!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                _("This password must contain at least 1 special case character."),
                code="no special character"
            )

    def get_help_text(self):
        return _(
            "Your password must contain special characters."
        )
    
