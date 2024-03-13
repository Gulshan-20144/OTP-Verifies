from django.core.mail import send_mail,EmailMessage
from django.utils.crypto import get_random_string
import random  # Consider removing this import if not used elsewhere
from django.conf import settings
import os
from .models import User

def send_otp_via_email(email):
    subject = 'Your Account Verification Email'
    otp = random.randint(1000, 9999)  # Using otp instead of random
    message = f"Your otp is {otp}"
    email_from = settings.EMAIL_HOST_USER
    # print(email_from)
    use = send_mail(subject, message, email_from, [email])
    # print(use)
    user_obj = User.objects.get(email=email)
    # print(user_obj)
    user_obj.otp = otp
    user_obj.save()

def send_email(data):
    eamil=EmailMessage(
        subject=data["email_subject"],
        body=data['body'],
        from_email=os.environ.get("EMAIL_FROM"),
        to=[data['to_email']]
    )
    eamil.send()