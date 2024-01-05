import random
from django.core.mail import send_mail
from django.conf import settings


def send_otp_via_email(email):
    subject = 'Your account verification email'
    otp = random.randint(1000, 9999)
    message = f'Your otp is {otp}'
    email_from = settings.EMAIL_HOST
    send_mail(subject, message, email_from, [email])
    return otp
    