from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .emails import send_otp_via_email
from .utils import generate_unique_username, generate_password
from django.contrib.auth import authenticate, login
import logging



class ParentRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        # checking email format
        try:
            validate_email(email)
        except ValidationError as e:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()
        if user:
            return Response({'error': 'User is already exists with this email. Please login with username and password!'}, status=status.HTTP_400_BAD_REQUEST)
        

        logger = logging.getLogger(__name__)
        logger.debug(f"Attempting to send otp to the given email: {email}")
        
        # sending otp to the given email
        otp = send_otp_via_email(email)
        
        # storing the OTP and email in the session for validation later
        request.session['otp'] = otp
        request.session['email'] = email

        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)


class VerifyOTPAndCreateUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        otp_entered = request.data.get('otp')

        # Retrieving the OTP and email from the session
        otp_stored = request.session.get('otp')
        email_stored = request.session.get('email')
        
        # To check if OTP verification is for login or registration
        existing_user = User.objects.filter(email=email_stored).first()

        if otp_entered == otp_stored:
            if existing_user is None:
                username = generate_unique_username()
                password = generate_password()
                
                logger = logging.getLogger(__name__)
                logger.debug(f"Attempting to create parent user with given email: {email_stored}")
                
                user = User(email=email_stored, username=username)
                if user:
                    user.set_password(password)
                    user.is_parent = True
                    user.save()
                else:
                    return Response({'error': 'User creation failed. Please try again !'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user = existing_user
            
            login(request, user)
            refresh_token = RefreshToken.for_user(user)
            response = Response()
            response.set_cookie(
                key='refresh_token',
                value=str(refresh_token),
                httponly=True
            )
            response.data = {
                    'status': status.HTTP_200_OK,
                    'token': str(refresh_token.access_token),
                }
            if existing_user is None:
                response.data['email'] = user.email
                response.data['username'] = username
                response.data['password'] = password
            else:
                response.data['message'] = "You have successfully logged in!"
            return response
        else:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
    