from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .emails import send_otp_via_email
from django.contrib.auth import authenticate, login



class LoginAPIView(APIView):
    
    def post(self, request):
        try:
            data = request.data
            user = authenticate(request, username=data['username'], password=data['password'])
            
            if not user:
                return Response({'error': 'Wrong credentials!'}, status=status.HTTP_400_BAD_REQUEST)
            if user.is_parent:
                otp = send_otp_via_email(user.email)
                
                # storing the OTP and email in the session for validation later
                request.session['otp'] = otp
                request.session['email'] = user.email
                
                return Response({'message': 'OTP sent successfully. Please verify to login !'}, status=status.HTTP_200_OK)
                
            else:
                login(request, user)
                refresh_token = RefreshToken.for_user(user)
                response = Response()
                response.set_cookie(key='refresh_token', 
                                    value=str(refresh_token),
                                    httponly=True)
                response.data = {
                    'token': str(refresh_token.access_token)
                        }
            return response
        except Exception as e:
            return e