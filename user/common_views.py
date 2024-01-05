from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .emails import send_otp_via_email
from django.contrib.auth import authenticate, login
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import FormParser, MultiPartParser
from .serializers import FileInfoSerializer
import logging



class LoginAPIView(APIView):
    
    def post(self, request):
        try:
            data = request.data
            
            logger = logging.getLogger(__name__)
            logger.debug("Attempting to authenticate the user to login")
            
            user = authenticate(request, username=data['username'], password=data['password'])
            
            if not user:
                return Response({'error': 'Wrong credentials!'}, status=status.HTTP_400_BAD_REQUEST)
            if user.is_parent:
                logger = logging.getLogger(__name__)
                logger.debug("Attempting to sending otp to verify parent user login !")
                
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


class FileUploadAPIView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    serializer_class = FileInfoSerializer
    permission_classes = [IsAuthenticated,]
    
    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        data['uploaded_by'] = request.user.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )