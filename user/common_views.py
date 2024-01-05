from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .emails import send_otp_via_email
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import FormParser, MultiPartParser
from .serializers import FileInfoSerializer
from .models import User, FileInfo
from django.db.models import Q
from .utils import store_otp
import logging
import base64



class LoginAPIView(APIView):
    """
    API endpoint for user login.

    Attempts to authenticate the user using the provided username and password.
    If the user is a parent, sends an OTP via email for additional verification.
    If the authentication is successful, returns a token for authorization.

    ---
    # Request Body
    - username: string, required, user's username
    - password: string, required, user's password

    # Response
    - Success (200 OK):
      {
        "message": "OTP sent successfully. Please verify to login !"  # (for parent user)
        "token": "access_token"  # (for non-parent user)
      }
    - Error (400 Bad Request):
      {
        "error": "Wrong credentials!"  # (if authentication fails)
      }
    ---
    """
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
                hashed_otp = store_otp(otp)
                request.session['encrypted_otp'] = hashed_otp
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


class LogoutAPIView(APIView):
    """
    API endpoint for user logout.

    Logs out the authenticated user and removes the refresh token from cookies.

    ---
    # Response
    - Success (200 OK):
      {
        "message": "Logout successful"
      }
    - Error (401 Unauthorized):
      {
        "error": "User not authenticated"
      }
    ---
    """
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            
            # removing the refresh token from cookies
            response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
            response.delete_cookie('refresh_token')
            return response
        else:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        

class FileUploadAPIView(APIView):
    """
    API endpoint for file upload and retrieval.

    Supports uploading files with authentication, associating them with the uploading user.
    Additionally, allows retrieving files based on the user's role (parent or child).

    ---
    # Request (POST) Body
    - file: file, required, the file to be uploaded

    # Response (POST)
    - Success (201 Created):
      { "file": "file_url",
        "uploaded_on": "2024-01-05T12:31:11.326389Z",
        "uploaded_by": 123,
      }
    - Error (400 Bad Request):
      {
        "error": "Invalid file format"  # (if file format is not supported)
      }

    # Response (GET)
    - Success (200 OK):
      [
        { "file": "file_url",
            "uploaded_on": "2024-01-05T12:31:11.326389Z",
            "uploaded_by": 123,
        },
        { "file": "file_url",
            "uploaded_on": "2024-01-05T12:31:11.326389Z",
            "uploaded_by": 23,
        },
        ...
      ]
    - Error (401 Unauthorized):
      {
        "error": "User not authenticated"
      }
    ---
    """
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
    
    def get(self, request, *args, **kwargs):
        user = request.user

        if user.is_parent:
            # If the user is a parent, retrieve files uploaded by both own and childs
            files = FileInfo.objects.filter(
                Q(uploaded_by=user) | Q(uploaded_by__parent_id=user)
            )
        elif user.is_child:
            # If the user is a child, retrieve files uploaded by him/her
            files = FileInfo.objects.filter(uploaded_by=user)
        else:
            files = FileInfo.objects.none()

        serializer = self.serializer_class(files, many=True)
        return Response(serializer.data)