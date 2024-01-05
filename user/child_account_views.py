from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import User
from .utils import generate_unique_username, check_is_strong_password
import logging



class ChildRegisterAPIView(APIView):
    """
    API endpoint for parent users to create child accounts.

    Validates the password format and creates a child user associated with the parent's account.

    ---
    # Request Body
    - password: string, required, the password for the child account

    # Response
    - Success (200 OK):
      {
        "status": 200,
        "username": "child_username"
      }
    - Error (400 Bad Request):
      {
        "error": "Child account creation failed. Please try again !"  # (if user creation fails)
        "message": "Wrong password format!",
        "password_criteria": {
          "minimum length": 8,
          "require 1 uppercase": true,
          "require 1 lowercase": true,
          "require 1 special character": true
        }
      }
    - Error (400 Bad Request):
      {
        "error": "You dont have permission to create child users. Only parent can create child user !"
      }
    ---
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        if request.user.is_parent:
            data = request.data
            password=data['password']
            valid_password = check_is_strong_password(password,length=8)
            if valid_password:
                username = generate_unique_username()
                
                logger = logging.getLogger(__name__)
                logger.debug(f"Attempting to create child user with the username: {username}")
                
                user = User(username=username)
                if user:
                    user.set_password(password)
                    user.is_child = True
                    user.parent_id = request.user
                    user.save()
                    response = Response()
                    response.data = {
                        'status': status.HTTP_200_OK,
                        'username': username,
                    }
                    return response
                return Response({'error': 'Child account creation failed. Please try again !'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                response_data = {
                        'status': status.HTTP_400_BAD_REQUEST,
                        'message': "Wrong password format!",
                        'password_criteria': {
                            'minimum length': 8,
                            'require 1 uppercase': True,
                            'require 1 lowercase': True,
                            'require 1 special character': True,
                        }
                    }
            return Response(response_data)
        else:
            return Response({'error': 'You dont have permission to create child users. Only parent can create child user !'}, status=status.HTTP_400_BAD_REQUEST)
        