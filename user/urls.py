from django.urls import path
from .parent_account_views import ParentRegisterView, VerifyOTPAndCreateUserView
from .child_account_views import ChildRegisterAPIView
from .common_views import LoginAPIView, LogoutAPIView, FileUploadAPIView


urlpatterns = [
    
    # parent related endpoints
    path('parent/register/', ParentRegisterView.as_view(), name='register_with_otp'),
    path('parent/verify-otp/', VerifyOTPAndCreateUserView.as_view(), name='verify_otp_and_create_user'),
    
    # child related endpoints
    path('child/create/', ChildRegisterAPIView.as_view(), name='create_child'),
     
    # common endpoints
    path('user/login/', LoginAPIView.as_view(), name='user_login'),
    path('user/logout/', LogoutAPIView.as_view(), name='user_logout'),
    path('upload-file/', FileUploadAPIView.as_view(), name='upload_file'),
]