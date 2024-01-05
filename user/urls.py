from django.urls import path
from .parent_account_views import ParentRegisterView, VerifyOTPAndCreateUserView
from .common_views import LoginAPIView


urlpatterns = [
    
    # parent related endpoints
    path('parent/register/', ParentRegisterView.as_view(), name='register_with_otp'),
    path('parent/verify-otp/', VerifyOTPAndCreateUserView.as_view(), name='verify_otp_and_create_user'),
    
    # common endpoints
    path('user/login/', LoginAPIView.as_view(), name='user_login'),
]