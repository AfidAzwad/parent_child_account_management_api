from rest_framework import serializers
from .models import FileInfo

class FileInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileInfo
        fields = ('file', 'uploaded_on','uploaded_by')