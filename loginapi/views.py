import jwt
from rest_framework_jwt.utils import jwt_decode_handler
from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserListSerializer
)

from .models import User
from django.contrib.auth import get_user_model







# Create your views here.

# registrarion view

class UserRegistrationView(APIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)

        if valid:
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'statusCode': status_code,
                'message': 'User successfully registered!',
                'user': serializer.data
            }

            return Response(response, status=status_code)
        
    
# login view

class UserLoginView(APIView):
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)

        if valid:
            status_code = status.HTTP_200_OK

            response = {
                'success': True,
                'statusCode': status_code,
                'message': 'User logged in successfully',
                'access': serializer.data['access'],
                'refresh': serializer.data['refresh'],
                'authenticatedUser': {
                    'email': serializer.data['email'],
                    
                }
            }

            return Response(response, status=status_code)



class changePasswordView(APIView):
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)
        
        decode = jwt.decode(serializer.data['access'], options={
                            "verify_signature": False})
        print(">>>>>>>>>>>>>>>>>", decode)
        id = decode.user_id
        if valid:
            status_code = status.HTTP_200_OK

            response = {
                # 'success': True,
                # 'statusCode': status_code,
                # 'message': 'User logged in successfully',
                # 'access': serializer.data['access'],
                # 'refresh': serializer.data['refresh'],
                'Decode': decode,
                'id' : id,
                # 'authenticatedUser': {
                #     'email': serializer.data['email'],

                # }
            }

            return Response(response, status=status_code)
