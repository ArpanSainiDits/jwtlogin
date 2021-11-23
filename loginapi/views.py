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
    UserListSerializer,
    ChangePasswordSerializer,
)

from .models import User
from django.contrib.auth import get_user_model
from rest_framework import generics


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


# class changePasswordView(APIView):
#     serializer_class = ChangePasswordSerializer
#     permission_classes = (AllowAny, )

#     def put(self, request):
#         serializer = self.serializer_class(data=request.data)
#         valid = serializer.is_valid(raise_exception=True)

#         decode = jwt.decode(serializer.data['access'], options={
#                             "verify_signature": False})
       
#         id = decode.get("user_id")
        
#         print(id)
#         if valid:
#             status_code = status.HTTP_200_OK

#             response = {  
#                 'id' : id,
#             }

#             return Response(response, status=status_code)


# class ChangePasswordView(generics.UpdateAPIView):

#     queryset = User.objects.all()
#     permission_classes = (IsAuthenticated,)
#     serializer_class = ChangePasswordSerializer
    

# class ChangePasswordView(APIView):
    

#     permission_classes = (IsAuthenticated,)
#     serializer_class = ChangePasswordSerializer

#     def post(self, request):
#         # serializer = self.serializer_class(data=request.data)
#         # valid = serializer.is_valid(raise_exception=True)
#         valid = True
#         status_code = 200
#         response = {}
#         print(request.user)
#         if valid:
#             status_code = 200
#             response['message'] = 'success'
#         else:
#             response['message'] = 'bad request'
#             status_code = 400
#         return Response(response, status=status_code)


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
