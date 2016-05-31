from rest_framework import permissions, viewsets, status, views
from rest_framework.response import Response
from .models import Account
from .serializers import AccountSerializer
from .permissions import IsAccountOwner
from django.contrib.auth import authenticate, login, logout
import json


class AccountViewSet(viewsets.ModelViewSet):
    lookup_field = 'username'
    queryset = Account.objects.all()
    serializer_class = AccountSerializer

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return permissions.AllowAny(),

        if self.request.method == 'POST':
            return permissions.AllowAny(),

        return permissions.IsAuthenticated(), IsAccountOwner()

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            Account.objects.create(**serializer.validated_data)
            return Response(serializer.validated_data, status=status.HTTP_201_CREATED)

        return Response(dict(
            status="Bad Request",
            message="Account cannot be created with the recieved data."
        ), status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    def post(self, request, fromat=None):
        data = json.loads(request.body)

        email = data.get('email', None)
        password = data.get('password', None)

        account = authenticate(email=email, password=password)

        if account is not None:
            if account.is_active:
                login(request, account)
                serialized = AccountSerializer(account)

                return Response(serialized.data)

            else:
                return Response(dict(
                    status="Unauthorized",
                    message="This account has been disabled."
                ), status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response(dict(
                status="Unauthorized",
                message="Username/password combination is invalid."
            ), status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(views.APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request, format=None):
        logout(request)

        return Response({}, status.HTTP_204_NO_CONTENT)