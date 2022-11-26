from django.db.models import Q
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.core.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime, timedelta
import plaid
from uuid import uuid4
from .models import User
from .utils import get_plaid_client
from .tasks import get_transactions, get_accounts, get_access_token


class RegisterUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(max_length=8)

    class Meta:
        model = User
        fields = (
            'email',
            'password'
        )


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField()
    token = serializers.CharField(required=False, read_only=True)

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        if not email and not password:
            raise ValidationError('Details not entered.')

        user = None
        try:
            user = User.objects.get(email=email, password=password)
            if user.is_logged_in:
                raise ValidationError('User already logged in.')
        except ObjectDoesNotExist:
            raise ValidationError('User credentials are not correct.')

        user.is_logged_in = True
        data['token'] = uuid4()
        user.token = data['token']
        user.save()
        return data

    class Meta:
        model = User
        fields = (
            'email',
            'password',
            'token',
        )

        read_only_fields = (
            'token',
        )


class UserLogoutSerializer(serializers.ModelSerializer):
    token = serializers.CharField()
    status = serializers.CharField(required=False, read_only=True)

    def validate(self, data):
        token = data.get("token", None)
        print(token)
        user = None
        try:
            user = User.objects.get(token=token)
            if not user.is_logged_in:
                raise ValidationError("User is not logged in.")
        except Exception as e:
            raise ValidationError(str(e))
        user.is_logged_in = False
        user.token = ""
        user.access_token = ""
        user.save()
        data['status'] = "User is logged out."
        return data

    class Meta:
        model = User
        fields = (
            'token',
            'status',
        )