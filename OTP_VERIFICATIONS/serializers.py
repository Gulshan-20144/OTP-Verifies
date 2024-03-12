from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate


class Ragistrationserializers(serializers.ModelSerializer):
    password=serializers.CharField(style={"input type":"password"},write_only=True)
    password2=serializers.CharField(style={"input type":"password2"},write_only=True)
    class Meta:
        model=User
        fields=['username','email','firstname','lastname','date_of_birth','is_admin','password','password2','verified',]
        ertra_fields={
            "password":{"write_only":True},
            "password":{"write_only":True},
        }
    def create(self, validated_data):
        username=validated_data.get('username')
        email=validated_data.get('email')
        firstname=validated_data.get('firstname')
        lastname=validated_data.get('lastname')
        date_of_birth=validated_data.get('date_of_birth')
        is_admin=validated_data.get('is_admin')
        verified=validated_data.get('verified')
        password=validated_data.get('password')
        password2=validated_data.get('password2')
        if password==password2:
            users=User(
                username=username,
                email=email,
                firstname=firstname,
                lastname=lastname,
                date_of_birth=date_of_birth,
                is_admin=is_admin
            )
            users.set_password(password)
            users.save()
            return users
        else:
            raise serializers.ValidationError({
                'error':'both password not match',
            }
            )
class loginserializers(serializers.Serializer):
    username=serializers.CharField(max_length=20)
    email=serializers.EmailField()
    password=serializers.CharField(max_length=100)
    
    def validate(self, valuse):
        username=valuse.get("username")
        email=valuse.get("email")
        password=valuse.get("password")
        if username and password and email:
            user=authenticate(username=username,password=password,email=email)
            # print(user)
            if user:
                valuse['user']=user
            else:
                raise serializers.ValidationError("username or password is incorrect")
        else:
            raise serializers.ValidationError("please fill correct all filled")
        return valuse
