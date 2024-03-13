from rest_framework import serializers
from .models import *
from .eamil import  *
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

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
        if password !=password2:
            raise serializers.ValidationError({
                'error':'both password not match',
            }
            )
class LoginSerializer(serializers.Serializer):
    
    username = serializers.CharField(max_length=20)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=100,style={"input_type":"password"},write_only=True)
    
    def validate(self, values):
        # import pdb;pdb.set_trace()
        username = values.get("username")
        email = values.get("email")
        password = values.get("password")
        
        if username and password and email:
            user = authenticate(username=username, password=password, email=email)
            
            if user:
                values['user'] = user
            else:
                raise serializers.ValidationError("Username or password is incorrect")
        else:
            return serializers.ValidationError("Please fill in all fields correctly")
        
        return values

class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={"input type": "password"}, write_only=True)
    password2 = serializers.CharField(style={"input type": "password"}, write_only=True)

    def validate(self, data):
        password1 = data.get("password")
        password2 = data.get("password2")
        user = self.context.get("user")

        if password1 != password2:
            raise serializers.ValidationError({"password": "Both passwords must match."})
        
        if user is None:
            raise serializers.ValidationError({"error": "User details not found."})
         
        if check_password(password1, user.password):
            raise serializers.ValidationError({"password": "This password is recently updated."})

        user.set_password(password1)
        user.save()
        return data

class SendLinkSerializers(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    
    class Meta:
        fields=["eamil"]
    def validate(self, attrs):
        email=attrs.get("email")
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            # print("Encoded Uid",uid)
            token=PasswordResetTokenGenerator().make_token(user)
            # print("password Reset token",token)
            link='http://127.0.0.1:8000/api/reset_password-link/'+uid+"/"+token
            # print("password link",link)
            
            #send mail code
            body="Click FOllowing Link To Reset Your Password"+link
            data={
                "email_subject":"RESET YOU PASSWORD ",
                "body":body,
                "to_email":user.email,
            }
            send_email(data)
            return attrs
            
        else:
            raise serializers.ValidationError("This Email Not Regiter Please Enter Register Email")


class ResetPasswordSerializers(serializers.Serializer):
    password = serializers.CharField(style={"input type": "password"}, write_only=True)
    password2 = serializers.CharField(style={"input type": "password"}, write_only=True)

    class Meta:
        fields=["password","password2"]
    def validate(self, data):
        try:
            
            password1 = data.get("password")
            password2 = data.get("password2")
            uid = self.context.get("uid")
            token = self.context.get("token")

            if password1 != password2:
                raise serializers.ValidationError({"password": "Both passwords must match."})
            
            id = smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError("Token is not Valid or Expired") 
            
            if check_password(password1, user.password):
                raise serializers.ValidationError({"password": "This password is recently updated."})

            user.set_password(password1)
            user.save()
            return data
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise serializers.ValidationError("Token is not Valid or Expired")