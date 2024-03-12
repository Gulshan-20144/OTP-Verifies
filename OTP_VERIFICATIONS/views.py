import logging
from . import status
from .models import User
from .eamil import *
from django.shortcuts import render
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import Ragistrationserializers,loginserializers
from rest_framework_simplejwt.authentication import JWTAuthentication


# Create your views here.
logger=logging.getLogger("get_Company")

class Userragistration(APIView):
   serializers_class=Ragistrationserializers
   def post(self,request):
      try:
         logger.info(
            f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {request.data}\n\n,",exc_info=True)
         serializers=self.serializers_class(data=request.data)
         if serializers.is_valid():
            serializers.save()
            send_otp_via_email(serializers.data["email"])
            status_code=status.CREATED
            response= {
                  "success":True,
                  "massage":" User Ragister Successfully",
                  "status_code":status_code,
                  "Data":serializers.data
               }
               # serializer_data=serializers.data
         elif User.username is not None:
               status_code=status.BAD_REQUEST
               response={
                  "success":False,
                  "status_code":status_code,
                  "Error":{"Username":"Username is already exists"}
                }
         elif serializers.errors:
                status_code=status.INTERNAL_SERVER_ERROR
                response={
                  "success":False,
                  "status_code":status_code,
                  "massage":"Internal Error",
                  "Error":str(serializers.errors)
                }
         logger.info(
            f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,",exc_info=True)
         # if serializers.errors:
         #    raise Exception
      except Exception as e:
         status_code=status.BAD_REQUEST
         response = {
            "success":False,
            "status_code":status_code,
            "message":"somthing went wrong",
            "error": str(e)
         }
         logger.error(
            f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,",exc_info=True)
      return Response(response,status=status_code)
   
class Userlogin(APIView):
   permission_classes = [AllowAny]
   def post(self,request):
      logger.info(
         f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
      )
      try:
         username=request.data.get("username")
         email1=request.data.get("email")
         data= User.objects.filter(username=username).first()
         email=data.email
         if email == email1:
            if data.verified == True:
               serializers=loginserializers(data=request.data)
               if serializers.is_valid():
                  user=serializers.validated_data['user']
                  refresh = RefreshToken.for_user(user)
                  status_code=status.CREATED
                  response={
                     "success":True,
                     "status_code":status_code,
                     "massege":"Token Created Successfully",
                     "refresh":str(refresh),
                     "Token":str(refresh.access_token)
                  }
            else:
               raise Exception("Please verified this user via OTP") 
         else:
            raise Exception("Please Enter Correct Email")  
         logger.info(
         f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
      )
      except Exception as e:
         status_code=status.OK
         response={
            "success":False,
            "status_code":status.BAD_REQUEST,
            "massege":"Somthing went wrong",
            "Error":str(e)
         }
         logger.error(
         f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      return Response(response,status=status_code)
  
class Userdetails(generics.GenericAPIView):
    permission_classes=[IsAuthenticated]
    # authentication_classes=[JWTAuthentication]
    def get(self, request, *args, **kwargs):
        
        logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.user}"
        )
        try:
            user =request.user
            if user:
                data={
                    "username":user.username,
                    "firstname":user.firstname,
                    "lastname":user.lastname,
                    "email":user.email,
                    "DOB":user.date_of_birth,
                    }
                print(data)
                status_code=status.OK
                response={
                    "Success":True,
                    "Status_code":status_code,
                    "Massege":"Data feched Succesfully",
                    "Data":data
                }
            else:
                status_code=status.NO_CONTENT
                response={
                    "Success":False,
                    "Status_code":status_code,
                    "Massege":"Not  feched User",
                }
            logger.info(
                f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
            )
        except Exception as e:
            status_code=status.BAD_REQUEST
            response={
                "Success":True,
                "Status_code":status_code,
                "Massege":"Somthing went wrong",
                "Data":str(e)
            }
            logger.error(
                f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
            )
        return Response(response,status=status_code)


class VerifyOTP(APIView):
   def post(self, request):
    try:
        logger.info(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {request.data}\n\n,")

        email = request.data.get('email')
        otp = request.data.get('otp')
        if otp is None or email is None:
            status_code = status.BAD_REQUEST
            response = {
                "success": False,
                "status_code": status_code,
                "msg": 'You Are Missing One Fields OTP Or Email',
            }
        else:
            user = User.objects.filter(email=email)
            
            if  user.exists():  
               Verified=user[0].verified
               if Verified == False:
                  
                  if user[0].otp != otp:
                     status_code = status.BAD_REQUEST
                     response = {
                        "success": False,
                        "status_code": status_code,
                        "msg": 'Please Enter Valid OTP',
                     }
                  elif user[0].otp == otp:
                     status_code = status.BAD_REQUEST
                     data = {
                        "email": user[0].email,
                        "username": user[0].username,
                     }
                     user=user.first()
                     user.verified = True
                     response = {
                        "success": True,
                        "status_code": status_code,
                        "msg": 'Verified Email Successfully',
                        "Verified": user.verified,
                        "Data": data

                     }
                     user.save()
               else:
                  raise Exception("This User is Already Verified")
            else:
               status_code = status.NO_CONTENT
               response = {
                     "success": False,
                     "status_code": status_code,
                     "msg": 'Email Not Exists',
                  }
        logger.info(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
    except Exception as e:
        status_code = status.BAD_REQUEST
        response = {
            "success": False,
            "status_code": status_code,
            "msg": 'Something Went Wrong',
            "error": str(e)
        }
        logger.error(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
    return Response(response, status=status_code)
 

class ResendOtp(APIView):
   def post(self,request):
      try:
         logger.info(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo:\n\n {request.data}\n\n"
         )
         email=request.data.get("email")
         print(email)
         if email is None:
            raise Exception("Please Enter Email")
         send_otp_via_email(email)
         status_code=status.CREATED
         response= {
                  "success":True,
                  "massage":" OTP Resend Successfully",
                  "status_code":status_code
         }
         logger.info(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n Additionalinfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response= {
                  "success":False,
                  "massage":" Something Went Wrong",
                  "status_code":status_code,
                  "error":str(e)
         }
         logger.error(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n Additionalinfo\n\n{response}"
         )
      return Response(response,status=status_code)
   
# class ChangePassword