from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.views import Response, status
# Create your views here.
from users.serializers import SignupSerializer

class SignupAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data = request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                Response(serializer.data, status=status.HTTP_201_CREATED)
            except:
                Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


