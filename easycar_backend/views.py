from jupyter_client.jsonutil import parse_date
from rest_framework import generics, status
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.http import JsonResponse, Http404
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.hashers import make_password
import json
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.exceptions import NotFound
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from .models import Car, Booking
from .serializers import CarSerializer
# from .serializers import PaymentSerializer
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter
from .filters import CarFilter

# class PaymentView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = PaymentSerializer(data=request.data)
#         if serializer.is_valid():
#             # Process the payment here
#             # For now, we'll just return the validated data
#             return Response(serializer.validated_data, status=200)
#         return Response(serializer.errors, status=400)


class CarListCreateView(generics.ListCreateAPIView):
    queryset = Car.objects.all()
    serializer_class = CarSerializer
    filter_backends = (DjangoFilterBackend, OrderingFilter,)
    filterset_class = CarFilter
    ordering_fields = ['price_per_day', 'year']  # Allow ordering by price and year

    def get_queryset(self):
        queryset = super().get_queryset()
        # print(queryset.query)  # This will print the SQL query to the console
        return queryset


def create_booking(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = request.user
            print(user)
            car_id = data['car_id']
            start_date = parse_date(data['start_date'])
            end_date = parse_date(data['end_date'])
            booking_location = data.get('booking_location', '')  # Optional, based on your model

            booking = Booking.objects.create(
                user=user,
                car_id=car_id,
                start_date=start_date,
                end_date=end_date,
                booking_location=booking_location,
            )

            return JsonResponse({"success": True, "booking_id": booking.id}, status=201)
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=400)
    else:
        return JsonResponse({"success": False, "error": "Only POST requests are allowed."}, status=405)


@api_view(['POST'])
@parser_classes((MultiPartParser, FormParser))
@permission_classes([IsAuthenticated])  # Ensure that the user is authenticated
def car_create_view(request, format=None):
    print("Car create view entered")
    serializer = CarSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(owner=request.user)
        owner = request.user
        print("serializer is valid")
        print("Owner is:" + str(owner))
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CarDetailsView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Car.objects.all()
    serializer_class = CarSerializer
    lookup_field = 'id'

    def get(self, request, *args, **kwargs):
        try:
            car = self.get_object()
            serializer = self.get_serializer(car)
            return Response(serializer.data)
        except Car.DoesNotExist:
            raise NotFound('A car with this ID does not exist.')


@csrf_exempt
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Check if all fields are provided
        if not all(key in data for key in ['username', 'email', 'password', 'first_name', 'last_name']):
            return JsonResponse({'error': 'All fields are required.'}, status=400)

        # Use create_user instead of create to handle password hashing
        user = User.objects.create_user(
            username=data['username'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            password=data['password']
        )
        login(request, user)  # Log the user in
        return JsonResponse({'id': user.id, 'username': user.username}, status=201)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data['username']
        password = data['password']
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            print("The user logged in, ID: " + str(user.id) + ". Token = " + str(refresh))
            return JsonResponse({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'id': user.id,
                'username': user.username
            }, status=200)
        return JsonResponse({'error': 'Invalid credentials'}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'success': 'Logged out'}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)
