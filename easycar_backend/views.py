import json

from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from django.views.generic import ListView
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, status
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.exceptions import NotFound
from rest_framework.filters import OrderingFilter
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .filters import CarFilter
from .models import Car, Booking
from .serializers import CarSerializer, BookingSerializer
from .serializers import PaymentSerializer


@api_view(['GET'])
@login_required
def check_authentication_status(request):
    return Response({'authenticated': True}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_booking_details(request, booking_id):
    print("Booking View entered")
    # Assumes that you have user authentication in place
    booking = get_object_or_404(Booking, id=booking_id, user=request.user)

    # Construct the data you want to send back to the frontend
    data = {
        'start_datetime': booking.start_datetime.strftime('%Y-%m-%d %H:%M'),
        'end_datetime': booking.end_datetime.strftime('%Y-%m-%d %H:%M'),
        'total_price': str(booking.total_price),
        'car': {
            'make': booking.car.make,
            'model': booking.car.model,
            'details_link': f'/cars/{booking.car.id}/'
        }
    }
    print("Booking Data is:", json.dumps(data))
    return JsonResponse(data)

from rest_framework.generics import ListAPIView
@require_GET
def csrf(request):
    token_to_print = get_token(request)
    print("CSRF Token accessed: " + str(token_to_print))
    return JsonResponse({'csrfToken': token_to_print})


def validate_new_password(password):
    # Check if password is at least 8 characters long
    if len(password) < 8:
        return False
    # Add more password validation rules as needed
    return True


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    try:
        old_password = request.data.get('oldPassword')
        new_password = request.data.get('newPassword')

        if not old_password or not new_password:
            return Response({'error': 'Old password and new password are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({'error': 'Wrong old password.'}, status=status.HTTP_400_BAD_REQUEST)

        if not validate_new_password(new_password):
            return Response({'error': 'New password does not meet requirements.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        return Response({'success': 'Password updated successfully.'})
    except Exception as e:
        # Log the exception message
        print(f'Error changing password: {str(e)}')
        return Response({'error': 'Error changing password.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_info(request):
    user = request.user
    user_data = {
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        # Add any other fields you need
    }
    return Response(user_data)


class PaymentView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            # Process the payment here
            # For now, we'll just return the validated data
            return Response(serializer.validated_data, status=200)
        return Response(serializer.errors, status=400)


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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_booking(request):
    print(f"CSRF Cookie from the request: {request.META.get('CSRF_COOKIE')}")
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = request.user
            print(user)
            car_id = data['car_id']
            start_datetime = parse_datetime(data['start_datetime'])
            end_datetime = parse_datetime(data['end_datetime'])
            booking_location = data.get('booking_location', '')  # Optional, based on your model

            booking = Booking.objects.create(
                user=user,
                car_id=car_id,
                start_datetime=start_datetime,
                end_datetime=end_datetime,
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
    license_plate = request.data.get('license_plate')
    vin = request.data.get('vin')

    # Check for existing cars with the same license plate or VIN
    if Car.objects.filter(license_plate=license_plate).exists():
        return JsonResponse({'license_plate': 'A car with this license plate already exists.'}, status=400)
    if Car.objects.filter(vin=vin).exists():
        return JsonResponse({'vin': 'A car with this VIN number already exists.'}, status=400)
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
@permission_classes([IsAuthenticated])
class BookingListView(ListAPIView):
    serializer_class = BookingSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            return Booking.objects.filter(user=user)
        else:
            raise Http404("No Bookings found")

    @permission_classes([IsAuthenticated])
    def render_to_response(self, context, **response_kwargs):
        queryset = self.get_queryset()
        serializer = BookingSerializer(queryset, many=True)
        print("Serialized data:", serializer.data)  # Check the serialized data
        return JsonResponse(serializer.data, safe=False)

    @api_view(['POST'])
    @permission_classes([IsAuthenticated])
    def create_booking(request):
        user = request.user
        print("User making the booking request:", user.username, user.email)
        # ... rest of your code ...


@csrf_exempt
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Check if all fields are provided
        if not all(key in data for key in ['username', 'email', 'password', 'first_name', 'last_name']):
            return JsonResponse({'error': 'All fields are required.'}, status=400)

        # Use create_user instead of create to handle password hashing
        try:
            user = User.objects.create_user(
                username=data['username'],
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                password=data['password']
            )
            login(request, user)  # Log the user in
            return JsonResponse({'id': user.id, 'username': user.username}, status=201)
        except IntegrityError as e:
            if 'auth_user_username_key' in str(e):
                return JsonResponse({'email': 'User with this email already exists.'}, status=400)
            else:
                return JsonResponse({'error': 'An error occurred during registration.'}, status=500)
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
