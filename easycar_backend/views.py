import json
from datetime import datetime

from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.db.models import Q
from django.http import JsonResponse, Http404
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
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
from datetime import timedelta, datetime
from .filters import CarFilter
from .models import Car, Booking
from .serializers import CarSerializer, BookingSerializer
from .serializers import PaymentSerializer
from django.utils.dateparse import parse_date
from django.utils import timezone



@api_view(['GET'])
def search_cars(request):
    # Extract parameters from request
    location = request.query_params.get('location')
    from_date = request.query_params.get('fromDate')
    from_time = request.query_params.get('fromTime')
    until_date = request.query_params.get('untilDate')
    until_time = request.query_params.get('untilTime')

    # Initialize the queryset for all cars
    queryset = Car.objects.all()

    if location:
        queryset = queryset.filter(location__icontains=location)

    if from_date and until_date:
        # Parse string dates into datetime objects
        from_datetime = timezone.make_aware(datetime.strptime(from_date + " " + from_time, '%Y-%m-%d %H:%M'))
        until_datetime = timezone.make_aware(datetime.strptime(until_date + " " + until_time, '%Y-%m-%d %H:%M'))

        # Look for bookings that overlap with the given time range
        overlapping_bookings = Q(bookings__start_datetime__lt=until_datetime, bookings__end_datetime__gt=from_datetime)

        # Exclude cars that have overlapping bookings
        queryset = queryset.exclude(overlapping_bookings).distinct()

    serializer = CarSerializer(queryset, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@login_required
def check_authentication_status(request):
    return Response({'authenticated': True}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_unavailable_times(request, car_id):
    # Get the date from the query parameters
    date_str = request.query_params.get('date', None)
    if not date_str:
        return JsonResponse({"error": "No date provided"}, status=400)
    
    # Parse the date string into a datetime object
    booking_date = parse_date(date_str)
    if not booking_date:
        return JsonResponse({"error": "Invalid date format"}, status=400)
    
    # Find bookings for the given car and date
    start_of_day = datetime.combine(booking_date, datetime.min.time())
    end_of_day = start_of_day + timedelta(days=1)
    bookings = Booking.objects.filter(
        car_id=car_id,
        start_datetime__gte=start_of_day,
        end_datetime__lt=end_of_day
    )
    
    # Generate a list of times that are unavailable
    # In your get_unavailable_times view
    unavailable_times = [booking.start_datetime.strftime('%H:%M') for booking in bookings]

    
    return JsonResponse({"unavailable_times": unavailable_times})
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

        from_date_str = self.request.query_params.get('fromDate')
        to_date_str = self.request.query_params.get('untilDate')
        from_time_str = self.request.query_params.get('fromTime', '00:00')
        to_time_str = self.request.query_params.get('untilTime', '23:59')

        if from_date_str and to_date_str:
            from_datetime = timezone.make_aware(parse_datetime(f"{from_date_str}T{from_time_str}"))
            to_datetime = timezone.make_aware(parse_datetime(f"{to_date_str}T{to_time_str}"))

            overlapping_bookings = Q(bookings__start_datetime__lt=to_datetime, bookings__end_datetime__gt=from_datetime)
            queryset = queryset.exclude(overlapping_bookings).distinct()

        return queryset


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_booking(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = request.user
            car_id = data['car_id']
            start_datetime = parse_datetime(data['start_datetime'])
            end_datetime = parse_datetime(data['end_datetime'])
            booking_location = data.get('booking_location', '')  # Optional, based on your model

            # Check if the car is already booked for the given time frame
            overlapping_bookings = Booking.objects.filter(
                car_id=car_id,
                end_datetime__gte=start_datetime,
                start_datetime__lte=end_datetime
            )
            
            if overlapping_bookings.exists():
                # Car is not available for booking as it's already booked for the time frame
                return JsonResponse({
                    "success": False,
                    "error": "The car is already booked for the selected time frame."
                }, status=status.HTTP_400_BAD_REQUEST)

            # If no overlapping bookings, create the new booking
            booking = Booking.objects.create(
                user=user,
                car_id=car_id,
                start_datetime=start_datetime,
                end_datetime=end_datetime,
                booking_location=booking_location,
            )
            
            return JsonResponse({"success": True, "booking_id": booking.id}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_booked_times(request, car_id):
    # Get all bookings for the car that are current or future
    bookings = Booking.objects.filter(
        car_id=car_id,
        end_datetime__gte=datetime.now()
    )
    booked_times = bookings.values_list('start_datetime', 'end_datetime')
    return JsonResponse({"booked_times": list(booked_times)})

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
            # Get all bookings for the current user
            return Booking.objects.filter(user=user).order_by('-start_datetime')
        else:
            raise Http404("No Bookings found")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        now = timezone.now()

        # Separate current/future bookings from past bookings
        current_bookings = queryset.filter(end_datetime__gte=now)
        past_bookings = queryset.filter(end_datetime__lt=now)

        # Serialize the data
        current_bookings_serializer = self.get_serializer(current_bookings, many=True)
        past_bookings_serializer = self.get_serializer(past_bookings, many=True)

        # Return both current and past bookings
        return Response({
            'current_bookings': current_bookings_serializer.data,
            'past_bookings': past_bookings_serializer.data
        })

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
