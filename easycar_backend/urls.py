from django.urls import path
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from . import views
from .views import PaymentView, check_authentication_status, search_cars

from .views import CarListCreateView, CarDetailsView, BookingListView, csrf
from .views import get_user_info, change_password
urlpatterns = [
    path('cars/create-booking/', views.create_booking, name='create-booking'),
    path('payment/', PaymentView.as_view(), name='payment'),
    path('cars/', CarListCreateView.as_view(), name='car-list-create'),
    path('car-create/', views.car_create_view, name='car-create'),
    path('cars/<int:id>/', CarDetailsView.as_view(), name='car-detail'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('csrf/', csrf, name='csrf'),
    # path('become_host/',)
    path('bookings/', BookingListView.as_view(), name='booking-list'),
    path('api/userinfo/', get_user_info, name='get_user_info'),
    path('api/change-password/', change_password, name='change_password'),
    path('booking/<int:booking_id>/', views.get_booking_details, name='booking-details'),
    path('check-authentication/', check_authentication_status, name='check-authentication'),
    path('search-cars/', search_cars, name='search_cars'),
    path('cars/<int:car_id>/unavailable-times/', views.get_unavailable_times, name='car-unavailable-times'),

]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
