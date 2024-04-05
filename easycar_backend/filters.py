import django_filters
from .models import Car
from django.db.models import Q

def filter_price_range(queryset, name, value):
    try:
        min_value, max_value = value.split('-')
        return queryset.filter(
            Q(price_per_day__gte=min_value) & Q(price_per_day__lte=max_value)
        )
    except ValueError:
        # If the input format is wrong, ignore the filter or handle as you see fit
        return queryset


class CarFilter(django_filters.FilterSet):
    make = django_filters.CharFilter(lookup_expr='icontains', label='Make')
    min_price = django_filters.NumberFilter(field_name='price_per_day', lookup_expr='gte', label='Min Price')
    max_price = django_filters.NumberFilter(field_name='price_per_day', lookup_expr='lte', label='Max Price')
    min_year = django_filters.NumberFilter(field_name='year', lookup_expr='gte', label='Min Year')
    max_year = django_filters.NumberFilter(field_name='year', lookup_expr='lte', label = 'Max Year')
    transmission = django_filters.ChoiceFilter(choices=Car.TRANSMISSION_CHOICES)
    price_range = django_filters.CharFilter(method='filter_price_range')
    fuel_type = django_filters.ChoiceFilter(choices=Car.FUEL_TYPE_CHOICES)
    location = django_filters.ChoiceFilter(choices=Car.LOCATION_CHOICES)
    class Meta:
        model = Car
        fields = {
        }