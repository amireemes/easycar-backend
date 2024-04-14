from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Car

from .models import Booking



User = get_user_model()
class PaymentSerializer(serializers.Serializer):
    cardNumber = serializers.CharField(max_length=16)
    expiryDate = serializers.CharField(max_length=5)
    cvv = serializers.CharField(max_length=3)
    nameOnCard = serializers.CharField(max_length=100)
    consent = serializers.BooleanField()

class CarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Car
        # fields = '__all__'
        exclude = ('owner',)

    def create(self, validated_data):
        print("Validated Data: ")
        print(validated_data)
        # Assuming that 'owner' is included in the validated data as a User instance
        # If 'owner' is not included, you need to add it from the context or somewhere else
        owner_popped = validated_data.pop('owner', None)
        if owner_popped is None:
            # You need to handle what happens if owner is not provided
            raise serializers.ValidationError("Owner is required.")

        # Create the Car instance
        car = Car.objects.create(**validated_data, owner=owner_popped)
        print("Car created: ", car)
        return car


class BookingSerializer(serializers.ModelSerializer):
    car_details = CarSerializer(source='car', read_only=True)  # Nested Serializer for car details

    class Meta:
        model = Booking
        fields = '__all__'  # Update this if you want to include the nested car serializer
        depth = 1  # This will include the nested details up to one level deep
