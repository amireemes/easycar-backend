from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Car

from .models import Booking

class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = '__all__'  # List all the fields you want to include in your serialized data

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
