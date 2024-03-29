# Generated by Django 4.2.7 on 2024-02-15 18:21

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import imagekit.models.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Car',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('make', models.CharField(default='Toyota', max_length=50)),
                ('model', models.CharField(default='RAV4', max_length=50)),
                ('year', models.IntegerField(default='2001')),
                ('license_plate', models.CharField(default='222ZNO01', max_length=20)),
                ('vin', models.CharField(default='123ZKA02LNQLB', max_length=17, verbose_name='VIN')),
                ('color', models.CharField(default='blue', max_length=30)),
                ('seats', models.IntegerField(default='2')),
                ('location', models.CharField(default='Astana,Kazakhstan', max_length=100)),
                ('price_per_day', models.DecimalField(decimal_places=2, default='150', max_digits=10)),
                ('availability', models.CharField(choices=[('available', 'Available'), ('unavailable', 'Unavailable')], default='available', max_length=12)),
                ('description', models.TextField(blank=True, default='nice nice car')),
                ('imgUrl', imagekit.models.fields.ProcessedImageField(upload_to='car_images')),
                ('active', models.BooleanField(default=True)),
                ('fuel_type', models.CharField(choices=[('petrol', 'Petrol'), ('diesel', 'Diesel'), ('electric', 'Electric'), ('hybrid', 'Hybrid')], default='automatic', max_length=10)),
                ('transmission', models.CharField(choices=[('automatic', 'Automatic'), ('manual', 'Manual')], max_length=10)),
                ('mileage', models.IntegerField(default='2000')),
                ('owner', models.ForeignKey(default='12', on_delete=django.db.models.deletion.CASCADE, related_name='cars', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
