# app_name/management/commands/close_sessions.py
from django.contrib.auth import logout
from django.core.management.base import BaseCommand
from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework import request


class Command(BaseCommand):
    help = 'Closes all active sessions'

    def handle(self, *args, **kwargs):
        # Get all active sessions
        active_sessions = Session.objects.filter(expire_date__gte=timezone.now())

        # Close all active sessions
        for session in active_sessions:
            session.delete()

        self.stdout.write(self.style.SUCCESS('Successfully closed all active sessions.'))
