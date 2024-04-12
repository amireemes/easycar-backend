from django.dispatch import receiver
from django.core.signals import request_started
from django.contrib.sessions.models import Session
from django.utils import timezone


@receiver(request_started)
def print_active_sessions(sender, **kwargs):
    # Get all active sessions
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())

    # Print active sessions
    print("Active sessions:")
    for session in active_sessions:
        print(f"Session ID: {session.session_key}, User ID: {session.get_decoded().get('_auth_user_id', 'Anonymous')}")
