from django.apps import AppConfig
from django.core.management import call_command


class EasycarAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'easycar_backend'

    def ready(self):
        call_command('close_sessions')
        import easycar_backend.signals  # noqa
