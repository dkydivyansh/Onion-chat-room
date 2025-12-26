import os
from django.core.asgi import get_asgi_application

# 1. Initialize Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ano_chat.settings')
django_asgi_app = get_asgi_application()

# 2. Imports
from channels.routing import ProtocolTypeRouter, URLRouter
# We need BOTH CookieMiddleware and SessionMiddleware
from channels.sessions import CookieMiddleware, SessionMiddleware
from channels.auth import AuthMiddleware
from chat.middleware import QueryAuthMiddleware
from chat import routing

print("\n[DEBUG] Loading CORRECTED manual asgi.py configuration...")

# 3. Build the Stack Manually
# Order is critical: Cookie -> Session -> Auth -> Custom -> Router
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": CookieMiddleware(  # <--- Added this wrapper
        SessionMiddleware(
            AuthMiddleware(
                QueryAuthMiddleware(
                    URLRouter(
                        routing.websocket_urlpatterns
                    )
                )
            )
        )
    ),
})