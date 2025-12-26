from django.contrib.auth.models import AnonymousUser as DjangoAnonymousUser
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from .models import AnonymousUser as ChatUser

@database_sync_to_async
def get_user_from_session(session):
    try:
        username = session.get('authenticated_user')
        if username:
            user = ChatUser.objects.get(username=username)
            user.is_authenticated = True
            return user
    except ChatUser.DoesNotExist:
        return DjangoAnonymousUser()
    except Exception:
        return DjangoAnonymousUser()
    return DjangoAnonymousUser()

class QueryAuthMiddleware(BaseMiddleware):
    def __init__(self, inner):
        super().__init__(inner)

    async def __call__(self, scope, receive, send):
        if 'session' in scope:
            custom_user = await get_user_from_session(scope['session'])
            if custom_user.is_authenticated:
                scope['user'] = custom_user
            
        return await super().__call__(scope, receive, send)