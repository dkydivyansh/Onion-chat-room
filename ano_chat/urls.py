# chat/urls.py

from django.contrib import admin
from django.urls import path
from chat import views
from django.views.generic.base import RedirectView

urlpatterns = [
    # Homepage Route
    path('', RedirectView.as_view(url='/login/', permanent=False), name='homepage'),

    path('admin/', admin.site.urls),
    
    # Registration URLs
    path('register/', views.register_page, name='register_page'),
    path('api/register/', views.register_user, name='register_user'),
    path('api/check-username/', views.check_username, name='check_username'),

    # Login URLs
    path('login/', views.login_page, name='login_page'),
    path('api/login/challenge/', views.get_login_challenge, name='get_login_challenge'),
    path('api/login/verify/', views.verify_login_signature, name='verify_login_signature'),

    # Dashboard & Logout URLs
    path('dashboard/', views.dashboard_page, name='dashboard_page'),
    path('logout/', views.logout_user, name='logout_user'),

    # Chat and Invitation APIs
    path('api/chats/create-and-invite/', views.create_chat_and_invite, name='create_chat_and_invite'),
    path('api/invitations/<int:invitation_id>/respond/', views.respond_to_invitation, name='respond_to_invitation'),
    path('api/invitations/<int:invitation_id>/remove-by-invitee/', views.remove_declined_by_invitee, name='remove_declined_by_invitee'),
    
    # Chat Room URLs
    path('chat/<uuid:room_id>/', views.chat_room_page, name='chat_room_page'),
    path('api/chats/<uuid:room_id>/delete/', views.delete_chat_room, name='delete_chat_room'),
    
    # FIX: Add the missing URL pattern for fetching messages
    path('api/chats/<uuid:room_id>/messages/', views.get_chat_messages, name='get_chat_messages'),
    path('api/chats/<uuid:room_id>/clear/', views.clear_chat_history, name='clear_chat_history'),
    path('api/account/delete/challenge/', views.get_delete_challenge, name='get_delete_challenge'),
    path('api/account/delete/verify/', views.verify_delete_account, name='verify_delete_account'),
]