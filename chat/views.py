import json
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from .models import AnonymousUser, ChatRoom, Invitation
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
from django.db import transaction
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

# --- Custom Decorator ---
def custom_login_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        if 'authenticated_user' not in request.session:
            return redirect('login_page')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def get_current_user(request):
    username = request.session.get('authenticated_user')
    if not username: return None
    try:
        # Filter out deleted users just in case
        return AnonymousUser.objects.get(username=username, is_deleted=False)
    except AnonymousUser.DoesNotExist:
        return None

# --- Dashboard View ---
@custom_login_required
def dashboard_page(request):
    user = get_current_user(request)
    if not user: return redirect('logout_user') # Safety logout if user was deleted
    
    all_user_chats = user.chat_rooms.all()
    active_chats = [chat for chat in all_user_chats if chat.members.count() == 2]

    pending_received_invitations = Invitation.objects.filter(invitee=user, status=Invitation.Status.PENDING).order_by('-created_at')
    declined_received_invitations = Invitation.objects.filter(invitee=user, status=Invitation.Status.DECLINED).order_by('-created_at')
    sent_invitations = Invitation.objects.filter(inviter=user).order_by('-created_at')
    
    declined_invitations_for_json = list(declined_received_invitations.values('id', 'inviter__username'))

    context = {
        'username': user.username,
        'active_chats': active_chats,
        'pending_invitations': pending_received_invitations,
        'declined_invitations': declined_received_invitations,
        'sent_invitations': sent_invitations,
        'declined_invitations_for_json': declined_invitations_for_json,
    }
    return render(request, 'chat/dashboard.html', context)

# --- Chat Room View ---
@custom_login_required
def chat_room_page(request, room_id):
    user = get_current_user(request)
    if not user: return redirect('logout_user')

    chat_room = get_object_or_404(ChatRoom, id=room_id)
    if user not in chat_room.members.all():
        return redirect('dashboard_page')

    other_user = chat_room.members.exclude(username=user.username).first()
    context = {
        'chat_room': chat_room,
        'other_user': other_user,
        'username': user.username,
    }
    return render(request, 'chat/chat_room.html', context)

# --- Logout View ---
def logout_user(request):
    try:
        del request.session['authenticated_user']
    except KeyError: pass
    return render(request, 'chat/logout.html')

# --- Registration ---
def register_page(request):
    return render(request, 'chat/register.html')

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username, public_key = data.get('username'), data.get('public_key')
            if not username or not public_key: return JsonResponse({'status': 'error', 'message': 'Missing data.'}, status=400)
            if len(username) < 3: return JsonResponse({'status': 'error', 'message': 'Username too short.'}, status=400)
            
            # Check existence, even if deleted (username remains taken)
            if AnonymousUser.objects.filter(username=username).exists(): 
                return JsonResponse({'status': 'error', 'message': 'Username is already taken.'}, status=409)
            
            AnonymousUser.objects.create(username=username, public_key=public_key)
            return JsonResponse({'status': 'ok', 'message': 'Registration successful!'})
        except json.JSONDecodeError: return JsonResponse({'status': 'error', 'message': 'Invalid JSON.'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
def check_username(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            if not username: return JsonResponse({'available': False, 'message': 'No username.'})
            is_taken = AnonymousUser.objects.filter(username=username).exists()
            return JsonResponse({'available': not is_taken})
        except json.JSONDecodeError: return JsonResponse({'available': False, 'message': 'Invalid JSON.'})
    return JsonResponse({'available': False, 'message': 'Method not allowed.'})

# --- Login ---
def login_page(request):
    if 'authenticated_user' in request.session:
        return redirect('dashboard_page')
    return render(request, 'chat/login.html')

@csrf_exempt
def get_login_challenge(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            if not username: return JsonResponse({'status': 'error', 'message': 'Username required.'}, status=400)
            
            # Prevent login if user is deleted
            try:
                user = AnonymousUser.objects.get(username=username)
                if user.is_deleted:
                    return JsonResponse({'status': 'error', 'message': 'This account has been deleted.'}, status=403)
            except AnonymousUser.DoesNotExist:
                pass # Let verification fail later to avoid enumeration, or fail here.

            nonce = secrets.token_hex(32)
            request.session['login_nonce'] = nonce
            request.session['login_username'] = username
            return JsonResponse({'status': 'ok', 'challenge': nonce})
        except json.JSONDecodeError: return JsonResponse({'status': 'error', 'message': 'Invalid JSON.'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
def verify_login_signature(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username, signature_b64 = data.get('username'), data.get('signature')
            original_nonce, session_username = request.session.get('login_nonce'), request.session.get('login_username')
            
            if not all([username, signature_b64, original_nonce, session_username]) or username != session_username:
                return JsonResponse({'status': 'error', 'message': 'Session expired.'}, status=400)
            
            user = AnonymousUser.objects.get(username=username)
            if user.is_deleted:
                 return JsonResponse({'status': 'error', 'message': 'Account deleted.'}, status=403)

            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{user.public_key}\n-----END PUBLIC KEY-----".encode('utf-8')
            public_key = load_pem_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            message_to_verify = original_nonce.encode('utf-8')
            public_key.verify(signature, message_to_verify, padding.PKCS1v15(), hashes.SHA256())
            
            del request.session['login_nonce']
            del request.session['login_username']
            request.session['authenticated_user'] = username 
            return JsonResponse({'status': 'ok', 'message': 'Success!', 'redirect_url': reverse('dashboard_page')})
        except (AnonymousUser.DoesNotExist, InvalidSignature):
            return JsonResponse({'status': 'error', 'message': 'Verification failed.'}, status=401)
        except Exception:
            return JsonResponse({'status': 'error', 'message': 'Server error.'}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

# --- ACCOUNT DELETION VIEWS ---

@csrf_exempt
@custom_login_required
def get_delete_challenge(request):
    """Generates a nonce specifically for account deletion."""
    if request.method == 'POST':
        nonce = secrets.token_hex(32)
        request.session['delete_nonce'] = nonce
        return JsonResponse({'status': 'ok', 'challenge': nonce})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
@custom_login_required
def verify_delete_account(request):
    """Verifies signature and marks account as deleted."""
    if request.method == 'POST':
        user = get_current_user(request)
        if not user: return JsonResponse({'status': 'error', 'message': 'User not authenticated.'}, status=401)
        
        try:
            data = json.loads(request.body)
            signature_b64 = data.get('signature')
            original_nonce = request.session.get('delete_nonce')
            
            if not signature_b64 or not original_nonce:
                return JsonResponse({'status': 'error', 'message': 'Missing signature or expired session.'}, status=400)
            
            # Verify Signature
            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{user.public_key}\n-----END PUBLIC KEY-----".encode('utf-8')
            public_key = load_pem_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            message_to_verify = original_nonce.encode('utf-8')
            public_key.verify(signature, message_to_verify, padding.PKCS1v15(), hashes.SHA256())
            
            # Perform Deletion (Soft Delete)
            user.is_deleted = True
            user.public_key = "" # Clear key so it cannot be used again
            user.save()
            
            # Cleanup session
            del request.session['authenticated_user']
            if 'delete_nonce' in request.session: del request.session['delete_nonce']
            
            return JsonResponse({'status': 'ok', 'message': 'Account deleted successfully.', 'redirect_url': reverse('login_page')})
            
        except InvalidSignature:
            return JsonResponse({'status': 'error', 'message': 'Invalid signature. Password may be wrong.'}, status=401)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)


# --- Chat Functions (Same as before) ---
@csrf_exempt
@custom_login_required
def create_chat_and_invite(request):
    if request.method == 'POST':
        user = get_current_user(request)
        try:
            data = json.loads(request.body)
            invitee_username = data.get('username')
            if not invitee_username: return JsonResponse({'status': 'error', 'message': 'Invitee required.'}, status=400)
            if invitee_username == user.username: return JsonResponse({'status': 'error', 'message': 'Cannot invite self.'}, status=400)
            
            try:
                invitee = AnonymousUser.objects.get(username=invitee_username)
                if invitee.is_deleted:
                     return JsonResponse({'status': 'error', 'message': 'User does not exist (deleted).'}, status=404)
            except AnonymousUser.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'User not found.'}, status=404)
                
            existing_invitation = Invitation.objects.filter((Q(inviter=user) & Q(invitee=invitee)) | (Q(inviter=invitee) & Q(invitee=user))).first()
            if existing_invitation:
                if existing_invitation.status == Invitation.Status.PENDING: return JsonResponse({'status': 'error', 'message': 'Invitation pending.'}, status=409)
                if existing_invitation.status == Invitation.Status.DECLINED: return JsonResponse({'status': 'error', 'message': 'Invitation previously declined.'}, status=403)
            if ChatRoom.objects.filter(members=user).filter(members=invitee).exists():
                return JsonResponse({'status': 'error', 'message': 'Chat exists.'}, status=409)
            
            new_room = ChatRoom.objects.create()
            new_room.members.add(user)
            Invitation.objects.create(room=new_room, inviter=user, invitee=invitee)
            return JsonResponse({'status': 'ok', 'message': f'Invitation sent to {invitee_username}.'})
        except json.JSONDecodeError: return JsonResponse({'status': 'error', 'message': 'Invalid JSON.'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
@custom_login_required
def respond_to_invitation(request, invitation_id):
    if request.method == 'POST':
        user = get_current_user(request)
        try:
            invitation = Invitation.objects.get(id=invitation_id, invitee=user)
            data = json.loads(request.body)
            response = data.get('response')
            if invitation.status != Invitation.Status.PENDING: return JsonResponse({'status': 'error', 'message': 'Already responded.'}, status=400)
            if response == 'accept':
                invitation.status = Invitation.Status.ACCEPTED
                invitation.room.members.add(user)
                msg = "Accepted."
            elif response == 'decline':
                invitation.status = Invitation.Status.DECLINED
                msg = "Declined."
            else: return JsonResponse({'status': 'error', 'message': 'Invalid response.'}, status=400)
            invitation.save()
            return JsonResponse({'status': 'ok', 'message': msg})
        except Invitation.DoesNotExist: return JsonResponse({'status': 'error', 'message': 'Not found.'}, status=404)
        except json.JSONDecodeError: return JsonResponse({'status': 'error', 'message': 'Invalid JSON.'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
@custom_login_required
def delete_chat_room(request, room_id):
    if request.method == 'POST':
        user = get_current_user(request)
        chat_room = get_object_or_404(ChatRoom, id=room_id)
        if user not in chat_room.members.all(): return JsonResponse({'status': 'error', 'message': 'Not authorized.'}, status=403)
        chat_room.delete()
        return JsonResponse({'status': 'ok', 'message': 'Room deleted.'})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@csrf_exempt
@custom_login_required
def remove_declined_by_invitee(request, invitation_id):
    if request.method == 'POST':
        user = get_current_user(request)
        invitation = get_object_or_404(Invitation, id=invitation_id, invitee=user)
        if invitation.status != Invitation.Status.DECLINED: return JsonResponse({'status': 'error', 'message': 'Not declined.'}, status=400)
        if invitation.room: invitation.room.delete()
        invitation.delete()
        return JsonResponse({'status': 'ok', 'message': 'Removed.'})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

@custom_login_required
def get_chat_messages(request, room_id):
    user = get_current_user(request)
    chat_room = get_object_or_404(ChatRoom, id=room_id)
    if user not in chat_room.members.all(): return JsonResponse({'status': 'error', 'message': 'Not authorized.'}, status=403)
    latest = chat_room.messages.order_by('-timestamp')[:50]
    messages = list(reversed(latest))
    messages_data = []
    for msg in messages:
        try:
            encrypted_payload = json.loads(msg.encrypted_content)
            user_specific_content = encrypted_payload.get(user.username)
            if user_specific_content:
                messages_data.append({'sender': msg.sender.username, 'content': user_specific_content, 'timestamp': msg.timestamp.isoformat()})
        except json.JSONDecodeError: continue
    return JsonResponse({'status': 'ok', 'messages': messages_data})

@csrf_exempt
@custom_login_required
def clear_chat_history(request, room_id):
    if request.method == 'POST':
        user = get_current_user(request)
        chat_room = get_object_or_404(ChatRoom, id=room_id)
        if user not in chat_room.members.all(): return JsonResponse({'status': 'error', 'message': 'Not authorized.'}, status=403)
        with transaction.atomic(): chat_room.messages.all().delete()
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(f'chat_{room_id}', {'type': 'chat_history_cleared', 'cleared_by': user.username})
        return JsonResponse({'status': 'ok', 'message': 'History cleared.'})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)