import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ChatRoom, Message, AnonymousUser

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        self.room_group_name = f'chat_{self.room_id}'

        if not self.user.is_authenticated:
            print("DEBUG: User not authenticated. Rejecting.") # <--- Add this
            await self.close()
            return
        
        is_member = await self.is_room_member(self.user, self.room_id)
        if not is_member:
            await self.close()
            return

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'presence_announce',
                'username': self.user.username,
                'channel_name': self.channel_name
            }
        )

    async def disconnect(self, close_code):
        if self.user.is_authenticated:
            await self.channel_layer.group_send(
                self.room_group_name,
                {'type': 'user_status', 'username': self.user.username, 'status': 'offline'}
            )
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # This consumer can now handle both text (JSON) and binary (file chunks) data.
        if text_data:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'get_public_key':
                other_user_username = data.get('username')
                public_key = await self.get_user_public_key(other_user_username)
                if public_key:
                    await self.send(text_data=json.dumps({
                        'type': 'public_key_response',
                        'username': other_user_username,
                        'public_key': public_key
                    }))

            elif message_type == 'chat_message':
                encrypted_payload_str = data.get('message')
                await self.save_message(self.user, self.room_id, encrypted_payload_str)
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message_broadcast',
                        'sender': self.user.username,
                        'payload': encrypted_payload_str,
                    }
                )

            # File Transfer Signaling
            elif message_type in ['file_transfer_offer', 'file_transfer_response', 'file_transfer_end', 'window_ack']:
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'file_signal_broadcast',
                        'sender': self.user.username,
                        'signal_data': data,
                    }
                )
        
        # File Chunk Relay
        elif bytes_data:
            # When we receive a binary chunk, just forward it to the group.
            # The frontend now prepends a 4-byte transfer ID to each chunk.
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'file_chunk_broadcast',
                    'sender': self.user.username,
                    'chunk': bytes_data,
                }
            )

    # --- Handler Methods called by group_send ---
    async def presence_announce(self, event):
        if self.channel_name != event['channel_name']:
            await self.channel_layer.send(
                event['channel_name'],
                { 'type': 'user_status', 'username': self.user.username, 'status': 'online' }
            )
        await self.send(text_data=json.dumps({ 'type': 'user_status', 'username': event['username'], 'status': 'online' }))

    async def user_status(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_message_broadcast(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message_broadcast',
            'sender': event['sender'],
            'payload': event['payload']
        }))

    async def chat_history_cleared(self, event):
        await self.send(text_data=json.dumps({
            'type': 'history_cleared',
            'cleared_by': event['cleared_by']
        }))
    
    # File Transfer Handlers
    async def file_signal_broadcast(self, event):
        # Relay signaling messages (offer, response, end) to other clients in the room.
        if self.user.username != event['sender']:
            await self.send(text_data=json.dumps(event['signal_data']))

    async def file_chunk_broadcast(self, event):
        # Relay binary file chunks to other clients in the room.
        if self.user.username != event['sender']:
            await self.send(bytes_data=event['chunk'])

    # --- Database Methods ---
    @database_sync_to_async
    def is_room_member(self, user, room_id):
        try:
            room = ChatRoom.objects.get(id=room_id)
            return user in room.members.all()
        except ChatRoom.DoesNotExist:
            return False

    @database_sync_to_async
    def get_user_public_key(self, username):
        try:
            return AnonymousUser.objects.get(username=username).public_key
        except AnonymousUser.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message(self, sender, room_id, content_str):
        room = ChatRoom.objects.get(id=room_id)
        Message.objects.create(room=room, sender=sender, encrypted_content=content_str)