import uuid
from django.db import models

class AnonymousUser(models.Model):
    username = models.CharField(max_length=50, unique=True, primary_key=True)
    public_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    # New field to mark account as deleted without freeing the username
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.username

class ChatRoom(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    members = models.ManyToManyField(AnonymousUser, related_name='chat_rooms')

    def __str__(self):
        return f"ChatRoom ({self.id})"

class Invitation(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        ACCEPTED = 'ACCEPTED', 'Accepted'
        DECLINED = 'DECLINED', 'Declined'

    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='invitations')
    inviter = models.ForeignKey(AnonymousUser, on_delete=models.CASCADE, related_name='sent_invitations')
    invitee = models.ForeignKey(AnonymousUser, on_delete=models.CASCADE, related_name='received_invitations')
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Invitation from {self.inviter} to {self.invitee} ({self.status})"

class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(AnonymousUser, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    encrypted_content = models.TextField()

    def __str__(self):
        return f"Message from {self.sender} in {self.room.id} at {self.timestamp}"