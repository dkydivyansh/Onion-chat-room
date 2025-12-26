from django.contrib import admin
from .models import AnonymousUser, Invitation, ChatRoom

# These classes allow you to customize how your models appear in the admin panel.
class AnonymousUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'created_at')
    search_fields = ('username',)

class InvitationAdmin(admin.ModelAdmin):
    list_display = ('inviter', 'invitee', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('inviter__username', 'invitee__username')

class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_members')
    filter_horizontal = ('members',) # Makes adding members easier

    def get_members(self, obj):
        return ", ".join([user.username for user in obj.members.all()])
    get_members.short_description = 'Members'


# Register your models with the admin site
admin.site.register(AnonymousUser, AnonymousUserAdmin)
admin.site.register(Invitation, InvitationAdmin)
admin.site.register(ChatRoom, ChatRoomAdmin)

