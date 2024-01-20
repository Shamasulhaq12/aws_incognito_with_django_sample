from django.contrib import admin
from django.contrib.auth import get_user_model

User = get_user_model()

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_admin', 'is_staff', 'is_superuser')
    search_fields = ('email',)
    readonly_fields = ( 'last_login','password','id')

    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('email',)
        return self.readonly_fields

# Register your models here.
