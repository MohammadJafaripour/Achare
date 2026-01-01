# admin.py
from django.contrib import admin
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from django.db.models import Count, Q, Avg, F

from .models import Ad, Review, Ticket, JobRequest

User = get_user_model()


# -------------------------
# Custom forms for User admin
# -------------------------
class CustomUserCreationForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Password confirmation", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ("email","username", "first_name", "last_name", "phone", "role")

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if not password1 or not password2:
            raise forms.ValidationError("Both password fields are required.")
        if password1 != password2:
            raise forms.ValidationError("Passwords don't match.")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CustomUserChangeForm(forms.ModelForm):
    """
    A form for updating users in admin. Displays password hash as read-only.
    """
    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_("Raw passwords are not stored, so there is no way to see "
                    "this user's password, but you can change the password "
                    "using <a href=\"../password/\">this form</a>.")
    )

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name", "phone", "role", "is_active", "is_staff", "is_superuser")

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        return self.initial["password"]


# -------------------------
# Inlines
# -------------------------
class ReviewInline(admin.TabularInline):
    model = Review
    fields = ("ad", "author", "performer", "rating", "text", "created_at")
    readonly_fields = ("ad", "author", "performer", "rating", "text", "created_at")
    extra = 0
    can_delete = False
    show_change_link = True


class JobRequestInline(admin.TabularInline):
    model = JobRequest
    fields = ("contractor", "message", "proposed_price", "status", "created_at")
    readonly_fields = ("contractor", "message", "proposed_price", "status", "created_at")
    extra = 0
    can_delete = False
    show_change_link = True


# -------------------------
# UserAdmin
# -------------------------
@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    model = User

    # email is used as the unique identifier
    list_display = ("id", "email", "first_name", "last_name", "role", "is_staff", "is_active", "average_rating", "total_reviews")
    list_filter = ("role", "is_staff", "is_superuser", "is_active")
    search_fields = ("email", "first_name", "last_name", "phone")
    ordering = ("-date_joined",)
    readonly_fields = ("average_rating", "total_reviews", "date_joined", "last_login")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name", "phone")}),
        (_("Permissions"), {"fields": ("role", "is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
        (_("Aggregates"), {"fields": ("average_rating", "total_reviews")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "first_name", "last_name", "phone", "role", "password1", "password2", "is_staff", "is_active"),
        }),
    )

    actions = ["make_staff", "make_active", "make_inactive"]

    def make_staff(self, request, queryset):
        updated = queryset.update(is_staff=True)
        self.message_user(request, f"{updated} user(s) marked as staff.")
    make_staff.short_description = "Mark selected users as staff"

    def make_active(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} user(s) activated.")
    make_active.short_description = "Activate selected users"

    def make_inactive(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} user(s) deactivated.")
    make_inactive.short_description = "Deactivate selected users"


# -------------------------
# Ad admin
# -------------------------
@admin.register(Ad)
class AdAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "creator", "performer", "status", "execution_time", "location", "created_at")
    list_filter = ("status", "category", "created_at", "execution_time")
    search_fields = ("title", "description", "creator__email", "performer__email", "location")
    readonly_fields = ("created_at", "updated_at")
    inlines = [JobRequestInline, ReviewInline]
    actions = ["mark_done", "cancel_ad"]

    def mark_done(self, request, queryset):
        updated = queryset.exclude(status=Ad.STATUS_DONE).update(status=Ad.STATUS_DONE, updated_at=timezone.now())
        self.message_user(request, f"{updated} ad(s) marked as done.")
    mark_done.short_description = "Mark selected ads as done"

    def cancel_ad(self, request, queryset):
        updated = queryset.exclude(status=Ad.STATUS_DONE).update(status="cancelled", updated_at=timezone.now())
        self.message_user(request, f"{updated} ad(s) cancelled.")
    cancel_ad.short_description = "Cancel selected ads"


# -------------------------
# Review admin
# -------------------------
@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ("id", "ad", "performer", "author", "rating", "created_at")
    list_filter = ("rating", "created_at")
    search_fields = ("ad__title", "author__email", "performer__email", "text")
    readonly_fields = ("created_at", "updated_at")
    actions = ["recalculate_performer_rating"]

    def recalculate_performer_rating(self, request, queryset):
        """
        Recalculate aggregate rating for affected performers.
        Useful if you bulk-edit reviews.
        """
        performers = set(q.performer for q in queryset)
        for performer in performers:
            agg = Review.objects.filter(performer=performer).aggregate(avg=Avg("rating"), cnt=Count("id"))
            performer.average_rating = agg["avg"] or 0.0
            performer.total_reviews = agg["cnt"] or 0
            performer.save(update_fields=["average_rating", "total_reviews"])
        self.message_user(request, "Performer ratings recalculated.")
    recalculate_performer_rating.short_description = "Recalculate performer aggregates"


# -------------------------
# Ticket admin
# -------------------------
@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("id", "subject", "creator", "status", "created_at", "updated_at")
    list_filter = ("status", "created_at")
    search_fields = ("subject", "creator__email", "messages")
    readonly_fields = ("created_at", "updated_at")
    actions = ["close_tickets"]

    def close_tickets(self, request, queryset):
        updated = queryset.exclude(status=Ticket.STATUS_CLOSED).update(status=Ticket.STATUS_CLOSED, updated_at=timezone.now())
        self.message_user(request, f"{updated} ticket(s) closed.")
    close_tickets.short_description = "Close selected tickets"


# -------------------------
# JobRequest admin
# -------------------------
@admin.register(JobRequest)
class JobRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "ad", "contractor", "proposed_price", "status", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("ad__title", "contractor__email", "message")
    readonly_fields = ("created_at",)
    actions = ["accept_requests", "cancel_requests", "reject_requests"]

    def accept_requests(self, request, queryset):
        accepted = 0
        for jr in queryset.filter(status=JobRequest.STATUS_PENDING):
            jr.status = JobRequest.STATUS_ACCEPTED
            jr.save(update_fields=["status"])
            # assign the ad to this contractor
            jr.ad.assign_to(jr.contractor, execution_time=jr.ad.execution_time, location=jr.ad.location)
            # mark others as rejected
            JobRequest.objects.filter(ad=jr.ad).exclude(pk=jr.pk).update(status=JobRequest.STATUS_REJECTED)
            accepted += 1
        self.message_user(request, f"{accepted} request(s) accepted and ads assigned.")
    accept_requests.short_description = "Accept selected job requests (assign ad)"

    def cancel_requests(self, request, queryset):
        updated = queryset.exclude(status=JobRequest.STATUS_CANCELLED).update(status=JobRequest.STATUS_CANCELLED)
        self.message_user(request, f"{updated} request(s) cancelled.")
    cancel_requests.short_description = "Cancel selected job requests"

    def reject_requests(self, request, queryset):
        updated = queryset.exclude(status=JobRequest.STATUS_REJECTED).update(status=JobRequest.STATUS_REJECTED)
        self.message_user(request, f"{updated} request(s) rejected.")
    reject_requests.short_description = "Reject selected job requests"
