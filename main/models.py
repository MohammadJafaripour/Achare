from django.db import models

from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models import Avg, Count
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
# ----------------------
# 1) User model
# ----------------------

from django.contrib.auth.base_user import BaseUserManager


class User(AbstractUser):
    """
    Custom user extending Django's AbstractUser so we have password management,
    is_active, date_joined, etc. Username remains (can login via username),
    email is made unique so we can locate by email as well.
    """
    ROLE_USER = "user"
    ROLE_CONTRACTOR = "contractor"
    ROLE_SUPPORT = "support"
    ROLE_ADMIN = "admin"
    ROLE_CHOICES = [
        (ROLE_USER, "User"),
        (ROLE_CONTRACTOR, "Contractor"),
        (ROLE_SUPPORT, "Support"),
        (ROLE_ADMIN, "Admin"),
    ]

    username = models.CharField(max_length=150, unique=True, null=True)
    # override email to be unique
    email = models.EmailField('email address', unique=True)
    phone = models.CharField("phone", max_length=30, blank=True, null=True,unique=True)
    role = models.CharField("role", max_length=30, choices=ROLE_CHOICES, default=ROLE_USER)



    # aggregated fields (keep updated with signals from Review model)
    average_rating = models.FloatField("average rating", default=0.0)
    total_reviews = models.PositiveIntegerField("total reviews", default=0)

    # Note: AbstractUser already defines: username, first_name, last_name,
    # password, is_active, date_joined, last_login, etc.

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self):
        name = f"{self.first_name} {self.last_name}".strip()
        return name or self.email
# ----------------------
# 2) Ad model
# ----------------------
class Ad(models.Model):
    """
    Ad / Job request posted by a user.
    After assignment to a performer it will have execution_time and location.
    """
    STATUS_OPEN = "open"
    STATUS_REVIEWING = "review"
    STATUS_DONE_BY_PERFORMER = "done but no acc yet"
    STATUS_DONE = "done"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_REVIEWING, "Under Review"),
        (STATUS_DONE_BY_PERFORMER , "done but no acc yet"),
        (STATUS_DONE, "Done"),
        (STATUS_CANCELLED , "Cancelled"),
    ]

    title = models.CharField("title", max_length=250)
    description = models.TextField("description")
    category = models.CharField("category", max_length=120, blank=True)
    status = models.CharField("status", max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)

    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL, verbose_name="creator", on_delete=models.CASCADE, related_name="ads"
    )
    performer = models.ForeignKey(
        settings.AUTH_USER_MODEL, verbose_name="performer", on_delete=models.SET_NULL,
        null=True, blank=True, related_name="assigned_ads"
    )

    execution_time = models.DateTimeField("execution time", null=True, blank=True)
    location = models.CharField("location", max_length=300, blank=True)

    created_at = models.DateTimeField("created at", auto_now_add=True)
    updated_at = models.DateTimeField("updated at", auto_now=True)

    class Meta:
        verbose_name = "ad"
        verbose_name_plural = "ads"
        ordering = ["-created_at"]

    def assign_to(self, performer, execution_time=None, location=None):
        """
        Helper to assign this ad to a performer.
        """
        self.performer = performer
        self.status = self.STATUS_REVIEWING
        if execution_time:
            self.execution_time = execution_time
        if location:
            self.location = location
        self.save(update_fields=["performer", "status", "execution_time", "location", "updated_at"])

    def mark_performer_done(self):
        self.status = self.STATUS_DONE_BY_PERFORMER
        self.save(update_fields=["status", "updated_at"])

    def mark_done(self):
        self.status = self.STATUS_DONE
        self.save(update_fields=["status", "updated_at"])

    def cancel(self):
        self.status = self.STATUS_CANCELLED
        self.save(update_fields=["status", "updated_at"])

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

# ----------------------
# 3) Review model
# ----------------------
class Review(models.Model):
    """
    Reviews / ratings:
    - Each review is written by an author (user).
    - Each review belongs to an ad and to a performer.
    - Rating ranges 1..5.
    """
    ad = models.ForeignKey(Ad, verbose_name="ad", on_delete=models.CASCADE, related_name="reviews")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name="author", on_delete=models.CASCADE, related_name="reviews_written")
    performer = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name="performer", on_delete=models.CASCADE, related_name="reviews_received")

    text = models.TextField("text", blank=True)
    rating = models.PositiveSmallIntegerField(
        "rating", validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    created_at = models.DateTimeField("created at", auto_now_add=True)
    updated_at = models.DateTimeField("updated at", auto_now=True)

    class Meta:
        verbose_name = "review"
        verbose_name_plural = "reviews"
        ordering = ["-created_at"]
        unique_together = ("ad", "author")  # optional: one review per author per ad

    def __str__(self):
        return f"Rating {self.rating} by {self.author} for {self.performer}"

# Signals to update aggregated performer stats
@receiver([post_save, post_delete], sender=Review)
def update_performer_rating(sender, instance, **kwargs):
    performer = instance.performer
    agg = Review.objects.filter(performer=performer).aggregate(avg=Avg("rating"), cnt=Count("id"))
    performer.average_rating = agg["avg"] or 0.0
    performer.total_reviews = agg["cnt"] or 0
    performer.save(update_fields=["average_rating", "total_reviews"])

# ----------------------
# 4) Ticket model
# ----------------------
class Ticket(models.Model):
    """
    Support tickets:
    - Each ticket is created by a user.
    - A ticket can be optionally related to an Ad.
    - Messages are stored in a JSONField (list of dicts). Each message: {"author_id": id, "text": "...", "created_at": "..."}
      If you prefer pagination/search over messages, create a separate TicketMessage model instead.
    """
    STATUS_OPEN = "open"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_CLOSED, "Closed"),
    ]

    creator = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name="creator", on_delete=models.CASCADE, related_name="tickets")
    ad = models.ForeignKey(Ad, verbose_name="related ad", on_delete=models.SET_NULL, null=True, blank=True, related_name="tickets")

    subject = models.CharField("subject", max_length=250)
    messages = models.JSONField("messages", default=list, blank=True)
    status = models.CharField("status", max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_at = models.DateTimeField("created at", auto_now_add=True)
    updated_at = models.DateTimeField("updated at", auto_now=True)

    class Meta:
        verbose_name = "ticket"
        verbose_name_plural = "tickets"
        ordering = ["-created_at"]

    def add_message(self, author, text):
        """
        Add a new message to the ticket (author: User instance).
        """
        entry = {
            "author_id": author.pk,
            "text": text,
            "created_at": timezone.now().isoformat()
        }
        msgs = self.messages or []
        msgs.append(entry)
        self.messages = msgs
        self.save(update_fields=["messages", "updated_at"])

    def __str__(self):
        return f"Ticket #{self.id} - {self.subject} ({self.get_status_display()})"

class JobRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_CANCELLED = "cancelled"
    STATUS_ACCEPTED = "accepted"
    STATUS_REJECTED = "rejected"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_ACCEPTED, "Accepted"),
        (STATUS_REJECTED, "Rejected"),
    ]

    ad = models.ForeignKey(Ad, on_delete=models.CASCADE, related_name="job_requests")
    contractor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="job_requests")
    message = models.TextField(blank=True)
    proposed_price = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)

    class Meta:
        unique_together = ("ad", "contractor")  # one request per contractor per ad
        ordering = ["-created_at"]

    def cancel(self):
        self.status = self.STATUS_CANCELLED
        self.save(update_fields=["status"])
