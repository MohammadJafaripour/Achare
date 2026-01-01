# serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import Ad, Review, Ticket, JobRequest, AdSchedule


User = get_user_model()

# --------------------
# User
# --------------------
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, min_length=6)

    class Meta:
        model = User
        fields = [
            "id", "username", "first_name", "last_name", "email", "phone", "role",
            "password", "date_joined", "average_rating", "total_reviews"
        ]
        read_only_fields = ["date_joined", "average_rating", "total_reviews"]

    def create(self, validated_data):
        pw = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(pw)
        user.save()
        return user

    def update(self, instance, validated_data):
        pw = validated_data.pop("password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if pw:
            instance.set_password(pw)
        instance.save()
        return instance


# --------------------
# Ad
# --------------------
class AdBaseSerializer(serializers.ModelSerializer):
    creator = serializers.PrimaryKeyRelatedField(read_only=True)
    performer = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Ad
        fields = "__all__"


class AdSerializer(serializers.ModelSerializer):
    """Full read serializer used across views (includes performer_marked_done)."""
    creator = serializers.PrimaryKeyRelatedField(read_only=True)
    performer = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Ad
        fields = [
            "id", "title", "description", "category", "status",
            "creator", "performer", #"performer_marked_done",
            "execution_time", "location", "created_at", "updated_at"
        ]
        read_only_fields = [
            "status", "creator", "performer", "performer_marked_done",
            "created_at", "updated_at"
        ]


class AdCreateSerializer(serializers.ModelSerializer):
    """Used for creating/updating by ad creator."""
    class Meta:
        model = Ad
        fields = ["id", "title", "description", "category", "execution_time", "location"]


# --------------------
# Review
# --------------------
class ReviewBaseSerializer(serializers.ModelSerializer):
    author = serializers.PrimaryKeyRelatedField(read_only=True)
    ad = serializers.PrimaryKeyRelatedField(queryset=Ad.objects.all())
    performer = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Review
        fields = ["id", "ad", "author", "performer", "text", "rating", "created_at", "updated_at"]
        read_only_fields = ["created_at", "updated_at", "author"]


class ReviewSerializer(ReviewBaseSerializer):
    """
    Used for GET/PUT/DELETE on a review.
    Validation enforces performer/ad consistency on create (checked below).
    On update (instance exists) we relax the 'ad.status == DONE' check to allow editing.
    """

    def validate(self, data):
        # If updating (instance exists), we allow editing with fewer constraints
        is_create = self.instance is None
        ad = data.get("ad") if "ad" in data else (self.instance.ad if self.instance else None)
        performer = data.get("performer") if "performer" in data else (self.instance.performer if self.instance else None)

        if ad is None or performer is None:
            return data  # let required validators handle missing fields

        # performer must match assigned performer
        if ad.performer is None or ad.performer.pk != performer.pk:
            raise serializers.ValidationError("Performer must be the ad's assigned performer.")

        # creation-only: ad must be confirmed DONE to create a review
        if is_create and ad.status != Ad.STATUS_DONE:
            raise serializers.ValidationError("You can leave a review only after the ad status is DONE.")

        return data

    def create(self, validated_data):
        validated_data["author"] = self.context["request"].user
        return super().create(validated_data)


class ReviewCreateSerializer(ReviewSerializer):
    """
    Explicit name used in views for creating reviews; inherits validation & create behavior.
    Fields presented to client are trimmed (no updated_at).
    """
    class Meta(ReviewSerializer.Meta):
        fields = ["id", "ad", "author", "performer", "text", "rating", "created_at"]
        read_only_fields = ["author", "created_at"]


class ReviewReadSerializer(serializers.ModelSerializer):
    """Read-friendly representation of review with author info."""
    author = serializers.SerializerMethodField()

    class Meta:
        model = Review
        fields = ["id", "author", "text", "rating", "created_at"]

    def get_author(self, obj):
        name = f"{obj.author.first_name} {obj.author.last_name}".strip()
        return {"id": obj.author.pk, "name": name or obj.author.email}


# --------------------
# JobRequest
# --------------------
class JobRequestSerializer(serializers.ModelSerializer):
    contractor = serializers.PrimaryKeyRelatedField(read_only=True)
    ad = serializers.PrimaryKeyRelatedField(queryset=Ad.objects.all())

    class Meta:
        model = JobRequest
        fields = ["id", "ad", "contractor", "message", "proposed_price", "status", "created_at"]
        read_only_fields = ["status", "created_at", "contractor"]

    def validate(self, data):
        ad = data["ad"]
        if ad.status != Ad.STATUS_OPEN:
            raise serializers.ValidationError("You can only request jobs for ads with status OPEN.")
        return data

    def create(self, validated_data):
        validated_data["contractor"] = self.context["request"].user
        return super().create(validated_data)


# --------------------
# Ticket
# --------------------
class TicketSerializer(serializers.ModelSerializer):
    creator = serializers.PrimaryKeyRelatedField(read_only=True)
    ad = serializers.PrimaryKeyRelatedField(queryset=Ad.objects.all(), required=False, allow_null=True)

    class Meta:
        model = Ticket
        fields = ["id", "creator", "ad", "subject", "messages", "status", "created_at", "updated_at"]
        read_only_fields = ["creator", "created_at", "updated_at"]

    def create(self, validated_data):
        validated_data["creator"] = self.context["request"].user
        if not validated_data.get("messages"):
            validated_data["messages"] = []
        return super().create(validated_data)


class TicketCreateSerializer(TicketSerializer):
    """Alias used by views for ticket creation (inherits create behavior)."""
    class Meta(TicketSerializer.Meta):
        read_only_fields = ["status", "created_at"]


# --------------------
# Profiles & helper serializers
# --------------------
class AdBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ad
        fields = ["id", "title", "status", "execution_time", "location", "created_at"]


class CustomerProfileSerializer(serializers.ModelSerializer):
    ads = AdBriefSerializer(many=True)  # creator.related_name == "ads"

    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "phone", "role", "ads"]


class ContractorProfileSerializer(serializers.ModelSerializer):
    completed_count = serializers.IntegerField()
    average_rating = serializers.FloatField()
    total_reviews = serializers.IntegerField()
    reviews = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "first_name", "last_name", "email", "phone", "role",
            "completed_count", "average_rating", "total_reviews", "reviews"
        ]

    def get_reviews(self, obj):
        reviews_qs = Review.objects.filter(performer=obj).order_by("-created_at")
        return [
            {
                "id": r.id,
                "author_id": r.author.pk,
                "author_name": f"{r.author.first_name} {r.author.last_name}".strip() or r.author.email,
                "text": r.text,
                "rating": r.rating,
                "created_at": r.created_at
            }
            for r in reviews_qs
        ]


class ContractorListItemSerializer(serializers.ModelSerializer):
    completed_count = serializers.IntegerField()
    average_rating = serializers.FloatField()
    total_reviews = serializers.IntegerField()

    class Meta:
        model = User
        fields = [
            "id", "first_name", "last_name", "email", "phone", "role",
            "completed_count", "average_rating", "total_reviews"
        ]


class AdScheduleSerializer(serializers.ModelSerializer):
    ad = serializers.PrimaryKeyRelatedField(queryset=Ad.objects.all())
    contractor = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = AdSchedule
        fields = ["id", "ad", "contractor", "start_time", "end_time", "location", "created_at", "updated_at"]
        read_only_fields = ["contractor", "created_at", "updated_at"]

    def validate(self, data):
        ad = data["ad"]
        # contractor will be set from request
        contractor = self.context["request"].user

        # ad must have performer set to this contractor
        if ad.performer is None or ad.performer.pk != contractor.pk:
            raise serializers.ValidationError("Only the assigned performer can set schedule for this ad.")

        start = data.get("start_time")
        end = data.get("end_time")
        if not start or not end:
            raise serializers.ValidationError("start_time and end_time are required.")
        if end <= start:
            raise serializers.ValidationError("end_time must be after start_time.")

        # check overlapping schedules for this contractor (exclude this ad's existing schedule if updating)
        qs = AdSchedule.objects.filter(contractor=contractor).exclude(ad=ad)
        overlap = qs.filter(start_time__lt=end, end_time__gt=start).exists()
        if overlap:
            raise serializers.ValidationError("Schedule overlaps with another assigned ad for this contractor.")

        return data

    def create(self, validated_data):
        validated_data["contractor"] = self.context["request"].user
        # if a schedule exists for this ad, update it (one-to-one)
        schedule, created = AdSchedule.objects.update_or_create(ad=validated_data["ad"], defaults=validated_data)
        return schedule