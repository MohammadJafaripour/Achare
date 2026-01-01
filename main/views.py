# views.py (refactored, duplicates removed)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q, Avg, F
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from .serializers import (
    UserSerializer,
    AdSerializer, AdCreateSerializer,
    ReviewSerializer, ReviewCreateSerializer, ReviewReadSerializer,
    TicketSerializer, TicketCreateSerializer,
    JobRequestSerializer, JobRequestSerializer as JRSerializer,
    CustomerProfileSerializer, ContractorProfileSerializer,
    ContractorListItemSerializer
)
from .models import Ad, Review, Ticket, JobRequest
from .permissions import (
    AdPermission, TicketPermission, IsOwnerOrAdmin, IsAdminUserRole, IsContractor,
    IsCreatorOrAdmin, IsSupportOrAdmin, IsTicketReplyAllowed, IsJobRequestOwnerOrAdmin,
    IsAdCreator
)

User = get_user_model()
# at the top of views.py add:
from drf_spectacular.utils import extend_schema, OpenApiExample

# --------------------------
# Auth: registration & login
# --------------------------
@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "email": {"type": "string"},
                "phone": {"type": "string"},
                "password": {"type": "string"},
                "role": {"type": "string", "description": "optional (admin only can set different roles)"}
            },
            "example": {
                "username": "AliRezaei",
                "first_name": "Ali",
                "last_name": "Rezaei",
                "email": "ali@example.com",
                "phone": "+1234567890",
                "password": "P@ssw0rd",
                "role": "user",
            }
        }
    },
    examples=[
        OpenApiExample(
            "Register response example",
            value={
                "id": 1,
                "username": "AliRezaei",
                "first_name": "Ali",
                "last_name": "Rezaei",
                "email": "ali@example.com",
                "phone": "+1234567890",
                "role": "user",
                "date_joined": "2026-01-01T12:00:00Z",
                "average_rating": 0.0,
                "total_reviews": 0,
                "token": "abcd1234-token-example"
            },
            response_only=True,
            status_codes=["201"]
        )
    ],
)
class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data.copy()
        data['role'] = data.get('role', 'user')
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            token, _ = Token.objects.get_or_create(user=user)
            out = UserSerializer(user).data
            out['token'] = token.key
            return Response(out, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "identifier": {"type": "string", "description": "username or email or phone"},
                "password": {"type": "string"}
            },
            "example": {"identifier": "ali@example.com", "password": "P@ssw0rd"}
        }
    },
    examples=[
        OpenApiExample(
            "Login success example",
            value={
                "id": 1,
                "username": "AliRezaei",
                "first_name": "Ali",
                "last_name": "Rezaei",
                "email": "ali@example.com",
                "phone": "+1234567890",
                "role": "user",
                "date_joined": "2026-01-01T12:00:00Z",
                "average_rating": 0.0,
                "total_reviews": 0,
                "token": "abcd1234-token-example"
            },
            response_only=True,
            status_codes=["200"]
        ),
        OpenApiExample(
            "Login error example",
            value={"detail": "Invalid credentials."},
            response_only=True,
            status_codes=["400"]
        )
    ]
)
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = request.data.get('identifier') or request.data.get('username') or request.data.get('email')
        password = request.data.get('password')
        if not identifier or not password:
            return Response({"detail": "Provide identifier and password."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email__iexact=identifier).first()
        if not user:
            user = User.objects.filter(phone__iexact=identifier).first()
        if not user and hasattr(User, "username"):
            user = User.objects.filter(username__iexact=identifier).first()

        if not user or not user.check_password(password):
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        token, _ = Token.objects.get_or_create(user=user)
        data = UserSerializer(user).data
        data['token'] = token.key
        return Response(data, status=status.HTTP_200_OK)


# --------------------------
# User detail / update (self)
# --------------------------
@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "email": {"type": "string"},
                "phone": {"type": "string"},
                "password": {"type": "string"},
                "role": {"type": "string", "description": "optional (admin only can set different roles)"}
            },
            "example": {
                "username": "AliRezaei",
                "first_name": "Alimmd",
                "last_name": "Rezaei",
                "email": "ali@example.com",
                "phone": "+1234567890",
                "password": "P@ssw0rd"
            }
        }
    },
    responses=[
        OpenApiExample(
            "Current user example (GET /auth/me/)",
            value={
                "id": 1,
                "username": "AliRezaei",
                "first_name": "Ali",
                "last_name": "Rezaei",
                "email": "ali@example.com",
                "phone": "+1234567890",
                "role": "user",
                "date_joined": "2026-01-01T12:00:00Z",
                "average_rating": 4.6,
                "total_reviews": 12
            },
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class UserDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)

    def put(self, request):
        data = request.data.copy()
        if 'role' in data and not (request.user.is_superuser or getattr(request.user, "role", "") == "admin"):
            data.pop('role')
        serializer = UserSerializer(request.user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --------------------------
# Ads: list/create/retrieve/update/delete
# --------------------------
@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "category": {"type": "string"},
                "execution_time": {"type": "string", "format": "date-time"},
                "location": {"type": "string"}
            },
            "example": {
                "title": "Fix leaking sink",
                "description": "Kitchen sink leaking, needs repair",
                "category": "plumbing",
                "execution_time": "2026-02-10T09:00:00Z",
                "location": "123 Main St"
            }
        }
    },
    examples=[
        OpenApiExample(
            "Create Ad response example",
            value={
                "id": 42,
                "title": "Fix leaking sink",
                "description": "Kitchen sink leaking, needs repair",
                "category": "plumbing",
                "status": "open",
                "creator": 5,
                "performer": None,
                "performer_marked_done": False,
                "execution_time": "2026-02-10T09:00:00Z",
                "location": "123 Main St",
                "created_at": "2026-01-05T10:00:00Z",
                "updated_at": "2026-01-05T10:00:00Z"
            },
            response_only=True,
            status_codes=["201"]
        )
    ]
)
class AdListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = Ad.objects.all().order_by("-created_at")
        if not (request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support")):
            qs = qs.exclude(status=Ad.STATUS_CANCELLED)
        return Response(AdSerializer(qs, many=True).data)

    def post(self, request):
        serializer = AdCreateSerializer(data=request.data)
        if serializer.is_valid():
            ad = serializer.save(creator=request.user)
            return Response(AdSerializer(ad).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    responses=[
        OpenApiExample(
            "Ad detail response example",
            value={
                "id": 42,
                "title": "Fix leaking sink",
                "description": "Kitchen sink leaking, needs repair",
                "category": "plumbing",
                "status": "open",
                "creator": 5,
                "performer": None,
                "performer_marked_done": False,
                "execution_time": "2026-02-10T09:00:00Z",
                "location": "123 Main St",
                "created_at": "2026-01-05T10:00:00Z",
                "updated_at": "2026-01-05T10:00:00Z"
            },
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, AdPermission]

    def get_object(self, pk):
        return get_object_or_404(Ad, pk=pk)

    def get(self, request, pk):
        ad = self.get_object(pk)
        return Response(AdSerializer(ad).data)

    def put(self, request, pk):
        ad = self.get_object(pk)
        self.check_object_permissions(request, ad)
        if ad.creator.pk != request.user.pk and not (request.user.is_superuser or getattr(request.user, "role", "") == "admin"):
            return Response({"detail": "You are not allowed to modify this ad."}, status=status.HTTP_403_FORBIDDEN)
        serializer = AdCreateSerializer(ad, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(AdSerializer(ad).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        ad = self.get_object(pk)
        self.check_object_permissions(request, ad)
        if ad.creator.pk != request.user.pk and not (request.user.is_superuser or getattr(request.user, "role", "") == "admin"):
            return Response({"detail": "You are not allowed to delete this ad."}, status=status.HTTP_403_FORBIDDEN)
        ad.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------
# Assignment & status transitions
# --------------------------
@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "performer_id": {"type": "integer"},
                "execution_time": {"type": "string", "format": "date-time"},
                "location": {"type": "string"}
            },
            "example": {"performer_id": 10, "execution_time": "2026-02-10T09:00:00Z", "location": "123 Main St"}
        }
    },
    examples=[
        OpenApiExample(
            "Assign ad response example",
            value={
                "id": 42,
                "title": "Fix leaking sink",
                "status": "assigned",
                "creator": 5,
                "performer": 10,
                "execution_time": "2026-02-10T09:00:00Z",
                "location": "123 Main St",
                "performer_marked_done": False
            },
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdAssignAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        ad = get_object_or_404(Ad, pk=pk)
        user = request.user
        if not (ad.creator.pk == user.pk or user.is_superuser or getattr(user, "role", "") in ("admin", "support")):
            return Response({"detail": "Only creator or admin/support can assign."}, status=status.HTTP_403_FORBIDDEN)

        performer_id = request.data.get("performer_id")
        if not performer_id:
            return Response({"detail": "performer_id required."}, status=status.HTTP_400_BAD_REQUEST)
        performer = get_object_or_404(User, pk=performer_id)
        if getattr(performer, "role", "") != "contractor" and not performer.is_superuser:
            return Response({"detail": "Assigned user must have contractor role."}, status=status.HTTP_400_BAD_REQUEST)

        ad.assign_to(performer, execution_time=request.data.get("execution_time"), location=request.data.get("location"))
        return Response(AdSerializer(ad).data)


@extend_schema(
    responses=[
        OpenApiExample(
            "Performer mark done response example",
            value={"detail": "Performer marked task as completed. Customer must confirm."},
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdPerformerMarkDoneAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not ad.performer or ad.performer.pk != request.user.pk:
            return Response({"detail": "Only assigned performer can mark done."}, status=status.HTTP_403_FORBIDDEN)
        if ad.status != Ad.STATUS_REVIEWING:
            return Response({"detail": "Ad must be ASSIGNED to mark completion."}, status=status.HTTP_400_BAD_REQUEST)
        ad.mark_performer_done()
        return Response(AdSerializer(ad).data)


@extend_schema(
    responses=[
        OpenApiExample(
            "Creator confirm done response example",
            value={
                "id": 42,
                "status": "done",
                "performer_marked_done": False
            },
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdCreatorConfirmDoneAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not (ad.creator.pk == request.user.pk or request.user.is_superuser or getattr(request.user, "role", "") == "admin"):
            return Response({"detail": "Only ad creator or admin can confirm completion."}, status=status.HTTP_403_FORBIDDEN)
        if ad.status == Ad.STATUS_DONE:
            return Response({"detail": "Ad already marked done."}, status=status.HTTP_400_BAD_REQUEST)
        if not ad.performer:
            return Response({"detail": "Ad has no assigned performer."}, status=status.HTTP_400_BAD_REQUEST)
        if not ad.mark_performer_done:
            return Response({"detail": "Performer has not declared completion yet."}, status=status.HTTP_400_BAD_REQUEST)
        ad.mark_done()
        return Response(AdSerializer(ad).data)


@extend_schema(
    responses=[
        OpenApiExample(
            "Cancel ad response example",
            value={"id": 42, "status": "cancelled"},
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdCancelAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        user = request.user
        if not (ad.creator.pk == user.pk or user.is_superuser or getattr(user, "role", "") in ("admin", "support")):
            return Response({"detail": "Only creator or admin/support can cancel ad."}, status=status.HTTP_403_FORBIDDEN)
        if ad.status == Ad.STATUS_DONE:
            return Response({"detail": "Cannot cancel a completed ad."}, status=status.HTTP_400_BAD_REQUEST)
        ad.cancel()
        return Response(AdSerializer(ad).data)


# --------------------------
# JobRequest endpoints (apply / cancel / delete / list applicants)
# --------------------------
@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "ad": {"type": "integer"},
                "message": {"type": "string"},
                "proposed_price": {"type": "string"}
            },
            "example": {"ad": 42, "message": "I can do this next week", "proposed_price": "150.00"}
        }
    },
    examples=[
        OpenApiExample(
            "JobRequest response example",
            value={
                "id": 101,
                "ad": 42,
                "contractor": 10,
                "message": "I can do this next week",
                "proposed_price": "150.00",
                "status": "pending",
                "created_at": "2026-01-10T12:00:00Z"
            },
            response_only=True,
            status_codes=["201"]
        )
    ]
)
class JobRequestCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, IsContractor]

    def post(self, request):
        serializer = JobRequestSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            jr = serializer.save()
            return Response(JobRequestSerializer(jr).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    responses=[
        OpenApiExample(
            "JobRequest cancel response example",
            value={"id": 101, "status": "cancelled"},
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class JobRequestCancelAPIView(APIView):
    permission_classes = [IsAuthenticated, IsJobRequestOwnerOrAdmin]

    def post(self, request, pk):
        jr = get_object_or_404(JobRequest, pk=pk)
        self.check_object_permissions(request, jr)
        if jr.status != JobRequest.STATUS_PENDING:
            return Response({"detail": "Only pending requests can be cancelled."}, status=status.HTTP_400_BAD_REQUEST)
        jr.cancel()
        return Response(JobRequestSerializer(jr).data)


class JobRequestDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated, IsJobRequestOwnerOrAdmin]

    def delete(self, request, pk):
        jr = get_object_or_404(JobRequest, pk=pk)
        self.check_object_permissions(request, jr)
        jr.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    responses=[
        OpenApiExample(
            "Applicants list example",
            value=[
                {
                    "id": 101,
                    "ad": 42,
                    "contractor": 10,
                    "message": "I can do this next week",
                    "proposed_price": "150.00",
                    "status": "pending",
                    "created_at": "2026-01-10T12:00:00Z"
                }
            ],
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdApplicantsListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not (ad.creator.pk == request.user.pk or request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support")):
            return Response({"detail": "Not allowed to view applicants."}, status=status.HTTP_403_FORBIDDEN)
        qs = ad.job_requests.all()
        return Response(JobRequestSerializer(qs, many=True).data)


@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "performer_id": {"type": "integer"},
                "execution_time": {"type": "string", "format": "date-time"},
                "location": {"type": "string"}
            },
            "example": {"performer_id": 10, "execution_time": "2026-02-12T09:00:00Z", "location": "123 Main St"}
        }
    },
    examples=[
        OpenApiExample(
            "Accept applicant response example",
            value={
                "id": 42,
                "status": "assigned",
                "performer": 10,
                "execution_time": "2026-02-12T09:00:00Z",
                "location": "123 Main St"
            },
            response_only=True,
            status_codes=["200"]
        )
    ]
)
class AdAcceptApplicantAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not (ad.creator.pk == request.user.pk or request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support")):
            return Response({"detail": "Only ad creator or admin/support can accept applicant."}, status=status.HTTP_403_FORBIDDEN)
        performer_id = request.data.get("performer_id")
        if not performer_id:
            return Response({"detail": "performer_id required."}, status=status.HTTP_400_BAD_REQUEST)
        performer = get_object_or_404(User, pk=performer_id)
        jr = JobRequest.objects.filter(ad=ad, contractor=performer, status=JobRequest.STATUS_PENDING).first()
        if not jr:
            return Response({"detail": "No pending application from this contractor."}, status=status.HTTP_400_BAD_REQUEST)
        jr.status = JobRequest.STATUS_ACCEPTED
        jr.save(update_fields=["status"])
        ad.assign_to(performer, execution_time=request.data.get("execution_time"), location=request.data.get("location"))
        JobRequest.objects.filter(ad=ad).exclude(pk=jr.pk).update(status=JobRequest.STATUS_REJECTED)
        return Response(AdSerializer(ad).data)

# --------------------------
# Reviews: create + detail (get/put/delete)
# --------------------------
@extend_schema(
    request=ReviewCreateSerializer,
    responses={
        201: ReviewReadSerializer,
        400: OpenApiExample("Invalid data", value={"detail": "error message"}, response_only=True)
    },
    examples=[
        OpenApiExample(
            "Create review request example",
            value={"ad": 42, "performer": 10, "text": "Great job!", "rating": 5},
            request_only=True,
        ),
        OpenApiExample(
            "Create review response example",
            value={"id": 11, "author": {"id": 7, "name": "Ali"}, "text": "Great job!", "rating": 5, "created_at": "2026-01-10T12:00:00Z"},
            response_only=True,
            status_codes=["201"]
        )
    ],
)
class ReviewCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ReviewCreateSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        ad = serializer.validated_data["ad"]
        if ad.creator.pk != request.user.pk and not (request.user.is_superuser or getattr(request.user, "role", "") == "admin"):
            return Response({"detail": "Only the ad creator can leave a review for this ad."}, status=status.HTTP_403_FORBIDDEN)
        review = serializer.save()
        return Response(ReviewReadSerializer(review).data, status=status.HTTP_201_CREATED)


@extend_schema(
    responses={
        200: ReviewSerializer,
        204: OpenApiExample("Deleted", value=None, response_only=True),
        403: OpenApiExample("Forbidden", value={"detail": "Not allowed"}, response_only=True)
    },
    examples=[
        OpenApiExample(
            "Review detail example (GET/PUT)",
            value={"id": 11, "ad": 42, "author": 7, "performer": 10, "text": "Great job!", "rating": 5, "created_at": "2026-01-10T12:00:00Z", "updated_at": "2026-01-10T12:00:00Z"},
            response_only=True,
            status_codes=["200"]
        )
    ],
)
class ReviewDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get(self, request, pk):
        r = get_object_or_404(Review, pk=pk)
        return Response(ReviewSerializer(r).data)

    def put(self, request, pk):
        r = get_object_or_404(Review, pk=pk)
        self.check_object_permissions(request, r)
        serializer = ReviewSerializer(r, data=request.data, partial=True, context={"request": request})
        if serializer.is_valid():
            serializer.save()
            return Response(ReviewSerializer(r).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        r = get_object_or_404(Review, pk=pk)
        self.check_object_permissions(request, r)
        r.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------
# Tickets: list/create/detail/update/delete + reply by support
# --------------------------
@extend_schema(
    request=TicketCreateSerializer,
    responses={
        201: TicketSerializer,
        400: OpenApiExample("Bad request", value={"detail": "error"}, response_only=True)
    },
    examples=[
        OpenApiExample(
            "Create ticket request example",
            value={"ad": 42, "subject": "Problem with job", "messages": [{"author_id": 7, "text": "Initial message", "created_at": "2026-01-10T12:00:00Z"}]},
            request_only=True
        ),
        OpenApiExample(
            "Create ticket response example",
            value={"id": 55, "creator": 7, "ad": 42, "subject": "Problem with job", "messages": [{"author_id": 7, "text": "Initial message", "created_at": "2026-01-10T12:00:00Z"}], "status": "open", "created_at": "2026-01-10T12:00:00Z"},
            response_only=True,
            status_codes=["201"]
        )
    ],
)
class TicketListCreateAPIView(APIView):
    permission_classes = [TicketPermission]

    def get(self, request):
        if request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support"):
            qs = Ticket.objects.all()
        else:
            qs = Ticket.objects.filter(creator=request.user)
        return Response(TicketSerializer(qs, many=True).data)

    def post(self, request):
        serializer = TicketCreateSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            t = serializer.save()
            return Response(TicketSerializer(t).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    responses={
        200: TicketSerializer,
        204: OpenApiExample("Deleted", value=None, response_only=True),
        403: OpenApiExample("Forbidden", value={"detail": "Not allowed"}, response_only=True)
    },
    examples=[
        OpenApiExample(
            "Ticket detail example",
            value={"id": 55, "creator": 7, "ad": 42, "subject": "Problem with job", "messages": [{"author_id":7,"text":"Initial message","created_at":"2026-01-10T12:00:00Z"}], "status": "open", "created_at": "2026-01-10T12:00:00Z"},
            response_only=True,
            status_codes=["200"]
        )
    ],
)
class TicketDetailAPIView(APIView):
    permission_classes = [TicketPermission]

    def get(self, request, pk):
        t = get_object_or_404(Ticket, pk=pk)
        self.check_object_permissions(request, t)
        return Response(TicketSerializer(t).data)

    def put(self, request, pk):
        t = get_object_or_404(Ticket, pk=pk)
        self.check_object_permissions(request, t)
        serializer = TicketSerializer(t, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(TicketSerializer(t).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        t = get_object_or_404(Ticket, pk=pk)
        self.check_object_permissions(request, t)
        t.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    request={"application/json": {"type": "object", "properties": {"text": {"type": "string"}}, "example": {"text": "We scheduled a contractor"}}},
    responses={200: OpenApiExample("Reply OK", value={"detail": "Reply added."}, response_only=True)}
)
class TicketReplyAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSupportOrAdmin]

    def post(self, request, ticket_pk):
        ticket = get_object_or_404(Ticket, pk=ticket_pk)
        text = request.data.get("text")
        if not text:
            return Response({"detail": "text required."}, status=status.HTTP_400_BAD_REQUEST)
        ticket.add_message(request.user, text)
        return Response({"detail": "Reply added."}, status=status.HTTP_200_OK)


# --------------------------
# Contractor list & profiles & filters
# --------------------------
@extend_schema(
    parameters=[
        OpenApiParameter(
            name="min_rating",
            type=OpenApiTypes.FLOAT,
            description="Filter contractors with average rating >= this value (e.g. 3.5).",
            required=False,
            location=OpenApiParameter.QUERY
        ),
        OpenApiParameter(
            name="min_reviews",
            type=OpenApiTypes.INT,
            description="Filter contractors with total reviews >= this integer (e.g. 5).",
            required=False,
            location=OpenApiParameter.QUERY
        ),
        OpenApiParameter(
            name="order_by",
            type=OpenApiTypes.STR,
            description="Order results. Options: rating_desc, rating_asc, reviews_desc, reviews_asc, rating_reviews_desc (default).",
            required=False,
            location=OpenApiParameter.QUERY
        ),
    ],
    responses={200: ContractorListItemSerializer(many=True)},
    examples=[
        OpenApiExample(
            "Query example (min_rating + order_by)",
            value=None,
            summary="Example request: /contractors/?min_rating=4.0&order_by=rating_desc",
            request_only=True
        ),
        OpenApiExample(
            "Response example (contractor list item)",
            value=[
                {
                    "id": 10,
                    "first_name": "Ahmad",
                    "last_name": "Saeed",
                    "email": "a@example.com",
                    "phone": "+123",
                    "role": "contractor",
                    "completed_count": 5,
                    "average_rating": 4.5,
                    "total_reviews": 10
                }
            ],
            response_only=True,
            status_codes=["200"]
        )
    ],
)
class ContractorListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = User.objects.filter(role="contractor").annotate(
            completed_count=Count('assigned_ads', filter=Q(assigned_ads__status=Ad.STATUS_DONE)),
            review_count=Count('reviews_received'),
            avg_rating=Avg('reviews_received__rating')
        )

        # filtering
        min_rating = request.query_params.get("min_rating")
        min_reviews = request.query_params.get("min_reviews")
        try:
            if min_rating is not None:
                mr = float(min_rating)
                qs = qs.filter(Q(avg_rating__gte=mr) | Q(average_rating__gte=mr))
            if min_reviews is not None:
                mv = int(min_reviews)
                qs = qs.filter(Q(review_count__gte=mv) | Q(total_reviews__gte=mv))
        except ValueError:
            return Response({"detail": "Invalid filter values."}, status=status.HTTP_400_BAD_REQUEST)

        order_by = request.query_params.get("order_by", "rating_reviews_desc")
        if order_by == "rating_desc":
            qs = qs.order_by(F('avg_rating').desc(nulls_last=True), F('average_rating').desc(nulls_last=True))
        elif order_by == "rating_asc":
            qs = qs.order_by(F('avg_rating').asc(nulls_last=True), F('average_rating').asc(nulls_last=True))
        elif order_by == "reviews_desc":
            qs = qs.order_by(F('review_count').desc(nulls_last=True), F('total_reviews').desc(nulls_last=True))
        elif order_by == "reviews_asc":
            qs = qs.order_by(F('review_count').asc(nulls_last=True), F('total_reviews').asc(nulls_last=True))
        else:
            qs = qs.order_by(F('avg_rating').desc(nulls_last=True), F('review_count').desc(nulls_last=True))

        result = []
        for u in qs:
            avg_val = u.avg_rating if u.avg_rating is not None else (getattr(u, "average_rating", 0.0) or 0.0)
            review_cnt = getattr(u, "review_count", None) or getattr(u, "total_reviews", 0) or 0
            completed = getattr(u, "completed_count", 0)
            result.append({
                "id": u.pk,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "email": u.email,
                "phone": u.phone,
                "role": u.role,
                "completed_count": completed,
                "average_rating": float(avg_val) or 0.0,
                "total_reviews": int(review_cnt) or 0
            })
        return Response(result)


@extend_schema(
    responses={200: ContractorProfileSerializer},
    examples=[
        OpenApiExample(
            "Contractor profile example",
            value={
                "id": 10,
                "first_name": "Ahmad",
                "last_name": "Saeed",
                "email": "a@example.com",
                "phone": "+123",
                "role": "contractor",
                "completed_count": 5,
                "average_rating": 4.5,
                "total_reviews": 10,
                "reviews": [
                    {"id": 1, "author_id": 7, "author_name": "Ali", "text": "Great!", "rating": 5, "created_at": "2026-01-10T12:00:00Z"}
                ]
            },
            response_only=True,
            status_codes=["200"]
        )
    ],
)
class ContractorProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, contractor_pk):
        contractor = get_object_or_404(User, pk=contractor_pk)
        completed_count = Ad.objects.filter(performer=contractor, status=Ad.STATUS_DONE).count()
        avg = getattr(contractor, "average_rating", None)
        total = getattr(contractor, "total_reviews", None)
        if avg is None or total is None:
            agg = Review.objects.filter(performer=contractor).aggregate(avg=Avg("rating"), cnt=Count("id"))
            avg = agg["avg"] or 0.0
            total = agg["cnt"] or 0
        contractor.completed_count = completed_count
        contractor.average_rating = float(avg)
        contractor.total_reviews = int(total)
        return Response(ContractorProfileSerializer(contractor).data)


@extend_schema(
    responses={200: CustomerProfileSerializer},
    examples=[
        OpenApiExample(
            "Customer profile example",
            value={
                "id": 7,
                "first_name": "Sara",
                "last_name": "Ahmadi",
                "email": "sara@example.com",
                "phone": "+987",
                "role": "user",
                "ads": [
                    {"id": 42, "title": "Fix leaking sink", "status": "done", "execution_time": "2026-02-10T09:00:00Z", "location": "123 Main St", "created_at": "2026-01-05T10:00:00Z"}
                ]
            },
            response_only=True,
            status_codes=["200"]
        )
    ],
)
class CustomerProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_pk):
        user = get_object_or_404(User, pk=user_pk)
        return Response(CustomerProfileSerializer(user).data)
