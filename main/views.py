# views.py (refactored, duplicates removed)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q, Avg, F

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

# --------------------------
# Auth: registration & login
# --------------------------
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


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = request.data.get('identifier') or request.data.get('username') or request.data.get('email')
        password = request.data.get('password')
        if not identifier or not password:
            return Response({"detail": "Provide identifier and password."}, status=status.HTTP_400_BAD_REQUEST)

        # Try email, phone, username (in that order)
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
class UserDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)

    def put(self, request):
        data = request.data.copy()
        # prevent non-admin role changes
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
class AdListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = Ad.objects.all().order_by("-created_at")
        # hide cancelled ads from normal users
        if not (request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support")):
            qs = qs.exclude(status=Ad.STATUS_CANCELLED)
        return Response(AdSerializer(qs, many=True).data)

    def post(self, request):
        serializer = AdCreateSerializer(data=request.data)
        if serializer.is_valid():
            ad = serializer.save(creator=request.user)
            return Response(AdSerializer(ad).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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


class AdPerformerMarkDoneAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not ad.performer or ad.performer.pk != request.user.pk:
            return Response({"detail": "Only assigned performer can mark done."}, status=status.HTTP_403_FORBIDDEN)
        if ad.status != Ad.STATUS_ASSIGNED:
            return Response({"detail": "Ad must be ASSIGNED to mark completion."}, status=status.HTTP_400_BAD_REQUEST)
        ad.mark_performer_done()
        return Response(AdSerializer(ad).data)


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
        if not ad.performer_marked_done:
            return Response({"detail": "Performer has not declared completion yet."}, status=status.HTTP_400_BAD_REQUEST)
        ad.confirm_done()
        return Response(AdSerializer(ad).data)


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
class JobRequestCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, IsContractor]

    def post(self, request):
        serializer = JobRequestSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            jr = serializer.save()
            return Response(JobRequestSerializer(jr).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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


class AdApplicantsListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ad_pk):
        ad = get_object_or_404(Ad, pk=ad_pk)
        if not (ad.creator.pk == request.user.pk or request.user.is_superuser or getattr(request.user, "role", "") in ("admin", "support")):
            return Response({"detail": "Not allowed to view applicants."}, status=status.HTTP_403_FORBIDDEN)
        qs = ad.job_requests.all()
        return Response(JobRequestSerializer(qs, many=True).data)


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


class CustomerProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_pk):
        user = get_object_or_404(User, pk=user_pk)
        return Response(CustomerProfileSerializer(user).data)
