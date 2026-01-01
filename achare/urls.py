# urls.py
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

from main import views
from django.contrib import admin



urlpatterns = [

    # project-level urls.py (or app urls to include)
    # admin
    # 1234
    path('admin/', admin.site.urls),
    # ... your other includes
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),                    # JSON schema
    path("api/schema/swagger-ui/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),  # Swagger UI
    path("api/schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),              # Redoc (optional)


    # Auth
    path("auth/register/", views.RegisterAPIView.as_view(), name="auth-register"),                # POST
    path("auth/login/", views.LoginAPIView.as_view(), name="auth-login"),                         # POST
    path("auth/me/", views.UserDetailAPIView.as_view(), name="auth-me"),                          # GET, PUT

    # Ads (list/create + detail + assignment/status)
    path("ads/", views.AdListCreateAPIView.as_view(), name="ads-list-create"),                    # GET, POST
    path("ads/<int:ad_pk>/", views.AdDetailAPIView.as_view(), name="ads-detail"),                    # GET, PUT, DELETE
    #path("ads/<int:pk>/assign/", views.AdAssignAPIView.as_view(), name="ads-assign"),             # POST
    path("ads/<int:ad_pk>/performer-mark-done/", views.AdPerformerMarkDoneAPIView.as_view(), name="ads-performer-mark-done"),  # POST
    path("ads/<int:ad_pk>/creator-confirm-done/", views.AdCreatorConfirmDoneAPIView.as_view(), name="ads-creator-confirm-done"),# POST
    path("ads/<int:ad_pk>/cancel/", views.AdCancelAPIView.as_view(), name="ads-cancel"),          # POST

    # Applicants / JobRequests
    path("job-requests/", views.JobRequestCreateAPIView.as_view(), name="jobrequest-create"),     # POST
    path("job-requests/<int:pk>/cancel/", views.JobRequestCancelAPIView.as_view(), name="jobrequest-cancel"), # POST
    path("job-requests/<int:pk>/", views.JobRequestDeleteAPIView.as_view(), name="jobrequest-delete"),         # DELETE

    # Ad applicants & accept
    path("ads/<int:ad_pk>/applicants/", views.AdApplicantsListAPIView.as_view(), name="ads-applicants"), # GET
    path("ads/<int:ad_pk>/accept/", views.AdAcceptApplicantAPIView.as_view(), name="ads-accept-applicant"), # POST

    # Reviews
    path("reviews/", views.ReviewCreateAPIView.as_view(), name="reviews-create"),                 # POST
    path("reviews/<int:pk>/", views.ReviewDetailAPIView.as_view(), name="reviews-detail"),        # GET, PUT, DELETE

    # Tickets
    path("tickets/", views.TicketListCreateAPIView.as_view(), name="tickets-list-create"),        # GET, POST
    path("tickets/<int:pk>/", views.TicketDetailAPIView.as_view(), name="tickets-detail"),        # GET, PUT, DELETE
    path("tickets/<int:ticket_pk>/reply/", views.TicketReplyAPIView.as_view(), name="tickets-reply"), # POST (support only)

    # Contractors: list, profile & filters
    path("contractors/", views.ContractorListAPIView.as_view(), name="contractors-list"),         # GET (filters / ordering via query params)
    path("contractors/<int:contractor_pk>/profile/", views.ContractorProfileAPIView.as_view(), name="contractors-profile"), # GET

    # Customer profile
    path("profiles/customer/<int:user_pk>/", views.CustomerProfileAPIView.as_view(), name="customer-profile"), # GET
]
