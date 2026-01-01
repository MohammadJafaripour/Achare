from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()

class IsAdminUserRole(permissions.BasePermission):
    """
    Allows access only to users with role == 'admin' or Django superuser.
    """
    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and (getattr(u, "role", "") == "admin" or u.is_superuser))

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Write allowed to object owner (creator) or admin; read allowed to authenticated users.
    Assumes the object has 'creator' attribute or 'author'.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        # admin can do anything
        if request.user.is_superuser or getattr(request.user, "role", "") == "admin":
            return True
        owner = getattr(obj, "creator", None) or getattr(obj, "author", None)
        return owner is not None and owner.pk == request.user.pk

class TicketPermission(permissions.BasePermission):
    """
    Rules:
    - Any authenticated user may create tickets.
    - Users can edit/delete their own tickets.
    - Support role (role=='support') or admin may read/edit/delete any ticket.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # safe methods allowed to creator and support/admin
        if request.user.is_superuser or getattr(request.user, "role", "") == "admin":
            return True
        if getattr(request.user, "role", "") == "support":
            return True
        # creator may modify own ticket
        return getattr(obj, "creator", None) and obj.creator.pk == request.user.pk

class AdPermission(permissions.BasePermission):
    """
    Rules for Ad:
    - Creator (customer) can create/edit/delete their ads.
    - Contractor cannot delete/edit ads created by other contractors (i.e. not their own).
    - Only admin can forcibly delete any ad.
    - Assignment endpoints enforce extra checks in views.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # SAFE to GET for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        # admin can do anything
        if request.user.is_superuser or getattr(request.user, "role", "") == "admin":
            return True
        # owner can modify
        if hasattr(obj, "creator") and obj.creator.pk == request.user.pk:
            return True
        # contractors cannot edit other's ads
        if getattr(request.user, "role", "") == "contractor":
            # allow if they are the creator (handled above), otherwise deny
            return False
        return False

class IsAdminOrSuper(permissions.BasePermission):
    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and (u.is_superuser or getattr(u,"role","")=="admin"))

class IsSupportOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and (u.is_superuser or getattr(u,"role","") in ("admin","support")))

class IsCreatorOrAdmin(permissions.BasePermission):
    """
    Allow write only to creator or admin; read for authenticated.
    Assumes object has .creator.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        if request.user.is_superuser or getattr(request.user,"role","")=="admin":
            return True
        return hasattr(obj, "creator") and obj.creator.pk == request.user.pk

class IsContractor(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and getattr(request.user, "role", "") == "contractor")

class IsTicketReplyAllowed(permissions.BasePermission):
    """
    Only support or admin can reply (add messages) to tickets.
    Regular users CAN create tickets but CANNOT reply (per requirement).
    """
    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and (u.is_superuser or getattr(u,"role","") in ("admin","support")))

class IsJobRequestOwnerOrAdmin(permissions.BasePermission):
    """
    - Contractor (owner) can cancel/delete their request.
    - Admin/support can manage any.
    - Customer (ad creator) CANNOT delete someone else's job requests.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or getattr(request.user,"role","") in ("admin","support"):
            return True
        # only contractor who created this request may modify/delete it
        return getattr(obj, "contractor", None) and obj.contractor.pk == request.user.pk
    

class IsAdCreator(permissions.BasePermission):
    """
    Allow action only if request.user is the ad creator or admin/superuser.
    """
    def has_object_permission(self, request, view, obj):
        # obj is Ad instance
        if request.user.is_superuser or getattr(request.user, "role", "") == "admin":
            return True
        return hasattr(obj, "creator") and obj.creator.pk == request.user.pk
    
# permissions.py (additions)

from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()

def user_has_role(user, role_name):
    """
    Helper: support both old single-field 'role' and new ManyToMany roles.
    """
    if not user or not user.is_authenticated:
        return False
    # legacy single-role field
    if hasattr(user, "role") and user.role == role_name:
        return True
    # new M2M roles
    if hasattr(user, "roles"):
        return user.roles.filter(name=role_name).exists()
    return False

class IsAdminOrRoleManager(permissions.BasePermission):
    """
    Allow only users with 'admin' role or superuser to manage roles.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and (request.user.is_superuser or user_has_role(request.user, "admin")))