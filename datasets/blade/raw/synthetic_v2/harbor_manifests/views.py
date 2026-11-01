from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.exceptions import PermissionDenied
from .models import Record, Membership

# Authentication: DRF TokenAuthentication in settings; @permission_classes([IsAuthenticated]) rejects anonymous callers (401).
# IsAdminUser requires request.user.is_staff. Group membership is a Membership(user, group_id) row.

@api_view(["GET"])
@permission_classes([AllowAny])
def harbor_manifests_catalogue_0(request, item_id):
    """Intentionally anonymous reference catalogue."""
    obj = get_object_or_404(Record, pk=item_id)
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([AllowAny])
def harbor_manifests_catalogue_1(request, item_id):
    """Intentionally anonymous reference catalogue."""
    obj = get_object_or_404(Record, pk=item_id)
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_drafts_0(request, item_id):
    """Only the record owner may read it."""
    obj = get_object_or_404(Record.objects.filter(owner=request.user), pk=item_id)  # ORM filter: owner only
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_drafts_1(request, item_id):
    """Only the record owner may read it."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_shared_0(request, item_id):
    """The record owner or an administrator may read it."""
    obj = get_object_or_404(Record, pk=item_id)
    if obj.owner_id != request.user.id and not request.user.is_staff: raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_shared_1(request, item_id):
    """The record owner or an administrator may read it."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_moderation_0(request, item_id):
    """The record owner or an administrator may read it."""
    obj = get_object_or_404(Record, pk=item_id)
    if obj.owner_id != request.user.id and not request.user.is_staff: raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_moderation_1(request, item_id):
    """The record owner or an administrator may read it."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_workspace_0(request, item_id):
    """Caller and record must share a tenant."""
    obj = get_object_or_404(Record, pk=item_id)
    if obj.tenant_id != request.user.profile.tenant_id: raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_workspace_1(request, item_id):
    """Caller and record must share a tenant."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAdminUser])
def harbor_manifests_audit_0(request, item_id):
    """Only administrators may read this operational resource."""
    obj = get_object_or_404(Record, pk=item_id)
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_audit_1(request, item_id):
    """Only administrators may read this operational resource."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_roster_0(request, item_id):
    """Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked."""
    obj = get_object_or_404(Record, pk=item_id)
    if not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_roster_1(request, item_id):
    """Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_pins_0(request, item_id):
    """Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked."""
    obj = get_object_or_404(Record, pk=item_id)
    if not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_pins_1(request, item_id):
    """Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked."""
    obj = get_object_or_404(Record, pk=item_id)
    # Deliberate fixture: object authorization check omitted.
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_council_0(request, item_id):
    """Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review."""
    obj = get_object_or_404(Record, pk=item_id)
    if obj.tenant_id != request.user.profile.tenant_id or not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def harbor_manifests_council_1(request, item_id):
    """Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review."""
    obj = get_object_or_404(Record, pk=item_id)
    if obj.tenant_id != request.user.profile.tenant_id or not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()
    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})

