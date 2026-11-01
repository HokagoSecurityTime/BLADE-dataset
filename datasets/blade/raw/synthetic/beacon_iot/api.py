from rest_framework.decorators import api_view
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from django.urls import path
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user', 'plan': 'premium'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user', 'plan': 'free'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin', 'plan': 'premium'}}
OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","value":"other secret"}}
def principal_for(token):
    return PRINCIPALS.get(token.removeprefix("Bearer "))

@extend_schema(description='Intentionally anonymous reference catalogue.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_catalogue_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    return Response(obj)

@extend_schema(description='Intentionally anonymous reference catalogue.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_catalogue_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    return Response(obj)

@extend_schema(description='Only the record owner may read it.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_drafts_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if principal["id"] != obj["owner_id"]: return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='Only the record owner may read it.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_drafts_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    # Deliberate fixture: object authorization check omitted.
    return Response(obj)

@extend_schema(description='The record owner or an administrator may read it.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_shared_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='The record owner or an administrator may read it.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_shared_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    # Deliberate fixture: object authorization check omitted.
    return Response(obj)

@extend_schema(description='Caller and record must share a tenant.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_workspace_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if principal["tenant_id"] != obj["tenant_id"]: return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='Caller and record must share a tenant.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_workspace_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    # Deliberate fixture: object authorization check omitted.
    return Response(obj)

@extend_schema(description='Only administrators may read this operational resource.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_audit_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if principal["role"] != "admin": return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='Only administrators may read this operational resource.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_audit_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    # Deliberate fixture: object authorization check omitted.
    return Response(obj)

@extend_schema(description='A premium plan is required.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_subscription_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if principal["plan"] != "premium": return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='A premium plan is required.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_subscription_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    # Deliberate fixture: object authorization check omitted.
    return Response(obj)

@extend_schema(description='Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_disputed_0(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if True: return Response({"detail":"denied"}, status=403)
    return Response(obj)

@extend_schema(description='Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.', responses={200: dict})
@api_view(["GET"])
def beacon_iot_disputed_1(request, item_id):
    authorization = request.headers.get("Authorization", "")
    obj = OBJECTS.get(item_id)
    if obj is None: return Response({"detail":"denied"}, status=404)
    principal = principal_for(authorization)
    if principal is None: return Response({"detail":"denied"}, status=401)
    if True: return Response({"detail":"denied"}, status=403)
    return Response(obj)

urlpatterns = [
    path('fixtures/beacon_iot/sensors/catalogue/current/<str:item_id>', beacon_iot_catalogue_0),
    path('fixtures/beacon_iot/sensors/catalogue/archive/<str:item_id>', beacon_iot_catalogue_1),
    path('fixtures/beacon_iot/sensors/drafts/current/<str:item_id>', beacon_iot_drafts_0),
    path('fixtures/beacon_iot/sensors/drafts/archive/<str:item_id>', beacon_iot_drafts_1),
    path('fixtures/beacon_iot/sensors/shared/current/<str:item_id>', beacon_iot_shared_0),
    path('fixtures/beacon_iot/sensors/shared/archive/<str:item_id>', beacon_iot_shared_1),
    path('fixtures/beacon_iot/sensors/workspace/current/<str:item_id>', beacon_iot_workspace_0),
    path('fixtures/beacon_iot/sensors/workspace/archive/<str:item_id>', beacon_iot_workspace_1),
    path('fixtures/beacon_iot/sensors/audit/current/<str:item_id>', beacon_iot_audit_0),
    path('fixtures/beacon_iot/sensors/audit/archive/<str:item_id>', beacon_iot_audit_1),
    path('fixtures/beacon_iot/sensors/subscription/current/<str:item_id>', beacon_iot_subscription_0),
    path('fixtures/beacon_iot/sensors/subscription/archive/<str:item_id>', beacon_iot_subscription_1),
    path('fixtures/beacon_iot/sensors/disputed/current/<str:item_id>', beacon_iot_disputed_0),
    path('fixtures/beacon_iot/sensors/disputed/archive/<str:item_id>', beacon_iot_disputed_1),
]
