from django.urls import path
from . import views
urlpatterns = [
    path('fixtures/harbor_manifests/manifests/catalogue/current/<str:item_id>', views.harbor_manifests_catalogue_0),
    path('fixtures/harbor_manifests/manifests/catalogue/archive/<str:item_id>', views.harbor_manifests_catalogue_1),
    path('fixtures/harbor_manifests/manifests/drafts/current/<str:item_id>', views.harbor_manifests_drafts_0),
    path('fixtures/harbor_manifests/manifests/drafts/archive/<str:item_id>', views.harbor_manifests_drafts_1),
    path('fixtures/harbor_manifests/manifests/shared/current/<str:item_id>', views.harbor_manifests_shared_0),
    path('fixtures/harbor_manifests/manifests/shared/archive/<str:item_id>', views.harbor_manifests_shared_1),
    path('fixtures/harbor_manifests/manifests/moderation/current/<str:item_id>', views.harbor_manifests_moderation_0),
    path('fixtures/harbor_manifests/manifests/moderation/archive/<str:item_id>', views.harbor_manifests_moderation_1),
    path('fixtures/harbor_manifests/manifests/workspace/current/<str:item_id>', views.harbor_manifests_workspace_0),
    path('fixtures/harbor_manifests/manifests/workspace/archive/<str:item_id>', views.harbor_manifests_workspace_1),
    path('fixtures/harbor_manifests/manifests/audit/current/<str:item_id>', views.harbor_manifests_audit_0),
    path('fixtures/harbor_manifests/manifests/audit/archive/<str:item_id>', views.harbor_manifests_audit_1),
    path('fixtures/harbor_manifests/manifests/roster/current/<str:item_id>', views.harbor_manifests_roster_0),
    path('fixtures/harbor_manifests/manifests/roster/archive/<str:item_id>', views.harbor_manifests_roster_1),
    path('fixtures/harbor_manifests/manifests/pins/current/<str:item_id>', views.harbor_manifests_pins_0),
    path('fixtures/harbor_manifests/manifests/pins/archive/<str:item_id>', views.harbor_manifests_pins_1),
    path('fixtures/harbor_manifests/manifests/council/current/<str:item_id>', views.harbor_manifests_council_0),
    path('fixtures/harbor_manifests/manifests/council/archive/<str:item_id>', views.harbor_manifests_council_1),
]
