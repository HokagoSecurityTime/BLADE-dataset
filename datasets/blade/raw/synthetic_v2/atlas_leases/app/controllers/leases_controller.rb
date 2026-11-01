class LeasesController < ApplicationController
  # Authentication outside the actions: before_action :authenticate! (401). It performs no authorization.
  before_action :authenticate!, except: [:atlas_leases_catalogue_0, :atlas_leases_catalogue_1]
  before_action :require_admin!, only: [:atlas_leases_audit_0]

  # Intentionally anonymous reference catalogue.
  def atlas_leases_catalogue_0
    record = Record.find(params[:item_id])
    render json: record
  end

  # Intentionally anonymous reference catalogue.
  def atlas_leases_catalogue_1
    record = Record.find(params[:item_id])
    render json: record
  end

  # Only the record owner may read it.
  def atlas_leases_drafts_0
    record = current_user.records.find(params[:item_id])  # ORM scope: only the caller's own records
    render json: record
  end

  # Only the record owner may read it.
  def atlas_leases_drafts_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # The record owner or an administrator may read it.
  def atlas_leases_shared_0
    record = Record.find(params[:item_id])
    head :forbidden and return if record.owner_id != current_user.id && !current_user.admin?
    render json: record
  end

  # The record owner or an administrator may read it.
  def atlas_leases_shared_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # The record owner or an administrator may read it.
  def atlas_leases_moderation_0
    record = Record.find(params[:item_id])
    head :forbidden and return if record.owner_id != current_user.id && !current_user.admin?
    render json: record
  end

  # The record owner or an administrator may read it.
  def atlas_leases_moderation_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # Caller and record must share a tenant.
  def atlas_leases_workspace_0
    record = Record.find(params[:item_id])
    head :forbidden and return if record.tenant_id != current_user.tenant_id
    render json: record
  end

  # Caller and record must share a tenant.
  def atlas_leases_workspace_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # Only administrators may read this operational resource.
  def atlas_leases_audit_0
    record = Record.find(params[:item_id])
    render json: record
  end

  # Only administrators may read this operational resource.
  def atlas_leases_audit_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
  def atlas_leases_roster_0
    record = Record.find(params[:item_id])
    head :forbidden and return unless Membership.exists?(user_id: current_user.id, group_id: record.group_id)
    render json: record
  end

  # Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
  def atlas_leases_roster_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
  def atlas_leases_pins_0
    record = Record.find(params[:item_id])
    head :forbidden and return unless Membership.exists?(user_id: current_user.id, group_id: record.group_id)
    render json: record
  end

  # Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.
  def atlas_leases_pins_1
    record = Record.find(params[:item_id])
    # Deliberate fixture: object authorization check omitted.
    render json: record
  end

  # Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.
  def atlas_leases_council_0
    record = Record.find(params[:item_id])
    head :forbidden and return if record.tenant_id != current_user.tenant_id || !Membership.exists?(user_id: current_user.id, group_id: record.group_id)
    render json: record
  end

  # Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.
  def atlas_leases_council_1
    record = Record.find(params[:item_id])
    head :forbidden and return if record.tenant_id != current_user.tenant_id || !Membership.exists?(user_id: current_user.id, group_id: record.group_id)
    render json: record
  end

  private

  def authenticate!
    @current_user = User.find_by(token: request.headers["Authorization"].to_s.delete_prefix("Bearer "))
    head :unauthorized unless @current_user
  end

  def require_admin!
    head :forbidden unless current_user.admin?
  end

  def current_user
    @current_user
  end
end
