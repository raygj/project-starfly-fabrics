# Starfly Fabrics — Management Plane Policy (ADR-0018 Hyper PAM)
#
# Execution-binding enforcement for management tool operations.
# Every admin action through management tools is verified at execution
# time, not just at session start.
#
# Override by mounting custom policies at /etc/starfly/policies/
# or configuring an OPA bundle source.

package starfly.management

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ── Mass Operations Require Multi-Person Approval ──

deny contains msg if {
    input.exec_act == "device-wipe"
    input.target_scope == "all"
    msg := "mass device wipe requires 2-person approval (structural condition: single admin can wipe everything)"
}

deny contains msg if {
    input.exec_act == "device-wipe"
    count_targets(input.target) > 100
    not input.context.approval_ticket
    msg := sprintf("device wipe affecting %d devices requires approval ticket", [count_targets(input.target)])
}

# ── Destructive Operations Require Change Ticket ──

deny contains msg if {
    destructive_operation(input.exec_act)
    not input.context.change_ticket
    msg := sprintf("destructive operation '%s' requires change ticket reference", [input.exec_act])
}

destructive_operation(op) if { op == "delete" }
destructive_operation(op) if { op == "destroy" }
destructive_operation(op) if { op == "seal" }
destructive_operation(op) if { op == "device-wipe" }
destructive_operation(op) if { op == "rotate-key" }

# ── Time-Based Restrictions ──

deny contains msg if {
    input.identity.role == "admin"
    time.hour(time.now_ns()) < 6
    not input.context.emergency_override
    msg := "admin operations restricted before 06:00 without emergency override"
}

deny contains msg if {
    input.identity.role == "admin"
    time.hour(time.now_ns()) > 22
    not input.context.emergency_override
    msg := "admin operations restricted after 22:00 without emergency override"
}

# ── Cross-Environment Restrictions ──

deny contains msg if {
    input.identity.source_environment == "staging"
    startswith(input.target, "prod")
    msg := "staging credentials cannot operate on production resources"
}

# ── Vendor / Third-Party Scoping ──

deny contains msg if {
    input.identity.type == "service-account"
    input.identity.managed_by == "third-party"
    destructive_operation(input.exec_act)
    msg := "third-party service accounts cannot perform destructive operations"
}

deny contains msg if {
    input.identity.type == "service-account"
    input.identity.managed_by == "third-party"
    not time_restricted_vendor_access(input)
    msg := "third-party access outside approved maintenance window"
}

time_restricted_vendor_access(inp) if {
    inp.context.maintenance_window == true
}

# ── Terraform Plan-Apply Binding ──

deny contains msg if {
    input.tool_id == "terraform-admin"
    input.exec_act == "apply"
    not input.context.plan_hash
    msg := "terraform apply requires a plan hash (inp_hash of the plan output)"
}

deny contains msg if {
    input.tool_id == "terraform-admin"
    input.exec_act == "apply"
    input.context.plan_hash != input.inp_hash
    msg := "terraform apply plan hash does not match — plan may have changed since approval"
}
