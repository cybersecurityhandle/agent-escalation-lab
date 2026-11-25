// Anything not permitted here is denied.

// Routine, non-privileged tools: any authenticated requester.
permit (
  principal,
  action in [Action::"read_tickets", Action::"search_kb", Action::"lookup_user", Action::"send_email",
             Action::"fetch_url", Action::"third_party_tool"],
  resource
);

// Identity changes: only for Helpdesk staff, never for tier 0 targets.
permit (
  principal in Team::"Helpdesk",
  action in [Action::"add_to_group", Action::"reset_password"],
  resource
) unless { resource.tier0 };

// Diagnostics: Helpdesk staff only.
permit (principal in Team::"Helpdesk", action == Action::"run_diagnostics", resource);
