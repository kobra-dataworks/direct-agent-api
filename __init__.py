"""Direct Hermes API coordination and central Jarvis approval routing."""
from .tools import (
    COORDINATE_AGENT_SCHEMA,
    TEAM_APPROVAL_RESPOND_SCHEMA,
    TEAM_APPROVALS_LIST_SCHEMA,
    check_approval_router_available,
    check_available,
    coordinate_agent,
    list_team_approvals,
    respond_team_approval,
    _start_reconciler,
)


def register(ctx):
    _start_reconciler()
    ctx.register_tool(
        name="coordinate_agent",
        toolset="direct_agent_api",
        schema=COORDINATE_AGENT_SCHEMA,
        handler=coordinate_agent,
        check_fn=check_available,
    )
    ctx.register_tool(
        name="team_approvals_list",
        toolset="direct_agent_api",
        schema=TEAM_APPROVALS_LIST_SCHEMA,
        handler=list_team_approvals,
        check_fn=check_approval_router_available,
    )
    ctx.register_tool(
        name="team_approval_respond",
        toolset="direct_agent_api",
        schema=TEAM_APPROVAL_RESPOND_SCHEMA,
        handler=respond_team_approval,
        check_fn=check_approval_router_available,
    )
