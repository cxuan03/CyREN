"""
The CyREN multi-agent pipeline, orchestrated with LangGraph.

Flow:

    ELK event
        |
        v
    [triage] --low--> [response] --> END     (log only, skip investigation)
        |
        | (high | uncertain)
        v
    [investigation]
        |
        v
    [correlation]
        |
        v
    [response] --> END

Usage:
    from app.agents.pipeline import run_pipeline
    final_state = run_pipeline(event_dict)
"""
from app.agents.state import AgentState
from app.agents.triage import triage_node
from app.agents.investigation import investigation_node
from app.agents.correlation import correlation_node
from app.agents.response import response_node

try:
    from langgraph.graph import StateGraph, END
    _HAS_LANGGRAPH = True
except ImportError:
    _HAS_LANGGRAPH = False


def enrich_node(state: AgentState) -> AgentState:
    """
    Run threat-intel / asset / vulnerability enrichment first, so Triage can use
    asset criticality and source reputation when it sets the risk tier, and so
    Investigation has the full context for the LLM. Enrichment must never break
    the pipeline, so failures fall through silently.
    """
    try:
        from app.enrichment import enrich_event
        return enrich_event(state)
    except Exception as exc:
        print(f"[pipeline] enrichment skipped: {exc}")
        return state


def _route_after_triage(state: AgentState) -> str:
    """Low-risk events skip investigation and correlation."""
    return "response" if state.get("risk") == "low" else "investigation"


def _build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("enrich", enrich_node)
    graph.add_node("triage", triage_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("response", response_node)

    graph.set_entry_point("enrich")
    graph.add_edge("enrich", "triage")
    graph.add_conditional_edges("triage", _route_after_triage,
                                {"investigation": "investigation", "response": "response"})
    graph.add_edge("investigation", "correlation")
    graph.add_edge("correlation", "response")
    graph.add_edge("response", END)
    return graph.compile()


_compiled = _build_graph() if _HAS_LANGGRAPH else None


def run_pipeline(event: dict) -> AgentState:
    """
    Run one event through the full pipeline and return the final state.

    `event` should contain at least: source_ip, dest_ip, rule, log_count, raw_logs
    """
    state: AgentState = dict(event)   # type: ignore

    if _compiled is not None:
        return _compiled.invoke(state)

    # Fallback if LangGraph is not installed: run the nodes in sequence.
    state = enrich_node(state)
    state = triage_node(state)
    if state.get("risk") != "low":
        state = investigation_node(state)
        state = correlation_node(state)
    state = response_node(state)
    return state
