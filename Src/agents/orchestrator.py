# Src/agents/orchestrator.py
import logging
from typing import TypedDict, Dict, Any
from langgraph.graph import StateGraph, END

from Src.agents import code_diffanalyzer, readme_updater, commiter

# Logging setup
logger = logging.getLogger("Orchestrator")
logging.basicConfig(level=logging.INFO)


# -------------------
# Define Shared State
# -------------------
class State(TypedDict, total=False):
    diffs: Dict[str, str]       # file → patch
    owner: str
    repo: str
    pr_number: int
    analysis: Dict[str, Any]
    readme_snippet: str
    pr_result: Dict[str, Any]


# -------------------
# Define Node Handlers
# -------------------
def node_analyze(state: State) -> State:
    """
    Analyzer agent node.
    Takes raw git diffs and produces structured analysis.
    """
    logger.info("🔍 Analyzer Agent: analyzing diffs...")
    diffs = state.get("diffs", {})
    state = {"diffs": {"utils.py": "+++ def greet(name): ..."}}
    analysis = code_diffanalyzer.analyze_diffs(state["diffs"])
    print(analysis)

    analysis = code_diffanalyzer.analyze_diffs(diffs)
    logger.info("Analyzer output: %s", analysis)
    return {**state, "analysis": analysis}


def node_write(state: State) -> State:
    """
    Writer agent node.
    Generates README snippet using structured prompts & LLM.
    """
    logger.info("✍️ Writer Agent: generating README snippet...")
    owner = state.get("owner")
    repo = state.get("repo")
    pr_number = state.get("pr_number", 0)

    snippet = readme_updater.generate_readme_snippet(
        owner, repo, pr_number, state.get("analysis", {})
    )
    logger.info("Writer output snippet:\n%s", snippet)
    return {**state, "readme_snippet": snippet}


def node_commit(state: State) -> State:
    """
    Committer agent node.
    Creates PR or commit with generated README snippet.
    """
    logger.info("📤 Committer Agent: creating PR with README changes...")
    owner = state.get("owner")
    repo = state.get("repo")
    pr_number = state.get("pr_number", 0)
    snippet = state.get("readme_snippet", "")

    if not snippet:
        logger.warning("⚠️ No README snippet found. Skipping commit.")
        return {**state, "pr_result": {"skipped": True}}

    result = commiter.create_readme_pr(owner, repo, pr_number, snippet)
    logger.info("Committer output: %s", result)
    return {**state, "pr_result": result}


# -------------------
# Build LangGraph
# -------------------
graph = StateGraph(State)

# Add nodes (agents)
graph.add_node("analyze", node_analyze)
graph.add_node("write", node_write)
graph.add_node("commit", node_commit)

# Set flow
graph.set_entry_point("analyze")
graph.add_edge("analyze", "write")
graph.add_edge("write", "commit")
graph.add_edge("commit", END)

# Compile the graph into an executable agent
agent = graph.compile()


# -------------------
# Run Function
# -------------------
def run_flow(state: State) -> State:
    """
    Orchestrates execution via LangGraph.
    Input: dict with diffs, owner, repo, pr_number, etc.
    Returns: dict with analysis, readme_snippet, and pr_result.
    """
    logger.info("🚀 Orchestrator: running multi-agent LangGraph pipeline")
    result = agent.invoke(state)
    logger.info("✅ Flow complete.")
    return result


mermaid_code = agent.get_graph().draw_mermaid()
print("Mermaid graph:\n", mermaid_code)