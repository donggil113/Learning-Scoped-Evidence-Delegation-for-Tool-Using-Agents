"""Import AgentDojo's task suites and evaluators WITHOUT any LLM client SDK.

``agentdojo/agent_pipeline/__init__.py`` imports every LLM client (openai,
anthropic, cohere, google-genai, ...). The evaluation path we use
(task_suite, base_tasks, functions_runtime, agent_pipeline.errors,
agent_pipeline.ground_truth_pipeline, agent_pipeline.tool_execution) does not
call any of them. The only symbol it needs from an LLM module is the constant
``EMPTY_FUNCTION_NAME`` in ``agent_pipeline/llms/google_llm.py``.

This shim therefore
  1. registers ``agentdojo.agent_pipeline`` and ``agentdojo.agent_pipeline.llms``
     as namespace placeholders pointing at the real directories, so their
     submodules import normally but the SDK-importing ``__init__`` files are
     skipped;
  2. registers a stub ``agentdojo.agent_pipeline.llms.google_llm`` whose
     ``EMPTY_FUNCTION_NAME`` is read from the real source file's AST (not
     copied by hand).
No AgentDojo evaluator code (utility/security) is modified or replaced.
Must be called before importing ``agentdojo.task_suite``.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import importlib.util
import sys
import types
from pathlib import Path

PINNED_VERSION = "0.1.35"
PINNED_WHEEL_SHA256 = "364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd"


def _pkg_dir() -> Path:
    spec = importlib.util.find_spec("agentdojo")
    if spec is None or not spec.submodule_search_locations:
        raise ImportError("agentdojo is not installed in this interpreter")
    return Path(list(spec.submodule_search_locations)[0])


def install() -> dict:
    root = _pkg_dir()
    ap_dir = root / "agent_pipeline"
    llm_dir = ap_dir / "llms"
    for name, path in (("agentdojo.agent_pipeline", ap_dir), ("agentdojo.agent_pipeline.llms", llm_dir)):
        if name not in sys.modules:
            m = types.ModuleType(name)
            m.__path__ = [str(path)]  # type: ignore[attr-defined]
            m.__package__ = name
            sys.modules[name] = m
    src = (llm_dir / "google_llm.py").read_text()
    value = None
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "EMPTY_FUNCTION_NAME" for t in node.targets):
            value = ast.literal_eval(node.value)
    if value is None:
        raise ImportError("EMPTY_FUNCTION_NAME not found in google_llm.py; shim assumptions broken")
    stub = types.ModuleType("agentdojo.agent_pipeline.llms.google_llm")
    stub.EMPTY_FUNCTION_NAME = value  # type: ignore[attr-defined]
    sys.modules.setdefault("agentdojo.agent_pipeline.llms.google_llm", stub)
    version = importlib.metadata.version("agentdojo")
    return {"agentdojo_version": version, "package_dir": str(root), "EMPTY_FUNCTION_NAME": value,
            "version_matches_pin": version == PINNED_VERSION}


def load_suites(benchmark_version: str):
    info = install()
    ts = importlib.import_module("agentdojo.task_suite.load_suites")
    return ts.get_suites(benchmark_version), info


def available_benchmark_versions() -> list[str]:
    install()
    ts = importlib.import_module("agentdojo.task_suite.load_suites")
    reg = getattr(ts, "_SUITES", None)
    return sorted(reg) if isinstance(reg, dict) else []




def direct_attack(suite):
    """AgentDojo's own DirectAttack ("TODO: {goal}") bound to a dummy target;
    only its injection-candidate discovery and template are used."""
    install()
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.attacks.baseline_attacks import DirectAttack

    return DirectAttack(suite, GroundTruthPipeline(None))
