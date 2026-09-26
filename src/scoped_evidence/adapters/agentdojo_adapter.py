"""AgentDojo -> headroom TaskRecords.  STATUS: DRAFT, NOT_RUN.

No approved local copy of AgentDojo exists in this environment, so this file
has never been executed. The API names below are ASSUMPTIONS written from
memory of the public project and must be checked against the pinned source
before the first run:

  A-DJ1  agentdojo.task_suite.load_suites.get_suites(benchmark_version)
         -> dict[str, TaskSuite]
  A-DJ2  TaskSuite.user_tasks / .injection_tasks : dict[str, task]
  A-DJ3  task.PROMPT (user tasks), task.GOAL (injection tasks)
  A-DJ4  task.ground_truth(pre_environment) -> list[FunctionCall] with
         .function (str) and .args (dict)
  A-DJ5  user_task.utility(model_output, pre_environment, post_environment,
         strict=True) -> bool ; injection_task.security(model_output,
         pre_environment, post_environment) -> bool (True = attack achieved)
  A-DJ6  TaskSuite.load_and_inject_default_environment(injections)
  A-DJ7  a functions runtime that executes a FunctionCall on an environment
         and returns the (typed, pydantic) result

Protocol decisions fixed in configs/headroom_r.json (not here):
  * fixed plan         = the task's benign ground-truth call sequence;
  * state-changing set = WRITE_TOOLS allow-list, reviewed against the pinned
                         source before running;
  * fixed contract     = for each state-changing argument, the (tool, field
                         path) of the read output in which its benign gold
                         value appears (derived once from the benign
                         ground truth and reused unchanged for every variant);
  * rule               = unique-or-abstain over the admitted candidates;
  * success            = benchmark utility() and, for injection variants,
                         not security(), evaluated on the post-environment
                         after executing the fixed plan with the assignment.
                         Our string labels are never used for success.
  * tasks whose benign gold plan does not pass utility() with an empty model
    output are UNRESOLVED("utility_depends_on_model_output").
"""

from __future__ import annotations

from . import SourceNotAvailable


def load_records(version: str, write_tools: dict[str, list[str]]):  # pragma: no cover - NOT_RUN
    try:
        from agentdojo.task_suite.load_suites import get_suites  # type: ignore  # A-DJ1
    except Exception as e:  # ImportError or API drift
        raise SourceNotAvailable(f"agentdojo not importable ({type(e).__name__}: {e})") from e
    raise NotImplementedError(
        "Adapter body intentionally not written against an unverified API. "
        "After approval: pin the version, verify A-DJ1..A-DJ7, then implement "
        "flatten(read outputs) -> CandidateRecord and success() per the docstring."
    )
