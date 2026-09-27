DEVELOPMENT smoke run (not the census; not used for any reported number).
Subset: banking/user_task_0, slack/user_task_5, workspace/user_task_35 (resolver
development tasks) and banking/user_task_15 (mutation-test task).
Purpose: code-path and cost check of scripts/run_contract_v2_census.py.
Finding: number extraction dropped sentence-final numbers ("rent is 2200.");
fixed in agentdojo_contract_v2.RX before the census (regression test
tests/test_contract_v2.py::TestNumberExtraction). The resolver, caps and
decision rule were not changed after this run.
Cost: 54.5 s wall, 86.8 CPU-s (2 worker processes, 1 thread each).
