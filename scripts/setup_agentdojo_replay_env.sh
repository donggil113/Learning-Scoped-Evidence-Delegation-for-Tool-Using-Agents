#!/usr/bin/env bash
# Recreate the offline-replay environment used for SED-E2-ADJ-* runs.
# Installs the pinned agentdojo wheel WITHOUT its LLM-client dependencies
# (anthropic, openai, cohere, google-genai, langchain are NOT installed) plus
# the minimal pure-Python packages the evaluator path imports.
# Usage: scripts/setup_agentdojo_replay_env.sh <venv_dir> <download_dir>
set -euo pipefail
VENV=${1:?venv dir}; DL=${2:?download dir}
mkdir -p "$DL"
python3 -m pip download agentdojo==0.1.35 --no-deps -d "$DL"
echo "364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd  $DL/agentdojo-0.1.35-py3-none-any.whl" | sha256sum -c -
uv venv "$VENV" --python /usr/bin/python3.11
uv pip install --python "$VENV/bin/python" --no-deps "$DL/agentdojo-0.1.35-py3-none-any.whl"
uv pip install --python "$VENV/bin/python" \
  annotated-types==0.8.0 cachebox==5.2.3 deepdiff==9.1.0 dnspython==2.8.0 docstring-parser==0.18.0 \
  email-validator==2.3.0 idna==3.20 markdown-it-py==4.2.0 mdurl==0.1.2 orderly-set==5.5.0 \
  pydantic==2.13.5 pydantic-core==2.46.5 pygments==2.21.0 pyyaml==6.0.3 rich==15.0.0 \
  typing-extensions==4.16.0 typing-inspection==0.4.4
