import os

collect_ignore_glob = [] if os.environ.get("RUN_LIVE_AGENT_SPECS") == "1" else ["live_spec.py"]
