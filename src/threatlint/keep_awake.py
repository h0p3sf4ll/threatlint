"""Keep a Mac from idle-sleeping while a headless AVIT run works.

Idle sleep freezes reviews and ServiceNow or Semgrep writes mid-flight. ``caffeinate -i`` blocks only idle sleep
(closing the lid still sleeps the Mac), and ``-w <pid>`` ends it automatically if Threatlint exits. Off when
THREATLINT_KEEP_AWAKE=0, on other platforms, and under pytest. Matches web/lib/keep-awake.cjs.
"""

from __future__ import annotations

import os
import subprocess
import sys
from contextlib import contextmanager

CAFFEINATE = "/usr/bin/caffeinate"


@contextmanager
def keep_awake(*, platform: str = sys.platform, env=None, popen=subprocess.Popen, exists=os.path.exists):
    env = os.environ if env is None else env
    process = None
    if platform == "darwin" and env.get("THREATLINT_KEEP_AWAKE") != "0" and not env.get("PYTEST_CURRENT_TEST") and exists(CAFFEINATE):
        try:
            process = popen([CAFFEINATE, "-i", "-w", str(os.getpid())], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            process = None
    try:
        yield process
    finally:
        if process is not None:
            try:
                process.terminate()
            except OSError:
                pass  # caffeinate also exits with this process (-w).
