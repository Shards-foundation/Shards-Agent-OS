"""Single-host polling worker. Uses the kernel's governed invocation path."""
from __future__ import annotations

import math
import signal
import time
from pathlib import Path
from threading import Event
from typing import Callable

from .interrupts import control_state
from .scheduler import run_once


def serve(db_path: str | Path, *, poll_s: float = 1.0, timeout_s: float = 30.0,
          max_running: int = 1, stop: Event | None = None,
          sleep: Callable[[float], None] = time.sleep,
          runner=None, max_ticks: int | None = None) -> int:
    """Process due jobs while unhalted; no daemonisation or auto-retry.

    SIGINT/SIGTERM are cooperative: a running operator call may outlive us.
    """
    if type(poll_s) not in (float, int) or not math.isfinite(poll_s) or not 0.05 <= poll_s <= 60:
        raise ValueError('poll_s must be finite and between 0.05 and 60 seconds')
    if max_ticks is not None and (type(max_ticks) is not int or max_ticks < 0):
        raise ValueError('max_ticks must be non-negative')
    flag = stop if stop is not None else Event()
    if stop is None:
        def handle_signal(_signum, _frame):
            flag.set()
        try:
            signal.signal(signal.SIGTERM, handle_signal)
            signal.signal(signal.SIGINT, handle_signal)
        except ValueError:
            # Signal installation is only permitted from the main thread.
            pass
    ticks = 0
    while not flag.is_set():
        if control_state(db_path)['halted']:
            break
        kwargs = {'timeout_s': timeout_s, 'max_running': max_running}
        if runner is not None:
            kwargs['runner'] = runner
        result = run_once(db_path, **kwargs)
        ticks += 1
        if max_ticks is not None and ticks >= max_ticks:
            break
        if result is None:
            sleep(poll_s)
    return ticks
