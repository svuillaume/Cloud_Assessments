import os
import sys
import shutil
import threading
import time
import logging
import logzero

_FRAMES = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

_BAR_FILL  = '█'
_BAR_EMPTY = '░'
_BAR_WIDTH = 24


def _get_console_handler():
    for h in logging.getLogger().handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            return h
    return None


class Spinner:

    def __init__(self, message='Generating report'):
        self.message = message
        self._stop = threading.Event()
        self._thread = None
        self._saved_stdout = None
        self._devnull = None
        self._console_handler = None
        self._saved_handler_level = None
        # progress state — updated from the main thread
        self._pct  = 0
        self._step = message
        self._lock = threading.Lock()

    def update(self, pct: int, step: str):
        """Call from main thread to advance the progress bar."""
        with self._lock:
            self._pct  = max(0, min(100, pct))
            self._step = step

    def _render_bar(self, pct):
        filled = int(_BAR_WIDTH * pct / 100)
        bar = _BAR_FILL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)
        return f'[{bar}] {pct:3d}%'

    def _run(self):
        i = 0
        while not self._stop.is_set():
            with self._lock:
                pct  = self._pct
                step = self._step

            frame = _FRAMES[i % len(_FRAMES)]
            bar   = self._render_bar(pct)
            cols  = shutil.get_terminal_size((120, 20)).columns
            line  = f'  {frame}  {bar}  {step}   '
            if len(line) > cols:
                line = line[:cols - 3] + '   '
            sys.__stdout__.write(f'\r{line}')
            sys.__stdout__.flush()
            time.sleep(0.08)
            i += 1

    def start(self):
        self._devnull = open(os.devnull, 'w')
        self._saved_stdout = sys.stdout
        sys.stdout = self._devnull

        self._console_handler = _get_console_handler()
        if self._console_handler:
            self._saved_handler_level = self._console_handler.level
            self._console_handler.setLevel(logging.CRITICAL + 1)

        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, success=True):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

        sys.stdout = self._saved_stdout
        if self._console_handler and self._saved_handler_level is not None:
            self._console_handler.setLevel(self._saved_handler_level)
        if self._devnull:
            self._devnull.close()

        mark   = '✓' if success else '✗'
        bar    = self._render_bar(100 if success else self._pct)
        suffix = 'done!' if success else 'failed — check lw_report_gen.log for details.'
        sys.__stdout__.write(f'\r  {mark}  {bar}  {suffix}                    \n')
        sys.__stdout__.flush()
