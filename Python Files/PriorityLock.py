import threading


class PriorityLock:
    def __init__(self):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._a_waiting = False
        self._b_waiting = False
        self._in_use = False

    def acquire(self, thread_type):
        with self._cond:
            if thread_type == 'A':
                self._a_waiting = True
                while self._in_use:
                    self._cond.wait()
                self._a_waiting = False
            elif thread_type == 'B':
                self._b_waiting = True
                while self._in_use or self._a_waiting:
                    self._cond.wait()
                self._b_waiting = False
            self._in_use = True

    def release(self):
        with self._cond:
            self._in_use = False
            self._cond.notify_all()
