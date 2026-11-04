"""LDW Commander: bounded normal-user OS process-group / Windows Job canary.

A disposable development proof ONLY. No Administrator/root, arbitrary command,
remote listener, Host Agent install, secret access or security sandbox.
Windows: Job Object with KILL_ON_JOB_CLOSE (assignment before worker starts its
child). POSIX: fresh process group with fixed worker that reaps its child.
The status QUARANTINED never claims that unverified cleanup succeeded.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from threading import RLock

# Fixed source, not caller-provided code or a shell command. The marker contains
# only the PID of a disposable child in a private temporary test directory.
_CANARY_SCRIPT = r'''
import os,signal,subprocess,sys,time
if sys.stdin.buffer.readline() != b"START\n":
    sys.exit(17)
child = subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(40)"],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
with open(sys.argv[1],"x",encoding="ascii") as stream:
    stream.write(str(child.pid))
def finish(signum,frame):
    try:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=2)
    except (OSError,subprocess.TimeoutExpired):
        try:
            child.kill();child.wait(timeout=2)
        except (OSError,subprocess.TimeoutExpired):
            pass
    sys.exit(0)
if os.name == "posix":
    signal.signal(signal.SIGTERM,finish)
while True:
    time.sleep(.15)
'''


class ContainmentRefused(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


if os.name == "nt":
    class _JobBasicLimits(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit",ctypes.c_longlong),
                    ("PerJobUserTimeLimit",ctypes.c_longlong),
                    ("LimitFlags",wintypes.DWORD),
                    ("MinimumWorkingSetSize",ctypes.c_size_t),
                    ("MaximumWorkingSetSize",ctypes.c_size_t),
                    ("ActiveProcessLimit",wintypes.DWORD),
                    ("Affinity",ctypes.c_size_t),
                    ("PriorityClass",wintypes.DWORD),
                    ("SchedulingClass",wintypes.DWORD)]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(x,ctypes.c_ulonglong) for x in (
            "ReadOperationCount","WriteOperationCount","OtherOperationCount",
            "ReadTransferCount","WriteTransferCount","OtherTransferCount")]

    class _JobExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation",_JobBasicLimits),
                    ("IoInfo",_IoCounters),
                    ("ProcessMemoryLimit",ctypes.c_size_t),
                    ("JobMemoryLimit",ctypes.c_size_t),
                    ("PeakProcessMemoryUsed",ctypes.c_size_t),
                    ("PeakJobMemoryUsed",ctypes.c_size_t)]

    class _JobAccounting(ctypes.Structure):
        _fields_ = [(x,ctypes.c_longlong) for x in (
            "TotalUserTime","TotalKernelTime","ThisPeriodTotalUserTime",
            "ThisPeriodKernelTime")]+[(x,wintypes.DWORD) for x in (
            "TotalPageFaultCount","TotalProcesses","ActiveProcesses",
            "TotalTerminatedProcesses")]

    class _WindowsJob:
        def __init__(self):
            k32 = ctypes.WinDLL("kernel32",use_last_error=True)
            self._k32 = k32
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p,wintypes.LPCWSTR]
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.SetInformationJobObject.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
            k32.SetInformationJobObject.restype = wintypes.BOOL
            k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE,wintypes.HANDLE]
            k32.AssignProcessToJobObject.restype = wintypes.BOOL
            k32.TerminateJobObject.argtypes = [wintypes.HANDLE,wintypes.UINT]
            k32.TerminateJobObject.restype = wintypes.BOOL
            k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p]
            k32.QueryInformationJobObject.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL
            self._handle = k32.CreateJobObjectW(None,None)
            if not self._handle:
                raise ContainmentRefused("WINDOWS_JOB_UNAVAILABLE")
            settings = _JobExtendedLimits()
            settings.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            if not k32.SetInformationJobObject(self._handle,9,ctypes.byref(settings),ctypes.sizeof(settings)):
                self.close()
                raise ContainmentRefused("WINDOWS_JOB_POLICY_UNAVAILABLE")

        def assign(self, proc):
            if not self._k32.AssignProcessToJobObject(self._handle,wintypes.HANDLE(proc._handle)):
                raise ContainmentRefused("WINDOWS_JOB_ASSIGNMENT_UNAVAILABLE")

        def terminate(self):
            if not self._k32.TerminateJobObject(self._handle,0):
                raise ContainmentRefused("WINDOWS_JOB_TERMINATION_UNVERIFIED")

        def active_count(self):
            state = _JobAccounting()
            if not self._k32.QueryInformationJobObject(self._handle,1,ctypes.byref(state),ctypes.sizeof(state),None):
                raise ContainmentRefused("WINDOWS_JOB_READBACK_UNAVAILABLE")
            return state.ActiveProcesses

        def close(self):
            if self._handle:
                self._k32.CloseHandle(self._handle)
                self._handle = None


class FixedProcessCanary:
    """One local canary and child, never a caller-supplied command."""
    def __init__(self, *, duration_seconds=5, clock=time.monotonic):
        if isinstance(duration_seconds,bool) or not isinstance(duration_seconds,(int,float)) or not 0 < duration_seconds <= 10:
            raise ContainmentRefused("INVALID_DURATION")
        self._clock = clock
        self._duration = duration_seconds
        self._started = None
        self._proc = None
        self._job = None
        self._fixture = None
        self._child_pid = None
        self._state = "NEW"
        self._lock = RLock()

    def status(self):
        with self._lock:
            return {"state":self._state,"privileged":False,
                    "arbitrary_commands":False,"host_service_installed":False}

    def start(self):
        with self._lock:
            if self._state != "NEW":
                raise ContainmentRefused("CANARY_NOT_ADMISSIBLE")
            self._state = "QUARANTINED"  # default safe on interrupted bootstrap
            try:
                self._fixture = tempfile.TemporaryDirectory(prefix="ldw-process-canary-")
                marker = str(Path(self._fixture.name)/"child.pid")
                self._job = _WindowsJob() if os.name == "nt" else None
                proc_env = {"PYTHONNOUSERSITE":"1"}
                if os.name == "nt":
                    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
                    if not root:
                        raise ContainmentRefused("WINDOWS_PYTHON_STARTUP_UNAVAILABLE")
                    proc_env["SystemRoot"] = root
                self._proc = subprocess.Popen(
                    [sys.executable,"-I","-u","-c",_CANARY_SCRIPT,marker],
                    stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,cwd=self._fixture.name,
                    env=proc_env,start_new_session=(os.name=="posix"),
                )
                if self._job:
                    # Worker blocks on private START gate. It cannot launch
                    # the descendant until assigned to this job.
                    self._job.assign(self._proc)
                self._proc.stdin.write(b"START\n")
                self._proc.stdin.flush()
                self._proc.stdin.close()
                until = time.monotonic()+5
                while time.monotonic()<until:
                    if Path(marker).is_file():
                        pid_text = Path(marker).read_text(encoding="ascii")
                        if not pid_text.isdecimal():
                            raise ContainmentRefused("CANARY_MARKER_INVALID")
                        self._child_pid = int(pid_text)
                        if self._proc.poll() is not None:
                            raise ContainmentRefused("CANARY_EXITED_EARLY")
                        self._started = self._clock()
                        self._state = "RUNNING"
                        return self.status()
                    if self._proc.poll() is not None:
                        raise ContainmentRefused("CANARY_EXITED_EARLY")
                    time.sleep(.03)
                raise ContainmentRefused("CANARY_START_UNVERIFIED")
            except Exception:
                self._best_effort_stop()
                raise

    def _best_effort_stop(self):
        try:
            if self._job:
                self._job.terminate()
            elif self._proc and self._proc.poll() is None:
                os.killpg(self._proc.pid,signal.SIGKILL)
        except (OSError,ContainmentRefused,ProcessLookupError):
            pass
        try:
            if self._proc:
                self._proc.wait(timeout=3)
        except (subprocess.TimeoutExpired,OSError):
            pass
        if self._job:
            self._job.close()
            self._job = None
        if self._fixture:
            try: self._fixture.cleanup()
            except OSError: pass
            self._fixture = None

    def stop(self, *, simulate_unverifiable=False):
        with self._lock:
            if self._state == "DRAINED_VERIFIED":
                return self.status()
            if self._state != "RUNNING":
                raise ContainmentRefused("CANARY_NOT_RUNNING")
            self._state = "QUARANTINED"
            try:
                if os.name == "nt":
                    self._job.terminate()
                    self._proc.wait(timeout=4)
                    deadline = time.monotonic()+3
                    while time.monotonic()<deadline and self._job.active_count():
                        time.sleep(.05)
                    verified = self._job.active_count() == 0
                else:
                    self._proc.terminate()  # fixed worker reaps own child
                    self._proc.wait(timeout=4)
                    deadline = time.monotonic()+3
                    verified = False
                    while time.monotonic()<deadline:
                        try:
                            os.killpg(self._proc.pid,0)
                        except ProcessLookupError:
                            verified = True
                            break
                        time.sleep(.05)
                if not verified or simulate_unverifiable:
                    raise ContainmentRefused("PROCESS_DRAIN_UNVERIFIED")
                self._state = "DRAINED_VERIFIED"
                return self.status()
            except (OSError,subprocess.TimeoutExpired,ContainmentRefused):
                raise ContainmentRefused("HOST_QUARANTINED") from None
            finally:
                self._best_effort_stop()

    def refresh(self):
        with self._lock:
            if self._state == "RUNNING":
                now = self._clock()
                if now < self._started:
                    try: self.stop(simulate_unverifiable=True)
                    except ContainmentRefused: pass
                    raise ContainmentRefused("CLOCK_UNTRUSTED_HOST_QUARANTINED")
                if now-self._started >= self._duration:
                    return self.stop()
            return self.status()

    def close(self):
        with self._lock:
            if self._state == "RUNNING":
                try: self.stop()
                except ContainmentRefused: pass
            else:
                self._best_effort_stop()

    def __enter__(self): return self
    def __exit__(self,*_): self.close()
