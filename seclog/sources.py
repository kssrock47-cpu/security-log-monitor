"""Ways to connect logs to the monitor.

  upload     a file you drop in (offline: read once, fast)
  watch      a file or folder on this computer, followed as it grows (online)
  url        a web address that serves a log, checked every few seconds (online)
  syslog     other devices send their logs here over the network (online)
  windows    this PC's own Windows Event Log (online, Windows only)
  simulator  the attack lab: a pretend network with attacks on request
"""
import glob
import gzip
import hashlib
import json
import os
import platform
import socket
import socketserver
import subprocess
import threading
import time
import urllib.request
from collections import deque

from .simulator import Simulator


class Source(threading.Thread):
    kind = "base"
    live = True

    def __init__(self, sid: int, name: str, config: dict, sink):
        super().__init__(daemon=True)
        self.sid, self.name, self.config, self.sink = sid, name, config, sink
        self.stop_flag = threading.Event()
        self.status = "starting"
        self.error = None
        self.lines = 0
        self.bytes = 0
        self.last_line = None
        self.done = False

    def emit(self, line: str, host=None):
        self.lines += 1
        self.bytes += len(line)
        self.last_line = line[:300]
        self.sink(self.sid, line, host)

    def stop(self):
        self.stop_flag.set()

    def info(self):
        return {"id": self.sid, "kind": self.kind, "name": self.name, "config": self.config, "status": self.status,
                "error": self.error, "lines": self.lines, "live": self.live, "last_line": self.last_line, "done": self.done}

    def run(self):
        try:
            self.status = "running"
            self.work()
            if not self.stop_flag.is_set() and not self.live:
                self.status, self.done = "finished", True
        except Exception as e:  # show the reason in plain words on the card
            self.status, self.error = "error", str(e)
        if self.stop_flag.is_set() and self.status != "error":
            self.status = "stopped"

    def work(self):
        raise NotImplementedError


def _open_text(path):
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


class UploadSource(Source):
    kind, live = "upload", False

    def work(self):
        path = self.config["path"]
        if path.lower().endswith(".evtx"):
            for line in _read_evtx(path):
                if self.stop_flag.is_set():
                    return
                self.emit(line)
            return
        with _open_text(path) as f:
            for line in f:
                if self.stop_flag.is_set():
                    return
                self.emit(line)


class WatchSource(Source):
    """Follow a file, or every log file in a folder, like `tail -f`."""
    kind = "watch"

    def work(self):
        target = os.path.expanduser(self.config["path"])
        pattern = self.config.get("pattern") or "*.log"
        from_start = bool(self.config.get("from_start"))
        if not os.path.exists(target):
            raise FileNotFoundError(f"Can't find {target}. Check the path.")
        pos: dict = {}
        first = True
        while not self.stop_flag.is_set():
            files = [target] if os.path.isfile(target) else sorted(
                set(glob.glob(os.path.join(target, pattern))) | set(glob.glob(os.path.join(target, "*.txt"))))
            if not files:
                self.status = "waiting"
            for fp in files:
                try:
                    size = os.path.getsize(fp)
                except OSError:
                    continue
                if fp not in pos:
                    pos[fp] = 0 if (from_start or not first) else size
                if size < pos[fp]:  # the file was rotated or cleared: start again
                    pos[fp] = 0
                if size > pos[fp]:
                    self.status = "running"
                    with open(fp, "rb") as f:
                        f.seek(pos[fp])
                        chunk = f.read(size - pos[fp])
                    cut = chunk.rfind(b"\n")
                    if cut < 0:
                        continue
                    pos[fp] += cut + 1
                    for line in chunk[:cut].decode("utf-8", "replace").splitlines():
                        self.emit(line)
            first = False
            time.sleep(0.5)


class UrlSource(Source):
    """Read a log from a web address, and keep checking it for new lines."""
    kind = "url"

    def work(self):
        url = self.config["url"]
        every = max(2, int(self.config.get("every") or 10))
        seen = deque(maxlen=20000)
        seen_set = set()
        while not self.stop_flag.is_set():
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityLogMonitor/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
            self.status = "running"
            for line in text.splitlines():
                h = hashlib.blake2b(line.encode(), digest_size=8).digest()
                if h in seen_set:
                    continue
                if len(seen) == seen.maxlen:
                    seen_set.discard(seen[0])
                seen.append(h)
                seen_set.add(h)
                self.emit(line)
            for _ in range(every * 10):
                if self.stop_flag.is_set():
                    return
                time.sleep(0.1)


class SyslogSource(Source):
    """Listen for syslog messages from routers, servers and other computers (UDP and TCP)."""
    kind = "syslog"

    def work(self):
        port = int(self.config.get("port") or 5140)
        src = self

        class TCPHandler(socketserver.StreamRequestHandler):
            def handle(self):
                for raw in self.rfile:
                    if src.stop_flag.is_set():
                        return
                    src.emit(raw.decode("utf-8", "replace"), host=self.client_address[0])

        tcp = socketserver.ThreadingTCPServer(("0.0.0.0", port), TCPHandler, bind_and_activate=False)
        tcp.allow_reuse_address = True
        tcp.daemon_threads = True
        tcp.server_bind()
        tcp.server_activate()
        threading.Thread(target=tcp.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("0.0.0.0", port))
        udp.settimeout(0.5)
        try:
            while not self.stop_flag.is_set():
                try:
                    data, addr = udp.recvfrom(65535)
                except socket.timeout:
                    continue
                for line in data.decode("utf-8", "replace").splitlines():
                    self.emit(line, host=addr[0])
        finally:
            udp.close()
            tcp.shutdown()
            tcp.server_close()


PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
foreach ($ch in @(%CHANNELS%)) {
  try {
    $f = @{ LogName = $ch; StartTime = (Get-Date).AddSeconds(-%SECONDS%) }
    $ev = Get-WinEvent -FilterHashtable $f -MaxEvents 500 -ErrorAction Stop
    foreach ($e in $ev) {
      $x = [xml]$e.ToXml(); $d = @{}
      foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
      $msg = ''; if ($e.Message) { $msg = ($e.Message -split "`n")[0] }
      $out += @{ _win = 1; id = $e.Id; rid = $e.RecordId; channel = $ch; host = $e.MachineName;
                 time = $e.TimeCreated.ToString('o'); level = $e.LevelDisplayName; text = $msg; fields = $d }
    }
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') { $out += @{ _err = 1; channel = $ch; text = $_.Exception.Message } }
  }
}
$out | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 }
"""


class WindowsSource(Source):
    """This PC's Windows Event Log. The Security channel needs the app to run as administrator."""
    kind = "windows"

    def work(self):
        if platform.system() != "Windows":
            raise RuntimeError("Windows events can only be read on a Windows PC.")
        chans = self.config.get("channels") or ["Security", "System", "Application"]
        admin_note = None
        if "Security" in chans and not _is_admin():
            # Windows returns "no events" (not an error) to normal users, so say it plainly
            admin_note = ("The Security log (logons and failed passwords) needs administrator rights. "
                          "Close the monitor, right-click run.bat and choose Run as administrator.")
        every = int(self.config.get("every") or 5)
        seen = deque(maxlen=50000)
        seen_set = set()
        lookback = int(self.config.get("history_minutes") or 60) * 60
        while not self.stop_flag.is_set():
            script = PS_SCRIPT.replace("%CHANNELS%", ",".join(f"'{c}'" for c in chans)).replace("%SECONDS%", str(lookback))
            p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                               capture_output=True, text=True, timeout=120,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            errs = []
            rows = []
            for line in p.stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                if j.get("_err"):
                    errs.append(f"{j['channel']}: {j['text']}")
                    continue
                key = (j.get("channel"), j.get("rid"))
                if key in seen_set:
                    continue
                if len(seen) == seen.maxlen:
                    seen_set.discard(seen[0])
                seen.append(key)
                seen_set.add(key)
                rows.append(j)
            for j in sorted(rows, key=lambda j: j.get("time", "")):
                self.emit(json.dumps(j))
            self.error = admin_note or (("Some channels could not be read: " + "; ".join(errs))[:300] if errs else None)
            self.status = "running"
            lookback = every * 4
            for _ in range(every * 10):
                if self.stop_flag.is_set():
                    return
                time.sleep(0.1)


class SimulatorSource(Source):
    kind = "simulator"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sim = Simulator(self.emit, rate=float(self.config.get("rate") or 8),
                             history_minutes=int(self.config.get("history_minutes") or 20))

    def stop(self):
        super().stop()
        self.sim.stop_flag.set()

    def work(self):
        self.sim.run()


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _read_evtx(path):
    """Windows .evtx files, if the optional python-evtx package is installed."""
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError as e:
        raise RuntimeError("To read .evtx files, install python-evtx (pip install python-evtx), "
                           "or export the log as text or CSV.") from e
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with evtx.Evtx(path) as log:
        for rec in log.records():
            try:
                root = ET.fromstring(rec.xml())
            except ET.ParseError:
                continue
            sysn = root.find("e:System", ns)
            eid = int(sysn.find("e:EventID", ns).text)
            tc = sysn.find("e:TimeCreated", ns).get("SystemTime")
            ch = sysn.find("e:Channel", ns).text
            host = sysn.find("e:Computer", ns).text
            fields = {d.get("Name"): d.text for d in root.iter("{%s}Data" % ns["e"]) if d.get("Name")}
            yield json.dumps({"_win": 1, "id": eid, "rid": rec.record_num(), "channel": ch, "host": host,
                              "time": tc, "level": "", "text": "", "fields": fields})


KINDS = {"upload": UploadSource, "watch": WatchSource, "url": UrlSource, "syslog": SyslogSource,
         "windows": WindowsSource, "simulator": SimulatorSource}


def lan_ip():
    """This computer's address on the local network, for the syslog instructions."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
