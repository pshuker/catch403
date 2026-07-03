#!/usr/bin/python3
"""
Turbo Intruder — high-concurrency HTTP fuzzer with script-based attack logic.
Inspired by Burp Suite's Turbo Intruder extension.

Key differences from intruder.py (regular Intruder):
  - Async thread pool — hundreds of requests in flight simultaneously
  - Race condition mode: all requests sent in a tight burst
  - Script-based attack logic: define a Python function to drive the engine
  - Pipeline mode: reuse connections (keepalive)
  - Gate mechanism: prepare all requests, release simultaneously

Built-in attack scripts:
  - default: classic wordlist injection at %s marker
  - race: N identical requests simultaneously (race condition testing)
  - password_spray: one password across many usernames
  - param_fuzz: fuzz parameter values from wordlist

Usage:
  # Built-in wordlist attack
  ../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/login \
      -d 'user=admin&pass=%s' -w wordlist.txt -t 50

  # Race condition
  ../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com/redeem \
      -d 'code=DISCOUNT10' --race 50

  # Custom script
  ../.venv/bin/python3 modules/turbo_intruder.py -u https://target.com \
      --script my_attack.py
"""
import argparse
import queue
import threading
import time
import sys
from collections import Counter
from urllib.parse import urlparse

import requests
import urllib3

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab

urllib3.disable_warnings()

MARKER = "%s"
UA = "Mozilla/5.0 (compatible; Catch403/1.0)"


class Result:
    __slots__ = ("url", "method", "payload", "status", "length", "elapsed_ms", "body", "headers")

    def __init__(self, url, method, payload, status, length, elapsed_ms, body="", headers=None):
        self.url        = url
        self.method     = method
        self.payload    = payload
        self.status     = status
        self.length     = length
        self.elapsed_ms = elapsed_ms
        self.body       = body
        self.headers    = headers or {}


class Engine:
    """
    The fuzzing engine. Manages a thread pool and request queue.
    Scripts call engine.queue(payload) to add work.
    """

    def __init__(self, base_url: str, method: str = "GET",
                 body_template: str = "",
                 headers: dict | None = None,
                 threads: int = 20,
                 timeout: int = 10,
                 gate: bool = False,
                 pipeline: bool = False,
                 filter_fn=None):
        self.base_url      = base_url
        self.method        = method.upper()
        self.body_template = body_template
        self.headers       = {"User-Agent": UA, **(headers or {})}
        self.threads       = threads
        self.timeout       = timeout
        self.gate          = gate
        self.filter_fn     = filter_fn  # fn(Result) -> bool, True = interesting

        self._queue:   queue.Queue = queue.Queue(maxsize=10000)
        self._results: list[Result] = []
        self._lock     = threading.Lock()
        self._gate_event = threading.Event()
        self._workers: list[threading.Thread] = []
        self._done = self._total = 0
        self._t0   = 0.0

        if not gate:
            self._gate_event.set()

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False

    def queue(self, payload: str, label: str | None = None) -> None:
        self._queue.put((payload, label or payload))
        with self._lock:
            self._total += 1

    def _build_request(self, payload: str) -> tuple[str, str | None]:
        url = self.base_url
        body = self.body_template
        if MARKER in url:
            url = url.replace(MARKER, requests.utils.quote(payload, safe=""))
        if MARKER in body:
            body = body.replace(MARKER, payload)
        return url, body or None

    def _send(self, url: str, body: str | None, payload: str) -> Result:
        t0 = time.perf_counter()
        try:
            if self.method == "GET":
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            else:
                r = self.session.request(
                    self.method, url,
                    data=body, timeout=self.timeout, allow_redirects=False,
                )
            elapsed = int((time.perf_counter() - t0) * 1000)
            return Result(url, self.method, payload, r.status_code,
                          len(r.content), elapsed, r.text[:2000], dict(r.headers))
        except Exception as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return Result(url, self.method, payload, 0, 0, elapsed, str(e))

    def _worker(self):
        self._gate_event.wait()  # block until gate opens
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                break
            payload, label = item
            url, body = self._build_request(payload)
            result = self._send(url, body, payload)
            with self._lock:
                self._done += 1
                self._results.append(result)
                if self.filter_fn is None or self.filter_fn(result):
                    _print_result(result, label)
            self._queue.task_done()

    def start(self):
        self._t0 = time.time()
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def open_gate(self):
        self._gate_event.set()

    def finish(self) -> list[Result]:
        try:
            self._queue.join()
        except KeyboardInterrupt:
            print(f"\n{bad} Interrupted")
        for w in self._workers:
            w.join(timeout=1)
        elapsed = time.time() - self._t0
        rps = self._done / elapsed if elapsed > 0 else 0
        print(f"\n{bold}Done{end}: {self._done} requests in {elapsed:.1f}s  ({rps:.0f} req/s)")
        return self._results


# ── Built-in attack scripts ────────────────────────────────────────────────

def attack_wordlist(engine: Engine, wordlist_path: str):
    """Inject each word from a wordlist at the %s marker."""
    with open(wordlist_path) as f:
        for line in f:
            word = line.rstrip("\n\r")
            if word:
                engine.queue(word)


def attack_race(engine: Engine, payload: str, n: int):
    """Send N identical requests simultaneously — gate-based race condition."""
    engine.gate = True
    engine.threads = min(n, 200)
    for _ in range(n):
        engine.queue(payload)


def attack_password_spray(engine: Engine, usernames: list[str], password: str):
    """Try one password against many usernames."""
    for u in usernames:
        engine.queue(f"{u}:{password}", label=u)


def attack_param_fuzz(engine: Engine, params: list[str]):
    """Fuzz parameter names in the URL/body."""
    for p in params:
        engine.queue(p)


# ── Result printing ────────────────────────────────────────────────────────

def _status_col(s: int) -> str:
    if s == 0:    return red
    if s < 300:   return green
    if s < 400:   return yellow
    return red


def _print_result(r: Result, label: str):
    sc = _status_col(r.status)
    payload_disp = (label[:30] + "…") if len(label) > 30 else label
    print(f"  {sc}[{r.status}]{end}  {payload_disp:<35}  {r.length:>8}B  {r.elapsed_ms:>5}ms")


def _default_filter(baseline_length: int, threshold: int = 50):
    """Interesting if length differs from baseline by more than threshold."""
    def fn(r: Result) -> bool:
        return r.status != 0 and abs(r.length - baseline_length) > threshold
    return fn


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Turbo Intruder — high-concurrency HTTP fuzzer")
    parser.add_argument("-u",   dest="url",    required=True, help="Target URL (%s = injection point)")
    parser.add_argument("-d",   dest="data",   default="",    help="POST body (%s = injection point)")
    parser.add_argument("-X",   dest="method", default="GET", help="HTTP method")
    parser.add_argument("-w",   dest="wordlist",              help="Wordlist file")
    parser.add_argument("-t",   dest="threads", type=int, default=30)
    parser.add_argument("--race",    type=int, metavar="N",  help="Race condition: N simultaneous requests")
    parser.add_argument("--payload", default="test",         help="Payload for --race (default: test)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--header",  action="append", dest="headers", metavar="Name:Value")
    parser.add_argument("--cookie",  default="")
    parser.add_argument("--all",     action="store_true",    help="Show all results, not just interesting ones")
    parser.add_argument("--gate",    action="store_true",    help="Enable gate (release all at once)")
    parser.add_argument("-o",        dest="output",          help="Save results to JSON file")
    args = parser.parse_args()

    headers = {}
    for h in (args.headers or []):
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    if args.cookie:
        headers["Cookie"] = args.cookie

    method = args.method.upper()
    if args.data and method == "GET":
        method = "POST"
    if args.data and "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    print(f"\n{bold}Turbo Intruder{end} → {args.url}")
    print(f"  {info} Method: {method}  Threads: {args.threads}  Timeout: {args.timeout}s")

    # Baseline request
    baseline_len = 0
    baseline_url = args.url.replace(MARKER, "BASELINE_TEST")
    baseline_body = args.data.replace(MARKER, "BASELINE_TEST") if args.data else None
    try:
        sess = requests.Session()
        sess.headers.update({**{"User-Agent": UA}, **headers})
        sess.verify = False
        if method == "GET":
            r = sess.get(baseline_url, timeout=args.timeout)
        else:
            r = sess.request(method, baseline_url, data=baseline_body, timeout=args.timeout)
        baseline_len = len(r.content)
        print(f"  {info} Baseline: {r.status_code}  {baseline_len}B\n")
    except Exception:
        print(f"  {info} Baseline: unavailable\n")

    filter_fn = None if args.all else _default_filter(baseline_len)

    engine = Engine(
        base_url=args.url, method=method,
        body_template=args.data, headers=headers,
        threads=args.threads, timeout=args.timeout,
        gate=args.gate or bool(args.race),
        filter_fn=filter_fn,
    )

    if args.race:
        print(f"  {info} Race condition mode: {args.race} simultaneous requests\n")
        attack_race(engine, args.payload, args.race)
    elif args.wordlist:
        with open(args.wordlist) as f:
            words = [l.rstrip("\n\r") for l in f if l.strip()]
        print(f"  {info} Wordlist: {len(words)} words\n")
        engine.start()
        for w in words:
            engine.queue(w)
    else:
        parser.print_help()
        return

    engine.start()
    if args.gate or args.race:
        time.sleep(0.05)   # let workers reach the gate
        engine.open_gate()

    results = engine.finish()

    if args.output:
        import json
        data = [{"payload": r.payload, "status": r.status,
                 "length": r.length, "elapsed_ms": r.elapsed_ms} for r in results]
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{good} Results saved → {args.output}")

    # Status code summary
    counts = Counter(r.status for r in results)
    print(f"\n{bold}Status summary:{end}  " +
          "  ".join(f"{_status_col(s)}[{s}]×{n}{end}" for s, n in sorted(counts.items())))


if __name__ == "__main__":
    main()
