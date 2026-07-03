"""
Module system — the plugin architecture.

This is the heart of the platform's extensibility: a clean, documented interface
that loadable modules implement, and a manager that discovers, loads, and runs
them against the traffic pipeline. Drop a module file into the modules directory
(or load one you pulled from elsewhere) and it hooks in.

A module implements any subset of the hooks it cares about:
  * on_request(flow)   — called for every intercepted request before it's sent
  * on_response(flow)  — called for every response before it's returned
  * on_load()          — called once when the module is loaded (setup)
  * on_unload()        — called once when unloaded (teardown)

Modules can inspect, annotate (flow.tag / flow.note), mutate (edit request/
response), or drop (flow.drop()) a flow. The manager runs them in registration
order and never lets one misbehaving module crash the pipeline.

NOTE ON SCOPE: this framework provides the extension points and the plumbing.
The platform ships with neutral, inspection-oriented example modules only. Any
active-testing modules are authored/added by the operator, who is responsible
for using them only against systems they are authorised to test.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Protocol, runtime_checkable

from core.flow import Flow


@runtime_checkable
class Module(Protocol):
    """The interface a loadable module implements. All hooks optional."""
    name: str

    def on_request(self, flow: Flow) -> None: ...
    def on_response(self, flow: Flow) -> None: ...
    def on_load(self) -> None: ...
    def on_unload(self) -> None: ...


class BaseModule:
    """
    Convenience base class — subclass this and override only the hooks you need.
    Gives you a name and no-op defaults so a module can be as small as:

        class MyModule(BaseModule):
            name = "my-module"
            def on_request(self, flow):
                flow.note("seen by my-module")
    """
    name: str = "unnamed-module"

    def on_request(self, flow: Flow) -> None:
        pass

    def on_response(self, flow: Flow) -> None:
        pass

    def on_load(self) -> None:
        pass

    def on_unload(self) -> None:
        pass


class ModuleManager:
    """
    Discovers, loads, and runs modules. Modules run in the order they were added.
    A hook raising an exception is caught and logged to the flow, never allowed to
    crash the proxy pipeline (an unstable third-party module must not take down
    the platform).
    """
    def __init__(self):
        self._modules: list[Module] = []
        self.errors: list[str] = []

    # --- registration -------------------------------------------------------

    def add(self, module: Module) -> None:
        """Register an already-instantiated module."""
        self._modules.append(module)
        self._safe(module, "on_load", None)

    def remove(self, name: str) -> None:
        for m in list(self._modules):
            if getattr(m, "name", None) == name:
                self._safe(m, "on_unload", None)
                self._modules.remove(m)

    def list_modules(self) -> list[str]:
        return [getattr(m, "name", "?") for m in self._modules]

    # --- loading from files -------------------------------------------------

    def load_file(self, path: str) -> list[str]:
        """
        Load a .py file and register every BaseModule subclass it defines.
        This is how you add a module you pulled from elsewhere: point at the file.
        Returns the names of modules loaded.
        """
        spec = importlib.util.spec_from_file_location(
            f"module_{os.path.basename(path).rstrip('.py')}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load module file: {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        loaded = []
        for attr in vars(mod).values():
            if (isinstance(attr, type) and issubclass(attr, BaseModule)
                    and attr is not BaseModule):
                inst = attr()
                self.add(inst)
                loaded.append(inst.name)
        return loaded

    def load_dir(self, directory: str) -> list[str]:
        """Load every .py module file in a directory."""
        loaded = []
        if not os.path.isdir(directory):
            return loaded
        for fn in sorted(os.listdir(directory)):
            if fn.endswith(".py") and not fn.startswith("_"):
                loaded += self.load_file(os.path.join(directory, fn))
        return loaded

    # --- pipeline hooks (called by the proxy) -------------------------------

    def run_request(self, flow: Flow) -> None:
        for m in self._modules:
            if flow.dropped:
                break
            self._safe(m, "on_request", flow)

    def run_response(self, flow: Flow) -> None:
        for m in self._modules:
            self._safe(m, "on_response", flow)

    # --- internals ----------------------------------------------------------

    def _safe(self, module: Module, hook: str, flow: Flow | None) -> None:
        """Call a module hook, catching any error so it can't crash the pipeline."""
        fn = getattr(module, hook, None)
        if fn is None:
            return
        try:
            fn(flow) if flow is not None else fn()
        except Exception as e:  # noqa: BLE001 — a module must not crash the platform
            msg = f"module {getattr(module,'name','?')}.{hook} error: {e}"
            self.errors.append(msg)
            if flow is not None:
                flow.note(msg)
