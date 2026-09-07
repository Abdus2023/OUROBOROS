"""Cold bootstrap and the repository trust boundary.

M1.9 adds authoritative mode: cold-start trust also requires an externally
provisioned TrustStore and a generation-bound signed checkpoint covering the
current journal head. Repository state alone can never satisfy that boundary.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from .generation import repository_generation
from .journal import Journal
from .kernel import Kernel
from .policy import Constitution, ConstitutionError, PolicyEngine, load_constitution
from .promotion import PromotionAuthority
from .skills import SkillRegistry, filesystem_skills, resolve_inside
from .trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository, load_external_authority
from .verify import Gate, GateConfigurationError, Verifier, load_gates

SKILLS_MANIFEST_SCHEMA = "ourob.skills.v1"
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_PACKAGE_PREFIX = "ouroboros/M0"
CAPABILITY_MODULE_NAMESPACE = "ourob_capability"


class BootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilityDeclaration:
    name: str
    module: str


@dataclass
class BootstrapResult:
    repo_root: Path
    generation_before: str
    generation_after: str
    constitution: Constitution
    gates: tuple[Gate, ...]
    capabilities: tuple[CapabilityDeclaration, ...]
    registry: SkillRegistry
    errors: list[str] = field(default_factory=list)
    trust_authenticated: bool = False
    trust_required: bool = False

    @property
    def trusted(self) -> bool:
        return not self.errors and self.generation_before == self.generation_after and (
            self.trust_authenticated or not self.trust_required
        )

    def summary(self) -> dict[str, Any]:
        return {
            "trusted": self.trusted,
            "trust_required": self.trust_required,
            "trust_authenticated": self.trust_authenticated,
            "generation": self.generation_after,
            "generation_stable": self.generation_before == self.generation_after,
            "gates": [g.name for g in self.gates],
            "capabilities": [c.name for c in self.capabilities],
            "skills": list(self.registry.names()),
            "errors": list(self.errors),
        }


def default_repo_root() -> Path:
    for candidate in (PACKAGE_DIR, *PACKAGE_DIR.parents):
        if (candidate / "policies" / "constitution.json").is_file() and (candidate / "verification" / "gates.json").is_file():
            return candidate
    raise BootstrapError("could not locate repository root (policies/constitution.json + verification/gates.json)")


def parse_skills_manifest(raw: Any) -> tuple[CapabilityDeclaration, ...]:
    if not isinstance(raw, dict):
        raise BootstrapError("skills manifest must be a JSON object")
    if raw.get("schema") != SKILLS_MANIFEST_SCHEMA:
        raise BootstrapError(f"unsupported skills manifest schema: {raw.get('schema')!r}")
    entries = raw.get("capabilities")
    if not isinstance(entries, list):
        raise BootstrapError("skills manifest must declare a capabilities list")
    declarations: list[CapabilityDeclaration] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "module"}:
            raise BootstrapError(f"capability entry must be exactly {{name, module}}: {entry!r}")
        name, module = entry["name"], entry["module"]
        if not isinstance(name, str) or not name.isidentifier():
            raise BootstrapError(f"capability name must be a valid identifier: {name!r}")
        if not isinstance(module, str) or not module.endswith(".py"):
            raise BootstrapError(f"capability module must be a repository-relative .py path: {module!r}")
        if name in seen:
            raise BootstrapError(f"duplicate capability name: {name}")
        seen.add(name)
        declarations.append(CapabilityDeclaration(name, module))
    return tuple(declarations)


def load_skills_manifest(path: Path) -> tuple[CapabilityDeclaration, ...]:
    if not path.exists():
        return ()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"skills manifest is not valid JSON: {exc.msg}") from exc
    return parse_skills_manifest(raw)


def _import_repository_module(repo_root: Path, declaration: CapabilityDeclaration) -> ModuleType:
    try:
        target, relative = resolve_inside(repo_root, declaration.module)
    except ValueError as exc:
        raise BootstrapError(f"capability {declaration.name}: {exc}") from exc
    if not target.is_file():
        raise BootstrapError(f"capability {declaration.name}: module not found: {relative.as_posix()}")
    module_name = f"{CAPABILITY_MODULE_NAMESPACE}.{declaration.name}"
    spec = importlib.util.spec_from_file_location(module_name, target)
    if spec is None or spec.loader is None:
        raise BootstrapError(f"capability {declaration.name}: cannot load {relative.as_posix()}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        if previous is not None:
            sys.modules[module_name] = previous
        else:
            sys.modules.pop(module_name, None)
        raise BootstrapError(f"capability {declaration.name}: import failed: {type(exc).__name__}: {exc}") from exc
    if Path(getattr(module, "__file__", "")).resolve() != target:
        raise BootstrapError(f"capability {declaration.name}: module origin mismatch")
    return module


def reconstruct_registry(repo_root: Path, declarations: tuple[CapabilityDeclaration, ...]) -> SkillRegistry:
    registry = filesystem_skills(repo_root)
    for declaration in declarations:
        if registry.has(declaration.name):
            raise BootstrapError(f"capability {declaration.name} collides with a built-in skill")
        module = _import_repository_module(repo_root, declaration)
        register = getattr(module, "register", None)
        if not callable(register):
            raise BootstrapError(f"capability {declaration.name}: module does not export register()")
        before = set(registry.names())
        register(registry)
        added = set(registry.names()) - before
        if added != {declaration.name}:
            raise BootstrapError(f"capability {declaration.name}: register() added {sorted(added)}, expected exactly [{declaration.name!r}]")
    return registry


class Bootstrap:
    def __init__(self, repo_root: Path | None = None, package_prefix: str = DEFAULT_PACKAGE_PREFIX, *,
                 trust_checkpoint: Path | None = None, trust_store: Path | None = None,
                 require_external_trust: bool = False):
        if (trust_checkpoint is None) != (trust_store is None):
            raise BootstrapError("trust_checkpoint and trust_store must be supplied together")
        if require_external_trust and trust_checkpoint is None:
            raise BootstrapError("authoritative bootstrap requires an external checkpoint and trust store")
        self.repo_root = Path(repo_root).resolve() if repo_root else default_repo_root()
        self.package_prefix = package_prefix
        self.trust_checkpoint = Path(trust_checkpoint).resolve() if trust_checkpoint else None
        self.trust_store = Path(trust_store).resolve() if trust_store else None
        self.require_external_trust = require_external_trust

    @property
    def constitution_path(self) -> Path: return self.repo_root / "policies" / "constitution.json"
    @property
    def gates_path(self) -> Path: return self.repo_root / "verification" / "gates.json"
    @property
    def skills_manifest_path(self) -> Path: return self.repo_root / "skills" / "manifest.json"
    @property
    def journal_path(self) -> Path: return self.repo_root / ".ourob" / "journal.jsonl"

    def _authenticate_external_trust(self) -> bool:
        if self.trust_checkpoint is None or self.trust_store is None:
            return False
        authority: ExternalTrustAuthority = load_external_authority(self.trust_checkpoint, self.trust_store)
        authenticate_current_repository(Journal(self.journal_path), authority, generation=repository_generation(self.repo_root).id)
        return True

    def cold_start(self) -> BootstrapResult:
        errors: list[str] = []
        generation_before = repository_generation(self.repo_root).id
        trust_authenticated = False
        constitution: Constitution | None = None
        try: constitution = load_constitution(self.constitution_path)
        except ConstitutionError as exc: errors.append(f"constitution: {exc}")
        gates: tuple[Gate, ...] = ()
        try: gates = load_gates(self.gates_path)
        except GateConfigurationError as exc: errors.append(f"gates: {exc}")
        capabilities: tuple[CapabilityDeclaration, ...] = ()
        registry = filesystem_skills(self.repo_root)
        try:
            capabilities = load_skills_manifest(self.skills_manifest_path)
            registry = reconstruct_registry(self.repo_root, capabilities)
        except BootstrapError as exc: errors.append(f"capabilities: {exc}")
        if self.trust_checkpoint is not None:
            try: trust_authenticated = self._authenticate_external_trust()
            except TrustBoundaryError as exc: errors.append(f"trust: {exc}")
        generation_after = repository_generation(self.repo_root).id
        if generation_after != generation_before: errors.append("generation: repository content changed during bootstrap")
        if constitution is None: constitution = Constitution("invalid", "invalid", (), ())
        return BootstrapResult(self.repo_root, generation_before, generation_after, constitution, gates, capabilities,
                               registry, errors, trust_authenticated, self.require_external_trust)

    def kernel(self, result: BootstrapResult | None = None, journal: Journal | None = None) -> Kernel:
        result = result or self.cold_start()
        if not result.trusted:
            raise BootstrapError("refusing to construct kernel from untrusted bootstrap: " + "; ".join(result.errors))
        return Kernel(repo_root=self.repo_root, journal=journal or Journal(self.journal_path),
                      policy=PolicyEngine(result.constitution, self.package_prefix), skills=result.registry,
                      verifier=Verifier(self.repo_root, result.gates),
                      promotion=PromotionAuthority(require_trust=result.trust_required),
                      trust_authenticated=result.trust_authenticated)
