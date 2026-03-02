"""Phase definitions for the crawl pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import auto

from prowl._compat import StrEnum


class PhaseState(StrEnum):
    PENDING = auto()
    RUNNING = auto()
    COMPLETE = auto()
    ERROR = auto()
    SKIPPED = auto()


@dataclass
class Phase:
    """A single pipeline phase containing one or more modules."""

    name: str
    modules: list[str]
    depends_on: list[str] = field(default_factory=list)
    parallel: bool = False
    state: PhaseState = PhaseState.PENDING


# Default pipeline phases - coverage-guided attack surface discovery
DEFAULT_PHASES: list[Phase] = [
    Phase(
        name="passive",
        modules=["s6_passive"],
        depends_on=[],
    ),
    Phase(
        name="active_crawl",
        modules=["s1_spider", "s2_bruteforce"],
        depends_on=["passive"],
        parallel=True,
    ),
    Phase(
        name="fingerprinting",
        modules=["s9_infra", "s10_tech"],
        depends_on=["active_crawl"],
        parallel=True,
    ),
    Phase(
        name="js_analysis",
        modules=["s4_js"],
        depends_on=["active_crawl"],
    ),
    Phase(
        name="api_discovery",
        modules=["s5_api"],
        depends_on=["active_crawl", "js_analysis"],
    ),
    Phase(
        name="state_transitions",
        modules=["s8_states"],
        depends_on=["active_crawl", "js_analysis"],
    ),
    Phase(
        name="auth_crawl",
        modules=["s7_auth"],
        depends_on=["active_crawl", "fingerprinting"],
    ),
    Phase(
        name="deep_crawl",
        modules=["s1_spider"],
        depends_on=["js_analysis", "api_discovery", "state_transitions", "auth_crawl"],
    ),
    Phase(
        name="param_discovery",
        modules=["s3_params"],
        depends_on=["deep_crawl"],
    ),
    Phase(
        name="classification",
        modules=["s11_input", "s12_auth"],
        depends_on=["param_discovery", "fingerprinting"],
        parallel=True,
    ),
    Phase(
        name="reporting",
        modules=["s13_report"],
        depends_on=["classification"],
    ),
]
