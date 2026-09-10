"""Score CVEs by what they are worth to your business, not by severity alone."""

__version__ = "0.3.1"  # keep in step with pyproject.toml; test_surfaces.py enforces it

from .assessment import assess_finding, assess_portfolio
from .exposure import measure_exposure
from .inventory import AssetProfile, Inventory
from .registry import ACTIONS, action_specs, invoke
from .schema import Assessment

__all__ = [
    "__version__",
    "Assessment",
    "AssetProfile",
    "Inventory",
    "assess_finding",
    "assess_portfolio",
    "measure_exposure",
    "ACTIONS",
    "invoke",
    "action_specs",
]
