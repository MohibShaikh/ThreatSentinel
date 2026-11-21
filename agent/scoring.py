"""
Risk score weighting shared by the planner (which computes the score) and the
reporter (which explains it), so the report can never drift from the math.
"""

from typing import Dict, Optional

INTEL_UNCERTAINTY_FLOOR = 0.25


def risk_weights(intel_available: bool, llm_used: bool) -> Dict[str, float]:
    """Component weights plus the additive uncertainty floor.

    When no external intelligence source answered, its weight is redistributed
    to event evidence and a fixed floor is added: an agent that could not look
    must never score as if it looked and saw nothing.
    """
    if not intel_available:
        if llm_used:
            return {"base": 0.45, "intel": 0.0, "pattern": 0.15, "llm": 0.30,
                    "uncertainty_floor": INTEL_UNCERTAINTY_FLOOR}
        return {"base": 0.70, "intel": 0.0, "pattern": 0.10, "llm": 0.0,
                "uncertainty_floor": INTEL_UNCERTAINTY_FLOOR}
    if llm_used:
        return {"base": 0.20, "intel": 0.35, "pattern": 0.15, "llm": 0.30, "uncertainty_floor": 0.0}
    return {"base": 0.30, "intel": 0.50, "pattern": 0.20, "llm": 0.0, "uncertainty_floor": 0.0}


def clamp01(value: Optional[float]) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # NaN
        return 0.0
    return max(0.0, min(1.0, number))


def combine_risk(base: float, intel: Optional[float], pattern: float, llm: Optional[float]) -> Dict[str, float]:
    """Weighted final score, clamped to [0, 1], with the weights that produced it."""
    weights = risk_weights(intel is not None, llm is not None)
    total = (clamp01(base) * weights["base"]
             + clamp01(intel) * weights["intel"]
             + clamp01(pattern) * weights["pattern"]
             + clamp01(llm) * weights["llm"]
             + weights["uncertainty_floor"])
    return {"score": clamp01(total), **weights}
