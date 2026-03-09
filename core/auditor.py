
import logging
import re
from typing import Dict, Any, Tuple
from core.industrial_logger import get_industrial_logger

class AdversarialAuditor:
    """
    The Skeptic (v4.0).
    Scans extraction results for placeholders, errors, and low-quality data.
    """
    
    def __init__(self):
        self.logger = get_industrial_logger("AdversarialAuditor")
        self.dirt_patterns = [
            r"not found",
            r"n/a",
            r"error",
            r"null",
            r"undefined",
            r"none",
            r"placeholder",
            r"\[.*\]", # Brackets often mean templates
            r"\{.*\}"
        ]

    def audit_yield(self, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Audits a data payload for industrial quality.
        Returns: (is_clean, reason)
        """
        if not payload:
            return False, "EMPTY_PAYLOAD"

        dirty_keys = []
        for key, value in payload.items():
            str_val = str(value).lower()
            
            # Check for dirt patterns
            for pattern in self.dirt_patterns:
                if re.search(pattern, str_val):
                    dirty_keys.append(key)
                    break
            
            # Check for zero/empty strings
            if value == "" or value is None:
                dirty_keys.append(key)

        if dirty_keys:
            self.logger.warning(f"AUDITOR: Dirty values detected in keys: {dirty_keys}")
            return False, f"DIRTY_DATA: {dirty_keys}"

        self.logger.info("AUDITOR: Payload passed industrial quality check.")
        return True, "CLEAN"

    def calculate_confidence(self, payload: Dict[str, Any]) -> float:
        """Heuristic confidence scoring."""
        if not payload: return 0.0
        
        score = 1.0
        # Reduce score for every 'UNKNOWN' in Reified hierarchy
        mandatories = ["company", "country", "region", "suburb"]
        for m in mandatories:
            if payload.get(m) == "UNKNOWN":
                score -= 0.15
        
        return max(0.1, score)

    def structural_diff(
        self, alpha_result: Dict[str, Any], beta_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Dual-Bot Verification: Structural comparison of Alpha vs Beta extractions.
        Computes field-by-field match ratio.

        Returns:
            {
                "match_ratio": float (0.0-1.0),
                "matched_keys": [...],
                "mismatched_keys": [...],
                "alpha_only": [...],
                "beta_only": [...],
                "verdict": "MATCH" | "PARTIAL" | "MISMATCH"
            }
        """
        if not alpha_result or not beta_result:
            return {
                "match_ratio": 0.0, "matched_keys": [], "mismatched_keys": [],
                "alpha_only": list(alpha_result.keys()) if alpha_result else [],
                "beta_only": list(beta_result.keys()) if beta_result else [],
                "verdict": "MISMATCH"
            }

        # Skip internal metadata keys
        skip = {"_audit", "status", "confidence_score", "source_summary"}
        alpha_keys = {k for k in alpha_result if k not in skip}
        beta_keys = {k for k in beta_result if k not in skip}

        all_keys = alpha_keys | beta_keys
        if not all_keys:
            return {
                "match_ratio": 0.0, "matched_keys": [], "mismatched_keys": [],
                "alpha_only": [], "beta_only": [], "verdict": "MISMATCH"
            }

        matched = []
        mismatched = []
        for key in all_keys:
            a_val = alpha_result.get(key)
            b_val = beta_result.get(key)

            if a_val == b_val:
                matched.append(key)
            elif str(a_val).strip().lower() == str(b_val).strip().lower():
                # Case-insensitive / whitespace-insensitive match
                matched.append(key)
            else:
                mismatched.append(key)

        ratio = len(matched) / len(all_keys) if all_keys else 0.0

        # Determine verdict
        if ratio >= 0.9:
            verdict = "MATCH"
        elif ratio >= 0.5:
            verdict = "PARTIAL"
        else:
            verdict = "MISMATCH"

        self.logger.info(
            f"AUDITOR: Dual-Bot Diff -> {verdict} "
            f"(ratio={ratio:.2f}, matched={len(matched)}, mismatched={len(mismatched)})"
        )

        return {
            "match_ratio": ratio,
            "matched_keys": matched,
            "mismatched_keys": mismatched,
            "alpha_only": list(alpha_keys - beta_keys),
            "beta_only": list(beta_keys - alpha_keys),
            "verdict": verdict
        }
