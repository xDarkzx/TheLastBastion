
import json
import logging
from typing import List, Dict, Any, Optional
from core.industrial_logger import get_industrial_logger
from core.llm_client import LLMClient

class ConsensusEngine:
    """
    The Last Bastion Supreme Court (v4.0).
    Aggregates results from multiple workers and verifies the Absolute Truth.
    """
    
    def __init__(self):
        self.logger = get_industrial_logger("ConsensusEngine")
        self.llm = LLMClient()

    async def resolve_conflicts(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Takes raw results from multiple workers and returns a unified, verified payload.
        """
        if not results:
            return {"status": "VOID", "data": {}}
        
        if len(results) == 1:
            self.logger.info("CONSENSUS: Single source provided. Trusting implicitly (Solo Mode).")
            return {"status": "VERIFIED", "data": results[0].get("data", {}), "confidence": 1.0}

        self.logger.info(f"CONSENSUS: Aggregating {len(results)} observation points...")
        
        # 1. Simple Deduplication (Structural Matching)
        fingerprints = [json.dumps(r.get("data", {}), sort_keys=True) for r in results]
        unique_fingerprints = list(set(fingerprints))
        
        if len(unique_fingerprints) == 1:
            self.logger.info("CONSENSUS: 100% Structural Agreement achieved.")
            return results[0]

        # 2. LLM-Based Arbitration (The Jury)
        self.logger.warning(f"CONSENSUS: Conflict detected between {len(unique_fingerprints)} unique views. Triggering LLM Jury...")
        return await self._arbitrate_via_jury(results)

    async def _arbitrate_via_jury(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Uses a high-level model to judge which result is more likely correct based on evidence."""
        system_prompt = """
        ### THE REGISTRY BASE CONSENSUS JURY (v4.0) ###
        You are a skeptical judge. Multiple autonomous agents have extracted data from the same target.
        Some might have failed, some might have hallucinated, and some might have found 'Liquid Gold'.

        Analyze the provided results and determine the MOST ACCURATE payload.
        Reject results that contain common error patterns (e.g., 'NOT_FOUND', 'N/A', empty strings).
        Prefer results with specific values (floats, dates, precise strings).

        OUTPUT FORMAT: Return the final, cleaned JSON data object that should be committed to the vault.
        """

        jury_input = {
            "observations": [
                {
                    "worker_id": r.get("worker_id"),
                    "extracted_data": r.get("data"),
                    "error": r.get("error")
                } for r in results
            ]
        }

        arbitrated = await self.llm.generate_response(
            json.dumps(jury_input),
            system_prompt=system_prompt,
            tier="strategist"
        )

        # Calculate confidence from fingerprint agreement ratio and data quality
        fingerprints = [json.dumps(r.get("data", {}), sort_keys=True) for r in results]
        unique_count = len(set(fingerprints))
        total_count = len(fingerprints)
        agreement_ratio = 1.0 - ((unique_count - 1) / max(total_count, 1))
        # Penalize results with errors or empty data
        valid_results = sum(1 for r in results if r.get("data") and not r.get("error"))
        data_quality = valid_results / max(total_count, 1)
        # Weighted confidence: 60% agreement + 40% data quality, floor at 0.3
        confidence = round(max(0.3, (agreement_ratio * 0.6) + (data_quality * 0.4)), 3)

        self.logger.info(f"CONSENSUS: Jury verdict — confidence={confidence} (agreement={agreement_ratio:.2f}, quality={data_quality:.2f})")
        return {
            "status": "ARBITRATED",
            "data": arbitrated,
            "confidence": confidence
        }
