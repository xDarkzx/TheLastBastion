"""
Task Executor — Processes Queued M2M Tasks.

The missing link in the M2M lifecycle. When an agent submits a task
via /m2m/submit, the executor picks it up and routes it to the
correct service handler (verification, extraction, etc.).

Architecture:
    /m2m/submit -> creates task dict -> executor.run_task(task)
    -> routes to handler by service_id
    -> updates status: queued -> running -> completed/failed
    -> stores result for /m2m/result/{id} retrieval

Service Handlers:
    svc-data-extraction     -> IngestPipeline + DocumentIntelligence
    svc-document-verification -> VerificationPipeline
    svc-market-intelligence  -> Stub (requires live scraping)
    svc-attestation-proof    -> AttestationVerifier
"""
import hashlib
import json
import logging
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.verification.pipeline import VerificationPipeline
from core.ingestion import IngestPipeline, SourceProvenance
from core.document_intelligence import DocumentIntelligence

logger = logging.getLogger("TaskExecutor")


class TaskExecutor:
    """
    Async task execution engine for M2M submitted tasks.

    Routes tasks to the correct service handler based on service_id,
    manages task lifecycle (queued -> running -> completed/failed),
    and stores results for retrieval.
    """

    def __init__(
        self,
        verification_pipeline: Optional[VerificationPipeline] = None,
    ) -> None:
        self._verification = verification_pipeline or VerificationPipeline()
        self._ingestion = IngestPipeline()
        self._doc_intel = DocumentIntelligence()
        self._stats = {
            "tasks_executed": 0,
            "tasks_succeeded": 0,
            "tasks_failed": 0,
        }
        # Service handler registry
        self._handlers: Dict[str, Callable] = {
            "svc-data-extraction": self._handle_data_extraction,
            "svc-document-verification": self._handle_verification,
            "svc-market-intelligence": self._handle_market_intelligence,
            "svc-attestation-proof": self._handle_attestation,
        }

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a single task and returns the result.

        Args:
            task: Task dict from /m2m/submit containing
                  task_id, service_id, agent_id, payload, etc.

        Returns:
            Result dict with status, output, and metadata.
        """
        task_id = task["task_id"]
        service_id = task["service_id"]
        agent_id = task["agent_id"]

        logger.info(
            f"EXECUTE: {task_id} (service={service_id}, "
            f"agent={agent_id})"
        )

        task["status"] = "running"
        task["started_at"] = datetime.utcnow().isoformat()
        self._stats["tasks_executed"] += 1

        handler = self._handlers.get(service_id)
        if not handler:
            task["status"] = "failed"
            task["result"] = {
                "error": f"Unknown service: {service_id}",
                "available_services": list(self._handlers.keys()),
            }
            self._stats["tasks_failed"] += 1
            logger.error(f"UNKNOWN SERVICE: {service_id} for task {task_id}")
            return task

        try:
            result = await handler(task)
            task["status"] = "completed"
            task["result"] = result
            task["completed_at"] = datetime.utcnow().isoformat()
            self._stats["tasks_succeeded"] += 1

            logger.info(
                f"COMPLETE: {task_id} -> "
                f"result_keys={list(result.keys())}"
            )

        except Exception as exc:
            task["status"] = "failed"
            task["result"] = {
                "error": "Internal processing error",
            }
            task["failed_at"] = datetime.utcnow().isoformat()
            self._stats["tasks_failed"] += 1
            logger.error("FAILED: %s -> %s\n%s", task_id, exc, traceback.format_exc())

        return task

    async def _handle_verification(
        self, task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handles document verification tasks.

        Runs the full verification pipeline on the task payload
        and returns the verdict + proof hash.
        """
        payload = task.get("payload", {})
        agent_id = task["agent_id"]

        result = await self._verification.process_mission_result(
            mission_id=hash(task["task_id"]) % 100000,
            agent_id=agent_id,
            payload=payload,
            context=task.get("context", {}),
        )

        return {
            "verdict": result["verdict"],
            "score": result["score"],
            "proof_hash": result["proof_hash"],
            "proof_record_id": result["proof_record_id"],
            "chain_length": result["chain_length"],
            "details": result.get("details", {}),
            "service": "svc-document-verification",
        }

    async def _handle_data_extraction(
        self, task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handles data extraction tasks.

        If payload contains structured data, runs it through
        document intelligence for schema inference.
        If target_url is provided, extraction would be delegated
        to the scraper swarm (future integration).
        """
        payload = task.get("payload", {})
        target_url = task.get("target_url", "")

        # If structured data is provided, extract + verify
        if payload:
            # Ingest the structured data
            provenance = SourceProvenance(
                source_agent_id=task["agent_id"],
                submission_protocol="m2m",
            )
            ingest_result = self._ingestion.ingest_structured(
                data=payload,
                provenance=provenance,
            )

            # Extract fields via document intelligence
            cleaned = self._doc_intel.extract_from_json(
                data=payload,
                submission_id=ingest_result.submission_id,
            )

            # Run verification on the extracted data
            verification_result = await self._verification.process_mission_result(
                mission_id=hash(task["task_id"]) % 100000,
                agent_id=task["agent_id"],
                payload=payload,
                context=task.get("context", {}),
            )

            return {
                "submission_id": ingest_result.submission_id,
                "data_hash": ingest_result.data_hash,
                "extracted_fields": cleaned.fields,
                "inferred_schema": cleaned.inferred_schema,
                "document_type": cleaned.document_type,
                "extraction_confidence": cleaned.overall_confidence,
                "verification": {
                    "verdict": verification_result["verdict"],
                    "score": verification_result["score"],
                    "proof_hash": verification_result["proof_hash"],
                },
                "service": "svc-data-extraction",
            }

        # If URL provided but no data — would need scraper integration
        if target_url:
            return {
                "status": "url_scraping_not_yet_available",
                "target_url": target_url,
                "message": (
                    "URL-based extraction requires scraper swarm "
                    "integration. Submit structured data instead."
                ),
                "service": "svc-data-extraction",
            }

        return {
            "error": "No payload or target_url provided",
            "service": "svc-data-extraction",
        }

    async def _handle_market_intelligence(
        self, task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handles market intelligence tasks.

        Returns available market data categories.
        Full live scraping integration is deferred.
        """
        payload = task.get("payload", {})
        category = payload.get("category", "energy")
        region = payload.get("region", "nz")

        # If the agent sends their own data to verify,
        # run it through extraction + verification
        if len(payload) > 2:
            verification_result = await self._verification.process_mission_result(
                mission_id=hash(task["task_id"]) % 100000,
                agent_id=task["agent_id"],
                payload=payload,
                context={"category": category, "region": region},
            )
            return {
                "category": category,
                "region": region,
                "verification": {
                    "verdict": verification_result["verdict"],
                    "score": verification_result["score"],
                    "proof_hash": verification_result["proof_hash"],
                },
                "service": "svc-market-intelligence",
            }

        return {
            "category": category,
            "region": region,
            "available_categories": [
                "energy", "insurance", "broadband",
            ],
            "message": (
                "Live market intelligence requires scraper swarm. "
                "Submit data with payload for verification."
            ),
            "service": "svc-market-intelligence",
        }

    async def _handle_attestation(
        self, task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handles attestation proof tasks.

        Verifies provenance of physical documents using
        GPS, depth maps, and device fingerprints.
        """
        payload = task.get("payload", {})

        # Run verification with attestation context
        result = await self._verification.process_mission_result(
            mission_id=hash(task["task_id"]) % 100000,
            agent_id=task["agent_id"],
            payload=payload,
            context={"attestation_mode": True},
        )

        return {
            "verdict": result["verdict"],
            "score": result["score"],
            "proof_hash": result["proof_hash"],
            "attestation_note": (
                "Full attestation requires GPS coordinates, "
                "depth maps, and device fingerprints in the payload."
            ),
            "service": "svc-attestation-proof",
        }

    @property
    def stats(self) -> Dict[str, int]:
        """Returns executor statistics."""
        return dict(self._stats)

