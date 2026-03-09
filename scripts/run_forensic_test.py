"""
Forensic Photo Test: Runs the full forensic integrity stack
on two user-provided images and compares results.

Usage:
    Place image1.* and image2.* in the photos/ folder, then run:
    python run_forensic_test.py
"""
import asyncio
import logging
import os
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ForensicTest")


async def analyze_image(filepath: Path) -> None:
    """Runs the full forensic integrity stack on a single image."""
    from core.verification.forensic_integrity import ForensicIntegrityAnalyzer

    logger.info("=" * 70)
    logger.info(f"ANALYZING: {filepath.name}")
    logger.info(f"  Size: {filepath.stat().st_size / 1024:.1f} KB")
    logger.info("=" * 70)

    file_bytes = filepath.read_bytes()
    file_type = filepath.suffix.lstrip(".")

    analyzer = ForensicIntegrityAnalyzer()
    result = await analyzer.analyze(file_bytes, file_type)

    # Print pillar summary
    logger.info("")
    logger.info(f"  PILLAR SCORE: {result.score:.4f}")
    logger.info(f"  VETO: {result.is_veto} {('— ' + result.veto_reason) if result.is_veto else ''}")
    logger.info("")

    # Print each layer's result
    for lr in result.layer_results:
        status = "✅" if lr.score >= 0.5 else "⚠️" if lr.score >= 0.3 else "❌"
        logger.info(f"  {status} {lr.layer_name:25s} score={lr.score:.4f}")

        # Show warnings
        for w in lr.warnings:
            logger.info(f"      ⚠  {w}")

        # Show anomalies
        for a in lr.anomalies:
            logger.info(f"      🚨 {a}")

        # Show evidence
        for ev in lr.evidence:
            symbol = "✓" if ev.confirms else "✗"
            logger.info(f"      {symbol}  {ev.reasoning[:90]}")

        # Show metadata
        if lr.metadata:
            for k, v in lr.metadata.items():
                if not isinstance(v, dict):
                    logger.info(f"         {k}: {v}")

        logger.info("")

    # Final verdict line
    if result.score >= 0.9:
        verdict = "🏆 GOLD — High confidence authentic document"
    elif result.score >= 0.7:
        verdict = "✅ VERIFIED — Likely authentic"
    elif result.score >= 0.4:
        verdict = "⚠️ QUARANTINE — Suspicious, needs more evidence"
    else:
        verdict = "❌ REJECTED — Strong tampering indicators"

    logger.info("=" * 70)
    logger.info(f"  VERDICT: {verdict}")
    logger.info(f"  COMPOSITE SCORE: {result.score:.4f}")
    logger.info("=" * 70)
    logger.info("")

    return result


async def main():
    photos_dir = Path("photos")

    if not photos_dir.exists():
        logger.error("photos/ folder not found. Create it and add image1.* and image2.*")
        sys.exit(1)

    # Find all images in the photos folder
    image_extensions = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp", ".pdf"}
    images = sorted([
        f for f in photos_dir.iterdir()
        if f.is_file() and f.suffix.lower() in image_extensions
    ])

    if not images:
        logger.error(
            f"No images found in photos/. "
            f"Supported: {', '.join(image_extensions)}"
        )
        sys.exit(1)

    logger.info(f"Found {len(images)} image(s) to analyze:")
    for img in images:
        logger.info(f"  → {img.name} ({img.stat().st_size / 1024:.1f} KB)")
    logger.info("")

    # Analyze each image
    results = {}
    for img_path in images:
        result = await analyze_image(img_path)
        results[img_path.name] = result

    # Comparison summary
    if len(results) >= 2:
        logger.info("=" * 70)
        logger.info("COMPARISON SUMMARY")
        logger.info("=" * 70)
        logger.info(f"  {'Image':<30s} {'Score':>8s}  {'Verdict'}")
        logger.info(f"  {'-' * 30} {'-' * 8}  {'-' * 30}")

        for name, r in results.items():
            if r.score >= 0.9:
                v = "GOLD"
            elif r.score >= 0.7:
                v = "VERIFIED"
            elif r.score >= 0.4:
                v = "QUARANTINE"
            else:
                v = "REJECTED"
            logger.info(f"  {name:<30s} {r.score:>8.4f}  {v}")

        # Layer-by-layer comparison
        logger.info("")
        all_layers = set()
        for r in results.values():
            for lr in r.layer_results:
                all_layers.add(lr.layer_name)

        header = f"  {'Layer':<25s}"
        for name in results:
            header += f"  {name[:15]:>15s}"
        logger.info(header)

        for layer in sorted(all_layers):
            row = f"  {layer:<25s}"
            for name, r in results.items():
                lr = next((l for l in r.layer_results if l.layer_name == layer), None)
                if lr:
                    row += f"  {lr.score:>15.4f}"
                else:
                    row += f"  {'N/A':>15s}"
            logger.info(row)

        logger.info("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
