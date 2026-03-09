"""
Ground Truth Forensic Test Suite
================================
Generates REAL tampered + clean document pairs and measures detection accuracy.

Target: 90% True Positive rate, <5% False Positive rate.

Test Categories:
1. Image tampering (ELA, noise, copy-move, lighting)
2. PDF manipulation (incremental saves, producer spoofing, JS injection)
3. Fabricated/AI-style images (no EXIF, generator dimensions, flat noise)
4. Metadata stripping and forgery
5. File structure attacks (magic byte mismatch, embedded executables)
6. Arithmetic fraud (invoice totals)
7. Schema injection attacks
8. Domain logic violations
9. Attestation attacks (GPS spoofing, replay, stale timestamps)
10. Full pipeline end-to-end scenarios
"""

import asyncio
import hashlib
import io
import json
import logging
import os
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.verification.analyzers.ela import ELAAnalyzer
from core.verification.analyzers.noise import NoiseAnalyzer
from core.verification.analyzers.copy_move import CopyMoveAnalyzer
from core.verification.analyzers.lighting import LightingAnalyzer
from core.verification.analyzers.metadata_forensics import MetadataForensicsAnalyzer
from core.verification.analyzers.file_structure import FileStructureAnalyzer
from core.verification.analyzers.pdf_forensics import PDFForensicsAnalyzer
from core.verification.analyzers.fabrication_detector import FabricationDetector
from core.verification.forensic_integrity import ForensicIntegrityAnalyzer
from core.verification.consistency import ConsistencyAnalyzer
from core.verification.schema_gatekeeper import SchemaGatekeeper
from core.verification.logic_triangulation import LogicTriangulationEngine
from core.verification.attestation import AttestationVerifier, AttestationBundle
from core.verification.adversarial import AdversarialChallengeAgent
from core.verification.verification_stack import VerificationOrchestrator
from core.verification.models import (
    DataClaim, DataSchema, FieldSpec, FieldType, Evidence, EvidenceType,
)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("GroundTruth")


# ============================================================
# DOCUMENT GENERATORS
# ============================================================

class DocumentFactory:
    """Generates paired clean + tampered test documents."""

    @staticmethod
    def create_clean_photo(width=800, height=600, seed=42) -> bytes:
        """Creates a realistic-looking photo with natural characteristics."""
        rng = np.random.RandomState(seed)
        # Create a natural-looking gradient scene (sky + ground)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)

        # Sky gradient (top half)
        for y in range(height // 2):
            ratio = y / (height // 2)
            img_array[y, :] = [
                int(135 + 50 * ratio),  # R
                int(206 - 30 * ratio),  # G
                int(235 - 20 * ratio),  # B
            ]

        # Ground (bottom half) with texture
        for y in range(height // 2, height):
            ratio = (y - height // 2) / (height // 2)
            base = [int(34 + 60 * ratio), int(139 - 40 * ratio), int(34 + 30 * ratio)]
            img_array[y, :] = base

        # Add natural noise (sensor noise simulation)
        noise = rng.normal(0, 8, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        # Add some "objects" - rectangles as buildings
        img = Image.fromarray(img_array)
        draw = ImageDraw.Draw(img)
        for i in range(3):
            x = 100 + i * 250
            h = rng.randint(100, 250)
            color = tuple(rng.randint(80, 200, 3).tolist())
            draw.rectangle([x, height // 2 - h, x + 80, height // 2], fill=color)

        # Save as JPEG with realistic EXIF-like compression
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        return buf.getvalue()

    @staticmethod
    def create_clean_photo_with_exif(width=800, height=600, seed=42) -> bytes:
        """Creates a photo that includes EXIF metadata like a real camera."""
        rng = np.random.RandomState(seed)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)

        # Natural scene
        for y in range(height):
            for x_block in range(0, width, 40):
                base_r = int(100 + 80 * np.sin(y / 50.0 + x_block / 100.0))
                base_g = int(120 + 60 * np.cos(y / 60.0))
                base_b = int(140 + 50 * np.sin(x_block / 80.0))
                img_array[y, x_block:x_block+40] = [
                    np.clip(base_r, 0, 255),
                    np.clip(base_g, 0, 255),
                    np.clip(base_b, 0, 255),
                ]

        # Add sensor noise
        noise = rng.normal(0, 6, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        img = Image.fromarray(img_array)

        # Add EXIF data
        from PIL.ExifTags import Base as ExifBase
        import piexif

        exif_dict = {
            "0th": {
                piexif.ImageIFD.Make: b"Canon",
                piexif.ImageIFD.Model: b"Canon EOS R5",
                piexif.ImageIFD.Software: b"Canon DPP 4.0",
                piexif.ImageIFD.DateTime: b"2026:03:01 14:30:00",
            },
            "Exif": {
                piexif.ExifIFD.DateTimeOriginal: b"2026:03:01 14:30:00",
                piexif.ExifIFD.ExposureTime: (1, 250),
                piexif.ExifIFD.FNumber: (56, 10),
                piexif.ExifIFD.ISOSpeedRatings: 400,
                piexif.ExifIFD.FocalLength: (50, 1),
            },
        }
        exif_bytes = piexif.dump(exif_dict)

        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85, exif=exif_bytes)
        return buf.getvalue()

    @staticmethod
    def create_tampered_photo_region_edit(width=800, height=600, seed=42) -> bytes:
        """
        Creates a photo then edits a rectangular region from a differently
        compressed source. This simulates real Photoshop editing: copy a region
        from one image (compressed at different quality), paste into another.
        ELA detects the compression level mismatch.
        """
        rng = np.random.RandomState(seed)

        # Start with a natural photo
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            ratio = y / height
            img_array[y, :] = [
                int(135 + 80 * ratio),
                int(180 - 50 * ratio),
                int(200 - 30 * ratio),
            ]
        noise = rng.normal(0, 6, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        # Save at HIGH quality first (Q95) — this bakes in Q95 artifacts
        img = Image.fromarray(img_array)
        buf1 = io.BytesIO()
        img.save(buf1, format='JPEG', quality=95)

        # Re-open and paste fresh content (simulates Photoshop edit)
        img1 = Image.open(buf1)
        img1_array = np.array(img1)

        # Create a realistic edit: paste a bright region with text-like
        # high-contrast content (like replacing text on an invoice)
        patch = np.full((200, 300, 3), [240, 240, 210], dtype=np.uint8)
        for i in range(6):
            y_off = 20 + i * 30
            patch[y_off:y_off+15, 15:285] = [30 + i * 15, 30, 30]
        patch_noise = rng.normal(0, 3, patch.shape).astype(np.int16)
        patch = np.clip(patch.astype(np.int16) + patch_noise, 0, 255).astype(np.uint8)

        y_start, x_start = 200, 250
        img1_array[y_start:y_start+200, x_start:x_start+300] = patch

        # Save at LOWER quality (Q70) — creates double-compression artifacts
        # Background: Q95→Q70 (double compressed, high ELA)
        # Edit: raw→Q70 (single compressed, different ELA pattern)
        result = Image.fromarray(img1_array)
        buf2 = io.BytesIO()
        result.save(buf2, format='JPEG', quality=70)

        return buf2.getvalue()

    @staticmethod
    def create_tampered_photo_double_compress(width=800, height=600, seed=42) -> bytes:
        """
        Double-compression artifact: save at q95, edit, save at q75.
        Creates visible ELA differences in the un-edited background.
        """
        rng = np.random.RandomState(seed)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            img_array[y, :] = [int(100 + 100 * y / height)] * 3
        noise = rng.normal(0, 8, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        img = Image.fromarray(img_array)

        # First save at high quality
        buf1 = io.BytesIO()
        img.save(buf1, format='JPEG', quality=95)

        # Re-open, modify a small area, save at low quality
        img2 = Image.open(buf1)
        draw = ImageDraw.Draw(img2)
        draw.rectangle([100, 100, 300, 200], fill=(255, 0, 0))  # Obvious edit

        buf2 = io.BytesIO()
        img2.save(buf2, format='JPEG', quality=70)

        return buf2.getvalue()

    @staticmethod
    def create_copy_move_image(width=800, height=600, seed=42) -> bytes:
        """Creates an image with a cloned TEXTURED region (copy-move forgery).

        Real copy-move clones complex content (faces, text, objects) not solid
        colors. The cloned region must have high pixel variance to be detectable.
        """
        rng = np.random.RandomState(seed)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)

        # Create a richly textured background
        for y in range(height):
            for x in range(width):
                img_array[y, x] = [
                    int(100 + 30 * np.sin(x / 20.0) + 20 * np.cos(y / 15.0)),
                    int(120 + 40 * np.cos(y / 25.0) + 15 * np.sin(x / 30.0)),
                    int(80 + 50 * np.sin((x + y) / 30.0)),
                ]
        noise = rng.normal(0, 8, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        # Add a distinctive textured object (checkerboard pattern = high variance)
        for y in range(100, 200):
            for x in range(100, 220):
                checker = ((x // 8) + (y // 8)) % 2
                if checker:
                    img_array[y, x] = [200, 60, 60]
                else:
                    img_array[y, x] = [60, 180, 60]

        # COPY-MOVE: clone that textured region to a distant location
        source_region = img_array[100:200, 100:220].copy()
        img_array[350:450, 500:620] = source_region

        img = Image.fromarray(img_array)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    @staticmethod
    def create_composite_image(width=800, height=600, seed=42) -> bytes:
        """Creates a composite from two different 'camera sources' (different noise profiles)."""
        rng = np.random.RandomState(seed)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)

        # Left half: low noise (camera 1, well-lit)
        left_noise = rng.normal(0, 3, (height, width // 2, 3)).astype(np.int16)
        img_array[:, :width//2] = np.clip(
            np.full((height, width // 2, 3), 150, dtype=np.int16) + left_noise,
            0, 255
        ).astype(np.uint8)

        # Right half: high noise (camera 2, low light)
        right_noise = rng.normal(0, 25, (height, width // 2, 3)).astype(np.int16)
        img_array[:, width//2:] = np.clip(
            np.full((height, width // 2, 3), 150, dtype=np.int16) + right_noise,
            0, 255
        ).astype(np.uint8)

        img = Image.fromarray(img_array)
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=90)
        return buf.getvalue()

    @staticmethod
    def create_lighting_composite(width=800, height=600) -> bytes:
        """Creates an image with inconsistent lighting (composite indicator)."""
        img_array = np.zeros((height, width, 3), dtype=np.uint8)

        # Top-left: very bright
        img_array[:height//2, :width//2] = [240, 240, 240]
        # Top-right: very dark
        img_array[:height//2, width//2:] = [20, 20, 20]
        # Bottom-left: medium
        img_array[height//2:, :width//2] = [120, 120, 120]
        # Bottom-right: very bright again (inconsistent with adjacent dark region)
        img_array[height//2:, width//2:] = [230, 230, 230]

        # Add some noise to make it not completely flat
        noise = np.random.RandomState(42).normal(0, 5, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        img = Image.fromarray(img_array)
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=90)
        return buf.getvalue()

    @staticmethod
    def create_ai_generated_image(width=512, height=512, seed=42) -> bytes:
        """Mimics AI-generated image characteristics: no EXIF, generator dimensions, uniform noise."""
        rng = np.random.RandomState(seed)
        # Very smooth gradients (no sensor noise)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                img_array[y, x] = [
                    int(128 + 127 * np.sin(x / 50.0) * np.cos(y / 50.0)),
                    int(128 + 127 * np.cos(x / 40.0 + y / 60.0)),
                    int(128 + 127 * np.sin((x + y) / 70.0)),
                ]

        # Minimal uniform noise (NOT natural sensor noise)
        noise = rng.normal(0, 0.5, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)

        img = Image.fromarray(img_array, 'RGB')
        # Save as PNG (AI generators often output PNG)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    @staticmethod
    def create_ai_generated_rgba(width=1024, height=1024, seed=42) -> bytes:
        """AI image with RGBA mode and generator dimensions."""
        rng = np.random.RandomState(seed)
        img_array = rng.randint(50, 200, (height, width, 4), dtype=np.uint8)
        img_array[:, :, 3] = 255  # Full alpha
        img = Image.fromarray(img_array, 'RGBA')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    @staticmethod
    def create_clean_pdf() -> bytes:
        """Creates a clean PDF using PyMuPDF (fitz)."""
        import fitz
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)  # A4
        page.insert_text(
            (72, 72),
            "INVOICE #INV-2026-001\n\n"
            "Item: Widget A\n"
            "Quantity: 10\n"
            "Unit Price: $25.00\n"
            "Subtotal: $250.00\n"
            "GST (15%): $37.50\n"
            "Total: $287.50",
            fontsize=12,
        )
        buf = io.BytesIO()
        doc.save(buf)
        doc.close()
        return buf.getvalue()

    @staticmethod
    def create_edited_pdf() -> bytes:
        """Creates a PDF with multiple %%EOF markers (simulates incremental saves)."""
        import fitz

        # Original document
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((72, 72), "Original invoice: Total $100.00", fontsize=12)
        buf1 = io.BytesIO()
        doc.save(buf1)
        doc.close()

        # Re-open and edit (save as new to avoid incremental error, then manually
        # inject multiple %%EOF markers to simulate what incremental saves look like)
        buf1.seek(0)
        doc2 = fitz.open(stream=buf1.read(), filetype="pdf")
        page2 = doc2[0]
        page2.insert_text((72, 120), "AMENDED: Total $500.00", fontsize=12, color=(1, 0, 0))
        buf2 = io.BytesIO()
        doc2.save(buf2)
        doc2.close()

        # Append extra %%EOF markers to simulate incremental saves
        pdf_data = buf2.getvalue()
        # Add a second %%EOF (the PDF forensics analyzer counts these)
        pdf_data += b"\n%%EOF\n"
        # Add a third for good measure (4+ triggers -0.20 penalty)
        pdf_data += b"\n%%EOF\n"
        pdf_data += b"\n%%EOF\n"

        return pdf_data

    @staticmethod
    def create_js_injected_pdf() -> bytes:
        """Creates a PDF with embedded JavaScript (malicious)."""
        # Build a minimal PDF with /JavaScript action manually
        pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\\('Malicious!\\')) >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000074 00000 n
0000000129 00000 n
0000000206 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
296
%%EOF
"""
        return pdf_content

    @staticmethod
    def create_photoshop_pdf() -> bytes:
        """Creates a PDF with Photoshop as producer (suspicious)."""
        pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Producer (Adobe Photoshop CC 2024) /Creator (Adobe Photoshop CC 2024) >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000190 00000 n
trailer
<< /Size 5 /Root 1 0 R /Info 4 0 R >>
startxref
296
%%EOF
"""
        return pdf_content

    @staticmethod
    def create_disguised_executable() -> bytes:
        """Creates a file that claims to be JPEG but starts with MZ (PE executable)."""
        # Windows PE header
        pe_header = b'MZ' + b'\x00' * 100
        # Append some JPEG-looking data after
        pe_header += b'\xff\xd8\xff\xe0' + b'\x00' * 200
        return pe_header

    @staticmethod
    def create_polyglot_image() -> bytes:
        """Creates a valid JPEG with embedded ZIP archive."""
        # Create a minimal JPEG
        img = Image.new('RGB', (100, 100), (128, 128, 128))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        jpeg_data = buf.getvalue()

        # Append a ZIP signature after the JPEG data
        zip_sig = b'PK\x03\x04' + b'\x00' * 100
        return jpeg_data + zip_sig

    @staticmethod
    def create_stripped_metadata_photo(width=800, height=600, seed=42) -> bytes:
        """Creates a photo with ALL metadata stripped (suspicious)."""
        rng = np.random.RandomState(seed)
        img_array = rng.randint(50, 200, (height, width, 3), dtype=np.uint8)

        # Smooth it to look more natural
        img = Image.fromarray(img_array)
        img = img.filter(ImageFilter.GaussianBlur(radius=2))

        # Add noise back
        img_array = np.array(img)
        noise = rng.normal(0, 8, img_array.shape).astype(np.int16)
        img_array = np.clip(img_array.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(img_array)

        # Save without any EXIF
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        return buf.getvalue()


# ============================================================
# TEST RUNNER
# ============================================================

class GroundTruthResults:
    """Tracks test results and computes accuracy metrics."""

    def __init__(self):
        self.results = defaultdict(list)  # category -> [(expected, actual, score, detail)]
        self.total_tests = 0
        self.passed = 0
        self.failed = 0

    def record(self, category: str, test_name: str, expected_bad: bool,
               detected_bad: bool, score: float, detail: str = ""):
        """
        Record a test result.
        expected_bad: True if the document IS tampered/fake
        detected_bad: True if the system DETECTED it as suspicious (score < threshold)
        """
        self.total_tests += 1
        is_correct = (expected_bad == detected_bad)
        if is_correct:
            self.passed += 1
        else:
            self.failed += 1

        self.results[category].append({
            "test": test_name,
            "expected_bad": expected_bad,
            "detected_bad": detected_bad,
            "correct": is_correct,
            "score": score,
            "detail": detail,
            "classification": self._classify(expected_bad, detected_bad),
        })

    def _classify(self, expected_bad, detected_bad):
        if expected_bad and detected_bad:
            return "TP"  # True positive: caught real fraud
        elif expected_bad and not detected_bad:
            return "FN"  # False negative: missed real fraud
        elif not expected_bad and detected_bad:
            return "FP"  # False positive: flagged clean document
        else:
            return "TN"  # True negative: passed clean document

    def print_report(self):
        print("\n" + "=" * 80)
        print("GROUND TRUTH FORENSIC TEST REPORT")
        print("=" * 80)

        overall_tp = overall_fp = overall_tn = overall_fn = 0

        for category, tests in sorted(self.results.items()):
            tp = sum(1 for t in tests if t["classification"] == "TP")
            fp = sum(1 for t in tests if t["classification"] == "FP")
            tn = sum(1 for t in tests if t["classification"] == "TN")
            fn = sum(1 for t in tests if t["classification"] == "FN")
            overall_tp += tp
            overall_fp += fp
            overall_tn += tn
            overall_fn += fn

            total = len(tests)
            correct = sum(1 for t in tests if t["correct"])
            accuracy = correct / total * 100 if total > 0 else 0
            tp_rate = tp / (tp + fn) * 100 if (tp + fn) > 0 else 100
            fp_rate = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0

            status = "PASS" if (tp_rate >= 90 and fp_rate <= 5) else "FAIL"
            marker = "[OK]" if status == "PASS" else "[!!]"

            print(f"\n{marker} {category}")
            print(f"    Accuracy: {accuracy:.0f}%  |  TP Rate: {tp_rate:.0f}%  |  FP Rate: {fp_rate:.0f}%")
            print(f"    TP={tp}  FP={fp}  TN={tn}  FN={fn}")

            for t in tests:
                icon = "v" if t["correct"] else "X"
                print(f"    [{icon}] {t['test']}: score={t['score']:.3f} "
                      f"({t['classification']}) {t['detail']}")

        # Overall
        print("\n" + "=" * 80)
        total_all = overall_tp + overall_fp + overall_tn + overall_fn
        overall_accuracy = (overall_tp + overall_tn) / total_all * 100 if total_all > 0 else 0
        overall_tp_rate = overall_tp / (overall_tp + overall_fn) * 100 if (overall_tp + overall_fn) > 0 else 100
        overall_fp_rate = overall_fp / (overall_fp + overall_tn) * 100 if (overall_fp + overall_tn) > 0 else 0

        print(f"OVERALL: {total_all} tests")
        print(f"  Accuracy:       {overall_accuracy:.1f}%")
        print(f"  True Positive:  {overall_tp_rate:.1f}%  (target >= 90%)")
        print(f"  False Positive: {overall_fp_rate:.1f}%  (target <= 5%)")
        print(f"  TP={overall_tp}  FP={overall_fp}  TN={overall_tn}  FN={overall_fn}")

        target_met = overall_tp_rate >= 90 and overall_fp_rate <= 5
        print(f"\n  TARGET {'MET' if target_met else 'NOT MET'}: "
              f"TP >= 90% = {'YES' if overall_tp_rate >= 90 else 'NO'}, "
              f"FP <= 5% = {'YES' if overall_fp_rate <= 5 else 'NO'}")
        print("=" * 80)

        return {
            "accuracy": overall_accuracy,
            "tp_rate": overall_tp_rate,
            "fp_rate": overall_fp_rate,
            "tp": overall_tp, "fp": overall_fp,
            "tn": overall_tn, "fn": overall_fn,
            "target_met": target_met,
        }


# ============================================================
# HELPERS
# ============================================================

def _load_image(file_bytes: bytes):
    """Load PIL Image from bytes."""
    return Image.open(io.BytesIO(file_bytes))


async def _run_analyzer(analyzer, file_bytes, file_type, metadata=None):
    """Run an analyzer with proper PIL image loading."""
    img = None
    if file_type in ("jpg", "jpeg", "png", "bmp", "tiff", "webp"):
        try:
            img = _load_image(file_bytes)
        except Exception:
            pass
    return await analyzer.analyze(file_bytes, file_type, image=img, metadata=metadata)


# ============================================================
# INDIVIDUAL ANALYZER TESTS
# ============================================================

async def test_ela_analyzer(results: GroundTruthResults):
    """Test ELA against clean vs tampered images."""
    analyzer = ELAAnalyzer()
    THRESHOLD = 0.60

    # Clean photo
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("ELA", "Clean photo", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Clean photo (different seed)
    clean2 = DocumentFactory.create_clean_photo(seed=99)
    r = await _run_analyzer(analyzer, clean2, "jpeg")
    results.record("ELA", "Clean photo (seed 99)", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Tampered: region edit at different quality
    tampered1 = DocumentFactory.create_tampered_photo_region_edit()
    r = await _run_analyzer(analyzer, tampered1, "jpeg")
    results.record("ELA", "Region edit (quality mismatch)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Tampered: double compression
    tampered2 = DocumentFactory.create_tampered_photo_double_compress()
    r = await _run_analyzer(analyzer, tampered2, "jpeg")
    results.record("ELA", "Double compression with edit", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Tampered: region edit with different seed
    tampered3 = DocumentFactory.create_tampered_photo_region_edit(seed=77)
    r = await _run_analyzer(analyzer, tampered3, "jpeg")
    results.record("ELA", "Region edit (seed 77)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_noise_analyzer(results: GroundTruthResults):
    """Test noise pattern against clean vs composite images."""
    analyzer = NoiseAnalyzer()
    THRESHOLD = 0.60

    # Clean photo (uniform noise)
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("Noise", "Clean photo (uniform noise)", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Composite: two different noise profiles
    composite = DocumentFactory.create_composite_image()
    r = await _run_analyzer(analyzer, composite, "jpeg")
    results.record("Noise", "Composite (2 noise profiles)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Composite: different seed
    composite2 = DocumentFactory.create_composite_image(seed=77)
    r = await _run_analyzer(analyzer, composite2, "jpeg")
    results.record("Noise", "Composite (seed 77)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_copy_move_analyzer(results: GroundTruthResults):
    """Test copy-move detection against clean vs cloned images."""
    analyzer = CopyMoveAnalyzer()
    THRESHOLD = 0.60

    # Clean photo (no cloned regions)
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("CopyMove", "Clean photo", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Copy-move forgery
    cloned = DocumentFactory.create_copy_move_image()
    r = await _run_analyzer(analyzer, cloned, "png")
    results.record("CopyMove", "Cloned region", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Copy-move with different seed
    cloned2 = DocumentFactory.create_copy_move_image(seed=88)
    r = await _run_analyzer(analyzer, cloned2, "png")
    results.record("CopyMove", "Cloned region (seed 88)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_lighting_analyzer(results: GroundTruthResults):
    """Test lighting consistency against clean vs composite images."""
    analyzer = LightingAnalyzer()
    THRESHOLD = 0.60

    # Clean photo (consistent lighting gradient)
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("Lighting", "Clean photo", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Inconsistent lighting composite
    bad_lighting = DocumentFactory.create_lighting_composite()
    r = await _run_analyzer(analyzer, bad_lighting, "jpeg")
    results.record("Lighting", "Inconsistent lighting composite", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_metadata_analyzer(results: GroundTruthResults):
    """Test metadata forensics."""
    analyzer = MetadataForensicsAnalyzer()
    THRESHOLD = 0.55

    # Clean JPEG with camera EXIF
    try:
        clean_exif = DocumentFactory.create_clean_photo_with_exif()
        r = await _run_analyzer(analyzer, clean_exif, "jpeg")
        results.record("Metadata", "Clean JPEG (camera EXIF)", expected_bad=False,
                       detected_bad=(r.score < THRESHOLD),
                       score=r.score, detail=str(r.metadata))
    except ImportError:
        # piexif not available, use plain photo
        clean = DocumentFactory.create_clean_photo()
        r = await _run_analyzer(analyzer, clean, "jpeg")
        results.record("Metadata", "Clean JPEG (no EXIF)", expected_bad=False,
                       detected_bad=(r.score < THRESHOLD),
                       score=r.score, detail=str(r.metadata))

    # Stripped metadata photo (no EXIF at all)
    stripped = DocumentFactory.create_stripped_metadata_photo()
    r = await _run_analyzer(analyzer, stripped, "jpeg")
    results.record("Metadata", "Stripped metadata (no EXIF)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_file_structure_analyzer(results: GroundTruthResults):
    """Test file structure validation."""
    analyzer = FileStructureAnalyzer()
    THRESHOLD = 0.60

    # Clean JPEG
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("FileStructure", "Clean JPEG", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Clean PDF
    clean_pdf = DocumentFactory.create_clean_pdf()
    r = await _run_analyzer(analyzer, clean_pdf, "pdf")
    results.record("FileStructure", "Clean PDF", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Disguised executable (.exe pretending to be .jpg)
    disguised = DocumentFactory.create_disguised_executable()
    r = await _run_analyzer(analyzer, disguised, "jpeg")
    results.record("FileStructure", "EXE disguised as JPEG", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Polyglot (valid JPEG with embedded ZIP)
    polyglot = DocumentFactory.create_polyglot_image()
    r = await _run_analyzer(analyzer, polyglot, "jpeg")
    results.record("FileStructure", "JPEG+ZIP polyglot", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # PNG claiming to be JPEG
    png_data = DocumentFactory.create_ai_generated_image()
    r = await _run_analyzer(analyzer, png_data, "jpeg")
    results.record("FileStructure", "PNG claiming to be JPEG", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_pdf_forensics(results: GroundTruthResults):
    """Test PDF forensic analysis."""
    analyzer = PDFForensicsAnalyzer()
    THRESHOLD = 0.55

    # Clean PDF
    clean = DocumentFactory.create_clean_pdf()
    r = await _run_analyzer(analyzer, clean, "pdf")
    results.record("PDFForensics", "Clean PDF", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Edited PDF (incremental saves)
    edited = DocumentFactory.create_edited_pdf()
    r = await _run_analyzer(analyzer, edited, "pdf")
    results.record("PDFForensics", "Edited PDF (incremental save)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # JS-injected PDF
    js_pdf = DocumentFactory.create_js_injected_pdf()
    r = await _run_analyzer(analyzer, js_pdf, "pdf")
    results.record("PDFForensics", "JavaScript injected PDF", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # Photoshop-produced PDF
    ps_pdf = DocumentFactory.create_photoshop_pdf()
    r = await _run_analyzer(analyzer, ps_pdf, "pdf")
    results.record("PDFForensics", "Photoshop-produced PDF", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_fabrication_detector(results: GroundTruthResults):
    """Test AI-generated / fabricated image detection."""
    analyzer = FabricationDetector()
    THRESHOLD = 0.60

    # Clean photo (camera-like)
    clean = DocumentFactory.create_clean_photo()
    r = await _run_analyzer(analyzer, clean, "jpeg")
    results.record("Fabrication", "Clean photo (camera-like)", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # AI-generated (512x512, no EXIF, flat noise, PNG)
    ai_img = DocumentFactory.create_ai_generated_image()
    r = await _run_analyzer(analyzer, ai_img, "png")
    results.record("Fabrication", "AI-generated 512x512 PNG", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))

    # AI-generated RGBA (1024x1024)
    ai_rgba = DocumentFactory.create_ai_generated_rgba()
    r = await _run_analyzer(analyzer, ai_rgba, "png")
    results.record("Fabrication", "AI-generated RGBA 1024x1024", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=str(r.metadata))


async def test_consistency_analyzer(results: GroundTruthResults):
    """Test arithmetic and cross-field consistency."""
    analyzer = ConsistencyAnalyzer()
    THRESHOLD = 0.55

    # Clean invoice (math checks out)
    clean_schema = DataSchema(
        name="invoice", version="1.0",
        fields=[
            FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True),
            FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="subtotal", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="tax", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="total", field_type=FieldType.FLOAT, required=True),
        ],
    )
    clean_payload = {
        "quantity": 10, "unit_price": 25.0,
        "subtotal": 250.0, "tax": 37.50, "total": 287.50,
    }
    r = analyzer.check(clean_payload, clean_schema)
    results.record("Consistency", "Clean invoice (math correct)", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"checks={len(r.evidence)}")

    # Fraudulent invoice (total doesn't add up)
    fraud_payload = {
        "quantity": 10, "unit_price": 25.0,
        "subtotal": 250.0, "tax": 37.50, "total": 500.00,  # Should be 287.50
    }
    r = analyzer.check(fraud_payload, clean_schema)
    results.record("Consistency", "Fraudulent total (250+37.5 != 500)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"checks={len(r.evidence)}")

    # Fraudulent quantity × price
    fraud2 = {
        "quantity": 5, "unit_price": 10.0,
        "subtotal": 250.0,  # Should be 50.0
        "tax": 37.50, "total": 287.50,
    }
    r = analyzer.check(fraud2, clean_schema)
    results.record("Consistency", "Fraudulent subtotal (5*10 != 250)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"checks={len(r.evidence)}")

    # Future invoice date
    date_schema = DataSchema(
        name="dated_doc", version="1.0",
        fields=[
            FieldSpec(name="invoice_date", field_type=FieldType.DATE, required=True),
            FieldSpec(name="amount", field_type=FieldType.FLOAT, required=True),
        ],
    )
    future = {"invoice_date": "2028-01-01", "amount": 100.0}
    r = analyzer.check(future, date_schema)
    results.record("Consistency", "Future invoice date", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"checks={len(r.evidence)}")

    # Negative price
    neg = {"quantity": 10, "unit_price": -5.0, "subtotal": -50.0, "tax": -7.50, "total": -57.50}
    r = analyzer.check(neg, clean_schema)
    results.record("Consistency", "Negative prices", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"checks={len(r.evidence)}")


async def test_schema_gatekeeper(results: GroundTruthResults):
    """Test injection detection and schema validation."""
    gatekeeper = SchemaGatekeeper()
    THRESHOLD = 0.55

    schema = DataSchema(
        name="test", version="1.0",
        fields=[
            FieldSpec(name="name", field_type=FieldType.STRING, required=True),
            FieldSpec(name="email", field_type=FieldType.EMAIL, required=True),
            FieldSpec(name="amount", field_type=FieldType.FLOAT, required=True),
        ],
    )

    # Clean payload
    clean = {"name": "John Smith", "email": "john@example.com", "amount": 100.0}
    r = gatekeeper.check(clean, schema)
    results.record("Schema", "Clean payload", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail="")

    # XSS injection
    xss = {"name": "<script>alert('xss')</script>", "email": "john@example.com", "amount": 100.0}
    r = gatekeeper.check(xss, schema)
    results.record("Schema", "XSS injection", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail=f"veto={r.is_veto}")

    # SQL injection
    sql = {"name": "'; DROP TABLE users; --", "email": "john@example.com", "amount": 100.0}
    r = gatekeeper.check(sql, schema)
    results.record("Schema", "SQL injection", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail=f"veto={r.is_veto}")

    # Template injection
    tmpl = {"name": "{{config.__class__}}", "email": "john@example.com", "amount": 100.0}
    r = gatekeeper.check(tmpl, schema)
    results.record("Schema", "Template injection", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail=f"veto={r.is_veto}")

    # Python injection
    pyinj = {"name": "__import__('os').system('rm -rf /')", "email": "john@example.com", "amount": 100.0}
    r = gatekeeper.check(pyinj, schema)
    results.record("Schema", "Python injection", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail=f"veto={r.is_veto}")

    # Invalid email
    bad_email = {"name": "John", "email": "not-an-email", "amount": 100.0}
    r = gatekeeper.check(bad_email, schema)
    results.record("Schema", "Invalid email format", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail="")

    # Missing required field
    missing = {"name": "John", "amount": 100.0}
    r = gatekeeper.check(missing, schema)
    results.record("Schema", "Missing required email field", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail="")


async def test_domain_logic(results: GroundTruthResults):
    """Test domain logic violations."""
    engine = LogicTriangulationEngine()
    THRESHOLD = 0.55

    # Clean claims (NZ electricity price in range)
    clean_claims = [
        DataClaim(field_name="electricity_price_kwh", value=0.28, source="payload"),
        DataClaim(field_name="quantity", value=100, source="payload"),
        DataClaim(field_name="weight_kg", value=25.5, source="payload"),
    ]
    r = await engine.triangulate(clean_claims, {"region": "NZ"})
    results.record("DomainLogic", "Valid NZ electricity price", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Impossible electricity price
    bad_claims = [
        DataClaim(field_name="electricity_price_kwh", value=50.0, source="payload"),
    ]
    r = await engine.triangulate(bad_claims, {"region": "NZ"})
    results.record("DomainLogic", "Impossible electricity price ($50/kWh)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Negative weight
    neg_claims = [
        DataClaim(field_name="weight_kg", value=-100, source="payload"),
    ]
    r = await engine.triangulate(neg_claims, {"region": "NZ"})
    results.record("DomainLogic", "Negative weight", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Placeholder value
    placeholder_claims = [
        DataClaim(field_name="company_name", value="test", source="payload"),
    ]
    r = await engine.triangulate(placeholder_claims, {})
    results.record("DomainLogic", "Placeholder value 'test'", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Future historical date
    future_claims = [
        DataClaim(field_name="manufacture_date", value="2030-01-01", source="payload"),
    ]
    r = await engine.triangulate(future_claims, {})
    results.record("DomainLogic", "Future manufacture date", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")


async def test_attestation(results: GroundTruthResults):
    """Test attestation attacks."""
    verifier = AttestationVerifier()
    THRESHOLD = 0.50

    dummy_bytes = b"test-document-content"

    # Clean attestation
    clean_bundle = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        timestamp=datetime.utcnow().isoformat(),
        device_fingerprint="device-abc-123",
        depth_map_available=True,
        depth_variance=0.15,
        file_hash=hashlib.sha256(b"real-document").hexdigest(),
    )
    r = await verifier.verify(clean_bundle)
    results.record("Attestation", "Clean attestation (Auckland GPS)", expected_bad=False,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Null Island GPS
    null_island = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=0.0,
        gps_longitude=0.0,
        timestamp=datetime.utcnow().isoformat(),
        file_hash=hashlib.sha256(b"doc1").hexdigest(),
    )
    r = await verifier.verify(null_island)
    results.record("Attestation", "Null Island GPS (0,0)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Invalid GPS coordinates
    invalid_gps = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=999.0,
        gps_longitude=-999.0,
        timestamp=datetime.utcnow().isoformat(),
        file_hash=hashlib.sha256(b"doc2").hexdigest(),
    )
    r = await verifier.verify(invalid_gps)
    results.record("Attestation", "Invalid GPS (999, -999)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail=f"veto={r.is_veto}")

    # Stale timestamp (48h old)
    stale = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        timestamp=(datetime.utcnow() - timedelta(hours=48)).isoformat(),
        file_hash=hashlib.sha256(b"doc3").hexdigest(),
    )
    r = await verifier.verify(stale)
    results.record("Attestation", "Stale timestamp (48h old)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Screen photo (flat depth)
    screen = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        timestamp=datetime.utcnow().isoformat(),
        depth_map_available=True,
        depth_variance=0.001,  # Flat = screen photo
        file_hash=hashlib.sha256(b"doc4").hexdigest(),
    )
    r = await verifier.verify(screen)
    results.record("Attestation", "Screen photo (flat depth)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD),
                   score=r.score, detail="")

    # Replay attack (same hash) — use identical timestamps so provenance hash matches
    replay_hash = hashlib.sha256(b"replay-test-doc").hexdigest()
    fixed_ts = datetime.utcnow().isoformat()
    bundle1 = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=-36.8485, gps_longitude=174.7633,
        timestamp=fixed_ts,
        file_hash=replay_hash,
    )
    await verifier.verify(bundle1)  # First submission
    bundle2 = AttestationBundle(
        file_bytes=dummy_bytes,
        gps_latitude=-36.8485, gps_longitude=174.7633,
        timestamp=fixed_ts,  # Same timestamp = same provenance hash
        file_hash=replay_hash,
    )
    r = await verifier.verify(bundle2)  # Replay
    results.record("Attestation", "Replay attack (same hash)", expected_bad=True,
                   detected_bad=(r.score < THRESHOLD or r.is_veto),
                   score=r.score, detail=f"veto={r.is_veto}")


async def test_full_pipeline(results: GroundTruthResults):
    """Test end-to-end pipeline with real fraud scenarios."""
    orchestrator = VerificationOrchestrator()
    THRESHOLD_REJECT = 0.40  # Below this = REJECTED
    THRESHOLD_PASS = 0.70    # Above this = VERIFIED

    # Scenario 1: Clean invoice (should VERIFY)
    clean_schema = DataSchema(
        name="invoice", version="1.0",
        fields=[
            FieldSpec(name="vendor", field_type=FieldType.STRING, required=True),
            FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True),
            FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="subtotal", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="tax", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="total", field_type=FieldType.FLOAT, required=True),
        ],
    )
    clean_payload = {
        "vendor": "Acme Supplies Ltd",
        "quantity": 10, "unit_price": 25.0,
        "subtotal": 250.0, "tax": 37.50, "total": 287.50,
    }
    v = await orchestrator.verify(clean_payload, schema=clean_schema)
    results.record("Pipeline", "Clean invoice (correct math)",
                   expected_bad=False,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 2: Fraudulent invoice (bad math + XSS)
    fraud_payload = {
        "vendor": "<script>alert('xss')</script>",
        "quantity": 10, "unit_price": 25.0,
        "subtotal": 250.0, "tax": 37.50, "total": 999.99,
    }
    v = await orchestrator.verify(fraud_payload, schema=clean_schema)
    results.record("Pipeline", "Fraudulent invoice (bad math + XSS)",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 3: Clean PDF attachment
    clean_pdf = DocumentFactory.create_clean_pdf()
    v = await orchestrator.verify(
        {"document_type": "invoice"},
        attachments=[{"bytes": clean_pdf, "type": "pdf", "name": "invoice.pdf"}],
    )
    results.record("Pipeline", "Clean PDF attachment",
                   expected_bad=False,
                   detected_bad=(v.verdict == "REJECTED"),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 4: Edited PDF attachment
    edited_pdf = DocumentFactory.create_edited_pdf()
    v = await orchestrator.verify(
        {"document_type": "invoice"},
        attachments=[{"bytes": edited_pdf, "type": "pdf", "name": "invoice.pdf"}],
    )
    results.record("Pipeline", "Edited PDF (incremental save)",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 5: JS-injected PDF (malicious)
    js_pdf = DocumentFactory.create_js_injected_pdf()
    v = await orchestrator.verify(
        {"document_type": "certificate"},
        attachments=[{"bytes": js_pdf, "type": "pdf", "name": "cert.pdf"}],
    )
    results.record("Pipeline", "JS-injected PDF (malicious)",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 6: Tampered photo attachment
    tampered = DocumentFactory.create_tampered_photo_region_edit()
    v = await orchestrator.verify(
        {"document_type": "receipt"},
        attachments=[{"bytes": tampered, "type": "jpeg", "name": "receipt.jpg"}],
    )
    results.record("Pipeline", "Tampered photo (region edit)",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 7: AI-generated fake document
    ai_img = DocumentFactory.create_ai_generated_image()
    v = await orchestrator.verify(
        {"document_type": "certificate"},
        attachments=[{"bytes": ai_img, "type": "png", "name": "cert.png"}],
    )
    results.record("Pipeline", "AI-generated fake image",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 8: Disguised executable
    exe = DocumentFactory.create_disguised_executable()
    v = await orchestrator.verify(
        {"document_type": "photo"},
        attachments=[{"bytes": exe, "type": "jpeg", "name": "photo.jpg"}],
    )
    results.record("Pipeline", "Disguised executable",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 9: Clean data with clean attestation
    clean_attestation = AttestationBundle(
        file_bytes=b"clean-pipeline-doc",
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        timestamp=datetime.utcnow().isoformat(),
        device_fingerprint="device-xyz",
        depth_map_available=True,
        depth_variance=0.2,
        file_hash=hashlib.sha256(b"clean-doc-pipeline").hexdigest(),
    )
    v = await orchestrator.verify(
        {"vendor": "Real Company", "amount": 100.0},
        attestation_bundle=clean_attestation,
    )
    results.record("Pipeline", "Clean data with attestation",
                   expected_bad=False,
                   detected_bad=(v.verdict == "REJECTED"),
                   score=v.score,
                   detail=f"verdict={v.verdict}")

    # Scenario 10: Data with null island GPS
    bad_attestation = AttestationBundle(
        file_bytes=b"bad-gps-doc",
        gps_latitude=0.0, gps_longitude=0.0,
        timestamp=datetime.utcnow().isoformat(),
        file_hash=hashlib.sha256(b"bad-gps-unique").hexdigest(),
    )
    v = await orchestrator.verify(
        {"vendor": "Suspicious Ltd", "amount": 50.0},
        attestation_bundle=bad_attestation,
    )
    results.record("Pipeline", "Data with null island GPS",
                   expected_bad=True,
                   detected_bad=(v.verdict in ["REJECTED", "QUARANTINE"]),
                   score=v.score,
                   detail=f"verdict={v.verdict}")


# ============================================================
# MAIN
# ============================================================

async def main():
    results = GroundTruthResults()

    print("=" * 80)
    print("GROUND TRUTH FORENSIC TEST SUITE")
    print("Generating test documents and measuring detection accuracy...")
    print("=" * 80)

    # Check if piexif is available for EXIF tests
    try:
        import piexif
        has_piexif = True
    except ImportError:
        has_piexif = False
        print("\n[WARN] piexif not installed - skipping EXIF-based tests")
        print("       Install with: pip install piexif\n")

    # Run all test categories
    test_functions = [
        ("ELA Analyzer", test_ela_analyzer),
        ("Noise Pattern Analyzer", test_noise_analyzer),
        ("Copy-Move Analyzer", test_copy_move_analyzer),
        ("Lighting Analyzer", test_lighting_analyzer),
        ("Metadata Forensics", test_metadata_analyzer),
        ("File Structure", test_file_structure_analyzer),
        ("PDF Forensics", test_pdf_forensics),
        ("Fabrication Detector", test_fabrication_detector),
        ("Consistency Analyzer", test_consistency_analyzer),
        ("Schema Gatekeeper", test_schema_gatekeeper),
        ("Domain Logic", test_domain_logic),
        ("Attestation", test_attestation),
        ("Full Pipeline (E2E)", test_full_pipeline),
    ]

    for name, func in test_functions:
        print(f"\n--- Testing: {name} ---")
        try:
            await func(results)
            print(f"    Done.")
        except Exception as e:
            print(f"    ERROR: {e}")
            import traceback
            traceback.print_exc()

    # Print comprehensive report
    report = results.print_report()
    return report


if __name__ == "__main__":
    report = asyncio.run(main())
    sys.exit(0 if report["target_met"] else 1)
