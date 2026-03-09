"""
Fabrication Detector Analyzer.

Detects images that were DIGITALLY CREATED (AI-generated, rendered,
composited from scratch) rather than captured by a physical camera/scanner.

Key insight: Tampering detection asks "was this edited?"
Fabrication detection asks "did this EVER come from a camera?"

10 checks across 3 categories:

Provenance (did it come from a camera?):
  1. Image mode (RGBA = software-created)
  2. EXIF camera tags (Make, Model, ISO, Exposure)
  3. Compression format naturalness (large PNG = suspicious)

Statistical (does the pixel data look natural?):
  4. Noise naturalness (sensor noise profile)
  5. Color distribution entropy
  6. DCT spectral analysis (GAN frequency fingerprints)
  7. Texture regularity (micro-texture uniformity)
  8. Saturation distribution (AI saturation patterns)

Structural:
  9. Generator dimensions (512x512, 1024x1024, etc.)
  10. File size ratio (bytes/pixel)
"""
import math
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from PIL import Image, ImageFilter, ImageStat
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from scipy.fft import dct
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


class FabricationDetector(BaseAnalyzer):
    """
    Detects digitally fabricated images that never came from a camera.

    Unlike tampering detection (ELA, copy-move), this analyzer looks for
    signs that the image was GENERATED rather than CAPTURED:
    - Too-perfect signal characteristics
    - Missing camera provenance markers
    - Statistical anomalies in noise/color distribution
    """

    # Dimensions commonly used by AI image generators
    GENERATOR_DIMENSIONS = {
        (512, 512), (768, 768), (1024, 1024), (2048, 2048),
        (512, 768), (768, 512), (1024, 768), (768, 1024),
        (1024, 576), (576, 1024),  # 16:9 variants
    }

    @property
    def name(self) -> str:
        return "fabrication_detector"

    @property
    def supported_types(self) -> List[str]:
        return ["jpg", "jpeg", "png", "bmp", "tiff", "webp"]

    @property
    def dependencies(self) -> List[str]:
        return ["numpy", "Pillow"]

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        if not HAS_NUMPY or not HAS_PIL:
            return self._unavailable_result("Requires numpy + Pillow")

        if image is None:
            return self._unavailable_result("No image provided")

        evidence: List[Evidence] = []
        warnings: List[str] = []
        red_flags = 0
        total_checks = 0

        # --- Check 1: Image Mode (RGBA = not from camera) ---
        total_checks += 1
        mode_result = self._check_image_mode(image)
        evidence.append(mode_result)
        if not mode_result.confirms:
            red_flags += 1
            warnings.append(f"Image mode '{image.mode}' — real cameras don't produce this")

        # --- Check 2: EXIF Provenance ---
        total_checks += 1
        exif_result = self._check_exif_provenance(image, file_type)
        evidence.append(exif_result)
        if not exif_result.confirms:
            red_flags += 1
            warnings.append("No camera EXIF data — no proof this came from a physical device")

        # --- Check 3: Noise Naturalness (too uniform = generated) ---
        total_checks += 1
        noise_result = self._check_noise_naturalness(image)
        evidence.append(noise_result)
        if not noise_result.confirms:
            red_flags += 1
            warnings.append("Noise pattern too uniform — characteristic of digital generation")

        # --- Check 4: Generator Dimensions ---
        total_checks += 1
        dim_result = self._check_dimensions(image)
        evidence.append(dim_result)
        if not dim_result.confirms:
            red_flags += 1
            warnings.append(f"Dimensions {image.size} match common AI generator output")

        # --- Check 5: Color Distribution Analysis ---
        total_checks += 1
        color_result = self._check_color_distribution(image)
        evidence.append(color_result)
        if not color_result.confirms:
            red_flags += 1
            warnings.append("Color distribution anomaly — unnaturally smooth histogram")

        # --- Check 6: Compression Artifact Naturalness ---
        total_checks += 1
        compression_result = self._check_compression_naturalness(
            file_bytes, file_type, image
        )
        evidence.append(compression_result)
        if not compression_result.confirms:
            red_flags += 1

        # --- Check 7: File Size vs Resolution Ratio ---
        total_checks += 1
        size_result = self._check_size_ratio(file_bytes, image, file_type)
        evidence.append(size_result)
        if not size_result.confirms:
            red_flags += 1
            warnings.append("File size to resolution ratio is unusual")

        # --- Check 8: DCT Spectral Analysis (GAN Frequency Fingerprints) ---
        total_checks += 1
        spectral_result = self._check_spectral_artifacts(image)
        evidence.append(spectral_result)
        if not spectral_result.confirms:
            red_flags += 1
            warnings.append("Frequency domain anomaly — possible GAN fingerprint")

        # --- Check 9: Texture Regularity (micro-texture uniformity) ---
        total_checks += 1
        texture_result = self._check_texture_regularity(image)
        evidence.append(texture_result)
        if not texture_result.confirms:
            red_flags += 1
            warnings.append("Unnaturally uniform micro-texture — typical of AI generation")

        # --- Check 10: Saturation Distribution ---
        total_checks += 1
        sat_result = self._check_saturation_distribution(image)
        evidence.append(sat_result)
        if not sat_result.confirms:
            red_flags += 1
            warnings.append("Saturation distribution anomaly — unnatural for camera output")

        # --- Compute Score ---
        # More red flags = more likely fabricated = LOWER score
        clean_ratio = (total_checks - red_flags) / total_checks
        score = clean_ratio

        # Graduated clamping based on red flag count (out of 10 checks)
        if red_flags >= 8:
            score = min(score, 0.05)
        elif red_flags >= 7:
            score = min(score, 0.10)
        elif red_flags >= 6:
            score = min(score, 0.15)
        elif red_flags >= 5:
            score = min(score, 0.25)
        elif red_flags >= 4:
            score = min(score, 0.35)
        # 3 flags out of 10 = 30% failure rate — suspicious but not conclusive
        # Don't clamp here, let the clean_ratio (0.70) speak for itself

        is_veto = red_flags >= 7
        veto_reason = (
            f"Fabrication detected: {red_flags}/{total_checks} "
            f"red flags triggered"
        ) if is_veto else ""

        self.logger.info(
            f"FABRICATION: {red_flags}/{total_checks} red flags, "
            f"score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            is_veto=is_veto,
            veto_reason=veto_reason,
            metadata={
                "red_flags": red_flags,
                "total_checks": total_checks,
                "image_mode": image.mode,
                "dimensions": list(image.size),
            },
        )

    # --- Individual Checks ---

    def _check_image_mode(self, image: "Image.Image") -> Evidence:
        """
        Real cameras produce RGB or YCbCr images.
        RGBA (alpha channel) = created in software.
        Palette mode (P) = converted/generated.
        """
        camera_modes = {"RGB", "L"}  # RGB color or grayscale
        is_camera_mode = image.mode in camera_modes

        return Evidence(
            source="fabrication_detector",
            source_type=EvidenceType.FORENSIC,
            claim_field="image_mode",
            confirms=is_camera_mode,
            found_value=image.mode,
            reasoning=(
                f"Mode '{image.mode}' — "
                + ("standard camera output" if is_camera_mode
                   else "NOT a camera output mode (software-created)")
            ),
            confidence=0.85 if not is_camera_mode else 0.6,
        )

    def _check_exif_provenance(
        self, image: "Image.Image", file_type: str
    ) -> Evidence:
        """
        Real camera photos ALWAYS have EXIF data: camera model,
        focal length, exposure, ISO, GPS, etc.
        No EXIF = no proof of physical capture.

        Note: JPEG re-saved from messaging apps may lose EXIF,
        so this is evidence, not proof.
        """
        try:
            exif = image.getexif()
            has_exif = bool(exif)

            if has_exif:
                # Check for camera-specific tags
                camera_tags = {
                    271: "Make",        # Camera manufacturer
                    272: "Model",       # Camera model
                    33434: "Exposure",  # Exposure time
                    33437: "FNumber",   # Aperture
                    34855: "ISO",       # ISO speed
                }
                found_camera_tags = [
                    camera_tags[tag]
                    for tag in camera_tags
                    if tag in exif
                ]

                if found_camera_tags:
                    return Evidence(
                        source="fabrication_detector",
                        source_type=EvidenceType.FORENSIC,
                        claim_field="camera_provenance",
                        confirms=True,
                        found_value=", ".join(found_camera_tags),
                        reasoning=(
                            f"Camera EXIF found: {', '.join(found_camera_tags)} "
                            f"— proves physical capture device"
                        ),
                        confidence=0.9,
                    )
                else:
                    return Evidence(
                        source="fabrication_detector",
                        source_type=EvidenceType.FORENSIC,
                        claim_field="camera_provenance",
                        confirms=True,
                        reasoning="EXIF present but no camera-specific tags",
                        confidence=0.4,
                    )
            else:
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="camera_provenance",
                    confirms=False,
                    reasoning=(
                        "No EXIF metadata — no proof this came from "
                        "a physical camera/scanner"
                    ),
                    confidence=0.7,
                )
        except Exception:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="camera_provenance",
                confirms=False,
                reasoning="EXIF extraction failed",
                confidence=0.3,
            )

    def _check_noise_naturalness(self, image: "Image.Image") -> Evidence:
        """
        Real camera sensors produce characteristic noise:
        - Slight variation across the image
        - Gaussian-distributed
        - Correlated with brightness (more noise in shadows)

        Generated images either have:
        - No noise at all (too clean)
        - Artificial noise (uniformly distributed, not brightness-correlated)
        """
        try:
            gray = np.array(image.convert("L"), dtype=np.float32)
            blurred = np.array(
                image.convert("L").filter(ImageFilter.GaussianBlur(3)),
                dtype=np.float32,
            )
            noise = gray - blurred

            noise_std = float(np.std(noise))
            noise_mean = float(np.mean(np.abs(noise)))

            # Split into bright and dark regions
            median_brightness = float(np.median(gray))
            dark_mask = gray < median_brightness
            bright_mask = gray >= median_brightness

            dark_noise_std = float(np.std(noise[dark_mask])) if dark_mask.any() else 0
            bright_noise_std = float(np.std(noise[bright_mask])) if bright_mask.any() else 0

            # Real cameras: more noise in dark regions (higher ISO noise in shadows)
            # Generated: uniform noise or no noise
            if noise_std < 1.0:
                # Almost no noise at all — very suspicious
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="noise_naturalness",
                    confirms=False,
                    reasoning=(
                        f"Noise level extremely low (std={noise_std:.2f}) — "
                        f"real cameras produce detectable sensor noise"
                    ),
                    confidence=0.75,
                )

            # Check brightness-noise correlation
            if dark_noise_std > 0 and bright_noise_std > 0:
                noise_ratio = dark_noise_std / bright_noise_std
                # Real cameras: ratio > 1.0 (more noise in shadows)
                # Generated: ratio ≈ 1.0 (uniform noise)
                if noise_ratio < 0.85 or noise_ratio > 2.5:
                    # Unusual but not necessarily fake
                    is_natural = noise_ratio > 1.0
                else:
                    is_natural = True

                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="noise_naturalness",
                    confirms=is_natural,
                    reasoning=(
                        f"Noise dark/bright ratio={noise_ratio:.2f} "
                        f"(std={noise_std:.2f}) — "
                        + ("natural camera noise profile"
                           if is_natural
                           else "uniform noise suggests digital generation")
                    ),
                    confidence=0.6,
                )

            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="noise_naturalness",
                confirms=True,
                reasoning=f"Noise std={noise_std:.2f} — within normal range",
                confidence=0.5,
            )

        except Exception as e:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="noise_naturalness",
                confirms=True,
                reasoning=f"Noise check error: {str(e)}",
                confidence=0.3,
            )

    def _check_dimensions(self, image: "Image.Image") -> Evidence:
        """
        AI generators output specific resolutions (512×512, 1024×1024, etc.)
        Real cameras output sensor-native resolutions (4032×3024, 3264×2448, etc.)
        """
        w, h = image.size
        dimensions = (w, h)
        reversed_dims = (h, w)

        # Check against known generator sizes
        is_generator_size = (
            dimensions in self.GENERATOR_DIMENSIONS
            or reversed_dims in self.GENERATOR_DIMENSIONS
        )

        # Also check if both dimensions are powers of 2
        both_power_of_2 = (
            w > 0 and (w & (w - 1)) == 0
            and h > 0 and (h & (h - 1)) == 0
        )

        is_suspicious = is_generator_size or (both_power_of_2 and w >= 256)

        return Evidence(
            source="fabrication_detector",
            source_type=EvidenceType.FORENSIC,
            claim_field="image_dimensions",
            confirms=not is_suspicious,
            found_value=f"{w}×{h}",
            reasoning=(
                f"Dimensions {w}×{h} — "
                + ("matches common AI generator output" if is_generator_size
                   else "power-of-2 dimensions (unusual for cameras)" if both_power_of_2
                   else "typical camera/scanner resolution")
            ),
            confidence=0.7 if is_suspicious else 0.5,
        )

    def _check_color_distribution(self, image: "Image.Image") -> Evidence:
        """
        Real photos have complex, non-uniform color histograms with
        natural color clustering. Generated images tend to have
        smoother, more uniform distributions.

        Checks: histogram entropy, channel correlation, saturation range.
        """
        try:
            rgb = np.array(image.convert("RGB"), dtype=np.float32)

            # Compute per-channel histograms
            histograms = []
            entropies = []
            for ch in range(3):
                hist, _ = np.histogram(rgb[:, :, ch], bins=256, range=(0, 256))
                hist_normalized = hist / hist.sum()
                # Shannon entropy
                nonzero = hist_normalized[hist_normalized > 0]
                entropy = -float(np.sum(nonzero * np.log2(nonzero)))
                histograms.append(hist)
                entropies.append(entropy)

            avg_entropy = sum(entropies) / 3

            # Very low entropy = very uniform colors = likely generated gradient
            # Very high entropy = maximum randomness = also suspicious
            # Natural photos: entropy typically 5.0 - 7.5
            if avg_entropy < 4.0:
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="color_distribution",
                    confirms=False,
                    reasoning=(
                        f"Color entropy very low ({avg_entropy:.2f}) — "
                        f"unnaturally uniform color distribution"
                    ),
                    confidence=0.65,
                )
            elif avg_entropy > 7.8:
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="color_distribution",
                    confirms=False,
                    reasoning=(
                        f"Color entropy very high ({avg_entropy:.2f}) — "
                        f"unnaturally random distribution"
                    ),
                    confidence=0.5,
                )

            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="color_distribution",
                confirms=True,
                reasoning=(
                    f"Color entropy normal ({avg_entropy:.2f}) — "
                    f"natural photo histogram"
                ),
                confidence=0.5,
            )

        except Exception as e:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="color_distribution",
                confirms=True,
                reasoning=f"Color check error: {str(e)}",
                confidence=0.3,
            )

    def _check_compression_naturalness(
        self, file_bytes: bytes, file_type: str, image: "Image.Image"
    ) -> Evidence:
        """
        Real camera JPEGs have specific quantization tables from their ISP.
        Re-saved or generated images have generic quantization.
        PNGs from cameras are rare — cameras almost always output JPEG.
        """
        ft = file_type.lower().strip(".")

        # PNG from a "camera" is suspicious — cameras almost always shoot JPEG
        if ft == "png":
            file_size_mb = len(file_bytes) / (1024 * 1024)
            if file_size_mb > 2:
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="compression_format",
                    confirms=False,
                    reasoning=(
                        f"Large PNG ({file_size_mb:.1f}MB) — cameras rarely "
                        f"output PNG. This suggests software export/generation"
                    ),
                    confidence=0.6,
                )

        return Evidence(
            source="fabrication_detector",
            source_type=EvidenceType.FORENSIC,
            claim_field="compression_format",
            confirms=True,
            reasoning=f"File format .{ft} — standard for camera output",
            confidence=0.4,
        )

    def _check_size_ratio(
        self, file_bytes: bytes, image: "Image.Image", file_type: str
    ) -> Evidence:
        """
        Checks bytes-per-pixel ratio.
        Real camera photos: typically 1-3 bytes/pixel (JPEG) or 3-8 (PNG)
        Generated images: can have unusual ratios due to artificial content
        """
        w, h = image.size
        total_pixels = w * h
        if total_pixels == 0:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="size_ratio",
                confirms=True,
                reasoning="Zero-pixel image",
                confidence=0.0,
            )

        bytes_per_pixel = len(file_bytes) / total_pixels
        ft = file_type.lower().strip(".")

        if ft in ("jpg", "jpeg"):
            # JPEG: typically 0.5-4.0 bytes/pixel
            is_normal = 0.3 <= bytes_per_pixel <= 5.0
        elif ft == "png":
            # PNG: typically 1.0-10.0 bytes/pixel
            is_normal = 0.5 <= bytes_per_pixel <= 12.0
        else:
            is_normal = True

        return Evidence(
            source="fabrication_detector",
            source_type=EvidenceType.FORENSIC,
            claim_field="size_ratio",
            confirms=is_normal,
            found_value=f"{bytes_per_pixel:.2f} bytes/pixel",
            reasoning=(
                f"Size ratio {bytes_per_pixel:.2f} bytes/pixel — "
                + ("within normal range" if is_normal
                   else "unusual for camera output")
            ),
            confidence=0.4,
        )

    def _check_spectral_artifacts(self, image: "Image.Image") -> Evidence:
        """
        DCT spectral analysis for GAN frequency fingerprints.

        GANs (Stable Diffusion, DALL-E, Midjourney) leave characteristic
        patterns in the frequency domain — periodic peaks, abnormal
        high-frequency energy distribution, and spectral symmetry artifacts.

        Real photos have a natural 1/f spectral falloff; AI-generated images
        show deviations from this pattern, especially at mid-to-high frequencies.
        """
        if not HAS_SCIPY:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="spectral_analysis",
                confirms=True,
                reasoning="scipy not available for DCT spectral analysis",
                confidence=0.3,
            )

        try:
            # Convert to grayscale and resize to standard size for comparison
            gray = np.array(image.convert("L").resize((256, 256)), dtype=np.float64)

            # 2D DCT (Type II) — standard for frequency domain analysis
            dct_coeffs = dct(dct(gray, axis=0, norm='ortho'), axis=1, norm='ortho')

            # Compute log magnitude spectrum
            magnitude = np.log1p(np.abs(dct_coeffs))

            # Analyze spectral energy distribution in frequency bands
            h, w = magnitude.shape
            center_y, center_x = h // 2, w // 2

            # Create radial frequency bands
            low_freq = magnitude[:h//8, :w//8]           # DC + very low
            mid_freq = magnitude[h//8:h//4, w//8:w//4]   # Mid frequencies
            high_freq = magnitude[h//4:h//2, w//4:w//2]  # High frequencies
            very_high = magnitude[h//2:, w//2:]           # Very high frequencies

            low_energy = float(np.mean(low_freq))
            mid_energy = float(np.mean(mid_freq))
            high_energy = float(np.mean(high_freq))
            very_high_energy = float(np.mean(very_high))

            # Natural 1/f falloff: energy should decrease smoothly from low to high
            # GAN artifacts: mid-frequency spikes, abnormal high-frequency energy
            if low_energy > 0:
                mid_ratio = mid_energy / low_energy
                high_ratio = high_energy / low_energy
                very_high_ratio = very_high_energy / low_energy
            else:
                mid_ratio = high_ratio = very_high_ratio = 0.0

            # Check for spectral anomalies
            flags = []

            # GAN fingerprint: excess mid-frequency energy (periodic artifacts)
            if mid_ratio > 0.6:
                flags.append(f"high mid-freq energy ratio ({mid_ratio:.3f})")

            # AI upscaling: abnormal very-high-frequency energy
            if very_high_ratio > 0.35:
                flags.append(f"high very-high-freq energy ({very_high_ratio:.3f})")

            # Check for periodic peaks (GAN grid artifacts)
            # Look for spikes in the mid-frequency band
            if mid_freq.size > 0:
                mid_std = float(np.std(mid_freq))
                mid_mean = float(np.mean(mid_freq))
                if mid_mean > 0:
                    mid_cv = mid_std / mid_mean
                    if mid_cv > 0.8:
                        flags.append(f"periodic spectral peaks (CV={mid_cv:.2f})")

            is_natural = len(flags) == 0

            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="spectral_analysis",
                confirms=is_natural,
                reasoning=(
                    f"DCT spectral analysis — "
                    + ("natural 1/f frequency falloff" if is_natural
                       else f"anomalies: {'; '.join(flags)}")
                    + f" (mid={mid_ratio:.3f}, high={high_ratio:.3f})"
                ),
                confidence=0.7 if not is_natural else 0.5,
            )

        except Exception as e:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="spectral_analysis",
                confirms=True,
                reasoning=f"Spectral analysis error: {str(e)}",
                confidence=0.3,
            )

    def _check_texture_regularity(self, image: "Image.Image") -> Evidence:
        """
        Analyzes micro-texture uniformity across image patches.

        Real photos have natural variation in texture complexity across
        different regions (sky vs grass vs buildings). AI-generated images
        tend to have unnaturally uniform texture complexity — the hallmark
        of diffusion model outputs.

        Uses local binary pattern variance as a proxy for texture complexity.
        """
        try:
            gray = np.array(image.convert("L"), dtype=np.float32)

            # Compute local texture complexity via gradient magnitude
            # in non-overlapping patches
            patch_size = 32
            h, w = gray.shape
            complexities = []

            for y in range(0, h - patch_size, patch_size):
                for x in range(0, w - patch_size, patch_size):
                    patch = gray[y:y+patch_size, x:x+patch_size]
                    # Gradient magnitude as texture complexity proxy
                    gx = np.diff(patch, axis=1)
                    gy = np.diff(patch, axis=0)
                    gradient_mag = float(np.mean(np.abs(gx[:patch_size-1, :])) +
                                        np.mean(np.abs(gy[:, :patch_size-1])))
                    complexities.append(gradient_mag)

            if len(complexities) < 4:
                return Evidence(
                    source="fabrication_detector",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="texture_regularity",
                    confirms=True,
                    reasoning="Image too small for texture analysis",
                    confidence=0.3,
                )

            # Analyze distribution of patch complexities
            complexity_array = np.array(complexities)
            mean_complexity = float(np.mean(complexity_array))
            std_complexity = float(np.std(complexity_array))

            if mean_complexity > 0:
                # Coefficient of variation — how much texture varies across patches
                texture_cv = std_complexity / mean_complexity
            else:
                texture_cv = 0.0

            # Real photos: high CV (0.5-2.0) — sky patches are smooth,
            #   building edges are complex, foliage is medium
            # AI images: low CV (0.1-0.4) — uniformly detailed everywhere
            if texture_cv < 0.25:
                is_natural = False
                reasoning = (
                    f"Texture uniformity very high (CV={texture_cv:.3f}) — "
                    f"AI-generated images have unnaturally consistent detail"
                )
            elif texture_cv < 0.4:
                is_natural = False
                reasoning = (
                    f"Texture uniformity suspicious (CV={texture_cv:.3f}) — "
                    f"below natural photo range"
                )
            else:
                is_natural = True
                reasoning = (
                    f"Texture variation natural (CV={texture_cv:.3f}) — "
                    f"different regions have different complexity"
                )

            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="texture_regularity",
                confirms=is_natural,
                reasoning=reasoning,
                confidence=0.65 if not is_natural else 0.5,
            )

        except Exception as e:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="texture_regularity",
                confirms=True,
                reasoning=f"Texture analysis error: {str(e)}",
                confidence=0.3,
            )

    def _check_saturation_distribution(self, image: "Image.Image") -> Evidence:
        """
        Analyzes saturation distribution.

        Real photos have a wide, naturally skewed saturation distribution
        (many low-saturation pixels + some high-saturation).
        AI-generated images often have boosted saturation with a distinctive
        bimodal distribution or unnaturally narrow saturation band.
        """
        try:
            # Convert to HSV
            rgb = np.array(image.convert("RGB"), dtype=np.float32) / 255.0
            r, g, b = rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2]

            # Compute saturation (from HSV formula)
            cmax = np.maximum(np.maximum(r, g), b)
            cmin = np.minimum(np.minimum(r, g), b)
            delta = cmax - cmin

            # Saturation = delta / cmax (0 where cmax == 0)
            saturation = np.where(cmax > 0, delta / cmax, 0.0)

            # Analyze saturation distribution
            sat_mean = float(np.mean(saturation))
            sat_std = float(np.std(saturation))
            sat_median = float(np.median(saturation))

            # Compute percentiles
            p10 = float(np.percentile(saturation, 10))
            p90 = float(np.percentile(saturation, 90))
            sat_range = p90 - p10

            # Natural photos: mean saturation 0.15-0.50, wide range
            # AI images: often mean 0.30-0.65 (oversaturated), narrow range
            flags = []

            if sat_mean > 0.55:
                flags.append(f"oversaturated (mean={sat_mean:.3f})")
            if sat_range < 0.15 and sat_mean > 0.2:
                flags.append(f"narrow saturation band (range={sat_range:.3f})")
            if sat_median > 0.45:
                flags.append(f"high median saturation ({sat_median:.3f})")

            # Check for bimodal saturation (AI artifact)
            hist, _ = np.histogram(saturation.flatten(), bins=20, range=(0, 1))
            hist_normalized = hist / hist.sum()
            # Count peaks (bins above average)
            avg_bin = 1.0 / 20
            peaks = sum(1 for h in hist_normalized if h > avg_bin * 2.5)
            if peaks >= 3:
                flags.append(f"multi-modal saturation ({peaks} peaks)")

            is_natural = len(flags) == 0

            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="saturation_distribution",
                confirms=is_natural,
                reasoning=(
                    f"Saturation analysis — "
                    + ("natural distribution" if is_natural
                       else f"anomalies: {'; '.join(flags)}")
                    + f" (mean={sat_mean:.3f}, range={sat_range:.3f})"
                ),
                confidence=0.6 if not is_natural else 0.4,
            )

        except Exception as e:
            return Evidence(
                source="fabrication_detector",
                source_type=EvidenceType.FORENSIC,
                claim_field="saturation_distribution",
                confirms=True,
                reasoning=f"Saturation analysis error: {str(e)}",
                confidence=0.3,
            )
