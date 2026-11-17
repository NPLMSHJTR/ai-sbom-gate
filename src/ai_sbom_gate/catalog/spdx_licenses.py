"""SPDX and AI-specific license registry with expression resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_sbom_gate.models import LicenseCategory


@dataclass(frozen=True)
class LicenseProfile:
    """Normalized legal metadata for an open-source, data, or AI model license."""

    spdx_id: str
    name: str
    category: LicenseCategory
    commercial_allowed: bool
    requires_source_disclosure: bool
    requires_notice: bool
    non_commercial: bool
    has_special_clauses: bool
    url: str
    notes: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "spdx_id": self.spdx_id,
            "name": self.name,
            "category": self.category.value,
            "commercial_allowed": self.commercial_allowed,
            "requires_source_disclosure": self.requires_source_disclosure,
            "requires_notice": self.requires_notice,
            "non_commercial": self.non_commercial,
            "has_special_clauses": self.has_special_clauses,
            "url": self.url,
            "notes": self.notes,
        }


_PROFILES: list[LicenseProfile] = [
    LicenseProfile(
        spdx_id="MIT",
        name="MIT License",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opensource.org/licenses/MIT",
        notes="Permissive; retain copyright and license notice.",
    ),
    LicenseProfile(
        spdx_id="Apache-2.0",
        name="Apache License 2.0",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://www.apache.org/licenses/LICENSE-2.0",
        notes="Permissive with explicit patent grant; retain NOTICE and LICENSE.",
    ),
    LicenseProfile(
        spdx_id="BSD-3-Clause",
        name="BSD 3-Clause 'New' or 'Revised' License",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opensource.org/licenses/BSD-3-Clause",
        notes="Permissive; retain copyright notice and non-endorsement clause.",
    ),
    LicenseProfile(
        spdx_id="BSD-2-Clause",
        name="BSD 2-Clause 'Simplified' License",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opensource.org/licenses/BSD-2-Clause",
    ),
    LicenseProfile(
        spdx_id="ISC",
        name="ISC License",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opensource.org/licenses/ISC",
    ),
    LicenseProfile(
        spdx_id="PSF-2.0",
        name="Python Software Foundation License 2.0",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://docs.python.org/3/license.html",
    ),
    LicenseProfile(
        spdx_id="0BSD",
        name="BSD Zero Clause License",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=False,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opensource.org/licenses/0BSD",
    ),
    LicenseProfile(
        spdx_id="Unlicense",
        name="The Unlicense",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=False,
        non_commercial=False,
        has_special_clauses=False,
        url="https://unlicense.org/",
    ),
    LicenseProfile(
        spdx_id="CC0-1.0",
        name="Creative Commons Zero v1.0 Universal",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=False,
        non_commercial=False,
        has_special_clauses=False,
        url="https://creativecommons.org/publicdomain/zero/1.0/",
    ),
    LicenseProfile(
        spdx_id="CC-BY-4.0",
        name="Creative Commons Attribution 4.0 International",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://creativecommons.org/licenses/by/4.0/",
        notes="Commercial use allowed with proper attribution.",
    ),
    LicenseProfile(
        spdx_id="ODC-BY-1.0",
        name="Open Data Commons Attribution License v1.0",
        category=LicenseCategory.PERMISSIVE,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://opendatacommons.org/licenses/by/1-0/",
    ),
    LicenseProfile(
        spdx_id="MPL-2.0",
        name="Mozilla Public License 2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=False,
        url="https://www.mozilla.org/en-US/MPL/2.0/",
        notes="File-level weak copyleft; modifications to MPL files must remain under MPL-2.0.",
    ),
    LicenseProfile(
        spdx_id="LGPL-2.1-only",
        name="GNU Lesser General Public License v2.1",
        category=LicenseCategory.WEAK_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html",
        notes="Weak copyleft; requires dynamic relinking or source for the LGPL component.",
    ),
    LicenseProfile(
        spdx_id="LGPL-3.0-only",
        name="GNU Lesser General Public License v3.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.gnu.org/licenses/lgpl-3.0.html",
        notes="Weak copyleft; requires relinking capability or LGPL component source disclosure.",
    ),
    LicenseProfile(
        spdx_id="CC-BY-SA-4.0",
        name="Creative Commons Attribution-ShareAlike 4.0",
        category=LicenseCategory.SHARE_ALIKE,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://creativecommons.org/licenses/by-sa/4.0/",
        notes="Adaptations/derivative datasets must be shared under the same CC-BY-SA-4.0 license.",
    ),
    LicenseProfile(
        spdx_id="GPL-2.0-only",
        name="GNU General Public License v2.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.gnu.org/licenses/old-licenses/gpl-2.0.html",
        notes="Strong copyleft; incompatible with Apache-2.0 and closed-source distribution.",
    ),
    LicenseProfile(
        spdx_id="GPL-3.0-only",
        name="GNU General Public License v3.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.gnu.org/licenses/gpl-3.0.html",
        notes="Strong copyleft; linked/combined works distributed externally must be GPL-3.0.",
    ),
    LicenseProfile(
        spdx_id="AGPL-3.0-only",
        name="GNU Affero General Public License v3.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        commercial_allowed=True,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.gnu.org/licenses/agpl-3.0.html",
        notes="Network copyleft; even SaaS/API network interaction triggers full source disclosure.",
    ),
    LicenseProfile(
        spdx_id="CC-BY-NC-4.0",
        name="Creative Commons Attribution-NonCommercial 4.0",
        category=LicenseCategory.NON_COMMERCIAL,
        commercial_allowed=False,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=True,
        has_special_clauses=True,
        url="https://creativecommons.org/licenses/by-nc/4.0/",
        notes="Strictly non-commercial; prohibited in commercial products and commercial model training.",
    ),
    LicenseProfile(
        spdx_id="CC-BY-NC-SA-4.0",
        name="Creative Commons Attribution-NonCommercial-ShareAlike 4.0",
        category=LicenseCategory.NON_COMMERCIAL,
        commercial_allowed=False,
        requires_source_disclosure=True,
        requires_notice=True,
        non_commercial=True,
        has_special_clauses=True,
        url="https://creativecommons.org/licenses/by-nc-sa/4.0/",
        notes="Non-commercial and ShareAlike.",
    ),
    LicenseProfile(
        spdx_id="FLUX-1-dev-Non-Commercial",
        name="FLUX.1 [dev] Non-Commercial License",
        category=LicenseCategory.NON_COMMERCIAL,
        commercial_allowed=False,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=True,
        has_special_clauses=True,
        url="https://huggingface.co/black-forest-labs/FLUX.1-dev/blob/main/LICENSE.md",
        notes="Prohibits commercial use of weights and commercial SaaS hosting without separate license.",
    ),
    LicenseProfile(
        spdx_id="Qwen-Research",
        name="Tongyi Qianwen RESEARCH LICENSE AGREEMENT",
        category=LicenseCategory.NON_COMMERCIAL,
        commercial_allowed=False,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=True,
        has_special_clauses=True,
        url="https://huggingface.co/Qwen/Qwen-7B-Chat/blob/main/LICENSE",
        notes="Legacy Qwen v1 research-only license (non-commercial unless separate authorization obtained).",
    ),
    LicenseProfile(
        spdx_id="LMSYS-Non-Commercial",
        name="LMSYS Terms of Use (Non-Commercial)",
        category=LicenseCategory.NON_COMMERCIAL,
        commercial_allowed=False,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=True,
        has_special_clauses=True,
        url="https://huggingface.co/datasets/lmsys/lmsys-chat-1m",
        notes="Non-commercial research use only.",
    ),
    LicenseProfile(
        spdx_id="Llama-3.1-Community",
        name="Llama 3.1 Community License Agreement",
        category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.llama.com/llama3_1/license/",
        notes="Requires 'Built with Llama' attribution, Acceptable Use Policy, and separate license if >700M MAU.",
    ),
    LicenseProfile(
        spdx_id="Llama-3.2-Community",
        name="Llama 3.2 Community License Agreement",
        category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://www.llama.com/llama3_2/license/",
        notes="Requires 'Built with Llama' notice, AUP compliance, and separate license if >700M MAU.",
    ),
    LicenseProfile(
        spdx_id="Gemma-Terms",
        name="Gemma Terms of Use",
        category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://ai.google.dev/gemma/terms",
        notes="Permits commercial use subject to Gemma Prohibited Use Policy and redistribution notice pass-through.",
    ),
    LicenseProfile(
        spdx_id="OpenRAIL-M",
        name="CreativeML OpenRAIL-M License",
        category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://huggingface.co/spaces/CompVis/stable-diffusion-license",
        notes="Commercial use allowed, but includes mandatory behavioral use-case restrictions that propagate downstream.",
    ),
    LicenseProfile(
        spdx_id="Stability-AI-Community",
        name="Stability AI Community License",
        category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        commercial_allowed=True,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="https://stability.ai/community-license-agreement",
        notes="Free commercial use only below $1M annual revenue threshold; enterprise license required above threshold.",
    ),
    LicenseProfile(
        spdx_id="UNKNOWN",
        name="Unknown or Unspecified License",
        category=LicenseCategory.UNKNOWN,
        commercial_allowed=False,
        requires_source_disclosure=False,
        requires_notice=True,
        non_commercial=False,
        has_special_clauses=True,
        url="",
        notes="No verifiable license identifier found; requires manual verification before distribution.",
    ),
]

LICENSE_PROFILES: dict[str, LicenseProfile] = {p.spdx_id: p for p in _PROFILES}

_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "expat": "MIT",
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "0bsd": "0BSD",
    "unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc by 4.0": "CC-BY-4.0",
    "odc-by": "ODC-BY-1.0",
    "odc-by-1.0": "ODC-BY-1.0",
    "mpl-2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl": "LGPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1-only": "LGPL-2.1-only",
    "lgpl-2.1-or-later": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "lgpl-3.0-or-later": "LGPL-3.0-only",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl-3.0-or-later": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "agpl": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "agpl-3.0-or-later": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc-by-nc": "CC-BY-NC-4.0",
    "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "flux-1-dev-non-commercial": "FLUX-1-dev-Non-Commercial",
    "qwen-research": "Qwen-Research",
    "llama3.1": "Llama-3.1-Community",
    "llama3.2": "Llama-3.2-Community",
    "llama-3.1": "Llama-3.1-Community",
    "llama-3.2": "Llama-3.2-Community",
    "gemma": "Gemma-Terms",
    "openrail": "OpenRAIL-M",
    "openrail-m": "OpenRAIL-M",
    "creativeml-openrail-m": "OpenRAIL-M",
    "stabilityai-ai-community": "Stability-AI-Community",
}

_CATEGORY_PRIORITY = {
    LicenseCategory.PERMISSIVE: 0,
    LicenseCategory.WEAK_COPYLEFT: 1,
    LicenseCategory.CUSTOM_AI_COMMERCIAL: 2,
    LicenseCategory.SHARE_ALIKE: 3,
    LicenseCategory.STRONG_COPYLEFT: 4,
    LicenseCategory.NON_COMMERCIAL: 5,
    LicenseCategory.PROPRIETARY: 6,
    LicenseCategory.UNKNOWN: 7,
}


def normalize_license_id(raw: str | None) -> str:
    """Normalize a raw license string or SPDX expression into a canonical identifier."""
    if not raw or not str(raw).strip():
        return "UNKNOWN"
    text = str(raw).strip()
    lower = re.sub(r"\s+", " ", text.lower())

    if lower in _ALIASES:
        return _ALIASES[lower]

    # Exact case-insensitive match against registered profiles
    for spdx_id in LICENSE_PROFILES:
        if spdx_id.lower() == lower:
            return spdx_id

    # Handle dual/disjunctive SPDX expressions ("MIT OR Apache-2.0", "Apache-2.0 / MIT")
    or_parts = re.split(r"\s+(?:OR|or)\s+|\s*/\s*", text)
    if len(or_parts) > 1:
        candidates = [normalize_license_id(part) for part in or_parts]
        known = [c for c in candidates if c != "UNKNOWN"]
        if known:
            known.sort(key=lambda cid: _CATEGORY_PRIORITY[resolve_license_profile(cid).category])
            return known[0]

    # Handle conjunctive SPDX expressions ("MIT AND GPL-3.0") -> pick strictest term
    and_parts = re.split(r"\s+(?:AND|and)\s+", text)
    if len(and_parts) > 1:
        candidates = [normalize_license_id(part) for part in and_parts]
        known = [c for c in candidates if c != "UNKNOWN"]
        if known:
            known.sort(key=lambda cid: -_CATEGORY_PRIORITY[resolve_license_profile(cid).category])
            return known[0]

    # Fuzzy substring fallbacks for verbose classifier/header text
    if "affero" in lower or "agpl" in lower:
        return "AGPL-3.0-only"
    if "non-commercial" in lower or "noncommercial" in lower or "by-nc" in lower:
        return "CC-BY-NC-4.0"
    if "lesser general public" in lower or "lgpl" in lower:
        return "LGPL-3.0-only"
    if "general public license" in lower or "gpl" in lower:
        return "GPL-3.0-only"
    if "mozilla public license" in lower:
        return "MPL-2.0"
    if "apache" in lower:
        return "Apache-2.0"
    if "bsd" in lower:
        return "BSD-3-Clause"
    if "mit" in lower:
        return "MIT"
    if "llama" in lower:
        return "Llama-3.1-Community"
    if "gemma" in lower:
        return "Gemma-Terms"
    if "openrail" in lower:
        return "OpenRAIL-M"

    return "UNKNOWN"


def resolve_license_profile(raw_or_spdx: str | None) -> LicenseProfile:
    """Resolve a raw or normalized license string to its LicenseProfile."""
    norm = normalize_license_id(raw_or_spdx)
    return LICENSE_PROFILES.get(norm, LICENSE_PROFILES["UNKNOWN"])
