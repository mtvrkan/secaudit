"""SPDX 2.3 software bill of materials — the licence-compliance half of the pair.

Why both formats. CycloneDX and SPDX are not competitors you pick between; they answer
different questions and different people ask them. CycloneDX is built around
vulnerability correlation, which is what `--format cyclonedx` and the CRA evidence pack are
for. SPDX is an ISO standard (ISO/IEC 5962:2021) and is what procurement, legal review and US
federal software-supply-chain requirements (EO 14028 / NTIA minimum elements) ask for, because
its centre of gravity is licensing and provenance. A product that ships one and not the other
will be asked for the other.

The component list is *not* re-derived here. It comes from `sbom.build()`, so the two documents
cannot disagree about what is in the product — which is the failure that makes a pair of SBOMs
worse than either alone, and which is exactly what happens when two emitters each walk the
manifest themselves.

Same determinism rule as CycloneDX: no clock, no random. `document_namespace` and `created` are
the caller's to supply, so the same tree produces byte-identical output and a diff between two
SPDX documents shows dependency changes rather than the time of day.
"""
from __future__ import annotations

import json
import re

from . import sbom

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"

# SPDXID must match `SPDXRef-[a-zA-Z0-9.\-]+`. npm names carry `@`, `/` and `_`, none of which
# survive — so they are mapped, not stripped: `@scope/pkg` and `scope-pkg` are different
# packages and must not collapse to the same id.
_ID_SAFE = re.compile(r"[^a-zA-Z0-9.\-]")


def _spdx_id(purl: str) -> str:
    return "SPDXRef-" + _ID_SAFE.sub("-", purl)


def _license_of(component: dict) -> str:
    """SPDX requires a licence field on every package and has a vocabulary for not knowing.

    `NOASSERTION` is the correct value here and it is not a placeholder to fill in later: this
    scan reads a manifest and a lockfile, neither of which states the licence of a dependency —
    that lives in each installed package's own metadata. Emitting a guessed SPDX licence
    identifier into a document whose purpose is licence compliance would be the single most
    damaging thing this module could do, so it does not guess.
    """
    declared = component.get("licenses")
    return declared if isinstance(declared, str) and declared else "NOASSERTION"


def build(root: str, target_name: str = "", document_namespace: str = "",
          created: str = "") -> dict:
    """An SPDX 2.3 document for the project at `root`, from the same components as CycloneDX."""
    source = sbom.build(root, target_name=target_name)
    root_component = source["metadata"]["component"]
    root_id = _spdx_id(root_component["bom-ref"])

    packages = [{
        "SPDXID": root_id,
        "name": root_component["name"],
        "versionInfo": root_component.get("version") or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }]

    for component in source["components"]:
        package_id = _spdx_id(component["bom-ref"])
        package = {
            "SPDXID": package_id,
            "name": component["name"],
            # An unresolved version is `NOASSERTION`, never the range. SPDX `versionInfo` is a
            # version, and putting `^4.17.1` there produces a document that looks precise to a
            # tool and is not — the same reason CycloneDX flags it in a property.
            "versionInfo": component["version"] or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": _license_of(component),
            "licenseDeclared": _license_of(component),
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component["purl"],
            }],
        }
        if not component["version"]:
            package["comment"] = next(
                (p["value"] for p in component.get("properties", [])
                 if p["name"] == "secaudit:version-unresolved"),
                "Version could not be resolved from a lockfile.")
        packages.append(package)
        relationships.append({
            "spdxElementId": root_id,
            # DEPENDS_ON, not CONTAINS: this is a manifest-level dependency relationship, and
            # CONTAINS would assert the files are inside the product, which was not checked.
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": package_id,
        })

    document: dict = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_component["name"] or "sbom",
        "documentDescribes": [root_id],
        "creationInfo": {
            "creators": ["Tool: SecAudit"],
            "comment": "Top-level dependencies only — the floor set by CRA Annex I Part II (1) "
                       "and the NTIA minimum elements. Not a resolved transitive dependency "
                       "graph. Licence fields are NOASSERTION because a manifest and lockfile "
                       "do not state dependency licences; they are not placeholders and must "
                       "not be read as permissive.",
        },
        "packages": packages,
        "relationships": relationships,
    }
    if document_namespace:
        document["documentNamespace"] = document_namespace
    if created:
        document["creationInfo"]["created"] = created
    return document


def to_json(root: str, target_name: str = "", document_namespace: str = "",
            created: str = "") -> str:
    return json.dumps(build(root, target_name, document_namespace, created), indent=2)


def is_supported(root: str) -> bool:
    return sbom.is_supported(root)
