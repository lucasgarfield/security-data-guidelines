"""Generate the disk image SBOM examples used in docs/sbom.md.

All checksums are synthetic (derived from the artifact name) so the examples are
deterministic. Run from this directory: ``python3 generate.py``.
"""

import hashlib
import json
from pathlib import Path

CREATED = "2006-08-14T02:34:56Z"
CREATORS = ["Tool: example SPDX document only", "Organization: Red Hat"]
NS = "https://www.redhat.com/{}.spdx.json"
HERE = Path(__file__).parent


def fake_sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def purl_ref(purl):
    return {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": purl,
    }


def rel(a, t, b):
    return {"spdxElementId": a, "relationshipType": t, "relatedSpdxElement": b}


def doc(name, packages, relationships, ext_refs=None, comment=None):
    d = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"created": CREATED, "creators": CREATORS},
        "name": name,
        "documentNamespace": NS.format(name),
    }
    if comment:
        d["creationInfo"]["comment"] = comment
    if ext_refs:
        d["externalDocumentRefs"] = ext_refs
    d["packages"] = packages
    d["files"] = []
    d["relationships"] = relationships
    return d


def write(d):
    text = json.dumps(d, indent=2) + "\n"
    (HERE / f"{d['name']}.spdx.json").write_text(text)
    return hashlib.sha1(text.encode()).hexdigest()


def ext_ref(doc_id, d, sha1):
    return {
        "externalDocumentId": doc_id,
        "spdxDocument": d["documentNamespace"],
        "checksum": {"algorithm": "SHA1", "checksumValue": sha1},
    }


# (name, version, arch, repository_id, srpm name)
RPMS = {
    "kernel-core": ("5.14.0-570.12.1.el9_6", "x86_64", "baseos", "kernel"),
    "openssl-libs": ("3.2.2-6.el9_5.1", "x86_64", "baseos", "openssl"),
    "bash": ("5.1.8-9.el9", "x86_64", "baseos", "bash"),
    "anaconda-core": ("34.25.5.17-1.el9_6", "x86_64", "appstream", "anaconda"),
    "osbuild": ("146-1.el9", "noarch", "appstream", "osbuild"),
    "xorriso": ("1.5.4-5.el9", "x86_64", "appstream", "libisoburn"),
}


def rpm_pkg(name, prefix=""):
    ver, arch, repo, _ = RPMS[name]
    repo_id = f"rhel-9-for-x86_64-{repo}-rpms"
    return {
        "SPDXID": f"SPDXRef-{prefix}{arch}-{name}".replace("_", "-"),
        "name": name,
        "versionInfo": ver,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "packageFileName": f"{name}-{ver}.{arch}.rpm",
        "licenseConcluded": "NOASSERTION",
        "externalRefs": [
            purl_ref(f"pkg:rpm/redhat/{name}@{ver}?arch={arch}&repository_id={repo_id}")
        ],
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": fake_sha256(f"{name}-{ver}.{arch}")}
        ],
    }


def srpm_pkg(name):
    ver, _, _, src = RPMS[name]
    return {
        "SPDXID": f"SPDXRef-SRPM-{src}",
        "name": src,
        "versionInfo": ver,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "packageFileName": f"{src}-{ver}.src.rpm",
        "licenseConcluded": "NOASSERTION",
        "primaryPackagePurpose": "SOURCE",
        "externalRefs": [purl_ref(f"pkg:rpm/redhat/{src}@{ver}?arch=src")],
        "checksums": [{"algorithm": "SHA256", "checksumValue": fake_sha256(f"{src}-{ver}.src")}],
    }


def with_rpms(container_id, names, packages, rels, prefix=""):
    seen = {p["SPDXID"] for p in packages}
    for n in names:
        p, s = rpm_pkg(n, prefix), srpm_pkg(n)
        for x in (p, s):
            if x["SPDXID"] not in seen:
                packages.append(x)
                seen.add(x["SPDXID"])
        rels.append(rel(container_id, "CONTAINS", p["SPDXID"]))
        r = rel(p["SPDXID"], "GENERATED_FROM", s["SPDXID"])
        if r not in rels:
            rels.append(r)


def disk_pkg(spdx_id, name, version, filename, purpose, download_url, oci=None):
    sha = fake_sha256(filename)
    purls = [
        f"pkg:generic/{name}@{version}?arch=x86_64"
        f"&checksum=sha256:{sha}&download_url={download_url}"
    ]
    if oci:
        purls.append(oci)
    return {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "packageFileName": filename,
        "licenseConcluded": "NOASSERTION",
        "primaryPackagePurpose": purpose,
        "externalRefs": [purl_ref(p) for p in purls],
        "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
    }


def buildroot(image_name):
    name = f"{image_name}-buildroot"
    root = {
        "SPDXID": "SPDXRef-buildroot",
        "name": name,
        "versionInfo": "9.6",
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "primaryPackagePurpose": "OPERATING_SYSTEM",
        "externalRefs": [purl_ref(f"pkg:generic/{name}@9.6?arch=x86_64")],
        "description": f"Build environment used to assemble {image_name}; "
        "build tools only, not shipped in the image.",
    }
    pkgs, rels = [root], [rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-buildroot")]
    with_rpms("SPDXRef-buildroot", ["osbuild", "xorriso", "bash"], pkgs, rels)
    d = doc(name, pkgs, rels, comment="SBOM generation context: build.")
    return d, write(d)


CDN = "https://access.redhat.com/downloads/content/rhel"

# 1. Package-based disk image (qcow2)
QNAME = "rhel-9.6-x86_64-kvm"
br, br_sha = buildroot(QNAME)
root = disk_pkg(
    "SPDXRef-disk-image",
    QNAME,
    "9.6",
    "rhel-9.6-x86_64-kvm.qcow2",
    "OPERATING_SYSTEM",
    f"{CDN}/rhel-9.6-x86_64-kvm.qcow2",
    oci="pkg:oci/rhel-kvm@sha256%3A"
    + fake_sha256("rhel-kvm-manifest")
    + "?repository_url=registry.redhat.io/rhel9/rhel-kvm&tag=9.6",
)
pkgs, rels = [root], [rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-disk-image")]
with_rpms("SPDXRef-disk-image", ["kernel-core", "openssl-libs", "bash"], pkgs, rels)
rels.append(rel("DocumentRef-buildroot:SPDXRef-buildroot", "BUILD_TOOL_OF", "SPDXRef-disk-image"))
write(
    doc(
        QNAME,
        pkgs,
        rels,
        [ext_ref("DocumentRef-buildroot", br, br_sha)],
        "SBOM generation context: build.",
    )
)

# 2. Installer ISO with two filesystems
INAME = "rhel-9.6-x86_64-dvd"
br, br_sha = buildroot(INAME)
iso = disk_pkg(
    "SPDXRef-disk-image",
    INAME,
    "9.6",
    "rhel-9.6-x86_64-dvd.iso",
    "OPERATING_SYSTEM",
    f"{CDN}/rhel-9.6-x86_64-dvd.iso",
)
inst = {
    "SPDXID": "SPDXRef-fs-installer",
    "name": f"{INAME}-installer-environment",
    "versionInfo": "9.6",
    "supplier": "Organization: Red Hat",
    "downloadLocation": "NOASSERTION",
    "packageFileName": "images/install.img",
    "licenseConcluded": "NOASSERTION",
    "primaryPackagePurpose": "INSTALL",
    "checksums": [{"algorithm": "SHA256", "checksumValue": fake_sha256("install.img")}],
    "description": "Anaconda installer runtime (squashfs). Runs during installation; "
    "not installed on the target system.",
}
payload = {
    "SPDXID": "SPDXRef-fs-payload",
    "name": f"{INAME}-payload",
    "versionInfo": "9.6",
    "supplier": "Organization: Red Hat",
    "downloadLocation": "NOASSERTION",
    "licenseConcluded": "NOASSERTION",
    "primaryPackagePurpose": "OPERATING_SYSTEM",
    "description": "Content installed onto the target system by the installer.",
}
pkgs = [iso, inst, payload]
rels = [
    rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-disk-image"),
    rel("SPDXRef-disk-image", "CONTAINS", "SPDXRef-fs-installer"),
    rel("SPDXRef-disk-image", "CONTAINS", "SPDXRef-fs-payload"),
]
with_rpms("SPDXRef-fs-installer", ["anaconda-core", "kernel-core", "bash"], pkgs, rels)
with_rpms("SPDXRef-fs-payload", ["kernel-core", "openssl-libs", "bash"], pkgs, rels)
rels.append(rel("DocumentRef-buildroot:SPDXRef-buildroot", "BUILD_TOOL_OF", "SPDXRef-disk-image"))
write(
    doc(
        INAME,
        pkgs,
        rels,
        [ext_ref("DocumentRef-buildroot", br, br_sha)],
        "SBOM generation context: build.",
    )
)

# 3. Disk image built from a bootc container image
CNAME = "rhel-bootc-container-9.6-1747000000_amd64"
cdigest = fake_sha256("rhel-bootc-9.6-amd64")
cimg = {
    "SPDXID": "SPDXRef-image",
    "name": "rhel-bootc",
    "versionInfo": "9.6-1747000000",
    "supplier": "Organization: Red Hat",
    "downloadLocation": "NOASSERTION",
    "licenseConcluded": "NOASSERTION",
    "primaryPackagePurpose": "CONTAINER",
    "externalRefs": [
        purl_ref(
            f"pkg:oci/rhel-bootc@sha256%3A{cdigest}"
            "?arch=amd64&repository_url=registry.redhat.io/rhel9/rhel-bootc&tag=9.6-1747000000"
        )
    ],
    "checksums": [{"algorithm": "SHA256", "checksumValue": cdigest}],
}
pkgs, rels = [cimg], [rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-image")]
with_rpms("SPDXRef-image", ["kernel-core", "openssl-libs", "bash"], pkgs, rels)
cdoc = doc(CNAME, pkgs, rels)
c_sha = write(cdoc)

BNAME = "rhel-bootc-9.6-1747000000-x86_64-qcow2"
br, br_sha = buildroot(BNAME)
bdisk = disk_pkg(
    "SPDXRef-disk-image",
    BNAME,
    "9.6-1747000000",
    "rhel-bootc-9.6-1747000000-x86_64.qcow2",
    "OPERATING_SYSTEM",
    f"{CDN}/rhel-bootc-9.6-1747000000-x86_64.qcow2",
)
# Container content is listed inline (scanners ignore externalDocumentRefs);
# the link to the container SBOM is kept for provenance.
bpkgs, rels = [bdisk], [rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-disk-image")]
with_rpms("SPDXRef-disk-image", ["kernel-core", "openssl-libs", "bash"], bpkgs, rels)
rels += [
    rel("SPDXRef-disk-image", "GENERATED_FROM", "DocumentRef-container:SPDXRef-image"),
    rel("DocumentRef-buildroot:SPDXRef-buildroot", "BUILD_TOOL_OF", "SPDXRef-disk-image"),
]
write(
    doc(
        BNAME,
        bpkgs,
        rels,
        [
            ext_ref("DocumentRef-container", cdoc, c_sha),
            ext_ref("DocumentRef-buildroot", br, br_sha),
        ],
        "SBOM generation context: build.",
    )
)
