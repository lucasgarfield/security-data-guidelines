# Understanding SBOMs

A Software Bill of Materials (SBOM) is at its core a listing of software components for a given deliverable. That
deliverable may be a single RPM package, a container image, or an entire product version. There are several use
cases where SBOMs are beneficial:

- in-depth review of the composition of a particular product for procurement or audit purposes,

- accurate vulnerability risk assessment when combined with VEX data,

- or faster incident response when aggregating SBOMs for an entire product portfolio, as well as the pipeline components
  that build them.

When talking about inventories of components, it's also important to describe what the current design goals of a
comprehensive SBOM are:

- Provide a complete and accurate listing of software components and their relationships to each other from a
  supply chain perspective:

    - For each software component, an SBOM must list its provenance. That is, if the (downstream) component is a
      redistributed version of an open source project (upstream), the downstream component must be directly linked
      to its upstream counterpart. If an upstream component is augmented in a mirrored repository before being used
      in a build of a downstream component, this version of the component (also called a midstream component) must
      be recorded as a separate package.

    - A manifest must list all components that are included in the final deliverable that can be deployed and run by an
      end user. Any software dependencies that are used strictly during the build process must be listed as well, but
      separate from the runtime dependencies.

- Define an accurate identification of components and products usable across all published security data.

It's equally important to clarify what remains outside the scope of an SBOM:

- Provide a component dependency graph: providing dependency relationships between components as part of an
  application or an operating system is currently out of scope. This type of information is varied between different
  ecosystems, and it would be difficult to express it correctly in product-level SBOMs.
  The relationships currently represented are limited to more direct dependencies, such as those between a container
  image and the packages it includes, an operating system and its constituent packages, or a package and its
  upstream counterpart. We do not include application-level dependencies, like those where a Python package such as
  [`requests`](https://pypi.org/project/requests/) depends on another package like
  [`certifi`](https://pypi.org/project/certifi/).

- Inclusion of complete listings of individual files for each component: for each listed component in an SBOM, it is
  assumed that the user can fetch it from its indicated location, and inspect the component itself to list out its
  files. For example, when downloading a source RPM, the downloaded archive can be unpacked and inspected to acquire
  a list of files contained in it.

## Formats

The two most widely used SBOM formats are [SPDX](https://spdx.dev/) and
[CycloneDX](https://cyclonedx.org/). Both offer similar features and data fields, and can be used to represent
complex inventories of components, their metadata (such as provenance or licensing), and additional document properties.

Most of this document focuses on Red Hat's use of SPDX 2.3 in its published SBOMs. CycloneDX 1.6 guidance for RPM
builds is in the [RPM (CycloneDX 1.6)](#rpm-cyclonedx-16) section below; SPDX 3.0 guidelines may be added in the
future.

## Types

Depending on how an SBOM is generated, it will contain varying levels of information. The sections below highlight
different viewpoints of when an SBOM is created and what type of data it includes.

### Build vs Release

_Build-time_ SBOMs are created during the initial build process of an artifact (for example, when an RPM is created
from source files or a container image is built using [`buildah`](https://buildah.io/)). These SBOMs document the
components used during the build process to produce the final artifact as well as any components used for the build
process itself. This SBOM type also aligns with the _Build_ SBOM type from CISA's guidance on
[Types of SBOM Documents](https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf).

_Release-time_ SBOMs are created when an artifact is released or published. These SBOMs build upon build-time
SBOMs by incorporating additional metadata, such as the repositories or locations where an artifact is
published, and associating it with the relevant product information if there is any. Release-time SBOMs reflect the
state of the software as it is distributed to end users. This SBOM type should still be considered as a _Build_ SBOM
as defined by CISA, but it simply includes additional metadata that is not available during the build process and is
added later on. For lack of a better term, we could call these _Curated Build SBOMs_.

For component-level _Release-time_ SBOMs (for example, container images), the package that represents the component may include product CPE(s) in its externalRefs with referenceCategory `SECURITY` and referenceType `cpe22Type` (and the CPE string in referenceLocator), so the component is explicitly associated with the Red Hat product(s) it is released as part of.

Red Hat's publicly available SBOMs are of the release-time type, including details about where an artifact
can be located after being released.

**Example**:

- Build-time SBOM of the `ubi9-micro` container image along with all of its installed components (RPMs):
  [build/ubi9-micro-container-9.4-6.1716471860_amd64](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/container_image/build/ubi9-micro-container-9.4-6.1716471860_amd64.spdx.json)
- Release-time SBOM of the same `ubi9-micro` container image:
  [release/ubi9-micro-container-9.4-6.1716471860_amd64](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/container_image/release/ubi9-micro-container-9.4-6.1716471860_amd64.spdx.json)

The difference between these two SBOMs is relatively minor; the release-time SBOM contains information on where the
container image (identified by two distinct purls) itself is available from:

```diff
--- sbom/examples/container_image/build/ubi9-micro-container-9.4-6.1716471860_amd64.spdx.json
+++ sbom/examples/container_image/release/ubi9-micro-container-9.4-6.1716471860_amd64.spdx.json
@@ -22,12 +22,12 @@
         {
           "referenceCategory": "PACKAGE-MANAGER",
           "referenceType": "purl",
-          "referenceLocator": "pkg:oci/ubi-micro@sha256%3A1c84[...]?arch=amd64"
+          "referenceLocator": "pkg:oci/ubi-micro@sha256%3A1c84[...]?arch=amd64&repository_url=registry.access.redhat.com/ubi9/ubi-micro&tag=9.4-6.1716471860"
         },
         {
           "referenceCategory": "PACKAGE-MANAGER",
           "referenceType": "purl",
-          "referenceLocator": "pkg:oci/ubi9-micro@sha256%3A1c84[...]?arch=amd64"
+          "referenceLocator": "pkg:oci/ubi9-micro@sha256%3A1c84[...]?arch=amd64&repository_url=registry.access.redhat.com/ubi9-micro&tag=9.4-6.1716471860"
         }
       ],
```

### Product vs Pipeline

_Product_ SBOMs, as described above in the Build vs Release section, align with the _Build_ SBOM type from CISA's guidance on
[Types of SBOM Documents](https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf).

_Pipeline_ SBOMs document the software components that make up systems, tools, and infrastructure (STIs) composing a Pipeline
for building our products. These SBOMs may align with _Build_ SBOM type as defined by CISA, or they may align with _Source_,
_Analyzed_, or even _Deployed_ SBOM types. The difference between these types lies in how the SBOMs are generated, which
depends on when during the build and deploy process of a Pipeline STI the SBOM is generated.


### Component-Level vs Product-Level

_Component-level_ SBOMs describe individual components, such as a single RPM package or a container
image. They document the full listing of individual components, libraries, and other relevant
software that went into building that component. Component-level SBOMs also include provenance metadata for certain
components. For example, a component-level SBOM of an RPM will point to the upstream sources that that RPM is based on.

_Product-level_ SBOMs describe an entire product and the subset of its components that were built and included in
the final product. A product-level SBOM may cover one or more component-level SBOMs, providing a way to connect each
release component to its parent product.

**Example**:

- Component-level SBOM of the `openssl-3.0.7-18.el9_2` RPM package:
  [release/openssl-3.0.7-18.el9_2](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/release/openssl-3.0.7-18.el9_2.spdx.json)

- Product-level SBOM of the `openssl-3.0.7-18.el9_2` RPM package as included in RHEL 9.2 EUS repositories:
  [product/rhel-9.2-eus](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/product/rhel-9.2-eus.spdx.json)

Note that the root package described by the component-level SBOM, the OpenSSL Source RPM (SRPM), is the only
reference present in the product-level SBOM to not duplicate information between the two SBOMs. The purl
reference from the SRPM package can be used to discover the component-level SBOM from the product-level SBOM.

### Shallow vs Complete

_Shallow_ SBOMs describe only the current layer of components that were used to build a specific artifact. They
focus on the immediate components without necessarily documenting their origins. The benefit of this approach is
smaller SBOM files, and the ability to make incremental changes in select SBOMs while others remain unchanged when
composing multiple SBOMs into a larger set (to describe a product, for example).

_Complete_ SBOMs provide a full, in-depth representation of all levels of the build process in a single file. A
Complete SBOM includes all component layers and their dependencies, offering a complete view of a product's composition.
These types of SBOMs are mostly used for procurement and audit.

Red Hat aims to publish Complete SBOMs at
[https://security.access.redhat.com/data/sbom/](https://security.access.redhat.com/data/sbom/) while Shallow SBOMs
may be published for individual components such as container images.

## Document Structure

The following snippet shows a minimal SBOM document:

=== "SPDX 2.3"

    ```json
    {
      "spdxVersion": "SPDX-2.3",// (1)!
      "dataLicense": "CC0-1.0",// (2)!
      "SPDXID": "SPDXRef-DOCUMENT",// (3)!
      "creationInfo": {
        "created": "2006-08-14T02:34:56Z",// (4)!
        "creators": [
          "Tool: example SPDX document only",
          "Organization: Red Hat"// (5)!
        ]
      },
      "name": "ubi9-micro-container-9.4-6.1716471860_amd64",
      "documentNamespace": "https://www.redhat.com/ubi9-micro-container-9.4-6.1716471860_amd64.spdx.json",
      "packages": [...],
      "files": [],
      "relationships": [...]
    }
    ```

    1. SPDX version 2.3 as described at [https://spdx.github.io/spdx-spec/v2.3/](https://spdx.github.io/spdx-spec/v2.3/).

    2. The CC0-1.0 license is required by the SPDX specification.

    3. [`SPDXID`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field)
       must be set to `SPDXRef-DOCUMENT`.

    4. UTC timestamps must use the `YYYY-MM-DDThh:mm:ssZ` format.

    5. creationInfo / creators includes the "Organization: Red Hat" value.

A more detailed breakdown of some of the fields:

`creationInfo`
:   This field must contain at least the
    [`created`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field) and
    [`creators`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field)
    fields. The timestamp in the `created` field must be set to an ISO 8601-formatted date and time string using
    the UTC timezone. The `creators` field must identify the tool and its version that was used to generate the SBOM
    file (for example, `Tool: SBOMer 1.2.3` or even `Tool: pkg:github/project-ncl/sbomer@1.0.0.M3`).
    The value `Organization: Red Hat` included in a separate string. This is required by Red Hat Trusted Profiler Analyser 2 in order to trigger special handling.

[`name`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field)
:   This is an arbitrary value that should describe the main artifact described by the SBOM document. This can be a
    product, a container image, or a specific package. The name should contain a descriptive value for that given
    artifact along with a version identifier. This field should only serve as a human-readable value and be shown in
    user interfaces for informational purposes. The metadata of the main package (the one _DESCRIBED_ by
    the SBOM document) should be used for any automation purposes. Note also that the `name` value may not be unique
    to a single SBOM document.

[`documentNamespace`](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field)
:   This field uniquely identifies the SPDX SBOM document and must be a valid URI, even though that URI does not
    have to be accessible. Red Hat SBOMs can use one of two possible values:

    - A URI that is namespaced to a generic Red Hat location: `https://www.redhat.com/[DocumentID].spdx.json`.
      This URI is not accessible and only serves the purpose of identifying the document to its namespace (here,
      Red Hat).

    - A URI that is namespaced to `access.redhat.com/security/data`:
     `https://security.access.redhat.com/data/sbom/spdx/[DocumentID].spdx.json`. This URI is assumed to be accessible
      and the identified SBOM can be downloaded from the specified location.

    The `documentNamespace` value has no direct relationship to the `name` value.

The `packages` and `relationships` fields are described in depth in the sections below for each respective software
content type. The `files` field is currently unused and will thus either not be present at all, or set to an empty
list. All software components in an SBOM are described as packages; all files are assumed to be a part of _some_
package and should thus not be listed on their own in the `files` field.

### Packages and Relationships

The purpose of listing out all components as separate package objects ensures we can define meaningful relationships
between them. Some packages may for example embed other software components, and other packages may be used only
during the build process of creating a set of packages. Differentiating between these different types of components
allows us to narrow down the scope of responding to vulnerabilities to only the components that are truly affected
by a given vulnerability.

The following example shows the structure of a package object for a specific component:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-[UUID]",// (1)!
      "name": "ubi9-micro-container",
      "versionInfo": "9.4-6.1716471860",
      "supplier": "Organization: Red Hat",// (2)!
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "NOASSERTION",
      "externalRefs": [...],
      "checksums": [...]
    }
    ```

    1. A unique identifier of a given component within this document. This value should only be used to associate
       relationships to other components described in an SBOM via their relationships.

    2. The value `Organization: Red Hat` must be used for all components that are distributed by Red Hat.

A more detailed breakdown of some of the fields:

[`name`](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field)
:   The name of the component. This value may differ for different types of package ecosystems. It is recommended to
    use the `name` field of the associated purl string for consistent results.

[`versionInfo`](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)
:   The version of the component. This value may differ for different types of package ecosystems. It is
    recommended to use the `version` field of the associated purl string for consistent results.

[`downloadLocation`](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)
:   This field is used to point to the VCS that holds the related source code for this component. In most cases,
    this field will be set to `NOASSERTION` because the upstream equivalent of a downstream component is represented
    with its own package object.

[`licenseConcluded`](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field)
:   The concluded license of the package, based on the information available during the build. If during the build,
    this information cannot be determined, the value `NOASSERTION` should be used.

[`externalRefs`](https://spdx.github.io/spdx-spec/v2.3/package-information/#722-external-reference-comment-field)
:   At least one of the references must include a Package URL (purl) unless the object is describing a product.
    [Identifying Red Hat components using Package URL](./purl.md) documents what purl strings for different types of
    components should look like. Note that multiple purls may be used for a single package to identify multiple
    locations from where the package can be accessed. For release-time component-level SBOMs, externalRefs may also
    include `SECURITY` references with referenceType `cpe22Type` and the product CPE string(s) in `referenceLocator`, linking
    the component to the Red Hat product(s) it is released as part of; one or more CPEs per package is allowed.

[`checksums`](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)
:   The checksums of the component. The type of checksum used will depend on the type of the component. See below
    sections for more information.


#### Container Image

A container image can be represented by a package object using the following data:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-image-index",
      "name": "ubi9-micro-container",// (1)!
      "versionInfo": "9.4-6.1716471860",
      "supplier": "Organization: Red Hat",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:oci/ubi-micro@sha256%3A1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d?repository_url=registry.access.redhat.com/ubi9&tag=9.4-6.1716471860"
        },
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:oci/ubi9-micro@sha256%3A1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d?repository_url=registry.access.redhat.com&tag=9.4-6.1716471860"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d"
        }
      ],
    }
    ```

    1. The name does not necessarily have to reflect what the container image is named in the container registry;
       the name component of the associated purl identifier should be used instead.

[`checksums`](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)
:   The checksum value for a container image refers to the image digest value as defined in the
    [OCI Image Format](https://github.com/opencontainers/image-spec/blob/v1.0.1/descriptor.md#digests).

purl identifiers
:   A container image may have one or more purls, depending on whether the same image is available in different
    registries, or different repositories within the same registry. Note that if multiple purls are present,
    they should only ever differ in their qualifier values, not the main components such as package type, name, or
    version; multiple package objects should be used if those values differ.

license information
:   Licensing information should in most cases be set to `NOASSERTION` since licensing is set on the software
    components provided by the container image, and not the image itself.

[`downloadLocation`](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)
:   The `downloadlocation` will never be set; container images don't have their own VCS repos. The location from
    where the image itself can be downloaded can be acquired from the purl identifier.

An SBOM should contain representation of both an
[Image Index](https://github.com/opencontainers/image-spec/blob/main/image-index.md) and an architecture-specific
image itself. The following is an example of an SPDX relationship between the two:

=== "SPDX 2.3"

    ```json
    {
      "relationships": [
        {
          "spdxElementId": "SPDXRef-DOCUMENT",
          "relationshipType": "DESCRIBES",
          "relatedSpdxElement": "SPDXRef-image-index"
        },
        {
          "spdxElementId": "SPDXRef-ubi9-micro-container-ppc64le",
          "relationshipType": "VARIANT_OF",
          "relatedSpdxElement": "SPDXRef-image-index"
        }
      ]
    }
    ```

An SBOM that represent a container image must also list out all the components included in that image, and create
relationships to the architecture-specific image that they are included in:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-ubi9-micro-container-amd64",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-x86_64-bash"
    }
    ```

A container image SBOM must also list its parent container image and any container images that were used in the
process of building the container image (that is, used in a multi-stage build). As an example, consider the following
Dockerfile used to create an image (`example-container`) by building the `foo` and `bar` dependencies using separate
images:

```Dockerfile
# Dockerfile of example-container
FROM img-a AS stage1
RUN make foo

FROM img-b AS stage2
RUN make bar

FROM ubi9
COPY --from=stage1 /work/foo /foo
COPY --from=stage2 /work/bar /bar
```

The relationship of `example-container` image to the two container images (`stage1` and `stage2`) that were used to
build `foo` and `bar` so they can be added to the final layers can be represented as:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-stage1-amd64",
      "relationshipType": "BUILD_TOOL_OF",
      "relatedSpdxElement": "SPDXRef-example-container-container-amd64"
    },
    {
      "spdxElementId": "SPDXRef-stage2-amd64",
      "relationshipType": "BUILD_TOOL_OF",
      "relatedSpdxElement": "SPDXRef-example-container-container-amd64"
    }
    ```

The parent image of `example-container` is `ubi9`. Its relationship to `example-container` can be represented as:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-example-container-amd64",
      "relationshipType": "DESCENDANT_OF",
      "relatedSpdxElement": "SPDXRef-ubi9-amd64"
    }
    ```

Container Images are also linked to one or more upstream sources that were used to build them. An upstream source can be represented by a package object using the following data:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-image-index-Source-origin",
      "name": "kernel-module-management",
      "versionInfo": "d027509b6861d8a9f923cc99dd3e15d9b209e63e",
      "downloadLocation": "https://github.com/rh-ecosystem-edge/kernel-module-management#d027509b6861d8a9f923cc99dd3e15d9b209e63e",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/kernel-model-management@d027509b6861d8a9f923cc99dd3e15d9b209e63e?download_url=https://github.com/rh-ecosystem-edge/kernel-module-management#d027509b6861d8a9f923cc99dd3e15d9b209e63e"
        }
      ]
    },
    ```

To associate a set of remote sources with the repository referencing them, use:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-image-index-Source",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-image-index-Source-origin"
    },
    ```

<!-- TODO: add diagram that shows all the relationships -->

#### RPM

Before defining what RPM package objects look like, let's also define the specific types of sources that can be involved
in the RPM build process:

- An _upstream source_ is the original source code as released by the software's primary developers or maintainers.

- A _midstream source_ is a copy of the upstream code, which may be modified or simply mirrored for distribution
  purposes. Midstream sources are optional.

- A _downstream source_ is a set of sources used to create a source RPM. These are the real build inputs that get
  packaged into an SRPM, regardless of whether they originated directly from upstream or came through a midstream
  archive. Downstream sources may include distribution-specific patches, build configuration changes, spec files,
  and any other files needed to build the final RPM package.

An architecture-specific (downstream) RPM built by Red Hat can be represented by a package object using
the following data:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-aarch64-openssl-libs",
      "name": "openssl-libs",
      "versionInfo": "3.0.7-18.el9_2",
      "supplier": "Organization: Red Hat",
      "downloadLocation": "NOASSERTION",
      "packageFileName": "openssl-libs-3.0.7-18.el9_2.aarch64.rpm",
      "licenseConcluded": "Apache-2.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=aarch64&repository_id=rhel-9-for-aarch64-baseos-eus-rpms"
        },
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=aarch64&repository_id=rhel-9-for-aarch64-baseos-aus-rpms"
        },
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=aarch64&repository_id=rhel-9-for-aarch64-baseos-e4s-rpms"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "cae5941219fd64e75c2b29509c6fe712bef77181a586702275a46a5e812d4dd4"
        }
      ],
      "annotations": [
        {
          "annotationType": "OTHER",
          "annotator": "Tool: example SPDX document only",
          "annotationDate": "2006-08-14T02:34:56+00:00",
          "comment": "sigmd5: 4cc665dd3173c8952184293588f9ee46"
        }
      ]
    }
    ```

[`downloadLocation`](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)
:   For binary RPM packages, `downloadLocation` is `NOASSERTION`. The RPM file is identified by its purl and
    checksum; repository download locations are represented via `repository_id` purl qualifiers in release-time SBOMs.

purl identifiers
:   A single RPM package may be available from multiple DNF/Yum repositories, in which case it will include a purl
    identifier for each repository it can be downloaded from. Note that if multiple purls are present,
    they should only ever differ in their qualifier values, not the main components such as package type, name, or
    version; multiple package objects should be used if those values differ.

[`checksums`](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)
:   Minimally, the list of checksums must include the SHA256 checksum of the RPM file or source archive itself.
    All other checksums should be specified as annotations (see below).

[`annotations`](https://spdx.github.io/spdx-spec/v2.3/annotations/)
:   A list of annotations may provide additional information that is specific to the RPM format. In the example
    above, two checksum values are included:
    - The MD5 checksum of the signed header of the RPM package is included.
    - The SHA256 checksum of the RPM header (this value does not change when an RPM is signed; unlike the file SHA256 \
      checksum used in `checksums`).

Each set of architecture-specific RPMs also has an associated source RPM (SRPM) that bundles all the source code
that was used to build those RPMs. SRPMs should be represented as a separate package object in an SBOM, and their
relationship to architecture-specific RPMs can be represented with:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-ppc64le-openssl-libs",
      "relationshipType": "GENERATED_FROM",
      "relatedSpdxElement": "SPDXRef-SRPM"
    }
    ```

SRPMs are also linked to one or more upstream sources that were used to build the downstream RPMs. An upstream
source can be represented by a package object using the following data:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-Source0-origin",
      "name": "openssl",
      "versionInfo": "3.0.7",
      "downloadLocation": "https://openssl.org/source/openssl-3.0.7.tar.gz",
      "homepage": "https://openssl-library.org/",
      "packageFileName": "openssl-3.0.7.tar.gz",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "83049d042a260e696f62406ac5c08bf706fd84383f945cf21bd61e9ed95c396e"
        }
      ],
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/openssl@3.0.7?download_url=https://openssl.org/source/openssl-3.0.7.tar.gz&checksum=sha256:83049d042a260e696f62406ac5c08bf706fd84383f945cf21bd61e9ed95c396e"
        }
      ]
    }
    ```

purl identifiers
:   In cases where the upstream source is a package in a registry such as PyPI or NPM, the purl identifier will use
    the respective package type. For components that are distributed as standalone bundles (such as OpenSSL in the
    example above), `generic` purls should be used with an exact download URL from where a specific bundle of source
    code was fetched from, including a checksum (which should also be specified in the `checksums` field).

To associate a set of source archives with the SRPM that includes them, use:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-SRPM",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-Source0"
    }
    ```

Optionally, an upstream source may be mirrored in a different repository where the source is modified in a way that
makes it consumable by the downstream distributor. This is referred to as a midstream source. The package object for
the midstream source looks identical to an upstream package, but with different download location and purl identifier.

The relationship between an upstream source and a midstream source can be represented with:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-Midstream0",
      "relationshipType": "GENERATED_FROM",
      "relatedSpdxElement": "SPDXRef-Source0"
    }
    ```

The complete diagram of the relationships between the various types of sources in an SBOM might look like this:

``` mermaid
graph TD
    A["https://openssl.org/source/openssl-3.0.7.tar.gz"]
    B["https://github.com/(RH openssl midstream repo)/archive/refs/tags/3.0.7.tar.gz"]
    C["SRPM: openssl 3.0.7-18.el9_2.src"]
    D["RPM: openssl 3.0.7-18.el9_2.aarch64"]
    C -->|CONTAINS| B
    B -->|GENERATED_FROM| A
    D -->|GENERATED_FROM| C
```

##### RPM build provenance

SBOM producers for RPM builds should record **upstream facts as observed** — not interpret or translate them. The RPM
name (for example `automation-controller`) may differ from the upstream project name (`awx`); downstream tools
resolve that mapping from provenance URLs and source refs. Do not emit synthetic upstream project packages solely to
carry a translated name.

Three complementary provenance layers apply to RPM build SBOMs:

| Layer | What it answers | RPM-path source | SPDX (SRPM) | CycloneDX (SRPM) |
|-------|-----------------|-----------------|-------------|------------------|
| **1. Build context** | Where Red Hat packages this RPM | Koji `build.source` | *(omit `externalRefs` vcs on rpm SRPM in release examples — stripped during release regen)* | `externalReferences` `{type: "vcs", url, comment: commit}` (placeholder URL in examples) |
| **2. Upstream project URL** | Where the upstream project lives | spec `%URL:`; public rows in `source-repos` | `homepage` on SRPM | `externalReferences` `{type: "website"}` |
| **3. Source artifacts** | What tarballs/archives were consumed | `rpmdev-spectool`; SBOMer pedigree | SourceN packages + `CONTAINS` / `GENERATED_FROM` | `pedigree.ancestors[]` nested chain |

**Producer guidance:**

1. **Source artifact `name`** — use the observed tarball stem or archive filename (`openssl`, `delve`, and so on). Do
   not rename to a canonical upstream project name.
2. **Spec `%URL:`** — when present in the spec and available to the producer, record it verbatim on the SRPM as SPDX
   `homepage` / CycloneDX `externalReferences.website`. This is especially useful when pedigree is missing.
3. **Do not** put spec `%URL:` in Source0 `downloadLocation` — that field is for the actual fetched archive URL.
4. **Do not** emit synthetic upstream project packages for name aliasing (for example, do not add a package named
   `awx` for `automation-controller`). The spec URL on the SRPM is sufficient for downstream resolution.
5. **Internal lookaside / dist-git hosts** — pedigree URLs on `*.redhat.com` hosts identify midstream packaging
   sources, not upstream. Treat them as midstream per the diagram above. Do not introduce new `*.redhat.com`
   hostnames into public docs or committed example SBOMs; use placeholders such as
   `github.com/(RH openssl midstream repo)/...`.
6. **`source-repos`** — record each upstream repo URL and commit as-is. Do not collapse multiple rows to a single
   derived name.

**Example URL policy:** committed examples and documentation snippets use public upstream URLs only
(`openssl.org`, `github.com/...`). Midstream, dist-git, and Koji source refs use placeholders matching the openssl
example pattern.

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-SRPM",
      "name": "openssl",
      "versionInfo": "3.0.7-18.el9_2",
      "homepage": "http://www.openssl.org/",
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&epoch=1"
        }
      ]
    }
    ```

=== "CycloneDX 1.6"

    ```json
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.7-18.el9_2",
      "purl": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&epoch=1",
      "externalReferences": [
        {
          "type": "website",
          "url": "http://www.openssl.org/"
        },
        {
          "type": "vcs",
          "url": "https://github.com/(RH openssl midstream repo)",
          "comment": "abc123def456"
        }
      ],
      "pedigree": {
        "ancestors": [
          {
            "type": "library",
            "name": "openssl",
            "version": "3.0.7",
            "purl": "pkg:generic/openssl@3.0.7?download_url=https://github.com/(RH openssl midstream repo)/archive/refs/tags/3.0.7.tar.gz"
          }
        ]
      }
    }
    ```

For `generic` source purls and `download_url` conventions, see [Upstream source purls for RPM builds](purl.md#upstream-source-purls-for-rpm-builds).

**SPDX 2.3 encoding options**

| Option | Mechanism | Pros | Cons |
|--------|-----------|------|------|
| **A. Tarball packages only** (current) | Source0-origin `name` + `downloadLocation` | Faithful to fetched artifacts | RPM name may not match upstream search terms |
| **B. SRPM homepage** | `homepage` from spec URL (verbatim) | Simple; enables downstream URL→name mapping | No structured upstream name in SBOM |
| **C. VCS externalRef** | `OTHER/vcs` on non-rpm source packages | Precise commit | SPDX rpm SRPM vcs refs lost on release regen |
| ~~D. Upstream project package~~ | ~~Synthetic package with derived name~~ | — | **Rejected:** name translation belongs downstream |

**Recommendation:** **A + B** for SPDX SRPM (`homepage` on rpm packages only).

**CycloneDX 1.6 encoding options**

| Option | Mechanism | Pros | Cons |
|--------|-----------|------|------|
| **A. pedigree.ancestors** (current SBOMer) | Nested ancestors on SRPM | Matches SBOMer output | `name` from tarball, not canonical upstream |
| **B. externalReferences** | `website` + `vcs` on SRPM | Standard fields; carries spec URL verbatim | Not in all current SBOMer output |
| ~~C. Separate upstream component~~ | ~~Extra component with derived name~~ | — | **Rejected:** name translation belongs downstream |
| ~~D. properties~~ | e.g. `redhat:upstream-name` | — | **Avoid** (non-standard) |

**Recommendation:** **A + B** as available.

**SPDX ↔ CycloneDX equivalence**

| Concept | SPDX | CycloneDX |
|---------|------|-----------|
| Upstream project URL (verbatim) | `homepage` on SRPM | `externalReferences[type=website]` |
| Dist-git checkout | *(omit vcs on rpm SRPM in release examples)* | `externalReferences[type=vcs]` (placeholder) |
| Upstream git (`source-repos`) | source package `downloadLocation` + vcs ref (URL as-is) | `externalReferences[type=vcs]` or pedigree leaf with literal URL |
| Tarball archive | SourceN package + `downloadLocation` | `pedigree.ancestors` leaf `purl` with `download_url` |
| SRPM → binary RPM | `GENERATED_FROM` | `dependencies` (`provides` / `dependsOn`) |
| RPM name → upstream name | **Not in SBOM** | **Not in SBOM** |

##### RPM (CycloneDX 1.6)

CycloneDX 1.6 RPM build SBOMs follow the same component model as SPDX: one document per Koji build, with the SRPM as
`metadata.component` and a matching entry in `components[]` that carries `pedigree.ancestors`.

**SRPM component**

- `metadata.component` — the SRPM without `bom-ref`; mirrors the top-level build subject.
- `components[]` SRPM entry — same purl as `metadata.component`, includes `bom-ref`, `pedigree`, and any
  `externalReferences` not duplicated on `metadata.component` (examples include both for clarity).
- Binary subpackage RPMs — separate `components[]` entries with `pkg:rpm/redhat/...` purls.

**Provenance**

- `pedigree.ancestors[]` — nested chain of source archives consumed by the SRPM, equivalent to SPDX `CONTAINS` /
  `GENERATED_FROM` between SourceN and midstream/upstream packages. Leaf `purl` values use `pkg:generic/...` with
  `download_url` per [purl guidelines](purl.md#upstream-source-purls-for-rpm-builds).
- `externalReferences` — `website` for spec `%URL:` (verbatim); `vcs` for dist-git/Koji build context (placeholder
  URLs in committed examples).

**Dependencies**

- `dependencies[].ref` — SRPM `bom-ref`.
- `dependencies[].provides` — purls of binary RPMs generated from the SRPM (`GENERATED_FROM` equivalent).
- `dependencies[].dependsOn` — bundled provides (`bundled()` / `golang()`) linked to the SRPM.

**Release-time additions**

- `evidence.identity` on binary RPM components — alternate purls with `repository_id` qualifiers (see release examples).
- `properties` — `package:rpm:sigmd5` and `package:rpm:sha256header` from RPM header annotations.

Example: [openssl-3.0.7-18.el9_2.cdx.json](../sbom/examples/rpm/release/openssl-3.0.7-18.el9_2.cdx.json).

##### Bundled dependencies

Some RPM spec files declare copylib or vendored components using `Provides: bundled(...)` or
`Provides: golang(...)`. These are recorded on binary subpackage RPM headers (for example
`vim-enhanced` may provide `bundled(libvterm)`), not on the SRPM itself. Collect them from
Koji `getRPMDeps` Provides (type `1`) across every RPM in the build.

Each bundled component should be represented as its own package object, linked to the SRPM with
a `DEPENDENCY_OF` relationship (the bundled package is a dependency of the SRPM build). Set
`primaryPackagePurpose` to `LIBRARY`, `downloadLocation` to `NOASSERTION`, and `filesAnalyzed`
to `false`.

Use a typed purl when the provide name indicates the ecosystem:

| Language prefix in provide | purl type | Example provide | Example purl |
|----------------------------|-----------|-----------------|--------------|
| *(none)* / generic bundled | `generic` | `bundled(libvterm)` | `pkg:generic/libvterm` |
| `golang(...)` | `golang` | `golang(github.com/foo/bar) = 1.2.3` | `pkg:golang/github.com/foo/bar@1.2.3` |
| `bundled(python*(...))` <br> `bundled(python*-...)` | `pypi` | `bundled(python(requests)) = 2.31.0` <br> `bundled(python3dist(requests)) = 2.31.0` <br> `bundled(python3-requests) = 2.31.0` | `pkg:pypi/requests@2.31.0` |
| `bundled(nodejs*(...))` <br> `bundled(npm*(...))` <br> `bundled(nodejs-...)` | `npm` | `bundled(nodejs(lodash)) = 4.17.21` <br> `bundled(npm(lodash)) = 4.17.21` <br> `bundled(nodejs-lodash) = 4.17.21` | `pkg:npm/lodash@4.17.21` |
| `bundled(ruby*(...))` <br> `bundled(rubygem-...)` | `gem` | `bundled(ruby(rake)) = 13.0.6` <br> `bundled(rubygem-rake) = 13.0.6` | `pkg:gem/rake@13.0.6` |
| `bundled(crate*(...))` | `cargo` | `bundled(crate(serde)) = 1.0.0` | `pkg:cargo/serde@1.0.0` |
| `bundled(mvn*(...))` | `maven` | `bundled(mvn(org/foo)) = 1.0.0` | `pkg:maven/org/foo@1.0.0` |

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-Bundled-11cdd6f19dc1",
      "name": "libvterm (generic)",
      "versionInfo": "NOASSERTION",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "primaryPackagePurpose": "LIBRARY",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/libvterm"
        }
      ]
    }
    ```

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-Bundled-11cdd6f19dc1",
      "relationshipType": "DEPENDENCY_OF",
      "relatedSpdxElement": "SPDXRef-SRPM"
    }
    ```

**Example:** the build-time SBOM for `vim-9.1.083-5.el10` includes `bundled(libvterm)` from
the `vim-enhanced` subpackage:
[build/vim-9.1.083-5.el10](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/build/vim-9.1.083-5.el10.spdx.json).

Bundled components declared in the spec are distinct from:

- **Source archives** (`Source0`, `Source1`, …), which are linked with `CONTAINS` from the SRPM.
- **Components discovered by scanning** an unpacked source tree (for example with Syft), which
  are nested under the relevant source archive.

#### Disk Image

!!! note "Proposal"
    This section is a proposal under review. Items marked **Open question** need a decision from Red Hat Product
    Security before they become normative.

A disk image is a single bootable or installable artifact (for example a qcow2, raw, vmdk, vhd, ami, or tar
image, or an installer ISO) that contains one or more filesystems with installed software. Unlike a container image,
a disk image has no native registry identity: it is a file, identified by its checksum. This section applies to disk
images built by Red Hat (for example with image-builder/osbuild) regardless of how they are distributed.

Complete examples: [`sbom/examples/disk_image/`](https://github.com/RedHatProductSecurity/security-data-guidelines/tree/main/sbom/examples/disk_image).

##### Disk image package

The SBOM document must _DESCRIBE_ exactly one package that represents the disk image artifact itself:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-disk-image",
      "name": "rhel-9.6-x86_64-kvm",// (1)!
      "versionInfo": "9.6",
      "supplier": "Organization: Red Hat",
      "downloadLocation": "NOASSERTION",
      "packageFileName": "rhel-9.6-x86_64-kvm.qcow2",// (2)!
      "licenseConcluded": "NOASSERTION",
      "primaryPackagePurpose": "OPERATING_SYSTEM",// (3)!
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/rhel-9.6-x86_64-kvm@9.6?arch=x86_64&checksum=sha256:9f3c...&download_url=https://access.redhat.com/downloads/content/rhel/rhel-9.6-x86_64-kvm.qcow2"// (4)!
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "9f3c..."// (5)!
        }
      ]
    }
    ```

    1. A descriptive name of the image, without the file extension.

    2. The file name of the final artifact as delivered.

    3. `OPERATING_SYSTEM` for any image that contains a bootable or installable operating system.

    4. See [purl identifiers](#disk-image-purl) below.

    5. SHA256 of the final artifact file exactly as delivered (after compression, if the delivered file is compressed).

[`checksums`](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)
:   The disk image package must include the SHA256 checksum of the final artifact file. The checksum must be computed
    after the artifact is fully assembled (and compressed, if applicable), so it can only be added at build time, not
    when the SBOM is generated ahead of the build from a manifest. An SBOM without this checksum must not be published
    as a release-time SBOM.

`packageFileName`
:   Must be set to the file name of the delivered artifact.

`primaryPackagePurpose`
:   Must be `OPERATING_SYSTEM` for images containing an operating system.

`supplier`, `versionInfo`
:   As for any other component: `Organization: Red Hat` and the most granular version of the image (for example the
    OS minor version plus a build or compose identifier).

license information
:   Should be `NOASSERTION`; licenses belong to the contained components.

<a id="disk-image-purl"></a>purl identifiers
:   There is no purl type for disk images. Disk images must use a [`generic` purl](./purl.md#generic-components)
    whose name is the image name, with the `arch` qualifier, a `checksum` qualifier equal to the SHA256 above, and a
    `download_url` qualifier pointing to where the artifact is published. When the image is also distributed as an
    OCI artifact in a container registry, the package should additionally carry an `oci` purl for that artifact (see
    [Distribution through a container registry](#distribution-through-a-container-registry)).

    **Open question:** a build-time SBOM does not know the final `download_url`. Should build-time SBOMs omit the
    qualifier (relaxing the generic purl rule) and have it added at release time, or should the build use a
    placeholder?

##### Installed content

All RPMs installed in the image must be listed as packages following the [RPM](#rpm) rules (purl with
`repository_id`, SHA256 checksum, `packageFileName`, SRPM linked with `GENERATED_FROM`), and must be linked to the
package that represents the filesystem they are installed in with `CONTAINS`. For a single-OS image, that is the disk
image package itself:

=== "SPDX 2.3"

    ```json
    {
      "relationships": [
        {
          "spdxElementId": "SPDXRef-DOCUMENT",
          "relationshipType": "DESCRIBES",
          "relatedSpdxElement": "SPDXRef-disk-image"
        },
        {
          "spdxElementId": "SPDXRef-disk-image",
          "relationshipType": "CONTAINS",
          "relatedSpdxElement": "SPDXRef-x86-64-openssl-libs"
        },
        {
          "spdxElementId": "SPDXRef-x86-64-openssl-libs",
          "relationshipType": "GENERATED_FROM",
          "relatedSpdxElement": "SPDXRef-SRPM-openssl"
        }
      ]
    }
    ```

Only content that is actually present in the delivered image may be linked with `CONTAINS`. Packages that were
present only in the build environment must not be listed in the image SBOM (see
[Build environment](#build-environment)). Software installed outside of RPM (for example firmware blobs or files
written by the build) should be listed as separate packages where it can be identified.

##### Multiple filesystems

Partitions of a single installed OS (for example `/`, `/boot`, `/boot/efi`) are populated from one package set and
should not be modelled separately; the RPMs are contained directly by the disk image package.

When an image contains filesystems with _independent_ content sets, each filesystem must be represented as its own
package, contained by the disk image package, and each RPM must be contained by the filesystem package(s) it is
installed in. The typical case is an installer ISO, which contains the installer runtime environment (which runs
during installation but is never installed on the target) and the payload (which is installed onto the target):

```
rhel-9.6-x86_64-dvd (OPERATING_SYSTEM, sha256 of the .iso)
├── CONTAINS rhel-9.6-x86_64-dvd-installer-environment (INSTALL, sha256 of images/install.img)
│   ├── CONTAINS anaconda-core, kernel-core, bash, ...
├── CONTAINS rhel-9.6-x86_64-dvd-payload (OPERATING_SYSTEM)
│   ├── CONTAINS kernel-core, openssl-libs, bash, ...
└── BUILD_TOOL_OF ← DocumentRef-buildroot:SPDXRef-buildroot   (separate SBOM)
```

- Filesystem packages must set `primaryPackagePurpose` to `INSTALL` for installer runtime environments and to
  `OPERATING_SYSTEM` for content installed onto the target.
- When the filesystem exists as a file inside the image (for example `images/install.img`), the filesystem package
  should set `packageFileName` to its path and include its SHA256 checksum.
- An RPM that is present in more than one filesystem (same NEVRA and checksum) must be listed once and contained by
  each filesystem package; it must not be duplicated.
- All filesystems of one deliverable must be described in a single SBOM document, so vulnerability tooling sees the
  complete content of the artifact.

**Open question:** are vulnerabilities in the installer environment in scope for Red Hat VEX statements for the
image, or should installer-only components be scoped differently (for example by a different relationship)?

##### Build environment

Packages used only to build the image (the build root: osbuild, xorriso, dracut, and so on) must not appear in the
image SBOM. They must be described in a separate SBOM document, referenced from the image SBOM through
`externalDocumentRefs`, with a `BUILD_TOOL_OF` relationship from the root package of the build environment SBOM to
the disk image package:

=== "SPDX 2.3"

    ```json
    {
      "externalDocumentRefs": [
        {
          "externalDocumentId": "DocumentRef-buildroot",
          "spdxDocument": "https://www.redhat.com/rhel-9.6-x86_64-kvm-buildroot.spdx.json",
          "checksum": {
            "algorithm": "SHA1",
            "checksumValue": "1d6b..."
          }
        }
      ],
      "relationships": [
        {
          "spdxElementId": "DocumentRef-buildroot:SPDXRef-buildroot",
          "relationshipType": "BUILD_TOOL_OF",
          "relatedSpdxElement": "SPDXRef-disk-image"
        }
      ]
    }
    ```

Keeping the build environment in a separate document prevents vulnerability scanners, which generally ignore
relationship types, from reporting build-only packages as shipped content.

##### Disk images built from a container image

Image mode (bootc) disk images are produced by converting a bootc container image into a disk image. The container
image already has its own SBOM. The disk image SBOM should not copy the container's content. Instead:

- the disk image package must be described as above, with its own SHA256 checksum, `packageFileName`, and purl;
- the container image SBOM must be referenced in `externalDocumentRefs`, and the disk image package must have a
  `GENERATED_FROM` relationship to the container image package in that document;
- content added by the disk build itself, if any (for example a bootloader installed outside the container's
  content), must be listed and contained by the disk image package;
- the build environment is referenced as described above.

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-disk-image",
      "relationshipType": "GENERATED_FROM",
      "relatedSpdxElement": "DocumentRef-container:SPDXRef-image"
    }
    ```

**Open question:** most scanners, as well as Trusted Profile Analyzer, do not follow `externalDocumentRefs`. Until
they do, is copying the container's packages into the disk image SBOM (with `CONTAINS`) an acceptable interim
alternative, and should the referenced container SBOM be resolvable through the `documentNamespace`?

##### Distribution through a container registry

Disk images may be pushed to a container registry as OCI artifacts, where the disk file is a blob in an artifact
manifest. This is a distribution channel; it does not change what the SBOM describes. The SBOM still describes the
disk image as defined above; no additional wrapper package for the OCI artifact is required. The disk image package:

- should carry an additional `oci` purl that identifies the artifact manifest, for example
  `pkg:oci/rhel-kvm@sha256%3A<manifest digest>?repository_url=registry.redhat.io/rhel9/rhel-kvm&tag=9.6`;
- keeps the SHA256 checksum of the disk file itself (which equals the digest of the disk blob in the artifact
  manifest, not the manifest digest);
- may be attached to the artifact as an SBOM attestation or referrer like any container image SBOM.

**Open question:** the `oci` purl differs in type from the `generic` purl, which conflicts with the rule that
multiple purls on one package may differ only in their qualifiers. Is this exception acceptable for disk images, or
should the OCI artifact be a separate package (for example with `DISTRIBUTION_ARTIFACT` or `CONTAINS`) that is
_DESCRIBED_ alongside the disk image?

##### CISA minimum elements

The rules above, together with the [Document Structure](#document-structure) rules, cover the
[CISA 2026 Minimum Elements for an SBOM](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom)
for disk images:

| CISA element | Where it is satisfied |
|---|---|
| SBOM author, tool name, timestamp | `creationInfo.creators`, `creationInfo.created` |
| Generation context | `creationInfo.comment` (for example `SBOM generation context: build.`) |
| Component name, version, producer | `name`, `versionInfo`, `supplier` of every package |
| Software identifiers | purl on every package (`generic`/`oci` for the image, `rpm` for content) |
| Component hash | SHA256 of the final artifact on the disk image package; SHA256 on every RPM |
| License | `licenseConcluded` on contained components |
| Dependency relationships | `CONTAINS` (image → filesystem → RPM), `GENERATED_FROM` (RPM → SRPM, disk → container) |
| Coverage of build tools | separate build environment SBOM linked with `BUILD_TOOL_OF` |

#### Product

Individual components such as packages and container images are almost always provided as part of a specific product.
Products represent a bundle of components that can be purchased, has a life cycle
([example](https://access.redhat.com/support/policy/updates/errata#RHEL8_and_9_Life_Cycle)) defined for it, and
a support policy.

If one or more components described in a given SBOM are being provided as part of a product, that product should
be represented with its own package object:

=== "SPDX 2.3"

    ```json
    {
      "SPDXID": "SPDXRef-RHEL-9.2-EUS",
      "name": "Red Hat Enterprise Linux",
      "versionInfo": "9.2 EUS",
      "supplier": "Organization: Red Hat",
      "downloadLocation": "NOASSERTION",// (1)!
      "licenseConcluded": "NOASSERTION",// (2)!
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceLocator": "cpe:/a:redhat:rhel_eus:9.2::baseos",
          "referenceType": "cpe22Type"
        }
      ]
    }
    ```

    1. Not used because this product component is not specific enough to an architecture or ISO variant (for example,
       workstation vs server) for there to be an exact download location.

    2. Not set, only components have licenses.

`name`
:   This field must contain a human-readable name of the product.

`versionInfo`
:   This field must contain the most granular version of the product, for which the SBOM was generated.

`externalRefs`
:   External references must contain a unique identifier of the product. Red Hat uses CPE IDs to identify products.
    A given product may have one or more of these identifiers, covering all possible variants of a single product
    version.

A relationship between a component and the product it is a part of can be represented as:

=== "SPDX 2.3"

    ```json
    {
      "spdxElementId": "SPDXRef-SRPM-1",
      "relationshipType": "PACKAGE_OF",
      "relatedSpdxElement": "SPDXRef-RHEL-9.2-EUS"
    }
    ```

## Compliance Validation

To validate an SBOM against the guidelines in this document, use
[SBOM-Grader](https://github.com/BorekZnovustvoritel/SBOM-Grader), a tool developed by the Red Hat
SBOM team in collaboration with Red Hat Product Security. It supports both SPDX and CycloneDX formats
and checks compliance against the rules defined here.

## Additional Notes

The guidelines highlighted in this document represent an ideal state across all of Red Hat-published security data
that we want to achieve in the long term. In some SBOMs, components may be missing their provenance data or their
license expressions may not be accurate. Please
[contact Red Hat Product Security](https://access.redhat.com/security/team/contact/) or file a Jira issue in the
[SECDATA project](https://redhat.atlassian.net/projects/SECDATA) if you find any discrepancies in Red Hat's security data.
Feedback on our SBOM design and publishing is always welcome and appreciated.
