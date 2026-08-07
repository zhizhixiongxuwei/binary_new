# Third-party notices

This source package contains application source, dependency lock files, and a
small set of reviewed license texts. It does not contain Docker images, Trivy
databases, decompiler binaries, JDK files, or downloaded dependency archives.

## Application dependencies

- The Go module inventory is fixed by `go.mod` and `go.sum`.
- The Vue/Node inventory is fixed by `web/package.json` and
  `web/package-lock.json`.
- `rardecode` is BSD-2-Clause; its reviewed text is in
  `licenses/rardecode-v2.2.3.txt`.
- The MIME helper's reviewed text is in `licenses/mimetype-v1.4.3.txt`.

## External runtime images

The separately delivered images are independent distribution artifacts and
must carry their own complete license and notice bundles:

- Trivy: Apache-2.0 and bundled dependency notices.
- Ghidra: Apache-2.0, NOTICE, and its third-party license directory.
- The selected JDK: distribution-specific license and notices.
- Vineflower and JADX: Apache-2.0 and applicable notices.
- CFR: MIT license and copyright notice.
- MySQL and every archive/image utility: the complete terms required by the
  exact selected build.

`licenses/tool-license-reviews.json` is an engineering review record, not a
substitute for legal approval or the license bundle inside each external
image. The image identities used for an acceptance release are recorded in
`images.lock.env`; image tar hashes are recorded separately in
`IMAGE_FILES.sha256`.
