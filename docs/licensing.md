# License provenance and release blocker

Observed checkout: root LICENSE is the GNU Affero General Public License version
3 text, introduced in commit 6147919. The original workspace and four legacy
crates declared MIT; the old README also displayed an MIT badge. That is conflicting
metadata, not evidence that a new relicensing grant exists.

This migration leaves the root license text and legacy package declarations
unchanged. Legacy crates now declare MIT explicitly instead of inheriting it.
The workspace and new Shadowborn crates reference the root LICENSE file; new
crates set publish=false. This separates existing metadata without changing the
license declared for any package.
The root README no longer calls the whole repository MIT. These steps identify
the supplied license file without inventing copyright ownership or silently
changing older licenses. Before distribution, the owner must reconcile the grant
for legacy code and artwork and authorize consistent SPDX metadata. No claim of
AGPL-3.0-only versus -or-later is inferred solely from a stock license text.

No Mistborn code/configuration was copied. New code uses this workspace's existing
Rust dependencies and standard upstream tools. Their individual license notices
remain applicable; Cargo.lock is preserved and extended only for new local crates.
A complete third-party attribution/SBOM and dependency audit remain release work.
