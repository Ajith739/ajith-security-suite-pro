# Third-party notices and provenance

Reviewed 21 October 2026. Existing copyright/license texts remain in place. No implementation, rules, signatures, data, assets or credentials from the twelve references were copied in this review. Independent changes extend Gracewell's existing services. Historical provenance of all project source has not been independently certified.

## Existing distributed components

| Component | Declared version / source | Local files and obligations |
|---|---|---|
| Three.js | r160 / https://github.com/mrdoob/three.js/tree/r160 | assets/vendor/three/three.module.js; MIT in assets/vendor/three/LICENSE.txt. Retain three.js authors' copyright, permission and disclaimer. Local REVISION is 160; upstream byte identity not verified. |
| qrcode-generator | Existing notice declares 2.0.4 / https://github.com/kazuhikoarase/qrcode-generator | assets/js/qrcode.js includes a local wrapper. Retain Kazuhiko Arase MIT header and full text in THIRD-PARTY-NOTICES.txt. Exact version/hash not independently verified. |
| lbuchs/webauthn | Bundled notice declares 2.2.0 / https://github.com/lbuchs/WebAuthn | includes/vendor/webauthn/; namespaces scoped to Gracewell. Preserve BUNDLED-NOTICE.txt and MIT LICENSE, including Lukas Buchs and Thomas Bleeker's CBOR/ByteBuffer attribution. Upstream modification diff remains to be verified. |

## Reference projects studied, not imported

| Project / actual local version | Author/source identity | Local license evidence / disposition |
|---|---|---|
| All-In-One Security 5.4.10 | Updraft / AIOS; https://wordpress.org/plugins/all-in-one-wp-security-and-firewall/ | GPLv3-or-later; separate dependencies. Study only. |
| BBQ 20260809 | Jeff Starr / Monzilla Media; https://perishablepress.com/block-bad-queries/ | GPLv2-or-later. Study only. |
| Fail2WP 1.3.0 | Joaquim Homrighausen / WebbPlatsen; https://github.com/joho1968/Fail2WP | GPL-2.0+ header and GPLv2 prose differ in later-version wording. Exact-file review required before reuse. |
| Patchstack 2.3.7 | Patchstack; https://github.com/patchstack/wordpress-plugin | GPLv3 header; GPL-3.0-or-later Composer. Feeds/rules/API rights separate. Study only. |
| Shield 22.3.0 | Fernleaf Systems / Paul Goodchild | Bootstrap GPLv2, Composer GPL-2.0-or-later, readme GPLv3. Human review required before copying. |
| Sucuri 2.8.1 | Sucuri; https://wordpress.org/plugins/sucuri-scanner/ | GPLv2-or-later bootstrap/readme; inspect individual headers/dependencies. Cloud services separate. |
| Two-Factor 0.17.0 | WordPress Contributors; https://github.com/WordPress/two-factor | GPL-2.0-or-later; bundled QR separate. Study only. |
| Wordfence 9.0.2 | Defiant; https://www.wordfence.com/ | GPLv3-or-later bootstrap. Project policy prohibits copying Wordfence code, rules or signatures. Premium feeds/services separate. |
| Wordpresscan, unversioned master | Swisskyrepo; https://github.com/swisskyrepo/Wordpresscan | No root MIT grant found. database/LICENSE contains WPScan Public Source License with commercial restrictions. Excluded from reuse pending verified rights. |
| WP fail2ban 5.4.2 | Charles Lecklider; https://github.com/wp-fail2ban/wp-fail2ban | Directory says 5.5-LTS; bootstrap says 5.4.2. Composer GPL-3.0-only conflicts with bootstrap GPLv3-or-later plus section 7 origin/modified-source terms. Human review before copying. |
| WP Activity Log 5.6.8 | Melapress; https://melapress.com/wordpress-activity-log/ | GPLv3-or-later bootstrap; separate vendor/SDK/assets/extension grants. Study only. |
| WP-WebAuthn 1.4.1 | Axton; https://github.com/yrccondor/wp-webauthn | GPLv3 header/license; later-version prose incomplete. Missing vendor build; exact-file review required. |

Exact paths, mechanisms and conflicts: [integration audit](docs/THIRD-PARTY-INTEGRATION-AUDIT.md) and [license audit](docs/OPEN-SOURCE-LICENSE-AUDIT.md). Source URLs identify provenance; local archives were not authenticated against upstream tags.

Do not infer blanket GPLv2 compatibility from public availability. Future combinations require compatible exact-file grants, preserved notices/disclaimers, corresponding source and applicable distribution obligations. See [GNU compatibility guidance](https://www.gnu.org/licenses/license-compatibility.en.html). This review imports none of those reference implementations. Restricted feeds, proprietary signatures and private keys remain excluded.

Development dependencies in tools/quality/vendor are excluded from runtime distribution. Their locked versions/licenses are in tools/quality/composer.lock; they are separate from runtime bundles and intelligence services.
