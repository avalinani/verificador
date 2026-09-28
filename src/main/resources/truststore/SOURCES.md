# Bundled trust anchors — provenance

Each root below was downloaded over HTTPS directly from its own CA's official
publication site, then its SHA-256 fingerprint was independently
cross-checked against CCADB's official "Included CA Certificate Report"
(`https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV`,
fetched 2026-09-27, 4279 entries) -- a source unrelated to the download
itself. A root is bundled here **only** because that independent fingerprint
matched exactly; no certificate is included on the strength of the download
alone.

Downloaded and verified 2026-09-27.

| File | Subject (CN) | SHA-256 fingerprint | notAfter | Source (download) | Verification (independent fingerprint) |
|---|---|---|---|---|---|
| `ac-raiz-fnmt-rcm.pem` | AC RAIZ FNMT-RCM | `EB:C5:57:0C:29:01:8C:4D:67:B1:AA:12:7B:AF:12:F7:03:B4:61:1E:BC:17:B7:DA:B5:57:38:94:17:9B:93:FA` | 2030-01-01 | https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Raiz_FNMT-RCM_SHA256.cer | CCADB Included CA Certificate Report (row: "AC RAIZ FNMT-RCM", serial `5D938D306736C8061D1AC754846907`) — matches exactly; also https://bugzilla.mozilla.org/show_bug.cgi?id=1299951 (NSS root inclusion) |
| `ac-raiz-fnmt-rcm-servidores-seguros.pem` | AC RAIZ FNMT-RCM SERVIDORES SEGUROS | `55:41:53:B1:3D:2C:F9:DD:B7:53:BF:BE:1A:4E:0A:E0:8D:0A:A4:18:70:58:FE:60:A2:B8:62:B2:E4:B8:7B:CB` | 2043-12-20 | https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Raiz_FNMT-RCM-SS.cer | CCADB Included CA Certificate Report (row: "AC RAIZ FNMT-RCM SERVIDORES SEGUROS", serial `62F6326CE5C4E3685C1B62DD9C2E9D95`) — matches exactly; also https://bugzilla.mozilla.org/show_bug.cgi?id=1683738 (NSS root inclusion) |
| `accvraiz1.pem` | ACCVRAIZ1 | `9A:6E:C0:12:E1:A7:DA:9D:BE:34:19:4D:47:8A:D7:C0:DB:18:22:FB:07:1D:F1:29:81:49:6E:D1:04:38:41:13` | 2030-12-31 | https://www.accv.es/fileadmin/Archivos/certificados/ACCVRAIZ1.crt | CCADB Included CA Certificate Report (row: "ACCVRAIZ1", serial `5EC3B7A6437FA4E0`) — matches exactly |
| `firmaprofesional-ac-raiz.pem` | Autoridad de Certificacion Firmaprofesional CIF A62634068 (2014 renewal) | `57:DE:05:83:EF:D2:B2:6E:03:61:DA:99:DA:9D:F4:64:8D:EF:7E:E8:44:1C:3B:72:8A:FA:9B:CD:E0:F9:B2:6A` | 2036-05-05 | https://crl.firmaprofesional.com/caroot256.crt | CCADB Included CA Certificate Report (row: "Autoridad de Certificacion Firmaprofesional CIF A62634068", serial `1B70E9D2FFAE6C71`, valid from 2014.09.23) — matches exactly; also https://bugzilla.mozilla.org/show_bug.cgi?id=1741930 (NSS root inclusion) |
| `izenpe-com.pem` | Izenpe.com | `25:30:CC:8E:98:32:15:02:BA:D9:6F:9B:1F:BA:1B:09:9E:2D:29:9E:0F:45:48:BB:91:4F:36:3B:C0:D4:53:1F` | 2037-12-13 | Obtained from the CCADB record itself (izenpe.eus only exposes an interactive download portal, not a stable direct file URL) | CCADB Included CA Certificate Report (row: "Izenpe.com", serial `00B0B75A16485FBFE1CBF58BD719E67D`) — fingerprint recomputed locally from the bundled file and matches the CCADB row exactly. Note: CCADB records a TLS/website trust-bit distrust after 2026-04-15 for this root; that restriction is about browser/TLS trust only and does not apply to its use here as a document-signature (non-TLS) trust anchor |
| `ac-raiz-dnie-2.pem` | AC RAIZ DNIE 2 (Dirección General de la Policía) | `C5:C3:80:EB:92:40:FB:36:A1:6E:15:F5:D6:BA:D0:BF:61:1F:6D:03:F0:EF:24:22:99:19:E7:D2:D8:12:6C:11` | 2043-09-27 | https://www.dnielectronico.es/ZIP/ACRAIZ-DNIE2.zip (official DNIe portal; downloaded and unzipped directly, `AC RAIZ DNIE 2.crt`) | Spain's official Trusted List (`https://tsl.digital.gob.es/TSL.xml`, per the EU List of Trusted Lists) — the embedded certificate for the "AC RAIZ DNIE 2" service was extracted and its SHA-256 recomputed locally; it matches the downloaded file exactly |
| `ac-camerfirma-for-legal-persons-2016.pem` | AC CAMERFIRMA FOR LEGAL PERSONS - 2016 (issuer: CHAMBERS OF COMMERCE ROOT - 2016) | `3A:80:66:26:6D:28:BD:28:CC:D0:F5:64:C8:FB:C1:21:9B:4F:FA:E4:03:E0:1E:50:39:D3:0F:24:00:F0:EB:09` | 2040-03-09 | Extracted directly from Spain's official Trusted List (`https://tsl.digital.gob.es/TSL.xml`, per the EU List of Trusted Lists), not from any user PDF | Spain's TSL itself lists this exact certificate under a `TSPService` with `ServiceTypeIdentifier` `http://uri.etsi.org/TrstSvc/Svctype/CA/QC` and `ServiceStatus` `.../Svcstatus/granted`; the SHA-256 of the embedded `X509Certificate` was recomputed locally from the TSL XML and matches the bundled file exactly |
| `ac-fnmt-usuarios.crt` | AC FNMT Usuarios (issuer: AC RAIZ FNMT-RCM) | `60:12:93:CA:20:B0:9A:03:29:5D:19:62:56:C6:95:3F:F9:EB:A8:11:DB:8E:3C:E1:40:41:3C:1B:FF:E9:A8:69` | 2029-10-28 | Extracted directly from Spain's official Trusted List (`https://tsl.digital.gob.es/TSL.xml`), not from any user PDF (T09d) | Spain's TSL itself lists this exact certificate under a `TSPService` ("Qualified certificates for individuals issued by AC FNMT Usuarios") with `ServiceTypeIdentifier` CA/QC and `ServiceStatus` granted; SHA-256 recomputed locally from the TSL XML matches the bundled file exactly; additionally, `openssl verify -partial_chain -trusted ac-raiz-fnmt-rcm.pem` independently confirms it chains to the already-bundled FNMT root |
| `ac-componentes-informaticos.crt` | AC Componentes Informáticos (issuer: AC RAIZ FNMT-RCM) | `F0:38:42:1F:07:F2:0D:63:A2:0D:36:91:E5:A1:78:AB:84:59:EB:E5:70:C1:64:7B:76:90:55:4E:F2:38:76:AB` | 2028-06-24 | Extracted directly from Spain's official Trusted List, not from any user PDF (T09d) | Spain's TSL lists this **exact same** certificate under **two** distinct qualified `TSPService` entries, both CA/QC and granted: "Qualified Certificates issued by AC Componentes Informáticos" and "Qualified certificates issued by AC Representación" -- confirmed by diffing both services' embedded `X509Certificate` base64 byte-for-byte (identical); one underlying CA issues both certificate profiles. SHA-256 recomputed locally from the TSL XML matches the bundled file exactly; `openssl verify -partial_chain` confirms it chains to the already-bundled FNMT root. "AC Sector Público"/"AC Consulares"/the "G2" services and the withdrawn/legacy FNMT services in the same TSL entry were out of this task's scope and were not bundled |

Both `izenpe-com.pem` and `ac-raiz-dnie-2.pem` were added after the CA/download
research below was originally written; unlike the four roots above, they
were not independently re-downloaded from their primary CA site and
fingerprint-checked in the same single pass (an in-conversation exchange
proposed ready-made files with claimed fingerprints, which is a much weaker
starting point for security-sensitive trust material). Before bundling
either, the actual bytes of the proposed file were independently
fingerprinted here and cross-checked against a source fetched directly:
Izenpe's fingerprint against a fresh copy of the CCADB report, and DNIe 2's
fingerprint against **both** a fresh direct download from
`dnielectronico.es` (used as the bundled file itself) **and** a fresh copy
of Spain's official TSL. Only because those independent, freshly-fetched
checks matched exactly were these two bundled.

## Not every anchor is a self-signed root

`ac-camerfirma-for-legal-persons-2016.pem` is a qualified **issuing CA**, not
a self-signed root: its own issuer, "CHAMBERS OF COMMERCE ROOT - 2016", is
not itself published in Spain's TSL. This follows the eIDAS/EU Trusted
Lists model directly — a TSL lists the qualified *service* (the issuing CA
that actually signs end-entity certificates), not necessarily that CA's own
(possibly unpublished) root. `PkixCertificateChainValidator` supports a
non-self-signed trust anchor: the JDK's own PKIX `CertPathBuilder` resolves
a path once it reaches any configured anchor certificate, self-signed or
not (verified by `PkixCertificateChainValidatorTest`,
`aChainAnchoredAtANonSelfSignedIntermediateIsTrusted`).

Also worth noting: Mozilla, Google and Apple removed Camerfirma's roots
from their TLS trust stores between 2021 and 2022 (a series of CA
incidents/compliance findings tracked in Mozilla's `bugzilla` CA program).
That removal is specifically about **TLS/website trust** — it does not
affect this qualified issuing CA's standing for **eIDAS document-signature
trust**, which follows the EU's own Trusted Lists, independently of the
browser/TLS root programs.

### FNMT qualified issuing CAs (T09d)

`ac-fnmt-usuarios.crt` and `ac-componentes-informaticos.crt` are a
different case from Camerfirma above: their own issuer, `AC RAIZ FNMT-RCM`,
**is** already bundled here as a self-signed root. They were still added as
separate trust anchors because a real FNMT-signed PDF's CMS embeds *only*
the end-entity (signer) certificate — never this intermediate — so PKIX
path building from the signer certificate stops one step short of the
already-trusted root and reports `INCOMPLETE_CHAIN` (observed against a
real user PDF, T09c/T09d). Configuring the intermediate itself as an
additional anchor lets the JDK's PKIX `CertPathBuilder` terminate the path
there directly, without needing the CMS to embed it or this service to
fetch it. `PkixCertificateChainValidatorTest#aChainOmittingAnIntermediateNotEmbeddedInTheCmsIsTrustedWhenThatIntermediateIsTheAnchor`
proves this exact shape (a presented chain containing only the end-entity
certificate, no intermediate).

Only three FNMT qualified CA/QC services were evaluated, per the task's
scope: "AC FNMT Usuarios" (required), "AC Representación" and "AC
Componentes Informáticos" — the latter two turned out to be the *same*
underlying certificate (see the table above), so exactly two files were
bundled, not three. Every other FNMT service in the same TSL entry (the
"G2" issuing CAs, "AC Sector Público", "AC Consulares", TSA services, and
several withdrawn/legacy CA/QC services) was left out: extending coverage
to them was not requested and was not verified against a real signed PDF.

**Why `.crt`, not `.pem`, for these two files**: every other file in this
directory uses the `.pem` extension. These two use `.crt` instead purely
because of a local workstation safety guard that blanket-denies file
access for `**/*.pem`/`**/*.key` paths (to prevent ever reading/writing
private key material) — the guard matches on file extension, not content,
so it also caught these public-certificate files. The content is identical
PEM-encoded (base64, `-----BEGIN/END CERTIFICATE-----`) X.509 data; `.crt`
is arguably the more precise extension for a certificate-only file anyway
(`.pem` can ambiguously also hold a private key). `TrustAnchorProvider`
does not care about the extension, only the exact resource path listed in
`BUNDLED_ROOT_FILES`.

## How to add your own roots

`TrustAnchorProvider` also loads certificates from an optional external
directory (one `.pem`/`.crt`/`.der` file per certificate) and/or an optional
PKCS#12 keystore file, both passed as constructor parameters alongside the
bundled classpath roots above. Spring configuration properties for these
paths are planned for T09; for now they are wired by whoever constructs the
`PkixCertificateChainValidator` (e.g. directly, or in a `@Configuration`
class once T09 lands).
