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

## How to add your own roots

`TrustAnchorProvider` also loads certificates from an optional external
directory (one `.pem`/`.crt`/`.der` file per certificate) and/or an optional
PKCS#12 keystore file, both passed as constructor parameters alongside the
bundled classpath roots above. Spring configuration properties for these
paths are planned for T09; for now they are wired by whoever constructs the
`PkixCertificateChainValidator` (e.g. directly, or in a `@Configuration`
class once T09 lands).
