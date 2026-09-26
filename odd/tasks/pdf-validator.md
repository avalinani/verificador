# Feature: pdf-validator

## Objective
Stateless web service (TFM) that audits a PDF in one pass: signature integrity (PAdES/CMS), post-signature modifications, RFC 3161 timestamps, X.509 chain trust, optional OCSP/CRL revocation, PDF/A-1b conformance, page properties.

## Constraints
- Java 25 LTS (local: OpenLogic `C:\Program Files\OpenLogic\jdk-25.0.4.7-hotspot`; CI/container: Temurin 25 — same GPLv2+CE license and `crypto.policy=unlimited`; system `java` is 8 — always set JAVA_HOME). Java 27 rejected: non-LTS, outside Boot 4.1 range (17–26). Maven wrapper, Spring Boot 4.1.1 (3.5.x OSS support ended 2026-06-30; user chose to move to 4).
- PDFBox 3.0.8 + preflight 3.0.8 (PDF/A-1b only), Bouncy Castle jdk18on 1.86, springdoc 3.1.1, ArchUnit 1.5.1.
- Boot 4 renamed the web starter: use `spring-boot-starter-webmvc` (non-deprecated), not `spring-boot-starter-web` (deprecated in the 4.1.1 BOM in favor of it).
- Hexagonal: `com.coam.pdfvalidator.{domain,application,infrastructure,api}`; domain free of Spring/PDFBox/BC.
- Code/tests/commits in English; README/UI/slides in Spanish. No login, no persistence.
- Revocation optional (flag), 2 s timeout, UNKNOWN on failure.
- ~400 changed lines per task is advisory only.

## TDD
- Mode: strict (source: user global config "Strict TDD Mode: enabled"). Runner: `./mvnw test` / `./mvnw verify` with JAVA_HOME set to JDK 25.

## Delivery
- Strategy: ask-on-risk. Branch per work unit, Conventional Commits, no AI attribution (user rule).

## Tasks
- [x] T01 Spike: Maven skeleton + wrapper, .gitignore, CI; JUnit test signing a PDF with a test CA (PDFBox+BC) and verifying signature + ByteRange; tampered copy detected. — route: delegated (writer trigger: pom, CI, test, helpers)
- [x] T02 TestPdfFactory fixtures (unsigned, signed, incremental edit, rotated, encrypted, corrupt) + domain records + ports — route: delegated (writer trigger: many non-trivial files — 7 fixture files, 28 domain model files, 8 port/exception files)
- [x] T03 HashCalculator + PdfBoxDocumentReader (versions, pages, rotation, boxes, orientation, encryption/permissions) — route: delegated (writer trigger: 2 new adapter classes + tests + fixtures)
- [ ] T04 BcSignatureVerifier: dict extraction, ByteRange validation, CMS verification, incremental-update detection, multi-signature
- [ ] T05 RFC 3161 timestamp extraction/verification + certificate info extraction
- [ ] T06 BcCertificateChainValidator (PKIX, configurable trust store)
- [ ] T07 PreflightPdfaValidator (PDF/A-1b) + XMP pdfaid detection
- [ ] T08 AnalyzePdfUseCase + ArchUnit rules
- [ ] T09 REST controller, DTOs, ProblemDetail, springdoc, MockMvc + real-PDF integration tests
- [ ] T10 RevocationChecker OCSP/CRL (WireMock)
- [ ] T11 Static UI (index.html, app.js, styles.css)
- [ ] T12 Dockerfile, docker-compose, memory check, VM deploy, Actuator
- [ ] T13 README (all TFM sections + slides URL), slides, JaCoCo

## Acceptance
`./mvnw verify` green (unit, integration, ArchUnit, JaCoCo ≥ 80% on domain/application/infrastructure); manual upload scenarios per plan; deployed URL in README.

## Progress / Evidence
- Setup: `.vscode/settings.json` points IDE and terminal to the local JDK (initially 21, now 25 — see below). Git repo initialized (`main`), branch `feat/signature-spike`.
- T01 done. Maven wrapper generated (3.9.9), `pom.xml` (Spring Boot parent 4.1.1, PDFBox 3.0.8 + preflight, BC jdk18on 1.86, springdoc-openapi-starter-webmvc-ui 3.1.1, ArchUnit 1.5.1, JaCoCo report-on-verify). `spring-boot-starter-web` replaced by `spring-boot-starter-webmvc` per Boot 4.1.1 BOM (starter-web's own POM description flags it "deprecated in favor of spring-boot-starter-webmvc"; confirmed against `spring-boot-dependencies-4.1.1.pom`). Minimal `PdfValidatorApplication` + `application.yml` (multipart max 20MB). `.gitignore`/`.gitattributes`/CI workflow added.
  - Strict TDD: wrote `SignatureSpikeTest` against a deliberately-stubbed `SpikeSignatureChecker` (RED stub returning wrong/false results).
    - RED: `./mvnw -B -q test` → `Tests run: 3, Failures: 2, Errors: 0` (byteRangeStartsAtZero/gap/coversWholeFile stubs returned `false`; the always-`false` `verifyCms` stub coincidentally satisfied the tamper test's `isFalse()`, so 2 of 3 failed as expected from an unimplemented checker).
    - Implemented `SpikeSignatureChecker` for real (PDFBox `Loader.loadPDF` + BC `CMSSignedData`/`SignerInformation`/`JcaSimpleSignerInfoVerifierBuilder`).
    - GREEN: `./mvnw -B -q test` → `target/surefire-reports/...SignatureSpikeTest.txt`: `Tests run: 3, Failures: 0, Errors: 0, Skipped: 0`.
  - Gotcha: PDFBox's `/Contents` placeholder is zero-padded to the reserved `preferredSignatureSize`, so `PDSignature.getContents(pdf)` returns the CMS DER followed by trailing zero bytes. Feeding that directly into `new CMSSignedData(CMSProcessable, byte[])` fails (`CMSException: IOException reading content` → `Extra data detected in stream`), because that constructor requires the byte array to be fully consumed as one ASN.1 object. Fix: parse a single object with `ASN1InputStream.readObject()` into a `ContentInfo` and use the `CMSSignedData(CMSProcessable, ContentInfo)` constructor instead, which tolerates the padding.
  - Full verification: `./mvnw -B verify` → `BUILD SUCCESS` (3/3 tests, jar built, Spring Boot repackage, JaCoCo report generated).
  - Commits (`feat/signature-spike`): `c14ba6e` feat: add project skeleton and PDF signature verification spike; `5cfa253` fix: mark mvnw as executable so CI can run it on Linux runners (git on this Windows checkout has `core.fileMode=false`, so `mvnw` was staged as non-executable `100644`; forced to `100755` via `git update-index --chmod=+x`).
  - Mid-task requirement change (user decision): moved from Spring Boot 3.5.16 to 4.1.1 (3.5.x OSS support ended 2026-06-30) and springdoc 2.9.1 → 3.1.1, before the first commit, so both commits above already reflect Boot 4.1.1.
- Java 25 switch (user decision): OpenLogic JDK 25.0.4+7 installed at `C:\Program Files\OpenLogic\jdk-25.0.4.7-hotspot`; `pom.xml` java.version 25, CI java-version 25, `.vscode/settings.json` updated. Evidence: `./mvnw -B verify` with JDK 25 → 3/3 tests, BUILD SUCCESS (local; CI on JDK 25 not yet run — no remote). Commit `2a15fc0`.
- Review (RDD, high risk: mvnw mode, CI shell): granted, 4 lenses, approved and acknowledged (lineage review-6f65fd116137cb4b, authority burned). Advisory only: stale JDK 21 notes (fixed), Java 25 unverified in CI (pending first push).
- T02 done on branch `feat/domain-model-fixtures` (branched from `feat/signature-spike`).
  - **Fixtures** (`src/test/java/com/coam/pdfvalidator/fixtures/`): `TestPki`/`TestPdfSigner` promoted from `spike` (package renamed only, logic untouched); `spike/SignatureSpikeTest` updated to import them; `spike` package kept as historical evidence. New `TestPdfFactory` (byte[] fixtures: `unsigned`, `unsignedMultiPage`, `signed`, `signedThenIncrementallyModified`, `signedThenTampered`, `doublySigned`, `rotated(int...)` with raw COS `/Rotate` incl. non-normalized `-90`/`450`, `landscape`, `withCropBox`, `encrypted`/`encryptedWithEmptyUserPassword` (AES-256 via `StandardProtectionPolicy`, print+extract denied), `corrupt`, `notAPdf`) and `TestPdfFactoryTest` (13 sanity tests, reusing `SpikeSignatureChecker` for CMS verification instead of duplicating it).
  - **Domain model** (`src/main/java/com/coam/pdfvalidator/domain/model/`): 20 immutable records/enums exactly as specified in the task (PdfAnalysisReport, DocumentHashes, DocumentStructure/PageInfo/Box/Rotation/Orientation, SecurityInfo/Permission, PdfaReport/PdfaDeclaration/PdfaIssue/PdfaValidationStatus, SignatureReport/ByteRangeCoverage/IntegrityStatus/CertificateInfo/ChainStatus/TimestampInfo/RevocationStatus/RevocationState). All compact constructors null-check and defensively copy (`List.copyOf`/`Set.copyOf`, `byte[].clone()`).
  - **Design choices**:
    - `Rotation.fromDegrees`: normalizes via `((d % 360) + 360) % 360`; throws `IllegalArgumentException` when `d % 90 != 0` (non-multiple of 90 is invalid per PDF spec — documented in Javadoc).
    - `Orientation.of(Box, Rotation)`: swaps width/height for DEG_90/DEG_270 before comparing, computed strictly after rotation as required.
    - `ByteRangeCoverage`: backed by `List<Long> ranges` (4 elements) rather than `long[]` so the record's own copy-on-construct covers it; validates size==4, start==0, non-overlap, end<=fileLength in the compact constructor so both the raw constructor and the `of(...)` static factory are protected.
    - `CertificateInfo`: carries `byte[] encoded` (DER, defensively copied on construct and on read via an explicit `encoded()` override) instead of a separate `EncodedCertificate` record — keeps one record per certificate and gives `CertificateChainValidator`/infrastructure everything needed to rebuild an `X509Certificate` without the domain depending on any certificate library.
    - `PdfaDeclaration`/`TimestampInfo`: nullable-together fields modeled with a `NONE`/`absent()` singleton constant plus `isDeclared()`/`isPresent()` and `Optional`-returning accessor methods (`declaredPart()`, `declaredConformance()`), rather than throwing on partial null.
    - `SignatureVerifier` port: returns the same `SignatureReport` type end-to-end (chain/revocation start as `NOT_CHECKED`/`notChecked()` placeholders, chain already populated) instead of introducing a separate `ExtractedSignature` type; the use case enriches via `SignatureReport#withChainAndRevocation(...)`. Justified in the interface's Javadoc.
  - **TDD (strict)**: two RED/GREEN cycles observed.
    - Fixtures: RED — `./mvnw -B -q test-compile` → 13 "cannot find symbol: TestPdfFactory" compile errors (`TestPdfFactoryTest` written first, `TestPdfFactory` did not exist yet). Implemented `TestPdfFactory`. GREEN — `./mvnw -B -q test -Dtest=TestPdfFactoryTest` → `target/surefire-reports/...TestPdfFactoryTest.txt`: `Tests run: 13, Failures: 0, Errors: 0, Skipped: 0`.
    - Domain model: RED — `./mvnw -B -q test-compile` → 409 "cannot find symbol" compile errors across 7 new domain test classes (Rotation/Orientation/Box/ByteRangeCoverage/DocumentHashes/CertificateInfo/DefensiveCopy), no domain classes existed yet. Implemented all 20 domain model files. GREEN — surefire reports: RotationTest 5/5, OrientationTest 6/6, BoxTest 2/2, ByteRangeCoverageTest 6/6, DocumentHashesTest 6/6, CertificateInfoTest 6/6, DefensiveCopyTest 5/5 (36/36).
  - **Verify**: `./mvnw -B verify` → `BUILD SUCCESS`, `Tests run: 52, Failures: 0, Errors: 0, Skipped: 0` (jar built, Spring Boot repackage, JaCoCo report generated). `grep -rE "import (org\.springframework|org\.apache\.pdfbox|org\.bouncycastle)" src/main/java/com/coam/pdfvalidator/domain` → no output (domain stays library-free).
  - **Commits** (`feat/domain-model-fixtures`): `682bef2` test: add PDF fixture factory for signed, rotated, encrypted and corrupt documents; `8ac3bbd` feat: add immutable domain model for PDF analysis; `4841cda` feat: add domain ports and exceptions.
  - Note: the CI step rename and `README.md` seen mid-task were made by the orchestrator (living README, user request), committed as `5608ef3`.
  - Parent spot check: `./mvnw -B verify` re-run → 52/52, BUILD SUCCESS.
  - Review (RDD, high risk: CI shell; 46 files, 2176 lines): granted, 4 lenses, approved and acknowledged (lineage review-7159f22ba2ef3703, authority burned). Advisory findings accepted as follow-up work → task T02b.
- Living README (`README.md`, Spanish) added and must be updated in every task (user request).

## Follow-up tasks
- [x] T02b Domain hardening from T02 review advisories (do before/with T03) — route: delegated (writer trigger: 6 domain files + fixtures + new tests)
  - `ByteRangeCoverage`: reject negative offsets/lengths and arithmetic overflow (flagged by risk, reliability and resilience lenses — hostile PDFs can carry arbitrary `/ByteRange`).
  - `Rotation`: a real PDF with `/Rotate` not a multiple of 90 must not abort the whole analysis — keep strict `fromDegrees`, add a lenient path (e.g. `tryFromDegrees` → `Optional`) and let the reader report the raw value as a page anomaly.
  - `CertificateInfo`: override `equals`/`hashCode`/`toString` so `byte[] encoded` compares by content.
  - `DocumentStructure`: enforce `pageCount == pages.size()` (or derive it).
  - `PdfaDeclaration`: reject partially-null declarations (part without conformance or vice versa).
  - Tests: `TestPdfFactoryTest` should not depend on `spike.SpikeSignatureChecker`; fix misleading `rotated` Javadoc.

## Progress / Evidence (T02b, T03)

- Branch `feat/document-reader` (branched from `feat/domain-model-fixtures`).

### T02b — Domain hardening

- **`ByteRangeCoverage`**: compact constructor now rejects negative `start1/len1/start2/len2` up front, and wraps `start1+len1`/`start2+len2` in `Math.addExact` (catches `ArithmeticException` → `IllegalArgumentException`) so a hostile `/ByteRange` (e.g. `len1=Long.MAX_VALUE`) cannot silently overflow past the overlap/file-length checks.
- **`Rotation`**: added `static Optional<Rotation> tryFromDegrees(int)` (empty for non-multiples of 90); `fromDegrees(int)` is now implemented in terms of it and stays strict.
- **`PageInfo`**: added `int rawRotation` component + `rotationValid()` (derived from `Rotation.tryFromDegrees(rawRotation).isPresent()`); `rotation()` stays the effective/normalized value used for `orientation` (defaulted to `DEG_0` when invalid), per the task's "simplest clean option" guidance. Existing 5-arg call sites (`DefensiveCopyTest`) updated mechanically.
- **`CertificateInfo`**: overrode `equals`/`hashCode` (content-based via `Arrays.equals`/`Arrays.hashCode` on `encoded`, `Objects.equals`/`Objects.hash` on the rest) and `toString` (reports `encoded.length` instead of the array). Caught and fixed a real bug while writing the test for this: `("a"+"b").formatted(...)` requires parentheses around the concatenation — `"a" + "b".formatted(...)` binds `.formatted()` to the second literal only (verified by reproducing it in isolation: `IllegalFormatConversionException: d != java.time.Instant`, because the first literal's `%s` placeholders were left un-substituted and the second literal's own placeholders were shifted against the full argument list).
- **`DocumentStructure`**: enforces `pageCount == pages.size()` in the compact constructor (`IllegalArgumentException` otherwise). Chose enforcement over deriving `pageCount` from `pages.size()`: keeps the record's shape and existing call sites unchanged, and keeps `pageCount` as an explicit, independently round-trippable component for JSON (de)serialization.
- **`PdfaDeclaration`**: compact constructor rejects `part`/`conformance` where exactly one is `null` (XOR check); `NONE` (both null) and fully-populated declarations remain valid.
- **`TestPdfFactoryTest`**: replaced the `spike.SpikeSignatureChecker` dependency with a new fixtures-local, package-private `FixtureCmsVerifier` (byte-range extraction + BC `CMSSignedData` verification, ~80 lines, no production dependency on `spike`). Fixed the `rotated(int...)` Javadoc: it claimed raw COS access was needed because `PDPage#setRotation(int)` would normalize on write; disassembled the PDFBox 3.0.8 bytecode (`javap -c`) and confirmed `setRotation` is a thin wrapper over the exact same `COSDictionary#setInt` call — normalization/inheritance only happen on read, via `PDPage#getRotation()` (confirmed the same way: it calls `PDPageTree.getInheritableAttribute`, then maps non-multiples-of-90 to `0` and otherwise normalizes to `[0,360)`).
- **TDD**: RED — `./mvnw -q -B test-compile` → compile errors (`PageInfo` constructor arity mismatch in `PageInfoTest`/`DocumentStructureTest`/`DefensiveCopyTest`; `cannot find symbol: tryFromDegrees`/`rotationValid`), i.e. the new tests referencing not-yet-existing API, consistent with T02's own precedent of using compile-error RED for shape changes. GREEN — after implementing all six domain changes: `./mvnw -B test` → `Tests run: 72, Failures: 0, Errors: 0, Skipped: 0` (surfaced and fixed 2 real regressions along the way: the `toString` bug above, and `DefensiveCopyTest.pdfAnalysisReportCopiesItsSignaturesList` using a stale `pageCount=1` against an empty `pages` list, now `0`).
- Commit: `3bbc70d` fix: harden domain model against hostile byte ranges and invalid rotations.

### T03 — HashCalculator + PdfBoxDocumentReader

- **`infrastructure/crypto/JcaHashCalculator`**: `HashCalculator` via `java.security.MessageDigest` + `HexFormat`. RED — `./mvnw -q -B test-compile` → `cannot find symbol: class JcaHashCalculator`. GREEN — `./mvnw -B -Dtest=JcaHashCalculatorTest test` → `Tests run: 3, Failures: 0, Errors: 0, Skipped: 0`, verified against the NIST SHA-256/SHA-512 vectors for the empty input and `"abc"` (values independently recomputed with a throwaway JDK `MessageDigest` probe before writing the test, not typed from memory).
- **`infrastructure/pdfbox/PdfBoxDocumentReader`**: implements `PdfDocumentReader`. RED — `./mvnw -q -B test-compile` → `cannot find symbol: class PdfBoxDocumentReader`. GREEN — `./mvnw -B -Dtest=PdfBoxDocumentReaderTest test` → `Tests run: 16, Failures: 0, Errors: 0, Skipped: 0` (one intermediate compile-only failure: `PDDocument.close()` throws `IOException`, needed a `catch (IOException e)` around each try-with-resources to convert it to `InvalidPdfException` since the domain port declares no checked exceptions).
  - **Design choices** (verified against the PDFBox 3.0.8 jar with `javap -c`/`javap -p` before writing code, not assumed):
    - **Rotation reading**: uses `PDPageTree.getInheritableAttribute(page.getCOSObject(), COSName.ROTATE)` directly (public static method) instead of `PDPage#getRotation()`. Both walk the page-tree inheritance chain (confirmed via bytecode: `getRotation()` itself calls `getInheritableAttribute`), but `getRotation()` additionally normalizes on read and silently returns `0` for a raw value that is not a multiple of 90 — which would hide exactly the anomaly the domain needs to report. Reading the raw `COSNumber` ourselves keeps the inheritance walk (confirmed working with a real inherited-`/Rotate`-on-`/Pages`-node fixture) while preserving the true raw value for `Rotation.tryFromDegrees`/`PageInfo.rotationValid()`.
    - **Revision counting**: counts non-overlapping raw `"%%EOF"` byte occurrences, floored at 1. Documented and empirically measured against the actual fixtures (not assumed): `TestPdfFactory.signed()` already contains **2** physical revisions, not 1, because `TestPdfSigner.sign(...)` performs the signing itself via `document.saveIncremental(...)` on top of an already fully-saved (`document.save(...)`) unsigned PDF — i.e. "signed" = creation revision + signing revision. `signedThenIncrementallyModified()` is therefore **3**, not 2. This was measured with a throwaway JUnit probe counting `%%EOF`/`startxref` occurrences (`unsigned`→1/1, `signed`→2/2, `signedThenIncrementallyModified`→3/3, `doublySigned`→3/3) before writing the real test, and the test/README reflect the measured values rather than the plan's initial guess.
    - **PDF/A declaration**: `PDMetadata#toByteArray()` → `xmpbox` `DomXmpParser#parse(byte[])` → `XMPMetadata#getPDFAIdentificationSchema()` → `getPart()`/`getConformance()`. Missing metadata, missing schema, a schema with only one of part/conformance, or a parsing failure (`XmpParsingException`) all map to `PdfaDeclaration.NONE` rather than aborting. `xmpbox` is on the classpath transitively via the already-declared `preflight` dependency (confirmed present in `~/.m2` and used directly, no `pom.xml` change needed).
    - **Encryption**: `Loader.loadPDF(byte[])` uses the empty-string default user password; PDFBox's `InvalidPasswordException` (an `IOException` subtype) on a non-empty-password document is mapped to the domain `EncryptedPdfException`; any other `IOException` (corrupt/non-PDF) maps to `InvalidPdfException`. `AccessPermission` mapped 1:1 to `Permission` (`canPrint`→PRINT, `canModify`→MODIFY, `canExtractContent`→EXTRACT_CONTENT, `canModifyAnnotations`→ANNOTATE, `canFillInForm`→FILL_FORMS, `canExtractForAccessibility`→EXTRACT_FOR_ACCESSIBILITY, `canAssembleDocument`→ASSEMBLE, `canPrintFaithful`→PRINT_HIGH_QUALITY).
  - **`TestPdfFactory`** gained `rotatedViaInheritedPagesNode(int)` (sets `/Rotate` on the shared `/Pages` node) and `pdfaDeclared(int, String)` (XMP with the `pdfaid` schema via `xmpbox`'s `XMPMetadata`/`XmpSerializer`), both exercised by the new reader tests.
  - Commit: `3cdb668` feat: add SHA-256/SHA-512 hash calculator; `65f5b2a` feat: add PDFBox document reader for structure, security and PDF/A declaration.

### Verify (T02b + T03, full suite)

- `./mvnw -B verify` → `BUILD SUCCESS`, `Tests run: 91, Failures: 0, Errors: 0, Skipped: 0` (jar built, Spring Boot repackage, JaCoCo report generated).
- `grep -rE "import (org\.springframework|org\.apache\.pdfbox|org\.bouncycastle)" src/main/java/com/coam/pdfvalidator/domain` → no output (domain stays library-free).
- `grep -rE "org\.apache\.pdfbox" src/main/java/com/coam/pdfvalidator --include=*.java -l` → only `src/main/java/com/coam/pdfvalidator/infrastructure/pdfbox/PdfBoxDocumentReader.java`.

- Living README updated (`README.md`): §2 gained a "Lectura de estructura, seguridad y declaración PDF/A" subsection, functionality table (hashes/structure/rotation/boxes/orientation/encryption/permissions/XMP declaration → ✅), project tree (`infrastructure/crypto`, `infrastructure/pdfbox`), tests section (91 total) and change history (2026-09-27). Commit `eb75cf7`.

## Next step
T04.
