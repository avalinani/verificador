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
- [ ] T02 TestPdfFactory fixtures (unsigned, signed, incremental edit, rotated, encrypted, corrupt) + domain records + ports
- [ ] T03 HashCalculator + PdfBoxDocumentReader (versions, pages, rotation, boxes, orientation, encryption/permissions)
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

## Next step
T02.
