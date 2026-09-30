package com.coam.pdfvalidator.application;

import com.coam.pdfvalidator.domain.exception.EncryptedPdfException;
import com.coam.pdfvalidator.domain.exception.InvalidPdfException;
import com.coam.pdfvalidator.domain.model.AnalysisSection;
import com.coam.pdfvalidator.domain.model.ByteRangeCoverage;
import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.model.DocumentStructure;
import com.coam.pdfvalidator.domain.model.IntegrityStatus;
import com.coam.pdfvalidator.domain.model.OverallVerdict;
import com.coam.pdfvalidator.domain.model.PdfAnalysisReport;
import com.coam.pdfvalidator.domain.model.PdfaDeclaration;
import com.coam.pdfvalidator.domain.model.PdfaIssue;
import com.coam.pdfvalidator.domain.model.PdfaReport;
import com.coam.pdfvalidator.domain.model.PdfaValidationStatus;
import com.coam.pdfvalidator.domain.model.Permission;
import com.coam.pdfvalidator.domain.model.RevocationState;
import com.coam.pdfvalidator.domain.model.RevocationStatus;
import com.coam.pdfvalidator.domain.model.SecurityInfo;
import com.coam.pdfvalidator.domain.model.SectionError;
import com.coam.pdfvalidator.domain.model.SignatureExtraction;
import com.coam.pdfvalidator.domain.model.SignatureReport;
import com.coam.pdfvalidator.domain.model.SignatureVerdict;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import com.coam.pdfvalidator.domain.policy.SignatureVerdictPolicy;
import com.coam.pdfvalidator.domain.port.CertificateChainValidator;
import com.coam.pdfvalidator.domain.port.HashCalculator;
import com.coam.pdfvalidator.domain.port.PdfDocumentReader;
import com.coam.pdfvalidator.domain.port.PdfaConformanceValidator;
import com.coam.pdfvalidator.domain.port.RevocationChecker;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link AnalyzePdfUseCase} exercised with hand-written fakes for every
 * domain port (no Mockito: each fake is a handful of lines and makes the
 * exact scenario under test -- a thrown exception, a captured argument --
 * obvious at the call site).
 */
class AnalyzePdfUseCaseTest {

    private static final byte[] CONTENT = "irrelevant-test-bytes".getBytes();
    private static final DocumentHashes HASHES = new DocumentHashes("a".repeat(64), "b".repeat(128));
    private static final DocumentStructure STRUCTURE = new DocumentStructure("1.7", null, 0, List.of(), 1);
    private static final SecurityInfo SECURITY = new SecurityInfo(false, EnumSet.allOf(Permission.class));
    private static final PdfaReport COMPLIANT_PDFA_REPORT =
            new PdfaReport(PdfaDeclaration.NONE, PdfaValidationStatus.COMPLIANT, List.of());
    private static final Instant FIXED_NOW = Instant.parse("2026-09-27T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    // ---- hand-written fakes ----

    private static final class FakeHashCalculator implements HashCalculator {
        @Override
        public DocumentHashes hash(byte[] content) {
            return HASHES;
        }
    }

    private static final class FakePdfDocumentReader implements PdfDocumentReader {
        private final DocumentStructure structure;
        private final SecurityInfo security;
        private final PdfaDeclaration declaration;
        private final RuntimeException throwOnRead;

        FakePdfDocumentReader(DocumentStructure structure, SecurityInfo security, PdfaDeclaration declaration) {
            this(structure, security, declaration, null);
        }

        FakePdfDocumentReader(RuntimeException throwOnRead) {
            this(STRUCTURE, SECURITY, PdfaDeclaration.NONE, throwOnRead);
        }

        private FakePdfDocumentReader(
                DocumentStructure structure, SecurityInfo security, PdfaDeclaration declaration,
                RuntimeException throwOnRead) {
            this.structure = structure;
            this.security = security;
            this.declaration = declaration;
            this.throwOnRead = throwOnRead;
        }

        @Override
        public DocumentStructure readStructure(byte[] pdf) {
            if (throwOnRead != null) {
                throw throwOnRead;
            }
            return structure;
        }

        @Override
        public SecurityInfo readSecurity(byte[] pdf) {
            return security;
        }

        @Override
        public PdfaDeclaration readPdfaDeclaration(byte[] pdf) {
            return declaration;
        }
    }

    private static final class FakeSignatureVerifier implements SignatureVerifier {
        private final List<SignatureReport> signatures;
        private final RuntimeException toThrow;

        FakeSignatureVerifier(List<SignatureReport> signatures) {
            this(signatures, null);
        }

        FakeSignatureVerifier(RuntimeException toThrow) {
            this(List.of(), toThrow);
        }

        private FakeSignatureVerifier(List<SignatureReport> signatures, RuntimeException toThrow) {
            this.signatures = signatures;
            this.toThrow = toThrow;
        }

        @Override
        public List<SignatureReport> verify(byte[] pdf) {
            if (toThrow != null) {
                throw toThrow;
            }
            return signatures;
        }
    }

    private static final class FakeCertificateChainValidator implements CertificateChainValidator {
        private final ChainStatus status;
        private final RuntimeException toThrow;
        private final List<Instant> capturedValidationTimes = new ArrayList<>();
        private List<CertificateInfo> validatedPathOverride;
        private List<CertificateInfo> tsaChain = List.of();
        private ChainStatus tsaStatus = ChainStatus.NOT_CHECKED;
        private final List<Instant> capturedTsaValidationTimes = new ArrayList<>();
        private RuntimeException tsaToThrow;

        FakeCertificateChainValidator(ChainStatus status) {
            this(status, null);
        }

        FakeCertificateChainValidator(RuntimeException toThrow) {
            this(null, toThrow);
        }

        private FakeCertificateChainValidator(ChainStatus status, RuntimeException toThrow) {
            this.status = status;
            this.toThrow = toThrow;
        }

        /** Simulates a real {@code PkixCertificateChainValidator} narrowing the presented chain (T10 security decision). */
        void overrideValidatedPath(List<CertificateInfo> validatedPath) {
            this.validatedPathOverride = validatedPath;
        }

        /** Chains equal to {@code chain} are answered with {@code status} (and recorded separately): the TSA chain. */
        void tsaChainIs(List<CertificateInfo> chain, ChainStatus status) {
            this.tsaChain = chain;
            this.tsaStatus = status;
        }

        void tsaChainThrows(List<CertificateInfo> chain, RuntimeException exception) {
            this.tsaChain = chain;
            this.tsaToThrow = exception;
        }

        @Override
        public ChainStatus validate(List<CertificateInfo> chain, Instant validationTime) {
            if (!tsaChain.isEmpty() && chain.equals(tsaChain)) {
                capturedTsaValidationTimes.add(validationTime);
                if (tsaToThrow != null) {
                    throw tsaToThrow;
                }
                return tsaStatus;
            }
            capturedValidationTimes.add(validationTime);
            if (toThrow != null) {
                throw toThrow;
            }
            return status;
        }

        @Override
        public List<CertificateInfo> validatedPath(List<CertificateInfo> chain, Instant validationTime) {
            return validatedPathOverride != null ? validatedPathOverride : chain;
        }
    }

    private static final class FakePdfaConformanceValidator implements PdfaConformanceValidator {
        private final PdfaReport report;
        private final RuntimeException toThrow;
        private int callCount;

        FakePdfaConformanceValidator(PdfaReport report) {
            this(report, null);
        }

        FakePdfaConformanceValidator(RuntimeException toThrow) {
            this(null, toThrow);
        }

        private FakePdfaConformanceValidator(PdfaReport report, RuntimeException toThrow) {
            this.report = report;
            this.toThrow = toThrow;
        }

        @Override
        public PdfaReport validate(byte[] pdf) {
            callCount++;
            if (toThrow != null) {
                throw toThrow;
            }
            return report;
        }
    }

    private static final class FakeRevocationChecker implements RevocationChecker {
        private final RevocationStatus status;
        private int callCount;
        private CertificateInfo lastCertificate;
        private CertificateInfo lastIssuer;

        FakeRevocationChecker(RevocationStatus status) {
            this.status = status;
        }

        @Override
        public RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer) {
            callCount++;
            lastCertificate = certificate;
            lastIssuer = issuer;
            return status;
        }
    }

    // ---- test data builders ----

    private static CertificateInfo certificate(String subject) {
        return new CertificateInfo(subject, null, "CN=issuer-of-" + subject, "01",
                Instant.parse("2020-01-01T00:00:00Z"), Instant.parse("2030-01-01T00:00:00Z"),
                "SHA256withRSA", List.of(), List.of(), new byte[] {1, 2, 3});
    }

    private static SignatureReport signatureWith(
            TimestampInfo timestamp, Instant claimedSigningTime, List<CertificateInfo> chain) {
        return new SignatureReport("Signature1", "adbe.pkcs7.detached",
                ByteRangeCoverage.of(0, 10, 10, 5, 15), IntegrityStatus.INTACT, claimedSigningTime,
                timestamp, chain, ChainStatus.NOT_CHECKED, RevocationStatus.notChecked(), null);
    }

    private static AnalyzePdfUseCase useCase(
            PdfDocumentReader reader, SignatureVerifier verifier, CertificateChainValidator chainValidator,
            PdfaConformanceValidator pdfaValidator, RevocationChecker revocationChecker) {
        return new AnalyzePdfUseCase(
                new FakeHashCalculator(), reader, verifier, chainValidator, pdfaValidator, revocationChecker, CLOCK);
    }

    private static AnalyzePdfUseCase happyPathUseCaseWithSignatures(
            List<SignatureReport> signatures, CertificateChainValidator chainValidator,
            RevocationChecker revocationChecker) {
        return useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(signatures),
                chainValidator,
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                revocationChecker);
    }

    // ---- orchestration ----

    @Test
    void assemblesEveryPortsResultIntoOneReport() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("test.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.fileName()).isEqualTo("test.pdf");
        assertThat(report.sizeBytes()).isEqualTo(CONTENT.length);
        assertThat(report.hashes()).isEqualTo(HASHES);
        assertThat(report.structure()).isEqualTo(STRUCTURE);
        assertThat(report.security()).isEqualTo(SECURITY);
        assertThat(report.pdfa()).isEqualTo(COMPLIANT_PDFA_REPORT);
        assertThat(report.signatures()).isEmpty();
    }

    @Test
    void analyzedAtComesFromTheInjectedClockRatherThanWallClockTime() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("test.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.analyzedAt()).isEqualTo(FIXED_NOW);
    }

    // ---- validationTime selection: only a TRUSTED timestamp moves it away from "now" (T19) ----

    private static final List<CertificateInfo> TSA_CHAIN = List.of(certificate("tsa"), certificate("tsa-root"));
    private static final Instant GEN_TIME = Instant.parse("2025-01-01T00:00:00Z");

    private static TimestampInfo timestamp(
            Instant genTime, boolean imprintValid, boolean signatureValid, boolean timeStampingEku) {
        return new TimestampInfo(genTime, "TSA", imprintValid, signatureValid, TSA_CHAIN.get(0), null,
                TSA_CHAIN, timeStampingEku, false);
    }

    private static FakeCertificateChainValidator chainValidatorWithTsaStatus(ChainStatus tsaStatus) {
        FakeCertificateChainValidator validator = new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED);
        validator.tsaChainIs(TSA_CHAIN, tsaStatus);
        return validator;
    }

    private static SignatureReport analyzeOne(SignatureReport signature, FakeCertificateChainValidator validator) {
        return happyPathUseCaseWithSignatures(
                List.of(signature), validator, new FakeRevocationChecker(RevocationStatus.notChecked()))
                .analyze("t.pdf", CONTENT, new AnalysisOptions(false)).signatures().get(0);
    }

    @Test
    void aTrustedTimestampGenTimeIsTheValidationTimeOfTheSignerChain() {
        FakeCertificateChainValidator chainValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);
        SignatureReport signature = signatureWith(
                timestamp(GEN_TIME, true, true, true), Instant.parse("2024-01-01T00:00:00Z"), List.of());

        SignatureReport result = analyzeOne(signature, chainValidator);

        assertThat(chainValidator.capturedTsaValidationTimes).containsExactly(GEN_TIME);
        assertThat(chainValidator.capturedValidationTimes).containsExactly(GEN_TIME);
        assertThat(result.timestamp().trusted()).isTrue();
    }

    @Test
    void aTimestampWhoseTsaChainIsNotTrustedNeverMovesTheValidationTimeAndIsReportedUntrusted() {
        FakeCertificateChainValidator chainValidator = chainValidatorWithTsaStatus(ChainStatus.UNTRUSTED_ROOT);
        SignatureReport signature = signatureWith(timestamp(GEN_TIME, true, true, true), null, List.of());

        SignatureReport result = analyzeOne(signature, chainValidator);

        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
        assertThat(result.timestamp().trusted()).isFalse();
        assertThat(result.timestamp().note()).contains("TSA not trusted").contains("UNTRUSTED_ROOT");
    }

    @Test
    void theClaimedSigningTimeIsNeverUsedAsTheValidationTime() {
        Instant claimedSigningTime = Instant.parse("2024-01-01T00:00:00Z");
        SignatureReport signature = signatureWith(TimestampInfo.absent(), claimedSigningTime, List.of());
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED);

        SignatureReport result = analyzeOne(signature, chainValidator);

        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
        assertThat(result.claimedSigningTime()).isEqualTo(claimedSigningTime);
    }

    @Test
    void validationTimeIsNowWhenThereIsNeitherATimestampNorAClaimedSigningTime() {
        SignatureReport signature = signatureWith(TimestampInfo.absent(), null, List.of());
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED);

        analyzeOne(signature, chainValidator);

        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
    }

    @Test
    void aTimestampWithAnInvalidImprintOrTsaSignatureIsNotTrustedEvenIfItsChainIs() {
        for (TimestampInfo timestamp : List.of(
                timestamp(GEN_TIME, false, true, true), timestamp(GEN_TIME, true, false, true))) {
            FakeCertificateChainValidator chainValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);

            SignatureReport result = analyzeOne(signatureWith(timestamp, null, List.of()), chainValidator);

            assertThat(result.timestamp().trusted()).isFalse();
            assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
        }
    }

    @Test
    void aTsaCertificateWithoutTheTimeStampingEkuIsNotTrustedEvenIfItsChainIs() {
        FakeCertificateChainValidator chainValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);

        SignatureReport result = analyzeOne(
                signatureWith(timestamp(GEN_TIME, true, true, false), null, List.of()), chainValidator);

        assertThat(result.timestamp().trusted()).isFalse();
        assertThat(result.timestamp().note()).contains("TSA not trusted").contains("id-kp-timeStamping");
        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
    }

    @Test
    void aGenTimeMoreThanFiveMinutesInTheFutureIsNotTrustedButFourMinutesIsTolerated() {
        Instant tooFar = FIXED_NOW.plusSeconds(5 * 60 + 1);
        Instant tolerated = FIXED_NOW.plusSeconds(4 * 60);

        FakeCertificateChainValidator rejectedValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);
        SignatureReport rejected = analyzeOne(
                signatureWith(timestamp(tooFar, true, true, true), null, List.of()), rejectedValidator);
        FakeCertificateChainValidator toleratedValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);
        SignatureReport accepted = analyzeOne(
                signatureWith(timestamp(tolerated, true, true, true), null, List.of()), toleratedValidator);

        assertThat(rejected.timestamp().trusted()).isFalse();
        assertThat(rejected.timestamp().note()).contains("TSA not trusted").contains("future");
        assertThat(rejectedValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
        assertThat(accepted.timestamp().trusted()).isTrue();
        assertThat(toleratedValidator.capturedValidationTimes).containsExactly(tolerated);
    }

    @Test
    void aTimestampWithoutAnyTsaChainIsNotTrusted() {
        TimestampInfo noChain = new TimestampInfo(GEN_TIME, "TSA", true, true, null, null, List.of(), true, false);
        FakeCertificateChainValidator chainValidator = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);

        SignatureReport result = analyzeOne(signatureWith(noChain, null, List.of()), chainValidator);

        assertThat(result.timestamp().trusted()).isFalse();
        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
    }

    @Test
    void anUnexpectedFailureValidatingTheTsaChainMakesTheTimestampUntrustedInsteadOfLosingTheSignature() {
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.TRUSTED);
        chainValidator.tsaChainThrows(TSA_CHAIN, new IllegalStateException("boom"));

        SignatureReport result = analyzeOne(
                signatureWith(timestamp(GEN_TIME, true, true, true), null, List.of()), chainValidator);

        assertThat(result.timestamp().trusted()).isFalse();
        assertThat(result.chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        assertThat(chainValidator.capturedValidationTimes).containsExactly(FIXED_NOW);
    }

    @Test
    void theCurrentTimeReasonIsReportedExactlyWhenNoTrustedTimestampExists() {
        FakeCertificateChainValidator trustedEverywhere = chainValidatorWithTsaStatus(ChainStatus.TRUSTED);
        SignatureReport untimestamped = analyzeOne(
                signatureWith(TimestampInfo.absent(), null, List.of()),
                new FakeCertificateChainValidator(ChainStatus.TRUSTED));
        SignatureReport timestamped = analyzeOne(
                signatureWith(timestamp(GEN_TIME, true, true, true), null, List.of()), trustedEverywhere);

        assertThat(untimestamped.verdictReasons())
                .contains(SignatureVerdictPolicy.REASON_VALIDATED_AT_CURRENT_TIME);
        assertThat(timestamped.verdictReasons())
                .doesNotContain(SignatureVerdictPolicy.REASON_VALIDATED_AT_CURRENT_TIME);
    }

    // ---- revocation flag on/off ----

    @Test
    void revocationIsNotCheckedAtAllWhenTheOptionIsDisabled() {
        SignatureReport signature =
                signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(signature), new FakeCertificateChainValidator(ChainStatus.TRUSTED), revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(revocationChecker.callCount).isZero();
        assertThat(report.signatures().get(0).revocation()).isEqualTo(RevocationStatus.notChecked());
    }

    @Test
    void revocationIsCheckedForTheSignerAndItsImmediateIssuerWhenTheOptionIsEnabled() {
        CertificateInfo signer = certificate("signer");
        CertificateInfo issuer = certificate("ca");
        SignatureReport signature = signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(signer, issuer));
        RevocationStatus good = new RevocationStatus(RevocationState.GOOD, "OCSP", null);
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(good);

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(signature), new FakeCertificateChainValidator(ChainStatus.TRUSTED), revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(revocationChecker.callCount).isEqualTo(1);
        assertThat(revocationChecker.lastCertificate).isEqualTo(signer);
        assertThat(revocationChecker.lastIssuer).isEqualTo(issuer);
        assertThat(report.signatures().get(0).revocation()).isEqualTo(good);
    }

    /**
     * Security decision (T10): the signer/issuer passed to the revocation
     * checker come from {@link CertificateChainValidator#validatedPath},
     * not from {@code signature.chain()} directly -- a real {@code
     * PkixCertificateChainValidator} narrows the presented (attacker-
     * controlled) CMS chain down to only the certificates PKIX actually
     * used, so an extra/unrelated certificate the chain also carries
     * (which {@code chain()} would still include) is never consulted.
     */
    @Test
    void revocationUsesTheValidatedPathRatherThanTheRawPresentedChain() {
        CertificateInfo signer = certificate("signer");
        CertificateInfo impostorExtraCertificate = certificate("impostor-embedded-in-cms");
        CertificateInfo realIssuer = certificate("ca");
        SignatureReport signature = signatureWith(
                TimestampInfo.absent(), FIXED_NOW, List.of(signer, impostorExtraCertificate, realIssuer));
        RevocationStatus good = new RevocationStatus(RevocationState.GOOD, "OCSP", null);
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(good);
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.TRUSTED);
        chainValidator.overrideValidatedPath(List.of(signer, realIssuer));

        AnalyzePdfUseCase useCase =
                happyPathUseCaseWithSignatures(List.of(signature), chainValidator, revocationChecker);
        useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(revocationChecker.lastCertificate).isEqualTo(signer);
        assertThat(revocationChecker.lastIssuer).isEqualTo(realIssuer);
    }

    /**
     * T10b: a {@code TRUSTED} chain whose {@code validatedPath} is
     * (unexpectedly) empty must still surface an explicit reason, never the
     * bare {@link RevocationStatus#notChecked()} placeholder that silently
     * looks the same as "revocation was simply not requested".
     */
    @Test
    void revocationSurfacesAnExplicitReasonWhenTheTrustedChainsValidatedPathIsEmpty() {
        SignatureReport signature = signatureWith(
                TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.TRUSTED);
        chainValidator.overrideValidatedPath(List.of());

        AnalyzePdfUseCase useCase =
                happyPathUseCaseWithSignatures(List.of(signature), chainValidator, revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(revocationChecker.callCount).isZero();
        assertThat(report.signatures().get(0).revocation()).isEqualTo(new RevocationStatus(
                RevocationState.NOT_CHECKED, null, "validated certification path unavailable"));
    }

    // ---- T21a: every non-anchor certificate of the validated path is checked ----

    /** Answers per certificate subject and records every (certificate, issuer) pair it was asked about. */
    private static final class ScriptedRevocationChecker implements RevocationChecker {
        private final java.util.Map<String, RevocationStatus> bySubject = new java.util.HashMap<>();
        private final List<String> asked = new ArrayList<>();

        ScriptedRevocationChecker answer(String subject, RevocationStatus status) {
            bySubject.put(subject, status);
            return this;
        }

        @Override
        public RevocationStatus check(CertificateInfo certificate, CertificateInfo issuer) {
            asked.add(certificate.subject() + " <- " + (issuer == null ? "none" : issuer.subject()));
            return bySubject.getOrDefault(certificate.subject(),
                    new RevocationStatus(RevocationState.UNKNOWN, null, "no answer scripted"));
        }
    }

    private RevocationStatus analyzeThreeTierPath(ScriptedRevocationChecker checker) {
        CertificateInfo leaf = certificate("leaf");
        CertificateInfo intermediate = certificate("intermediate-ca");
        CertificateInfo root = certificate("root-ca");
        SignatureReport signature = signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(leaf, intermediate, root));
        FakeCertificateChainValidator chainValidator = new FakeCertificateChainValidator(ChainStatus.TRUSTED);
        chainValidator.overrideValidatedPath(List.of(leaf, intermediate, root));
        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(List.of(signature), chainValidator, checker);
        return useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true)).signatures().get(0).revocation();
    }

    @Test
    void aRevokedIntermediateMakesTheWholePathRevokedEvenWhenTheLeafIsGood() {
        ScriptedRevocationChecker checker = new ScriptedRevocationChecker()
                .answer("leaf", new RevocationStatus(RevocationState.GOOD, "http://ocsp/leaf", null))
                .answer("intermediate-ca",
                        new RevocationStatus(RevocationState.REVOKED, "http://ocsp/ca", "revoked at 2026-01-01T00:00:00Z"));

        RevocationStatus revocation = analyzeThreeTierPath(checker);

        assertThat(revocation.state()).isEqualTo(RevocationState.REVOKED);
        assertThat(revocation.source()).isEqualTo("http://ocsp/ca");
        assertThat(revocation.detail()).contains("intermediate-ca").contains("revoked at 2026-01-01T00:00:00Z");
    }

    @Test
    void everyNonAnchorCertificateIsCheckedAgainstItsIssuerAndTheAnchorItselfIsNot() {
        ScriptedRevocationChecker checker = new ScriptedRevocationChecker()
                .answer("leaf", new RevocationStatus(RevocationState.GOOD, "l", null))
                .answer("intermediate-ca", new RevocationStatus(RevocationState.GOOD, "c", null));

        RevocationStatus revocation = analyzeThreeTierPath(checker);

        assertThat(checker.asked).containsExactly("leaf <- intermediate-ca", "intermediate-ca <- root-ca");
        assertThat(revocation.state()).isEqualTo(RevocationState.GOOD);
        assertThat(revocation.source()).isEqualTo("l");
    }

    @Test
    void anUnknownIntermediateMakesTheWholePathUnknownEvenWhenTheLeafIsGood() {
        ScriptedRevocationChecker checker = new ScriptedRevocationChecker()
                .answer("leaf", new RevocationStatus(RevocationState.GOOD, "l", null))
                .answer("intermediate-ca", new RevocationStatus(RevocationState.UNKNOWN, null, "OCSP request timed out"));

        RevocationStatus revocation = analyzeThreeTierPath(checker);

        assertThat(revocation.state()).isEqualTo(RevocationState.UNKNOWN);
        assertThat(revocation.detail()).contains("intermediate-ca").contains("OCSP request timed out");
    }

    @Test
    void aRevokedIntermediateWinsOverAnUnknownLeaf() {
        ScriptedRevocationChecker checker = new ScriptedRevocationChecker()
                .answer("leaf", new RevocationStatus(RevocationState.UNKNOWN, null, "no OCSP/CRL URL available"))
                .answer("intermediate-ca", new RevocationStatus(RevocationState.REVOKED, "c", "revoked"));

        assertThat(analyzeThreeTierPath(checker).state()).isEqualTo(RevocationState.REVOKED);
    }

    @Test
    void aLeafResultKeepsItsOriginalDetailTextUnchanged() {
        ScriptedRevocationChecker checker = new ScriptedRevocationChecker()
                .answer("leaf", new RevocationStatus(RevocationState.REVOKED, "l", "revoked at X"))
                .answer("intermediate-ca", new RevocationStatus(RevocationState.GOOD, "c", null));

        RevocationStatus revocation = analyzeThreeTierPath(checker);

        assertThat(revocation).isEqualTo(new RevocationStatus(RevocationState.REVOKED, "l", "revoked at X"));
    }

    @Test
    void revocationIsNotCheckedWhenTheSignatureHasNoCertificateChainEvenIfTheOptionIsEnabled() {
        SignatureReport signature = signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of());
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        // An empty chain can never validate as TRUSTED (PkixCertificateChainValidator
        // itself returns NOT_CHECKED for it), so this exercises the same
        // trust gate as the dedicated untrusted/incomplete/expired tests below.
        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(signature), new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED), revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(revocationChecker.callCount).isZero();
        assertThat(report.signatures().get(0).revocation()).isEqualTo(new RevocationStatus(
                RevocationState.NOT_CHECKED, null, "revocation not checked: certificate chain is not trusted"));
    }

    /**
     * Security decision (T10): revocation is only ever attempted for a
     * {@code TRUSTED} chain -- see {@code AnalyzePdfUseCase#resolveRevocation}'s
     * Javadoc for why (an untrusted chain's AIA/CDP URLs are not
     * necessarily written by a real CA). Covers the three other {@link
     * ChainStatus} values a real {@code PkixCertificateChainValidator} can
     * report; {@code NOT_CHECKED} itself is covered by the test above.
     */
    @Test
    void revocationIsNotCheckedForAnUntrustedRootEvenIfTheOptionIsEnabled() {
        assertRevocationSkippedForChainStatus(ChainStatus.UNTRUSTED_ROOT);
    }

    @Test
    void revocationIsNotCheckedForAnIncompleteChainEvenIfTheOptionIsEnabled() {
        assertRevocationSkippedForChainStatus(ChainStatus.INCOMPLETE_CHAIN);
    }

    @Test
    void revocationIsNotCheckedForAnExpiredChainEvenIfTheOptionIsEnabled() {
        assertRevocationSkippedForChainStatus(ChainStatus.EXPIRED);
    }

    private void assertRevocationSkippedForChainStatus(ChainStatus status) {
        SignatureReport signature = signatureWith(
                TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(signature), new FakeCertificateChainValidator(status), revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(revocationChecker.callCount)
                .as("chainStatus=%s must never invoke the revocation checker", status)
                .isZero();
        assertThat(report.signatures().get(0).revocation()).isEqualTo(new RevocationStatus(
                RevocationState.NOT_CHECKED, null, "revocation not checked: certificate chain is not trusted"));
    }

    // ---- T11: overall verdict wiring ----

    /**
     * {@code SignatureVerdictPolicy} itself is exhaustively unit-tested
     * (every decision-table row); this only proves {@code AnalyzePdfUseCase}
     * actually wires it in -- the final assembled report's per-signature
     * {@code verdict} and document-level {@code overallVerdict} reflect a
     * real end-to-end TRUSTED/GOOD signature.
     */
    @Test
    void assembledReportCarriesTheComputedOverallVerdict() {
        SignatureReport signature =
                signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));
        FakeRevocationChecker revocationChecker = new FakeRevocationChecker(
                new RevocationStatus(RevocationState.GOOD, "OCSP", null));

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(signature), new FakeCertificateChainValidator(ChainStatus.TRUSTED), revocationChecker);
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(true));

        assertThat(report.signatures().get(0).verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.VALID);
        assertThat(report.modifiedAfterLastSignature()).isFalse();
    }

    @Test
    void anUnsignedDocumentHasTheNoSignaturesOverallVerdict() {
        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(), new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.NO_SIGNATURES);
        assertThat(report.modifiedAfterLastSignature()).isFalse();
    }

    /**
     * A signature whose coverage does not reach the end of file, with no
     * other signature that does, is exposed both as an {@code INVALID}
     * per-signature verdict and as the document-level {@code
     * modifiedAfterLastSignature} flag -- the user's own example of content
     * appended after the last (only) signature with nothing re-signing it.
     */
    @Test
    void aDocumentModifiedAfterItsOnlySignatureIsFlaggedBothWays() {
        SignatureReport modified = new SignatureReport(
                "Signature1", "adbe.pkcs7.detached", ByteRangeCoverage.of(0, 10, 10, 5, 100),
                IntegrityStatus.MODIFIED_AFTER_SIGNING, FIXED_NOW, TimestampInfo.absent(),
                List.of(certificate("signer"), certificate("ca")), ChainStatus.NOT_CHECKED,
                RevocationStatus.notChecked(), null);

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(modified), new FakeCertificateChainValidator(ChainStatus.TRUSTED),
                new FakeRevocationChecker(RevocationStatus.notChecked()));
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.signatures().get(0).verdict()).isEqualTo(SignatureVerdict.INVALID);
        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.INVALID);
        assertThat(report.modifiedAfterLastSignature()).isTrue();
    }

    // ---- T20: signature fields skipped by the verifier's cap ----

    /** A verifier that analysed {@code signatures} and skipped {@code skipped} further fields (cap reached). */
    private static final class CappedSignatureVerifier implements SignatureVerifier {
        private final List<SignatureReport> signatures;
        private final int skipped;

        CappedSignatureVerifier(List<SignatureReport> signatures, int skipped) {
            this.signatures = signatures;
            this.skipped = skipped;
        }

        @Override
        public List<SignatureReport> verify(byte[] pdf) {
            return signatures;
        }

        @Override
        public SignatureExtraction extract(byte[] pdf) {
            return new SignatureExtraction(signatures, skipped);
        }
    }

    private PdfAnalysisReport analyzeWithSkipped(List<SignatureReport> signatures, int skipped) {
        return useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new CappedSignatureVerifier(signatures, skipped),
                new FakeCertificateChainValidator(ChainStatus.TRUSTED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(new RevocationStatus(RevocationState.GOOD, "OCSP", null)))
                .analyze("t.pdf", CONTENT, new AnalysisOptions(true));
    }

    /**
     * SECURITY (T20): a fully valid analysed signature must not make the document VALID while other signature
     * fields were left unanalysed -- the decisive (invalid) signature could be hidden behind the cap.
     */
    @Test
    void aDocumentWithSkippedSignatureFieldsIsNeverOverallValid() {
        SignatureReport valid =
                signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));

        PdfAnalysisReport report = analyzeWithSkipped(List.of(valid), 2);

        assertThat(report.signatures().get(0).verdict()).isEqualTo(SignatureVerdict.VALID);
        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.ANALYSIS_INCOMPLETE);
        assertThat(report.sectionErrors()).hasSize(1);
        assertThat(report.sectionErrors().get(0).section()).isEqualTo(AnalysisSection.SIGNATURES);
        assertThat(report.sectionErrors().get(0).message()).contains("2 signature field(s) were not analysed");
    }

    @Test
    void aSkippedLaterSignatureNeverCoversAnEarlierModification() {
        SignatureReport modified = new SignatureReport(
                "Signature1", "adbe.pkcs7.detached", ByteRangeCoverage.of(0, 10, 10, 5, 100),
                IntegrityStatus.MODIFIED_AFTER_SIGNING, FIXED_NOW, TimestampInfo.absent(),
                List.of(certificate("signer"), certificate("ca")), ChainStatus.NOT_CHECKED,
                RevocationStatus.notChecked(), null);

        PdfAnalysisReport report = analyzeWithSkipped(List.of(modified), 1);

        assertThat(report.signatures().get(0).verdict()).isEqualTo(SignatureVerdict.INVALID);
        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.ANALYSIS_INCOMPLETE);
    }

    @Test
    void aDocumentWithoutSkippedFieldsKeepsItsVerdictAndHasNoSectionError() {
        SignatureReport valid =
                signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer"), certificate("ca")));

        PdfAnalysisReport report = analyzeWithSkipped(List.of(valid), 0);

        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.VALID);
        assertThat(report.sectionErrors()).isEmpty();
    }

    // ---- PDF/A-2/3 declaration ----

    @Test
    void aDocumentDeclaringPdfA2IsReportedAsNotValidatedInsteadOfTheFormalOneBResult() {
        PdfaDeclaration declaresPart2 = new PdfaDeclaration(2, "U");
        // The formal validator, run unconditionally against 1b rules, would
        // almost certainly find the document NON_COMPLIANT with 1b-specific
        // issues that say nothing about its real PDF/A-2 conformance.
        PdfaReport misleadingFormalResult = new PdfaReport(
                declaresPart2, PdfaValidationStatus.NON_COMPLIANT, List.of(new PdfaIssue("3.1.3", "not embedded")));

        FakePdfaConformanceValidator pdfaValidator = new FakePdfaConformanceValidator(misleadingFormalResult);
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, declaresPart2),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                pdfaValidator,
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.pdfa().status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.pdfa().declaration()).isEqualTo(declaresPart2);
        assertThat(report.pdfa().issues()).hasSize(1);
        assertThat(report.pdfa().issues().get(0).code()).isEqualTo("PDFA_PART_NOT_SUPPORTED");
        // T08b: the declaration is checked before invoking the formal
        // validator, and a declared PDF/A-2/3 document skips that call
        // entirely -- its result would only be discarded anyway.
        assertThat(pdfaValidator.callCount).isZero();
    }

    @Test
    void aDocumentDeclaringPdfA1UsesTheFormalValidatorsOwnResultUnchanged() {
        PdfaDeclaration declaresPart1 = new PdfaDeclaration(1, "B");
        PdfaReport formalResult = new PdfaReport(declaresPart1, PdfaValidationStatus.COMPLIANT, List.of());

        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, declaresPart1),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(formalResult),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.pdfa()).isEqualTo(formalResult);
    }

    // ---- section failure isolation ----

    @Test
    void anUnexpectedPdfaValidatorFailureIsReportedAsNotValidatedWithoutLosingTheRestOfTheReport() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(new IllegalStateException("preflight blew up")),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.pdfa().status()).isEqualTo(PdfaValidationStatus.NOT_VALIDATED);
        assertThat(report.pdfa().issues()).isNotEmpty();
        // The rest of the report must still be there.
        assertThat(report.hashes()).isEqualTo(HASHES);
        assertThat(report.structure()).isEqualTo(STRUCTURE);
        assertThat(report.security()).isEqualTo(SECURITY);
        // T08b: the failure must also be explicit, not just a degraded status.
        assertThat(report.sectionErrors()).hasSize(1);
        assertThat(report.sectionErrors().get(0).section()).isEqualTo(AnalysisSection.PDFA);
        // T09b: the raw exception message must never reach the client.
        assertThat(report.sectionErrors().get(0).message())
                .doesNotContain("preflight blew up")
                .contains("PDF/A-1b validation failed unexpectedly");
    }

    @Test
    void anUnexpectedSignatureVerifierFailureYieldsNoSignaturesWithoutLosingTheRestOfTheReport() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(new IllegalStateException("BC blew up")),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.signatures()).isEmpty();
        assertThat(report.hashes()).isEqualTo(HASHES);
        assertThat(report.pdfa()).isEqualTo(COMPLIANT_PDFA_REPORT);
        // T08b: an empty signatures list caused by a verifier failure must
        // not be silently indistinguishable from "this document is unsigned".
        assertThat(report.sectionErrors()).hasSize(1);
        assertThat(report.sectionErrors().get(0).section()).isEqualTo(AnalysisSection.SIGNATURES);
        // T09b: the raw exception message must never reach the client.
        assertThat(report.sectionErrors().get(0).message())
                .doesNotContain("BC blew up")
                .contains("signature verification failed unexpectedly");
        // T11c: an empty signatures list caused by the verifier itself
        // blowing up must not look like a legitimately unsigned document
        // (OverallVerdict.NO_SIGNATURES) -- the analysis is incomplete, not
        // conclusively "no signatures".
        assertThat(report.overallVerdict()).isEqualTo(OverallVerdict.ANALYSIS_INCOMPLETE);
    }

    @Test
    void aSuccessfulAnalysisHasNoSectionErrors() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(STRUCTURE, SECURITY, PdfaDeclaration.NONE),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.sectionErrors()).isEmpty();
    }

    @Test
    void anUnexpectedChainValidationFailureIsIsolatedToItsOwnSignature() {
        SignatureReport failing = signatureWith(TimestampInfo.absent(), FIXED_NOW, List.of(certificate("signer")));
        SignatureReport unaffected =
                new SignatureReport("Signature2", "adbe.pkcs7.detached", ByteRangeCoverage.of(0, 10, 10, 5, 15),
                        IntegrityStatus.INTACT, FIXED_NOW, TimestampInfo.absent(), List.of(),
                        ChainStatus.NOT_CHECKED, RevocationStatus.notChecked(), null);

        CertificateChainValidator chainValidator = new CertificateChainValidator() {
            @Override
            public ChainStatus validate(List<CertificateInfo> chain, Instant validationTime) {
                if (!chain.isEmpty()) {
                    throw new IllegalStateException("PKIX blew up");
                }
                return ChainStatus.NOT_CHECKED;
            }
        };

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(failing, unaffected), chainValidator, new FakeRevocationChecker(RevocationStatus.notChecked()));
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        assertThat(report.signatures()).hasSize(2);
        SignatureReport failingResult = report.signatures().get(0);
        assertThat(failingResult.chainStatus()).isEqualTo(ChainStatus.NOT_CHECKED);
        assertThat(failingResult.revocation()).isEqualTo(RevocationStatus.notChecked());
        assertThat(failingResult.anomalyOptional()).isPresent();
        assertThat(failingResult.anomalyOptional().get()).contains("chain/revocation enrichment failed");
        // The other signature must be entirely unaffected.
        assertThat(report.signatures().get(1).chainStatus()).isEqualTo(ChainStatus.NOT_CHECKED);
        assertThat(report.signatures().get(1).anomalyOptional()).isEmpty();
    }

    @Test
    void anEnrichmentFailureAppendsToAnExistingAnomalyRatherThanReplacingIt() {
        SignatureReport withExistingAnomaly = new SignatureReport("Signature1", "adbe.pkcs7.detached",
                ByteRangeCoverage.of(0, 10, 10, 5, 15), IntegrityStatus.INTACT, FIXED_NOW, TimestampInfo.absent(),
                List.of(certificate("signer")), ChainStatus.NOT_CHECKED, RevocationStatus.notChecked(),
                "1 certificate(s) could not be mapped");
        CertificateChainValidator chainValidator = new CertificateChainValidator() {
            @Override
            public ChainStatus validate(List<CertificateInfo> chain, Instant validationTime) {
                throw new IllegalStateException("PKIX blew up");
            }
        };

        AnalyzePdfUseCase useCase = happyPathUseCaseWithSignatures(
                List.of(withExistingAnomaly), chainValidator, new FakeRevocationChecker(RevocationStatus.notChecked()));
        PdfAnalysisReport report = useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false));

        String anomaly = report.signatures().get(0).anomalyOptional().orElseThrow();
        assertThat(anomaly).contains("1 certificate(s) could not be mapped");
        assertThat(anomaly).contains("chain/revocation enrichment failed");
    }

    // ---- whole-document failures propagate ----

    @Test
    void encryptedDocumentExceptionPropagatesRatherThanBeingCaught() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(new EncryptedPdfException("needs a password")),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        assertThatThrownBy(() -> useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false)))
                .isInstanceOf(EncryptedPdfException.class);
    }

    @Test
    void invalidPdfExceptionPropagatesRatherThanBeingCaught() {
        AnalyzePdfUseCase useCase = useCase(
                new FakePdfDocumentReader(new InvalidPdfException("not a PDF")),
                new FakeSignatureVerifier(List.of()),
                new FakeCertificateChainValidator(ChainStatus.NOT_CHECKED),
                new FakePdfaConformanceValidator(COMPLIANT_PDFA_REPORT),
                new FakeRevocationChecker(RevocationStatus.notChecked()));

        assertThatThrownBy(() -> useCase.analyze("t.pdf", CONTENT, new AnalysisOptions(false)))
                .isInstanceOf(InvalidPdfException.class);
    }
}
