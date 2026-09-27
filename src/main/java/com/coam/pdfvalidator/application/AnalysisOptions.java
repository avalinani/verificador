package com.coam.pdfvalidator.application;

/**
 * Per-analysis options for {@link AnalyzePdfUseCase}.
 *
 * @param checkRevocation whether to call the configured {@code
 *                        RevocationChecker} for each signature's certificate
 *                        chain. Revocation checking is network-bound and
 *                        optional by design (see README, section 10): when
 *                        {@code false}, every signature's revocation status
 *                        is {@code RevocationStatus.notChecked()} with no
 *                        network call at all.
 */
public record AnalysisOptions(boolean checkRevocation) {
}
