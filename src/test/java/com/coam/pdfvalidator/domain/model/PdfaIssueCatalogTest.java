package com.coam.pdfvalidator.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PdfaIssueCatalog} translates a PDFBox {@code preflight} error code
 * (see {@code org.apache.pdfbox.preflight.PreflightConstants}, verified with
 * {@code javap -constants} against the vendored {@code preflight-3.0.8.jar}
 * rather than guessed) into neutral, professional Spanish for the web UI --
 * exact code first, then a cascading fallback to the code's own parent
 * category ("3.1.1" -&gt; "3.1" -&gt; "3"), and no translation at all for a
 * code (or category) this catalog does not recognize.
 */
class PdfaIssueCatalogTest {

    @Test
    void aKnownLeafCodeHasASpanishTranslation() {
        // 1.4 = ERROR_SYNTAX_TRAILER: the exact code seen in a real
        // /XRef-cross-reference-streams trailer error (T11).
        assertThat(PdfaIssueCatalog.spanishMessage("1.4"))
                .isPresent()
                .get(org.assertj.core.api.InstanceOfAssertFactories.STRING)
                .containsIgnoringCase("trailer");
    }

    @Test
    void anotherKnownLeafCodeHasASpanishTranslation() {
        // 3.1.3 = ERROR_FONTS_FONT_FILEX_INVALID: seen in a real
        // missing-FontFile error (T11).
        assertThat(PdfaIssueCatalog.spanishMessage("3.1.3"))
                .isPresent()
                .get(org.assertj.core.api.InstanceOfAssertFactories.STRING)
                .containsIgnoringCase("fuente");
    }

    @Test
    void aMetadataCodeHasASpanishTranslation() {
        // 7.1 = ERROR_METADATA_FORMAT: seen in a real "Metadata is not a
        // stream" error (T11).
        assertThat(PdfaIssueCatalog.spanishMessage("7.1"))
                .isPresent()
                .get(org.assertj.core.api.InstanceOfAssertFactories.STRING)
                .containsIgnoringCase("metadatos");
    }

    @Test
    void aColorSpaceCodeHasASpanishTranslation() {
        // 2.4.3 = ERROR_GRAPHIC_INVALID_COLOR_SPACE_MISSING: seen in a real
        // "DeviceGray default ... can't be used without Color Profile" error (T11).
        assertThat(PdfaIssueCatalog.spanishMessage("2.4.3"))
                .isPresent()
                .get(org.assertj.core.api.InstanceOfAssertFactories.STRING)
                .containsIgnoringCase("color");
    }

    @Test
    void anUnlistedLeafCodeFallsBackToItsParentCategory() {
        // "3.1.99" does not exist in PreflightConstants (real leaf codes
        // under 3.1 stop at 3.1.14); the cascading fallback must still find
        // "3.1" (ERROR_FONTS_INVALID_DATA)'s own translation.
        assertThat(PdfaIssueCatalog.spanishMessage("3.1.99"))
                .isEqualTo(PdfaIssueCatalog.spanishMessage("3.1"));
    }

    @Test
    void anUnlistedLeafCodeUnderAnUntranslatedParentFallsBackToTheTopCategory() {
        // "1.9.9" has no "1.9" entry in PreflightConstants either; the
        // cascade must skip straight to "1" (ERROR_SYNTAX_MAIN).
        assertThat(PdfaIssueCatalog.spanishMessage("1.9.9"))
                .isEqualTo(PdfaIssueCatalog.spanishMessage("1"));
    }

    @Test
    void anEntirelyUnknownCodeHasNoSpanishTranslation() {
        // "-1" is PDFBox's own ERROR_UNKNOWN_ERROR marker: deliberately not
        // catalogued (it names an uncategorised error, not a real PDF/A
        // rule), so the UI shows only the original English message for it --
        // exactly the "unknown code" case this catalog must handle safely.
        assertThat(PdfaIssueCatalog.spanishMessage("-1")).isEmpty();
    }

    @Test
    void aCodeFromOutsidePreflightConstantsHasNoSpanishTranslation() {
        assertThat(PdfaIssueCatalog.spanishMessage("NOT_VALIDATED")).isEmpty();
        assertThat(PdfaIssueCatalog.spanishMessage("TRUNCATED")).isEmpty();
    }

    @Test
    void aNullCodeHasNoSpanishTranslation() {
        assertThat(PdfaIssueCatalog.spanishMessage(null)).isEmpty();
    }
}
