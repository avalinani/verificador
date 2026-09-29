package com.coam.pdfvalidator.api.dto;

import java.util.List;

/**
 * Structural properties of the uploaded PDF.
 *
 * @param headerVersion  the {@code %PDF-x.y} header version, or {@code null}
 *                       when no such header could be found (some readers,
 *                       including this service's own PDF engine, can still
 *                       parse such a document instead of rejecting it)
 * @param catalogVersion the catalog's {@code /Version} override, or {@code
 *                       null} when the document does not declare one
 * @param revisionCount  number of incremental update sections (at least 1)
 */
public record DocumentStructureDto(
        String headerVersion,
        String catalogVersion,
        int pageCount,
        List<PageInfoDto> pages,
        int revisionCount) {
}
