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
 * @param pagesTruncated {@code true} when {@code pages} holds only the first pages of a longer document (the
 *                       configured cap); {@code pageCount} is always the real total
 * @param revisionCountLowerBound {@code true} when a resource cap stopped the revision walk, so {@code
 *                       revisionCount} is a lower bound
 */
public record DocumentStructureDto(
        String headerVersion,
        String catalogVersion,
        int pageCount,
        List<PageInfoDto> pages,
        int revisionCount,
        boolean pagesTruncated,
        boolean revisionCountLowerBound) {
}
