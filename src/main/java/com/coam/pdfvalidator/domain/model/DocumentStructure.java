package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * Structural properties of a PDF: declared versions, pages, and how many
 * incremental revisions the file went through.
 *
 * @param headerVersion  the {@code %PDF-x.y} header version, e.g. {@code "1.7"}
 * @param catalogVersion the catalog's {@code /Version} override, or
 *                       {@code null} when the document does not declare one
 * @param revisionCount  number of incremental update sections (at least 1
 *                       for the original revision)
 */
public record DocumentStructure(
        String headerVersion,
        String catalogVersion,
        int pageCount,
        List<PageInfo> pages,
        int revisionCount) {

    public DocumentStructure {
        Objects.requireNonNull(headerVersion, "headerVersion");
        Objects.requireNonNull(pages, "pages");
        pages = List.copyOf(pages);
        if (pageCount < 0) {
            throw new IllegalArgumentException("pageCount must be >= 0, got: " + pageCount);
        }
        if (revisionCount < 1) {
            throw new IllegalArgumentException("revisionCount must be >= 1, got: " + revisionCount);
        }
    }
}
