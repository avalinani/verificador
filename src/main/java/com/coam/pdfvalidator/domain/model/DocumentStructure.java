package com.coam.pdfvalidator.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * Structural properties of a PDF: declared versions, pages, and how many
 * incremental revisions the file went through.
 *
 * @param headerVersion  the {@code %PDF-x.y} header version, e.g. {@code "1.7"},
 *                       or {@code null} when no such header could be found in
 *                       the first bytes of the file (some real-world readers,
 *                       including PDFBox, can still parse such a document
 *                       instead of rejecting it outright)
 * @param catalogVersion the catalog's {@code /Version} override, or
 *                       {@code null} when the document does not declare one
 * @param pageCount      total number of pages of the document
 * @param pages          per-page details; at most the configured page cap (T20), so it can be shorter than
 *                       {@code pageCount} exactly when {@code pagesTruncated} is set
 * @param revisionCount  number of incremental update sections (at least 1
 *                       for the original revision)
 * @param pagesTruncated {@code true} when {@code pages} holds only the first pages of a longer document
 * @param revisionCountLowerBound {@code true} when a resource cap stopped the revision walk, so the document
 *                       has <em>at least</em> {@code revisionCount} revisions
 */
public record DocumentStructure(
        String headerVersion,
        String catalogVersion,
        int pageCount,
        List<PageInfo> pages,
        int revisionCount,
        boolean pagesTruncated,
        boolean revisionCountLowerBound) {

    /** A structure whose page list and revision count are complete and exact. */
    public DocumentStructure(
            String headerVersion, String catalogVersion, int pageCount, List<PageInfo> pages, int revisionCount) {
        this(headerVersion, catalogVersion, pageCount, pages, revisionCount, false, false);
    }

    public DocumentStructure {
        Objects.requireNonNull(pages, "pages");
        pages = List.copyOf(pages);
        if (pageCount < 0) {
            throw new IllegalArgumentException("pageCount must be >= 0, got: " + pageCount);
        }
        // Enforced rather than derived from pages.size(): pageCount stays an
        // explicit, independently-checkable component (e.g. for JSON
        // (de)serialization) instead of a computed accessor, at the cost of
        // this one consistency check.
        if (pagesTruncated ? pageCount <= pages.size() : pageCount != pages.size()) {
            throw new IllegalArgumentException("pageCount (" + pageCount + ") must "
                    + (pagesTruncated ? "exceed" : "equal") + " pages.size() (" + pages.size()
                    + ") when pagesTruncated=" + pagesTruncated);
        }
        if (revisionCount < 1) {
            throw new IllegalArgumentException("revisionCount must be >= 1, got: " + revisionCount);
        }
    }
}
