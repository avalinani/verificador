package com.coam.pdfvalidator.infrastructure.pdfbox;

/**
 * Resource caps for the structural read of a (possibly hostile) PDF (T20).
 *
 * @param maxPages            pages whose details are read and reported; further pages are only counted
 * @param maxRevisionMarkers  occurrences of each of the {@code stream}, {@code startxref} and {@code /Prev}
 *                            keywords collected while counting revisions; crossing it makes the revision count
 *                            a lower bound
 * @param maxRevisions        cross-reference sections followed by the revision walk; further ones make the
 *                            revision count a lower bound
 */
public record StructureLimits(int maxPages, int maxRevisionMarkers, int maxRevisions) {

    public static final StructureLimits DEFAULT = new StructureLimits(1_000, 1_000_000, 10_000);

    public StructureLimits {
        if (maxPages < 1 || maxRevisionMarkers < 1 || maxRevisions < 1) {
            throw new IllegalArgumentException("structure limits must be >= 1: " + maxPages + ", "
                    + maxRevisionMarkers + ", " + maxRevisions);
        }
    }
}
