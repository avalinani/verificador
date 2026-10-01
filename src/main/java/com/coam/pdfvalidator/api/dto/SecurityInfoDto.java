package com.coam.pdfvalidator.api.dto;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Whether the PDF is encrypted, and which permissions its security handler
 * grants (e.g. {@code "PRINT"}, {@code "MODIFY"}, {@code "EXTRACT_CONTENT"}).
 */
public record SecurityInfoDto(boolean encrypted, Set<String> permissions) {
    public SecurityInfoDto {
        // Snapshot in insertion order: Set.copyOf would randomize the iteration
        // order per JVM run and with it the order of the JSON array.
        permissions = Collections.unmodifiableSet(new LinkedHashSet<>(permissions));
    }
}
