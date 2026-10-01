package com.coam.pdfvalidator.api.dto;

import java.util.Set;

/**
 * Whether the PDF is encrypted, and which permissions its security handler
 * grants (e.g. {@code "PRINT"}, {@code "MODIFY"}, {@code "EXTRACT_CONTENT"}).
 */
public record SecurityInfoDto(boolean encrypted, Set<String> permissions) {
    public SecurityInfoDto {
        permissions = Set.copyOf(permissions);
    }
}
