package com.coam.pdfvalidator.domain.model;

import java.util.Objects;
import java.util.Set;

/** Whether a PDF is encrypted, and which permissions its security handler grants. */
public record SecurityInfo(boolean encrypted, Set<Permission> permissions) {

    public SecurityInfo {
        Objects.requireNonNull(permissions, "permissions");
        permissions = Set.copyOf(permissions);
    }
}
