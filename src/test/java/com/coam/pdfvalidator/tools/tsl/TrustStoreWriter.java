package com.coam.pdfvalidator.tools.tsl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Replaces the trust store directory with a freshly rendered one. The new
 * files are first written to a sibling staging directory; only when that
 * succeeded is every regular file of the old directory removed (the tool owns
 * the directory) and the staged files moved in.
 */
final class TrustStoreWriter {

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");

    private TrustStoreWriter() {
    }

    static void replace(Path directory, SortedMap<String, String> files) throws IOException {
        for (String name : files.keySet()) {
            if (!SAFE_NAME.matcher(name).matches()) {
                throw new IOException("Refusing to write an unsafe file name: " + name);
            }
        }
        Path target = directory.toAbsolutePath().normalize();
        Files.createDirectories(target);
        Path staging = Files.createTempDirectory(target.getParent(), ".truststore-staging-");
        try {
            for (Map.Entry<String, String> file : files.entrySet()) {
                Files.writeString(staging.resolve(file.getKey()), file.getValue(), StandardCharsets.UTF_8);
            }
            for (Path existing : regularFiles(target)) {
                Files.delete(existing);
            }
            for (String name : files.keySet()) {
                Files.move(staging.resolve(name), target.resolve(name), StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            for (Path leftover : regularFiles(staging)) {
                Files.deleteIfExists(leftover);
            }
            Files.deleteIfExists(staging);
        }
    }

    private static List<Path> regularFiles(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return new ArrayList<>(entries.filter(Files::isRegularFile).toList());
        }
    }
}
