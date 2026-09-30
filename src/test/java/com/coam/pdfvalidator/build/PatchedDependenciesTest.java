package com.coam.pdfvalidator.build;

import org.apache.catalina.util.ServerInfo;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T18b: Spring Boot 4.1.1 (the latest release) still manages Tomcat 11.0.24
 * and Jackson 3.1.5 / 2.21.5, which OSV.dev flags (Tomcat CVE-2026-65905,
 * CVE-2026-65182, CVE-2026-68525; Jackson 3 CVE-2026-68497, CVE-2026-83557,
 * CVE-2026-19032; Jackson 2 fixed in 2.21.6). The pom overrides the managed
 * versions; this test fails if the override is dropped or a BOM bump
 * regresses the resolved versions below the patched ones.
 */
class PatchedDependenciesTest {

    @Test
    void tomcatIsAtLeastTheFirstPatchedRelease() {
        assertThat(atLeast(ServerInfo.getServerNumber(), 11, 0, 25))
                .as("resolved Tomcat %s", ServerInfo.getServerNumber())
                .isTrue();
    }

    @Test
    void jackson3IsAtLeastTheFirstPatchedRelease() {
        String version = tools.jackson.core.json.PackageVersion.VERSION.toString();
        assertThat(atLeast(version, 3, 1, 6)).as("resolved Jackson 3 %s", version).isTrue();
    }

    @Test
    void jackson2IsAtLeastTheFirstPatchedRelease() {
        String version = com.fasterxml.jackson.core.json.PackageVersion.VERSION.toString();
        assertThat(atLeast(version, 2, 21, 6)).as("resolved Jackson 2 %s", version).isTrue();
    }

    private static boolean atLeast(String version, int major, int minor, int patch) {
        String[] parts = version.split("[.-]");
        int[] actual = {Integer.parseInt(parts[0]), Integer.parseInt(parts[1]), Integer.parseInt(parts[2])};
        int[] wanted = {major, minor, patch};
        for (int i = 0; i < 3; i++) {
            if (actual[i] != wanted[i]) {
                return actual[i] > wanted[i];
            }
        }
        return true;
    }
}
