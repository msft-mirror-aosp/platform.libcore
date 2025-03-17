/*
 * Copyright (c) 2024, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import jdk.test.lib.artifacts.Artifact;
import jdk.test.lib.artifacts.ArtifactResolver;
import jdk.test.lib.json.JSONValue;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/*
 * @test
 * @bug 8342442 8345057
 * @library /test/lib
 * @modules java.base/sun.security.provider
 */

/// This test runs on `internalProjection.json`-style files generated by NIST's
/// ACVP Server ([GitHub repository](https://github.com/usnistgov/ACVP-Server)).
/// These files are included in ZIP archives available under the
/// [tags section](https://github.com/usnistgov/ACVP-Server/tags)
/// of the repository.
///
/// The zip archive is either hosted on artifactory server or
/// specified with local path to the test.
/// The test looks for test data files in the archive listed with `TEST_FILES`.
///
/// These tests are currently compatible with ACVP version 1.1.0.38.
///
/// By default, the test uses system-preferred implementations.
/// If you want to test a specific provider, set the
/// `test.acvp.provider` test property. The provider must be
/// registered.
///
/// Tests for each algorithm must be compliant to its specification linked from
/// [https://github.com/usnistgov/ACVP?tab=readme-ov-file#supported-algorithms].
///
/// Example:
///
/// Run locally with ArtifactResolver
/// ```
/// jtreg -Djdk.test.lib.artifacts.ACVP-Server=<path-to-archive-file>
/// ```
/// OR host the zip archive on artifactory server.
///

public class Launcher {

    private static final Provider PROVIDER;

    private static final String ACVP_BUNDLE_LOC = "jpg.tests.jdk";
    private static final String ACVP_BUNDLE_NAME = "ACVP-Server";
    private static final String ACVP_BUNDLE_VERSION = "1.1.0.38";
    // Zip archive entry name, do not update to use File.separator
    private static final String[] TEST_FILES = {
            "gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json",
            "gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json",
            "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
            "gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json",
            "gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json"
    };

    private static int count = 0;
    private static int invalidTest = 0;
    private static int unsupportedTest = 0;

    static {
        var provProp = System.getProperty("test.acvp.provider");
        if (provProp != null) {
            var p = Security.getProvider(provProp);
            if (p == null) {
                System.err.println(provProp + " is not a registered provider name");
                throw new RuntimeException(provProp + " is not a registered provider name");
            }
            PROVIDER = p;
        } else {
            PROVIDER = null;
        }
    }

    public static void main(String[] args) throws Exception {

        Path archivePath = ArtifactResolver.fetchOne(ACVP_SERVER_TESTS.class);
        System.out.println("Data path: " + archivePath);

        if (PROVIDER != null) {
            System.out.println("Provider: " + PROVIDER.getName());
        }

        // Read test data files from zip archive
        try (ZipFile zf = new ZipFile(archivePath.toFile())) {
            for (String testFile : TEST_FILES) {
                // Zip archive entry name, do not update to use File.separator
                String fullEntryName = ACVP_BUNDLE_NAME + "-" + ACVP_BUNDLE_VERSION + "/" + testFile;
                System.out.println("Find and test with: " + fullEntryName);
                ZipEntry ze = zf.getEntry(fullEntryName);
                if (ze != null) {
                    run(zf.getInputStream(ze));
                } else {
                    throw new RuntimeException("Entry not found: " + fullEntryName);
                }
            }
        }

        if (count > 0) {
            System.out.println();
            System.out.println("Test completed: " + count);
            System.out.println("Invalid tests: " + invalidTest);
            System.out.println("Unsupported tests: " + unsupportedTest);
        } else {
            throw new RuntimeException("No supported test found");
        }

        if (invalidTest != 0 || unsupportedTest != 0){
            throw new RuntimeException("Invalid or Unsupported tests found");
        }
    }

    static void run(InputStream test) {
        try {
            JSONValue kat;
            try (test) {
                kat = JSONValue.parse(new String(test.readAllBytes()));
            } catch (Exception e) {
                System.out.println("Warning: cannot parse " + test + ". Skipped");
                invalidTest++;
                return;
            }
            var alg = kat.get("algorithm").asString();
            switch (alg) {
                case "ML-DSA" -> {
                    ML_DSA_Test.run(kat, PROVIDER);
                    count++;
                }
                case "ML-KEM" -> {
                    ML_KEM_Test.run(kat, PROVIDER);
                    count++;
                }
                case "SHA2-256", "SHA2-224", "SHA3-256", "SHA3-224" -> {
                    SHA_Test.run(kat, PROVIDER);
                    count++;
                }
                default -> {
                    System.out.println("Skipped unsupported algorithm: " + alg);
                    unsupportedTest++;
                }
            }
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Artifact(
            organization = ACVP_BUNDLE_LOC,
            name = ACVP_BUNDLE_NAME,
            revision = ACVP_BUNDLE_VERSION,
            extension = "zip",
            unpack = false)
    private static class ACVP_SERVER_TESTS {
    }
}
