package com.coam.pdfvalidator.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/**
 * Enforces this project's hexagonal architecture (README section 5):
 * {@code domain} is pure Java with no library dependencies, {@code
 * application} depends only on {@code domain}, {@code infrastructure} never
 * reaches into {@code api}/{@code application}, and the top-level packages
 * never form an import cycle.
 *
 * <p>Imports only the project's own compiled classes (test sources are
 * excluded via {@link ImportOption.Predefined#DO_NOT_INCLUDE_TESTS}) --
 * fixtures and other test-only helpers intentionally use PDFBox/Bouncy
 * Castle directly and would otherwise trip these same rules for no reason
 * related to the production architecture they exist to protect.
 */
class ArchitectureTest {

    private static final String DOMAIN = "com.coam.pdfvalidator.domain..";
    private static final String APPLICATION = "com.coam.pdfvalidator.application..";
    private static final String INFRASTRUCTURE = "com.coam.pdfvalidator.infrastructure..";
    private static final String API = "com.coam.pdfvalidator.api..";

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.coam.pdfvalidator");
    }

    /**
     * {@code domain} is plain Java: no Spring, PDFBox, Bouncy Castle, or any
     * other third-party library -- verified since T02 with a plain {@code
     * grep} in every task's evidence; this makes that same guarantee an
     * enforced, always-run test instead. {@code java.security.cert} and
     * {@code java.awt} are additionally excluded even though they are
     * technically part of {@code java..}: the domain represents certificates
     * and colors with its own library-free types ({@code CertificateInfo},
     * plain numeric boxes) precisely so it never needs either.
     */
    @Test
    void domainDependsOnNothingButPlainJava() {
        ArchRule onlyJava = classes().that().resideInAPackage(DOMAIN)
                .should().onlyDependOnClassesThat().resideInAnyPackage(DOMAIN, "java..", "javax..");
        onlyJava.check(classes);

        ArchRule noCertOrAwt = noClasses().that().resideInAPackage(DOMAIN)
                .should().dependOnClassesThat().resideInAnyPackage("java.security.cert..", "java.awt..");
        noCertOrAwt.check(classes);
    }

    /** {@code application} orchestrates the domain ports only; it must never reach into infrastructure or api. */
    @Test
    void applicationDependsOnlyOnDomainAndPlainJava() {
        ArchRule rule = classes().that().resideInAPackage(APPLICATION)
                .should().onlyDependOnClassesThat().resideInAnyPackage(APPLICATION, DOMAIN, "java..", "javax..");
        rule.check(classes);
    }

    /**
     * {@code infrastructure} adapters implement domain ports; they must
     * never depend "upward" on the use case or a future REST layer.
     */
    @Test
    void infrastructureNeverDependsOnApplicationOrApi() {
        ArchRule rule = noClasses().that().resideInAPackage(INFRASTRUCTURE)
                .should().dependOnClassesThat().resideInAnyPackage(APPLICATION, API);
        rule.check(classes);
    }

    /**
     * {@code api} may depend on {@code application} and {@code domain}
     * (never on {@code infrastructure} directly -- it should only ever see
     * infrastructure adapters through the ports/use case they implement),
     * plus the web framework and API-documentation libraries a REST
     * controller layer legitimately needs to exist at all (Spring MVC/HTTP
     * types, springdoc/swagger annotations). This does not weaken the
     * boundary the rule exists for: {@code infrastructure} is still not in
     * the allowed list, so an {@code api} class reaching around the use case
     * into a concrete adapter is still caught. {@code allowEmptyShould(true)}
     * lets this rule pass vacuously before T09, when the package did not yet
     * exist.
     */
    @Test
    void apiDependsOnlyOnApplicationAndDomain() {
        ArchRule rule = classes().that().resideInAPackage(API)
                .should().onlyDependOnClassesThat().resideInAnyPackage(
                        API, APPLICATION, DOMAIN, "java..", "javax..", "org.springframework..", "io.swagger..")
                .allowEmptyShould(true);
        rule.check(classes);
    }

    /** No import cycle between the four top-level packages (or any of their sub-packages). */
    @Test
    void topLevelPackagesAreFreeOfCycles() {
        ArchRule rule = slices().matching("com.coam.pdfvalidator.(*)..").should().beFreeOfCycles();
        rule.check(classes);
    }
}
