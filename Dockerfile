# syntax=docker/dockerfile:1

# ---- Build stage: compile and split the Spring Boot jar into layers ----
# Base images are pinned by digest (the multi-arch index digest, so linux/amd64 and
# linux/arm64 both resolve); the tag is kept for readability and is ignored by Docker
# when a digest is present. Pinned 2026-09-30. To refresh (they do not update themselves):
#   docker buildx imagetools inspect eclipse-temurin:25-jdk-alpine   (and 25-jre-alpine)
# or read the `docker-content-digest` header of the Docker Hub registry manifest
# (Accept: application/vnd.oci.image.index.v1+json), then update BOTH FROM lines.
FROM eclipse-temurin:25-jdk-alpine@sha256:3fd2d245c4e0eba615fe366a71b8bd25f5db7104f53e4026b24bf508b880bd2a AS build
WORKDIR /workspace

# Dependency layer: only re-resolved when pom.xml or the wrapper change.
COPY mvnw pom.xml ./
COPY .mvn .mvn
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw \
    && ./mvnw -B -q dependency:go-offline

# Sources: tests run in CI (./mvnw verify), not in the image build.
COPY src src
RUN ./mvnw -B -DskipTests package \
    && java -Djarmode=tools -jar target/pdf-validator.jar \
        extract --layers --launcher --destination /workspace/extracted

# ---- Runtime stage: JRE only, non-root ----
FROM eclipse-temurin:25-jre-alpine@sha256:3c0a9084927a221ccd1d007fcaf614465672c0af37aaa834c5184483afe56d61
RUN addgroup -g 10001 -S app && adduser -u 10001 -S -G app -H -s /sbin/nologin app
WORKDIR /app

# Least-changing layers first so rebuilds reuse the cache.
COPY --from=build --chown=app:app /workspace/extracted/dependencies/ ./
COPY --from=build --chown=app:app /workspace/extracted/spring-boot-loader/ ./
COPY --from=build --chown=app:app /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build --chown=app:app /workspace/extracted/application/ ./

# Memory budget for the 2 GB container limit (worst case, everything at its cap):
#   heap           1024 MB  (-Xmx1024m; measured: 5 concurrent 79 MB analyses, max-concurrent=2, peaked ~1 GB total)
#   metaspace        96 MB  (-XX:MaxMetaspaceSize=96m)
#   code cache       48 MB  (-XX:ReservedCodeCacheSize=48m)
#   direct buffers   32 MB  (-XX:MaxDirectMemorySize=32m)
#   thread stacks    20 MB  (~40 threads: 20 Tomcat + JIT/VM/misc, x 512 KB via -Xss512k)
#   other native     64 MB  (malloc arenas, GC structures, CDS, libc)
#   --------------- 1284 MB
#   tmpfs /tmp      256 MB  (compose/CI; counted against the cgroup when full: at most
#                            max-concurrent (2) uploads x 81 MB = 162 MB + ~90 MB spare)
#   --------------- 1540 MB -> ~500 MB of headroom under 2048 MB.
# SerialGC = no GC worker threads / lowest footprint. Compact object headers are
# stable in Java 25 and shrink every object. Request concurrency is bounded in
# application.yml (server.tomcat.threads.max / accept-count) so the thread term holds, and
# simultaneous analyses by the bulkhead (pdfvalidator.analysis.max-concurrent), which is
# what keeps the heap term realistic. For a smaller VM override JAVA_TOOL_OPTIONS,
# mem_limit and the tmpfs size together (and lower the upload limit).
ENV JAVA_TOOL_OPTIONS="-XX:+UseSerialGC -Xms64m -Xmx1024m -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -XX:MaxDirectMemorySize=32m -Xss512k -XX:+UseCompactObjectHeaders -XX:+ExitOnOutOfMemoryError"

USER app:app
EXPOSE 8963

# Only /tmp needs to be writable (Tomcat work dir, PDFBox scratch files).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8963/actuator/health || exit 1

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
