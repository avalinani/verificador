# syntax=docker/dockerfile:1

# ---- Build stage: compile and split the Spring Boot jar into layers ----
# Base images are pinned by tag (the patch level floats). For reproducible builds pin
# by digest: run `docker buildx imagetools inspect eclipse-temurin:25-jdk-alpine`
# and use `FROM eclipse-temurin:25-jdk-alpine@sha256:<digest>` (same for the JRE image).
FROM eclipse-temurin:25-jdk-alpine AS build
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
FROM eclipse-temurin:25-jre-alpine
RUN addgroup -g 10001 -S app && adduser -u 10001 -S -G app -H -s /sbin/nologin app
WORKDIR /app

# Least-changing layers first so rebuilds reuse the cache.
COPY --from=build --chown=app:app /workspace/extracted/dependencies/ ./
COPY --from=build --chown=app:app /workspace/extracted/spring-boot-loader/ ./
COPY --from=build --chown=app:app /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build --chown=app:app /workspace/extracted/application/ ./

# Memory budget for the 512 MB container limit (worst case, everything at its cap):
#   heap            240 MB  (-Xmx240m)
#   metaspace        80 MB  (-XX:MaxMetaspaceSize=80m)
#   code cache       32 MB  (-XX:ReservedCodeCacheSize=32m)
#   direct buffers   24 MB  (-XX:MaxDirectMemorySize=24m)
#   thread stacks    20 MB  (~40 threads: 20 Tomcat + JIT/VM/misc, x 512 KB via -Xss512k)
#   other native     32 MB  (malloc arenas, GC structures, CDS, libc)
#   --------------- 428 MB
#   tmpfs /tmp       64 MB  (compose/CI; counted against the cgroup when full; in practice
#                            at most 2 uploads x 20 MB = 40 MB thanks to the bulkhead)
#   --------------- 492 MB  -> ~20 MB of headroom under 512 MB.
# SerialGC = no GC worker threads / lowest footprint. Compact object headers are
# stable in Java 25 and shrink every object. Request concurrency is bounded in
# application.yml (server.tomcat.threads.max / accept-count) so the thread term holds, and
# simultaneous analyses by the bulkhead (pdfvalidator.analysis.max-concurrent=2), which is
# what keeps the heap term realistic (2 analyses x ~100 MB worst case < 240 MB).
ENV JAVA_TOOL_OPTIONS="-XX:+UseSerialGC -Xms64m -Xmx240m -XX:MaxMetaspaceSize=80m -XX:ReservedCodeCacheSize=32m -XX:MaxDirectMemorySize=24m -Xss512k -XX:+UseCompactObjectHeaders -XX:+ExitOnOutOfMemoryError"

USER app:app
EXPOSE 8963

# Only /tmp needs to be writable (Tomcat work dir, PDFBox scratch files).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8963/actuator/health || exit 1

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
