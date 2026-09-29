# syntax=docker/dockerfile:1

# ---- Build stage: compile and split the Spring Boot jar into layers ----
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
    && java -Djarmode=tools -jar target/pdf-validator-*.jar \
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

# Constrained JVM profile for a small VM (container limit: 512 MB):
# SerialGC = no GC worker threads / lowest footprint; heap capped at 384 MB,
# metaspace at 128 MB, leaving headroom for thread stacks and direct buffers.
# Compact object headers are stable in Java 25 and shrink every object.
ENV JAVA_TOOL_OPTIONS="-XX:+UseSerialGC -Xmx384m -XX:MaxMetaspaceSize=128m -XX:+UseCompactObjectHeaders -XX:+ExitOnOutOfMemoryError"

USER app:app
EXPOSE 8963

# Only /tmp needs to be writable (Tomcat work dir, PDFBox scratch files).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8963/actuator/health || exit 1

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
