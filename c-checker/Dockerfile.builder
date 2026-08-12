ARG MAVEN_IMAGE=maven:3.9.11-eclipse-temurin-17
FROM ${MAVEN_IMAGE}

WORKDIR /opt/binaryscan/c-checker-build
COPY pom.xml ./
RUN mvn -B -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -B -DskipTests package
RUN rm -rf src target
