# Standard OpenJDK image
FROM cgr.dev/chainguard-private/maven:3.8-jdk11-dev AS build

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source and build
COPY Worker.java /app/src/main/java/com/demo/worker/Worker.java
RUN mvn clean package -DskipTests

# Runtime stage - Chainguard JRE image (minimal, hardened base)
FROM cgr.dev/chainguard/jre:latest

WORKDIR /app

# Copy built JAR
COPY --from=build /app/target/worker-service-1.0.0.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]
