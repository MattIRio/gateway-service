FROM eclipse-temurin:21-jre

COPY target/gateway-service-*.jar /app.jar

EXPOSE 80

ENTRYPOINT ["java", "-jar", "/app.jar"]