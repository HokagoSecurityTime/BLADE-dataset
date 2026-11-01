FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /fixture
COPY . .
RUN mvn -q -DskipTests package
FROM eclipse-temurin:21-jre
WORKDIR /fixture
COPY --from=build /fixture/target/campus-1.0.jar app.jar
EXPOSE 8080
CMD ["java","-jar","app.jar"]
