## 환경
- JDK 17
- Gradle 8.10.2
- Spring boot 3.3.4


## 의존성
```gradle
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.3.4'
	id 'io.spring.dependency-management' version '1.1.6'
}

group = 'com.example'
version = '0.0.1-SNAPSHOT'

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

configurations {
	compileOnly {
		extendsFrom annotationProcessor
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
	implementation 'org.springframework.boot:spring-boot-starter-security'
	implementation 'org.springframework.boot:spring-boot-starter-web'
	developmentOnly 'org.springframework.boot:spring-boot-devtools'
	implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
	runtimeOnly 'com.h2database:h2'
	testImplementation 'org.springframework.boot:spring-boot-starter-test'
	testImplementation 'org.springframework.security:spring-security-test'
	compileOnly 'org.projectlombok:lombok'
	annotationProcessor 'org.projectlombok:lombok'
	testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}

tasks.named('test') {
	useJUnitPlatform()
}


```
## 학습자료 저장소
- [노션](https://youngwan2.notion.site/oauth2-0-Basic-HTTP-JWT-7-0-Nimbus-11268acd779b807792a0eb2c27330d6f?pvs=4)
