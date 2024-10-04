package com.example.demo.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("jwt.public.key")
    private String publicKey;


    // 시큐리티 필터 체인
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );
        // 세션 저장 비활성화(세션을 생성하되 세션을 저장하지 않고 요청 처리가 끝나면 제거 됨)
        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.formLogin(AbstractHttpConfigurer::disable); // 기본 폼 로그인 비활성화
        http.httpBasic(Customizer.withDefaults()); // 기본 HTTP 활성화
        http.csrf(AbstractHttpConfigurer::disable); // CSRF 비활성화

        // OAuth Resource Server 사용 등록(jwt 사용)
        http.oauth2ResourceServer((oauth2ResourceServer) ->
                oauth2ResourceServer
                        .jwt((jwt) ->
                                {
                                    try {
                                        jwt
                                                .decoder(jwtDecoder(rsaKey(keyPair())));
                                    } catch (JOSEException e) {
                                        throw new RuntimeException(e);
                                    }
                                } // jwt 디코더 설정
                        )
        );
        return http.build();
    }

    // 서버 실행 시 더미 유저 정보(Bean 으로 등록해두면 로그인 요청 시 해당 빈에서 생성된 정보가 UserDetails 에 담김
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.builder()
                .username("user")
                .password("{noop}password") // 평문
                .roles("USER")
                .build();

        UserDetails user2 = User.builder()
                .username("admin")
                .password("{noop}password") // 평문
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    // 키페어 생성
    @Bean
    public KeyPair keyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // RSAKey 객체 생성
    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){
        var jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> {
            // 선택된 키는 JWK 세트 내의 위치에 따라 정렬되며, 일치하는 키가 없거나 JWK가 null인 경우 빈 리스트입니다.
            return jwkSelector.select(jwkSet);
        };

//        return new JWKSource<>(){
//            @Override
//            public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//                // 선택된 키는 JWK 세트 내의 위치에 따라 정렬되며, 일치하는 키가 없거나 JWK가 null인 경우 빈 리스트입니다.
//                return jwkSelector.select(jwkSet);
//            }
//        };
    }


    // JWT 를 디코딩 할 때 사용() ; Bearer TOKEN
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    // JWT 인코딩 시 사용
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }
}