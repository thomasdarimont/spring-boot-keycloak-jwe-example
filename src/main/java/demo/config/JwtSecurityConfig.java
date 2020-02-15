package demo.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import demo.keycloak.KeycloakGrantedAuthoritiesConverter;
import demo.keycloak.KeycloakJwtAuthenticationConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.List;

@Configuration
@RequiredArgsConstructor
class JwtSecurityConfig {

    private final RSAKey jweEncKey;

    @Bean
    JwtDecoder jwtDecoder(List<OAuth2TokenValidator<Jwt>> validators, OAuth2ResourceServerProperties properties) throws Exception {

        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));

        //Hack for configuring JWE KeySelector for JWE key lookup
        //TODO Find a better way to configure JWESelectror
        Field jwtProcessorField = ReflectionUtils.findField(NimbusJwtDecoder.class, "jwtProcessor");
        ReflectionUtils.makeAccessible(jwtProcessorField);
        DefaultJWTProcessor<?> djp = (DefaultJWTProcessor) jwtProcessorField.get(jwtDecoder);

        djp.setJWEKeySelector((var jweHeader, var context) -> {
            try {
                return List.of(jweEncKey.toPrivateKey());
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        });

        return jwtDecoder;
    }

    @Bean
    OAuth2TokenValidator<Jwt> defaultTokenValidator(OAuth2ResourceServerProperties properties) {
        return JwtValidators.createDefaultWithIssuer(properties.getJwt().getIssuerUri());
    }

    @Bean
    KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> converter) {
        return new KeycloakJwtAuthenticationConverter(converter);
    }

    @Bean
    Converter<Jwt, Collection<GrantedAuthority>> keycloakGrantedAuthoritiesConverter( //
                                                                                      @Value("${keycloak.clientId}") String clientId, //
                                                                                      GrantedAuthoritiesMapper mapper //
    ) {
        return new KeycloakGrantedAuthoritiesConverter(clientId, mapper);
    }

}
