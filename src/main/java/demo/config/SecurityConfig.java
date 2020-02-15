package demo.config;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;

import java.security.KeyStore;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, proxyTargetClass = true)
class SecurityConfig extends GlobalMethodSecurityConfiguration {

    @Value("${keycloak.jwt.encryption.keyId}")
    String encKeyId;

    @Value("${keycloak.jwt.encryption.keystore.type}")
    String keystoreType;

    @Value("${keycloak.jwt.encryption.keystore.path}")
    String keystorePath;

    @Value("${keycloak.jwt.encryption.keystore.password}")
    String keystorePassword;

    @Bean
    GrantedAuthoritiesMapper keycloakAuthoritiesMapper() {

        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setConvertToUpperCase(true);
        return mapper;
    }

    @Bean
    KeyStore jweKeystore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        char[] password = keystorePassword.toCharArray();
        keyStore.load(getClass().getClassLoader().getResourceAsStream(keystorePath), password);

        return keyStore;
    }

    @Bean
    RSAKey jweEncKey(KeyStore jweKeystore) throws Exception {

        char[] password = keystorePassword.toCharArray();
        RSAKey key = RSAKey.load(jweKeystore, encKeyId, password);

        RSAKey encryptionKey = new RSAKey.Builder(key)
                .keyID(encKeyId)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(new Algorithm("RSA-OAEP"))
                .build();

        return encryptionKey;
    }
}
