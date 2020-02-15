package demo.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
class JwksEndpoint {

    private final RSAKey jweEncKey;

    @GetMapping("/oauth/jwks")
    Object getJwks() {
        return new JWKSet(jweEncKey).toJSONObject();
    }
}
