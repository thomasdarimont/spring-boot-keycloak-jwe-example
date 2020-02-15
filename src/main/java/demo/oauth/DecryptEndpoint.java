package demo.oauth;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URL;

@RestController
@RequiredArgsConstructor
public class DecryptEndpoint {

//    private final RSAKey jweEncKey;
//
//    @PostMapping("/oauth/decrypt")
//    Object decrypt(@RequestParam String token) throws Exception {
//
//        JWEObject jweObject = JWEObject.parse(token);
//        jweObject.decrypt(new RSADecrypter(jweEncKey));
//
//        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
//        JWKSet jwks = JWKSet.load(new URL("http://localhost:8081/auth/realms/jwedemo/protocol/openid-connect/certs"));
//        JWK signKey = jwks.getKeyByKeyId(signedJWT.getHeader().getKeyID());
//        signedJWT.verify(new RSASSAVerifier((RSAKey) signKey));
//
//        return signedJWT.getJWTClaimsSet();
//    }
}
