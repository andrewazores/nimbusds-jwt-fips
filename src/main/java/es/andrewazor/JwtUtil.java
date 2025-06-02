package es.andrewazor;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Produces;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Produces
@ApplicationScoped
public class JwtUtil {

    private final UUID issuer = UUID.randomUUID();
    @Inject JWSSigner signer;
    @Inject JWSVerifier verifier;
    @Inject JWEEncrypter encrypter;
    @Inject JWEDecrypter decrypter;
    @Inject Algorithms algorithms;

    @ConfigProperty(name = "jwt.signature.algorithm")
    String sigAlg;

    @ConfigProperty(name = "jwt.encryption.algorithm")
    String encAlg;

    @ConfigProperty(name = "jwt.encryption.method")
    String encMtd;

    public String createToken() throws JOSEException {
        Date now = Date.from(Instant.now());
        Date expiry = Date.from(now.toInstant().plus(Duration.ofMinutes(1)));
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(issuer.toString())
                        .audience(List.of(issuer.toString(), "testaud"))
                        .issueTime(now)
                        .notBeforeTime(now)
                        .expirationTime(expiry)
                        .subject("testsubj")
                        .claim("claimA", "a-claim")
                        .build();

        SignedJWT jwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.parse(algorithms.signature())).build(),
                        claims);
        jwt.sign(signer);

        JWEHeader header =
                new JWEHeader.Builder(
                                JWEAlgorithm.parse(algorithms.encryption()),
                                EncryptionMethod.parse(algorithms.encryptionMethod()))
                        .contentType("JWT")
                        .build();
        JWEObject jwe = new JWEObject(header, new Payload(jwt));
        jwe.encrypt(encrypter);

        return jwe.serialize();
    }

    public JWT parseToken(String rawToken) throws JOSEException, ParseException, BadJWTException {
        JWEObject jwe = JWEObject.parse(rawToken);
        jwe.decrypt(decrypter);

        SignedJWT jwt = jwe.getPayload().toSignedJWT();
        jwt.verify(verifier);

        JWTClaimsSet exactMatchClaims =
                new JWTClaimsSet.Builder()
                        .issuer(issuer.toString())
                        .audience(List.of(issuer.toString(), "testaud"))
                        .subject("testsubj")
                        .claim("claimA", "a-claim")
                        .build();
        Set<String> requiredClaimNames =
                new HashSet<>(Set.of("iat", "iss", "aud", "sub", "exp", "nbf", "claimA"));
        DefaultJWTClaimsVerifier<SecurityContext> verifier =
                new DefaultJWTClaimsVerifier<>(
                        issuer.toString(), exactMatchClaims, requiredClaimNames);
        verifier.setMaxClockSkew(5);
        verifier.verify(jwt.getJWTClaimsSet(), null);

        return jwt;
    }

    static class Algorithms {
        String signature;
        String encryption;
        String encryptionMethod;

        public Algorithms(String signature, String encryption, String encryptionMethod) {
            this.signature = signature;
            this.encryption = encryption;
            this.encryptionMethod = encryptionMethod;
        }

        public String signature() {
            return signature;
        }

        public String encryption() {
            return encryption;
        }

        public String encryptionMethod() {
            return encryptionMethod;
        }
    }
}
