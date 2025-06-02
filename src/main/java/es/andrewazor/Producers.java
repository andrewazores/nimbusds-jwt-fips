package es.andrewazor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.eclipse.microprofile.config.inject.ConfigProperty;

public class Producers {

    @Produces
    @ApplicationScoped
    public SecretKey produceSecretKey(
            @ConfigProperty(name = "jwt.secret.algorithm") String alg,
            @ConfigProperty(name = "jwt.secret.keysize") int keysize) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(alg);
            generator.init(keysize);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }

    @Produces
    @ApplicationScoped
    public JWSSigner produceJwsSigner(SecretKey key) {
        try {
            return new MACSigner(key);
        } catch (KeyLengthException kle) {
            throw new RuntimeException(kle);
        }
    }

    @Produces
    @ApplicationScoped
    public JWSVerifier produceJwsVerifier(SecretKey key) {
        try {
            return new MACVerifier(key);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Produces
    @ApplicationScoped
    public JWEEncrypter produceJweEncrypter(SecretKey key) {
        try {
            return new DirectEncrypter(key);
        } catch (KeyLengthException kle) {
            throw new RuntimeException(kle);
        }
    }

    @Produces
    @ApplicationScoped
    public JWEDecrypter produceJweDecrypter(SecretKey key) {
        try {
            return new DirectDecrypter(key);
        } catch (KeyLengthException kle) {
            throw new RuntimeException(kle);
        }
    }

    @Produces
    @ApplicationScoped
    public JwtUtil.Algorithms produceAlgorithms(
            @ConfigProperty(name = "jwt.signature.algorithm") String sigAlg,
            @ConfigProperty(name = "jwt.encryption.algorithm") String encAlg,
            @ConfigProperty(name = "jwt.encryption.method") String encMtd) {
        return new JwtUtil.Algorithms(sigAlg, encAlg, encMtd);
    }
}
