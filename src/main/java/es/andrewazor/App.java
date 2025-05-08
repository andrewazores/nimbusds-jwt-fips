package es.andrewazor;

import java.util.Collections;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

public class App {

    static final String JWT_SECRET_ALGORITHM = "AES";
    static final int JWT_SECRET_KEYSIZE = 256;
    static final String JWT_SIGNATURE_ALGORITHM = "HS256";
    static final String JWT_ENCRYPTION_ALGORITHM = "dir";
    static final String JWT_ENCRYPTION_METHOD = "A256GCM";

    public static void main(String[] args) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(JWT_SECRET_ALGORITHM);
        generator.init(JWT_SECRET_KEYSIZE);
        SecretKey secretKey = generator.generateKey();

        JWSSigner jwsSigner = new MACSigner(secretKey);
        JWSVerifier jwsVerifier = new MACVerifier(secretKey);
        JWEEncrypter jweEncrypter = new DirectEncrypter(secretKey);
        JWEDecrypter jweDecrypter = new DirectDecrypter(secretKey);

        JwtUtil jwtUtil = new JwtUtil(jwsSigner, jwsVerifier, jweEncrypter, jweDecrypter, new JwtUtil.Algorithms(JWT_SIGNATURE_ALGORITHM, JWT_ENCRYPTION_ALGORITHM, JWT_ENCRYPTION_METHOD));

        System.out.println(String.format(
                    "Creating JWT with SECRET_ALGORITHM=%s SECRET_KEYSIZE=%d SIGNATURE_ALGORITHM=%s ENCRYPTION_ALGORITHM=%s ENCRYPTION_METHOD=%s",
                    JWT_SECRET_ALGORITHM,
                    JWT_SECRET_KEYSIZE,
                    JWT_SIGNATURE_ALGORITHM,
                    JWT_ENCRYPTION_ALGORITHM,
                    JWT_ENCRYPTION_METHOD
                    ));

        String token = jwtUtil.createToken();
        System.out.println(String.format("JWT:%n\t\"%s\"", token));
        JWT jwt = jwtUtil.parseToken(token);
        System.out.println(String.format(
                    "Parsed token:%n\talg=\"%s\"%n\tclaims=\"%s\"",
                    jwt.getHeader().getAlgorithm(),
                    Collections.unmodifiableMap(jwt.getJWTClaimsSet().getClaims())
                    ));
    }
}
