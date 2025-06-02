package es.andrewazor;

import com.nimbusds.jwt.JWT;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import jakarta.inject.Inject;
import java.util.Collections;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@QuarkusMain
public class App {

    public static void main(String[] args) throws Exception {
        Quarkus.run(Launcher.class, args);
    }

    public static class Launcher implements QuarkusApplication {

        @Inject JwtUtil jwtUtil;

        @ConfigProperty(name = "jwt.secret.algorithm")
        String JWT_SECRET_ALGORITHM;

        @ConfigProperty(name = "jwt.secret.keysize")
        int JWT_SECRET_KEYSIZE;

        @ConfigProperty(name = "jwt.signature.algorithm")
        String JWT_SIGNATURE_ALGORITHM;

        @ConfigProperty(name = "jwt.encryption.algorithm")
        String JWT_ENCRYPTION_ALGORITHM;

        @ConfigProperty(name = "jwt.encryption.method")
        String JWT_ENCRYPTION_METHOD;

        @Override
        public int run(String... args) throws Exception {
            System.out.println(
                    String.format(
                            "Creating JWT with SECRET_ALGORITHM=%s SECRET_KEYSIZE=%d"
                                    + " SIGNATURE_ALGORITHM=%s ENCRYPTION_ALGORITHM=%s"
                                    + " ENCRYPTION_METHOD=%s",
                            JWT_SECRET_ALGORITHM,
                            JWT_SECRET_KEYSIZE,
                            JWT_SIGNATURE_ALGORITHM,
                            JWT_ENCRYPTION_ALGORITHM,
                            JWT_ENCRYPTION_METHOD));

            String token = jwtUtil.createToken();
            System.out.println(String.format("JWT:%n\t\"%s\"", token));
            JWT jwt = jwtUtil.parseToken(token);
            System.out.println(
                    String.format(
                            "Parsed token:%n\talg=\"%s\"%n\tclaims=\"%s\"",
                            jwt.getHeader().getAlgorithm(),
                            Collections.unmodifiableMap(jwt.getJWTClaimsSet().getClaims())));
            return 0;
        }
    }
}
