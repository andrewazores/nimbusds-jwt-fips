Simple application using nimbusds-jose-jwt to generate a signed and symmetrically encrypted JWT (JWE), print the token, then decrypt the token and print its contents.

Intended to be used to verify that the JDK crypto primitives on the runner system are available and sufficient for this JWT workflow.

1. `$ mvn clean compile assembly:single`
2. `$ java -jar target/nimbusds-jwt-fips-1.0-SNAPSHOT.jar`
3. Verify output looks like:
```
Creating JWT with SECRET_ALGORITHM=AES SECRET_KEYSIZE=256 SIGNATURE_ALGORITHM=HS256 ENCRYPTION_ALGORITHM=dir ENCRYPTION_METHOD=A256GCM
JWT:
	"eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0..6gaqLNpD92JD48g9.BlfvwJCwljd-5KC8jmE963YgLP-fIhTkmnhIbnl3W3UZF6qVVe3pIlA0UnshTyNHdee0ep_-i8JYUfJFOckJJSBV7Kb9sZEt3MDpwT29BlqIYpkf6UPOMcSB9t1CkylfSpHwFFFN5ROU6C6kFJL61zNgmvAb8cDHpAiRvq47L6SwWHRwtGvMuLhn8HOWGBh7EcLsSeccK2MXIe_xudnFzPrjwwqap43LqfcY3_evgSL0Vll3_lj6Y6z5hxFs1ES_r01rGATXAc5fqw5AvPv1uYrf_lE2GenUL7WykQhwWYUr2uJn1MhpKFep2-88RdPBTNIbriZmBqVepLVCv7dye68vFD61H50uDnz3j_BvOnwBeSKr_S1AmlPfd-dvIE0En71bG002YaOkkektfMM536ab-EWyO_FmrKcXSC0rgQ.OsnHWp8aL8du0YPRQrRLQw"
Parsed token:
	alg="HS256"
	claims="{aud=[2707f51b-6890-453a-a6c7-d8be815751b0, testaud], sub=testsubj, nbf=Thu May 08 16:05:17 EDT 2025, iss=2707f51b-6890-453a-a6c7-d8be815751b0, claimA=a-claim, exp=Thu May 08 16:06:17 EDT 2025, iat=Thu May 08 16:05:17 EDT 2025}"
```

There should be no exception stacktraces or other unexpected output.
