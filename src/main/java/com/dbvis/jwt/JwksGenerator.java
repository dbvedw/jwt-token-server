package com.dbvis.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;


class JwksGenerator {

    private static final int EXPIRY_SECONDS = 24 * 60 * 60;
    private static final String USERNAME = "me";

    public static String generateToken(String certKeysPath) {

        // *******************************
        // Load private key data from file
        // *******************************
        String filePath = certKeysPath + "privkey.pem";
        String publicPath = certKeysPath + "pubkey.pem";

        String privateKeyContent;
        String publicKeyContent;
        try {
            privateKeyContent = new String(Files.readAllBytes(Paths.get(filePath)))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("\n", "")
                    .replace("\r", "");
            publicKeyContent = new String(Files.readAllBytes(Paths.get(publicPath)))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("\n", "")
                    .replace("\r", "");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // ******************
        // Create private key
        // ******************
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(privateKeyContent)
        );

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                Base64.getDecoder().decode(publicKeyContent), "EC"
        );

        ECPrivateKey privateKey; // Use this key also to sign JWT!
        ECPublicKey publicKey;
        try {
            privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        // *****************
        // Create public key
        // *****************

        JWK jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID("1")
                .keyUse(KeyUse.SIGNATURE)
                .build();
        JWKSet set = new JWKSet(jwk);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonStr = gson.toJson(set.toJSONObject());
        System.out.println(jsonStr);

        // *********************
        // Prepare JWKS response
        // *********************


        // *******************
        // Example JWT signing
        // *******************
        String jwtHeaderString =
                """
                        { "alg": "ES256", "typ": "JWT", "kid": "1"}
                        """.replace(" ", "").replace("\n", "");

        String jwtHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(jwtHeaderString.getBytes(StandardCharsets.UTF_8));

        String jwtPayloadTemplate = """
                {
                    "sub": "%s",
                    "iat": %s,
                    "iss": "https://bla.bla.bla/",
                    "exp": %s
                }
                """.replace(" ", "").replace("\n", "");


        String jwtPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                String.format(
                        jwtPayloadTemplate,
                        USERNAME,
                        Instant.now().getEpochSecond(),
                        Instant.now().plusSeconds(EXPIRY_SECONDS).getEpochSecond()
                ).replace(" ", "").replace("\n", "").getBytes(StandardCharsets.UTF_8)
        );

        String jwtContent = jwtHeader + "." + jwtPayload;

        Signature signature;
        ECDSASigner ecdsaSigner;

        try {
            ecdsaSigner = new ECDSASigner(privateKey);
            signature = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException | JOSEException e) {
            throw new RuntimeException(e);
        }

        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        String jwtSignature;
        Base64URL sign;
        try {
            signature.update(jwtContent.getBytes());
            jwtSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    signature.sign()
            );

            sign = ecdsaSigner.sign(JWSHeader.parse(jwtHeaderString), jwtContent.getBytes());
        } catch (JOSEException | ParseException | SignatureException e) {
            throw new RuntimeException(e);
        }

        //String jwt = jwtContent + "." + jwtSignature;
        //System.out.println(jwt);

        return jwtContent + "." + sign.toString();
    }
}