package com.dbvis.jwt;

import java.io.IOException;

import fi.iki.elonen.NanoHTTPD;

public class TokenServer extends NanoHTTPD {

    private static final String DEFAULT_USERNAME = "me";

    private final String certKeysPath;

    public TokenServer(String certKeysPath) throws IOException {
        super(8088);
        this.certKeysPath = certKeysPath;
        start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        System.out.println("\nRunning! Point your browsers to http://localhost:8088/ \n");
    }

    public static void main(String[] args) {
        try {
            String path = args[0];
            new TokenServer(path);
        } catch (IOException ioe) {
            System.err.println("Couldn't start server:\n" + ioe);
        }
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        String user = DEFAULT_USERNAME;
        if (uri.contains("token/")) {
            String inputUser = uri.substring(uri.lastIndexOf("token/") + 6);
            if (inputUser.length() > 0) {
                user = inputUser;
            }
        }

        String output = "<html><body>" +
                "<h1>" + JwksGenerator.generateToken(certKeysPath, user) + "</h1>" +
                "</body></html>";
        return newFixedLengthResponse(output);
    }
}