package com.dbvis.jwt;

import java.io.IOException;

import fi.iki.elonen.NanoHTTPD;

public class TokenServer extends NanoHTTPD {

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
        String output = "<html><body>" +
                "<h1>" + JwksGenerator.generateToken(certKeysPath) + "</h1>" +
                "</body></html>";
        return newFixedLengthResponse(output);
    }
}