package com.example.pantoken;

import com.example.pantoken.api.HttpServerApp;
import com.example.pantoken.crypto.AesGcmCipherService;
import com.example.pantoken.crypto.KeyProvider;
import com.example.pantoken.crypto.TokenGenerator;
import com.example.pantoken.service.TokenVaultService;

public final class Main {

    private static final int DEFAULT_PORT = 8080;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;

        KeyProvider keyProvider = new KeyProvider();
        AesGcmCipherService cipherService = new AesGcmCipherService();
        TokenGenerator tokenGenerator = new TokenGenerator();
        TokenVaultService vaultService = new TokenVaultService(keyProvider, cipherService, tokenGenerator);

        new HttpServerApp(vaultService, port).start();
    }
}
