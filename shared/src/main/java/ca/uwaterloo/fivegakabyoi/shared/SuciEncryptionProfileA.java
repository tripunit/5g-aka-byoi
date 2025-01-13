// Copyright (c) 2023-2024 Julian Parkin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ca.uwaterloo.fivegakabyoi.shared;

import java.lang.IllegalArgumentException;
import java.lang.IllegalStateException;
import java.lang.NumberFormatException;
import java.lang.StringBuilder;
import java.lang.System;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class SuciEncryptionProfileA implements SuciEncryptionProfile
{
    public static final int EPH_ENC_KEY_LEN_BYTES = 16;
    public static final int ICB_LEN_BYTES         = 16;
    public static final int EPH_MAC_KEY_LEN_BYTES = 32;

    public static final int SUCI_MAC_TAG_LEN_BYTES = 8;

    private final X25519PublicKeyParameters  hnPublicKey;
    private final X25519PrivateKeyParameters hnPrivateKey;
    private final AsymmetricCipherKeyPair    ueEphKeyPair;
    private final SecureRandom               randomGenerator;

    private static class EncryptedSuciFields
    {
        public final byte[] eccKey;
        public final byte[] cip;
        public final byte[] mac;

        public EncryptedSuciFields(byte[] eccKey, byte[] cip, byte[] mac)
        {
            this.eccKey = eccKey;
            this.cip    = cip;
            this.mac    = mac;
        }
    }

    public SuciEncryptionProfileA(
        X25519PublicKeyParameters  hnPublicKey,
        X25519PrivateKeyParameters hnPrivateKey,
        AsymmetricCipherKeyPair    ueEphKeyPair,
        SecureRandom               randomGenerator
    )
    {
        if (ueEphKeyPair != null &&
            (!(ueEphKeyPair.getPublic()  instanceof X25519PublicKeyParameters) ||
             !(ueEphKeyPair.getPrivate() instanceof X25519PrivateKeyParameters)))
            throw new IllegalArgumentException("Provided ueEphKeyPair must be an X25519 key pair");

        this.hnPublicKey     = hnPublicKey;
        this.hnPrivateKey    = hnPrivateKey;
        this.randomGenerator = randomGenerator;
        this.ueEphKeyPair    = ueEphKeyPair;
    }

    @Override
    public String getProtectionSchemeId() { return "1"; }

    @Override
    public String encrypt(byte[] schemeInput) throws SuciEncryptionException
    {
        if (hnPublicKey == null)
            throw new SuciEncryptionException("hnPublicKey must be provided to encrypt a SUPI");

        X25519PublicKeyParameters  ephPublicKey;
        X25519PrivateKeyParameters ephPrivateKey;

        if (ueEphKeyPair != null) {
            // Use existing ephemeral key pair if provided in the constructor.
            // Mostly for testing purposes.
            ephPublicKey  = (X25519PublicKeyParameters)  ueEphKeyPair.getPublic();
            ephPrivateKey = (X25519PrivateKeyParameters) ueEphKeyPair.getPrivate();
        } else {
            if (randomGenerator == null)
                throw new SuciEncryptionException("randomGenerator must be provided if not providing ueEphKeyPair");

            // Generate an ephemeral key pair
            X25519KeyPairGenerator generator = new X25519KeyPairGenerator();

            generator.init(new X25519KeyGenerationParameters(randomGenerator));

            AsymmetricCipherKeyPair ephKeyPair = generator.generateKeyPair();

            ephPublicKey  = (X25519PublicKeyParameters)  ephKeyPair.getPublic();
            ephPrivateKey = (X25519PrivateKeyParameters) ephKeyPair.getPrivate();
        }

        // Generate the ephemeral encryption key using ECDH

        X25519Agreement agreement = new X25519Agreement();

        byte[] sharedSecret = new byte[agreement.getAgreementSize()];
        byte[] sharedInfo   = new byte[X25519PublicKeyParameters.KEY_SIZE];

        agreement.init(ephPrivateKey);
        agreement.calculateAgreement(hnPublicKey, sharedSecret, 0);

        // Ephemeral public key is used as the sharedInfo
        ephPublicKey.encode(sharedInfo, 0);

        byte[] keyData = ansiX9Dot63Kdf(
            sharedSecret,
            sharedInfo,
            EPH_ENC_KEY_LEN_BYTES + ICB_LEN_BYTES + EPH_MAC_KEY_LEN_BYTES
         );

        byte[] ciphertext = encryptWithAesCtr(schemeInput, keyData);
        byte[] macTag     = macWithSha256Hmac(ciphertext,  keyData);

        StringBuilder schemeOutput = new StringBuilder();
        HexFormat     hex          = HexFormat.of().withUpperCase();

        schemeOutput = hex.formatHex(schemeOutput, sharedInfo);
        schemeOutput = hex.formatHex(schemeOutput, ciphertext);
        // Truncated MAC tag
        schemeOutput = hex.formatHex(schemeOutput, macTag, 0, SUCI_MAC_TAG_LEN_BYTES);

        return schemeOutput.toString();
    }

    @Override
    public byte[] decrypt(String schemeOutput) throws SuciEncryptionException
    {
        if (hnPrivateKey == null)
            throw new SuciEncryptionException("hnPrivateKey must be provided to decrypt a SUPI");

        EncryptedSuciFields fields = parseEncryptedSupi(schemeOutput);

        X25519PublicKeyParameters ephPublicKey;

        try {
            ephPublicKey = new X25519PublicKeyParameters(fields.eccKey);
        } catch (IllegalArgumentException e) {
            throw new SuciEncryptionException(
                String.format(
                    "Encrypted SUPI did not contain a valid X25519 public key (incorrect length): %s",
                    schemeOutput
                ),
                e
            );
        }

        // Generate the ephemeral encryption key using ECDH

        X25519Agreement agreement = new X25519Agreement();

        byte[] sharedSecret = new byte[agreement.getAgreementSize()];
        byte[] sharedInfo   = new byte[X25519PublicKeyParameters.KEY_SIZE];

        agreement.init(hnPrivateKey);

        try {
            agreement.calculateAgreement(ephPublicKey, sharedSecret, 0);
        } catch (IllegalStateException e) {
            // RFC 7748 does not required checking that the output of the ECDH
            // operation is not the identity element (which occurs when a
            // point of small order is used instead of a valid public key),
            // as protocols using ECDH should not rely solely on the DH
            // primitive for authentication. In this application (ECIES),
            // the result of using a point of small order instead of a valid
            // public key is that the message can be constructed to decrypt
            // under any private key, which is unexpected but does not usually
            // violate any security properties. However, Bouncy Castle does
            // perform the optional check, so the resulting exception must be
            // caught and handled when dealing with untrusted input.

            throw new SuciEncryptionException(
                String.format(
                    "Encrypted SUPI did not contain a valid X25519 public key (ECDH produced the identity): %s",
                    schemeOutput
                ),
                e
            );
        }

        // Ephemeral public key is used as the sharedInfo
        ephPublicKey.encode(sharedInfo, 0);

        byte[] keyData = ansiX9Dot63Kdf(
            sharedSecret,
            sharedInfo,
             EPH_ENC_KEY_LEN_BYTES + ICB_LEN_BYTES + EPH_MAC_KEY_LEN_BYTES
         );

        // Check MAC: expected length

        if (fields.mac.length != SUCI_MAC_TAG_LEN_BYTES)
            throw new SuciEncryptionException(
                String.format(
                    "Unable to verify MAC on encrypted SUPI (incorrect tag length): %s",
                    schemeOutput
                )
            );

        // Check MAC: expected tag

        byte[] expectedMacTag = macWithSha256Hmac(fields.cip, keyData);

        boolean macEqual = Arrays.constantTimeAreEqual(
            SUCI_MAC_TAG_LEN_BYTES,
            expectedMacTag, 0,
            fields.mac, 0
        );

        if (!macEqual)
            throw new SuciEncryptionException(
                String.format(
                    "Unable to verify MAC on encrypted SUPI (incorrect tag value): %s",
                    schemeOutput
                )
            );

        // Use encrypt function since they are identical for CTR
        return encryptWithAesCtr(fields.cip, keyData);
    }

    public byte[] ansiX9Dot63Kdf(
        byte[] sharedSecret,
        byte[] sharedInfo,
        int    keyDataLen)
    {
        if (keyDataLen < 0)
            throw new IllegalArgumentException("keyDataLen must be positive");

        SHA256Digest digest       = new SHA256Digest();
        int          hashLen      = digest.getDigestSize();
        byte[]       keyData      = new byte[keyDataLen];
        int          counter      = 1;
        byte[]       counterBytes = new byte[4];

        for (int i = 0; i < keyDataLen; i += hashLen) {
            // Big endian
            counterBytes[0] = (byte) (counter >> 24);
            counterBytes[1] = (byte) (counter >> 16);
            counterBytes[2] = (byte) (counter >>  8);
            counterBytes[3] = (byte) (counter >>  0);

            digest.update(sharedSecret, 0, sharedSecret.length);
            digest.update(counterBytes, 0, counterBytes.length);
            digest.update(sharedInfo,   0, sharedInfo.length  );

            if (i + hashLen <= keyDataLen) {
                digest.doFinal(keyData, i);     // Also calls reset()
            } else {
                // Special case for final hash when keyDataLen is not a
                // multiple of hashLen: there is not enough space to copy the
                // full digest into keyData, so a temporary array is needed.

                byte[] hash = new byte[hashLen];

                digest.doFinal(hash, 0);

                System.arraycopy(hash, 0, keyData, i, keyDataLen - i);
            }

            counter++;
        }

        return keyData;
    }

    private byte[] encryptWithAesCtr(byte[] plaintext, byte[] keyData)
    {
        byte[]         ciphertext = new byte[plaintext.length];
        // CTR is called SIC in BouncyCastle
        SICBlockCipher cipher     = new SICBlockCipher(AESEngine.newInstance());

        cipher.init(
            true,
            new ParametersWithIV(
                new KeyParameter(keyData, 0, EPH_ENC_KEY_LEN_BYTES),
                keyData,
                EPH_ENC_KEY_LEN_BYTES,
                ICB_LEN_BYTES
            )
        );

        cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

        return ciphertext;
    }

    private byte[] macWithSha256Hmac(byte[] ciphertext, byte[] keyData)
    {
        byte[] macTag = new byte[EPH_MAC_KEY_LEN_BYTES];
        HMac   mac    = new HMac(new SHA256Digest());

        assert EPH_MAC_KEY_LEN_BYTES == mac.getMacSize();

        mac.init(
            new KeyParameter(
                keyData,
                EPH_ENC_KEY_LEN_BYTES + ICB_LEN_BYTES,
                EPH_MAC_KEY_LEN_BYTES
            )
        );

        mac.update(ciphertext, 0, ciphertext.length);
        mac.doFinal(macTag, 0);

        return macTag;
    }

    private EncryptedSuciFields parseEncryptedSupi(String schemeOutput)
    throws SuciEncryptionException
    {
        int cipOffset = 2 * X25519PublicKeyParameters.KEY_SIZE;
        int macOffset = schemeOutput.length() - 2 * SUCI_MAC_TAG_LEN_BYTES;

        if (macOffset < 0 || (macOffset & 1) == 1)
            throw new SuciEncryptionException(String.format("Invalid length: %s", schemeOutput));

        byte[] eccKey, cip, mac;

        try {
            HexFormat hex = HexFormat.of().withUpperCase();

            eccKey = hex.parseHex(schemeOutput.substring(0,         cipOffset            ));
            cip    = hex.parseHex(schemeOutput.substring(cipOffset, macOffset            ));
            mac    = hex.parseHex(schemeOutput.substring(macOffset, schemeOutput.length()));
        } catch(IllegalArgumentException e) {
            throw new SuciEncryptionException(String.format("Invalid hex: %s", schemeOutput), e);
        }

        return new EncryptedSuciFields(eccKey, cip, mac);
    }
}
