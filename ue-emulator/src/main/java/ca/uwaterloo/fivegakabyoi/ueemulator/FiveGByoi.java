// Copyright (c) 2024-2025 Julian Parkin
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

package ca.uwaterloo.fivegakabyoi.ueemulator;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.KDFParameters;

import ca.uwaterloo.fivegakabyoi.shared.Utf8;

public class FiveGByoi
{
    private static final byte[] EK_PARAM = Utf8.str2bytes("5GBYOIEK");

    public static void deriveEk(byte[] ck, byte[] ik, byte[] ekHn, byte[] ekUe)
    {
        byte[] ckConcatIk = new byte[ck.length + ik.length];

        System.arraycopy(ck, 0, ckConcatIk, 0,         ck.length);
        System.arraycopy(ik, 0, ckConcatIk, ck.length, ik.length);

        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(new SHA256Digest());

        kdf.init(new KDFParameters(ckConcatIk, EK_PARAM));

        kdf.generateBytes(ekHn, 0, ekHn.length);
        kdf.generateBytes(ekUe, 0, ekUe.length);
    }

    public static byte[] encryptUrl(byte[] ek, String authUrl)
    {
        GCMBlockCipher enc = new GCMBlockCipher(AESEngine.newInstance());

        byte[] nonce = new byte[12]; // zero

        enc.init(
            /* forEncryption = */ true,
            new AEADParameters(
                new KeyParameter(ek, 0, ek.length),
                128,
                nonce
            )
        );

        byte[] urlPlain = Utf8.str2bytes(authUrl);
        byte[] urlEnc   = new byte[enc.getOutputSize(urlPlain.length)];

        int pos = 0;

        pos += enc.processBytes(urlPlain, 0, urlPlain.length, urlEnc, pos);

        try {
            pos += enc.doFinal(urlEnc, pos);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("MAC failure on encryption (should not be possible)");
        }

        assert pos == urlEnc.length;

        return urlEnc;
    }

    public static String decryptUrl(byte[] ek, byte[] authUrl)
    throws FiveGByoiException
    {
        GCMBlockCipher enc = new GCMBlockCipher(AESEngine.newInstance());

        byte[] nonce = new byte[12]; // zero

        enc.init(
            /* forEncryption = */ false,
            new AEADParameters(
                new KeyParameter(ek, 0, ek.length),
                128,
                nonce
            )
        );

        byte[] urlPlain = new byte[enc.getOutputSize(authUrl.length)];

        int pos = 0;

        pos += enc.processBytes(authUrl, 0, authUrl.length, urlPlain, pos);

        try {
            pos += enc.doFinal(urlPlain, pos);
        } catch (InvalidCipherTextException e) {
            throw new FiveGByoiException("MAC failure while decrypting URL");
        }

        assert pos == urlPlain.length;

        return Utf8.bytes2str(urlPlain);
    }

    public static byte[] computeMac(byte[] k, String msg)
    {
        HMac   hmac = new HMac(new SHA256Digest());
        byte[] mac  = new byte[hmac.getMacSize()];

        hmac.init(
            new KeyParameter(
                k,
                0,
                k.length
            )
        );

        byte[] msgBytes = msg.getBytes();

        hmac.update(msgBytes, 0, msgBytes.length);
        hmac.doFinal(mac, 0);

        return mac;
    }
}
