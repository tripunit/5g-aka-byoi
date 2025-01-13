// Copyright (c) 2024 Julian Parkin
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

import java.lang.System;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class FiveGAka
{
    public static final int K_AUSF_LEN_BYTES     = 32;
    public static final int K_SEAF_LEN_BYTES     = 32;
    public static final int K_AMF_LEN_BYTES      = 32;
    public static final int RES_STAR_LEN_BYTES   = 16;
    public static final int H_RES_STAR_LEN_BYTES = 16;
    public static final int ABBA_LEN_BYTES       =  2;

    private static class Ts33Dot220Kdf
    {
        public static final int ENCODED_LEN_BYTES = 2;

        private final HMac   mac;
        private final byte[] lenBuf;

        public Ts33Dot220Kdf(byte[] key, byte fc)
        {
            mac    = new HMac(new SHA256Digest());
            lenBuf = new byte[ENCODED_LEN_BYTES];

            mac.init(new KeyParameter(key, 0, key.length));
            mac.update(fc);
        }

        public void update(byte[] data)
        {
            mac.update(data, 0, data.length);

            // Big endian
            lenBuf[0] = (byte) (data.length >> 8);
            lenBuf[1] = (byte) (data.length >> 0);

            assert data.length >> 16 == 0;

            mac.update(lenBuf, 0, lenBuf.length);
        }

        public byte[] finalize(int keyLen)
        {
            byte[] key = new byte[keyLen];

            if (keyLen == mac.getMacSize()) {
                mac.doFinal(key, 0);
            } else {
                assert keyLen < mac.getMacSize();

                byte [] macTag = new byte[mac.getMacSize()];

                mac.doFinal(macTag, 0);

                System.arraycopy(macTag, 0, key, 0, keyLen);
            }

            return key;
        }
    }

    public static byte[] encryptSqn(byte[] ak, byte[] sqn)
    {
        checkLength("ak",  ak,  Milenage.Result.AK_LEN_BYTES);
        checkLength("sqn", sqn, Milenage.SQN_LEN_BYTES);

        byte[] sqnEnc = new byte[Milenage.SQN_LEN_BYTES];

        for (int i = 0; i < Milenage.SQN_LEN_BYTES; i++)
            sqnEnc[i] = (byte) (sqn[i] ^ ak[i]);

        return sqnEnc;
    }

    public static byte[] deriveKAusf(byte[] ck, byte[] ik, String snn, byte[] sqnEnc)
    {
        checkLength("ck",     ck,     Milenage.Result.CK_LEN_BYTES);
        checkLength("ik",     ik,     Milenage.Result.IK_LEN_BYTES);
        checkLength("sqnEnc", sqnEnc, Milenage.SQN_LEN_BYTES);

        Ts33Dot220Kdf kdf = new Ts33Dot220Kdf(concatCkIk(ck, ik), (byte) 0x6A);

        kdf.update(Utf8.str2bytes(snn));
        kdf.update(sqnEnc);

        return kdf.finalize(K_AUSF_LEN_BYTES);
    }

    public static byte[] deriveResStar(byte[] ck, byte[] ik, String snn, byte[] rand, byte[] res)
    {
        checkLength("ck",   ck,   Milenage.Result.CK_LEN_BYTES);
        checkLength("ik",   ik,   Milenage.Result.IK_LEN_BYTES);
        checkLength("rand", rand, Milenage.RAND_LEN_BYTES);
        checkLength("res",  res,  Milenage.Result.RES_LEN_BYTES);

        Ts33Dot220Kdf kdf = new Ts33Dot220Kdf(concatCkIk(ck, ik), (byte) 0x6B);

        kdf.update(Utf8.str2bytes(snn));
        kdf.update(rand);
        kdf.update(res);

        return kdf.finalize(RES_STAR_LEN_BYTES);
    }

    public static byte[] deriveHResStar(byte[] rand, byte[] resStar)
    {
        checkLength("rand",    rand,     Milenage.RAND_LEN_BYTES);
        checkLength("resStar", resStar,  RES_STAR_LEN_BYTES);

        SHA256Digest digest = new SHA256Digest();

        digest.update(rand,    0, rand.length);
        digest.update(resStar, 0, resStar.length);

        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        byte[] hResStar = new byte[H_RES_STAR_LEN_BYTES];

        assert hResStar.length <= hash.length;

        System.arraycopy(hash, 0, hResStar, 0, hResStar.length);

        return hResStar;
    }

    public static byte[] deriveKSeaf(byte[] kAusf, String snn)
    {
        Ts33Dot220Kdf kdf = new Ts33Dot220Kdf(kAusf, (byte) 0x6C);

        kdf.update(Utf8.str2bytes(snn));

        return kdf.finalize(K_SEAF_LEN_BYTES);
    }

    public static byte[] deriveKAmf(byte[] kSeaf, String supi, byte[] abba)
    {
        checkLength("abba", abba, ABBA_LEN_BYTES);

        Ts33Dot220Kdf kdf = new Ts33Dot220Kdf(kSeaf, (byte) 0x6D);

        kdf.update(Utf8.str2bytes(supi));
        kdf.update(abba);

        return kdf.finalize(K_AMF_LEN_BYTES);
    }

    private static void checkLength(String name, byte[] param, int expectedLen)
    {
        if (param.length != expectedLen)
            throw new IllegalArgumentException(
                    String.format(
                        "Invalid length for %s: %d (expected %d)",
                        name,
                        param.length,
                        expectedLen
                    )
                );
    }

    private static byte[] concatCkIk(byte[] ck, byte[] ik)
    {
        byte[] key = new byte[ck.length + ik.length];

        System.arraycopy(ck, 0, key, 0,         ck.length);
        System.arraycopy(ik, 0, key, ck.length, ik.length);

        return key;
    }
}
