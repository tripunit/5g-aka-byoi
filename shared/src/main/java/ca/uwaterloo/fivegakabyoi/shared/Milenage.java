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

import java.lang.IllegalArgumentException;
import java.lang.System;
import java.util.EnumSet;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

// MILENAGE implementation according to 3GPP TS 33.206

public class Milenage
{
    public enum Flags
    {
        RESYNC,
        CHECK
    }

    public static class Result
    {
        public static int MAC_LEN_BYTES =  8;
        public static int RES_LEN_BYTES =  8;
        public static int CK_LEN_BYTES  = 16;
        public static int IK_LEN_BYTES  = 16;
        public static int AK_LEN_BYTES  =  6;

        public final byte[] mac;
        public final byte[] res;
        public final byte[] ck;
        public final byte[] ik;
        public final byte[] ak;

        private Result()
        {
            mac = new byte[MAC_LEN_BYTES];
            res = new byte[RES_LEN_BYTES];
            ck  = new byte[CK_LEN_BYTES];
            ik  = new byte[IK_LEN_BYTES];
            ak  = new byte[AK_LEN_BYTES];
        }
    }

    public static final int OP_LEN_BYTES   = 16;
    public static final int K_LEN_BYTES    = 16;
    public static final int AMF_LEN_BYTES  =  2;
    public static final int RAND_LEN_BYTES = 16;
    public static final int SQN_LEN_BYTES  =  6;

    private static final int AES_BLOCK_BYTES = 16;

    private final byte[] op;
    private final byte[] k;

    public Milenage(byte[] op, byte[] k)
    {
        checkLength("OP", op, OP_LEN_BYTES);
        checkLength("K",  k,  K_LEN_BYTES);

        this.op = op.clone();
        this.k  = k .clone();
    }

    public Result milenage(EnumSet<Flags> flags, byte[] amf, byte[] rand, byte[] sqn)
    {
        checkLength("AMF",  amf,  AMF_LEN_BYTES);
        checkLength("RAND", rand, RAND_LEN_BYTES);
        checkLength("SQN",  sqn,  SQN_LEN_BYTES);

        AESEngine aes = (AESEngine) AESEngine.newInstance();
        Result    res = new Result();

        aes.init(/* forEncryption = */ true, new KeyParameter(k));

        byte[] t1  = new byte[AES_BLOCK_BYTES];
        byte[] t2  = new byte[AES_BLOCK_BYTES];

        // Compute OPc

        byte[] opc = new byte[AES_BLOCK_BYTES];

        aes.processBlock(op, 0, opc, 0);
        xor(opc, opc, op);

        // Compute TEMP

        byte[] temp = new byte[AES_BLOCK_BYTES];

        xor(t1, rand, opc);
        aes.processBlock(t1, 0, temp, 0);

        // Compute f2--f5

        xor(t1, temp, opc);

        for (int i = 2; i < 6; i++) {
            int cn = 0x01 << (i - 2);

            t1[15] ^= cn;
            aes.processBlock(t1, 0, t2, 0);
            xor(t2, t2, opc);

            switch (i) {
                case 2:
                    if (!flags.contains(Flags.RESYNC)) // f5
                        System.arraycopy(t2, 0, res.ak, 0, res.ak.length);

                    // f2
                    System.arraycopy(t2, 8, res.res, 0, res.res.length);
                    break;

                case 3: // f3
                    System.arraycopy(t2, 0, res.ck, 0, res.ck.length);
                    break;

                case 4: // f4
                    System.arraycopy(t2, 0, res.ik, 0, res.ik.length);
                    break;

                case 5: // f5*
                    if (flags.contains(Flags.RESYNC))
                        System.arraycopy(t2, 0, res.ak, 0, res.ak.length);
                    break;

                default:
                    assert false;
                    break;
            }

            t1[15] ^= cn;
            rot32(t1);
        }

        byte[] sqnDec = new byte[sqn.length];

        if (flags.contains(Flags.CHECK))
            xor(sqnDec, sqn, res.ak);
        else
            System.arraycopy(sqn, 0, sqnDec, 0, sqn.length);

        // Compute f1

        byte[] in1 = new byte[AES_BLOCK_BYTES];

        int pos = 0;

        System.arraycopy(sqnDec, 0, in1, pos, sqnDec.length); pos += sqnDec.length;
        System.arraycopy(amf,    0, in1, pos, amf.length   ); pos += amf.length;
        System.arraycopy(sqnDec, 0, in1, pos, sqnDec.length); pos += sqnDec.length;
        System.arraycopy(amf,    0, in1, pos, amf.length   ); pos += amf.length;

        assert pos == in1.length;

        xor(t1, in1, opc);
        rot32(t1);
        rot32(t1);
        xor(t1, t1, temp);
        aes.processBlock(t1, 0, t2, 0);
        xor(t2, t2, opc);

        if (flags.contains(Flags.RESYNC)) // f1*
            System.arraycopy(t2, 8, res.mac, 0, res.mac.length);
        else        // f1
            System.arraycopy(t2, 0, res.mac, 0, res.mac.length);

        return res;
    }

    private void checkLength(String name, byte[] param, int expectedLen)
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

    private void rot32(byte[] x)
    {
        assert x.length == AES_BLOCK_BYTES;

        byte t0 = x[0];
        byte t1 = x[1];
        byte t2 = x[2];
        byte t3 = x[3];

        x[ 0] = x[ 4];
        x[ 1] = x[ 5];
        x[ 2] = x[ 6];
        x[ 3] = x[ 7];
        x[ 4] = x[ 8];
        x[ 5] = x[ 9];
        x[ 6] = x[10];
        x[ 7] = x[11];
        x[ 8] = x[12];
        x[ 9] = x[13];
        x[10] = x[14];
        x[11] = x[15];
        x[12] = t0;
        x[13] = t1;
        x[14] = t2;
        x[15] = t3;
    }

    private void xor(byte[] z, byte[] x, byte[] y)
    {
        assert x.length == y.length;
        assert x.length == z.length;

        for (int i = 0; i < x.length; i++)
            z[i] = (byte) (x[i] ^ y[i]);
    }
}
