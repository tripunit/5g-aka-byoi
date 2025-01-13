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
import java.util.EnumSet;
import java.util.HexFormat;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestMilenage
{
    public static final byte[] op;
    public static final byte[] k;
    public static final byte[] amf;
    public static final byte[] rand;
    public static final byte[] sqn;
    public static final byte[] f1;
    public static final byte[] f1_star;
    public static final byte[] f2;
    public static final byte[] f3;
    public static final byte[] f4;
    public static final byte[] f5;
    public static final byte[] f5_star;

    static {
        HexFormat hex = HexFormat.of().withUpperCase();

        // Generated test vector; see util/milenage/
        op      = hex.parseHex("63bfa50ee6523365ff14c1f45f88737d");
        k       = hex.parseHex("dcffed9b05ee5aa9c2ad02bf9cd18d46");
        amf     = hex.parseHex("0f7a");
        rand    = hex.parseHex("93c3d18f122ea476f44d60d53d40d1d1");
        sqn     = hex.parseHex("6ed90f356fd9");
        f1      = hex.parseHex("f69f20011fed867d");
        f1_star = hex.parseHex("354724155fe7a057");
        f2      = hex.parseHex("235bc5b57558abf4");
        f3      = hex.parseHex("872fb2d61622ac25a4ce28b547e243e9");
        f4      = hex.parseHex("1ae3fa6989e6b40e7ab9cd724620ec08");
        f5      = hex.parseHex("2abfff7a6daf");
        f5_star = hex.parseHex("56d63633ebfd");
    }

    @DataProvider(name = "auth_types")
    private String[] dataProviderAuthTypes()
    {
        return new String[] { "auth", "reauth" };
    }

    @Test
    public void testAuth()
    {
        Milenage milenage = new Milenage(op, k);

        Milenage.Result gen = milenage.milenage(EnumSet.noneOf(Milenage.Flags.class), amf, rand, sqn);

        byte[] sqnEnc = new byte[Milenage.SQN_LEN_BYTES];

        for (int i = 0; i < Milenage.SQN_LEN_BYTES; i++)
            sqnEnc[i] = (byte) (sqn[i] ^ gen.ak[i]);

        Milenage.Result chk = milenage.milenage(EnumSet.of(Milenage.Flags.CHECK), amf, rand, sqnEnc);

        Assert.assertEquals(gen.mac, f1);
        Assert.assertEquals(gen.res, f2);
        Assert.assertEquals(gen.ck,  f3);
        Assert.assertEquals(gen.ik,  f4);
        Assert.assertEquals(gen.ak,  f5);

        Assert.assertEquals(chk.mac, f1);
        Assert.assertEquals(chk.res, f2);
        Assert.assertEquals(chk.ck,  f3);
        Assert.assertEquals(chk.ik,  f4);
        Assert.assertEquals(chk.ak,  f5);
    }

    @Test
    public void testResync()
    {
        Milenage milenage = new Milenage(op, k);

        Milenage.Result gen = milenage.milenage(EnumSet.of(Milenage.Flags.RESYNC), amf, rand, sqn);

        byte[] sqnEnc = new byte[Milenage.SQN_LEN_BYTES];

        for (int i = 0; i < Milenage.SQN_LEN_BYTES; i++)
            sqnEnc[i] = (byte) (sqn[i] ^ gen.ak[i]);

        Milenage.Result chk = milenage.milenage(EnumSet.of(Milenage.Flags.RESYNC, Milenage.Flags.CHECK), amf, rand, sqnEnc);

        Assert.assertEquals(gen.mac, f1_star);
        Assert.assertEquals(gen.ak,  f5_star);

        Assert.assertEquals(chk.mac, f1_star);
        Assert.assertEquals(chk.ak,  f5_star);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWrongLenOp()
    {
        byte[] op_wrong = new byte[3];

        Milenage milenage = new Milenage(op_wrong, k);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWrongLenK()
    {
        byte[] k_wrong = new byte[3];

        Milenage milenage = new Milenage(op, k_wrong);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAuthWrongLenAmf()
    {
        byte[] amf_wrong = new byte[3];

        Milenage milenage = new Milenage(op, k);

        milenage.milenage(EnumSet.noneOf(Milenage.Flags.class), amf_wrong, rand, sqn);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAuthWrongLenRand()
    {
        byte[] rand_wrong = new byte[3];

        Milenage milenage = new Milenage(op, k);

        milenage.milenage(EnumSet.noneOf(Milenage.Flags.class), amf, rand_wrong, sqn);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAuthWrongLenSqn()
    {
        byte[] sqn_wrong = new byte[3];

        Milenage milenage = new Milenage(op, k);

        milenage.milenage(EnumSet.noneOf(Milenage.Flags.class), amf, rand, sqn_wrong);
    }
}
