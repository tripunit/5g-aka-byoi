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

import java.util.HexFormat;

import org.testng.Assert;
import org.testng.annotations.Test;

class TestFiveGAka
{
    public static final String SNN = "5G:mnc015.mcc234.3gppnetwork.org";
    public static final String SUPI = "user@example.com";

    public static final byte[] RAND;
    public static final byte[] SQN;
    public static final byte[] RES;
    public static final byte[] CK;
    public static final byte[] IK;
    public static final byte[] AK;
    public static final byte[] ABBA;

    public static final byte[] SQN_ENC;
    public static final byte[] K_AUSF;
    public static final byte[] RES_STAR;
    public static final byte[] H_RES_STAR;
    public static final byte[] K_SEAF;
    public static final byte[] K_AMF;

    static {
        HexFormat hex = HexFormat.of().withUpperCase();

        // Generated test vector; see util/test_vectors_5g_aka.py

        RAND       = hex.parseHex("68F6832A9DF9DDCBA02A1D330EE75E5D");
        SQN        = hex.parseHex("406560223C5E");
        RES        = hex.parseHex("991C327981912A67");
        CK         = hex.parseHex("43AE4F4B9893AB6C09BF0C85386CF9CD");
        IK         = hex.parseHex("DC25EA870727432F44DCA214F7DC42BD");
        AK         = hex.parseHex("12BEEE701037");
        ABBA       = hex.parseHex("0000");

        SQN_ENC    = hex.parseHex("52DB8E522C69");
        K_AUSF     = hex.parseHex("7D7D074119FE48185CEA5EA388CC625CF61C1BA044D1BBBD2A74631331F54A71");
        RES_STAR   = hex.parseHex("A24BD7994F11C0BE543463B7F8CF86C6");
        H_RES_STAR = hex.parseHex("BDBAC30C9450525030A7D324EB26D456");
        K_SEAF     = hex.parseHex("77D0D3B02EAB24261E2B3DD77F0D132D8B711E2C5074330D36080A043954C5E0");
        K_AMF      = hex.parseHex("4423BE8B15072DF55F6F444DA67F5EE261A8CEDA66083021B8842A0B1F60BA17");
    }

    @Test
    public void testEncryptSqn()
    {
        byte[] sqnEnc = FiveGAka.encryptSqn(AK, SQN);

        Assert.assertEquals(sqnEnc, SQN_ENC);
    }

    @Test
    public void testDeriveKAusf()
    {
        byte[] kAusf = FiveGAka.deriveKAusf(CK, IK, SNN, SQN_ENC);

        Assert.assertEquals(kAusf, K_AUSF);
    }

    @Test
    public void testDeriveResStar()
    {
        byte[] resStar = FiveGAka.deriveResStar(CK, IK, SNN, RAND, RES);

        Assert.assertEquals(resStar, RES_STAR);
    }

    @Test
    public void testDeriveHResStar()
    {
        byte[] hResStar = FiveGAka.deriveHResStar(RAND, RES_STAR);

        Assert.assertEquals(hResStar, H_RES_STAR);
    }

    @Test
    public void testDeriveKSeaf()
    {
        byte[] kSeaf = FiveGAka.deriveKSeaf(K_AUSF, SNN);

        Assert.assertEquals(kSeaf, K_SEAF);
    }

    @Test
    public void testDeriveKAmf()
    {
        byte[] kAmf = FiveGAka.deriveKAmf(K_SEAF, SUPI, ABBA);

        Assert.assertEquals(kAmf, K_AMF);
    }
}
