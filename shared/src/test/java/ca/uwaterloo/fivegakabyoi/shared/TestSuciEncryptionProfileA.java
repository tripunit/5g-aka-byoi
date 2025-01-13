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

import java.lang.System;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.IntStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestSuciEncryptionProfileA
{
    public static String TEST_HN_PUBKEY     = "5A8D38864820197C3394B92613B20B91633CBD897119273BF8e4A6f4EEC0A650";
    public static String TEST_HN_PRIVKEY    = "C53C22208B61860B06C62E5406A7B330C2B577AA5558981510D128247D38BD1D";
    public static String TEST_EPH_PUBKEY    = "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222";
    public static String TEST_EPH_PRIVKEY   = "BE9EFF3E9F22A4B42A3D236E7A6C500B3F2E7E0C7449988BA800D664BF4FCD97";
    public static byte[] TEST_SCHEME_INPUT;
    public static String TEST_SCHEME_OUTPUT = "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC";

    static {
        HexFormat hex = HexFormat.of().withUpperCase();

        TEST_SCHEME_INPUT = hex.parseHex("766572796C6F6E67757365726E616D6531"); // = verylongusername1
    }

    @DataProvider(name = "invalid_suci_cases")
    public String[] dataProviderInvalidSuciCases()
    {
        return new String[] {
            // Too short
            "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D203",
            // Not hex
            "977D8B2Fnot_hexAA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC",
            // Odd number of hex digits
            "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D2039A12E1D7783A97F1A",
            // Invalid key (small order)
            "00000000000000000000000000000000000000000000000000000000000000008E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC",
            // Invalid key (small order)
            "01000000000000000000000000000000000000000000000000000000000000008E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC",
            // Invalid key (small order)
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b8008E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC",
            // Invalid MAC                                                                                     v (changed 1 -> 0)
            "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D2039A02E1D7783A97F1AC"
        };
    }

    @DataProvider(name = "kdf_ts_examples")
    public String[][] dataProviderKdfTsExamples()
    {
        return new String[][] {
            {
                // C.4.3.1
                "028DDF890EC83CDF163947CE45F6EC1A0E3070EA5FE57E2B1F05139F3E82422A",
                "B2E92F836055A255837DEBF850B528997CE0201CB82ADFE4BE1F587D07D8457D",
                "2BA342CABD2B3B1E5E4E890DA11B65F6",
                "E2622CB0CDD08204E721C8EA9B95A7C6",
                "D9846966FB7CF5FCF11266C5957DEA60B83FFF2B7C940690A4BFE57B1EB52BD2",
            },
            {
                // C.4.3.2
                "511C1DF473BB88317F923501F8BA944FD3B667D25699DCB552DBCEF60BBDC56D",
                "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222",
                "FE77B87D87F40428EDD71BCA69D79059",
                "CAFA5287DE2B20E3DF1BD3A858DA00AC",     // Recreated since ICB wasn't in test vector
                "D87B69F4FE8CD6B211264EA5E69F682F151A82252684CDB15A047E6EF0595028",
            },
            {
                // C.4.4.1 (Profile B, but using same KDF)
                "6C7E6518980025B982FBB2FF746E3C2E85A196D252099A7AD23EA7B4C0959CAE",
                "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
                "8A65C3AED80295C12BD55087E965702A",
                "EF285B4061C3BAEE858AB6EC68487DAE",
                "A5EBAC0BC48D9CF7AE5CE39CD840AC6C761AEC04078FAB954D634F923E901C64",
            },
            {
                // C.4.4.2 (Profile B, but using same KDF)
                "BC3529ED79541CF8C007CE9806330F4A5FF15064D7CF4B16943EF8F007597872",
                "03759BB22C563D9F4A6B3C1419E543FC2F39D6823F02A9D71162B39399218B244B",
                "84F9A78995D39E6968047547ECC12C4F",
                "A1A6B7F89D422A733675996EBE781EB7",     // Recreated since ICB wasn't in test vector
                "39D5517E965F8E1252B61345ED45226C5F1A8C69F03D6C91437591F0B8E48FA0",
            },
        };
    }

    @DataProvider(name = "example_usernames")
    public String[] dataProviderExampleUsernames()
    {
        return new String[] {
            "bob",
            "fred.smith",
            "fred_smith",
            "fred$",
            "fred=?#$&*+-/^smith",
        };
    }

    @Test
    public void testGetProtectionSchemeId()
    {
        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(null, null, null,  null);

        Assert.assertEquals(suciEnc.getProtectionSchemeId(), "1");
    }

    @Test
    public void testEncryptTsExample() throws SuciEncryptionException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            new AsymmetricCipherKeyPair(
                new X25519PublicKeyParameters  (hex.parseHex(TEST_EPH_PUBKEY)),
                new X25519PrivateKeyParameters (hex.parseHex(TEST_EPH_PRIVKEY))
            ),
            null
        );

        Assert.assertEquals(suciEnc.encrypt(TEST_SCHEME_INPUT), TEST_SCHEME_OUTPUT);
    }

    @Test(expectedExceptions = SuciEncryptionException.class)
    public void testEncryptNoHnPublicKey() throws SuciEncryptionException
    {
        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            null,
            null,
            null,
            new SecureRandom()
        );

        suciEnc.encrypt(TEST_SCHEME_INPUT);
    }

    @Test(expectedExceptions = SuciEncryptionException.class)
    public void testEncryptNoRandomGenerator() throws SuciEncryptionException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            null,
            null
        );

        suciEnc.encrypt(TEST_SCHEME_INPUT);
    }

    @Test
    public void testDecryptTsExample() throws SuciEncryptionException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            null,
            new X25519PrivateKeyParameters(hex.parseHex(TEST_HN_PRIVKEY)),
            null,
            null
        );

        Assert.assertEquals(suciEnc.decrypt(TEST_SCHEME_OUTPUT), TEST_SCHEME_INPUT);
    }

    @Test(expectedExceptions = SuciEncryptionException.class)
    public void testDecryptNoHnPrivateKey() throws SuciEncryptionException
    {
        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            null,
            null,
            null,
            null
        );

        suciEnc.decrypt(TEST_SCHEME_OUTPUT);
    }

    @Test(
        dataProvider       = "invalid_suci_cases",
        expectedExceptions = SuciEncryptionException.class
    )
    public void testDecryptInvalidSuci(String schemeOutput)
    throws SuciEncryptionException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            null,
            new X25519PrivateKeyParameters(hex.parseHex(TEST_HN_PRIVKEY)),
            null,
            null
        );
 
       suciEnc.decrypt(schemeOutput);
    }

    @Test(dataProvider = "example_usernames")
    public void testRoundTrip(String schemeInput) throws SuciEncryptionException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters  (hex.parseHex(TEST_HN_PUBKEY)),
            new X25519PrivateKeyParameters (hex.parseHex(TEST_HN_PRIVKEY)),
            null,
            new SecureRandom()
        );

        byte[] inputBytes = Utf8.str2bytes(schemeInput);

        Assert.assertEquals(
            suciEnc.decrypt(suciEnc.encrypt(inputBytes)),
            inputBytes
        );
    }

    @Test(dataProvider = "kdf_ts_examples")
    public void testKdfTsExamples(
        String ephSharedKey,
        String ephPublicKey,
        String ephEncKey,
        String icb,
        String ephMacKey
    )
    {
        SecureRandom random = new SecureRandom();

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(null, null, null, random);

        HexFormat hex = HexFormat.of().withUpperCase();

        byte[] sharedSecret = hex.parseHex(ephSharedKey);
        byte[] sharedInfo   = hex.parseHex(ephPublicKey);

        int[] outputLengths = new int[] {
                SuciEncryptionProfileA.EPH_ENC_KEY_LEN_BYTES,
                SuciEncryptionProfileA.ICB_LEN_BYTES,
                SuciEncryptionProfileA.EPH_MAC_KEY_LEN_BYTES,
        };

        byte[] keyData = suciEnc.ansiX9Dot63Kdf(
            sharedSecret,
            sharedInfo,
            IntStream.of(outputLengths).sum()
        );

        String[] output = new String[outputLengths.length];

        for (int i = 0, off = 0; i < outputLengths.length; i++) {
            output[i] = hex.formatHex(keyData, off, off + outputLengths[i]);

            off += outputLengths[i];
        }

        Assert.assertEquals(output[0], ephEncKey);
        Assert.assertEquals(output[1], icb);
        Assert.assertEquals(output[2], ephMacKey);
    }
}
