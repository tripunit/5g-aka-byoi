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

import java.lang.UnsupportedOperationException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;

import org.apache.commons.lang3.tuple.ImmutablePair;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestSuci
{
    public static String TEST_USERNAME            = "verylongusername1";
    public static String TEST_REALM               = "3gpp.org";
    public static String TEST_ROUTING_IND         = "123";
    public static String TEST_PUBKEY_ID           = "5";

    public static String TEST_HN_PUBKEY           = "5A8D38864820197C3394B92613B20B91633CBD897119273BF8e4A6f4EEC0A650";
    public static String TEST_HN_PRIVKEY          = "C53C22208B61860B06C62E5406A7B330C2B577AA5558981510D128247D38BD1D";
    public static String TEST_EPH_PUBKEY          = "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222";
    public static String TEST_EPH_PRIVKEY         = "BE9EFF3E9F22A4B42A3D236E7A6C500B3F2E7E0C7449988BA800D664BF4FCD97";

    public static String TEST_SUCI_NULL           = "1-3gpp.org-123-0-0-verylongusername1";
    public static String TEST_SUCI_PROFILE_A      = "1-3gpp.org-123-1-5-977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C922228E358A1582ADB15322C10E515141D2039A12E1D7783A97F1AC";

    public static String TEST_IMSI_MSIN           = "001002086";
    public static String TEST_IMSI_HN_ID          = "274-012";

    public static String TEST_IMSI_EPH_PUBKEY     = "B2E92F836055A255837DEBF850B528997CE0201CB82ADFE4BE1F587D07D8457D";
    public static String TEST_IMSI_EPH_PRIVKEY    = "C80949F13EBE61AF4EBDBD293EA4F942696B9E815D7E8F0096BBF6ED7DE62256";

    public static String TEST_IMSI_SUCI_NULL      = "0-274-012-123-0-0-001002086";
    public static String TEST_IMSI_SUCI_PROFILE_A = "0-274-012-123-1-5-B2E92F836055A255837DEBF850B528997CE0201CB82ADFE4BE1F587D07D8457DCB02352410CDDD9E730EF3FA87";

    private static Supi buildNsiSupi(String username, String realm)
    throws FormatException, UnknownSupiTypeException
    {
        return Supi.getFactory(Supi.SUPI_TYPE_NSI).buildSupi(username, realm);
    }

    @DataProvider(name = "invalid_suci_cases")
    public String[] dataProviderInvalidSuciCases()
    {
        return new String[] {
            // Invalid SUPI Type
            "xx-3gpp.org-123-0-0-useridverylongusername1",
            // Invalid Home Network Identifier
            "1-example_9.com-123-0-0-useridverylongusername1",
            "1--123-0-0-useridverylongusername1",
            // Invalid Rounting Indicator
            "1-3gpp.org-xx-0-0-useridverylongusername1",
            "1-3gpp.org-12345-0-0-useridverylongusername1",
            "1-3gpp.org-F-0-0-useridverylongusername1",
            // Invalid Protection Scheme ID
            "1-3gpp.org-123-12-0-useridverylongusername1",
            "1-3gpp.org-123-xx-0-useridverylongusername1",
            // Invalid Home Network Public Key ID
            "1-3gpp.org-123-0-F-useridverylongusername1",
            "1-3gpp.org-123-0-420-useridverylongusername1",
            "1-3gpp.org-123-0-12345-useridverylongusername1",
            "1-3gpp.org-123-0-xx-useridverylongusername1",
            // Not an NSI-based SUCI
            "0-3gpp.org-123-0-0-310170845466094",
            // Incompatible Protection Scheme ID and Home Network Public Key ID
            "1-3gpp.org-123-0-1-useridverylongusername1",
            "1-3gpp.org-123-1-0-ecckey977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222.cip8E358A1582ADB15322C10E515141D2039A.mac12E1D7783A97F1AC"
        };
    }

    @DataProvider(name = "rfc_7542_examples")
    public String[][] dataProviderRfc7542Examples()
    {
        return new String[][] {
            {"joe@example.com"},
            {"fred@foo-9.example.com"},
            {"jack@3rd.depts.example.com"},
            {"fred.smith@example.com"},
            {"fred_smith@example.com"},
            {"fred$@example.com"},
            {"fred=?#$&*+-/^smith@example.com",},
            {"nancy@eng.example.net"},
            {"eng.example.net!nancy@example.net"},
            {"eng%nancy@example.net"},
            {"@privatecorp.example.net"}
        };
    }

    @Test
    public void testConstructor()
    throws FormatException, UnknownSupiTypeException
    {
        Supi   supi       = buildNsiSupi("user", "example.com");
        String routingInd = "0";

        Suci suci = new Suci(supi, routingInd);

        Assert.assertEquals(suci.getSupi(),       supi);
        Assert.assertEquals(suci.getRoutingInd(), routingInd);
    }

    @Test(expectedExceptions = FormatException.class)
    public void testConstructorInvalidRoutingInd()
    throws FormatException, UnknownSupiTypeException
    {
        Supi   supi       = buildNsiSupi("user", "example.com");
        String routingInd = "abc";

        Suci suci = new Suci(supi, routingInd);
    }

    @Test
    public void testSetSupi()
    throws FormatException, UnknownSupiTypeException
    {
        Supi supi1 = buildNsiSupi("user1", "example.com");
        Supi supi2 = buildNsiSupi("user2", "example.net");

        Suci suci = new Suci(supi1, "0");

        Assert.assertEquals(suci.getSupi(), supi1);

        suci.setSupi(supi2);

        Assert.assertEquals(suci.getSupi(), supi2);
    }

    @Test
    public void testSetRoutingInd()
    throws FormatException, UnknownSupiTypeException
    {
        String routingInd1 = "0";
        String routingInd2 = "12";

        Suci suci = new Suci(buildNsiSupi("user", "example.com"), routingInd1);

        Assert.assertEquals(suci.getRoutingInd(), routingInd1);

        suci.setRoutingInd(routingInd2);

        Assert.assertEquals(suci.getRoutingInd(), routingInd2);
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetRoutingIndInvalid()
    throws FormatException, UnknownSupiTypeException
    {
        Suci suci = new Suci(buildNsiSupi("user", "example.com"), "0");

        suci.setRoutingInd("abc");
    }

    @Test
    public void testEncryptNull()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        String encrypted = suci.encrypt(new SuciEncryptionNull(), "0");

        Assert.assertEquals(encrypted, TEST_SUCI_NULL);
    }

    @Test
    public void testEncryptProfileA()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        HexFormat hex  = HexFormat.of().withUpperCase();

        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            new AsymmetricCipherKeyPair(
                new X25519PublicKeyParameters  (hex.parseHex(TEST_EPH_PUBKEY)),
                new X25519PrivateKeyParameters (hex.parseHex(TEST_EPH_PRIVKEY))
            ),
            null
        );

        String encrypted = suci.encrypt(suciEnc, TEST_PUBKEY_ID);

        Assert.assertEquals(encrypted, TEST_SUCI_PROFILE_A);
    }

    @Test(expectedExceptions = FormatException.class)
    public void testEncryptInvalidSchemeId()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        String encrypted = suci.encrypt(
            new SuciEncryptionProfile()
            {
                public String getProtectionSchemeId() { return "abc"; }

                public String encrypt(byte[] schemeInput) throws SuciEncryptionException
                {
                    throw new UnsupportedOperationException();
                }

                public byte[] decrypt(String schemeOutput) throws SuciEncryptionException
                {
                    throw new UnsupportedOperationException();
                }
            },
            TEST_PUBKEY_ID
        );
    }

    @Test(expectedExceptions = FormatException.class)
    public void testEncryptInvalidPubkeyId()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        String encrypted = suci.encrypt(new SuciEncryptionNull(), "abc");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testEncryptNullIncompatiblePubkeyId()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        String encrypted = suci.encrypt(new SuciEncryptionNull(), "1");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testEncryptProfileAIncompatiblePubkeyId()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        HexFormat hex  = HexFormat.of().withUpperCase();

        Suci suci = new Suci(
            buildNsiSupi(TEST_USERNAME, TEST_REALM),
            TEST_ROUTING_IND
        );

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            new AsymmetricCipherKeyPair(
                new X25519PublicKeyParameters  (hex.parseHex(TEST_EPH_PUBKEY)),
                new X25519PrivateKeyParameters (hex.parseHex(TEST_EPH_PRIVKEY))
            ),
            null
        );

        String encrypted = suci.encrypt(suciEnc, "0");
    }

    @Test
    public void testDecryptNull()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = Suci.fromEncrypted(
            TEST_SUCI_NULL,
            new Suci.EncryptionProfileMap()
            {
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    if (schemeId.equals("0") && hnPubkeyId.equals("0"))
                        return Optional.of(new SuciEncryptionNull());

                    return Optional.empty();
                }
            }
        );

        Assert.assertEquals(suci.getSupi(),       buildNsiSupi(TEST_USERNAME, TEST_REALM));
        Assert.assertEquals(suci.getRoutingInd(), TEST_ROUTING_IND);
    }

    @Test
    public void testDecryptProfileA()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        Suci suci = Suci.fromEncrypted(
            TEST_SUCI_PROFILE_A,
            new Suci.EncryptionProfileMap()
            {
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    if (schemeId.equals("1") && hnPubkeyId.equals("5"))
                        return Optional.of(
                            new SuciEncryptionProfileA(
                                null,
                                new X25519PrivateKeyParameters(hex.parseHex(TEST_HN_PRIVKEY)),
                                null,
                                null
                            )
                        );

                    return Optional.empty();
                }
            }
        );

        Assert.assertEquals(suci.getSupi(),       buildNsiSupi(TEST_USERNAME, TEST_REALM));
        Assert.assertEquals(suci.getRoutingInd(), TEST_ROUTING_IND);
    }

    @Test(
        dataProvider       = "invalid_suci_cases",
        expectedExceptions = FormatException.class
    )
    public void testDecryptInvalidSupi(String encrypted)
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = Suci.fromEncrypted(
            encrypted,
            new Suci.EncryptionProfileMap()
            {
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    if (schemeId.equals("0") && hnPubkeyId.equals("0"))
                        return Optional.of(new SuciEncryptionNull());

                    return Optional.empty();
                }
            }
        );
    }

    @Test(expectedExceptions = FormatException.class)
    public void testDecryptUnknownProfile()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Suci suci = Suci.fromEncrypted(
            TEST_SUCI_PROFILE_A,
            new Suci.EncryptionProfileMap()
            {
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    return Optional.empty();
                }
            }
        );
    }

    @Test(dataProvider = "rfc_7542_examples")
    public void roundTripRfc7542(String nai)
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        String routingInd = "0001";
        String hnPubkeyId = "128";
        Supi   supi       = new NsiSupi(new Rfc7542Nai(nai));

        Suci suci = new Suci(supi, routingInd);

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            null,
            new SecureRandom()
        );

        String encrypted = suci.encrypt(suciEnc, hnPubkeyId);

        Suci decrypted = Suci.fromEncrypted(
            encrypted,
            new Suci.EncryptionProfileMap()
            {
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    if (schemeId.equals("1") && hnPubkeyId.equals(hnPubkeyId))
                        return Optional.of(
                            new SuciEncryptionProfileA(
                                null,
                                new X25519PrivateKeyParameters(hex.parseHex(TEST_HN_PRIVKEY)),
                                null,
                                null
                            )
                        );

                    return Optional.empty();
                }
            }
        );

        Assert.assertEquals(decrypted.getSupi(), supi);
    }

    @Test
    public void testEncryptNullImsi()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        Supi supi = Supi.getFactory(Supi.SUPI_TYPE_IMSI)
            .buildSupi(TEST_IMSI_MSIN, TEST_IMSI_HN_ID);

        Suci suci = new Suci(supi, TEST_ROUTING_IND);

        String encrypted = suci.encrypt(new SuciEncryptionNull(), "0");

        Assert.assertEquals(encrypted, TEST_IMSI_SUCI_NULL);
    }

    @Test
    public void testEncryptProfileAImsi()
    throws FormatException, SuciEncryptionException, UnknownSupiTypeException
    {
        HexFormat hex  = HexFormat.of().withUpperCase();

        Supi supi = Supi.getFactory(Supi.SUPI_TYPE_IMSI)
            .buildSupi(TEST_IMSI_MSIN, TEST_IMSI_HN_ID);

        Suci suci = new Suci(supi, TEST_ROUTING_IND);

        SuciEncryptionProfileA suciEnc = new SuciEncryptionProfileA(
            new X25519PublicKeyParameters(hex.parseHex(TEST_HN_PUBKEY)),
            null,
            new AsymmetricCipherKeyPair(
                new X25519PublicKeyParameters  (hex.parseHex(TEST_IMSI_EPH_PUBKEY)),
                new X25519PrivateKeyParameters (hex.parseHex(TEST_IMSI_EPH_PRIVKEY))
            ),
            null
        );

        String encrypted = suci.encrypt(suciEnc, TEST_PUBKEY_ID);

        Assert.assertEquals(encrypted, TEST_IMSI_SUCI_PROFILE_A);
    }

    @Test
    public void testGetRoutingInfo()
    throws FormatException
    {
        ImmutablePair<String, String> rountingInfo = Suci.getRoutingInfo("1-3gpp.org-123-0-0-useridverylongusername1");

        Assert.assertEquals(rountingInfo.getLeft(),  "3gpp.org");
        Assert.assertEquals(rountingInfo.getRight(), "123");
    }

    @Test
    public void testGetRoutingInfoDashedUrl()
    throws FormatException
    {
        ImmutablePair<String, String> rountingInfo = Suci.getRoutingInfo("1-url-with-dashes-in-it.com-123-0-0-useridverylongusername1");

        Assert.assertEquals(rountingInfo.getLeft(),  "url-with-dashes-in-it.com");
        Assert.assertEquals(rountingInfo.getRight(), "123");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testGetRoutingInfoInvalidHnId()
    throws FormatException
    {
        ImmutablePair<String, String> rountingInfo = Suci.getRoutingInfo("1-example_9.com-123-0-0-useridverylongusername1");
    }
}
