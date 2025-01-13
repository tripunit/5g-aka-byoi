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

import java.util.HexFormat;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestSuciEncryptionNull
{
    public static String TEST_SCHEME_OUTPUT = "verylongusername1";
    public static byte[] TEST_SCHEME_INPUT;

    static {
        HexFormat hex = HexFormat.of().withUpperCase();

        TEST_SCHEME_INPUT = hex.parseHex("766572796C6F6E67757365726E616D6531");
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
        SuciEncryptionNull suciEnc = new SuciEncryptionNull();

        Assert.assertEquals(suciEnc.getProtectionSchemeId(), "0");
    }

    @Test
    public void testEncryptTsExample() throws SuciEncryptionException
    {
        SuciEncryptionNull suciEnc = new SuciEncryptionNull();

        Assert.assertEquals(suciEnc.encrypt(TEST_SCHEME_INPUT), TEST_SCHEME_OUTPUT);
    }

    @Test
    public void testDecryptTsExample() throws SuciEncryptionException
    {
        SuciEncryptionNull suciEnc = new SuciEncryptionNull();

        Assert.assertEquals(suciEnc.decrypt(TEST_SCHEME_OUTPUT), TEST_SCHEME_INPUT);
    }

    @Test(dataProvider = "example_usernames")
    public void testRoundTrip(String schemeInput) throws SuciEncryptionException
    {
        SuciEncryptionNull suciEnc = new SuciEncryptionNull();

        byte[] inputBytes = Utf8.str2bytes(schemeInput);

        Assert.assertEquals(
            suciEnc.decrypt(suciEnc.encrypt(inputBytes)),
            inputBytes
        );
    }
}
