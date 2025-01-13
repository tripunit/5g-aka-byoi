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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestRfc7542Nai
{
    @DataProvider(name = "rfc_examples_valid")
    public String[][] dataProviderRfcExamplesValid()
    {
        return new String[][] {
            {"bob",                               "bob",                   ""},
            {"joe@example.com",                   "joe",                   "example.com"},
            {"fred@foo-9.example.com",            "fred",                  "foo-9.example.com"},
            {"jack@3rd.depts.example.com",        "jack",                  "3rd.depts.example.com"},
            {"fred.smith@example.com",            "fred.smith",            "example.com"},
            {"fred_smith@example.com",            "fred_smith",            "example.com"},
            {"fred$@example.com",                 "fred$",                 "example.com"},
            {"fred=?#$&*+-/^smith@example.com",   "fred=?#$&*+-/^smith",   "example.com"},
            {"nancy@eng.example.net",             "nancy",                 "eng.example.net"},
            {"eng.example.net!nancy@example.net", "eng.example.net!nancy", "example.net"},
            {"eng%nancy@example.net",             "eng%nancy",             "example.net"},
            {"@privatecorp.example.net",          "",                      "privatecorp.example.net"},
            // Included in the RFC but escaped characters are not defined.
            // Probably a holdover from RFC4282.
            // {"\\(user\\)@example.net",            "\\(user\\)",            "example.net"},
        };
    }

    @DataProvider(name = "rfc_examples_invalid")
    public String[] dataProviderExamplesInvalid()
    {
        return new String[] {
            "fred@example",
            "fred@example_9.com",
            "fred@example.net@example.net",
            "fred.@example.net",
            "eng:nancy@example.net",
            "eng;nancy@example.net",
            "(user)@example.net",
            "<nancy>@example.net",
        };
    }

    @Test(dataProvider = "rfc_examples_valid")
    public void testConstructor(
        String naiString,
        String username,
        String realm
    ) throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai(naiString);

        Assert.assertEquals(nai.getUsername(), username);
        Assert.assertEquals(nai.getRealm(),    realm);
        Assert.assertEquals(nai.toNaiString(), naiString);
    }

    @Test(dataProvider = "rfc_examples_invalid", expectedExceptions = FormatException.class)
    public void testConstructorInvalid(String naiString) throws FormatException
    {
        new Rfc7542Nai(naiString);
    }

    @Test
    public void testConstructorNonAscii() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("üsername@éxample.com");

        Assert.assertEquals(nai.getUsername(), "üsername");
        Assert.assertEquals(nai.getRealm(),    "éxample.com");
    }

    @Test
    public void testSetUserName() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("bob@example.com");

        Assert.assertEquals(nai.getUsername(), "bob");
        Assert.assertEquals(nai.getRealm(),    "example.com");

        nai.setUsername("fred");

        Assert.assertEquals(nai.getUsername(), "fred");
        Assert.assertEquals(nai.getRealm(),    "example.com");
        Assert.assertEquals(nai.toNaiString(), "fred@example.com");

        nai.setUsername("");

        Assert.assertEquals(nai.getUsername(), "");
        Assert.assertEquals(nai.getRealm(),    "example.com");
        Assert.assertEquals(nai.toNaiString(), "@example.com");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetUserNameInvalid() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("bob@example.com");

        nai.setUsername("eng:nancy");
    }

    @Test
    public void testSetRealm() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("bob@example.com");

        Assert.assertEquals(nai.getUsername(), "bob");
        Assert.assertEquals(nai.getRealm(),    "example.com");

        nai.setRealm("example.net");

        Assert.assertEquals(nai.getUsername(), "bob");
        Assert.assertEquals(nai.getRealm(),    "example.net");
        Assert.assertEquals(nai.toNaiString(), "bob@example.net");

        nai.setRealm("");

        Assert.assertEquals(nai.getUsername(), "bob");
        Assert.assertEquals(nai.getRealm(),    "");
        Assert.assertEquals(nai.toNaiString(), "bob");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetRealmInvalid() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("bob@example.com");

        nai.setRealm("example");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testToNaiStringEmpty() throws FormatException
    {
        Rfc7542Nai nai = new Rfc7542Nai("bob@example.com");

        nai.setUsername ("");
        nai.setRealm    ("");

        nai.toNaiString();
    }
}
