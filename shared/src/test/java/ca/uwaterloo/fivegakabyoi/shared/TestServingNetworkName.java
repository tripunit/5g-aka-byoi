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

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestServingNetworkName
{
    @Test
    public void testConstructorSnn() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        Assert.assertEquals(snn.getMnc(), "015");
        Assert.assertEquals(snn.getMcc(), "234");
        Assert.assertEquals(snn.getNid(), "");
    }

    @Test
    public void testConstructorSnnWithNid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org:123456ABCDE");

        Assert.assertEquals(snn.getMnc(), "015");
        Assert.assertEquals(snn.getMcc(), "234");
        Assert.assertEquals(snn.getNid(), "123456ABCDE");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testConstructorSnnInvalid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("invalid");
    }

    @Test
    public void testConstructorComponents() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("015", "234", "");

        Assert.assertEquals(snn.getMnc(), "015");
        Assert.assertEquals(snn.getMcc(), "234");
        Assert.assertEquals(snn.getNid(), "");
    }

    @Test
    public void testConstructorComponentsWithNid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("015", "234", "123456ABCDE");

        Assert.assertEquals(snn.getMnc(), "015");
        Assert.assertEquals(snn.getMcc(), "234");
        Assert.assertEquals(snn.getNid(), "123456ABCDE");
    }

    @Test
    public void testSetMnc() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setMnc("123");

        Assert.assertEquals(snn.getMnc(), "123");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetMncInvalid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setMnc("1234");
    }

    @Test
    public void testSetMcc() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setMcc("123");

        Assert.assertEquals(snn.getMcc(), "123");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetMccInvalid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setMcc("1234");
    }

    @Test
    public void testSetNid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setNid("123456ABCDE");

        Assert.assertEquals(snn.getNid(), "123456ABCDE");

        snn.setNid("");

        Assert.assertEquals(snn.getNid(), "");
    }

    @Test(expectedExceptions = FormatException.class)
    public void testSetNidInvalid() throws FormatException
    {
        ServingNetworkName snn = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");

        snn.setNid("123456");
    }

    @Test
    public void testToString() throws FormatException
    {
        ServingNetworkName snn1 = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org");
        ServingNetworkName snn2 = new ServingNetworkName("5G:mnc015.mcc234.3gppnetwork.org:123456ABCDE");

        Assert.assertEquals(snn1.toString(), "5G:mnc015.mcc234.3gppnetwork.org");
        Assert.assertEquals(snn2.toString(), "5G:mnc015.mcc234.3gppnetwork.org:123456ABCDE");
    }
}
