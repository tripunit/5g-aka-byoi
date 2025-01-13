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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

// SNN parsing according to 3GPP TS 24.501

public class ServingNetworkName
{
    private static final Pattern SNN_REGEX            = Pattern.compile("5G:mnc(?<snnMncDigits>[0-9]{3})\\.mcc(?<snnMccDigits>[0-9]{3})\\.3gppnetwork\\.org(?::(?<snnNid>[0-9A-Z]{11}))?");
    private static final Pattern SNN_MNC_DIGITS_REGEX = Pattern.compile("[0-9]{3}");
    private static final Pattern SNN_MCC_DIGITS_REGEX = SNN_MNC_DIGITS_REGEX;
    private static final Pattern SNN_NID_REGEX        = Pattern.compile("[0-9A-Z]{11}");

    private String mnc;
    private String mcc;
    private String nid; // empty string = no NID

    public ServingNetworkName(String mnc, String mcc)
    throws FormatException
    {
        this(mnc, mcc, "");
    }

    public ServingNetworkName(String mnc, String mcc, String nid)
    throws FormatException
    {
        setMnc(mnc);
        setMcc(mcc);
        setNid(nid);
    }

    public ServingNetworkName(String snn)
    throws FormatException
    {
        Matcher m = SNN_REGEX.matcher(snn);

        if (m.matches()) {
            mnc = m.group("snnMncDigits");
            mcc = m.group("snnMccDigits");
            nid = m.group("snnNid");

            if (nid == null)
                nid = "";
        } else {
            throw new FormatException(String.format("Not a valid Serving Network name: %s", snn));
        }
    }

    @Override
    public String toString()
    {
        if (nid.isEmpty())
            return "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org";
        else
            return "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org:" + nid;
    }

    public String getMnc() { return mnc; }
    public String getMcc() { return mcc; }
    public String getNid() { return nid; }

    public void setMnc(String mnc)
    throws FormatException
    {
        Matcher m = SNN_MNC_DIGITS_REGEX.matcher(mnc);

        if (!m.matches())
            throw new FormatException(String.format("Not a valid MNC: %s", mnc));

        this.mnc = mnc;
    }

    public void setMcc(String mcc)
    throws FormatException
    {
        Matcher m = SNN_MCC_DIGITS_REGEX.matcher(mcc);

        if (!m.matches())
            throw new FormatException(String.format("Not a valid MCC: %s", mcc));

        this.mcc = mcc;
    }

    public void setNid(String nid)
    throws FormatException
    {
        Matcher m = SNN_NID_REGEX.matcher(nid);

        if (!m.matches() && !nid.isEmpty())
            throw new FormatException(String.format("Not a valid NID: %s", nid));

        this.nid = nid;
    }
}
