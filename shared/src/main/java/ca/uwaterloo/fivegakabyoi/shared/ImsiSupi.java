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
import java.util.regex.Pattern;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.lang.System;

public class ImsiSupi extends Supi
{
    public static final Pattern REGEX_DIGITS = Pattern.compile("[0-9]+");

    private final String mcc;
    private final String mnc;
    private final String msin;

    public static boolean isValidMcc(String mcc)
    {
        try {
            validateNum(mcc, "MCC", 3, 3);
        } catch(FormatException e) {
            return false;
        }

        return true;
    }

    public static boolean isValidMnc(String mnc)
    {
        try {
            validateNum(mnc, "MNC", 2,  3);
        } catch(FormatException e) {
            return false;
        }

        return true;
    }

    public ImsiSupi(String mcc, String mnc, String msin) throws FormatException
    {
        validateNum(mcc,  "MCC",  3,  3);
        validateNum(mnc,  "MNC",  2,  3);
        validateNum(msin, "MSIN", 0, 10);

        if (mcc.length() + mnc.length() + msin.length() > 15)
            throw new FormatException("IMSI cannot contain more than 15 digits between MCC, MNC, and MSIN");

        this.mcc  = mcc;
        this.mnc  = mnc;
        this.msin = msin;
    }

    @Override public String getType()   { return SUPI_TYPE_IMSI;  }
    @Override public String getUserId() { return msin;            }
    @Override public String getHnId()   { return mcc + "-" + mnc; }

    @Override
    public byte[] encodeUserId(boolean nullScheme)
    {
        // Skip BCD encoding when using the null scheme, since a plaintext
        // IMSI must be represented as digits in the SUCI
        if (nullScheme)
            return super.encodeUserId(nullScheme);

        byte[] bcd = new byte[(msin.length() + 1) >> 1];

        for (int i = 0; i < msin.length(); i++) {
            int val = msin.charAt(i) - '0';

            bcd[i >> 1] |= val << ((i & 1) << 2);
        }

        if ((msin.length() & 1) == 1)
            bcd[msin.length() >> 1] |= 0xF0;

        return bcd;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || obj.getClass() != this.getClass())
            return false;

        if (this == obj)
            return true;

        ImsiSupi s = (ImsiSupi) obj;

        return new EqualsBuilder()
            .append(mcc,  s.mcc )
            .append(mnc,  s.mnc )
            .append(msin, s.msin)
            .isEquals();
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder(47701, 4969)
            .append(mcc)
            .append(mnc)
            .append(msin)
            .toHashCode();
    }

    private static void validateNum(String num, String name, int minLen, int maxLen)
    throws FormatException
    {
        if (!REGEX_DIGITS.matcher(num).matches())
            throw new FormatException(String.format("Invalid %s (must only contain digits): %s", name, num));

        if (num.length() < minLen || num.length() > maxLen)
            throw new FormatException(String.format("Invalid %s (unexpected length): %s", name, num));
    }
}
