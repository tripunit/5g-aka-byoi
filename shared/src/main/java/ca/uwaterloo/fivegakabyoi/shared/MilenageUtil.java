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

public class MilenageUtil
{
    public static final int SQN_LEN_BYTES  = 6;
    public static final int AMF_LEN_BYTES  = 2;
    public static final int MAC_LEN_BYTES  = 8;
    public static final int AUTN_LEN_BYTES = SQN_LEN_BYTES + AMF_LEN_BYTES + MAC_LEN_BYTES;
    public static final int AUTS_LEN_BYTES = SQN_LEN_BYTES + MAC_LEN_BYTES;

    public static byte[] sqnLongToBytes(long sqn)
    {
        byte[] sqnBytes = new byte[SQN_LEN_BYTES];

        for (int i = 0; i < SQN_LEN_BYTES; i++)
            sqnBytes[i] = (byte) (sqn >> (8 * (SQN_LEN_BYTES - i - 1)));

        return sqnBytes;
    }

    public static long sqnBytesToLong(byte[] sqn)
    {
        assert sqn.length == SQN_LEN_BYTES;

        long sqnLong = 0;

        for (int i = 0; i < SQN_LEN_BYTES; i++)
            sqnLong |= ((long) sqn[i] & 0xFFL) << (8 * (SQN_LEN_BYTES - i - 1));

        return sqnLong;
    }

    public static void packAutn(byte[] autn, byte[] sqn, byte[] amf, byte[] mac)
    {
        assert autn.length == AUTN_LEN_BYTES;
        assert sqn.length  == SQN_LEN_BYTES;
        assert amf.length  == AMF_LEN_BYTES;
        assert mac.length  == MAC_LEN_BYTES;

        int pos = 0;

        System.arraycopy(sqn, 0, autn, pos, sqn.length); pos += sqn.length;
        System.arraycopy(amf, 0, autn, pos, amf.length); pos += amf.length;
        System.arraycopy(mac, 0, autn, pos, mac.length); pos += mac.length;
    }

    public static void unpackAutn(byte[] autn, byte[] sqn, byte[] amf, byte[] mac)
    {
        assert autn.length == AUTN_LEN_BYTES;
        assert sqn.length  == SQN_LEN_BYTES;
        assert amf.length  == AMF_LEN_BYTES;
        assert mac.length  == MAC_LEN_BYTES;

        int pos = 0;

        System.arraycopy(autn, pos, sqn, 0, sqn.length); pos += sqn.length;
        System.arraycopy(autn, pos, amf, 0, amf.length); pos += amf.length;
        System.arraycopy(autn, pos, mac, 0, mac.length); pos += mac.length;
    }

    public static void packAuts(byte[] auts, byte[] sqn, byte[] mac)
    {
        assert auts.length == AUTS_LEN_BYTES;
        assert sqn.length  == SQN_LEN_BYTES;
        assert mac.length  == MAC_LEN_BYTES;

        int pos = 0;

        System.arraycopy(sqn, 0, auts, pos, sqn.length); pos += sqn.length;
        System.arraycopy(mac, 0, auts, pos, mac.length); pos += mac.length;
    }

    public static void unpackAuts(byte[] auts, byte[] sqn, byte[] mac)
    {
        assert auts.length == AUTS_LEN_BYTES;
        assert sqn.length  == SQN_LEN_BYTES;
        assert mac.length  == MAC_LEN_BYTES;

        int pos = 0;

        System.arraycopy(auts, pos, sqn, 0, sqn.length); pos += sqn.length;
        System.arraycopy(auts, pos, mac, 0, mac.length); pos += mac.length;
    }
}
