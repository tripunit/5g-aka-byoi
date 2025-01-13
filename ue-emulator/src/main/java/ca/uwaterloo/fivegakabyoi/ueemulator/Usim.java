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

package ca.uwaterloo.fivegakabyoi.ueemulator;

import java.util.HexFormat;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import ca.uwaterloo.fivegakabyoi.shared.Milenage;

public class Usim
{
    private static final ObjectMapper mapper;

    static {
        mapper = new ObjectMapper();

        mapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
    }

    private final byte[] k;
    private final String mcc;
    private final String mnc;
    private final String msin;
    private final byte[] milenageOp;
    private final String routingInd;
    private final byte[] hnPublicKey;
    private final String hnPublicKeyId;
    private       long   sqn;

    public Usim(
        byte[] k,
        String mcc,
        String mnc,
        String msin,
        byte[] milenageOp,
        String routingInd,
        byte[] hnPublicKey,
        String hnPublicKeyId
    )
    {
        this.k             = k;
        this.mcc           = mcc;
        this.mnc           = mnc;
        this.msin          = msin;
        this.milenageOp    = milenageOp;
        this.routingInd    = routingInd;
        this.hnPublicKey   = hnPublicKey;
        this.hnPublicKeyId = hnPublicKeyId;
    }

    public static Usim fromJson(String json)
    throws UsimLoadingException
    {
        UsimJson usim;

        try {
            usim = mapper.readValue(json, UsimJson.class);
        } catch (JsonProcessingException e) {
            throw new UsimLoadingException(e);
        }

        byte[] k           = parseHexField(usim.k,           "k",           Milenage.K_LEN_BYTES              );
        byte[] milenageOp  = parseHexField(usim.milenageOp,  "milenageOp",  Milenage.OP_LEN_BYTES             );
        byte[] hnPublicKey = parseHexField(usim.hnPublicKey, "hnPublicKey", X25519PublicKeyParameters.KEY_SIZE);

        return new Usim(
            k,
            usim.mcc,
            usim.mnc,
            usim.msin,
            milenageOp,
            usim.routingInd,
            hnPublicKey,
            usim.hnPublicKeyId
        );
    }

    public byte[] getK()             { return k;             }
    public String getMcc()           { return mcc;           }
    public String getMnc()           { return mnc;           }
    public String getMsin()          { return msin;          }
    public byte[] getOp()            { return milenageOp;    }
    public long   getSqn()           { return sqn;           }
    public byte[] getHnPublicKey()   { return hnPublicKey;   }
    public String getHnPublicKeyId() { return hnPublicKeyId; }

    public String getRoutingInd()
    {
        // TS23.003: default Routing Indicator is "0" if not present in the USIM
        return Optional.ofNullable(routingInd).orElse("0");
    }

    public void setSqn(long sqn)
    {
        this.sqn = sqn;
    }

    private static byte[] parseHexField(String field, String name, int expectedLen)
    throws UsimLoadingException
    {
        HexFormat hex = HexFormat.of().withUpperCase();

        byte[] parsed;

        try {
            parsed = hex.parseHex(field);
        } catch(IllegalArgumentException e) {
            throw new UsimLoadingException(String.format("%s contains invalid hex: %s", name, field), e);
        }

        if (parsed.length != expectedLen)
            throw new UsimLoadingException(
                String.format(
                    "%s is of unexpected length: expected %d bytes, was %d bytes",
                    parsed.length,
                    expectedLen
                )
            );

        return parsed;
    }
}
