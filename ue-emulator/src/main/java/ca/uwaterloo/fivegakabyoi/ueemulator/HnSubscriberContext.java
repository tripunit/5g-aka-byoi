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

import java.lang.System;

import ca.uwaterloo.fivegakabyoi.shared.MilenageUtil;
import ca.uwaterloo.fivegakabyoi.shared.SqnGenerationException;
import ca.uwaterloo.fivegakabyoi.shared.SqnGenerator;
import ca.uwaterloo.fivegakabyoi.shared.SqnGeneratorProfile1;

public class HnSubscriberContext
{
    private static SqnGeneratorProfile1.GlobalClock clock = new SqnGeneratorClock();

    private final String       supi;
    private final byte[]       k;
    private final byte[]       op;
    private final SqnGenerator sg;
    private       String       sessionId;
    private       OAuthSession oAuthSession;
    private       byte[]       xResStar;
    private       byte[]       kSeaf;
    private       byte[]       ek;

    public HnSubscriberContext(Usim u)
    {
        supi         = u.getMsin();
        k            = u.getK();
        op           = u.getOp();
        sg           = new SqnGeneratorProfile1(clock, u.getSqn());
        sessionId    = null;
        oAuthSession = null;
        xResStar     = null;
        kSeaf        = null;
        ek           = null;
    }

    public String       getSupi()         { return supi;         }
    public byte[]       getK()            { return k;            }
    public byte[]       getOp()           { return op;           }
    public String       getSessionId()    { return sessionId;    }
    public OAuthSession getOAuthSession() { return oAuthSession; }
    public byte[]       getXResStar()     { return xResStar;     }
    public byte[]       getKSeaf()        { return kSeaf;        }
    public byte[]       getEk()           { return ek;           }

    public void setSessionId(String sessionId)
    {
        this.sessionId = sessionId;
    }

    public void authStart(OAuthSession oAuthSession, byte[] kSeaf, byte[] xResStar, byte[] ek)
    {
        this.oAuthSession = oAuthSession;
        this.xResStar     = xResStar;
        this.kSeaf        = kSeaf;
        this.ek           = ek;
    }

    public byte[] generateSqn()
    throws SqnGenerationException
    {
        return MilenageUtil.sqnLongToBytes(sg.generate());
    }
}
