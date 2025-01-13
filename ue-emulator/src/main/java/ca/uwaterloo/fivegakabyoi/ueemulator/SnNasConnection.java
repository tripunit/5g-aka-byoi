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

import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasEndpoint;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessage;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessageVisitor;

public class SnNasConnection
{
    private final NasEndpoint       ue;
    private       NasMessageVisitor visitor;
    private       String            sessionId;
    private       byte[]            hXResStar;
    private       byte[]            rand;
    private       String            supi;
    private       byte[]            kSeaf;

    public SnNasConnection(NasEndpoint ue)
    {
        this.ue        = ue;
        this.visitor   = null;
        this.sessionId = null;
        this.hXResStar = null;
        this.rand      = null;
        this.supi      = null;
        this.kSeaf     = null;
    }

    public String getSessionId() { return sessionId; }
    public byte[] getHXResStar() { return hXResStar; }
    public byte[] getRand()      { return rand;      }
    public String getSupi()      { return supi;      }
    public byte[] getKSeaf()     { return kSeaf;     }

    public void setVisitor(NasMessageVisitor visitor)
    {
        this.visitor = visitor;
    }

    public void authStart(String sessionId, byte[] hXResStar, byte[] rand)
    {
        this.sessionId = sessionId;
        this.hXResStar = hXResStar;
        this.rand      = rand;
    }

    public void authFinish(String supi, byte[] kSeaf)
    {
        this.supi  = supi;
        this.kSeaf = kSeaf;
    }

    public void process(NasMessage m)
    {
        m.accept(visitor);
    }

    public void send(NasMessage m)
    {
        ue.sendNasMessage(m);
    }
}
