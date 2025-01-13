// Copyright (c) 2024-2025 Julian Parkin
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

import java.lang.IllegalStateException;
import java.util.HexFormat;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.util.Arrays;

import ca.uwaterloo.fivegakabyoi.shared.FiveGAka;
import ca.uwaterloo.fivegakabyoi.shared.FormatException;
import ca.uwaterloo.fivegakabyoi.shared.ServingNetworkName;
import ca.uwaterloo.fivegakabyoi.shared.Suci;

import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationReject;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationRequest;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationResponse;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.FiveGMmCause;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.FiveGMmStatus;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasEndpoint;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessage;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessageVisitor;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.RegistrationReject;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.RegistrationRequest;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.SecurityModeCommand;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.SecurityModeComplete;

public class SnNasThread extends Thread
{
    private static final long   JOIN_TIMEOUT_MS = 5000;
    private static final String ROUTING_IND     = "0";
    private static final byte[] ABBA            = { 0x00, 0x00 };

    private static final Logger    log      = LogManager.getLogger();
    private static final HexFormat hex      = HexFormat.of().withUpperCase();

    private final String    snn;
    private final LinkedBlockingQueue<ImmutablePair<SnNasConnection, NasMessage>> nasMessageQueue;
    private final HnAusfUdm hn;

    public SnNasThread(
        String    mcc,
        String    mnc,
        HnAusfUdm hn
    )
    {
        log.trace("SnNasThread(mcc = {}, mnc = {}, hn = {})", mcc, mnc, hn.getHnId());

        this.nasMessageQueue = new LinkedBlockingQueue<>();
        this.hn              = hn;

        try {
            ServingNetworkName name = new ServingNetworkName(mcc, mnc);

            this.snn = name.toString();
        } catch (FormatException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getSnName() { return snn; }

    public NasEndpoint connect(NasEndpoint ue)
    {
        log.trace("connect()");

        SnNasConnection connection = new SnNasConnection(ue);

        connection.setVisitor(new NasMessageVisitor() {
            // XXX: Resynchronisation not implemented yet

            @Override
            public void visitUnknownMessage(NasMessage m)
            {
                connection.send(new FiveGMmStatus(FiveGMmCause.MESSAGE_TYPE_NON_EXISTENT));
            }

            @Override
            public void visitFiveGMmStatus(FiveGMmStatus s)
            {
                log.warn("Received 5GMM STATUS with cause = {}", s.cause.getName());
            }

            @Override
            public void visitRegistrationRequest(RegistrationRequest r)
            {
                processRegistrationRequest(r, connection);
            }

            @Override
            public void visitAuthenticationResponse(AuthenticationResponse a)
            {
                processAuthenticationResponse(a, connection);
            }

            @Override
            public void visitSecurityModeComplete(SecurityModeComplete s)
            {
                processSecurityModeComplete(s, connection);
            }
        });

        return new NasEndpoint() {
            public void sendNasMessage(NasMessage m)
            {
                try {
                    nasMessageQueue.put(ImmutablePair.of(connection, m));
                } catch (InterruptedException e) {
                    throw new IllegalStateException("LinkedBlockingQueue.put() was interrupted");
                }
            }
        };
    }

    public void exit()
    {
        log.trace("exit()");

        try {
            nasMessageQueue.put(null);
        } catch (InterruptedException e) {
            throw new IllegalStateException("LinkedBlockingQueue.put() was interrupted");
        }

        try {
            this.join(JOIN_TIMEOUT_MS);
        } catch (InterruptedException e) {
            throw new IllegalStateException("Thead.join() was interrupted");
        }
    }

    @Override
    public void run()
    {
        log.trace("run()");

        log.info("SN NAS thread starting");

        while (true) {
            ImmutablePair<SnNasConnection, NasMessage> m;

            try {
                m = nasMessageQueue.take();
            } catch (InterruptedException e) {
                throw new IllegalStateException("LinkedBlockingQueue.take() was interrupted");
            }

            if (m == null) {
                log.info("SN NAS thread exiting");
                break;
            }

            m.left.process(m.right);
        }
    }

    private void processRegistrationRequest(RegistrationRequest r, SnNasConnection c)
    {
        log.trace("processRegistrationRequest()");

        ImmutablePair<String, String> routing;

        try {
            routing = Suci.getRoutingInfo(r.fivegsMobileIdentity);
        } catch (FormatException e) {
            log.debug("SUCI not parseable", e);

            c.send(new RegistrationReject(FiveGMmCause.TRACKING_AREA_NOT_ALLOWED));
            return;
        }

        // For simple modelling, we expect to serve exactly one network. Could
        // model roaming here by allowing multiple HN IDs with different
        // subscriber databases.

        if (!routing.left.equals(hn.getHnId()) || !routing.right.equals(ROUTING_IND)) {
            log.debug("SUCI points to wrong tracking area");

            c.send(new RegistrationReject(FiveGMmCause.TRACKING_AREA_NOT_ALLOWED));
            return;
        }

        UeAuthenticationInitResult res;

        try {
            res = hn.nAusfUeAuthenticationInit(snn, r.fivegsMobileIdentity, r.byoiIdentity);
        } catch (UeaAuthenticationException | UeaUnknownSubscriberException e) {
            // Mapping everything to ILLEGAL_UE for now since the only
            // authentication failure is if the SQN maxes out (which
            // shouldn't happen).

            log.debug("nAusfUeAuthenticationInit failed: {}", e);

            c.send(new RegistrationReject(FiveGMmCause.ILLEGAL_UE));
            return;
        }

        AuthenticationRequest ar = new AuthenticationRequest(res.rand, res.autn, ABBA, res.authUrl);

        log.debug(
            "AUTHENTICATION REQUEST (RAND, AUTN, ABBA, authUrl) = ({}, {}, {}, {})",
            () -> hex.formatHex(res.rand),
            () -> hex.formatHex(res.autn),
            () -> hex.formatHex(ABBA),
            () -> hex.formatHex(res.authUrl)
        );

        log.info("Sending AUTHENTICATION REQUEST to {}", r.fivegsMobileIdentity);

        c.authStart(res.sessionId, res.hXResStar, res.rand);
        c.send(ar);
    }

    private void processAuthenticationResponse(AuthenticationResponse a, SnNasConnection c)
    {
        log.trace("processAuthenticationResponse()");

        byte[] hResStar  = FiveGAka.deriveHResStar(c.getRand(), a.resStar);
        byte[] hXResStar = c.getHXResStar();

        log.debug(
            "Comparing HRES* = {} XHRES* = {}",
            () -> hex.formatHex(hResStar),
            () -> hex.formatHex(hXResStar)
        );

        if (!Arrays.constantTimeAreEqual(hXResStar.length, hXResStar, 0, hResStar, 0)) {
            log.debug("Invalid RES*");

            c.send(new AuthenticationReject());
            return;
        }

        UeAuthenticationConfirmResult res;

        try {
            res = hn.nAusfUeAuthenticationConfirm(c.getSessionId(), a.resStar, a.respUrl);
        } catch (UeaAuthenticationException | UeaIllegalStateException e) {
            log.debug("HN rejected authentication: {}", e);

            c.send(new AuthenticationReject());
            return;
        }

        log.debug(
            "HN accepted authentication (SUPI = {}, K_SEAF = {})",
            () -> res.supi,
            () -> hex.formatHex(res.kSeaf)
        );

        c.authFinish(res.supi, res.kSeaf);

        log.info("Sending SECURITY MODE COMMAND to {}", res.supi);

        // Since we aren't simulating the full NAS protocol, calculate a MAC
        // over a constant string, as in the Tamarin model, so that the UE
        // has something to check that it computed the same key.
        c.send(new SecurityModeCommand(FiveGByoi.computeMac(res.kSeaf, "SecurityModeCommand")));
    }

    private void processSecurityModeComplete(SecurityModeComplete s, SnNasConnection c)
    {
        log.trace("processSecurityModeComplete()");

        byte[] mac = FiveGByoi.computeMac(c.getKSeaf(), "SecurityModeComplete");

        log.debug(
            "Comparing MAC = {} expected MAC = {}", 
            () -> hex.formatHex(s.mac), 
            () -> hex.formatHex(mac)
        );

        boolean macEqual = Arrays.constantTimeAreEqual(
            mac.length,
            mac,   0,
            s.mac, 0
        );

        if (!macEqual) {
            // According to TS 24.501, NAS messages that fail the integrity
            // check should simply be ignored. For demo purposes, we log a
            // warning, since we know this is a protocol error rather than
            // a malicious message.

            log.warn("Failed to process SECURITY MODE COMPLETE for UE = {}", c.getSupi());
            return;
        }

        log.debug("Completed authentication with UE = {}", c.getSupi());
    }
}
