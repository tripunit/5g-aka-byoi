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
import java.lang.Thread;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;

import io.vertx.core.Context;
import io.vertx.ext.web.RoutingContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
 
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.util.Arrays;

import ca.uwaterloo.fivegakabyoi.shared.FiveGAka;
import ca.uwaterloo.fivegakabyoi.shared.FormatException;
import ca.uwaterloo.fivegakabyoi.shared.ImsiSupi;
import ca.uwaterloo.fivegakabyoi.shared.Milenage;
import ca.uwaterloo.fivegakabyoi.shared.MilenageUtil;
import ca.uwaterloo.fivegakabyoi.shared.NsiSupi;
import ca.uwaterloo.fivegakabyoi.shared.Rfc7542Nai;
import ca.uwaterloo.fivegakabyoi.shared.Suci;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionException;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionProfile;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionProfileA;
import ca.uwaterloo.fivegakabyoi.shared.Supi;

import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationFailure;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationRequest;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.AuthenticationResponse;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.FiveGMmCause;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.FiveGMmStatus;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasEndpoint;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessage;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasMessageVisitor;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.RegistrationRequest;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.SecurityModeCommand;
import ca.uwaterloo.fivegakabyoi.ueemulator.nas.SecurityModeComplete;

public class UeNasThread extends Thread
{
    public interface RegistrationRequestCallback
    {
        void callback(String authenticationRequestUrl);
    }

    public interface AuthorizationResponseCallback
    {
        void callback();
    }

    private static final int    EK_LEN_BYTES    = 16;
    private static final long   JOIN_TIMEOUT_MS = 5000L;
    private static final long   DELTA           = 1L << 32;

    private static final HexFormat hex          = HexFormat.of().withUpperCase();
    private static final Logger    log          = LogManager.getLogger();

    private enum RegistrationState
    {
        FIVEGMM_DEREGISTERED         ("5GMM-DEREGISTERED"          ),
        FIVEGMM_REGISTERED_INITIATED ("5GMM-REGISTERED-INITIATED"  ),
        FIVEGMM_REGISTERED           ("5GMM-REGISTERED"            );

        public String name;

        private RegistrationState(String name)
        {
            this.name = name;
        }
    }

    private final Usim                            usim;
    private final Milenage                        milenage;
    private final LinkedBlockingQueue<NasMessage> nasQueue;
    private final SuciEncryptionProfile           suciEnc;
    private final NasMessageVisitor               nasVisitor;
    private       NasEndpoint                     sn;
    private       String                          snName;
    private       RegistrationState               state;
    private       long                            sqn;

    private       byte[]                          akaEkUe;
    private       byte[]                          akaResStar;
    private       byte[]                          kSeaf;

    private       RegistrationRequestCallback     cbRegistrationRequest;
    private       AuthorizationResponseCallback   cbAuthorizationResponse;

    public UeNasThread(Usim usim)
    {
        log.trace("UeNasThread(usim = {})", usim.getMsin());

        this.usim     = usim;
        this.milenage = new Milenage(usim.getOp(), usim.getK());
        this.nasQueue = new LinkedBlockingQueue<>();
        this.sn       = null;
        this.snName   = null;
        this.state    = RegistrationState.FIVEGMM_DEREGISTERED;
        this.sqn      = usim.getSqn();

        X25519PublicKeyParameters hnPublicKey = new X25519PublicKeyParameters(usim.getHnPublicKey());

        this.suciEnc = new SuciEncryptionProfileA(hnPublicKey, null, null, new SecureRandom());

        this.nasVisitor = new NasMessageVisitor() {
            @Override
            public void visitUnknownMessage(NasMessage m)
            {
                send(new FiveGMmStatus(FiveGMmCause.MESSAGE_TYPE_NON_EXISTENT));
            }

            @Override
            public void visitFiveGMmStatus(FiveGMmStatus s)
            {
                log.warn("Received 5GMM STATUS with cause = {}", s.cause.getName());
            }

            @Override
            public void visitAuthenticationRequest(AuthenticationRequest a)
            {
                processAuthenticationRequest(a);
            }

            @Override
            public void visitSecurityModeCommand(SecurityModeCommand s)
            {
                processSecurityModeCommand(s);
            }
        };
    }

    public void connect(NasEndpoint sn, String snName)
    {
        log.trace("connect({})", snName);

        this.sn     = sn;
        this.snName = snName;
    }

    public void exit()
    {
        log.trace("exit()");

        try {
            nasQueue.put(null);
        } catch (InterruptedException e) {
            throw new IllegalStateException("LinkedBlockingQueue.put() was interrupted");
        }

        try {
            this.join(JOIN_TIMEOUT_MS);
        } catch (InterruptedException e) {
            throw new IllegalStateException("Thead.join() was interrupted");
        }
    }

    public NasEndpoint getNasEndpoint()
    {
        log.trace("getNasEndpoint()");

        return new NasEndpoint() {
            public void sendNasMessage(NasMessage m)
            {
                try {
                    nasQueue.put(m);
                } catch (InterruptedException e) {
                    throw new IllegalStateException("LinkedBlockingQueue.put() was interrupted");
                }
            }
        };
    }

    public void registrationRequest(String byoiUsername, RegistrationRequestCallback callback)
    throws UeNasException
    {
        log.trace("registrationRequest({})", byoiUsername);

        cbRegistrationRequest = callback;

        Supi fivegsSupi;

        try {
            fivegsSupi = new ImsiSupi(usim.getMcc(), usim.getMnc(), usim.getMsin());
        } catch (FormatException e) {
            throw new IllegalStateException("USIM contains an invalid IMSI", e);
        }

        Supi byoiSupi;

        try {
            byoiSupi = new NsiSupi(new Rfc7542Nai(byoiUsername));
        } catch (FormatException e) {
            throw new UeNasException(String.format("Illegal username: %s", byoiUsername), e);
        }

        Suci fivegsSuci;
        Suci byoiSuci;

        try {
            fivegsSuci = new Suci(fivegsSupi, usim.getRoutingInd());
            byoiSuci   = new Suci(byoiSupi,   usim.getRoutingInd());
        } catch (FormatException e) {
            throw new IllegalStateException("USIM contains an invalid Routing Indicator", e);
        }

        String fivegsSuciEnc;
        String byoiSuciEnc;

        try {
            fivegsSuciEnc = fivegsSuci.encrypt(suciEnc, usim.getHnPublicKeyId());
            byoiSuciEnc   = byoiSuci  .encrypt(suciEnc, usim.getHnPublicKeyId());
        } catch (FormatException | SuciEncryptionException e) {
            throw new IllegalStateException("Failed to encrypt SUCI", e);
        }

        log.debug("REGISTRATION REQUEST (SUCI, BYOI-SUCI) = ({}, {})", fivegsSuciEnc, byoiSuciEnc);

        log.info("Sending REGISTRATION REQUEST");

        send(new RegistrationRequest(fivegsSuciEnc, byoiSuciEnc));
        updateState(RegistrationState.FIVEGMM_REGISTERED_INITIATED);
    }

    public void oauthAuthorizationResponse(String url, AuthorizationResponseCallback callback)
    {
        log.trace("oauthAuthorizationResponse({})", url);

        byte[] urlEnc = FiveGByoi.encryptUrl(akaEkUe, url);

        cbAuthorizationResponse = callback;

        log.debug(
            "AUTHENTICATION RESPONSE (RES*, urlEnc) = ({}, {})",
            () -> hex.formatHex(akaResStar),
            () -> hex.formatHex(urlEnc)
        );

        log.info("Sending AUTHENTICATION RESPONSE");

        send(new AuthenticationResponse(akaResStar, urlEnc));
    }

    @Override
    public void run()
    {
        log.trace("run()");

        log.info("UE NAS thread starting");

        while (true) {
            NasMessage m;

            try {
                m = nasQueue.take();
            } catch (InterruptedException e) {
                throw new IllegalStateException("LinkedBlockingQueue.take() was interrupted");
            }

            if (m == null) {
                log.info("UE NAS thread exiting");

                break;
            }

            m.accept(nasVisitor);
        }
    }

    private void send(NasMessage m)
    {
        log.trace("send()");

        if (sn == null)
            throw new IllegalStateException("Must call connect() before starting NAS operations");

        sn.sendNasMessage(m);
    }

    private void updateState(RegistrationState newState)
    {
        log.info("State Update: {} -> {}", state.name, newState.name);

        state = newState;
    }

    private void processAuthenticationRequest(AuthenticationRequest a)
    {
        log.trace(
            "processAuthenticationRequest(AUTN = {}, RAND = {}, authUrl = {}",
            () -> hex.formatHex(a.autn),
            () -> hex.formatHex(a.rand),
            () -> hex.formatHex(a.authUrl)
        );

        byte[] sqnEnc = new byte[MilenageUtil.SQN_LEN_BYTES];
        byte[] amf    = new byte[MilenageUtil.AMF_LEN_BYTES];
        byte[] mac    = new byte[MilenageUtil.MAC_LEN_BYTES];

        MilenageUtil.unpackAutn(a.autn, sqnEnc, amf, mac);

        Milenage.Result av = milenage.milenage(EnumSet.of(Milenage.Flags.CHECK), amf, a.rand, sqnEnc);

        log.debug(
            "Comparing MAC = {} XMAC = {}",
            () -> hex.formatHex(mac),
            () -> hex.formatHex(av.mac)
        );

        boolean macEqual = Arrays.constantTimeAreEqual(
            av.mac.length,
            av.mac, 0,
            mac,    0
        );

        if (!macEqual) {
            log.info("Authentication Request failed MAC check");

            send(new AuthenticationFailure(FiveGMmCause.MAC_FAILURE,
                Optional.empty()
            ));
            return;
        }

        if ((amf[0] & 0x80) != 0x80) {
            log.info("Authentication Request did not have AMF separation bit set");

            send(new AuthenticationFailure(
                FiveGMmCause.NON_5G_AUTHENTICATION_UNACCEPTABLE,
                Optional.empty()
            ));
            return;
        }

        byte[] sqnBytes = FiveGAka.encryptSqn     (av.ak, sqnEnc);
        byte[] kAusf    = FiveGAka.deriveKAusf    (av.ck, av.ik, snName, sqnEnc);
        byte[] kSeaf    = FiveGAka.deriveKSeaf    (kAusf, snName);
        byte[] resStar  = FiveGAka.deriveResStar  (av.ck, av.ik, snName, a.rand, av.res);

        long sqnHn = MilenageUtil.sqnBytesToLong(sqnBytes);

        log.debug("Comparing SQN_HN = {} SQN_UE = {}", sqnHn, sqn);

        if (sqnHn <= sqn || sqnHn - sqn > DELTA) {
            log.info("Authentication Request failed SQN check");

            byte[] sqnUe = MilenageUtil.sqnLongToBytes(sqn);

            Milenage.Result av_resync = milenage.milenage(
                EnumSet.of(Milenage.Flags.RESYNC),
                amf,
                a.rand,
                sqnUe
            );

            byte[] auts     = new byte[MilenageUtil.AUTS_LEN_BYTES];
            byte[] sqnUeEnc = FiveGAka.encryptSqn(av_resync.ak, sqnUe);

            MilenageUtil.packAuts(auts, sqnUeEnc, av_resync.mac);

            send(new AuthenticationFailure(
                FiveGMmCause.SYNCH_FAILURE,
                Optional.of(auts)
            ));

            return;
        }

        byte[] ekHn = new byte[EK_LEN_BYTES];
        byte[] ekUe = new byte[EK_LEN_BYTES];

        FiveGByoi.deriveEk(av.ck, av.ik, ekHn, ekUe);

        String url;

        try {
            url = FiveGByoi.decryptUrl(ekHn, a.authUrl);
        } catch (FiveGByoiException e) {
            log.debug("Unable to decrypt URL", e);

            // Reuse MAC failure for MAC failure while decrypting the URL
            send(new AuthenticationFailure(FiveGMmCause.MAC_FAILURE,
                Optional.empty()
            ));
            return;
        }

        log.debug("AS URL = {}", url);

        log.info("SQN Update: {} -> {} ", sqn, sqnHn);

        sqn        = sqnHn;
        akaEkUe    = ekUe;
        akaResStar = resStar;
        this.kSeaf = kSeaf;

        cbRegistrationRequest.callback(url);
    }

    private void processSecurityModeCommand(SecurityModeCommand s)
    {
        log.trace("processSecurityModeCommand()");

        byte[] mac = FiveGByoi.computeMac(kSeaf, "SecurityModeCommand");

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

            log.warn("Failed to process SECURITY MODE COMMAND");
            return;
        }

        send(new SecurityModeComplete(FiveGByoi.computeMac(kSeaf, "SecurityModeComplete")));
        cbAuthorizationResponse.callback();
        updateState(RegistrationState.FIVEGMM_REGISTERED);
    }
}
