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

import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.lang.IllegalStateException;
import java.lang.InterruptedException;
import java.lang.SecurityException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.util.Arrays;

import ca.uwaterloo.fivegakabyoi.shared.FiveGAka;
import ca.uwaterloo.fivegakabyoi.shared.FormatException;
import ca.uwaterloo.fivegakabyoi.shared.ImsiSupi;
import ca.uwaterloo.fivegakabyoi.shared.Milenage;
import ca.uwaterloo.fivegakabyoi.shared.MilenageUtil;
import ca.uwaterloo.fivegakabyoi.shared.NsiSupi;
import ca.uwaterloo.fivegakabyoi.shared.SqnGenerationException;
import ca.uwaterloo.fivegakabyoi.shared.Suci;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionException;
import ca.uwaterloo.fivegakabyoi.shared.Supi;

public class HnAusfUdm
{
    private static final byte[]       AMF      = { (byte) 0x80, (byte) 0x00 };
    private static final int          EK_LEN   = 16;

    private static final SecureRandom sr       = new SecureRandom();
    private static final Logger       log      = LogManager.getLogger();
    private static final HexFormat    hex      = HexFormat.of().withUpperCase();

    private final String                               mcc;
    private final String                               mnc;
    private final String                               redirectUri;
    private final HashMap<String, HnSubscriberContext> subscribers;
    private final HashMap<String, HnSubscriberContext> sessions;
    private final HashMap<String, OAuthProvider>       authenticators;
    private final Suci.EncryptionProfileMap            suciKeys;
    private final HttpClient                           httpClient;

    public HnAusfUdm(
        String                    mcc,
        String                    mnc,
        List<Usim>                subscribers,
        List<OAuthProvider>       providers,
        String                    redirectUri,
        Suci.EncryptionProfileMap suciKeys
    )
    {
        log.trace("HnAusfUdm(mcc = {}, mnc = {}, ...)", mcc, mnc);

        this.mcc            = mcc;
        this.mnc            = mnc;
        this.redirectUri    = redirectUri;
        this.subscribers    = new HashMap<>();
        this.sessions       = new HashMap<>();
        this.authenticators = new HashMap<>();

        this.httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(20))
            .build();

        for (Usim u : subscribers)
            this.subscribers.put(u.getMsin(), new HnSubscriberContext(u));

        for (OAuthProvider p : providers)
            this.authenticators.put(p.getHost(), p);

        this.suciKeys = suciKeys;
    }

    public String getHnId() { return mcc + "-" + mnc; }

    public UeAuthenticationInitResult nAusfUeAuthenticationInit(
        String snn,
        String fivegsMobileIdentity,
        String byoiIdentity
    )
    throws UeaAuthenticationException, UeaUnknownSubscriberException
    {
        log.trace(
            "nAusfUeAuthenticationInit(snn = {}, fivegsMobileIdentity = {}, byoiIdentity = {})",
            snn,
            fivegsMobileIdentity,
            byoiIdentity
        );

        HnSubscriberContext subscriber = getSubscriber(fivegsMobileIdentity);

        log.debug("Found subscriber (SUPI = {})", subscriber.getSupi());

        Milenage milenage = new Milenage(subscriber.getOp(), subscriber.getK());

        byte[] rand = generateRand();
        byte[] sqn;

        try {
            sqn = subscriber.generateSqn();
        } catch (SqnGenerationException e) {
            log.warn("Unable to generate SQN {}", e);

            throw new UeaAuthenticationException(e);
        }

        Milenage.Result av = milenage.milenage(EnumSet.noneOf(Milenage.Flags.class), AMF, rand, sqn);

        byte[] sqnEnc    = FiveGAka.encryptSqn     (av.ak, sqn);
        byte[] kAusf     = FiveGAka.deriveKAusf    (av.ck, av.ik, snn, sqnEnc);
        byte[] kSeaf     = FiveGAka.deriveKSeaf    (kAusf, snn);
        byte[] xResStar  = FiveGAka.deriveResStar  (av.ck, av.ik, snn, rand, av.res);
        byte[] hXResStar = FiveGAka.deriveHResStar (rand, xResStar);

        byte[] ekHn     = new byte[EK_LEN];
        byte[] ekUe     = new byte[EK_LEN];

        FiveGByoi.deriveEk(av.ck, av.ik, ekHn, ekUe);

        OAuthSession oauth   = startOAuthSession(byoiIdentity);
        String       authUrl = oauth.getAuthenticationRequestUrl(redirectUri);

        byte[] urlEnc    = FiveGByoi.encryptUrl(ekHn, authUrl);
        byte[] autn      = new byte[MilenageUtil.AUTN_LEN_BYTES];

        MilenageUtil.packAutn(autn, sqnEnc, AMF, av.mac);

        log.debug(
            "5G HE AV (RAND, AUTN, XRES*) = ({}, {}, {})",
            () -> hex.formatHex(rand),
            () -> hex.formatHex(autn),
            () -> hex.formatHex(xResStar)
        );

        subscriber.authStart(oauth, kSeaf, xResStar, ekUe);

        String existingSession = subscriber.getSessionId();

        if (existingSession != null) {
            log.debug("Removing existing session (sessionId = {})", existingSession);

            sessions.remove(subscriber.getSessionId());
        }

        String sessionId = OAuthUtils.randomString(16);

        log.debug("Creating session (sessionId = {})", sessionId);

        sessions.put(sessionId, subscriber);

        log.info("Sending 5G SE AV for SUPI {}", subscriber.getSupi());

        return new UeAuthenticationInitResult(sessionId, autn, rand, hXResStar, urlEnc);
    }

    public UeAuthenticationConfirmResult nAusfUeAuthenticationConfirm(String sessionId, byte[] resStar, byte[] respUrl)
    throws UeaAuthenticationException, UeaIllegalStateException
    {
        log.trace(
            "nAusfUeAuthenticationConfirm(sessionId = {}, resStar = {}, respUrl = {})",
            () -> sessionId,
            () -> hex.formatHex(resStar),
            () -> hex.formatHex(respUrl)
        );

        HnSubscriberContext subscriber = sessions.get(sessionId);

        if (subscriber == null) {
            log.debug("No active session for {}", sessionId);

            throw new UeaIllegalStateException("No active session");
        }

        byte[] xResStar = subscriber.getXResStar();

        log.debug(
            "Comparing RES* = {} XRES* = {}",
            () -> hex.formatHex(resStar),
            () -> hex.formatHex(xResStar)
        );

        if (!Arrays.constantTimeAreEqual(xResStar.length, xResStar, 0, resStar, 0))
            throw new UeaAuthenticationException("RES* mismatch");

        String url;

        try {
            url = FiveGByoi.decryptUrl(subscriber.getEk(), respUrl);
        } catch (FiveGByoiException e) {
            log.debug("Unable to decrypt URL", e);

            throw new UeaAuthenticationException("Unable to confirm subscriber ID");
        }

        log.debug("Decrypted RedirectURI = {}", url);

        try {
            subscriber.getOAuthSession().readAuthenticationResponse(url);
        } catch (OAuthSessionException e) {
            log.debug("Invalid authentication response", e);

            throw new UeaAuthenticationException("Unable to confirm subscriber ID");
        }

        String tokenReqUrl  = subscriber.getOAuthSession().getTokenRequestUrl();
        String tokenReqBody = subscriber.getOAuthSession().getTokenRequestBody();

        log.debug("Send to Token Server: POST {} {}", tokenReqUrl, tokenReqBody);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(tokenReqUrl))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(tokenReqBody))
            .build();

        HttpResponse<String> response;

        try {
            response = httpClient.send(request,  HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            log.debug("Unable to request Access Token", e);

            throw new UeaAuthenticationException("Unable to confirm subscriber ID");
        }

        if (response.statusCode() != 200) {
            log.debug("Access Token request returned HTTP status {}", response.statusCode());

            throw new UeaAuthenticationException("Unable to confirm subscriber ID");
        }

        log.debug("Received from Token Server: Access Token = {}", response.body());

        try {
            subscriber.getOAuthSession().readTokenResponse(response.body());
        } catch (OAuthSessionException e) {
            log.warn("Invalid Access Token response", e);

            throw new UeaAuthenticationException("Unable to confirm subscriber ID");
        }

        log.debug("Authenticated subscriber {}", subscriber.getOAuthSession().getSubscriber());

        return new UeAuthenticationConfirmResult(
            subscriber.getSupi(),
            subscriber.getKSeaf()
        );
    }

    private static byte[] generateRand()
    {
        byte[] rand = new byte[Milenage.RAND_LEN_BYTES];

        sr.nextBytes(rand);

        log.trace("generateRand() = {}", () -> hex.formatHex(rand));

        return rand;
    }

    private Supi decryptSuci(String suci)
    throws UeaUnknownSubscriberException
    {
        Suci decrypted;

        try {
            decrypted = Suci.fromEncrypted(suci, suciKeys);
        } catch(FormatException | SuciEncryptionException e) {
            throw new UeaUnknownSubscriberException("Unable to parse SUCI", e);
        }

        log.trace("decryptSuci({}) = {}", suci, decrypted.getSupi());

        return decrypted.getSupi();
    }

    private HnSubscriberContext getSubscriber(String fivegsMobileIdentity)
    throws UeaUnknownSubscriberException
    {
        Supi supi = decryptSuci(fivegsMobileIdentity);

        if (!(supi instanceof ImsiSupi))
            throw new UeaUnknownSubscriberException("Unsupported SUCI type (only an IMSI-based SUCIs are supported)");

        String mccDashMnc = supi.getHnId();
        String msin       = supi.getUserId();

        if (!mccDashMnc.equals(getHnId()))
            throw new UeaUnknownSubscriberException("Subscriber does not exist");

        HnSubscriberContext subscriber = subscribers.get(msin);

        if (subscriber == null)
            throw new UeaUnknownSubscriberException("Subscriber does not exist");

        log.trace("getSubscriber({}-{}) = {}", mccDashMnc, msin, subscriber.getSupi());

        return subscriber;
    }

    private OAuthSession startOAuthSession(String byoiIdentity)
    throws UeaAuthenticationException, UeaUnknownSubscriberException
    {
        Supi supi = decryptSuci(byoiIdentity);

        if (!(supi instanceof NsiSupi))
            throw new UeaUnknownSubscriberException("Unsupported SUCI type (need an NSI-based SUCI for BYOI)");

        String hostname = supi.getHnId();

        log.trace("startOAuthSession({})", hostname);

        OAuthProvider provider = authenticators.get(hostname);

        if (provider == null)
            throw new UeaAuthenticationException(String.format("Unknown OAuth2.0 provider: %s", hostname));

        return provider.createSession();
    }
}
