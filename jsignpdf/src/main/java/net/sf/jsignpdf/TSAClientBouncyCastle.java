/*
 * $Id: TSAClientBouncyCastle.java 4065 2009-09-16 23:09:11Z psoares33 $
 *
 * Copyright 2009 Martin Brunecky, Aiken Sam
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999-2005 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2009 by Martin Brunecky. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * https://github.com/LibrePDF/OpenPDF
 */

package net.sf.jsignpdf;

import com.lowagie.text.error_messages.MessageLocalization;
import com.lowagie.text.pdf.TSAClient;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tsp.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

/**
 * Time Stamp Authority Client interface implementation using Bouncy Castle
 * org.bouncycastle.tsp package.
 * <p>
 * Created by Aiken Sam, 2006-11-15, refactored by Martin Brunecky, 07/15/2007
 * for ease of subclassing.
 * </p>
 *
 * @since 2.1.6
 */
public class TSAClientBouncyCastle implements TSAClient {
    /**
     * URL of the Time Stamp Authority
     */
    protected String tsaURL;
    /**
     * TSA Username
     */
    protected String tsaUsername;
    /**
     * TSA password
     */
    protected String tsaPassword;
    /**
     * Estimate of the received time stamp token
     */
    protected int tokSzEstimate;

    private Proxy proxy;
    private String policy;
    private String digestName;

    public String apiKey;

    public String sercetKey;

    public final static String SERVICE_TYPE = "2";

    /**
     * Creates an instance of a TSAClient that will use BouncyCastle.
     *
     * @param url String - Time Stamp Authority URL (i.e.
     *            "http://tsatest1.digistamp.com/TSA")
     */
    public TSAClientBouncyCastle(String url) {
        this(url, null, null, 4096);
    }

    /**
     * Creates an instance of a TSAClient that will use BouncyCastle.
     *
     * @param url      String - Time Stamp Authority URL (i.e.
     *                 "http://tsatest1.digistamp.com/TSA")
     * @param username String - user(account) name
     * @param password String - password
     */
    public TSAClientBouncyCastle(String url, String username, String password) {
        this(url, username, password, 4096);
    }

    /**
     * Constructor. Note the token size estimate is updated by each call, as the
     * token size is not likely to change (as long as we call the same TSA using
     * the same imprint length).
     *
     * @param url           String - Time Stamp Authority URL (i.e.
     *                      "http://tsatest1.digistamp.com/TSA")
     * @param username      String - user(account) name
     * @param password      String - password
     * @param tokSzEstimate int - estimated size of received time stamp token (DER encoded)
     */
    public TSAClientBouncyCastle(String url, String username, String password, int tokSzEstimate) {
        this.tsaURL = url;
        this.tsaUsername = username;
        this.tsaPassword = password;
        this.tokSzEstimate = tokSzEstimate;
    }

    /**
     * Get the token size estimate. Returned value reflects the result of the last
     * succesfull call, padded
     *
     * @return an estimate of the token size
     */
    @Override
    public int getTokenSizeEstimate() {
        return tokSzEstimate;
    }

    /**
     * Get the MessageDigest.
     * Default algorithm `SHA-1` used as per algorithm used without tsaClient
     *
     * @return SHA-1 MessageDigest
     * @see com.lowagie.text.pdf.PdfPKCS7#getEncodedPKCS7(byte[], java.util.Calendar, TSAClient, byte[]) (upto 1.3.11)
     * or check status of https://github.com/LibrePDF/OpenPDF/issues/320
     */
    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return MessageDigest.getInstance(isNotEmpty(digestName) ? digestName : "SHA-1");
    }

    @Override
    public byte[] getTimeStampToken(com.lowagie.text.pdf.PdfPKCS7 caller, byte[] imprint) throws Exception {
        byte[] respBytes = null;
        return respBytes;
    }

    /**
     * Get RFC 3161 timeStampToken. Method may return null indicating that
     * timestamp should be skipped.
     *
     * @param caller  PdfPKCS7 - calling PdfPKCS7 instance (in case caller needs it)
     * @param imprint byte[] - data imprint to be time-stamped
     * @return byte[] - encoded, TSA signed data of the timeStampToken
     * @throws Exception - TSA request failed
     * @see TSAClient#getTimeStampToken(com.lowagie.text.pdf.PdfPKCS7,
     * byte[])
     */
    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint) throws Exception {
        return getTimeStampToken(imprint, caller);
    }

    /**
     * Get timestamp token - Bouncy Castle request encoding / decoding layer
     *
     * @param imprint a byte array containing the imprint
     * @return the timestamp token
     * @throws Exception on error
     */
    protected byte[] getTimeStampToken(byte[] imprint, PdfPKCS7 caller) throws Exception {
        byte[] respBytes = null;
        try {
            // Setup the time stamp request
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.setCertReq(true);
            if (isNotEmpty(policy)) {
                tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(policy));
            }
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            ASN1ObjectIdentifier digestOid = X509ObjectIdentifiers.id_SHA1;
            if (isNotEmpty(digestName)) {
                digestOid = new ASN1ObjectIdentifier(com.lowagie.text.pdf.PdfPKCS7.getDigestOid(digestName));
            }
            TimeStampRequest request = tsqGenerator.generate(digestOid, imprint, nonce);
            byte[] requestBytes = request.getEncoded();

            // Call the communications layer
            respBytes = getTSAResponse(requestBytes);

            // Handle the TSA response
            TimeStampResponse response = new TimeStampResponse(respBytes);

            // validate communication level attributes (RFC 3161 PKIStatus)
            response.validate(request);
            PKIFailureInfo failure = response.getFailInfo();
            int value = (failure == null) ? 0 : failure.intValue();
            if (value != 0) {
                // @todo: Translate value of 15 error codes defined by
                // PKIFailureInfo to string
                throw new Exception(MessageLocalization.getComposedMessage("invalid.tsa.1.response.code.2", tsaURL, String.valueOf(value)));
            }
            // @todo: validate the time stap certificate chain (if we want
            // assure we do not sign using an invalid timestamp).

            // extract just the time stamp token (removes communication status
            // info)
            TimeStampToken tsToken = response.getTimeStampToken();
            if (tsToken == null) {
                throw new Exception(MessageLocalization.getComposedMessage("tsa.1.failed.to.return.time.stamp.token.2", tsaURL, response.getStatusString()));
            }
            TimeStampTokenInfo info = tsToken.getTimeStampInfo(); // to view

            caller.setTimeStampToken(tsToken);
            caller.setSignDate(caller.getTimeStampDate());

            // details
            byte[] encoded = tsToken.getEncoded();
            long stop = System.currentTimeMillis();

            // Update our token size estimate for the next call (padded to be
            // safe)
            this.tokSzEstimate = encoded.length + 32;
            return encoded;
        } catch (Exception e) {
            throw e;
        } catch (Throwable t) {
            throw new Exception(MessageLocalization.getComposedMessage("failed.to.get.tsa.response.from.1", tsaURL), t);
        }
//        byte[] respBytes = null;
//        String httpsURL = this.getTsaURL();
//
//        URL url = new URL(httpsURL);
//
//        /*set request*/
//        HttpURLConnection con = (HttpURLConnection) url.openConnection();
//        con.setRequestMethod("POST");
//        con.setRequestProperty("Content-Type", "application/json");
//        con.setRequestProperty("Accept", "application/json");
//
//        /*set API KEY*/
//        con.setRequestProperty("X-API-KEY", this.apiKey);
//        con.setRequestProperty("ServiceType", SERVICE_TYPE);
//
//        System.out.println(con.getRequestProperties().toString());
//
//        con.setDoOutput(true);
//
//        /*data body*/
//        UUID uuid = UUID.randomUUID();
//        Date today = new Date();
//        LocalDateTime date = LocalDateTime.now();
//        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyMM");
//        MessageDigest digestSHA256 = MessageDigest.getInstance("SHA-256");
//
//
//        String jsonContent = "{\"data\":{\"digest\":\"" + SignerLogic.getHex(imprint) + "\",";
//        jsonContent += "\"algorithm\":\"" + this.getDigestName() + "\"}}";
//
//        String jsonInfo = "{\"version\":\"1.0.0\",\"senderId\":\"C10016ICORP\",\"receiverId\":\"P10001EVERIFY\",\"messageType\":1,";
//        jsonInfo += "\"sendDate\":" + Date.from(date.toInstant(ZoneOffset.UTC)).getTime() + ",";
//        jsonInfo += "\"messageId\":\"" + ("C10016ICORP" + date.format(formatter) + uuid.toString()) + "\"}";
//
//        /*hased info*/
//        byte[] encodedhash = digestSHA256.digest(jsonInfo.getBytes(StandardCharsets.UTF_8));
//        String A = SignerLogic.getHex(encodedhash).toUpperCase();
//
//        /*hashed content*/
//        encodedhash = digestSHA256.digest(jsonContent.getBytes(StandardCharsets.UTF_8));
//        String B = SignerLogic.getHex(encodedhash).toUpperCase();
//
//        String C = A + "." + B;
//
//        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
//        SecretKeySpec secret_key = new SecretKeySpec(this.sercetKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
//        sha256_HMAC.init(secret_key);
//
//
//        String signature = SignerLogic.getHex(sha256_HMAC.doFinal(C.getBytes(StandardCharsets.UTF_8))).toUpperCase();
//
//        String jsonInputString = "{\"content\":" + jsonContent + ",";
//        jsonInputString += "\"info\":" + jsonInfo + ",";
//        jsonInputString += "\"signature\":\"" + signature + "\"}";
//
//        try (OutputStream os = con.getOutputStream()) {
//            byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
//            os.write(input, 0, input.length);
//        }
//
//        String responseLine = "";
//        try (BufferedReader br = new BufferedReader(
//                new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
//            StringBuilder response = new StringBuilder();
//
//            while ((responseLine = br.readLine()) != null) {
//                response.append(responseLine.trim());
//            }
//            System.out.println("CeCA Timestamp response:");
//            System.out.println(response);
//        }
//
//        return responseLine.getBytes();
    }

    /**
     * Get timestamp token - communications layer
     *
     * @param requestBytes the request bytes
     * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
     * @throws Exception on error
     */
    protected byte[] getTSAResponse(byte[] requestBytes) throws Exception {
        // Setup the TSA connection
        URL url = new URL(tsaURL);
        URLConnection tsaConnection;
        Proxy tmpProxy = proxy == null ? Proxy.NO_PROXY : proxy;
        tsaConnection = url.openConnection(tmpProxy);

        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        // tsaConnection.setRequestProperty("Content-Transfer-Encoding",
        // "base64");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

        if (isNotEmpty(tsaUsername)) {
            String userPassword = tsaUsername + ":" + tsaPassword;
            tsaConnection.setRequestProperty("Authorization", "Basic " + new String(Base64.getEncoder().encode(userPassword.getBytes())));
        }
        OutputStream out = tsaConnection.getOutputStream();
        out.write(requestBytes);
        out.close();

        // Get TSA response as a byte array
        InputStream inp = tsaConnection.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }
        byte[] respBytes = baos.toByteArray();

        String encoding = tsaConnection.getContentEncoding();
        if (encoding != null && encoding.equalsIgnoreCase("base64")) {
            respBytes = Base64.getDecoder().decode(respBytes);
        }
        return respBytes;
    }

    /**
     * Sets Proxy which will be used for URL connection.
     *
     * @param aProxy Proxy to set
     */
    public void setProxy(final Proxy aProxy) {
        this.proxy = aProxy;
    }

    /**
     * Returns Proxy object used for URL connections.
     *
     * @return
     */
    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Gets Policy OID of TSA request.
     *
     * @param policy
     */
    public String getPolicy() {
        return policy;
    }

    /**
     * Sets Policy OID of TSA request.
     *
     * @param policy
     */
    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public String getTsaURL() {
        return tsaURL;
    }

    public String getTsaUsername() {
        return tsaUsername;
    }

    public String getTsaPassword() {
        return tsaPassword;
    }

    public int getTokSzEstimate() {
        return tokSzEstimate;
    }

    public String getDigestName() {
        return digestName;
    }

    public void setDigestName(String hashAlgorithm) {
        this.digestName = hashAlgorithm;
    }

    private static boolean isNotEmpty(String arg) {
        return arg != null && !arg.isEmpty();
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setSecretKey(String secretKey) {
        this.sercetKey = secretKey;
    }
}
