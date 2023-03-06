/*
 * Copyright 2004 by Paulo Soares.
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
 * the Initial Developer are Copyright (C) 1999, 2000, 2001, 2002 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000, 2001, 2002 by Paulo Soares. All Rights Reserved.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.lowagie.text.pdf.TSAClient;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

import com.lowagie.text.ExceptionConverter;

/**
 * This class does all the processing related to signing and verifying a PKCS#7
 * signature.
 * <p>
 * It's based in code found at org.bouncycastle.
 */
public class CustomPdfPKCS7 extends com.lowagie.text.pdf.PdfPKCS7 {

    private byte[] sigAttr;
    private byte[] digestAttr;
    private int version, signerversion;
    private Set<String> digestalgos;
    private final List<Certificate> certs;
    private List<Certificate> signCerts;
    private final List<CRL> crls;
    private X509Certificate signCert;
    private byte[] digest;
    private MessageDigest messageDigest;
    private String digestAlgorithm, digestEncryptionAlgorithm;
    private Signature sig;
    private transient PrivateKey privKey;
    private byte[] RSAdata;
    private boolean verified;
    private boolean verifyResult;
    private byte[] externalDigest;
    private byte[] externalRSAdata;
    private final String provider;

    private static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";
    private static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";
    private static final String ID_RSA = "1.2.840.113549.1.1.1";
    private static final String ID_DSA = "1.2.840.10040.4.1";
    private static final String ID_ECDSA = "1.2.840.10045.2.1";
    private static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
    private static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";
    /**
     * Holds value of property reason.
     */
    private String reason;

    /**
     * Holds value of property location.
     */
    private String location;

    /**
     * Holds value of property signDate.
     */
    private Calendar signDate;

    /**
     * Holds value of property signName.
     */
    private String signName;

    private TimeStampToken timeStampToken;

    private static final Map<String, String> digestNames = new HashMap<>();
    private static final Map<String, String> algorithmNames = new HashMap<>();
    private static final Map<String, String> allowedDigests = new HashMap<>();

    static {
        digestNames.put("1.2.840.113549.2.5", "MD5");
        digestNames.put("1.2.840.113549.2.2", "MD2");
        digestNames.put("1.3.14.3.2.26", "SHA1");
        digestNames.put("2.16.840.1.101.3.4.2.4", "SHA224");
        digestNames.put("2.16.840.1.101.3.4.2.1", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.2.2", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.2.3", "SHA512");
        digestNames.put("1.3.36.3.2.2", "RIPEMD128");
        digestNames.put("1.3.36.3.2.1", "RIPEMD160");
        digestNames.put("1.3.36.3.2.3", "RIPEMD256");
        digestNames.put("1.2.840.113549.1.1.4", "MD5");
        digestNames.put("1.2.840.113549.1.1.2", "MD2");
        digestNames.put("1.2.840.113549.1.1.5", "SHA1");
        digestNames.put("1.2.840.113549.1.1.14", "SHA224");
        digestNames.put("1.2.840.113549.1.1.11", "SHA256");
        digestNames.put("1.2.840.113549.1.1.12", "SHA384");
        digestNames.put("1.2.840.113549.1.1.13", "SHA512");
        digestNames.put("1.2.840.10040.4.3", "SHA1");    // TODO: bug - duplicate key - overwrites this with DSA
        digestNames.put("2.16.840.1.101.3.4.3.1", "SHA224");  // TODO: bug - duplicate key - overwrites this with DSA
        digestNames.put("2.16.840.1.101.3.4.3.2", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.3.3", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.3.4", "SHA512");
        digestNames.put("1.3.36.3.3.1.3", "RIPEMD128");
        digestNames.put("1.3.36.3.3.1.2", "RIPEMD160");
        digestNames.put("1.3.36.3.3.1.4", "RIPEMD256");

        algorithmNames.put("1.2.840.113549.1.1.1", "RSA");
        algorithmNames.put("1.2.840.10040.4.1", "DSA");
        algorithmNames.put("1.2.840.113549.1.1.2", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.4", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.5", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.14", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.11", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.12", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.13", "RSA");
        algorithmNames.put("1.2.840.10040.4.3", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.1", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.2", "DSA");
        algorithmNames.put("1.3.36.3.3.1.3", "RSA");
        algorithmNames.put("1.3.36.3.3.1.2", "RSA");
        algorithmNames.put("1.3.36.3.3.1.4", "RSA");
        algorithmNames.put(ID_ECDSA, "ECDSA");

        allowedDigests.put("MD5", "1.2.840.113549.2.5");
        allowedDigests.put("MD2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA1", "1.3.14.3.2.26");
        allowedDigests.put("SHA224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("MD-5", "1.2.840.113549.2.5");
        allowedDigests.put("MD-2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA-1", "1.3.14.3.2.26");
        allowedDigests.put("SHA-224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA-256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA-384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA-512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("RIPEMD128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD-128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD-160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD256", "1.3.36.3.2.3");
        allowedDigests.put("RIPEMD-256", "1.3.36.3.2.3");
    }

    public CustomPdfPKCS7(byte[] contentsKey, byte[] certsKey, String provider) {
        super(contentsKey, certsKey, provider);
        crls = (List<CRL>) super.getCRLs();
        this.provider = provider;
        this.certs = Arrays.asList(super.getCertificates());
    }

    public CustomPdfPKCS7(byte[] contentsKey, String provider) {
        super(contentsKey, provider);
        crls = (List<CRL>) super.getCRLs();
        this.provider = provider;
        this.certs = Arrays.asList(super.getCertificates());
    }

    public CustomPdfPKCS7(PrivateKey privKey, Certificate[] certChain, CRL[] crlList, String hashAlgorithm, String provider, boolean hasRSAdata) throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException {
        super(privKey, certChain, crlList, hashAlgorithm, provider, hasRSAdata);
        crls = (List<CRL>) super.getCRLs();
        this.provider = provider;
        this.certs = Arrays.asList(super.getCertificates());
    }

    /**
     * Gets the digest name for a certain id
     *
     * @param oid an id (for instance "1.2.840.113549.2.5")
     * @return a digest name (for instance "MD5")
     * @since 2.1.6
     */
    public static String getDigest(String oid) {
        return Optional.ofNullable(digestNames.get(oid))
                .orElse(oid);
    }

    /**
     * Gets the algorithm name for a certain id.
     *
     * @param oid an id (for instance "1.2.840.113549.1.1.1")
     * @return an algorithm name (for instance "RSA")
     * @since 2.1.6
     */
    public static String getAlgorithm(String oid) {
        return Optional.ofNullable(algorithmNames.get(oid))
                .orElse(oid);
    }

    /**
     * Gets the oid for given digest name.
     *
     * @param digestName digest name (for instance "SHA-256")
     * @return a digest OID (for instance "2.16.840.1.101.3.4.2.1") or {@code null} if the oid for provided name is not found
     */
    public static String getDigestOid(String digestName) {
        return digestName != null ? allowedDigests.get(digestName) : null;
    }

    /**
     * Gets the timestamp token if there is one.
     *
     * @return the timestamp token or null
     * @since 2.1.6
     */
    public TimeStampToken getTimeStampToken() {
        return timeStampToken;
    }

    /**
     * Gets the timestamp date
     *
     * @return a date
     * @since 2.1.6
     */
    public Calendar getTimeStampDate() {
        if (timeStampToken == null)
            return null;
        Calendar cal = new GregorianCalendar();
        Date date = timeStampToken.getTimeStampInfo().getGenTime();
        cal.setTime(date);
        return cal;
    }

    private BasicOCSPResp basicResp;

    private void findOcsp(ASN1Sequence seq) throws IOException {
        basicResp = null;
        while ((!(seq.getObjectAt(0) instanceof ASN1ObjectIdentifier))
                || !((ASN1ObjectIdentifier) seq.getObjectAt(0)).getId().equals(
                OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId())) {
            boolean ret = true;
            int k = 0;
            while (k < seq.size()) {
                if (seq.getObjectAt(k) instanceof ASN1Sequence) {
                    seq = (ASN1Sequence) seq.getObjectAt(0);
                    ret = false;
                    break;
                }
                if (seq.getObjectAt(k) instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tag = (ASN1TaggedObject) seq.getObjectAt(k);
                    if (tag.getObject() instanceof ASN1Sequence) {
                        seq = (ASN1Sequence) tag.getObject();
                        ret = false;
                        break;
                    } else
                        return;
                }
                ++k;
            }
            if (ret)
                return;
        }
        DEROctetString os = (DEROctetString) seq.getObjectAt(1);
        ASN1InputStream inp = new ASN1InputStream(os.getOctets());
        BasicOCSPResponse resp = BasicOCSPResponse.getInstance(inp.readObject());
        basicResp = new BasicOCSPResp(resp);
    }

    private void signCertificateChain() {
        List<Certificate> cc = new ArrayList<>();
        cc.add(signCert);
        List<Certificate> oc = new ArrayList<>(certs);
        for (int k = 0; k < oc.size(); ++k) {
            if (signCert.getSerialNumber().equals(
                    ((X509Certificate) oc.get(k)).getSerialNumber())) {
                oc.remove(k);
                --k;
            }
        }
        boolean found = true;
        while (found) {
            X509Certificate v = (X509Certificate) cc.get(cc.size() - 1);
            found = false;
            for (int k = 0; k < oc.size(); ++k) {
                try {
                    if (provider == null)
                        v.verify(oc.get(k).getPublicKey());
                    else
                        v.verify(oc.get(k).getPublicKey(), provider);
                    found = true;
                    cc.add(oc.get(k));
                    oc.remove(k);
                    break;
                } catch (Exception ignored) {
                }
            }
        }
        signCerts = cc;
    }

    private static ASN1Primitive getExtensionValue(X509Certificate cert,
                                                   String oid) throws IOException {
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }

    private static String getStringFromGeneralName(ASN1Primitive names) {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) names;
        return new String(ASN1OctetString.getInstance(taggedObject, false)
                .getOctets(), StandardCharsets.ISO_8859_1);
    }

    /**
     * Get the "issuer" from the TBSCertificate bytes that are passed in
     *
     * @param enc a TBSCertificate in a byte array
     * @return a ASN1Primitive
     */
    private static ASN1Primitive getIssuer(byte[] enc) {
        try {
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(enc));
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            return (ASN1Primitive) seq
                    .getObjectAt(seq.getObjectAt(0) instanceof ASN1TaggedObject ? 3 : 2);
        } catch (IOException e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Get the "subject" from the TBSCertificate bytes that are passed in
     *
     * @param enc A TBSCertificate in a byte array
     * @return a ASN1Primitive
     */
    private static ASN1Primitive getSubject(byte[] enc) {
        try {
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(enc));
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            return (ASN1Primitive) seq
                    .getObjectAt(seq.getObjectAt(0) instanceof ASN1TaggedObject ? 5 : 4);
        } catch (IOException e) {
            throw new ExceptionConverter(e);
        }
    }


    /**
     * Gets the bytes for the PKCS7SignedData object. Optionally the
     * authenticatedAttributes in the signerInfo can also be set, OR a
     * time-stamp-authority client may be provided.
     *
     * @param secondDigest the digest in the authenticatedAttributes
     * @param signingTime  the signing time in the authenticatedAttributes
     * @param tsaClient    TSAClient - null or an optional time stamp authority client
     * @param ocsp         a byte array
     * @return byte[] the bytes for the PKCS7SignedData object
     * @since 2.1.6
     */
    @Override
    public byte[] getEncodedPKCS7(byte[] secondDigest, Calendar signingTime,
                                  TSAClient tsaClient, byte[] ocsp) {
        try {
            if (externalDigest != null) {
                digest = externalDigest;
                if (RSAdata != null)
                    RSAdata = externalRSAdata;
            } else if (externalRSAdata != null && RSAdata != null) {
                RSAdata = externalRSAdata;
                sig.update(RSAdata);
                digest = sig.sign();
            } else {
                if (RSAdata != null) {
                    RSAdata = messageDigest.digest();
                    sig.update(RSAdata);
                }
                digest = sig.sign();
            }

            // Create the set of Hash algorithms
            ASN1EncodableVector digestAlgorithms = new ASN1EncodableVector();
            for (String digestalgo : digestalgos) {
                ASN1EncodableVector algos = new ASN1EncodableVector();
                algos.add(new ASN1ObjectIdentifier(digestalgo));
                algos.add(DERNull.INSTANCE);
                digestAlgorithms.add(new DERSequence(algos));
            }

            // Create the contentInfo.
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(ID_PKCS7_DATA));
            if (RSAdata != null)
                v.add(new DERTaggedObject(0, new DEROctetString(RSAdata)));
            DERSequence contentinfo = new DERSequence(v);

            // Get all the certificates
            //
            v = new ASN1EncodableVector();
            for (Object cert : certs) {
                ASN1InputStream tempstream = new ASN1InputStream(
                        new ByteArrayInputStream(((X509Certificate) cert).getEncoded()));
                v.add(tempstream.readObject());
            }

            DERSet dercertificates = new DERSet(v);

            // Create signerinfo structure.
            //
            ASN1EncodableVector signerinfo = new ASN1EncodableVector();

            // Add the signerInfo version
            //
            signerinfo.add(new ASN1Integer(signerversion));

            v = new ASN1EncodableVector();
            v.add(getIssuer(signCert.getTBSCertificate()));
            v.add(new ASN1Integer(signCert.getSerialNumber()));
            signerinfo.add(new DERSequence(v));

            // Add the digestAlgorithm
            v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(digestAlgorithm));
            v.add(DERNull.INSTANCE);
            signerinfo.add(new DERSequence(v));

            // add the authenticated attribute if present
            if (secondDigest != null && signingTime != null) {
                signerinfo.add(new DERTaggedObject(false, 0,
                        getAuthenticatedAttributeSet(secondDigest, signingTime, ocsp)));
            }
            // Add the digestEncryptionAlgorithm
            v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(digestEncryptionAlgorithm));
            v.add(DERNull.INSTANCE);
            signerinfo.add(new DERSequence(v));

            // Add the digest
            signerinfo.add(new DEROctetString(digest));

            // When requested, go get and add the timestamp. May throw an exception.
            if (tsaClient != null) {
                byte[] tsImprint = tsaClient.getMessageDigest().digest(digest);
                byte[] tsToken = tsaClient.getTimeStampToken(this, tsImprint);
                if (tsToken != null) {
                    ASN1EncodableVector unauthAttributes = buildUnauthenticatedAttributes(tsToken);
                    if (unauthAttributes != null) {
                        signerinfo.add(new DERTaggedObject(false, 1, new DERSet(
                                unauthAttributes)));
                    }
                }
            }

            // Finally build the body out of all the components above
            ASN1EncodableVector body = new ASN1EncodableVector();
            body.add(new ASN1Integer(version));
            body.add(new DERSet(digestAlgorithms));
            body.add(contentinfo);
            body.add(new DERTaggedObject(false, 0, dercertificates));

            // Only allow one signerInfo
            body.add(new DERSet(new DERSequence(signerinfo)));

            // Now we have the body, wrap it in it's PKCS7Signed shell
            // and return it
            //
            ASN1EncodableVector whole = new ASN1EncodableVector();
            whole.add(new ASN1ObjectIdentifier(ID_PKCS7_SIGNED_DATA));
            whole.add(new DERTaggedObject(0, new DERSequence(body)));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            ASN1OutputStream dout = ASN1OutputStream.create(bOut);
            dout.writeObject(new DERSequence(whole));
            dout.close();

            return bOut.toByteArray();
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Added by Aiken Sam, 2006-11-15, modifed by Martin Brunecky 07/12/2007 to
     * start with the timeStampToken (signedData 1.2.840.113549.1.7.2). Token is
     * the TSA response without response status, which is usually handled by the
     * (vendor supplied) TSA request/response interface).
     *
     * @param timeStampToken byte[] - time stamp token, DER encoded signedData
     * @return ASN1EncodableVector
     * @throws IOException
     */
    private ASN1EncodableVector buildUnauthenticatedAttributes(
            byte[] timeStampToken) throws IOException {
        if (timeStampToken == null)
            return null;

        // @todo: move this together with the rest of the defintions
        String ID_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"; // RFC 3161
        // id-aa-timeStampToken

        ASN1InputStream tempstream = new ASN1InputStream(new ByteArrayInputStream(
                timeStampToken));
        ASN1EncodableVector unauthAttributes = new ASN1EncodableVector();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(ID_TIME_STAMP_TOKEN)); // id-aa-timeStampToken
        ASN1Sequence seq = (ASN1Sequence) tempstream.readObject();
        v.add(new DERSet(seq));

        unauthAttributes.add(new DERSequence(v));
        return unauthAttributes;
    }

    private DERSet getAuthenticatedAttributeSet(byte[] secondDigest,
                                                Calendar signingTime, byte[] ocsp) {
        try {
            ASN1EncodableVector attribute = new ASN1EncodableVector();
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(ID_CONTENT_TYPE));
            v.add(new DERSet(new ASN1ObjectIdentifier(ID_PKCS7_DATA)));
            attribute.add(new DERSequence(v));
            v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(ID_SIGNING_TIME));
            v.add(new DERSet(new DERUTCTime(signingTime.getTime())));
            attribute.add(new DERSequence(v));
            v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(ID_MESSAGE_DIGEST));
            v.add(new DERSet(new DEROctetString(secondDigest)));
            attribute.add(new DERSequence(v));
            if (ocsp != null) {
                v = new ASN1EncodableVector();
                v.add(new ASN1ObjectIdentifier(ID_ADBE_REVOCATION));
                DEROctetString doctet = new DEROctetString(ocsp);
                ASN1EncodableVector vo1 = new ASN1EncodableVector();
                ASN1EncodableVector v2 = new ASN1EncodableVector();
                v2.add(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
                v2.add(doctet);
                ASN1Enumerated den = new ASN1Enumerated(0);
                ASN1EncodableVector v3 = new ASN1EncodableVector();
                v3.add(den);
                v3.add(new DERTaggedObject(true, 0, new DERSequence(v2)));
                vo1.add(new DERSequence(v3));
                v.add(new DERSet(new DERSequence(new DERTaggedObject(true, 1,
                        new DERSequence(vo1)))));
                attribute.add(new DERSequence(v));
            } else if (!crls.isEmpty()) {
                v = new ASN1EncodableVector();
                v.add(new ASN1ObjectIdentifier(ID_ADBE_REVOCATION));
                ASN1EncodableVector v2 = new ASN1EncodableVector();
                for (Object crl : crls) {
                    ASN1InputStream t = new ASN1InputStream(new ByteArrayInputStream(
                            ((X509CRL) crl).getEncoded()));
                    v2.add(t.readObject());
                }
                v.add(new DERSet(new DERSequence(new DERTaggedObject(true, 0,
                        new DERSequence(v2)))));
                attribute.add(new DERSequence(v));
            }
            return new DERSet(attribute);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    private static String getStandardJavaName(String algName) {
        if ("SHA1".equals(algName)) {
            return "SHA-1";
        }
        if ("SHA224".equals(algName)) {
            return "SHA-224";
        }
        if ("SHA256".equals(algName)) {
            return "SHA-256";
        }
        if ("SHA384".equals(algName)) {
            return "SHA-384";
        }
        if ("SHA512".equals(algName)) {
            return "SHA-512";
        }
        return algName;

    }

    public byte[] getDigest() {
        return this.digest;
    }

    public byte[] getSigAttr() {
        return this.sigAttr;
    }
}
