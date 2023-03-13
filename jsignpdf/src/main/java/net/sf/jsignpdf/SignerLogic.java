/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is 'JSignPdf, a free application for PDF signing'.
 *
 * The Initial Developer of the Original Code is Josef Cacek.
 * Portions created by Josef Cacek are Copyright (C) Josef Cacek. All Rights Reserved.
 *
 * Contributor(s): Josef Cacek.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU Lesser General Public License, version 2.1 (the  "LGPL License"), in which case the
 * provisions of LGPL License are applicable instead of those
 * above. If you wish to allow use of your version of this file only
 * under the terms of the LGPL License and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the LGPL License. If you do not delete
 * the provisions above, a recipient may use your version of this file
 * under either the MPL or the LGPL License.
 */
package net.sf.jsignpdf;

import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_CONTACT;
import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_LOCATION;
import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_REASON;
import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_SIGNER;
import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_TIMESTAMP;
import static net.sf.jsignpdf.Constants.L2TEXT_PLACEHOLDER_CERTIFICATE;
import static net.sf.jsignpdf.Constants.RES;
import static net.sf.jsignpdf.Constants.LOGGER;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;

import com.lowagie.text.pdf.*;
import net.sf.jsignpdf.crl.CRLInfo;
import net.sf.jsignpdf.extcsp.CloudFoxy;
import net.sf.jsignpdf.ssl.SSLInitializer;
import net.sf.jsignpdf.types.HashAlgorithm;
import net.sf.jsignpdf.types.PDFEncryption;
import net.sf.jsignpdf.types.PdfVersion;
import net.sf.jsignpdf.types.RenderMode;
import net.sf.jsignpdf.types.ServerAuthentication;
import net.sf.jsignpdf.utils.FontUtils;
import net.sf.jsignpdf.utils.KeyStoreUtils;
import net.sf.jsignpdf.utils.PKCS11Utils;

import net.sf.jsignpdf.utils.PdfUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;

import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
//import com.lowagie.text.pdf.TSAClientBouncyCastle;
//import com.lowagie.text.pdf.PdfPKCS7;

/**
 * Main logic of signer application. It uses iText to create signature in PDF.
 *
 * @author Josef Cacek
 */
public class SignerLogic implements Runnable {

    private final BasicSignerOptions options;

    /**
     * Constructor with all necessary parameters.
     *
     * @param anOptions options of signer
     */
    public SignerLogic(final BasicSignerOptions anOptions) {
        if (anOptions == null) {
            throw new NullPointerException("Options has to be filled.");
        }
        options = anOptions;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Runnable#run()
     */
    @Override
    public void run() {
        signFile();
    }

    /**
     * Signs a single file.
     *
     * @return true when signing is finished succesfully, false otherwise
     */
    public boolean signFile() {
        final String outFile = options.getOutFileX();
        if (!validateInOutFiles(options.getInFile(), outFile)) {
            LOGGER.info(RES.get("console.skippingSigning"));
            return false;
        }

        boolean finished = false;
        Throwable tmpException = null;
        FileOutputStream fout = null;
        try {
            SSLInitializer.init(options);

            final PrivateKeyInfo pkInfo;
            final PrivateKey key;
            final Certificate[] chain;
            // the 'cloudfoxy' crypto provider computes signatures externally and there are
            // no
            // certificates or keys available via Java CSPs -> they have to be pulled from
            // an
            // external source in 2 steps: 1. certificate chain, 2. signature itself
            if (StringUtils.equalsIgnoreCase(options.getKsType(), Constants.KEYSTORE_TYPE_CLOUDFOXY)) {
                key = null;
                chain = CloudFoxy.getInstance().getChain(this.options);
                if (chain == null) {
                    return false;
                }
            } else {
                pkInfo = KeyStoreUtils.getPkInfo(options);
                key = pkInfo.getKey();
                chain = pkInfo.getChain();
            }

            if (ArrayUtils.isEmpty(chain)) {
                // the certificate was not found
                LOGGER.info(RES.get("console.certificateChainEmpty"));
                return false;
            }
            LOGGER.info(RES.get("console.createPdfReader", options.getInFile()));
            PdfReader reader;
            try {
                reader = new PdfReader(options.getInFile(), options.getPdfOwnerPwdStrX().getBytes());
            } catch (Exception e) {
                try {
                    reader = new PdfReader(options.getInFile(), new byte[0]);
                } catch (Exception e2) {
                    // try to read without password
                    reader = new PdfReader(options.getInFile());
                }
            }

            LOGGER.info(RES.get("console.createOutPdf", outFile));
            fout = new FileOutputStream(outFile);

            final HashAlgorithm hashAlgorithm = options.getHashAlgorithmX();

            LOGGER.info(RES.get("console.createSignature"));
            char tmpPdfVersion = '\0'; // default version - the same as input
            char inputPdfVersion = reader.getPdfVersion();
            char requiredPdfVersionForGivenHash = hashAlgorithm.getPdfVersion().getCharVersion();
            if (inputPdfVersion < requiredPdfVersionForGivenHash) {
                // this covers also problems with visible signatures (embedded
                // fonts) in PDF 1.2, because the minimal version
                // for hash algorithms is 1.3 (for SHA1)
                if (options.isAppendX()) {
                    // if we are in append mode and version should be updated
                    // then return false (not possible)
                    LOGGER.info(RES.get("console.updateVersionNotPossibleInAppendModeForGivenHash", hashAlgorithm.getAlgorithmName(), hashAlgorithm.getPdfVersion().getVersionName(), PdfVersion.fromCharVersion(inputPdfVersion).getVersionName(), HashAlgorithm.valuesWithPdfVersionAsString()));
                    return false;
                }
                tmpPdfVersion = requiredPdfVersionForGivenHash;
                LOGGER.info(RES.get("console.updateVersion", new String[]{String.valueOf(inputPdfVersion), String.valueOf(tmpPdfVersion)}));
            }

            final PdfStamper stp = PdfStamper.createSignature(reader, fout, tmpPdfVersion, null, options.isAppendX());
            if (!options.isAppendX()) {
                // we are not in append mode, let's remove existing signatures
                // (otherwise we're getting to troubles)
                final AcroFields acroFields = stp.getAcroFields();
                @SuppressWarnings("unchecked") final List<String> sigNames = acroFields.getSignatureNames();
                for (String sigName : sigNames) {
                    acroFields.removeField(sigName);
                }
            }
            if (options.isAdvanced() && options.getPdfEncryption() != PDFEncryption.NONE) {
                LOGGER.info(RES.get("console.setEncryption"));
                final int tmpRight = options.getRightPrinting().getRight() | (options.isRightCopy() ? PdfWriter.ALLOW_COPY : 0) | (options.isRightAssembly() ? PdfWriter.ALLOW_ASSEMBLY : 0) | (options.isRightFillIn() ? PdfWriter.ALLOW_FILL_IN : 0) | (options.isRightScreanReaders() ? PdfWriter.ALLOW_SCREENREADERS : 0) | (options.isRightModifyAnnotations() ? PdfWriter.ALLOW_MODIFY_ANNOTATIONS : 0) | (options.isRightModifyContents() ? PdfWriter.ALLOW_MODIFY_CONTENTS : 0);
                switch (options.getPdfEncryption()) {
                    case PASSWORD:
                        stp.setEncryption(true, options.getPdfUserPwdStr(), options.getPdfOwnerPwdStrX(), tmpRight);
                        break;
                    case CERTIFICATE:
                        final X509Certificate encCert = KeyStoreUtils.loadCertificate(options.getPdfEncryptionCertFile());
                        if (encCert == null) {
                            LOGGER.severe(RES.get("console.pdfEncError.wrongCertificateFile", StringUtils.defaultString(options.getPdfEncryptionCertFile())));
                            return false;
                        }
                        if (!KeyStoreUtils.isEncryptionSupported(encCert)) {
                            LOGGER.severe(RES.get("console.pdfEncError.cantUseCertificate", encCert.getSubjectDN().getName()));
                            return false;
                        }
                        stp.setEncryption(new Certificate[]{encCert}, new int[]{tmpRight}, PdfWriter.ENCRYPTION_AES_128);
                        break;
                    default:
                        LOGGER.severe(RES.get("console.unsupportedEncryptionType"));
                        return false;
                }
            }

            final PdfSignatureAppearance sap = stp.getSignatureAppearance();
            sap.setCrypto(key, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
            final String reason = options.getReason();
            if (StringUtils.isNotEmpty(reason)) {
                LOGGER.info(RES.get("console.setReason", reason));
                sap.setReason(reason);
            }
            final String location = options.getLocation();
            if (StringUtils.isNotEmpty(location)) {
                LOGGER.info(RES.get("console.setLocation", location));
                sap.setLocation(location);
            }
            final String contact = options.getContact();
            if (StringUtils.isNotEmpty(contact)) {
                LOGGER.info(RES.get("console.setContact", contact));
                sap.setContact(contact);
            }
            LOGGER.info(RES.get("console.setCertificationLevel"));
            sap.setCertificationLevel(options.getCertLevelX().getLevel());

            if (options.isVisible()) {
                // visible signature is enabled
                LOGGER.info(RES.get("console.configureVisible"));
                LOGGER.info(RES.get("console.setAcro6Layers", Boolean.toString(options.isAcro6Layers())));
                sap.setAcro6Layers(options.isAcro6Layers());

                final String tmpImgPath = options.getImgPath();
                if (tmpImgPath != null) {
                    LOGGER.info(RES.get("console.createImage", tmpImgPath));
                    final Image img = Image.getInstance(tmpImgPath);
                    LOGGER.info(RES.get("console.setSignatureGraphic"));
                    sap.setSignatureGraphic(img);
                }
                final String tmpBgImgPath = options.getBgImgPath();
                if (tmpBgImgPath != null) {
                    LOGGER.info(RES.get("console.createImage", tmpBgImgPath));
                    final Image img = Image.getInstance(tmpBgImgPath);
                    LOGGER.info(RES.get("console.setImage"));
                    sap.setImage(img);
                }
                LOGGER.info(RES.get("console.setImageScale"));
                sap.setImageScale(options.getBgImgScale());
                LOGGER.info(RES.get("console.setL2Text"));
                String signer = PdfPKCS7.getSubjectFields((X509Certificate) chain[0]).getField("CN");
                if (StringUtils.isNotEmpty(options.getSignerName())) {
                    signer = options.getSignerName();
                }
                final String certificate = PdfPKCS7.getSubjectFields((X509Certificate) chain[0]).toString();
                final String timestamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(sap.getSignDate().getTime());
                if (options.getL2Text() != null) {
                    final Map<String, String> replacements = new HashMap<String, String>();
                    replacements.put(L2TEXT_PLACEHOLDER_SIGNER, StringUtils.defaultString(signer));
                    replacements.put(L2TEXT_PLACEHOLDER_CERTIFICATE, certificate);
                    replacements.put(L2TEXT_PLACEHOLDER_TIMESTAMP, timestamp);
                    replacements.put(L2TEXT_PLACEHOLDER_LOCATION, StringUtils.defaultString(location));
                    replacements.put(L2TEXT_PLACEHOLDER_REASON, StringUtils.defaultString(reason));
                    replacements.put(L2TEXT_PLACEHOLDER_CONTACT, StringUtils.defaultString(contact));
                    final String l2text = StrSubstitutor.replace(options.getL2Text(), replacements);
                    sap.setLayer2Text(l2text);
                } else {
                    final StringBuilder buf = new StringBuilder();
                    buf.append(RES.get("default.l2text.signedBy")).append(" ").append(signer).append('\n');
                    buf.append(RES.get("default.l2text.date")).append(" ").append(timestamp);
                    if (StringUtils.isNotEmpty(reason))
                        buf.append('\n').append(RES.get("default.l2text.reason")).append(" ").append(reason);
                    if (StringUtils.isNotEmpty(location))
                        buf.append('\n').append(RES.get("default.l2text.location")).append(" ").append(location);
                    sap.setLayer2Text(buf.toString());
                }
                if (FontUtils.getL2BaseFont() != null) {
                    sap.setLayer2Font(new Font(FontUtils.getL2BaseFont(), options.getL2TextFontSize()));
                }
                LOGGER.info(RES.get("console.setL4Text"));
                sap.setLayer4Text(options.getL4Text());
                LOGGER.info(RES.get("console.setRender"));
                RenderMode renderMode = options.getRenderMode();
                if (renderMode == RenderMode.GRAPHIC_AND_DESCRIPTION && sap.getSignatureGraphic() == null) {
                    LOGGER.warning("Render mode of visible signature is set to GRAPHIC_AND_DESCRIPTION, but no image is loaded. Fallback to DESCRIPTION_ONLY.");
                    LOGGER.info(RES.get("console.renderModeFallback"));
                    renderMode = RenderMode.DESCRIPTION_ONLY;
                }
                sap.setRender(renderMode.getRender());
                LOGGER.info(RES.get("console.setVisibleSignature"));
                int page = options.getPage();
                if (page < 1 || page > reader.getNumberOfPages()) {
                    page = reader.getNumberOfPages();
                }
                sap.setVisibleSignature(new Rectangle(options.getPositionLLX(), options.getPositionLLY(), options.getPositionURX(), options.getPositionURY()), page, null);
            }

            LOGGER.info(RES.get("console.processing"));
            final PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
            if (!StringUtils.isEmpty(reason)) {
                dic.setReason(sap.getReason());
            }
            if (!StringUtils.isEmpty(location)) {
                dic.setLocation(sap.getLocation());
            }
            if (!StringUtils.isEmpty(contact)) {
                dic.setContact(sap.getContact());
            }
            dic.setDate(new PdfDate(sap.getSignDate()));
            sap.setCryptoDictionary(dic);

            final Proxy tmpProxy = options.createProxy();

            final CRLInfo crlInfo = new CRLInfo(options, chain);

            // CRLs are stored twice in PDF c.f.
            // net.sf.jsignpdf.CustomPdfPKCS7.getAuthenticatedAttributeBytes
            final int contentEstimated = (int) (Constants.DEFVAL_SIG_SIZE + 2L * crlInfo.getByteCount());
            final Map<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
            sap.preClose(exc);

            String provider = PKCS11Utils.getProviderNameForKeystoreType(options.getKsType());
            PdfPKCS7 sgn = new PdfPKCS7(key, chain, crlInfo.getCrls(), hashAlgorithm.getAlgorithmName(), provider, false);
            InputStream data = sap.getRangeStream();
            final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithmName());
            byte buf[] = new byte[8192];
            int n;
            while ((n = data.read(buf)) > 0) {
                messageDigest.update(buf, 0, n);
            }
            byte hash[] = messageDigest.digest();
            Calendar cal = Calendar.getInstance();
            byte[] ocsp = null;
            if (options.isOcspEnabledX() && chain.length >= 2) {
                LOGGER.info(RES.get("console.getOCSPURL"));
                String url = PdfPKCS7.getOCSPURL((X509Certificate) chain[0]);
                if (StringUtils.isEmpty(url)) {
                    // get from options
                    LOGGER.info(RES.get("console.noOCSPURL"));
                    url = options.getOcspServerUrl();
                }
                if (!StringUtils.isEmpty(url)) {
                    LOGGER.info(RES.get("console.readingOCSP", url));
                    final OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle((X509Certificate) chain[0], (X509Certificate) chain[1], url);
                    ocspClient.setProxy(tmpProxy);
                    ocsp = ocspClient.getEncoded();
                }
            }
            byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);

            // THIS IS THE SIGNING, we need to have a new branch for external signers
            if (StringUtils.equalsIgnoreCase(options.getKsType(), Constants.KEYSTORE_TYPE_CLOUDFOXY)) {
                byte[] signature = CloudFoxy.getInstance().getSignature(options, sh);
                if (signature == null) {
                    return false;
                } else {
                    sgn.setExternalDigest(signature, null, "RSA");
                }
            } else {
                sgn.update(sh, 0, sh.length);
            }

            /*update Sign Date*/
            sgn.setSignDate(Calendar.getInstance());

            TSAClientBouncyCastle tsc = null;
            if (options.isTimestampX() && !StringUtils.isEmpty(options.getTsaUrl())) {
                LOGGER.info(RES.get("console.creatingTsaClient"));
                if (options.getTsaServerAuthn() == ServerAuthentication.PASSWORD) {
                    tsc = new TSAClientBouncyCastle(options.getTsaUrl(), StringUtils.defaultString(options.getTsaUser()), StringUtils.defaultString(options.getTsaPasswd()));
                } else {
                    tsc = new TSAClientBouncyCastle(options.getTsaUrl());

                }
                final String tsaHashAlg = options.getTsaHashAlgWithFallback();
                LOGGER.info(RES.get("console.settingTsaHashAlg", tsaHashAlg));
                tsc.setDigestName(tsaHashAlg);
                tsc.setProxy(tmpProxy);
                final String policyOid = options.getTsaPolicy();
                if (StringUtils.isNotEmpty(policyOid)) {
                    LOGGER.info(RES.get("console.settingTsaPolicy", policyOid));
                    tsc.setPolicy(policyOid);
                }
            }

            /*set API Key*/
            if (options.hasApiKey()) {
                assert tsc != null;
                tsc.setApiKey(options.getApiKey());
            }

            /*set Secret Key*/
            if (options.hasSecretKey()) {
                assert tsc != null;
                tsc.setSecretKey(options.getSecretKey());
            }

            byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);

            if (contentEstimated + 2 < encodedSig.length) {
                System.err.println("SigSize - contentEstimated=" + contentEstimated + ", sigLen=" + encodedSig.length);
                throw new Exception("Not enough space");
            }

            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            LOGGER.info(RES.get("console.closeStream"));
            sap.close(dic2);
            fout.close();
            fout = null;
            finished = true;

            /*padded sig*/
//            System.out.println("Padded Sig:");
//            System.out.println(SignerLogic.getHex(paddedSig));

//            String dataToSave = "";
//            dataToSave += "{";
//
//            System.out.println("Sign Date:");
//            System.out.println(sgn.getTimeStampDate().getTime().getTime());
//
//            dataToSave += "\"timestamp\":" + sgn.getTimeStampDate().getTimeInMillis() + ",";
//            dataToSave += "\n";
//
//            System.out.println("Digest Algorithm:");
//            System.out.println(sgn.getDigestAlgorithm());
//
//
//            System.out.println("Hash Algorithm:");
//            System.out.println(sgn.getHashAlgorithm());
//
////            dataToSave += "\"hashAlgorithm\":" + sgn.getHashAlgorithm() + "\",";
////            dataToSave += "\n";
//
//            System.out.println("Signature Algorithm:");
//            System.out.println(PdfPKCS7.getAlgorithm(sgn.digestEncryptionAlgorithm));
//
//            dataToSave += "\"signatureAlgorithm\":\"" + PdfPKCS7.getAlgorithm(sgn.digestEncryptionAlgorithm) + "\",";
//            dataToSave += "\n";
//
//            System.out.println("Digest:");
//            System.out.println(SignerLogic.getHex(sgn.digest));
//
//            dataToSave += "\"signature\":\"" + SignerLogic.getHex(sgn.digest) + "\",";
//            dataToSave += "\n";
//
//            System.out.println("Sig Attr:");
//            System.out.println(Arrays.toString(sgn.sigAttr));
//
//            System.out.println("x509Certificate:");
//            System.out.println(getHex(sgn.getSigningCertificate().getEncoded()));
//
//            dataToSave += "\"x509Certificate\":\"" + getHex(sgn.getSigningCertificate().getEncoded()) + "\"";
//            dataToSave += "\n";
//
//            dataToSave += "}";
//
//            Files.write(Paths.get(outFile.replace(".pdf", "_extra.txt")), dataToSave.getBytes(StandardCharsets.UTF_8));

            extract(outFile);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, RES.get("console.exception"), e);
        } catch (OutOfMemoryError e) {
            LOGGER.log(Level.SEVERE, RES.get("console.memoryError"), e);
        } finally {
            if (fout != null) {
                try {
                    fout.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            LOGGER.info(RES.get("console.finished." + (finished ? "ok" : "error")));
            options.fireSignerFinishedEvent(tmpException);
        }
        return finished;
    }

    /**
     * Validates if input and output files are valid for signing.
     *
     * @param inFile  input file
     * @param outFile output file
     * @return true if valid, false otherwise
     */
    private boolean validateInOutFiles(final String inFile, final String outFile) {
        LOGGER.info(RES.get("console.validatingFiles"));
        if (StringUtils.isEmpty(inFile) || StringUtils.isEmpty(outFile)) {
            LOGGER.info(RES.get("console.fileNotFilled.error"));
            return false;
        }
        final File tmpInFile = new File(inFile);
        final File tmpOutFile = new File(outFile);
        if (!(tmpInFile.exists() && tmpInFile.isFile() && tmpInFile.canRead())) {
            LOGGER.info(RES.get("console.inFileNotFound.error"));
            return false;
        }
        if (tmpInFile.getAbsolutePath().equals(tmpOutFile.getAbsolutePath())) {
            LOGGER.info(RES.get("console.filesAreEqual.error"));
            return false;
        }
        return true;
    }

    private static final String HEXES = "0123456789ABCDEF";

    static String getHex(byte[] raw) {
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    public static void extract(String pdf) throws Exception {
        String dataToSave = "";

        dataToSave += "[";

        List<X509Certificate> certificates = new ArrayList<>();
        System.out.println("pdf name: " + pdf);
        MessageDigest digestSHA256 = MessageDigest.getInstance("SHA-256");

//        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();

        try (PdfReader reader = new PdfReader(pdf)) {
            AcroFields fields = reader.getAcroFields();

            List<String> signatures = fields.getSignedFieldNames();
            System.out.println("Signs: " + signatures.size());
            for (String signature : signatures) {
                int index = signatures.indexOf(signature);

                dataToSave += "{";

                System.out.println("Signature name: " + signature);
                System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(signature));
                System.out.println("Document revision: " + fields.getRevision(signature) + " of " + fields.getTotalRevisions());

                dataToSave += "\"Name\":\"" + signature + "\",";
                dataToSave += "\"Revision\":" + fields.getRevision(signature) + ",";
                dataToSave += "\"TotalRevision\":" + fields.getTotalRevisions() + ",";

                /*VERIFYING SIGNATURE*/
                PdfPKCS7 custPk;

                String provider = null;

                PdfDictionary v = fields.getSignatureDictionary(signature);

                PdfName sub = v.getAsName(PdfName.SUBFILTER);
                PdfString contents = v.getAsString(PdfName.CONTENTS);
                if (sub.equals(PdfName.ADBE_X509_RSA_SHA1)) {
                    PdfString cert = v.getAsString(PdfName.CERT);
                    custPk = new PdfPKCS7(contents.getOriginalBytes(), cert.getBytes(), provider);
                } else {
                    custPk = new PdfPKCS7(contents.getOriginalBytes(), provider);
                }
                updateByteRange(custPk, v, reader);
                PdfString str = v.getAsString(PdfName.M);
                if (str != null) {
                    custPk.setSignDate(PdfDate.decode(str.toString()));
                }
                PdfObject obj = PdfReader.getPdfObject(v.get(PdfName.NAME));
                if (obj != null) {
                    if (obj.isString()) {
                        custPk.setSignName(((PdfString) obj).toUnicodeString());
                    } else if (obj.isName()) {
                        custPk.setSignName(PdfName.decodeName(obj.toString()));
                    }
                }
                str = v.getAsString(PdfName.REASON);
                if (str != null) {
                    custPk.setReason(str.toUnicodeString());
                }
                str = v.getAsString(PdfName.LOCATION);
                if (str != null) {
                    custPk.setLocation(str.toUnicodeString());
                }
                /*end*/

                Calendar cal = custPk.getSignDate();
                Certificate[] pkc = custPk.getCertificates();

                X509Certificate certificate = custPk.getSigningCertificate();
                certificates.add(certificate);

                System.out.println("Sign date:" + cal.getTime());
                System.out.println("Subject: " + PdfPKCS7.getSubjectFields(certificate));
                System.out.println("Digest:" + getHex(digestSHA256.digest((custPk.sigAttr))));
                System.out.println("Signature:" + getHex(custPk.digest));

                System.out.println("Document modified: " + !custPk.verify());
                System.out.println("Timestamp date: " + custPk.getTimeStampDate().getTimeInMillis());
                System.out.println("Timestamp valid: " + custPk.verifyTimestampImprint());
                System.out.println("x509Certificate: " + getHex(certificate.getEncoded()));

                dataToSave += "\"SignDate\":\"" + cal.getTime() + "\",";
                dataToSave += "\"Subject\":\"" + PdfPKCS7.getSubjectFields(certificate).toString() + "\",";
                dataToSave += "\"Digest\":\"" + getHex(digestSHA256.digest((custPk.sigAttr))) + "\",";
                dataToSave += "\"Signature\":\"" + getHex(custPk.digest) + "\",";
                dataToSave += "\"DocumentModified\":" + !custPk.verify() + ",";
                dataToSave += "\"TimestampDate\":" + custPk.getTimeStampDate().getTimeInMillis() + ",";
                dataToSave += "\"TimestampValid\":" + custPk.verifyTimestampImprint() + ",";
                dataToSave += "\"x509Certificate\":\"" + getHex(certificate.getEncoded()) + "\"";

                KeyStore kall = PdfPKCS7.loadCacertsKeyStore();
                Object[] fails = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
                if (fails == null) {
                    System.out.println("Certificates verified against the KeyStore");
                } else {
                    System.out.println("Certificate failed: " + fails[1]);
                }
                System.out.println("----------------------------------------------------");


                dataToSave += "}";

                if (index < signatures.size() - 1) {
                    dataToSave += ",";
                }

            }

            dataToSave += "]";
            Files.write(Paths.get(pdf.replace(".pdf", "_extra.txt")), dataToSave.getBytes(StandardCharsets.UTF_8));
        }


    }

    private static void updateByteRange(PdfPKCS7 pkcs7, PdfDictionary v, PdfReader reader) {
        PdfArray b = v.getAsArray(PdfName.BYTERANGE);
        RandomAccessFileOrArray rf = reader.getSafeFile();
        try {
            rf.reOpen();
            byte[] buf = new byte[8192];
            for (int k = 0; k < b.size(); ++k) {
                int start = b.getAsNumber(k).intValue();
                int length = b.getAsNumber(++k).intValue();
                rf.seek(start);
                while (length > 0) {
                    int rd = rf.read(buf, 0, Math.min(length, buf.length));
                    if (rd <= 0) {
                        break;
                    }
                    length -= rd;
                    pkcs7.update(buf, 0, rd);
                }
            }
        } catch (Exception e) {

        } finally {
            try {
                rf.close();
            } catch (Exception e) {
            }
        }
    }
}
