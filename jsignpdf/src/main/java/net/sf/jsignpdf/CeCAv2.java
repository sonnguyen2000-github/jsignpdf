package net.sf.jsignpdf;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import net.sf.jsignpdf.utils.PKCS11Utils;

import java.io.*;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static net.sf.jsignpdf.Constants.LOGGER;
import static net.sf.jsignpdf.Constants.RES;

public class CeCAv2 {
    public static final String DOCUMENT_HASHING_ALGORITHM = "SHA256";
    public static final String CERTIFICATE_TYPE = "X.509";
    public static final String SIGNATURE_ENCRYPTION_ALGORITHM = "RSA";

    public static BasicSignerOptions basicSignerOptions;

    /**
     * @param filepath     Đường dẫn file PDF
     * @param trucCertPath Đường dẫn file CTS của Trục
     * @return this is the hash sent to remote server for signing
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public static byte[] attachSignaturePlaceholder(String filepath, String trucCertPath) throws Exception {
        ByteArrayOutputStream preSignedDocument = new ByteArrayOutputStream();
        Path customerPathInDataStorage = Paths.get("./temp.pdf");
        PdfReader pdfReader = new PdfReader(filepath);
        PdfStamper stamper = PdfStamper.createSignature(pdfReader, preSignedDocument, '\0', customerPathInDataStorage.toFile(), true);

        // create certificate chain using certificate received from remote server system
        // this is the customer certificate received one time from the remote server and used for every document signing initialization
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(trucCertPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new java.security.cert.Certificate[0]);

        // create empty digital signature inside pre-signed document
        PdfSignatureAppearance sap = stamper.getSignatureAppearance();
        sap.setVisibleSignature(new Rectangle(basicSignerOptions.getPositionLLX(), basicSignerOptions.getPositionLLY(), basicSignerOptions.getPositionURX(), basicSignerOptions.getPositionURY()), pdfReader.getNumberOfPages(), basicSignerOptions.getFieldName());
        sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        sap.setCrypto(null, certificate, null, PdfSignatureAppearance.WINCER_SIGNED);
        /*TODO*/
        if (basicSignerOptions.getBgImgPath() != null) {
            final Image img = Image.getInstance(basicSignerOptions.getBgImgPath());
            LOGGER.info(RES.get("console.setImage"));
            sap.setImage(img);
        }

        sap.setImageScale(0);

        sap.setLayer2Text(basicSignerOptions.getL2Text());
        sap.setLayer4Text("");
        /**/

        /*copy from Signer Logic*/
        final PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(dic);

        final int contentEstimated = 8192;
        final Map<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        sap.preClose(exc);

        String provider = PKCS11Utils.getProviderNameForKeystoreType(basicSignerOptions.getKsType());
        InputStream data = sap.getRangeStream();
        final MessageDigest messageDigest = MessageDigest.getInstance(DOCUMENT_HASHING_ALGORITHM);

        byte hash[] = DigestAlgorithms.digest(data, messageDigest);

        byte[] encodedSig = new byte[0];

        byte[] paddedSig = new byte[contentEstimated];
        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        LOGGER.info(RES.get("console.closeStream"));
        sap.close(dic2);
        /**/

        ExternalDigest digest = new CeCA.SignExternalDigest();
        com.itextpdf.text.pdf.security.PdfPKCS7 sgn = new com.itextpdf.text.pdf.security.PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);

        Calendar cal = Calendar.getInstance();
        byte[] ocsp = null;


        String dataToSave = "";
        dataToSave += "{";
        byte[] signatureDigest = hash;
        dataToSave += "\"Digest\":\"" + SignerLogic.getHex(signatureDigest) + "\",";
//        byte[] signatureDigest = hash;

        byte[] authAttributes = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);

        byte[] hashForSigning = DigestAlgorithms.digest(new ByteArrayInputStream(authAttributes), DigestAlgorithms.getMessageDigest(DOCUMENT_HASHING_ALGORITHM, null));

        dataToSave += "\"Hash\":\"" + SignerLogic.getHex(hashForSigning) + "\"";
        dataToSave += "}";

        Files.write(Paths.get(filepath.replace(".pdf", "_placeholder.pdf")), preSignedDocument.toByteArray());

//        documentDetails.setPreSignedContent(preSignedDocument.toByteArray()); // this is the intermediary document content used in 2nd step in the line with the comment ***PRESIGNED_CONTENT****
//        documentDetails.setSignatureDigest(signatureDigest); // this is the signature digest used in 2nd step in the line with comment ****SIGNATURE_DIGEST****
//        documentDetails.setSigningHash(hashForSigning); // this is the hash sent to remote server for signing

//        stamper.close();
//        pdfReader.close();

        return dataToSave.getBytes(StandardCharsets.UTF_8);

        // we create the signature infrastructure
//        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
//        dic.setReason(sap.getReason());
//        dic.setLocation(sap.getLocation());
//        dic.setContact(sap.getContact());
//        dic.setDate(new PdfDate(sap.getSignDate()));
//        sap.setCryptoDictionary(dic);
//
//        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
//        exc.put(PdfName.CONTENTS, 8192 * 2 + 2);
//        sap.preClose(exc);
//        ExternalDigest externalDigest = new ExternalDigest() {
//            public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
//                return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
//            }
//        };
//        PdfPKCS7 sgn = new PdfPKCS7(null, certificatesChain, "SHA256", null, externalDigest, false);
//        InputStream data = sap.getRangeStream();
//        byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
//        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);
//        InputStream sh_is = new ByteArrayInputStream(sh);
//        byte[] signedAttributesHash = DigestAlgorithms.digest(sh_is, externalDigest.getMessageDigest("SHA256"));
//
//        return signedAttributesHash;

    }

    /**
     * @param filepath     Đường dẫn file PDF
     * @param trucCertPath Đường dẫn file CTS của Trục
     * @return this is the hash sent to remote server for signing
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public static void attachSignaturePlaceholderAndRemoteSign(String filepath, String trucCertPath) throws Exception {
        ByteArrayOutputStream preSignedDocument = new ByteArrayOutputStream();
        Path customerPathInDataStorage = Paths.get("./temp.pdf");
        PdfReader pdfReader = new PdfReader(filepath);
        PdfStamper stamper = PdfStamper.createSignature(pdfReader, preSignedDocument, '\0', customerPathInDataStorage.toFile(), true);

        // create certificate chain using certificate received from remote server system
        // this is the customer certificate received one time from the remote server and used for every document signing initialization
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(trucCertPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new java.security.cert.Certificate[0]);

        // create empty digital signature inside pre-signed document
        PdfSignatureAppearance sap = stamper.getSignatureAppearance();
        sap.setVisibleSignature(new Rectangle(basicSignerOptions.getPositionLLX(), basicSignerOptions.getPositionLLY(), basicSignerOptions.getPositionURX(), basicSignerOptions.getPositionURY()), pdfReader.getNumberOfPages(), basicSignerOptions.getFieldName());
        sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        sap.setCrypto(null, certificate, null, PdfSignatureAppearance.WINCER_SIGNED);
        /*TODO*/
        if (basicSignerOptions.getBgImgPath() != null) {
            final Image img = Image.getInstance(basicSignerOptions.getBgImgPath());
            LOGGER.info(RES.get("console.setImage"));
            sap.setImage(img);
        }

        sap.setImageScale(0);

        sap.setLayer2Text(basicSignerOptions.getL2Text());
        sap.setLayer4Text("");
        /**/

        /*copy from Signer Logic*/
        final PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(dic);

        final int contentEstimated = 8192;
        final Map<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        sap.preClose(exc);

        String provider = PKCS11Utils.getProviderNameForKeystoreType(basicSignerOptions.getKsType());
        InputStream data = sap.getRangeStream();
        final MessageDigest messageDigest = MessageDigest.getInstance(DOCUMENT_HASHING_ALGORITHM);

        byte hash[] = DigestAlgorithms.digest(data, messageDigest);

//        byte[] encodedSig = new byte[0];

//        byte[] paddedSig = new byte[contentEstimated];
//        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

//        PdfDictionary dic2 = new PdfDictionary();
//        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
//        LOGGER.info(RES.get("console.closeStream"));
//        sap.close(dic2);
        /**/

        ExternalDigest digest = new CeCA.SignExternalDigest();
        com.itextpdf.text.pdf.security.PdfPKCS7 pdfPKCS7 = new com.itextpdf.text.pdf.security.PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);

        Calendar cal = Calendar.getInstance();
        byte[] ocsp = null;


        String dataToSave = "";
        dataToSave += "{";
        byte[] signatureDigest = hash;
        dataToSave += "\"Digest\":\"" + SignerLogic.getHex(signatureDigest) + "\",";
//        byte[] signatureDigest = hash;

        byte[] authAttributes = pdfPKCS7.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);

        byte[] hashForSigning = DigestAlgorithms.digest(new ByteArrayInputStream(authAttributes), DigestAlgorithms.getMessageDigest(DOCUMENT_HASHING_ALGORITHM, null));

        dataToSave += "\"Hash\":\"" + SignerLogic.getHex(hashForSigning) + "\",";
        dataToSave += "\"FilePath\":\"" + filepath + "\",";
        dataToSave += "\"Metadata\":\"" + basicSignerOptions.getMetadata() + "\"";
        dataToSave += "}";


        // start send to server
        String remoteSigningUrl = basicSignerOptions.getRemoteSigningUrl();
        URL url = new URL(remoteSigningUrl);
        URLConnection connection;
        connection = url.openConnection();

        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.setRequestProperty("Content-Type", "application/json");

        OutputStream out = connection.getOutputStream();
        out.write(dataToSave.getBytes());
        out.close();

        // Get response as a byte array
        InputStream inp = connection.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }

        /* end send to server */

        String resData = baos.toString();
        System.out.println("resData: " + resData);
        String hexRemoteSigned = resData.split("###")[1];
        String tsaServerUrl = resData.split("###")[0];

        byte[] signed = SignerLogic.hexStringToByteArray(hexRemoteSigned);

        pdfPKCS7.setExternalDigest(signed, null, SIGNATURE_ENCRYPTION_ALGORITHM);

        com.itextpdf.text.pdf.security.TSAClientBouncyCastle tsc = null;

//        String tsaServerUrl = basicSignerOptions.getTsaUrl();

        if (tsaServerUrl != null) {
            LOGGER.info(RES.get("console.creatingTsaClient"));

            tsc = new com.itextpdf.text.pdf.security.TSAClientBouncyCastle(tsaServerUrl, basicSignerOptions.getTsaUser(), basicSignerOptions.getTsaPasswd(), 64, "SHA256");
        }

        byte[] encodedSignature = pdfPKCS7.getEncodedPKCS7(signatureDigest, tsc, null, null, MakeSignature.CryptoStandard.CMS);
        byte[] paddedSig = new byte[contentEstimated];
        System.arraycopy(encodedSignature, 0, paddedSig, 0, encodedSignature.length);

        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        LOGGER.info(RES.get("console.closeStream"));
        sap.close(dic2);

        Files.write(Paths.get(filepath.replace(".pdf", "_appended.pdf")), preSignedDocument.toByteArray());

    }
}
