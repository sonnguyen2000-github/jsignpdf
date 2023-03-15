package net.sf.jsignpdf;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.log.Logger;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static net.sf.jsignpdf.Constants.LOGGER;
import static net.sf.jsignpdf.Constants.RES;

public class CeCA {

    public static final String DOCUMENT_HASHING_ALGORITHM = "SHA256";
    public static final String CERTIFICATE_TYPE = "X.509";
    public static final String SIGNATURE_ENCRYPTION_ALGORITHM = "RSA";

    public static BasicSignerOptions basicSignerOptions;

    /**
     * @param filepath     Đường dẫn file PDF
     * @param certPath Đường dẫn file CTS của Trục
     * @return this is the hash sent to remote server for signing
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public static byte[] attachSignaturePlaceholder(String filepath, String certPath) throws IOException, DocumentException, GeneralSecurityException {
        ByteArrayOutputStream preSignedDocument = new ByteArrayOutputStream();
        Path customerPathInDataStorage = Paths.get("./temp.pdf");
        PdfReader pdfReader = new PdfReader(filepath);
        PdfStamper stamper = PdfStamper.createSignature(pdfReader, preSignedDocument, '\0', customerPathInDataStorage.toFile(), true);

        // create certificate chain using certificate received from remote server system
        // this is the customer certificate received one time from the remote server and used for every document signing initialization
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(certPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new java.security.cert.Certificate[0]);

        // create empty digital signature inside pre-signed document
        PdfSignatureAppearance sap = stamper.getSignatureAppearance();
        sap.setVisibleSignature(new Rectangle(basicSignerOptions.getPositionLLX(), basicSignerOptions.getPositionLLY(), basicSignerOptions.getPositionURX(), basicSignerOptions.getPositionURY()), pdfReader.getNumberOfPages(), basicSignerOptions.getFieldName());
        sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        sap.setCertificate(certificate);
        /*TODO*/
        if (basicSignerOptions.getBgImgPath() != null) {
            final Image img = Image.getInstance(basicSignerOptions.getBgImgPath());
            LOGGER.info(RES.get("console.setImage"));
            sap.setImage(img);
        }

        sap.setImageScale(0);

        sap.setLayer2Text(basicSignerOptions.getL2Text());
        /**/

        CustomPreSignExternalSignature externalSignatureContainer = new CustomPreSignExternalSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        MakeSignature.signExternalContainer(sap, externalSignatureContainer, 8192);
//        InputStream data = signatureAppearance.getRangeStream();
//        final MessageDigest messageDigest = MessageDigest.getInstance(DOCUMENT_HASHING_ALGORITHM);
//        byte buf[] = new byte[8192];
//        int n;
//        while ((n = data.read(buf)) > 0) {
//            messageDigest.update(buf, 0, n);
//        }
//        byte hash[] = messageDigest.digest();

        ExternalDigest digest = new SignExternalDigest();
        PdfPKCS7 pdfPKCS7 = new PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);

        String dataToSave = "";
        dataToSave += "{";
        byte[] signatureDigest = externalSignatureContainer.getSignatureDigest();
        dataToSave += "\"Digest\":\"" + SignerLogic.getHex(signatureDigest) + "\",";
//        byte[] signatureDigest = hash;
        byte[] authAttributes = pdfPKCS7.getAuthenticatedAttributeBytes(signatureDigest, null, null, MakeSignature.CryptoStandard.CMS);


        Files.write(Paths.get(filepath.replace(".pdf", "_placeholder.pdf")), preSignedDocument.toByteArray());

//        documentDetails.setPreSignedContent(preSignedDocument.toByteArray()); // this is the intermediary document content used in 2nd step in the line with the comment ***PRESIGNED_CONTENT****
//        documentDetails.setSignatureDigest(signatureDigest); // this is the signature digest used in 2nd step in the line with comment ****SIGNATURE_DIGEST****
        byte[] hashForSigning = DigestAlgorithms.digest(new ByteArrayInputStream(authAttributes), digest.getMessageDigest(DOCUMENT_HASHING_ALGORITHM));
//        documentDetails.setSigningHash(hashForSigning); // this is the hash sent to remote server for signing

//        stamper.close();
//        pdfReader.close();

        dataToSave += "\"Hash\":\"" + SignerLogic.getHex(hashForSigning) + "\"";
        dataToSave += "}";

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

    public static class CustomPreSignExternalSignature implements ExternalSignatureContainer {

        private final Logger logger = LoggerFactory.getLogger(CustomPreSignExternalSignature.class);

        private PdfDictionary dictionary;
        private byte[] signatureDigest;

        public CustomPreSignExternalSignature(PdfName filter, PdfName subFilter) {
            dictionary = new PdfDictionary();
            dictionary.put(PdfName.FILTER, filter);
            dictionary.put(PdfName.SUBFILTER, subFilter);
        }

        @Override
        public byte[] sign(InputStream data) throws GeneralSecurityException {
            try {
                ExternalDigest digest = new SignExternalDigest();
                signatureDigest = DigestAlgorithms.digest(data, digest.getMessageDigest(DOCUMENT_HASHING_ALGORITHM));
            } catch (IOException e) {
                logger.error("CustomSignExternalSignature - can not create hash to be signed");
                e.printStackTrace();
                throw new GeneralSecurityException("CustomPreSignExternalSignature - can not create hash to be signed", e);
            }

            return new byte[0];
        }

        @Override
        public void modifySigningDictionary(PdfDictionary pdfDictionary) {
            pdfDictionary.putAll(dictionary);
        }

        public byte[] getSignatureDigest() {
            return signatureDigest;
        }
    }

    public static class SignExternalDigest implements ExternalDigest {

        @Override
        public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
            return DigestAlgorithms.getMessageDigest(hashAlgorithm.toUpperCase(), null);
        }

    }

    public static class CustomExternalSignature implements ExternalSignatureContainer {

        private byte[] signatureContent;

        public CustomExternalSignature(byte[] signatureContent) {
            this.signatureContent = signatureContent;
        }

        @Override
        public byte[] sign(InputStream data) throws GeneralSecurityException {
            return signatureContent;
        }

        @Override
        public void modifySigningDictionary(PdfDictionary pdfDictionary) {
        }
    }

    public static byte[] attachExternalSignature(String filepath) throws IOException, DocumentException, GeneralSecurityException {
        String certPath = basicSignerOptions.getCertPath();
        String externalSignature = basicSignerOptions.getExternalSignature();
        String tsaServerUrl = basicSignerOptions.getTsaUrl();
        String externalDigest = basicSignerOptions.getExternalDigest();

        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(certPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new Certificate[0]);

        // create digital signature from detached signature
        ExternalDigest digest = new SignExternalDigest();
        PdfPKCS7 pdfPKCS7 = new PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);

        pdfPKCS7.setExternalDigest(SignerLogic.hexStringToByteArray(externalSignature), null, SIGNATURE_ENCRYPTION_ALGORITHM);

        byte[] secondDigest = SignerLogic.hexStringToByteArray(externalDigest); // this is the value from 1st step for ****SIGNATURE_DIGEST****

        TSAClientBouncyCastle tsc = null;
        if (tsaServerUrl != null) {
            LOGGER.info(RES.get("console.creatingTsaClient"));

            tsc = new TSAClientBouncyCastle(tsaServerUrl, null, null, 64, "SHA512");
        }

        byte[] encodedSignature = pdfPKCS7.getEncodedPKCS7(secondDigest, (TSAClient) tsc, null, null, MakeSignature.CryptoStandard.CMS);
//        byte[] paddedSig = new byte[8192];
//        System.arraycopy(encodedSignature, 0, paddedSig, 0, encodedSignature.length);

//        ExternalSignatureContainer externalSignatureContainer = new CustomExternalSignature(encodedSignature);

        // create certificate chain from detached signature
        byte[] detachedSignatureContent = encodedSignature; // this is the detached signature file content received from the remote server which contains also customer the certificate
        ExternalSignatureContainer externalSignatureContainer = new CustomExternalSignature(detachedSignatureContent);

        // add signature content to existing signature container of the intermediary PDF document
        PdfReader pdfReader = new PdfReader(filepath);// this is the value from 1st step for ***PRESIGNED_CONTENT****
        ByteArrayOutputStream signedPdfOutput = new ByteArrayOutputStream();
//        PdfStamper pdfStamper = new PdfStamper(pdfReader, signedPdfOutput, pdfReader.getPdfVersion());
//        PdfSignatureAppearance sap = pdfStamper.getSignatureAppearance();

//        PdfDictionary dic2 = new PdfDictionary();
//        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

//        try {
//            sap.close(dic2);
//        } catch (DocumentException e) {
//            throw new IOException(e);
//        }

        MakeSignature.signDeferred(pdfReader, basicSignerOptions.getFieldName(), signedPdfOutput, externalSignatureContainer);

//        pdfReader.close();

        return signedPdfOutput.toByteArray();
    }
}
