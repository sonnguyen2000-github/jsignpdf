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
import net.sf.jsignpdf.types.ServerAuthentication;
import org.apache.commons.lang3.StringUtils;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static net.sf.jsignpdf.Constants.LOGGER;
import static net.sf.jsignpdf.Constants.RES;

public class CeCA {

    public static final String DOCUMENT_HASHING_ALGORITHM = "SHA256";
    public static final String CERTIFICATE_TYPE = "X.509";
    public static final String SIGNATURE_ENCRYPTION_ALGORITHM = "RSA";

    /**
     * @param filepath     Đường dẫn file PDF
     * @param trucCertPath Đường dẫn file CTS của Trục
     * @return this is the hash sent to remote server for signing
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public static byte[] attachTrucSignaturePlaceholder(String filepath, String trucCertPath) throws IOException, DocumentException, GeneralSecurityException {
        ByteArrayOutputStream preSignedDocument = new ByteArrayOutputStream();
        Path customerPathInDataStorage = Paths.get("./temp.pdf");
        PdfReader pdfReader = new PdfReader(filepath);
        PdfStamper stamper = PdfStamper.createSignature(pdfReader, preSignedDocument, '\0', customerPathInDataStorage.toFile(), true);

        // create certificate chain using certificate received from remote server system
        // this is the customer certificate received one time from the remote server and used for every document signing initialization
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(trucCertPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new java.security.cert.Certificate[0]);

        // create empty digital signature inside pre-signed document
        PdfSignatureAppearance signatureAppearance = stamper.getSignatureAppearance();
        signatureAppearance.setVisibleSignature(new Rectangle(72, 750, 400, 770), pdfReader.getNumberOfPages(), "P10001EVERIFY");
        signatureAppearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        signatureAppearance.setCertificate(certificate);
        /*TODO*/
        final Image img = Image.getInstance("/Users/sonnh/Pictures/my_avatar.jpeg");
        LOGGER.info(RES.get("console.setImage"));
        signatureAppearance.setImage(img);
        signatureAppearance.setImageScale(0);

        signatureAppearance.setLayer2Text("This is signature of BCT");

        CustomPreSignExternalSignature externalSignatureContainer = new CustomPreSignExternalSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        MakeSignature.signExternalContainer(signatureAppearance, externalSignatureContainer, 8192);
//        InputStream data = signatureAppearance.getRangeStream();
//        final MessageDigest messageDigest = MessageDigest.getInstance(DOCUMENT_HASHING_ALGORITHM);
//        byte buf[] = new byte[8192];
//        int n;
//        while ((n = data.read(buf)) > 0) {
//            messageDigest.update(buf, 0, n);
//        }
//        byte hash[] = messageDigest.digest();

//        ExternalDigest digest = new SignExternalDigest();
//        PdfPKCS7 pdfPKCS7 = new PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);


        byte[] signatureDigest = externalSignatureContainer.getSignatureDigest();
//        byte[] signatureDigest = hash;
//        byte[] authAttributes = pdfPKCS7.getAuthenticatedAttributeBytes(signatureDigest, null, null,
//                MakeSignature.CryptoStandard.CMS);


        Files.write(Paths.get(filepath.replace(".pdf", "_placeholder.pdf")), preSignedDocument.toByteArray());

//        documentDetails.setPreSignedContent(preSignedDocument.toByteArray()); // this is the intermediary document content used in 2nd step in the line with the comment ***PRESIGNED_CONTENT****
//        documentDetails.setSignatureDigest(signatureDigest); // this is the signature digest used in 2nd step in the line with comment ****SIGNATURE_DIGEST****
//        byte[] hashForSigning = DigestAlgorithms.digest(new ByteArrayInputStream(authAttributes),
//                digest.getMessageDigest(DOCUMENT_HASHING_ALGORITHM));
//        documentDetails.setSigningHash(hashForSigning); // this is the hash sent to remote server for signing

        stamper.close();
        pdfReader.close();

        return signatureDigest;

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

    /**
     * @param filepath
     * @param externalSignature in HEX
     * @param hashedContent
     * @param tsaServerUrl
     * @param trucCertPath
     */
    public static byte[] attachExternalSignature(String filepath, String externalSignature, String hashedContent, @Nullable String tsaServerUrl, String trucCertPath) throws IOException, DocumentException, GeneralSecurityException {
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(Files.newInputStream(Paths.get(trucCertPath)));
        Certificate[] certificatesChain = CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate)).getCertificates().toArray(new Certificate[0]);

        // create digital signature from detached signature
        ExternalDigest digest = new SignExternalDigest();
        PdfPKCS7 pdfPKCS7 = new PdfPKCS7(null, certificatesChain, DOCUMENT_HASHING_ALGORITHM, null, digest, false);

        pdfPKCS7.setExternalDigest(SignerLogic.hexStringToByteArray(externalSignature), null, SIGNATURE_ENCRYPTION_ALGORITHM);

        byte[] signatureDigest = SignerLogic.hexStringToByteArray(hashedContent); // this is the value from 1st step for ****SIGNATURE_DIGEST****

        TSAClientBouncyCastle tsc = null;
        if (tsaServerUrl != null) {
            LOGGER.info(RES.get("console.creatingTsaClient"));

            tsc = new TSAClientBouncyCastle(tsaServerUrl, null, null, 64, "SHA512");
        }

        byte[] encodedSignature = pdfPKCS7.getEncodedPKCS7(signatureDigest, (TSAClient) tsc, null, null, MakeSignature.CryptoStandard.CMS);
        ExternalSignatureContainer externalSignatureContainer = new CustomExternalSignature(encodedSignature);

        // create certificate chain from detached signature
//        byte[] detachedSignatureContent = SignerLogic.hexStringToByteArray(externalSignature); // this is the detached signature file content received from the remote server which contains also customer the certificate
//        ExternalSignatureContainer externalSignatureContainer = new CustomExternalSignature(detachedSignatureContent);

        // add signature content to existing signature container of the intermediary PDF document
        PdfReader pdfReader = new PdfReader(filepath);// this is the value from 1st step for ***PRESIGNED_CONTENT****
        ByteArrayOutputStream signedPdfOutput = new ByteArrayOutputStream();

        MakeSignature.signDeferred(pdfReader, "P10001EVERIFY", signedPdfOutput, externalSignatureContainer);

        pdfReader.close();

        return signedPdfOutput.toByteArray();
    }
}
