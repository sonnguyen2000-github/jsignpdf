package net.sf.jsignpdf;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import net.sf.jsignpdf.crl.CRLInfo;
import net.sf.jsignpdf.utils.PKCS11Utils;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
    public static byte[] attachTrucSignaturePlaceholder(String filepath, String trucCertPath) throws Exception {
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
        /**/

        /*copy from Signer Logic*/
        final PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(dic);

        final CRLInfo crlInfo = new CRLInfo(basicSignerOptions, certificatesChain);

        final int contentEstimated = (int) (Constants.DEFVAL_SIG_SIZE + 2L * crlInfo.getByteCount());
        final Map<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        sap.preClose(exc);

        String provider = PKCS11Utils.getProviderNameForKeystoreType(basicSignerOptions.getKsType());
        InputStream data = sap.getRangeStream();
        final MessageDigest messageDigest = MessageDigest.getInstance(DOCUMENT_HASHING_ALGORITHM);
        byte buf[] = new byte[8192];
        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }
        byte hash[] = messageDigest.digest();

        byte[] encodedSig = new byte[0];

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
        /**/

        PdfPKCS7 sgn = new PdfPKCS7(sap.getPrivKey(), certificatesChain, crlInfo.getCrls(), DOCUMENT_HASHING_ALGORITHM, provider, false);

        Calendar cal = Calendar.getInstance();
        byte[] ocsp = null;


        String dataToSave = "";
        dataToSave += "{";
        byte[] signatureDigest = hash;
        dataToSave += "\"Digest\":\"" + SignerLogic.getHex(signatureDigest) + "\",";
//        byte[] signatureDigest = hash;

        byte[] authAttributes = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);

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
}
