package com.jcmw.cert.validator;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.Enumeration;

import java.security.MessageDigest;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidator;
import java.security.cert.X509Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateValidation {

    private static final Logger log = LoggerFactory.getLogger(CertificateValidation.class);

    public static void main(String[] args) throws Exception {

        String[] inputValues = readConsoleInputs();
        boolean isValid = validateCertificate(inputValues[0], inputValues[1], inputValues[2]);

        if(isValid) {
            log.info("The provided certificate/certificate chain is trusted by the provided truststore, " +
                    inputValues[1]);
        } else {
            log.error("The provided certificate/certificate chain is not-trusted by the provided truststore, If " +
                    "there are no error stack printed in the console and If the provided certificate files are " +
                    "in expected order with desired certificates please import the subjected certificates to the " +
                    "truststore, " + inputValues[1] + " and try out the validation again.");
        }
    }

    public static String[] readConsoleInputs() {
        Scanner scanner = new Scanner(System.in);
        String[] inputValues = new String[3];

        System.out.print("Enter the path to the certificate file: ");
        inputValues[0] = scanner.nextLine();

        System.out.print("Enter the path to the truststore file (JKS): ");
        inputValues[1] = scanner.nextLine();

        System.out.print("Enter the truststore password: ");
        inputValues[2] = scanner.nextLine();

        scanner.close();

        log.info("You have added following details, The certificate File path as: " + inputValues[0]
                + ", The truststore file path as: " + inputValues[1] + ", The truststore password as: " +
                inputValues[2] + ".");

        return inputValues;
    }

    public static boolean validateCertificate(String certificateFilePath, String truststorePath, String truststorePassword) throws Exception {

        // Load the certificate file
        KeyStore truststore = KeyStore.getInstance("JKS");
        truststore.load(Files.newInputStream(Paths.get(truststorePath)), truststorePassword.toCharArray());

        // Load the certificate chain from the file
        FileInputStream certificateFileInputStream = new FileInputStream(certificateFilePath);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Loop though the certs and come up with a chain in given order.
        List<Certificate> certificateChain = new ArrayList<>();
        Certificate curretCertificate = null; // use to get the certificate
        while (certificateFileInputStream.available() > 0) {
            Certificate certificate = certificateFactory.generateCertificate(certificateFileInputStream);
            certificateChain.add(certificate);
            curretCertificate = certificate;
        }

        // Initialize cert path validator.
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");

        if(!certificateChain.isEmpty()) {
            log.info("The certificate chain, " + Arrays.toString(certificateChain.toArray()) + " which is provided " +
                    "via the file, " + certificateFilePath + "will be validated against the provided trust store, " +
                    truststorePath + ".");

            // Generate PKIX params using the content of the truststore.
            PKIXParameters params;
            try {
                params = new PKIXParameters(truststore);
                params.setRevocationEnabled(false); // Optional: Disable CRL and OCSP checks
            } catch (InvalidAlgorithmParameterException e) {
                log.error("An Exception was triggered, please validate the existence " +
                        "of trusted entries in pointed trust-store file.", e);
                throw new InvalidAlgorithmParameterException(e);
            }

            // Create a CertPath from the certificate chain
            CertPath certPath = certificateFactory.generateCertPath(certificateChain);

            try {
                certPathValidator.validate(certPath, params);
                log.info("Certificate chain is valid.");
                return true;
            } catch (CertPathValidatorException e) {
                log.debug("Certificate chain is NOT valid with the error stack", e);
                log.info("Certificate chain validation is failed, now trying to validate the exact existence of the " +
                        "certificate in the pointed trust store: " + e.getMessage());
                boolean isCertExist = false;
                try {
                    isCertExist = validateCertExistence(truststore, curretCertificate);
                } catch (Exception validateCertExistenceStack) {
                    log.error("An error as occurred when validating the certificate existence, hence the certificate " +
                            "trust validation will be failed.", validateCertExistenceStack);
                    return false;
                }
                return isCertExist;
            }
        } else {
            log.error("Invalid number of certificate detected, please check the content of the certificate file, '" +
                    certificateFilePath + "'.");
            return false;
        }
    }

    private static byte[] calculateCertFingerprint(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest certificateSHA256Digest = null;
        byte[] certificateSHA256FingerPrint = null;
        try {
            certificateSHA256Digest = MessageDigest.getInstance("SHA-256");
            certificateSHA256FingerPrint = certificate.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(e);
        } catch (CertificateEncodingException e) {
            throw new CertificateEncodingException(e);
        }
        return certificateSHA256Digest.digest(certificateSHA256FingerPrint);
    }

    private static Boolean validateCertExistence(KeyStore truststore, Certificate curretCertificate) throws Exception {
        log.info("The provided certificate file contains only one certificate, since the chain validation is failed, " +
                "the single certificate validation will be executed base on certificate fingerprint.");

        byte[] currentCertificateFingerprint = new byte[0];
        currentCertificateFingerprint = calculateCertFingerprint((X509Certificate) curretCertificate);
        log.debug("The sha256 fingerprint value of the given certificate is: " +
                formatCertFingerprint(currentCertificateFingerprint));
        Enumeration<String> trustStoreAliases = truststore.aliases();
        while (trustStoreAliases.hasMoreElements()) {
            String alias = trustStoreAliases.nextElement();
            Certificate truststoreCertificate = truststore.getCertificate(alias);
            if (truststoreCertificate instanceof X509Certificate) {
                X509Certificate storedX509Certificate = (X509Certificate) truststoreCertificate;
                byte[] storedFingerprint = calculateCertFingerprint(storedX509Certificate);
                if (MessageDigest.isEqual(currentCertificateFingerprint, storedFingerprint)) {
                    log.info("The exact certificate was found in the pointed trust store under the alias, '" + alias +
                            "', hence the pointed trust store will trust the pointed cert.");
                    return true; // Certificate fingerprint matches a certificate in the truststore
                }
            }
        }
        log.error("The exact certificate was not found in the pointed trust store, hence the pointed trust " +
                "store will not trust the pointed cert.");
        return false;
    }

    public static String formatCertFingerprint(byte[] currentCertificateFingerprint) {
        StringBuilder fingerprint = new StringBuilder(2 * currentCertificateFingerprint.length);
        for (byte b : currentCertificateFingerprint) {
            fingerprint.append(String.format("%02X:", b & 0xFF));
        }
        // Remove the trailing colon
        return fingerprint.substring(0, fingerprint.length() - 1);
    }
}
