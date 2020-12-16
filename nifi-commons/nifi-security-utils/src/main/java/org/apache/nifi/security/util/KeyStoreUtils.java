/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.nifi.security.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreUtils {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreUtils.class);

    public static final String SUN_PROVIDER_NAME = "SUN";
    public static final String KEYSTORE_JKS = "JKS";
    public static final String KEYSTORE_PKCS12 = "PKCS12";
    public static final String KEYSTORE_JKS_EXT = ".jks";
    public static final String KEYSTORE_PKCS12_EXT = ".p12";
    public static final String KEYSTORE_PASSWORD = "passwordpassword";
    public static final String TRUSTSTORE_PASSWORD = "passwordpassword";
    public static final String CLIENT_ALIAS = "client";
    public static final String SERVER_ALIAS = "server";
    public static final String TLS_PROTOCOL_VERSION = TlsConfiguration.getHighestCurrentSupportedTlsProtocolVersion();

    public static Path keyStorePath;
    public static Path trustStorePath;
    public static StandardTlsConfiguration tlsConfiguration;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Returns the provider that will be used for the given keyStoreType
     *
     * @param keyStoreType the keyStoreType
     * @return the provider that will be used
     */
    public static String getKeyStoreProvider(String keyStoreType) {
        if (KeystoreType.PKCS12.toString().equalsIgnoreCase(keyStoreType)) {
            return BouncyCastleProvider.PROVIDER_NAME;
        } else if (KeystoreType.JKS.toString().equalsIgnoreCase(keyStoreType)) {
            return SUN_PROVIDER_NAME;
        }
        return null;
    }

    /**
     * Returns an empty KeyStore backed by the appropriate provider
     *
     * @param keyStoreType the keyStoreType
     * @return an empty KeyStore
     * @throws KeyStoreException if a KeyStore of the given type cannot be instantiated
     */
    public static KeyStore getKeyStore(String keyStoreType) throws KeyStoreException {
        String keyStoreProvider = getKeyStoreProvider(keyStoreType);
        if (StringUtils.isNotEmpty(keyStoreProvider)) {
            try {
                return KeyStore.getInstance(keyStoreType, keyStoreProvider);
            } catch (Exception e) {
                logger.error("Unable to load " + keyStoreProvider + " " + keyStoreType
                        + " keystore.  This may cause issues getting trusted CA certificates as well as Certificate Chains for use in TLS.", e);
            }
        }
        return KeyStore.getInstance(keyStoreType);
    }

    /**
     * Returns an empty KeyStore intended for use as a TrustStore backed by the appropriate provider
     *
     * @param trustStoreType the trustStoreType
     * @return an empty KeyStore
     * @throws KeyStoreException if a KeyStore of the given type cannot be instantiated
     */
    public static KeyStore getTrustStore(String trustStoreType) throws KeyStoreException {
        if (KeystoreType.PKCS12.toString().equalsIgnoreCase(trustStoreType)) {
            logger.warn(trustStoreType + " truststores are deprecated.  " + KeystoreType.JKS.toString() + " is preferred.");
        }
        return getKeyStore(trustStoreType);
    }

    /**
     * Returns a loaded {@link KeyStore} given the provided configuration values.
     *
     * @param keystorePath     the file path to the keystore
     * @param keystorePassword the keystore password
     * @param keystoreType     the keystore type ({@code JKS} or {@code PKCS12})
     * @return the loaded keystore
     * @throws TlsException if there is a problem loading the keystore
     */
    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType) throws TlsException {
        final KeyStore keyStore;
        try {
            keyStore = KeyStoreUtils.getKeyStore(keystoreType);
            try (final InputStream keyStoreStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreStream, keystorePassword);
            }
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            logger.error("Encountered an error loading keystore: {}", e.getLocalizedMessage());
            throw new TlsException("Error loading keystore", e);
        }
    }

    /**
     * Creates a temporary default Keystore and Truststore and returns it wrapped in a TLS Configuration.
     *
     * @return a {@link org.apache.nifi.security.util.TlsConfiguration}
     */
    public static StandardTlsConfiguration createTlsConfigWithNewKeystoreAndTruststore() throws IOException, GeneralSecurityException {
        return createTlsConfigWithNewKeystoreAndTruststore(KEYSTORE_PKCS12, KEYSTORE_PASSWORD, KEYSTORE_PASSWORD, KEYSTORE_PKCS12, TRUSTSTORE_PASSWORD);
    }

    /**
     * Creates a temporary Keystore and Truststore and returns it wrapped in a TLS Configuration with the given values.
     *
     * @param keystoreType       the keystore type as a String
     * @param keystorePassword   the keystore password
     * @param truststoreType     the truststore type as a String
     * @param truststorePassword the truststore password
     * @return a {@link org.apache.nifi.security.util.TlsConfiguration}
     */
    public static StandardTlsConfiguration createTlsConfigWithNewKeystoreAndTruststore(String keystoreType, String keystorePassword, String truststoreType, String truststorePassword) throws IOException, GeneralSecurityException {
        return createTlsConfigWithNewKeystoreAndTruststore(keystoreType, keystorePassword, keystorePassword, truststoreType, truststorePassword);
    }

    /**
     * Creates a temporary Keystore and Truststore and returns it wrapped in a TLS Configuration with the given values.
     *
     * @param keystoreType       the keystore type as a String
     * @param keystorePassword   the keystore password
     * @param truststoreType     the truststore type as a String
     * @return a {@link org.apache.nifi.security.util.TlsConfiguration}
     */
    public static StandardTlsConfiguration createTlsConfigWithNewKeystoreAndTruststore(String keystoreType, String keystorePassword, String truststoreType) throws IOException, GeneralSecurityException {
        return createTlsConfigWithNewKeystoreAndTruststore(keystoreType, keystorePassword, keystorePassword, truststoreType, TRUSTSTORE_PASSWORD);
    }

    //TODO: Do I need a constructor for a scenario where I only pass a keystore pw + Key pw, but no Truststore pw. The problem is that this constructor of (String, String, String, String) is already defined.
//    /**
//     * Creates a temporary Keystore and Truststore and returns it wrapped in a TLS Configuration with the given values.
//     *
//     * @param keystoreType       the keystore type as a String
//     * @param keystorePassword   the keystore password
//     * @param keyPassword        the key password
//     * @param truststoreType     the truststore type as a String
//     * @return a {@link org.apache.nifi.security.util.TlsConfiguration}
//     */
//    public static StandardTlsConfiguration createTlsConfigWithNewKeystoreAndTruststore(String keystoreType, String keystorePassword, String keyPassword, String truststoreType) throws IOException, GeneralSecurityException {
//        return createTlsConfigWithNewKeystoreAndTruststore(keystoreType, keystorePassword, keyPassword, truststoreType, TRUSTSTORE_PASSWORD);
//    }

    public static StandardTlsConfiguration createNewKeystoreAndTruststoreWithTlsConfig(StandardTlsConfiguration tlsConfiguration) throws GeneralSecurityException, IOException {
        // Check if KS/TS/Keystore PW properties are populated
        // TODO: If a Keystore or Truststore already exist in the TLS config, should we overwrite it or not?
        if (tlsConfiguration.isKeystorePopulated()) {
            logger.debug("A Keystore file already exists with the given TLS configuration. Overwriting with a new Keystore.");
        } else if (tlsConfiguration.isTruststorePopulated()) {
            logger.debug("A Truststore already exists with the given TLS configuration. Overwriting with a new Truststore.");
        } else if (tlsConfiguration.getKeystorePassword() == null) { // Check if KS PW is set
            logger.debug("The Keystore password property cannot be empty in the given TLS configuration.");
            throw new IllegalArgumentException("The Keystore password cannot be empty in the given TLS configuration.");
        }

        // Check if Key PW is set
        // If not set, use Keystore PW

        // Check if KS type is set
        // If not set, default to PKCS12

        // Extract TLS props to create temp KS/TS path
        // Return new TLS configs
        return createTlsConfigWithNewKeystoreAndTruststore(
                (tlsConfiguration.getKeystoreType() != null ? tlsConfiguration.getKeystoreType().toString() : KEYSTORE_PKCS12),
                tlsConfiguration.getKeystorePassword(),
                (tlsConfiguration.getKeyPassword() != null ? tlsConfiguration.getKeyPassword() : tlsConfiguration.getKeystorePassword()),
                (tlsConfiguration.getTruststoreType() != null ? tlsConfiguration.getTruststoreType().toString() : KEYSTORE_PKCS12),
                (tlsConfiguration.getTruststorePassword() != null ? tlsConfiguration.getTruststorePassword() : "")
        );
    }

    /**
     * Creates a temporary Keystore and Truststore and returns it wrapped in a TLS Configuration with the given values.
     *
     * @param keystoreType       the keystore type as a String
     * @param keystorePassword   the keystore password
     * @param keyPassword        the key password
     * @param truststoreType     the truststore type as a String
     * @param truststorePassword the truststore password
     * @return a {@link org.apache.nifi.security.util.TlsConfiguration}
     */
    public static StandardTlsConfiguration createTlsConfigWithNewKeystoreAndTruststore(String keystoreType, String keystorePassword, String keyPassword, String truststoreType, String truststorePassword) throws IOException, GeneralSecurityException {

        // Create temporary Keystore and Truststore files
        try {
            keyStorePath = generateTempKeystorePath(keystoreType);
            trustStorePath = generateTempTruststorePath(truststoreType);
        } catch (IOException e) {
            throw new IOException("There was an error creating a keystore or truststore: " + e.getMessage());
        }

        // Create X509 Certificate
        final X509Certificate clientCert = createKeyStoreAndGetX509Certificate(CLIENT_ALIAS, keystorePassword, keyPassword, keyStorePath.toString(), keystoreType);
        // Create Truststore
        createTrustStore(clientCert, CLIENT_ALIAS, truststorePassword, trustStorePath.toString(), getKeystoreType(truststoreType));

        return tlsConfiguration = new StandardTlsConfiguration(
                keyStorePath.toString(),
                keystorePassword,
                keyPassword,
                getKeystoreType(keystoreType),
                trustStorePath.toString(),
                truststorePassword,
                getKeystoreType(keystoreType),
                TLS_PROTOCOL_VERSION);
    }

    public static StandardTlsConfiguration createTlsConfigWithNewTruststoreOnly(String truststoreType, String truststorePassword) throws IOException, GeneralSecurityException {
        // Create temp Truststore file path
        try {
            trustStorePath = generateTempTruststorePath(truststoreType);
        } catch (IOException e) {
            throw new IOException("There was an error creating a keystore or truststore: " + e.getMessage());
        }

        final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final X509Certificate selfSignedCert = CertificateUtils.generateSelfSignedX509Certificate(
                keyPair, "CN=localhost,OU=NiFi", "SHA256withRSA", 365
        );

        // Create Truststore
        createTrustStore(selfSignedCert, CLIENT_ALIAS, truststorePassword, trustStorePath.toString(), getKeystoreType(truststoreType));

        // Return a Truststore wrapped in TLS Configuration
        return tlsConfiguration = new StandardTlsConfiguration(
                null,
                null,
                null,
                null,
                trustStorePath.toString(),
                truststorePassword,
                getKeystoreType(truststoreType),
                TLS_PROTOCOL_VERSION);
    }

    /**
     * Loads the Keystore and returns a X509 Certificate with the given values.
     *
     * @param alias              the certificate alias
     * @param keyStorePassword   the keystore password
     * @param keyStorePath       the keystore path
     * @param keyStoreType       the keystore type as a String
     * @return a {@link X509Certificate}
     */
    public static X509Certificate createKeyStoreAndGetX509Certificate(
            final String alias, final String keyStorePassword, final String keyStorePath, final String keyStoreType)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        try (final FileOutputStream outputStream = new FileOutputStream(keyStorePath)) {
            final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            final X509Certificate selfSignedCert = CertificateUtils.generateSelfSignedX509Certificate(
                    keyPair, "CN=localhost,OU=NiFi", "SHA256withRSA", 365
            );

            final char[] passwordChars = keyStorePassword.toCharArray();
            final KeyStore keyStore = loadEmptyKeyStore(keyStoreType);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), passwordChars, new Certificate[]{selfSignedCert});
            keyStore.store(outputStream, passwordChars);

            return selfSignedCert;
        }
    }

    /**
     * Loads the Keystore and returns a X509 Certificate with the given values.
     *
     * @param alias              the certificate alias
     * @param keyStorePassword   the keystore password
     * @param keyPassword        the key password
     * @param keyStorePath       the keystore path
     * @param keyStoreType       the keystore type as a String
     * @return a {@link X509Certificate}
     */
    public static X509Certificate createKeyStoreAndGetX509Certificate(
            final String alias, final String keyStorePassword, final String keyPassword, final String keyStorePath,
            final String keyStoreType) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        try (final FileOutputStream outputStream = new FileOutputStream(keyStorePath)) {
            final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            final X509Certificate selfSignedCert = CertificateUtils.generateSelfSignedX509Certificate(
                    keyPair, "CN=localhost,OU=NiFi", "SHA256withRSA", 365
            );

            final KeyStore keyStore = loadEmptyKeyStore(keyStoreType);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{selfSignedCert});
            keyStore.store(outputStream, keyStorePassword.toCharArray());

            return selfSignedCert;
        }
    }

    public static void createTrustStore(final X509Certificate cert,
                                        final String alias, final String password, final String path, final String truststoreType)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        try (final FileOutputStream outputStream = new FileOutputStream(path)) {
            final KeyStore trustStore = loadEmptyKeyStore(truststoreType);
            trustStore.setCertificateEntry(alias, cert);
            trustStore.store(outputStream, password.toCharArray());
        }
    }

    private static Path generateTempKeystorePath(String keystoreType) throws IOException {
        return Files.createTempFile("test-keystore-", getKeystoreExtension(keystoreType));
    }

    private static Path generateTempTruststorePath(String truststoreType) throws IOException {
        return Files.createTempFile("test-truststore-", getKeystoreExtension(truststoreType));
    }

    /**
     * Loads and returns an empty KeyStore backed by the appropriate provider
     *
     * @param keyStoreType the keyStoreType
     * @return an empty KeyStore
     * @throws KeyStoreException if a KeyStore of the given type cannot be instantiated
     */
    public static KeyStore loadEmptyKeyStore(String keyStoreType) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        final KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(Objects.requireNonNull(getKeystoreType(keyStoreType)));
//            keyStore = KeyStoreUtils.getKeyStore(keyStoreType);
            keyStore.load(null, null);
            return keyStore;
        } catch (IOException e) {
            logger.error("Encountered an error loading keystore: {}", e.getLocalizedMessage());
            throw new IOException("Error loading keystore", e);
        }
    }

    /**
     * Returns the Keystore type in the correct format given the Keystore type.
     *
     * @param keystoreType     the Keystore type as a String
     * @return the keystore type
     */
    public static String getKeystoreType(String keystoreType) {
        // if true
        if (KeystoreType.isValidKeystoreType(keystoreType)) {
            return KeystoreType.valueOf(keystoreType.toUpperCase()).toString();
        } else {
            logger.debug("The given Keystore must be of type JKS or PKCS12.");
            throw new IllegalArgumentException("The given Keystore type is not valid: " + keystoreType);
        }
    }

    /**
     * Returns the Keystore extension given the Keystore type.
     *
     * @param keystoreType     the Keystore type as a String
     * @return the keystore extension
     */
    public static String getKeystoreExtension(String keystoreType) {
        if (KeystoreType.PKCS12.toString().equalsIgnoreCase(keystoreType)) {
            return KEYSTORE_PKCS12_EXT;
        } else if (KeystoreType.JKS.toString().equalsIgnoreCase(keystoreType)){
            return KEYSTORE_JKS_EXT;
        } else {
            logger.debug("There is no Keystore file extension for the given Keystore Type: " + keystoreType +
                    ". The Keystore must be of type JKS or PKCS12.");
            throw new IllegalArgumentException("There was an error finding the appropriate Keystore extension. " +
                    "The given Keystore type is not valid: " + keystoreType);
        }
    }

    /**
     * Returns the {@link KeyManagerFactory} from the provided {@link KeyStore} object, initialized with the key or keystore password.
     *
     * @param keyStore         the loaded keystore
     * @param keystorePassword the keystore password
     * @param keyPassword      the key password
     * @return the key manager factory
     * @throws TlsException if there is a problem initializing or reading from the keystore
     */
    public static KeyManagerFactory getKeyManagerFactoryFromKeyStore(KeyStore keyStore, char[] keystorePassword, char[] keyPassword) throws TlsException {
        try {
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            if (keyPassword == null) {
                keyManagerFactory.init(keyStore, keystorePassword);
            } else {
                keyManagerFactory.init(keyStore, keyPassword);
            }
            return keyManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            logger.error("Encountered an error loading keystore: {}", e.getLocalizedMessage());
            throw new TlsException("Error loading keystore", e);
        }
    }

    /**
     * Returns the intialized {@link KeyManagerFactory}.
     *
     * @param tlsConfiguration the TLS configuration
     * @return the initialized key manager factory
     * @throws TlsException if there is a problem initializing or reading from the keystore
     */
    public static KeyManagerFactory loadKeyManagerFactory(TlsConfiguration tlsConfiguration) throws TlsException {
        return loadKeyManagerFactory(tlsConfiguration.getKeystorePath(), tlsConfiguration.getKeystorePassword(),
                tlsConfiguration.getFunctionalKeyPassword(), tlsConfiguration.getKeystoreType().getType());
    }

    /**
     * Returns the initialized {@link KeyManagerFactory}.
     *
     * @param keystorePath     the file path to the keystore
     * @param keystorePassword the keystore password
     * @param keyPassword      the key password
     * @param keystoreType     the keystore type ({@code JKS} or {@code PKCS12})
     * @return the initialized key manager factory
     * @throws TlsException if there is a problem initializing or reading from the keystore
     */
    public static KeyManagerFactory loadKeyManagerFactory(String keystorePath, String keystorePassword, String keyPassword, String keystoreType) throws TlsException {
        if (StringUtils.isEmpty(keystorePassword)) {
            throw new IllegalArgumentException("The keystore password cannot be null or empty");
        }
        final char[] keystorePasswordChars = keystorePassword.toCharArray();
        final char[] keyPasswordChars = (StringUtils.isNotEmpty(keyPassword)) ? keyPassword.toCharArray() : keystorePasswordChars;
        KeyStore keyStore = loadKeyStore(keystorePath, keystorePasswordChars, keystoreType);
        return getKeyManagerFactoryFromKeyStore(keyStore, keystorePasswordChars, keyPasswordChars);
    }

    /**
     * Returns a loaded {@link KeyStore} (acting as a truststore) given the provided configuration values.
     *
     * @param truststorePath     the file path to the truststore
     * @param truststorePassword the truststore password
     * @param truststoreType     the truststore type ({@code JKS} or {@code PKCS12})
     * @return the loaded truststore
     * @throws TlsException if there is a problem loading the truststore
     */
    public static KeyStore loadTrustStore(String truststorePath, char[] truststorePassword, String truststoreType) throws TlsException {
        final KeyStore trustStore;
        try {
            trustStore = KeyStoreUtils.getTrustStore(truststoreType);
            try (final InputStream trustStoreStream = new FileInputStream(truststorePath)) {
                trustStore.load(trustStoreStream, truststorePassword);
            }
            return trustStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            logger.error("Encountered an error loading truststore: {}", e.getLocalizedMessage());
            throw new TlsException("Error loading truststore", e);
        }
    }

    /**
     * Returns the {@link TrustManagerFactory} from the provided {@link KeyStore} object, initialized.
     *
     * @param trustStore the loaded truststore
     * @return the trust manager factory
     * @throws TlsException if there is a problem initializing or reading from the truststore
     */
    public static TrustManagerFactory getTrustManagerFactoryFromTrustStore(KeyStore trustStore) throws TlsException {
        try {
            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            return trustManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            logger.error("Encountered an error loading truststore: {}", e.getLocalizedMessage());
            throw new TlsException("Error loading truststore", e);
        }
    }

    /**
     * Returns the initialized {@link TrustManagerFactory}.
     *
     * @param tlsConfiguration the TLS configuration
     * @return the initialized trust manager factory
     * @throws TlsException if there is a problem initializing or reading from the truststore
     */
    public static TrustManagerFactory loadTrustManagerFactory(TlsConfiguration tlsConfiguration) throws TlsException {
        return loadTrustManagerFactory(tlsConfiguration.getTruststorePath(), tlsConfiguration.getTruststorePassword(), tlsConfiguration.getTruststoreType().getType());
    }

    /**
     * Returns the initialized {@link TrustManagerFactory}.
     *
     * @param truststorePath     the file path to the truststore
     * @param truststorePassword the truststore password
     * @param truststoreType     the truststore type ({@code JKS} or {@code PKCS12})
     * @return the initialized trust manager factory
     * @throws TlsException if there is a problem initializing or reading from the truststore
     */
    public static TrustManagerFactory loadTrustManagerFactory(String truststorePath, String truststorePassword, String truststoreType) throws TlsException {
        // Legacy truststore passwords can be empty
        final char[] truststorePasswordChars = StringUtils.isNotBlank(truststorePassword) ? truststorePassword.toCharArray() : null;
        KeyStore trustStore = loadTrustStore(truststorePath, truststorePasswordChars, truststoreType);
        return getTrustManagerFactoryFromTrustStore(trustStore);
    }

    /**
     * Returns true if the given keystore can be loaded using the given keystore type and password. Returns false otherwise.
     *
     * @param keystore     the keystore to validate
     * @param keystoreType the type of the keystore
     * @param password     the password to access the keystore
     * @return true if valid; false otherwise
     */
    public static boolean isStoreValid(final URL keystore, final KeystoreType keystoreType, final char[] password) {

        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        } else if (keystoreType == null) {
            throw new IllegalArgumentException("Keystore type may not be null");
        } else if (password == null) {
            throw new IllegalArgumentException("Password may not be null");
        }

        BufferedInputStream bis = null;
        final KeyStore ks;
        try {

            // Load the keystore
            bis = new BufferedInputStream(keystore.openStream());
            ks = KeyStoreUtils.getKeyStore(keystoreType.name());
            ks.load(bis, password);

            return true;

        } catch (Exception e) {
            return false;
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (final IOException ioe) {
                    logger.warn("Failed to close input stream", ioe);
                }
            }
        }
    }

    /**
     * Returns true if the given keystore can be loaded using the given keystore type and password and the default
     * (first) alias can be retrieved with the key-specific password. Returns false otherwise.
     *
     * @param keystore     the keystore to validate
     * @param keystoreType the type of the keystore
     * @param password     the password to access the keystore
     * @param keyPassword  the password to access the specific key
     * @return true if valid; false otherwise
     */
    public static boolean isKeyPasswordCorrect(final URL keystore, final KeystoreType keystoreType, final char[] password, final char[] keyPassword) {

        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        } else if (keystoreType == null) {
            throw new IllegalArgumentException("Keystore type may not be null");
        } else if (password == null) {
            throw new IllegalArgumentException("Password may not be null");
        }

        BufferedInputStream bis = null;
        final KeyStore ks;
        try {

            // Load the keystore
            bis = new BufferedInputStream(keystore.openStream());
            ks = KeyStoreUtils.getKeyStore(keystoreType.name());
            ks.load(bis, password);

            // Determine the default alias
            String alias = ks.aliases().nextElement();
            try {
                Key privateKeyEntry = ks.getKey(alias, keyPassword);
                return true;
            } catch (UnrecoverableKeyException e) {
                logger.warn("Tried to access a key in keystore " + keystore + " with a key password that failed");
                return false;
            }
        } catch (Exception e) {
            return false;
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (final IOException ioe) {
                    logger.warn("Failed to close input stream", ioe);
                }
            }
        }
    }

    public static String sslContextToString(SSLContext sslContext) {
        return new ToStringBuilder(sslContext)
                .append("protocol", sslContext.getProtocol())
                .append("provider", sslContext.getProvider().toString())
                .toString();
    }

    public static String sslParametersToString(SSLParameters sslParameters) {
        return new ToStringBuilder(sslParameters)
                .append("protocols", sslParameters.getProtocols())
                .append("wantClientAuth", sslParameters.getWantClientAuth())
                .append("needClientAuth", sslParameters.getNeedClientAuth())
                .toString();
    }

    public static String sslServerSocketToString(SSLServerSocket sslServerSocket) {
        return new ToStringBuilder(sslServerSocket)
                .append("enabledProtocols", sslServerSocket.getEnabledProtocols())
                .append("needClientAuth", sslServerSocket.getNeedClientAuth())
                .append("wantClientAuth", sslServerSocket.getWantClientAuth())
                .append("useClientMode", sslServerSocket.getUseClientMode())
                .toString();
    }
}
