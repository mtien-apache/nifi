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
package org.apache.nifi.security.util

import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@RunWith(JUnit4.class)
class KeyStoreUtilsGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreUtilsGroovyTest.class)

    private static final File KEYSTORE_FILE = new File("src/test/resources/keystore.jks")
    private static final String KEYSTORE_PASSWORD = "passwordpassword"
    private static final String TRUSTSTORE_PASSWORD = "passwordpassword"
    private static final String KEY_PASSWORD = "keypassword"
    private static final KeystoreType KEYSTORE_TYPE = KeystoreType.JKS

    private static tlsConfiguration

    @BeforeClass
    static void setUpOnce() {
        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

//        tlsConfiguration = KeyStoreUtils.createTlsConfigWithNewKeystoreAndTruststore()
    }

    @Before
    void setUp() {

    }

    @After
    void tearDown() {

    }

    @AfterClass
    static void tearDownOnce() {
//        try {
//            Files.deleteIfExists(Path.of(tlsConfiguration.getKeystorePath()))
//            Files.deleteIfExists(Path.of(tlsConfiguration.getTruststorePath()))
//        } catch (IOException e) {
//            throw new IOException("There was an error deleting a keystore or truststore: " + e.getMessage());
//        }
    }

    @Test
    void testShouldVerifyKeystoreIsValid() {
        // Arrange

        // Act
        boolean keystoreIsValid = KeyStoreUtils.isStoreValid(KEYSTORE_FILE.toURI().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.toCharArray())

        // Assert
        assert keystoreIsValid
    }

    @Test
    void testShouldVerifyKeystoreIsNotValid() {
        // Arrange

        // Act
        boolean keystoreIsValid = KeyStoreUtils.isStoreValid(KEYSTORE_FILE.toURI().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.reverse().toCharArray())

        // Assert
        assert !keystoreIsValid
    }

    @Test
    void testShouldVerifyKeyPasswordIsValid() {
        // Arrange

        // Act
        boolean keyPasswordIsValid = KeyStoreUtils.isKeyPasswordCorrect(KEYSTORE_FILE.toURI().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.toCharArray(), KEYSTORE_PASSWORD.toCharArray())

        // Assert
        assert keyPasswordIsValid
    }

    @Test
    void testShouldVerifyKeyPasswordIsNotValid() {
        // Arrange

        // Act
        boolean keyPasswordIsValid = KeyStoreUtils.isKeyPasswordCorrect(KEYSTORE_FILE.toURI().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.toCharArray(), KEYSTORE_PASSWORD.reverse().toCharArray())

        // Assert
        assert !keyPasswordIsValid
    }

    @Test
    @Ignore("Used to create passwordless truststore file for testing NIFI-6770")
    void createPasswordlessTruststore() {
        // Retrieve the public certificate from https://nifi.apache.org
        String hostname = "nifi.apache.org"
        SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory()
        SSLSocket socket = (SSLSocket) factory.createSocket(hostname, 443)
        socket.startHandshake()
        List<Certificate> certs = socket.session.peerCertificateChain as List<Certificate>
        Certificate nodeCert = CertificateUtils.formX509Certificate(certs.first().encoded)

        // Create a JKS truststore containing that cert as a trustedCertEntry and do not put a password on the truststore
        KeyStore truststore = KeyStore.getInstance("JKS")
        // Explicitly set the second parameter to empty to avoid a password
        truststore.load(null, "".chars)
        truststore.setCertificateEntry("nifi.apache.org", nodeCert)

        // Save the truststore to disk
        FileOutputStream fos = new FileOutputStream("target/nifi.apache.org.ts.jks")
        truststore.store(fos, "".chars)
    }

    @Test
    @Ignore("Used to create passwordless truststore file for testing NIFI-6770")
    void createLocalPasswordlessTruststore() {
        KeyStore truststoreWithPassword = KeyStore.getInstance("JKS")
        truststoreWithPassword.load(new FileInputStream("/Users/alopresto/Workspace/nifi/nifi-nar-bundles/nifi-standard-bundle/nifi-standard-processors/src/test/resources/truststore.jks"), "passwordpassword".chars)
        Certificate nodeCert = truststoreWithPassword.getCertificate("nifi-cert")

        // Create a JKS truststore containing that cert as a trustedCertEntry and do not put a password on the truststore
        KeyStore truststore = KeyStore.getInstance("JKS")
        // Explicitly set the second parameter to empty to avoid a password
        truststore.load(null, "".chars)
        truststore.setCertificateEntry("nifi.apache.org", nodeCert)

        // Save the truststore to disk
        FileOutputStream fos = new FileOutputStream("/Users/alopresto/Workspace/nifi/nifi-nar-bundles/nifi-standard-bundle/nifi-standard-processors/src/test/resources/truststore.no-password.jks")
        truststore.store(fos, "".chars)
    }

    //TODO: Escape the forward slash
    @Test
    void testShouldValidateTempKeystorePath() {
        // Act
        Path testKeystorePath = KeyStoreUtils.generateTempKeystorePath(KEYSTORE_TYPE.toString())

        // Assert
        logger.info("Keystore path: ${testKeystorePath.getParent()}/${testKeystorePath.getFileName()}")
        assert testKeystorePath
    }

    @Test
    void testShouldValidateTempTruststorePath() {
        // Act
        Path truststorePath = KeyStoreUtils.generateTempTruststorePath(KEYSTORE_TYPE.toString())

        // Assert
        logger.info("Truststore path: ${truststorePath.getParent()}/${truststorePath.getFileName()}")
        assert truststorePath
    }

    @Test
    void testShouldValidateTlsConfigAndNewKeystoreAndTruststoreWithParams() {
        // Act
        StandardTlsConfiguration tlsConfig = KeyStoreUtils.createTlsConfigWithNewKeystoreAndTruststore(KEYSTORE_TYPE.toString(), KEYSTORE_PASSWORD, KEY_PASSWORD, KEYSTORE_TYPE.toString(), TRUSTSTORE_PASSWORD)

        // Assert
        assert tlsConfig
        assert tlsConfig.getKeystorePath()
        assert tlsConfig.getTruststorePath()
        assert tlsConfig.getKeystoreType().toString() == "JKS"
    }

    @Test
    void testShouldVerifyTlsConfigAndNewKeystoreAndTruststoreWithoutParams() {
        // Act
        StandardTlsConfiguration tlsConfig = KeyStoreUtils.createTlsConfigWithNewKeystoreAndTruststore()

        // Assert
        assert tlsConfig
        assert tlsConfig.getKeystorePath()
        assert tlsConfig.getTruststorePath()
        assert tlsConfig.getKeystoreType().toString() == "PKCS12"
    }

    @Test
    void testShouldValidateTlsConfigAndNewTruststoreOnly() {
        // Act
        StandardTlsConfiguration tlsConfig = KeyStoreUtils.createTlsConfigWithNewTruststoreOnly(KEYSTORE_TYPE.toString(), TRUSTSTORE_PASSWORD)

        // Assert
        assert tlsConfig
        assert tlsConfig.getTruststorePath()
        assert tlsConfig.getKeystorePath() == null
    }

    @Test
    void testShouldValidateTlsConfigWithoutKeyPasswordParam() {
        // Act
        StandardTlsConfiguration tlsConfig = KeyStoreUtils.createTlsConfigWithNewKeystoreAndTruststore(KEYSTORE_TYPE.toString(), KEYSTORE_PASSWORD, KEYSTORE_TYPE.toString())

        // Assert
        assert tlsConfig
        assert tlsConfig.getKeyPassword() == KEYSTORE_PASSWORD
    }

    @Test
    void testShouldValidateNewTlsConfigWithTlsConfigParam() {
        // Arrange
        StandardTlsConfiguration tlsConfig = new StandardTlsConfiguration(null, KEYSTORE_PASSWORD, KEYSTORE_TYPE, null, TRUSTSTORE_PASSWORD, KEYSTORE_TYPE)

        // Act
        StandardTlsConfiguration newTlsConfig = KeyStoreUtils.createNewKeystoreAndTruststoreWithTlsConfig(tlsConfig)

        // Assert
        assert newTlsConfig.getKeystorePath() != null
        assert newTlsConfig.getTruststorePath() != null
        assert newTlsConfig.getKeystoreType() == KEYSTORE_TYPE
    }

    @Test
    void testShouldReturnX509CertWithKeyPasswordParam() {
        // Arrange
        Path keystorePath = KeyStoreUtils.generateTempKeystorePath(KEYSTORE_TYPE.toString())
        String testKeyPassword = "testKeyPassword"

        // Act
        X509Certificate x509Cert = KeyStoreUtils.createKeyStoreAndGetX509Certificate(KeyStoreUtils.CLIENT_ALIAS, KEYSTORE_PASSWORD, testKeyPassword, keystorePath.toString(), KEYSTORE_TYPE.toString())

        // Assert
        assert x509Cert

        // Assert certDN
        final String certDN = x509Cert.getIssuerDN().toString()
        logger.info("Certificate DN: ${certDN}")
        assert certDN == "OU=NiFi,CN=localhost"

        // Assert Key password is not the same as Keystore password
        boolean keyPassAndKeystorePassDoNotMatch = KeyStoreUtils.isKeyPasswordCorrect(keystorePath.toUri().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.toCharArray(), testKeyPassword.toCharArray())
        logger.info("Key password and Keystore password are not the same: ${keyPassAndKeystorePassDoNotMatch}")
        assert keyPassAndKeystorePassDoNotMatch
    }

    @Test
    void testShouldReturnX509CertWithoutKeyPasswordParam() {
        // Arrange
        Path keystorePath = KeyStoreUtils.generateTempKeystorePath(KEYSTORE_TYPE.toString())

        // Act
        X509Certificate x509Cert = KeyStoreUtils.createKeyStoreAndGetX509Certificate(KeyStoreUtils.CLIENT_ALIAS, KEYSTORE_PASSWORD, keystorePath.toString(), KEYSTORE_TYPE.toString())

        // Assert
        assert x509Cert

        // Assert certDN
        final String certDN = x509Cert.getIssuerDN().toString()
        logger.info("Certificate DN: ${certDN}")
        assert certDN == "OU=NiFi,CN=localhost"

        // Assert Key password is same as Keystore password
        boolean keyPassAndKeystorePassMatch = KeyStoreUtils.isKeyPasswordCorrect(keystorePath.toUri().toURL(), KEYSTORE_TYPE, KEYSTORE_PASSWORD.toCharArray(), KEYSTORE_PASSWORD.toCharArray())
        logger.info("Key password and Keystore password are the same: ${keyPassAndKeystorePassMatch}")
        assert keyPassAndKeystorePassMatch
    }

    @Test
    void testShouldValidateGetKeystoreType() {
        // Act
        List<String> jks = ["jks", "Jks"]
        List<String> pkcs12 = ["pkcs12", "Pkcs12"]

        final String EXPECTED_JKS = "JKS"
        final String EXPECTED_PKCS12 = "PKCS12"

        def jks_results = []
        def pkcs12_results = []

        // Arrange
        jks.each { String jks_input ->
            String correct_jks = KeyStoreUtils.getKeystoreType(jks_input)
            jks_results << correct_jks
        }

        pkcs12.each { String pkcs12_input ->
            String correct_pkcs12 = KeyStoreUtils.getKeystoreType(pkcs12_input)
            pkcs12_results << correct_pkcs12
        }

        // Assert
        assert jks_results.every { it == EXPECTED_JKS }
        assert pkcs12_results.every { it == EXPECTED_PKCS12 }
    }

    @Test
    void testShouldHandleInvalidKeystoreType() {
        // Arrange
        final String invalidKeystore = "bks"

        // Act
        def msg = shouldFail(IllegalArgumentException) {
            String invalidKS = KeyStoreUtils.getKeystoreType(invalidKeystore)
            logger.info("Invalid Keystore type: ${invalidKS}")
        }

        // Assert
        logger.expected(msg)
        assert msg =~ "The given Keystore type is not valid"
    }

    @Test
    void testShouldValidateGetKeystoreExtension() {
        // Act
        List<String> jks = ["jks", "Jks"]
        List<String> pkcs12 = ["pkcs12", "Pkcs12"]

        final String EXPECTED_JKS_EXTENSION = ".jks"
        final String EXPECTED_PKCS12_EXTENSION = ".p12"

        def jks_results = []
        def pkcs12_results = []

        // Arrange
        jks.each { String jks_input ->
            String correct_jks = KeyStoreUtils.getKeystoreExtension(jks_input)
            jks_results << correct_jks
        }

        pkcs12.each { String pkcs12_input ->
            String correct_pkcs12 = KeyStoreUtils.getKeystoreExtension(pkcs12_input)
            pkcs12_results << correct_pkcs12
        }

        // Assert
        assert jks_results.every { it == EXPECTED_JKS_EXTENSION }
        assert pkcs12_results.every { it == EXPECTED_PKCS12_EXTENSION }
    }

    @Test
    void testShouldHandleInvalidKeystoreExtension() {
        // Arrange
        final String invalidKeystore = "bks"

        // Act
        def msg = shouldFail(IllegalArgumentException) {
            String invalidKS = KeyStoreUtils.getKeystoreExtension(invalidKeystore)
            logger.info("Invalid Keystore type: ${invalidKS}")
        }

        // Assert
        logger.expected(msg)
        assert msg =~ "There was an error finding the appropriate Keystore extension"
    }

    // TODO: Add unit tests that handle errors, exceptions, existing keystore/truststores in path parameters, etc
}
