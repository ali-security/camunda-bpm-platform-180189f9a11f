/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.connect.httpclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.net.NamedEndpoint;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.reactor.ssl.SSLSessionInitializer;
import org.apache.hc.core5.reactor.ssl.SSLSessionVerifier;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.reactor.ssl.TransportSecurityLayer;
import org.apache.hc.core5.util.Timeout;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * The async TLS upgrade of the bundled HTTP client must apply the built-in (JSSE)
 * hostname verification to the SSL engine whenever the hostname verification
 * policy asks for it, so a server presenting a trusted certificate that was
 * issued for another host is rejected (CVE-2026-71290).
 */
public class ClientTlsStrategyHostnameVerificationTest {

  protected static final String CERTIFICATE_HOST = "attacker.example";
  protected static final String TARGET_HOST = "victim.example";
  protected static final String PASSWORD = "changeit";
  protected static final int BUFFER_SIZE = 1 << 17;

  @ClassRule
  public static TemporaryFolder folder = new TemporaryFolder();

  protected static SSLContext serverContext;
  protected static SSLContext clientContext;

  @BeforeClass
  public static void createSslContexts() throws Exception {
    File keyStoreFile = new File(folder.getRoot(), "server.p12");
    generateKeyStore(keyStoreFile);

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream in = new FileInputStream(keyStoreFile)) {
      keyStore.load(in, PASSWORD.toCharArray());
    }
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
    serverContext = SSLContext.getInstance("TLS");
    serverContext.init(keyManagerFactory.getKeyManagers(), null, null);

    // the client trusts the server certificate, like a certificate issued by a trusted CA
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("server", keyStore.getCertificate("server"));
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    clientContext = SSLContext.getInstance("TLS");
    clientContext.init(null, trustManagerFactory.getTrustManagers(), null);
  }

  @Test
  public void shouldRejectCertificateOfOtherHostWithBuiltinHostnameVerification() {
    InMemoryTlsSession session = upgrade(HostnameVerificationPolicy.BUILTIN, TARGET_HOST);

    assertNotNull("A certificate issued for " + CERTIFICATE_HOST + " must not be accepted for " + TARGET_HOST,
        session.getFailure());
    assertTrue("Expected the TLS handshake to fail but got " + session.getFailure(),
        session.getFailure() instanceof SSLHandshakeException);
    assertEquals(URIScheme.HTTPS.id, session.getClientEngine().getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void shouldRejectCertificateOfOtherHostDuringHandshakeWithDefaultHostnameVerification() {
    InMemoryTlsSession session = upgrade(null, TARGET_HOST);

    assertTrue("Expected the TLS handshake to fail but got " + session.getFailure(),
        session.getFailure() instanceof SSLHandshakeException);
    assertEquals(URIScheme.HTTPS.id, session.getClientEngine().getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void shouldAcceptCertificateOfTargetHostWithBuiltinHostnameVerification() {
    InMemoryTlsSession session = upgrade(HostnameVerificationPolicy.BUILTIN, CERTIFICATE_HOST);

    assertNull("Unexpected TLS failure " + session.getFailure(), session.getFailure());
    assertTrue(session.isVerified());
    assertEquals(URIScheme.HTTPS.id, session.getClientEngine().getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void shouldLeaveHostnameVerificationToClientVerifierWithClientPolicy() {
    InMemoryTlsSession session = upgrade(HostnameVerificationPolicy.CLIENT, TARGET_HOST);

    assertNull(session.getClientEngine().getSSLParameters().getEndpointIdentificationAlgorithm());
    assertTrue("Expected the hostname verifier to reject the session but got " + session.getFailure(),
        session.getFailure() instanceof SSLPeerUnverifiedException);
  }

  protected InMemoryTlsSession upgrade(HostnameVerificationPolicy policy, String host) {
    DefaultClientTlsStrategy tlsStrategy = new DefaultClientTlsStrategy(clientContext, policy, null);
    InMemoryTlsSession session = new InMemoryTlsSession();

    tlsStrategy.upgrade(session, new HttpHost("https", host, 443), null, Timeout.ofSeconds(10), null);

    assertNotNull("The TLS strategy did not start TLS", session.getClientEngine());
    return session;
  }

  protected static void generateKeyStore(File keyStoreFile) throws Exception {
    String keytool = new File(new File(System.getProperty("java.home"), "bin"), "keytool").getAbsolutePath();
    Process process = new ProcessBuilder(keytool,
        "-genkeypair",
        "-alias", "server",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-dname", "CN=" + CERTIFICATE_HOST,
        "-ext", "SAN=dns:" + CERTIFICATE_HOST,
        "-validity", "2",
        "-keystore", keyStoreFile.getAbsolutePath(),
        "-storetype", "PKCS12",
        "-storepass", PASSWORD,
        "-keypass", PASSWORD,
        "-noprompt")
        .redirectErrorStream(true)
        .start();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (InputStream in = process.getInputStream()) {
      byte[] buffer = new byte[1024];
      int read;
      while ((read = in.read(buffer)) != -1) {
        output.write(buffer, 0, read);
      }
    }
    assertTrue("keytool did not finish in time", process.waitFor(60, TimeUnit.SECONDS));
    assertEquals("keytool failed: " + new String(output.toByteArray(), StandardCharsets.UTF_8), 0, process.exitValue());
  }

  /**
   * Runs the TLS session requested by a TLS strategy over in-memory SSL engines,
   * initializing, handshaking and verifying it the way the async I/O reactor does.
   */
  protected static class InMemoryTlsSession implements TransportSecurityLayer {

    protected SSLEngine clientEngine;
    protected SSLException failure;
    protected boolean verified;

    @Override
    public void startTls(SSLContext sslContext,
                         NamedEndpoint endpoint,
                         SSLBufferMode sslBufferMode,
                         SSLSessionInitializer initializer,
                         SSLSessionVerifier verifier,
                         Timeout handshakeTimeout) {
      clientEngine = sslContext.createSSLEngine(endpoint.getHostName(), endpoint.getPort());
      clientEngine.setUseClientMode(true);
      if (initializer != null) {
        initializer.initialize(endpoint, clientEngine);
      }

      SSLEngine serverEngine = serverContext.createSSLEngine();
      serverEngine.setUseClientMode(false);
      try {
        handshake(clientEngine, serverEngine);
        if (verifier != null) {
          verifier.verify(endpoint, clientEngine);
        }
        verified = true;
      } catch (SSLException e) {
        failure = e;
      }
    }

    @Override
    public TlsDetails getTlsDetails() {
      return null;
    }

    public SSLEngine getClientEngine() {
      return clientEngine;
    }

    public SSLException getFailure() {
      return failure;
    }

    public boolean isVerified() {
      return verified;
    }
  }

  protected static void handshake(SSLEngine client, SSLEngine server) throws SSLException {
    ByteBuffer empty = ByteBuffer.allocate(0);
    ByteBuffer clientToServer = ByteBuffer.allocate(BUFFER_SIZE);
    ByteBuffer serverToClient = ByteBuffer.allocate(BUFFER_SIZE);
    ByteBuffer clientData = ByteBuffer.allocate(BUFFER_SIZE);
    ByteBuffer serverData = ByteBuffer.allocate(BUFFER_SIZE);

    client.beginHandshake();
    server.beginHandshake();
    for (int i = 0; i < 200; i++) {
      if (!isHandshaking(client) && !isHandshaking(server)) {
        return;
      }
      // every engine operation rethrows a failure raised by a delegated task
      client.wrap(empty, clientToServer);
      runDelegatedTasks(client);
      server.wrap(empty, serverToClient);
      runDelegatedTasks(server);

      clientToServer.flip();
      serverToClient.flip();
      client.unwrap(serverToClient, clientData);
      runDelegatedTasks(client);
      server.unwrap(clientToServer, serverData);
      runDelegatedTasks(server);
      clientToServer.compact();
      serverToClient.compact();
    }
    throw new IllegalStateException("The TLS handshake did not complete");
  }

  protected static boolean isHandshaking(SSLEngine engine) {
    HandshakeStatus status = engine.getHandshakeStatus();
    return status != HandshakeStatus.NOT_HANDSHAKING && status != HandshakeStatus.FINISHED;
  }

  protected static void runDelegatedTasks(SSLEngine engine) {
    Runnable task;
    while ((task = engine.getDelegatedTask()) != null) {
      task.run();
    }
  }

}
