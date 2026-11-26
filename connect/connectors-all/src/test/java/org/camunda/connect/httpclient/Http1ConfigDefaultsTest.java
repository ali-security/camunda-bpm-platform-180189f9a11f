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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.apache.hc.core5.http.MessageConstraintException;
import org.apache.hc.core5.http.config.Http1Config;
import org.camunda.connect.ConnectorRequestException;
import org.camunda.connect.httpclient.impl.HttpConnectorImpl;
import org.junit.After;
import org.junit.Test;

/**
 * The HTTP/1.1 message parser defaults bundled with the connectors must bound
 * the number of response headers and the length of a response line, so a
 * malicious server cannot make the connector buffer an unbounded response head
 * (CVE-2026-54399).
 */
public class Http1ConfigDefaultsTest {

  protected ServerSocket serverSocket;
  protected Thread serverThread;

  @After
  public void stopServer() throws Exception {
    if (serverSocket != null) {
      serverSocket.close();
    }
    if (serverThread != null) {
      serverThread.join(5000);
    }
  }

  @Test
  public void shouldLimitHeaderCountAndLineLengthByDefault() {
    assertEquals(1024, Http1Config.DEFAULT.getMaxHeaderCount());
    assertEquals(8192, Http1Config.DEFAULT.getMaxLineLength());

    Http1Config config = Http1Config.custom().build();
    assertEquals(1024, config.getMaxHeaderCount());
    assertEquals(8192, config.getMaxLineLength());
  }

  @Test
  public void shouldKeepExplicitLimits() {
    Http1Config config = Http1Config.custom()
        .setMaxHeaderCount(-1)
        .setMaxLineLength(-1)
        .build();
    assertEquals(-1, config.getMaxHeaderCount());
    assertEquals(-1, config.getMaxLineLength());

    Http1Config copy = Http1Config.copy(config).build();
    assertEquals(-1, copy.getMaxHeaderCount());
    assertEquals(-1, copy.getMaxLineLength());
  }

  @Test
  public void shouldRejectResponseWithTooManyHeaders() throws Exception {
    StringBuilder headers = new StringBuilder();
    for (int i = 0; i < 5000; i++) {
      headers.append("X-Flood-").append(i).append(": v\r\n");
    }

    String url = serve(response(headers.toString()));

    assertResponseRejected(url);
  }

  @Test
  public void shouldRejectResponseWithOverlongHeaderLine() throws Exception {
    String headers = "X-Long: " + repeat('a', 64 * 1024) + "\r\n";

    String url = serve(response(headers));

    assertResponseRejected(url);
  }

  @Test
  public void shouldRejectResponseWithOverlongStatusLine() throws Exception {
    String url = serve("HTTP/1.1 200 " + repeat('a', 64 * 1024) + "\r\n"
        + "Content-Length: 2\r\n"
        + "Connection: close\r\n"
        + "\r\n"
        + "ok");

    assertResponseRejected(url);
  }

  @Test
  public void shouldAcceptResponseWithinDefaultLimits() throws Exception {
    StringBuilder headers = new StringBuilder();
    for (int i = 0; i < 1000; i++) {
      headers.append("X-Header-").append(i).append(": v\r\n");
    }
    String longValue = repeat('a', 8000);
    headers.append("X-Long: ").append(longValue).append("\r\n");

    String url = serve(response(headers.toString()));

    HttpResponse response = new HttpConnectorImpl().createRequest().get().url(url).execute();
    try {
      assertEquals(Integer.valueOf(200), response.getStatusCode());
      assertEquals(longValue, response.getHeader("X-Long"));
      assertEquals("v", response.getHeader("X-Header-999"));
      assertEquals("ok", response.getResponse());
    } finally {
      response.close();
    }
  }

  protected void assertResponseRejected(String url) {
    HttpConnector connector = new HttpConnectorImpl();
    try {
      HttpResponse response = connector.createRequest().get().url(url).execute();
      response.close();
      fail("Response head exceeding the default HTTP/1.1 limits must be rejected");
    } catch (ConnectorRequestException e) {
      assertTrue("Expected a MessageConstraintException cause but got " + e, hasCause(e, MessageConstraintException.class));
    }
  }

  protected static boolean hasCause(Throwable throwable, Class<? extends Throwable> type) {
    for (Throwable t = throwable; t != null; t = t.getCause()) {
      if (type.isInstance(t)) {
        return true;
      }
      if (t.getCause() == t) {
        break;
      }
    }
    return false;
  }

  protected static String response(String headers) {
    return "HTTP/1.1 200 OK\r\n"
        + headers
        + "Content-Length: 2\r\n"
        + "Connection: close\r\n"
        + "\r\n"
        + "ok";
  }

  protected static String repeat(char c, int count) {
    StringBuilder builder = new StringBuilder(count);
    for (int i = 0; i < count; i++) {
      builder.append(c);
    }
    return builder.toString();
  }

  /**
   * Starts a minimal HTTP server answering every request with the given raw response.
   */
  protected String serve(final String rawResponse) throws IOException {
    final ServerSocket socket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    serverSocket = socket;
    final byte[] responseBytes = rawResponse.getBytes(StandardCharsets.ISO_8859_1);

    serverThread = new Thread(() -> {
      while (!socket.isClosed()) {
        try (Socket client = socket.accept()) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
          String line;
          while ((line = reader.readLine()) != null && !line.isEmpty()) {
            // consume the request head
          }
          OutputStream out = client.getOutputStream();
          out.write(responseBytes);
          out.flush();
        } catch (IOException e) {
          // server socket closed or the client aborted the exchange
        }
      }
    });
    serverThread.setDaemon(true);
    serverThread.start();

    return "http://127.0.0.1:" + socket.getLocalPort() + "/";
  }

}
