import org.apache.commons.lang3.StringUtils;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.Grizzly;
import org.glassfish.grizzly.attributes.Attribute;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.ssl.SSLBaseFilter;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.sni.SNIConfig;
import org.glassfish.grizzly.sni.SNIFilter;
import org.glassfish.grizzly.sni.SNIServerConfigResolver;
import org.glassfish.grizzly.ssl.SSLContextConfigurator;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;
import org.glassfish.grizzly.http.server.AddOn;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;

public class SniTest  {

    Server server;

    @Before
    public void prepareServer() throws IOException {
        server = new Server();
        server.startServer();
    }

    @After
    public void teardownServer() {
        server.stopServer();
    }

    @Test
    public void testClientServerSNI() throws Exception {
        System.out.println("A request to https://localhost:8081 should fail as SNI won't be passed in a non FQDN");
        System.out.println("It should work instead with https://localhost.localdomain:8081 (if present on /etc/hosts)");
        Thread.sleep(120000);
    }

    public class Server {
        private HttpServer webServer;

        SSLEngineConfigurator sslServerEngineConfig;

        protected void startServer() throws IOException {
            NetworkListener networkListener = new NetworkListener("sample-listener", "localhost", 8081);

            sslServerEngineConfig = new SSLEngineConfigurator(createSSLContextConfigurator().createSSLContext(), false, false, false);
            networkListener.setSSLEngineConfig(sslServerEngineConfig);

            webServer = HttpServer.createSimpleServer();
            webServer.addListener(networkListener);
            networkListener.setSecure(true);
            networkListener.registerAddOn(new SniAddOn());
            webServer.start();
        }

        protected void stopServer() {
            webServer.shutdownNow();
        }

        private SNIFilter getSniFilter() {
            final Attribute<String> sniHostAttr = Grizzly.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("sni-host-attr");

            SNIFilter sniFilter = new SNIFilter();
            sniFilter.setServerSSLConfigResolver(new SNIServerConfigResolver() {
                @Override
                public SNIConfig resolve(Connection connection, String hostname) {
                    sniHostAttr.set(connection, hostname);
                    if (StringUtils.isEmpty(hostname)) {
                        throw new IllegalArgumentException("SNI Has not been sent");
                    }
                    return SNIConfig.newServerConfig(sslServerEngineConfig);
                }
            });
            return sniFilter;
        }

        private SSLContextConfigurator createSSLContextConfigurator() {
            SSLContextConfigurator sslContextConfigurator = new SSLContextConfigurator();
            ClassLoader cl = SniTest.class.getClassLoader();

//            URL cacertsUrl = cl.getResource("sni_truststore_client");
//            if (cacertsUrl != null) {
//                sslContextConfigurator.setTrustStoreFile(cacertsUrl.getFile());
//                sslContextConfigurator.setTrustStorePass("mulepassword");
//            }
//
//            URL keystoreUrl = cl.getResource("sni_keystore_server");
//            if (keystoreUrl != null) {
//                sslContextConfigurator.setKeyStoreFile(keystoreUrl.getFile());
//                sslContextConfigurator.setKeyStorePass("mulepassword");
//                sslContextConfigurator.setKeyPass("mulepassword");
//            }

            URL cacertsUrl = cl.getResource("ssltest-cacerts.jks");
            if (cacertsUrl != null) {
                sslContextConfigurator.setTrustStoreFile(cacertsUrl.getFile());
                sslContextConfigurator.setTrustStorePass("changeit");
            }

            URL keystoreUrl = cl.getResource("ssltest-keystore.jks");
            if (keystoreUrl != null) {
                sslContextConfigurator.setKeyStoreFile(keystoreUrl.getFile());
                sslContextConfigurator.setKeyStorePass("changeit");
            }
            return sslContextConfigurator;
        }
        
        private class SniAddOn implements AddOn {

            public void setup(NetworkListener networkListener,
                    FilterChainBuilder builder) {
                // replace SSLFilter (if any) with SNIFilter
                final int idx = builder.indexOfType(SSLBaseFilter.class);
                if (idx != -1) {
                    builder.set(idx, getSniFilter());
                }
            }
        }        
    }
}
