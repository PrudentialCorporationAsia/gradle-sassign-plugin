/*
 * Copyright 2017 Prudential Corporation Asia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

package hk.com.prudential.gradle.sassign;

import com.symantec.ws.api.webtrust.codesigningservice.*;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;

import javax.annotation.Nonnull;
import javax.net.ssl.KeyManagerFactory;
import javax.xml.ws.BindingProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * The main interface to a SAS signer class. This is created through the internal
 * @see SasSignManager.Builder class.
 */
public class SasSignManager {
    private static final String AUTHTYPE_BASIC = "Basic";
    private static final String ERROR_SIGN_FAILED = "Signing failed";
    private static final String ERROR_INIT_FAILED = "Initialisation failed";
    private static final String ERROR_SERVICE_FAILED = "Service failed";
    private static final String ERROR_KEYSTORE_NOT_FOUND = "Keystore not found";

    /**
     * List of endpoints
     */
    public enum SasEndpoint {
        PROD("https://api.ws.symantec.com/webtrust/SigningService"),
        TEST("https://test-api.ws.symantec.com/webtrust/SigningService");

        private final String endpoint;

        /**
         * Create and enum of urls
         * @param endpoint The endpoint URL
         */
        SasEndpoint(final String endpoint) {
            this.endpoint = endpoint;
        }

        /**
         * @see Enum#toString()
         * @return The URL
         */
        @Override
        public String toString() {
            return endpoint;
        }
    }

    public enum SasSigningService {
        ANDROID(1342, "Android Code Signing");

        private final int serviceId;
        private final String serviceName;

        /**
         * Create and enum of urls
         * @param serviceId The signing service ID
         * @param serviceName The signing service name
         */
        SasSigningService(final int serviceId, final String serviceName) {
            this.serviceId = serviceId;
            this.serviceName = serviceName;
        }

        /**
         * Get the registered service ID
         * @return The service ID
         */
        public int getId() {
            return serviceId;
        }

        /**
         * Get the name of the service
         * @return The service name
         */
        public String getName() {
            return serviceName;
        }


        /**
         * @see Enum#toString()
         * @return The signing service name
         */
        @Override
        public String toString() {
            return String.format("%d: %s", serviceId, serviceName);
        }
    }

    private SasEndpoint endpoint = SasEndpoint.PROD;
    private AuthToken authToken = new AuthToken();
    private int publisherId = -1;

    private String keystore;
    private String keystorePassword;
    private String keystoreEntryPassword;

    private String proxyHost;
    private int proxyPort = 80;
    private String proxyUsername;
    private String proxyPassword;

    /**
     * Private constructor. Use the @see SasSignManager.Builder class.
     */
    private SasSignManager() {
    }

    public SasEndpoint getEndpoint() {
        return endpoint;
    }
    private void setEndpoint(@Nonnull SasEndpoint endpoint) {
        this.endpoint = endpoint;
    }
    public int getPublisherId() {
        return publisherId;
    }
    public void setPublisherId(int publisherId) {
        this.publisherId = publisherId;
    }
    public String getPartnerCode() {
        return authToken.getPartnerCode();
    }
    private void setPartnerCode(@Nonnull String partnerCode) {
        authToken.setPartnerCode(partnerCode);
    }
    public String getUsername() {
        return authToken.getUserName();
    }
    private void setUsername(@Nonnull String username) {
        authToken.setUserName(username);
    }
    private void setPassword(@Nonnull String password) {
        authToken.setPassword(password);
    }

    public String getKeystore() {
        return keystore;
    }
    private void setKeystore(@Nonnull String keystore) {
        this.keystore = keystore;
    }
    private void setKeystorePassword(@Nonnull String keystorePassword) {
        this.keystorePassword = keystorePassword;
        if (null == keystoreEntryPassword) setKeystoreEntryPassword(keystorePassword);
    }
    private void setKeystoreEntryPassword(@Nonnull String keystoreEntryPassword) {
        this.keystoreEntryPassword = keystoreEntryPassword;
    }

    public String getProxyHost() {
        return proxyHost;
    }
    private void setProxyHost(@Nonnull String proxyHost) {
        this.proxyHost = proxyHost;
    }
    public int getProxyPort() {
        return proxyPort;
    }
    private void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }
    public String getProxyUsername() {
        return proxyUsername;
    }
    private void setProxyUsername(@Nonnull String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }
    private void setProxyPassword(@Nonnull String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    /**
     * Builder class for the SAS signer manager
     */
    public static class Builder {
        private SasSignManager instance;

        public Builder() {
            instance = new SasSignManager();
        }

        public Builder setEndPoint(@Nonnull SasEndpoint endpoint) {
            instance.setEndpoint(endpoint);
            return this;
        }

        public Builder setPartnerCode(@Nonnull String partnerCode) {
            instance.setPartnerCode(partnerCode);
            return this;
        }

        public Builder setPublisherId(int publisherId) {
            instance.setPublisherId(publisherId);
            return this;
        }

        public Builder setUsername(@Nonnull String username) {
            instance.setUsername(username);
            return this;
        }

        public Builder setPassword(@Nonnull String password) {
            instance.setPassword(password);
            return this;
        }

        public Builder setKeystore(@Nonnull String keystore) {
            instance.setKeystore(keystore);
            return this;
        }

        public Builder setKeystorePassword(@Nonnull String keystorePassword) {
            instance.setKeystorePassword(keystorePassword);
            return this;
        }

        public Builder setKeystoreEntryPassword(@Nonnull String keystoreEntryPassword) {
            instance.setKeystoreEntryPassword(keystoreEntryPassword);
            return this;
        }

        public Builder setProxyHost(@Nonnull String proxyHost) {
            instance.setProxyHost(proxyHost);
            return this;
        }

        public Builder setProxyPort(@Nonnull int proxyPort) {
            instance.setProxyPort(proxyPort);
            return this;
        }

        public Builder setProxyUsername(@Nonnull String proxyUsername) {
            instance.setProxyUsername(proxyUsername);
            return this;
        }

        public Builder setProxyPassword(@Nonnull String proxyPassword) {
            instance.setProxyPassword(proxyPassword);
            return this;
        }

        public SasSignManager build() {
            return instance;
        }
    }

    /**
     * Sign an APK file
     */
    public void signApk(String filename, String applicationName, String version) throws SasSignException {
        signFiles(filename, SasSigningService.ANDROID, applicationName, version);
    }


    /**
     * Sign a file using a particular service
     * @param filename The file name to sign
     * @param signingService The service to sign with
     */
    private void signFiles(String filename, SasSigningService signingService, String applicationName, String version) throws SasSignException {
        File f = new File(filename);
        if (!f.exists() || !f.canRead()) {
            throw new SasSignException(ERROR_SIGN_FAILED, new IOException("signing file does not exist or cannot be read"));
        }

        RequestSigningRequestType signingRequest = new RequestSigningRequestType();
        signingRequest.setAuthToken(authToken);
        if (-1 != getPublisherId()) signingRequest.setPublisherID(publisherId);

        signingRequest.setApplication("String file in base64".getBytes(StandardCharsets.UTF_8));
        signingRequest.setApplicationName(applicationName);
        signingRequest.setApplicationVersion(version);
        signingRequest.setCommaDelimitedFileNames(f.getName());
        signingRequest.setSigningServiceName(signingService.toString());
    }


    /**
     * Get a list of the available signing services
     * @return The signing service names
     */
    public List<Integer> getSigningServices() throws SasSignException {
        SigningServicesRequestType servicesRequest = new SigningServicesRequestType();
        servicesRequest.setAuthToken(authToken);
        if (-1 != publisherId) servicesRequest.setPublisherID(publisherId);

        Signing signing = getConfiguredPort();
        SigningServicesResponseType servicesResponse = signing.getSigningServices(servicesRequest);

        checkResult(servicesResponse.getResult());

        List<Integer> responseIds = new ArrayList<>();
        List<String> actualResponse = servicesResponse.getSigningServiceIDs().getSigningServiceID();
        if (null != actualResponse) {
            for (String r : actualResponse) {
                responseIds.add(new Integer(r));
            }
        }
        return responseIds;
    }

    /**
     * Get details on a specific signing service
     * @param serviceId The service ID being requested
     * @return The signing service name
     */
    public String getSigningServiceDetails(int serviceId) throws SasSignException {
        SigningServiceDetailsRequestType serviceDetailsRequest = new SigningServiceDetailsRequestType();
        serviceDetailsRequest.setAuthToken(authToken);
        if (-1 != publisherId) serviceDetailsRequest.setPublisherID(publisherId);
        serviceDetailsRequest.setSigningServiceID(serviceId);

        Signing signing = getConfiguredPort();
        SigningServiceDetailsResponseType serviceDetailsResponse = signing.getSigningServiceDetails(serviceDetailsRequest);

        checkResult(serviceDetailsResponse.getResult());

        return serviceDetailsResponse.getSigningService().getSigningServiceName();
    }

    /**
     * Get a list of certificates
     * @return The the list of certificate friendly names
     */
    public List<String> getCertificates(SasSigningService signingService, boolean showEv) throws SasSignException {
        CertificateListRequestType certificateListRequest = new CertificateListRequestType();
        certificateListRequest.setAuthToken(authToken);
        if (-1 != publisherId) certificateListRequest.setPublisherID(publisherId);
        certificateListRequest.setSigningServiceName(signingService.getName());
        // FIXME: if (showEv) certificateListRequest.setReturnEvInd(Boolean.toString(showEv));

        Signing signing = getConfiguredPort();
        CertificateListResponseType certificateListResponse = signing.getCertificateList(certificateListRequest);

        checkResult(certificateListResponse.getResult());

        return certificateListResponse.getCertificateFriendlyNameList().getCertficateFriendlyName();
    }


    /**
     * Get details on a specific certificate
     * @param certificateName The name of the certificate being requested
     * @param signingService The signing service the certificate is tied to
     * @return The signing service name
     */
    public String getCertificateDetails(String certificateName, SasSigningService signingService) throws SasSignException {
        CertificateDetailsRequestType certificateDetailsRequest = new CertificateDetailsRequestType();
        certificateDetailsRequest.setAuthToken(authToken);
        if (-1 != publisherId) certificateDetailsRequest.setPublisherID(publisherId);
        certificateDetailsRequest.setCertificateFriendlyName(certificateName);
        certificateDetailsRequest.setSigningServiceName(signingService.getName());

        Signing signing = getConfiguredPort();
        CertificateDetailsResponseType certificateDetailsResponse = signing.getCertificateDetails(certificateDetailsRequest);

        checkResult(certificateDetailsResponse.getResult());

        // FIXME
        return certificateDetailsResponse.toString();
    }

    /**
     * Configure the conduit (proxy/keystore etc)
     */
    private Signing getConfiguredPort() throws SasSignException {
        // FIXME: import the WSDL from a local resource to avoid the initial request hit
        SigningService signingService = new SigningService();
        Signing signing = signingService.getSigningPort();

        Client client = ClientProxy.getClient(signing);
        HTTPConduit conduit = (HTTPConduit)client.getConduit();

        // Setup the endpoint address
        BindingProvider provider = (BindingProvider)signing;
        provider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpoint.toString());

        // Proxy setup
        if (null != proxyHost) {
            HTTPClientPolicy clientPolicy = conduit.getClient();
            clientPolicy.setProxyServer(proxyHost);
            clientPolicy.setProxyServerPort(proxyPort);
        }

        // If there is a proxy username & password. Only support basic ATM.
        // We set this even if no proxy host is set because of transparent proxies.
        ProxyAuthorizationPolicy proxyAuth = conduit.getProxyAuthorization();
        if (null != proxyUsername) {
            proxyAuth.setAuthorizationType(AUTHTYPE_BASIC);
            proxyAuth.setUserName(proxyUsername);
        }
        if (null != proxyPassword) {
            proxyAuth.setAuthorizationType(AUTHTYPE_BASIC);
            proxyAuth.setPassword(proxyPassword);
        }

        // SSL keystore. Use the standard JVM trust store
        if (null != keystore) {
            TLSClientParameters tlsClientParameters = conduit.getTlsClientParameters();
            if (null == tlsClientParameters) {
                tlsClientParameters = new TLSClientParameters();
            }

            // Prepare the KeyManager
            KeyManagerFactory keyManagerFactory;
            try {
                URI keystoreUri = new URI(keystore);
                // If no scheme, then assume it is a classpath resource
                InputStream keystoreStream;
                if (null == keystoreUri.getScheme()) {
                    keystoreStream = this.getClass().getResourceAsStream(keystore);
                    if (null == keystoreStream) {
                        throw new SasSignException(ERROR_KEYSTORE_NOT_FOUND);
                    }
                } else {
                    keystoreStream = keystoreUri.toURL().openStream();
                }


                keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                String keystoreType = keystoreUri.getPath().replaceAll("^.*\\.", "").toUpperCase();
                KeyStore keyStore = KeyStore.getInstance(keystoreType);

                // Setup the keystore parameters
                keyStore.load(keystoreStream, (null==keystorePassword?null:keystorePassword.toCharArray()));
                //keyStore.load(new FileInputStream(f), (null==keystorePassword?null:keystorePassword.toCharArray()));

                // Setup the key parameters
                keyManagerFactory.init(keyStore, (null==keystoreEntryPassword?null:keystoreEntryPassword.toCharArray()));
            } catch (URISyntaxException|NoSuchAlgorithmException|KeyStoreException|IOException|CertificateException|UnrecoverableKeyException e) {
                throw new SasSignException(ERROR_INIT_FAILED, e);
            }

            tlsClientParameters.setKeyManagers(keyManagerFactory.getKeyManagers());
        }

        return signing;
    }

    /**
     * Check a @see Result object for a good response
     * @param result The @see Result object
     * @throws SasSignException In the case of a bad response
     */
    private void checkResult(Result result) throws SasSignException {
        if (result.getResultCode() < 0) {
            throw new SasSignException(ERROR_SIGN_FAILED, new SasSignServiceException(ERROR_SERVICE_FAILED, result.getErrors()));
            // Failed, throw an exception
        }

        // Successful, but may have warnings
    }
}
