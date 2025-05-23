/*
 * Copyright 2024 gdgd009xcd
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
package org.zaproxy.zap.extension.automacrobuilder.mdepend;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpMethodHelper;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.UUIDGenerator;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;
import org.zaproxy.zap.extension.forceduser.ExtensionForcedUser;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.users.User;

/**
 * @author gdgd009xcd
 */
public class ClientDependent {

    public enum CLIENT_TYPE {
        BURPSUITE,
        ZAP
    }

    private HttpRequestConfig httpRequestConfig = null;

    private ExtensionForcedUser extensionForcedUser = null;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public static final String LOG4JXML_DIR = Constant.getZapHome();

    private String comments = "";

    private boolean iserror = false;

    private UUID uuid = null;

    private HttpMessage currentmessage = null;

    // HttpMethodHelper has NO variable members. so, this instance can share any threads.

    @Deprecated private static HttpMethodHelper helper = new HttpMethodHelper();

    /**
     * get Client Type
     *
     * @return
     */
    public CLIENT_TYPE getClientType() {
        return ClientDependent.CLIENT_TYPE.ZAP;
    }

    /**
     * initialize this members.
     *
     * <p>members no need copy.
     */
    private void init() {
        comments = "";
        iserror = false;
        uuid = null;
        currentmessage = null;
    }

    public ClientDependent() {
        init();
        setUUID(UUIDGenerator.getUUID());
    }

    protected void burpSendToRepeater(
            String host, int port, boolean useHttps, byte[] messages, String tabtitle) {}

    protected void burpDoActiveScan(String host, int port, boolean useHttps, byte[] messages) {}

    protected void burpSendToIntruder(String host, int port, boolean useHttps, byte[] messages) {}

    protected PRequestResponse clientHttpRequest(PRequest request) {
        return null;
    }

    /**
     * Modified version runMethod. this method based on HttpSender class′s method No follow
     * redirects No authentication
     *
     * @param sender
     * @param msg
     * @return
     * @throws IOException
     */
    @Deprecated
    private HttpMethod runMethod(HttpSender sender, HttpMessage msg) throws IOException {
        HttpMethod method = null;

        // HttpMethodParams params = new HttpMethodParams();
        // int sotimeout = params.getSoTimeout();
        // LOGGER4J.debug("default timeout:" + sotimeout);

        method = helper.createRequestMethod(msg.getRequestHeader(), msg.getRequestBody());
        HttpMethodParams params = method.getParams();
        int sotimeout = params.getSoTimeout();
        LOGGER4J.debug("default timeout:" + sotimeout);

        // anyway, I decided to disable followRedirects
        method.setFollowRedirects(false);

        // ZAP: Use custom HttpState if needed

        sender.executeMethod(method, null);

        HttpMethodHelper.updateHttpRequestHeaderSent(msg.getRequestHeader(), method);

        return method;
    }

    /**
     * Send HttpMessage using specified sender. this method based on HttpSender class′s method No
     * follow redirects No authentication
     *
     * @param sender
     * @param msg
     * @throws IOException
     */
    @Deprecated
    public void sendDeprecated(HttpSender sender, HttpMessage msg) throws IOException {
        boolean isFollowRedirect = false;
        HttpMethod method = null;
        HttpResponseHeader resHeader = null;
        long starttime = 0;

        try {
            starttime = System.currentTimeMillis();
            method = runMethod(sender, msg);
            // successfully executed;
            resHeader = HttpMethodHelper.getHttpResponseHeader(method);
            resHeader.setHeader(
                    HttpHeader.TRANSFER_ENCODING,
                    null); // replaceAll("Transfer-Encoding: chunked\r\n",
            // "");
            msg.setResponseHeader(resHeader);
            msg.getResponseBody().setCharset(resHeader.getCharset());
            msg.getResponseBody().setLength(0);

            // ZAP: Do not read response body for Server-Sent Events stream
            // ZAP: Moreover do not set content length to zero
            if (!msg.isEventStream()) {
                msg.getResponseBody().append(method.getResponseBody());
            }
            msg.setResponseFromTargetHost(true);

            // ZAP: set method to retrieve upgraded channel later
            // if (method instanceof ZapGetMethod) {
            //    msg.setUserObject(method);
            // }
        } finally {
            if (method != null) {
                method.releaseConnection();
            }
            LOGGER4J.debug("release Connection and shutdown completed.");
            long endtime = System.currentTimeMillis();
            LOGGER4J.debug("runMethod lapse : " + (endtime - starttime) / 1000 + "sec.");
        }
    }

    /**
     * create RequestConfig
     *
     * @param httpAuthEnabled true: enable notifyListers false: disable notifyListeners
     * @return HttpRequestConfig instance
     */
    private HttpRequestConfig getHttpRequestConfig(boolean httpAuthEnabled) {
        if (httpRequestConfig == null || httpRequestConfig.isNotifyListeners() != httpAuthEnabled) {
            HttpRequestConfig.Builder builder = HttpRequestConfig.builder();
            builder.setFollowRedirects(false);
            builder.setNotifyListeners(httpAuthEnabled);
            httpRequestConfig = builder.build();
            int sotimeout = httpRequestConfig.getSoTimeout();
            LOGGER4J.debug("default timeout=" + sotimeout);
        }
        return httpRequestConfig;
    }

    private ExtensionForcedUser getExtensionForcedUserInstance() {
        if (extensionForcedUser == null) {
            extensionForcedUser = ZapUtil.getExtensionInstance(ExtensionForcedUser.class);
        }
        return extensionForcedUser;
    }

    private boolean isHttpAuthenticated(User user) {
        boolean httpAuthEnabled = false;
        org.zaproxy.zap.model.Context context = user.getContext();
        if (context != null) {
            AuthenticationMethod authenticationMethod = context.getAuthenticationMethod();
            if (authenticationMethod
                    instanceof HttpAuthenticationMethodType.HttpAuthenticationMethod) {
                httpAuthEnabled = true;
                LOGGER4J.debug("authenticationMethod is HttpAuthenticationMethod");
            } else {
                LOGGER4J.debug("authenticationMethod is not HttpAuthenticationMethod or null");
            }
        } else {
            LOGGER4J.debug("User::getContext returns null");
        }
        return httpAuthEnabled;
    }

    /**
     * send HttpMessage Without SenderListener and Authentication.
     *
     * @param sender
     * @param msg
     * @throws IOException
     */
    @Deprecated
    public void sendDeprecated20250401(HttpSender sender, HttpMessage msg) throws IOException {
        sender.setFollowRedirect(false); // No follow redirects

        msg.setRequestingUser(null); // No Authenticate

        User user = sender.getUser(msg); // user which is provided by sender through scanners.

        boolean httpAuthEnabled = false;
        if (user != null) {
            httpAuthEnabled = isHttpAuthenticated(user);
        } else {
            LOGGER4J.debug("HttpSender::getUser returns null");
        }

        if (httpAuthEnabled) {
            LOGGER4J.debug("sender user is httpAuthenticated");
            sender.setRemoveUserDefinedAuthHeaders(true);
        } else {
            sender.setUser(null); // No Authenticate
            List<Context> contexts = Model.getSingleton().getSession().getContexts();
            for (Context context : contexts) {
                if (context.isInContext(msg.getRequestHeader().getURI().toString())) {
                    // is enabled forceUser?
                    User forcedUser =
                            getExtensionForcedUserInstance().getForcedUser(context.getId());
                    if (forcedUser != null) {
                        httpAuthEnabled = isHttpAuthenticated(forcedUser);
                        if (httpAuthEnabled) {
                            LOGGER4J.debug("forcedUser is httpAuthenticated");
                            sender.setRemoveUserDefinedAuthHeaders(true);
                            break;
                        } else {
                            LOGGER4J.debug("forcedUser is Not HttpAuthenticated.");
                        }
                    } else {
                        LOGGER4J.debug("forced User is null");
                    }
                }
            }
        }

        ZapUtil.updateOriginalEncodedHttpMessage(msg);
        sender.sendAndReceive(msg, getHttpRequestConfig(true));
    }

    public void send(HttpSender sender, HttpMessage msg) throws IOException {
        sender.setFollowRedirect(false); // No follow redirects
        ZapUtil.updateOriginalEncodedHttpMessage(msg);
        sender.sendAndReceive(msg, getHttpRequestConfig(true));
    }

    public int getScanQuePercentage() {

        return -1;
    }

    protected void scanQueNull() {}

    /**
     * set UUID custom header unused function
     *
     * @param preq
     */
    protected void setUUID2CustomHeader(PRequest preq) {
        // preq.setUUID2CustomHeader(getUUID());
    }

    /**
     * set UUID unique that represents this instance
     *
     * @param uuid
     */
    private void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    /**
     * get UUID unique that represents this instance
     *
     * @return
     */
    public UUID getUUID() {
        return this.uuid;
    }

    public void clearComments() {
        comments = ""; // no null
    }

    public void addComments(String _v) {
        comments += _v + "\n";
    }

    void setComments(String _v) {
        comments = _v;
    }

    public String getComments() {
        return comments;
    }

    public void setError(boolean _b) {
        iserror = _b;
    }

    public boolean isError() {
        return iserror;
    }

    /** reset ZAP(HttpClient)'s cookie state */
    protected void resetZapCookieState(HttpSender sender) {
        sender.setUseCookies(false); // reset(clear) cookie state
        sender.setUseCookies(true);
    }
}
