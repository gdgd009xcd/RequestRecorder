package org.zaproxy.zap.extension.automacrobuilder.zap;

import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.A_TAB_ICON;

import java.io.IOException;
import javax.swing.*;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.view.SwingTimerFakeRunner;
import org.zaproxy.zap.model.SessionStructure;

@SuppressWarnings("serial")
public class PopUpItemSingleSend extends JMenuItem {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private HttpSender sender = null;

    @Deprecated private static HttpMethodHelper helper = new HttpMethodHelper();

    private BeforeMacroDoActionProvider beforemacroprovider = null;
    private PostMacroDoActionProvider postmacroprovider = null;
    private ExtensionHistory extensionHistory = null;

    PopUpItemSingleSend(
            MacroBuilderUI mbui,
            StartedActiveScanContainer acon,
            BeforeMacroDoActionProvider beforemacroprovider,
            PostMacroDoActionProvider postmacroprovider) {
        super(Constant.messages.getString("autoMacroBuilder.PopUpItemSingleSend.title.text"));
        this.beforemacroprovider = beforemacroprovider;
        this.postmacroprovider = postmacroprovider;
        this.setToolTipText(
                Constant.messages.getString("autoMacroBuilder.PopUpItemSingleSend.Tooltip.text"));
        this.setIcon(A_TAB_ICON);

        final StartedActiveScanContainer f_acon = acon;
        final MacroBuilderUI f_mbui = mbui;

        addActionListener(
                e -> {
                    singleSendSelectedRequest(f_mbui, f_acon);
                });
    }

    /**
     * send current selected Message in AutoMacroBuilder
     *
     * @param f_mbui
     * @param f_acon
     */
    private void singleSendSelectedRequest(
            MacroBuilderUI f_mbui, StartedActiveScanContainer f_acon) {

        PRequest newrequest = ZapUtil.getPRequestFromMacroRequest(f_mbui, false);

        if (newrequest != null) {

            f_mbui.clearMessageResponse();
            int selectedTabIndex = f_mbui.getSelectedTabIndexOfMacroRequestList();

            int currentSelectedPos =
                    f_mbui.getRequestJListSelectedIndexAtTabIndex(selectedTabIndex);

            ParmGenMacroTrace pmt = f_mbui.getParmGenMacroTraceAtTabIndex(selectedTabIndex);
            int subSequenceScanLimit = f_mbui.getSubSequenceScanLimit();
            int lastStepNo = pmt.getLastStepNo(currentSelectedPos, subSequenceScanLimit);
            final HttpMessage htmess = ZapUtil.getHttpMessageFromPRequest(newrequest);
            final ParmGenMacroTraceParams pmtParams =
                    new ParmGenMacroTraceParams(currentSelectedPos, lastStepNo, selectedTabIndex);
            ParmGenMacroTraceProvider pmtProvider = f_acon.getPmtProvider();
            SwingTimerFakeRunner runner =
                    new SwingTimerFakeRunner(
                            selectedTabIndex,
                            f_mbui,
                            new Runnable() {
                                @Override
                                public void run() {
                                    // by below calling methods, all three display
                                    // components(messageRequest/messageResponse/MacroComments)
                                    // will be updated by sending result.
                                    // messageRequest may have request being edited
                                    // in it's own StyledDocument,
                                    // but by result of sending messages,
                                    // it will modify request message
                                    // so must be update also messageRequest contents.
                                    // so contents being edited in messageRequest
                                    // may be discarded.
                                    f_mbui.updateCurrentSelectedRequestListDisplayContentsSpecific(
                                            false, false, false);
                                    f_mbui.showMessageViewOnWorkBench(1);
                                }
                            });
            pmtProvider.setUseSwingRunner(selectedTabIndex, runner);

            final Thread t =
                    new Thread(
                            new Runnable() {
                                @Override
                                public void run() {
                                    try {

                                        f_acon.addParmGenMacroTraceParams(pmtParams);
                                        HttpSender sender = getHttpSenderInstance();
                                        beforemacroprovider.setParameters(
                                                f_acon,
                                                htmess,
                                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                                sender);
                                        ThreadManagerProvider.getThreadManager()
                                                .beginProcess(beforemacroprovider);
                                        htmess.setTimeSentMillis(System.currentTimeMillis());
                                        pmt.send(sender, htmess);
                                        postmacroprovider.setParameters(
                                                f_acon,
                                                htmess,
                                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                                sender);
                                        ThreadManagerProvider.getThreadManager()
                                                .beginProcess(postmacroprovider);

                                        Session session = Model.getSingleton().getSession();
                                        HistoryReference ref =
                                                new HistoryReference(
                                                        session,
                                                        HistoryReference.TYPE_ZAP_USER,
                                                        htmess);
                                        final ExtensionHistory extHistory = getHistoryExtension();
                                        if (extHistory != null) {
                                            extHistory.addHistory(ref);
                                        }
                                        SessionStructure.addPath(
                                                Model.getSingleton(),
                                                ref,
                                                htmess); // must add SiteNode Tree.
                                    } catch (Exception exception) {
                                        LOGGER4J.error(exception.getMessage(), exception);
                                    } finally {
                                        shutdownHttpSender();
                                        runner.doneRunningInstance();
                                    }
                                }
                            });
            t.start();
            // no need t.join();
            // because there is swing action in HttpSender::sendAndReceive method,
            // so t.join will stop to dispatch swing event queue in current main thread.
        }
    }

    /**
     * Get HttpSender Instance
     *
     * <p>no need to use sender.shutdown.
     */
    public HttpSender getHttpSenderInstance() {
        if (sender == null) {
            sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return sender;
    }

    private ExtensionHistory getHistoryExtension() {
        if (this.extensionHistory == null) {
            this.extensionHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return this.extensionHistory;
    }

    /**
     * shudown HttpSender instance
     *
     * <p>and initialize it's parameter to null
     */
    public void shutdownHttpSender() {
        if (sender != null) {
            sender = null;
        }
    }

    @Deprecated
    private HttpMethod runMethod(HttpMessage msg) throws IOException {
        HttpMethod method = null;

        // HttpMethodParams params = new HttpMethodParams();
        // int sotimeout = params.getSoTimeout();
        // LOGGER4J.debug("default timeout:" + sotimeout);

        method = helper.createRequestMethod(msg.getRequestHeader(), msg.getRequestBody());
        HttpMethodParams params = method.getParams();
        int sotimeout = params.getSoTimeout();
        LOGGER4J.debug("default timeout:" + sotimeout);

        // Anyway, We disable followredirects
        method.setFollowRedirects(false);

        // ZAP: Use custom HttpState if needed

        getHttpSenderInstance().executeMethod(method, null);

        HttpMethodHelper.updateHttpRequestHeaderSent(msg.getRequestHeader(), method);

        return method;
    }

    @Deprecated
    private void send(HttpMessage msg) throws IOException {
        boolean isFollowRedirect = false;
        HttpMethod method = null;
        HttpResponseHeader resHeader = null;
        long starttime = 0;

        try {
            starttime = System.currentTimeMillis();
            method = runMethod(msg);
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
            // shutdownHttpSender();
            LOGGER4J.debug("release Connection and shutdown completed.");
            long endtime = System.currentTimeMillis();
            LOGGER4J.debug("runMethod lapse : " + (endtime - starttime) / 1000 + "sec.");
        }
    }
}
