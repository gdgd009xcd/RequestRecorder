package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManagerProvider;
import org.zaproxy.zap.extension.automacrobuilder.view.SwingTimerFakeRunner;
import org.zaproxy.zap.extension.automacrobuilder.zap.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

import javax.swing.*;
import java.awt.*;

@SuppressWarnings("serial")
public class PopUpMenuItem extends PopupMenuItemHttpMessageContainer {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static final long serialVersionUID = 1L;

    private String packageName;

    private MacroBuilderUI mbui;

    private HttpSender sender = null;

    private ExtensionHistory extensionHistory = null;
    StartedActiveScanContainer acon = null;

    /**
     * create new instance of PopUpMenuItem
     * you must define this in your extended classes for creating instance of your class
     *
     * @param mbui
     * @param acon
     * @param packageName
     * @param label
     * @param icon
     * @return PopUpMenuItem instance
     */
    public static PopUpMenuItem newInstance(MacroBuilderUI mbui, StartedActiveScanContainer acon,String packageName,
                                            String label, Icon icon) {
        return new PopUpMenuItem(mbui, acon,packageName, label, icon).buildThis(mbui, acon,packageName, label, icon);
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * see newInstance() method.<br>
     * In extended class, you must call super.buildThis() in your buildThis method.
     *
     * @param mbui
     * @param acon
     * @param packageName
     * @param label
     * @param icon
     * @return this instance
     */
    protected PopUpMenuItem buildThis(MacroBuilderUI mbui, StartedActiveScanContainer acon,String packageName,
                                      String label, Icon icon) {
        this.packageName = packageName;
        this.mbui = mbui;
        this.acon = acon;
        this.setToolTipText(Constant.messages.getString("autoMacroBuilder.PopUpItemSingleSend.Tooltip.text"));

        if (icon != null) {
            setIcon(icon);
        }
        setMenuIndex(1);
        return this;
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param mbui
     * @param acon
     * @param packageName
     * @param label
     * @param icon
     */
    protected PopUpMenuItem(MacroBuilderUI mbui, StartedActiveScanContainer acon,String packageName,
                         String label, Icon icon) {
        super(label);
    }

    @Override
    protected void performAction(HttpMessage message) {
        if (message != null) {
            String note = message.getNote();
            LOGGER4J.debug("PopUPMenu performed. note[" + note +"]");
            Integer[] pmtParmsArray = ZapUtil.callCustomActiveScanMethodReturner(
                    Integer[].class,
                    message,
                    "org.zaproxy.zap.extension.customactivescan.HttpMessageWithLCSResponse",
                    "getPmtParamsArray", null,null);

            ParmGenMacroTraceParams pmtParams = null;
            if (pmtParmsArray != null && pmtParmsArray.length > 0 && this.acon.hasCustomActiveScanPmtParamsByScanner(pmtParmsArray[0])) {
                int index = 0;
                for (Integer i : pmtParmsArray) {
                    index++;
                }

                pmtParams = new ParmGenMacroTraceParams(
                        pmtParmsArray[1],
                        pmtParmsArray[2],
                        pmtParmsArray[3]);
            }
            if (pmtParams != null) {
                singleSendMessage(message, pmtParams, this.mbui,this.acon);
            } else {
                JOptionPane.showMessageDialog(
                        this,
                        "err",
                        "eror",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public void singleSendMessage(HttpMessage message, ParmGenMacroTraceParams pmtParams, MacroBuilderUI f_mbui, StartedActiveScanContainer f_acon) {

        BeforeMacroDoActionProvider beforemacroprovider = new BeforeMacroDoActionProvider();
        PostMacroDoActionProvider postmacroprovider = new PostMacroDoActionProvider();

        if (message != null) {
            f_mbui.setSelectedRequestInRequestJlist(pmtParams.getTabIndex(), pmtParams.getSelectedRequestNo());
            f_mbui.clearMessageResponse();

            ParmGenMacroTrace pmt =
                    f_mbui.getParmGenMacroTraceAtTabIndex(pmtParams.getTabIndex());
            ParmGenMacroTraceProvider pmtProvider = f_acon.getPmtProvider();
            int tabIndex = pmtParams.getTabIndex();


            SwingTimerFakeRunner runner = new SwingTimerFakeRunner(tabIndex, f_mbui, new Runnable() {
                @Override
                public void run() {
                    f_mbui.updateCurrentSelectedRequestListDisplayContents();
                    f_mbui.showMessageViewOnWorkBench(1);
                }
            });

            pmtProvider.setUseSwingRunner(tabIndex, runner);

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
                                                message,
                                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                                sender);
                                        ThreadManagerProvider.getThreadManager()
                                                .beginProcess(beforemacroprovider);
                                        message.setTimeSentMillis(
                                                System.currentTimeMillis());
                                        pmt.send(sender, message);
                                        postmacroprovider.setParameters(
                                                f_acon,
                                                message,
                                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                                sender);
                                        ThreadManagerProvider.getThreadManager()
                                                .beginProcess(postmacroprovider);

                                        Session session = Model.getSingleton().getSession();
                                        HistoryReference ref =
                                                new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, message);
                                        final ExtensionHistory extHistory = getHistoryExtension();
                                        if (extHistory != null) {
                                            extHistory.addHistory(ref);
                                        }
                                        SessionStructure.addPath(Model.getSingleton(), ref, message);// must add SiteNode Tree.
                                    } catch (Exception exception) {
                                        LOGGER4J.error(exception.getMessage(), exception);
                                    } finally {
                                        shutdownHttpSender();
                                        runner.doneRunningInstance();
                                    }
                                }
                            });
            t.start();
            try {
                t.join();
            } catch (InterruptedException ex) {
                LOGGER4J.error("", ex);
            }
            /**
            SwingUtilities.invokeLater(
                    () -> {
                        f_mbui.updateCurrentSelectedRequestListDisplayContents();
                        f_mbui.showMessageViewOnWorkBench(1);
                    });**/
        }
    }

    @Override
    public boolean isEnableForMessageContainer(MessageContainer<?> messageContainer) {
        boolean result = super.isEnableForMessageContainer(messageContainer);
        if (this.acon.sizeOfCustomActiveScanPmtParamsByScanner()==0) return false;
        if (packageName != null && messageContainer != null) {
            Component compo =  messageContainer.getComponent();
            if (compo != null) {
                if (LOGGER4J.isDebugEnabled()) {
                    if (packageName.equals(compo.getClass().getName())) {

                        LOGGER4J.debug("is Enable compo is same Name clazz[" + packageName + "]==compo[" + compo.getClass().getName() + "]");
                    } else {
                        LOGGER4J.debug("is Enable compo is different Name clazz[" + packageName + "]" + "]<>compo[" + compo.getClass().getName() + "]");
                    }
                }
                Integer scannerId = ZapUtil.callCustomActiveScanMethodReturner(Integer.class,
                        compo,
                        packageName,
                        "getScannerId",
                        null,
                        null);
                if (scannerId != null) {
                    if (!this.acon.hasCustomActiveScanPmtParamsByScanner(scannerId)){
                        return false;
                    }
                } else {
                    return false;
                }
                return packageName.equals(compo.getClass().getName());
            }
        }
        return result;
    }

    private HttpSender getHttpSenderInstance() {
        if (sender == null) {
            sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return sender;
    }

    private ExtensionHistory getHistoryExtension() {
        if (this.extensionHistory == null) {
            this.extensionHistory = Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(
                            ExtensionHistory
                                    .class);
        }
        return this.extensionHistory;
    }

    private void shutdownHttpSender() {
        if (sender != null) {
            sender = null;
        }
    }
}

