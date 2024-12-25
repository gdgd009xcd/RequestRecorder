package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionActiveScanWrapper;
import java.awt.*;
import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.A_TAB_ICON;

@SuppressWarnings("serial")
public class MessageViewStatusPanel extends AbstractPanel {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private MacroBuilderUI mbui;

    /**
     * create new instance of MessageViewStatusPanel
     *
     * @param extscanwrapper
     * @param mbui
     * @param exthook
     * @return new instance of MessageViewStatusPanel
     */
    public static MessageViewStatusPanel newInstance(ExtensionActiveScanWrapper extscanwrapper,
                                                     MacroBuilderUI mbui,
                                                     ExtensionHook exthook) {
        return new MessageViewStatusPanel().buildThis(extscanwrapper, mbui, exthook);
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * see newInstance() method.<br>
     * In extended class, you must call super.buildThis(extscanwrapper, mbui, exthook) in your buildThis method.
     *
     * @param extscanwrapper
     * @param mbui
     * @param exthook
     * @return this instance
     */
    protected MessageViewStatusPanel buildThis(ExtensionActiveScanWrapper extscanwrapper,
                                               MacroBuilderUI mbui,
                                               ExtensionHook exthook) {
        setLayout(new BorderLayout());

        // without calling below method, then NULL pointer exception will be occured.
        this.setName(
                EnvironmentVariables.getZapResourceString("autoMacroBuilder.MessageViewStatusPanel.title.text"));

        this.setIcon(A_TAB_ICON);
        this.mbui = mbui;
        this.add(mbui.getMessageViewPanel());
        return this;
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     */
    protected MessageViewStatusPanel() {
        super();
    }

    public void setTabIndex(int tabIndex) {

    }
}
