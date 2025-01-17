package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.automacrobuilder.*;

public class BeforeMacroDoAction implements InterfaceDoAction {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private ThreadLocal<List<InterfaceAction>> ACTION_LIST = new ThreadLocal<>();

    BeforeMacroDoAction() {}

    /**
     * set parameters to be passed to StartBeforeMacroDoAction
     *
     * @param msg
     * @param initiator
     * @param sender
     */
    void setParameters(
            StartedActiveScanContainer acon, HttpMessage msg, int initiator, HttpSender sender) {
        // newly create ParmGenMacroTrace
        final ParmGenMacroTrace pmt = acon.getNewRunningInstance(sender);

        UUID uuid = pmt.getUUID();
        // Add uuid to StartedActiveScanContainer to get ParmGenMacroTrace later
        acon.addUUID(uuid);
        LOGGER4J.debug(
                "addUUID:"
                        + uuid.toString()
                        + " currentThread:"
                        + ParmGenUtil.getThreadId(Thread.currentThread()));

        List<InterfaceAction> actions = new CopyOnWriteArrayList<>();

        actions.add(
                (t, o) -> {
                    pmt.startBeforePreMacro(o);
                    if (msg != null) {
                        ParmGenMacroTrace.clientrequest.startZapCurrentRequest(pmt, msg);
                    }
                    return false;
                });

        ACTION_LIST.set(actions);
    }

    @Override
    public List<InterfaceAction> startAction(ThreadManager tm, OneThreadProcessor otp) {
        try {
            List<InterfaceAction> actions = ACTION_LIST.get();

            return actions;
        } catch (Exception e) {
            LOGGER4J.error("", e);
            return null;
        } finally {
            ACTION_LIST.remove();
        }
    }

    @Override
    public InterfaceEndAction endAction(ThreadManager tm, OneThreadProcessor otp) {
        return null;
    }
}
