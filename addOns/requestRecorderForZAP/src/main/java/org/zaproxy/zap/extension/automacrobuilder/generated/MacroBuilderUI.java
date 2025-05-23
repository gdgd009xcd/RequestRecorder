/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.text.DefaultEditorKit;
import javax.swing.text.JTextComponent;
import javax.swing.text.StyledDocument;
import com.google.gson.JsonElement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.view.CloseXbtnTabPanel;
import org.zaproxy.zap.extension.automacrobuilder.view.JTextPaneContents;
import org.zaproxy.zap.extension.automacrobuilder.view.MyFontUtils;
import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;
import org.zaproxy.zap.extension.automacrobuilder.zap.view.DecoderSelector;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.LocaleUtils;

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.JSONFileIANACharsetName;
import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.ZAP_ICONS;
import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.A_TAB_ICON;
import static org.zaproxy.zap.extension.automacrobuilder.ListDeepCopy.listDeepCopyPRequestResponse;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class MacroBuilderUI extends javax.swing.JPanel implements  InterfaceParmGenRegexSaveCancelAction {

    
    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();
    
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private static final ImageIcon PLUS_BUTTON_ICON = MyFontUtils.getScaledIcon(
            new ImageIcon(MacroBuilderUI.class.getResource(ZAP_ICONS + "/plus.png")));
    public static final ImageIcon QUESTION_BUTTON_ICON = MyFontUtils.getScaledIcon(
            new ImageIcon(MacroBuilderUI.class.getResource(ZAP_ICONS + "/Q.png")));

    // List<PRequestResponse> rlist = null;
    // ParmGenMacroTrace pmt = null;
    
    ParmGenMacroTraceProvider pmtProvider = null;
    List<JList<String>> requestJLists = null;
    DisplayInfoOfRequestListTab displayInfo = null;
    int MacroRequestListTabsCurrentIndex = 0;
    int maxTabIndex = 0;// maximum index number of added tab to RequestList tab

    int EditTarget = -1;
    Encode EditPageEnc = Encode.ISO_8859_1;
    static final int REQUEST_DISPMAXSIZ = 500000;//0.5MB
    static final int RESPONSE_DISPMAXSIZ = 1000000;//1MB
    private static String RAILS_CSRF_PARAM = "csrf-param";
    public static String RAILS_CSRF_TOKEN = "csrf-token";


    JPanel plusBtnPanel = null;


    ExtensionAutoMacroBuilder extensionAutoMacroBuilder = null;

    /**
     * new instance method<br>
     * you must define this in your extended classes for instantiation
     *
     * @param pmtProvider
     * @param extensionAutoMacroBuilder
     * @return
     */
    public static MacroBuilderUI newInstance(ParmGenMacroTraceProvider pmtProvider, ExtensionAutoMacroBuilder extensionAutoMacroBuilder) {
        return new MacroBuilderUI(pmtProvider, extensionAutoMacroBuilder).buildThis(pmtProvider, extensionAutoMacroBuilder);
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param pmtProvider
     * @param extensionAutoMacroBuilder
     */
    @SuppressWarnings("unchecked")
    protected MacroBuilderUI(ParmGenMacroTraceProvider pmtProvider, ExtensionAutoMacroBuilder extensionAutoMacroBuilder) {
        super();
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * See newInstance() method.
     *
     * @param pmtProvider
     * @param extensionAutoMacroBuilder
     * @return this
     */
    protected MacroBuilderUI buildThis(ParmGenMacroTraceProvider pmtProvider, ExtensionAutoMacroBuilder extensionAutoMacroBuilder) {
        this.extensionAutoMacroBuilder = extensionAutoMacroBuilder;
        maxTabIndex = 0;
        this.MacroRequestListTabsCurrentIndex = 0;
        this.pmtProvider = pmtProvider;
        ParmGenMacroTrace pmt = this.pmtProvider.getBaseInstance(maxTabIndex);
        displayInfo = new DisplayInfoOfRequestListTab();
        requestJLists = new ArrayList<>();
        initComponents();
        jButton1.setIcon(QUESTION_BUTTON_ICON);
        MacroComments.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                MacroCommentsMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                MacroCommentsMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                MacroCommentsMouseClicked(evt);
            }
        });
        jLabel3.putClientProperty("html.disable", Boolean.FALSE);
        LOGGER4J.debug("MacroBuilderUI after initComponents");
        RequestList.setCellRenderer((ListCellRenderer<Object>)new MacroBuilderUIRequestListRender(pmt));
        DefaultListModel<String> RequestListModel = new DefaultListModel<>();
        RequestListModel.clear();
        RequestList.setModel(RequestListModel);

        requestJLists.add(RequestList);

        // Button for adding new Tab to JtabbedPane.
        addPlusTabButtonToRequestList();

        pmt.setUI(this);

        pmtProvider.setCBreplaceCookie(true);
        pmtProvider.setCBInheritFromCache(CBinheritFromCache.isSelected());
        pmtProvider.setCBFinalResponse(FinalResponse.isSelected());
        pmtProvider.setCBResetToOriginal(true);

        pmtProvider.setCBreplaceTrackingParam(isReplaceMode());

        // waittimer setting.
        WaitTimerCheckBoxActionPerformed(null);
        return this;
    }

    public javax.swing.JPopupMenu getPopupMenuForRequestList(){
        return PopupMenuForRequestList;
    }

    public javax.swing.JPopupMenu getPopupMenuRequestEdit() {
        return RequestEdit;
    }

    public javax.swing.JButton getScanMacroButton(){
        return StartScan;
    }

    boolean isReplaceMode(){
        boolean mode = true;
        String selected = (String)TrackMode.getSelectedItem();
        if(selected!=null){
            if(selected.equals("replace")){
                return true;
            }else{
                return false;
            }
        }
        return true;
        
    }

    /**
     * get ParmGenMacroTrace of selected tab<br>
     * <br>
     * Caution: This function may return null<br>
     * if there are no tabs selected in the macro request list.
     *
     * @return ParmGenMacroTrace or maybe null
     */
    public ParmGenMacroTrace getSelectedParmGenMacroTrace() {
        return this.pmtProvider.getBaseInstance(getSelectedTabIndexOfMacroRequestList());
    }

    /**
     * get tabIndex of current(default) value.<br>
     * current tab may be a tab with tabIndex 0 which means default tab.
     *
     * @return
     */
    public int getMacroRequestListTabsCurrentIndex() {
        return this.MacroRequestListTabsCurrentIndex;
    }

    /**
     * get ParmGenMacroTrace of current(default) tab<br>
     * current tab may be a tab with tabIndex 0 which means default tab.
     *
     * @return
     */
    public ParmGenMacroTrace getCurrentParmGenMacroTrace() {
        return getParmGenMacroTraceAtTabIndex(this.MacroRequestListTabsCurrentIndex);
    }

    /**
     * get ParmGenMacroTrace at specified tabIndex
     *
     * @param tabIndex
     * @return ParmGenMacroTrace or maybe null
     */
    public ParmGenMacroTrace getParmGenMacroTraceAtTabIndex(int tabIndex) {
        return this.pmtProvider.getBaseInstance(tabIndex);
    }
    
    /** 
     * get RequestList at specified tab index
     *
     * @param tabIndex
     * @return 
     */
    public List<PRequestResponse> getPRequestResponseListAtTabIndex(int tabIndex) {
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        if (pmt != null) {
            return pmt.getPRequestResponseList();
        }
        return null;
    }
    
    @SuppressWarnings("unchecked")
    public void clear() {
        this.MacroRequestListTabsCurrentIndex = 0;
        displayInfo = new DisplayInfoOfRequestListTab();
        requestJLists.forEach(list ->{
            DefaultListModel<String> defaultListModel = new DefaultListModel<>();
            // To clean up JList contents, you should replace ListModel instead of deleting Jlist contents.
            defaultListModel.removeAllElements();
            list.setModel(defaultListModel);
        });
        JList<String> requestJList = requestJLists.get(0);
        requestJLists.clear();
        requestJLists.add(requestJList);

        // remove Tabs except default tab.
        while (MacroRequestListTabs.getTabCount() > 1) {
            int lastTabIndex = MacroRequestListTabs.getTabCount() - 1;
            MacroRequestListTabs.remove(lastTabIndex);
        }
        // Button for adding new Tab to JtabbedPane.
        addPlusTabButtonToRequestList();

        messageRequest.setText("");
        messageResponse.setText("");

        MacroComments.setText("");
        this.pmtProvider.clear();
        this.maxTabIndex = 0;
        EnvironmentVariables.Saved(false);
    }

    @SuppressWarnings("unchecked")
    public ParmGenMacroTrace addNewRequests(List<PRequestResponse> _rlist) {
        AppParmsIni pini;
        
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(this.MacroRequestListTabsCurrentIndex);

        if (_rlist != null && pmt != null) {
            
            if (pmt != null) {
                pmt.setRecords(_rlist);
            }
            Iterator<PRequestResponse> it = pmt.getIteratorOfRlist();
            int ii = 0;

            JList<String> requestJList = getSelectedRequestJList();
            if (requestJList != null) {
                DefaultListModel<String> listModel = (DefaultListModel<String>) requestJList.getModel();
                listModel.removeAllElements();
                while (it.hasNext()) {

                    //model.addRow(new Object[] {false, pini.url, pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDsp(),pini.getAppValuesDsp(),pini.getCurrentValue()});
                    PRequestResponse pqr = it.next();
                    String url = pqr.request.getURL();
                    listModel.addElement((String.format("%03d",ii++) + '|' + url));
                }
                requestJList.setModel(listModel);
            }
        }

        return pmt;
    }


    /**
     * add PRequestResponses to ParmGenMacroTrace and add new tab which is created if necessary
     *
     * @param appParmAndSequence
     * @param maxTabIndex
     * @return
     */
    public ParmGenMacroTrace addNewRequestsToTabsPaneAtMaxTabIndex(ParmGenGSON.AppParmAndSequence appParmAndSequence, int maxTabIndex) {

        List<PRequestResponse> pRequestResponses= null;
        if (appParmAndSequence != null) {
            pRequestResponses = appParmAndSequence.pRequestResponses;
        }

        if (maxTabIndex < 0) {
            maxTabIndex = 0;
        }

        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(maxTabIndex);
        if (pmt == null) {
            pmt = pmtProvider.addNewBaseInstance();
            pmt.setUI(this);
        }

        if (appParmAndSequence != null && appParmAndSequence.appParmsIniList != null) {
            pmt.updateAppParmsIniAndClearCache(appParmAndSequence.appParmsIniList);
        }

        JList<String> requestJList = null;
        try {
            requestJList = getRequestJListAtTabIndex(maxTabIndex);
        } catch (Exception e) {
            // nothing to do with occuring exceptions.
        }
        if(requestJList == null) {
            requestJList = new javax.swing.JList<>();
            requestJList.setAutoscrolls(false);
            requestJList.addMouseListener(new java.awt.event.MouseAdapter() {
                public void mousePressed(java.awt.event.MouseEvent evt) {
                    RequestListMousePressed(evt);
                }
                public void mouseReleased(java.awt.event.MouseEvent evt) {
                    RequestListMouseReleased(evt);
                }
                public void mouseClicked(java.awt.event.MouseEvent evt) {
                    RequestListMouseClicked(evt);
                }
            });
            requestJList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
                public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                    RequestListValueChanged(evt);
                }
            });
            javax.swing.JScrollPane scrollPane = new JScrollPane();
            scrollPane.setAutoscrolls(true);
            scrollPane.setViewportView(requestJList);

            String tabIndexString = Integer.toString(maxTabIndex);

            MacroRequestListTabs.insertTab(tabIndexString, null, scrollPane, "", maxTabIndex);
            // setting close button on tab
            createCloseXbtnForTabbedPane(tabIndexString, maxTabIndex);

            requestJLists.add(requestJList);
        }
        requestJList.setCellRenderer((ListCellRenderer<Object>)new MacroBuilderUIRequestListRender(pmt));
        DefaultListModel<String> RequestListModel = new DefaultListModel<>();
        RequestListModel.clear();
        requestJList.setModel(RequestListModel);

        if (pRequestResponses != null && pmt != null) {

            if (pmt != null) {
                pmt.setRecords(pRequestResponses);
            }
            Iterator<PRequestResponse> it = pmt.getIteratorOfRlist();
            int ii = 0;


            if (requestJList != null) {
                DefaultListModel<String> listModel = (DefaultListModel<String>) requestJList.getModel();
                listModel.removeAllElements();
                while (it.hasNext()) {

                    //model.addRow(new Object[] {false, pini.url, pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDsp(),pini.getAppValuesDsp(),pini.getCurrentValue()});
                    PRequestResponse pqr = it.next();
                    String url = pqr.request.getURL();
                    listModel.addElement((String.format("%03d",ii++) + '|' + url));
                }
                requestJList.setModel(listModel);
            }
        }

        displayInfo.clearAll();

        return pmt;
    }

    /**
     * update GUI contents with Current Selected request
     *
     */
    public void updateCurrentSelectedRequestListDisplayContents() {
        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList != null) {
            int cpos = requestJList.getSelectedIndex();
            if (cpos != -1) { // current cpos request is displayed in MacroRequest.
                int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
                displayInfo.clearAll();
                displayInfo.selected_request_idx = cpos;
                messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
            }
        }
    }

    public void updateCurrentSelectedRequestListDisplayContentsSpecific(boolean isRemainRequest, boolean isRemainResponse, boolean isRemainComment) {
        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList != null) {
            int cpos = requestJList.getSelectedIndex();
            if (cpos != -1) { // current cpos request is displayed in MacroRequest.
                int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
                displayInfo.clearSpecific(isRemainRequest, isRemainResponse, isRemainComment);
                displayInfo.selected_request_idx = cpos;
                messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
            }
        }
    }


    private void Redraw() {
        //ListModel cmodel = RequestList.getModel();
        //RequestList.setModel(cmodel);
        LOGGER4J.debug("RequestList.repaint called.");
        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList != null) {
            requestJList.repaint();
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        PopupMenuForRequestList = new javax.swing.JPopupMenu();
        SendTo = new javax.swing.JMenu();
        Repeater = new javax.swing.JMenuItem();
        Scanner = new javax.swing.JMenuItem();
        Intruder = new javax.swing.JMenuItem();
        disableRequest = new javax.swing.JMenuItem();
        enableRequest = new javax.swing.JMenuItem();
        deleteRequest = new javax.swing.JMenuItem();
        showMessageView = new javax.swing.JMenuItem();
        RequestEdit = new javax.swing.JPopupMenu();
        editMenuItem = new javax.swing.JMenuItem();
        restoreMenuItem = new javax.swing.JMenuItem();
        updateMenuItem = new javax.swing.JMenuItem();
        decodeMenuItem = new javax.swing.JMenuItem();
        copyMenuItem = new javax.swing.JMenuItem(new DefaultEditorKit.CopyAction());
        pasteMenuItem = new javax.swing.JMenuItem(new DefaultEditorKit.PasteAction());
        ResponseShow = new javax.swing.JPopupMenu();
        showMenuItem = new javax.swing.JMenuItem();
        jScrollPane2 = new javax.swing.JScrollPane();
        jPanel4 = new javax.swing.JPanel();
        messageView = new javax.swing.JTabbedPane();
        requestView = new javax.swing.JPanel();
        requestScroller = new javax.swing.JScrollPane();
        messageRequest = new javax.swing.JTextPane();
        responseView = new javax.swing.JPanel();
        responseScroller = new javax.swing.JScrollPane();
        messageResponse = new javax.swing.JTextPane();
        trackingView = new javax.swing.JPanel();
        trackingScroller = new javax.swing.JScrollPane();
        MacroComments = new javax.swing.JTextArea();
        ParamTracking = new javax.swing.JButton();
        custom = new javax.swing.JButton();
        ClearMacro = new javax.swing.JButton();
        Load = new javax.swing.JButton();
        Save = new javax.swing.JButton();
        StartScan = new javax.swing.JButton();
        macroRequestListLabelTitle = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        CBinheritFromCache = new javax.swing.JCheckBox();
        jLabel4 = new javax.swing.JLabel();
        burpTrackingParameter = new javax.swing.JPanel();
        TrackMode = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        WaitTimerCheckBox = new javax.swing.JCheckBox();
        waitsec = new javax.swing.JTextField();
        MBfromStepNo = new javax.swing.JCheckBox();
        OtherOptionsLabelTitle = new javax.swing.JLabel();
        jPanel7 = new javax.swing.JPanel();
        FinalResponse = new javax.swing.JCheckBox();
        requestListNum = new javax.swing.JLabel();
        subSequenceScanLimit = new javax.swing.JTextField();
        jCheckBox1 = new javax.swing.JCheckBox();
        MBtoStepNo = new javax.swing.JCheckBox();
        MBmonitorofprocessing = new javax.swing.JCheckBox();
        UpSelected = new javax.swing.JButton();
        DownSelected = new javax.swing.JButton();
        MacroRequestListTabs = new javax.swing.JTabbedPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        RequestList = new javax.swing.JList<>();
        generalHelpBtn = new JButton(QUESTION_BUTTON_ICON);

        messageResponse.setEditable(false);

        generalHelpBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ExtensionHelp.showHelp("addon.automacrobuilder");
                AddOn addon = ZapUtil.getAddOnWithinExtension("ExtensionAutoMacroBuilder");
                if (addon != null) {
                    AddOn.HelpSetData helpSetData = addon.getHelpSetData();
                    if (helpSetData != null) {
                        if( !helpSetData.isEmpty() ){
                            LOGGER4J.info("baseName:" + helpSetData.getBaseName()
                                    + " locale:" + helpSetData.getLocaleToken() );
                        } else {
                            LOGGER4J.info("helpSetData is Empty");
                        }
                        ClassLoader classLoader = addon.getClassLoader();
                        URL helpSetUrl =
                                LocaleUtils.findResource(
                                        helpSetData.getBaseName(),
                                        "hs",
                                        helpSetData.getLocaleToken(),
                                        Constant.getLocale(),
                                        classLoader::getResource);
                        if (helpSetUrl == null) {
                            LOGGER4J.error("helpSetUrl is null");
                        } else {
                            LOGGER4J.info("helpSetUrl:" + helpSetUrl.toString());
                        }
                    }
                }
            }
        });




        SendTo.setText(bundle.getString("MacroBuilderUI.SENDTO.text")); // NOI18N

        Repeater.setText(bundle.getString("MacroBuilderUI.REPEATER.text")); // NOI18N
        Repeater.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RepeaterActionPerformed(evt);
            }
        });
        SendTo.add(Repeater);

        Scanner.setText(bundle.getString("MacroBuilderUI.SCANNER.text")); // NOI18N
        Scanner.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ScannerActionPerformed(evt);
            }
        });
        SendTo.add(Scanner);

        Intruder.setText(bundle.getString("MacroBuilderUI.INTRUDER.text")); // NOI18N
        Intruder.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IntruderActionPerformed(evt);
            }
        });
        SendTo.add(Intruder);

        PopupMenuForRequestList.add(SendTo);

        disableRequest.setText(bundle.getString("MacroBuilderUI.DISABLEREQUEST.text")); // NOI18N
        disableRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disableRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(disableRequest);

        enableRequest.setText(bundle.getString("MacroBuilderUI.ENABLEREQUEST.text")); // NOI18N
        enableRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enableRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(enableRequest);

        deleteRequest.setText(bundle.getString("MacroBuilderUI.DELETEREQUEST.text")); // NOI18N
        deleteRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(deleteRequest);

        showMessageView.setIcon(A_TAB_ICON);
        showMessageView.setText(bundle.getString("MacroBuilderUI.showMessageView.text")); // NOI18N
        showMessageView.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                final MacroBuilderUI ui = MacroBuilderUI.this;
                ui.showMessageViewOnWorkBench(-1);
            }
        });
        PopupMenuForRequestList.add(showMessageView);


        editMenuItem.setText(bundle.getString("MacroBuilderUI.REQUESTEDIT.text")); // NOI18N
        editMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editActionPerformed(evt);
            }
        });
        RequestEdit.add(editMenuItem);

        restoreMenuItem.setText(bundle.getString("MacroBuilderUI.restore.text")); // NOI18N
        restoreMenuItem.setToolTipText(bundle.getString("MacroBuilderUI.restore.tooltip.text"));
        restoreMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                restoreActionPerformed(evt);
            }
        });
        RequestEdit.add(restoreMenuItem);

        updateMenuItem.setText(bundle.getString("MacroBuilderUI.update.text")); // NOI18N
        updateMenuItem.setToolTipText(bundle.getString("MacroBuilderUI.update.tooltip.text"));
        updateMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateActionPerformed(evt);
            }
        });
        RequestEdit.add(updateMenuItem);

        decodeMenuItem.setText(bundle.getString("MacroBuilderUI.decode.text"));
        decodeMenuItem.setToolTipText(bundle.getString("MacroBuilderUI.decode.tooltip.text"));
        decodeMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DecodeMenuItemActionPerformed(e);
            }
        });
        RequestEdit.add(decodeMenuItem);

        copyMenuItem.setText(bundle.getString("MacroBuilderUI.copy.text"));
        RequestEdit.add(copyMenuItem);
        pasteMenuItem.setText(bundle.getString("MacroBuilderUI.paste.text"));
        RequestEdit.add(pasteMenuItem);

        showMenuItem.setText(bundle.getString("MacroBuilderUI.RESPONSESHOW.text")); // NOI18N
        showMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showActionPerformed(evt);
            }
        });
        ResponseShow.add(showMenuItem);

        setPreferredSize(new java.awt.Dimension(873, 850));

        jPanel4.setPreferredSize(new java.awt.Dimension(871, 1500));

        descriptionVacantArea = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        JLabel messageAreaMovedToStatusLabel = new JLabel();
        messageAreaMovedToStatusLabel.putClientProperty("html.disable", Boolean.FALSE);
        messageAreaMovedToStatusLabel.setText(bundle.getString("MacroBuilderUI.describeMessageView.text"));
        descriptionVacantArea.add(messageAreaMovedToStatusLabel);
        LineBorder lborder = new LineBorder(Color.BLACK, 2, false);
        descriptionVacantArea.setBorder(lborder);

        messageView.setPreferredSize(new java.awt.Dimension(847, 300));
        messageView.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                messageViewStateChanged(evt);
            }
        });


        messageRequest.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                messageRequestMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                messageRequestMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                messageRequestMouseClicked(evt);
            }
        });
        requestScroller.setViewportView(messageRequest);

        javax.swing.GroupLayout requestViewLayout = new javax.swing.GroupLayout(requestView);
        requestView.setLayout(requestViewLayout);
        requestViewLayout.setHorizontalGroup(
            requestViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(requestViewLayout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addComponent(requestScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
                .addGap(0, 0, 0))
        );
        requestViewLayout.setVerticalGroup(
            requestViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(requestScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(bundle.getString("MacroBuilderUI.messageViewToAddRequestTabTitle.text"), requestView); // NOI18N

        messageResponse.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                messageResponseMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                messageResponseMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                messageResponseMouseClicked(evt);
            }
        });
        responseScroller.setViewportView(messageResponse);

        javax.swing.GroupLayout responseViewLayout = new javax.swing.GroupLayout(responseView);
        responseView.setLayout(responseViewLayout);
        responseViewLayout.setHorizontalGroup(
            responseViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(responseScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
        );
        responseViewLayout.setVerticalGroup(
            responseViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(responseScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(bundle.getString("MacroBuilderUI.messageViewToAddResponseTabTitle.text"), responseView); // NOI18N

        trackingScroller.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        MacroComments.setColumns(20);
        MacroComments.setLineWrap(true);
        MacroComments.setRows(5);
        trackingScroller.setViewportView(MacroComments);

        javax.swing.GroupLayout trackingViewLayout = new javax.swing.GroupLayout(trackingView);
        trackingView.setLayout(trackingViewLayout);
        trackingViewLayout.setHorizontalGroup(
            trackingViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(trackingScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
        );
        trackingViewLayout.setVerticalGroup(
            trackingViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(trackingScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(
                bundle.getString("MacroBuilderUI.messageViewToAddTrackingTabTitle.text"),
                null,
                trackingView,
                bundle.getString("MacroBuilderUI.messageViewToAddTrackingTabToolTop.text")); // NOI18N


        messageViewPanel = new JPanel(new BorderLayout());
        messageViewPanel.add(messageView);

        ParamTracking.setText(bundle.getString("MacroBuilderUI.ParamTrackingBtn.text")); // NOI18N
        ParamTracking.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ParamTrackingActionPerformed(null, evt);
            }
        });

        custom.setText(bundle.getString("MacroBuilderUI.CUSTOM.text")); // NOI18N
        custom.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                customActionPerformed(evt);
            }
        });

        ClearMacro.setText(bundle.getString("MacroBuilderUI.ClearMacroBtn.text")); // NOI18N
        ClearMacro.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ClearMacroActionPerformed(evt);
            }
        });

        Load.setText(bundle.getString("MacroBuilderUI.LOAD.text")); // NOI18N
        Load.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LoadActionPerformed(evt);
            }
        });

        Save.setText(bundle.getString("MacroBuilderUI.SAVE.text")); // NOI18N
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });

        StartScan.setText(bundle.getString("MacroBuilderUI.StartScan.text")); // NOI18N
        StartScan.setEnabled(false);
        StartScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                StartScanActionPerformed(evt);
            }
        });

        macroRequestListLabelTitle.setText(bundle.getString("MacroBuilderUI.MacroRequestListLabelTitle.text")); // NOI18N
        // macroRequestListLabelTitle.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("MacroBuilderUI.TakeOverCache.text"))); // NOI18N

        CBinheritFromCache.setSelected(true);
        CBinheritFromCache.setText(bundle.getString("MacroBuilderUI.TakeOverCacheCheckBox.text")); // NOI18N
        CBinheritFromCache.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CBinheritFromCacheActionPerformed(evt);
            }
        });

        jLabel4.putClientProperty("html.disable", Boolean.FALSE);
        jLabel4.setText(bundle.getString("MacroBuilderUI.TakeOverInfoLabel.text")); // NOI18N

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(CBinheritFromCache, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addComponent(jLabel4)))
                .addContainerGap())
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(CBinheritFromCache)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 29, Short.MAX_VALUE)
                .addContainerGap())
        );

        burpTrackingParameter.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("MacroBuilderUI.TrackingParamBorder.text"))); // NOI18N

        TrackMode.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "replace", "baseline" }));
        TrackMode.setToolTipText("<HTML>\n[baseline] mode:<BR>\nthe token parameter value is changed only the baseline part , so which you can tamper by burp tools.<BR>\n<BR>\nyou can add test pattern in parameter value, e.g. '||'<BR>\nex.<BR>\ntoken=8B12C123'||' ===> token=A912D8VC'||'<BR><BR>\nNote:  In baseline mode,if you encounter problem which fails tracking tokens, you should select \"■update baseline■\" menu in BurpTool's popup menu.<BR>\n<BR>\n[replace] mode:<BR>\nthe token parameter value is completely replaced with tracking value, so which you cannot tamper by burp tools.<BR>\nex.<BR>\ntoken=8B12C123'||' ===> token=A912D8VC<BR>");
        TrackMode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TrackModeActionPerformed(evt);
            }
        });

        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        //jLabel3.setText("<HTML>\n<DL>\n<BR>\n<LI>baseline(experimental): you can test(tamper) tracking tokens<BR> with scanner/intruder which has baseline request.\n<LI>replace(default): Tracking tokens is completely replaced with extracted value from previous page's response.\n<BR><BR>* For Details , refer ?button in the \"baseline/replace mode\" section. \n<DL>\n</HTML>");
        jLabel3.setText(bundle.getString("MacroBuilderUI.TrackingParamterConfig.text"));
        jLabel3.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        //LineBorder lborder = new LineBorder(Color.RED, 2, false);
        //jLabel3.setBorder(lborder);


        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout burpTrackingParameterLayout = new javax.swing.GroupLayout(burpTrackingParameter);
        burpTrackingParameter.setLayout(burpTrackingParameterLayout);
        burpTrackingParameterLayout.setHorizontalGroup(
            burpTrackingParameterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(burpTrackingParameterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(burpTrackingParameterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(TrackMode, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        burpTrackingParameterLayout.setVerticalGroup(
            burpTrackingParameterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, burpTrackingParameterLayout.createSequentialGroup()
                .addContainerGap(14, Short.MAX_VALUE)
                .addGroup(burpTrackingParameterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(burpTrackingParameterLayout.createSequentialGroup()
                        .addComponent(TrackMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(39, 39, 39)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        // burpTrackingParameter is no need for ZAP.
        burpTrackingParameter = new JPanel();
        JLabel burpTrackingParameterPanelDisabledLabel = new JLabel();
        burpTrackingParameterPanelDisabledLabel.putClientProperty("html.disable", Boolean.FALSE);
        burpTrackingParameterPanelDisabledLabel.setText(bundle.getString("MacroBuilderUI.burpTrackingParameterPanelDisabledLabel.text"));
        burpTrackingParameter.add(burpTrackingParameterPanelDisabledLabel);

        WaitTimerCheckBox.setText("WaitTimer(sec)");
        WaitTimerCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                WaitTimerCheckBoxActionPerformed(evt);
            }
        });

        waitsec.setText("0");

        MBfromStepNo.setText(bundle.getString("MacroBuilderUI.FromStepBtn.text")); // NOI18N
        MBfromStepNo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MBfromStepNoActionPerformed(evt);
            }
        });

        OtherOptionsLabelTitle.setText("Other Options(Usually, you do not need chage options below.)");

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder("Pass response of subsequent request  back as the result of scan/resend request"));

        FinalResponse.setSelected(true);
        FinalResponse.setText(bundle.getString("MacroBuilderUI.FINAL RESPONSE.text")); // NOI18N
        FinalResponse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FinalResponseActionPerformed(evt);
            }
        });

        requestListNum.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        requestListNum.setText("subsequence scan limit");

        subSequenceScanLimit.setText("-1");
        subSequenceScanLimit.setToolTipText("maximum number of subsequent requests after scan/resend request currently being tested.");
        subSequenceScanLimit.setInputVerifier(new IntegerInputVerifier());
        subSequenceScanLimit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                subSequenceScanLimitActionPerformed(evt);
            }
        });

        jCheckBox1.setText("scan all from current target to [Subsequence scan limit]/[Final Response] ");
        jCheckBox1.setEnabled(false);
        jCheckBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jCheckBox1, javax.swing.GroupLayout.PREFERRED_SIZE, 569, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(FinalResponse, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(53, 53, 53)
                        .addComponent(requestListNum, javax.swing.GroupLayout.PREFERRED_SIZE, 178, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(subSequenceScanLimit, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel7Layout.createSequentialGroup()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(FinalResponse)
                    .addComponent(requestListNum)
                    .addComponent(subSequenceScanLimit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jCheckBox1))
        );

        MBtoStepNo.setText(bundle.getString("MacroBuilderUI.MBtoStepNo.text")); // NOI18N

        MBmonitorofprocessing.setText(bundle.getString("MacroBuilderUI.MBmonitorofprocessing.text")); // NOI18N
        MBmonitorofprocessing.setEnabled(false);
        MBmonitorofprocessing.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MBmonitorofprocessingActionPerformed(evt);
            }
        });

        UpSelected.setText(bundle.getString("MacroBuilderUI.UpSelected.text")); // NOI18N
        UpSelected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                UpSelectedActionPerformed(evt);
            }
        });

        DownSelected.setText(bundle.getString("MacroBuilderUI.DownSelected.text")); // NOI18N
        DownSelected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DownSelectedActionPerformed(evt);
            }
        });

        MacroRequestListTabs.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                MacroRequestListTabsStateChanged(evt);
            }
        });

        jScrollPane1.setAutoscrolls(true);

        RequestList.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        RequestList.setAutoscrolls(false);
        RequestList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                RequestListMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                RequestListMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                RequestListMouseClicked(evt);
            }
        });
        RequestList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                RequestListValueChanged(evt);
            }
        });
        jScrollPane1.setViewportView(RequestList);

        MacroRequestListTabs.addTab("0", jScrollPane1);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(generalHelpBtn, javax.swing.GroupLayout.Alignment.TRAILING,javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(macroRequestListLabelTitle, javax.swing.GroupLayout.PREFERRED_SIZE, 402, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(MacroRequestListTabs))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(custom, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ClearMacro, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ParamTracking, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Load, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Save, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(StartScan, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(UpSelected, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(DownSelected, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addContainerGap())
                    .addGroup(jPanel4Layout.createSequentialGroup()
                            .addComponent(OtherOptionsLabelTitle, javax.swing.GroupLayout.PREFERRED_SIZE, 826, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                            .addComponent(descriptionVacantArea, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addContainerGap())
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(WaitTimerCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(18, 18, 18)
                                .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, 68, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(150, 150, 150))
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(MBfromStepNo, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(26, 26, 26)))
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)

                            .addComponent(MBtoStepNo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(MBmonitorofprocessing, javax.swing.GroupLayout.PREFERRED_SIZE, 405, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jPanel7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(burpTrackingParameter, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))

                        .addGap(26, 26, 26))))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                    .addGroup(jPanel4Layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                        .addComponent(generalHelpBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(23, 23, 23))
                .addComponent(macroRequestListLabelTitle)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(42, 42, 42)
                        .addComponent(ParamTracking)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(custom)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ClearMacro)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(Load)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(Save)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(UpSelected)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(DownSelected)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(StartScan))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addComponent(MacroRequestListTabs, javax.swing.GroupLayout.PREFERRED_SIZE, 298, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(28, 28, 28)
                .addComponent(descriptionVacantArea, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(burpTrackingParameter, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(73, 73, 73)
                .addComponent(OtherOptionsLabelTitle)
                .addGap(18, 18, 18)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(WaitTimerCheckBox)
                    .addComponent(MBmonitorofprocessing)
                    .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(43, 43, 43)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(MBfromStepNo)
                    .addComponent(MBtoStepNo))
                .addContainerGap(121, Short.MAX_VALUE))
        );

        jScrollPane2.setViewportView(jPanel4);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 873, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 1437, Short.MAX_VALUE)
        );

        getAccessibleContext().setAccessibleName("");
    }// </editor-fold>//GEN-END:initComponents

    private void customActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_customActionPerformed
        /*
        * Open Custom Parameter Config dialog
        */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        List<String> poslist = requestJList.getSelectedValuesList();
        ArrayList<PRequestResponse> messages = new ArrayList<PRequestResponse>();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        if (prequestResponseList != null) {
            for (String s : poslist) {
                String[] values = s.split("[|]", 0);
                if (values.length > 0) {
                    int i = Integer.parseInt(values[0]);
                    PRequestResponse pqr = prequestResponseList.get(i);
                    pqr.setMacroPos(i);
                    messages.add(pqr);
                }
            }
        }
            

        pmt.updateAppParmsIniAndClearCache(null);
        CustomTrackingParamterConfigMain top = new CustomTrackingParamterConfigMain(
                this,
                Dialog.ModalityType.DOCUMENT_MODAL,
                pmt,
                new ParmGenGSONSaveV2(this.getParmGenMacroTraceProvider()),
                messages
        );


        top.VisibleWhenJSONSaved(this);
        updateSelectedTabIndex();


    }//GEN-LAST:event_customActionPerformed

    /**
     * load content to messageRequest TextPane if it is needed.
     *
     * @param selectedTabIndexOfRequestList
     * @return true - content is Newly loaded<BR>false - content is NOT loaded. the messageRequest remains with its current content.
     */
    private boolean messageRequestLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedMessageRequestContents) {
            
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);

            JTextPaneContents reqdoc = new JTextPaneContents(messageRequest);

            reqdoc.setRequestChunksWithDecodedCustomTag(pqr.request);

            displayInfo.isLoadedMessageRequestContents = true;
            return true;
        }
        return false;
    }


    
    private void messageResponseLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedmessageResponseContents) {
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);
            
            JTextPaneContents resdoc = new JTextPaneContents(messageResponse);
            resdoc.setResponseChunks(pqr.response);
            displayInfo.isLoadedmessageResponseContents = true;
        }
    }
    
    private void MacroCommentLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedMacroCommentContents) {
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);
            MacroComments.setText(pqr.getComments());
            displayInfo.isLoadedMacroCommentContents = true;
        }
    }

    /**
     * load when tabbed pane content is selected
     *
     * @param selectedTabIndexOfRequestList
     */
    private void messageViewTabbedPaneSelectedContentsLoad(int selectedTabIndexOfRequestList){
        int selIndex = messageView.getSelectedIndex();//tabbedpanes selectedidx 0start..
        switch(selIndex){
            case 0:
                messageRequestLoadContents(selectedTabIndexOfRequestList);
                break;
            case 1:
                messageResponseLoadContents(selectedTabIndexOfRequestList);
                break;
            case 2:
                MacroCommentLoadContents(selectedTabIndexOfRequestList);
                break;
            default:
                messageRequestLoadContents(selectedTabIndexOfRequestList);
                break;
        }
    }
    
    private void RequestListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_RequestListValueChanged
        /*
         * called when MacroRequestList item is selected
         */
        // TODO add your handling code here:
        // we need magical coding below,,,
        if (evt.getValueIsAdjusting()) {
            // The user is still manipulating the selection.
            return;
        }

        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList == null) return;
        LOGGER4J.debug("RequestListValueChanged Start...");
        int pos = requestJList.getSelectedIndex();
        if (pos != -1) {
            LOGGER4J.debug("RequestListValueChanged selected pos:" + pos);
            //
            int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
            displayInfo.clearAll();
            displayInfo.selected_request_idx = pos;
            messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
        } else {
            LOGGER4J.debug("RequestListValueChanged noselect pos:" + pos);
        }
        LOGGER4J.debug("RequestListValueChanged done");
    }//GEN-LAST:event_RequestListValueChanged

    private void CBinheritFromCacheActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CBinheritFromCacheActionPerformed
        /*
         * checkbox: at the start of sequence, session cache/Token value ia set from cache
         */
        // TODO add your handling code here:
        pmtProvider.setCBInheritFromCache(CBinheritFromCache.isSelected());
    }//GEN-LAST:event_CBinheritFromCacheActionPerformed

    private void WaitTimerCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox2ActionPerformed
        // TODO add your handling code here:
        ParmGenMacroTrace pmt = getSelectedParmGenMacroTrace();
        if (pmt != null) {
            if(WaitTimerCheckBox.isSelected()){
                pmtProvider.setWaitTimer(waitsec.getText());
            }else{
                pmtProvider.setWaitTimer("0");
            }
        }
    }//GEN-LAST:event_jCheckBox2ActionPerformed

    private void FinalResponseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FinalResponseActionPerformed
        // TODO add your handling code here:
        pmtProvider.setCBFinalResponse(FinalResponse.isSelected());
    }//GEN-LAST:event_FinalResponseActionPerformed

    private void RequestListMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMousePressed
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RequestListMousePressed

    private void disableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disableRequestActionPerformed
        /*
         * Disable selected request in ParmGenMacroTrace::rlist. this action does not affect ParmGenMacroTrace::originalrlist
         */
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                pmt.DisableRequest(pos);
            }
            Redraw();
        }
    }//GEN-LAST:event_disableRequestActionPerformed

    private void enableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enableRequestActionPerformed
        /*
         * Enable selected request in ParmGenMacroTrace::rlist. this action does not affect ParmGenMacroTrace::originalrlist
         */
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();

        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                pmt.EnableRequest(pos);
            }
            Redraw();
        }

    }//GEN-LAST:event_enableRequestActionPerformed

    private void RequestListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMouseClicked
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked
            JList<String> requestJList = getSelectedRequestJList();
            if (requestJList == null) return;
            int sidx = requestJList.locationToIndex(evt.getPoint());
            if (sidx > -1) {
                LOGGER4J.debug("RequestList mouse left button clicked: sidx:" + sidx);
                if (displayInfo.selected_request_idx == sidx){
                    requestJList.clearSelection();
                    requestJList.setSelectedIndex(sidx);
                    LOGGER4J.debug("clearSelection and setSelectidx:" + sidx);
                }
            }
        }
    }//GEN-LAST:event_RequestListMouseClicked

    private void RequestListMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RequestListMouseReleased

    @SuppressWarnings("serial")
    public void ParamTrackingActionPerformed(List<PRequestResponse> newPRequestResposeList, java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ParamTrackingActionPerformed
        // TODO add your handling code here:
        ParmGenMacroTrace pmt = getSelectedParmGenMacroTrace();
        if (pmt == null) return;

        List<PRequestResponse> originalList = pmt.getOriginalPRequestResponseList();
        List<PRequestResponse> mergedPRequestResponseList = originalList;;
        if (newPRequestResposeList != null) {
            mergedPRequestResponseList = listDeepCopyPRequestResponse(originalList);// copy original
            if (mergedPRequestResponseList != null) {
                mergedPRequestResponseList.addAll(newPRequestResposeList);// merge copied original with new one
            } else {
                mergedPRequestResponseList = newPRequestResposeList;// original is null , so choice new one.
            }
        }


        String choosedFileName = null;
        if (mergedPRequestResponseList != null && !mergedPRequestResponseList.isEmpty()) {
            if (!EnvironmentVariables.isSaved()) {
                if ((choosedFileName = EnvironmentVariables.saveMacroBuilderJSONFileChooser(this)) == null){
                    return;
                }
            }

            // setting page encoding
            // detemination of web page encoding.
            // extract page encoding from first web page response.
            PRequestResponse toppage = mergedPRequestResponseList.get(0);
            String tcharset = toppage.response.getCharset();

            String tknames[] = {// list of reserved token names
                    "PHPSESSID",
                    "JSESSIONID",
                    "SESID",
                    "TOKEN",
                    "_CSRF_TOKEN",
                    "authenticity_token",
                    "NONCE",
                    "access_id",
                    "fid",
                    "ethna_csrf",
                    "uniqid",
                    "oauth"
            };

            ArrayList<ParmGenResTokenCollections> urltokens = new ArrayList<>();// extracted token parameter from Responses.
            Pattern patternw32 = ParmGenUtil.Pattern_compile("\\w{32}");

            List<AppParmsIni> newparms = new ArrayList<AppParmsIni>();// generating parameter for tracking
            PRequestResponse respqrs = null;
            //int row = 0;
            int pos = 0;

            for (PRequestResponse pqrs : mergedPRequestResponseList) {
                HashMap<ParmGenTrackingToken, String> addedtokens = new HashMap<ParmGenTrackingToken, String>();// tokens already extracted from urltokens
                for (ListIterator<ParmGenResTokenCollections> it = urltokens.listIterator(urltokens.size()); it.hasPrevious(); ) {//urltokens: extracted tokenHashMap from Response.
                    //for loop order: fromStepno in descending order(hasPrevious)

                    ParmGenResTokenCollections resTokenCollections = it.previous();
                    Encode resEncode = resTokenCollections.resEncode;
                    int fromStepNo = resTokenCollections.fromStepNo;

                    ArrayList<ParmGenTrackingToken> requesttokenlist = new ArrayList<ParmGenTrackingToken>();// response tokens that matched request parameter.

                    // parse request for extracting JSON request parameters.
                    ParmGenGSONDecoder reqjdecoder = new ParmGenGSONDecoder(pqrs.request.getBodyStringWithoutHeader());
                    List<ParmGenToken> reqjtklist = reqjdecoder.parseJSON2Token();

                    ParmGenRequestToken _QToken = null;
                    ParmGenToken _RToken = null;

                    // searching for JSON token within request body
                    for (ParmGenToken reqtkn : reqjtklist) {

                        ParmGenToken foundResToken = resTokenCollections.findResponseToken(reqtkn);

                        if (foundResToken != null) {
                            //We found json tracking parameter in request.
                            _RToken = foundResToken;
                            _QToken = new ParmGenRequestToken(reqtkn);

                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                            if (!addedtokens.containsKey(tracktoken)) {
                                requesttokenlist.add(tracktoken);
                                addedtokens.put(tracktoken, "");
                            }
                        }
                    }

                    // searching for token within body or query in request.
                    for (ParmGenRequestToken requestToken : pqrs.request.getRequestTokens()) {
                        ParmGenToken foundResToken = resTokenCollections.findResponseToken(requestToken);

                        if (foundResToken != null) {

                            //add a token to  Query / Body Request parameter.
                            switch (foundResToken.getTokenKey().getTokenType()) {
                                case ACTION:
                                case HREF:

                                    ParmGenParseURL _psrcurl = new ParmGenParseURL(foundResToken.getTokenValue().getURL());
                                    ParmGenParseURL _pdesturl = new ParmGenParseURL(pqrs.request.getURL());
                                    String srcurl = _psrcurl.getPath();
                                    String desturl = _pdesturl.getPath();
                                    LOGGER4J.debug("srcurl|desturl:[" + srcurl + "]|[" + desturl + "]");
                                    if (desturl.indexOf(srcurl) != -1) {// ACTION SRC/HREF attribute's path == destination request path
                                        _RToken = foundResToken;
                                        if (requestToken != null) {
                                            //We found same name/value ACTION/HREF's query paramter in request's query parameter.
                                            _QToken = requestToken;
                                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                            if (!addedtokens.containsKey(tracktoken)) {
                                                requesttokenlist.add(tracktoken);
                                                addedtokens.put(tracktoken, "");
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    _RToken = foundResToken;
                                    if (requestToken != null) {
                                        //We found same name/value INPUT TAG(<INPUT type=...>)'s paramter in request's query parameter.
                                        _QToken = requestToken;
                                        ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                        if (!addedtokens.containsKey(tracktoken)) {
                                            requesttokenlist.add(tracktoken);
                                            addedtokens.put(tracktoken, "");
                                        }
                                    }
                                    break;
                            }
                        }
                    }

                    //searching for token within Request-Line/bearer/cookie in request headers
                    ArrayList<HeaderPattern> hlist = pqrs.request.hasMatchedValueExistInHeaders(resTokenCollections);
                    if (hlist != null && hlist.size() > 0) {
                        for (HeaderPattern hpattern : hlist) {
                            _QToken = hpattern.getQToken();
                            _RToken = hpattern.getFoundResponseToken();
                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, hpattern.getTokenValueRegex());
                            if (!addedtokens.containsKey(tracktoken)) {
                                requesttokenlist.add(tracktoken);
                                addedtokens.put(tracktoken, "");
                            }
                        }
                    }

                    if (requesttokenlist.size() > 0) {//tracking parameters are generated from requesttokenlist.
                        // construct tracking parameter configrations.
                        AppParmsIni aparms = new AppParmsIni();//add new record
                        //request URL
                        //String TargetURLRegex = ".*" + pqrs.request.getPath() + ".*";
                        String TargetURLRegex = ".*";//SetTo any
                        //boolean isformdata = pqrs.request.isFormData();
                        aparms.setUrl(TargetURLRegex);
                        aparms.setLen(4);//default
                        aparms.setTypeVal(AppParmsIni.T_TRACK);
                        aparms.setIniVal(0);
                        aparms.setMaxVal(0);
                        aparms.setCsvName("");
                        aparms.initPause(false);
                        // aparms.parmlist = new ArrayList<AppValue>();
                        if (MBfromStepNo.isSelected()) {
                            aparms.setTrackFromStep(fromStepNo);
                        } else {
                            aparms.setTrackFromStep(-1);
                        }

                        if (MBtoStepNo.isSelected()) {
                            aparms.setSetToStep(pos);
                        } else {
                            aparms.setSetToStep(EnvironmentVariables.TOSTEPANY);
                        }

                        for (ParmGenTrackingToken PGTtkn : requesttokenlist) {
                            AppValue apv = new AppValue();

                            _QToken = PGTtkn.getRequestToken();
                            _RToken = PGTtkn.getResponseToken();
                            ParmGenRequestTokenKey.RequestParamType rptype = _QToken.getKey().getRequestParamType();
                            String token = _RToken.getTokenKey().getName();
                            //body/query/header
                            String valtype = "query";

                            switch (rptype) {
                                case Query:
                                    break;
                                case Header:
                                    valtype = "header";
                                    break;
                                case Request_Line:
                                    valtype = "path";
                                    break;
                                default:
                                    valtype = "body";
                                    break;
                            }

                            apv.setHttpSectionTypeEmbedToExported(valtype);
                            apv.clearNoCountExported();
                            apv.setCsvpos(-1);
                            // (?:[&=?]+|^)token=(value)

                            String value = _RToken.getTokenValue().getValue();
                            apv.setResFetchedValue(value);
                            int len = value.length();// For Future use. len is currently No Used. len: token value length. May be,we should be specified len into regex's token value length
                            String paramname = token;
                            if (_QToken != null) {// May be Request Token name(_QToken's Name) != Response Token name(_RToken's name)
                                int rlen = _QToken.getValue().length();
                                if (len < rlen) len = rlen;
                                paramname = _QToken.getKey().getName();
                            }

                            apv.setUrlEncode(true); // www-form-urlencoded default

                            String regex = "(?:[&=?]|^)" + ParmGenUtil.escapeRegexChars(paramname) + "=([^&=\\r\\n ;#]+)";//default regex. It may be necessary to set the embedding token value length.
                            switch (rptype) {
                                case Form_data:
                                    regex = "(?:[A-Z].* name=\"" + ParmGenUtil.escapeRegexChars(paramname) + "\".*(?:\\r|\\n|\\r\\n))(?:[A-Z].*(?:\\r|\\n|\\r\\n)){0,}(?:\\r|\\n|\\r\\n)(?:.*?)(.+)";
                                    apv.setUrlEncode(false);
                                    break;
                                case Json:
                                    regex = "\"" + ParmGenUtil.escapeRegexChars(paramname) + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)\"(.+?)\"(?:[\\t \\]\\r\\n]*)(?:,|})";
                                    List<String> jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, pqrs.request.getBodyStringWithoutHeader());
                                    boolean jsonmatched = false;
                                    String jsonvalue = _QToken.getValue();

                                    if (jsonmatchlist != null && jsonmatchlist.size() > 0) {
                                        jsonmatched = true;
                                    }
                                    if (!jsonmatched) {// "key": value
                                        regex = "\"" + ParmGenUtil.escapeRegexChars(paramname) + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)([^,:{}\\\"]+?)(?:[\\t \\]\\r\\n]*)(?:,|})";
                                        jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, pqrs.request.getBodyStringWithoutHeader());

                                        if (jsonmatchlist != null && jsonmatchlist.size() > 0) {
                                            jsonmatched = true;
                                        }
                                    }
                                    apv.setUrlEncode(false);
                                    break;
                                case X_www_form_urlencoded:
                                    regex = "(?:[&=?]|^)" + ParmGenUtil.escapeRegexChars(paramname) + "=([^&=]+)";
                                    break;
                                case Request_Line:
                                    regex = PGTtkn.getRegex();
                                    apv.setUrlEncode(true);
                                    break;
                                case Header:
                                    regex = PGTtkn.getRegex();
                                    apv.setUrlEncode(false);
                                    break;
                            }


                            String encodedregex = regex;
                            try {
                                encodedregex = URLEncoder.encode(regex, JSONFileIANACharsetName);
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(MacroBuilderUI.class.getName()).log(Level.SEVERE, null, ex);

                            }
                            apv.setURLencodedVal(encodedregex);
                            //apv.setresURL(".*" + restoken.request.getPath() + ".*");
                            apv.setRegexTrackURLFromExported(".*");//TrackFrom any URL
                            apv.setResRegexURLencoded("");
                            AppValue.HttpSectionTypes httpSectionTypeTrackFrom = AppValue.HttpSectionTypes.ResponseBody;
                            switch (_RToken.getTokenKey().getTokenType()) {
                                case LOCATION:
                                    httpSectionTypeTrackFrom = AppValue.HttpSectionTypes.Header;
                                    break;
                                case XCSRF:
                                    break;
                                default:
                                    break;

                            }
                            apv.setHttpSectionTypeTrackFrom(httpSectionTypeTrackFrom);
                            apv.setPositionTrackFrom(_RToken.getTokenKey().getFcnt());
                            apv.setParamNameTrackFrom(token);


                            apv.setFromStepNo(-1);

                            apv.setToStepNo(EnvironmentVariables.TOSTEPANY);
                            apv.setTokenTypeTrackFrom(_RToken.getTokenKey().getTokenType());
                            apv.setEnabledExported(_RToken.isEnabled());
                            aparms.addAppValue(apv);
                        }
                        //aparms.setRow(row);
                        //row++;
                        //aparms.crtGenFormat(true);
                        newparms.add(aparms);
                    }

                }


                // analyze response for finding tracking tokens.
                String body = pqrs.response.getBodyStringWithoutHeader();

                String res_contentMimeType = pqrs.response.getContentMimeType();// Content-Type's Mimetype: ex. "text/html"

                // Content-Type/subtype matched excludeMimeType then skip below codes..
                if (!EnvironmentVariables.isMimeTypeExcluded(res_contentMimeType)) {
                    //### skip start
                    // extract parameter and it's value from response body.
                    ParmGenParser pgparser = new ParmGenParser(body);
                    List<ParmGenToken> bodytklist = pgparser.getNameValues();
                    ParmGenArrayList tklist = new ParmGenArrayList();// tklist: tracking token list
                    ParmGenResTokenCollections trackurltoken = new ParmGenResTokenCollections();
                    //trackurltoken.request = pqrs.request;
                    trackurltoken.resTokenUrlDecodedNameSlashValueHash = new HashMap<>();
                    trackurltoken.resTokenUrlDecodedNameHash = new HashMap<>();
                    trackurltoken.resTokenUrlDecodedValueHash = new HashMap<>();
                    trackurltoken.resEncode = pqrs.response.getPageEnc();
                    InterfaceCollection<ParmGenToken> ic = pqrs.response.getLocationTokens(tklist);
                    //JSON parse
                    ParmGenGSONDecoder jdecoder = new ParmGenGSONDecoder(body);
                    List<ParmGenToken> jtklist = jdecoder.parseJSON2Token();

                    //add extracted tokens to tklist
                    tklist.addAll(bodytklist);
                    tklist.addAll(jtklist);

                    for (ParmGenToken token : tklist) {
                        //PHPSESSID, token, SesID, jsessionid
                        String tokenName = token.getTokenKey().getName();
                        String tokenValue = token.getTokenValue().getValue();
                        if (tokenName != null && !tokenName.isEmpty() && tokenValue != null && !tokenValue.isEmpty()) { // token must have name and value.
                            boolean namematched = false;
                            for (String tkn : tknames) {// Tests if a parameter name matches a reserved token name in tknames
                                if (tokenName.equalsIgnoreCase(tkn)) {// matched totally.
                                    namematched = true;
                                    break;
                                }
                            }
                            if (!namematched) {// if no parameter name matched reserved token names
                                for (String tkn : tknames) {
                                    if (tokenName.toUpperCase().indexOf(tkn.toUpperCase()) != -1) {//tokenname partially matched reserved token name
                                        namematched = true;
                                        break;
                                    }
                                }
                                if (ParmGenUtil.isTokenValue(tokenValue)) {// token value that looks like tracking token
                                    namematched = true;
                                }
                            }

                            token.setEnabled(namematched);//namematched==true: token that looks like tracking token
                            String urlDecodedTokenName = ParmGenUtil.URLdecode(tokenName, trackurltoken.resEncode.getIANACharsetName());
                            String urlDecodedTokenValue = ParmGenUtil.URLdecode(tokenValue, trackurltoken.resEncode.getIANACharsetName());
                            String nameSlashValue = urlDecodedTokenName + "/" + urlDecodedTokenValue;
                            trackurltoken.resTokenUrlDecodedNameSlashValueHash.put(nameSlashValue, token);
                            trackurltoken.resTokenUrlDecodedNameHash.put(urlDecodedTokenName, token);
                            trackurltoken.resTokenUrlDecodedValueHash.put(urlDecodedTokenValue, token);
                            trackurltoken.fromStepNo = pos;
                        }

                    }

                    // handling rails token in meta tag
                    ParmGenToken csrfParamNameToken = trackurltoken.resTokenUrlDecodedNameHash.get(RAILS_CSRF_PARAM);
                    if (csrfParamNameToken != null && csrfParamNameToken.getTokenKey().getTokenType() == AppValue.TokenTypeNames.META) {
                        String authenticityTokenName = csrfParamNameToken.getTokenValue().getValue();
                        ParmGenToken csrfTokenValue = trackurltoken.resTokenUrlDecodedNameHash.get(RAILS_CSRF_TOKEN);
                        if (csrfTokenValue != null && csrfTokenValue.getTokenKey().getTokenType() == AppValue.TokenTypeNames.META) {
                            trackurltoken.resTokenUrlDecodedNameHash.put(authenticityTokenName, csrfTokenValue);
                        }
                    }

                    if (!trackurltoken.resTokenUrlDecodedNameSlashValueHash.isEmpty()) {
                        urltokens.add(trackurltoken);
                    }
                    //### skip end
                } else {
                    LOGGER4J.debug("automacro:Response analysis skipped stepno:" + pos + " MIMEtype:" + res_contentMimeType);
                }


                pos++;
            }

            LOGGER4J.debug("newparms.size=" + newparms.size());
            ParmGenTokenJDialog.newInstance(this,
                    choosedFileName,
                    pmtProvider,
                    Dialog.ModalityType.DOCUMENT_MODAL,
                    newPRequestResposeList,
                    newparms,
                    pmt).setVisible(true);
        }
    }//GEN-LAST:event_ParamTrackingActionPerformed

    private void ClearMacroActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ClearMacroActionPerformed
        // TODO add your handling code here:
        clear();
    }//GEN-LAST:event_ClearMacroActionPerformed

    private void LoadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LoadActionPerformed
        // TODO add your handling code here:
        loadProject();
    }//GEN-LAST:event_LoadActionPerformed

    private void RepeaterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RepeaterActionPerformed
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToRepeater(pos, tabIndex);
            }
            Redraw();
        }
    }//GEN-LAST:event_RepeaterActionPerformed

    private void ScannerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ScannerActionPerformed
        // TODO add your handling code here:
    	int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToScanner(pos, tabIndex);

            }
            Redraw();
        }
    }//GEN-LAST:event_ScannerActionPerformed

    private void IntruderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IntruderActionPerformed
        // TODO add your handling code here:
    	int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToIntruder(pos, tabIndex);

            }
            Redraw();
        }
    }//GEN-LAST:event_IntruderActionPerformed

    private void SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveActionPerformed
        // TODO add your handling code here:
        String fileName;
        if ((fileName=EnvironmentVariables.saveMacroBuilderJSONFileChooser(this)) != null){
            ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
            gson.GSONsave(fileName);
            updateSelectedTabIndex();
        }
    }//GEN-LAST:event_SaveActionPerformed

    private void editActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editActionPerformed
        // TODO add your handling code here:
        String reg = "";
        //String orig = MacroRequest.getText();


    
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList == null) return;
    	int pos = requestJList.getSelectedIndex();
        if(pos<0)return;
        
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        if(pmt!=null){
            if (!isMessageRequestEditable()) {
                pmt.restoreOrigialToRequestList();
                setMessageRequestEditMode(true);
                updateCurrentSelectedRequestListDisplayContents();
            }
            PRequestResponse pqr = pmt.getRequestResponseCurrentList(pos);
            if (pqr != null) {
                StyledDocumentWithChunk chunkdoc = this.getStyledDocumentOfSelectedMessageRequest();
                if (chunkdoc != null) {
                    StyledDocumentWithChunk newchunkdoc = StyledDocumentWithChunk.newInstance(chunkdoc); // newchunkdoc is newly created and independent from chunkdoc.
                    ParmGenRegex.newInstance(bundle.getString("MacroBuilderUI.requestEditorTitle.text"),this, reg, newchunkdoc).setVisible(true);
                }
            }
        }
      
        
    }//GEN-LAST:event_editActionPerformed

    private void showActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showActionPerformed
        // TODO add your handling code here:
        String reg = "";
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            String orig = messageResponse.getText();
            if (pos != -1) {
                StyledDocument doc = messageResponse.getStyledDocument();
                if (doc instanceof StyledDocumentWithChunk) {
                    StyledDocumentWithChunk newchunkdoc = StyledDocumentWithChunk.newInstance((StyledDocumentWithChunk) doc);
                    ParmGenRegex.newInstance("Response", this, reg, newchunkdoc).setVisible(true);
                }
            }
        }
        
    }//GEN-LAST:event_showActionPerformed

    private void StartScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartScanActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_StartScanActionPerformed

    private void MBmonitorofprocessingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBmonitorofprocessingActionPerformed
        // TODO add your handling code here:

    }//GEN-LAST:event_MBmonitorofprocessingActionPerformed

    private void MBfromStepNoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBfromStepNoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_MBfromStepNoActionPerformed

    private void TrackModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TrackModeActionPerformed
        // TODO add your handling code here:
        pmtProvider.setCBreplaceTrackingParam(isReplaceMode());

    }//GEN-LAST:event_TrackModeActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

    }//GEN-LAST:event_jButton1ActionPerformed

    private void messageViewStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_messageViewStateChanged
        // TODO add your handling code here:
        // jTabbedPane tab select problem fixed. by this eventhandler is defined... what a strange behavior. 
        //int selIndex = messageView.getSelectedIndex();
	//String t = messageView.getTitleAt(selIndex);
	//LOGGER4J.info("messageViewStateChanged: title[" + t + "]");
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
    }//GEN-LAST:event_messageViewStateChanged

    private void UpSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_UpSelectedActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int pos = requestJList.getSelectedIndex();
        if ( pos > 0 ) {
            ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
            List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
            // rlist,  RequestList
            LOGGER4J.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = prequestResponseList.get(pos);
            PRequestResponse downobj = prequestResponseList.get(pos-1);
            prequestResponseList.set(pos-1, upobj);
            prequestResponseList.set(pos, downobj);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            upobj = originalPRR.get(pos);
            downobj = originalPRR.get(pos-1);
            originalPRR.set(pos-1, upobj);
            originalPRR.set(pos, downobj);

            String upelem = String.format("%03d",pos-1) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos) + '|' + downobj.request.getURL();

            DefaultListModel<String> requestJListModel = (DefaultListModel<String>)requestJList.getModel();
            requestJListModel.set(pos-1, upelem);
            requestJListModel.set(pos, downelem);
            pmt.exchangeStepNo(pos-1, pos);

            if (EnvironmentVariables.isSaved()) { // if you have been saved params. then overwrite.
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave(null);
            }

            requestJList.setSelectedIndex(pos-1);
        }
        
    }//GEN-LAST:event_UpSelectedActionPerformed

    private void DownSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DownSelectedActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        int pos = requestJList.getSelectedIndex();
        int siz = prequestResponseList != null ? prequestResponseList.size() : 0;
        if ( pos > -1 && pos < siz - 1 ) {
            
            // rlist,  RequestList
            LOGGER4J.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = prequestResponseList.get(pos+1);
            PRequestResponse downobj = prequestResponseList.get(pos);
            prequestResponseList.set(pos, upobj);
            prequestResponseList.set(pos+1, downobj);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            upobj = originalPRR.get(pos+1);
            downobj = originalPRR.get(pos);
            originalPRR.set(pos, upobj);
            originalPRR.set(pos+1, downobj);

            String upelem = String.format("%03d",pos) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos+1) + '|' + downobj.request.getURL();

            DefaultListModel<String> requestJListModel = (DefaultListModel<String>) requestJList.getModel();
            requestJListModel.set(pos, upelem);
            requestJListModel.set(pos+1, downelem);
            pmt.exchangeStepNo(pos, pos+1);

            if (EnvironmentVariables.isSaved()) { // if you have been saved params. then overwrite.
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave(null);
            }

            requestJList.setSelectedIndex(pos+1);
        }
    }//GEN-LAST:event_DownSelectedActionPerformed

    private void deleteRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteRequestActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int pos = requestJList.getSelectedIndex();
        if ( pos != -1 ) {
            ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
            List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
            List<AppParmsIni> hasposlist = pmt.getAppParmIniHasStepNoSpecified(pos);
            if ( !hasposlist.isEmpty()) {
                PRequestResponse pqrs = prequestResponseList.get(pos);
                String m = String.format(
                        java.text.MessageFormat.format(
                                bundle.getString("MacroBuilderUI.deleteRequestAction.text"),
                                new Object[] {pqrs.request.getURL()}));
                int rv = JOptionPane.showConfirmDialog(
                        this, m, bundle.getString("MacroBuilderUI.deleteConfirm.text"), JOptionPane.YES_NO_OPTION);
                if (rv != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            prequestResponseList.remove(pos);
            DefaultListModel<String> requestJListModel = (DefaultListModel<String>) requestJList.getModel();
            requestJListModel.remove(pos);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            originalPRR.remove(pos);

            for(int i = pos; i < requestJListModel.size(); i++) {
                PRequestResponse pqrs = prequestResponseList.get(i);
                String elem = String.format("%03d",i) + '|' + pqrs.request.getURL();
                requestJListModel.set(i, elem);
            }
            int siz = prequestResponseList.size();
            if ( pos == siz - 1 && siz > 1) {
                int npos = pos - 1;
                requestJList.setSelectedIndex(npos);
            }
            
            
            hasposlist.stream().forEach(pini -> {
                int trackfromstep = pini.getTrackFromStep();
                if ( trackfromstep == pos) {
                    pini.setTrackFromStep(-1); // any stepno
                } else if ( trackfromstep > pos ) {
                    pini.setTrackFromStep(trackfromstep-1);
                }
                int settostep = pini.getSetToStep();
                if ( settostep == pos) {
                    pini.setSetToStep(EnvironmentVariables.TOSTEPANY); // any stepno
                } else if ( settostep > pos && settostep != EnvironmentVariables.TOSTEPANY) {
                    pini.setSetToStep(settostep-1);
                }
            });
            if (EnvironmentVariables.isSaved()) {
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave(null);
            } else if (pmt != null) {
                pmt.nullfetchResValAndCookieMan();
            }
            
        }
    }//GEN-LAST:event_deleteRequestActionPerformed

    private void messageRequestMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageRequestMouseClicked
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured.
            LOGGER4J.debug("messageRequestMouseClicked PopupTriggered.");
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_messageRequestMouseClicked

    private void messageRequestMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageRequestMousePressed
        // TODO add your handling code here:
        LOGGER4J.debug("messageRequestMousePressed...start");
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // must content load before RequestEdit.show
        if (evt.isPopupTrigger()) {
            LOGGER4J.debug("messageRequestMousePressed PopupTriggered.");
            int startPos = this.messageRequest.getSelectionStart();
            int endPos = this.messageRequest.getSelectionEnd();

            if (startPos >= 0 && startPos < endPos) {
                StyledDocumentWithChunk requestChunkDoc = getStyledDocumentOfSelectedMessageRequest();
                if (requestChunkDoc != null
                        && requestChunkDoc.isExistPlaceHolderBetweenStartEndPos(startPos, endPos)) {
                    decodeMenuItem.setEnabled(false);
                } else {
                    decodeMenuItem.setEnabled(true);
                }
                copyMenuItem.setEnabled(true);
            } else {
                decodeMenuItem.setEnabled(false);
                copyMenuItem.setEnabled(false);
            }
            pasteMenuItem.setEnabled(ZapUtil.hasSystemClipBoardString());
            LOGGER4J.debug("selection start=" + startPos + " end=" + endPos);
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        LOGGER4J.debug("messageRequestMousePressed...end");
    }//GEN-LAST:event_messageRequestMousePressed

    private void messageRequestMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageRequestMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured. 
            LOGGER4J.debug("messageRequestMouseReleased PopupTriggered.");
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_messageRequestMouseReleased

    private void messageResponseMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageResponseMouseClicked
        // TODO add your handling code here:
        LOGGER4J.debug("messageResponseMouseClicked start");
        if (evt.isPopupTrigger()) {// popup menu trigger occured.
            LOGGER4J.debug("messageResponseMouseClicked PoupupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        LOGGER4J.debug("messageResponseMouseClicked end");
    }//GEN-LAST:event_messageResponseMouseClicked

    private void messageResponseMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageResponseMousePressed
        // TODO add your handling code here:
        LOGGER4J.debug( "messageResponseMousePressed...start");
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // must content load before ResponseShow.show
        if (evt.isPopupTrigger()) {
            LOGGER4J.debug("messageResponseMousePressed PopupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        LOGGER4J.debug("messageResponseMousePressed...end");
    }//GEN-LAST:event_messageResponseMousePressed

    private void messageResponseMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_messageResponseMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured. 
            LOGGER4J.debug("messageResponseMouseReleased PopupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_messageResponseMouseReleased

    private void restoreActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_restoreActionPerformed
        /**
         * update current PRequestResponse(clone PRequestResponse from originalrlist to rlist)
         */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if (idx > -1 && prequestResponseList != null && idx < prequestResponseList.size()) {
            PRequestResponse prr = pmt.getOriginalPRequestResponse(idx);// get original PRequestResponse in originalrlist
            if (prr != null) {
                PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
                current.updateRequestResponse(prr.request.clone(), prr.response.clone());// clone original PRequestResponse to CurrentList(rlist)
                JTextPaneContents reqdoc = new JTextPaneContents(messageRequest);
                reqdoc.setRequestChunksWithDecodedCustomTag(prr.request);
                JTextPaneContents resdoc = new JTextPaneContents(messageResponse);
                resdoc.setResponseChunks(prr.response);
                if (pmt != null) {
                    //pmt.nullfetchResValAndCookieMan();
                }
            }
        }
    }//GEN-LAST:event_restoreActionPerformed

    private void updateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_updateActionPerformed
        /**
         * update Original PRequestResponse with current selected(displayed) PRequestResponse
         */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if (idx > -1 && prequestResponseList != null && idx < prequestResponseList.size()) {
            PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
            StyledDocumentWithChunk doc = this.getStyledDocumentOfSelectedMessageRequest();
            if (doc != null) {
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunksWithEncodeCustomTag(); // request newly created from DocText and Chunks
                current.request = newrequest;

                PRequestResponse original = pmt.getOriginalPRequestResponse(idx);
                original.updateRequestResponse(current.request, current.response);// copy current PRequestResponse to original list(originalrlist)
                if (EnvironmentVariables.isSaved()) { // if you have been saved params. then overwrite.
                    ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                    gson.GSONsave(null);
                } else {
                    pmt.nullfetchResValAndCookieMan();
                }
            }
        }
    }//GEN-LAST:event_updateActionPerformed

    private void jCheckBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox1ActionPerformed
        /**
         * scan all requests from current request to FinalResponse or until subsequence scan limit.
         */
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBox1ActionPerformed

    private void subSequenceScanLimitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_subSequenceScanLimitActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_subSequenceScanLimitActionPerformed

    private void MacroRequestListTabsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_MacroRequestListTabsStateChanged
        // TODO add your handling code here:
        LOGGER4J.debug("Enter stateChanged");
        updateSelectedTabIndex();
        setCloseButtonStates();
        int indexOfPlusBtnPanel = MacroRequestListTabs.indexOfComponent(plusBtnPanel);
        LOGGER4J.debug("indexOfPlusBtnPanel=" + indexOfPlusBtnPanel);
        if (MacroRequestListTabsCurrentIndex != -1 && indexOfPlusBtnPanel != -1) {
            if (MacroRequestListTabsCurrentIndex == indexOfPlusBtnPanel) {
                LOGGER4J.debug("Enter setSelectedIndex(" + (indexOfPlusBtnPanel - 1) + ")");
                MacroRequestListTabs.setSelectedIndex(indexOfPlusBtnPanel - 1);
                LOGGER4J.debug("Leave setSelectedIndex(" + (indexOfPlusBtnPanel - 1) + ")");
                if (this.maxTabIndex < indexOfPlusBtnPanel) {
                    // start the event of clicked plusBtnPanel icon
                    LOGGER4J.debug("plusBtnPanel icon clicked. create new tab.");
                    this.maxTabIndex++;
                    addNewRequestsToTabsPaneAtMaxTabIndex(null, this.maxTabIndex);
                    // end the event of clicked plusBtnPanel icon
                }
            } else {
                LOGGER4J.debug("MacroRequestListTabsCurrentIndex["
                        + MacroRequestListTabsCurrentIndex
                        + "] " + (MacroRequestListTabsCurrentIndex==indexOfPlusBtnPanel?"==":"!=") + " indexOfPlusBtnPanel[" + indexOfPlusBtnPanel + "]");
                LOGGER4J.debug("maxTabIndex[" + this.maxTabIndex + "] " + (this.maxTabIndex<indexOfPlusBtnPanel?"<":">=") + " indexOfPlusBtnPanel[" + indexOfPlusBtnPanel + "]");
                updateCurrentSelectedRequestListDisplayContents();
            }
        }
        LOGGER4J.debug("Leave stateChanged");
    }//GEN-LAST:event_MacroRequestListTabsStateChanged


    /**
     * get StyledDocument of selected message in MacroRequestList TabbedPane
     * @return StyledDocumentWithChunk of messageRequest
     */
    public StyledDocumentWithChunk getStyledDocumentOfSelectedMessageRequest() {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (displayInfo == null || pos < 0 || pos != displayInfo.selected_request_idx) {
                LOGGER4J.error(
                        "getStyledDocumentOfSelectedMessageRequest pos["
                                + pos
                                + "]!=selected_request_idx["
                                + displayInfo.selected_request_idx + "]");
                return null;
            }
            StyledDocumentWithChunk doc = CastUtils.castToType(messageRequest.getStyledDocument());

            messageRequestLoadContents(selectedTabIndex);

            return doc;
        }
        return null;
    }
    
    public JTextPane getMessageRequest() {
        return this.messageRequest;
    }

    /**
     * update current PRequestResponse with Edited(displayed) PRequestResponse
     *
     * @param changedDoc
     */
    @Override
    public void ParmGenRegexSaveAction(StyledDocumentWithChunk changedDoc) {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if(prequestResponseList != null && idx > -1 &&  idx < prequestResponseList.size()){
            try {
                /**
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks();// get edited request
                if (newrequest != null) {
                    pmt.updateRequestCurrentList(idx, newrequest);// copy edited request to current request
                    JTextPaneContents ndoc = new JTextPaneContents(messageRequest);
                    ndoc.setRequestChunks(newrequest);
                    pmt.nullfetchResValAndCookieMan();
                }
                 **/
                if (changedDoc != null) {
                    if (changedDoc.isRequest()) {
                        // update only the StyledDocument in messageRequest
                        StyledDocumentWithChunk updatedDoc = StyledDocumentWithChunk.newInstance(changedDoc);
                        messageRequest.setStyledDocument((StyledDocument) updatedDoc);
                        pmt.nullfetchResValAndCookieMan();
                    }
                }
            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
    }

    @Override
    public void ParmGenRegexCancelAction(boolean isLabelSaveBtn) {

    }

    @Override
    public String getParmGenRegexSaveBtnText(boolean isLabelSaveBtn) {
        if(!isLabelSaveBtn){
            return "Close";
        }
        return "Save";
    }

    @Override
    public String getParmGenRegexCancelBtnText(boolean isLabelSaveBtn) {
        if(!isLabelSaveBtn){
            return "Close";
        }
        return "Cancel";
    }
    
    /**
     * get subSequenceScanLimit value.
     *
     * @return 
     */
    public int getSubSequenceScanLimit() {
        String v = subSequenceScanLimit.getText();
        int subSequenceScanLimitValue = Integer.parseInt(v);
        return subSequenceScanLimitValue;
    }

    /**
     * integer input verifier for JTextField.
     */
    static class IntegerInputVerifier extends InputVerifier {
        @Override public boolean verify(JComponent c) {
          boolean verified = false;
          if (c instanceof JTextComponent) {
            JTextComponent textField = (JTextComponent) c;
            try {
              Integer.parseInt(textField.getText());
              verified = true;
            } catch (NumberFormatException ex) {
              UIManager.getLookAndFeel().provideErrorFeedback(c);
            }
            if (!verified) {
                JOptionPane.showMessageDialog(c,"subsequence scan limit\nPlease input numeric only.");
            }
          }
          return verified;
        }
    }

    /**
     * get selected tab index of Macro Request List Tabs
     * @return >= 0: selected index ==-1: no selection
     */
    public int getSelectedTabIndexOfMacroRequestList() {
        return MacroRequestListTabs.getSelectedIndex();
    }

    /**
     * get request list of selected tab
     *
     * @return 
     */
    private JList<String> getSelectedRequestJList() {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        try {
            return getRequestJListAtTabIndex(selectedTabIndex);
        } catch (IndexOutOfBoundsException e) {
            
        }
        return null;
    }
    
    public JList<String> getRequestJListAtTabIndex(int tabIndex) throws IndexOutOfBoundsException {
        try {
            JList<String> requestJList = requestJLists.get(tabIndex);
            return requestJList;
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return null;
    }
    
    /**
     * Gets the selectedIndex of the RequestJList that is exist in the specified tab
     *
     * @param tabIndex
     * @return >=0: selected index ==-1: no selected
     */
    public int getRequestJListSelectedIndexAtTabIndex(int tabIndex) {
        int pos = -1;
        try {
            JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
            pos = requestJList.getSelectedIndex();
        } catch (IndexOutOfBoundsException e) {
        }
        return pos;
    }

    /**
     * Load Project file.
     *
     * @return true - succeeded, false - load failed.
     */
    public boolean loadProject() {
        // TODO add your handling code here:

        String pathName;
        if((pathName=EnvironmentVariables.loadMacroBuilderJSONFileChooser(this)) != null) {
            //code to handle choosed file here.
            return loadProjectFromFile(pathName);
        }
        return false;
    }

    /**
     * load project from specified filename.
     *
     * @param filename project file name
     * @return true - success false - failed
     */
    public boolean loadProjectFromFile(String filename) {
        if(checkAndLoadFile(filename)){
            EnvironmentVariables.commitChoosedFile(filename);
            //load succeeded..
            updateSelectedTabIndex();
            return true;
        }
        return false;
    }

    private boolean checkAndLoadFile(String filename) {
        //
        boolean noerror = false;
        List<Exception> exlist = new ArrayList<>(); // Exception list
        LOGGER4J.info("checkAndLoadFile called.");

        ArrayList<AppParmsIni> rlist = null;
        String pfile = filename;

        try {

            String rdata;
            String jsondata = new String("");
            FileReader fr = new FileReader(pfile);
            try {

                BufferedReader br = new BufferedReader(fr);
                while ((rdata = br.readLine()) != null) {
                    jsondata += rdata;
                } // end of while((rdata = br.readLine()) != null)
                fr.close();
                fr = null;
            } catch (Exception e) {
                LOGGER4J.error("File Open/RW error", e);
                exlist.add(e);
            } finally {
                if (fr != null) {
                    try {
                        fr.close();
                        fr = null;
                    } catch (Exception e) {
                        fr = null;
                        LOGGER4J.error("File Close error", e);
                        exlist.add(e);
                    }
                }
            }

            if (exlist.size() > 0) return noerror;

            GsonParser parser = new GsonParser();

            ParmGenGSON gjson = new ParmGenGSON();
            JsonElement element = com.google.gson.JsonParser.parseString(jsondata);

            if (parser.elementLoopParser(element, gjson)) {
                rlist = gjson.Getrlist();
                List<PRequestResponse> requestList = gjson.GetMacroRequests();
                List<ParmGenGSON.AppParmAndSequence> appParmAndSequenceList = gjson.getAppParmAndSequenceList();
                if (appParmAndSequenceList != null
                    && appParmAndSequenceList.size() > 0) { // v2 format JSON file
                    clear();
                    EnvironmentVariables.Version = gjson.getVersion();
                    EnvironmentVariables.setExcludeMimeTypes(gjson.getExcludeMimeTypes());
                    appParmAndSequenceList.forEach(
                            pRequestResponseSequence -> {
                                addNewRequestsToTabsPaneAtMaxTabIndex(pRequestResponseSequence, this.maxTabIndex);
                                this.maxTabIndex++;
                            }
                    );
                    if (this.maxTabIndex > 0) {
                        this.maxTabIndex--;
                    }
                    noerror = true;
                    Redraw();
                    EnvironmentVariables.Saved(true);
                } else if (requestList != null && requestList.size() > 0) { // v1 format JSON file
                    clear();
                    ParmGenMacroTrace pmt = addNewRequests(requestList);
                    if (pmt != null) {
                        int creq = gjson.getCurrentRequest();
                        pmt.setCurrentRequest(creq);
                        EnvironmentVariables.Version = gjson.getVersion();
                        Encode firstRequestEncode = requestList.get(0).request.getPageEnc();
                        pmt.setSequenceEncode(firstRequestEncode);
                        EnvironmentVariables.setExcludeMimeTypes(gjson.getExcludeMimeTypes());
                        pmt.updateAppParmsIniAndClearCache(rlist);
                        noerror = true;
                        Redraw();
                        EnvironmentVariables.Saved(true);
                    } else {
                        LOGGER4J.error("pmt is null");
                    }
                } else {
                    LOGGER4J.error("requestList size is zero");
                }
            }
        } catch (Exception e) { // JSON file load failed.
            LOGGER4J.error("Parse error", e);
            exlist.add(e);
        }

        LOGGER4J.info("--------- JSON load END ----------");
        return noerror;
    }

    static class DisplayInfoOfRequestListTab {
        public int selected_request_idx = -1;
        public boolean isLoadedMacroCommentContents = false;
        public boolean isLoadedMessageRequestContents = false;
        public boolean isLoadedmessageResponseContents = false;
        
        DisplayInfoOfRequestListTab() {
            clearAll();
        }

        public void clearAll() {
            selected_request_idx = -1;
            clearViewFlags(false, false, false);
        }

        public void clearSpecific(boolean isRemainRequest,
                                  boolean isRemainResponse,
                                  boolean isRemainComment){

            selected_request_idx = -1;
            clearViewFlags(isRemainRequest, isRemainResponse, isRemainComment);
        }

        public void clearViewFlags(boolean isRemainRequest,
                                   boolean isRemainResponse,
                                   boolean isRemainComment) {
            isLoadedMacroCommentContents = isRemainComment;
            isLoadedMessageRequestContents = isRemainRequest;
            isLoadedmessageResponseContents = isRemainResponse;
        }
    }

    /**
     * get MacroRequest Tab Title String
     * @param tabIndex
     * @return
     */
    public String getMacroRequestTabTitleAt(int tabIndex) {
        return MacroRequestListTabs.getTitleAt(tabIndex);
    }

    /**
     * get MacroRequest's tab count except "+"(addNewTab) button tab.
     * @return int
     */
    public int getMacroRequestTabCount() {
        return MacroRequestListTabs.getTabCount() - 1;
    }

    public ParmGenMacroTraceProvider getParmGenMacroTraceProvider() {
        return this.pmtProvider;
    }

    private void updateSelectedTabIndex() {
        int selectedTabIndex = MacroRequestListTabs.getSelectedIndex();
        if (selectedTabIndex != -1) MacroRequestListTabsCurrentIndex = selectedTabIndex;

        LOGGER4J.debug("selectedindex:" + selectedTabIndex + " MacroRequestListTabsCurrentIndex:" + MacroRequestListTabsCurrentIndex);
    }

    /**
     * Button for adding new Tab to RequestList(jTabbedPane).
     */
    private void addPlusTabButtonToRequestList() {
        // Button for adding new Tab to JTabbedPane.
        plusBtnPanel = new JPanel();
        MacroRequestListTabs.addTab("", PLUS_BUTTON_ICON, plusBtnPanel, EnvironmentVariables.getZapResourceString("autoMacroBuilder.MacroBuilderUI.addNewTabToolTip.text"));
        // MacroRequestListTabs.addTab("", PLUS_BUTTON_ICON, plusBtnPanel);
    }

    /**
     * create Close "X" button for Tab in TabbedPane
     * @param tabTitle
     * @param maxTabIndex
     * @return
     */
    private JPanel createCloseXbtnForTabbedPane(String tabTitle, int maxTabIndex) {
        CloseXbtnTabPanel tabPanel = CloseXbtnTabPanel.newInstance(tabTitle,
                new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        LOGGER4J.debug("Enter closeXbtnActionPerfomed");
                        closeXbtnActionPerfomed();
                        LOGGER4J.debug("Leave closeXbtnActionPerfomed");
                    }
                });
        MacroRequestListTabs.setTabComponentAt(maxTabIndex, tabPanel);
        return tabPanel;
    }

    private void closeXbtnActionPerfomed() {
        int currentSelectedTabIndex = MacroRequestListTabs.getSelectedIndex();
        if (currentSelectedTabIndex > 0 && currentSelectedTabIndex <= maxTabIndex) {
            pmtProvider.removeBaseInstance(currentSelectedTabIndex);
            requestJLists.remove(currentSelectedTabIndex);
            LOGGER4J.debug("Begin MacroRequestListTabs.remove");
            MacroRequestListTabs.remove(currentSelectedTabIndex);
            LOGGER4J.debug("End MacroRequestListTabs.remove");
            maxTabIndex--;
            LOGGER4J.debug("currentIndex deleted: " + currentSelectedTabIndex + " maxTabIndex: " + maxTabIndex);
        }
    }

    private void setCloseButtonStates() {
        // Hide all 'close' buttons except for the selected tab
        for (int i = 0; i < MacroRequestListTabs.getTabCount(); i++) {
            Component tabCom = MacroRequestListTabs.getTabComponentAt(i);
            if (tabCom != null && tabCom instanceof CloseXbtnTabPanel) {
                CloseXbtnTabPanel jp = (CloseXbtnTabPanel) tabCom;
                jp.setEnableCloseButton(i == MacroRequestListTabs.getSelectedIndex());
                LOGGER4J.debug("setCloseButtonState i:" + i + (i== MacroRequestListTabs.getSelectedIndex() ? " Enable" : " Disable"));
            }
        }
    }

    private void MacroCommentsMouseClicked(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    private void MacroCommentsMousePressed(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // at this point, must load contents because first called MousePressed Event than any other mouse events
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    private void MacroCommentsMouseReleased(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    private void DecodeMenuItemActionPerformed(java.awt.event.ActionEvent evt) {
        int startPos = this.messageRequest.getSelectionStart();
        int endPos = this.messageRequest.getSelectionEnd();
        if (startPos >= 0 && startPos < endPos) {

            String selectedText = this.messageRequest.getSelectedText();
            StyledDocumentWithChunk doc = CastUtils.castToType(this.messageRequest.getStyledDocument());
            Encode enc = doc.getEnc();
            if (selectedText.indexOf("\n") == -1) {
                StartEndPosition startEndPosition = new StartEndPosition(startPos, endPos, selectedText);
                DecoderSelector decoderSelector = DecoderSelector.newInstance(this, startEndPosition, enc);
                decoderSelector.setVisible(true);
            }

        }
    }

    public void clearDisplayInfoViewFlags() {
        displayInfo.clearViewFlags(false, false, false);
    }

    public JPanel getMessageViewPanel() {
        return this.messageViewPanel;
    }

    public void showMessageViewOnWorkBench(int tabIndex) {
        final ExtensionAutoMacroBuilder ext = MacroBuilderUI.this.extensionAutoMacroBuilder;
        View.getSingleton()
                .getWorkbench().showPanel(ext.getMessageViewStatusPanel(tabIndex));
    }

    public void setTabIndexOnMesssageViewTabbedPane(int tabIndex) {
        if (this.messageView != null
        && tabIndex < this.messageView.getTabCount()
        && tabIndex > -1) {
            this.messageView.setSelectedIndex(tabIndex);
        }
    }

    /**
     * restore current selected current ReqeustResponse List with originalRequestResponse List.
     */
    public void restoreAllCurrentSelectedMacroRequestFromOriginal() {
        int selectedTabIndex = getMacroRequestListTabsCurrentIndex();// return 0 or actually selected tab index
        // int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();// may return -1 so no usable.
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null || prequestResponseList == null) return;

        int selectedIndex = requestJList.getSelectedIndex();

        for (int index = 0; index < prequestResponseList.size(); index++) {
            PRequestResponse prr = pmt.getOriginalPRequestResponse(index);// get original PRequestResponse in original
            PRequestResponse current = pmt.getRequestResponseCurrentList(index);
            current.updateRequestResponse(prr.request.clone(), prr.response.clone());// clone original PRequestResponse to CurrentList(rlist)

            if (selectedIndex == index) {
                JTextPaneContents reqdoc = new JTextPaneContents(messageRequest);
                reqdoc.setRequestChunksWithDecodedCustomTag(prr.request);
                JTextPaneContents resdoc = new JTextPaneContents(messageResponse);
                resdoc.setResponseChunks(prr.response);
                if (pmt != null) {
                    pmt.nullfetchResValAndCookieMan();
                }
            }
        }
    }

    public void setSelectedRequestInRequestJlist(int tabIndex, int selectedIndex) {
        setSelectdMacroRequestListTabs(tabIndex);
        JList<String> jList = getRequestJListAtTabIndex(tabIndex);
        if (jList != null) {
            jList.setSelectedIndex(selectedIndex);
        }
    }
    public void setSelectdMacroRequestListTabs(int tabIndex) {
        if (tabIndex > -1 && tabIndex < getPlusBtnPanelTabIndexOfMacroRequestListTabs()) {
            this.MacroRequestListTabs.setSelectedIndex(tabIndex);
        }
    }

    private int getPlusBtnPanelTabIndexOfMacroRequestListTabs() {
        int indexOfPlusBtnPanel = MacroRequestListTabs.indexOfComponent(plusBtnPanel);
        return indexOfPlusBtnPanel;
    }


    public int getListModelSize(int tabIndex) {
        DefaultListModel<String> listModel = (DefaultListModel<String>)getRequestJListAtTabIndex(tabIndex).getModel();
        return listModel.getSize();
    }
    public void updateJlistForRepaintInvokeLater(int tabIndexVal, int countDown) {

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                DefaultListModel<String> listModel = (DefaultListModel<String>)getRequestJListAtTabIndex(tabIndexVal).getModel();
                int selectedIndexVal = listModel.getSize() - countDown;

                if (selectedIndexVal>=0) {
                    String value = listModel.getElementAt(selectedIndexVal);
                    listModel.setElementAt("", selectedIndexVal);
                    listModel.setElementAt(value, selectedIndexVal);
                }
            }
        });

    }

    public void updateJlistForRepaint(int tabIndexVal, ParmGenMacroTrace basePmt, int countDown) {


        int currentSelectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        if (currentSelectedTabIndex == tabIndexVal) {
            DefaultListModel<String> listModel = (DefaultListModel<String>) getRequestJListAtTabIndex(tabIndexVal).getModel();

            int selectedIndexVal = listModel.getSize() - countDown;
            int runnningNo = selectedIndexVal;

            if (countDown < 0) {
                selectedIndexVal = listModel.getSize() - 1;
                runnningNo = -1;
            }

            if (selectedIndexVal >= 0) {
                basePmt.setRunningStepNo(runnningNo);
                String value = listModel.getElementAt(selectedIndexVal);
                listModel.setElementAt("", selectedIndexVal);
                listModel.setElementAt(value, selectedIndexVal);
            }
        }
    }

    public void clearMessageResponse() {
        this.messageResponse.setText("");
    }

    public void setMessageRequestEditMode(boolean b) {
        this.messageRequest.setEditable(b);
    }

    public boolean isMessageRequestEditable() {
        return this.messageRequest.isEditable();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox CBinheritFromCache;
    private javax.swing.JButton ClearMacro;
    private javax.swing.JButton DownSelected;
    private javax.swing.JCheckBox FinalResponse;
    private javax.swing.JMenuItem Intruder;
    private javax.swing.JButton Load;
    private javax.swing.JCheckBox MBfromStepNo;
    private javax.swing.JCheckBox MBmonitorofprocessing;
    private javax.swing.JCheckBox MBtoStepNo;
    private javax.swing.JTextArea MacroComments;
    private javax.swing.JTextPane messageRequest;
    private javax.swing.JTabbedPane MacroRequestListTabs;
    private javax.swing.JTextPane messageResponse;
    private javax.swing.JButton ParamTracking;
    private javax.swing.JPopupMenu PopupMenuForRequestList;
    private javax.swing.JMenuItem Repeater;
    private javax.swing.JPopupMenu RequestEdit;
    private javax.swing.JList<String> RequestList;
    private javax.swing.JPopupMenu ResponseShow;
    private javax.swing.JButton Save;
    private javax.swing.JMenuItem Scanner;
    private javax.swing.JMenu SendTo;
    private javax.swing.JButton StartScan;
    private javax.swing.JComboBox<String> TrackMode;
    private javax.swing.JButton UpSelected;
    private javax.swing.JButton custom;
    private javax.swing.JMenuItem deleteRequest;
    private javax.swing.JMenuItem showMessageView;
    private javax.swing.JMenuItem disableRequest;
    private javax.swing.JMenuItem editMenuItem;
    private javax.swing.JMenuItem enableRequest;
    private javax.swing.JButton jButton1;
    private javax.swing.JCheckBox jCheckBox1;
    private javax.swing.JCheckBox WaitTimerCheckBox;
    private javax.swing.JLabel OtherOptionsLabelTitle;
    private javax.swing.JLabel macroRequestListLabelTitle;
    private javax.swing.JButton generalHelpBtn;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel requestView;
    private javax.swing.JPanel responseView;
    private javax.swing.JPanel trackingView;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel burpTrackingParameter;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane requestScroller;
    private javax.swing.JScrollPane trackingScroller;
    private javax.swing.JScrollPane responseScroller;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTabbedPane messageView;
    private javax.swing.JPanel messageViewPanel;
    private javax.swing.JPanel descriptionVacantArea;
    private javax.swing.JLabel dummyLabel;
    private javax.swing.JLabel requestListNum;
    private javax.swing.JMenuItem restoreMenuItem;
    private javax.swing.JMenuItem showMenuItem;
    private javax.swing.JTextField subSequenceScanLimit;
    private javax.swing.JMenuItem updateMenuItem;
    private javax.swing.JMenuItem decodeMenuItem;
    private javax.swing.JMenuItem copyMenuItem;
    private javax.swing.JMenuItem pasteMenuItem;
    private javax.swing.JTextField waitsec;
    // End of variables declaration//GEN-END:variables


}