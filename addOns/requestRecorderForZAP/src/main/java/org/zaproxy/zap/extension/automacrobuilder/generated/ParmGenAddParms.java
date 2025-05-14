/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.DefaultComboBoxModel;

import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

import org.zaproxy.zap.extension.automacrobuilder.*;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class ParmGenAddParms extends javax.swing.JDialog implements InterfaceParmGenWin {

    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();
    ParmGenNew parentwin;// parenrt window which create this dialog.
    PRequest selected_request;
    DefaultTableModel ReqParsedTableModel;
    boolean replaceEntireValue;// == true: replace entire value  == false: replace a part of value
    boolean isformdata;// == true form-data == false www-url-encoded
    String primeHeaderOfRequest = null;
    public static final int VT_DEFAULT=0;
    public static final int VT_NUMBERFIXED=1;
    public static final int VT_ALPHANUMFIXED = 2;
    public static final int VT_NUMBER=3;
    public static final int VT_ALPHANUM=4;
    public static final int VT_FIXED = 5;// comboModel has selectable values from VT_DEFAULT  until this Value.
    public static final int VT_PARAMVALUE = 6;
    public static final int VT_NUMCOUNTER = 7;
    public static final int VT_VALUE = 8;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    private static  DefaultComboBoxModel<String> comboModel = null;
    private int[] ListSelectionModel;

    public enum OptTypes {
        Json,
        Cookie,
        FormData,
        Default;

        public static OptTypes parseString(String httpSectionTypeString) {
            if (httpSectionTypeString != null && !httpSectionTypeString.isEmpty()) {
                OptTypes[] tktypearray = OptTypes.values();
                for (OptTypes tktype : tktypearray) {
                    if (tktype.name().equalsIgnoreCase(httpSectionTypeString)) {
                        return tktype;
                    }
                }
            }
            return OptTypes.Default;
        }

        @Override
        public String toString() {
            String val = super.toString();
            if (this == Default) {
                val = "";
            }
            return val;
        }
    }

    /**
     * new instance method<br>
     * you must define this in your extended classes for instantiation
     *
     * @param _parentwin
     * @param _replaceEntireValue
     * @return
     */
    public static ParmGenAddParms newInstance(ParmGenNew _parentwin,  boolean _replaceEntireValue) {
        return new ParmGenAddParms(_parentwin, _replaceEntireValue).buildThis(_parentwin, _replaceEntireValue);
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param _parentwin
     * @param _replaceEntireValue
     */
    protected ParmGenAddParms(ParmGenNew _parentwin,  boolean _replaceEntireValue) {
        super();
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * See newInstance() method.
     * In extended class, you must call parent class's buildThis() method.<br>
     * e.g.:<br>
     * <pre>
     *     &#64;Override
     *     protected ChildObject buildThis(ParmGenNew _parentwin, boolean _replaceEntireValue) {
     *         super.buildThis(_parentwin, _replaceEntireValue);
     *         ... arbitary code...
     *         return this;
     *     }
     * </pre>
     * @param _parentwin
     * @param _replaceEntireValue
     * @return this
     */
    protected ParmGenAddParms buildThis(ParmGenNew _parentwin, boolean _replaceEntireValue) {
        parentwin = _parentwin;
        isformdata = false;
        replaceEntireValue = _replaceEntireValue;
        if(comboModel==null){
            comboModel = new javax.swing.DefaultComboBoxModel<>(new String[] {
                    bundle.getString("ParmGenAddParms.comboModel.Default.text"),
                    bundle.getString("ParmGenAddParms.comboModel.NumberFixedLength.text"),
                    bundle.getString("ParmGenAddParms.comboModel.AlphanumFixedLength.text"),
                    bundle.getString("ParmGenAddParms.comboModel.NumberHasAnyLength.text"),
                    bundle.getString("ParmGenAddParms.comboModel.AlphanumHasAnyLength.text"),
                    bundle.getString("ParmGenAddParms.comboModel.FixedValue.text") });
        }
        //initComponents();
        customInitComponents();

        this.setModal(true);
        update();
        return this;
    }

    private void deleteRows(){
        for( int i = ReqParsedTableModel.getRowCount() - 1; i >= 0; i-- ){
            ReqParsedTableModel.removeRow(i);
        }
    }


    public void update(){
        ReqParsedTableModel = (DefaultTableModel)ReqParsedTable.getModel();
        Select_ReplaceTargetURL.removeAllItems();
        PRequestResponse selected_message = getSelectedMessagesInstance().getChoosedMessage();
        // get PrimeHeader within request.
        this.primeHeaderOfRequest = selected_message.request.getPrimeHeaderWithoutCRLF();
        int mpos = selected_message.getMacroPos();
        if(mpos<0){
            mpos = EnvironmentVariables.TOSTEPANY;
        }
        EnvironmentVariables.getTemporaryValueStorageInstance().put(
                TemporaryValueStorage.Keys.K_TOPOS,
                TemporaryValueStorage.Keys.Class_K_TOPOS,
                Integer.toString(mpos));
        selected_request = selected_message.request;
        String newtargetURL = ".*" + selected_request.getURIWithoutQueryPart() + ".*";
        Select_ReplaceTargetURL.addItem(newtargetURL);
        String currenturl = parentwin.getTargetURL();
        if ( currenturl != null && !currenturl.isEmpty()){
            if(currenturl.indexOf(newtargetURL)==-1){// currenturl does not contain newtargetURL, so add it to currenturl.
                Select_ReplaceTargetURL.addItem(currenturl);
                Select_ReplaceTargetURL.addItem(currenturl + "|.*" + selected_request.getURIWithoutQueryPart() + ".*");
            }
        }
        deleteRows();

        AppValue ap = new AppValue();

        // entire URL
        String wholepath = selected_request.getURL();
        ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Path, OptTypes.Default, Integer.toString(0), wholepath});

        Iterator<String> pit = selected_request.pathparams.iterator();
        int ppos = 1;
        while(pit.hasNext()){
            ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Path, OptTypes.Default, Integer.toString(ppos), pit.next()});
            ppos++;
        }

        Iterator<String[]> it = selected_request.getQueryParams().iterator();
        int rcnt = 0;
        while(it.hasNext()){
            rcnt++;
            String[] nv = it.next();
            ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Query, OptTypes.Default, nv[0], nv[1]});
        }
        Iterator<String[]> itb = selected_request.getBodyParamsFromRequest().iterator();

        while(itb.hasNext()){
            rcnt++;
            String[] nv = itb.next();
            if(selected_request.isFormData()){
                ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Body, OptTypes.FormData, nv[0], nv[1]});
            } else {
                ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Body, OptTypes.Default, nv[0], nv[1]});
            }
        }
        
        //JSON request
        ParmGenGSONDecoder reqjdecoder = new ParmGenGSONDecoder(selected_request.getBodyStringWithoutHeader());
        List<ParmGenToken> reqjtklist = reqjdecoder.parseJSON2Token();
        for(ParmGenToken tk: reqjtklist){
            rcnt++;
            String name = tk.getTokenKey().getName();
            String value = tk.getTokenValue().getValue();
            ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Body, OptTypes.Json, name, value});
        }
        
        if (rcnt<=0){
            ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Body, OptTypes.Default, "null", "null"});
        }

        // List cookies
        Iterator<String[]> cit = selected_request.cookieparams.iterator();
        while(cit.hasNext()){
            String[] nv = cit.next();
            ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Header, OptTypes.Cookie, nv[0], nv[1]});
        }

        // List headers
        ArrayList<String[]> hlist = selected_request.getHeaders();
        Iterator<String[]> hit = hlist.iterator();
        while(hit.hasNext()){
            String[] nv = hit.next();
            if(nv.length>1){
                if(!nv[0].matches("[Cc]ookie")){
                    ReqParsedTableModel.addRow(new Object[]{AppValue.HttpSectionTypes.Header, OptTypes.Default, nv[0], nv[1]});
                }
            }

        }
        int i = 0;
        if(replaceEntireValue){
            i = 1;
        }
        ValReplacePart.setSelectedItem(i);
        if(selected_request.isFormData()){
            isformdata = true;
        }

        // List tracking parameters
        int j = 0;
        ArrayList<String> names = new ArrayList<>();

        for(j=0; j<1000; j++){
            String n = EnvironmentVariables.getTemporaryValueStorageInstance().get(
                    j,
                    TemporaryValueStorage.Keys.K_TOKEN,
                    TemporaryValueStorage.Keys.Class_K_TOKEN);
            if(n==null)break;
            names.add(n);
        }

        String targetparam = EnvironmentVariables.getTemporaryValueStorageInstance().get(
                TemporaryValueStorage.Keys.K_TARGETPARAM,
                TemporaryValueStorage.Keys.Class_K_TARGETPARAM);

        int rmax = ReqParsedTableModel.getRowCount();
        ListSelectionModel lmodel = ReqParsedTable.getSelectionModel();
        Encode selectedRequestEncode = selected_request.getPageEnc();
        for(j=0; j<rmax;j++){
            AppValue.HttpSectionTypes httpSectionTypesEmbedTo = (AppValue.HttpSectionTypes)ReqParsedTableModel.getValueAt(j, 0); // HttpSectionType of target
            String name = (String)ReqParsedTableModel.getValueAt(j, 2);//name
            String namedecoded = name;
            try {
                namedecoded = URLDecoder.decode(name, selectedRequestEncode.getIANACharsetName());
            } catch (Exception ex) {// catch all Exceptions which contains null.
                LOGGER4J.error(ex.getMessage(), ex);
            }
            if(names.contains(namedecoded)){// select list entry which value matched namedecoded
                lmodel.addSelectionInterval(j, j);
            }
        }
    }

    @Override
    public SelectedMessages getSelectedMessagesInstance() {
        return this.parentwin.getSelectedMessagesInstance();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})

    private void CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_CancelActionPerformed

    private String getValueRegex(String v, boolean ispath, boolean iscookie, boolean isheader, boolean isjson, boolean iswholepath){
        replaceEntireValue = false;
        boolean fixed = true;
        String regpattern = "";
        String prepostpattern = "";

        if(iswholepath){
            return ParmGenUtil.getPathsRegex(v);
        }

        int selidx = ValReplacePart.getSelectedIndex();// selected type of regular expression
        if(selidx==VT_DEFAULT){ // when selected Default
            switch(parentwin.getCurrentModel()){
                case ParmGenNew.P_NUMBERMODEL:
                    selidx = VT_NUMCOUNTER;
                    break;
                default:
                    selidx = VT_VALUE;
                    break;
            }
        }
        switch(selidx){
            case VT_NUMCOUNTER:
                fixed = false;// any number length
                regpattern = "\\-?\\d";// regex type of value is only numbers.
                prepostpattern = "([^0-9]*)";
                break;
            case VT_NUMBERFIXED:
                fixed = true;// fixed number length
                regpattern = "\\-?\\d";
                prepostpattern = "([^0-9]*)";
                break;
            case VT_NUMBER:
                fixed = false;
                regpattern = "\\-?\\d";
                prepostpattern = "([^0-9]*)";
                break;
            case VT_ALPHANUMFIXED:
                fixed = true;
                if(ispath){
                    regpattern = "[0-9a-zA-Z]";
                }else{
                    if(isformdata){
                        regpattern = "[0-9a-zA-Z]";
                    }else{
                        regpattern = "[0-9a-zA-Z]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
            case VT_ALPHANUM:
                fixed = false;
                if(ispath){
                    regpattern = "[0-9a-zA-Z]";
                }else{
                    if(isformdata){
                        regpattern = "[0-9a-zA-Z]";
                    }else{
                        regpattern = "[0-9a-zA-Z]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
           case VT_PARAMVALUE:
                fixed = false;
                if(ispath){
                    regpattern = "[^=;/\\s]";
                }else{
                    if(isformdata){
                        regpattern = "[^=;\\s]";
                    }else{
                        regpattern = "[^=;&\\s]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
            case VT_VALUE:
                replaceEntireValue = true;
                break;
            case VT_FIXED:
                replaceEntireValue = true;
                break;
        }
        String prefix = "";

        if(iscookie){
            prefix = "[^=]*?";
        }else if(isheader){
            prefix = "";
        }

        if(selidx==VT_FIXED ){// use original value as regex pattern
            // // this choice is nonsense. but later Users could change the value for their own purposes
            String escv = ParmGenUtil.escapeRegexChars(v);
            if(isformdata){
                return "(" + escv + ")";
            }
            return prefix + "(" + escv + ")";
        }

        if (!replaceEntireValue){
            //Pattern pattern = ParmGenUtil.Pattern_compile("([^0-9]*)(\\d+)([^0-9]*)");
            Pattern pattern = ParmGenUtil.Pattern_compile(prepostpattern + "(" + regpattern+ "+)" + prepostpattern);
            Matcher matcher = pattern.matcher(v);
            if (matcher.find()){
                String prestr = null;
                String poststr = null;
                String numstr = null;
                int gcnt = matcher.groupCount();
                String chrcnt = "";
                for(int n = 0; n < gcnt ; n++){
                    switch(n){
                        case 0:
                            prestr = matcher.group(n+1);
                            break;
                        case 1:
                            numstr = matcher.group(n+1);
                            int l = numstr.length();
                            if ( l>0){
                                if(fixed){
                                    chrcnt = "{" +Integer.toString(l) + "})";
                                }else{
                                    chrcnt = "+)";
                                }
                            }else{
                                chrcnt = "+)";
                            }
                            break;
                        case 2:
                            poststr = matcher.group(n+1);
                            break;
                        default:
                            break;
                    }
                }
                if (isformdata){
                    return ParmGenUtil.escapeRegexChars(prestr) + "(" + regpattern + chrcnt + ParmGenUtil.escapeRegexChars(poststr) ;
                }else{
                    return prefix + ParmGenUtil.escapeRegexChars(prestr) + "(" + regpattern + chrcnt+ ParmGenUtil.escapeRegexChars(poststr) ;
                }
            }
        }

        if(isjson){
            return v;// use original
        }
        
        if (isformdata){
            return "(.+)";
        }
        if(isheader) {
            return prefix + "([^\\r\\n\\t ]+)";
        } else if (ispath) {
            return prefix + "([^\\r\\n\\t /]+)";
        } else if(iscookie) {
            return prefix + "([^\\r\\n\\t;\\= ]+)";
        }
        return prefix + "([^&=\\r\\n\\t ]+)";
    }

    private void AddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AddActionPerformed
        // TODO add your handling code here:
        int[] rowsSelected = ReqParsedTable.getSelectedRows();
        String url = (String)Select_ReplaceTargetURL.getSelectedItem();
        String fromstr = EnvironmentVariables.getTemporaryValueStorageInstance().get(
                TemporaryValueStorage.Keys.K_FROMPOS,
                TemporaryValueStorage.Keys.Class_K_FROMPOS);
        int frompos = -1;
        if(fromstr!=null){
            frompos = Integer.parseInt(fromstr);
        }
        String tostr = EnvironmentVariables.getTemporaryValueStorageInstance().get(
                TemporaryValueStorage.Keys.K_TOPOS,
                TemporaryValueStorage.Keys.Class_K_TOPOS);
        int topos = EnvironmentVariables.TOSTEPANY;
        if(tostr!=null){
            topos = Integer.parseInt(tostr);
        }
        parentwin.updateFromToPos(frompos, topos);
        
        if(topos>=0){//SetTo specified. then  URL target is any match
            url = ".*";
        }
        if(url!=null)  parentwin.updateTargetURL(url);
        

        for (int k=0; k<rowsSelected.length; k++){
            AppValue.HttpSectionTypes httpSectionTypesEmbedTo = (AppValue.HttpSectionTypes)ReqParsedTableModel.getValueAt(rowsSelected[k], 0);// HttpSectionType of embeding target
            OptTypes optTypes = (OptTypes)ReqParsedTableModel.getValueAt(rowsSelected[k], 1);
            String pname = (String)ReqParsedTableModel.getValueAt(rowsSelected[k], 2);//parameter
            String pvalue = (String)ReqParsedTableModel.getValueAt(rowsSelected[k], 3);//value
            boolean islastparam = false;
            if(k+1==rowsSelected.length){
                islastparam = true;
            }
            if (parentwin != null){
                // default regex pattern name=[^&]value(\d+)[^&]
                boolean ispath= false;
                boolean iscookie = false;
                boolean isheader = false;
                boolean iswholepath = false;
                boolean isjson = false;
                String cookiepref = "";
                String pathpref = "";
                String headerpref ="";
                if (httpSectionTypesEmbedTo == AppValue.HttpSectionTypes.Path) {
                    int pn = Integer.parseInt(pname);
                    if (pn==0) {
                        iswholepath = true;// this choice is nonsense. but later Users could change the value for their own purposes(replace entire URL to pvalue.)
                    } else {
                        pathpref = "(?:[a-z]+\\://[^\\r\\n\\t /]+/|/)";// URL of request through proxy or direct
                        for (int j = 1; j < pn; j++) {
                            pathpref += "[^\\r\\n\\t /]+?/";
                        }
                    }
                    ispath = true;
                    pname = null;
                } else if(optTypes == OptTypes.Json) {
                    isjson = true;
                } else if(optTypes == OptTypes.Cookie) {
                    cookiepref = "[Cc]ookie:.*?" + pname + "=";
                    pname = null;
                    iscookie = true;
                } else if(httpSectionTypesEmbedTo == AppValue.HttpSectionTypes.Header) {
                    headerpref = pname + ":[    ]*";
                    pname = null;
                    isheader = true;
                }

                
                parentwin.addParamToSelectedModel(httpSectionTypesEmbedTo, optTypes ,pname, k, headerpref + cookiepref + pathpref + getValueRegex(pvalue, ispath, iscookie, isheader,isjson, iswholepath), isformdata, islastparam);

            }
        }
        
        dispose();
    }//GEN-LAST:event_AddActionPerformed

    private void Select_ReplaceTargetURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Select_ReplaceTargetURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_Select_ReplaceTargetURLActionPerformed

    private void ValReplacePartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ValReplacePartActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_ValReplacePartActionPerformed

   

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Add;
    private javax.swing.JButton Cancel;
    private javax.swing.JTable ReqParsedTable;
    private javax.swing.JComboBox<String> Select_ReplaceTargetURL;
    private javax.swing.JComboBox<String> ValReplacePart;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane8;
    // End of variables declaration//GEN-END:variables

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        //
    }

    @SuppressWarnings("rawtypes")
    private void customInitComponents() {

        jLabel5 = new javax.swing.JLabel();
        jLabel5.putClientProperty("html.disable", Boolean.FALSE);
        jScrollPane8 = new javax.swing.JScrollPane();
        ReqParsedTable = new javax.swing.JTable();
        Add = new javax.swing.JButton();
        Cancel = new javax.swing.JButton();
        Select_ReplaceTargetURL = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        ValReplacePart = new javax.swing.JComboBox<>();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(bundle.getString("ParmGenAddParms.DialogTitle.text")); // NOI18N

        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel5.setText(bundle.getString("ParmGenAddParms.jLabel5.text")); // NOI18N
        jLabel5.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        ReqParsedTable.setModel(new javax.swing.table.DefaultTableModel(
                new Object [][] {
                        {"path", OptTypes.Default, "", "/input.php"},
                        {"query", OptTypes.Default, "search", "aiueo"},
                        {"body", OptTypes.Default, "name", "chikara"},
                        {"body", OptTypes.Default, "password", "secret"},
                        {"body", OptTypes.Default, "", null},
                        {"body", OptTypes.Default, null, null}
                },
                new String [] {
                        "position", "Type","Parameter", "Value"
                }
        ) {
            Class[] types = new Class [] {
                    AppValue.HttpSectionTypes.class, OptTypes.class, java.lang.String.class, java.lang.String.class
            };

            @Override
            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        ReqParsedTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        ReqParsedTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane8.setViewportView(ReqParsedTable);
        if (ReqParsedTable.getColumnModel().getColumnCount() > 0) {
            ReqParsedTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenAddParms.position.text")); // NOI18N
        }

        Add.setText(bundle.getString("ParmGenAddParms.AddBtn.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenAddParms.CancelBtn.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        Select_ReplaceTargetURL.setEditable(true);
        Select_ReplaceTargetURL.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        Select_ReplaceTargetURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Select_ReplaceTargetURLActionPerformed(evt);
            }
        });

        jLabel1.setText(bundle.getString("ParmGenAddParms.HowToRestoreTargetPathRegexInfoTitleLabel1.text")); // NOI18N

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenAddParms.jPanel1.border.text"))); // NOI18N

        ValReplacePart.setModel(comboModel);
        ValReplacePart.setToolTipText(bundle.getString("ParmGenAddParms.numbertooltip.text")); // NOI18N
        ValReplacePart.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ValReplacePartActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
                jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(ValReplacePart, 0, 140, Short.MAX_VALUE)
                                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
                jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(ValReplacePart, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 10, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .addComponent(Select_ReplaceTargetURL, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(Add)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                .addComponent(Cancel))
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 247, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                                .addGap(12, 12, 12))
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jScrollPane8, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                                                .addContainerGap())))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(Select_ReplaceTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel5)
                                        .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane8, javax.swing.GroupLayout.DEFAULT_SIZE, 105, Short.MAX_VALUE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(Add)
                                        .addComponent(Cancel))
                                .addContainerGap())
        );

        pack();
    }
}
