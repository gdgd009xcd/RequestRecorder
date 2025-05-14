/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class ParsedRequestResponseTracker extends javax.swing.JFrame implements InterfaceRegex, InterfaceParmGenWin {

    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    ParmGenNew parentWin;
    boolean valueExistOnly = false;
    private Set<Integer> selectedRowsHash;

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param _pwin
     */
    protected ParsedRequestResponseTracker(ParmGenNew _pwin) {
        super();
    }

    /**
     * new instance method<br>
     * you must define this in your extended classes for instantiation
     *
     * @param _pwin
     * @return this
     */
    public static ParsedRequestResponseTracker newInstance(ParmGenNew _pwin) {
        return new ParsedRequestResponseTracker(_pwin).buildThis(_pwin);
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * See newInstance() method.
     * In extended class, you must call parent class's buildThis() method in your buildThis() method.
     *
     * @param _pwin
     * @return this
     */
    protected ParsedRequestResponseTracker buildThis(ParmGenNew _pwin) {
        parentWin = _pwin;//parent window
        selectedRowsHash = new HashSet<Integer>();
        // initComponents();
        customInitComponents();
        return this;
    }


    private void NextBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NextBtnActionPerformed
        // TODO add your handling code here:
        //store selected parameters to session buffer.
        AppValue ap = new AppValue();
        int[] rowsSelected = tokenTable.getSelectedRows();
        DefaultTableModel model = (DefaultTableModel) tokenTable.getModel();
        AppValue.HttpSectionTypes httpSectionTypeTrackFrom = AppValue.HttpSectionTypes.Default;
        for (int i = 0;i < rowsSelected.length;i++ ){
            httpSectionTypeTrackFrom = (AppValue.HttpSectionTypes)model.getValueAt(rowsSelected[i], 0); // type of tracking AppValue.HttpSectionTypes.class
            AppValue.TokenTypeNames tokenTypeTrackFrom = (AppValue.TokenTypeNames)model.getValueAt(rowsSelected[i], 1);// type of token AppValue.TokenTypeNames.class
            String num = (String)model.getValueAt(rowsSelected[i], 2); // number of appearing value  
            String name = (String)model.getValueAt(rowsSelected[i], 3);//name
            String value = (String)model.getValueAt(rowsSelected[i], 4);//value
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    i,
                    TemporaryValueStorage.Keys.K_RESPONSEREGEX,
                    TemporaryValueStorage.Keys.Class_K_RESPONSEREGEX,
                    "");
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    i,
                    TemporaryValueStorage.Keys.K_RESPONSEPART,
                    TemporaryValueStorage.Keys.Class_K_RESPONSEPART,
                    httpSectionTypeTrackFrom);
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    i,
                    TemporaryValueStorage.Keys.K_RESPONSEPOSITION,
                    TemporaryValueStorage.Keys.Class_K_RESPONSEPOSITION,
                    num);
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    i,
                    TemporaryValueStorage.Keys.K_TOKEN,
                    TemporaryValueStorage.Keys.Class_K_TOKEN,
                    name);
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    i,
                    TemporaryValueStorage.Keys.K_TOKENTYPE,
                    TemporaryValueStorage.Keys.Class_K_TOKENTYPE,
                    tokenTypeTrackFrom);

            if (httpSectionTypeTrackFrom==AppValue.HttpSectionTypes.ResponseBody) {
                //When extracting tracking values from the response body, use URL-encoded values and set them into the request.
                EnvironmentVariables.getTemporaryValueStorageInstance().put(
                        i,
                        TemporaryValueStorage.Keys.K_URLENCODE,
                        TemporaryValueStorage.Keys.Class_K_URLENCODE,
                        "true");
            }
        }
        dispose();
        if (httpSectionTypeTrackFrom != AppValue.HttpSectionTypes.Request
                && httpSectionTypeTrackFrom != AppValue.HttpSectionTypes.Response) {
            RequestResponseSelector.newInstance(bundle.getString("ParmGenAutoTrack.SelectRequest.text"), parentWin, ParmGenAddParms.newInstance(parentWin, true), ParmGenNew.P_REQUESTTAB).setVisible(true);
        } else {
            RequestResponseRegexTracker rtrack = RequestResponseRegexTracker.newInstance(parentWin, httpSectionTypeTrackFrom == AppValue.HttpSectionTypes.Response);
            rtrack.update();
            dispose();
            rtrack.setVisible(true);
        }
    }//GEN-LAST:event_NextBtnActionPerformed

    private void RegexBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RegexBtnActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_RegexBtnActionPerformed

    private void CancelBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelBtnActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_CancelBtnActionPerformed

    private void valuefilterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_valuefilterActionPerformed
        // checkbox for displaying value which has not null only.
        if(valuefilter.isSelected()){
            valueExistOnly = true;
        }else{
            valueExistOnly = false;
        }
        update();
    }//GEN-LAST:event_valuefilterActionPerformed

    private void customInitComponents() {

        usageDescLabel = new javax.swing.JLabel();
        usageDescLabel.putClientProperty("html.disable", Boolean.FALSE);
        tokenTablePane = new javax.swing.JScrollPane();
        tokenTable = new javax.swing.JTable();
        jSeparator1 = new javax.swing.JSeparator();
        nextBtn = new javax.swing.JButton();
        cancelBtn = new javax.swing.JButton();
        regexBtn = new javax.swing.JButton();
        valuefilter = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ParmGenAutoTrack.title.text")); // NOI18N

        usageDescLabel.setText(bundle.getString("ParmGenAutoTrack.UsageDescLabel.text")); // NOI18N

        tokenTable.setModel(new javax.swing.table.DefaultTableModel(
                new Object [][] {

                },
                new String [] {
                        "type", "tokentype", "order", "name", "value"
                }
        ) {
            boolean[] canEdit = new boolean [] {
                    false, false, false, false, false
            };

            Class<?>[] types = new Class<?> [] {
                    AppValue.HttpSectionTypes.class,
                    AppValue.TokenTypeNames.class,
                    java.lang.String.class,
                    java.lang.String.class,
                    java.lang.String.class
            };

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        tokenTable.getTableHeader().setReorderingAllowed(false);
        tokenTablePane.setViewportView(tokenTable);
        if (tokenTable.getColumnModel().getColumnCount() > 0) {
            tokenTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenAutoTrack.title0.part.text")); // NOI18N
            tokenTable.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenAutoTrack.title2.order.text")); // NOI18N
        }

        nextBtn.setText(bundle.getString("ParmGenAutoTrack.NextBtn.text")); // NOI18N
        nextBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NextBtnActionPerformed(evt);
            }
        });

        cancelBtn.setText(bundle.getString("ParmGenAutoTrack.CancelBtn.text")); // NOI18N
        cancelBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelBtnActionPerformed(evt);
            }
        });

        regexBtn.setText(bundle.getString("ParmGenAutoTrack.RegexBtn.text")); // NOI18N
        regexBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RegexBtnActionPerformed(evt);
            }
        });

        valuefilter.setText(bundle.getString("ParmGenAutoTrack.valuefilter.text")); // NOI18N
        valuefilter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                valuefilterActionPerformed(evt);
            }
        });

        ListSelectionModel selectionModel = tokenTable.getSelectionModel();

        selectionModel.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }

            DefaultTableModel model = (DefaultTableModel) tokenTable.getModel();
            int[] rowsSelected = tokenTable.getSelectedRows();
            List<Integer> clickedRows = getListIndexOfRowIsClicked(rowsSelected);
            AppValue.HttpSectionTypes httpSectionTypeTrackFrom = AppValue.HttpSectionTypes.Default;
            int pos = -1;
            if (rowsSelected.length > 1) {
                for (Integer i : clickedRows) {
                    LOGGER4J.debug("clicked i:" + i);
                    httpSectionTypeTrackFrom = (AppValue.HttpSectionTypes) model.getValueAt(i, 0); // type of tracking
                    if (httpSectionTypeTrackFrom == AppValue.HttpSectionTypes.Request
                            || httpSectionTypeTrackFrom == AppValue.HttpSectionTypes.Response) {
                        selectedRowsHash.clear();
                        selectedRowsHash.add(i);
                        ZapUtil.SwingInvokeLaterIfNeeded(new Runnable() {
                            @Override
                            public void run() {
                                tokenTable.clearSelection();
                                tokenTable.setRowSelectionInterval(i, i);
                            }
                        });
                        return;
                    }
                }

                List<Integer> listRR = new ArrayList<>();
                List<Integer> listNoRR = new ArrayList<>();
                Arrays.stream(rowsSelected)
                        .forEach(i->{
                            AppValue.HttpSectionTypes httpSectionTypeTrackFromLambda = (AppValue.HttpSectionTypes) model.getValueAt(i, 0); // type of tracking
                            if (httpSectionTypeTrackFromLambda == AppValue.HttpSectionTypes.Request
                                    || httpSectionTypeTrackFromLambda == AppValue.HttpSectionTypes.Response) {
                                listRR.add(i);
                            } else {
                                listNoRR.add(i);
                            }
                        });
                if (listRR.size() > 0) {
                    selectedRowsHash.clear();
                    listNoRR.forEach(i -> {selectedRowsHash.add(i);});
                    ZapUtil.SwingInvokeLaterIfNeeded(new Runnable() {
                        @Override
                        public void run() {
                            tokenTable.clearSelection();
                            listNoRR.forEach(i -> {
                                tokenTable.addRowSelectionInterval(i, i);
                            });
                        }
                    });
                    return;
                }
            }
            selectedRowsHash.clear();
            Arrays.stream(rowsSelected).forEach(i -> {
                LOGGER4J.debug("rowsSelected i:" + i);
                selectedRowsHash.add(i);
            });
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addGap(12, 12, 12)
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(jSeparator1)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(nextBtn)
                                                                .addGap(50, 50, 50)
                                                                /* .addComponent(RegexBtn) */
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                .addComponent(cancelBtn))))
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                .addContainerGap()
                                                .addComponent(tokenTablePane))
                                        .addGroup(layout.createSequentialGroup()
                                                .addGap(31, 31, 31)
                                                .addComponent(usageDescLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 271, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(valuefilter)))
                                .addContainerGap())
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addContainerGap()
                                                .addComponent(usageDescLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE)
                                                .addGap(18, 18, 18))
                                        .addGroup(layout.createSequentialGroup()
                                                .addGap(32, 32, 32)
                                                .addComponent(valuefilter)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                .addComponent(tokenTablePane, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(nextBtn)
                                        /*.addComponent(RegexBtn) */
                                        .addComponent(cancelBtn))
                                .addGap(23, 23, 23))
        );

        pack();
    }

    private List<Integer> getListIndexOfRowIsClicked(int[] selectedRows) {
        List<Integer> clickedRows =
                Arrays.stream(selectedRows)
                        .mapToObj(row -> {
                            return Integer.valueOf(row);
                        })
                        .filter(row -> {
                            return !selectedRowsHash.contains(row);
                        })
                        .collect(Collectors.toList());
        return clickedRows;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelBtn;
    private javax.swing.JButton nextBtn;
    private javax.swing.JButton regexBtn;
    private javax.swing.JTable tokenTable;
    private javax.swing.JScrollPane tokenTablePane;
    private javax.swing.JLabel usageDescLabel;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JCheckBox valuefilter;
    // End of variables declaration//GEN-END:variables

    @Override
    public String getRegex() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getOriginal() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setRegex(String regex) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void update() {
        if ( getSelectedMessagesInstance().getChoosedMessageListSize() > 0){
            DefaultTableModel model = (DefaultTableModel) tokenTable.getModel();
            while(model.getRowCount()>0){ // delete all rows of table
                model.removeRow(0);
            }
            PRequestResponse rs = getSelectedMessagesInstance().getChoosedMessage();
            int mpos = rs.getMacroPos();
            if(mpos<-1){
                mpos = -1;
            }
            EnvironmentVariables.
                     getTemporaryValueStorageInstance().
                     put(
                             TemporaryValueStorage.Keys.K_FROMPOS,
                             TemporaryValueStorage.Keys.Class_K_FROMPOS,
                             Integer.toString(mpos)
                     );
            String body = rs.response.getBodyStringWithoutHeader();
            AppValue ap = new AppValue();
            // get Location header value
            ParmGenArrayList tklist = new ParmGenArrayList();
            InterfaceCollection<ParmGenToken> ic = rs.response.getLocationTokens(tklist);
            if(ic!=null){
            	for(ParmGenToken tkn : ic){
            		if(tkn!=null){
            		ParmGenTokenKey tkey = tkn.getTokenKey();
                        ParmGenTokenValue tval = tkn.getTokenValue();
                        String name = tkey.getName();
                        String value = tval.getValue();
                        AppValue.TokenTypeNames tokenTypeTrackFrom = tkey.getTokenType();
                        int npos = 0;
                        if(valueExistOnly ==true&&(value==null||value.isEmpty())){
                            //exclude the parameter which doesn't have value
                        }else{
                            model.addRow(new Object[]{
                                    AppValue.HttpSectionTypes.Header,
                                    tokenTypeTrackFrom,
                                    Integer.toString(npos),
                                    name,
                                    value
                            });
                        }
            		}

            	}
            }
            // get response parameters
            HashMap<String,Integer> namepos = new HashMap<String,Integer>();
            List<ParmGenToken> lst = rs.response.getBodyParamsFromResponse();
            List<ParmGenToken> jlst = rs.response.getJSONParamList();
            lst.addAll(jlst);

            for (Iterator<ParmGenToken> it = lst.iterator(); it.hasNext();) {
                ParmGenToken tkn = it.next();
                if (tkn!=null) {
                    ParmGenTokenKey tkey = tkn.getTokenKey();
                    ParmGenTokenValue tval = tkn.getTokenValue();
                    String name = tkey.getName();
                    String value = tval.getValue();
                    AppValue.TokenTypeNames tokenTypeTrackFrom = tkey.getTokenType();
                    int npos = tkey.getFcnt();
                    if (valueExistOnly && (value == null || value.isEmpty())) {
                        // exclude the parameter which doesn't have value.
                    }else{
                        model.addRow(new Object[]{
                                AppValue.HttpSectionTypes.ResponseBody,
                                tokenTypeTrackFrom,
                                Integer.toString(npos),
                                name,
                                value});
                    }
                }
            }

            // get request parameters
            // get parameters from path
            namepos.clear();
            Iterator<String> pit = rs.request.pathparams.iterator();
            int ppos = 1;
            while(pit.hasNext()){
                int npos = 0;
                String name = Integer.toString(ppos);
                if(namepos.containsKey(name)){
                    npos = namepos.get(name);
                    npos++;
                }
                namepos.put(name, npos);                
                model.addRow(new Object[]{
                        AppValue.HttpSectionTypes.RequestPath,
                        AppValue.TokenTypeNames.DEFAULT,
                        Integer.toString(npos),
                        Integer.toString(ppos),
                        pit.next()
                });
                ppos++;
            }

            // get parameters from query
            namepos.clear();
            Iterator<String[]> it = rs.request.getQueryParams().iterator();
            int rcnt = 0;
            while(it.hasNext()){
                rcnt++;
                String[] nv = it.next();
                int npos = 0;
                String name = nv[0];
                if(namepos.containsKey(name)){
                    npos = namepos.get(name);
                    npos++;
                }
                namepos.put(name, npos);
                model.addRow(new Object[]{
                        AppValue.HttpSectionTypes.RequestQuery,
                        AppValue.TokenTypeNames.DEFAULT,
                        Integer.toString(npos),
                        nv[0],
                        nv[1]
                });
            }

            AppValue.TokenTypeNames tokenTypeNameTrackingFromRequest = AppValue.TokenTypeNames.DEFAULT;
            if (rs.request.getContentSubtype().equalsIgnoreCase("JSON")) {
                tokenTypeNameTrackingFromRequest = AppValue.TokenTypeNames.JSON;
                // get JSON parameters from body
                List<ParmGenToken> jsonList = rs.request.getJSONParamList();
                namepos.clear();
                for (Iterator<ParmGenToken> itJSON = jsonList.iterator(); itJSON.hasNext();) {
                    ParmGenToken tkn = itJSON.next();
                    if (tkn != null) {
                        ParmGenTokenKey tkey = tkn.getTokenKey();
                        ParmGenTokenValue tval = tkn.getTokenValue();
                        String name = tkey.getName();
                        String value = tval.getValue();
                        AppValue.TokenTypeNames tokenTypeTrackFrom = tkey.getTokenType();
                        int npos = tkey.getFcnt();
                        if (valueExistOnly && (value == null || value.isEmpty())) {
                            // exclude the parameter which doesn't have value.
                        }else{
                            model.addRow(new Object[]{
                                    AppValue.HttpSectionTypes.RequestBody,
                                    tokenTypeTrackFrom,
                                    Integer.toString(npos),
                                    name,
                                    value});
                        }
                    }
                }
            } else {
                // get parameters from body (www-url-encoded/multipart)
                Iterator<String[]> itb = rs.request.getBodyParamsFromRequest().iterator();
                namepos.clear();
                while(itb.hasNext()){
                    rcnt++;
                    String[] nv = itb.next();
                    int npos = 0;
                    String name = nv[0];
                    if(namepos.containsKey(name)){
                        npos = namepos.get(name);
                        npos++;
                    }
                    namepos.put(name, npos);
                    model.addRow(new Object[]{
                            AppValue.HttpSectionTypes.RequestBody,
                            AppValue.TokenTypeNames.DEFAULT,
                            Integer.toString(npos),
                            nv[0],
                            nv[1]
                    });
                }
            }

            // add request/response for extracting values from it with regex.
            model.addRow(new Object[]{
                    AppValue.HttpSectionTypes.Request,
                    tokenTypeNameTrackingFromRequest,
                    "0",
                    "",
                    ""
            });

            AppValue.TokenTypeNames tokenTypeNameTrackingFromResponse = AppValue.TokenTypeNames.DEFAULT;
            if (rs.response.getContentSubtype().equalsIgnoreCase("JSON")) {
                tokenTypeNameTrackingFromResponse = AppValue.TokenTypeNames.JSON;
            }
            model.addRow(new Object[]{
                    AppValue.HttpSectionTypes.Response,
                    tokenTypeNameTrackingFromResponse,
                    "0",
                    "",
                    ""
            });

        }
        //throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SelectedMessages getSelectedMessagesInstance() {
        return this.parentWin.getSelectedMessagesInstance();
    }

    @Override
    public PRequestResponse getOriginalRequestResponse() {
        return null;
    }
}
