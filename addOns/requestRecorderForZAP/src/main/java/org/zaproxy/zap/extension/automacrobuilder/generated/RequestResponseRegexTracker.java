/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.view.JTextPaneContents;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class RequestResponseRegexTracker extends javax.swing.JFrame implements InterfaceRegex, InterfaceParmGenWin {

    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();

    ParmGenNew parentWin;

    public static final int T_NAME = 0;
    public static final int T_VALUE = 1;
    public static final int T_OPTIONTITLE = 2;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    PRequestResponse currentRequestResponse = null;

    // order number of applying Regex
    // 0-8
    // end of array == -1
    int REXSEQ[] ={
      7,8,0,1,2,3,4,5,6,-1
    };

    int matchPos;
    int headerLength;
    String regexPattern;
    AppValue.HttpSectionTypes httpSectionTypesTrackingFrom;
    boolean isHeader;
    boolean sourceIsResponse;

    /**
     * create new instance of RequestResponseRegexTracker
     *
     * @param _pwin
     * @return RequestResponseRegexTracker
     */
    public static RequestResponseRegexTracker newInstance(ParmGenNew _pwin, boolean sourceIsResponse){
        return new RequestResponseRegexTracker(_pwin).buildThis(_pwin, sourceIsResponse);
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * See newInstace() method.<br>
     * In extended class, you must call super.buildThis in overridden buildThis method
     *
     * @param _pwin
     * @return this
     */
    protected RequestResponseRegexTracker buildThis(ParmGenNew _pwin, boolean sourceIsResponse){
        parentWin = _pwin;
        // initComponents();
        customInitComponents();
        this.matchPos = -1;
        this.regexPattern = null;

        this.isHeader = false;
        this.sourceIsResponse = sourceIsResponse;
        if (sourceIsResponse) {
            this.httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.Response;
        } else {
            this.httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.Request;
        }
        return this;
    }

    /**
     * Do not use this constructor directly.<br>
     * use newInstance() instead.
     *
     * @param _pwin
     */
    protected RequestResponseRegexTracker(ParmGenNew _pwin) {
        super();
    }
    
    public String getRegex(){
        return regexPatternTextField.getText();
    }
    
    public String getOriginal(){
        return regextTextAreaTextPane.getText();
    }
    
    public void setRegex(String regex){
        regexPattern = regex;
        regexPatternTextField.setText(regexPattern);
    }
    
    /**
     * get regex of The tag before the selected text
     *
     * @param ssinfo
     * @return StrSelectInfo
     */
    private StrSelectInfo getSelectionPrefixRegex(StrSelectInfo ssinfo) {
        int startpos = regextTextAreaTextPane.getSelectionStart();
        int lfcnt=0;
        int tagcnt = 0;
        int tagbgn = -1;
        int lbgn = -1;
        for(int i = startpos; i>=0 ; i--){
            int offs = i;
            try{
                String ch = regextTextAreaTextPane.getText(offs, 1);
                char c = ch.charAt(0);
                switch(c){
                    case '\n':
                        lfcnt++;
                        break;
                    case '>':
                        if (tagcnt==0){
                            tagcnt = 1;
                        }
                        break;
                    case '<':
                        if(tagcnt==1){
                            tagcnt = 2;
                            tagbgn = offs;
                        }
                        break;
                    default:
                        break;
                }
                if (lfcnt>1){
                    break;
                }
                lbgn = offs;
            }catch(BadLocationException e){
                EnvironmentVariables.plog.printException(e);
            }
        }
        
        // lbgn < tagbgn < startpos
        if ( tagbgn > -1){
            try {
                ssinfo.val = regextTextAreaTextPane.getText(tagbgn, startpos - tagbgn);
                ssinfo.start = tagbgn;
                ssinfo.end = startpos;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(RequestResponseRegexTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(lbgn > -1){
            try {
                ssinfo.val = regextTextAreaTextPane.getText(lbgn, startpos - lbgn);
                ssinfo.start = lbgn;
                ssinfo.end = startpos;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(RequestResponseRegexTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    /**
     * get regex of the tag after selected text
     *
     * @param ssinfo
     * @return StrSelectInfo
     */
    private StrSelectInfo getSelectionSuffixRegex(StrSelectInfo ssinfo){
        int endpos = regextTextAreaTextPane.getSelectionEnd();
        int lastpos = regextTextAreaTextPane.getText().length();
        int lfcnt=0;
        int tagcnt = 0;
        int tagend = -1;
        int lend = -1;
        for(int i = endpos; i<lastpos ; i++){
            int offs = i;
            try{
                String ch = regextTextAreaTextPane.getText(offs, 1);
                char c = ch.charAt(0);
                switch(c){
                    case '\n':
                        lfcnt++;
                        break;
                    case '<':
                        if (tagcnt==0){
                            tagcnt = 1;
                        }
                        break;
                    case '>':
                        if(tagcnt==1){
                            tagcnt = 2;
                            tagend = offs;
                        }
                        break;
                    default:
                        break;
                }
                if (lfcnt>1){
                    break;
                }
                lend = offs;
            }catch(BadLocationException e){
                EnvironmentVariables.plog.printException(e);
            }
        }
        
        // endpos < tagend < lend
        if ( tagend > -1){
            try {
                ssinfo.val = regextTextAreaTextPane.getText(endpos, tagend - endpos+1);
                ssinfo.start = endpos;
                ssinfo.end = tagend;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(RequestResponseRegexTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(lend > -1){
            try {
                ssinfo.val = regextTextAreaTextPane.getText(endpos, lend - endpos+1);
                ssinfo.start = endpos;
                ssinfo.end = lend;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(RequestResponseRegexTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    private boolean isMatched(int i, int s, int e, String regex, String reqstr, ArrayList<String> groupvalues, boolean first){
        Pattern pattern = ParmGenUtil.Pattern_compile(regex,Pattern.CASE_INSENSITIVE|Pattern.MULTILINE);
        Matcher matcher;
        matchPos = -1;
        try{
            String trueregex = null;
            matcher = pattern.matcher(reqstr);
            while(matcher.find()){
                matchPos++;
                groupvalues.clear();
                int gcnt = matcher.groupCount();
                if ( gcnt > 0){
                    int valuepos;
                    switch (i){
                        case 0://<input name="(g1)" value="(g2)">
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add(matcher.group(1));
                                groupvalues.add("");
                            }
                            break;
                        case 1://<option value="(1 val)">(2optiontitle)</option>
                        case 7://<option value="(1 val)" selected>(2optiontitle)</option>
                        case 8://<option selected value="(1 val)">(2optiontitle)</option>
                            valuepos = 1;
                            if(gcnt>1){
                                groupvalues.add("");
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 2:
                            valuepos = gcnt;
                            if(gcnt>2){
                                valuepos = 2;
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add(matcher.group(3));
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 3://<(1 tagname)>(2value)<xxx>
                        case 4:
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 5:
                        case 6:
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        default:
                            valuepos = gcnt;
                            groupvalues.add(matcher.group(1));
                            break;
                    }
                    int _s = matcher.start(valuepos);
                    int _e = matcher.end(valuepos);
                    
                    if (isHeader){
                        if (_s > headerLength){
                            matcher.reset();
                            break;
                        }
                    }
                    if ( _s == s && _e == e){
                        matcher.reset();
                        return true;
                    }
                }
                if(first){
                    matcher.reset();
                    break;
                }
            }
            matcher.reset();

        }catch(Exception err){
            LOGGER4J.error("", err);
        }
        return false;
    }
    
    private String getNameVal(int i){
        switch(i){
            case 3:
                return "(\\s|[^\\<\\>]*?)";
            case 5:
                return "([^\\<\\>:]*?(?:[ \\t]*?):(?:[ \\t]*?)(?:.*)[0-9A-Za-z_\\-\\.]+=)";//header: name=value...
            case 6:
                return "([^\\<\\>:]*?(?:[ \\t]*?):(?:[ \\t]*?)(?:.*))";//header: value...
            default:
                break;
        }
        return "(.*?)";
    }
    
    private String getOptionVal(int i){
        switch(i){
            case 2:
                return "(.*)";
            default:
                break;
        }
        return "(\\s|[^\\s\\>\\<]*?)";// menu title including CR or LF chars.
    }
    
    private String getInputTagRegex(int i,  String nameval, String optiontitle, String val, String realval){
        switch(i){
            case 0:
                //return  "\\<input(?:[ \\t]+)(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\"" + nameval + "\"(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"" ;
                return  "\\<input(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\"" + nameval + "\"(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"" ;
            case 1://option tag
                return  "\\<option(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)\\>" + optiontitle + "\\</option\\>";
                //return "\\<select(?:[ \\t]+)(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\""+ nameval +"\"(?:.*?)\\>(?:\\s|[^\\s])*?<option(?:[ \\t]*?)*?value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"(?:.*?)>" + optiontitle + "\\</option\\>";
            case 2:
                return "^"+ nameval + "(?:\"|\\>)" + realval + "(?:\"|\\<)" + optiontitle + "$";
            case 3:
                return "\\<"+ nameval + "\\>" + val + "\\<[^\\<\\>]+\\>";
            case 4:
                return "\\<"+ nameval + "\\>" + val + "$";//改行終了
            case 5 :
                return "^" + nameval +  val + "(?:[ \t;]*?)" + ".*$";
            case 6 :
                return "^" + nameval +  val +  ".*$";
            case 7://<option value="(val)" selected>optiontitle</option>
                return  "\\<option(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)selected(?:.*?)\\>" + optiontitle + "\\</option\\>";
            case 8://<option selected value="(val)">optiontitle</option>
                return  "\\<option(?:.*?)selected(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)\\>" + optiontitle + "\\</option\\>";
            default:
                break;
        }
        return null;
    }
 
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    private void customInitComponents() {
        regexTextButton = new javax.swing.JButton();
        instructionDescLabel = new javax.swing.JLabel();
        instructionDescLabel.putClientProperty("html.disable", Boolean.FALSE);
        responseURLTextField = new javax.swing.JTextField();
        urlLabel = new javax.swing.JLabel();
        regexPatternTextField = new javax.swing.JTextField();
        selectValueButton = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        nextButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        messageLabel = new javax.swing.JLabel();
        fixedValueCheckBox = new javax.swing.JCheckBox();
        regexTextAreaScrollPane = new javax.swing.JScrollPane();
        regextTextAreaTextPane = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("RequestResponseRegexTracker.ExtractTrackingParamTitle.text")); // NOI18N

        regexTextButton.setText(bundle.getString("RequestResponseRegexTracker.RegexTextBtn.text")); // NOI18N
        regexTextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                regexTextButtonActionPerformed(evt);
            }
        });

        instructionDescLabel.setText(bundle.getString("RequestResponseRegexTracker.InstructionDescLabel1.text")); // NOI18N
        instructionDescLabel.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        responseURLTextField.setText("jTextField1");

        urlLabel.setText(bundle.getString("RequestResponseRegexTracker.URL.text")); // NOI18N

        selectValueButton.setText(bundle.getString("RequestResponseRegexTracker.SelectValue.text")); // NOI18N
        selectValueButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selectValueButtonActionPerformed(evt);
            }
        });

        nextButton.setText(bundle.getString("RequestResponseRegexTracker.NextBtn3.text")); // NOI18N
        nextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextButtonActionPerformed(evt);
            }
        });

        cancelButton.setText(bundle.getString("RequestResponseRegexTracker.CancelBtn4.text")); // NOI18N
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        messageLabel.setText(bundle.getString("RequestResponseRegexTracker.MessageLabel.text")); // NOI18N

        fixedValueCheckBox.setText(bundle.getString("RequestResponseRegexTracker.FixedValueCheckBox.text")); // NOI18N

        regexTextAreaScrollPane.setViewportView(regextTextAreaTextPane);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(urlLabel)
                                                .addGap(58, 58, 58)
                                                .addComponent(instructionDescLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                                .addContainerGap())
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jSeparator1)
                                                .addContainerGap())
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(nextButton)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                .addComponent(cancelButton))
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                                        .addGroup(layout.createSequentialGroup()
                                                                                .addComponent(selectValueButton, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                .addGap(18, 18, 18)
                                                                                .addComponent(fixedValueCheckBox))
                                                                        .addGroup(layout.createSequentialGroup()
                                                                                .addComponent(regexPatternTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 488, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                .addGap(18, 18, 18)
                                                                                .addComponent(regexTextButton)))
                                                                .addGap(0, 345, Short.MAX_VALUE)))
                                                .addGap(12, 12, 12))
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(messageLabel)
                                                .addContainerGap(931, Short.MAX_VALUE))
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(regexTextAreaScrollPane)
                                                        .addComponent(responseURLTextField))
                                                .addContainerGap())))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(urlLabel)
                                        .addComponent(instructionDescLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(responseURLTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(14, 14, 14)
                                .addComponent(messageLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(regexTextAreaScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 194, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(selectValueButton)
                                        .addComponent(fixedValueCheckBox))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(regexPatternTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(regexTextButton))
                                .addGap(18, 18, 18)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(nextButton)
                                        .addComponent(cancelButton))
                                .addGap(22, 22, 22))
        );

        pack();
    }

    public void update(){
        if ( this.parentWin.getSelectedMessagesInstance().getChoosedMessageListSize() > 0){
            PRequestResponse rs = this.parentWin.getSelectedMessagesInstance().getChoosedMessage();
            currentRequestResponse = rs;
            responseURLTextField.setText(rs.request.getURL());
            if (this.sourceIsResponse) {
                JTextPaneContents rdoc = new JTextPaneContents(regextTextAreaTextPane);
                rdoc.setResponseChunks(rs.response);
                headerLength = rs.response.getHeaderLength();
            } else {
                JTextPaneContents rdoc = new JTextPaneContents(regextTextAreaTextPane);
                rdoc.setRequestChunks(rs.request);
                headerLength = rs.request.getHeaderLength();
            }
            regextTextAreaTextPane.setCaretPosition(0);
        }
    }

    @Override
    public SelectedMessages getSelectedMessagesInstance() {
        return this.parentWin.getSelectedMessagesInstance();
    }

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void selectValueButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selectValueButtonActionPerformed
        // TODO add your handling code here:
        if (this.sourceIsResponse) {
            selectValueFromResponse();
        } else {
            selectValueFromRequest();
        }
      

    }//GEN-LAST:event_selectValueButtonActionPerformed

    private void selectValueFromRequest() {
        String selected_value = regextTextAreaTextPane.getSelectedText();
        String trimmed = selected_value.trim();
        int offset = selected_value.length() - trimmed.length();
        selected_value = trimmed;
        int startpos = regextTextAreaTextPane.getSelectionStart();
        int endpos = regextTextAreaTextPane.getSelectionEnd()-offset;
        String reqstr = regextTextAreaTextPane.getText();

        String quant = null;
        if(!fixedValueCheckBox.isSelected()){
            quant = "+";
        }
        if(startpos < headerLength && endpos >= headerLength){
            JOptionPane.showMessageDialog(this,
                    bundle.getString("RequestResponseRegexTracker.CantSelectSpanHeaderAndBody.text") ,
                    bundle.getString("RequestResponseRegexTracker.CantSelectSpanHeaderAndBody.title.text"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        // headerlength == until response... headersCRLF...CRLFCRLF
        if (endpos > headerLength){
            EnvironmentVariables.plog.AppendPrint("body endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerLength));
            httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.Request;
            isHeader = false;
        }else{
            EnvironmentVariables.plog.AppendPrint("header endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerLength));
            httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.Request;
            isHeader = true;
        }
        matchPos = -1;
        regexPattern = null;
        String regex = "(.*?)";// blank
        String realval = "()";
        if ( startpos >=0 && startpos < endpos ){
            regex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            realval = "(" + ParmGenRegex.EscapeSpecials(selected_value) + ")";
        }

        //<input ... name="xxx" value="">
        int i = 0;
        String inputtagregex;
        String optiontitle = getOptionVal(i);
        String nameval = getNameVal(i);
        boolean hasHREF = false;
        ArrayList<String> groupvalues = new ArrayList<String>();
        while((inputtagregex = getInputTagRegex(REXSEQ[i], nameval, optiontitle, regex, realval))!=null){
            EnvironmentVariables.plog.AppendPrint(Integer.toString(REXSEQ[i]) +":[" + inputtagregex + "]");
            groupvalues.clear();
            if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                EnvironmentVariables.plog.AppendPrint("matched...");
                Iterator<String> it = groupvalues.iterator();
                if(it.hasNext()){
                    String rawnameval = groupvalues.get(RequestResponseRegexTracker.T_NAME);
                    String rawoptiontitle = groupvalues.get(RequestResponseRegexTracker.T_OPTIONTITLE);
                    rawnameval = ParmGenRegex.EscapeSpecials(rawnameval);
                    String lowerval = rawnameval.toLowerCase();
                    if(lowerval.contains("href")){// no match HREF link.
                        hasHREF = true;
                        break;
                    }
                    rawoptiontitle = ParmGenRegex.EscapeSpecials(rawoptiontitle);
                    String rawval = groupvalues.get(RequestResponseRegexTracker.T_VALUE);
                    String parsedregex = ParmGenRegex.getParsedRegexGroup(rawval, quant);
                    EnvironmentVariables.plog.AppendPrint("rawnameval[" + rawnameval + "] rawoptiontitle[" + rawoptiontitle + "] rawval[" + rawval + "] regex[" + parsedregex + "]");
                    groupvalues.clear();
                    inputtagregex = getInputTagRegex(REXSEQ[i], rawnameval, rawoptiontitle, regex, parsedregex);
                    EnvironmentVariables.plog.AppendPrint(inputtagregex);
                    if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                        EnvironmentVariables.plog.AppendPrint("matched validregex[" + inputtagregex + "]");
                        regexPattern = inputtagregex;
                        regexPatternTextField.setText(regexPattern);
                        break;
                    }
                }
            }
            i++;
            nameval = getNameVal(REXSEQ[i]);
            optiontitle = getOptionVal(REXSEQ[i]);
        }
        if (regexPattern ==null && startpos >=0 && startpos < endpos){// selected any texts.
            StrSelectInfo prefix = new StrSelectInfo();
            StrSelectInfo suffix = new StrSelectInfo();
            prefix=getSelectionPrefixRegex(prefix);
            suffix=getSelectionSuffixRegex(suffix);
            if(hasHREF){
                inputtagregex = ParmGenUtil.getPathsRegex(selected_value);
            }else{
                inputtagregex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            }
            if(prefix!=null&&startpos!= headerLength){ // No prefix if startpos is same as body start position
                inputtagregex = ParmGenRegex.EscapeSpecials(prefix.val) + inputtagregex;
            }
            if(suffix!=null){
                inputtagregex += ParmGenRegex.EscapeSpecials(suffix.val);
            }
            //inputtagregex = "(" + EscapeSpecials(selected_value) + ")";

            EnvironmentVariables.plog.AppendPrint("any tag[" + inputtagregex + "]");
            if (isMatched(99,startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                EnvironmentVariables.plog.AppendPrint("matched any pattern validregex[" + inputtagregex + "]");
                regexPattern = inputtagregex;
                regexPatternTextField.setText(regexPattern);
            }else{
                String selected_value_escaped  = selected_value.replaceAll("(\r|\n)+", "(?:\\\\r|\\\\n)+?");
                regexPattern = "(" + selected_value_escaped + ")";
                regexPatternTextField.setText(regexPattern);
            }
        }
    }
    private void selectValueFromResponse() {
        String selected_value = regextTextAreaTextPane.getSelectedText();
        String trimmed = selected_value.trim();
        int offset = selected_value.length() - trimmed.length();
        selected_value = trimmed;
        int startpos = regextTextAreaTextPane.getSelectionStart();
        int endpos = regextTextAreaTextPane.getSelectionEnd()-offset;
        String reqstr = regextTextAreaTextPane.getText();

        String quant = null;
        if(!fixedValueCheckBox.isSelected()){
            quant = "+";
        }
        if(startpos < headerLength && endpos >= headerLength){
            JOptionPane.showMessageDialog(this,
                    bundle.getString("RequestResponseRegexTracker.CantSelectSpanHeaderAndBody.text") ,
                    bundle.getString("RequestResponseRegexTracker.CantSelectSpanHeaderAndBody.title.text"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        // headerlength == until response... headersCRLF...CRLFCRLF
        if (endpos > headerLength){
            EnvironmentVariables.plog.AppendPrint("body endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerLength));
            httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.ResponseBody;
            isHeader = false;
        }else{
            EnvironmentVariables.plog.AppendPrint("header endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerLength));
            httpSectionTypesTrackingFrom = AppValue.HttpSectionTypes.Header;
            isHeader = true;
        }
        matchPos = -1;
        regexPattern = null;
        String regex = "(.*?)";// blank
        String realval = "()";
        if ( startpos >=0 && startpos < endpos ){
            regex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            realval = "(" + ParmGenRegex.EscapeSpecials(selected_value) + ")";
        }

        //<input ... name="xxx" value="">
        int i = 0;
        String inputtagregex;
        String optiontitle = getOptionVal(i);
        String nameval = getNameVal(i);
        boolean hasHREF = false;
        ArrayList<String> groupvalues = new ArrayList<String>();
        while((inputtagregex = getInputTagRegex(REXSEQ[i], nameval, optiontitle, regex, realval))!=null){
            EnvironmentVariables.plog.AppendPrint(Integer.toString(REXSEQ[i]) +":[" + inputtagregex + "]");
            groupvalues.clear();
            if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                EnvironmentVariables.plog.AppendPrint("matched...");
                Iterator<String> it = groupvalues.iterator();
                if(it.hasNext()){
                    String rawnameval = groupvalues.get(RequestResponseRegexTracker.T_NAME);
                    String rawoptiontitle = groupvalues.get(RequestResponseRegexTracker.T_OPTIONTITLE);
                    rawnameval = ParmGenRegex.EscapeSpecials(rawnameval);
                    String lowerval = rawnameval.toLowerCase();
                    if(lowerval.contains("href")){// no match HREF link.
                        hasHREF = true;
                        break;
                    }
                    rawoptiontitle = ParmGenRegex.EscapeSpecials(rawoptiontitle);
                    String rawval = groupvalues.get(RequestResponseRegexTracker.T_VALUE);
                    String parsedregex = ParmGenRegex.getParsedRegexGroup(rawval, quant);
                    EnvironmentVariables.plog.AppendPrint("rawnameval[" + rawnameval + "] rawoptiontitle[" + rawoptiontitle + "] rawval[" + rawval + "] regex[" + parsedregex + "]");
                    groupvalues.clear();
                    inputtagregex = getInputTagRegex(REXSEQ[i], rawnameval, rawoptiontitle, regex, parsedregex);
                    EnvironmentVariables.plog.AppendPrint(inputtagregex);
                    if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                        EnvironmentVariables.plog.AppendPrint("matched validregex[" + inputtagregex + "]");
                        regexPattern = inputtagregex;
                        regexPatternTextField.setText(regexPattern);
                        break;
                    }
                }
            }
            i++;
            nameval = getNameVal(REXSEQ[i]);
            optiontitle = getOptionVal(REXSEQ[i]);
        }
        if (regexPattern ==null && startpos >=0 && startpos < endpos){// selected any texts.
            StrSelectInfo prefix = new StrSelectInfo();
            StrSelectInfo suffix = new StrSelectInfo();
            prefix=getSelectionPrefixRegex(prefix);
            suffix=getSelectionSuffixRegex(suffix);
            if(hasHREF){
                inputtagregex = ParmGenUtil.getPathsRegex(selected_value);
            }else{
                inputtagregex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            }
            if(prefix!=null&&startpos!= headerLength){ // No prefix if startpos is same as body start position
                inputtagregex = ParmGenRegex.EscapeSpecials(prefix.val) + inputtagregex;
            }
            if(suffix!=null){
                inputtagregex += ParmGenRegex.EscapeSpecials(suffix.val);
            }
            //inputtagregex = "(" + EscapeSpecials(selected_value) + ")";

            EnvironmentVariables.plog.AppendPrint("any tag[" + inputtagregex + "]");
            if (isMatched(99,startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                EnvironmentVariables.plog.AppendPrint("matched any pattern validregex[" + inputtagregex + "]");
                regexPattern = inputtagregex;
                regexPatternTextField.setText(regexPattern);
            }else{
                String selected_value_escaped  = selected_value.replaceAll("(\r|\n)+", "(?:\\\\r|\\\\n)+?");
                regexPattern = "(" + selected_value_escaped + ")";
                regexPatternTextField.setText(regexPattern);
            }
        }
    }
    private void regexTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_regexTextButtonActionPerformed
        // TODO add your handling code here:
        ParmGenRegex.newInstance(this, !this.sourceIsResponse).setVisible(true);
    }//GEN-LAST:event_regexTextButtonActionPerformed

    private void nextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextButtonActionPerformed
        // TODO add your handling code here:
        if ( currentRequestResponse == null ) return;
        EnvironmentVariables.getTemporaryValueStorageInstance().put(
                TemporaryValueStorage.Keys.K_RESPONSEREGEX,
                TemporaryValueStorage.Keys.Class_K_RESPONSEREGEX,
                regexPattern);
        EnvironmentVariables.getTemporaryValueStorageInstance().put(
                TemporaryValueStorage.Keys.K_RESPONSEPART,
                TemporaryValueStorage.Keys.Class_K_RESPONSEPART,
                httpSectionTypesTrackingFrom);

        String message = currentRequestResponse.response.getMessage();
        if (httpSectionTypesTrackingFrom == AppValue.HttpSectionTypes.Request) {
            message = currentRequestResponse.request.getMessage();
        }
       
        int mcnt = ParmGenUtil.getRegexMatchpos(getRegex(), message);
        String poscnt = null;
        
        if(mcnt>0){
            poscnt = Integer.toString(mcnt-1);
        }
        if(poscnt!=null){
            EnvironmentVariables.getTemporaryValueStorageInstance().put(
                    TemporaryValueStorage.Keys.K_RESPONSEPOSITION,
                    TemporaryValueStorage.Keys.Class_K_RESPONSEPOSITION,
                    poscnt);
            dispose();
            RequestResponseSelector.newInstance(
                    bundle.getString("RequestResponseRegexTracker.SelectRequestTitle.text"),
                    parentWin,
                    ParmGenAddParms.newInstance(parentWin, true),
                    ParmGenNew.P_REQUESTTAB).setVisible(true);
        }else{
            JOptionPane.showMessageDialog(
                    this,
                    bundle.getString("RequestResponseRegexTracker.InvalidRegex.text"),
                    bundle.getString("RequestResponseRegexTracker.InvalidRegex.title.text"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_nextButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox fixedValueCheckBox;
    private javax.swing.JTextField regexPatternTextField;
    private javax.swing.JButton regexTextButton;
    private javax.swing.JTextPane regextTextAreaTextPane;
    private javax.swing.JTextField responseURLTextField;
    private javax.swing.JButton selectValueButton;
    private javax.swing.JButton nextButton;
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel instructionDescLabel;
    private javax.swing.JLabel urlLabel;
    private javax.swing.JLabel messageLabel;
    private javax.swing.JScrollPane regexTextAreaScrollPane;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        //NOP
    }

    @Override
    public PRequestResponse getOriginalRequestResponse() {
        return currentRequestResponse;
    }
}
