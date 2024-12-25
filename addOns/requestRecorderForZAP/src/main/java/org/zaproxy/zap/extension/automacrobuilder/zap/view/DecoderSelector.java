package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.zaproxy.zap.extension.automacrobuilder.CastUtils;
import org.zaproxy.zap.extension.automacrobuilder.Encode;
import org.zaproxy.zap.extension.automacrobuilder.StartEndPosition;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.view.GridBagJDialog;
import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.zap.DecoderTag;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;

import javax.swing.*;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

@SuppressWarnings("serial")
public class DecoderSelector extends GridBagJDialog<Object> {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    // ### START: GUI parameters. these parameters should initialize createMainPanelContent
    JComboBox<DecodeType> decodeComboBox;
    JTextPane textPane;
    JLabel infoLabel;
    // ### END:  GUI parameters. these parameters should initialize createMainPanelContent

    private StartEndPosition startEndPosition;
    private MacroBuilderUI mbui;
    private Encode enc;

    /**
     * create new instance of DecoderSelector
     *
     * @param mbui
     * @param startEndPosition
     * @param enc
     * @return new instance of DecoderSelector
     */
    public static DecoderSelector newInstance(MacroBuilderUI mbui, StartEndPosition startEndPosition, Encode enc) {
        return new DecoderSelector(mbui).buildThis(mbui, startEndPosition, enc);
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * see newInstance() method.<br>
     * In extended class, you must call super.buildThis(mbui, startEndPosition, enc) in your buildThis method.
     *
     * @param mbui
     * @param startEndPosition
     * @param enc
     * @return this instance
     */
    protected DecoderSelector buildThis(MacroBuilderUI mbui, StartEndPosition startEndPosition, Encode enc) {
        postSuper();
        this.enc = enc;
        this.mbui = mbui;
        this.startEndPosition = startEndPosition;
        this.textPane.setText(startEndPosition.value);
        return this;
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param mbui
     */
    protected DecoderSelector(MacroBuilderUI mbui) {
        super(SwingUtilities.windowForComponent(mbui), bundle.getString("DecoderSelector.dialog.title.text"), Dialog.ModalityType.DOCUMENT_MODAL);
    }

    @Override
    public void disposeChild() {

    }

    public enum DecodeType {
        original,
        base64,
        URL
    }

    @Override
    protected Component createMainPanelContent(Component mainPanel, Object optionalObject) {
        DefaultComboBoxModel<DecodeType> comboModel =  new DefaultComboBoxModel<>(new DecodeType[] {
                DecodeType.original,
                DecodeType.base64,
                DecodeType.URL
        });

        decodeComboBox =  new JComboBox<>(comboModel);

        textPane = new JTextPane();
        BoxAndScrollerPanel boxAndScrollerPanel = BoxAndScrollerPanel.newInstance();
        infoLabel = new JLabel("");
        boxAndScrollerPanel.addComponentToBoxPanelAtYaxis(decodeComboBox);
        boxAndScrollerPanel.addComponentToBoxPanelAtYaxis(infoLabel);
        infoLabel.setAlignmentX(Component.RIGHT_ALIGNMENT);
        infoLabel.setMaximumSize(new Dimension(9999, 9999));
        //infoLabel.setHorizontalAlignment(JLabel.LEFT);
        Color defaultLabelForeColor = infoLabel.getForeground();
        //LineBorder lborder = new LineBorder(Color.BLACK, 2, false);
        //infoLabel.setBorder(lborder);
        boxAndScrollerPanel.setComponentToScroller(textPane);

        decodeComboBox.addActionListener(new ActionListener() {
            final DecoderSelector thisDecoderSelector = DecoderSelector.this;
            final JComboBox<DecodeType> thisDecodeComboBox = decodeComboBox;
            final JTextPane thisTextPane = textPane;
            final JLabel thisInfoLabel = infoLabel;
            @Override
            public void actionPerformed(ActionEvent e) {
                DecodeType decodeType = CastUtils.castToType(thisDecodeComboBox.getSelectedItem());
                Color labelForeColor = defaultLabelForeColor;
                String infoMessage = "";
                String originalValue = thisDecoderSelector.startEndPosition.value;
                String decodedValue = originalValue;
                if (decodeType != null) {
                    switch(decodeType) {
                        case base64:
                            if (ZapUtil.isBase64(originalValue)) {
                                decodedValue = ZapUtil.decodeBase64(originalValue, thisDecoderSelector.enc);
                            } else {
                                labelForeColor = Color.RED;
                                infoMessage = bundle.getString("DecoderSelector.nobase64.info.text");
                            }
                            break;
                        case URL:
                            if (ZapUtil.isURLencoded(originalValue)) {
                                decodedValue = ZapUtil.decodeURL(originalValue, thisDecoderSelector.enc);
                            } else {
                                labelForeColor = Color.RED;
                                infoMessage = bundle.getString("DecoderSelector.nourl.info.text");
                            }
                            break;
                    }
                }
                this.thisTextPane.setText(decodedValue);
                this.thisInfoLabel.setText(infoMessage);
                this.thisInfoLabel.setForeground(labelForeColor);
            }
        });

        return boxAndScrollerPanel;
    }


    @Override
    protected void okBtnActionPerformed() {
        JTextPane messageRequest = this.mbui.getMessageRequest();
        StyledDocumentWithChunk requestChunkDoc = CastUtils.castToType(messageRequest.getStyledDocument());

        String encodedText = this.textPane.getText();
        DecodeType decodeType = CastUtils.castToType(this.decodeComboBox.getSelectedItem());
        String decodeAreaPrefix = "";
        String decodeAreaSuffix = "";
        switch(decodeType) {
            case URL:
                decodeAreaPrefix = DecoderTag.DECODE_PREFIX_URL_STRING;
                decodeAreaSuffix = DecoderTag.DECODE_SUFFIX_URL_STRING;
                break;
            case base64:
                decodeAreaPrefix = DecoderTag.DECODE_PREFIX_BASE64_STRING;
                decodeAreaSuffix = DecoderTag.DECODE_SUFFIX_BASE64_STRING;
                break;
        }
        String embedString = decodeAreaPrefix + encodedText + decodeAreaSuffix;
        LOGGER4J.debug("decodeType:" + decodeType.name() + "embedString[" + embedString + "]");
        try {
            int len = this.startEndPosition.end - this.startEndPosition.start;
            requestChunkDoc.remove(this.startEndPosition.start, len);
            requestChunkDoc.insertString(this.startEndPosition.start, embedString, null);
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        dispose();
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }
}
