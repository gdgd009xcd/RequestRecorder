package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import javax.swing.*;
import java.awt.*;

@SuppressWarnings("serial")
public class BoxAndScrollerPanel extends JPanel {
    // create borderlayout for adding option input components in the future
    //  |-------------border layout PAGE_START--------------------|
    //  | |---------Box layout BoxLayout.Y_AXIS-----------------| |
    //  | | checkBox1 ------------------|                       | |
    //  | | checkBox2 ------------------|                       | |
    //  | |-----------------------------------------------------| |
    //  |-------------border layout PAGE_CENTER-------------------|
    //  | |---------------- JScrollPane ------------------------| |
    //  | |                                                     | |
    //  | |-----------------------------------------------------| |
    //  |---------------------------------------------------------|

    private JPanel boxPanel;
    private JScrollPane scroller;

    /**
     * create new instance of BoxAndScrollerPanel with default scroll policy
     * @return BoxAndScrollerPanel instance
     */
    public static BoxAndScrollerPanel newInstance() {
        return new BoxAndScrollerPanel().buildThis(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
    }

    /**
     * create new instance of BoxAndScrollerPanel with specified scroll policy
     *
     * @param horizontalPolicy
     * @param verticalPolicy
     * @return BoxAndScrollerPanel instance
     */
    public static BoxAndScrollerPanel newInstance(int horizontalPolicy, int verticalPolicy) {
        return new BoxAndScrollerPanel().buildThis(horizontalPolicy, verticalPolicy);
    }

    /**
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     */
    protected BoxAndScrollerPanel() {
        super();
    }

    /**
     * you must call this method in newInstance method after creating this object<br>
     * See newInstance() method.<br>
     * In extended class, you must override this method and call super.buildThis(horizontalPolicy, verticalPolicy) in it.
     *
     * @param horizontalPolicy
     * @param verticalPolicy
     * @return this instance
     */
    protected BoxAndScrollerPanel buildThis(int horizontalPolicy, int verticalPolicy) {
        initialize(horizontalPolicy, verticalPolicy);
        return this;
    }

    private void initialize(int horizontalPolicy, int verticalPolicy) {
        // create borderlayout for total background
        BorderLayout boxAndScrollerBorderLayout = new BorderLayout();
        boxAndScrollerBorderLayout.setVgap(10);
        this.setLayout(boxAndScrollerBorderLayout);

        // create BoxLayout.Y=AXIS in PAGE_START
        boxPanel = new JPanel();
        boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.PAGE_AXIS));
        // add BoxLayout to PAGE_START of Borderlayout JPanel
        this.add(boxPanel, BorderLayout.PAGE_START);

        // create JScrollPane in PAGE_CENTER
        scroller = new JScrollPane();
        scroller.setHorizontalScrollBarPolicy(horizontalPolicy);
        scroller.setVerticalScrollBarPolicy(verticalPolicy);
        scroller.setPreferredSize(new Dimension(400,400));
        scroller.setAutoscrolls(true);


        // add JScrolledPane to CENTER area of BorderLayout JPanel
        this.add(scroller, BorderLayout.CENTER);
    }

    public void addComponentToBoxPanelAtYaxis(Component compo) {
        boxPanel.add(compo);
    }

    public void setComponentToScroller(Component compo) {
        scroller.setViewportView(compo);
    }
}
