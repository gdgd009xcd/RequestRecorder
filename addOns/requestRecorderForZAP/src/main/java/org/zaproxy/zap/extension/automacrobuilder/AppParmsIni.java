/*
 * Copyright 2024 gdgd009xcd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.io.File;
import java.util.*;
import java.util.regex.Pattern;

/**
 * @author gdgd009xcd
 */
//
// class AppParmsIni
//
public class AppParmsIni {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    private String url;
    private Pattern urlregex;
    private ArrayList<AppValue> parmlist = null;
    private Iterator<AppValue> it;
    private int len = 4;
    private String type;
    private int typeval; // number:0, rand:1, csv:2, track:3
    private int inival = 0;
    private int maxval = 2147483646;
    private FileReadLine frl = null;
    private String csvName = null;
    private String exerr = "";
    private Integer cntCount = null;
    long csvSeekIndex = 0;
    int csvCurrentRecordNumber = 0;
    private int rndval = 1;
    // public int row;
    private Boolean pause = false;
    private int TrackFromStep = -1; // StepNo== -1:any  >0:TrackingFrom
    private int SetToStep =
            EnvironmentVariables.TOSTEPANY; // == TOSTEPANY:any   0<= SetToStep < TOSTEPANY:SetTo

    public static final int T_NUMBER = 0; // ascent order number value
    public static final int T_RANDOM = 1; // random value
    public static final int T_CSV = 2; // csv
    public static final int T_TRACK = 3; // tracking tokens
    public static final int T_TAMPER = 4; // TamperProxy
    public static final String T_NUMBER_NAME = "number";
    public static final String T_RANDOM_NAME = "random";
    public static final String T_CSV_NAME = "csv";
    public static final String T_TRACK_NAME = "track";
    public static final String T_TAMPER_NAME = "tamper";
    public static final int T_TRACK_AVCNT = 8;

    public void setCsvName(String csvname) {
        this.csvName = csvname;
    }

    public String getCsvName() {
        return this.csvName;
    }

    public void crtFrl(String filepath) {
        frl = new FileReadLine(this, filepath);
    }

    public String getFrlFileName() {
        if (frl != null) {
            return frl.getFileName();
        }
        return null;
    }

    public void setLen(int len) {
        this.len = len;
    }

    public int getLen() {
        return this.len;
    }

    public enum NumberCounterTypes {
        NumberCount,
        DateCount,
    }

    public void setTrackFromStep(int _step) {
        TrackFromStep = _step;
    }

    public int getTrackFromStep() {
        return TrackFromStep;
    }

    public void setSetToStep(int _step) {
        SetToStep = _step;
    }

    public int getSetToStep() {
        return SetToStep;
    }

    /**
     * is Paused
     *
     * <p>Get boolean pause value
     */
    public boolean isPaused() {
        return pause;
    }

    /**
     * Set pause when JSON load/parameter generate
     *
     * @param b boolean
     */
    public void initPause(boolean b) {
        this.pause = b;
    }

    /**
     * Update pause status when GUI manipulation
     *
     * @param b boolean
     */
    public void updatePause(boolean b) {
        pause = b;
        String _c = getCurrentValue();
        switch (typeval) {
            case T_NUMBER:
            case T_CSV:
                int _i = Integer.parseInt(_c);
                if (pause) {
                    if (_i > 0) {
                        _i--;
                        updateCurrentValue(_i);
                    }
                } else {
                    _i++;
                    updateCurrentValue(_i);
                }
                break;
            case T_TRACK:
                break;
            case T_RANDOM:
                break;
        }
    }

    public void clearAppValues() {
        parmlist = new ArrayList<AppValue>();
    }

    public void addAppValue(AppValue app) {
        if (parmlist != null) {
            parmlist.add(app);
        }
    }

    public int getIniVal() {
        return this.inival;
    }

    public void setIniVal(int inival) {
        this.inival = inival;
    }

    public Integer getCntCount() {
        return this.cntCount;
    }

    public void setCntCount(Integer val) {
        EnvironmentVariables.modified(true);
        this.cntCount = val;
    }

    public int getMaxVal() {
        return this.maxval;
    }

    public void setMaxVal(int maxval) {
        this.maxval = maxval;
    }

    public String getIniValDsp() {
        switch (typeval) {
            case T_NUMBER:
                return Integer.toString(inival);
            case T_CSV:
                return frl.getFileName();
            case T_TRACK:
                return "";
            case T_RANDOM:
                return "";
        }
        return "";
    }

    public String getTypeValDspString() {
        switch (typeval) {
            case T_NUMBER:
                return bundle.getString("ParmGen.AscendingOrder.text");
            case T_CSV:
                return bundle.getString("ParmGen.CSVAscendOrder.text");
            case T_RANDOM:
                return bundle.getString("ParmGen.Random.text");
            case T_TRACK:
                return bundle.getString("ParmGen.Tracking.text");
            case T_TAMPER:
                return bundle.getString("ParmGen.TAMPERPROXY.text");
        }
        return "";
    }

    public void setTypeValFromString(String _type) {
        type = _type;
        if (type.indexOf(T_RANDOM_NAME) != -1) { // random
            for (int x = 0; x < len; x++) {
                rndval = rndval * 10;
            }
            typeval = T_RANDOM;
        } else if (type.indexOf(T_NUMBER_NAME) != -1) {
            typeval = T_NUMBER;
        } else if (type.indexOf(T_TRACK_NAME) != -1) {
            typeval = T_TRACK;
        } else if (type.indexOf(T_TAMPER_NAME) != -1) {
            typeval = T_TAMPER;
        } else {
            typeval = T_CSV;
        }
    }

    public int getTypeVal() {
        return typeval;
    }

    public void setTypeVal(int typeval) {
        this.typeval = typeval;
    }

    public String getLenDsp() {
        return Integer.toString(len);
    }

    public int getAppValuesLineCnt() {
        if (parmlist != null) {
            int l = parmlist.size();
            if (l <= 0) l = 1;
            return l;
        }
        return 1;
    }

    public String getAppValuesDsp() {
        it = parmlist.iterator();
        String appvalues = "";
        while (it.hasNext()) {
            AppValue ap = it.next();
            if (appvalues.length() > 0) {
                appvalues += "\n";
            }
            appvalues += ap.getAppValueDsp(typeval);
        }
        return appvalues;
    }

    public String setUrl(String _url) {
        exerr = null;
        try {
            url = _url;
            urlregex = ParmGenUtil.Pattern_compile(url);

        } catch (Exception e) {
            urlregex = null;
            exerr = e.toString();
        }
        return exerr;
    }

    public String getUrl() {
        return url;
    }

    public Pattern getPatternUrl() {
        return urlregex;
    }

    // --------------constructors begin----------------

    public AppParmsIni() {
        parmlist = new ArrayList<AppValue>();
        rewindAppValues();
    }

    // --------------constructors end----------------

    @Deprecated
    public String getTypeValToString() {
        switch (typeval) {
            case T_NUMBER:
                return T_NUMBER_NAME;
            case T_RANDOM:
                return T_RANDOM_NAME;
            case T_CSV:
                return T_CSV_NAME;
            case T_TRACK:
                return T_TRACK_NAME;
            case T_TAMPER:
                return T_TAMPER_NAME;
            default:
                break;
        }
        return "";
    }

    @Deprecated
    private String getCurrentSaveDir() {
        File cfile = new File(EnvironmentVariables.getSaveFilePathName());
        String dirname = cfile.getParent();
        return dirname;
    }

    @Deprecated
    private String crtRandomFileName() {
        String fname = null;

        UUID uuid = UUIDGenerator.getUUID();
        String uustr = uuid.toString();
        fname = uustr + ".txt";
        return fname;
    }

    // when entry AppParmIni/AppValue modified, accidentally last AppValue entry NOCOUNT flag maybe
    // be set.
    // so it must be clear NOCOUNT.
    public void clearLastAppValueNOCOUNT() {
        if (parmlist != null) {
            int plast = parmlist.size() - 1;
            if (plast >= 0) {
                AppValue av = parmlist.get(plast);
                av.clearNoCountExported();
                parmlist.set(plast, av);
            }
        }
    }

    String getFillZeroInt(int v) {
        String nval = Integer.toString(v);
        int minus = v < 0 ? -1 : 0;
        if (minus < 0) {
            nval = nval.substring(1);
        }
        int zero = len - nval.length() + minus;
        while (zero > 0) {
            nval = "0" + nval;
            zero--;
        }
        if (minus < 0) {
            nval = "-" + nval;
        }
        return nval;
    }

    String getGenValue(
            ParmGenMacroTrace pmt,
            AppValue apv,
            ParmGenTokenKey tk,
            int currentStepNo,
            int toStepNo,
            int csvpos) {
        int n;
        switch (typeval) {
            case T_NUMBER: // number
                n = countUp(apv.isNoCount(), this, apv, pmt); // synchronized
                return getFillZeroInt(n); // thread safe
            case T_RANDOM: // random
                Random rand = new Random();
                n = rand.nextInt(rndval);
                return getFillZeroInt(n); // thread safe
            case T_TRACK: // loc
                // if ( global.Location != void ){
                return pmt.getFetchResponseVal()
                        .getLocVal(
                                apv.getTrackKey(),
                                tk,
                                currentStepNo,
                                toStepNo,
                                apv); // per thread object
                // }
            default: // csv
                if (frl != null) {
                    LOGGER4J.debug("frl.csvfile:" + frl.csvfile);
                    if (csvpos == -1) {
                        csvpos = len;
                    }
                    return frl.readLine(
                            apv.isNoCount(), csvpos, apv, pmt); // read CSV 1 record. synchronized
                } else {
                    LOGGER4J.debug("getGenValue frl is NULL");
                }
                break;
        }
        return null;
    }

    String getStrCnt(
            ParmGenMacroTrace pmt,
            AppValue apv,
            ParmGenTokenKey tk,
            int currentStepNo,
            int toStepNo,
            int csvpos) {
        // if ( cstrcnt == null|| typeval == 3){
        String cstrcnt = getGenValue(pmt, apv, tk, currentStepNo, toStepNo, csvpos);
        // }
        return cstrcnt;
    }

    synchronized int countUp(
            boolean isNoCount, AppParmsIni _parent, AppValue apv, ParmGenMacroTrace pmt) {
        // counter file open
        int cnt = inival;
        if (cntCount != null) {
            cnt = cntCount;
        }

        int nextCnt = cnt + 1;

        boolean condInValid = false;
        if (pmt != null && apv != null) {
            condInValid = !pmt.getFetchResponseVal().getCondValid(apv) && apv.hasCond();
        }
        if (condInValid || isNoCount || _parent.isPaused()) {
            nextCnt = cnt;
        } else if (cnt > maxval) {
            LOGGER4J.debug(
                    "CountUp maxval reached. reset to inival"
                            + Integer.toString(cnt)
                            + "->"
                            + Integer.toString(inival));
            nextCnt = inival;
        } else {
            LOGGER4J.debug("CountUp ncnt:" + Integer.toString(cnt));
        }

        if (!isNoCount) {
            setCntCount(nextCnt);
        }
        return cnt;
    }

    int updateCounter(int i) {
        setCntCount(i);
        return i;
    }

    public String getCurrentValue() {
        String rval = null;
        switch (typeval) {
            case T_NUMBER:
                int i = countUp(true, this, null, null); // synchronized
                rval = Integer.toString(i);
                break;
            case T_RANDOM:
                break;
            case T_CSV:
                rval = frl.getCurrentReadLine(); // synchronized
                break;
            case T_TRACK:
                break;
            default:
                break;
        }
        return rval;
    }

    public void updateCurrentValue(int i) {
        switch (typeval) {
            case T_NUMBER:
                updateCounter(i);
                break;
            case T_RANDOM:
                break;
            case T_CSV:
                frl.skipLine(i);
                break;
            case T_TRACK:
                break;
            default:
                break;
        }
    }

    public final void rewindAppValues() {
        if (parmlist != null) {
            it = parmlist.iterator();
        } else {
            it = null;
        }
    }

    /**
     * get JTable row which is generated from AppValue
     *
     * @return Object[]
     */
    public Object[] getNextAppValuesRow() {
        AppValue app;
        if (it != null && it.hasNext()) {
            app = it.next();
            switch (typeval) {
                case T_NUMBER:
                    return new Object[] {
                        app.getHttpSectionTypeEmbedTo(),
                        (app.isEnabled() ? false : true),
                        app.getRegexEmbedValTo(),
                        app.isNoCount() ? false : true
                    };
                case T_RANDOM:
                    break;
                case T_CSV:
                    return new Object[] {
                        app.getHttpSectionTypeEmbedTo(),
                        (app.isEnabled() ? false : true),
                        app.getCsvpos(),
                        app.getRegexEmbedValTo(),
                        app.isNoCount() ? false : true
                    };
                case T_TRACK:
                    return new Object[] {
                        app.getHttpSectionTypeEmbedTo(),
                        (app.isEnabled() ? false : true),
                        app.getRegexEmbedValTo(),
                        app.getRegexTrackURLFrom(),
                        app.getRegexTrackValFrom(),
                        app.getHttpSectionTypeTrackFrom(),
                        Integer.toString(app.getPositionTrackFrom()),
                        app.getParamNameTrackFrom(),
                        app.isUrlEncode(),
                        app.getFromStepNo() == -1 ? "*" : Integer.toString(app.getFromStepNo()),
                        app.getToStepNo() == EnvironmentVariables.TOSTEPANY
                                ? "*"
                                : Integer.toString(app.getToStepNo()),
                        app.getTokenTypeTrackFrom().name(),
                        app.getCondRegex(),
                        app.getCondTargetNo(),
                        app.requestIsCondRegexTarget(),
                        app.isReplaceZeroSize()
                    };
                default:
                    break;
            }
        }
        return null;
    }

    /**
     * whether this object is same as argument specified or not.
     *
     * @param bini
     * @return
     */
    public boolean isSameContents(AppParmsIni bini) {

        if (ParmGenUtil.nullableStringEquals(this.url, bini.url)
                && this.len == bini.len
                && ParmGenUtil.nullableStringEquals(this.type, bini.type)
                && this.typeval == bini.typeval
                && this.inival == bini.inival
                && this.maxval == bini.maxval
                && ParmGenUtil.nullableStringEquals(this.getFrlFileName(), bini.getFrlFileName())
                && this.TrackFromStep == bini.TrackFromStep
                && this.SetToStep == bini.SetToStep) {
            boolean issame = true;
            for (AppValue thisapp : this.parmlist) {
                for (AppValue otherapp : bini.parmlist) {
                    if (!thisapp.isSameContents(otherapp)) {
                        issame = false;
                        break;
                    }
                }
            }
            return issame;
        }
        return false;
    }

    /**
     * Get modifiable {@code List<AppValue>} Original.
     *
     * @return parmlist {@code List<AppValue>}
     */
    public List<AppValue> getAppValueReadWriteOriginal() {
        return parmlist;
    }

    public void setCsvSeekIndex(long csvSeekIndex) {
        EnvironmentVariables.modified(true);
        this.csvSeekIndex = csvSeekIndex;
    }

    public long getCsvSeekIndex() {
        return this.csvSeekIndex;
    }

    public void setCsvCurrentRecordNumber(int csvCurrentRecordNumber) {
        EnvironmentVariables.modified(true);
        this.csvCurrentRecordNumber = csvCurrentRecordNumber;
    }

    public int getCsvCurrentRecordNumber() {
        return this.csvCurrentRecordNumber;
    }
}
