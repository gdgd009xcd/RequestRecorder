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

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.JSONFileIANACharsetName;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author gdgd009xcd
 */
//
// class AppValue
//
public class AppValue {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private HttpSectionTypes httpSectionTypeEmbedTo;
    // 32(100000) == no modify
    private String regexEmbedTo = null; // Target Regex String to embed value in
    private Pattern pattern_RegexEmbedTo; //  Target Regex to embed value in

    private int csvpos;

    private UUID trackKey = null;
    private String regexTrackURLFrom = "";
    private Pattern pattern_regexTrackURLFrom = null;
    private String regexTrackValFrom = "";
    private Pattern pattern_regexTrackValFrom = null;
    private HttpSectionTypes httpSectionTypeTrackFrom;
    private int positionTrackFrom = -1; // Tracking trackParamName　position on page(start 0)
    private String paramNameTrackFrom; // Tracking Parameter name
    //
    // This parameter does not use when scanning. only temporarily use for GUI manipulation,
    // so it is not saved to file.
    private String resFetchedValue = null; // Token extracted from response during tracking process

    private TokenTypeNames tokenTypeTrackFrom = TokenTypeNames.INPUT;

    // conditional parameter tracking feature
    private int condTargetNo = -1; // conditinal tracking targetNo default: -1(any == wildcard "*")
    private String condRegex = ""; // conditional tracking regex. if requestNO == condTargetNo
    private Pattern Pattern_condRegex = null; // compiled pattern of condRegex
    // and it's request or response matched this regex then cache value  is updated.
    // if below value is true then condRegex matches request.
    private boolean condRegexTargetIsRequest = false;
    // if below value is true, request parameter replaced even if fetched tracking
    // value is zero size string.
    private boolean replaceZeroSize = false;
    private boolean isNoCount = false;

    public enum TokenTypeNames {
        DEFAULT,
        INPUT,
        LOCATION,
        HREF,
        XCSRF,
        TEXT,
        TEXTAREA,
        JSON,
        ACTION,
        META;

        public static TokenTypeNames parseString(String tkname) {
            if (tkname != null && !tkname.isEmpty()) {
                TokenTypeNames[] tktypearray = TokenTypeNames.values();
                for (TokenTypeNames tktype : tktypearray) {
                    if (tktype.name().equalsIgnoreCase(tkname)) {
                        return tktype;
                    }
                }
            }
            return TokenTypeNames.DEFAULT;
        }

        public static boolean isExist(String tkname) {
            if (tkname != null && !tkname.isEmpty()) {
                TokenTypeNames[] tktypearray = TokenTypeNames.values();
                for (TokenTypeNames tktype : tktypearray) {
                    if (tktype.name().equalsIgnoreCase(tkname)) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public String toString() {
            String value = super.toString();
            if (this == TokenTypeNames.DEFAULT) {
                value = "";
            }
            return value;
        }
    };

    private boolean urlEncoded; // Whether to  encode URL

    // below value is the position to extract the tracking parameter value
    private int fromStepNo = -1;

    // this is the position to embed the tracking parameter value
    // < 0: get tracking value from any response
    // >=0: get tracking value from specified request line number's response
    //  <0 : No Operation.
    //  >=0 and < TOSTEPANY: set tracking value to specified line number's request
    //  ==TOSTEPANY: set tracking value to any request.
    private int toStepNo = EnvironmentVariables.TOSTEPANY;

    public enum HttpSectionTypes {
        Default,
        Query,
        Body,
        Header,
        Path,
        // Track Value From Response
        Response, //  get tracking value with regex from whole response message
        ResponseBody, // get tracking value from parsed response body
        // Track Value From Request. ordinal() >= Request.ordinal()
        Request, // get tracking value with regex from whole request message
        RequestBody, // get tracking value from parsed request body
        RequestQuery, // get tracking value from parsed query params
        RequestPath; // get tracking value from parsed path params

        /**
         * parse HttpSectionTypes String. the param is Case-Insensitive.
         *
         * @param httpSectionTypeString
         * @return HttpSectionTypes
         */
        public static HttpSectionTypes parseString(String httpSectionTypeString) {
            if (httpSectionTypeString != null && !httpSectionTypeString.isEmpty()) {
                HttpSectionTypes[] tktypearray = HttpSectionTypes.values();
                for (HttpSectionTypes tktype : tktypearray) {
                    if (tktype.name().equalsIgnoreCase(httpSectionTypeString)) {
                        return tktype;
                    }
                }
            }
            return HttpSectionTypes.Default;
        }

        public static boolean isExist(String httpSectionTypeString) {
            if (httpSectionTypeString != null && !httpSectionTypeString.isEmpty()) {
                HttpSectionTypes[] tktypearray = HttpSectionTypes.values();
                for (HttpSectionTypes tktype : tktypearray) {
                    if (tktype.name().equalsIgnoreCase(httpSectionTypeString)) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public String toString() {
            String value = super.toString();
            if (this == HttpSectionTypes.Default) {
                value = "";
            }
            return value;
        }
    }

    private boolean enabled = true; // enable/disable flag

    private void initctype() {
        Pattern_condRegex = null;
        condTargetNo = -1;
        condRegex = null;
        trackKey = null;
        resFetchedValue = null;
        enabled = true;
        httpSectionTypeTrackFrom = HttpSectionTypes.Default;
        tokenTypeTrackFrom = TokenTypeNames.INPUT;
        replaceZeroSize = false;
    }

    public AppValue() {
        setRegexEmbedValTo(null);
        initctype();
        positionTrackFrom = -1;
    }

    AppValue(HttpSectionTypes httpSectionTypeEmbedTo, boolean _disabled, String regexEmbedTo) {
        initctype();
        setHttpSectionTypeEmbedoTo(httpSectionTypeEmbedTo);
        setEnabled(!_disabled); // NOT
        // value = _value;
        setRegexEmbedValTo(regexEmbedTo);
        positionTrackFrom = -1;
    }

    public AppValue(
            HttpSectionTypes _Type,
            boolean _disabled,
            int _csvpos,
            String regexEmbedTo,
            boolean increment) {
        initctype();
        setHttpSectionTypeEmbedoTo(_Type);
        setEnabled(!_disabled); // NOT
        csvpos = _csvpos;
        // value = _value;
        setRegexEmbedValTo(regexEmbedTo);
        positionTrackFrom = -1;
        if (increment) {
            clearNoCount();
        } else {
            setNoCount();
        }
    }

    public AppValue(
            HttpSectionTypes httpSectionTypeEmbedTo,
            boolean _disabled,
            String regexEmbedTo,
            boolean increment) {
        initctype();
        setHttpSectionTypeEmbedoTo(httpSectionTypeEmbedTo);
        setEnabled(!_disabled); // NOT
        // value = _value;
        setRegexEmbedValTo(regexEmbedTo);
        this.positionTrackFrom = -1;
        if (increment) {
            clearNoCount();
        } else {
            setNoCount();
        }
    }

    public AppValue(
            HttpSectionTypes part,
            boolean noOperation,
            String regexEmbedValTo,
            String regexTrackURLFrom,
            String regexTrackValFrom,
            HttpSectionTypes httpSectionTypeTrackFrom,
            String positionTrackFrom,
            String paramNameTrackFrom,
            boolean urlEncoded,
            int fromStepNo,
            int toStepNo,
            TokenTypeNames tokenTypeTrackFrom,
            String condRegex,
            int condTargetNo,
            boolean condRegexTargetIsRequest,
            boolean replaceZeroSize) {
        initctype();
        setHttpSectionTypeEmbedoTo(part);
        setEnabled(!noOperation); // NOT
        // value = _value;
        setRegexEmbedValTo(regexEmbedValTo);
        setRegexTrackURLFrom(regexTrackURLFrom);
        setRegexTrackValFrom(regexTrackValFrom);
        this.httpSectionTypeTrackFrom = httpSectionTypeTrackFrom;
        setPositionTrackFromString(positionTrackFrom);
        this.paramNameTrackFrom = paramNameTrackFrom;
        this.urlEncoded = urlEncoded;
        this.fromStepNo = fromStepNo;
        this.toStepNo = toStepNo;
        this.tokenTypeTrackFrom = tokenTypeTrackFrom;
        setCondRegex(condRegex);
        this.condTargetNo = condTargetNo;
        this.condRegexTargetIsRequest = condRegexTargetIsRequest;
        this.replaceZeroSize = replaceZeroSize;
    }

    /**
     * Get toStepNo: Line number of request to which setting tracking value in RequestList sequence.
     *
     * @return
     */
    public int getToStepNo() {
        return this.toStepNo;
    }

    /**
     * Set toStepNo: line number of request to which setting tracking value in RequestList sequence.
     *
     * @param toStepNo
     */
    public void setToStepNo(int toStepNo) {
        this.toStepNo = toStepNo;
    }

    /**
     * Get fromStepNo: Line number of response from which getting tracking parameter in RequestList
     * sequence
     *
     * @return
     */
    public int getFromStepNo() {
        return this.fromStepNo;
    }

    /**
     * Set fromStepNo: Line number of response from which getting tracking parameter in RequestList
     * sequence
     *
     * @param fromStepNo
     */
    public void setFromStepNo(int fromStepNo) {
        this.fromStepNo = fromStepNo;
    }

    /**
     * Whether to encode URL
     *
     * @return
     */
    public boolean isUrlEncode() {
        return this.urlEncoded;
    }

    /**
     * Set urlencode value
     *
     * @param urlEncoded
     */
    public void setUrlEncode(boolean urlEncoded) {
        this.urlEncoded = urlEncoded;
    }

    /** Get TokenType value */
    public TokenTypeNames getTokenTypeTrackFrom() {
        return this.tokenTypeTrackFrom;
    }

    /**
     * Set TokenType value
     *
     * @param tokentype
     */
    public void setTokenTypeTrackFrom(TokenTypeNames tokentype) {
        this.tokenTypeTrackFrom = tokentype;
    }

    /**
     * Get resFetchedValue This parameter does not use when scanning. only temporarily use for GUI
     * manipulation
     *
     * @param resFetchedValue
     */
    public void setResFetchedValue(String resFetchedValue) {
        this.resFetchedValue = resFetchedValue;
    }

    public String getResFetchedValue() {
        return this.resFetchedValue;
    }

    /**
     * Set token value
     *
     * @param paramNameTrackFrom
     */
    public void setParamNameTrackFrom(String paramNameTrackFrom) {
        this.paramNameTrackFrom = paramNameTrackFrom;
    }

    /**
     * Get token value
     *
     * @return
     */
    public String getParamNameTrackFrom() {
        return this.paramNameTrackFrom;
    }

    /**
     * Get csvpos value
     *
     * @return
     */
    public int getCsvpos() {
        return this.csvpos;
    }

    /**
     * Set csvpos value
     *
     * @param csvpos
     */
    public void setCsvpos(int csvpos) {
        this.csvpos = csvpos;
    }

    /**
     * Get the key. If the key has a null value, the key is created
     *
     * @return UUID
     */
    public synchronized UUID getTrackKey() {
        if (trackKey == null) {
            trackKey = UUIDGenerator.getUUID();
        }
        return trackKey;
    }

    public boolean isEnabled() {
        return enabled;
    }

    private void setEnabled(boolean b) {
        enabled = b;
    }

    public void setEnabledExported(boolean b) {
        setEnabled(b);
    }

    //
    //
    String QUOTE(String t) {
        if (t == null || t.isEmpty()) {
            return "";
        }
        return "\"" + t + "\"";
    }

    String QUOTE_PREFCOMMA(String t) {
        String q = QUOTE(t);
        if (q != null && !q.isEmpty()) {
            return "," + q;
        }
        return "";
    }

    private void setRegexTrackURLFrom(String _url) {
        if (_url == null) _url = "";
        regexTrackURLFrom = _url.trim();
        try {
            pattern_regexTrackURLFrom = ParmGenUtil.Pattern_compile(regexTrackURLFrom);
        } catch (Exception e) {
            pattern_regexTrackURLFrom = null;
            LOGGER4J.error("ERROR: setresURL ", e);
        }
    }

    public void setRegexTrackURLFromExported(String _url) {
        setRegexTrackURLFrom(_url);
    }

    public String getRegexTrackURLFrom() {
        return regexTrackURLFrom;
    }

    public Pattern getPattern_regexTrackURLFrom() {
        return pattern_regexTrackURLFrom;
    }

    public Pattern getPattern_regexTrackValFrom() {
        return pattern_regexTrackValFrom;
    }

    /**
     * get regex pattern for conditional parameter tracking
     *
     * @return
     */
    public Pattern getPattern_condRegex() {
        return Pattern_condRegex;
    }

    public String getRegexTrackValFrom() {
        return regexTrackValFrom;
    }

    public void setResRegexURLencoded(String _regex) {
        if (_regex == null) _regex = "";
        setRegexTrackValFrom(ParmGenUtil.URLdecode(_regex, JSONFileIANACharsetName));
    }

    private void setRegexTrackValFrom(String _regex) {
        if (_regex == null) _regex = "";
        regexTrackValFrom = _regex;
        try {
            pattern_regexTrackValFrom = ParmGenUtil.Pattern_compile(regexTrackValFrom);
        } catch (Exception e) {
            LOGGER4J.error("ERROR: setResRegex ", e);
            pattern_regexTrackValFrom = null;
        }
    }

    /**
     * set regex pattern for conditional parameter tracking
     *
     * @param _regex
     */
    private void setCondRegex(String _regex) {
        if (_regex == null) _regex = "";
        this.condRegex = _regex;
        try {
            this.Pattern_condRegex = ParmGenUtil.Pattern_compile(this.condRegex);
        } catch (Exception e) {
            LOGGER4J.error("ERROR: setcondRegex ", e);
            this.Pattern_condRegex = null;
        }
    }

    public String getCondRegex() {
        return condRegex;
    }

    public void setCondRegexURLencoded(String _regex) {
        if (_regex == null) _regex = "";
        setCondRegex(ParmGenUtil.URLdecode(_regex, JSONFileIANACharsetName));
    }

    /**
     * get conditinal target request No.
     *
     * @return
     */
    public int getCondTargetNo() {
        return condTargetNo;
    }

    /**
     * set conditinal target request No.
     *
     * @param nstr String - String of number representation. specialcase is "*" or "" => -1
     */
    public void setCondTargetNo(String nstr) {
        if (nstr == null || nstr.isEmpty() || nstr.equals("*")) {
            condTargetNo = -1;
        } else {
            try {
                condTargetNo = Integer.parseInt(nstr);
            } catch (Exception e) {
                condTargetNo = -1;
            }
        }
    }

    public void setCondTargetNo(int no) {
        condTargetNo = no;
    }

    /** condition parameter tracking is exist */
    public boolean hasCond() {
        return Pattern_condRegex != null && condTargetNo != -1;
    }

    /**
     * Whether the conditional regular expression applies to requests or responses
     *
     * @return true - applies to request.
     */
    public boolean requestIsCondRegexTarget() {
        return condRegexTargetIsRequest;
    }

    /**
     * set conditional reqular expression target which is request or not.
     *
     * @param b
     */
    public void setRequestIsCondTegexTarget(boolean b) {
        condRegexTargetIsRequest = b;
    }

    /**
     * get replaceZeroSize boolean. if this value true, then request parameter replace even if
     * tracking value is zero size string.
     *
     * @return
     */
    public boolean isReplaceZeroSize() {
        return this.replaceZeroSize;
    }

    /**
     * set replaceZeroSize boolean. if this value true, then request parameter replace even if
     * tracking value is zero size string.
     *
     * @param b
     */
    public void setReplaceZeroSize(boolean b) {
        this.replaceZeroSize = b;
    }

    public void setHttpSectionTypeTrackFrom(HttpSectionTypes httpSectionType) {
        httpSectionTypeTrackFrom = httpSectionType;
    }

    public void setHttpSectionTypeTrackFromExported(String httpSectionTypeString) {
        if (HttpSectionTypes.isExist(httpSectionTypeString)) {
            setHttpSectionTypeTrackFrom(HttpSectionTypes.parseString((httpSectionTypeString)));
        }
        setHttpSectionTypeTrackFrom(HttpSectionTypes.Default);
    }

    /**
     * Get resRegexPos value
     *
     * @return
     */
    public int getPositionTrackFrom() {
        return this.positionTrackFrom;
    }

    /**
     * Set resRegexPos value
     *
     * @param positionTrackFrom
     */
    public void setPositionTrackFrom(int positionTrackFrom) {
        this.positionTrackFrom = positionTrackFrom;
    }

    /**
     * Set String number to resRegexPos
     *
     * @param _resregexpos
     */
    private void setPositionTrackFromString(String _resregexpos) {
        this.positionTrackFrom = Integer.parseInt(_resregexpos);
    }

    public HttpSectionTypes getHttpSectionTypeTrackFrom() {
        return httpSectionTypeTrackFrom;
    }

    public String getAppValueDsp(int _typeval) {
        String avrec =
                QUOTE(
                                getHttpSectionTypeEmbedTo().toString()
                                        + (isEnabled() ? "" : "+")
                                        + (isNoCount() ? "" : "+")
                                        + (_typeval == AppParmsIni.T_CSV
                                                ? ":" + Integer.toString(csvpos)
                                                : ""))
                        + ","
                        + QUOTE(regexEmbedTo)
                        + QUOTE_PREFCOMMA(regexTrackURLFrom)
                        + QUOTE_PREFCOMMA(regexTrackValFrom)
                        + QUOTE_PREFCOMMA(httpSectionTypeTrackFrom.toString())
                        + (positionTrackFrom != -1
                                ? QUOTE_PREFCOMMA(Integer.toString(positionTrackFrom))
                                : "")
                        + QUOTE_PREFCOMMA(paramNameTrackFrom)
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(urlEncoded == true ? "true" : "false")
                                : "")
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(Integer.toString(fromStepNo))
                                : "")
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(Integer.toString(toStepNo))
                                : "")
                        + QUOTE_PREFCOMMA(tokenTypeTrackFrom.toString());

        return avrec;
    }

    HttpSectionTypes getHttpSectionTypeEmbedTo() {
        return this.httpSectionTypeEmbedTo;
    }

    public void setTokenTypeName(String tknames) {
        tokenTypeTrackFrom = TokenTypeNames.parseString(tknames);
    }

    public boolean setHttpSectionTypeEmbedToExported(String httpSectionTypeString) {
        boolean isExist = HttpSectionTypes.isExist(httpSectionTypeString);
        HttpSectionTypes type = HttpSectionTypes.Default;
        if (isExist) {
            type = HttpSectionTypes.parseString(httpSectionTypeString);
        }
        setHttpSectionTypeEmbedoTo(type);
        return isExist;
    }

    private void setHttpSectionTypeEmbedoTo(HttpSectionTypes httpSectionTypeEmbedTo) {
        this.httpSectionTypeEmbedTo = httpSectionTypeEmbedTo;
    }

    private void setNoCount() {
        this.isNoCount = true;
    }

    public void setNoCountExported() {
        setNoCount();
    }

    private void clearNoCount() {
        this.isNoCount = false;
    }

    public void clearNoCountExported() {
        clearNoCount();
    }

    public boolean isNoCount() {
        return this.isNoCount;
    }

    public boolean setURLencodedVal(String _value) {
        boolean noerror = false;
        pattern_RegexEmbedTo = null;
        try {
            regexEmbedTo = URLDecoder.decode(_value, JSONFileIANACharsetName);
            pattern_RegexEmbedTo = ParmGenUtil.Pattern_compile(regexEmbedTo);
            noerror = true;
        } catch (UnsupportedEncodingException e) {
            LOGGER4J.error("decode failed value:[" + _value + "]", e);
            pattern_RegexEmbedTo = null;
        }

        return noerror;
    }

    private void setRegexEmbedValTo(String _value) {
        pattern_RegexEmbedTo = null;
        regexEmbedTo = _value;
        if (regexEmbedTo != null) {
            pattern_RegexEmbedTo = ParmGenUtil.Pattern_compile(regexEmbedTo);
        }
    }

    String getRegexEmbedValTo() {
        return regexEmbedTo;
    }

    public String[] replacePathContents(
            ParmGenMacroTrace pmt,
            AppParmsIni pini,
            String contents,
            String org_contents_iso8859,
            ParmGenHashMap errorhash) {
        return replaceContents(pmt, pini, contents, org_contents_iso8859, errorhash, 1);
    }

    public String[] replaceContents(
            ParmGenMacroTrace pmt,
            AppParmsIni pini,
            String contents,
            String org_contents_iso8859,
            ParmGenHashMap errorhash) {
        return replaceContents(pmt, pini, contents, org_contents_iso8859, errorhash, -1);
    }

    /**
     * replace target contents with value of org_contents_iso8859
     *
     * @param pmt
     * @param pini
     * @param contents replace target
     * @param org_contents_iso8859 the value of replacing
     * @param errorhash buffer for collecting results or errors.
     * @param foundCount matcher.find counter.<br>
     *     >0: replace until reaching this value.<br>
     *     ==-1 : replace All.
     * @return
     */
    private String[] replaceContents(
            ParmGenMacroTrace pmt,
            AppParmsIni pini,
            String contents,
            String org_contents_iso8859,
            ParmGenHashMap errorhash,
            int foundCount) {
        if (contents == null) return null;
        if (pattern_RegexEmbedTo == null) return null;

        int currentStepNo = pmt.getStepNo();
        ParmGenTokenKey tk = null;
        if (toStepNo >= 0) {
            if (toStepNo != EnvironmentVariables.TOSTEPANY) {
                if (currentStepNo != toStepNo) {
                    return null; //
                }
                // tokentype is the type for tracking value source,
                // it is no relation to toStepNo.
                // toStepNo is a sequence number in the RequestResponse List
                // It is the target request number to embed value.
                new ParmGenTokenKey(
                        TokenTypeNames.DEFAULT,
                        paramNameTrackFrom,
                        currentStepNo); // token: tracking param name, currentStepNo: target
                // request StepNo
            } else {
                // ParmVars.plog.debuglog(0, "replaceContents toStepNo==TOSTEPANY " + toStepNo + "
                // ==" + ParmVars.TOSTEPANY);
            }
        } else {
            // ParmVars.plog.debuglog(0, "replaceContents toStepNo<0 " + toStepNo + "<0 TOSTEPANY="
            // + ParmVars.TOSTEPANY);
        }

        String[] nv = new String[2];

        String errKeyName =
                "TypeVal:"
                        + Integer.toString(pini.getTypeVal())
                        + " TargetPart:"
                        + getHttpSectionTypeEmbedTo()
                        + " TargetRegex:"
                        + regexEmbedTo
                        + " ResRegex:"
                        + regexTrackValFrom
                        + " TokenName:"
                        + paramNameTrackFrom;
        ParmGenTokenKey errorhash_key = new ParmGenTokenKey(TokenTypeNames.DEFAULT, errKeyName, 0);
        Matcher m = pattern_RegexEmbedTo.matcher(contents); // embed target match
        Matcher m_org = null;
        if (org_contents_iso8859 != null) {
            m_org = pattern_RegexEmbedTo.matcher(org_contents_iso8859);
        }

        String newcontents = "";
        String tailcontents = "";
        String o_newcontents = "";
        String o_tailcontents = "";
        String strcnt = null;
        int cpt = 0;
        int o_cpt = 0;

        while (m.find()) {
            int spt = -1;
            int ept = -1;
            int o_spt = -1;
            int o_ept = -1;
            int gcnt = m.groupCount();
            String matchval = null;
            for (int n = 0; n < gcnt; n++) {
                spt = m.start(n + 1);
                ept = m.end(n + 1);
                matchval = m.group(n + 1);
            }
            String org_matchval = null;
            if (m_org != null) {
                if (m_org.find()) {
                    int org_gcnt = m_org.groupCount();
                    for (int n = 0; n < org_gcnt; n++) {
                        o_spt = m_org.start(n + 1);
                        o_ept = m_org.end(n + 1);
                        org_matchval = m_org.group(n + 1);
                    }
                }
            }
            if (spt != -1 && ept != -1) {
                strcnt = pini.getStrCnt(pmt, this, tk, currentStepNo, toStepNo, csvpos);
                boolean isnull = false;
                ParmGenTokenValue errorhash_value = null;
                String org_newval = strcnt;
                if (org_matchval != null) {
                    ParmGenStringDiffer differ = new ParmGenStringDiffer(org_matchval, matchval);
                    LOGGER4J.debug("org_matchval[" + org_matchval + "] matchval[" + matchval + "]");
                    strcnt = differ.replaceOrgMatchedValue(strcnt);
                }
                if (strcnt != null
                        && (!strcnt.isEmpty() || strcnt.isEmpty() && this.isReplaceZeroSize())) {
                    LOGGER4J.info(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_msg1.text"),
                                    new Object[] {
                                        pmt.getStepNo(),
                                        paramNameTrackFrom,
                                        matchval,
                                        strcnt,
                                        regexEmbedTo
                                    }));
                    //
                    pmt.addComments(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_msg2.text"),
                                    new Object[] {
                                        pmt.getStepNo(),
                                        paramNameTrackFrom,
                                        matchval,
                                        strcnt,
                                        regexEmbedTo
                                    }));
                    errorhash_value = new ParmGenTokenValue("", strcnt, true);
                    errorhash.put(errorhash_key, errorhash_value);
                } else {
                    LOGGER4J.warn(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_err1.text"),
                                    new Object[] {
                                        pmt.getStepNo(), paramNameTrackFrom, matchval, regexEmbedTo
                                    }));
                    pmt.addComments(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_err2.text"),
                                    new Object[] {
                                        pmt.getStepNo(), paramNameTrackFrom, matchval, regexEmbedTo
                                    }));
                    isnull = true;
                    errorhash_value = new ParmGenTokenValue("", strcnt, false);
                    ParmGenTokenValue storederror = errorhash.get(errorhash_key);
                    if (storederror == null || storederror.getBoolean() == false) {
                        errorhash.put(errorhash_key, errorhash_value);
                    }
                }
                if (isnull) { // if
                    strcnt = matchval;
                    org_newval = org_matchval;
                }
                newcontents += contents.substring(cpt, spt) + strcnt;
                cpt = ept;
                tailcontents = contents.substring(ept);
                if (org_matchval != null) {
                    o_newcontents += org_contents_iso8859.substring(o_cpt, o_spt) + org_newval;
                    o_cpt = o_ept;
                    o_tailcontents = org_contents_iso8859.substring(o_ept);
                }
            }
            if (foundCount > 0) {
                if (--foundCount <= 0) {
                    break;
                }
            }
        }
        newcontents = newcontents + tailcontents;
        if (newcontents.length() == 0) {
            newcontents = contents;
        }
        o_newcontents = o_newcontents + o_tailcontents;
        if (o_newcontents.length() == 0) {
            o_newcontents = org_contents_iso8859;
        }
        nv[0] = newcontents;
        nv[1] = o_newcontents;
        return nv;
    }

    /**
     * whether this object same as argument specified or not
     *
     * @param app
     * @return
     */
    public boolean isSameContents(AppValue app) {
        if (this.httpSectionTypeEmbedTo == app.httpSectionTypeEmbedTo
                && ParmGenUtil.nullableStringEquals(this.regexEmbedTo, app.regexEmbedTo)
                && this.csvpos == app.csvpos
                && ParmGenUtil.nullableStringEquals(this.regexTrackURLFrom, app.regexTrackURLFrom)
                && ParmGenUtil.nullableStringEquals(this.regexTrackValFrom, app.regexTrackValFrom)
                && this.httpSectionTypeTrackFrom == app.httpSectionTypeTrackFrom
                && this.positionTrackFrom == app.positionTrackFrom
                && ParmGenUtil.nullableStringEquals(this.paramNameTrackFrom, app.paramNameTrackFrom)
                && this.tokenTypeTrackFrom == app.tokenTypeTrackFrom
                && this.urlEncoded == app.urlEncoded
                && this.fromStepNo == app.fromStepNo
                && this.toStepNo == app.toStepNo
                && ParmGenUtil.nullableStringEquals(this.condRegex, app.condRegex)
                && this.condTargetNo == app.condTargetNo
                && this.condRegexTargetIsRequest == app.condRegexTargetIsRequest
                && this.isNoCount == app.isNoCount) {
            return true;
        }
        return false;
    }
}
