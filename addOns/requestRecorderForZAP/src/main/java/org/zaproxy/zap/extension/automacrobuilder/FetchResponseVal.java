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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;

// <?xml version="1.0" encoding="utf-8"?>
// <AuthUpload>
//	<codeResult>0</codeResult>
//	<password>eUnknfj73OFBrMenCfFh</password>
// </AuthUpload>

//
// class variable
//
// FetchResponse
//

class FetchResponseVal implements DeepClone {
    //

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    // ====================== copy per thread members begin ===============
    // Key: String token  int toStepNo Val: distance = responseStepNo - currentStepNo
    private Map<ParmGenTokenKey, Integer> distances;

    private ParmGenTrackKeyPerThread trackkeys;

    // ====================== copy per thread members end =================

    //
    FetchResponseVal() {
        init();
    }

    /**
     * this function<br>
     * for internal use<br>
     */
    private void init() {

        // pattern = "<AuthUpload>(?:.|\r|\n|\t)*?<password>([a-zA-Z0-9]+)</password>";
        allocLocVal();

        initLocVal();
    }

    private String strrowcol(int r, int c) {
        return Integer.toString(r) + "," + Integer.toString(c);
    }

    private void allocLocVal() {
        trackkeys = new ParmGenTrackKeyPerThread();
        distances = new HashMap<ParmGenTokenKey, Integer>();
    }

    private void initLocVal() {
        clearCachedLocVal();
        if (distances != null) {
            distances.clear();
        }
    }

    public void clearCachedLocVal() {
        if (trackkeys != null) trackkeys.clear();
    }

    public boolean isCachedLocValCleared() {
        if (trackkeys != null) return trackkeys.isCleared();
        return true;
    }

    public void clearDistances() {
        if (distances != null) {
            distances.clear();
        }
    }

    // this function affects AppParmsIni.T_TRACK only..
    /**
     * get response's tracking token from TrackJarFactory
     *
     * @param k (unique key) int
     * @param tk ParmGenTokenKey
     * @param currentStepNo int
     * @param toStepNo int
     * @return token value String
     */
    String getLocVal(UUID k, ParmGenTokenKey tk, int currentStepNo, int toStepNo, AppValue ap) {
        String rval = null;
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {

            // String v = locarray[r][c];
            // int responseStepNo = responseStepNos[r][c];

            String v = tkparam.getValue(ap);
            int responseStepNo = tkparam.getResponseStepNo();

            if (toStepNo >= 0) {
                if (currentStepNo == toStepNo) {
                    rval = v;
                } else if (toStepNo == EnvironmentVariables.TOSTEPANY) {
                    rval = v;
                }
            }

            if (rval == null) {
                // ParmVars.plog.debuglog(0, "????????????getLocVal rval==null toStepNo:" + toStepNo
                // + "currentStepNo=" + currentStepNo );
            }

            if (tk != null && distances != null) {
                if (rval != null) {
                    int newdistance = currentStepNo - responseStepNo; // from to distance
                    Integer intobj = distances.get(tk);

                    if (intobj != null) {
                        int prevdistance = intobj.intValue();
                        if (prevdistance >= 0) {
                            if (prevdistance < newdistance) {
                                rval = null;
                            }
                        }
                    }
                    if (rval != null) {
                        distances.put(tk, Integer.valueOf(newdistance));
                    }
                }
            }
        }
        if (rval == null) {
            // ParmVars.plog.debuglog(0, "?!???!??????getLocVal rval==null toStepNo:" + toStepNo +
            // "currentStepNo=" + currentStepNo );
        }
        return rval;
    }

    private int getStepNo(UUID k) {
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {
            // return responseStepNos[r][c];
            return tkparam.getResponseStepNo();
        }
        return -1;
    }

    /** set response's tracking token to TrackJarFactory */
    private UUID setLocVal(
            int currentStepNo, int fromStepNo, String val, boolean overwrite, AppValue av) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam == null) { // if tkparam has No exist, then create tkparam with new unique key
            // key
            tkparam = trackkeys.create(k);
        }

        String cachedval = tkparam.getValue(null);
        if (val != null && (!val.isEmpty() || val.isEmpty() && av.isReplaceZeroSize())) {
            if (cachedval == null) {
                tkparam.setValue(val);
            } else if (overwrite == true) {
                tkparam.setValue(val);
            }
        }

        if (fromStepNo < 0
                || currentStepNo == fromStepNo) { // if fromStepNo <0 : token value from any
            // or
            // currentStepNo == fromStepNo : token value from fromStepNo
            // then set ResponseStepNo
            // setStepNo(currentStepNo, r, c);
            tkparam.setResponseStepNo(currentStepNo);
        }

        trackkeys.put(k, tkparam);

        return k;
    }

    /**
     * update conditional parameter is valid or not
     *
     * @param av
     * @param b
     */
    void updateCond(AppValue av, boolean b) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam == null) { // if tkparam has No exist, then create tkparam with new unique key
            // key
            tkparam = trackkeys.create(k);
        }
        tkparam.setCondValid(b);
        if (!b) {
            tkparam.rollBackValue();
        } else {
            tkparam.overWriteOldValue();
        }
    }

    boolean getCondValid(AppValue av) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {
            return tkparam.getCondValid();
        }
        return false;
    }

    void printlog(String v) {
        LOGGER4J.info(v);
    }

    /**
     * extract tracking source parameters from the header of the response
     *
     * @param pmt
     * @param url
     * @param presponse
     * @param r
     * @param c
     * @param overwrite
     * @param av
     * @return
     */
    boolean responseHeaderMatch(
            ParmGenMacroTrace pmt,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            AppValue av) {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        String name = av.getParamNameTrackFrom();
        AppValue.TokenTypeNames _tokentype = av.getTokenTypeTrackFrom();
        String comments = "";
        if (urlmatch(av, url)) {
            if (_tokentype == AppValue.TokenTypeNames.LOCATION) {
                ParmGenToken tkn = presponse.fetchNameValue(name, _tokentype, 0);
                if (tkn != null) {
                    ParmGenTokenValue tval = tkn.getTokenValue();
                    if (tval != null) { // value値nullは追跡しない
                        String extractedMatchVal = tval.getValue();
                        if (extractedMatchVal
                                != null) { // matchval !=null or matchval.isEmpty() is acceptable.
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + " => "
                                                + extractedMatchVal;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getHeaderSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), "Location", extractedMatchVal
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(currentStepNo, fromStepNo, extractedMatchVal, overwrite, av);
                            return true;
                        }
                    } else {
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                            + r
                                            + ","
                                            + c
                                            + " => null";

                        } else {
                            comments =
                                    java.text.MessageFormat.format(
                                            bundle.getString(
                                                    "FetchResponseVal.getHeaderFailed.text"),
                                            new Object[] {pmt.getStepNo(), "Location"});
                        }
                        printlog(comments);
                        pmt.addComments(comments);
                    }
                }
            }
            if (av.getPattern_regexTrackValFrom() != null) {
                //
                int size = presponse.getHeadersCnt();
                for (int i = 0; i < size; i++) {
                    // String nvName = (nv[i]).getName();
                    // String nvValue = (nv[i]).getValue();
                    // String hval = nvName + ": " + nvValue;
                    String hval = presponse.getHeaderLine(i);
                    Matcher matcher = null;
                    try {
                        matcher = av.getPattern_regexTrackValFrom().matcher(hval);
                    } catch (Exception e) {
                        printlog("Exception matcher：" + e.toString());
                    }
                    if (matcher.find()) {
                        int gcnt = matcher.groupCount();
                        String regexExtractedMatchVal = null;
                        for (int n = 0; n < gcnt; n++) {
                            regexExtractedMatchVal = matcher.group(n + 1);
                        }

                        if (regexExtractedMatchVal != null) { // regexExtractedMatchVal != null or
                            // regexExtractedMatchVal.isEmpty() is acceptable.
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => "
                                                + regexExtractedMatchVal;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getHeaderSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), hval, regexExtractedMatchVal
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(
                                    currentStepNo,
                                    fromStepNo,
                                    regexExtractedMatchVal,
                                    overwrite,
                                    av);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => null";

                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getHeaderFailed.text"),
                                                new Object[] {pmt.getStepNo(), hval});
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * extract tracking source parameters from the response
     *
     * @param pmt
     * @param url
     * @param presponse
     * @param r
     * @param c
     * @param overwrite
     * @param av
     * @return
     * @throws UnsupportedEncodingException
     */
    boolean responseBodyMatch(
            ParmGenMacroTrace pmt,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            AppValue av)
            throws UnsupportedEncodingException {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        int fcnt = av.getPositionTrackFrom();
        String name = av.getParamNameTrackFrom();
        boolean _uencode = av.isUrlEncode();
        AppValue.TokenTypeNames tokenTypeTrackFrom = av.getTokenTypeTrackFrom();
        if (urlmatch(av, url)) {

            Matcher matcher = null;

            if (av.getHttpSectionTypeTrackFrom() == AppValue.HttpSectionTypes.ResponseBody) {
                ParmGenToken tkn = presponse.fetchNameValue(name, tokenTypeTrackFrom, fcnt);
                if (tkn != null) {
                    ParmGenTokenValue tval = tkn.getTokenValue();
                    if (tval != null) {
                        String v = tval.getValue();
                        if (v != null) { // this variable != null or isEmpty() is acceptable.
                            if (_uencode == true && !ParmGenUtil.isURLencoded(v)) {
                                String venc = v;
                                try {
                                    venc =
                                            URLEncoder.encode(
                                                    v, presponse.getPageEnc().getIANACharsetName());
                                } catch (UnsupportedEncodingException e) {
                                    // NOP
                                }
                                v = venc.replaceAll(",", "%2C");
                            }
                            String extractedMatchedValue = v;

                            setLocVal(
                                    currentStepNo,
                                    fromStepNo,
                                    extractedMatchedValue,
                                    overwrite,
                                    av);
                            String comments = "";
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE auto track body key/r,c,p:"
                                                + av.getTrackKey()
                                                + "/"
                                                + r
                                                + ","
                                                + c
                                                + ","
                                                + fcnt
                                                + ": "
                                                + name
                                                + "="
                                                + v;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, v, "Response"
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            return true;
                        } else {
                            String comments = "";
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxx FAILED FETCHRESPONSE auto track body r,c,p:"
                                                + r
                                                + ","
                                                + c
                                                + ","
                                                + fcnt
                                                + ": "
                                                + name
                                                + "="
                                                + "null";

                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenFailed.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, "is null", "Response"
                                                });
                            }
                            LOGGER4J.warn(comments);
                            pmt.addComments(comments);
                        }
                    }
                } else {
                    String comments = "";
                    if (LOGGER4J.isDebugEnabled()) {
                        comments =
                                "xxxxx FAILED FETCHRESPONSE auto track body r,c,p:"
                                        + r
                                        + ","
                                        + c
                                        + ","
                                        + fcnt
                                        + ": "
                                        + name
                                        + "="
                                        + "null";

                    } else {
                        comments =
                                java.text.MessageFormat.format(
                                        bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                        new Object[] {
                                            pmt.getStepNo(), name, "not found", "Response"
                                        });
                    }
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                }
            }
            if (av.getPattern_regexTrackValFrom() != null
                    && av.getRegexTrackValFrom() != null
                    && !av.getRegexTrackValFrom().isEmpty()) { // extracted by regex
                String message = presponse.getMessage();

                try {
                    matcher = av.getPattern_regexTrackValFrom().matcher(message);
                } catch (Exception e) {
                    String comments =
                            "xxxxx EXCEPTION FETCHRESPONSE r,c:"
                                    + r
                                    + ","
                                    + c
                                    + ": "
                                    + name
                                    + " regex["
                                    + av.getRegexTrackValFrom()
                                    + "] exception："
                                    + e.toString();
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                    matcher = null;
                }

                if (matcher != null && matcher.find()) {
                    int gcnt = matcher.groupCount();
                    String matchval = null;
                    for (int n = 0; n < gcnt; n++) {
                        matchval = matcher.group(n + 1);
                    }

                    if (matchval != null) {
                        switch (tokenTypeTrackFrom) {
                            case JSON:
                                ParmGenGSONDecoder jdec = new ParmGenGSONDecoder(null);
                                matchval = jdec.decodeStringValue(matchval);
                                break;
                            default:
                                break;
                        }
                        if (_uencode == true && !ParmGenUtil.isURLencoded(matchval)) {
                            String venc = matchval;
                            try {
                                venc =
                                        URLEncoder.encode(
                                                matchval,
                                                presponse.getPageEnc().getIANACharsetName());
                            } catch (UnsupportedEncodingException e) {
                                // NOP
                            }
                            matchval = venc.replaceAll(",", "%2C");
                        }
                        String regexExtractedMatchedValue = matchval;
                        String comments = "";

                        if (regexExtractedMatchedValue
                                != null) { // this variable !=null or isEmpty() is acceptable.

                            setLocVal(
                                    currentStepNo,
                                    fromStepNo,
                                    regexExtractedMatchedValue,
                                    overwrite,
                                    av);
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE body key/r,c:"
                                                + av.getTrackKey()
                                                + "/"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + regexExtractedMatchedValue;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, matchval, "Response"
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + "null";

                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenFailed.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, "is null", "Response"
                                                });
                            }
                            LOGGER4J.warn(comments);
                            pmt.addComments(comments);
                        }
                    } else {
                        String comments = "";
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + name
                                            + "="
                                            + "null";

                        } else {
                            comments =
                                    java.text.MessageFormat.format(
                                            bundle.getString(
                                                    "FetchResponseVal.getTokenFailed.text"),
                                            new Object[] {
                                                pmt.getStepNo(), name, "is null", "Response"
                                            });
                        }
                        LOGGER4J.warn(comments);
                        pmt.addComments(comments);
                    }
                } else {
                    String comments = "";
                    if (LOGGER4J.isDebugEnabled()) {
                        comments =
                                "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                        + r
                                        + ","
                                        + c
                                        + ": "
                                        + name
                                        + "="
                                        + "null";

                    } else {
                        comments =
                                java.text.MessageFormat.format(
                                        bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                        new Object[] {
                                            pmt.getStepNo(),
                                            name,
                                            "No matched regex[" + av.getRegexTrackValFrom() + "]",
                                            "Response"
                                        });
                    }
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                }
            } else { // extract parameter from parse response

            }
        }
        return false;
    }

    /**
     * extract tracking source parameters from the request
     *
     * @param pmt
     * @param av
     * @param url
     * @param pRequest
     * @param r
     * @param c
     * @param overwrite
     * @return
     */
    boolean requestBodyMatch(
            ParmGenMacroTrace pmt,
            AppValue av,
            String url,
            PRequest pRequest,
            int r,
            int c,
            boolean overwrite) {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        int fcnt = av.getPositionTrackFrom();
        String name = av.getParamNameTrackFrom();
        boolean isUrlEncoded = av.isUrlEncode();
        String comments = "";
        if (urlmatch(av, url)) {
            Matcher matcher = null;
            if (av.getHttpSectionTypeTrackFrom() == AppValue.HttpSectionTypes.RequestBody
                    && name != null
                    && !name.isEmpty()) {
                if (av.getTokenTypeTrackFrom() != AppValue.TokenTypeNames.JSON) {
                    List<String[]> namelist = pRequest.getBodyParamsFromRequest();
                    Iterator<String[]> it = namelist.iterator();
                    Map<String, Integer> sameNameHash = new HashMap<String, Integer>();
                    while (it.hasNext()) {
                        String[] nv = it.next();
                        int npos = 0;
                        String nvName = nv[0];
                        if (sameNameHash.containsKey(nvName)) {
                            npos = sameNameHash.get(nvName);
                            npos++;
                        }
                        sameNameHash.put(nvName, npos);
                        if (name.equals(nv[0]) && npos == fcnt) {
                            if (nv.length > 1 && nv[1] != null) {
                                String valueString = nv[1];
                                // this variable is != null or isEmpty() is
                                // acceptable
                                // if target parameter is not URLencoded and extracted the value is
                                // encoded
                                // then it should decode the value.
                                if (!isUrlEncoded && ParmGenUtil.isURLencoded(valueString)) {
                                    String decodedString =
                                            ParmGenUtil.URLdecode(
                                                    valueString,
                                                    pRequest.getPageEnc().getIANACharsetName());
                                    if (!decodedString.isEmpty()) {
                                        valueString = decodedString;
                                    }
                                }
                                if (LOGGER4J.isDebugEnabled()) {
                                    comments =
                                            "******FETCH REQUEST body r,c: name=value:"
                                                    + r
                                                    + ","
                                                    + c
                                                    + ": "
                                                    + nv[0]
                                                    + "="
                                                    + valueString;
                                } else {
                                    comments =
                                            java.text.MessageFormat.format(
                                                    bundle.getString(
                                                            "FetchResponseVal.getTokenSucceeded.text"),
                                                    new Object[] {
                                                        pmt.getStepNo(),
                                                        nv[0],
                                                        valueString,
                                                        "Request"
                                                    });
                                }
                                printlog(comments);
                                pmt.addComments(comments);
                                setLocVal(currentStepNo, fromStepNo, valueString, overwrite, av);
                                return true;
                            } else {
                                if (LOGGER4J.isDebugEnabled()) {
                                    comments =
                                            "xxxxxFAILED FETCH REQUEST body r,c: name=value:"
                                                    + r
                                                    + ","
                                                    + c
                                                    + ": "
                                                    + nv[0]
                                                    + "=null";

                                } else {
                                    comments =
                                            java.text.MessageFormat.format(
                                                    bundle.getString(
                                                            "FetchResponseVal.getTokenFailed.text"),
                                                    new Object[] {
                                                        pmt.getStepNo(), nv[0], "Request"
                                                    });
                                }
                                LOGGER4J.warn(comments);
                                pmt.addComments(comments);
                            }
                        }
                    }
                } else { // token is JSON
                    ParmGenToken extractedToken = pRequest.getJSONParam(name, fcnt);
                    if (extractedToken != null) {
                        String value = extractedToken.getTokenValue().getValue();
                        if (value != null) { // the empty value is available.
                            // acceptable
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "******FETCH REQUEST body r,c: name=value:"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + value;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, value, "Request"
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(currentStepNo, fromStepNo, value, overwrite, av);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxFAILED FETCH REQUEST body r,c: name=value:"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "=null";

                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenFailed.text"),
                                                new Object[] {pmt.getStepNo(), name, "Request"});
                            }
                            LOGGER4J.warn(comments);
                            pmt.addComments(comments);
                        }
                    }
                }
            }
            if (av.getPattern_regexTrackValFrom() != null
                    && av.getRegexTrackValFrom() != null
                    && !av.getRegexTrackValFrom().isEmpty()) { // extracted by regex
                String message = pRequest.getMessage();

                try {
                    matcher = av.getPattern_regexTrackValFrom().matcher(message);
                } catch (Exception e) {
                    comments =
                            "xxxxx EXCEPTION FETCHREQUEST r,c:"
                                    + r
                                    + ","
                                    + c
                                    + ": "
                                    + name
                                    + " regex["
                                    + av.getRegexTrackValFrom()
                                    + "] exception："
                                    + e.toString();
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                    matcher = null;
                }

                if (matcher != null && matcher.find()) {
                    int gcnt = matcher.groupCount();
                    String matchval = null;
                    for (int n = 0; n < gcnt; n++) {
                        matchval = matcher.group(n + 1);
                    }

                    if (matchval != null) {
                        switch (av.getTokenTypeTrackFrom()) {
                            case JSON:
                                ParmGenGSONDecoder jdec = new ParmGenGSONDecoder(null);
                                matchval = jdec.decodeStringValue(matchval);
                                break;
                            default:
                                break;
                        }
                        if (isUrlEncoded == true && !ParmGenUtil.isURLencoded(matchval)) {
                            String venc = matchval;
                            try {
                                venc =
                                        URLEncoder.encode(
                                                matchval,
                                                pRequest.getPageEnc().getIANACharsetName());
                            } catch (UnsupportedEncodingException e) {
                                // NOP
                            }
                            matchval = venc.replaceAll(",", "%2C");
                        }
                        String regexExtractedMatchedValue = matchval;

                        if (regexExtractedMatchedValue
                                != null) { // this variable !=null or isEmpty() is acceptable.

                            setLocVal(
                                    currentStepNo,
                                    fromStepNo,
                                    regexExtractedMatchedValue,
                                    overwrite,
                                    av);
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHREQUEST body key/r,c:"
                                                + av.getTrackKey()
                                                + "/"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + regexExtractedMatchedValue;
                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenSucceeded.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, matchval, "Request"
                                                });
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxx FAILED FETCHREQUEST body r,c:"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + "null";

                            } else {
                                comments =
                                        java.text.MessageFormat.format(
                                                bundle.getString(
                                                        "FetchResponseVal.getTokenFailed.text"),
                                                new Object[] {
                                                    pmt.getStepNo(), name, "is null", "Request"
                                                });
                            }
                            LOGGER4J.warn(comments);
                            pmt.addComments(comments);
                        }
                    } else {
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxx FAILED FETCHREQUEST body r,c:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + name
                                            + "="
                                            + "null";

                        } else {
                            comments =
                                    java.text.MessageFormat.format(
                                            bundle.getString(
                                                    "FetchResponseVal.getTokenFailed.text"),
                                            new Object[] {
                                                pmt.getStepNo(), name, "is null", "Request"
                                            });
                        }
                        LOGGER4J.warn(comments);
                        pmt.addComments(comments);
                    }
                } else {
                    if (LOGGER4J.isDebugEnabled()) {
                        comments =
                                "xxxxxx FAILED FETCHREQUEST body r,c:"
                                        + r
                                        + ","
                                        + c
                                        + ": "
                                        + name
                                        + "="
                                        + "null";

                    } else {
                        comments =
                                java.text.MessageFormat.format(
                                        bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                        new Object[] {
                                            pmt.getStepNo(),
                                            name,
                                            "No matched regex[" + av.getRegexTrackValFrom() + "]",
                                            "Request"
                                        });
                    }
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                }
            }
        }
        return false;
    }

    //
    // URL match
    //
    boolean urlmatch(AppValue av, String url) {

        try {
            if (av.getPattern_regexTrackURLFrom() != null) {
                Matcher matcher = av.getPattern_regexTrackURLFrom().matcher(url);
                if (matcher.find()) {
                    // printlog("*****FETCHRESPONSE URL match:" + url);
                    LOGGER4J.debug(" FETCH RESPONSE URL matched:[" + url + "]");
                    return true;
                }
                // printlog("urlmatch find failed:r,c,url, rmax=" + strrowcol(r,c) + "," + url + ","
                // + Integer.toString(rmax));

            }
        } catch (Exception e) {
            printlog("matcher exception：" + e.toString());
        }
        return false;
    }

    @Override
    public FetchResponseVal clone() {
        FetchResponseVal nobj = null;
        try {
            nobj = (FetchResponseVal) super.clone();
            nobj.distances =
                    HashMapDeepCopy.hashMapDeepCopyParmGenTokenKeyKIntegerV(this.distances);
            nobj.trackkeys = this.trackkeys.clone();
            return nobj;
        } catch (CloneNotSupportedException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return nobj;
    }
}
