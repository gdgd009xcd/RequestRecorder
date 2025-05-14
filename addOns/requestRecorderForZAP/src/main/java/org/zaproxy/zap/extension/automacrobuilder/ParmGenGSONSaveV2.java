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

import com.google.gson.GsonBuilder;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Iterator;

/**
 * This class Used only when saving parameter settings.
 *
 * @author gdgd009xcd
 */
public class ParmGenGSONSaveV2 {
    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();
    ParmGenWriteFile pfile;
    private ParmGenMacroTraceProvider pmtProvider = null;

    public ParmGenGSONSaveV2(ParmGenMacroTraceProvider pmtProvider) {
        this.pmtProvider = pmtProvider;
        pfile = null;
    }

    /**
     * convert String to URLencode (code is UTF-8)
     *
     * @param _d
     * @return URLencoded with UTF-8
     */
    private String URLencodeToJSON(String _d) {
        // String _dd = _d.replaceAll("\\\\", "\\\\");
        String _dd = _d;
        // String _ddd = _dd.replaceAll("\"", "\"\"");
        String encoded = _d;
        try {
            if (_dd != null) {
                encoded = URLEncoder.encode(_dd, JSONFileIANACharsetName);
            }
        } catch (UnsupportedEncodingException e) {
            EnvironmentVariables.plog.printException(e);
            encoded = _dd;
        }
        return encoded;
    }

    private String QUOTE(String val, boolean comma) {
        return "\"" + (val == null ? "" : val) + "\"" + (comma ? "," : "");
    }

    /**
     * save tracking parameter and RequestResponseList to file.
     *
     * @param choosedFileName if null then overwrite existing saved file(saveFilePathName).<br>
     *     if choosedFileName is not empty then saved to it.
     * @return true-succeed false-failed
     */
    public boolean GSONsave(String choosedFileName) {
        String fileName;
        try {
            fileName = EnvironmentVariables.getSaveFilePathName();
            if (choosedFileName != null && !choosedFileName.isEmpty()) {
                fileName = choosedFileName;
            }
            FileInfo finfo = new FileInfo(fileName);
            pfile = new ParmGenWriteFile(finfo.getFullFileName());
        } catch (Exception ex) {
            EnvironmentVariables.plog.printException(ex);
            return false;
        }

        pfile.truncate();

        GSONSaveObjectV2 gsobject = new GSONSaveObjectV2();

        gsobject.ProxyInScope = ParmGen.ProxyInScope;
        gsobject.IntruderInScope = ParmGen.IntruderInScope;
        gsobject.RepeaterInScope = ParmGen.RepeaterInScope;
        gsobject.ScannerInScope = ParmGen.ScannerInScope;

        // excludeMimeTypelist
        //
        // { "ExcludeMimeTypes" : ["image/.*", "application/json"],
        //

        EnvironmentVariables.ExcludeMimeTypes.forEach(
                (mtype) -> {
                    gsobject.ExcludeMimeTypes.add(mtype);
                });

        Iterator<ParmGenMacroTrace> pit = pmtProvider.getBaseInstanceIterator();
        while (pit.hasNext()) {
            ParmGenMacroTrace pmt = pit.next();
            if (pmt.getAppParmsIniList() == null) {
                pmt.updateAppParmsIniAndClearCache(null);
            }
            Iterator<AppParmsIni> it = pmt.getIteratorOfAppParmsIni();
            GSONSaveObjectV2.AppParmAndSequence appParmAndSequence =
                    new GSONSaveObjectV2.AppParmAndSequence();
            while (it.hasNext()) {
                AppParmsIni prec = it.next();
                // String URL, String initval, String valtype, String incval,
                // ArrayList<ParmGenParam>
                // parms
                GSONSaveObjectV2.AppParmsIni_List AppParmsIni_ListObj =
                        new GSONSaveObjectV2.AppParmsIni_List();
                AppParmsIni_ListObj.URL = prec.getUrl();
                AppParmsIni_ListObj.len = prec.getLen();
                AppParmsIni_ListObj.typeval = prec.getTypeVal();
                AppParmsIni_ListObj.inival = prec.getIniVal();
                AppParmsIni_ListObj.maxval = prec.getMaxVal();
                AppParmsIni_ListObj.cntCount = prec.getCntCount();
                AppParmsIni_ListObj.csvname =
                        (prec.getTypeVal() == AppParmsIni.T_CSV
                                ? URLencodeToJSON(prec.getFrlFileName())
                                : "");
                AppParmsIni_ListObj.csvSeekIndex = prec.getCsvSeekIndex();
                AppParmsIni_ListObj.csvCurrentRecordNumber = prec.getCsvCurrentRecordNumber();
                AppParmsIni_ListObj.pause = prec.isPaused();
                AppParmsIni_ListObj.TrackFromStep = prec.getTrackFromStep();
                AppParmsIni_ListObj.SetToStep = prec.getSetToStep();

                Iterator<AppValue> pt = prec.getAppValueReadWriteOriginal().iterator();

                while (pt.hasNext()) {
                    AppValue param = pt.next();
                    GSONSaveObjectV2.AppValue_List AppValue_ListObj =
                            new GSONSaveObjectV2.AppValue_List();
                    AppValue_ListObj.valpart = param.getHttpSectionTypeEmbedTo();
                    AppValue_ListObj.isEnabled = param.isEnabled();
                    AppValue_ListObj.isNoCount = param.isNoCount();
                    AppValue_ListObj.csvpos = param.getCsvpos();
                    AppValue_ListObj.value = URLencodeToJSON(param.getRegexEmbedValTo());
                    AppValue_ListObj.resURL =
                            param.getRegexTrackURLFrom() == null
                                    ? ""
                                    : param.getRegexTrackURLFrom();
                    AppValue_ListObj.resRegex =
                            (URLencodeToJSON(param.getRegexTrackValFrom()) == null
                                    ? ""
                                    : URLencodeToJSON(param.getRegexTrackValFrom()));
                    AppValue_ListObj.resValpart = param.getHttpSectionTypeTrackFrom();
                    AppValue_ListObj.resRegexPos = param.getPositionTrackFrom();
                    AppValue_ListObj.token =
                            param.getParamNameTrackFrom() == null
                                    ? ""
                                    : param.getParamNameTrackFrom();
                    AppValue_ListObj.urlencode = param.isUrlEncode();
                    AppValue_ListObj.fromStepNo = param.getFromStepNo();
                    AppValue_ListObj.toStepNo = param.getToStepNo();
                    AppValue_ListObj.tokenType = param.getTokenTypeTrackFrom();
                    AppValue_ListObj.condTargetNo = param.getCondTargetNo();
                    AppValue_ListObj.condRegex =
                            (URLencodeToJSON(param.getCondRegex()) == null
                                    ? ""
                                    : URLencodeToJSON(param.getCondRegex()));
                    AppValue_ListObj.condRegexTargetIsRequest = param.requestIsCondRegexTarget();

                    AppParmsIni_ListObj.AppValue_Lists.add(AppValue_ListObj);
                }

                appParmAndSequence.AppParmsIni_Lists.add(AppParmsIni_ListObj);
            }

            // save RequestResponses
            pmt.GSONSaveV2(appParmAndSequence);
            gsobject.AppParmAndSequences.add(appParmAndSequence);
        }

        PrintWriter pw = pfile.getPrintWriter();

        GsonBuilder gbuilder = new GsonBuilder();
        gbuilder.setPrettyPrinting();
        String prettygson = gbuilder.create().toJson(gsobject);
        pw.print(prettygson);

        pfile.close();
        pfile = null;
        EnvironmentVariables.commitChoosedFile(fileName);
        EnvironmentVariables.Saved(true);
        EnvironmentVariables.modified(false);
        return true;
    }
}
