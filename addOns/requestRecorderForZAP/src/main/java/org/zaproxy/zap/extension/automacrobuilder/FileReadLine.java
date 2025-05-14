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

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.DefaultCSVFileIANACharsetName;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;

/**
 * @author gdgd009xcd
 */
//
// class FileReadLine
//
public class FileReadLine {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static int MAX_COLUMN_READABLE = 9999;
    String csvfile;
    RandomAccessFile raf = null;
    long seekIndex;
    int currentRecordNumber;
    boolean saveSeekp;
    ArrayList<String> columns;
    private AppParmsIni appParmsIni = null;

    private String csvFileIANACharsetName =
            DefaultCSVFileIANACharsetName; // CSV file Input/Output encoding

    public FileReadLine(AppParmsIni appParmsIni, String _filepath) {
        this.csvfile = _filepath;
        this.raf = null;
        this.seekIndex = 0;
        this.currentRecordNumber = 0;
        this.columns = null;
        this.appParmsIni = appParmsIni;
        if (this.appParmsIni != null) {
            this.seekIndex = this.appParmsIni.getCsvSeekIndex();
            this.currentRecordNumber = this.appParmsIni.getCsvCurrentRecordNumber();
        }
    }

    public String getFileName() {
        return this.csvfile;
    }

    private void rewind() {
        this.seekIndex = 0;
        this.currentRecordNumber = 0;
        if (this.appParmsIni != null) {
            this.appParmsIni.setCsvSeekIndex(this.seekIndex);
            this.appParmsIni.setCsvCurrentRecordNumber(this.currentRecordNumber);
        }
    }

    /**
     * convert byte array which is readed from <code>RandomAccessFile</code> to encoded String.
     *
     * @param f
     * @return
     * @throws IOException
     */
    private String readLineRandomAccessFileCharset(RandomAccessFile f) throws IOException {
        ParmGenBinUtil barray = new ParmGenBinUtil();
        byte[] onebyte = new byte[1];
        int c = -1;
        boolean eol = false;
        while (!eol) {
            switch (c = f.read()) {
                case -1: // reached EOF
                case '\n':
                    eol = true;
                    break;
                case '\r':
                    eol = true;
                    long cur = f.getFilePointer();
                    if ((f.read()) != '\n') {
                        f.seek(cur);
                    }
                    break;
                default:
                    onebyte[0] = (byte) c;
                    barray.concat(onebyte);
                    break;
            }
        }

        if ((c == -1) && (barray.length() == 0)) {
            return null;
        }

        return new String(barray.getBytes(), csvFileIANACharsetName);
    }

    public synchronized ArrayList<String> readOneRecordWithColumns() {
        if (this.columns == null) {
            this.columns = new ArrayList<String>();
        }
        this.columns.clear();
        String dummy = readLineWithoutUpdateAppParmsIni(MAX_COLUMN_READABLE);
        if (this.columns.size() > 0) {
            return this.columns;
        }
        return null;
    }

    synchronized int skipLine(int l) {
        if (l >= 0) {
            rewind();
            this.columns = null;
            while (l-- > 0) {
                String dummy = readLineWithoutUpdateAppParmsIni(1);
                if (dummy == null) {
                    break;
                }
            }
            if (this.appParmsIni != null) {
                this.appParmsIni.setCsvSeekIndex(this.seekIndex);
                this.appParmsIni.setCsvCurrentRecordNumber(this.currentRecordNumber);
            }
        } else {
            return -1;
        }
        return this.currentRecordNumber;
    }

    synchronized String readLine(
            boolean isNoCount, int columnPos, AppValue apv, ParmGenMacroTrace pmt) {
        this.seekIndex = 0;
        this.currentRecordNumber = 0;
        String line = null;
        try {
            if (this.appParmsIni != null) {
                this.seekIndex = this.appParmsIni.getCsvSeekIndex();
                this.currentRecordNumber = this.appParmsIni.getCsvCurrentRecordNumber();
            }

            // open csv file with random access mode.
            this.raf = new RandomAccessFile(this.csvfile, "r");

            if (this.raf.length() <= this.seekIndex) {
                LOGGER4J.debug("seekp reached EOF\n");
                this.raf.close();
                this.raf = null;
                return null;
            }

            this.raf.seek(this.seekIndex);

            // read one record from csv file.
            line = readLineRandomAccessFileCharset(this.raf);
            String _col = line;

            CSVParser.Parse(line);

            CSVParser.CSVFields csvf = new CSVParser.CSVFields();
            while (CSVParser.getField(csvf)) {
                _col = csvf.field;
                if (this.columns != null) {
                    String _c = _col;
                    _c = _c.replace("\r", "");
                    _c = _c.replace("\n", "");
                    this.columns.add(_c);
                }
                if (columnPos-- <= 0) break;
            }
            line = _col;
            line = line.replace("\r", "");
            line = line.replace("\n", "");

            boolean condInValid = false;
            if (pmt != null && apv != null) {
                condInValid = !pmt.getFetchResponseVal().getCondValid(apv) && apv.hasCond();
            }
            if (condInValid
                    || isNoCount
                    || (this.appParmsIni != null && this.appParmsIni.isPaused())) {
            } else {
                LOGGER4J.debug(" seek forward:" + Long.toString(this.seekIndex));
                // get current seek point
                this.seekIndex = this.raf.getFilePointer();
                this.currentRecordNumber++;
            }

            if (this.appParmsIni != null && !this.appParmsIni.isPaused()) {
                this.appParmsIni.setCsvSeekIndex(this.seekIndex);
                this.appParmsIni.setCsvCurrentRecordNumber(this.currentRecordNumber);
            }
        } catch (IOException e) {
            LOGGER4J.error(
                    "FileReadLine::readLine failed csvfile:"
                            + this.csvfile
                            + " ERR:"
                            + e.toString(),
                    e);
        } finally {
            if (this.raf != null) {
                try {
                    this.raf.close();
                } catch (Exception e) {
                    //
                }
                this.raf = null;
            }
        }
        return line;
    }

    synchronized String readLineWithoutUpdateAppParmsIni(int columnPos) {
        String line = null;
        try {
            // open csv file with random access mode.
            this.raf = new RandomAccessFile(this.csvfile, "r");

            if (this.raf.length() <= this.seekIndex) {
                LOGGER4J.debug("seekp reached EOF\n");
                this.raf.close();
                this.raf = null;
                return null;
            }

            this.raf.seek(this.seekIndex);

            // read one record from csv file.
            line = readLineRandomAccessFileCharset(this.raf);
            String _col = line;

            CSVParser.Parse(line);

            CSVParser.CSVFields csvf = new CSVParser.CSVFields();
            while (CSVParser.getField(csvf)) {
                _col = csvf.field;
                if (this.columns != null) {
                    String _c = _col;
                    _c = _c.replace("\r", "");
                    _c = _c.replace("\n", "");
                    this.columns.add(_c);
                }
                if (columnPos-- <= 0) break;
            }
            line = _col;
            line = line.replace("\r", "");
            line = line.replace("\n", "");

            // get current seek point
            this.seekIndex = this.raf.getFilePointer();
            this.currentRecordNumber++;
        } catch (IOException e) {
            LOGGER4J.error(
                    "FileReadLine::readLineWithoutUpdateAppParmsIni failed csvfile:"
                            + this.csvfile
                            + " ERR:"
                            + e.toString(),
                    e);
        } finally {
            if (this.raf != null) {
                try {
                    this.raf.close();
                } catch (Exception e) {
                    //
                }
                this.raf = null;
            }
        }
        return line;
    }

    synchronized String getCurrentReadLine() {
        return String.valueOf(this.currentRecordNumber);
    }
}
