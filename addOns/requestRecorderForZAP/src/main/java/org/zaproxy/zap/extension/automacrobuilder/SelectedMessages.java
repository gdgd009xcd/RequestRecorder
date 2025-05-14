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

import static org.zaproxy.zap.extension.automacrobuilder.Encode.UTF_8;

import java.util.ArrayList;
import java.util.List;

/**
 * This class Used only when saving parameter settings.
 *
 * @author gdgd009xcd
 */
public class SelectedMessages {
    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();

    private List<PRequestResponse> choosed_messages_for_extract_value = null;
    private List<PRequestResponse> selected_messages = null;

    /**
     * selected messages
     *
     * @param _selected_messages
     */
    public SelectedMessages(List<PRequestResponse> _selected_messages) {
        this.choosed_messages_for_extract_value = new ArrayList<PRequestResponse>();
        this.selected_messages = _selected_messages;
        if (this.selected_messages == null || this.selected_messages.isEmpty()) {
            // create dummy message
            String requeststr =
                    "GET /index.php?DB=1 HTTP/1.1\r\n"
                            + "Host: test\r\n"
                            + "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n\r\n";
            String responsestr =
                    "HTTP/1.1 200 OK\r\n"
                            + "Date: Sat, 20 Jun 2020 01:10:28 GMT\r\n"
                            + "Content-Length: 0\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n\r\n";

            PRequestResponse dummy =
                    new PRequestResponse(
                            "localhost",
                            80,
                            false,
                            requeststr.getBytes(),
                            responsestr.getBytes(),
                            UTF_8,
                            UTF_8);
            this.selected_messages =
                    this.selected_messages == null ? new ArrayList<>() : this.selected_messages;
            this.selected_messages.add(dummy);
        }
        this.choosed_messages_for_extract_value.add(this.selected_messages.get(0));
    }

    public PRequestResponse getChoosedMessage() {
        return this.choosed_messages_for_extract_value.get(0);
    }

    public void clearChoosedMessageList() {
        this.choosed_messages_for_extract_value.clear();
    }

    public int getChoosedMessageListSize() {
        return this.choosed_messages_for_extract_value != null
                ? this.choosed_messages_for_extract_value.size()
                : -1;
    }

    public int getSelectedMessageListSize() {
        return this.selected_messages.size();
    }

    public List<PRequestResponse> getSelectedMessageList() {
        return this.selected_messages;
    }

    public void setChoosedMessageWithSpecifiedIndex(int index) {
        this.choosed_messages_for_extract_value.add(this.selected_messages.get(index));
    }
}
