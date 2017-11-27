/*
 * Copyright 2017 Prudential Corporation Asia
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

package hk.com.prudential.gradle.sassign;

import com.symantec.ws.api.webtrust.codesigningservice.Error;
import com.symantec.ws.api.webtrust.codesigningservice.Errors;

public class SasSignServiceException extends Exception {
    private Errors errors;

    public SasSignServiceException(String message) {
        super(message);
    }

    public SasSignServiceException(String message, Errors errors) {
        super(message);
        this.errors = errors;
    }

    @Override
    public String toString() {
        String defaultMessage = super.toString();

        StringBuilder sb = new StringBuilder("[");

        for (Error e: errors.getError()) {
            sb.append("{code: ")
                    .append(e.getErrorCode())
                    .append(", field: \"")
                    .append(e.getErrorField())
                    .append("\", message: \"")
                    .append(e.getErrorMessage())
                    .append("\"},");
        }
        if (1 == sb.length()) {
            sb.append("]");
        } else {
            sb.setCharAt(sb.length()-1, ']');
        }

        return sb.insert(0, defaultMessage+": ").toString();
    }
}
