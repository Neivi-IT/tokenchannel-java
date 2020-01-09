/*
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
package io.tokenchannel;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class ErrorInfo implements Serializable {

    /**
     * The value for the "code" name/value pair is a language-independent string. Its value is a service-defined error code that SHOULD be human-readable. This code serves as a more specific indicator of the error than the HTTP error code specified in the response. Services SHOULD have a relatively small number (about 20) of possible values for "code," and all clients MUST be capable of handling all of them.
     */
    private String code;
    /**
     * The value for the "message" name/value pair MUST be a human-readable representation of the error. It is intended as an aid to developers and is not suitable for exposure to end users.
     */
    private String message;

    /**
     * The value for the "details" name/value pair MUST be an array of JSON objects that MUST contain name/value pairs for "code" and "message," and MAY contain a name/value pair for "target," as described above. The objects in the "details" array usually represent distinct, related errors that occurred during the request.
     */
    private List<FieldErrorResource> details;
}
