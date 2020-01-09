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

@Data
public class FieldErrorResource implements Serializable {
    /**
     * Field related to the error
     */
    private String target;

    /**
     * A more specific error code than was provided by the containing error.
     */
    private String code;

    /**
     * A human-readable representation of the error.
     */
    private String message;
}

