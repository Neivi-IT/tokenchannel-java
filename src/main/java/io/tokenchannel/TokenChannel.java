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

import com.google.gson.Gson;
import io.tokenchannel.exceptions.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class TokenChannel {

    public static final String TOKENCHANNEL_BASE_URI = "https://api.tokenchannel.io";

    private final TokenChannelProperties properties;
    private final Gson gson;

    public TokenChannel(TokenChannelProperties properties, Gson gson) {
        this.properties = properties;
        this.gson = gson;
    }

    /**
     * Creates a challenge, ie, generates a token to be sent by a given a channel to a given identifier
     *
     * @param channel - The channel the token is being delivered
     * @param identifier - the customer identifier in the given channel
     * @param options - The challenge workflow configuration
     *
     * @throws InvalidIdentifierException whether the identifier is invalid for the given channel
     * @throws TargetOptOutException whether the target user opted out this service via this channel
     * @throws BadRequestException whether there is an invalid value in the request. The field errorInfo in the BadRequestError describes the invalid value
     * @throws OutOfBalanceException whether there is not enough balance to attend a balance consumer challenge creation
     * @throws ForbiddenException whether requesting an action that provided api key is not allowed
     * @throws UnauthorizedException whether an invalid api key value is provided
     * @throws QuotaExceededException whether Sandbox quota, QPS o QPM have been exceeded
     */
    public ChallengeResponse challenge(ChannelType channel, String identifier, ChallengeOptions options) {
        if (this.properties.getTestMode() != null && this.properties.getTestMode()) {
            options.setTest(true);
        }

        try {

            final String uri = String.format("%s/challenge/%s/%s", TOKENCHANNEL_BASE_URI,
                    channel.toString(), URLEncoder.encode(identifier, StandardCharsets.UTF_8.toString()));
            HttpURLConnection con = this.buildConnection(uri, "POST");

            // Adds post payload
            try (OutputStream os = con.getOutputStream()) {
                byte[] input = gson.toJson(options).getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            return this.processResponse(con, ChallengeResponse.class);
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Verifies a previously created challenge
     *
     * @param requestId - The handle to a given challenge
     * @param authCode - The token or validation code to try challenge authentication
     *
     * @throws InvalidCodeException whether the token or validation code provide is invalid
     * @throws BadRequestException whether the requestId format is invalid
     * @throws ChallengeClosedException whether the challenge is closed and no interaction is expected
     * @throws ChallengeExpiredException whether the challenge validity is over
     * @throws ChallengeNotFoundException whether the requestId is well formatted but a challenge for that id cannot be found
     * @throws MaxAttemptsExceededException whether the max number ot attempts allowed has been reached
     * @throws ForbiddenException whether requesting an action that provided api key is not allowed to perform
     * @throws UnauthorizedException whether an invalid api key value is provided
     * @throws QuotaExceededException whether Sandbox quota, QPS o QPM have been exceeded
     */
    public AuthenticateResponse authenticate(String requestId, String authCode) {

        final String uri = String.format("%s/authenticate/%s/%s", TOKENCHANNEL_BASE_URI,
                requestId, authCode);

        try {
            HttpURLConnection con = this.buildConnection(uri, "POST");
            return this.processResponse(con, AuthenticateResponse.class);
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the validation code of a challenge that was previously created with test mode enabled
     *
     * @param requestId - The handle to a given challenge
     *
     * @throws BadRequestException whether the requestId format is invalid
     * @throws ForbiddenException whether requesting an action that provided api key is not allowed to perform
     * @throws UnauthorizedException whether an invalid api key value is provided
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public TestResponse getValidationCodeByTestChallengeId(String requestId) {

        final String uri = String.format("%s/test/%s", TOKENCHANNEL_BASE_URI,
                requestId);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return this.processResponse(con, TestResponse.class);
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the countries TokenChannel service is available
     *
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public List<String> getSupportedCountries() {

        final String uri = String.format("%s/countries", TOKENCHANNEL_BASE_URI);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return Arrays.asList(this.processResponse(con, String[].class));
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the available languages or locales for the token notification templates
     *
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public List<String> getSupportedLanguages() {

        final String uri = String.format("%s/languages", TOKENCHANNEL_BASE_URI);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return Arrays.asList(this.processResponse(con, String[].class));
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the SMS pricing list for supported countries
     *
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public List<SMSPriceItem> getSMSPrices() {

        final String uri = String.format("%s/pricing/sms", TOKENCHANNEL_BASE_URI);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return Arrays.asList(this.processResponse(con, SMSPriceItem[].class));
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the voice call pricing list for supported countries
     *
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public List<VoicePriceItem> getVoicePrices() {

        final String uri = String.format("%s/pricing/voice", TOKENCHANNEL_BASE_URI);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return Arrays.asList(this.processResponse(con, VoicePriceItem[].class));
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    /**
     * Retrieves the Whatsapp pricing list for supported countries
     *
     * @throws QuotaExceededException whether QPS o QPM have been exceeded
     */
    public List<WhatsappPriceItem> getWhatsappPrices() {

        final String uri = String.format("%s/pricing/whatsapp", TOKENCHANNEL_BASE_URI);

        try {
            HttpURLConnection con = this.buildConnection(uri, "GET");
            return Arrays.asList(this.processResponse(con, WhatsappPriceItem[].class));
        } catch (IOException e) {
            throw new TokenChannelException(e);
        }
    }

    private HttpURLConnection buildConnection(String uri, String httpMethod) throws IOException {
        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestProperty("Content-Type", "application/json; utf-8");
        con.setRequestProperty("Accept", "application/json; utf-8");
        con.setRequestProperty("X-Api-Key", this.properties.getApiKey());
        con.setRequestProperty("User-Agent", "io/tokenchannel/java");

        con.setDoOutput(true);

        int timeout = this.properties.getTimeoutInSeconds()*1000;
        con.setConnectTimeout(timeout);
        con.setReadTimeout(timeout);

        con.setRequestMethod(httpMethod);

        return con;
    }

    private <T> T processResponse(HttpURLConnection con, Class<T> responseType) throws IOException {
        if (con.getResponseCode() == 200) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                return gson.fromJson(response.toString(), responseType);
            }
        } else if (con.getResponseCode() == 400 ||
                con.getResponseCode() == 404) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(con.getErrorStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                if (con.getResponseCode() == 400) {
                    ErrorInfo errorInfo = gson.fromJson(response.toString(), ErrorInfo.class);
                    if (errorInfo.getCode().equals("InvalidCode")) {
                        throw new InvalidCodeException();
                    } else if (errorInfo.getCode().equals("InvalidIdentifier")) {
                        throw new InvalidIdentifierException(errorInfo.getMessage());
                    } else if (errorInfo.getCode().equals("OptOut")) {
                        throw new TargetOptOutException();
                    }
                    throw new BadRequestException(errorInfo);
                } else {
                    ErrorInfo errorInfo = gson.fromJson(response.toString(), ErrorInfo.class);
                    if (errorInfo.getCode().equals("ChallengeExpired")) {
                        throw new ChallengeExpiredException();
                    } else if (errorInfo.getCode().equals("ChallengeClosed")) {
                        throw new ChallengeClosedException();
                    } else if (errorInfo.getCode().equals("MaxAttemptsExceeded")) {
                        throw new MaxAttemptsExceededException();
                    }
                    throw new ChallengeNotFoundException();
                }
            }
        } else if (con.getResponseCode() == 401) {
            throw new UnauthorizedException();
        } else if (con.getResponseCode() == 402) {
            throw new OutOfBalanceException();
        } else if (con.getResponseCode() == 403) {
            throw new ForbiddenException();
        } else if (con.getResponseCode() == 429) {
            throw new QuotaExceededException();
        }
        throw new TokenChannelException(String.format("Unexpected error response: ", con.getResponseCode()));
    }
}
