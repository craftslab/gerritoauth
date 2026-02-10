// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.googlesource.gerrit.plugins.oauth;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

public class UacApi extends DefaultApi20 {
  private static final String GRANT_TYPE = "authorization_code";
  private static final String RESPONSE_TYPE = "code";

  private final String tokenUrl;
  private final String authorizeUrl;

  public UacApi(String tokenUrl, String authorizeUrl) {
    this.tokenUrl = tokenUrl;
    this.authorizeUrl = authorizeUrl;
    if (!tokenUrl.startsWith("http://") && !tokenUrl.startsWith("https://")) {
      throw new IllegalArgumentException("Token URL must start with http:// or https://: " + tokenUrl);
    }
    if (!authorizeUrl.startsWith("http://") && !authorizeUrl.startsWith("https://")) {
      throw new IllegalArgumentException("Authorize URL must start with http:// or https://: " + authorizeUrl);
    }
  }

  @Override
  public String getAccessTokenEndpoint() {
    return tokenUrl;
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config) {
    Preconditions.checkValidUrl(config.getCallback(),
        "Must provide a valid url as callback. UAC does not support OOB");

    StringBuilder url = new StringBuilder(authorizeUrl);
    String separator = authorizeUrl.contains("?") ? "&" : "?";
    url.append(separator).append("response_type=").append(RESPONSE_TYPE);
    url.append("&client_id=").append(config.getApiKey());
    url.append("&redirect_uri=").append(OAuthEncoder.encode(config.getCallback()));
    if (config.hasScope()) {
      url.append("&scope=").append(OAuthEncoder.encode(config.getScope()));
    }
    String result = url.toString();
    // Note: state parameter will be added by Gerrit's OAuth infrastructure
    return result;
  }

  @Override
  public Verb getAccessTokenVerb() {
    return Verb.POST;
  }

  @Override
  public OAuthService createService(OAuthConfig config) {
    return new UacOAuthService(this, config);
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return new UacTokenExtractor();
  }

  private static final class UacOAuthService implements OAuthService {
    private static final String VERSION = "2.0";

    private final DefaultApi20 api;
    private final OAuthConfig config;

    private UacOAuthService(DefaultApi20 api, OAuthConfig config) {
      this.api = api;
      this.config = config;
    }

    @Override
    public Token getAccessToken(Token requestToken, Verifier verifier) {
      OAuthRequest request =
          new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
      request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
      request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
      request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
      request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
      if (config.hasScope()) {
        request.addBodyParameter(OAuthConstants.SCOPE, config.getScope());
      }
      request.addBodyParameter("grant_type", GRANT_TYPE);
      Response response = request.send();
      return api.getAccessTokenExtractor().extract(response.getBody());
    }

    @Override
    public Token getRequestToken() {
      throw new UnsupportedOperationException(
          "Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
    }

    @Override
    public String getVersion() {
      return VERSION;
    }

    @Override
    public void signRequest(Token accessToken, OAuthRequest request) {
      request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
    }

    @Override
    public String getAuthorizationUrl(Token requestToken) {
      return api.getAuthorizationUrl(config);
    }
  }

  private static final class UacTokenExtractor implements AccessTokenExtractor {
    private static final Pattern JSON_ACCESS_TOKEN =
        Pattern.compile("\"access_token\"\\s*:\\s*\"(\\S*?)\"");

    @Override
    public Token extract(String response) {
      Preconditions.checkEmptyString(response,
          "Cannot extract a token from a null or empty String");

      Matcher matcher = JSON_ACCESS_TOKEN.matcher(response);
      if (matcher.find()) {
        return new Token(matcher.group(1), "", response);
      }

      Map<String, String> params = parseFormEncoded(response);
      String accessToken = params.get("access_token");
      if (accessToken == null || accessToken.isEmpty()) {
        throw new OAuthException(
            "Cannot extract an access token. Response was: " + response);
      }
      return new Token(accessToken, "", response);
    }

    private Map<String, String> parseFormEncoded(String body) {
      Map<String, String> params = new HashMap<>();
      for (String param : body.split("&")) {
        String[] kv = param.split("=", 2);
        if (kv.length == 2) {
          try {
            params.put(kv[0], URLDecoder.decode(kv[1], "UTF-8"));
          } catch (Exception e) {
            throw new OAuthException("Cannot decode token response parameter: " + param, e);
          }
        }
      }
      return params;
    }
  }
}
