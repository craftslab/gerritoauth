// Copyright (C) 2015 The Android Open Source Project
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

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;
import com.github.scribejava.core.oauth2.clientauthentication.RequestBodyAuthenticationScheme;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class UacApi extends DefaultApi20 {
  private final String tokenUrl;
  private final String authorizeUrl;

  public UacApi(String tokenUrl, String authorizeUrl) {
    this.tokenUrl = tokenUrl;
    this.authorizeUrl = authorizeUrl;
  }

  @Override
  public String getAccessTokenEndpoint() {
    return tokenUrl;
  }

  @Override
  protected String getAuthorizationBaseUrl() {
    return authorizeUrl;
  }

  @Override
  public ClientAuthentication getClientAuthentication() {
    return RequestBodyAuthenticationScheme.instance();
  }

  @Override
  public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
    return new TokenExtractor<OAuth2AccessToken>() {
      @Override
      public OAuth2AccessToken extract(Response response) throws IOException {
        if (response.getCode() != 200) {
          throw new OAuthException(
              String.format("Failed to get access token: %s", response.getBody()));
        }

        String body = response.getBody();
        if (body == null || body.isEmpty()) {
          throw new OAuthException("Empty response body from token endpoint");
        }

        // Parse form-encoded response: access_token=XXX&token_type=Bearer&expires_in=3600
        Map<String, String> params = new HashMap<>();
        for (String param : body.split("&")) {
          String[] kv = param.split("=", 2);
          if (kv.length == 2) {
            try {
              params.put(kv[0], URLDecoder.decode(kv[1], "UTF-8"));
            } catch (Exception e) {
              throw new OAuthException("Failed to parse token response parameter: " + param, e);
            }
          }
        }

        String accessToken = params.get("access_token");
        if (accessToken == null || accessToken.isEmpty()) {
          throw new OAuthException(
              String.format("No access_token in response: %s", body));
        }

        String tokenType = params.getOrDefault("token_type", "Bearer");
        Integer expiresIn = null;
        if (params.containsKey("expires_in")) {
          try {
            expiresIn = Integer.parseInt(params.get("expires_in"));
          } catch (NumberFormatException e) {
            // Ignore invalid expires_in
          }
        }

        String refreshToken = params.get("refresh_token");
        String scope = params.get("scope");

        return new OAuth2AccessToken(accessToken, tokenType, expiresIn, refreshToken, scope, body);
      }
    };
  }
}
