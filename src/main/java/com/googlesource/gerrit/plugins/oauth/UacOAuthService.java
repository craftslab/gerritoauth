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

import static com.google.gerrit.json.OutputFormat.JSON;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.CharMatcher;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutionException;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class UacOAuthService implements OAuthServiceProvider {
  private static final Logger log = LoggerFactory.getLogger(UacOAuthService.class);
  static final String CONFIG_SUFFIX = "-uac-oauth";
  private static final String UAC_PROVIDER_PREFIX = "uac-oauth:";
  private static final String SCOPE = "openid";
  private static final int GERRIT_FULL_NAME_COUNT = 2;
  private static final String SPACE_CHAR = " ";

  private final OAuth20Service service;
  private final String resourceUrl;

  @Inject
  UacOAuthService(
      PluginConfigFactory cfgFactory,
      @PluginName String pluginName,
      @CanonicalWebUrl Provider<String> urlProvider) {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(pluginName + CONFIG_SUFFIX);
    String canonicalWebUrl = CharMatcher.is('/').trimTrailingFrom(urlProvider.get()) + "/";

    String tokenUrl = cfg.getString(InitOAuth.TOKEN_URL);
    String authorizeUrl = cfg.getString(InitOAuth.AUTHORIZE_URL);
    String resourceUrlValue = cfg.getString(InitOAuth.RESOURCE_URL);

    if (tokenUrl == null || tokenUrl.trim().isEmpty()) {
      throw new com.google.inject.ProvisionException(
          "Token URL is required for UAC OAuth provider. Please configure token-url in [plugin \"oauth-uac-oauth\"]");
    }
    if (authorizeUrl == null || authorizeUrl.trim().isEmpty()) {
      throw new com.google.inject.ProvisionException(
          "Authorize URL is required for UAC OAuth provider. Please configure authorize-url in [plugin \"oauth-uac-oauth\"]");
    }
    if (resourceUrlValue == null || resourceUrlValue.trim().isEmpty()) {
      throw new com.google.inject.ProvisionException(
          "Resource URL is required for UAC OAuth provider. Please configure resource-url in [plugin \"oauth-uac-oauth\"]");
    }

    // Trim URLs
    tokenUrl = tokenUrl.trim();
    authorizeUrl = authorizeUrl.trim();
    resourceUrlValue = resourceUrlValue.trim();

    try {
      if (!URI.create(tokenUrl).isAbsolute()) {
        throw new com.google.inject.ProvisionException(
            "Token URL must be absolute URL: " + tokenUrl);
      }
      if (!URI.create(authorizeUrl).isAbsolute()) {
        throw new com.google.inject.ProvisionException(
            "Authorize URL must be absolute URL: " + authorizeUrl);
      }
      if (!URI.create(resourceUrlValue).isAbsolute()) {
        throw new com.google.inject.ProvisionException(
            "Resource URL must be absolute URL: " + resourceUrlValue);
      }
    } catch (IllegalArgumentException e) {
      throw new com.google.inject.ProvisionException(
          "Invalid URL format in UAC OAuth configuration: " + e.getMessage(), e);
    }

    // Assign to final field
    this.resourceUrl = resourceUrlValue;

    service =
        new ServiceBuilder(cfg.getString(InitOAuth.CLIENT_ID))
            .apiSecret(cfg.getString(InitOAuth.CLIENT_SECRET))
            .callback(canonicalWebUrl + "oauth")
            .defaultScope(SCOPE)
            .build(new UacApi(tokenUrl, authorizeUrl));
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    OAuthRequest request = new OAuthRequest(Verb.GET, resourceUrl);
    OAuth2AccessToken t = new OAuth2AccessToken(token.getToken(), token.getRaw());
    service.signRequest(t, request);

    JsonElement userJson = null;
    try (Response response = service.execute(request)) {
      if (response.getCode() != HttpServletResponse.SC_OK) {
        throw new IOException(
            String.format(
                "Status %s (%s) for request %s",
                response.getCode(), response.getBody(), request.getUrl()));
      }
      String responseBody = response.getBody();
      log.info("====================>getUserInfo -> responseBody:{}", responseBody);
      userJson = JSON.newGson().fromJson(responseBody, JsonElement.class);

      if (log.isDebugEnabled()) {
        log.debug("User info response: {}", responseBody);
      }

      if (userJson != null && userJson.isJsonObject()) {
        JsonObject jsonObject = userJson.getAsJsonObject();
        String id = getJsonElementValue(jsonObject.get("id"));
        if (id == null) {
          throw new IOException(String.format("Response doesn't contain id field: %s", responseBody));
        }

        String email = getJsonElementValue(jsonObject.get("email"));
        String login = getJsonElementValue(jsonObject.get("login"));
        String name = getJsonElementValue(jsonObject.get("name"));

        String gerritId = getGerritId(id, login);
        String gerritUsername = getGerritUsername(id, login);
        String gerritFullname = getGerritFullname(name, gerritUsername);

        return new OAuthUserInfo(gerritId, gerritUsername, email, gerritFullname, null);
      } else {
        throw new IOException(String.format(
            "Invalid JSON '%s': not a JSON Object", userJson));
      }
    } catch (ExecutionException | InterruptedException e) {
      throw new RuntimeException("Cannot retrieve user info resource", e);
    }
  }

  private String getGerritUsername(String id, String login) {
    try {
      if (login == null || login.isEmpty()) {
        return id;
      }

      if (login.contains(SPACE_CHAR)
          && GERRIT_FULL_NAME_COUNT == login.split(SPACE_CHAR).length) {
        return login.split(SPACE_CHAR)[1];
      }
      return login;
    } catch (Exception e) {
      return null;
    }
  }

  private String getGerritId(String id, String login) {
    try {
      if (login == null || login.isEmpty()) {
        return UAC_PROVIDER_PREFIX + id;
      }

      if (!login.contains(SPACE_CHAR)
          || GERRIT_FULL_NAME_COUNT != login.split(SPACE_CHAR).length) {
        return UAC_PROVIDER_PREFIX + login;
      }
    } catch (Exception e) {
      // Ignore
    }
    return UAC_PROVIDER_PREFIX + id;
  }

  private String getGerritFullname(String name, String gerritUsername) {
    if (name == null || name.isEmpty()) {
      return gerritUsername;
    }
    return name + SPACE_CHAR + gerritUsername;
  }

  private String getJsonElementValue(JsonElement je) {
    return je != null && !je.isJsonNull() ? je.getAsString() : null;
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier rv) {
    try {
      OAuth2AccessToken accessToken = service.getAccessToken(rv.getValue());
      return new OAuthToken(
          accessToken.getAccessToken(), accessToken.getTokenType(), accessToken.getRawResponse());
    } catch (InterruptedException | ExecutionException | IOException e) {
      String msg = "Cannot retrieve access token";
      log.error(msg, e);
      throw new RuntimeException(msg, e);
    }
  }

  @Override
  public String getAuthorizationUrl() {
    return service.getAuthorizationUrl();
  }

  @Override
  public String getVersion() {
    return service.getVersion();
  }

  @Override
  public String getName() {
    return "UAC OAuth2";
  }
}
