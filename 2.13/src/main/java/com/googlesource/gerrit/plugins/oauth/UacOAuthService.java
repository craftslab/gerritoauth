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

import static com.google.gerrit.server.OutputFormat.JSON;

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
import com.google.inject.ProvisionException;
import com.google.inject.Singleton;
import java.io.IOException;
import java.net.URI;
import javax.servlet.http.HttpServletResponse;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
class UacOAuthService implements OAuthServiceProvider {
  private static final Logger log = LoggerFactory.getLogger(UacOAuthService.class);
  static final String CONFIG_SUFFIX = "-uac-oauth";
  private static final String UAC_PROVIDER_PREFIX = "uac-oauth:";
  private static final String DEFAULT_SCOPE = "";
  private static final String SPACE_CHAR = " ";

  private final OAuthService service;
  private final String resourceUrl;
  private final boolean linkToExistingOpenIDAccounts;

  @Inject
  UacOAuthService(PluginConfigFactory cfgFactory,
      @PluginName String pluginName,
      @CanonicalWebUrl Provider<String> urlProvider) {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(
        pluginName + CONFIG_SUFFIX);
    String canonicalWebUrl = CharMatcher.is('/').trimTrailingFrom(
        urlProvider.get()) + "/";

    this.linkToExistingOpenIDAccounts = cfg.getBoolean(
        InitOAuth.LINK_TO_EXISTING_OPENID_ACCOUNT, false);

    log.info(
        "UAC OAuth Service initialized: link-to-existing-openid-accounts = {}",
        linkToExistingOpenIDAccounts);

    String tokenUrl = cfg.getString(InitOAuth.TOKEN_URL);
    String authorizeUrl = cfg.getString(InitOAuth.AUTHORIZE_URL);
    String resourceUrlValue = cfg.getString(InitOAuth.RESOURCE_URL);

    if (tokenUrl == null || tokenUrl.trim().isEmpty()) {
      throw new ProvisionException(
          "Token URL is required for UAC OAuth provider. Please configure token-url in [plugin \""
              + pluginName
              + CONFIG_SUFFIX
              + "\"]");
    }
    if (authorizeUrl == null || authorizeUrl.trim().isEmpty()) {
      throw new ProvisionException(
          "Authorize URL is required for UAC OAuth provider. Please configure authorize-url in [plugin \""
              + pluginName
              + CONFIG_SUFFIX
              + "\"]");
    }
    if (resourceUrlValue == null || resourceUrlValue.trim().isEmpty()) {
      throw new ProvisionException(
          "Resource URL is required for UAC OAuth provider. Please configure resource-url in [plugin \""
              + pluginName
              + CONFIG_SUFFIX
              + "\"]");
    }

    log.info(
        "Initializing UAC OAuth service with token-url: {}, authorize-url: {}, resource-url: {}",
        tokenUrl,
        authorizeUrl,
        resourceUrlValue);

    tokenUrl = tokenUrl.trim();
    authorizeUrl = authorizeUrl.trim();
    resourceUrlValue = resourceUrlValue.trim();

    try {
      if (!URI.create(tokenUrl).isAbsolute()) {
        throw new ProvisionException("Token URL must be absolute URL: " + tokenUrl);
      }
      if (!URI.create(authorizeUrl).isAbsolute()) {
        throw new ProvisionException("Authorize URL must be absolute URL: " + authorizeUrl);
      }
      if (!URI.create(resourceUrlValue).isAbsolute()) {
        throw new ProvisionException("Resource URL must be absolute URL: " + resourceUrlValue);
      }
    } catch (IllegalArgumentException e) {
      throw new ProvisionException(
          "Invalid URL format in UAC OAuth configuration: " + e.getMessage(), e);
    }
    this.resourceUrl = resourceUrlValue;

    String scope = cfg.getString("scope");
    if (scope == null || scope.trim().isEmpty()) {
      scope = DEFAULT_SCOPE;
    }

    ServiceBuilder serviceBuilder = new ServiceBuilder()
        .provider(new UacApi(tokenUrl, authorizeUrl))
        .apiKey(cfg.getString(InitOAuth.CLIENT_ID))
        .apiSecret(cfg.getString(InitOAuth.CLIENT_SECRET))
        .callback(canonicalWebUrl + "oauth");

    if (!scope.isEmpty()) {
      serviceBuilder.scope(scope);
    }

    service = serviceBuilder.build();
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    Token t = new Token(token.getToken(), token.getSecret(), token.getRaw());
    OAuthRequest request = new OAuthRequest(Verb.GET, resourceUrl);
    service.signRequest(t, request);
    Response response = request.send();
    if (response.getCode() != HttpServletResponse.SC_OK) {
      throw new IOException(String.format("Status %s (%s) for request %s",
          response.getCode(), response.getBody(), request.getUrl()));
    }

    String responseBody = response.getBody();
    log.info("UAC getUserInfo response (HTTP {}): {}", response.getCode(), responseBody);

    JsonElement userJson = JSON.newGson().fromJson(responseBody, JsonElement.class);
    if (userJson != null && userJson.isJsonObject()) {
      JsonObject root = userJson.getAsJsonObject();
      JsonObject jsonObject = resolveUserObject(root);

      String login = extractField(jsonObject, "login", "username", "userName",
          "user_name", "account", "accountName", "sAMAccountName", "uid");
      String id = extractField(jsonObject, "id", "userId", "user_id", "userid");

      String ldapUsername = login;
      if (ldapUsername == null || ldapUsername.isEmpty()) {
        ldapUsername = id;
      }
      if (ldapUsername == null || ldapUsername.isEmpty()) {
        throw new IOException(String.format(
            "Response doesn't contain id or login field: %s", responseBody));
      }

      String email = extractField(jsonObject, "email", "mail", "emailAddress",
          "email_address", "userEmail", "user_email", "userMail", "workEmail");
        if ((email == null || email.isEmpty()) && ldapUsername != null && !ldapUsername.isEmpty()) {
        log.info(
          "UAC email is null, username: {} will be used for account linking without email",
          ldapUsername);
        }
      String name = extractField(jsonObject, "name", "displayName",
          "display_name", "fullName", "realName");

      String gerritId = UAC_PROVIDER_PREFIX + ldapUsername;

      // When link-to-existing-openid-accounts is enabled:
      // 1. Set username to NULL to prevent creating duplicate "username:XXX" external ID
      // 2. Set claimedIdentity to "username:XXX" to tell Gerrit which account to link to
      // Gerrit's OAuthSession will look up the account by claimedIdentity and link the
      // new OAuth external ID to that existing account.
      String gerritUsername;
      String claimedIdentity;
      if (linkToExistingOpenIDAccounts) {
        gerritUsername = null;  // Don't create new username external ID
        claimedIdentity = "username:" + ldapUsername;  // Link to existing account
      } else {
        gerritUsername = ldapUsername;  // Create new account with username
        claimedIdentity = null;
      }
      String gerritFullname = getGerritFullname(name, ldapUsername);

      log.info(
          "UAC user mapping - UAC login: {}, UAC id: {}, ldapUsername: {}, email: {}, name: {}, gerritId: {}, gerritUsername: {}, gerritFullname: {}, claimedIdentity: {}, linkToExistingOpenIDAccounts: {}",
          login,
          id,
          ldapUsername,
          email,
          name,
          gerritId,
          gerritUsername,
          gerritFullname,
          claimedIdentity,
          linkToExistingOpenIDAccounts);

      return new OAuthUserInfo(gerritId, gerritUsername, email,
          gerritFullname, claimedIdentity);
    }

    throw new IOException(String.format(
        "Invalid JSON '%s': not a JSON Object", userJson));
  }


  private JsonObject resolveUserObject(JsonObject root) {
    if (hasAnyField(root, "id", "userId", "user_id", "userid", "login",
        "username", "userName", "user_name")) {
      return root;
    }

    String[] wrappers = new String[] {"data", "datas", "result", "content",
        "user", "userinfo"};
    for (String w : wrappers) {
      JsonElement je = root.get(w);
      if (je != null && !je.isJsonNull() && je.isJsonObject()) {
        JsonObject candidate = je.getAsJsonObject();
        if (hasAnyField(candidate, "id", "userId", "user_id", "userid",
            "login", "username", "userName", "user_name")) {
          return candidate;
        }
      }
    }
    return root;
  }

  private boolean hasAnyField(JsonObject obj, String... keys) {
    for (String k : keys) {
      JsonElement je = obj.get(k);
      if (je != null && !je.isJsonNull()) {
        return true;
      }
    }
    return false;
  }

  private String extractField(JsonObject obj, String... keys) {
    for (String k : keys) {
      String v = getJsonElementValue(obj.get(k));
      if (v != null && !v.isEmpty()) {
        return v;
      }
    }
    return null;
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
    Verifier vi = new Verifier(rv.getValue());
    Token to = service.getAccessToken(null, vi);
    return new OAuthToken(to.getToken(), to.getSecret(), to.getRawResponse());
  }

  @Override
  public String getAuthorizationUrl() {
    return service.getAuthorizationUrl(null);
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
