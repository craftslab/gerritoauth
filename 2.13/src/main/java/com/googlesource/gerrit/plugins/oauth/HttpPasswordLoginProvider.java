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

import com.google.common.base.Strings;
import com.google.gerrit.extensions.auth.oauth.OAuthLoginProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.server.account.AccountCache;
import com.google.gerrit.server.account.AccountState;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.lang.reflect.Method;

@Singleton
class HttpPasswordLoginProvider implements OAuthLoginProvider {
  private final AccountCache accountCache;

  @Inject
  HttpPasswordLoginProvider(AccountCache accountCache) {
    this.accountCache = accountCache;
  }

  @Override
  public OAuthUserInfo login(String username, String secret) throws IOException {
    if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(secret)) {
      throw new IOException("Missing credentials");
    }

    AccountState state = accountCache.getByUsername(username);
    if (state == null || !state.getAccount().isActive()) {
      throw new IOException("Invalid credentials");
    }

    if (!checkPassword(state, username, secret)) {
      throw new IOException("Invalid credentials");
    }

    return new OAuthUserInfo(
        "username:" + username,
        username,
        state.getAccount().getPreferredEmail(),
        state.getAccount().getFullName(),
        null);
  }

  private boolean checkPassword(AccountState state, String username, String secret) {
    // Prefer PasswordVerifier if available to match newer Gerrit behavior.
    try {
      Object externalIds = getExternalIds(state);
      if (externalIds != null) {
        Class<?> verifierClass =
            Class.forName("com.google.gerrit.server.account.externalids.PasswordVerifier");
        Method verifier = findVerifierMethod(verifierClass);
        if (verifier != null) {
          Object result = verifier.invoke(null, externalIds, username, secret);
          if (result instanceof Boolean) {
            return (Boolean) result;
          }
        }
      }
    } catch (ReflectiveOperationException ignored) {
      // Fall back to legacy password check below.
    }

    String expected = state.getPassword(username);
    return !Strings.isNullOrEmpty(expected) && expected.equals(secret);
  }

  private static Object getExternalIds(AccountState state) throws ReflectiveOperationException {
    try {
      Method method = state.getClass().getMethod("externalIds");
      return method.invoke(state);
    } catch (NoSuchMethodException ignored) {
      Method method = state.getClass().getMethod("getExternalIds");
      return method.invoke(state);
    }
  }

  private static Method findVerifierMethod(Class<?> verifierClass) {
    for (Method method : verifierClass.getMethods()) {
      if (!"checkPassword".equals(method.getName())) {
        continue;
      }
      Class<?>[] params = method.getParameterTypes();
      if (params.length == 3 && params[1] == String.class && params[2] == String.class) {
        return method;
      }
    }
    return null;
  }
}
