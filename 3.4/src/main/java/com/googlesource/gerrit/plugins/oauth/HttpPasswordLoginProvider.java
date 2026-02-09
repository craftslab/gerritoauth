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
import com.google.gerrit.entities.Account;
import com.google.gerrit.extensions.auth.oauth.OAuthLoginProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.server.account.AccountCache;
import com.google.gerrit.server.account.AccountState;
import com.google.gerrit.server.account.externalids.PasswordVerifier;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;

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

    AccountState state = accountCache.getByUsername(username).orElse(null);
    if (state == null || state.account().inactive()) {
      throw new IOException("Invalid credentials");
    }

    if (!PasswordVerifier.checkPassword(state.externalIds(), username, secret)) {
      throw new IOException("Invalid credentials");
    }

    Account account = state.account();

    return new OAuthUserInfo(
        "username:" + username,
        username,
        account.preferredEmail(),
        account.fullName(),
        null);
  }
}
