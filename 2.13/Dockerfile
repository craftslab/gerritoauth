# Use Ubuntu as base image
FROM ubuntu:18.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH=/usr/local/bin:$PATH

# Update system and install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-8-jdk \
    curl \
    git \
    python \
    python3 \
    python3-distutils \
    zip \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /workspace
RUN mkdir /workspace/oauth

# Install Buck via .deb and verify installation
RUN set -eux; \
    apt-get update && apt-get install -y python3-distutils; \
    BUCK_DEB_URL="https://github.com/facebook/buck/releases/download/v2022.05.05.01/buck.2022.05.05.01_all.deb"; \
    curl -fL "$BUCK_DEB_URL" -o /tmp/buck.deb; \
    dpkg -i /tmp/buck.deb || (apt-get -f install -y && dpkg -i /tmp/buck.deb); \
    rm -f /tmp/buck.deb; \
    buck --version

# Copy plugin source code and all necessary files
COPY lib/ /workspace/oauth/lib/
COPY src/ /workspace/oauth/src/
COPY tools/ /workspace/oauth/tools/
COPY bucklets /workspace/oauth/bucklets
COPY BUCK /workspace/oauth/
COPY VERSION /workspace/oauth/
COPY .buckconfig /workspace/oauth/
COPY .bazelrc /workspace/oauth/
COPY .buckversion /workspace/oauth/
COPY .watchmanconfig /workspace/oauth/

# Initialize plugin as separate git repo to use VERSION file for version tagging
RUN cd /workspace/oauth \
    && git init \
    && git config user.email "builder@localhost" \
    && git config user.name "Builder" \
    && git add . \
    && git commit -m "oauth plugin" \
    && PLUGIN_VERSION=$(grep -oP "PLUGIN_VERSION = '\K[^']+" VERSION) \
    && git tag -a "v${PLUGIN_VERSION}" -m "oauth plugin v${PLUGIN_VERSION}"

# Build plugin
WORKDIR /workspace/oauth
RUN buck kill || true && buck build //:gerrit-oauth-provider

# Export built plugin (switch back to root for file operations)
USER root
RUN mkdir -p /workspace/output \
    && cp /workspace/oauth/buck-out/gen/gerrit-oauth-provider.jar /workspace/output/

# Set working directory
WORKDIR /workspace/oauth

# Expose ports
EXPOSE 8080 29418

# Default command
CMD ["/bin/bash"]
