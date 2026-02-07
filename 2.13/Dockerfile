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
COPY bucklets /workspace/bucklets
COPY lib/ /workspace/oauth/lib/
COPY src/ /workspace/oauth/src/
COPY tools/ /workspace/oauth/tools/
COPY BUCK /workspace/oauth/
COPY VERSION /workspace/oauth/

# Link bucklets into plugin dir and setup
RUN set -eux; \
    cd /workspace/oauth; \
    ln -s ../bucklets ./bucklets || true; \
    ln -s bucklets/buckversion .buckversion || true; \
    ln -s bucklets/watchmanconfig .watchmanconfig || true;

# Build plugin
WORKDIR /workspace/oauth
RUN buck kill || true && buck build plugin

# Export built plugin (switch back to root for file operations)
USER root
RUN mkdir -p /workspace/output \
    && cp /workspace/oauth/buck-out/gen/oauth.jar /workspace/output/

# Set working directory
WORKDIR /workspace/oauth

# Expose ports
EXPOSE 8080 29418

# Default command
CMD ["/bin/bash"]
