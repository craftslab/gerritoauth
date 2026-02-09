# Use Ubuntu as base image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:/usr/local/bin:/usr/bin:$PATH

# Update system and install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    zip \
    unzip \
    wget \
    build-essential \
    ca-certificates \
    openjdk-11-jdk-headless \
    python3 \
    python3-distutils \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 16.x and npm from NodeSource
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - \
    && apt-get install -y nodejs

# Install Bazelisk (Bazel version manager)
RUN wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/v1.19.0/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel

# Ensure `python` points to Python 3 for Bazel builds
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Ensure `node` binary exists
RUN [ -e /usr/bin/node ] || ln -sf /usr/bin/nodejs /usr/bin/node

# Create working directory
WORKDIR /workspace

# Create a non-root user for building (bower doesn't allow root)
RUN useradd -m -s /bin/bash builder \
    && chown -R builder:builder /workspace

# Clone Gerrit
RUN git clone https://gerrit.googlesource.com/gerrit -b stable-3.4 \
    && chown -R builder:builder /workspace/gerrit

# Initialize Gerrit submodules
RUN git config --global --add safe.directory '*' \
    && cd gerrit && git submodule update --init --recursive \
    && chown -R builder:builder /workspace/gerrit

# Copy plugin source code and all necessary files
COPY --chown=builder:builder src/ /workspace/gerrit/plugins/oauth/src/
COPY --chown=builder:builder BUILD /workspace/gerrit/plugins/oauth/
COPY --chown=builder:builder VERSION /workspace/gerrit/plugins/oauth/
COPY --chown=builder:builder tools/ /workspace/gerrit/plugins/oauth/tools/
COPY --chown=builder:builder bazlets.bzl /workspace/gerrit/plugins/oauth/
COPY --chown=builder:builder external_plugin_deps.bzl /workspace/gerrit/plugins/oauth/

# Initialize plugin as separate git repo to use VERSION file instead of parent repo's git describe
RUN cd /workspace/gerrit/plugins/oauth \
    && git init \
    && git config user.email "builder@localhost" \
    && git config user.name "Builder" \
    && git add . \
    && git commit -m "oauth plugin" \
    && PLUGIN_VERSION=$(grep PLUGIN_VERSION VERSION | cut -d"'" -f2) \
    && git tag -a "v${PLUGIN_VERSION}" -m "oauth plugin v${PLUGIN_VERSION}" \
    && chown -R builder:builder /workspace/gerrit/plugins/oauth

# Add external dependencies to Gerrit's WORKSPACE
# Load the external_plugin_deps function and call it to add required dependencies
RUN echo '' >> /workspace/gerrit/WORKSPACE \
    && echo 'load("//plugins/oauth:external_plugin_deps.bzl", "external_plugin_deps")' >> /workspace/gerrit/WORKSPACE \
    && echo 'external_plugin_deps(omit_commons_codec = False)' >> /workspace/gerrit/WORKSPACE

# Switch to non-root user for build
USER builder
ENV HOME=/home/builder

# Build plugin
WORKDIR /workspace/gerrit
RUN bazel build plugins/oauth

# Export built plugin (switch back to root for file operations)
USER root
RUN mkdir -p /workspace/output \
    && cp /workspace/gerrit/bazel-bin/plugins/oauth/oauth.jar /workspace/output/gerrit-oauth-provider.jar \
    && chown -R builder:builder /workspace/output

# Set working directory
WORKDIR /workspace/gerrit

# Expose ports
EXPOSE 8080 29418

# Default command
CMD ["/bin/bash"]
