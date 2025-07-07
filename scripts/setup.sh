# Download and extract the appropriate rabbit.go 0.0.4 release for the current OS and architecture

set -e

REPO_URL="https://github.com/SyneHQ/rabbit.go"

# make a api request to the repo to get the latest release
# LATEST_RELEASE=$(curl -s https://api.github.com/repos/SyneHQ/rabbit.go/releases/latest)
# RABBIT_VERSION=$(echo "$LATEST_RELEASE" | tr -d '\000-\037' | jq -r '.tag_name' | cut -c 2-)
RABBIT_VERSION="0.0.4"
BASE_URL="${REPO_URL}/releases/download/v${RABBIT_VERSION}"

echo "Latest rabbit.go version: $RABBIT_VERSION"
echo "Downloading from: $BASE_URL"

# Map uname output to Go arch/os
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)   PLATFORM_OS="linux" ;;
  darwin)  PLATFORM_OS="darwin" ;;
  msys*|mingw*|cygwin*|windowsnt) PLATFORM_OS="windows" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)   PLATFORM_ARCH="amd64" ;;
  arm64|aarch64)  PLATFORM_ARCH="arm64" ;;
  i386|i686)      PLATFORM_ARCH="386" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

FILENAME="rabbit.go_${RABBIT_VERSION}_${PLATFORM_OS}_${PLATFORM_ARCH}.tar.gz"

# Optionally, you can add a checksum verification here using sha256sum

echo "Downloading $FILENAME..."
curl -L -o "$FILENAME" "$BASE_URL/$FILENAME"

echo "Extracting $FILENAME..."
tar -xzf "$FILENAME"

sudo mv rabbit.go /usr/local/bin/rabbit.go

# remove the tar.gz file
rm "$FILENAME"

echo "rabbit.go $RABBIT_VERSION for $PLATFORM_OS/$PLATFORM_ARCH is ready."

# check if the binary is executable
if [ ! -x /usr/local/bin/rabbit.go ]; then
  sudo chmod +x /usr/local/bin/rabbit.go
fi

# check if the binary is working
if ! /usr/local/bin/rabbit.go --help; then
  echo "rabbit.go is not working"
  exit 1
fi

echo "rabbit.go is ready"