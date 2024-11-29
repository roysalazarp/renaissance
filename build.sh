#!/bin/bash

BUILD_ENV=$1

# Check if the build environment is provided
if [ -z "$BUILD_ENV" ]; then
    echo "Error: No build environment specified. Use 'prod' or 'dev'."
    exit 1
fi

# Create the build folder for the environment
BUILD_DIR="./build-$BUILD_ENV"

rm -rf "$BUILD_DIR"

# Create the build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

if [ "$BUILD_ENV" == "prod" ]; then
    echo "Building for production..."
  
    gcc \
        -std=c89 \
        -g \
        -o "$BUILD_DIR/app" \
        main.c \
        -I/usr/include/postgresql \
        -lpq \
        -largon2 \
        -pthread \
        -lssl \
        -lcrypto

elif [ "$BUILD_ENV" == "dev" ]; then
    echo "Building for development..."

    gcc \
        -std=c89 \
        -g \
        -Wall \
        -Wextra \
        -Werror \
        -pedantic \
        -Wno-declaration-after-statement \
        -Wno-unused-variable \
        -Wno-unused-parameter \
        -o "$BUILD_DIR/app" \
        main.c \
        -I/usr/include/postgresql \
        -lpq \
        -largon2 \
        -pthread \
        -lssl \
        -lcrypto

else
    echo "Invalid or no environment specified. Use 'prod' or 'dev'."
    exit 1
fi

set -o allexport && source <(grep '^COMPILE_' ".env.$BUILD_ENV") && set +o allexport

for var in $(env | grep '^COMPILE_' | cut -d= -f1); do
    source="${!var}"  # Get the value of the environment variable
    if [ -d "$source" ]; then
        # If the source exists, copy it to $BUILD_DIR
        cp -r "$source" $BUILD_DIR
    elif [ -f "$source" ]; then
        # If the source is a file, copy the individual file
        target_dir="$BUILD_DIR/$(dirname "$source")"
        mkdir -p "$target_dir"
        cp "$source" "$target_dir/"
    else
        echo "Warning: $source does not exist, skipping..."
    fi
done

cp ".env.$BUILD_ENV" "$BUILD_DIR/.env"

echo "Done!"
