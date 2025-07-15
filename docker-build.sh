#!/bin/bash
docker run --rm -v $(pwd):/build \
  -w /build \
  registry.gitlab.com/gitlab-org/android-docker/android-ndk:latest \
  /bin/bash -c '
  # 设置 NDK 环境
  export NDK_HOME=/opt/android-ndk
  export TOOLCHAIN=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
  export PATH=$TOOLCHAIN/bin:$PATH

  # 编译 libevent（静态库）
  wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
  tar -xzf libevent-2.1.12-stable.tar.gz
  cd libevent-2.1.12-stable
  ./configure \
    --host=aarch64-linux-android \
    --disable-shared \
    --enable-static \
    CC=aarch64-linux-android28-clang \
    CFLAGS="-fPIE -fPIC" \
    --prefix=/tmp/libevent-android
  make && make install
  cd ..

  # 编译 redsocks
  make clean
  make \
    CC=aarch64-linux-android28-clang \
    CFLAGS="-fPIE -fPIC -I/tmp/libevent-android/include" \
    LDFLAGS="-pie -static-libstdc++ -L/tmp/libevent-android/lib -levent"
  
  # 检查输出文件
  file redsocks
  '