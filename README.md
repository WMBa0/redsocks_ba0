1、 下载 NDK r25c（官方长期支持版本）
wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
unzip android-ndk-r25c-linux.zip
export NDK_HOME=$(pwd)/android-ndk-r25c

2、将以下内容添加到 ~/.bashrc
添加进环境变量
export NDK_HOME=/home/bao/Desktop/android-ndk-r25c
export TOOLCHAIN=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
export PATH=$TOOLCHAIN/bin:$PATH
export TARGET=aarch64-linux-android
export API_LEVEL=28  # 适配 Android 9.0+


source ~/.bashrc

3、安装软件包
sudo apt install -y \
    build-essential \
    clang \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config


4、
# 进入 redsocks 源码目录
cd redsocks

# 设置编译参数
export CC=$TARGET$API_LEVEL-clang
export CXX=$TARGET$API_LEVEL-clang++
export CFLAGS="-fPIE -fPIC -D__ANDROID_API__=$API_LEVEL"
export LDFLAGS="-pie -static-libstdc++"

#此时还不能编译，redsocks用到了 libevent库 
#需先交叉编译 libevent（静态库）：
git clone https://github.com/libevent/libevent.git
cd libevent
./autogen.sh

./configure --host=$TARGET --prefix=$TOOLCHAIN/sysroot/usr --disable-shared --enable-static  CC="$TOOLCHAIN/bin/$TARGET$API_LEVEL-clang"  CFLAGS="-fPIE -D__ANDROID_API__=$API_LEVEL"  LDFLAGS="-pie"

make && make install

#检查是否成功编译：ls $TOOLCHAIN/sysroot/usr/include/event2/event.h
#如果有路径输出说明安装成功


#再次编译redsocks  如果没有魔改的话，正常是成功了
export CFLAGS="-fPIE -fPIC -D__ANDROID_API__=$API_LEVEL -I$TOOLCHAIN/sysroot/usr/include"
export LDFLAGS="-pie -L$TOOLCHAIN/sysroot/usr/lib -levent"

make CC="$TOOLCHAIN/bin/$TARGET$API_LEVEL-clang"


#正常应该成功了，但我新增了库，导致错误
redsocks.c:33:10: fatal error: 'uthash.h' file not found
#include <uthash.h> // 哈希表库
         ^~~~~~~~~~
1 warning and 1 error generated.
make: *** [<内置>：redsocks.o] 错误 1

#手动指定uthash.h头文件
wget https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.tar.gz
tar -xzvf v2.3.0.tar.gz
sudo cp uthash-2.3.0/src/uthash.h $TOOLCHAIN/sysroot/usr/include/

#再次编译就成功了
make CC="$TOOLCHAIN/bin/$TARGET$API_LEVEL-clang" \
     CFLAGS="-fPIE -fPIC -D__ANDROID_API__=$API_LEVEL -I$TOOLCHAIN/sysroot/usr/include" \
     LDFLAGS="-pie -L$TOOLCHAIN/sysroot/usr/lib -levent"
