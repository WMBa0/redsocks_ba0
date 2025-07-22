1、下载 NDK r25c（官方长期支持版本）
wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip 
unzip android-ndk-r25c-linux.zip
pwd #查看当前NDK路径

2、配置Android NDK环境变量(写到bashrc文件)
sudo gedit ~/.bashrc
export NDK_HOME=$(pwd)/android-ndk-r25c
export TOOLCHAIN=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
export PATH=$TOOLCHAIN/bin:$PATH
#下面这些也写入，就不用每一个终端敲了
export TARGET=aarch64-linux-android 
export API_LEVEL=28 # 适配 Android 9.0+
export CC=$TARGET$API_LEVEL-clang #使用arm64 clang
export CXX=$TARGET$API_LEVEL-clang++

source ~/.bashrc 

3、安装编译环境包
sudo apt install -y build-essential clang make autoconf automake libtool pkg-config

3.1、需要安装libevent库（redsocks编译用到）
git clone https://github.com/libevent/libevent.git 
cd libevent 
./autogen.sh

#--host  指定目标平台
#--prefix  指定安装路径
./configure --host=$TARGET --prefix=$TOOLCHAIN/sysroot/usr --disable-shared --enable-static CC="$TOOLCHAIN/bin/$TARGET$API_LEVEL-clang" CFLAGS="-fPIE -D__ANDROID_API__=$API_LEVEL" LDFLAGS="-pie"

make && make install

#检查是否成功编译
ls $TOOLCHAIN/sysroot/usr/include/event2/event.h #如果有路径输出说明安装成功

3.2、需要安装uthash库（魔改redsocks用到了这个库文件）
wget https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.tar.gz
tar -xzvf ./v2.3.0.tar.gz
sudo cp uthash-2.3.0/src/uthash.h $TOOLCHAIN/sysroot/usr/include/

4、编译
make CC="$TOOLCHAIN/bin/$TARGET$API_LEVEL-clang"
CFLAGS="-fPIE -fPIC -D__ANDROID_API__=$API_LEVEL -I$TOOLCHAIN/sysroot/usr/include"
LDFLAGS="-pie -L$TOOLCHAIN/sysroot/usr/lib -levent"

5、没有报错就成功了
编译环境：Ubunto20
