#!/bin/bash

set -euo pipefail

# Note that opam needs bash, not just sh
# Also it uses undefined variables so let's set them now otherwise it'll fail due to strict mode
if [ -z ${PERL5LIB+x} ]; then
  export PERL5LIB=''
fi
if [ -z ${MANPATH+x} ]; then
  export MANPATH=''
fi
if [ -z ${PROMPT_COMMAND+x} ]; then
  export PROMPT_COMMAND=''
fi

DPDK_RELEASE='20.08'
KLEE_RELEASE='master'
KLEE_UCLIBC_RELEASE='klee_uclibc_v1.2'
LLVM_RELEASE=8.0.0
Z3_RELEASE='z3-4.5.0'
OCAML_RELEASE='4.06.0'

# Stop script if we do not have root access
check_sudo()
{
	echo 'Checking for sudo rights:'
	if ! sudo -v;
	then
		echo 'sudo rights not obtained, or sudo not installed.' >&2;
		exit 1;
	fi
}

# Detect the running operating system
# stdout: 'windows', 'docker' or 'linux'
detect_os()
{
	# Detect WSL
	case $(uname -r) in
		*Microsoft*)
			echo 'windows'
			return 0
			;;
	esac

	# Or docker ?
	if grep docker /proc/1/cgroup -qa;
	then
		echo 'docker'
		return 0
	fi

	# Use generic "linux" tag for the rest.
	# XXX: Support some more distributions ?
	echo 'linux'
	return 0
}

# Install arguments using system's package manager.
# XXX: Make the package manager depend on "$OS".
# shellcheck disable=SC2086
package_install()
{
	# Concatenate arguments into a list
	old_ifs="$IFS"
	IFS=' '
	packages="$*"
	IFS="$old_ifs"

	sudo apt-get install -yqq $packages
}

# Update list of available packages.
# XXX: Make the package manager depend on "$OS".
package_sync()
{
	sudo apt-get update -qq
}

source_install_dpdk()
{
	cd "$BUILDDIR"

	# Install kernel headers
	case "$OS" in
		'microsoft')
			package_install "linux-headers-$KERNEL_VER-generic"

			# Fix the kernel dir, since the WSL doesn't have an actual Linux kernel.
			export RTE_KERNELDIR="/usr/src/linux-headers-$KERNEL_VER-generic/"
			;;
		'linux')
			package_install linux-headers-generic
			;;
	esac

	# Install other dependencies
	package_install \
		gperf \
		libgoogle-perftools-dev \
		libpcap-dev

	# Ensure environment is correct.
	line "$PATHSFILE" 'RTE_TARGET' 'x86_64-native-linuxapp-gcc'
	line "$PATHSFILE" 'RTE_SDK' "$BUILDDIR/dpdk"

	# shellcheck source=../paths.sh
	. "$PATHSFILE"

	# Get, Patch and Compile
	if [ ! -f dpdk/.version ] || [ "$(cat dpdk/.version)" != "$DPDK_RELEASE" ]
	then
		# get sources
		rm -rf dpdk
		curl -s "https://fast.dpdk.org/rel/dpdk-$DPDK_RELEASE.tar.xz" | tar xJf -
		mv "dpdk-$DPDK_RELEASE" dpdk

		# patch
		cd dpdk
		for p in "$VNDSDIR"/setup/dpdk.*.patch;
		do
			patch -p 1 < "$p"
		done

		# Compile
		make config T=x86_64-native-linuxapp-gcc
		make install -j T=x86_64-native-linuxapp-gcc DESTDIR=.

		echo "$DPDK_RELEASE" > .version
	fi
}

clean_dpdk()
{
	cd "$BUILDDIR"
	rm -rf dpdk
}

source_install_z3()
{
	cd "$BUILDDIR"
	if [ -d 'z3/.git' ];
	then
		cd z3;
		git fetch && git checkout "$Z3_RELEASE"
	else
		git clone --depth 1 --branch "$Z3_RELEASE" https://github.com/Z3Prover/z3 "$BUILDDIR/z3"
		cd z3;
	fi

	if  [ ! -f "build/z3" ] || [ ! "z3-$(build/z3 --version | cut -f3 -d' ')" = "$Z3_RELEASE" ];	then
		python scripts/mk_make.py -p "$BUILDDIR/z3/build"
		cd build
		make -kj || make
		make install
	fi
}

clean_z3()
{
	cd "$BUILDDIR"
	rm -rf z3
}

source_install_llvm()
{
	package_install bison flex zlib1g-dev libncurses5-dev libpcap-dev
	# Python2 needs to be available as python for some configure scripts, which is not the case in Ubuntu 20.04
	if [ ! -e /usr/bin/python ] ; then
  		sudo ln -s /usr/bin/python2.7 /usr/bin/python
	fi

	line_multi "$PATHSFILE" 'PATH' "$BUILDDIR/llvm/build/bin:\$PATH"
	# shellcheck source=../paths.sh
	. "$PATHSFILE"

	cd "$BUILDDIR"

	# TODO: Optimize. Currently we clone and build from scratch even if source is present but hasn't been built
	if [ ! -f llvm/build/bin/clang-8 ] || [ ! -f llvm/build/bin/llvm-config ];
	then
		git clone --branch llvmorg-$LLVM_RELEASE --depth 1  \
		https://github.com/llvm/llvm-project "$BUILDDIR/llvm-project"
		mv "$BUILDDIR/llvm-project/llvm" "$BUILDDIR/llvm"
		mv "$BUILDDIR/llvm-project/clang" "$BUILDDIR/llvm/tools/clang"
		rm -rf "$BUILDDIR/llvm-project"
		cd llvm
	       	mkdir build
		cd build
		[ -f "Makefile" ] || \
			CXXFLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" \
			cmake ../
		make -j30
	fi
}

clean_llvm()
{
	cd "$BUILDDIR"
	rm -rf llvm
}

source_install_klee_uclibc()
{
	cd "$BUILDDIR"
	if [ -d 'klee-uclibc/.git' ];
	then
		cd klee-uclibc
		git fetch && git checkout "$KLEE_UCLIBC_RELEASE"
	else
		git clone --depth 1 --branch "$KLEE_UCLIBC_RELEASE" https://github.com/klee/klee-uclibc.git "$BUILDDIR/klee-uclibc";
		cd klee-uclibc
	fi

	./configure \
		--make-llvm-lib \
		--with-llvm-config="../llvm/build/bin/llvm-config" \
		--with-cc="../llvm/build/bin/clang"

	cp "$VNDSDIR/install/klee-uclibc.config" '.config'
	make -kj
}

clean_klee_uclibc()
{
	cd "$BUILDDIR"
	rm -rf klee-uclibc
}

source_install_klee()
{
	line "$PATHSFILE" 'KLEE_INCLUDE' "$BUILDDIR/klee/include"
	line_multi "$PATHSFILE" 'PATH' "$BUILDDIR/klee/build/bin:\$PATH"
	# shellcheck source=../paths.sh
	. "$PATHSFILE"

	cd "$BUILDDIR"
	if [ -d 'klee/.git' ];
	then
		cd klee
		git fetch && git checkout "$KLEE_RELEASE"
	else
		git clone --recurse-submodules https://github.com/bolt-perf-contracts/klee.git
		cd klee
		git checkout "$KLEE_RELEASE"
	fi

	./build.sh
}

clean_klee()
{
	cd "$BUILDDIR"
	rm -rf klee
}

bin_install_ocaml() {
	# we depend on an OCaml package that needs libgmp-dev
	package_install opam m4 libgmp-dev

	opam init -y
	eval "$(opam config env)"
	# Opam 1.x doesn't have "create", later versions require it but only the first time
	if opam --version | grep '^1.' >/dev/null ; then
		opam switch $OCAML_RELEASE
	else
		opam switch list
		if ! opam switch list 2>&1 | grep -Fq 4.06 ; then
			opam switch create $OCAML_RELEASE
		fi
	fi

	line_multi "$PATHSFILE" 'PATH' "$HOME/.opam/system/bin:\$PATH"
    # `|| :` at the end of the following command ensures that in the event the
    # init.sh script fails, the shell will not exit. opam suggests we do this.
	echo ". $HOME/.opam/opam-init/init.sh || :" >> "$PATHSFILE"
	. "$PATHSFILE"

	# Codegenerator dependencies.
	opam install goblint-cil core -y
	opam install ocamlfind num -y
	opam install ocamlfind sexplib menhir -y
}

clean_ocaml() {
	rm -rf $HOME/.opam
}

source_install_rs3() {
  package_install libsctp-dev
  if [ ! -e "$BUILDDIR/libr3s" ]; then
    git clone --depth 1 https://github.com/fchamicapereira/libr3s.git "$BUILDDIR/libr3s"
    pushd "$BUILDDIR/libr3s"
      rm -rf build
      mkdir build
      pushd build
        ../build.sh
        echo "export R3S_DIR=$BUILDDIR/libr3s" >> "$PATHSFILE"
        . "$PATHSFILE"
      popd
    popd
  fi
}

clean_rs3() {
  cd "$BUILDDIR"
	rm -rf rs3
}

## Constants
VNDSDIR="$(dirname "$(realpath "$0")")"
BUILDDIR="$(realpath -e "$VNDSDIR"/..)"
PATHSFILE="$BUILDDIR/paths.sh"
KERNEL_VER=$(uname -r | sed 's/-Microsoft//')
OS="$(detect_os)"

# Environment
check_sudo
package_sync

# Common dependencies
package_install \
	build-essential \
	curl \
	git \
	libgoogle-perftools-dev \
	python2.7 \
	python3 \
	python3-pip \
	parallel \
	gcc-multilib \
	graphviz \
  libpcap-dev \
	libnuma-dev \
	cmake \
  ca-certificates \
  software-properties-common \
  patch \
  wget \
  build-essential \
  cloc

# Clean things
clean_dpdk
clean_pin
clean_z3
clean_llvm
clean_klee_uclibc
clean_klee
clean_ocaml
clean_rs3

# Install things
source_install_dpdk
source_install_pin
source_install_z3
source_install_llvm
source_install_klee_uclibc
bin_install_ocaml
source_install_klee

GCC_RELEASE="5.4.0"
pushd "$BUILDDIR"
  if [ ! -e gcc-build ]; then
    wget -O gnu-keyring.gpg https://ftp.gnu.org/gnu/gnu-keyring.gpg
    wget -O gcc.tar.gz \
         "https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-$GCC_RELEASE.tar.gz"
    wget -O gcc.tar.gz.sig \
         "https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-$GCC_RELEASE.tar.gz.sig"

    gpg --verify --keyring ./gnu-keyring.gpg gcc.tar.gz.sig gcc.tar.gz

    tar xf gcc.tar.gz
    mv "gcc-$GCC_RELEASE" gcc
    rm gcc.tar.gz gcc.tar.gz.sig

    mkdir gcc-build
    pushd gcc-build
      ../gcc/configure --target=$NFOS_TARGET --prefix="$BUILDDIR/gcc-build" \
                       --disable-nls --enable-languages=c --without-headers
      make -j$(nproc) all-gcc
      make -j$(nproc) all-target-libgcc
      make -j$(nproc) install-gcc
      make -j$(nproc) install-target-libgcc
      make clean
      echo 'PATH='"$BUILDDIR/gcc-build/bin"':$PATH' >> "$PATHSFILE"
      . "$PATHSFILE"
    popd
  fi
popd

# LLVM required to build klee-uclibc
# (including the libc necessary to build NFOS)
sudo apt-get install -y bison flex zlib1g-dev libncurses5-dev \
                        libcap-dev python2.7

# Python2 needs to be available as python for some configure scripts, which is not the case in Ubuntu 20.04
if [ ! -e /usr/bin/python ] ; then
  sudo ln -s /usr/bin/python2.7 /usr/bin/python
fi

if [ ! -e "$BUILDDIR/llvm" ]; then
  git clone --branch llvmorg-3.4.2 --depth 1 https://github.com/llvm/llvm-project "$BUILDDIR/llvm-project"
  mv "$BUILDDIR/llvm-project/llvm" "$BUILDDIR/llvm"
  mv "$BUILDDIR/llvm-project/clang" "$BUILDDIR/llvm/tools/clang"
  mv "$BUILDDIR/llvm-project/libcxx" "$BUILDDIR/llvm/projects/libcxx"
  rm -rf "$BUILDDIR/llvm-project"
  pushd "$BUILDDIR/llvm"
    CXXFLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" \
        ./configure --enable-optimized --disable-assertions \
                    --enable-targets=host --with-python='/usr/bin/python2'
    make -j$(nproc)
    echo 'PATH='"$BUILDDIR/llvm/Release/bin"':$PATH' >> "$PATHSFILE"
    . "$PATHSFILE"
  popd
fi


# ==
# Z3
# ==

sudo apt-get install -y python2.7

# for Z3 ML bindings
# Num is required for Big_int
opam install ocamlfind num -y

if [ ! -e "$BUILDDIR/z3" ]; then
  git clone --depth 1 --branch z3-4.5.0 \
            https://github.com/Z3Prover/z3 "$BUILDDIR/z3"
  pushd "$BUILDDIR/z3"
    python2 scripts/mk_make.py --ml -p "$BUILDDIR/z3/build"
    pushd build
      make -k -j$(nproc) || true
      # -jN here may break the make (hidden deps or something)
      make
      make install
      # Weird, but required sometimes
      # Remove the outdated libz3.so
      sudo apt-get remove -y libz3-dev || true
      sudo rm -f /usr/lib/x86_64-linux-gnu/libz3.so || true
      sudo rm -f /usr/lib/x86_64-linux-gnu/libz3.so.4 || true
      sudo rm -f /usr/lib/libz3.so || true
      # Install the new libz3.so
      sudo ln -fs "$BUILDDIR/z3/build/libz3.so" "/usr/lib/libz3.so"
      sudo ldconfig
      # Install it in .opam as well, VeriFast wants it there...
      ln -fs /usr/lib/libz3.so ~/.opam/4.06.0/.
      echo "export Z3_DIR=$BUILDDIR/z3" >> "$PATHSFILE"
      . "$PATHSFILE"
    popd
  popd
fi

# ====
# KLEE
# ====

if [ ! -e "$BUILDDIR/klee-uclibc" ]; then
  git clone --depth 1 --branch klee_uclibc_v1.2 \
            https://github.com/klee/klee-uclibc.git "$BUILDDIR/klee-uclibc"
  pushd "$BUILDDIR/klee-uclibc"
    ./configure \
     --make-llvm-lib \
     --with-llvm-config="../llvm/Release/bin/llvm-config" \
     --with-cc="../llvm/Release/bin/clang"

    # Use our minimalistic config
    cp "$VNDSDIR/setup/klee-uclibc.config" '.config'

    # Use our patches
    for f in "$VNDSDIR/setup/uclibc/"* ; do
      cat "$f" >> "libc/stdio/$(basename "$f")"
    done

    make -j$(nproc)
  popd
fi

if [ ! -e "$BUILDDIR/klee" ]; then
  git clone --depth 1 https://github.com/fchamicapereira/vigor-klee.git "$BUILDDIR/klee"
  pushd "$BUILDDIR/klee"
    ./build.sh
    echo 'PATH='"$BUILDDIR/klee/Release/bin"':$PATH' >> "$PATHSFILE"
    echo "export KLEE_DIR=$BUILDDIR/klee" >> "$PATHSFILE"
    echo "export KLEE_INCLUDE=$BUILDDIR/klee/include" >> "$PATHSFILE"
    echo "export KLEE_BUILD_PATH=$BUILDDIR/klee/Release" >> "$PATHSFILE"
    . "$PATHSFILE"
  popd
fi
