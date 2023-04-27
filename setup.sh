#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

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
KLEE_UCLIBC_RELEASE='klee_uclibc_v1.2'
LLVM_RELEASE='3.4.2'
Z3_RELEASE='z3-4.5.0'
OCAML_RELEASE='4.06.0'

# Detect the running operating system
# stdout: 'windows', 'docker' or 'linux'
detect_os() {
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

## Constants
SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
BUILD_DIR="$SCRIPT_DIR/build"
PATHSFILE="$BUILD_DIR/paths.sh"
KERNEL_VER=$(uname -r | sed 's/-Microsoft//')
OS="$(detect_os)"

# Checks if a variable is set in a file. If it is not in the file, add it with
# given value, otherwise change the value to match the current one.
# $1 : the name of the variable
# $2 : the value to set
add_var_to_paths_file() {
	if grep "^export $1" "$PATHSFILE" >/dev/null;
	then
		# Using sed directly to change the value would be dangerous as
		# we would need to correctly escape the value, which is hard.
		sed -i "/^export $1/d" "$PATHSFILE"
	fi
	echo "export ${1}=${2}" >> "$PATHSFILE"
}

# Same as line, but without the unicity checks.
# $1 : the name of the file
# $2 : the name of the variable
# $3 : the value to set
add_var_to_paths_file_multiline() {
	if ! grep "^export ${1}=${2}" "$PATHSFILE" >/dev/null;
	then
		echo "export ${1}=${2}" >> "$PATHSFILE"
	fi
}

# Install arguments using system's package manager.
# XXX: Make the package manager depend on "$OS".
# shellcheck disable=SC2086
package_install() {
	# Concatenate arguments into a list
	old_ifs="$IFS"
	IFS=' '
	packages="$*"
	IFS="$old_ifs"

	sudo apt-get install -yqq $packages
}

# Update list of available packages.
# XXX: Make the package manager depend on "$OS".
package_sync() {
	sudo apt-get update -qq
}

source_paths_in_profile() {
	if ! grep "^source $PATHSFILE" ~/.profile >/dev/null;
	then
		echo "source $PATHSFILE" >> ~/.profile
	fi
}

create_paths_file() {
	rm -f $PATHSFILE > /dev/null 2>&1 || true
	touch $PATHSFILE
}

create_build_dir() {
	mkdir -p $BUILD_DIR
}

installation_setup() {
	create_build_dir
	create_paths_file
	source_paths_in_profile
}

# Checks if a variable is set in a file. If it is not in the file, add it with
# given value, otherwise change the value to match the current one.
# $1 : the name of the variable
# $2 : the value to set
add_var_to_paths_file()
{
	if grep "^export $1" "$PATHSFILE" >/dev/null;
	then
		# Using sed directly to change the value would be dangerous as
		# we would need to correctly escape the value, which is hard.
		sed -i "/^export $1/d" "$PATHSFILE"
	fi
	echo "export ${1}=${2}" >> "$PATHSFILE"
}

# Same as line, but without the unicity checks.
# $1 : the name of the variable
# $2 : the value to set
add_multiline_var_to_paths_file()
{
	if ! grep "^export ${1}=${2}" "$PATHSFILE" >/dev/null;
	then
		echo "export ${1}=${2}" >> "$PATHSFILE"
	fi
}

source_install_dpdk() {
	echo "Installing DPDK..."
	cd "$BUILD_DIR"

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
	add_var_to_paths_file 'RTE_TARGET' 'x86_64-native-linuxapp-gcc'
	add_var_to_paths_file 'RTE_SDK' "$BUILD_DIR/dpdk"

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
		for p in "$SCRIPT_DIR"/setup/dpdk.*.patch;
		do
			patch -p 1 < "$p"
		done

		# Compile
		make config T=x86_64-native-linuxapp-gcc MAKE_PAUSE=n
		make install -j T=x86_64-native-linuxapp-gcc MAKE_PAUSE=n DESTDIR=.

		echo "$DPDK_RELEASE" > .version
	fi
	echo "Done."
}

clean_dpdk() {
	cd "$BUILD_DIR"
	rm -rf dpdk
}

source_install_z3() {
	echo "Installing Z3..."
	cd "$BUILD_DIR"
	if [ -d 'z3/.git' ];
	then
		cd z3;
		git fetch && git checkout "$Z3_RELEASE"
	else
		git clone --depth 1 --branch "$Z3_RELEASE" https://github.com/Z3Prover/z3 "$BUILD_DIR/z3"
		cd z3;
	fi

	if  [ ! -f "build/z3" ] || [ ! "z3-$(build/z3 --version | cut -f3 -d' ')" = "$Z3_RELEASE" ];	then
		python3 scripts/mk_make.py -p "$BUILD_DIR/z3/build"
		cd build
		make -kj || make
		make install
	fi

	add_var_to_paths_file 'Z3_DIR' "$BUILD_DIR/z3"
	echo "Done."
}

clean_z3() {
	cd "$BUILD_DIR"
	rm -rf z3
}

source_install_llvm() {
	echo "Installing LLVM..."
	
	package_install bison flex zlib1g-dev libncurses5-dev libpcap-dev

	# Python2 needs to be available as python for some configure scripts, which is not the case in Ubuntu 20.04
	if [ ! -e /usr/bin/python ] ; then
  		sudo ln -s /usr/bin/python2.7 /usr/bin/python
	fi

	add_multiline_var_to_paths_file 'PATH' "$BUILD_DIR/llvm/Release/bin:\$PATH"
	# shellcheck source=../paths.sh
	. "$PATHSFILE"

	cd "$BUILD_DIR"

	# TODO: Optimize. Currently we clone and build from scratch even if source is present but hasn't been built
	if [ ! -f llvm/Release/bin/clang-8 ] || [ ! -f llvm/Release/bin/llvm-config ];
	then
		git clone --branch llvmorg-$LLVM_RELEASE --depth 1  \
			https://github.com/llvm/llvm-project "$BUILD_DIR/llvm-project"

		mv "$BUILD_DIR/llvm-project/llvm" "$BUILD_DIR/llvm"
		mv "$BUILD_DIR/llvm-project/clang" "$BUILD_DIR/llvm/tools/clang"
		mv "$BUILD_DIR/llvm-project/libcxx" "$BUILD_DIR/llvm/projects/libcxx"

		rm -rf "$BUILD_DIR/llvm-project"
		cd llvm
		CXXFLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" \
                ./configure --enable-optimized --disable-assertions \
                    --enable-targets=host --with-python='/usr/bin/python'
		REQUIRES_RTTI=1 make -j$(nproc)
	fi
	echo "Done."
}

clean_llvm() {
	cd "$BUILD_DIR"
	rm -rf llvm
}

source_install_klee_uclibc() {
	echo "Installing KLEE uclibc..."
	cd "$BUILD_DIR"

	# If there is a single version of GCC and it's a single digit, as in e.g. GCC 9 on Ubuntu 20.04,
	# our clang won't detect it because it expects a version in the format x.y.z with all components
	# so let's create a symlink
	# 0 -> nothing, 2 -> a single dot (because there is also \0)
	GCC_VER=$(ls -1 /usr/lib/gcc/x86_64-linux-gnu/ | sort -V | tail -n 1)
	
	if [ $(echo $GCC_VER | grep -Fo . | wc -c) -eq 0 ]; then
		sudo ln -s "/usr/lib/gcc/x86_64-linux-gnu/$GCC_VER" "/usr/lib/gcc/x86_64-linux-gnu/$GCC_VER.0.0" ;
	fi

	if [ $(echo $GCC_VER | grep -Fo . | wc -c) -eq 2 ]; then
		sudo ln -s "/usr/lib/gcc/x86_64-linux-gnu/$GCC_VER" "/usr/lib/gcc/x86_64-linux-gnu/$GCC_VER.0" ;
	fi

	git clone --depth 1 --branch "$KLEE_UCLIBC_RELEASE" \
		https://github.com/klee/klee-uclibc.git "$BUILD_DIR/klee-uclibc";
	cd klee-uclibc

	./configure \
		--make-llvm-lib \
		--with-llvm-config="$BUILD_DIR/llvm/Release/bin/llvm-config" \
		--with-cc="$BUILD_DIR/llvm/Release/bin/clang"

	cp "$SCRIPT_DIR/setup/klee-uclibc.config" '.config'

	# Use our patches
    for f in "$SCRIPT_DIR/setup/uclibc/"* ; do
    	cat "$f" >> "libc/stdio/$(basename "$f")"
    done		
	
	make -kj
	echo "Done."
}

clean_klee_uclibc() {
	cd "$BUILD_DIR"
	rm -rf klee-uclibc
}

source_install_klee() {
	echo "Installing KLEE..."

	add_var_to_paths_file 'KLEE_DIR' "$BUILD_DIR/klee"
	add_var_to_paths_file 'KLEE_INCLUDE' "$BUILD_DIR/klee/include"
	add_var_to_paths_file 'KLEE_BUILD_PATH' "$BUILD_DIR/klee/Release"

	add_multiline_var_to_paths_file 'PATH' "$BUILD_DIR/klee/Release/bin:\$PATH"

	# shellcheck source=../paths.sh
	. "$PATHSFILE"

	cd "$BUILD_DIR"
	git clone --recurse-submodules https://github.com/fchamicapereira/maestro-klee.git klee

	cd klee
	./build.sh
	echo "Done."
}

clean_klee() {
	cd "$BUILD_DIR"
	rm -rf klee
}

bin_install_ocaml() {
	echo "Installing OCaml..."
	# we depend on an OCaml package that needs libgmp-dev
	package_install opam m4 libgmp-dev

	opam init --disable-sandboxing -y
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

	add_multiline_var_to_paths_file 'PATH' "$HOME/.opam/system/bin:\$PATH"
    # `|| :` at the end of the following command ensures that in the event the
    # init.sh script fails, the shell will not exit. opam suggests we do this.
	echo ". $HOME/.opam/opam-init/init.sh || :" >> "$PATHSFILE"
	. "$PATHSFILE"

	# Codegenerator dependencies.
	opam install goblint-cil core -y
	opam install ocamlfind num -y
	opam install ocamlfind sexplib menhir -y
	echo "Done."
}

clean_ocaml() {
	rm -rf $HOME/.opam
}

source_install_rs3() {
	echo "Installing RS3..."
	package_install libsctp-dev
	if [ ! -e "$BUILD_DIR/libr3s" ]; then
		git clone --depth 1 https://github.com/fchamicapereira/libr3s.git "$BUILD_DIR/libr3s"
		pushd "$BUILD_DIR/libr3s"
			rm -rf build
			mkdir build
			pushd build
				../build.sh
				echo "export R3S_DIR=$BUILD_DIR/libr3s" >> "$PATHSFILE"
				. "$PATHSFILE"
			popd
		popd
	fi
	echo "Done."
}

clean_rs3() {
	cd "$BUILD_DIR"
	rm -rf rs3
}

# Environment
package_sync
installation_setup

# Common dependencies
package_install \
	build-essential \
	curl \
	wget \
	git \
	wget \
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
	cloc \
	time

# Clean things
clean_dpdk
clean_z3
clean_llvm
clean_klee_uclibc
clean_ocaml
clean_klee
clean_rs3

# Install things
source_install_dpdk
source_install_z3
source_install_llvm
source_install_klee_uclibc
source_install_klee
bin_install_ocaml
source_install_rs3
