#!/usr/bin/env bash

set -e
set -x

if [ ! -d "$1/lightning" -o "$2" != "true" -a "$2" != "false" ]; then
	echo "USAGE: $0 path-to-rust-lightning allow-std"
	echo "allow-std must be either 'true' or 'false' to indicate if we should be built relying on time and pthread support"
	exit 1
fi

SKIP_TESTS_ARGUMENT=$3
RUN_CPP_TESTS=true

if [ ! -z "$SKIP_TESTS_ARGUMENT" ]; then
  if [ "$SKIP_TESTS_ARGUMENT" != "skip-tests" ]; then
    echo "To skip tests, usage must be: $0 path-to-rust-lightning allow-std skip-tests"
    exit 1
  else
    RUN_CPP_TESTS=false
  fi
fi

export LC_ALL=C

# On reasonable systems, we can use realpath here, but OSX is a diva with 20-year-old software.
ORIG_PWD="$(pwd)"
cd "$1"
LIGHTNING_PATH="$(pwd)"
LIGHTNING_GIT="$(git describe --tag --dirty --abbrev=16)"
cd "$ORIG_PWD"

# Generate (and reasonably test) C bindings

# First we set various compiler flags...
HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"
ENV_TARGET=$(echo $HOST_PLATFORM | sed 's/-/_/g')

# Set path to include our rustc wrapper as well as cbindgen
export LDK_RUSTC_PATH="$(which rustc)"
export RUSTC="$(pwd)/deterministic-build-wrappers/rustc"
PATH="$PATH:~/.cargo/bin"

# Set up CFLAGS and RUSTFLAGS vars appropriately for building libsecp256k1 and demo apps...
BASE_CFLAGS="" # CFLAGS for libsecp256k1
LOCAL_CFLAGS="" # CFLAGS for demo apps

# Remap paths so that our builds are deterministic
BASE_RUSTFLAGS="--cfg=c_bindings --remap-path-prefix $LIGHTNING_PATH=rust-lightning --remap-path-prefix $(pwd)=ldk-c-bindings --remap-path-prefix $HOME/.cargo="

# If the C compiler supports it, also set -ffile-prefix-map
echo "int main() {}" > genbindings_path_map_test_file.c
clang -o /dev/null -ffile-prefix-map=$HOME/.cargo= genbindings_path_map_test_file.c > /dev/null 2>&1 &&
export BASE_CFLAGS="-ffile-prefix-map=$HOME/.cargo="

BASE_CFLAGS="$BASE_CFLAGS -frandom-seed=42"
LOCAL_CFLAGS="-Wall -Wno-nullability-completeness -pthread -Iinclude/"

HOST_OSX=false
if [ "$HOST_PLATFORM" = "x86_64-apple-darwin" ]; then
	HOST_OSX=true
elif [ "$HOST_PLATFORM" = "aarch64-apple-darwin" ]; then
	HOST_OSX=true
fi

BASE_HOST_CFLAGS="$BASE_CFLAGS"

if [ "$MACOS_SDK" = "" -a "$HOST_OSX" = "true" ]; then
	MACOS_SDK="$(xcrun --show-sdk-path)"
	[ "$MACOS_SDK" = "" ] && exit 1
fi

if [ "$MACOS_SDK" != "" ]; then
	export MACOSX_DEPLOYMENT_TARGET=10.9
	BASE_HOST_OSX_CFLAGS="$BASE_HOST_CFLAGS -isysroot$MACOS_SDK -mmacosx-version-min=10.9"
	export CFLAGS_aarch64_apple_darwin="$BASE_HOST_OSX_CFLAGS --target=aarch64-apple-darwin -mcpu=apple-a14"
	export CFLAGS_x86_64_apple_darwin="$BASE_HOST_OSX_CFLAGS --target=x86_64-apple-darwin -march=sandybridge -mtune=sandybridge"
	if [ "$HOST_OSX" = "true" ]; then
		LOCAL_CFLAGS="$LOCAL_CFLAGS --target=$HOST_PLATFORM -isysroot$MACOS_SDK -mmacosx-version-min=10.9"
		BASE_HOST_CFLAGS="$BASE_HOST_OSX_CFLAGS --target=$HOST_PLATFORM"
	fi
fi

rm genbindings_path_map_test_file.c

case "$ENV_TARGET" in
	"x86_64"*)
		export RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=sandybridge"
		export BASE_HOST_CFLAGS="$BASE_HOST_CFLAGS -march=sandybridge -mtune=sandybridge"
		export CFLAGS_$ENV_TARGET="$BASE_HOST_CFLAGS"
		;;
	"aarch64_apple_darwin")
		export RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14"
		export BASE_HOST_CFLAGS="$BASE_HOST_CFLAGS -mcpu=apple-a14"
		export CFLAGS_$ENV_TARGET="$BASE_HOST_CFLAGS"
		;;
	*)
		# Assume this isn't targeted at another host and build for the host's CPU.
		export RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=native"
		export BASE_HOST_CFLAGS="$BASE_HOST_CFLAGS -march=native -mtune=native"
		export CFLAGS_$ENV_TARGET="$BASE_HOST_CFLAGS"
		;;
esac

# First build the latest c-bindings-gen binary
cd c-bindings-gen && cargo build --release && cd ..

# Then wipe all the existing C bindings (because we're being run in the right directory)
# note that we keep the few manually-generated files first:
mv lightning-c-bindings/src/c_types/mod.rs ./
mv lightning-c-bindings/src/bitcoin ./

# Before we try to sed the Cargo.toml, generate version define tags
# (ignoring any files that we're about to generate)

git checkout lightning-c-bindings/src
git checkout lightning-c-bindings/include
BINDINGS_GIT="$(git describe --tag --dirty --abbrev=16)"
echo "$(cat <<EOF
#ifndef _LDK_HEADER_VER
static inline int _ldk_strncmp(const char *s1, const char *s2, uint64_t n) {
	if (n && *s1 != *s2) return 1;
	while (n && *s1 != 0 && *s2 != 0) {
		s1++; s2++; n--;
		if (n && *s1 != *s2) return 1;
	}
	return 0;
}

#define _LDK_HEADER_VER "${LIGHTNING_GIT}"
#define _LDK_C_BINDINGS_HEADER_VER "${BINDINGS_GIT}"
static inline const char* check_get_ldk_version() {
	LDKStr bin_ver = _ldk_get_compiled_version();
	if (_ldk_strncmp(_LDK_HEADER_VER, (const char*)bin_ver.chars, bin_ver.len) != 0) {
	// Version mismatch, we don't know what we're running!
		return 0;
	}
	return _LDK_HEADER_VER;
}
static inline const char* check_get_ldk_bindings_version() {
	LDKStr bin_ver = _ldk_c_bindings_get_compiled_version();
	if (_ldk_strncmp(_LDK_C_BINDINGS_HEADER_VER, (const char*)bin_ver.chars, bin_ver.len) != 0) {
	// Version mismatch, we don't know what we're running!
		return 0;
	}
	return _LDK_C_BINDINGS_HEADER_VER;
}
#endif /* _LDK_HEADER_VER */
EOF
)" > lightning-c-bindings/include/ldk_ver.h

rm -rf lightning-c-bindings/src

mkdir -p lightning-c-bindings/src/{c_types,lightning}
mv ./mod.rs lightning-c-bindings/src/c_types/
mv ./bitcoin lightning-c-bindings/src/

# Finally, run the c-bindings-gen binary, building fresh bindings.
OUT="$(pwd)/lightning-c-bindings/src"
OUT_TEMPL="$(pwd)/lightning-c-bindings/src/c_types/derived.rs"
OUT_F="$(pwd)/lightning-c-bindings/include/ldk_rust_types.h"
OUT_CPP="$(pwd)/lightning-c-bindings/include/lightningpp.hpp"
BIN="$(pwd)/c-bindings-gen/target/release/c-bindings-gen"

function is_gnu_sed(){
  sed --version >/dev/null 2>&1
}

function add_crate() {
	pushd "$LIGHTNING_PATH/$1"
	RUSTC_BOOTSTRAP=1 cargo rustc --profile=check -Z avoid-dev-deps --no-default-features $3 -- --cfg=c_bindings -Zunpretty=expanded > /tmp/$1-crate-source.txt
	popd
	if [ "$HOST_OSX" = "true" ]; then
		sed -i".original" "1i\\
pub mod $2 {
" /tmp/$1-crate-source.txt
	else
		sed -i "1ipub mod $2 {\n" /tmp/$1-crate-source.txt
	fi
	echo "}" >> /tmp/$1-crate-source.txt
	cat /tmp/$1-crate-source.txt >> /tmp/crate-source.txt
	rm /tmp/$1-crate-source.txt
	if is_gnu_sed; then
		sed -E -i 's|#*'$1' = \{ .*|'$1' = \{ path = "'"$LIGHTNING_PATH"'/'$1'", default-features = false }|' lightning-c-bindings/Cargo.toml
	else
		# OSX sed is for some reason not compatible with GNU sed
		sed -E -i '' 's|#*'$1' = \{ .*|'$1' = \{ path = "'"$LIGHTNING_PATH"'/'$1'", default-features = false }|' lightning-c-bindings/Cargo.toml
	fi
}

function drop_crate() {
	if is_gnu_sed; then
		sed -E -i 's|'$1' = \{ (.*)|#'$1' = \{ \1|' lightning-c-bindings/Cargo.toml
	else
		# OSX sed is for some reason not compatible with GNU sed
		sed -E -i '' 's|'$1' = \{ (.*)|#'$1' = \{ \1|' lightning-c-bindings/Cargo.toml
	fi
}

echo > /tmp/crate-source.txt
if [ "$2" = "true" ]; then
	add_crate lightning lightning --features=std
	add_crate "lightning-persister" "lightning_persister"
	add_crate "lightning-background-processor" "lightning_background_processor" --features=std
	add_crate "lightning-invoice" "lightning_invoice" --features=std
	add_crate "lightning-rapid-gossip-sync" "lightning_rapid_gossip_sync" --features=std
	CARGO_BUILD_ARGS="--features=std"
else
	add_crate lightning lightning --features=no-std
	drop_crate "lightning-persister"
	add_crate "lightning-background-processor" "lightning_background_processor" --features=no-std
	add_crate "lightning-rapid-gossip-sync" "lightning_rapid_gossip_sync" --features=no-std
	add_crate "lightning-invoice" "lightning_invoice" --features=no-std
	CARGO_BUILD_ARGS="--features=no-std"
fi

cat /tmp/crate-source.txt | RUST_BACKTRACE=1 "$BIN" "$OUT/" "$OUT_TEMPL" "$OUT_F" "$OUT_CPP"

echo "$(cat <<EOF
#[no_mangle]
pub extern "C" fn _ldk_get_compiled_version() -> crate::c_types::Str {
	"${LIGHTNING_GIT}".into()
}
#[no_mangle]
pub extern "C" fn _ldk_c_bindings_get_compiled_version() -> crate::c_types::Str {
	"${BINDINGS_GIT}".into()
}
EOF
)" >> lightning-c-bindings/src/version.rs

# Now cd to lightning-c-bindings, build the generated bindings, and call cbindgen to build a C header file
cd lightning-c-bindings

RUSTFLAGS="$RUSTFLAGS --cfg=test_mod_pointers" cargo build $CARGO_BUILD_ARGS
if [ "$CFLAGS_aarch64_apple_darwin" != "" -a "$HOST_OSX" = "true" ]; then
	RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14" cargo build $CARGO_BUILD_ARGS --target aarch64-apple-darwin
fi
cbindgen -v --config cbindgen.toml -o include/lightning.h >/dev/null 2>&1

# cbindgen is relatively braindead when exporting typedefs -
# it happily exports all our typedefs for private types, even with the
# generics we specified in C mode! So we drop all those types manually here.
if is_gnu_sed; then
	sed -i 's/typedef LDKnative.*Import.*LDKnative.*;//g' include/lightning.h

	# UnsafeCell is `repr(transparent)` so should be ignored here
	sed -i 's/LDKUnsafeCell<\(.*\)> /struct \1 /g' include/lightning.h

	# stdlib.h doesn't exist in clang's wasm sysroot, and cbindgen
	# doesn't actually use it anyway, so drop the import.
	sed -i 's/#include <stdlib.h>/#include "ldk_rust_types.h"/g' include/lightning.h
else
	# OSX sed is for some reason not compatible with GNU sed
	sed -i '' 's/typedef LDKnative.*Import.*LDKnative.*;//g' include/lightning.h

	# UnsafeCell is `repr(transparent)` so should be ignored by cbindgen
	sed -i '' 's/LDKUnsafeCell<\(.*\)> /struct \1 /g' include/lightning.h

	# stdlib.h doesn't exist in clang's wasm sysroot, and cbindgen
	# doesn't actually use it anyway, so drop the import.
	sed -i '' 's/#include <stdlib.h>/#include "ldk_rust_types.h"/g' include/lightning.h
fi

# Build C++ class methods which call trait methods
echo "Updating C++ header, this may take some time, especially on macOS"
set +x # Echoing every command is very verbose here
OLD_IFS="$IFS"
export IFS=''
echo '#include <string.h>' > include/lightningpp_new.hpp
echo 'namespace LDK {' >> include/lightningpp_new.hpp
echo '// Forward declarations' >> include/lightningpp_new.hpp
cat include/lightningpp.hpp | sed -n 's/class \(.*\) {/class \1;/p' >> include/lightningpp_new.hpp
echo '' >> include/lightningpp_new.hpp

DECLS=""
while read LINE; do
	case "$LINE" in
		"#include <string.h>")
			# We already printed this above.
			;;
		"namespace LDK {")
			# We already printed this above.
			;;
		"}")
			# We'll print this at the end
			;;
		"XXX"*)
			NEW_STRUCT_NAME="$(echo "$LINE" | awk '{ print $2 }')"
			if [ "$NEW_STRUCT_NAME" != "$STRUCT_NAME" ]; then
				STRUCT_CONTENTS="$(cat include/lightning.h  | sed -n -e "/struct LDK$NEW_STRUCT_NAME/{:s" -e "/\} LDK$NEW_STRUCT_NAME;/!{N" -e "b s" -e "}" -e p -e "}")"
			fi
			STRUCT_NAME="$NEW_STRUCT_NAME"
			METHOD_NAME="$(echo "$LINE" | awk '{ print $3 }')"
			METHOD="$(echo "$STRUCT_CONTENTS" | grep "(\*$METHOD_NAME)")"
			if [ "$METHOD" = "" ]; then
				echo "Unable to find method declaration for $LINE"
				exit 1
			fi
			RETVAL="$(echo "$METHOD" | sed 's/[ ]*\([A-Za-z0-9 _]*\)(\*\(.*\)).*/\1/' | sed -E 's/^(struct|enum) LDK/LDK::/g' | tr -d ' ')"
			[ "$RETVAL" = "LDK::SecretKey" ] && RETVAL="LDKSecretKey"
			[ "$RETVAL" = "LDK::PublicKey" ] && RETVAL="LDKPublicKey"
			[ "$RETVAL" = "LDK::ThirtyTwoBytes" ] && RETVAL="LDKThirtyTwoBytes"
			PARAMS="$(echo "$METHOD" | sed 's/.*(\*.*)(\(const \)*void \*this_arg\(, \)*\(.*\));/\3/')"

			echo -e "\tinline $RETVAL $METHOD_NAME($PARAMS);" >> include/lightningpp_new.hpp
			DECLS="$DECLS"$'\n'"inline $RETVAL $STRUCT_NAME::$METHOD_NAME($PARAMS) {"

			DECLS="$DECLS"$'\n'$'\t'
			[ "$RETVAL" != "void" ] && DECLS="$DECLS$RETVAL ret = "
			DECLS="$DECLS(self.$METHOD_NAME)(self.this_arg"

			IFS=','; for PARAM in $PARAMS; do
				DECLS="$DECLS, "
				DECLS="$DECLS$(echo $PARAM | sed 's/.* (*\**\([a-zA-Z0-9_]*\)\()[\[0-9\]*]\)*/\1/')"
			done
			IFS=''

			DECLS="$DECLS);"
			[ "$RETVAL" != "void" ] && DECLS="$DECLS"$'\n'$'\t'"return ret;"
			DECLS="$DECLS"$'\n'"}"
			;;
		*)
			echo "$LINE" >> include/lightningpp_new.hpp
	esac
done < include/lightningpp.hpp
echo "$DECLS" >> include/lightningpp_new.hpp
echo "}" >> include/lightningpp_new.hpp
export IFS="$OLD_IFS"
set -x
mv include/lightningpp_new.hpp include/lightningpp.hpp

if $RUN_CPP_TESTS; then
  # Finally, sanity-check the generated C and C++ bindings with demo apps:
  # Naively run the C demo app:
  gcc $LOCAL_CFLAGS -Wall -g -pthread demo.c target/debug/libldk.a -ldl -lm
  ./a.out

  # And run the C++ demo app
  if [ "$2" = "true" ]; then
    g++ $LOCAL_CFLAGS -std=c++11 -Wall -g -pthread demo.cpp -Ltarget/debug/ -lldk -ldl
    LD_LIBRARY_PATH=target/debug/ ./a.out > /dev/null
  fi

  # Finally, run the C++ demo app with our native networking library
  # in valgrind to test memory model correctness and lack of leaks.
  gcc $LOCAL_CFLAGS -fPIC -std=c99 -Wall -g -pthread -I../ldk-net ../ldk-net/ldk_net.c -c -o ldk_net.o
  if [ "$2" = "true" ]; then
    g++ $LOCAL_CFLAGS -std=c++11 -Wall -g -pthread -DREAL_NET -I../ldk-net ldk_net.o demo.cpp target/debug/libldk.a -ldl -lm
    if [ -x "`which valgrind`" -a "$(uname -m)" != "ppc64le" ]; then
      valgrind --error-exitcode=4 --memcheck:leak-check=full --show-leak-kinds=all ./a.out
      echo
    else
      echo "WARNING: Please install valgrind for more testing"
      ./a.out
    fi
  fi


  # Test a statically-linked C++ version, tracking the resulting binary size and runtime
  # across debug, LTO, and cross-language LTO builds (using the same compiler each time).
  if [ "$2" = "true" ]; then
    clang++ $LOCAL_CFLAGS -std=c++11 demo.cpp target/debug/libldk.a -ldl
    strip ./a.out
    time ./a.out
    echo " C++ Bin size and runtime w/o optimization:"
    ls -lha a.out
  fi

else
  echo "Skipping tests!"
fi

function REALLY_PIN_CC {
	# -Zbuild-std fails if we have any dependencies of build-deps, which
	# cc added in 1.0.80, thus we pin back to 1.0.79 to avoid that.
	cargo update -p cc --precise "1.0.79" --verbose
	( RUSTC_BOOTSTRAP=1 cargo build --features=std -v --release --target x86_64-apple-darwin -Zbuild-std=std,panic_abort > /dev/null 2>&1 ) || echo -n
	( RUSTC_BOOTSTRAP=1 cargo build --features=std -v --release --target aarch64-apple-darwin -Zbuild-std=std,panic_abort > /dev/null 2>&1 ) || echo -n
	# Sadly, std also depends on cc, and we can't pin it in that tree
	# directly. Instead, we have to delete the file out of the cargo
	# registry and build --offline to avoid it using the latest version.
	NEW_CC_DEP="$CARGO_HOME"
	[ "$NEW_CC_DEP" = "" ] && NEW_CC_DEP="$HOME"
	[ -d "$NEW_CC_DEP/.cargo/registry/cache/"github.com-* ] && CARGO_REGISTRY_CACHE="$NEW_CC_DEP/.cargo/registry/cache/"github.com-*
	[ -d "$NEW_CC_DEP/.cargo/registry/cache/"index.crates.io-* ] && CARGO_REGISTRY_CACHE="$NEW_CC_DEP/.cargo/registry/cache/"index.crates.io-*
	if [ -d "$CARGO_REGISTRY_CACHE" ]; then
		if [ -f "$CARGO_REGISTRY_CACHE/cc-1.0.79.crate" ]; then
			mv "$CARGO_REGISTRY_CACHE/cc-1.0.79.crate" ./
		fi
		rm -f "$CARGO_REGISTRY_CACHE/"*/cc-*.crate
		[ -f ./cc-1.0.79.crate ] && mv ./cc-1.0.79.crate "$CARGO_REGISTRY_CACHE/"
	else
		echo "Couldn't find cargo cache, build-std builds are likely to fail!"
	fi
}

# Then, check with memory sanitizer, if we're on Linux and have rustc nightly
if [ "$HOST_PLATFORM" = "x86_64-unknown-linux-gnu" ]; then
	if cargo +nightly --version >/dev/null 2>&1; then
		LLVM_V=$(rustc +nightly --version --verbose | grep "LLVM version" | awk '{ print substr($3, 0, 2); }')
		if [ -x "$(which clang-$LLVM_V)" ]; then
			cargo +nightly clean

			REALLY_PIN_CC
			cargo +nightly rustc --offline $CARGO_BUILD_ARGS -Zbuild-std=std,panic_abort --target x86_64-unknown-linux-gnu -v -- -Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes
			mv target/x86_64-unknown-linux-gnu/debug/libldk.* target/debug/

			# Sadly, std doesn't seem to compile into something that is memsan-safe as of Aug 2020,
			# so we'll always fail, not to mention we may be linking against git rustc LLVM which
			# may differ from clang-llvm, so just allow everything here to fail.
			set +e

			# First the C demo app...
			clang-$LLVM_V $LOCAL_CFLAGS -fsanitize=memory -fsanitize-memory-track-origins -g demo.c target/debug/libldk.a -ldl
			./a.out

			if [ "$2" = "true" ]; then
				# ...then the C++ demo app
				clang++-$LLVM_V $LOCAL_CFLAGS -std=c++11 -fsanitize=memory -fsanitize-memory-track-origins -g demo.cpp target/debug/libldk.a -ldl
				./a.out >/dev/null

				# ...then the C++ demo app with the ldk_net network implementation
				clang-$LLVM_V $LOCAL_CFLAGS -std=c99 -fsanitize=memory -fsanitize-memory-track-origins -g -I../ldk-net ../ldk-net/ldk_net.c -c -o ldk_net.o
				clang++-$LLVM_V $LOCAL_CFLAGS -std=c++11 -fsanitize=memory -fsanitize-memory-track-origins -g -DREAL_NET -I../ldk-net ldk_net.o demo.cpp target/debug/libldk.a -ldl
				./a.out >/dev/null
			fi

			# restore exit-on-failure
			set -e
		else
			echo "WARNING: Can't use memory sanitizer without clang-$LLVM_V"
		fi
	else
		echo "WARNING: Can't use memory sanitizer without rustc nightly"
	fi
else
	echo "WARNING: Can't use memory sanitizer on non-Linux, non-x86 platforms"
fi

RUSTC_LLVM_V=$(rustc --version --verbose | grep "LLVM version" | awk '{ print substr($3, 0, 2); }')

if [ "$HOST_OSX" = "true" ]; then
	# Apple is special, as always, and their versions of clang aren't
	# compatible with upstream LLVM.
	if [ "$(clang --version | grep 'Apple clang')" != "" ]; then
		echo "Apple clang isn't compatible with upstream clang, install upstream clang"
		CLANG_LLVM_V="0"
	else
		CLANG_LLVM_V=$(clang --version | head -n1 | awk '{ print substr($3, 0, 2); }')
		if [ -x "$(which ld64.lld)" ]; then
			LLD_LLVM_V="$(ld64.lld --version | awk '{ print substr($2, 0, 2); }')"
		fi
	fi
else
	# Output is something like clang version 17.0.3 (Fedora 17.0.3-1.fc39) or Debian clang version 14.0.6
	CLANG_LLVM_V=$(clang --version | head -n1 | awk '{ print substr($3, 0, 2); }')
	[ "$CLANG_LLVM_V" = "ve" ] && CLANG_LLVM_V=$(clang --version | head -n1 | awk '{ print substr($4, 0, 2); }')
	if [ -x "$(which ld.lld)" ]; then
		LLD_LLVM_V="$(ld.lld --version | awk '{ print $2; }')"
		if [ "$LLD_LLVM_V" = "LLD" ]; then # eg if the output is "Debian LLD ..."
			LLD_LLVM_V="$(ld.lld --version | awk '{ print substr($3, 0, 2); }')"
		else
			LLD_LLVM_V="$(ld.lld --version | awk '{ print substr($2, 0, 2); }')"
		fi
	fi
fi


if [ "$CLANG_LLVM_V" = "$RUSTC_LLVM_V" ]; then
	CLANG=clang
	CLANGPP=clang++
	if [ "$LLD_LLVM_V" = "$CLANG_LLVM_V" ]; then
		LLD=lld
	fi
elif [ -x "$(which clang-$RUSTC_LLVM_V)" ]; then
	CLANG="$(which clang-$RUSTC_LLVM_V)"
	CLANGPP="$(which clang++-$RUSTC_LLVM_V || echo clang++)"
	if [ "$($CLANG --version)" != "$($CLANGPP --version)" ]; then
		echo "$CLANG and $CLANGPP are not the same version of clang!"
		unset CLANG
		unset CLANGPP
	fi
	if [ "$LLD_LLVM_V" != "$RUSTC_LLVM_V" ]; then
		LLD="lld"
		[ -x "$(which lld-$RUSTC_LLVM_V)" ] && LLD="lld-$RUSTC_LLVM_V"
		LLD_LLVM_V="$(ld.lld-$RUSTC_LLVM_V --version | awk '{ print $2; }')"
		if [ "$LLD_LLVM_V" = "LLD" ]; then # eg if the output is "Debian LLD ..."
			LLD_LLVM_V="$(ld.lld-$RUSTC_LLVM_V --version | awk '{ print substr($3, 0, 2); }')"
		else
			LLD_LLVM_V="$(ld.lld-$RUSTC_LLVM_V --version | awk '{ print substr($2, 0, 2); }')"
		fi
		if [ "$LLD_LLVM_V" != "$RUSTC_LLVM_V" ]; then
			echo "Could not find a workable version of lld, not using cross-language LTO"
			unset LLD
		fi
	fi
fi

if [ "$CLANG" != "" -a "$CLANGPP" = "" ]; then
	echo "WARNING: It appears you have a clang-$RUSTC_LLVM_V but not clang++-$RUSTC_LLVM_V. This is common, but leaves us unable to compile C++ with LLVM $RUSTC_LLVM_V"
	echo "You should create a symlink called clang++-$RUSTC_LLVM_V pointing to $CLANG in $(dirname $CLANG)"
fi

# Finally, if we're on Linux, build the final debug binary with address sanitizer (and leave it there)
if [ "$HOST_PLATFORM" = "x86_64-unknown-linux-gnu" ]; then
	if [ "$CLANGPP" != "" ]; then
		if is_gnu_sed; then
			sed -i.bk 's/,"cdylib"]/]/g' Cargo.toml
		else
			# OSX sed is for some reason not compatible with GNU sed
			sed -i .bk 's/,"cdylib"]/]/g' Cargo.toml
		fi

		RUSTFLAGS="$RUSTFLAGS --cfg=test_mod_pointers" RUSTC_BOOTSTRAP=1 cargo rustc $CARGO_BUILD_ARGS -v -- -Zsanitizer=address -Cforce-frame-pointers=yes || ( mv Cargo.toml.bk Cargo.toml; exit 1)
		mv Cargo.toml.bk Cargo.toml

		# Sadly, address sanitizer appears to have had some regression on Debian and now fails to
		# get past its init stage, so we disable it for now.

		# First the C demo app...
		#$CLANG $LOCAL_CFLAGS -fsanitize=address -g demo.c target/debug/libldk.a -ldl
		#ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out

		#if [ "$2" = "true" ]; then
		#	# ...then the C++ demo app
		#	$CLANGPP $LOCAL_CFLAGS -std=c++11 -fsanitize=address -g demo.cpp target/debug/libldk.a -ldl
		#	ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out >/dev/null

		#	# ...then the C++ demo app with the ldk_net network implementation
		#	$CLANG $LOCAL_CFLAGS -fPIC -fsanitize=address -g -I../ldk-net ../ldk-net/ldk_net.c -c -o ldk_net.o
		#	$CLANGPP $LOCAL_CFLAGS -std=c++11 -fsanitize=address -g -DREAL_NET -I../ldk-net ldk_net.o demo.cpp target/debug/libldk.a -ldl
		#	ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out >/dev/null
		#fi
	else
		echo "WARNING: Please install clang-$RUSTC_LLVM_V and clang++-$RUSTC_LLVM_V to build with address sanitizer"
	fi
else
	echo "WARNING: Can't use address sanitizer on non-Linux, non-x86 platforms"
fi

# Now build with LTO on on both C++ and rust, but without cross-language LTO:
# Clear stale release build artifacts from previous runs
cargo clean --release
CARGO_PROFILE_RELEASE_LTO=true RUSTFLAGS="$RUSTFLAGS -C embed-bitcode=yes -C lto" cargo build $CARGO_BUILD_ARGS -v --release
if [ "$2" = "true" ]; then
	clang++ $LOCAL_CFLAGS -std=c++11 -O2 demo.cpp target/release/libldk.a -ldl
fi

strip ./a.out
time ./a.out
echo "C++ Bin size and runtime with only RL (LTO) optimized:"
ls -lha a.out

if [ "$CLANGPP" != "" ]; then
	# If we can use cross-language LTO, use it for building C dependencies (i.e. libsecp256k1) as well
	export CC="$CLANG"
	# The cc-rs crate tries to force -fdata-sections and -ffunction-sections on, which
	# breaks -fembed-bitcode, so we turn off cc-rs' default flags and specify exactly
	# what we want here.
	export CFLAGS_$ENV_TARGET="$BASE_HOST_CFLAGS -fPIC -fembed-bitcode"
	export CRATE_CC_NO_DEFAULTS=true
fi

if [ "$2" = "false" -a "$(rustc --print target-list | grep wasm32-wasi)" != "" ]; then
	# Test to see if clang supports wasm32 as a target (which is needed to build rust-secp256k1)
	echo "int main() {}" > genbindings_wasm_test_file.c
	if clang -nostdlib -o /dev/null --target=wasm32-wasi -Wl,--no-entry genbindings_wasm_test_file.c > /dev/null 2>&1; then
		# And if it does, build a WASM binary without capturing errors
		export CFLAGS_wasm32_wasi="$BASE_CFLAGS -target wasm32-wasi -O1"
		RUSTFLAGS="$BASE_RUSTFLAGS -C opt-level=1 --cfg=test_mod_pointers" cargo build $CARGO_BUILD_ARGS -v --target=wasm32-wasi
		export CFLAGS_wasm32_wasi="$BASE_CFLAGS -fembed-bitcode -target wasm32-wasi -Oz"
		RUSTFLAGS="$BASE_RUSTFLAGS -C embed-bitcode=yes -C opt-level=z -C linker-plugin-lto -C lto" CARGO_PROFILE_RELEASE_LTO=true cargo build $CARGO_BUILD_ARGS -v --release --target=wasm32-wasi
	else
		echo "Cannot build WASM lib as clang does not seem to support the wasm32-wasi target"
	fi
	rm genbindings_wasm_test_file.c
fi

EXTRA_TARGETS=( $LDK_C_BINDINGS_EXTRA_TARGETS )
EXTRA_CCS=( $LDK_C_BINDINGS_EXTRA_TARGET_CCS )
EXTRA_LINK_LTO=( $LDK_C_BINDINGS_EXTRA_TARGET_LINK_LTO )

if [ ${#EXTRA_TARGETS[@]} != ${#EXTRA_CCS[@]} ]; then
	echo "LDK_C_BINDINGS_EXTRA_TARGETS and LDK_C_BINDINGS_EXTRA_TARGET_CCS didn't have the same number of elements!"
	exit 1
fi

for IDX in ${!EXTRA_TARGETS[@]}; do
	EXTRA_ENV_TARGET=$(echo "${EXTRA_TARGETS[$IDX]}" | sed 's/-/_/g')
	export CFLAGS_$EXTRA_ENV_TARGET="$BASE_CFLAGS"
	export CC_$EXTRA_ENV_TARGET=${EXTRA_CCS[$IDX]}
	EXTRA_RUSTFLAGS=""
	case "$EXTRA_ENV_TARGET" in
		"x86_64"*)
			export CFLAGS_$EXTRA_ENV_TARGET="$BASE_CFLAGS -march=sandybridge -mtune=sandybridge"
			EXTRA_RUSTFLAGS="-C target-cpu=sandybridge"
			;;
	esac
	[ "${EXTRA_LINK_LTO[$IDX]}" != "" ] && EXTRA_RUSTFLAGS="-C linker-plugin-lto"
	RUSTFLAGS="$BASE_RUSTFLAGS -C embed-bitcode=yes -C lto -C linker=${EXTRA_CCS[$IDX]} $EXTRA_RUSTFLAGS" CARGO_PROFILE_RELEASE_LTO=true cargo build $CARGO_BUILD_ARGS -v --release --target "${EXTRA_TARGETS[$IDX]}"
done

if [ "$CLANGPP" != "" -a "$LLD" != "" ]; then
	# Finally, test cross-language LTO. Note that this will fail if rustc and clang++
	# build against different versions of LLVM (eg when rustc is installed via rustup
	# or Ubuntu packages). This should work fine on Distros which do more involved
	# packaging than simply shipping the rustup binaries (eg Debian should Just Work
	# here).
	LINK_ARG_FLAGS="-C link-arg=-fuse-ld=$LLD"
	export LDK_CLANG_PATH=$(which $CLANG)
	if [ "$MACOS_SDK" != "" ]; then
		REALLY_PIN_CC
		export CLANG="$(pwd)/../deterministic-build-wrappers/clang-lto-link-osx"
		for ARG in $CFLAGS_aarch64_apple_darwin; do
			MANUAL_LINK_CFLAGS="$MANUAL_LINK_CFLAGS -C link-arg=$ARG"
		done
		export CFLAGS_aarch64_apple_darwin="$CFLAGS_aarch64_apple_darwin -O3 -fPIC -fembed-bitcode"
		RUSTC_BOOTSTRAP=1 RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14 -C embed-bitcode=yes -C linker-plugin-lto -C lto -C linker=$CLANG $MANUAL_LINK_CFLAGS $LINK_ARG_FLAGS -C link-arg=-mcpu=apple-a14" CARGO_PROFILE_RELEASE_LTO=true cargo build $CARGO_BUILD_ARGS --offline -v --release --target aarch64-apple-darwin -Zbuild-std=std,panic_abort
		if [ "$HOST_OSX" != "true" ]; then
			# If we're not on OSX but can build OSX binaries, build the x86_64 OSX release now
			MANUAL_LINK_CFLAGS=""
			for ARG in $CFLAGS_x86_64_apple_darwin; do
				MANUAL_LINK_CFLAGS="$MANUAL_LINK_CFLAGS -C link-arg=$ARG"
			done
			export CFLAGS_x86_64_apple_darwin="$CFLAGS_x86_64_apple_darwin -O3 -fPIC -fembed-bitcode"
			RUSTC_BOOTSTRAP=1 RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=sandybridge -C embed-bitcode=yes -C linker-plugin-lto -C lto -C linker=$CLANG $MANUAL_LINK_CFLAGS $LINK_ARG_FLAGS -C link-arg=-march=sandybridge -C link-arg=-mtune=sandybridge" CARGO_PROFILE_RELEASE_LTO=true cargo build $CARGO_BUILD_ARGS --offline -v --release --target x86_64-apple-darwin -Zbuild-std=std,panic_abort
		fi
	fi
	# If we're on an M1 don't bother building X86 binaries
	if [ "$HOST_PLATFORM" != "aarch64-apple-darwin" ]; then
		[ "$HOST_OSX" != "true" ] && export CLANG="$LDK_CLANG_PATH"
		export CFLAGS_$ENV_TARGET="$BASE_HOST_CFLAGS -O3 -fPIC -fembed-bitcode"
		# Rust doesn't recognize CFLAGS changes, so we need to clean build artifacts
		cargo clean --release
		CARGO_PROFILE_RELEASE_LTO=true RUSTFLAGS="$RUSTFLAGS -C embed-bitcode=yes -C linker-plugin-lto -C lto -C linker=$CLANG $LINK_ARG_FLAGS -C link-arg=-march=sandybridge -C link-arg=-mtune=sandybridge" cargo build $CARGO_BUILD_ARGS -v --release

		if [ "$2" = "true" ]; then
			$CLANGPP $LOCAL_CFLAGS -flto -fuse-ld=$LLD -O2 -c demo.cpp -o demo.o
			$CLANGPP $LOCAL_CFLAGS -flto -fuse-ld=$LLD -Wl,--lto-O2 -Wl,-O2 -O2 demo.o target/release/libldk.a -ldl
			strip ./a.out
			time ./a.out
			echo "C++ Bin size and runtime with cross-language LTO:"
			ls -lha a.out
		fi
	fi
else
	if [ "$CFLAGS_aarch64_apple_darwin" != "" ]; then
		RUSTFLAGS="$BASE_RUSTFLAGS -C embed-bitcode=yes -C lto -C target-cpu=apple-a14" CARGO_PROFILE_RELEASE_LTO=true cargo build $CARGO_BUILD_ARGS -v --release --target aarch64-apple-darwin
	fi
	echo "WARNING: Building with cross-language LTO is not avilable without clang-$RUSTC_LLVM_V and lld-$RUSTC_LLVM_V"
fi
