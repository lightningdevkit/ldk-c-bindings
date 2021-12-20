#!/usr/bin/env bash

set -e
set -x

if [ ! -d "$1/lightning" -o "$2" != "true" -a "$2" != "false" ]; then
	echo "USAGE: $0 path-to-rust-lightning allow-std"
	echo "allow-std must be either 'true' or 'false' to indicate if we should be built relying on time and pthread support"
	exit 1
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
HOST_PLATFORM="$(rustc --version --verbose | grep "host:")"

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

if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
	export MACOSX_DEPLOYMENT_TARGET=10.9
	LOCAL_CFLAGS="$LOCAL_CFLAGS -isysroot$(xcrun --show-sdk-path) -mmacosx-version-min=10.9"
	BASE_CFLAGS="$BASE_CFLAGS -isysroot$(xcrun --show-sdk-path) -mmacosx-version-min=10.9"
	# Targeting aarch64 appears to be supported only starting with Big Sur, so check it before use
	clang -o /dev/null $BASE_CFLAGS --target=aarch64-apple-darwin -mcpu=apple-a14 genbindings_path_map_test_file.c &&
	export CFLAGS_aarch64_apple_darwin="$BASE_CFLAGS --target=aarch64-apple-darwin -mcpu=apple-a14" ||
	echo "WARNING: Can not build targeting aarch64-apple-darin. Upgrade to Big Sur or try upstream clang"
fi

rm genbindings_path_map_test_file.c

ENV_TARGET=$(rustc --version --verbose | grep host | awk '{ print $2 }' | sed 's/-/_/g')
case "$ENV_TARGET" in
	"x86_64"*)
		export RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=sandybridge"
		export CFLAGS_$ENV_TARGET="$BASE_CFLAGS -march=sandybridge -mcpu=sandybridge -mtune=sandybridge"
		;;
	*)
		# Assume this isn't targeted at another host and build for the host's CPU.
		export RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=native"
		export CFLAGS_$ENV_TARGET="$BASE_CFLAGS -mcpu=native"
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
echo -e "#ifndef _LDK_HEADER_VER" > lightning-c-bindings/include/ldk_ver.h
echo -e "static inline int _ldk_strncmp(const char *s1, const char *s2, uint64_t n) {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\tif (n && *s1 != *s2) return 1;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\twhile (n && *s1 != 0 && *s2 != 0) {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t\ts1++; s2++; n--;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t\tif (n && *s1 != *s2) return 1;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\treturn 0;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "" >> lightning-c-bindings/include/ldk_ver.h
echo -e "#define _LDK_HEADER_VER \"$LIGHTNING_GIT\"" >> lightning-c-bindings/include/ldk_ver.h
echo -e "#define _LDK_C_BINDINGS_HEADER_VER \"$BINDINGS_GIT\"" >> lightning-c-bindings/include/ldk_ver.h
echo -e "static inline const char* check_get_ldk_version() {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\tLDKStr bin_ver = _ldk_get_compiled_version();" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\tif (_ldk_strncmp(_LDK_HEADER_VER, (const char*)bin_ver.chars, bin_ver.len) != 0) {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t// Version mismatch, we don't know what we're running!" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t\treturn 0;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\treturn _LDK_HEADER_VER;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "static inline const char* check_get_ldk_bindings_version() {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\tLDKStr bin_ver = _ldk_c_bindings_get_compiled_version();" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\tif (_ldk_strncmp(_LDK_C_BINDINGS_HEADER_VER, (const char*)bin_ver.chars, bin_ver.len) != 0) {" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t// Version mismatch, we don't know what we're running!" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t\treturn 0;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\t}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "\treturn _LDK_C_BINDINGS_HEADER_VER;" >> lightning-c-bindings/include/ldk_ver.h
echo -e "}" >> lightning-c-bindings/include/ldk_ver.h
echo -e "#endif /* _LDK_HEADER_VER */" >> lightning-c-bindings/include/ldk_ver.h

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

function add_crate() {
	pushd "$LIGHTNING_PATH/$1"
	RUSTC_BOOTSTRAP=1 cargo rustc --profile=check $3 -- --cfg=c_bindings -Zunpretty=expanded > /tmp/$1-crate-source.txt
	popd
	if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
		sed -i".original" "1i\\
pub mod $2 {
" /tmp/$1-crate-source.txt
	else
		sed -i "1ipub mod $2 {\n" /tmp/$1-crate-source.txt
	fi
	echo "}" >> /tmp/$1-crate-source.txt
	cat /tmp/$1-crate-source.txt >> /tmp/crate-source.txt
	rm /tmp/$1-crate-source.txt
	if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
		# OSX sed is for some reason not compatible with GNU sed
		sed -E -i '' 's|#?'$1' = \{ .*|'$1' = \{ path = "'"$LIGHTNING_PATH"'/'$1'" '"$4"' }|' lightning-c-bindings/Cargo.toml
	else
		sed -E -i 's|#?'$1' = \{ .*|'$1' = \{ path = "'"$LIGHTNING_PATH"'/'$1'" '"$4"' }|' lightning-c-bindings/Cargo.toml
	fi
}

function drop_crate() {
	if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
		# OSX sed is for some reason not compatible with GNU sed
		sed -E -i '' 's|'$1' = \{ (.*)|#'$1' = \{ \1|' lightning-c-bindings/Cargo.toml
	else
		sed -E -i 's|'$1' = \{ (.*)|#'$1' = \{ \1|' lightning-c-bindings/Cargo.toml
	fi
}

echo > /tmp/crate-source.txt
if [ "$2" = "true" ]; then
	add_crate lightning lightning --features=std ', features = ["std"]'
	add_crate "lightning-persister" "lightning_persister"
	add_crate "lightning-background-processor" "lightning_background_processor"
else
	add_crate lightning lightning --features=no-std ', features = ["no-std"]'
	drop_crate "lightning-persister"
	drop_crate "lightning-background-processor"
fi
add_crate "lightning-invoice" "lightning_invoice"

cat /tmp/crate-source.txt | RUST_BACKTRACE=1 "$BIN" "$OUT/" "$OUT_TEMPL" "$OUT_F" "$OUT_CPP"

echo -e '#[no_mangle]' >> lightning-c-bindings/src/version.rs
echo -e 'pub extern "C" fn _ldk_get_compiled_version() -> crate::c_types::Str {' >> lightning-c-bindings/src/version.rs
echo -e '\t"'"$LIGHTNING_GIT"'".into()' >> lightning-c-bindings/src/version.rs
echo -e '}' >> lightning-c-bindings/src/version.rs
echo -e '#[no_mangle]' >> lightning-c-bindings/src/version.rs
echo -e 'pub extern "C" fn _ldk_c_bindings_get_compiled_version() -> crate::c_types::Str {' >> lightning-c-bindings/src/version.rs
echo -e '\t"'"$BINDINGS_GIT"'".into()' >> lightning-c-bindings/src/version.rs
echo -e '}' >> lightning-c-bindings/src/version.rs

# Now cd to lightning-c-bindings, build the generated bindings, and call cbindgen to build a C header file
cd lightning-c-bindings

RUSTFLAGS="$RUSTFLAGS --cfg=test_mod_pointers" cargo build
if [ "$CFLAGS_aarch64_apple_darwin" != "" ]; then
	RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14" cargo build --target aarch64-apple-darwin
fi
cbindgen -v --config cbindgen.toml -o include/lightning.h >/dev/null 2>&1

# cbindgen is relatively braindead when exporting typedefs -
# it happily exports all our typedefs for private types, even with the
# generics we specified in C mode! So we drop all those types manually here.
if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
	# OSX sed is for some reason not compatible with GNU sed
	sed -i '' 's/typedef LDKnative.*Import.*LDKnative.*;//g' include/lightning.h

	# stdlib.h doesn't exist in clang's wasm sysroot, and cbindgen
	# doesn't actually use it anyway, so drop the import.
	sed -i '' 's/#include <stdlib.h>/#include "ldk_rust_types.h"/g' include/lightning.h
else
	sed -i 's/typedef LDKnative.*Import.*LDKnative.*;//g' include/lightning.h

	# stdlib.h doesn't exist in clang's wasm sysroot, and cbindgen
	# doesn't actually use it anyway, so drop the import.
	sed -i 's/#include <stdlib.h>/#include "ldk_rust_types.h"/g' include/lightning.h
fi

# Build C++ class methods which call trait methods
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
			RETVAL="$(echo "$METHOD" | sed 's/[ ]*\([A-Za-z0-9 _]*\)(\*\(.*\)).*/\1/' | sed 's/^struct LDK/LDK::/g' | tr -d ' ')"
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
	if [ -x "`which valgrind`" ]; then
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
	echo " C++ Bin size and runtime w/o optimization:"
	ls -lha a.out
	time ./a.out > /dev/null
fi

# Then, check with memory sanitizer, if we're on Linux and have rustc nightly
if [ "$HOST_PLATFORM" = "host: x86_64-unknown-linux-gnu" ]; then
	if cargo +nightly --version >/dev/null 2>&1; then
		LLVM_V=$(rustc +nightly --version --verbose | grep "LLVM version" | awk '{ print substr($3, 0, 2); }')
		if [ -x "$(which clang-$LLVM_V)" ]; then
			cargo +nightly clean
			cargo +nightly rustc -Zbuild-std=std,panic_abort --target x86_64-unknown-linux-gnu -v -- -Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes
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

if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
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
	CLANG_LLVM_V=$(clang --version | head -n1 | awk '{ print substr($4, 0, 2); }')
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

# Finally, if we're on OSX or on Linux, build the final debug binary with address sanitizer (and leave it there)
if [ "$HOST_PLATFORM" = "host: x86_64-unknown-linux-gnu" -o "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
	if [ "$CLANGPP" != "" ]; then
		if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
			# OSX sed is for some reason not compatible with GNU sed
			sed -i .bk 's/,"cdylib"]/]/g' Cargo.toml
		else
			sed -i.bk 's/,"cdylib"]/]/g' Cargo.toml
		fi
		if [ "$CFLAGS_aarch64_apple_darwin" != "" ]; then
			RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14" RUSTC_BOOTSTRAP=1 cargo rustc --target aarch64-apple-darwin -v -- -Zsanitizer=address -Cforce-frame-pointers=yes || ( mv Cargo.toml.bk Cargo.toml; exit 1)
		fi
		RUSTFLAGS="$RUSTFLAGS --cfg=test_mod_pointers" RUSTC_BOOTSTRAP=1 cargo rustc -v -- -Zsanitizer=address -Cforce-frame-pointers=yes || ( mv Cargo.toml.bk Cargo.toml; exit 1)
		mv Cargo.toml.bk Cargo.toml

		# First the C demo app...
		$CLANG $LOCAL_CFLAGS -fsanitize=address -g demo.c target/debug/libldk.a -ldl
		ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out

		if [ "$2" = "true" ]; then
			# ...then the C++ demo app
			$CLANGPP $LOCAL_CFLAGS -std=c++11 -fsanitize=address -g demo.cpp target/debug/libldk.a -ldl
			ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out >/dev/null

			# ...then the C++ demo app with the ldk_net network implementation
			$CLANG $LOCAL_CFLAGS -fPIC -fsanitize=address -g -I../ldk-net ../ldk-net/ldk_net.c -c -o ldk_net.o
			$CLANGPP $LOCAL_CFLAGS -std=c++11 -fsanitize=address -g -DREAL_NET -I../ldk-net ldk_net.o demo.cpp target/debug/libldk.a -ldl
			ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' ./a.out >/dev/null
		fi
	else
		echo "WARNING: Please install clang-$RUSTC_LLVM_V and clang++-$RUSTC_LLVM_V to build with address sanitizer"
	fi
else
	echo "WARNING: Can't use address sanitizer on non-Linux, non-OSX non-x86 platforms"
fi

# Now build with LTO on on both C++ and rust, but without cross-language LTO:
# Clear stale release build artifacts from previous runs
cargo clean --release
CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release -- -C lto
if [ "$2" = "true" ]; then
	clang++ $LOCAL_CFLAGS -std=c++11 -O2 demo.cpp target/release/libldk.a -ldl
fi

strip ./a.out
echo "C++ Bin size and runtime with only RL (LTO) optimized:"
ls -lha a.out
time ./a.out > /dev/null

if [ "$CLANGPP" != "" ]; then
	# If we can use cross-language LTO, use it for building C dependencies (i.e. libsecp256k1) as well
	export CC="$CLANG"
	# The cc-rs crate tries to force -fdata-sections and -ffunction-sections on, which
	# breaks -fembed-bitcode, so we turn off cc-rs' default flags and specify exactly
	# what we want here.
	export CFLAGS_$ENV_TARGET="$BASE_CFLAGS -fPIC -fembed-bitcode -march=sandybridge -mcpu=sandybridge -mtune=sandybridge"
	export CRATE_CC_NO_DEFAULTS=true
fi

if [ "$2" = "false" -a "$(rustc --print target-list | grep wasm32-wasi)" != "" ]; then
	# Test to see if clang supports wasm32 as a target (which is needed to build rust-secp256k1)
	echo "int main() {}" > genbindings_wasm_test_file.c
	if clang -nostdlib -o /dev/null --target=wasm32-wasi -Wl,--no-entry genbindings_wasm_test_file.c > /dev/null 2>&1; then
		# And if it does, build a WASM binary without capturing errors
		export CFLAGS_wasm32_wasi="$BASE_CFLAGS -target wasm32"
		cargo rustc -v --target=wasm32-wasi
		export CFLAGS_wasm32_wasi="$BASE_CFLAGS -target wasm32 -Os"
		CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release --target=wasm32-wasi -- -C embed-bitcode=yes -C opt-level=s -C linker-plugin-lto -C lto
	else
		echo "Cannot build WASM lib as clang does not seem to support the wasm32-wasi target"
	fi
	rm genbindings_wasm_test_file.c
fi

EXTRA_TARGETS=( $LDK_C_BINDINGS_EXTRA_TARGETS )
EXTRA_CCS=( $LDK_C_BINDINGS_EXTRA_TARGET_CCS )

if [ ${#EXTRA_TARGETS[@]} != ${#EXTRA_CCS[@]} ]; then
	echo "LDK_C_BINDINGS_EXTRA_TARGETS and LDK_C_BINDINGS_EXTRA_TARGET_CCS didn't have the same number of elements!"
	exit 1
fi

for IDX in ${!EXTRA_TARGETS[@]}; do
	EXTRA_ENV_TARGET=$(echo "${EXTRA_TARGETS[$IDX]}" | sed 's/-/_/g')
	export CFLAGS_$EXTRA_ENV_TARGET="$BASE_CFLAGS"
	export CC_$EXTRA_ENV_TARGET=${EXTRA_CCS[$IDX]}
	RUSTFLAGS="$BASE_RUSTFLAGS -C linker=${EXTRA_CCS[$IDX]}" CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release --target "${EXTRA_TARGETS[$IDX]}" -- -C lto
done

if [ "$CLANGPP" != "" -a "$LLD" != "" ]; then
	# Finally, test cross-language LTO. Note that this will fail if rustc and clang++
	# build against different versions of LLVM (eg when rustc is installed via rustup
	# or Ubuntu packages). This should work fine on Distros which do more involved
	# packaging than simply shipping the rustup binaries (eg Debian should Just Work
	# here).
	LINK_ARG_FLAGS="-C link-arg=-fuse-ld=$LLD"
	if [ "$HOST_PLATFORM" = "host: x86_64-apple-darwin" ]; then
		export LDK_CLANG_PATH=$(which $CLANG)
		export CLANG="$(pwd)/../deterministic-build-wrappers/clang-lto-link-osx"
		for ARG in "CFLAGS_aarch64_apple_darwin"; do
			MANUAL_LINK_CFLAGS="$MANUAL_LINK_CFLAGS -C link-arg=$ARG"
		done
		export CFLAGS_aarch64_apple_darwin="$CFLAGS_aarch64_apple_darwin -O3 -fPIC -fembed-bitcode"
		LINK_ARG_FLAGS="$LINK_ARG_FLAGS -C link-arg="-isysroot$(xcrun --show-sdk-path)" -C link-arg=-mmacosx-version-min=10.9"
		RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14" CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release --target aarch64-apple-darwin -- -C linker-plugin-lto -C lto -C linker=$CLANG $LINK_ARG_FLAGS -C link-arg=-mcpu=apple-a14
	fi
	export CFLAGS_$ENV_TARGET="$BASE_CFLAGS -O3 -fPIC -fembed-bitcode -march=sandybridge -mcpu=sandybridge -mtune=sandybridge"
	# Rust doesn't recognize CFLAGS changes, so we need to clean build artifacts
	cargo clean --release
	CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release -- -C linker-plugin-lto -C lto -C linker=$CLANG $LINK_ARG_FLAGS -C link-arg=-march=sandybridge -C link-arg=-mcpu=sandybridge -C link-arg=-mtune=sandybridge

	if [ "$2" = "true" ]; then
		$CLANGPP $LOCAL_CFLAGS -flto -fuse-ld=$LLD -O2 demo.cpp target/release/libldk.a -ldl
		strip ./a.out
		echo "C++ Bin size and runtime with cross-language LTO:"
		ls -lha a.out
		time ./a.out > /dev/null
	fi
else
	if [ "$CFLAGS_aarch64_apple_darwin" != "" ]; then
		RUSTFLAGS="$BASE_RUSTFLAGS -C target-cpu=apple-a14" CARGO_PROFILE_RELEASE_LTO=true cargo rustc -v --release --target aarch64-apple-darwin -- -C lto
	fi
	echo "WARNING: Building with cross-language LTO is not avilable without clang-$RUSTC_LLVM_V"
fi
