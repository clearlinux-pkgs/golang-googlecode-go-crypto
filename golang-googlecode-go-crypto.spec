Name     : golang-googlecode-go-crypto 
Version  : 0 
Release  : 1
URL      : https://github.com/golang/crypto/archive/aedad9a179ec1ea11b7064c57cbc6dc30d7724ec.tar.gz
Source0  : https://github.com/golang/crypto/archive/aedad9a179ec1ea11b7064c57cbc6dc30d7724ec.tar.gz
Summary  : No detailed summary available
Group    : Development/Tools
License  : BSD-3-Clause
BuildRequires : go

%description
This repository holds supplementary Go cryptography libraries.
To submit changes to this repository, see http://golang.org/doc/contribute.html.

%prep
%setup -q -n crypto-aedad9a179ec1ea11b7064c57cbc6dc30d7724ec

%build

%install
%global gopath /usr/lib/golang
%global library_path golang.org/x/crypto
rm -rf %{buildroot}
# Copy all *.go and *.s files
install -d -p %{buildroot}%{gopath}/src/%{library_path}/
for ext in go s; do
    for file in $(find . -iname "*.$ext") ; do
         install -d -p %{buildroot}%{gopath}/src/%{library_path}/$(dirname $file)
         cp -pav $file %{buildroot}%{gopath}/src/%{library_path}/$file
    done
done

# Copy extra files 
for file in ./sha3/testdata/keccakKats.json.deflate; do
    install -d -p %{buildroot}/%{gopath}/src/%{library_path}/sha3/testdata
    cp -pav $file %{buildroot}/%{gopath}/src/%{library_path}/$file
done

%check
export http_proxy=http://127.0.0.1:9/
export https_proxy=http://127.0.0.1:9/
export no_proxy=localhost
export GOPATH=%{buildroot}%{gopath}
go test %{library_path}/bcrypt
go test %{library_path}/blowfish
go test %{library_path}/bn256
go test %{library_path}/cast5
go test %{library_path}/curve25519
go test %{library_path}/hkdf
go test %{library_path}/md4
go test %{library_path}/nacl/box
go test %{library_path}/nacl/secretbox
go test %{library_path}/ocsp
go test %{library_path}/openpgp
go test %{library_path}/openpgp/armor
go test %{library_path}/openpgp/clearsign
go test %{library_path}/openpgp/elgamal
go test %{library_path}/openpgp/packet
go test %{library_path}/openpgp/s2k
go test %{library_path}/otr
go test %{library_path}/pbkdf2
go test %{library_path}/poly1305
go test %{library_path}/ripemd160
go test %{library_path}/salsa20
go test %{library_path}/salsa20/salsa
go test %{library_path}/scrypt
go test %{library_path}/sha3
go test %{library_path}/ssh
go test %{library_path}/ssh/agent
go test %{library_path}/ssh/terminal
go test %{library_path}/ssh/test
go test %{library_path}/twofish
go test %{library_path}/xtea
go test %{library_path}/xts


%files
%defattr(-,root,root,-)
/usr/lib/golang/src/golang.org/x/crypto/bcrypt/base64.go
/usr/lib/golang/src/golang.org/x/crypto/bcrypt/bcrypt.go
/usr/lib/golang/src/golang.org/x/crypto/bcrypt/bcrypt_test.go
/usr/lib/golang/src/golang.org/x/crypto/blowfish/block.go
/usr/lib/golang/src/golang.org/x/crypto/blowfish/blowfish_test.go
/usr/lib/golang/src/golang.org/x/crypto/blowfish/cipher.go
/usr/lib/golang/src/golang.org/x/crypto/blowfish/const.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/bn256.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/bn256_test.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/constants.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/curve.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/example_test.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/gfp12.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/gfp2.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/gfp6.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/optate.go
/usr/lib/golang/src/golang.org/x/crypto/bn256/twist.go
/usr/lib/golang/src/golang.org/x/crypto/cast5/cast5.go
/usr/lib/golang/src/golang.org/x/crypto/cast5/cast5_test.go
/usr/lib/golang/src/golang.org/x/crypto/curve25519/const_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/curve25519/cswap_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/curve25519/curve25519.go
/usr/lib/golang/src/golang.org/x/crypto/curve25519/curve25519_test.go
/usr/lib/golang/src/golang.org/x/crypto/curve25519/doc.go
/usr/lib/golang/src/golang.org/x/crypto/curve25519/freeze_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/curve25519/ladderstep_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/curve25519/mont25519_amd64.go
/usr/lib/golang/src/golang.org/x/crypto/curve25519/mul_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/curve25519/square_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/hkdf/example_test.go
/usr/lib/golang/src/golang.org/x/crypto/hkdf/hkdf.go
/usr/lib/golang/src/golang.org/x/crypto/hkdf/hkdf_test.go
/usr/lib/golang/src/golang.org/x/crypto/md4/md4.go
/usr/lib/golang/src/golang.org/x/crypto/md4/md4_test.go
/usr/lib/golang/src/golang.org/x/crypto/md4/md4block.go
/usr/lib/golang/src/golang.org/x/crypto/nacl/box/box.go
/usr/lib/golang/src/golang.org/x/crypto/nacl/box/box_test.go
/usr/lib/golang/src/golang.org/x/crypto/nacl/secretbox/secretbox.go
/usr/lib/golang/src/golang.org/x/crypto/nacl/secretbox/secretbox_test.go
/usr/lib/golang/src/golang.org/x/crypto/ocsp/ocsp.go
/usr/lib/golang/src/golang.org/x/crypto/ocsp/ocsp_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/armor/armor.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/armor/armor_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/armor/encode.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/canonical_text.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/canonical_text_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/clearsign/clearsign.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/clearsign/clearsign_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/elgamal/elgamal.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/elgamal/elgamal_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/errors/errors.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/keys.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/keys_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/compressed.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/compressed_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/config.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/encrypted_key.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/encrypted_key_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/literal.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/ocfb.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/ocfb_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/one_pass_signature.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/opaque.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/opaque_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/packet.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/packet_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/private_key.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/private_key_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/public_key.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/public_key_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/public_key_v3.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/public_key_v3_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/reader.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/signature.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/signature_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/signature_v3.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/signature_v3_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/symmetric_key_encrypted.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/symmetric_key_encrypted_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/symmetrically_encrypted.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/symmetrically_encrypted_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/userattribute.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/userattribute_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/userid.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/packet/userid_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/read.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/read_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/s2k/s2k.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/s2k/s2k_test.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/write.go
/usr/lib/golang/src/golang.org/x/crypto/openpgp/write_test.go
/usr/lib/golang/src/golang.org/x/crypto/otr/otr.go
/usr/lib/golang/src/golang.org/x/crypto/otr/otr_test.go
/usr/lib/golang/src/golang.org/x/crypto/otr/smp.go
/usr/lib/golang/src/golang.org/x/crypto/pbkdf2/pbkdf2.go
/usr/lib/golang/src/golang.org/x/crypto/pbkdf2/pbkdf2_test.go
/usr/lib/golang/src/golang.org/x/crypto/poly1305/const_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/poly1305/poly1305.go
/usr/lib/golang/src/golang.org/x/crypto/poly1305/poly1305_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/poly1305/poly1305_arm.s
/usr/lib/golang/src/golang.org/x/crypto/poly1305/poly1305_test.go
/usr/lib/golang/src/golang.org/x/crypto/poly1305/sum_amd64.go
/usr/lib/golang/src/golang.org/x/crypto/poly1305/sum_arm.go
/usr/lib/golang/src/golang.org/x/crypto/poly1305/sum_ref.go
/usr/lib/golang/src/golang.org/x/crypto/ripemd160/ripemd160.go
/usr/lib/golang/src/golang.org/x/crypto/ripemd160/ripemd160_test.go
/usr/lib/golang/src/golang.org/x/crypto/ripemd160/ripemd160block.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/hsalsa20.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/salsa2020_amd64.s
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/salsa208.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/salsa20_amd64.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/salsa20_ref.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa/salsa_test.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa20.go
/usr/lib/golang/src/golang.org/x/crypto/salsa20/salsa20_test.go
/usr/lib/golang/src/golang.org/x/crypto/scrypt/scrypt.go
/usr/lib/golang/src/golang.org/x/crypto/scrypt/scrypt_test.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/doc.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/hashes.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/keccakf.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/register.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/sha3.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/sha3_test.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/shake.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/testdata/keccakKats.json.deflate
/usr/lib/golang/src/golang.org/x/crypto/sha3/xor.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/xor_generic.go
/usr/lib/golang/src/golang.org/x/crypto/sha3/xor_unaligned.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/client.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/client_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/forward.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/keyring.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/server.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/server_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/agent/testdata_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/benchmark_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/buffer.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/buffer_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/certs.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/certs_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/channel.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/cipher.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/cipher_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/client.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/client_auth.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/client_auth_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/client_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/common.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/connection.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/doc.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/example_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/handshake.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/handshake_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/kex.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/kex_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/keys.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/keys_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/mac.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/mempipe_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/messages.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/messages_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/mux.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/mux_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/server.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/session.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/session_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/tcpip.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/tcpip_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/terminal.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/terminal_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/util.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/util_bsd.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/util_linux.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/terminal/util_windows.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/agent_unix_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/cert_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/doc.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/forward_unix_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/session_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/tcpip_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/test_unix_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/test/testdata_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/testdata/doc.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/testdata/keys.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/testdata_test.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/transport.go
/usr/lib/golang/src/golang.org/x/crypto/ssh/transport_test.go
/usr/lib/golang/src/golang.org/x/crypto/tea/cipher.go
/usr/lib/golang/src/golang.org/x/crypto/tea/tea_test.go
/usr/lib/golang/src/golang.org/x/crypto/twofish/twofish.go
/usr/lib/golang/src/golang.org/x/crypto/twofish/twofish_test.go
/usr/lib/golang/src/golang.org/x/crypto/xtea/block.go
/usr/lib/golang/src/golang.org/x/crypto/xtea/cipher.go
/usr/lib/golang/src/golang.org/x/crypto/xtea/xtea_test.go
/usr/lib/golang/src/golang.org/x/crypto/xts/xts.go
/usr/lib/golang/src/golang.org/x/crypto/xts/xts_test.go
