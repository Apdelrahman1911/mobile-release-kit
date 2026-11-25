/* Nonshipping E2 translation-unit coverage ONLY. These are deliberately invalid
 * empty ASN.1 sequences, not certificates. No Rust entry calls the renamed
 * exports, and this header never selects the ordinary producer identity. */
#define MRK_INSTALL_PRODUCER_CONFIGURED 1
#define MRK_INSTALL_PRODUCER_RSA_BITS 2048
static const uint8_t mrk_install_producer_leaf_der[2] = {0x30,0x00};
static const uint8_t mrk_install_producer_issuer_der[2] = {0x30,0x00};
static const uint8_t mrk_install_producer_root_der[2] = {0x30,0x00};
#define MRK_COMPILE_ONLY_SHA256 {0xe4,0xf6,0x0d,0x0a,0xa6,0xd7,0xf3,0xd3,0xb6,0xa6,0x49,0x4b,0x1c,0x86,0x1b,0x99,0xf6,0x49,0xc6,0xf9,0xec,0x51,0xab,0xaf,0x20,0x1b,0x20,0xf2,0x97,0x32,0x7c,0x95}
static const uint8_t mrk_install_producer_leaf_sha256[32] = MRK_COMPILE_ONLY_SHA256;
static const uint8_t mrk_install_producer_issuer_sha256[32] = MRK_COMPILE_ONLY_SHA256;
static const uint8_t mrk_install_producer_root_sha256[32] = MRK_COMPILE_ONLY_SHA256;
static const uint8_t mrk_install_producer_public_key_pkcs1_sha256[32] = MRK_COMPILE_ONLY_SHA256;
#undef MRK_COMPILE_ONLY_SHA256
static const uint8_t mrk_install_producer_leaf_sha1[20] = {0xf9,0x44,0xdc,0xd6,0x35,0xf9,0x80,0x1f,0x7a,0xc9,0x0a,0x40,0x7f,0xbc,0x47,0x99,0x64,0xde,0xc0,0x24};
static const uint8_t mrk_install_producer_team[11] = "TEST000001";
