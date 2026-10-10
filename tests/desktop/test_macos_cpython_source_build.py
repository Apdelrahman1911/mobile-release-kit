"""Focused DATA/filesystem contracts; never launch a compiler/native/process test.

Run only through the admitted test owner. Synthetic archives are small ordinary
files in a test-owned TemporaryDirectory; no upstream archive, network, command,
tool/SDK discovery, source build or supplier activation occurs here.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch
import zlib


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILD = load("_mrk_darwin_build_test_data", "macos_cpython_source_build.py")
PROBE = load("_mrk_darwin_probe_test_data", "macos_cpython_source_probe.py")


@contextmanager
def scratch():
    with tempfile.TemporaryDirectory(prefix="mrk-darwin-source-data-") as name:
        path = Path(name)
        try:
            yield path
        finally:
            # Only this original test directory, never a project/cache path.
            for directory, children, _ in os.walk(path, followlinks=False):
                os.chmod(directory, 0o700)
                for child in children:
                    selected = Path(directory) / child
                    if not selected.is_symlink():
                        os.chmod(selected, 0o700)


# Complete generated Apple linker object-table DATA from the nominated public
# CPython 3.14.7/OpenSSL/zlib build, native run37459521777/1 (not executable code).
# Existing source-lock requiredPublicNoticeInputs and Build.project notice assembly
# continue to carry the CPython/OpenSSL/zlib/HACL/Expat upstream notices unchanged.
# Original whole-map SHA256: 386529c561703fc3d41e985b97952cabfc23ade4b2366266de1f71e3e3bbcc58
# Original selected-table SHA256: 4a7f6a892c2afdb1672866589b0229d6249a9dc0c4aa7b2bdc3aeac393e52e64
# Only original prefix/SDK role substitutions (909/18); build-root occurrences0.
NATIVE_LINK_MAP_OBJECTS = b"""[  0] linker synthesized
[  1] /Apple/SDK/MacOSX26.sdk/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd
[  2] Programs/python.o
[  3] Modules/getbuildinfo.o
[  4] Parser/token.o
[  5] Parser/pegen.o
[  6] Parser/pegen_errors.o
[  7] Parser/action_helpers.o
[  8] Parser/parser.o
[  9] Parser/string_parser.o
[ 10] Parser/peg_api.o
[ 11] Parser/lexer/buffer.o
[ 12] Parser/lexer/lexer.o
[ 13] Parser/lexer/state.o
[ 14] Parser/tokenizer/file_tokenizer.o
[ 15] Parser/tokenizer/readline_tokenizer.o
[ 16] Parser/tokenizer/string_tokenizer.o
[ 17] Parser/tokenizer/utf8_tokenizer.o
[ 18] Parser/tokenizer/helpers.o
[ 19] Parser/myreadline.o
[ 20] Objects/abstract.o
[ 21] Objects/boolobject.o
[ 22] Objects/bytes_methods.o
[ 23] Objects/bytearrayobject.o
[ 24] Objects/bytesobject.o
[ 25] Objects/call.o
[ 26] Objects/capsule.o
[ 27] Objects/cellobject.o
[ 28] Objects/classobject.o
[ 29] Objects/codeobject.o
[ 30] Objects/complexobject.o
[ 31] Objects/descrobject.o
[ 32] Objects/enumobject.o
[ 33] Objects/exceptions.o
[ 34] Objects/genericaliasobject.o
[ 35] Objects/genobject.o
[ 36] Objects/fileobject.o
[ 37] Objects/floatobject.o
[ 38] Objects/frameobject.o
[ 39] Objects/funcobject.o
[ 40] Objects/interpolationobject.o
[ 41] Objects/iterobject.o
[ 42] Objects/listobject.o
[ 43] Objects/longobject.o
[ 44] Objects/dictobject.o
[ 45] Objects/odictobject.o
[ 46] Objects/memoryobject.o
[ 47] Objects/methodobject.o
[ 48] Objects/moduleobject.o
[ 49] Objects/namespaceobject.o
[ 50] Objects/object.o
[ 51] Objects/obmalloc.o
[ 52] Objects/picklebufobject.o
[ 53] Objects/rangeobject.o
[ 54] Objects/setobject.o
[ 55] Objects/sliceobject.o
[ 56] Objects/structseq.o
[ 57] Objects/templateobject.o
[ 58] Objects/tupleobject.o
[ 59] Objects/typeobject.o
[ 60] Objects/typevarobject.o
[ 61] Objects/unicodeobject.o
[ 62] Objects/unicodectype.o
[ 63] Objects/unionobject.o
[ 64] Objects/weakrefobject.o
[ 65] Python/_contextvars.o
[ 66] Python/_warnings.o
[ 67] Python/Python-ast.o
[ 68] Python/Python-tokenize.o
[ 69] Python/asdl.o
[ 70] Python/assemble.o
[ 71] Python/ast.o
[ 72] Python/ast_preprocess.o
[ 73] Python/ast_unparse.o
[ 74] Python/bltinmodule.o
[ 75] Python/brc.o
[ 76] Python/ceval.o
[ 77] Python/codecs.o
[ 78] Python/codegen.o
[ 79] Python/compile.o
[ 80] Python/context.o
[ 81] Python/critical_section.o
[ 82] Python/crossinterp.o
[ 83] Python/dynamic_annotations.o
[ 84] Python/errors.o
[ 85] Python/flowgraph.o
[ 86] Python/frame.o
[ 87] Python/frozenmain.o
[ 88] Python/future.o
[ 89] Python/gc.o
[ 90] Python/gc_free_threading.o
[ 91] Python/gc_gil.o
[ 92] Python/getargs.o
[ 93] Python/getcompiler.o
[ 94] Python/getcopyright.o
[ 95] Python/getplatform.o
[ 96] Python/getversion.o
[ 97] Python/ceval_gil.o
[ 98] Python/hamt.o
[ 99] Python/hashtable.o
[100] Python/import.o
[101] Python/importdl.o
[102] Python/index_pool.o
[103] Python/initconfig.o
[104] Python/interpconfig.o
[105] Python/instrumentation.o
[106] Python/instruction_sequence.o
[107] Python/intrinsics.o
[108] Python/jit.o
[109] Python/legacy_tracing.o
[110] Python/lock.o
[111] Python/marshal.o
[112] Python/modsupport.o
[113] Python/mysnprintf.o
[114] Python/mystrtoul.o
[115] Python/object_stack.o
[116] Python/optimizer.o
[117] Python/optimizer_analysis.o
[118] Python/optimizer_symbols.o
[119] Python/parking_lot.o
[120] Python/pathconfig.o
[121] Python/preconfig.o
[122] Python/pyarena.o
[123] Python/pyctype.o
[124] Python/pyfpe.o
[125] Python/pyhash.o
[126] Python/pylifecycle.o
[127] Python/pymath.o
[128] Python/pystate.o
[129] Python/pythonrun.o
[130] Python/pytime.o
[131] Python/qsbr.o
[132] Python/bootstrap_hash.o
[133] Python/specialize.o
[134] Python/stackrefs.o
[135] Python/structmember.o
[136] Python/symtable.o
[137] Python/sysmodule.o
[138] Python/thread.o
[139] Python/traceback.o
[140] Python/tracemalloc.o
[141] Python/uniqueid.o
[142] Python/getopt.o
[143] Python/pystrcmp.o
[144] Python/pystrtod.o
[145] Python/pystrhex.o
[146] Python/dtoa.o
[147] Python/formatter_unicode.o
[148] Python/fileutils.o
[149] Python/suggestions.o
[150] Python/perf_trampoline.o
[151] Python/perf_jit_trampoline.o
[152] Python/remote_debugging.o
[153] Python/dynload_shlib.o
[154] Modules/config.o
[155] Modules/main.o
[156] Modules/gcmodule.o
[157] Modules/_bisectmodule.o
[158] Modules/_heapqmodule.o
[159] Modules/_json.o
[160] Modules/_randommodule.o
[161] Modules/_struct.o
[162] Modules/mathmodule.o
[163] Modules/binascii.o
[164] Modules/zlibmodule.o
[165] Modules/fcntlmodule.o
[166] Modules/_posixsubprocess.o
[167] Modules/selectmodule.o
[168] Modules/unicodedata.o
[169] Modules/_ctypes/_ctypes.o
[170] Modules/_ctypes/callbacks.o
[171] Modules/_ctypes/callproc.o
[172] Modules/_ctypes/stgdict.o
[173] Modules/_ctypes/cfield.o
[174] Modules/_ctypes/malloc_closure.o
[175] Modules/socketmodule.o
[176] Modules/_ssl.o
[177] Modules/pyexpat.o
[178] Modules/resource.o
[179] Modules/_scproxy.o
[180] Modules/md5module.o
[181] Modules/sha1module.o
[182] Modules/sha2module.o
[183] Modules/sha3module.o
[184] Modules/blake2module.o
[185] Modules/hmacmodule.o
[186] Modules/atexitmodule.o
[187] Modules/faulthandler.o
[188] Modules/posixmodule.o
[189] Modules/signalmodule.o
[190] Modules/_tracemalloc.o
[191] Modules/_suggestions.o
[192] Modules/_datetimemodule.o
[193] Modules/_codecsmodule.o
[194] Modules/_collectionsmodule.o
[195] Modules/errnomodule.o
[196] Modules/_io/_iomodule.o
[197] Modules/_io/iobase.o
[198] Modules/_io/fileio.o
[199] Modules/_io/bytesio.o
[200] Modules/_io/bufferedio.o
[201] Modules/_io/textio.o
[202] Modules/_io/stringio.o
[203] Modules/itertoolsmodule.o
[204] Modules/_sre/sre.o
[205] Modules/_sysconfig.o
[206] Modules/_threadmodule.o
[207] Modules/timemodule.o
[208] Modules/_typesmodule.o
[209] Modules/_typingmodule.o
[210] Modules/_weakref.o
[211] Modules/_abc.o
[212] Modules/_functoolsmodule.o
[213] Modules/_localemodule.o
[214] Modules/_opcode.o
[215] Modules/_operator.o
[216] Modules/_stat.o
[217] Modules/symtablemodule.o
[218] Modules/pwdmodule.o
[219] Modules/getpath.o
[220] Python/frozen.o
[221] /Apple/SDK/MacOSX26.sdk/usr/lib/libdl.tbd
[222] /private/test/prefix/lib/libz.a(adler32.o)
[223] /private/test/prefix/lib/libz.a(crc32.o)
[224] /private/test/prefix/lib/libz.a(deflate.o)
[225] /private/test/prefix/lib/libz.a(inffast.o)
[226] /private/test/prefix/lib/libz.a(inflate.o)
[227] /private/test/prefix/lib/libz.a(inftrees.o)
[228] /private/test/prefix/lib/libz.a(trees.o)
[229] /private/test/prefix/lib/libz.a(zutil.o)
[230] /Apple/SDK/MacOSX26.sdk/usr/lib/libffi.tbd
[231] /private/test/prefix/lib/libssl.a(libssl-lib-d1_lib.o)
[232] /private/test/prefix/lib/libssl.a(libssl-lib-d1_msg.o)
[233] /private/test/prefix/lib/libssl.a(libssl-lib-d1_srtp.o)
[234] /private/test/prefix/lib/libssl.a(libssl-lib-methods.o)
[235] /private/test/prefix/lib/libssl.a(libssl-lib-pqueue.o)
[236] /private/test/prefix/lib/libssl.a(libssl-lib-s3_enc.o)
[237] /private/test/prefix/lib/libssl.a(libssl-lib-s3_lib.o)
[238] /private/test/prefix/lib/libssl.a(libssl-lib-s3_msg.o)
[239] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_asn1.o)
[240] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_cert.o)
[241] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_ciph.o)
[242] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_conf.o)
[243] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_init.o)
[244] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_lib.o)
[245] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_mcnf.o)
[246] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_rsa.o)
[247] /private/test/prefix/lib/libssl.a(libssl-lib-ssl_sess.o)
[248] /private/test/prefix/lib/libssl.a(libssl-lib-t1_enc.o)
[249] /private/test/prefix/lib/libssl.a(libssl-lib-t1_lib.o)
[250] /private/test/prefix/lib/libssl.a(libssl-lib-tls13_enc.o)
[251] /private/test/prefix/lib/libssl.a(libssl-lib-tls_depr.o)
[252] /private/test/prefix/lib/libssl.a(libssl-lib-tls_srp.o)
[253] /private/test/prefix/lib/libssl.a(libssl-lib-cc_newreno.o)
[254] /private/test/prefix/lib/libssl.a(libssl-lib-json_enc.o)
[255] /private/test/prefix/lib/libssl.a(libssl-lib-qlog.o)
[256] /private/test/prefix/lib/libssl.a(libssl-lib-qlog_event_helpers.o)
[257] /private/test/prefix/lib/libssl.a(libssl-lib-quic_ackm.o)
[258] /private/test/prefix/lib/libssl.a(libssl-lib-quic_cfq.o)
[259] /private/test/prefix/lib/libssl.a(libssl-lib-quic_channel.o)
[260] /private/test/prefix/lib/libssl.a(libssl-lib-quic_demux.o)
[261] /private/test/prefix/lib/libssl.a(libssl-lib-quic_engine.o)
[262] /private/test/prefix/lib/libssl.a(libssl-lib-quic_fc.o)
[263] /private/test/prefix/lib/libssl.a(libssl-lib-quic_fifd.o)
[264] /private/test/prefix/lib/libssl.a(libssl-lib-quic_impl.o)
[265] /private/test/prefix/lib/libssl.a(libssl-lib-quic_lcidm.o)
[266] /private/test/prefix/lib/libssl.a(libssl-lib-quic_method.o)
[267] /private/test/prefix/lib/libssl.a(libssl-lib-quic_obj.o)
[268] /private/test/prefix/lib/libssl.a(libssl-lib-quic_port.o)
[269] /private/test/prefix/lib/libssl.a(libssl-lib-quic_reactor.o)
[270] /private/test/prefix/lib/libssl.a(libssl-lib-quic_reactor_wait_ctx.o)
[271] /private/test/prefix/lib/libssl.a(libssl-lib-quic_record_rx.o)
[272] /private/test/prefix/lib/libssl.a(libssl-lib-quic_record_shared.o)
[273] /private/test/prefix/lib/libssl.a(libssl-lib-quic_record_tx.o)
[274] /private/test/prefix/lib/libssl.a(libssl-lib-quic_record_util.o)
[275] /private/test/prefix/lib/libssl.a(libssl-lib-quic_rstream.o)
[276] /private/test/prefix/lib/libssl.a(libssl-lib-quic_rx_depack.o)
[277] /private/test/prefix/lib/libssl.a(libssl-lib-quic_sf_list.o)
[278] /private/test/prefix/lib/libssl.a(libssl-lib-quic_srtm.o)
[279] /private/test/prefix/lib/libssl.a(libssl-lib-quic_sstream.o)
[280] /private/test/prefix/lib/libssl.a(libssl-lib-quic_statm.o)
[281] /private/test/prefix/lib/libssl.a(libssl-lib-quic_stream_map.o)
[282] /private/test/prefix/lib/libssl.a(libssl-lib-quic_thread_assist.o)
[283] /private/test/prefix/lib/libssl.a(libssl-lib-quic_tls.o)
[284] /private/test/prefix/lib/libssl.a(libssl-lib-quic_txp.o)
[285] /private/test/prefix/lib/libssl.a(libssl-lib-quic_txpim.o)
[286] /private/test/prefix/lib/libssl.a(libssl-lib-quic_types.o)
[287] /private/test/prefix/lib/libssl.a(libssl-lib-quic_wire.o)
[288] /private/test/prefix/lib/libssl.a(libssl-lib-quic_wire_pkt.o)
[289] /private/test/prefix/lib/libssl.a(libssl-lib-uint_set.o)
[290] /private/test/prefix/lib/libssl.a(libssl-lib-rec_layer_d1.o)
[291] /private/test/prefix/lib/libssl.a(libssl-lib-rec_layer_s3.o)
[292] /private/test/prefix/lib/libssl.a(libssl-lib-dtls_meth.o)
[293] /private/test/prefix/lib/libssl.a(libssl-lib-ssl3_meth.o)
[294] /private/test/prefix/lib/libssl.a(libssl-lib-tls13_meth.o)
[295] /private/test/prefix/lib/libssl.a(libssl-lib-tls1_meth.o)
[296] /private/test/prefix/lib/libssl.a(libssl-lib-tls_common.o)
[297] /private/test/prefix/lib/libssl.a(libssl-lib-tls_multib.o)
[298] /private/test/prefix/lib/libssl.a(libssl-lib-tlsany_meth.o)
[299] /private/test/prefix/lib/libssl.a(libssl-lib-rio_notifier.o)
[300] /private/test/prefix/lib/libssl.a(libssl-lib-extensions.o)
[301] /private/test/prefix/lib/libssl.a(libssl-lib-extensions_clnt.o)
[302] /private/test/prefix/lib/libssl.a(libssl-lib-extensions_cust.o)
[303] /private/test/prefix/lib/libssl.a(libssl-lib-extensions_srvr.o)
[304] /private/test/prefix/lib/libssl.a(libssl-lib-statem.o)
[305] /private/test/prefix/lib/libssl.a(libssl-lib-statem_clnt.o)
[306] /private/test/prefix/lib/libssl.a(libssl-lib-statem_dtls.o)
[307] /private/test/prefix/lib/libssl.a(libssl-lib-statem_lib.o)
[308] /private/test/prefix/lib/libssl.a(libssl-lib-statem_srvr.o)
[309] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aes_cbc.o)
[310] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aes_core.o)
[311] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aesv8-armx.o)
[312] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bsaes-armv8.o)
[313] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-vpaes-armv8.o)
[314] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aria.o)
[315] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_bitstr.o)
[316] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_d2i_fp.o)
[317] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_digest.o)
[318] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_dup.o)
[319] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_gentm.o)
[320] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_i2d_fp.o)
[321] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_int.o)
[322] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_mbstr.o)
[323] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_object.o)
[324] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_octet.o)
[325] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_print.o)
[326] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_sign.o)
[327] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_strex.o)
[328] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_strnid.o)
[329] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_time.o)
[330] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_type.o)
[331] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_utctm.o)
[332] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_utf8.o)
[333] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-a_verify.o)
[334] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ameth_lib.o)
[335] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn1_err.o)
[336] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn1_gen.o)
[337] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn1_lib.o)
[338] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn1_parse.o)
[339] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn_moid.o)
[340] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn_mstbl.o)
[341] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn_pack.o)
[342] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-d2i_pr.o)
[343] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_asn1.o)
[344] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-f_int.o)
[345] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-f_string.o)
[346] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i2d_evp.o)
[347] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-nsseq.o)
[348] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p5_pbe.o)
[349] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p5_pbev2.o)
[350] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p5_scrypt.o)
[351] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p8_pkey.o)
[352] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-t_pkey.o)
[353] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_dec.o)
[354] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_enc.o)
[355] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_fre.o)
[356] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_new.o)
[357] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_prn.o)
[358] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_typ.o)
[359] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-tasn_utl.o)
[360] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_algor.o)
[361] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_bignum.o)
[362] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_info.o)
[363] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_int64.o)
[364] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_pkey.o)
[365] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_sig.o)
[366] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_spki.o)
[367] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_val.o)
[368] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-async_posix.o)
[369] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-async.o)
[370] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-async_err.o)
[371] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-async_wait.o)
[372] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_cfb64.o)
[373] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_ecb.o)
[374] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_enc.o)
[375] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_ofb64.o)
[376] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_skey.o)
[377] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_buff.o)
[378] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_prefix.o)
[379] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bf_readbuff.o)
[380] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_addr.o)
[381] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_dump.o)
[382] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_err.o)
[383] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_lib.o)
[384] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_meth.o)
[385] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_print.o)
[386] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_sock.o)
[387] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_sock2.o)
[388] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_conn.o)
[389] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_core.o)
[390] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_dgram.o)
[391] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_dgram_pair.o)
[392] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_fd.o)
[393] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_file.o)
[394] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_mem.o)
[395] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_null.o)
[396] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bss_sock.o)
[397] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ossl_core_bio.o)
[398] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-armv8-mont.o)
[399] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_add.o)
[400] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_asm.o)
[401] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_blind.o)
[402] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_const.o)
[403] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_conv.o)
[404] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_ctx.o)
[405] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_dh.o)
[406] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_div.o)
[407] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_err.o)
[408] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_exp.o)
[409] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_exp2.o)
[410] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_gcd.o)
[411] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_gf2m.o)
[412] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_intern.o)
[413] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_kron.o)
[414] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_lib.o)
[415] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_mod.o)
[416] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_mont.o)
[417] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_mul.o)
[418] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_prime.o)
[419] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_print.o)
[420] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_rand.o)
[421] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_recp.o)
[422] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_rsa_fips186_4.o)
[423] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_shift.o)
[424] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_sqr.o)
[425] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_sqrt.o)
[426] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_srp.o)
[427] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bn_word.o)
[428] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-buf_err.o)
[429] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-buffer.o)
[430] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-camellia.o)
[431] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cmll_cbc.o)
[432] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cmll_misc.o)
[433] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_cfb64.o)
[434] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_ecb.o)
[435] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_enc.o)
[436] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_ofb64.o)
[437] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_skey.o)
[438] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-chacha-armv8-sve.o)
[439] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-chacha-armv8.o)
[440] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cmac.o)
[441] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cmp_err.o)
[442] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cmp_util.o)
[443] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cms_err.o)
[444] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_brotli.o)
[445] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_zlib.o)
[446] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_zstd.o)
[447] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-comp_err.o)
[448] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-comp_lib.o)
[449] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_api.o)
[450] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_def.o)
[451] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_err.o)
[452] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_lib.o)
[453] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_mall.o)
[454] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_mod.o)
[455] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_sap.o)
[456] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-conf_ssl.o)
[457] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-crmf_err.o)
[458] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_b64.o)
[459] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_err.o)
[460] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_log.o)
[461] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_oct.o)
[462] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_policy.o)
[463] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_prn.o)
[464] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_sct.o)
[465] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_sct_ctx.o)
[466] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_vfy.o)
[467] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ct_x509v3.o)
[468] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cfb64ede.o)
[469] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cfb64enc.o)
[470] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cfb_enc.o)
[471] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-des_enc.o)
[472] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecb3_enc.o)
[473] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecb_enc.o)
[474] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ofb64ede.o)
[475] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ofb64enc.o)
[476] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-set_key.o)
[477] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-xcbc_enc.o)
[478] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_ameth.o)
[479] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_asn1.o)
[480] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_backend.o)
[481] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_check.o)
[482] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_err.o)
[483] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_gen.o)
[484] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_group_params.o)
[485] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_kdf.o)
[486] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_key.o)
[487] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_lib.o)
[488] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_pmeth.o)
[489] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_ameth.o)
[490] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_asn1.o)
[491] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_backend.o)
[492] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_check.o)
[493] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_err.o)
[494] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_gen.o)
[495] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_key.o)
[496] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_lib.o)
[497] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_ossl.o)
[498] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_pmeth.o)
[499] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_sign.o)
[500] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_vrf.o)
[501] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dso_err.o)
[502] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dso_lib.o)
[503] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dso_openssl.o)
[504] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-f_impl64.o)
[505] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-curve448.o)
[506] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-curve448_tables.o)
[507] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-eddsa.o)
[508] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-f_generic.o)
[509] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-scalar.o)
[510] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-curve25519.o)
[511] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec2_oct.o)
[512] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec2_smpl.o)
[513] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_ameth.o)
[514] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_asn1.o)
[515] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_backend.o)
[516] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_check.o)
[517] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_curve.o)
[518] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_cvt.o)
[519] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_err.o)
[520] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_key.o)
[521] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_kmeth.o)
[522] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_lib.o)
[523] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_mult.o)
[524] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_oct.o)
[525] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_pmeth.o)
[526] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecdh_kdf.o)
[527] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecdh_ossl.o)
[528] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecdsa_ossl.o)
[529] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecdsa_sign.o)
[530] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecdsa_vrf.o)
[531] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-eck_prn.o)
[532] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_mont.o)
[533] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_nistz256-armv8.o)
[534] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_nistz256.o)
[535] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_oct.o)
[536] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_sm2p256-armv8.o)
[537] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_sm2p256.o)
[538] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_sm2p256_table.o)
[539] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecp_smpl.o)
[540] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecx_backend.o)
[541] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecx_key.o)
[542] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ecx_meth.o)
[543] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-decoder_lib.o)
[544] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-decoder_meth.o)
[545] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-decoder_pkey.o)
[546] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-encoder_lib.o)
[547] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-encoder_meth.o)
[548] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-encoder_pkey.o)
[549] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err.o)
[550] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err_all.o)
[551] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err_blocks.o)
[552] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err_mark.o)
[553] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err_prn.o)
[554] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-err_save.o)
[555] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ess_err.o)
[556] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asymcipher.o)
[557] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_enc.o)
[558] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bio_md.o)
[559] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_allc.o)
[560] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-c_alld.o)
[561] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ctrl_params_translate.o)
[562] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_ctrl.o)
[563] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dh_support.o)
[564] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-digest.o)
[565] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-dsa_ctrl.o)
[566] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_aes.o)
[567] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_aes_cbc_hmac_sha1.o)
[568] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_aes_cbc_hmac_sha256.o)
[569] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_aria.o)
[570] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_bf.o)
[571] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_camellia.o)
[572] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_cast.o)
[573] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_chacha20_poly1305.o)
[574] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_des.o)
[575] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_des3.o)
[576] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_idea.o)
[577] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_rc2.o)
[578] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_rc4.o)
[579] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_rc4_hmac_md5.o)
[580] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_seed.o)
[581] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_sm4.o)
[582] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-e_xcbc_d.o)
[583] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_ctrl.o)
[584] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ec_support.o)
[585] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-encode.o)
[586] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_cnf.o)
[587] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_enc.o)
[588] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_err.o)
[589] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_fetch.o)
[590] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_key.o)
[591] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_lib.o)
[592] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_pbe.o)
[593] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_pkey.o)
[594] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_rand.o)
[595] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-evp_utils.o)
[596] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-exchange.o)
[597] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-kdf_lib.o)
[598] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-kdf_meth.o)
[599] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-kem.o)
[600] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-keymgmt_lib.o)
[601] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-keymgmt_meth.o)
[602] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_blake2.o)
[603] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_md4.o)
[604] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_md5.o)
[605] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_md5_sha1.o)
[606] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_mdc2.o)
[607] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_ripemd.o)
[608] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_sha.o)
[609] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_wp.o)
[610] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-m_null.o)
[611] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-m_sigver.o)
[612] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-mac_lib.o)
[613] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-mac_meth.o)
[614] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-names.o)
[615] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p5_crpt.o)
[616] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p5_crpt2.o)
[617] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p_legacy.o)
[618] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p_lib.o)
[619] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p_sign.o)
[620] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p_verify.o)
[621] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pbe_scrypt.o)
[622] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pmeth_check.o)
[623] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pmeth_gn.o)
[624] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pmeth_lib.o)
[625] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-s_lib.o)
[626] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-signature.o)
[627] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-skeymgmt_meth.o)
[628] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_backend.o)
[629] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_dh.o)
[630] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_key_generate.o)
[631] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_key_validate.o)
[632] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_params.o)
[633] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_params_generate.o)
[634] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ffc_params_validate.o)
[635] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-hashfunc.o)
[636] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-hashtable.o)
[637] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-hmac.o)
[638] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-hpke_util.o)
[639] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-http_client.o)
[640] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-http_err.o)
[641] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-http_lib.o)
[642] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i_cbc.o)
[643] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i_cfb64.o)
[644] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i_ecb.o)
[645] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i_ofb64.o)
[646] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-i_skey.o)
[647] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-lhash.o)
[648] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-arm64cpuid.o)
[649] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-armcap.o)
[650] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-asn1_dsa.o)
[651] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-bsearch.o)
[652] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-comp_methods.o)
[653] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-context.o)
[654] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-core_algorithm.o)
[655] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-core_fetch.o)
[656] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-core_namemap.o)
[657] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cpt_err.o)
[658] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cryptlib.o)
[659] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ctype.o)
[660] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cversion.o)
[661] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-defaults.o)
[662] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-der_writer.o)
[663] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-deterministic_nonce.o)
[664] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ex_data.o)
[665] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-getenv.o)
[666] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-indicator_core.o)
[667] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-info.o)
[668] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-init.o)
[669] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-initthread.o)
[670] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-mem.o)
[671] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-mem_sec.o)
[672] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-o_dir.o)
[673] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-o_fopen.o)
[674] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-o_str.o)
[675] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-o_time.o)
[676] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-packet.o)
[677] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-param_build.o)
[678] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-param_build_set.o)
[679] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-params.o)
[680] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-params_dup.o)
[681] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-params_from_text.o)
[682] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-params_idx.o)
[683] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-passphrase.o)
[684] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-provider.o)
[685] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-provider_child.o)
[686] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-provider_conf.o)
[687] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-provider_core.o)
[688] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-provider_predefined.o)
[689] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-punycode.o)
[690] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-quic_vlint.o)
[691] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-self_test_core.o)
[692] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sleep.o)
[693] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sparse_array.o)
[694] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ssl_err.o)
[695] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-threads_pthread.o)
[696] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-time.o)
[697] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-trace.o)
[698] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-uid.o)
[699] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-md4_dgst.o)
[700] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-md5-aarch64.o)
[701] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-md5_dgst.o)
[702] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-md5_sha1.o)
[703] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-mdc2dgst.o)
[704] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_encoders.o)
[705] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_key.o)
[706] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_key_compress.o)
[707] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_matrix.o)
[708] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_ntt.o)
[709] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_params.o)
[710] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_sample.o)
[711] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_dsa_sign.o)
[712] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ml_kem.o)
[713] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aes-gcm-armv8-unroll8_64.o)
[714] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-aes-gcm-armv8_64.o)
[715] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cbc128.o)
[716] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ccm128.o)
[717] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-cfb128.o)
[718] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ctr128.o)
[719] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-gcm128.o)
[720] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ghashv8-armx.o)
[721] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocb128.o)
[722] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ofb128.o)
[723] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-siv128.o)
[724] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-wrap128.o)
[725] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-xts128.o)
[726] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-xts128gb.o)
[727] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-o_names.o)
[728] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-obj_dat.o)
[729] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-obj_err.o)
[730] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-obj_lib.o)
[731] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-obj_xref.o)
[732] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocsp_asn.o)
[733] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocsp_cl.o)
[734] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocsp_err.o)
[735] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocsp_ext.o)
[736] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ocsp_lib.o)
[737] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ocsp.o)
[738] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_all.o)
[739] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_err.o)
[740] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_info.o)
[741] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_lib.o)
[742] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_oth.o)
[743] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_pk8.o)
[744] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_pkey.o)
[745] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_x509.o)
[746] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pem_xaux.o)
[747] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pvkfmt.o)
[748] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_add.o)
[749] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_asn.o)
[750] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_attr.o)
[751] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_crpt.o)
[752] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_decr.o)
[753] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_init.o)
[754] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_key.o)
[755] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_kiss.o)
[756] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_mutl.o)
[757] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_p8d.o)
[758] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_p8e.o)
[759] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_sbag.o)
[760] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-p12_utl.o)
[761] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pk12err.o)
[762] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pk7_asn1.o)
[763] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pk7_attr.o)
[764] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pk7_doit.o)
[765] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pk7_lib.o)
[766] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pkcs7err.o)
[767] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-poly1305-armv8.o)
[768] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-poly1305.o)
[769] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-defn_cache.o)
[770] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-property.o)
[771] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-property_err.o)
[772] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-property_parse.o)
[773] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-property_query.o)
[774] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-property_string.o)
[775] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-prov_seed.o)
[776] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rand_err.o)
[777] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rand_lib.o)
[778] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rand_meth.o)
[779] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rand_pool.o)
[780] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rand_uniform.o)
[781] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc2_cbc.o)
[782] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc2_ecb.o)
[783] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc2_skey.o)
[784] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc2cfb64.o)
[785] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc2ofb64.o)
[786] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc4_enc.o)
[787] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rc4_skey.o)
[788] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rmd_dgst.o)
[789] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_ameth.o)
[790] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_asn1.o)
[791] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_backend.o)
[792] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_chk.o)
[793] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_crpt.o)
[794] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_err.o)
[795] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_gen.o)
[796] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_lib.o)
[797] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_mp.o)
[798] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_mp_names.o)
[799] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_none.o)
[800] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_oaep.o)
[801] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_ossl.o)
[802] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_pk1.o)
[803] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_pmeth.o)
[804] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_pss.o)
[805] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_saos.o)
[806] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_schemes.o)
[807] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_sign.o)
[808] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_sp800_56b_check.o)
[809] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_sp800_56b_gen.o)
[810] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-rsa_x931.o)
[811] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-seed.o)
[812] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-seed_cbc.o)
[813] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-seed_cfb.o)
[814] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-seed_ecb.o)
[815] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-seed_ofb.o)
[816] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-keccak1600-armv8.o)
[817] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha1-armv8.o)
[818] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha1_one.o)
[819] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha1dgst.o)
[820] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha256-armv8.o)
[821] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha256.o)
[822] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha3.o)
[823] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha512-armv8.o)
[824] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sha512.o)
[825] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-siphash.o)
[826] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_adrs.o)
[827] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_dsa.o)
[828] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_dsa_hash_ctx.o)
[829] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_dsa_key.o)
[830] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_fors.o)
[831] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_hash.o)
[832] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_hypertree.o)
[833] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_params.o)
[834] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_wots.o)
[835] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-slh_xmss.o)
[836] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm2_crypt.o)
[837] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm2_err.o)
[838] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm2_key.o)
[839] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm2_sign.o)
[840] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-legacy_sm3.o)
[841] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm3-armv8.o)
[842] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm3.o)
[843] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm4-armv8.o)
[844] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-sm4.o)
[845] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-vpsm4-armv8.o)
[846] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-vpsm4_ex-armv8.o)
[847] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-srp_lib.o)
[848] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-srp_vfy.o)
[849] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-stack.o)
[850] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_err.o)
[851] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_init.o)
[852] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_lib.o)
[853] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_meth.o)
[854] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_register.o)
[855] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-store_result.o)
[856] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-thread_posix.o)
[857] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-arch.o)
[858] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-internal.o)
[859] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ts_err.o)
[860] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-txt_db.o)
[861] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ui_err.o)
[862] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ui_lib.o)
[863] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ui_null.o)
[864] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ui_openssl.o)
[865] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-ui_util.o)
[866] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-wp_block.o)
[867] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-wp_dgst.o)
[868] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-by_dir.o)
[869] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-by_file.o)
[870] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-by_store.o)
[871] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_cache.o)
[872] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_data.o)
[873] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_lib.o)
[874] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_map.o)
[875] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_node.o)
[876] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-pcy_tree.o)
[877] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-t_x509.o)
[878] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_aaa.o)
[879] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ac_tgt.o)
[880] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_addr.o)
[881] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_admis.o)
[882] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_akeya.o)
[883] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_akid.o)
[884] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_asid.o)
[885] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_attrdesc.o)
[886] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_attrmap.o)
[887] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_audit_id.o)
[888] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_authattid.o)
[889] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_battcons.o)
[890] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_bcons.o)
[891] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_bitst.o)
[892] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_conf.o)
[893] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_cpols.o)
[894] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_crld.o)
[895] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_enum.o)
[896] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_extku.o)
[897] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_genn.o)
[898] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_group_ac.o)
[899] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ia5.o)
[900] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ind_iss.o)
[901] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_info.o)
[902] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_int.o)
[903] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_iobo.o)
[904] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ist.o)
[905] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_lib.o)
[906] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_ncons.o)
[907] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_no_ass.o)
[908] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_no_rev_avail.o)
[909] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_pci.o)
[910] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_pcia.o)
[911] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_pcons.o)
[912] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_pku.o)
[913] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_pmaps.o)
[914] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_prn.o)
[915] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_purp.o)
[916] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_rolespec.o)
[917] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_san.o)
[918] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_sda.o)
[919] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_single_use.o)
[920] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_skid.o)
[921] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_soa_id.o)
[922] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_sxnet.o)
[923] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_timespec.o)
[924] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_tlsf.o)
[925] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_usernotice.o)
[926] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_utf8.o)
[927] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3_utl.o)
[928] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-v3err.o)
[929] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_acert.o)
[930] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_att.o)
[931] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_cmp.o)
[932] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_d2.o)
[933] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_def.o)
[934] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_err.o)
[935] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_ext.o)
[936] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_lu.o)
[937] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_obj.o)
[938] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_req.o)
[939] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_set.o)
[940] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_trust.o)
[941] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_txt.o)
[942] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_v3.o)
[943] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_vfy.o)
[944] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509_vpm.o)
[945] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509cset.o)
[946] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509name.o)
[947] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x509rset.o)
[948] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_all.o)
[949] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_attrib.o)
[950] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_crl.o)
[951] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_exten.o)
[952] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_name.o)
[953] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_pubkey.o)
[954] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_req.o)
[955] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_x509.o)
[956] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-x_x509a.o)
[957] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-baseprov.o)
[958] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-defltprov.o)
[959] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-nullprov.o)
[960] /private/test/prefix/lib/libcrypto.a(libcrypto-lib-prov_running.o)
[961] /private/test/prefix/lib/libcrypto.a(libdefault-lib-der_rsa_sig.o)
[962] /private/test/prefix/lib/libcrypto.a(libdefault-lib-der_sm2_gen.o)
[963] /private/test/prefix/lib/libcrypto.a(libdefault-lib-der_sm2_sig.o)
[964] /private/test/prefix/lib/libcrypto.a(libdefault-lib-bio_prov.o)
[965] /private/test/prefix/lib/libcrypto.a(libdefault-lib-capabilities.o)
[966] /private/test/prefix/lib/libcrypto.a(libdefault-lib-digest_to_nid.o)
[967] /private/test/prefix/lib/libcrypto.a(libdefault-lib-provider_seeding.o)
[968] /private/test/prefix/lib/libcrypto.a(libdefault-lib-provider_util.o)
[969] /private/test/prefix/lib/libcrypto.a(libdefault-lib-securitycheck.o)
[970] /private/test/prefix/lib/libcrypto.a(libdefault-lib-securitycheck_default.o)
[971] /private/test/prefix/lib/libcrypto.a(libdefault-lib-rsa_enc.o)
[972] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sm2_enc.o)
[973] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes.o)
[974] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_cbc_hmac_sha.o)
[975] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_cbc_hmac_sha1_hw.o)
[976] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_cbc_hmac_sha256_hw.o)
[977] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_ccm.o)
[978] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_ccm_hw.o)
[979] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_gcm.o)
[980] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_gcm_hw.o)
[981] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_gcm_siv.o)
[982] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_gcm_siv_hw.o)
[983] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_gcm_siv_polyval.o)
[984] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_hw.o)
[985] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_ocb.o)
[986] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_ocb_hw.o)
[987] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_siv.o)
[988] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_siv_hw.o)
[989] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_wrp.o)
[990] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_xts.o)
[991] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_xts_fips.o)
[992] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aes_xts_hw.o)
[993] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria.o)
[994] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria_ccm.o)
[995] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria_ccm_hw.o)
[996] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria_gcm.o)
[997] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria_gcm_hw.o)
[998] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_aria_hw.o)
[999] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_camellia.o)
[1000] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_camellia_hw.o)
[1001] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_chacha20.o)
[1002] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_chacha20_hw.o)
[1003] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_chacha20_poly1305.o)
[1004] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_chacha20_poly1305_hw.o)
[1005] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_cts.o)
[1006] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_null.o)
[1007] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4.o)
[1008] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_ccm.o)
[1009] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_ccm_hw.o)
[1010] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_gcm.o)
[1011] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_gcm_hw.o)
[1012] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_hw.o)
[1013] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_xts.o)
[1014] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_sm4_xts_hw.o)
[1015] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes.o)
[1016] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_common.o)
[1017] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_default.o)
[1018] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_default_hw.o)
[1019] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_hw.o)
[1020] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_wrap.o)
[1021] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cipher_tdes_wrap_hw.o)
[1022] /private/test/prefix/lib/libcrypto.a(libdefault-lib-blake2_prov.o)
[1023] /private/test/prefix/lib/libcrypto.a(libdefault-lib-blake2b_prov.o)
[1024] /private/test/prefix/lib/libcrypto.a(libdefault-lib-blake2s_prov.o)
[1025] /private/test/prefix/lib/libcrypto.a(libdefault-lib-md5_prov.o)
[1026] /private/test/prefix/lib/libcrypto.a(libdefault-lib-md5_sha1_prov.o)
[1027] /private/test/prefix/lib/libcrypto.a(libdefault-lib-null_prov.o)
[1028] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ripemd_prov.o)
[1029] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sha2_prov.o)
[1030] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sha3_prov.o)
[1031] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sm3_prov.o)
[1032] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_der2key.o)
[1033] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_epki2pki.o)
[1034] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_msblob2key.o)
[1035] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_pem2der.o)
[1036] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_pvk2key.o)
[1037] /private/test/prefix/lib/libcrypto.a(libdefault-lib-decode_spki2typespki.o)
[1038] /private/test/prefix/lib/libcrypto.a(libdefault-lib-encode_key2any.o)
[1039] /private/test/prefix/lib/libcrypto.a(libdefault-lib-encode_key2blob.o)
[1040] /private/test/prefix/lib/libcrypto.a(libdefault-lib-encode_key2ms.o)
[1041] /private/test/prefix/lib/libcrypto.a(libdefault-lib-encode_key2text.o)
[1042] /private/test/prefix/lib/libcrypto.a(libdefault-lib-endecoder_common.o)
[1043] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_common_codecs.o)
[1044] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_dsa_codecs.o)
[1045] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_kem_codecs.o)
[1046] /private/test/prefix/lib/libcrypto.a(libdefault-lib-dh_exch.o)
[1047] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ecdh_exch.o)
[1048] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ecx_exch.o)
[1049] /private/test/prefix/lib/libcrypto.a(libdefault-lib-kdf_exch.o)
[1050] /private/test/prefix/lib/libcrypto.a(libdefault-lib-argon2.o)
[1051] /private/test/prefix/lib/libcrypto.a(libdefault-lib-hkdf.o)
[1052] /private/test/prefix/lib/libcrypto.a(libdefault-lib-hmacdrbg_kdf.o)
[1053] /private/test/prefix/lib/libcrypto.a(libdefault-lib-kbkdf.o)
[1054] /private/test/prefix/lib/libcrypto.a(libdefault-lib-krb5kdf.o)
[1055] /private/test/prefix/lib/libcrypto.a(libdefault-lib-pbkdf2.o)
[1056] /private/test/prefix/lib/libcrypto.a(libdefault-lib-pbkdf2_fips.o)
[1057] /private/test/prefix/lib/libcrypto.a(libdefault-lib-pkcs12kdf.o)
[1058] /private/test/prefix/lib/libcrypto.a(libdefault-lib-scrypt.o)
[1059] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sshkdf.o)
[1060] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sskdf.o)
[1061] /private/test/prefix/lib/libcrypto.a(libdefault-lib-tls1_prf.o)
[1062] /private/test/prefix/lib/libcrypto.a(libdefault-lib-x942kdf.o)
[1063] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ec_kem.o)
[1064] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ecx_kem.o)
[1065] /private/test/prefix/lib/libcrypto.a(libdefault-lib-kem_util.o)
[1066] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_kem_kem.o)
[1067] /private/test/prefix/lib/libcrypto.a(libdefault-lib-mlx_kem.o)
[1068] /private/test/prefix/lib/libcrypto.a(libdefault-lib-rsa_kem.o)
[1069] /private/test/prefix/lib/libcrypto.a(libdefault-lib-dh_kmgmt.o)
[1070] /private/test/prefix/lib/libcrypto.a(libdefault-lib-dsa_kmgmt.o)
[1071] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ec_kmgmt.o)
[1072] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ecx_kmgmt.o)
[1073] /private/test/prefix/lib/libcrypto.a(libdefault-lib-kdf_legacy_kmgmt.o)
[1074] /private/test/prefix/lib/libcrypto.a(libdefault-lib-mac_legacy_kmgmt.o)
[1075] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_dsa_kmgmt.o)
[1076] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_kem_kmgmt.o)
[1077] /private/test/prefix/lib/libcrypto.a(libdefault-lib-mlx_kmgmt.o)
[1078] /private/test/prefix/lib/libcrypto.a(libdefault-lib-rsa_kmgmt.o)
[1079] /private/test/prefix/lib/libcrypto.a(libdefault-lib-slh_dsa_kmgmt.o)
[1080] /private/test/prefix/lib/libcrypto.a(libdefault-lib-blake2b_mac.o)
[1081] /private/test/prefix/lib/libcrypto.a(libdefault-lib-blake2s_mac.o)
[1082] /private/test/prefix/lib/libcrypto.a(libdefault-lib-cmac_prov.o)
[1083] /private/test/prefix/lib/libcrypto.a(libdefault-lib-gmac_prov.o)
[1084] /private/test/prefix/lib/libcrypto.a(libdefault-lib-hmac_prov.o)
[1085] /private/test/prefix/lib/libcrypto.a(libdefault-lib-kmac_prov.o)
[1086] /private/test/prefix/lib/libcrypto.a(libdefault-lib-poly1305_prov.o)
[1087] /private/test/prefix/lib/libcrypto.a(libdefault-lib-siphash_prov.o)
[1088] /private/test/prefix/lib/libcrypto.a(libdefault-lib-drbg.o)
[1089] /private/test/prefix/lib/libcrypto.a(libdefault-lib-drbg_ctr.o)
[1090] /private/test/prefix/lib/libcrypto.a(libdefault-lib-drbg_hash.o)
[1091] /private/test/prefix/lib/libcrypto.a(libdefault-lib-drbg_hmac.o)
[1092] /private/test/prefix/lib/libcrypto.a(libdefault-lib-seed_src.o)
[1093] /private/test/prefix/lib/libcrypto.a(libdefault-lib-test_rng.o)
[1094] /private/test/prefix/lib/libcrypto.a(libdefault-lib-rand_unix.o)
[1095] /private/test/prefix/lib/libcrypto.a(libdefault-lib-dsa_sig.o)
[1096] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ecdsa_sig.o)
[1097] /private/test/prefix/lib/libcrypto.a(libdefault-lib-eddsa_sig.o)
[1098] /private/test/prefix/lib/libcrypto.a(libdefault-lib-mac_legacy_sig.o)
[1099] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ml_dsa_sig.o)
[1100] /private/test/prefix/lib/libcrypto.a(libdefault-lib-rsa_sig.o)
[1101] /private/test/prefix/lib/libcrypto.a(libdefault-lib-slh_dsa_sig.o)
[1102] /private/test/prefix/lib/libcrypto.a(libdefault-lib-sm2_sig.o)
[1103] /private/test/prefix/lib/libcrypto.a(libdefault-lib-aes_skmgmt.o)
[1104] /private/test/prefix/lib/libcrypto.a(libdefault-lib-generic.o)
[1105] /private/test/prefix/lib/libcrypto.a(libdefault-lib-file_store.o)
[1106] /private/test/prefix/lib/libcrypto.a(libdefault-lib-file_store_any2obj.o)
[1107] /private/test/prefix/lib/libcrypto.a(libdefault-lib-ssl3_cbc.o)
[1108] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_dsa_gen.o)
[1109] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_dsa_sig.o)
[1110] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ec_gen.o)
[1111] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ec_sig.o)
[1112] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ecx_gen.o)
[1113] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ecx_key.o)
[1114] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ml_dsa_gen.o)
[1115] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_ml_dsa_key.o)
[1116] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_rsa_gen.o)
[1117] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_rsa_key.o)
[1118] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_slh_dsa_gen.o)
[1119] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_slh_dsa_key.o)
[1120] /private/test/prefix/lib/libcrypto.a(libcommon-lib-der_wrap_gen.o)
[1121] /private/test/prefix/lib/libcrypto.a(libcommon-lib-provider_ctx.o)
[1122] /private/test/prefix/lib/libcrypto.a(libcommon-lib-provider_err.o)
[1123] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon.o)
[1124] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_block.o)
[1125] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_ccm.o)
[1126] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_ccm_hw.o)
[1127] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_gcm.o)
[1128] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_gcm_hw.o)
[1129] /private/test/prefix/lib/libcrypto.a(libcommon-lib-ciphercommon_hw.o)
[1130] /private/test/prefix/lib/libcrypto.a(libcommon-lib-digestcommon.o)
[1131] /private/test/prefix/lib/libcrypto.a(libcommon-lib-tls_pad.o)
[1132] /Apple/SDK/MacOSX26.sdk/usr/lib/libm.tbd
[1133] Modules/expat/libexpat.a(xmlparse.o)
[1134] Modules/expat/libexpat.a(xmlrole.o)
[1135] Modules/expat/libexpat.a(xmltok.o)
[1136] /Apple/SDK/MacOSX26.sdk/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration.tbd
[1137] Modules/_hacl/libHacl_Hash_MD5.a(Hacl_Hash_MD5.o)
[1138] Modules/_hacl/libHacl_Hash_SHA1.a(Hacl_Hash_SHA1.o)
[1139] Modules/_hacl/libHacl_Hash_SHA2.a(Hacl_Hash_SHA2.o)
[1140] Modules/_hacl/libHacl_Hash_SHA3.a(Hacl_Hash_SHA3.o)
[1141] Modules/_hacl/libHacl_Hash_BLAKE2.a(Hacl_Hash_Blake2s.o)
[1142] Modules/_hacl/libHacl_Hash_BLAKE2.a(Hacl_Hash_Blake2b.o)
[1143] Modules/_hacl/libHacl_Hash_BLAKE2.a(Lib_Memzero0.o)
[1144] Modules/_hacl/libHacl_HMAC.a(Hacl_HMAC.o)
[1145] Modules/_hacl/libHacl_HMAC.a(Hacl_Streaming_HMAC.o)
[1146] /Apple/SDK/MacOSX26.sdk/usr/lib/libSystem.tbd
[1147] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libcommonCrypto.tbd
[1148] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libcompiler_rt.tbd
[1149] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libcopyfile.tbd
[1150] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libdyld.tbd
[1151] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_c.tbd
[1152] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_info.tbd
[1153] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_kernel.tbd
[1154] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_m.tbd
[1155] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_malloc.tbd
[1156] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_platform.tbd
[1157] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_pthread.tbd
[1158] /Apple/SDK/MacOSX26.sdk/usr/lib/system/libsystem_trace.tbd
"""
NATIVE_LINK_MAP_SDK_INTERFACES = (
    'System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd',
    'usr/lib/libdl.tbd',
    'usr/lib/libffi.tbd',
    'usr/lib/libm.tbd',
    'System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration.tbd',
    'usr/lib/libSystem.tbd',
    'usr/lib/system/libcommonCrypto.tbd',
    'usr/lib/system/libcompiler_rt.tbd',
    'usr/lib/system/libcopyfile.tbd',
    'usr/lib/system/libdyld.tbd',
    'usr/lib/system/libsystem_c.tbd',
    'usr/lib/system/libsystem_info.tbd',
    'usr/lib/system/libsystem_kernel.tbd',
    'usr/lib/system/libsystem_m.tbd',
    'usr/lib/system/libsystem_malloc.tbd',
    'usr/lib/system/libsystem_platform.tbd',
    'usr/lib/system/libsystem_pthread.tbd',
    'usr/lib/system/libsystem_trace.tbd',
)


def make_configuration(exe=".exe", multiarch="darwin", target=BUILD.ARM_TARGET):
    prefix, sdk = Path("/private/task/prefix"), Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")
    values = {
        "BUILDEXE": exe, "BUILDPYTHON": "python$(BUILDEXE)", "VERSION": "3.14", "MACHDEP": "darwin",
        "ABIFLAGS": "", "PY_ENABLE_SHARED": "0", "CC": "/Apple/clang", "PYTHON_FOR_REGEN": "/chosen/python3",
        "LIBEXPAT_A": "Modules/expat/libexpat.a", "MODULE_ZLIB_LDFLAGS": str(prefix / "lib/libz.a"),
        "CONFIGURE_CFLAGS": BUILD.compiler_flags(sdk, target), "CONFIGURE_CPPFLAGS": "",
        "CONFIGURE_LDFLAGS": BUILD.linker_flags(sdk, target) + " -L" + str(prefix / "lib"),
        "MACOSX_DEPLOYMENT_TARGET": "26.0",
        "MODBUILT_NAMES": " ".join(BUILD.BOOTSTRAP + BUILD.OPTIONAL), "MODSHARED_NAMES": "",
        "MODDISABLED_NAMES": " ".join(BUILD.DISABLED),
        "MODULE__CTYPES_CFLAGS": "-fno-strict-overflow -I" + str(sdk / "usr/include/ffi") + " -DUSING_APPLE_OS_LIBFFI=1 -DUSING_MALLOC_CLOSURE_DOT_C=1",
        "MODULE__CTYPES_LDFLAGS": "-lffi -ldl",
        "MODULE_PYEXPAT_CFLAGS": "-I$(srcdir)/Modules/expat",
        "MODULE_PYEXPAT_LDFLAGS": "-lm $(LIBEXPAT_A)",
        "MODULE__SCPROXY_LDFLAGS": "-framework SystemConfiguration -framework CoreFoundation",
        "MODULE__SSL_CFLAGS": "-I" + str(prefix / "include"),
        "MODULE__SSL_LDFLAGS": "-L" + str(prefix / "lib") + " -lssl -lcrypto", "MULTIARCH": multiarch,
    }
    required = "WITH_PYMALLOC HAVE_FORK HAVE_POSIX_SPAWN HAVE_SYS_RESOURCE_H HAVE_WAITPID HAVE_POLL HAVE_SOCKETPAIR HAVE_FFI_PREP_CIF_VAR HAVE_FFI_PREP_CLOSURE_LOC HAVE_FFI_CLOSURE_ALLOC".split()
    setup = (ROOT / "desktop/tools/macos_cpython_source_setup.local").read_bytes().replace(b"@MRK_PREFIX@", str(prefix).encode())
    names = BUILD.BOOTSTRAP + BUILD.INTRINSIC + BUILD.OPTIONAL
    files = {"Makefile": "".join(key + ("?=" if key == "PYTHON_FOR_REGEN" else "=") + value + "\n" for key, value in values.items()).encode(),
        "pyconfig.h": "".join("#define " + key + " 1\n" for key in required).encode(),
        "Modules/config.c": ("struct _inittab _PyImport_Inittab[] = {\n" +
            "".join('{"' + name + '", init_' + name + "},\n" for name in names) + "{0, 0}\n};\n").encode(),
        "Modules/Setup.local": setup}
    return files, prefix, sdk


def observed_arm_configuration():
    """Full inert configured CPython 3.14.7 DATA from Mac run37450356440.

    No lines are filtered. Only four authenticated path roles are substituted.
    Upstream copyright/comments are retained; existing CPython LICENSE and
    Doc/license.rst nominations in the source lock remain applicable.
    This fixture is not native build or supplier evidence.
    """
    # Makefile original SHA256 a02de2583b3bb2cfbb04e2fac1c5f5c72bf6f5a437895fa698f3e1486a857476
    # pyconfig.h original SHA256 9c567e7631b61240ec54ad6c4c342e59cabbf5881b8b441c13041102aaa703c3
    # Modules/config.c original SHA256 128e09577eeba21c93cb1a273d71b40a3a8df40c61bd3f20f132a90844c8d182
    # Modules/Setup.local original SHA256 2796c904873e2dfbe01e27c557317ad3a7c7629ea7623636ee3f124134914562
    files = {
        'Makefile': rb"""# Generated automatically from Makefile.pre by makesetup.
# Top-level Makefile for Python
#
# As distributed, this file is called Makefile.pre.in; it is processed
# into the real Makefile by running the script ./configure, which
# replaces things like @spam@ with values appropriate for your system.
# This means that if you edit Makefile, your changes get lost the next
# time you run the configure script.  Ideally, you can do:
#
#	./configure
#	make
#	make test
#	make install
#
# If you have a previous version of Python installed that you don't
# want to overwrite, you can use "make altinstall" instead of "make
# install".  Refer to the "Installing" section in the README file for
# additional details.
#
# See also the section "Build instructions" in the README file.

# === Variables set by makesetup ===

MODBUILT_NAMES=      _bisect  _heapq  _json  _random  _struct  math  binascii  zlib  fcntl  _posixsubprocess  select  unicodedata  _ctypes  _socket  _ssl  pyexpat  resource  _scproxy  _md5  _sha1  _sha2  _sha3  _blake2  _hmac  atexit  faulthandler  posix  _signal  _tracemalloc  _suggestions  _datetime  _codecs  _collections  errno  _io  itertools  _sre  _sysconfig  _thread  time  _types  _typing  _weakref  _abc  _functools  _locale  _opcode  _operator  _stat  _symtable  pwd
MODSHARED_NAMES=   
MODDISABLED_NAMES=   _asyncio  _bz2  _codecs_cn  _codecs_hk  _codecs_iso2022  _codecs_jp  _codecs_kr  _codecs_tw  _csv  _ctypes_test  _curses  _curses_panel  _dbm  _decimal  _elementtree  _gdbm  _hashlib  _interpchannels  _interpqueues  _interpreters  _lsprof  _lzma  _multibytecodec  _multiprocessing  _pickle  _posixshmem  _queue  _remote_debugging  _sqlite3  _statistics  _testbuffer  _testcapi  _testclinic  _testclinic_limited  _testimportmultiple  _testinternalcapi  _testlimitedcapi  _testmultiphase  _testsinglephase  _tkinter  _uuid  _xxtestfuzz  _zoneinfo  _zstd  array  cmath  grp  mmap  readline  syslog  termios  xxlimited  xxlimited_35  xxsubtype
MODOBJS=             Modules/_bisectmodule.o  Modules/_heapqmodule.o  Modules/_json.o  Modules/_randommodule.o  Modules/_struct.o  Modules/mathmodule.o  Modules/binascii.o  Modules/zlibmodule.o  Modules/fcntlmodule.o  Modules/_posixsubprocess.o  Modules/selectmodule.o  Modules/unicodedata.o  Modules/_ctypes/_ctypes.o Modules/_ctypes/callbacks.o Modules/_ctypes/callproc.o Modules/_ctypes/stgdict.o Modules/_ctypes/cfield.o Modules/_ctypes/malloc_closure.o  Modules/socketmodule.o  Modules/_ssl.o  Modules/pyexpat.o  Modules/resource.o  Modules/_scproxy.o  Modules/md5module.o  Modules/sha1module.o  Modules/sha2module.o  Modules/sha3module.o  Modules/blake2module.o  Modules/hmacmodule.o  Modules/atexitmodule.o  Modules/faulthandler.o  Modules/posixmodule.o  Modules/signalmodule.o  Modules/_tracemalloc.o  Modules/_suggestions.o  Modules/_datetimemodule.o  Modules/_codecsmodule.o  Modules/_collectionsmodule.o  Modules/errnomodule.o  Modules/_io/_iomodule.o Modules/_io/iobase.o Modules/_io/fileio.o Modules/_io/bytesio.o Modules/_io/bufferedio.o Modules/_io/textio.o Modules/_io/stringio.o  Modules/itertoolsmodule.o  Modules/_sre/sre.o  Modules/_sysconfig.o  Modules/_threadmodule.o  Modules/timemodule.o  Modules/_typesmodule.o  Modules/_typingmodule.o  Modules/_weakref.o  Modules/_abc.o  Modules/_functoolsmodule.o  Modules/_localemodule.o  Modules/_opcode.o  Modules/_operator.o  Modules/_stat.o  Modules/symtablemodule.o  Modules/pwdmodule.o
MODLIBS=           $(LOCALMODLIBS) $(BASEMODLIBS)

# === Variables set by configure
VERSION=	3.14
srcdir=		/private/task/sources/cpython
VPATH=		/private/task/sources/cpython
abs_srcdir=	/private/task/sources/cpython
abs_builddir=	/private/task/build/cpython


CC=		/Apple/clang
CXX=		/usr/bin/clang++
LINKCC=		$(PURIFY) $(CC)
AR=		/Library/Developer/CommandLineTools/usr/bin/ar
READELF=	@READELF@
SOABI=		cpython-314-darwin
ABIFLAGS=	
ABI_THREAD=	
LDVERSION=	$(VERSION)$(ABIFLAGS)
LIBPYTHON=
GITVERSION=	
GITTAG=		
GITBRANCH=	
PGO_PROF_GEN_FLAG=-fprofile-instr-generate
PGO_PROF_USE_FLAG=-fprofile-instr-use="$(shell pwd)/code.profclangd"
LLVM_PROF_MERGER= /usr/bin/xcrun llvm-profdata merge -output="$(shell pwd)/code.profclangd" "$(shell pwd)"/*.profclangr 
LLVM_PROF_FILE=LLVM_PROFILE_FILE="$(shell pwd)/code-%p.profclangr"
LLVM_PROF_ERR=no
DTRACE=         
DFLAGS=         
DTRACE_HEADERS= 
DTRACE_OBJS=    
DSYMUTIL=       
DSYMUTIL_PATH=  

GNULD=		no

# Shell used by make (some versions default to the login shell, which is bad)
SHELL=		/bin/sh -e

# Use this to make a link between python$(VERSION) and python in $(BINDIR)
LN=		ln

# Portable install script (configure doesn't always guess right)
INSTALL=	/usr/bin/install -c
INSTALL_PROGRAM=${INSTALL}
INSTALL_SCRIPT= ${INSTALL}
INSTALL_DATA=	${INSTALL} -m 644
# Shared libraries must be installed with executable mode on some systems;
# rather than figuring out exactly which, we always give them executable mode.
INSTALL_SHARED= ${INSTALL} -m 755

MKDIR_P=	mkdir -p

MAKESETUP=      $(srcdir)/Modules/makesetup

# Compiler options
OPT=		-DNDEBUG -g -O3 -Wall
BASECFLAGS=	 -fno-strict-overflow -Wsign-compare -Wunreachable-code
BASECPPFLAGS=	-IObjects -IInclude -IPython
CONFIGURE_CFLAGS=	-O2 -g0 -fPIC -arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0
# CFLAGS_NODIST is used for building the interpreter and stdlib C extensions.
# Use it when a compiler flag should _not_ be part of the distutils CFLAGS
# once Python is installed (Issue #21121).
CONFIGURE_CFLAGS_NODIST= -std=c11 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wstrict-prototypes -Werror=implicit-function-declaration -fvisibility=hidden -Werror=unguarded-availability
# LDFLAGS_NODIST is used in the same manner as CFLAGS_NODIST.
# Use it when a linker flag should _not_ be part of the distutils LDFLAGS
# once Python is installed (bpo-35257)
CONFIGURE_LDFLAGS_NODIST=
# LDFLAGS_NOLTO is an extra flag to disable lto. It is used to speed up building
# of _bootstrap_python and _freeze_module tools, which don't need LTO.
CONFIGURE_LDFLAGS_NOLTO=
CONFIGURE_CPPFLAGS=	
CONFIGURE_LDFLAGS=	-arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0 -L/private/task/prefix/lib
# Avoid assigning CFLAGS, LDFLAGS, etc. so users can use them on the
# command line to append to these values without stomping the pre-set
# values.
PY_CFLAGS=	$(BASECFLAGS) $(OPT) $(CONFIGURE_CFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
PY_CFLAGS_NODIST=$(CONFIGURE_CFLAGS_NODIST) $(CFLAGS_NODIST) -I$(srcdir)/Include/internal -I$(srcdir)/Include/internal/mimalloc
# Both CPPFLAGS and LDFLAGS need to contain the shell's value for setup.py to
# be able to build extension modules using the directories specified in the
# environment variables
PY_CPPFLAGS=	$(BASECPPFLAGS) -I. -I$(srcdir)/Include $(CONFIGURE_CPPFLAGS) $(CPPFLAGS)
PY_LDFLAGS=	$(CONFIGURE_LDFLAGS) $(LDFLAGS)
PY_LDFLAGS_NODIST=$(CONFIGURE_LDFLAGS_NODIST) $(LDFLAGS_NODIST)
PY_LDFLAGS_NOLTO=$(PY_LDFLAGS) $(CONFIGURE_LDFLAGS_NOLTO) $(LDFLAGS_NODIST)
NO_AS_NEEDED=	
CCSHARED=	
# LINKFORSHARED are the flags passed to the $(CC) command that links
# the python executable -- this is only needed for a few systems
LINKFORSHARED=	-Wl,-stack_size,1000000  -framework CoreFoundation
ARFLAGS=	rcs
# Extra C flags added for building the interpreter object files.
CFLAGSFORSHARED=
# C flags used for building the interpreter object files
PY_STDMODULE_CFLAGS= $(PY_CFLAGS) $(PY_CFLAGS_NODIST) $(PY_CPPFLAGS) $(CFLAGSFORSHARED)
PY_BUILTIN_MODULE_CFLAGS= $(PY_STDMODULE_CFLAGS) -DPy_BUILD_CORE_BUILTIN
PY_CORE_CFLAGS=	$(PY_STDMODULE_CFLAGS) -DPy_BUILD_CORE
# Linker flags used for building the interpreter object files
PY_CORE_LDFLAGS=$(PY_LDFLAGS) $(PY_LDFLAGS_NODIST)
# Strict or non-strict aliasing flags used to compile dtoa.c, see above
CFLAGS_ALIASING=
# Compilation flags only for ceval.c.
CFLAGS_CEVAL=


# Machine-dependent subdirectories
MACHDEP=	darwin

# Multiarch directory (may be empty)
MULTIARCH=	darwin
MULTIARCH_CPPFLAGS = -DMULTIARCH=\"darwin\"

# Install prefix for architecture-independent files
prefix=		/mrk-python-not-installed

# Install prefix for architecture-dependent files
exec_prefix=	${prefix}

# For cross compilation, we distinguish between "prefix" (where we install the
# files) and "host_prefix" (where getpath.c expects to find the files at
# runtime)
host_prefix= 	${prefix}
host_exec_prefix= 	${exec_prefix}


# Install prefix for data files
datarootdir=    ${prefix}/share

# Expanded directories
BINDIR=		${exec_prefix}/bin
LIBDIR=		${exec_prefix}/lib
MANDIR=		${datarootdir}/man
INCLUDEDIR=	${prefix}/include
CONFINCLUDEDIR=	$(exec_prefix)/include
PLATLIBDIR=	lib
SCRIPTDIR=	$(prefix)/$(PLATLIBDIR)
# executable name for shebangs
EXENAME=	$(BINDIR)/python$(LDVERSION)$(EXE)
# Variable used by ensurepip
WHEEL_PKG_DIR=	

# Detailed destination directories
BINLIBDEST=	${exec_prefix}/${PLATLIBDIR}/python$(VERSION)$(ABI_THREAD)
LIBDEST=	$(SCRIPTDIR)/python$(VERSION)$(ABI_THREAD)
INCLUDEPY=	$(INCLUDEDIR)/python$(LDVERSION)
CONFINCLUDEPY=	$(CONFINCLUDEDIR)/python$(LDVERSION)

# Symbols used for using shared libraries
SHLIB_SUFFIX=	.so
EXT_SUFFIX=	.cpython-314-darwin.so
LDSHARED=	$(CC) -bundle -undefined dynamic_lookup $(PY_LDFLAGS)
BLDSHARED=	$(CC) -bundle -undefined dynamic_lookup $(PY_CORE_LDFLAGS)
LDCXXSHARED=	$(CXX) -bundle -undefined dynamic_lookup $(PY_LDFLAGS)
DESTSHARED=	$(BINLIBDEST)/lib-dynload

# List of exported symbols for AIX
EXPORTSYMS=	
EXPORTSFROM=	

# Executable suffix (.exe on Windows and Mac OS X)
EXE=		
BUILDEXE=	.exe

# Name of the patch file to apply for app store compliance
APP_STORE_COMPLIANCE_PATCH=

# Short name and location for Mac OS X Python framework
UNIVERSALSDK=
PYTHONFRAMEWORK=	
PYTHONFRAMEWORKDIR=	no-framework
PYTHONFRAMEWORKPREFIX=	
PYTHONFRAMEWORKINSTALLDIR= 
PYTHONFRAMEWORKINSTALLNAMEPREFIX= 
RESSRCDIR= 
# macOS deployment target selected during configure, to be checked
# by distutils. The export statement is needed to ensure that the
# deployment target is active during build.
MACOSX_DEPLOYMENT_TARGET=26.0
export MACOSX_DEPLOYMENT_TARGET

# iOS Deployment target selected during configure. Unlike macOS, the iOS
# deployment target is controlled using `-mios-version-min` arguments added to
# CFLAGS and LDFLAGS by the configure script. This variable is not used during
# the build, and is only listed here so it will be included in sysconfigdata.
IPHONEOS_DEPLOYMENT_TARGET=

# Option to install to strip binaries
STRIPFLAG=-s

# Flags to lipo to produce a 32-bit-only universal executable
LIPO_32BIT_FLAGS=

# Flags to lipo to produce an intel-64-only universal executable
LIPO_INTEL64_FLAGS=

# Environment to run shared python without installed libraries
RUNSHARED=       

# ensurepip options
ENSUREPIP=      no

# Internal static libraries
LIBMPDEC_A= Modules/_decimal/libmpdec/libmpdec.a
LIBEXPAT_A= Modules/expat/libexpat.a

# HACL* build configuration
LIBHACL_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
LIBHACL_LDFLAGS=
LIBHACL_BLAKE2_SIMD128_CFLAGS= -DHACL_CAN_COMPILE_VEC128
LIBHACL_BLAKE2_SIMD256_CFLAGS= -DHACL_CAN_COMPILE_VEC256

# Module state, compiler flags and linker flags
# Empty CFLAGS and LDFLAGS are omitted.
# states:
#   * yes: module is available
#   * missing: build dependency is missing
#   * disabled: module is disabled
#   * n/a: module is not available on the current platform
# MODULE_EGG_STATE=yes  # yes, missing, disabled, n/a
# MODULE_EGG_CFLAGS=
# MODULE_EGG_LDFLAGS=
MODULE__IO_STATE=yes
MODULE__IO_CFLAGS=-I$(srcdir)/Modules/_io
MODULE_TIME_STATE=yes
MODULE_TIME_LDFLAGS=
MODULE_ARRAY_STATE=yes
MODULE__ASYNCIO_STATE=yes
MODULE__BISECT_STATE=yes
MODULE__CSV_STATE=yes
MODULE__HEAPQ_STATE=yes
MODULE__JSON_STATE=yes
MODULE__LSPROF_STATE=yes
MODULE__PICKLE_STATE=yes
MODULE__POSIXSUBPROCESS_STATE=yes
MODULE__QUEUE_STATE=yes
MODULE__RANDOM_STATE=yes
MODULE__REMOTE_DEBUGGING_STATE=yes
MODULE_SELECT_STATE=yes
MODULE__STRUCT_STATE=yes
MODULE__TYPES_STATE=yes
MODULE__TYPING_STATE=yes
MODULE__INTERPRETERS_STATE=yes
MODULE__INTERPCHANNELS_STATE=yes
MODULE__INTERPQUEUES_STATE=yes
MODULE__ZONEINFO_STATE=yes
MODULE__MULTIPROCESSING_STATE=yes
MODULE__MULTIPROCESSING_CFLAGS=-I$(srcdir)/Modules/_multiprocessing
MODULE__POSIXSHMEM_STATE=yes
MODULE__POSIXSHMEM_CFLAGS=-I$(srcdir)/Modules/_multiprocessing
MODULE__POSIXSHMEM_LDFLAGS=
MODULE__STATISTICS_STATE=yes
MODULE__STATISTICS_LDFLAGS=
MODULE_CMATH_STATE=yes
MODULE_CMATH_LDFLAGS=
MODULE_MATH_STATE=yes
MODULE_MATH_LDFLAGS=
MODULE__DATETIME_STATE=yes
MODULE__DATETIME_LDFLAGS= 
MODULE_FCNTL_STATE=yes
MODULE_FCNTL_LDFLAGS=
MODULE_MMAP_STATE=yes
MODULE__SOCKET_STATE=yes
MODULE__SOCKET_LDFLAGS=
MODULE_GRP_STATE=yes
MODULE_PWD_STATE=yes
MODULE_RESOURCE_STATE=yes
MODULE__SCPROXY_STATE=yes
MODULE__SCPROXY_LDFLAGS=-framework SystemConfiguration -framework CoreFoundation
MODULE_SYSLOG_STATE=yes
MODULE_TERMIOS_STATE=yes
MODULE_PYEXPAT_STATE=yes
MODULE_PYEXPAT_CFLAGS=-I$(srcdir)/Modules/expat
MODULE_PYEXPAT_LDFLAGS=-lm $(LIBEXPAT_A)
MODULE__ELEMENTTREE_STATE=yes
MODULE__ELEMENTTREE_CFLAGS=-I$(srcdir)/Modules/expat
MODULE__CODECS_CN_STATE=yes
MODULE__CODECS_HK_STATE=yes
MODULE__CODECS_ISO2022_STATE=yes
MODULE__CODECS_JP_STATE=yes
MODULE__CODECS_KR_STATE=yes
MODULE__CODECS_TW_STATE=yes
MODULE__MULTIBYTECODEC_STATE=yes
MODULE_UNICODEDATA_STATE=yes
MODULE__MD5_STATE=yes
MODULE__MD5_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__MD5_LDFLAGS=$(LIBHACL_MD5_LIB_STATIC)
MODULE__SHA1_STATE=yes
MODULE__SHA1_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__SHA1_LDFLAGS=$(LIBHACL_SHA1_LIB_STATIC)
MODULE__SHA2_STATE=yes
MODULE__SHA2_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__SHA2_LDFLAGS=$(LIBHACL_SHA2_LIB_STATIC)
MODULE__SHA3_STATE=yes
MODULE__SHA3_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__SHA3_LDFLAGS=$(LIBHACL_SHA3_LIB_STATIC)
MODULE__BLAKE2_STATE=yes
MODULE__BLAKE2_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__BLAKE2_LDFLAGS=$(LIBHACL_BLAKE2_LIB_STATIC)
MODULE__HMAC_STATE=yes
MODULE__HMAC_CFLAGS=-I$(srcdir)/Modules/_hacl -I$(srcdir)/Modules/_hacl/include -D_BSD_SOURCE -D_DEFAULT_SOURCE $(PY_STDMODULE_CFLAGS) $(CCSHARED)
MODULE__HMAC_LDFLAGS=$(LIBHACL_HMAC_LIB_STATIC)
MODULE__CTYPES_STATE=yes
MODULE__CTYPES_CFLAGS=-fno-strict-overflow -I/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk/usr/include/ffi -DUSING_APPLE_OS_LIBFFI=1 -DUSING_MALLOC_CLOSURE_DOT_C=1
MODULE__CTYPES_LDFLAGS=-lffi -ldl
MODULE__CURSES_STATE=yes
MODULE__CURSES_CFLAGS= -D_XOPEN_SOURCE_EXTENDED=1
MODULE__CURSES_LDFLAGS=-lncurses

MODULE__CURSES_PANEL_STATE=yes
MODULE__CURSES_PANEL_CFLAGS=  -D_XOPEN_SOURCE_EXTENDED=1
MODULE__CURSES_PANEL_LDFLAGS=-lpanel -lncurses

MODULE__DECIMAL_STATE=yes
MODULE__DECIMAL_CFLAGS=-I$(srcdir)/Modules/_decimal/libmpdec -DUNIVERSAL=1
MODULE__DECIMAL_LDFLAGS=-lm $(LIBMPDEC_A)
MODULE__DBM_STATE=yes
MODULE__DBM_CFLAGS=-DUSE_NDBM
MODULE__DBM_LDFLAGS=
MODULE__GDBM_STATE=missing
MODULE_READLINE_STATE=yes
MODULE_READLINE_CFLAGS=
MODULE_READLINE_LDFLAGS=-lreadline
MODULE__SQLITE3_STATE=yes
MODULE__SQLITE3_CFLAGS= -I$(srcdir)/Modules/_sqlite
MODULE__SQLITE3_LDFLAGS=-lsqlite3
MODULE__TKINTER_STATE=missing
MODULE__UUID_STATE=yes
MODULE__UUID_CFLAGS=
MODULE__UUID_LDFLAGS=
MODULE_ZLIB_STATE=yes
MODULE_ZLIB_CFLAGS=-I/private/task/prefix/include
MODULE_ZLIB_LDFLAGS=/private/task/prefix/lib/libz.a
MODULE_BINASCII_STATE=yes
MODULE_BINASCII_CFLAGS=-DUSE_ZLIB_CRC32 -I/private/task/prefix/include
MODULE_BINASCII_LDFLAGS=/private/task/prefix/lib/libz.a
MODULE__BZ2_STATE=yes
MODULE__BZ2_CFLAGS=
MODULE__BZ2_LDFLAGS=-lbz2
MODULE__LZMA_STATE=missing
MODULE__ZSTD_STATE=missing
MODULE__SSL_STATE=yes
MODULE__SSL_CFLAGS=-I/private/task/prefix/include
MODULE__SSL_LDFLAGS=-L/private/task/prefix/lib  -lssl -lcrypto
MODULE__HASHLIB_STATE=yes
MODULE__HASHLIB_CFLAGS=-I/private/task/prefix/include
MODULE__HASHLIB_LDFLAGS=-L/private/task/prefix/lib   -lcrypto
MODULE__TESTCAPI_STATE=disabled
MODULE__TESTCLINIC_STATE=disabled
MODULE__TESTCLINIC_LIMITED_STATE=disabled
MODULE__TESTLIMITEDCAPI_STATE=disabled
MODULE__TESTINTERNALCAPI_STATE=disabled
MODULE__TESTBUFFER_STATE=disabled
MODULE__TESTIMPORTMULTIPLE_STATE=disabled
MODULE__TESTMULTIPHASE_STATE=disabled
MODULE__TESTSINGLEPHASE_STATE=disabled
MODULE_XXSUBTYPE_STATE=disabled
MODULE__XXTESTFUZZ_STATE=disabled
MODULE__CTYPES_TEST_STATE=disabled
MODULE_XXLIMITED_STATE=disabled
MODULE_XXLIMITED_35_STATE=disabled


# Default zoneinfo.TZPATH. Added here to expose it in sysconfig.get_config_var
TZPATH=/usr/share/zoneinfo:/usr/lib/zoneinfo:/usr/share/lib/zoneinfo:/etc/zoneinfo

# If to install mimalloc headers
INSTALL_MIMALLOC=no

# Modes for directories, executables and data files created by the
# install process.  Default to user-only-writable for all file types.
DIRMODE=	755
EXEMODE=	755
FILEMODE=	644

# configure script arguments
CONFIG_ARGS=	 '--prefix=/mrk-python-not-installed' '--with-platlibdir=lib' '--disable-shared' '--without-mimalloc' '--with-pymalloc' '--with-lto=no' '--disable-optimizations' '--disable-test-modules' '--with-ensurepip=no' '--with-pkg-config=no' '--with-openssl-rpath=no' '--with-openssl=/private/task/prefix' 'CC=/Apple/clang' 'CFLAGS=-O2 -g0 -fPIC -arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0' 'LDFLAGS=-arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0 -L/private/task/prefix/lib' 'CPPFLAGS=' 'ZLIB_CFLAGS=-I/private/task/prefix/include' 'ZLIB_LIBS=/private/task/prefix/lib/libz.a'


# Subdirectories with code
SRCDIRS= 	  Modules   Modules/_ctypes   Modules/_decimal   Modules/_decimal/libmpdec   Modules/_hacl   Modules/_io   Modules/_multiprocessing   Modules/_sqlite   Modules/_sre   Modules/_testcapi   Modules/_testinternalcapi   Modules/_testlimitedcapi   Modules/_xxtestfuzz   Modules/_zstd   Modules/cjkcodecs   Modules/expat   Objects   Objects/mimalloc   Objects/mimalloc/prim   Parser   Parser/tokenizer   Parser/lexer   Programs   Python   Python/frozen_modules

# Other subdirectories
SUBDIRSTOO=	Include Lib Misc

# Files and directories to be distributed
CONFIGFILES=	configure configure.ac acconfig.h pyconfig.h.in Makefile.pre.in
DISTFILES=	README.rst ChangeLog $(CONFIGFILES)
DISTDIRS=	$(SUBDIRS) $(SUBDIRSTOO) Ext-dummy
DIST=		$(DISTFILES) $(DISTDIRS)


LIBRARY=	libpython$(VERSION)$(ABIFLAGS).a
LDLIBRARY=      libpython$(VERSION)$(ABIFLAGS).a
BLDLIBRARY=     $(LDLIBRARY)
MODULE_LDFLAGS_SHARED=$(if $(LIBPYTHON),$(BLDLIBRARY))
PY3LIBRARY=     
DLLLIBRARY=	
LDLIBRARYDIR=   
INSTSONAME=	$(LDLIBRARY)
LIBRARY_DEPS=	$(LIBRARY) $(PY3LIBRARY) $(EXPORTSYMS)
LINK_PYTHON_DEPS=$(LIBRARY_DEPS)
PY_ENABLE_SHARED=	0
STATIC_LIBPYTHON=	1


LIBS=		-ldl  -framework CoreFoundation
LIBM=		
LIBC=		
SYSLIBS=	$(LIBM) $(LIBC)
SHLIBS=		$(LIBS)

DLINCLDIR=	.
DYNLOADFILE=	dynload_shlib.o
MACHDEP_OBJS=	
LIBOBJDIR=	Python/
LIBOBJS=	

PYTHON=		python$(EXE)
BUILDPYTHON=	python$(BUILDEXE)

HOSTRUNNER= 

PYTHON_FOR_REGEN?=/chosen/python3
UPDATE_FILE=$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/update_file.py
PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E
# Single-platform builds depend on $(BUILDPYTHON). Cross builds use an
# external "build Python" and have an empty PYTHON_FOR_BUILD_DEPS.
PYTHON_FOR_BUILD_DEPS=$(BUILDPYTHON)

# Single-platform builds use Programs/_freeze_module.c for bootstrapping and
# ./_bootstrap_python Programs/_freeze_module.py for remaining modules
# Cross builds use an external "build Python" for all modules.
PYTHON_FOR_FREEZE=./_bootstrap_python
FREEZE_MODULE_BOOTSTRAP=./Programs/_freeze_module
FREEZE_MODULE_BOOTSTRAP_DEPS=Programs/_freeze_module
FREEZE_MODULE=$(PYTHON_FOR_FREEZE) $(srcdir)/Programs/_freeze_module.py
FREEZE_MODULE_DEPS=_bootstrap_python $(srcdir)/Programs/_freeze_module.py

_PYTHON_HOST_PLATFORM=
BUILD_GNU_TYPE=	aarch64-apple-darwin25.6.0
HOST_GNU_TYPE=	aarch64-apple-darwin25.6.0

# The task to run while instrumented when building the profile-opt target.
# To speed up profile generation, we don't run the full unit test suite
# by default. The default is "-m test --pgo". To run more tests, use
# PROFILE_TASK="-m test --pgo-extended"
PROFILE_TASK=	-m test --pgo --timeout=$(TESTTIMEOUT)

# report files for gcov / lcov coverage report
COVERAGE_INFO=	$(abs_builddir)/coverage.info
COVERAGE_REPORT=$(abs_builddir)/lcov-report
COVERAGE_LCOV_OPTIONS=--rc lcov_branch_coverage=1
COVERAGE_REPORT_OPTIONS=--rc lcov_branch_coverage=1 --branch-coverage --title "CPython $(VERSION) LCOV report [commit $(shell $(GITVERSION))]"


# === Definitions added by makesetup ===


LOCALMODLIBS= $(MODULE__BISECT_LDFLAGS) $(MODULE__HEAPQ_LDFLAGS) $(MODULE__JSON_LDFLAGS) $(MODULE__RANDOM_LDFLAGS) $(MODULE__STRUCT_LDFLAGS) $(MODULE_MATH_LDFLAGS)  /private/task/prefix/lib/libz.a  /private/task/prefix/lib/libz.a $(MODULE_FCNTL_LDFLAGS) $(MODULE__POSIXSUBPROCESS_LDFLAGS) $(MODULE_SELECT_LDFLAGS) $(MODULE_UNICODEDATA_LDFLAGS) $(MODULE__CTYPES_LDFLAGS) $(MODULE__SOCKET_LDFLAGS)  /private/task/prefix/lib/libssl.a /private/task/prefix/lib/libcrypto.a $(MODULE_PYEXPAT_LDFLAGS) $(MODULE_RESOURCE_LDFLAGS) $(MODULE__SCPROXY_LDFLAGS)  Modules/_hacl/libHacl_Hash_MD5.a  Modules/_hacl/libHacl_Hash_SHA1.a  Modules/_hacl/libHacl_Hash_SHA2.a  Modules/_hacl/libHacl_Hash_SHA3.a  Modules/_hacl/libHacl_Hash_BLAKE2.a  Modules/_hacl/libHacl_HMAC.a $(MODULE_ATEXIT_LDFLAGS) $(MODULE_FAULTHANDLER_LDFLAGS) $(MODULE_POSIX_LDFLAGS) $(MODULE__SIGNAL_LDFLAGS) $(MODULE__TRACEMALLOC_LDFLAGS) $(MODULE__SUGGESTIONS_LDFLAGS) $(MODULE__DATETIME_LDFLAGS) $(MODULE__CODECS_LDFLAGS) $(MODULE__COLLECTIONS_LDFLAGS) $(MODULE_ERRNO_LDFLAGS) $(MODULE__IO_LDFLAGS) $(MODULE_ITERTOOLS_LDFLAGS) $(MODULE__SRE_LDFLAGS) $(MODULE__SYSCONFIG_LDFLAGS) $(MODULE__THREAD_LDFLAGS) $(MODULE_TIME_LDFLAGS) $(MODULE__TYPES_LDFLAGS) $(MODULE__TYPING_LDFLAGS) $(MODULE__WEAKREF_LDFLAGS) $(MODULE__ABC_LDFLAGS) $(MODULE__FUNCTOOLS_LDFLAGS) $(MODULE__LOCALE_LDFLAGS) $(MODULE__OPCODE_LDFLAGS) $(MODULE__OPERATOR_LDFLAGS) $(MODULE__STAT_LDFLAGS) $(MODULE__SYMTABLE_LDFLAGS) $(MODULE_PWD_LDFLAGS)
BASEMODLIBS=
PYTHONPATH=$(COREPYTHONPATH)
COREPYTHONPATH=$(DESTPATH)$(SITEPATH)$(TESTPATH)
TESTPATH=
SITEPATH=
DESTPATH=
MACHDESTLIB=$(BINLIBDEST)
DESTLIB=$(LIBDEST)



##########################################################################
# Modules
MODULE_OBJS=	\
		Modules/config.o \
		Modules/main.o \
		Modules/gcmodule.o

IO_H=		Modules/_io/_iomodule.h

IO_OBJS=	\
		Modules/_io/_iomodule.o \
		Modules/_io/iobase.o \
		Modules/_io/fileio.o \
		Modules/_io/bufferedio.o \
		Modules/_io/textio.o \
		Modules/_io/bytesio.o \
		Modules/_io/stringio.o


##########################################################################
# mimalloc

MIMALLOC_HEADERS= \
	$(srcdir)/Include/internal/pycore_mimalloc.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc/atomic.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc/internal.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc/prim.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc/track.h \
	$(srcdir)/Include/internal/mimalloc/mimalloc/types.h


##########################################################################
# Parser

PEGEN_OBJS=		\
		Parser/pegen.o \
		Parser/pegen_errors.o \
		Parser/action_helpers.o \
		Parser/parser.o \
		Parser/string_parser.o \
		Parser/peg_api.o

TOKENIZER_OBJS=		\
		Parser/lexer/buffer.o \
		Parser/lexer/lexer.o \
		Parser/lexer/state.o \
		Parser/tokenizer/file_tokenizer.o \
		Parser/tokenizer/readline_tokenizer.o \
		Parser/tokenizer/string_tokenizer.o \
		Parser/tokenizer/utf8_tokenizer.o \
		Parser/tokenizer/helpers.o

PEGEN_HEADERS= \
		$(srcdir)/Include/internal/pycore_parser.h \
		$(srcdir)/Parser/pegen.h \
		$(srcdir)/Parser/string_parser.h

TOKENIZER_HEADERS= \
		Parser/lexer/buffer.h \
		Parser/lexer/lexer.h \
		Parser/lexer/state.h \
		Parser/tokenizer/tokenizer.h \
		Parser/tokenizer/helpers.h

POBJS=		\
		Parser/token.o \

PARSER_OBJS=	$(POBJS) $(PEGEN_OBJS) $(TOKENIZER_OBJS) Parser/myreadline.o

PARSER_HEADERS= \
		$(PEGEN_HEADERS) \
		$(TOKENIZER_HEADERS)

##########################################################################
# Python

PYTHON_OBJS=	\
		Python/_contextvars.o \
		Python/_warnings.o \
		Python/Python-ast.o \
		Python/Python-tokenize.o \
		Python/asdl.o \
		Python/assemble.o \
		Python/ast.o \
		Python/ast_preprocess.o \
		Python/ast_unparse.o \
		Python/bltinmodule.o \
		Python/brc.o \
		Python/ceval.o \
		Python/codecs.o \
		Python/codegen.o \
		Python/compile.o \
		Python/context.o \
		Python/critical_section.o \
		Python/crossinterp.o \
		Python/dynamic_annotations.o \
		Python/errors.o \
		Python/flowgraph.o \
		Python/frame.o \
		Python/frozenmain.o \
		Python/future.o \
		Python/gc.o \
		Python/gc_free_threading.o \
		Python/gc_gil.o \
		Python/getargs.o \
		Python/getcompiler.o \
		Python/getcopyright.o \
		Python/getplatform.o \
		Python/getversion.o \
		Python/ceval_gil.o \
		Python/hamt.o \
		Python/hashtable.o \
		Python/import.o \
		Python/importdl.o \
		Python/index_pool.o \
		Python/initconfig.o \
		Python/interpconfig.o \
		Python/instrumentation.o \
		Python/instruction_sequence.o \
		Python/intrinsics.o \
		Python/jit.o \
		Python/legacy_tracing.o \
		Python/lock.o \
		Python/marshal.o \
		Python/modsupport.o \
		Python/mysnprintf.o \
		Python/mystrtoul.o \
		Python/object_stack.o \
		Python/optimizer.o \
		Python/optimizer_analysis.o \
		Python/optimizer_symbols.o \
		Python/parking_lot.o \
		Python/pathconfig.o \
		Python/preconfig.o \
		Python/pyarena.o \
		Python/pyctype.o \
		Python/pyfpe.o \
		Python/pyhash.o \
		Python/pylifecycle.o \
		Python/pymath.o \
		Python/pystate.o \
		Python/pythonrun.o \
		Python/pytime.o \
		Python/qsbr.o \
		Python/bootstrap_hash.o \
		Python/specialize.o \
		Python/stackrefs.o \
		Python/structmember.o \
		Python/symtable.o \
		Python/sysmodule.o \
		Python/thread.o \
		Python/traceback.o \
		Python/tracemalloc.o \
		Python/uniqueid.o \
		Python/getopt.o \
		Python/pystrcmp.o \
		Python/pystrtod.o \
		Python/pystrhex.o \
		Python/dtoa.o \
		Python/formatter_unicode.o \
		Python/fileutils.o \
		Python/suggestions.o \
		Python/perf_trampoline.o \
		Python/perf_jit_trampoline.o \
		Python/remote_debugging.o \
		Python/$(DYNLOADFILE) \
		$(LIBOBJS) \
		$(MACHDEP_OBJS) \
		$(DTRACE_OBJS) \
		


##########################################################################
# Objects
OBJECT_OBJS=	\
		Objects/abstract.o \
		Objects/boolobject.o \
		Objects/bytes_methods.o \
		Objects/bytearrayobject.o \
		Objects/bytesobject.o \
		Objects/call.o \
		Objects/capsule.o \
		Objects/cellobject.o \
		Objects/classobject.o \
		Objects/codeobject.o \
		Objects/complexobject.o \
		Objects/descrobject.o \
		Objects/enumobject.o \
		Objects/exceptions.o \
		Objects/genericaliasobject.o \
		Objects/genobject.o \
		Objects/fileobject.o \
		Objects/floatobject.o \
		Objects/frameobject.o \
		Objects/funcobject.o \
		Objects/interpolationobject.o \
		Objects/iterobject.o \
		Objects/listobject.o \
		Objects/longobject.o \
		Objects/dictobject.o \
		Objects/odictobject.o \
		Objects/memoryobject.o \
		Objects/methodobject.o \
		Objects/moduleobject.o \
		Objects/namespaceobject.o \
		Objects/object.o \
		Objects/obmalloc.o \
		Objects/picklebufobject.o \
		Objects/rangeobject.o \
		Objects/setobject.o \
		Objects/sliceobject.o \
		Objects/structseq.o \
		Objects/templateobject.o \
		Objects/tupleobject.o \
		Objects/typeobject.o \
		Objects/typevarobject.o \
		Objects/unicodeobject.o \
		Objects/unicodectype.o \
		Objects/unionobject.o \
		Objects/weakrefobject.o \
		

##########################################################################
# objects that get linked into the Python library
LIBRARY_OBJS_OMIT_FROZEN=	\
		Modules/getbuildinfo.o \
		$(PARSER_OBJS) \
		$(OBJECT_OBJS) \
		$(PYTHON_OBJS) \
		$(MODULE_OBJS) \
		$(MODOBJS)

LIBRARY_OBJS=	\
		$(LIBRARY_OBJS_OMIT_FROZEN) \
		Modules/getpath.o \
		Python/frozen.o

LINK_PYTHON_OBJS=$(LIBRARY_OBJS)

##########################################################################
# DTrace

# On some systems, object files that reference DTrace probes need to be modified
# in-place by dtrace(1).
DTRACE_DEPS = \
	Python/ceval.o Python/gc.o Python/import.o Python/sysmodule.o

##########################################################################
# decimal's libmpdec

LIBMPDEC_OBJS= \
		Modules/_decimal/libmpdec/basearith.o \
		Modules/_decimal/libmpdec/constants.o \
		Modules/_decimal/libmpdec/context.o \
		Modules/_decimal/libmpdec/convolute.o \
		Modules/_decimal/libmpdec/crt.o \
		Modules/_decimal/libmpdec/difradix2.o \
		Modules/_decimal/libmpdec/fnt.o \
		Modules/_decimal/libmpdec/fourstep.o \
		Modules/_decimal/libmpdec/io.o \
		Modules/_decimal/libmpdec/mpalloc.o \
		Modules/_decimal/libmpdec/mpdecimal.o \
		Modules/_decimal/libmpdec/numbertheory.o \
		Modules/_decimal/libmpdec/sixstep.o \
		Modules/_decimal/libmpdec/transpose.o
		# _decimal does not use signaling API
		# Modules/_decimal/libmpdec/mpsignal.o

LIBMPDEC_HEADERS= \
		$(srcdir)/Modules/_decimal/libmpdec/basearith.h \
		$(srcdir)/Modules/_decimal/libmpdec/bits.h \
		$(srcdir)/Modules/_decimal/libmpdec/constants.h \
		$(srcdir)/Modules/_decimal/libmpdec/convolute.h \
		$(srcdir)/Modules/_decimal/libmpdec/crt.h \
		$(srcdir)/Modules/_decimal/libmpdec/difradix2.h \
		$(srcdir)/Modules/_decimal/libmpdec/fnt.h \
		$(srcdir)/Modules/_decimal/libmpdec/fourstep.h \
		$(srcdir)/Modules/_decimal/libmpdec/io.h \
		$(srcdir)/Modules/_decimal/libmpdec/mpalloc.h \
		$(srcdir)/Modules/_decimal/libmpdec/mpdecimal.h \
		$(srcdir)/Modules/_decimal/libmpdec/numbertheory.h \
		$(srcdir)/Modules/_decimal/libmpdec/sixstep.h \
		$(srcdir)/Modules/_decimal/libmpdec/transpose.h \
		$(srcdir)/Modules/_decimal/libmpdec/typearith.h \
		$(srcdir)/Modules/_decimal/libmpdec/umodarith.h

##########################################################################
# pyexpat's expat library

LIBEXPAT_OBJS= \
		Modules/expat/xmlparse.o \
		Modules/expat/xmlrole.o \
		Modules/expat/xmltok.o

LIBEXPAT_HEADERS= \
		Modules/expat/ascii.h \
		Modules/expat/asciitab.h \
		Modules/expat/expat.h \
		Modules/expat/expat_config.h \
		Modules/expat/expat_external.h \
		Modules/expat/fallthrough.h \
		Modules/expat/iasciitab.h \
		Modules/expat/internal.h \
		Modules/expat/latin1tab.h \
		Modules/expat/memory_sanitizer.h \
		Modules/expat/nametab.h \
		Modules/expat/pyexpatns.h \
		Modules/expat/siphash.h \
		Modules/expat/utf8tab.h \
		Modules/expat/xcsinc.c \
		Modules/expat/xmlrole.h \
		Modules/expat/xmltok.h \
		Modules/expat/xmltok_impl.h \
		Modules/expat/xmltok_impl.c \
		Modules/expat/xmltok_ns.c

##########################################################################
# hashlib's HACL* library
#
# On WASI, static build is required.
# On other platforms, a shared library is used.

LIBHACL_MD5_OBJS= \
		Modules/_hacl/Hacl_Hash_MD5.o
LIBHACL_MD5_LIB_STATIC=Modules/_hacl/libHacl_Hash_MD5.a
LIBHACL_MD5_LIB_SHARED=$(LIBHACL_MD5_OBJS)

LIBHACL_SHA1_OBJS= \
		Modules/_hacl/Hacl_Hash_SHA1.o
LIBHACL_SHA1_LIB_STATIC=Modules/_hacl/libHacl_Hash_SHA1.a
LIBHACL_SHA1_LIB_SHARED=$(LIBHACL_SHA1_OBJS)

LIBHACL_SHA2_OBJS= \
		Modules/_hacl/Hacl_Hash_SHA2.o
LIBHACL_SHA2_LIB_STATIC=Modules/_hacl/libHacl_Hash_SHA2.a
LIBHACL_SHA2_LIB_SHARED=$(LIBHACL_SHA2_OBJS)

LIBHACL_SHA3_OBJS= \
		Modules/_hacl/Hacl_Hash_SHA3.o
LIBHACL_SHA3_LIB_STATIC=Modules/_hacl/libHacl_Hash_SHA3.a
LIBHACL_SHA3_LIB_SHARED=$(LIBHACL_SHA3_OBJS)

LIBHACL_BLAKE2_SIMD128_OBJS=
LIBHACL_BLAKE2_SIMD256_OBJS=
LIBHACL_BLAKE2_OBJS= \
		Modules/_hacl/Hacl_Hash_Blake2s.o \
		Modules/_hacl/Hacl_Hash_Blake2b.o \
		Modules/_hacl/Lib_Memzero0.o \
		$(LIBHACL_BLAKE2_SIMD128_OBJS) \
		$(LIBHACL_BLAKE2_SIMD256_OBJS)
LIBHACL_BLAKE2_LIB_STATIC=Modules/_hacl/libHacl_Hash_BLAKE2.a
LIBHACL_BLAKE2_LIB_SHARED=$(LIBHACL_BLAKE2_OBJS)

LIBHACL_HMAC_OBJS= \
		Modules/_hacl/Hacl_HMAC.o \
		Modules/_hacl/Hacl_Streaming_HMAC.o \
		$(LIBHACL_MD5_OBJS) \
		$(LIBHACL_SHA1_OBJS) \
		$(LIBHACL_SHA2_OBJS) \
		$(LIBHACL_SHA3_OBJS) \
		$(LIBHACL_BLAKE2_OBJS)
LIBHACL_HMAC_LIB_STATIC=Modules/_hacl/libHacl_HMAC.a
LIBHACL_HMAC_LIB_SHARED=$(LIBHACL_HMAC_OBJS)

LIBHACL_HEADERS= \
		Modules/_hacl/include/krml/FStar_UInt128_Verified.h \
		Modules/_hacl/include/krml/FStar_UInt_8_16_32_64.h \
		Modules/_hacl/include/krml/fstar_uint128_struct_endianness.h \
		Modules/_hacl/include/krml/internal/compat.h \
		Modules/_hacl/include/krml/internal/target.h \
		Modules/_hacl/include/krml/internal/types.h \
		Modules/_hacl/include/krml/lowstar_endianness.h \
		Modules/_hacl/Hacl_Streaming_Types.h \
		Modules/_hacl/internal/Hacl_Streaming_Types.h \
		Modules/_hacl/libintvector.h \
		Modules/_hacl/python_hacl_namespaces.h

LIBHACL_MD5_HEADERS= \
		Modules/_hacl/Hacl_Hash_MD5.h \
		Modules/_hacl/internal/Hacl_Hash_MD5.h \
		$(LIBHACL_HEADERS)

LIBHACL_SHA1_HEADERS= \
		Modules/_hacl/Hacl_Hash_SHA1.h \
		Modules/_hacl/internal/Hacl_Hash_SHA1.h \
		$(LIBHACL_HEADERS)

LIBHACL_SHA2_HEADERS= \
		Modules/_hacl/Hacl_Hash_SHA2.h \
		Modules/_hacl/internal/Hacl_Hash_SHA2.h \
		$(LIBHACL_HEADERS)

LIBHACL_SHA3_HEADERS= \
		Modules/_hacl/Hacl_Hash_SHA3.h \
		Modules/_hacl/internal/Hacl_Hash_SHA3.h \
		$(LIBHACL_HEADERS)

LIBHACL_BLAKE2_HEADERS= \
		Modules/_hacl/Hacl_Hash_Blake2b.h \
		Modules/_hacl/Hacl_Hash_Blake2s.h \
		Modules/_hacl/Hacl_Hash_Blake2s_Simd128.h \
		Modules/_hacl/Hacl_Hash_Blake2b_Simd256.h \
		Modules/_hacl/internal/Hacl_Hash_Blake2b.h \
		Modules/_hacl/internal/Hacl_Hash_Blake2s.h \
		Modules/_hacl/internal/Hacl_Impl_Blake2_Constants.h \
		Modules/_hacl/internal/Hacl_Hash_Blake2s_Simd128.h \
		Modules/_hacl/internal/Hacl_Hash_Blake2b_Simd256.h \
		$(LIBHACL_HEADERS)

LIBHACL_HMAC_HEADERS= \
		Modules/_hacl/Hacl_HMAC.h \
		Modules/_hacl/Hacl_Streaming_HMAC.h \
		Modules/_hacl/internal/Hacl_HMAC.h \
		Modules/_hacl/internal/Hacl_Streaming_HMAC.h \
		Modules/_hacl/libintvector-shim.h \
		$(LIBHACL_MD5_HEADERS) \
		$(LIBHACL_SHA1_HEADERS) \
		$(LIBHACL_SHA2_HEADERS) \
		$(LIBHACL_SHA3_HEADERS) \
		$(LIBHACL_BLAKE2_HEADERS) \
		$(LIBHACL_HEADERS)

#########################################################################
# Rules

# Default target
all:		build_all

# First target in Makefile is implicit default. So .PHONY needs to come after
# all.
.PHONY: all

# Provide quick help for common Makefile targets.
.PHONY: help
help:
	@echo "Run 'make' to build the Python executable and extension modules"
	@echo ""
	@echo "or 'make <target>' where <target> is one of:"
	@echo "  test         run the test suite"
	@echo "  install      install built files"
	@echo "  regen-all    regenerate a number of generated source files"
	@echo "  clinic       run Argument Clinic over source files"
	@echo ""
	@echo "  clean        to remove build files"
	@echo "  distclean    'clean' + remove other generated files (patch, exe, etc)"
	@echo ""
	@echo "  recheck      rerun configure with last cmdline options"
	@echo "  reindent     reindent .py files in Lib directory"
	@echo "  tags         build a tags file (useful for Emacs and other editors)"
	@echo "  list-targets list all targets in the Makefile"

# Display a full list of Makefile targets
.PHONY: list-targets
list-targets:
	@grep -E '^[A-Za-z][-A-Za-z0-9]+:' Makefile | awk -F : '{print $$1}'

.PHONY: build_all
build_all:	check-clean-src check-app-store-compliance $(BUILDPYTHON) platform sharedmods \
		gdbhooks Programs/_testembed scripts checksharedmods rundsymutil build-details.json

.PHONY: build_wasm
build_wasm: check-clean-src $(BUILDPYTHON) platform sharedmods \
		python-config checksharedmods build-details.json

.PHONY: build_emscripten
build_emscripten: build_wasm web_example web_example_pyrepl_jspi

# Check that the source is clean when building out of source.
.PHONY: check-clean-src
check-clean-src:
	@if test -n "$(VPATH)" -a \( \
	    -f "$(srcdir)/$(BUILDPYTHON)" \
	    -o -f "$(srcdir)/Programs/python.o" \
	    -o -f "$(srcdir)/Python/frozen_modules/importlib._bootstrap.h" \
	\); then \
		echo "Error: The source directory ($(srcdir)) is not clean" ; \
		echo "Building Python out of the source tree (in $(abs_builddir)) requires a clean source tree ($(abs_srcdir))" ; \
		echo "Build artifacts such as .o files, executables, and Python/frozen_modules/*.h must not exist within $(srcdir)." ; \
		echo "Try to run:" ; \
		echo "  (cd \"$(srcdir)\" && make distclean || git clean -fdx -e Doc/venv)" ; \
		exit 1; \
	fi

# Check that the app store compliance patch can be applied (if configured).
# This is checked as a dry-run against the original library sources;
# the patch will be actually applied during the install phase.
.PHONY: check-app-store-compliance
check-app-store-compliance:
	@if [ "$(APP_STORE_COMPLIANCE_PATCH)" != "" ]; then \
		patch --dry-run --quiet --force --strip 1 --directory "$(abs_srcdir)" --input "$(abs_srcdir)/$(APP_STORE_COMPLIANCE_PATCH)"; \
		echo "App store compliance patch can be applied."; \
	fi

# Profile generation build must start from a clean tree.
profile-clean-stamp:
	$(MAKE) clean-profile
	touch $@

# Compile with profile generation enabled.
profile-gen-stamp: profile-clean-stamp
	@if [ $(LLVM_PROF_ERR) = yes ]; then \
		echo "Error: Cannot perform PGO build because llvm-profdata was not found in PATH" ;\
		echo "Please add it to PATH and run ./configure again" ;\
		exit 1;\
	fi
	@echo "Building with support for profile generation:"
	$(MAKE) all CFLAGS_NODIST="$(CFLAGS_NODIST) $(PGO_PROF_GEN_FLAG)" LDFLAGS_NODIST="$(LDFLAGS_NODIST) $(PGO_PROF_GEN_FLAG)" LIBS="$(LIBS)"
	touch $@

# Run task with profile generation build to create profile information.
profile-run-stamp:
	@echo "Running code to generate profile data (this can take a while):"
	# First, we need to create a clean build with profile generation
	# enabled.
	$(MAKE) profile-gen-stamp
	# Next, run the profile task to generate the profile information.
	@ # FIXME: can't run for a cross build
	$(LLVM_PROF_FILE) $(RUNSHARED) ./$(BUILDPYTHON) $(PROFILE_TASK)
	$(LLVM_PROF_MERGER)
	# Remove profile generation binary since we are done with it.
	$(MAKE) clean-retain-profile
	# This is an expensive target to build and it does not have proper
	# makefile dependency information.  So, we create a "stamp" file
	# to record its completion and avoid re-running it.
	touch $@

# Compile Python binary with profile guided optimization.
# To force re-running of the profile task, remove the profile-run-stamp file.
.PHONY: profile-opt
profile-opt: profile-run-stamp
	@echo "Rebuilding with profile guided optimizations:"
	-rm -f profile-clean-stamp
	$(MAKE) all CFLAGS_NODIST="$(CFLAGS_NODIST) $(PGO_PROF_USE_FLAG)" LDFLAGS_NODIST="$(LDFLAGS_NODIST)"

# List of binaries that BOLT runs on.
BOLT_BINARIES := $(BUILDPYTHON)

BOLT_INSTRUMENT_FLAGS :=  -update-debug-sections -skip-funcs=_PyEval_EvalFrameDefault,sre_ucs1_match/1,sre_ucs2_match/1,sre_ucs4_match/1 
BOLT_APPLY_FLAGS :=   -update-debug-sections -skip-funcs=_PyEval_EvalFrameDefault,sre_ucs1_match/1,sre_ucs2_match/1,sre_ucs4_match/1  -reorder-blocks=ext-tsp -reorder-functions=cdsort -split-functions -icf=1 -inline-all -split-eh -reorder-functions-use-hot-size -peepholes=none -jump-tables=aggressive -inline-ap -indirect-call-promotion=all -dyno-stats -use-gnu-stack -frame-opt=hot 

.PHONY: clean-bolt
clean-bolt:
	# Profile data.
	rm -f *.fdata
	# Pristine binaries before BOLT optimization.
	rm -f *.prebolt
	# BOLT instrumented binaries.
	rm -f *.bolt_inst

profile-bolt-stamp: $(BUILDPYTHON)
	# Ensure a pristine, pre-BOLT copy of the binary and no profile data from last run.
	for bin in $(BOLT_BINARIES); do \
	  prebolt="$${bin}.prebolt"; \
	  if [ -e "$${prebolt}" ]; then \
	    echo "Restoring pre-BOLT binary $${prebolt}"; \
	    mv "$${bin}.prebolt" "$${bin}"; \
	  fi; \
	  cp "$${bin}" "$${prebolt}"; \
	  rm -f $${bin}.bolt.*.fdata $${bin}.fdata; \
	done
	# Instrument each binary.
	for bin in $(BOLT_BINARIES); do \
	   "$${bin}" -instrument -instrumentation-file-append-pid -instrumentation-file=$(abspath $${bin}.bolt) -o $${bin}.bolt_inst $(BOLT_INSTRUMENT_FLAGS); \
	  mv "$${bin}.bolt_inst" "$${bin}"; \
	done
	# Run instrumented binaries to collect data.
	$(RUNSHARED) ./$(BUILDPYTHON) $(PROFILE_TASK)
	# Merge all the data files together.
	for bin in $(BOLT_BINARIES); do \
	   $${bin}.*.fdata > "$${bin}.fdata"; \
	  rm -f $${bin}.*.fdata; \
	done
	# Run bolt against the merged data to produce an optimized binary.
	for bin in $(BOLT_BINARIES); do \
	   "$${bin}.prebolt" -o "$${bin}.bolt" -data="$${bin}.fdata" $(BOLT_APPLY_FLAGS); \
	  mv "$${bin}.bolt" "$${bin}"; \
	done
	touch $@

.PHONY: bolt-opt
bolt-opt:
	$(MAKE) 
	$(MAKE) profile-bolt-stamp

# Compile and run with gcov
.PHONY: coverage
coverage:
	@echo "Building with support for coverage checking:"
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS) -O0 -pg --coverage" LDFLAGS="$(LDFLAGS) --coverage"

.PHONY: coverage-lcov
coverage-lcov:
	@echo "Creating Coverage HTML report with LCOV:"
	@rm -f $(COVERAGE_INFO)
	@rm -rf $(COVERAGE_REPORT)
	@lcov $(COVERAGE_LCOV_OPTIONS) --capture \
	    --directory $(abs_builddir) \
	    --base-directory $(realpath $(abs_builddir)) \
	    --path $(realpath $(abs_srcdir)) \
	    --output-file $(COVERAGE_INFO)
	@ # remove 3rd party modules, system headers and internal files with
	@ # debug, test or dummy functions.
	@lcov $(COVERAGE_LCOV_OPTIONS) --remove $(COVERAGE_INFO) \
	    '*/Modules/_hacl/*' \
	    '*/Modules/_ctypes/libffi*/*' \
	    '*/Modules/_decimal/libmpdec/*' \
	    '*/Modules/expat/*' \
	    '*/Modules/xx*.c' \
	    '*/Python/pyfpe.c' \
	    '*/Python/pystrcmp.c' \
	    '/usr/include/*' \
	    '/usr/local/include/*' \
	    '/usr/lib/gcc/*' \
	    --output-file $(COVERAGE_INFO)
	@genhtml $(COVERAGE_INFO) \
	    --output-directory $(COVERAGE_REPORT) \
	    $(COVERAGE_REPORT_OPTIONS)
	@echo
	@echo "lcov report at $(COVERAGE_REPORT)/index.html"
	@echo

# Force regeneration of parser and frozen modules
.PHONY: coverage-report
coverage-report: regen-token regen-frozen
	@ # build with coverage info
	$(MAKE) coverage
	@ # run tests, ignore failures
	$(TESTRUNNER) --fast-ci --timeout=$(TESTTIMEOUT) $(TESTOPTS) || true
	@ # build lcov report
	$(MAKE) coverage-lcov

# Run "Argument Clinic" over all source files
.PHONY: clinic
clinic: check-clean-src
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/clinic/clinic.py --force --make --exclude Lib/test/clinic.test.c --srcdir $(srcdir)

.PHONY: clinic-tests
clinic-tests: check-clean-src $(srcdir)/Lib/test/clinic.test.c
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/clinic/clinic.py -f $(srcdir)/Lib/test/clinic.test.c

# Build the interpreter
$(BUILDPYTHON):	Programs/python.o $(LINK_PYTHON_DEPS)
	$(LINKCC) $(PY_CORE_LDFLAGS) $(LINKFORSHARED) -o $@ Programs/python.o $(LINK_PYTHON_OBJS) $(LIBS) $(MODLIBS) $(SYSLIBS)

platform: $(PYTHON_FOR_BUILD_DEPS) pybuilddir.txt
	$(RUNSHARED) $(PYTHON_FOR_BUILD) -c 'import sys ; from sysconfig import get_platform ; print("%s-%d.%d" % (get_platform(), *sys.version_info[:2]))' >platform

# Create build directory and generate the sysconfig build-time data there.
# pybuilddir.txt contains the name of the build dir and is used for
# sys.path fixup -- see Modules/getpath.c.
# Since this step runs before shared modules are built, try to avoid bootstrap
# problems by creating a dummy pybuilddir.txt just to allow interpreter
# initialization to succeed.  It will be overwritten by generate-posix-vars
# or removed in case of failure.
pybuilddir.txt: $(PYTHON_FOR_BUILD_DEPS)
	@echo "none" > ./pybuilddir.txt
	$(RUNSHARED) $(PYTHON_FOR_BUILD) -S -m sysconfig --generate-posix-vars ;\
	if test $$? -ne 0 ; then \
		echo "generate-posix-vars failed" ; \
		rm -f ./pybuilddir.txt ; \
		exit 1 ; \
	fi

build-details.json: pybuilddir.txt
	$(RUNSHARED) $(PYTHON_FOR_BUILD) $(srcdir)/Tools/build/generate-build-details.py `cat pybuilddir.txt`/build-details.json

# Build static library
$(LIBRARY): $(LIBRARY_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBRARY_OBJS)

libpython$(LDVERSION).so: $(LIBRARY_OBJS) $(DTRACE_OBJS)
	# AIX Linker don't support "-h" option
	if test "$(MACHDEP)" != "aix"; then \
		$(BLDSHARED) -Wl,-h$(INSTSONAME) -o $(INSTSONAME) $(LIBRARY_OBJS) $(MODLIBS) $(SHLIBS) $(LIBC) $(LIBM); \
	else \
		$(BLDSHARED) -o $@ $(LIBRARY_OBJS) $(MODLIBS) $(SHLIBS) $(LIBC) $(LIBM); \
	fi
	if test $(INSTSONAME) != $@; then \
		$(LN) -f $(INSTSONAME) $@; \
	fi

libpython3.so:	libpython$(LDVERSION).so
	$(BLDSHARED) $(NO_AS_NEEDED) -o $@ -Wl,-h$@ $^

libpython$(LDVERSION).dylib: $(LIBRARY_OBJS)
	 $(CC) -dynamiclib $(PY_CORE_LDFLAGS) -undefined dynamic_lookup -Wl,-install_name,$(prefix)/lib/libpython$(LDVERSION).dylib -Wl,-compatibility_version,$(VERSION) -Wl,-current_version,$(VERSION) -o $@ $(LIBRARY_OBJS) $(DTRACE_OBJS) $(SHLIBS) $(LIBC) $(LIBM); \


libpython$(VERSION).sl: $(LIBRARY_OBJS)
	$(LDSHARED) -o $@ $(LIBRARY_OBJS) $(MODLIBS) $(SHLIBS) $(LIBC) $(LIBM)

# List of exported symbols for AIX
Modules/python.exp: $(LIBRARY)
	$(srcdir)/Modules/makexp_aix $@ "$(EXPORTSFROM)" $?

# Copy up the gdb python hooks into a position where they can be automatically
# loaded by gdb during Lib/test/test_gdb.py
#
# Distributors are likely to want to install this somewhere else e.g. relative
# to the stripped DWARF data for the shared library.
.PHONY: gdbhooks
gdbhooks: $(BUILDPYTHON)-gdb.py

SRC_GDB_HOOKS=$(srcdir)/Tools/gdb/libpython.py
$(BUILDPYTHON)-gdb.py: $(SRC_GDB_HOOKS)
	$(INSTALL_DATA) $(SRC_GDB_HOOKS) $(BUILDPYTHON)-gdb.py

# This rule is here for OPENSTEP/Rhapsody/MacOSX. It builds a temporary
# minimal framework (not including the Lib directory and such) in the current
# directory.
$(PYTHONFRAMEWORKDIR)/Versions/$(VERSION)/$(PYTHONFRAMEWORK): \
		$(LIBRARY) \
		$(RESSRCDIR)/Info.plist
	$(INSTALL) -d -m $(DIRMODE) $(PYTHONFRAMEWORKDIR)/Versions/$(VERSION)
	$(CC) -o $(LDLIBRARY) $(PY_CORE_LDFLAGS) -dynamiclib \
		-all_load $(LIBRARY) \
		-install_name $(PYTHONFRAMEWORKINSTALLNAMEPREFIX)/$(PYTHONFRAMEWORK) \
		-compatibility_version $(VERSION) \
		-current_version $(VERSION) \
		-framework CoreFoundation $(LIBS);
	$(INSTALL) -d -m $(DIRMODE)  \
		$(PYTHONFRAMEWORKDIR)/Versions/$(VERSION)/Resources/English.lproj
	$(INSTALL_DATA) $(RESSRCDIR)/Info.plist \
		$(PYTHONFRAMEWORKDIR)/Versions/$(VERSION)/Resources/Info.plist
	$(LN) -fsn $(VERSION) $(PYTHONFRAMEWORKDIR)/Versions/Current
	$(LN) -fsn Versions/Current/$(PYTHONFRAMEWORK) $(PYTHONFRAMEWORKDIR)/$(PYTHONFRAMEWORK)
	$(LN) -fsn Versions/Current/Resources $(PYTHONFRAMEWORKDIR)/Resources

# This rule is for iOS, which requires an annoyingly just slightly different
# format for frameworks to macOS. It *doesn't* use a versioned framework, and
# the Info.plist must be in the root of the framework.
$(PYTHONFRAMEWORKDIR)/$(PYTHONFRAMEWORK): \
		$(LIBRARY) \
		$(RESSRCDIR)/Info.plist
	$(INSTALL) -d -m $(DIRMODE) $(PYTHONFRAMEWORKDIR)
	$(CC) -o $(LDLIBRARY) $(PY_CORE_LDFLAGS) -dynamiclib \
		-all_load $(LIBRARY) \
		-install_name $(PYTHONFRAMEWORKINSTALLNAMEPREFIX)/$(PYTHONFRAMEWORK) \
		-compatibility_version $(VERSION) \
		-current_version $(VERSION) \
		-framework CoreFoundation $(LIBS);
	$(INSTALL_DATA) $(RESSRCDIR)/Info.plist $(PYTHONFRAMEWORKDIR)/Info.plist

# This rule builds the Cygwin Python DLL and import library if configured
# for a shared core library; otherwise, this rule is a noop.
$(DLLLIBRARY) libpython$(LDVERSION).dll.a: $(LIBRARY_OBJS)
	if test -n "$(DLLLIBRARY)"; then \
		$(LDSHARED) -Wl,--out-implib=$@ -o $(DLLLIBRARY) $^ \
			$(LIBS) $(MODLIBS) $(SYSLIBS); \
	else true; \
	fi

# wasm32-emscripten browser web example

EMSCRIPTEN_DIR=$(srcdir)/Platforms/emscripten
WEBEX_DIR=$(EMSCRIPTEN_DIR)/web_example/

ZIP_STDLIB=python$(VERSION)$(ABI_THREAD).zip
$(ZIP_STDLIB): $(srcdir)/Lib/*.py $(srcdir)/Lib/*/*.py \
	    $(EMSCRIPTEN_DIR)/wasm_assets.py \
	    Makefile pybuilddir.txt Modules/Setup.local
	$(PYTHON_FOR_BUILD) $(EMSCRIPTEN_DIR)/wasm_assets.py \
	    --buildroot . --prefix $(prefix) -o $@

web_example/index.html: $(WEBEX_DIR)/index.html
	@mkdir -p web_example
	@cp $< $@

web_example/python.worker.mjs: $(WEBEX_DIR)/python.worker.mjs
	@mkdir -p web_example
	@cp $< $@

web_example/server.py: $(WEBEX_DIR)/server.py
	@mkdir -p web_example
	@cp $< $@

web_example/$(ZIP_STDLIB): $(ZIP_STDLIB)
	@mkdir -p web_example
	@cp $< $@

web_example/python.mjs web_example/python.wasm: $(BUILDPYTHON)
	@if test $(HOST_GNU_TYPE) != 'wasm32-unknown-emscripten' ; then \
		echo "Can only build web_example when target is Emscripten" ;\
		exit 1 ;\
	fi
	cp python.mjs web_example/python.mjs
	cp python.wasm web_example/python.wasm

.PHONY: web_example
web_example: web_example/python.mjs web_example/python.worker.mjs web_example/index.html web_example/server.py web_example/$(ZIP_STDLIB)

WEBEX2=web_example_pyrepl_jspi
WEBEX2_DIR=$(EMSCRIPTEN_DIR)/$(WEBEX2)/

$(WEBEX2)/python.mjs $(WEBEX2)/python.wasm: $(BUILDPYTHON)
	@if test $(HOST_GNU_TYPE) != 'wasm32-unknown-emscripten' ; then \
		echo "Can only build web_example when target is Emscripten" ;\
		exit 1 ;\
	fi
	@mkdir -p $(WEBEX2)
	@cp python.mjs $(WEBEX2)/python.mjs
	@cp python.wasm $(WEBEX2)/python.wasm

$(WEBEX2)/index.html: $(WEBEX2_DIR)/index.html
	@mkdir -p $(WEBEX2)
	@cp $< $@

$(WEBEX2)/src.mjs: $(WEBEX2_DIR)/src.mjs
	@mkdir -p $(WEBEX2)
	@cp $< $@

$(WEBEX2)/$(ZIP_STDLIB): $(ZIP_STDLIB)
	@mkdir -p $(WEBEX2)
	@cp $< $@

.PHONY: web_example_pyrepl_jspi
web_example_pyrepl_jspi: $(WEBEX2)/python.mjs $(WEBEX2)/index.html $(WEBEX2)/src.mjs $(WEBEX2)/$(ZIP_STDLIB)


############################################################################
# Header files

PYTHON_HEADERS= \
		$(srcdir)/Include/Python.h \
		$(srcdir)/Include/abstract.h \
		$(srcdir)/Include/audit.h \
		$(srcdir)/Include/bltinmodule.h \
		$(srcdir)/Include/boolobject.h \
		$(srcdir)/Include/bytearrayobject.h \
		$(srcdir)/Include/bytesobject.h \
		$(srcdir)/Include/ceval.h \
		$(srcdir)/Include/codecs.h \
		$(srcdir)/Include/compile.h \
		$(srcdir)/Include/complexobject.h \
		$(srcdir)/Include/critical_section.h \
		$(srcdir)/Include/descrobject.h \
		$(srcdir)/Include/dictobject.h \
		$(srcdir)/Include/dynamic_annotations.h \
		$(srcdir)/Include/enumobject.h \
		$(srcdir)/Include/errcode.h \
		$(srcdir)/Include/exports.h \
		$(srcdir)/Include/fileobject.h \
		$(srcdir)/Include/fileutils.h \
		$(srcdir)/Include/floatobject.h \
		$(srcdir)/Include/frameobject.h \
		$(srcdir)/Include/genericaliasobject.h \
		$(srcdir)/Include/import.h \
		$(srcdir)/Include/intrcheck.h \
		$(srcdir)/Include/iterobject.h \
		$(srcdir)/Include/listobject.h \
		$(srcdir)/Include/lock.h \
		$(srcdir)/Include/longobject.h \
		$(srcdir)/Include/marshal.h \
		$(srcdir)/Include/memoryobject.h \
		$(srcdir)/Include/methodobject.h \
		$(srcdir)/Include/modsupport.h \
		$(srcdir)/Include/moduleobject.h \
		$(srcdir)/Include/monitoring.h \
		$(srcdir)/Include/object.h \
		$(srcdir)/Include/objimpl.h \
		$(srcdir)/Include/opcode.h \
		$(srcdir)/Include/opcode_ids.h \
		$(srcdir)/Include/osdefs.h \
		$(srcdir)/Include/osmodule.h \
		$(srcdir)/Include/patchlevel.h \
		$(srcdir)/Include/pyatomic.h \
		$(srcdir)/Include/pybuffer.h \
		$(srcdir)/Include/pycapsule.h \
		$(srcdir)/Include/pydtrace.h \
		$(srcdir)/Include/pyerrors.h \
		$(srcdir)/Include/pyexpat.h \
		$(srcdir)/Include/pyframe.h \
		$(srcdir)/Include/pyhash.h \
		$(srcdir)/Include/pylifecycle.h \
		$(srcdir)/Include/pymacconfig.h \
		$(srcdir)/Include/pymacro.h \
		$(srcdir)/Include/pymath.h \
		$(srcdir)/Include/pymem.h \
		$(srcdir)/Include/pyport.h \
		$(srcdir)/Include/pystate.h \
		$(srcdir)/Include/pystats.h \
		$(srcdir)/Include/pystrcmp.h \
		$(srcdir)/Include/pystrtod.h \
		$(srcdir)/Include/pythonrun.h \
		$(srcdir)/Include/pythread.h \
		$(srcdir)/Include/pytypedefs.h \
		$(srcdir)/Include/rangeobject.h \
		$(srcdir)/Include/refcount.h \
		$(srcdir)/Include/setobject.h \
		$(srcdir)/Include/sliceobject.h \
		$(srcdir)/Include/structmember.h \
		$(srcdir)/Include/structseq.h \
		$(srcdir)/Include/sysmodule.h \
		$(srcdir)/Include/traceback.h \
		$(srcdir)/Include/tupleobject.h \
		$(srcdir)/Include/typeslots.h \
		$(srcdir)/Include/unicodeobject.h \
		$(srcdir)/Include/warnings.h \
		$(srcdir)/Include/weakrefobject.h \
		$(srcdir)/Python/remote_debug.h \
		\
		pyconfig.h \
		$(PARSER_HEADERS) \
		\
		$(srcdir)/Include/cpython/abstract.h \
		$(srcdir)/Include/cpython/audit.h \
		$(srcdir)/Include/cpython/bytearrayobject.h \
		$(srcdir)/Include/cpython/bytesobject.h \
		$(srcdir)/Include/cpython/cellobject.h \
		$(srcdir)/Include/cpython/ceval.h \
		$(srcdir)/Include/cpython/classobject.h \
		$(srcdir)/Include/cpython/code.h \
		$(srcdir)/Include/cpython/compile.h \
		$(srcdir)/Include/cpython/complexobject.h \
		$(srcdir)/Include/cpython/context.h \
		$(srcdir)/Include/cpython/critical_section.h \
		$(srcdir)/Include/cpython/descrobject.h \
		$(srcdir)/Include/cpython/dictobject.h \
		$(srcdir)/Include/cpython/fileobject.h \
		$(srcdir)/Include/cpython/fileutils.h \
		$(srcdir)/Include/cpython/floatobject.h \
		$(srcdir)/Include/cpython/frameobject.h \
		$(srcdir)/Include/cpython/funcobject.h \
		$(srcdir)/Include/cpython/genobject.h \
		$(srcdir)/Include/cpython/import.h \
		$(srcdir)/Include/cpython/initconfig.h \
		$(srcdir)/Include/cpython/listobject.h \
		$(srcdir)/Include/cpython/lock.h \
		$(srcdir)/Include/cpython/longintrepr.h \
		$(srcdir)/Include/cpython/longobject.h \
		$(srcdir)/Include/cpython/memoryobject.h \
		$(srcdir)/Include/cpython/methodobject.h \
		$(srcdir)/Include/cpython/modsupport.h \
		$(srcdir)/Include/cpython/monitoring.h \
		$(srcdir)/Include/cpython/object.h \
		$(srcdir)/Include/cpython/objimpl.h \
		$(srcdir)/Include/cpython/odictobject.h \
		$(srcdir)/Include/cpython/picklebufobject.h \
		$(srcdir)/Include/cpython/pthread_stubs.h \
		$(srcdir)/Include/cpython/pyatomic.h \
		$(srcdir)/Include/cpython/pyatomic_gcc.h \
		$(srcdir)/Include/cpython/pyatomic_std.h \
		$(srcdir)/Include/cpython/pyctype.h \
		$(srcdir)/Include/cpython/pydebug.h \
		$(srcdir)/Include/cpython/pyerrors.h \
		$(srcdir)/Include/cpython/pyfpe.h \
		$(srcdir)/Include/cpython/pyframe.h \
		$(srcdir)/Include/cpython/pyhash.h \
		$(srcdir)/Include/cpython/pylifecycle.h \
		$(srcdir)/Include/cpython/pymem.h \
		$(srcdir)/Include/cpython/pystate.h \
		$(srcdir)/Include/cpython/pystats.h \
		$(srcdir)/Include/cpython/pythonrun.h \
		$(srcdir)/Include/cpython/pythread.h \
		$(srcdir)/Include/cpython/setobject.h \
		$(srcdir)/Include/cpython/traceback.h \
		$(srcdir)/Include/cpython/tracemalloc.h \
		$(srcdir)/Include/cpython/tupleobject.h \
		$(srcdir)/Include/cpython/unicodeobject.h \
		$(srcdir)/Include/cpython/warnings.h \
		$(srcdir)/Include/cpython/weakrefobject.h \
		\
		$(MIMALLOC_HEADERS) \
		\
		$(srcdir)/Include/internal/pycore_abstract.h \
		$(srcdir)/Include/internal/pycore_asdl.h \
		$(srcdir)/Include/internal/pycore_ast.h \
		$(srcdir)/Include/internal/pycore_ast_state.h \
		$(srcdir)/Include/internal/pycore_atexit.h \
		$(srcdir)/Include/internal/pycore_audit.h \
		$(srcdir)/Include/internal/pycore_backoff.h \
		$(srcdir)/Include/internal/pycore_bitutils.h \
		$(srcdir)/Include/internal/pycore_blocks_output_buffer.h \
		$(srcdir)/Include/internal/pycore_brc.h \
		$(srcdir)/Include/internal/pycore_bytes_methods.h \
		$(srcdir)/Include/internal/pycore_bytesobject.h \
		$(srcdir)/Include/internal/pycore_call.h \
		$(srcdir)/Include/internal/pycore_capsule.h \
		$(srcdir)/Include/internal/pycore_cell.h \
		$(srcdir)/Include/internal/pycore_ceval.h \
		$(srcdir)/Include/internal/pycore_ceval_state.h \
		$(srcdir)/Include/internal/pycore_code.h \
		$(srcdir)/Include/internal/pycore_codecs.h \
		$(srcdir)/Include/internal/pycore_compile.h \
		$(srcdir)/Include/internal/pycore_complexobject.h \
		$(srcdir)/Include/internal/pycore_condvar.h \
		$(srcdir)/Include/internal/pycore_context.h \
		$(srcdir)/Include/internal/pycore_critical_section.h \
		$(srcdir)/Include/internal/pycore_crossinterp.h \
		$(srcdir)/Include/internal/pycore_crossinterp_data_registry.h \
		$(srcdir)/Include/internal/pycore_debug_offsets.h \
		$(srcdir)/Include/internal/pycore_descrobject.h \
		$(srcdir)/Include/internal/pycore_dict.h \
		$(srcdir)/Include/internal/pycore_dict_state.h \
		$(srcdir)/Include/internal/pycore_dtoa.h \
		$(srcdir)/Include/internal/pycore_exceptions.h \
		$(srcdir)/Include/internal/pycore_faulthandler.h \
		$(srcdir)/Include/internal/pycore_fileutils.h \
		$(srcdir)/Include/internal/pycore_floatobject.h \
		$(srcdir)/Include/internal/pycore_flowgraph.h \
		$(srcdir)/Include/internal/pycore_format.h \
		$(srcdir)/Include/internal/pycore_frame.h \
		$(srcdir)/Include/internal/pycore_freelist.h \
		$(srcdir)/Include/internal/pycore_freelist_state.h \
		$(srcdir)/Include/internal/pycore_function.h \
		$(srcdir)/Include/internal/pycore_gc.h \
		$(srcdir)/Include/internal/pycore_genobject.h \
		$(srcdir)/Include/internal/pycore_getopt.h \
		$(srcdir)/Include/internal/pycore_gil.h \
		$(srcdir)/Include/internal/pycore_global_objects.h \
		$(srcdir)/Include/internal/pycore_global_objects_fini_generated.h \
		$(srcdir)/Include/internal/pycore_global_strings.h \
		$(srcdir)/Include/internal/pycore_hamt.h \
		$(srcdir)/Include/internal/pycore_hashtable.h \
		$(srcdir)/Include/internal/pycore_import.h \
		$(srcdir)/Include/internal/pycore_importdl.h \
		$(srcdir)/Include/internal/pycore_index_pool.h \
		$(srcdir)/Include/internal/pycore_initconfig.h \
		$(srcdir)/Include/internal/pycore_instruments.h \
		$(srcdir)/Include/internal/pycore_instruction_sequence.h \
		$(srcdir)/Include/internal/pycore_interp.h \
		$(srcdir)/Include/internal/pycore_interp_structs.h \
		$(srcdir)/Include/internal/pycore_interpframe.h \
		$(srcdir)/Include/internal/pycore_interpframe_structs.h \
		$(srcdir)/Include/internal/pycore_interpolation.h \
		$(srcdir)/Include/internal/pycore_intrinsics.h \
		$(srcdir)/Include/internal/pycore_jit.h \
		$(srcdir)/Include/internal/pycore_list.h \
		$(srcdir)/Include/internal/pycore_llist.h \
		$(srcdir)/Include/internal/pycore_lock.h \
		$(srcdir)/Include/internal/pycore_long.h \
		$(srcdir)/Include/internal/pycore_memoryobject.h \
		$(srcdir)/Include/internal/pycore_mimalloc.h \
		$(srcdir)/Include/internal/pycore_modsupport.h \
		$(srcdir)/Include/internal/pycore_moduleobject.h \
		$(srcdir)/Include/internal/pycore_namespace.h \
		$(srcdir)/Include/internal/pycore_object.h \
		$(srcdir)/Include/internal/pycore_object_alloc.h \
		$(srcdir)/Include/internal/pycore_object_deferred.h \
		$(srcdir)/Include/internal/pycore_object_stack.h \
		$(srcdir)/Include/internal/pycore_object_state.h \
		$(srcdir)/Include/internal/pycore_obmalloc.h \
		$(srcdir)/Include/internal/pycore_obmalloc_init.h \
		$(srcdir)/Include/internal/pycore_opcode_metadata.h \
		$(srcdir)/Include/internal/pycore_opcode_utils.h \
		$(srcdir)/Include/internal/pycore_optimizer.h \
		$(srcdir)/Include/internal/pycore_parking_lot.h \
		$(srcdir)/Include/internal/pycore_parser.h \
		$(srcdir)/Include/internal/pycore_pathconfig.h \
		$(srcdir)/Include/internal/pycore_pyarena.h \
		$(srcdir)/Include/internal/pycore_pyatomic_ft_wrappers.h \
		$(srcdir)/Include/internal/pycore_pybuffer.h \
		$(srcdir)/Include/internal/pycore_pyerrors.h \
		$(srcdir)/Include/internal/pycore_pyhash.h \
		$(srcdir)/Include/internal/pycore_pylifecycle.h \
		$(srcdir)/Include/internal/pycore_pymath.h \
		$(srcdir)/Include/internal/pycore_pymem.h \
		$(srcdir)/Include/internal/pycore_pymem_init.h \
		$(srcdir)/Include/internal/pycore_pystate.h \
		$(srcdir)/Include/internal/pycore_pystats.h \
		$(srcdir)/Include/internal/pycore_pythonrun.h \
		$(srcdir)/Include/internal/pycore_pythread.h \
		$(srcdir)/Include/internal/pycore_qsbr.h \
		$(srcdir)/Include/internal/pycore_range.h \
		$(srcdir)/Include/internal/pycore_runtime.h \
		$(srcdir)/Include/internal/pycore_runtime_init.h \
		$(srcdir)/Include/internal/pycore_runtime_init_generated.h \
		$(srcdir)/Include/internal/pycore_runtime_structs.h \
		$(srcdir)/Include/internal/pycore_semaphore.h \
		$(srcdir)/Include/internal/pycore_setobject.h \
		$(srcdir)/Include/internal/pycore_signal.h \
		$(srcdir)/Include/internal/pycore_sliceobject.h \
		$(srcdir)/Include/internal/pycore_stats.h \
		$(srcdir)/Include/internal/pycore_strhex.h \
		$(srcdir)/Include/internal/pycore_stackref.h \
		$(srcdir)/Include/internal/pycore_structs.h \
		$(srcdir)/Include/internal/pycore_structseq.h \
		$(srcdir)/Include/internal/pycore_symtable.h \
		$(srcdir)/Include/internal/pycore_sysmodule.h \
		$(srcdir)/Include/internal/pycore_template.h \
		$(srcdir)/Include/internal/pycore_time.h \
		$(srcdir)/Include/internal/pycore_token.h \
		$(srcdir)/Include/internal/pycore_traceback.h \
		$(srcdir)/Include/internal/pycore_tracemalloc.h \
		$(srcdir)/Include/internal/pycore_tstate.h \
		$(srcdir)/Include/internal/pycore_tuple.h \
		$(srcdir)/Include/internal/pycore_typedefs.h \
		$(srcdir)/Include/internal/pycore_typeobject.h \
		$(srcdir)/Include/internal/pycore_typevarobject.h \
		$(srcdir)/Include/internal/pycore_ucnhash.h \
		$(srcdir)/Include/internal/pycore_unicodeobject.h \
		$(srcdir)/Include/internal/pycore_unicodeobject_generated.h \
		$(srcdir)/Include/internal/pycore_unionobject.h \
		$(srcdir)/Include/internal/pycore_uniqueid.h \
		$(srcdir)/Include/internal/pycore_uop_ids.h \
		$(srcdir)/Include/internal/pycore_uop_metadata.h \
		$(srcdir)/Include/internal/pycore_warnings.h \
		$(srcdir)/Include/internal/pycore_weakref.h \
		$(DTRACE_HEADERS) \
		 \
		\
		$(srcdir)/Python/stdlib_module_names.h

##########################################################################
# Build static libmpdec.a
LIBMPDEC_CFLAGS=-I$(srcdir)/Modules/_decimal/libmpdec -DUNIVERSAL=1 $(PY_STDMODULE_CFLAGS) $(CCSHARED)

# "%.o: %c" is not portable
Modules/_decimal/libmpdec/basearith.o: $(srcdir)/Modules/_decimal/libmpdec/basearith.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/basearith.c

Modules/_decimal/libmpdec/constants.o: $(srcdir)/Modules/_decimal/libmpdec/constants.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/constants.c

Modules/_decimal/libmpdec/context.o: $(srcdir)/Modules/_decimal/libmpdec/context.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/context.c

Modules/_decimal/libmpdec/convolute.o: $(srcdir)/Modules/_decimal/libmpdec/convolute.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/convolute.c

Modules/_decimal/libmpdec/crt.o: $(srcdir)/Modules/_decimal/libmpdec/crt.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/crt.c

Modules/_decimal/libmpdec/difradix2.o: $(srcdir)/Modules/_decimal/libmpdec/difradix2.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/difradix2.c

Modules/_decimal/libmpdec/fnt.o: $(srcdir)/Modules/_decimal/libmpdec/fnt.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/fnt.c

Modules/_decimal/libmpdec/fourstep.o: $(srcdir)/Modules/_decimal/libmpdec/fourstep.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/fourstep.c

Modules/_decimal/libmpdec/io.o: $(srcdir)/Modules/_decimal/libmpdec/io.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/io.c

Modules/_decimal/libmpdec/mpalloc.o: $(srcdir)/Modules/_decimal/libmpdec/mpalloc.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/mpalloc.c

Modules/_decimal/libmpdec/mpdecimal.o: $(srcdir)/Modules/_decimal/libmpdec/mpdecimal.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/mpdecimal.c

Modules/_decimal/libmpdec/mpsignal.o: $(srcdir)/Modules/_decimal/libmpdec/mpsignal.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/mpsignal.c

Modules/_decimal/libmpdec/numbertheory.o: $(srcdir)/Modules/_decimal/libmpdec/numbertheory.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/numbertheory.c

Modules/_decimal/libmpdec/sixstep.o: $(srcdir)/Modules/_decimal/libmpdec/sixstep.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/sixstep.c

Modules/_decimal/libmpdec/transpose.o: $(srcdir)/Modules/_decimal/libmpdec/transpose.c $(LIBMPDEC_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBMPDEC_CFLAGS) -o $@ $(srcdir)/Modules/_decimal/libmpdec/transpose.c

$(LIBMPDEC_A): $(LIBMPDEC_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBMPDEC_OBJS)

##########################################################################
# Build static libexpat.a
LIBEXPAT_CFLAGS=-I$(srcdir)/Modules/expat $(PY_STDMODULE_CFLAGS) $(CCSHARED)

Modules/expat/xmlparse.o: $(srcdir)/Modules/expat/xmlparse.c $(LIBEXPAT_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBEXPAT_CFLAGS) -o $@ $(srcdir)/Modules/expat/xmlparse.c

Modules/expat/xmlrole.o: $(srcdir)/Modules/expat/xmlrole.c $(LIBEXPAT_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBEXPAT_CFLAGS) -o $@ $(srcdir)/Modules/expat/xmlrole.c

Modules/expat/xmltok.o: $(srcdir)/Modules/expat/xmltok.c $(LIBEXPAT_HEADERS) $(PYTHON_HEADERS)
	$(CC) -c $(LIBEXPAT_CFLAGS) -o $@ $(srcdir)/Modules/expat/xmltok.c

$(LIBEXPAT_A): $(LIBEXPAT_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBEXPAT_OBJS)

##########################################################################
# HACL* library build
#
# The HACL* modules are dynamically compiled and linked with the
# corresponding CPython built-in modules on demand, depending on
# whether the module is built or not.
#
# In particular, the HACL* objects are also dependencies of the
# corresponding C extension modules but makesetup must NOT create
# a rule for them.
#
# For WASI, static linking is needed and HACL* is statically linked instead.

Modules/_hacl/Lib_Memzero0.o: $(srcdir)/Modules/_hacl/Lib_Memzero0.c $(LIBHACL_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Lib_Memzero0.c

Modules/_hacl/Hacl_Hash_MD5.o: $(srcdir)/Modules/_hacl/Hacl_Hash_MD5.c $(LIBHACL_MD5_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_MD5.c
$(LIBHACL_MD5_LIB_STATIC): $(LIBHACL_MD5_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_MD5_OBJS)

Modules/_hacl/Hacl_Hash_SHA1.o: $(srcdir)/Modules/_hacl/Hacl_Hash_SHA1.c $(LIBHACL_SHA1_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_SHA1.c
$(LIBHACL_SHA1_LIB_STATIC): $(LIBHACL_SHA1_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_SHA1_OBJS)

Modules/_hacl/Hacl_Hash_SHA2.o: $(srcdir)/Modules/_hacl/Hacl_Hash_SHA2.c $(LIBHACL_SHA2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_SHA2.c
$(LIBHACL_SHA2_LIB_STATIC): $(LIBHACL_SHA2_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_SHA2_OBJS)

Modules/_hacl/Hacl_Hash_SHA3.o: $(srcdir)/Modules/_hacl/Hacl_Hash_SHA3.c $(LIBHACL_SHA3_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_SHA3.c
$(LIBHACL_SHA3_LIB_STATIC): $(LIBHACL_SHA3_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_SHA3_OBJS)

Modules/_hacl/Hacl_Hash_Blake2s.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s.c
Modules/_hacl/Hacl_Hash_Blake2b.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b.c
Modules/_hacl/Hacl_Hash_Blake2s_Simd128.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s_Simd128.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) $(LIBHACL_BLAKE2_SIMD128_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s_Simd128.c
Modules/_hacl/Hacl_Hash_Blake2s_Simd128_universal2.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s_Simd128_universal2.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) $(LIBHACL_BLAKE2_SIMD128_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2s_Simd128_universal2.c
Modules/_hacl/Hacl_Hash_Blake2b_Simd256.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b_Simd256.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) $(LIBHACL_BLAKE2_SIMD256_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b_Simd256.c
Modules/_hacl/Hacl_Hash_Blake2b_Simd256_universal2.o: $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b_Simd256_universal2.c $(LIBHACL_BLAKE2_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) $(LIBHACL_BLAKE2_SIMD256_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Hash_Blake2b_Simd256_universal2.c
$(LIBHACL_BLAKE2_LIB_STATIC): $(LIBHACL_BLAKE2_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_BLAKE2_OBJS)

# Other HACL* cryptographic primitives

Modules/_hacl/Hacl_HMAC.o: $(srcdir)/Modules/_hacl/Hacl_HMAC.c $(LIBHACL_HMAC_HEADERS)
	$(CC) -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_HMAC.c
Modules/_hacl/Hacl_Streaming_HMAC.o: $(srcdir)/Modules/_hacl/Hacl_Streaming_HMAC.c $(LIBHACL_HMAC_HEADERS)
	$(CC) -Wno-unused-variable -c $(LIBHACL_CFLAGS) -o $@ $(srcdir)/Modules/_hacl/Hacl_Streaming_HMAC.c
$(LIBHACL_HMAC_LIB_STATIC): $(LIBHACL_HMAC_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIBHACL_HMAC_OBJS)

##########################################################################
# create relative links from build/lib.platform/egg.so to Modules/egg.so
# pybuilddir.txt is created too late. We cannot use it in Makefile
# targets. ln --relative is not portable.
.PHONY: sharedmods
sharedmods: $(SHAREDMODS) pybuilddir.txt
	@target=`cat pybuilddir.txt`; \
	$(MKDIR_P) $$target; \
	for mod in X $(SHAREDMODS); do \
		if test $$mod != X; then \
			$(LN) -sf ../../$$mod $$target/`basename $$mod`; \
		fi; \
	done

# dependency on BUILDPYTHON ensures that the target is run last
.PHONY: checksharedmods
checksharedmods: sharedmods $(PYTHON_FOR_BUILD_DEPS) $(BUILDPYTHON)
	@$(RUNSHARED) $(PYTHON_FOR_BUILD) $(srcdir)/Tools/build/check_extension_modules.py

.PHONY: rundsymutil
rundsymutil: sharedmods $(PYTHON_FOR_BUILD_DEPS) $(BUILDPYTHON)
	@if [ ! -z $(DSYMUTIL) ] ; then \
		echo $(DSYMUTIL_PATH) $(BUILDPYTHON); \
		$(DSYMUTIL_PATH) $(BUILDPYTHON); \
		if test -f $(LDLIBRARY); then \
			echo $(DSYMUTIL_PATH) $(LDLIBRARY); \
			$(DSYMUTIL_PATH) $(LDLIBRARY); \
		fi; \
		for mod in X $(SHAREDMODS); do \
			if test $$mod != X; then \
				echo $(DSYMUTIL_PATH) $$mod; \
				$(DSYMUTIL_PATH) $$mod; \
			fi; \
		done \
	fi

Modules/Setup.local:
	@# Create empty Setup.local when file was deleted by user
	echo "# Edit this file for local setup changes" > $@

Modules/Setup.bootstrap: $(srcdir)/Modules/Setup.bootstrap.in config.status
	./config.status $@

Modules/Setup.stdlib: $(srcdir)/Modules/Setup.stdlib.in config.status
	./config.status $@

Makefile Modules/config.c: Makefile.pre \
				$(srcdir)/Modules/config.c.in \
				$(MAKESETUP) \
				$(srcdir)/Modules/Setup \
				Modules/Setup.local \
				Modules/Setup.bootstrap \
				Modules/Setup.stdlib
	$(MAKESETUP) -c $(srcdir)/Modules/config.c.in \
				-s Modules \
				Modules/Setup.local \
				Modules/Setup.stdlib \
				Modules/Setup.bootstrap \
				$(srcdir)/Modules/Setup
	@mv config.c Modules
	@echo "The Makefile was updated, you may need to re-run make."

.PHONY: regen-test-frozenmain
regen-test-frozenmain: $(BUILDPYTHON)
	# Regenerate Programs/test_frozenmain.h
	# from Programs/test_frozenmain.py
	# using Programs/freeze_test_frozenmain.py
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Programs/freeze_test_frozenmain.py Programs/test_frozenmain.h

.PHONY: regen-test-levenshtein
regen-test-levenshtein:
	# Regenerate Lib/test/levenshtein_examples.json
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_levenshtein_examples.py $(srcdir)/Lib/test/levenshtein_examples.json

.PHONY: regen-re
regen-re: $(BUILDPYTHON)
	# Regenerate Lib/re/_casefix.py
	# using Tools/build/generate_re_casefix.py
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/build/generate_re_casefix.py $(srcdir)/Lib/re/_casefix.py

Programs/_testembed: Programs/_testembed.o $(LINK_PYTHON_DEPS)
	$(LINKCC) $(PY_CORE_LDFLAGS) $(LINKFORSHARED) -o $@ Programs/_testembed.o $(LINK_PYTHON_OBJS) $(LIBS) $(MODLIBS) $(SYSLIBS)

############################################################################
# "Bootstrap Python" used to run Programs/_freeze_module.py

BOOTSTRAP_HEADERS = \
	Python/frozen_modules/importlib._bootstrap.h \
	Python/frozen_modules/importlib._bootstrap_external.h \
	Python/frozen_modules/zipimport.h

Programs/_bootstrap_python.o: Programs/_bootstrap_python.c $(BOOTSTRAP_HEADERS) $(PYTHON_HEADERS)

_bootstrap_python: $(LIBRARY_OBJS_OMIT_FROZEN) Programs/_bootstrap_python.o Modules/getpath.o Modules/Setup.local
	$(LINKCC) $(PY_LDFLAGS_NOLTO) -o $@ $(LIBRARY_OBJS_OMIT_FROZEN) \
		Programs/_bootstrap_python.o Modules/getpath.o $(LIBS) $(MODLIBS) $(SYSLIBS)
	# Dummy pybuilddir.txt  is needed for _bootstrap_python to be runnable
	@echo "none" > ./pybuilddir.txt


############################################################################
# frozen modules (including importlib)
#
# Freezing is a multi step process. It works differently for standard builds
# and cross builds. Standard builds use Programs/_freeze_module and
# _bootstrap_python for freezing, so users can build Python
# without an existing Python installation. Cross builds cannot execute
# compiled binaries and therefore rely on an external build Python
# interpreter. The build interpreter must have same version and same bytecode
# as the host (target) binary.
#
# Standard build process:
# 1) compile minimal core objects for Py_Compile*() and PyMarshal_Write*().
# 2) build Programs/_freeze_module binary.
# 3) create frozen module headers for importlib and getpath.
# 4) build _bootstrap_python binary.
# 5) create remaining frozen module headers with
#    ``./_bootstrap_python Programs/_freeze_module.py``. The pure Python
#    script is used to test the cross compile code path.
#
# Cross compile process:
# 1) create all frozen module headers with external build Python and
#    Programs/_freeze_module.py script.
#

# FROZEN_FILES_* are auto-generated by Tools/build/freeze_modules.py.
FROZEN_FILES_IN = \
		Lib/importlib/_bootstrap.py \
		Lib/importlib/_bootstrap_external.py \
		Lib/zipimport.py \
		Lib/abc.py \
		Lib/codecs.py \
		Lib/io.py \
		Lib/_collections_abc.py \
		Lib/_sitebuiltins.py \
		Lib/genericpath.py \
		Lib/ntpath.py \
		Lib/posixpath.py \
		Lib/os.py \
		Lib/site.py \
		Lib/stat.py \
		Lib/importlib/util.py \
		Lib/importlib/machinery.py \
		Lib/runpy.py \
		Lib/__hello__.py \
		Lib/__phello__/__init__.py \
		Lib/__phello__/ham/__init__.py \
		Lib/__phello__/ham/eggs.py \
		Lib/__phello__/spam.py \
		Tools/freeze/flag.py
# End FROZEN_FILES_IN
FROZEN_FILES_OUT = \
		Python/frozen_modules/importlib._bootstrap.h \
		Python/frozen_modules/importlib._bootstrap_external.h \
		Python/frozen_modules/zipimport.h \
		Python/frozen_modules/abc.h \
		Python/frozen_modules/codecs.h \
		Python/frozen_modules/io.h \
		Python/frozen_modules/_collections_abc.h \
		Python/frozen_modules/_sitebuiltins.h \
		Python/frozen_modules/genericpath.h \
		Python/frozen_modules/ntpath.h \
		Python/frozen_modules/posixpath.h \
		Python/frozen_modules/os.h \
		Python/frozen_modules/site.h \
		Python/frozen_modules/stat.h \
		Python/frozen_modules/importlib.util.h \
		Python/frozen_modules/importlib.machinery.h \
		Python/frozen_modules/runpy.h \
		Python/frozen_modules/__hello__.h \
		Python/frozen_modules/__phello__.h \
		Python/frozen_modules/__phello__.ham.h \
		Python/frozen_modules/__phello__.ham.eggs.h \
		Python/frozen_modules/__phello__.spam.h \
		Python/frozen_modules/frozen_only.h
# End FROZEN_FILES_OUT

Programs/_freeze_module.o: Programs/_freeze_module.c Makefile

Modules/getpath_noop.o: $(srcdir)/Modules/getpath_noop.c Makefile

Programs/_freeze_module: Programs/_freeze_module.o Modules/getpath_noop.o $(LIBRARY_OBJS_OMIT_FROZEN)
	$(LINKCC) $(PY_CORE_LDFLAGS) -o $@ Programs/_freeze_module.o Modules/getpath_noop.o $(LIBRARY_OBJS_OMIT_FROZEN) $(LIBS) $(MODLIBS) $(SYSLIBS)

# We manually freeze getpath.py rather than through freeze_modules
Python/frozen_modules/getpath.h: Modules/getpath.py $(FREEZE_MODULE_BOOTSTRAP_DEPS)
	$(FREEZE_MODULE_BOOTSTRAP) getpath $(srcdir)/Modules/getpath.py Python/frozen_modules/getpath.h

# BEGIN: freezing modules

Python/frozen_modules/importlib._bootstrap.h: Lib/importlib/_bootstrap.py $(FREEZE_MODULE_BOOTSTRAP_DEPS)
	$(FREEZE_MODULE_BOOTSTRAP) importlib._bootstrap $(srcdir)/Lib/importlib/_bootstrap.py Python/frozen_modules/importlib._bootstrap.h

Python/frozen_modules/importlib._bootstrap_external.h: Lib/importlib/_bootstrap_external.py $(FREEZE_MODULE_BOOTSTRAP_DEPS)
	$(FREEZE_MODULE_BOOTSTRAP) importlib._bootstrap_external $(srcdir)/Lib/importlib/_bootstrap_external.py Python/frozen_modules/importlib._bootstrap_external.h

Python/frozen_modules/zipimport.h: Lib/zipimport.py $(FREEZE_MODULE_BOOTSTRAP_DEPS)
	$(FREEZE_MODULE_BOOTSTRAP) zipimport $(srcdir)/Lib/zipimport.py Python/frozen_modules/zipimport.h

Python/frozen_modules/abc.h: Lib/abc.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) abc $(srcdir)/Lib/abc.py Python/frozen_modules/abc.h

Python/frozen_modules/codecs.h: Lib/codecs.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) codecs $(srcdir)/Lib/codecs.py Python/frozen_modules/codecs.h

Python/frozen_modules/io.h: Lib/io.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) io $(srcdir)/Lib/io.py Python/frozen_modules/io.h

Python/frozen_modules/_collections_abc.h: Lib/_collections_abc.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) _collections_abc $(srcdir)/Lib/_collections_abc.py Python/frozen_modules/_collections_abc.h

Python/frozen_modules/_sitebuiltins.h: Lib/_sitebuiltins.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) _sitebuiltins $(srcdir)/Lib/_sitebuiltins.py Python/frozen_modules/_sitebuiltins.h

Python/frozen_modules/genericpath.h: Lib/genericpath.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) genericpath $(srcdir)/Lib/genericpath.py Python/frozen_modules/genericpath.h

Python/frozen_modules/ntpath.h: Lib/ntpath.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) ntpath $(srcdir)/Lib/ntpath.py Python/frozen_modules/ntpath.h

Python/frozen_modules/posixpath.h: Lib/posixpath.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) posixpath $(srcdir)/Lib/posixpath.py Python/frozen_modules/posixpath.h

Python/frozen_modules/os.h: Lib/os.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) os $(srcdir)/Lib/os.py Python/frozen_modules/os.h

Python/frozen_modules/site.h: Lib/site.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) site $(srcdir)/Lib/site.py Python/frozen_modules/site.h

Python/frozen_modules/stat.h: Lib/stat.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) stat $(srcdir)/Lib/stat.py Python/frozen_modules/stat.h

Python/frozen_modules/importlib.util.h: Lib/importlib/util.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) importlib.util $(srcdir)/Lib/importlib/util.py Python/frozen_modules/importlib.util.h

Python/frozen_modules/importlib.machinery.h: Lib/importlib/machinery.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) importlib.machinery $(srcdir)/Lib/importlib/machinery.py Python/frozen_modules/importlib.machinery.h

Python/frozen_modules/runpy.h: Lib/runpy.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) runpy $(srcdir)/Lib/runpy.py Python/frozen_modules/runpy.h

Python/frozen_modules/__hello__.h: Lib/__hello__.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) __hello__ $(srcdir)/Lib/__hello__.py Python/frozen_modules/__hello__.h

Python/frozen_modules/__phello__.h: Lib/__phello__/__init__.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) __phello__ $(srcdir)/Lib/__phello__/__init__.py Python/frozen_modules/__phello__.h

Python/frozen_modules/__phello__.ham.h: Lib/__phello__/ham/__init__.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) __phello__.ham $(srcdir)/Lib/__phello__/ham/__init__.py Python/frozen_modules/__phello__.ham.h

Python/frozen_modules/__phello__.ham.eggs.h: Lib/__phello__/ham/eggs.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) __phello__.ham.eggs $(srcdir)/Lib/__phello__/ham/eggs.py Python/frozen_modules/__phello__.ham.eggs.h

Python/frozen_modules/__phello__.spam.h: Lib/__phello__/spam.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) __phello__.spam $(srcdir)/Lib/__phello__/spam.py Python/frozen_modules/__phello__.spam.h

Python/frozen_modules/frozen_only.h: Tools/freeze/flag.py $(FREEZE_MODULE_DEPS)
	$(FREEZE_MODULE) frozen_only $(srcdir)/Tools/freeze/flag.py Python/frozen_modules/frozen_only.h

# END: freezing modules

Tools/build/freeze_modules.py: $(FREEZE_MODULE)

.PHONY: regen-frozen
regen-frozen: Tools/build/freeze_modules.py $(FROZEN_FILES_IN)
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/freeze_modules.py --frozen-modules
	@echo "The Makefile was updated, you may need to re-run make."

# We keep this renamed target around for folks with muscle memory.
.PHONY: regen-importlib
regen-importlib: regen-frozen

############################################################################
# Global objects

# Dependencies which can add and/or remove _Py_ID() identifiers:
# - "make clinic"
.PHONY: regen-global-objects
regen-global-objects: $(srcdir)/Tools/build/generate_global_objects.py clinic
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_global_objects.py

############################################################################
# ABI

.PHONY: regen-abidump
regen-abidump: all
	@$(MKDIR_P) $(srcdir)/Doc/data/
	abidw "libpython$(LDVERSION).so" --no-architecture --out-file $(srcdir)/Doc/data/python$(LDVERSION).abi.new
	@$(UPDATE_FILE) --create $(srcdir)/Doc/data/python$(LDVERSION).abi $(srcdir)/Doc/data/python$(LDVERSION).abi.new

.PHONY: check-abidump
check-abidump: all
	abidiff $(srcdir)/Doc/data/python$(LDVERSION).abi "libpython$(LDVERSION).so" --drop-private-types --no-architecture --no-added-syms

.PHONY: regen-limited-abi
regen-limited-abi: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/build/stable_abi.py --generate-all

############################################################################
# Regenerate Unicode Data

.PHONY: regen-unicodedata
regen-unicodedata:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/unicode/makeunicodedata.py


############################################################################
# Regenerate all generated files

# "clinic" is regenerated implicitly via "regen-global-objects".
.PHONY: regen-all
regen-all: regen-cases regen-typeslots \
	regen-token regen-ast regen-keyword regen-sre regen-frozen \
	regen-pegen-metaparser regen-pegen regen-test-frozenmain \
	regen-test-levenshtein regen-global-objects
	@echo
	@echo "Note: make regen-stdlib-module-names, make regen-limited-abi, "
	@echo "make regen-configure, make regen-sbom, and make regen-unicodedata should be run manually"

############################################################################
# Special rules for object files

Modules/getbuildinfo.o: $(PARSER_OBJS) \
		$(OBJECT_OBJS) \
		$(PYTHON_OBJS) \
		$(MODULE_OBJS) \
		$(MODOBJS) \
		$(DTRACE_OBJS) \
		$(srcdir)/Modules/getbuildinfo.c
	$(CC) -c $(PY_CORE_CFLAGS) \
	      -DGITVERSION="\"`LC_ALL=C $(GITVERSION)`\"" \
	      -DGITTAG="\"`LC_ALL=C $(GITTAG)`\"" \
	      -DGITBRANCH="\"`LC_ALL=C $(GITBRANCH)`\"" \
	      -o $@ $(srcdir)/Modules/getbuildinfo.c

Modules/getpath.o: $(srcdir)/Modules/getpath.c Python/frozen_modules/getpath.h Makefile $(PYTHON_HEADERS)
	$(CC) -c $(PY_CORE_CFLAGS) -DPYTHONPATH='"$(PYTHONPATH)"' \
		-DPREFIX='"$(host_prefix)"' \
		-DEXEC_PREFIX='"$(host_exec_prefix)"' \
		-DVERSION='"$(VERSION)"' \
		-DVPATH='"$(VPATH)"' \
		-DPLATLIBDIR='"$(PLATLIBDIR)"' \
		-DPYTHONFRAMEWORK='"$(PYTHONFRAMEWORK)"' \
		-o $@ $(srcdir)/Modules/getpath.c

Programs/python.o: $(srcdir)/Programs/python.c
	$(CC) -c $(PY_CORE_CFLAGS) -o $@ $(srcdir)/Programs/python.c

Programs/_testembed.o: $(srcdir)/Programs/_testembed.c Programs/test_frozenmain.h $(PYTHON_HEADERS)
	$(CC) -c $(PY_CORE_CFLAGS) -o $@ $(srcdir)/Programs/_testembed.c

Modules/_sre/sre.o: $(srcdir)/Modules/_sre/sre.c $(srcdir)/Modules/_sre/sre.h $(srcdir)/Modules/_sre/sre_constants.h $(srcdir)/Modules/_sre/sre_lib.h

Modules/posixmodule.o: $(srcdir)/Modules/posixmodule.c $(srcdir)/Modules/posixmodule.h

Modules/grpmodule.o: $(srcdir)/Modules/grpmodule.c $(srcdir)/Modules/posixmodule.h

Modules/pwdmodule.o: $(srcdir)/Modules/pwdmodule.c $(srcdir)/Modules/posixmodule.h

Modules/signalmodule.o: $(srcdir)/Modules/signalmodule.c $(srcdir)/Modules/posixmodule.h

Modules/_interpretersmodule.o: $(srcdir)/Modules/_interpretersmodule.c $(srcdir)/Modules/_interpreters_common.h

Modules/_interpqueuesmodule.o: $(srcdir)/Modules/_interpqueuesmodule.c $(srcdir)/Modules/_interpreters_common.h

Modules/_interpchannelsmodule.o: $(srcdir)/Modules/_interpchannelsmodule.c $(srcdir)/Modules/_interpreters_common.h

Python/crossinterp.o: $(srcdir)/Python/crossinterp.c $(srcdir)/Python/crossinterp_data_lookup.h $(srcdir)/Python/crossinterp_exceptions.h

Python/initconfig.o: $(srcdir)/Python/initconfig.c $(srcdir)/Python/config_common.h

Python/interpconfig.o: $(srcdir)/Python/interpconfig.c $(srcdir)/Python/config_common.h

Python/dynload_shlib.o: $(srcdir)/Python/dynload_shlib.c Makefile
	$(CC) -c $(PY_CORE_CFLAGS) \
		-DSOABI='"$(SOABI)"' \
		-o $@ $(srcdir)/Python/dynload_shlib.c

Python/dynload_hpux.o: $(srcdir)/Python/dynload_hpux.c Makefile
	$(CC) -c $(PY_CORE_CFLAGS) \
		-DSHLIB_EXT='"$(EXT_SUFFIX)"' \
		-o $@ $(srcdir)/Python/dynload_hpux.c

Python/sysmodule.o: $(srcdir)/Python/sysmodule.c Makefile $(srcdir)/Include/pydtrace.h
	$(CC) -c $(PY_CORE_CFLAGS) \
		-DABIFLAGS='"$(ABIFLAGS)"' \
		$(MULTIARCH_CPPFLAGS) \
		-o $@ $(srcdir)/Python/sysmodule.c

$(IO_OBJS): $(IO_H)

.PHONY: regen-pegen-metaparser
regen-pegen-metaparser:
	@$(MKDIR_P) $(srcdir)/Tools/peg_generator/pegen
	PYTHONPATH=$(srcdir)/Tools/peg_generator $(PYTHON_FOR_REGEN) -m pegen -q python \
	$(srcdir)/Tools/peg_generator/pegen/metagrammar.gram \
	-o $(srcdir)/Tools/peg_generator/pegen/grammar_parser.py.new
	$(UPDATE_FILE) $(srcdir)/Tools/peg_generator/pegen/grammar_parser.py \
	$(srcdir)/Tools/peg_generator/pegen/grammar_parser.py.new

.PHONY: regen-pegen
regen-pegen:
	@$(MKDIR_P) $(srcdir)/Parser
	@$(MKDIR_P) $(srcdir)/Parser/tokenizer
	@$(MKDIR_P) $(srcdir)/Parser/lexer
	PYTHONPATH=$(srcdir)/Tools/peg_generator $(PYTHON_FOR_REGEN) -m pegen -q c \
		$(srcdir)/Grammar/python.gram \
		$(srcdir)/Grammar/Tokens \
		-o $(srcdir)/Parser/parser.c.new
	$(UPDATE_FILE) --create $(srcdir)/Parser/parser.c $(srcdir)/Parser/parser.c.new

.PHONY: regen-ast
regen-ast:
	# Regenerate 3 files using Parser/asdl_c.py:
	# - Include/internal/pycore_ast.h
	# - Include/internal/pycore_ast_state.h
	# - Python/Python-ast.c
	$(MKDIR_P) $(srcdir)/Include
	$(MKDIR_P) $(srcdir)/Python
	$(PYTHON_FOR_REGEN) $(srcdir)/Parser/asdl_c.py \
		$(srcdir)/Parser/Python.asdl \
		-H $(srcdir)/Include/internal/pycore_ast.h.new \
		-I $(srcdir)/Include/internal/pycore_ast_state.h.new \
		-C $(srcdir)/Python/Python-ast.c.new

	$(UPDATE_FILE) $(srcdir)/Include/internal/pycore_ast.h $(srcdir)/Include/internal/pycore_ast.h.new
	$(UPDATE_FILE) $(srcdir)/Include/internal/pycore_ast_state.h $(srcdir)/Include/internal/pycore_ast_state.h.new
	$(UPDATE_FILE) $(srcdir)/Python/Python-ast.c $(srcdir)/Python/Python-ast.c.new

.PHONY: regen-token
regen-token:
	# Regenerate Doc/library/token-list.inc from Grammar/Tokens
	# using Tools/build/generate_token.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_token.py rst \
		$(srcdir)/Grammar/Tokens \
		$(srcdir)/Doc/library/token-list.inc \
		$(srcdir)/Doc/library/token.rst
	# Regenerate Include/internal/pycore_token.h from Grammar/Tokens
	# using Tools/build/generate_token.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_token.py h \
		$(srcdir)/Grammar/Tokens \
		$(srcdir)/Include/internal/pycore_token.h
	# Regenerate Parser/token.c from Grammar/Tokens
	# using Tools/build/generate_token.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_token.py c \
		$(srcdir)/Grammar/Tokens \
		$(srcdir)/Parser/token.c
	# Regenerate Lib/token.py from Grammar/Tokens
	# using Tools/build/generate_token.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_token.py py \
		$(srcdir)/Grammar/Tokens \
		$(srcdir)/Lib/token.py

.PHONY: regen-keyword
regen-keyword:
	# Regenerate Lib/keyword.py from Grammar/python.gram and Grammar/Tokens
	# using Tools/peg_generator/pegen
	PYTHONPATH=$(srcdir)/Tools/peg_generator $(PYTHON_FOR_REGEN) -m pegen.keywordgen \
		$(srcdir)/Grammar/python.gram \
		$(srcdir)/Grammar/Tokens \
		$(srcdir)/Lib/keyword.py.new
	$(UPDATE_FILE) $(srcdir)/Lib/keyword.py $(srcdir)/Lib/keyword.py.new

.PHONY: regen-stdlib-module-names
regen-stdlib-module-names: all Programs/_testembed
	# Regenerate Python/stdlib_module_names.h
	# using Tools/build/generate_stdlib_module_names.py
	$(RUNSHARED) ./$(BUILDPYTHON) \
		$(srcdir)/Tools/build/generate_stdlib_module_names.py \
		> $(srcdir)/Python/stdlib_module_names.h.new
	$(UPDATE_FILE) $(srcdir)/Python/stdlib_module_names.h $(srcdir)/Python/stdlib_module_names.h.new

.PHONY: regen-sre
regen-sre:
	# Regenerate Modules/_sre/sre_constants.h and Modules/_sre/sre_targets.h
	# from Lib/re/_constants.py using Tools/build/generate_sre_constants.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_sre_constants.py \
		$(srcdir)/Lib/re/_constants.py \
		$(srcdir)/Modules/_sre/sre_constants.h \
		$(srcdir)/Modules/_sre/sre_targets.h

Python/compile.o Python/codegen.o Python/symtable.o Python/ast_unparse.o Python/ast.o Python/future.o: $(srcdir)/Include/internal/pycore_ast.h $(srcdir)/Include/internal/pycore_ast.h

Python/getplatform.o: $(srcdir)/Python/getplatform.c
		$(CC) -c $(PY_CORE_CFLAGS) -DPLATFORM='"$(MACHDEP)"' -o $@ $(srcdir)/Python/getplatform.c

Python/importdl.o: $(srcdir)/Python/importdl.c
		$(CC) -c $(PY_CORE_CFLAGS) -I$(DLINCLDIR) -o $@ $(srcdir)/Python/importdl.c

Objects/unicodectype.o:	$(srcdir)/Objects/unicodectype.c \
				$(srcdir)/Objects/unicodetype_db.h

BYTESTR_DEPS = \
		$(srcdir)/Objects/stringlib/count.h \
		$(srcdir)/Objects/stringlib/ctype.h \
		$(srcdir)/Objects/stringlib/fastsearch.h \
		$(srcdir)/Objects/stringlib/find.h \
		$(srcdir)/Objects/stringlib/join.h \
		$(srcdir)/Objects/stringlib/partition.h \
		$(srcdir)/Objects/stringlib/split.h \
		$(srcdir)/Objects/stringlib/stringdefs.h \
		$(srcdir)/Objects/stringlib/transmogrify.h

UNICODE_DEPS = \
		$(srcdir)/Objects/stringlib/asciilib.h \
		$(srcdir)/Objects/stringlib/codecs.h \
		$(srcdir)/Objects/stringlib/count.h \
		$(srcdir)/Objects/stringlib/fastsearch.h \
		$(srcdir)/Objects/stringlib/find.h \
		$(srcdir)/Objects/stringlib/find_max_char.h \
		$(srcdir)/Objects/stringlib/localeutil.h \
		$(srcdir)/Objects/stringlib/partition.h \
		$(srcdir)/Objects/stringlib/replace.h \
		$(srcdir)/Objects/stringlib/repr.h \
		$(srcdir)/Objects/stringlib/split.h \
		$(srcdir)/Objects/stringlib/ucs1lib.h \
		$(srcdir)/Objects/stringlib/ucs2lib.h \
		$(srcdir)/Objects/stringlib/ucs4lib.h \
		$(srcdir)/Objects/stringlib/undef.h \
		$(srcdir)/Objects/stringlib/unicode_format.h

Objects/bytes_methods.o: $(srcdir)/Objects/bytes_methods.c $(BYTESTR_DEPS)
Objects/bytesobject.o: $(srcdir)/Objects/bytesobject.c $(BYTESTR_DEPS)
Objects/bytearrayobject.o: $(srcdir)/Objects/bytearrayobject.c $(BYTESTR_DEPS)

Objects/unicodeobject.o: $(srcdir)/Objects/unicodeobject.c $(UNICODE_DEPS)

Objects/dictobject.o: $(srcdir)/Objects/stringlib/eq.h
Objects/setobject.o: $(srcdir)/Objects/stringlib/eq.h

Objects/obmalloc.o: $(srcdir)/Objects/mimalloc/alloc.c \
		$(srcdir)/Objects/mimalloc/alloc-aligned.c \
		$(srcdir)/Objects/mimalloc/alloc-posix.c \
		$(srcdir)/Objects/mimalloc/arena.c \
		$(srcdir)/Objects/mimalloc/bitmap.c \
		$(srcdir)/Objects/mimalloc/heap.c \
		$(srcdir)/Objects/mimalloc/init.c \
		$(srcdir)/Objects/mimalloc/options.c \
		$(srcdir)/Objects/mimalloc/os.c \
		$(srcdir)/Objects/mimalloc/page.c \
		$(srcdir)/Objects/mimalloc/random.c \
		$(srcdir)/Objects/mimalloc/segment.c \
		$(srcdir)/Objects/mimalloc/segment-map.c \
		$(srcdir)/Objects/mimalloc/stats.c \
		$(srcdir)/Objects/mimalloc/prim/prim.c \
		$(srcdir)/Objects/mimalloc/prim/osx/prim.c \
		$(srcdir)/Objects/mimalloc/prim/unix/prim.c \
		$(srcdir)/Objects/mimalloc/prim/wasi/prim.c

Objects/mimalloc/page.o: $(srcdir)/Objects/mimalloc/page-queue.c


# Regenerate various files from Python/bytecodes.c
# Pass CASESFLAG=-l to insert #line directives in the output

.PHONY: regen-cases
regen-cases: \
        regen-opcode-ids regen-opcode-targets regen-uop-ids regen-opcode-metadata-py \
		regen-generated-cases regen-executor-cases regen-optimizer-cases \
		regen-opcode-metadata regen-uop-metadata

.PHONY: regen-opcode-ids
regen-opcode-ids:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/opcode_id_generator.py \
	    -o $(srcdir)/Include/opcode_ids.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Include/opcode_ids.h $(srcdir)/Include/opcode_ids.h.new

.PHONY: regen-opcode-targets
regen-opcode-targets:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/target_generator.py \
	    -o $(srcdir)/Python/opcode_targets.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Python/opcode_targets.h $(srcdir)/Python/opcode_targets.h.new

.PHONY: regen-uop-ids
regen-uop-ids:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/uop_id_generator.py \
	    -o $(srcdir)/Include/internal/pycore_uop_ids.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Include/internal/pycore_uop_ids.h $(srcdir)/Include/internal/pycore_uop_ids.h.new

.PHONY: regen-opcode-metadata-py
regen-opcode-metadata-py:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/py_metadata_generator.py \
	    -o $(srcdir)/Lib/_opcode_metadata.py.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Lib/_opcode_metadata.py $(srcdir)/Lib/_opcode_metadata.py.new

.PHONY: regen-generated-cases
regen-generated-cases:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/tier1_generator.py \
	    -o $(srcdir)/Python/generated_cases.c.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Python/generated_cases.c.h $(srcdir)/Python/generated_cases.c.h.new

.PHONY: regen-executor-cases
regen-executor-cases:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/tier2_generator.py \
	    -o $(srcdir)/Python/executor_cases.c.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Python/executor_cases.c.h $(srcdir)/Python/executor_cases.c.h.new

.PHONY: regen-optimizer-cases
regen-optimizer-cases:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/optimizer_generator.py \
	    -o $(srcdir)/Python/optimizer_cases.c.h.new \
	    $(srcdir)/Python/optimizer_bytecodes.c \
	    $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Python/optimizer_cases.c.h $(srcdir)/Python/optimizer_cases.c.h.new

.PHONY: regen-opcode-metadata
regen-opcode-metadata:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/opcode_metadata_generator.py \
	    -o $(srcdir)/Include/internal/pycore_opcode_metadata.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Include/internal/pycore_opcode_metadata.h $(srcdir)/Include/internal/pycore_opcode_metadata.h.new

.PHONY: regen-uop-metadata
regen-uop-metadata:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/cases_generator/uop_metadata_generator.py -o \
	    $(srcdir)/Include/internal/pycore_uop_metadata.h.new $(srcdir)/Python/bytecodes.c
	$(UPDATE_FILE) $(srcdir)/Include/internal/pycore_uop_metadata.h $(srcdir)/Include/internal/pycore_uop_metadata.h.new

Python/compile.o Python/codegen.o Python/assemble.o Python/flowgraph.o Python/instruction_sequence.o: \
                $(srcdir)/Include/internal/pycore_compile.h \
                $(srcdir)/Include/internal/pycore_flowgraph.h \
                $(srcdir)/Include/internal/pycore_instruction_sequence.h \
                $(srcdir)/Include/internal/pycore_opcode_metadata.h \
                $(srcdir)/Include/internal/pycore_opcode_utils.h

Python/ceval.o: \
		$(srcdir)/Python/ceval_macros.h \
		$(srcdir)/Python/condvar.h \
		$(srcdir)/Python/generated_cases.c.h \
		$(srcdir)/Python/executor_cases.c.h \
		$(srcdir)/Python/opcode_targets.h

Python/flowgraph.o: \
		$(srcdir)/Include/internal/pycore_opcode_metadata.h

Python/optimizer.o: \
		$(srcdir)/Python/executor_cases.c.h \
		$(srcdir)/Include/internal/pycore_opcode_metadata.h \
		$(srcdir)/Include/internal/pycore_optimizer.h

Python/optimizer_analysis.o: \
		$(srcdir)/Include/internal/pycore_opcode_metadata.h \
		$(srcdir)/Include/internal/pycore_optimizer.h \
		$(srcdir)/Python/optimizer_cases.c.h

Python/frozen.o: $(FROZEN_FILES_OUT)

# Generate DTrace probe macros, then rename them (PYTHON_ -> PyDTrace_) to
# follow our naming conventions. dtrace(1) uses the output filename to generate
# an include guard, so we can't use a pipeline to transform its output.
Include/pydtrace_probes.h: $(srcdir)/Include/pydtrace.d
	$(MKDIR_P) Include
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -h -s $(srcdir)/Include/pydtrace.d
	: sed in-place edit with POSIX-only tools
	sed 's/PYTHON_/PyDTrace_/' $@ > $@.tmp
	mv $@.tmp $@

Python/ceval.o: $(srcdir)/Include/pydtrace.h
Python/gc.o: $(srcdir)/Include/pydtrace.h
Python/import.o: $(srcdir)/Include/pydtrace.h

Python/pydtrace.o: $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -G -s $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)

Objects/typeobject.o: Objects/typeslots.inc

.PHONY: regen-typeslots
regen-typeslots:
	# Regenerate Objects/typeslots.inc from Include/typeslotsh
	# using Objects/typeslots.py
	$(PYTHON_FOR_REGEN) $(srcdir)/Objects/typeslots.py \
		< $(srcdir)/Include/typeslots.h \
		$(srcdir)/Objects/typeslots.inc.new
	$(UPDATE_FILE) $(srcdir)/Objects/typeslots.inc $(srcdir)/Objects/typeslots.inc.new

$(LIBRARY_OBJS) $(MODOBJS) Programs/python.o: $(PYTHON_HEADERS)


######################################################################

TESTOPTS=	$(EXTRATESTOPTS)
TESTPYTHON=	$(RUNSHARED) $(PYTHON_FOR_BUILD) $(TESTPYTHONOPTS)
TESTRUNNER=	$(TESTPYTHON) -m test
TESTTIMEOUT=

# Remove "test_python_*" directories of previous failed test jobs.
# Pass TESTOPTS options because it can contain --tempdir option.
.PHONY: cleantest
cleantest: all
	$(TESTRUNNER) $(TESTOPTS) --cleanup

# Run a basic set of regression tests.
# This excludes some tests that are particularly resource-intensive.
# Similar to buildbottest, but use --fast-ci option, instead of --slow-ci.
.PHONY: test
test: all
	$(TESTRUNNER) --fast-ci -u-gui --timeout=$(TESTTIMEOUT) $(TESTOPTS)

# Run a basic set of regression tests inside the CI.
# This excludes some tests that are particularly resource-intensive.
# Similar to test, but also runs GUI tests.
ci: all
	$(TESTRUNNER) --fast-ci --timeout=$(TESTTIMEOUT) $(TESTOPTS)

# Run the test suite for both architectures in a Universal build on OSX.
# Must be run on an Intel box.
.PHONY: testuniversal
testuniversal: all
	@if [ `arch` != 'i386' ]; then \
		echo "This can only be used on OSX/i386" ;\
		exit 1 ;\
	fi
	$(TESTRUNNER) --slow-ci --timeout=$(TESTTIMEOUT) $(TESTOPTS)
	$(RUNSHARED) /usr/libexec/oah/translate \
		./$(BUILDPYTHON) -E -m test -j 0 -u all $(TESTOPTS)

# Run the test suite on the iOS simulator. Must be run on a macOS machine with
# a full Xcode install that has an iPhone SE (3rd edition) simulator available.
# This must be run *after* a `make install` has completed the build. The
# `--with-framework-name` argument *cannot* be used when configuring the build.
XCFOLDER:=iOSTestbed.$(MULTIARCH).$(shell date +%s).$$PPID
.PHONY: testios
testios:
	@if test "$(MACHDEP)" != "ios"; then \
		echo "Cannot run the iOS testbed for a non-iOS build."; \
		exit 1;\
	fi
	@if test "$(findstring -iphonesimulator,$(MULTIARCH))" != "-iphonesimulator"; then \
		echo "Cannot run the iOS testbed for non-simulator builds."; \
		exit 1;\
	fi
	@if test $(PYTHONFRAMEWORK) != "Python"; then \
		echo "Cannot run the iOS testbed with a non-default framework name."; \
		exit 1;\
	fi
	@if ! test -d $(PYTHONFRAMEWORKPREFIX); then \
		echo "Cannot find a finalized iOS Python.framework. Have you run 'make install' to finalize the framework build?"; \
		exit 1;\
	fi

	# Clone the testbed project into the XCFOLDER
	$(PYTHON_FOR_BUILD) $(srcdir)/Apple/testbed clone --framework $(PYTHONFRAMEWORKPREFIX) "$(XCFOLDER)"

	# Run the testbed project
	$(PYTHON_FOR_BUILD) "$(XCFOLDER)" run --verbose -- test -uall --single-process --rerun -W

# Like test, but using --slow-ci which enables all test resources and use
# longer timeout. Run an optional pybuildbot.identify script to include
# information about the build environment.
.PHONY: buildbottest
buildbottest: all
	-@if which pybuildbot.identify >/dev/null 2>&1; then \
		pybuildbot.identify "CC='$(CC)'" "CXX='$(CXX)'"; \
	fi
	$(TESTRUNNER) --slow-ci --timeout=$(TESTTIMEOUT) $(TESTOPTS)

.PHONY: pythoninfo
pythoninfo: all
		$(RUNSHARED) $(HOSTRUNNER) ./$(BUILDPYTHON) -m test.pythoninfo

QUICKTESTOPTS=	-x test_subprocess test_io \
		test_multibytecodec test_urllib2_localnet test_itertools \
		test_multiprocessing_fork test_multiprocessing_spawn \
		test_multiprocessing_forkserver \
		test_mailbox test_socket test_poll \
		test_select test_zipfile test_concurrent_futures

.PHONY: quicktest
quicktest: all
	$(TESTRUNNER) --fast-ci --timeout=$(TESTTIMEOUT) $(TESTOPTS) $(QUICKTESTOPTS)

# SSL tests
.PHONY: multisslcompile
multisslcompile: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/ssl/multissltests.py --steps=modules

.PHONY: multissltest
multissltest: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/ssl/multissltests.py

# All install targets use the "all" target as synchronization point to
# prevent race conditions with PGO builds. PGO builds use recursive make,
# which can lead to two parallel `./python setup.py build` processes that
# step on each others toes.
.PHONY: install
install:  commoninstall bininstall maninstall 
	if test "x$(ENSUREPIP)" != "xno"  ; then \
		case $(ENSUREPIP) in \
			upgrade) ensurepip="--upgrade" ;; \
			install|*) ensurepip="" ;; \
		esac; \
		$(RUNSHARED) $(PYTHON_FOR_BUILD) -m ensurepip \
			$$ensurepip --root=$(DESTDIR)/ ; \
	fi

.PHONY: altinstall
altinstall: commoninstall
	if test "x$(ENSUREPIP)" != "xno"  ; then \
		case $(ENSUREPIP) in \
			upgrade) ensurepip="--altinstall --upgrade" ;; \
			install|*) ensurepip="--altinstall" ;; \
		esac; \
		$(RUNSHARED) $(PYTHON_FOR_BUILD) -m ensurepip \
			$$ensurepip --root=$(DESTDIR)/ ; \
	fi

.PHONY: commoninstall
commoninstall:  check-clean-src  \
		altbininstall libinstall inclinstall libainstall \
		sharedinstall altmaninstall 

# Install shared libraries enabled by Setup
DESTDIRS=	$(exec_prefix) $(LIBDIR) $(BINLIBDEST) $(DESTSHARED)

.PHONY: sharedinstall
sharedinstall: all
		@for i in $(DESTDIRS); \
		do \
			if test ! -d $(DESTDIR)$$i; then \
				echo "Creating directory $$i"; \
				$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
			else    true; \
			fi; \
		done
		@for i in X $(SHAREDMODS); do \
		  if test $$i != X; then \
		    echo $(INSTALL_SHARED) $$i $(DESTSHARED)/`basename $$i`; \
		    $(INSTALL_SHARED) $$i $(DESTDIR)$(DESTSHARED)/`basename $$i`; \
			if test -d "$$i.dSYM"; then \
				echo $(DSYMUTIL_PATH) $(DESTDIR)$(DESTSHARED)/`basename $$i`; \
				$(DSYMUTIL_PATH) $(DESTDIR)$(DESTSHARED)/`basename $$i`; \
			fi; \
		  fi; \
		done

# Install the interpreter with $(VERSION) affixed
# This goes into $(exec_prefix)
.PHONY: altbininstall
altbininstall: $(BUILDPYTHON) 
	@for i in $(BINDIR) $(LIBDIR); \
	do \
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	if test "$(PYTHONFRAMEWORKDIR)" = "no-framework" ; then \
		$(INSTALL_PROGRAM) $(BUILDPYTHON) $(DESTDIR)$(BINDIR)/python$(LDVERSION)$(EXE); \
	else \
		$(INSTALL_PROGRAM) $(STRIPFLAG) Mac/pythonw $(DESTDIR)$(BINDIR)/python$(LDVERSION)$(EXE); \
	fi
	-if test "$(VERSION)" != "$(LDVERSION)"; then \
		if test -f $(DESTDIR)$(BINDIR)/python$(VERSION)$(EXE) -o -h $(DESTDIR)$(BINDIR)/python$(VERSION)$(EXE); \
		then rm -f $(DESTDIR)$(BINDIR)/python$(VERSION)$(EXE); \
		fi; \
		(cd $(DESTDIR)$(BINDIR); $(LN) python$(LDVERSION)$(EXE) python$(VERSION)$(EXE)); \
	fi
	@if test "$(PY_ENABLE_SHARED)" = 1 -o "$(STATIC_LIBPYTHON)" = 1; then \
		if test -f $(LDLIBRARY) && test "$(PYTHONFRAMEWORKDIR)" = "no-framework" ; then \
			if test -n "$(DLLLIBRARY)" ; then \
				$(INSTALL_SHARED) $(DLLLIBRARY) $(DESTDIR)$(BINDIR); \
			else \
				$(INSTALL_SHARED) $(LDLIBRARY) $(DESTDIR)$(LIBDIR)/$(INSTSONAME); \
				if test $(LDLIBRARY) != $(INSTSONAME); then \
					(cd $(DESTDIR)$(LIBDIR); $(LN) -sf $(INSTSONAME) $(LDLIBRARY)) \
				fi \
			fi; \
			if test -n "$(PY3LIBRARY)"; then \
				$(INSTALL_SHARED) $(PY3LIBRARY) $(DESTDIR)$(LIBDIR)/$(PY3LIBRARY); \
			fi; \
		else	true; \
		fi; \
	fi
	if test "x$(LIPO_32BIT_FLAGS)" != "x" ; then \
		rm -f $(DESTDIR)$(BINDIR)/python$(VERSION)-32$(EXE); \
		lipo $(LIPO_32BIT_FLAGS) \
			-output $(DESTDIR)$(BINDIR)/python$(VERSION)-32$(EXE) \
			$(DESTDIR)$(BINDIR)/python$(VERSION)$(EXE); \
	fi
	if test "x$(LIPO_INTEL64_FLAGS)" != "x" ; then \
		rm -f $(DESTDIR)$(BINDIR)/python$(VERSION)-intel64$(EXE); \
		lipo $(LIPO_INTEL64_FLAGS) \
			-output $(DESTDIR)$(BINDIR)/python$(VERSION)-intel64$(EXE) \
			$(DESTDIR)$(BINDIR)/python$(VERSION)$(EXE); \
	fi
	# Install macOS debug information (if available)
	if test -d "$(BUILDPYTHON).dSYM"; then \
		echo $(DSYMUTIL_PATH) $(DESTDIR)$(BINDIR)/python$(LDVERSION)$(EXE); \
		$(DSYMUTIL_PATH) $(DESTDIR)$(BINDIR)/python$(LDVERSION)$(EXE); \
	fi
	if test "$(PYTHONFRAMEWORKDIR)" = "no-framework" ; then \
		if test -d "$(LDLIBRARY).dSYM"; then \
			echo $(DSYMUTIL_PATH) $(DESTDIR)$(LIBDIR)/$(INSTSONAME); \
			$(DSYMUTIL_PATH) $(DESTDIR)$(LIBDIR)/$(INSTSONAME); \
		fi \
	else \
		if test -d "$(LDLIBRARY).dSYM"; then \
			echo $(DSYMUTIL_PATH) $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/$(INSTSONAME); \
      $(DSYMUTIL_PATH) $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/$(INSTSONAME); \
		fi \
	fi

.PHONY: bininstall
# We depend on commoninstall here to make sure the installation is already usable
# before we possibly overwrite the global 'python3' symlink to avoid causing
# problems for anything else trying to run 'python3' while we install, particularly
# if we're installing in parallel with -j.
bininstall: commoninstall altbininstall
	if test ! -d $(DESTDIR)$(LIBPC); then \
		echo "Creating directory $(LIBPC)"; \
		$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(LIBPC); \
	fi
	-if test -f $(DESTDIR)$(BINDIR)/python3$(EXE) -o -h $(DESTDIR)$(BINDIR)/python3$(EXE); \
	then rm -f $(DESTDIR)$(BINDIR)/python3$(EXE); \
	else true; \
	fi
	(cd $(DESTDIR)$(BINDIR); $(LN) -s python$(VERSION)$(EXE) python3$(EXE))
	-if test "$(VERSION)" != "$(LDVERSION)"; then \
		rm -f $(DESTDIR)$(BINDIR)/python$(VERSION)-config; \
		(cd $(DESTDIR)$(BINDIR); $(LN) -s python$(LDVERSION)-config python$(VERSION)-config); \
		rm -f $(DESTDIR)$(LIBPC)/python-$(VERSION).pc; \
		(cd $(DESTDIR)$(LIBPC); $(LN) -s python-$(LDVERSION).pc python-$(VERSION).pc); \
		rm -f $(DESTDIR)$(LIBPC)/python-$(VERSION)-embed.pc; \
		(cd $(DESTDIR)$(LIBPC); $(LN) -s python-$(LDVERSION)-embed.pc python-$(VERSION)-embed.pc); \
	fi
	-rm -f $(DESTDIR)$(BINDIR)/python3-config
	(cd $(DESTDIR)$(BINDIR); $(LN) -s python$(VERSION)-config python3-config)
	-rm -f $(DESTDIR)$(LIBPC)/python3.pc
	(cd $(DESTDIR)$(LIBPC); $(LN) -s python-$(VERSION).pc python3.pc)
	-rm -f $(DESTDIR)$(LIBPC)/python3-embed.pc
	(cd $(DESTDIR)$(LIBPC); $(LN) -s python-$(VERSION)-embed.pc python3-embed.pc)
	-rm -f $(DESTDIR)$(BINDIR)/idle3
	(cd $(DESTDIR)$(BINDIR); $(LN) -s idle$(VERSION) idle3)
	-rm -f $(DESTDIR)$(BINDIR)/pydoc3
	(cd $(DESTDIR)$(BINDIR); $(LN) -s pydoc$(VERSION) pydoc3)
	if test "x$(LIPO_32BIT_FLAGS)" != "x" ; then \
		rm -f $(DESTDIR)$(BINDIR)/python3-32$(EXE); \
		(cd $(DESTDIR)$(BINDIR); $(LN) -s python$(VERSION)-32$(EXE) python3-32$(EXE)) \
	fi
	if test "x$(LIPO_INTEL64_FLAGS)" != "x" ; then \
		rm -f $(DESTDIR)$(BINDIR)/python3-intel64$(EXE); \
		(cd $(DESTDIR)$(BINDIR); $(LN) -s python$(VERSION)-intel64$(EXE) python3-intel64$(EXE)) \
	fi

# Install the versioned manual page
.PHONY: altmaninstall
altmaninstall:
	@for i in $(MANDIR) $(MANDIR)/man1; \
	do \
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	$(INSTALL_DATA) $(srcdir)/Misc/python.man \
		$(DESTDIR)$(MANDIR)/man1/python$(VERSION).1

# Install the unversioned manual page
.PHONY: maninstall
maninstall:	altmaninstall
	-rm -f $(DESTDIR)$(MANDIR)/man1/python3.1
	(cd $(DESTDIR)$(MANDIR)/man1; $(LN) -s python$(VERSION).1 python3.1)

# Install the library
XMLLIBSUBDIRS=  xml xml/dom xml/etree xml/parsers xml/sax
LIBSUBDIRS=	asyncio \
		collections \
		compression compression/_common compression/zstd \
		concurrent concurrent/futures concurrent/interpreters \
		csv \
		ctypes ctypes/macholib \
		curses \
		dbm \
		email email/mime \
		encodings \
		ensurepip ensurepip/_bundled \
		html \
		http \
		idlelib idlelib/Icons \
		importlib importlib/resources importlib/metadata \
		json \
		logging \
		multiprocessing multiprocessing/dummy \
		pathlib \
		pydoc_data \
		re \
		site-packages \
		sqlite3 \
		string \
		sysconfig \
		tkinter \
		tomllib \
		turtledemo \
		unittest \
		urllib \
		venv venv/scripts venv/scripts/common venv/scripts/posix \
		wsgiref \
		$(XMLLIBSUBDIRS) \
		xmlrpc \
		zipfile zipfile/_path \
		zoneinfo \
		_pyrepl \
		__phello__
TESTSUBDIRS=	idlelib/idle_test \
		test \
		test/test_ast \
		test/test_ast/data \
		test/archivetestdata \
		test/audiodata \
		test/certdata \
		test/certdata/capath \
		test/cjkencodings \
		test/configdata \
		test/crashers \
		test/data \
		test/decimaltestdata \
		test/dtracedata \
		test/encoded_modules \
		test/leakers \
		test/libregrtest \
		test/mathdata \
		test/regrtestdata \
		test/regrtestdata/import_from_tests \
		test/regrtestdata/import_from_tests/test_regrtest_b \
		test/subprocessdata \
		test/support \
		test/support/_hypothesis_stubs \
		test/test_asyncio \
		test/test_capi \
		test/test_cext \
		test/test_concurrent_futures \
		test/test_cppext \
		test/test_ctypes \
		test/test_dataclasses \
		test/test_doctest \
		test/test_email \
		test/test_email/data \
		test/test_free_threading \
		test/test_future_stmt \
		test/test_gdb \
		test/test_import \
		test/test_import/data \
		test/test_import/data/circular_imports \
		test/test_import/data/circular_imports/subpkg \
		test/test_import/data/circular_imports/subpkg2 \
		test/test_import/data/circular_imports/subpkg2/parent \
		test/test_import/data/package \
		test/test_import/data/package2 \
		test/test_import/data/package3 \
		test/test_import/data/package4 \
		test/test_import/data/unwritable \
		test/test_importlib \
		test/test_importlib/builtin \
		test/test_importlib/extension \
		test/test_importlib/frozen \
		test/test_importlib/import_ \
		test/test_importlib/metadata \
		test/test_importlib/metadata/data \
		test/test_importlib/metadata/data/sources \
		test/test_importlib/metadata/data/sources/example \
		test/test_importlib/metadata/data/sources/example/example \
		test/test_importlib/metadata/data/sources/example2 \
		test/test_importlib/metadata/data/sources/example2/example2 \
		test/test_importlib/namespace_pkgs \
		test/test_importlib/namespace_pkgs/both_portions \
		test/test_importlib/namespace_pkgs/both_portions/foo \
		test/test_importlib/namespace_pkgs/module_and_namespace_package \
		test/test_importlib/namespace_pkgs/module_and_namespace_package/a_test \
		test/test_importlib/namespace_pkgs/not_a_namespace_pkg \
		test/test_importlib/namespace_pkgs/not_a_namespace_pkg/foo \
		test/test_importlib/namespace_pkgs/portion1 \
		test/test_importlib/namespace_pkgs/portion1/foo \
		test/test_importlib/namespace_pkgs/portion2 \
		test/test_importlib/namespace_pkgs/portion2/foo \
		test/test_importlib/namespace_pkgs/project1 \
		test/test_importlib/namespace_pkgs/project1/parent \
		test/test_importlib/namespace_pkgs/project1/parent/child \
		test/test_importlib/namespace_pkgs/project2 \
		test/test_importlib/namespace_pkgs/project2/parent \
		test/test_importlib/namespace_pkgs/project2/parent/child \
		test/test_importlib/namespace_pkgs/project3 \
		test/test_importlib/namespace_pkgs/project3/parent \
		test/test_importlib/namespace_pkgs/project3/parent/child \
		test/test_importlib/partial \
		test/test_importlib/resources \
		test/test_importlib/source \
		test/test_inspect \
		test/test_interpreters \
		test/test_json \
		test/test_module \
		test/test_multiprocessing_fork \
		test/test_multiprocessing_forkserver \
		test/test_multiprocessing_spawn \
		test/test_pathlib \
		test/test_pathlib/support \
		test/test_peg_generator \
		test/test_pydoc \
		test/test_pyrepl \
		test/test_string \
		test/test_sqlite3 \
		test/test_tkinter \
		test/test_tomllib \
		test/test_tomllib/data \
		test/test_tomllib/data/invalid \
		test/test_tomllib/data/invalid/array \
		test/test_tomllib/data/invalid/array-of-tables \
		test/test_tomllib/data/invalid/boolean \
		test/test_tomllib/data/invalid/dates-and-times \
		test/test_tomllib/data/invalid/dotted-keys \
		test/test_tomllib/data/invalid/inline-table \
		test/test_tomllib/data/invalid/keys-and-vals \
		test/test_tomllib/data/invalid/literal-str \
		test/test_tomllib/data/invalid/multiline-basic-str \
		test/test_tomllib/data/invalid/multiline-literal-str \
		test/test_tomllib/data/invalid/table \
		test/test_tomllib/data/valid \
		test/test_tomllib/data/valid/array \
		test/test_tomllib/data/valid/dates-and-times \
		test/test_tomllib/data/valid/multiline-basic-str \
		test/test_tools \
		test/test_tools/i18n_data \
		test/test_tools/msgfmt_data \
		test/test_ttk \
		test/test_unittest \
		test/test_unittest/namespace_test_pkg \
		test/test_unittest/namespace_test_pkg/bar \
		test/test_unittest/namespace_test_pkg/noop \
		test/test_unittest/namespace_test_pkg/noop/no2 \
		test/test_unittest/testmock \
		test/test_warnings \
		test/test_warnings/data \
		test/test_zipfile \
		test/test_zipfile/_path \
		test/test_zoneinfo \
		test/test_zoneinfo/data \
		test/tkinterdata \
		test/tokenizedata \
		test/tracedmodules \
		test/translationdata \
		test/translationdata/argparse \
		test/translationdata/getopt \
		test/translationdata/optparse \
		test/typinganndata \
		test/typinganndata/partialexecution \
		test/wheeldata \
		test/xmltestdata \
		test/xmltestdata/c14n-20 \
		test/zipimport_data

COMPILEALL_OPTS=-j0

TEST_MODULES=no

.PHONY: libinstall
libinstall:	all $(srcdir)/Modules/xxmodule.c
	@for i in $(SCRIPTDIR) $(LIBDEST); \
	do \
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	@if test "$(TEST_MODULES)" = yes; then \
		subdirs="$(LIBSUBDIRS) $(TESTSUBDIRS)"; \
	else \
		subdirs="$(LIBSUBDIRS)"; \
	fi; \
	for d in $$subdirs; \
	do \
		a=$(srcdir)/Lib/$$d; \
		if test ! -d $$a; then continue; else true; fi; \
		b=$(LIBDEST)/$$d; \
		if test ! -d $(DESTDIR)$$b; then \
			echo "Creating directory $$b"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$b; \
		else	true; \
		fi; \
	done
	@for i in $(srcdir)/Lib/*.py; \
	do \
		if test -x $$i; then \
			$(INSTALL_SCRIPT) $$i $(DESTDIR)$(LIBDEST); \
			echo $(INSTALL_SCRIPT) $$i $(LIBDEST); \
		else \
			$(INSTALL_DATA) $$i $(DESTDIR)$(LIBDEST); \
			echo $(INSTALL_DATA) $$i $(LIBDEST); \
		fi; \
	done
	@if test "$(TEST_MODULES)" = yes; then \
		subdirs="$(LIBSUBDIRS) $(TESTSUBDIRS)"; \
	else \
		subdirs="$(LIBSUBDIRS)"; \
	fi; \
	for d in $$subdirs; \
	do \
		a=$(srcdir)/Lib/$$d; \
		if test ! -d $$a; then continue; else true; fi; \
		if test `ls $$a | wc -l` -lt 1; then continue; fi; \
		b=$(LIBDEST)/$$d; \
		for i in $$a/*; \
		do \
			case $$i in \
			*CVS) ;; \
			*.py[co]) ;; \
			*.orig) ;; \
			*~) ;; \
			*) \
				if test -d $$i; then continue; fi; \
				if test -x $$i; then \
				    echo $(INSTALL_SCRIPT) $$i $$b; \
				    $(INSTALL_SCRIPT) $$i $(DESTDIR)$$b; \
				else \
				    echo $(INSTALL_DATA) $$i $$b; \
				    $(INSTALL_DATA) $$i $(DESTDIR)$$b; \
				fi;; \
			esac; \
		done; \
	done
	$(INSTALL_DATA) `cat pybuilddir.txt`/_sysconfigdata_$(ABIFLAGS)_$(MACHDEP)_$(MULTIARCH).py $(DESTDIR)$(LIBDEST); \
	$(INSTALL_DATA) `cat pybuilddir.txt`/_sysconfig_vars_$(ABIFLAGS)_$(MACHDEP)_$(MULTIARCH).json $(DESTDIR)$(LIBDEST); \
	$(INSTALL_DATA) `cat pybuilddir.txt`/build-details.json $(DESTDIR)$(LIBDEST); \
	$(INSTALL_DATA) $(srcdir)/LICENSE $(DESTDIR)$(LIBDEST)/LICENSE.txt
	@ # If app store compliance has been configured, apply the patch to the
	@ # installed library code. The patch has been previously validated against
	@ # the original source tree, so we can ignore any errors that are raised
	@ # due to files that are missing because of --disable-test-modules etc.
	@if [ "$(APP_STORE_COMPLIANCE_PATCH)" != "" ]; then \
		echo "Applying app store compliance patch"; \
		patch --force --reject-file "$(abs_builddir)/app-store-compliance.rej" --strip 2 --directory "$(DESTDIR)$(LIBDEST)" --input "$(abs_srcdir)/$(APP_STORE_COMPLIANCE_PATCH)" || true ; \
	fi
	@ # Build PYC files for the 3 optimization levels (0, 1, 2)
	-PYTHONPATH=$(DESTDIR)$(LIBDEST) $(RUNSHARED) \
		$(PYTHON_FOR_BUILD) -Wi $(DESTDIR)$(LIBDEST)/compileall.py \
		-o 0 -o 1 -o 2 $(COMPILEALL_OPTS) -d $(LIBDEST) -f \
		-x 'bad_coding|badsyntax|site-packages' \
		$(DESTDIR)$(LIBDEST)
	-PYTHONPATH=$(DESTDIR)$(LIBDEST) $(RUNSHARED) \
		$(PYTHON_FOR_BUILD) -Wi $(DESTDIR)$(LIBDEST)/compileall.py \
		-o 0 -o 1 -o 2 $(COMPILEALL_OPTS) -d $(LIBDEST)/site-packages -f \
		-x badsyntax $(DESTDIR)$(LIBDEST)/site-packages

# bpo-21536: Misc/python-config.sh is generated in the build directory
# from $(srcdir)Misc/python-config.sh.in.
python-config: $(srcdir)/Misc/python-config.in Misc/python-config.sh
	@ # Substitution happens here, as the completely-expanded BINDIR
	@ # is not available in configure
	sed -e "s,@EXENAME@,$(EXENAME)," < $(srcdir)/Misc/python-config.in >python-config.py
	@ # Replace makefile compat. variable references with shell script compat. ones; $(VAR) -> ${VAR}
	LC_ALL=C sed -e 's,\$$(\([A-Za-z0-9_]*\)),\$$\{\1\},g' < Misc/python-config.sh >python-config
	@ # On Darwin, always use the python version of the script, the shell
	@ # version doesn't use the compiler customizations that are provided
	@ # in python (_osx_support.py).
	@if test `uname -s` = Darwin; then \
		cp python-config.py python-config; \
	fi

# macOS' make seems to ignore a dependency on a
# "$(BUILD_SCRIPTS_DIR): $(MKDIR_P) $@" rule.
BUILD_SCRIPTS_DIR=build/scripts-$(VERSION)
SCRIPT_IDLE=$(BUILD_SCRIPTS_DIR)/idle$(VERSION)
SCRIPT_PYDOC=$(BUILD_SCRIPTS_DIR)/pydoc$(VERSION)

$(SCRIPT_IDLE): $(srcdir)/Tools/scripts/idle3
	@$(MKDIR_P) $(BUILD_SCRIPTS_DIR)
	sed -e "s,/usr/bin/env python3,$(EXENAME)," < $(srcdir)/Tools/scripts/idle3 > $@
	@chmod +x $@

$(SCRIPT_PYDOC): $(srcdir)/Tools/scripts/pydoc3
	@$(MKDIR_P) $(BUILD_SCRIPTS_DIR)
	sed -e "s,/usr/bin/env python3,$(EXENAME)," < $(srcdir)/Tools/scripts/pydoc3 > $@
	@chmod +x $@

.PHONY: scripts
scripts: $(SCRIPT_IDLE) $(SCRIPT_PYDOC) python-config

# Install the include files
INCLDIRSTOMAKE=$(INCLUDEDIR) $(CONFINCLUDEDIR) $(INCLUDEPY) $(CONFINCLUDEPY)

.PHONY: inclinstall
inclinstall:
	@for i in $(INCLDIRSTOMAKE); \
	do \
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	@if test ! -d $(DESTDIR)$(INCLUDEPY)/cpython; then \
		echo "Creating directory $(DESTDIR)$(INCLUDEPY)/cpython"; \
		$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(INCLUDEPY)/cpython; \
	else	true; \
	fi
	@if test ! -d $(DESTDIR)$(INCLUDEPY)/internal; then \
		echo "Creating directory $(DESTDIR)$(INCLUDEPY)/internal"; \
		$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(INCLUDEPY)/internal; \
	else	true; \
	fi
	@if test "$(INSTALL_MIMALLOC)" = "yes"; then \
		if test ! -d $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc; then \
			echo "Creating directory $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc; \
		fi; \
	fi
	@for i in $(srcdir)/Include/*.h; \
	do \
		echo $(INSTALL_DATA) $$i $(INCLUDEPY); \
		$(INSTALL_DATA) $$i $(DESTDIR)$(INCLUDEPY); \
	done
	@for i in $(srcdir)/Include/cpython/*.h; \
	do \
		echo $(INSTALL_DATA) $$i $(INCLUDEPY)/cpython; \
		$(INSTALL_DATA) $$i $(DESTDIR)$(INCLUDEPY)/cpython; \
	done
	@for i in $(srcdir)/Include/internal/*.h; \
	do \
		echo $(INSTALL_DATA) $$i $(INCLUDEPY)/internal; \
		$(INSTALL_DATA) $$i $(DESTDIR)$(INCLUDEPY)/internal; \
	done
	@if test "$(INSTALL_MIMALLOC)" = "yes"; then \
		echo $(INSTALL_DATA) $(srcdir)/Include/internal/mimalloc/mimalloc.h $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc.h; \
		$(INSTALL_DATA) $(srcdir)/Include/internal/mimalloc/mimalloc.h $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc.h; \
		for i in $(srcdir)/Include/internal/mimalloc/mimalloc/*.h; \
		do \
			echo $(INSTALL_DATA) $$i $(INCLUDEPY)/internal/mimalloc/mimalloc; \
			$(INSTALL_DATA) $$i $(DESTDIR)$(INCLUDEPY)/internal/mimalloc/mimalloc; \
		done; \
	fi
	echo $(INSTALL_DATA) pyconfig.h $(DESTDIR)$(CONFINCLUDEPY)/pyconfig.h
	$(INSTALL_DATA) pyconfig.h $(DESTDIR)$(CONFINCLUDEPY)/pyconfig.h

# Install the library and miscellaneous stuff needed for extending/embedding
# This goes into $(exec_prefix)
LIBPL=		$(prefix)/lib/python3.14/config-$(VERSION)$(ABIFLAGS)-darwin

# pkgconfig directory
LIBPC=		$(LIBDIR)/pkgconfig

.PHONY: libainstall
libainstall: all scripts
	@for i in $(LIBDIR) $(LIBPL) $(LIBPC) $(BINDIR); \
	do \
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	@if test "$(STATIC_LIBPYTHON)" = 1; then \
		if test -d $(LIBRARY); then :; else \
			if test "$(PYTHONFRAMEWORKDIR)" = no-framework; then \
				if test "$(SHLIB_SUFFIX)" = .dll; then \
					$(INSTALL_DATA) $(LDLIBRARY) $(DESTDIR)$(LIBPL) ; \
				else \
					$(INSTALL_DATA) $(LIBRARY) $(DESTDIR)$(LIBPL)/$(LIBRARY) ; \
				fi; \
			else \
				echo Skip install of $(LIBRARY) - use make frameworkinstall; \
			fi; \
		fi; \
		$(INSTALL_DATA) Programs/python.o $(DESTDIR)$(LIBPL)/python.o; \
	fi
	$(INSTALL_DATA) Modules/config.c $(DESTDIR)$(LIBPL)/config.c
	$(INSTALL_DATA) $(srcdir)/Modules/config.c.in $(DESTDIR)$(LIBPL)/config.c.in
	$(INSTALL_DATA) Makefile $(DESTDIR)$(LIBPL)/Makefile
	$(INSTALL_DATA) $(srcdir)/Modules/Setup $(DESTDIR)$(LIBPL)/Setup
	$(INSTALL_DATA) Modules/Setup.bootstrap $(DESTDIR)$(LIBPL)/Setup.bootstrap
	$(INSTALL_DATA) Modules/Setup.stdlib $(DESTDIR)$(LIBPL)/Setup.stdlib
	$(INSTALL_DATA) Modules/Setup.local $(DESTDIR)$(LIBPL)/Setup.local
	$(INSTALL_DATA) Misc/python.pc $(DESTDIR)$(LIBPC)/python-$(LDVERSION).pc
	$(INSTALL_DATA) Misc/python-embed.pc $(DESTDIR)$(LIBPC)/python-$(LDVERSION)-embed.pc
	$(INSTALL_SCRIPT) $(srcdir)/Modules/makesetup $(DESTDIR)$(LIBPL)/makesetup
	$(INSTALL_SCRIPT) $(srcdir)/install-sh $(DESTDIR)$(LIBPL)/install-sh
	$(INSTALL_SCRIPT) python-config.py $(DESTDIR)$(LIBPL)/python-config.py
	$(INSTALL_SCRIPT) python-config $(DESTDIR)$(BINDIR)/python$(LDVERSION)-config
	$(INSTALL_SCRIPT) $(SCRIPT_IDLE) $(DESTDIR)$(BINDIR)/idle$(VERSION)
	$(INSTALL_SCRIPT) $(SCRIPT_PYDOC) $(DESTDIR)$(BINDIR)/pydoc$(VERSION)
	@if [ -s Modules/python.exp -a \
		"`echo $(MACHDEP) | sed 's/^\(...\).*/\1/'`" = "aix" ]; then \
		echo; echo "Installing support files for building shared extension modules on AIX:"; \
		$(INSTALL_DATA) Modules/python.exp		\
				$(DESTDIR)$(LIBPL)/python.exp;		\
		echo; echo "$(LIBPL)/python.exp";		\
		$(INSTALL_SCRIPT) $(srcdir)/Modules/makexp_aix	\
				$(DESTDIR)$(LIBPL)/makexp_aix;		\
		echo "$(LIBPL)/makexp_aix";			\
		$(INSTALL_SCRIPT) Modules/ld_so_aix	\
				$(DESTDIR)$(LIBPL)/ld_so_aix;		\
		echo "$(LIBPL)/ld_so_aix";			\
		echo; echo "See Misc/README.AIX for details.";	\
	else true; \
	fi

# Here are a couple of targets for MacOSX again, to install a full
# framework-based Python. frameworkinstall installs everything, the
# subtargets install specific parts. Much of the actual work is offloaded to
# the Makefile in Mac
#
#
# This target is here for backward compatibility, previous versions of Python
# hadn't integrated framework installation in the normal install process.
.PHONY: frameworkinstall
frameworkinstall: install

# On install, we re-make the framework
# structure in the install location, /Library/Frameworks/ or the argument to
# --enable-framework. If --enable-framework has been specified then we have
# automatically set prefix to the location deep down in the framework, so we
# only have to cater for the structural bits of the framework.

.PHONY: frameworkinstallframework
frameworkinstallframework:  install frameworkinstallmaclib

# macOS uses a versioned frameworks structure that includes a full install
.PHONY: frameworkinstallversionedstructure
frameworkinstallversionedstructure:	$(LDLIBRARY)
	@if test "$(PYTHONFRAMEWORKDIR)" = no-framework; then \
		echo Not configured with --enable-framework; \
		exit 1; \
	else true; \
	fi
	@for i in $(prefix)/Resources/English.lproj $(prefix)/lib; do\
		if test ! -d $(DESTDIR)$$i; then \
			echo "Creating directory $(DESTDIR)$$i"; \
			$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$$i; \
		else	true; \
		fi; \
	done
	$(LN) -fsn include/python$(LDVERSION) $(DESTDIR)$(prefix)/Headers
	sed 's/%VERSION%/'"`$(RUNSHARED) ./$(BUILDPYTHON) -c 'import platform; print(platform.python_version())'`"'/g' < $(RESSRCDIR)/Info.plist > $(DESTDIR)$(prefix)/Resources/Info.plist
	$(LN) -fsn $(VERSION) $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Versions/Current
	$(LN) -fsn Versions/Current/$(PYTHONFRAMEWORK) $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/$(PYTHONFRAMEWORK)
	$(LN) -fsn Versions/Current/Headers $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Headers
	$(LN) -fsn Versions/Current/Resources $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Resources
	$(INSTALL_SHARED) $(LDLIBRARY) $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/$(LDLIBRARY)

# iOS/tvOS/watchOS uses a non-versioned framework with Info.plist in the
# framework root, no .lproj data, and only stub compilation assistance binaries
.PHONY: frameworkinstallunversionedstructure
frameworkinstallunversionedstructure:	$(LDLIBRARY)
	@if test "$(PYTHONFRAMEWORKDIR)" = no-framework; then \
		echo Not configured with --enable-framework; \
		exit 1; \
	else true; \
	fi
	if test -d $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/include; then \
		echo "Clearing stale header symlink directory"; \
		rm -rf $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/include; \
	fi
	$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)
	sed 's/%VERSION%/'"`$(RUNSHARED) $(PYTHON_FOR_BUILD) -c 'import platform; print(platform.python_version())'`"'/g' < $(RESSRCDIR)/Info.plist > $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Info.plist
	$(INSTALL_SHARED) $(LDLIBRARY) $(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/$(LDLIBRARY)
	$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(LIBDIR)
	$(LN) -fs "../$(LDLIBRARY)" "$(DESTDIR)$(prefix)/lib/libpython$(LDVERSION).dylib"
	$(LN) -fs "../$(LDLIBRARY)" "$(DESTDIR)$(prefix)/lib/libpython$(VERSION).dylib"
	$(INSTALL) -d -m $(DIRMODE) $(DESTDIR)$(BINDIR)
	for file in $(srcdir)/$(RESSRCDIR)/bin/* ; do \
		$(INSTALL) -m $(EXEMODE) $$file $(DESTDIR)$(BINDIR); \
	done

# This installs Mac/Lib into the framework
# Install a number of symlinks to keep software that expects a normal unix
# install (which includes python-config) happy.
.PHONY: frameworkinstallmaclib
frameworkinstallmaclib:
	$(LN) -fs "../../../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(LIBPL)/libpython$(LDVERSION).a"
	$(LN) -fs "../../../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(LIBPL)/libpython$(LDVERSION).dylib"
	$(LN) -fs "../../../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(LIBPL)/libpython$(VERSION).a"
	$(LN) -fs "../../../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(LIBPL)/libpython$(VERSION).dylib"
	$(LN) -fs "../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(prefix)/lib/libpython$(LDVERSION).dylib"
	$(LN) -fs "../$(PYTHONFRAMEWORK)" "$(DESTDIR)$(prefix)/lib/libpython$(VERSION).dylib"

# This installs the IDE, the Launcher and other apps into /Applications
.PHONY: frameworkinstallapps
frameworkinstallapps:
	cd Mac && $(MAKE) installapps DESTDIR="$(DESTDIR)"

# Build the bootstrap executable that will spawn the interpreter inside
# an app bundle within the framework.  This allows the interpreter to
# run OS X GUI APIs.
.PHONY: frameworkpythonw
frameworkpythonw:
	cd Mac && $(MAKE) pythonw

# This installs the python* and other bin symlinks in $prefix/bin or in
# a bin directory relative to the framework root
.PHONY: frameworkinstallunixtools
frameworkinstallunixtools:
	cd Mac && $(MAKE) installunixtools DESTDIR="$(DESTDIR)"

.PHONY: frameworkaltinstallunixtools
frameworkaltinstallunixtools:
	cd Mac && $(MAKE) altinstallunixtools DESTDIR="$(DESTDIR)"

# This installs the Tools into the applications directory.
# It is not part of a normal frameworkinstall
.PHONY: frameworkinstallextras
frameworkinstallextras:
	cd Mac && $(MAKE) installextras DESTDIR="$(DESTDIR)"

# On iOS, bin/lib can't live inside the framework; include needs to be called
# "Headers", but *must* be in the framework, and *not* include the `python3.X`
# subdirectory. The install has put these folders in the same folder as
# Python.framework; Move the headers to their final framework-compatible home.
.PHONY: frameworkinstallmobileheaders
frameworkinstallmobileheaders: frameworkinstallunversionedstructure inclinstall
	if test -d $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Headers; then \
		echo "Removing old framework headers"; \
		rm -rf $(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Headers; \
	fi
	mv "$(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/include/python$(LDVERSION)" "$(DESTDIR)$(PYTHONFRAMEWORKINSTALLDIR)/Headers"
	$(LN) -fs "../$(PYTHONFRAMEWORKDIR)/Headers" "$(DESTDIR)$(PYTHONFRAMEWORKPREFIX)/include/python$(LDVERSION)"

# Build the toplevel Makefile
Makefile.pre: $(srcdir)/Makefile.pre.in config.status
	CONFIG_FILES=Makefile.pre CONFIG_HEADERS= ./config.status
	$(MAKE) -f Makefile.pre Makefile

# Run the configure script.
config.status:	$(srcdir)/configure
	$(srcdir)/configure $(CONFIG_ARGS)

.PRECIOUS: config.status $(BUILDPYTHON) Makefile Makefile.pre

Python/asm_trampoline.o: $(srcdir)/Python/asm_trampoline.S
	$(CC) -c $(PY_CORE_CFLAGS) -o $@ $<

Python/emscripten_trampoline_inner.wasm: $(srcdir)/Python/emscripten_trampoline_inner.c
	# emcc has a path that ends with emsdk/upstream/emscripten/emcc, we're looking for emsdk/upstream/bin/clang.
	$$(em-config LLVM_ROOT)/clang -o $@ $< -mgc -O2 -Wl,--no-entry -Wl,--import-table -Wl,--import-memory -target wasm32-unknown-unknown -nostdlib

Python/emscripten_trampoline_wasm.c: Python/emscripten_trampoline_inner.wasm
	$(PYTHON_FOR_REGEN) $(srcdir)/Platforms/emscripten/prepare_external_wasm.py $< $@ getWasmTrampolineModule

JIT_DEPS = \
		$(srcdir)/Tools/jit/*.c \
		$(srcdir)/Tools/jit/*.py \
		$(srcdir)/Python/executor_cases.c.h \
		pyconfig.h

jit_stencils.h: $(JIT_DEPS)
	

Python/jit.o: $(srcdir)/Python/jit.c 
	$(CC) -c $(PY_CORE_CFLAGS) -o $@ $<

.PHONY: regen-jit
regen-jit:
	

# Some make's put the object file in the current directory
.c.o:
	$(CC) -c $(PY_CORE_CFLAGS) -o $@ $<

# bpo-30104: dtoa.c uses union to cast double to unsigned long[2]. clang 4.0
# with -O2 or higher and strict aliasing miscompiles the ratio() function
# causing rounding issues. Compile dtoa.c using -fno-strict-aliasing on clang.
# https://bugs.llvm.org//show_bug.cgi?id=31928
Python/dtoa.o: Python/dtoa.c
	$(CC) -c $(PY_CORE_CFLAGS) $(CFLAGS_ALIASING) -o $@ $<

Python/ceval.o: Python/ceval.c
	$(CC) -c $(PY_CORE_CFLAGS) $(CFLAGS_CEVAL) -o $@ $<

# Run reindent on the library
.PHONY: reindent
reindent:
	./$(BUILDPYTHON) $(srcdir)/Tools/patchcheck/reindent.py -r $(srcdir)/Lib

# Rerun configure with the same options as it was run last time,
# provided the config.status script exists
.PHONY: recheck
recheck:
	./config.status --recheck
	./config.status

# Regenerate configure and pyconfig.h.in
.PHONY: autoconf
autoconf:
	(cd $(srcdir); autoreconf -ivf -Werror)

.PHONY: regen-configure
regen-configure:
	$(srcdir)/Tools/build/regen-configure.sh

.PHONY: regen-sbom
regen-sbom:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/build/generate_sbom.py

# Create a tags file for vi
tags::
	ctags -w $(srcdir)/Include/*.h $(srcdir)/Include/cpython/*.h $(srcdir)/Include/internal/*.h
	for i in $(SRCDIRS); do ctags -f tags -w -a $(srcdir)/$$i/*.[ch]; done
	ctags -f tags -w -a $(srcdir)/Modules/_ctypes/*.[ch]
	find $(srcdir)/Lib -type f -name "*.py" -not -name "test_*.py" -not -path "*/test/*" -not -path "*/tests/*" -not -path "*/*_test/*" | ctags -f tags -w -a -L -
	LC_ALL=C sort -o tags tags

# Create a tags file for GNU Emacs
TAGS::
	cd $(srcdir); \
	etags Include/*.h Include/cpython/*.h Include/internal/*.h; \
	for i in $(SRCDIRS); do etags -a $$i/*.[ch]; done
	etags -a $(srcdir)/Modules/_ctypes/*.[ch]
	find $(srcdir)/Lib -type f -name "*.py" -not -name "test_*.py" -not -path "*/test/*" -not -path "*/tests/*" -not -path "*/*_test/*" | etags - -a

# Sanitation targets -- clean leaves libraries, executables and tags
# files, which clobber removes as well
.PHONY: pycremoval
pycremoval:
	-find $(srcdir) -depth -name '__pycache__' -exec rm -rf {} ';'
	-find $(srcdir) -name '*.py[co]' -exec rm -f {} ';'

.PHONY: rmtestturds
rmtestturds:
	-rm -f *BAD *GOOD *SKIPPED
	-rm -rf OUT
	-rm -f *.TXT
	-rm -f *.txt
	-rm -f gb-18030-2000.xml

.PHONY: docclean
docclean:
	$(MAKE) -C $(srcdir)/Doc clean

# like the 'clean' target but retain the profile guided optimization (PGO)
# data.  The PGO data is only valid if source code remains unchanged.
.PHONY: clean-retain-profile
clean-retain-profile: pycremoval
	find . -name '*.[oa]' -exec rm -f {} ';'
	find . -name '*.s[ol]' -exec rm -f {} ';'
	find . -name '*.so.[0-9]*.[0-9]*' -exec rm -f {} ';'
	find . -name '*.lto' -exec rm -f {} ';'
	find . -name '*.wasm' -exec rm -f {} ';'
	find . -name '*.lst' -exec rm -f {} ';'
	find build -name 'fficonfig.h' -exec rm -f {} ';' || true
	find build -name '*.py' -exec rm -f {} ';' || true
	find build -name '*.py[co]' -exec rm -f {} ';' || true
	-rm -f pybuilddir.txt
	-rm -f _bootstrap_python
	-rm -rf web_example python.mjs python.wasm python*.symbols python*.map
	-rm -f Programs/_testembed Programs/_freeze_module
	-rm -rf Python/deepfreeze
	-rm -f Python/frozen_modules/*.h
	-rm -f Python/frozen_modules/MANIFEST
	-find build -type f -a ! -name '*.gc??' -exec rm -f {} ';'
	-rm -f Include/pydtrace_probes.h
	-rm -f profile-gen-stamp
	-rm -rf Apple/iOS/testbed/Python.xcframework/ios-*/bin
	-rm -rf Apple/iOS/testbed/Python.xcframework/ios-*/lib
	-rm -rf Apple/iOS/testbed/Python.xcframework/ios-*/include
	-rm -rf Apple/iOS/testbed/Python.xcframework/ios-*/Python.framework

.PHONY: profile-removal
profile-removal:
	find . -name '*.gc??' -exec rm -f {} ';'
	find . -name '*.profclang?' -exec rm -f {} ';'
	find . -name '*.dyn' -exec rm -f {} ';'
	rm -f $(COVERAGE_INFO)
	rm -rf $(COVERAGE_REPORT)
	rm -f profile-run-stamp
	rm -f profile-bolt-stamp

.PHONY: clean-profile
clean-profile: clean-retain-profile clean-bolt
	@if test build_all = profile-opt -o build_all = bolt-opt; then \
		rm -f profile-gen-stamp profile-clean-stamp; \
		$(MAKE) profile-removal; \
	fi

# gh-141808: The JIT stencils are deliberately kept in clean-profile
.PHONY: clean-jit-stencils
clean-jit-stencils:
	-rm -f jit_stencils*.h

.PHONY: clean
clean: clean-profile clean-jit-stencils

.PHONY: clobber
clobber: clean
	-rm -f $(BUILDPYTHON) $(LIBRARY) $(LDLIBRARY) $(DLLLIBRARY) \
		tags TAGS \
		config.cache config.log pyconfig.h Modules/config.c
	-rm -rf build platform
	-rm -rf $(PYTHONFRAMEWORKDIR)
	-rm -rf Apple/iOS/Frameworks
	-rm -rf iOSTestbed.*
	-rm -f python-config.py python-config
	-rm -rf cross-build

# Make things extra clean, before making a distribution:
# remove all generated files, even Makefile[.pre]
# Keep configure and Python-ast.[ch], it's possible they can't be generated
.PHONY: distclean
distclean: clobber docclean
	for file in $(srcdir)/Lib/test/data/* ; do \
	    if test "$$file" != "$(srcdir)/Lib/test/data/README"; then rm "$$file"; fi; \
	done
	-rm -f core Makefile Makefile.pre config.status Modules/Setup.local \
	    Modules/Setup.bootstrap Modules/Setup.stdlib \
		Modules/ld_so_aix Modules/python.exp Misc/python.pc \
		Misc/python-embed.pc Misc/python-config.sh
	-rm -f python*-gdb.py
	# Issue #28258: set LC_ALL to avoid issues with Estonian locale.
	# Expansion is performed here by shell (spawned by make) itself before
	# arguments are passed to find. So LC_ALL=C must be set as a separate
	# command.
	LC_ALL=C; find $(srcdir)/[a-zA-Z]* '(' -name '*.fdc' -o -name '*~' \
				     -o -name '[@,#]*' -o -name '*.old' \
				     -o -name '*.orig' -o -name '*.rej' \
				     -o -name '*.bak' ')' \
				     -exec rm -f {} ';'

# Check that all symbols exported by libpython start with "Py" or "_Py"
.PHONY: smelly
smelly: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/build/smelly.py

# Check if any unsupported C global variables have been added.
.PHONY: check-c-globals
check-c-globals:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/c-analyzer/check-c-globals.py \
		--format summary \
		--traceback

# Check for undocumented C APIs.
.PHONY: check-c-api-docs
check-c-api-docs:
	$(PYTHON_FOR_REGEN) $(srcdir)/Tools/check-c-api-docs/main.py

# Find files with funny names
.PHONY: funny
funny:
	find $(SUBDIRS) $(SUBDIRSTOO) \
		-type d \
		-o -name '*.[chs]' \
		-o -name '*.py' \
		-o -name '*.pyw' \
		-o -name '*.dat' \
		-o -name '*.el' \
		-o -name '*.fd' \
		-o -name '*.in' \
		-o -name '*.gif' \
		-o -name '*.txt' \
		-o -name '*.xml' \
		-o -name '*.xbm' \
		-o -name '*.xpm' \
		-o -name '*.uue' \
		-o -name '*.decTest' \
		-o -name '*.tmCommand' \
		-o -name '*.tmSnippet' \
		-o -name 'Setup' \
		-o -name 'Setup.*' \
		-o -name README \
		-o -name NEWS \
		-o -name HISTORY \
		-o -name Makefile \
		-o -name ChangeLog \
		-o -name .hgignore \
		-o -name MANIFEST \
		-o -print

# Perform some verification checks on any modified files.
.PHONY: patchcheck
patchcheck: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/patchcheck/patchcheck.py

.PHONY: check-limited-abi
check-limited-abi: all
	$(RUNSHARED) ./$(BUILDPYTHON) $(srcdir)/Tools/build/stable_abi.py --all

.PHONY: update-config
update-config:
	curl -sL -o config.guess 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
	curl -sL -o config.sub 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
	chmod +x config.guess config.sub

# Dependencies

Python/thread.o:  $(srcdir)/Python/thread_nt.h $(srcdir)/Python/thread_pthread.h $(srcdir)/Python/thread_pthread_stubs.h $(srcdir)/Python/condvar.h

##########################################################################
# Module dependencies and platform-specific files

# force rebuild when header file or module build flavor (static/shared) is changed
MODULE_DEPS_STATIC=Modules/config.c
MODULE_DEPS_SHARED=$(MODULE_DEPS_STATIC) $(EXPORTSYMS)

MODULE__CURSES_DEPS=$(srcdir)/Include/py_curses.h
MODULE__CURSES_PANEL_DEPS=$(srcdir)/Include/py_curses.h
MODULE__DATETIME_DEPS=$(srcdir)/Include/datetime.h
MODULE_CMATH_DEPS=$(srcdir)/Modules/_math.h
MODULE_MATH_DEPS=$(srcdir)/Modules/_math.h
MODULE_PYEXPAT_DEPS=$(LIBEXPAT_HEADERS) $(LIBEXPAT_A)
MODULE_UNICODEDATA_DEPS=$(srcdir)/Modules/unicodedata_db.h $(srcdir)/Modules/unicodename_db.h
MODULE__CTYPES_DEPS=$(srcdir)/Modules/_ctypes/ctypes.h
MODULE__CTYPES_TEST_DEPS=$(srcdir)/Modules/_ctypes/_ctypes_test_generated.c.h
MODULE__CTYPES_MALLOC_CLOSURE=_ctypes/malloc_closure.c
MODULE__DECIMAL_DEPS=$(srcdir)/Modules/_decimal/docstrings.h $(LIBMPDEC_HEADERS) $(LIBMPDEC_A)
MODULE__ELEMENTTREE_DEPS=$(srcdir)/Modules/pyexpat.c $(LIBEXPAT_HEADERS) $(LIBEXPAT_A)
MODULE__HASHLIB_DEPS=$(srcdir)/Modules/hashlib.h
MODULE__IO_DEPS=$(srcdir)/Modules/_io/_iomodule.h

# HACL*-based cryptographic primitives
MODULE__MD5_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_MD5_HEADERS) $(LIBHACL_MD5_LIB_STATIC)
MODULE__MD5_LDEPS=$(LIBHACL_MD5_LIB_STATIC)
MODULE__SHA1_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_SHA1_HEADERS) $(LIBHACL_SHA1_LIB_STATIC)
MODULE__SHA1_LDEPS=$(LIBHACL_SHA1_LIB_STATIC)
MODULE__SHA2_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_SHA2_HEADERS) $(LIBHACL_SHA2_LIB_STATIC)
MODULE__SHA2_LDEPS=$(LIBHACL_SHA2_LIB_STATIC)
MODULE__SHA3_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_SHA3_HEADERS) $(LIBHACL_SHA3_LIB_STATIC)
MODULE__SHA3_LDEPS=$(LIBHACL_SHA3_LIB_STATIC)
MODULE__BLAKE2_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_BLAKE2_HEADERS) $(LIBHACL_BLAKE2_LIB_STATIC)
MODULE__BLAKE2_LDEPS=$(LIBHACL_BLAKE2_LIB_STATIC)
MODULE__HMAC_DEPS=$(srcdir)/Modules/hashlib.h $(LIBHACL_HMAC_HEADERS) $(LIBHACL_HMAC_LIB_STATIC)
MODULE__HMAC_LDEPS=$(LIBHACL_HMAC_LIB_STATIC)

MODULE__SOCKET_DEPS=$(srcdir)/Modules/socketmodule.h $(srcdir)/Modules/addrinfo.h $(srcdir)/Modules/getaddrinfo.c $(srcdir)/Modules/getnameinfo.c
MODULE__SSL_DEPS=$(srcdir)/Modules/_ssl.h $(srcdir)/Modules/_ssl/cert.c $(srcdir)/Modules/_ssl/debughelpers.c $(srcdir)/Modules/_ssl/misc.c $(srcdir)/Modules/_ssl_data_111.h $(srcdir)/Modules/_ssl_data_300.h $(srcdir)/Modules/socketmodule.h
MODULE__TESTCAPI_DEPS=$(srcdir)/Modules/_testcapi/parts.h $(srcdir)/Modules/_testcapi/util.h
MODULE__TESTLIMITEDCAPI_DEPS=$(srcdir)/Modules/_testlimitedcapi/testcapi_long.h $(srcdir)/Modules/_testlimitedcapi/parts.h $(srcdir)/Modules/_testlimitedcapi/util.h
MODULE__TESTINTERNALCAPI_DEPS=$(srcdir)/Modules/_testinternalcapi/parts.h
MODULE__SQLITE3_DEPS=$(srcdir)/Modules/_sqlite/connection.h $(srcdir)/Modules/_sqlite/cursor.h $(srcdir)/Modules/_sqlite/microprotocols.h $(srcdir)/Modules/_sqlite/module.h $(srcdir)/Modules/_sqlite/prepare_protocol.h $(srcdir)/Modules/_sqlite/row.h $(srcdir)/Modules/_sqlite/util.h
MODULE__ZSTD_DEPS=$(srcdir)/Modules/_zstd/_zstdmodule.h $(srcdir)/Modules/_zstd/buffer.h $(srcdir)/Modules/_zstd/zstddict.h

CODECS_COMMON_HEADERS=$(srcdir)/Modules/cjkcodecs/multibytecodec.h $(srcdir)/Modules/cjkcodecs/cjkcodecs.h
MODULE__CODECS_CN_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_cn.h $(CODECS_COMMON_HEADERS)
MODULE__CODECS_HK_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_hk.h  $(CODECS_COMMON_HEADERS)
MODULE__CODECS_ISO2022_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_jisx0213_pair.h $(srcdir)/Modules/cjkcodecs/alg_jisx0201.h $(srcdir)/Modules/cjkcodecs/emu_jisx0213_2000.h $(CODECS_COMMON_HEADERS)
MODULE__CODECS_JP_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_jisx0213_pair.h $(srcdir)/Modules/cjkcodecs/alg_jisx0201.h $(srcdir)/Modules/cjkcodecs/emu_jisx0213_2000.h $(srcdir)/Modules/cjkcodecs/mappings_jp.h $(CODECS_COMMON_HEADERS)
MODULE__CODECS_KR_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_kr.h $(CODECS_COMMON_HEADERS)
MODULE__CODECS_TW_DEPS=$(srcdir)/Modules/cjkcodecs/mappings_tw.h $(CODECS_COMMON_HEADERS)
MODULE__MULTIBYTECODEC_DEPS=$(srcdir)/Modules/cjkcodecs/multibytecodec.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
# Local Variables:
# mode: makefile
# End:

# Rules appended by makesetup

Modules/_bisectmodule.o: $(srcdir)/Modules/_bisectmodule.c $(MODULE__BISECT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__BISECT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_bisectmodule.c -o Modules/_bisectmodule.o
Modules/_bisect$(EXT_SUFFIX):  Modules/_bisectmodule.o $(MODULE__BISECT_LDEPS); $(BLDSHARED)  Modules/_bisectmodule.o $(MODULE__BISECT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_bisect$(EXT_SUFFIX)
Modules/_heapqmodule.o: $(srcdir)/Modules/_heapqmodule.c $(MODULE__HEAPQ_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__HEAPQ_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_heapqmodule.c -o Modules/_heapqmodule.o
Modules/_heapq$(EXT_SUFFIX):  Modules/_heapqmodule.o $(MODULE__HEAPQ_LDEPS); $(BLDSHARED)  Modules/_heapqmodule.o $(MODULE__HEAPQ_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_heapq$(EXT_SUFFIX)
Modules/_json.o: $(srcdir)/Modules/_json.c $(MODULE__JSON_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__JSON_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_json.c -o Modules/_json.o
Modules/_json$(EXT_SUFFIX):  Modules/_json.o $(MODULE__JSON_LDEPS); $(BLDSHARED)  Modules/_json.o $(MODULE__JSON_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_json$(EXT_SUFFIX)
Modules/_randommodule.o: $(srcdir)/Modules/_randommodule.c $(MODULE__RANDOM_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__RANDOM_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_randommodule.c -o Modules/_randommodule.o
Modules/_random$(EXT_SUFFIX):  Modules/_randommodule.o $(MODULE__RANDOM_LDEPS); $(BLDSHARED)  Modules/_randommodule.o $(MODULE__RANDOM_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_random$(EXT_SUFFIX)
Modules/_struct.o: $(srcdir)/Modules/_struct.c $(MODULE__STRUCT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__STRUCT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_struct.c -o Modules/_struct.o
Modules/_struct$(EXT_SUFFIX):  Modules/_struct.o $(MODULE__STRUCT_LDEPS); $(BLDSHARED)  Modules/_struct.o $(MODULE__STRUCT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_struct$(EXT_SUFFIX)
Modules/mathmodule.o: $(srcdir)/Modules/mathmodule.c $(MODULE_MATH_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_MATH_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/mathmodule.c -o Modules/mathmodule.o
Modules/math$(EXT_SUFFIX):  Modules/mathmodule.o $(MODULE_MATH_LDEPS); $(BLDSHARED)  Modules/mathmodule.o $(MODULE_MATH_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/math$(EXT_SUFFIX)
Modules/binascii.o: $(srcdir)/Modules/binascii.c $(MODULE_BINASCII_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE_BINASCII_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/binascii.c -o Modules/binascii.o
Modules/binascii$(EXT_SUFFIX):  Modules/binascii.o $(MODULE_BINASCII_LDEPS); $(BLDSHARED)  Modules/binascii.o  /private/task/prefix/lib/libz.a $(MODULE_LDFLAGS_SHARED) -o Modules/binascii$(EXT_SUFFIX)
Modules/zlibmodule.o: $(srcdir)/Modules/zlibmodule.c $(MODULE_ZLIB_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE_ZLIB_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/zlibmodule.c -o Modules/zlibmodule.o
Modules/zlib$(EXT_SUFFIX):  Modules/zlibmodule.o $(MODULE_ZLIB_LDEPS); $(BLDSHARED)  Modules/zlibmodule.o  /private/task/prefix/lib/libz.a $(MODULE_LDFLAGS_SHARED) -o Modules/zlib$(EXT_SUFFIX)
Modules/fcntlmodule.o: $(srcdir)/Modules/fcntlmodule.c $(MODULE_FCNTL_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_FCNTL_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/fcntlmodule.c -o Modules/fcntlmodule.o
Modules/fcntl$(EXT_SUFFIX):  Modules/fcntlmodule.o $(MODULE_FCNTL_LDEPS); $(BLDSHARED)  Modules/fcntlmodule.o $(MODULE_FCNTL_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/fcntl$(EXT_SUFFIX)
Modules/_posixsubprocess.o: $(srcdir)/Modules/_posixsubprocess.c $(MODULE__POSIXSUBPROCESS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__POSIXSUBPROCESS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_posixsubprocess.c -o Modules/_posixsubprocess.o
Modules/_posixsubprocess$(EXT_SUFFIX):  Modules/_posixsubprocess.o $(MODULE__POSIXSUBPROCESS_LDEPS); $(BLDSHARED)  Modules/_posixsubprocess.o $(MODULE__POSIXSUBPROCESS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_posixsubprocess$(EXT_SUFFIX)
Modules/selectmodule.o: $(srcdir)/Modules/selectmodule.c $(MODULE_SELECT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_SELECT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/selectmodule.c -o Modules/selectmodule.o
Modules/select$(EXT_SUFFIX):  Modules/selectmodule.o $(MODULE_SELECT_LDEPS); $(BLDSHARED)  Modules/selectmodule.o $(MODULE_SELECT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/select$(EXT_SUFFIX)
Modules/unicodedata.o: $(srcdir)/Modules/unicodedata.c $(MODULE_UNICODEDATA_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_UNICODEDATA_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/unicodedata.c -o Modules/unicodedata.o
Modules/unicodedata$(EXT_SUFFIX):  Modules/unicodedata.o $(MODULE_UNICODEDATA_LDEPS); $(BLDSHARED)  Modules/unicodedata.o $(MODULE_UNICODEDATA_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/unicodedata$(EXT_SUFFIX)
Modules/_ctypes/_ctypes.o: $(srcdir)/Modules/_ctypes/_ctypes.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/_ctypes.c -o Modules/_ctypes/_ctypes.o
Modules/_ctypes/callbacks.o: $(srcdir)/Modules/_ctypes/callbacks.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/callbacks.c -o Modules/_ctypes/callbacks.o
Modules/_ctypes/callproc.o: $(srcdir)/Modules/_ctypes/callproc.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/callproc.c -o Modules/_ctypes/callproc.o
Modules/_ctypes/stgdict.o: $(srcdir)/Modules/_ctypes/stgdict.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/stgdict.c -o Modules/_ctypes/stgdict.o
Modules/_ctypes/cfield.o: $(srcdir)/Modules/_ctypes/cfield.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/cfield.c -o Modules/_ctypes/cfield.o
Modules/_ctypes/malloc_closure.o: $(srcdir)/Modules/_ctypes/malloc_closure.c $(MODULE__CTYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CTYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ctypes/malloc_closure.c -o Modules/_ctypes/malloc_closure.o
Modules/_ctypes$(EXT_SUFFIX):  Modules/_ctypes/_ctypes.o Modules/_ctypes/callbacks.o Modules/_ctypes/callproc.o Modules/_ctypes/stgdict.o Modules/_ctypes/cfield.o Modules/_ctypes/malloc_closure.o $(MODULE__CTYPES_LDEPS); $(BLDSHARED)  Modules/_ctypes/_ctypes.o Modules/_ctypes/callbacks.o Modules/_ctypes/callproc.o Modules/_ctypes/stgdict.o Modules/_ctypes/cfield.o Modules/_ctypes/malloc_closure.o $(MODULE__CTYPES_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_ctypes$(EXT_SUFFIX)
Modules/socketmodule.o: $(srcdir)/Modules/socketmodule.c $(MODULE__SOCKET_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SOCKET_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/socketmodule.c -o Modules/socketmodule.o
Modules/_socket$(EXT_SUFFIX):  Modules/socketmodule.o $(MODULE__SOCKET_LDEPS); $(BLDSHARED)  Modules/socketmodule.o $(MODULE__SOCKET_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_socket$(EXT_SUFFIX)
Modules/_ssl.o: $(srcdir)/Modules/_ssl.c $(MODULE__SSL_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__SSL_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_ssl.c -o Modules/_ssl.o
Modules/_ssl$(EXT_SUFFIX):  Modules/_ssl.o $(MODULE__SSL_LDEPS); $(BLDSHARED)  Modules/_ssl.o  /private/task/prefix/lib/libssl.a /private/task/prefix/lib/libcrypto.a $(MODULE_LDFLAGS_SHARED) -o Modules/_ssl$(EXT_SUFFIX)
Modules/pyexpat.o: $(srcdir)/Modules/pyexpat.c $(MODULE_PYEXPAT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_PYEXPAT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/pyexpat.c -o Modules/pyexpat.o
Modules/pyexpat$(EXT_SUFFIX):  Modules/pyexpat.o $(MODULE_PYEXPAT_LDEPS); $(BLDSHARED)  Modules/pyexpat.o $(MODULE_PYEXPAT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/pyexpat$(EXT_SUFFIX)
Modules/resource.o: $(srcdir)/Modules/resource.c $(MODULE_RESOURCE_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_RESOURCE_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/resource.c -o Modules/resource.o
Modules/resource$(EXT_SUFFIX):  Modules/resource.o $(MODULE_RESOURCE_LDEPS); $(BLDSHARED)  Modules/resource.o $(MODULE_RESOURCE_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/resource$(EXT_SUFFIX)
Modules/_scproxy.o: $(srcdir)/Modules/_scproxy.c $(MODULE__SCPROXY_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SCPROXY_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_scproxy.c -o Modules/_scproxy.o
Modules/_scproxy$(EXT_SUFFIX):  Modules/_scproxy.o $(MODULE__SCPROXY_LDEPS); $(BLDSHARED)  Modules/_scproxy.o $(MODULE__SCPROXY_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_scproxy$(EXT_SUFFIX)
Modules/md5module.o: $(srcdir)/Modules/md5module.c $(MODULE__MD5_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__MD5_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/md5module.c -o Modules/md5module.o
Modules/_md5$(EXT_SUFFIX):  Modules/md5module.o $(MODULE__MD5_LDEPS); $(BLDSHARED)  Modules/md5module.o  Modules/_hacl/libHacl_Hash_MD5.a $(MODULE_LDFLAGS_SHARED) -o Modules/_md5$(EXT_SUFFIX)
Modules/sha1module.o: $(srcdir)/Modules/sha1module.c $(MODULE__SHA1_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__SHA1_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/sha1module.c -o Modules/sha1module.o
Modules/_sha1$(EXT_SUFFIX):  Modules/sha1module.o $(MODULE__SHA1_LDEPS); $(BLDSHARED)  Modules/sha1module.o  Modules/_hacl/libHacl_Hash_SHA1.a $(MODULE_LDFLAGS_SHARED) -o Modules/_sha1$(EXT_SUFFIX)
Modules/sha2module.o: $(srcdir)/Modules/sha2module.c $(MODULE__SHA2_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__SHA2_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/sha2module.c -o Modules/sha2module.o
Modules/_sha2$(EXT_SUFFIX):  Modules/sha2module.o $(MODULE__SHA2_LDEPS); $(BLDSHARED)  Modules/sha2module.o  Modules/_hacl/libHacl_Hash_SHA2.a $(MODULE_LDFLAGS_SHARED) -o Modules/_sha2$(EXT_SUFFIX)
Modules/sha3module.o: $(srcdir)/Modules/sha3module.c $(MODULE__SHA3_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__SHA3_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/sha3module.c -o Modules/sha3module.o
Modules/_sha3$(EXT_SUFFIX):  Modules/sha3module.o $(MODULE__SHA3_LDEPS); $(BLDSHARED)  Modules/sha3module.o  Modules/_hacl/libHacl_Hash_SHA3.a $(MODULE_LDFLAGS_SHARED) -o Modules/_sha3$(EXT_SUFFIX)
Modules/blake2module.o: $(srcdir)/Modules/blake2module.c $(MODULE__BLAKE2_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__BLAKE2_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/blake2module.c -o Modules/blake2module.o
Modules/_blake2$(EXT_SUFFIX):  Modules/blake2module.o $(MODULE__BLAKE2_LDEPS); $(BLDSHARED)  Modules/blake2module.o  Modules/_hacl/libHacl_Hash_BLAKE2.a $(MODULE_LDFLAGS_SHARED) -o Modules/_blake2$(EXT_SUFFIX)
Modules/hmacmodule.o: $(srcdir)/Modules/hmacmodule.c $(MODULE__HMAC_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC)  $(MODULE__HMAC_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/hmacmodule.c -o Modules/hmacmodule.o
Modules/_hmac$(EXT_SUFFIX):  Modules/hmacmodule.o $(MODULE__HMAC_LDEPS); $(BLDSHARED)  Modules/hmacmodule.o  Modules/_hacl/libHacl_HMAC.a $(MODULE_LDFLAGS_SHARED) -o Modules/_hmac$(EXT_SUFFIX)
Modules/atexitmodule.o: $(srcdir)/Modules/atexitmodule.c $(MODULE_ATEXIT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_ATEXIT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/atexitmodule.c -o Modules/atexitmodule.o
Modules/atexit$(EXT_SUFFIX):  Modules/atexitmodule.o $(MODULE_ATEXIT_LDEPS); $(BLDSHARED)  Modules/atexitmodule.o $(MODULE_ATEXIT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/atexit$(EXT_SUFFIX)
Modules/faulthandler.o: $(srcdir)/Modules/faulthandler.c $(MODULE_FAULTHANDLER_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_FAULTHANDLER_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/faulthandler.c -o Modules/faulthandler.o
Modules/faulthandler$(EXT_SUFFIX):  Modules/faulthandler.o $(MODULE_FAULTHANDLER_LDEPS); $(BLDSHARED)  Modules/faulthandler.o $(MODULE_FAULTHANDLER_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/faulthandler$(EXT_SUFFIX)
Modules/posixmodule.o: $(srcdir)/Modules/posixmodule.c $(MODULE_POSIX_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_POSIX_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/posixmodule.c -o Modules/posixmodule.o
Modules/posix$(EXT_SUFFIX):  Modules/posixmodule.o $(MODULE_POSIX_LDEPS); $(BLDSHARED)  Modules/posixmodule.o $(MODULE_POSIX_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/posix$(EXT_SUFFIX)
Modules/signalmodule.o: $(srcdir)/Modules/signalmodule.c $(MODULE__SIGNAL_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SIGNAL_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/signalmodule.c -o Modules/signalmodule.o
Modules/_signal$(EXT_SUFFIX):  Modules/signalmodule.o $(MODULE__SIGNAL_LDEPS); $(BLDSHARED)  Modules/signalmodule.o $(MODULE__SIGNAL_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_signal$(EXT_SUFFIX)
Modules/_tracemalloc.o: $(srcdir)/Modules/_tracemalloc.c $(MODULE__TRACEMALLOC_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__TRACEMALLOC_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_tracemalloc.c -o Modules/_tracemalloc.o
Modules/_tracemalloc$(EXT_SUFFIX):  Modules/_tracemalloc.o $(MODULE__TRACEMALLOC_LDEPS); $(BLDSHARED)  Modules/_tracemalloc.o $(MODULE__TRACEMALLOC_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_tracemalloc$(EXT_SUFFIX)
Modules/_suggestions.o: $(srcdir)/Modules/_suggestions.c $(MODULE__SUGGESTIONS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SUGGESTIONS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_suggestions.c -o Modules/_suggestions.o
Modules/_suggestions$(EXT_SUFFIX):  Modules/_suggestions.o $(MODULE__SUGGESTIONS_LDEPS); $(BLDSHARED)  Modules/_suggestions.o $(MODULE__SUGGESTIONS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_suggestions$(EXT_SUFFIX)
Modules/_datetimemodule.o: $(srcdir)/Modules/_datetimemodule.c $(MODULE__DATETIME_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__DATETIME_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_datetimemodule.c -o Modules/_datetimemodule.o
Modules/_datetime$(EXT_SUFFIX):  Modules/_datetimemodule.o $(MODULE__DATETIME_LDEPS); $(BLDSHARED)  Modules/_datetimemodule.o $(MODULE__DATETIME_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_datetime$(EXT_SUFFIX)
Modules/_codecsmodule.o: $(srcdir)/Modules/_codecsmodule.c $(MODULE__CODECS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__CODECS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_codecsmodule.c -o Modules/_codecsmodule.o
Modules/_codecs$(EXT_SUFFIX):  Modules/_codecsmodule.o $(MODULE__CODECS_LDEPS); $(BLDSHARED)  Modules/_codecsmodule.o $(MODULE__CODECS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_codecs$(EXT_SUFFIX)
Modules/_collectionsmodule.o: $(srcdir)/Modules/_collectionsmodule.c $(MODULE__COLLECTIONS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__COLLECTIONS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_collectionsmodule.c -o Modules/_collectionsmodule.o
Modules/_collections$(EXT_SUFFIX):  Modules/_collectionsmodule.o $(MODULE__COLLECTIONS_LDEPS); $(BLDSHARED)  Modules/_collectionsmodule.o $(MODULE__COLLECTIONS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_collections$(EXT_SUFFIX)
Modules/errnomodule.o: $(srcdir)/Modules/errnomodule.c $(MODULE_ERRNO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_ERRNO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/errnomodule.c -o Modules/errnomodule.o
Modules/errno$(EXT_SUFFIX):  Modules/errnomodule.o $(MODULE_ERRNO_LDEPS); $(BLDSHARED)  Modules/errnomodule.o $(MODULE_ERRNO_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/errno$(EXT_SUFFIX)
Modules/_io/_iomodule.o: $(srcdir)/Modules/_io/_iomodule.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/_iomodule.c -o Modules/_io/_iomodule.o
Modules/_io/iobase.o: $(srcdir)/Modules/_io/iobase.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/iobase.c -o Modules/_io/iobase.o
Modules/_io/fileio.o: $(srcdir)/Modules/_io/fileio.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/fileio.c -o Modules/_io/fileio.o
Modules/_io/bytesio.o: $(srcdir)/Modules/_io/bytesio.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/bytesio.c -o Modules/_io/bytesio.o
Modules/_io/bufferedio.o: $(srcdir)/Modules/_io/bufferedio.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/bufferedio.c -o Modules/_io/bufferedio.o
Modules/_io/textio.o: $(srcdir)/Modules/_io/textio.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/textio.c -o Modules/_io/textio.o
Modules/_io/stringio.o: $(srcdir)/Modules/_io/stringio.c $(MODULE__IO_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__IO_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_io/stringio.c -o Modules/_io/stringio.o
Modules/_io$(EXT_SUFFIX):  Modules/_io/_iomodule.o Modules/_io/iobase.o Modules/_io/fileio.o Modules/_io/bytesio.o Modules/_io/bufferedio.o Modules/_io/textio.o Modules/_io/stringio.o $(MODULE__IO_LDEPS); $(BLDSHARED)  Modules/_io/_iomodule.o Modules/_io/iobase.o Modules/_io/fileio.o Modules/_io/bytesio.o Modules/_io/bufferedio.o Modules/_io/textio.o Modules/_io/stringio.o $(MODULE__IO_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_io$(EXT_SUFFIX)
Modules/itertoolsmodule.o: $(srcdir)/Modules/itertoolsmodule.c $(MODULE_ITERTOOLS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_ITERTOOLS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/itertoolsmodule.c -o Modules/itertoolsmodule.o
Modules/itertools$(EXT_SUFFIX):  Modules/itertoolsmodule.o $(MODULE_ITERTOOLS_LDEPS); $(BLDSHARED)  Modules/itertoolsmodule.o $(MODULE_ITERTOOLS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/itertools$(EXT_SUFFIX)
Modules/_sre/sre.o: $(srcdir)/Modules/_sre/sre.c $(MODULE__SRE_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SRE_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_sre/sre.c -o Modules/_sre/sre.o
Modules/_sre$(EXT_SUFFIX):  Modules/_sre/sre.o $(MODULE__SRE_LDEPS); $(BLDSHARED)  Modules/_sre/sre.o $(MODULE__SRE_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_sre$(EXT_SUFFIX)
Modules/_sysconfig.o: $(srcdir)/Modules/_sysconfig.c $(MODULE__SYSCONFIG_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SYSCONFIG_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_sysconfig.c -o Modules/_sysconfig.o
Modules/_sysconfig$(EXT_SUFFIX):  Modules/_sysconfig.o $(MODULE__SYSCONFIG_LDEPS); $(BLDSHARED)  Modules/_sysconfig.o $(MODULE__SYSCONFIG_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_sysconfig$(EXT_SUFFIX)
Modules/_threadmodule.o: $(srcdir)/Modules/_threadmodule.c $(MODULE__THREAD_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__THREAD_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_threadmodule.c -o Modules/_threadmodule.o
Modules/_thread$(EXT_SUFFIX):  Modules/_threadmodule.o $(MODULE__THREAD_LDEPS); $(BLDSHARED)  Modules/_threadmodule.o $(MODULE__THREAD_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_thread$(EXT_SUFFIX)
Modules/timemodule.o: $(srcdir)/Modules/timemodule.c $(MODULE_TIME_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_TIME_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/timemodule.c -o Modules/timemodule.o
Modules/time$(EXT_SUFFIX):  Modules/timemodule.o $(MODULE_TIME_LDEPS); $(BLDSHARED)  Modules/timemodule.o $(MODULE_TIME_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/time$(EXT_SUFFIX)
Modules/_typesmodule.o: $(srcdir)/Modules/_typesmodule.c $(MODULE__TYPES_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__TYPES_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_typesmodule.c -o Modules/_typesmodule.o
Modules/_types$(EXT_SUFFIX):  Modules/_typesmodule.o $(MODULE__TYPES_LDEPS); $(BLDSHARED)  Modules/_typesmodule.o $(MODULE__TYPES_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_types$(EXT_SUFFIX)
Modules/_typingmodule.o: $(srcdir)/Modules/_typingmodule.c $(MODULE__TYPING_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__TYPING_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_typingmodule.c -o Modules/_typingmodule.o
Modules/_typing$(EXT_SUFFIX):  Modules/_typingmodule.o $(MODULE__TYPING_LDEPS); $(BLDSHARED)  Modules/_typingmodule.o $(MODULE__TYPING_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_typing$(EXT_SUFFIX)
Modules/_weakref.o: $(srcdir)/Modules/_weakref.c $(MODULE__WEAKREF_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__WEAKREF_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_weakref.c -o Modules/_weakref.o
Modules/_weakref$(EXT_SUFFIX):  Modules/_weakref.o $(MODULE__WEAKREF_LDEPS); $(BLDSHARED)  Modules/_weakref.o $(MODULE__WEAKREF_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_weakref$(EXT_SUFFIX)
Modules/_abc.o: $(srcdir)/Modules/_abc.c $(MODULE__ABC_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__ABC_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_abc.c -o Modules/_abc.o
Modules/_abc$(EXT_SUFFIX):  Modules/_abc.o $(MODULE__ABC_LDEPS); $(BLDSHARED)  Modules/_abc.o $(MODULE__ABC_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_abc$(EXT_SUFFIX)
Modules/_functoolsmodule.o: $(srcdir)/Modules/_functoolsmodule.c $(MODULE__FUNCTOOLS_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__FUNCTOOLS_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_functoolsmodule.c -o Modules/_functoolsmodule.o
Modules/_functools$(EXT_SUFFIX):  Modules/_functoolsmodule.o $(MODULE__FUNCTOOLS_LDEPS); $(BLDSHARED)  Modules/_functoolsmodule.o $(MODULE__FUNCTOOLS_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_functools$(EXT_SUFFIX)
Modules/_localemodule.o: $(srcdir)/Modules/_localemodule.c $(MODULE__LOCALE_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__LOCALE_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_localemodule.c -o Modules/_localemodule.o
Modules/_locale$(EXT_SUFFIX):  Modules/_localemodule.o $(MODULE__LOCALE_LDEPS); $(BLDSHARED)  Modules/_localemodule.o $(MODULE__LOCALE_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_locale$(EXT_SUFFIX)
Modules/_opcode.o: $(srcdir)/Modules/_opcode.c $(MODULE__OPCODE_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__OPCODE_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_opcode.c -o Modules/_opcode.o
Modules/_opcode$(EXT_SUFFIX):  Modules/_opcode.o $(MODULE__OPCODE_LDEPS); $(BLDSHARED)  Modules/_opcode.o $(MODULE__OPCODE_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_opcode$(EXT_SUFFIX)
Modules/_operator.o: $(srcdir)/Modules/_operator.c $(MODULE__OPERATOR_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__OPERATOR_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_operator.c -o Modules/_operator.o
Modules/_operator$(EXT_SUFFIX):  Modules/_operator.o $(MODULE__OPERATOR_LDEPS); $(BLDSHARED)  Modules/_operator.o $(MODULE__OPERATOR_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_operator$(EXT_SUFFIX)
Modules/_stat.o: $(srcdir)/Modules/_stat.c $(MODULE__STAT_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__STAT_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/_stat.c -o Modules/_stat.o
Modules/_stat$(EXT_SUFFIX):  Modules/_stat.o $(MODULE__STAT_LDEPS); $(BLDSHARED)  Modules/_stat.o $(MODULE__STAT_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_stat$(EXT_SUFFIX)
Modules/symtablemodule.o: $(srcdir)/Modules/symtablemodule.c $(MODULE__SYMTABLE_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE__SYMTABLE_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/symtablemodule.c -o Modules/symtablemodule.o
Modules/_symtable$(EXT_SUFFIX):  Modules/symtablemodule.o $(MODULE__SYMTABLE_LDEPS); $(BLDSHARED)  Modules/symtablemodule.o $(MODULE__SYMTABLE_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/_symtable$(EXT_SUFFIX)
Modules/pwdmodule.o: $(srcdir)/Modules/pwdmodule.c $(MODULE_PWD_DEPS) $(MODULE_DEPS_STATIC) $(PYTHON_HEADERS); $(CC) $(MODULE_PWD_CFLAGS) $(PY_BUILTIN_MODULE_CFLAGS) -c $(srcdir)/Modules/pwdmodule.c -o Modules/pwdmodule.o
Modules/pwd$(EXT_SUFFIX):  Modules/pwdmodule.o $(MODULE_PWD_LDEPS); $(BLDSHARED)  Modules/pwdmodule.o $(MODULE_PWD_LDFLAGS) $(MODULE_LDFLAGS_SHARED) -o Modules/pwd$(EXT_SUFFIX)
""",
        'pyconfig.h': rb"""/* pyconfig.h.  Generated from pyconfig.h.in by configure.  */
/* pyconfig.h.in.  Generated from configure.ac by autoheader.  */


#ifndef Py_PYCONFIG_H
#define Py_PYCONFIG_H


/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* BUILD_GNU_TYPE + AIX_BUILDDATE are used to construct the PEP425 tag of the
   build system. */
/* #undef AIX_BUILDDATE */

/* Define for AIX if your compiler is a genuine IBM xlC/xlC_r and you want
   support for AIX C++ shared extension modules. */
/* #undef AIX_GENUINE_CPLUSPLUS */

/* The normal alignment of 'long', in bytes. */
#define ALIGNOF_LONG 8

/* The normal alignment of 'max_align_t', in bytes. */
#define ALIGNOF_MAX_ALIGN_T 8

/* The normal alignment of 'size_t', in bytes. */
#define ALIGNOF_SIZE_T 8

/* Alternative SOABI used in debug build to load C extensions built in release
   mode */
/* #undef ALT_SOABI */

/* The Android API level. */
/* #undef ANDROID_API_LEVEL */

/* Define if C doubles are 64-bit IEEE 754 binary format, stored in ARM
   mixed-endian order (byte order 45670123) */
/* #undef DOUBLE_IS_ARM_MIXED_ENDIAN_IEEE754 */

/* Define if C doubles are 64-bit IEEE 754 binary format, stored with the most
   significant byte first */
/* #undef DOUBLE_IS_BIG_ENDIAN_IEEE754 */

/* Define if C doubles are 64-bit IEEE 754 binary format, stored with the
   least significant byte first */
#define DOUBLE_IS_LITTLE_ENDIAN_IEEE754 1

/* Define if --enable-ipv6 is specified */
#define ENABLE_IPV6 1

/* Define if getpgrp() must be called as getpgrp(0). */
/* #undef GETPGRP_HAVE_ARG */

/* Define if you have the 'accept' function. */
#define HAVE_ACCEPT 1

/* Define to 1 if you have the 'accept4' function. */
/* #undef HAVE_ACCEPT4 */

/* Define to 1 if you have the 'acosh' function. */
#define HAVE_ACOSH 1

/* struct addrinfo (netdb.h) */
#define HAVE_ADDRINFO 1

/* Define to 1 if you have the 'alarm' function. */
#define HAVE_ALARM 1

/* Define if aligned memory access is required */
/* #undef HAVE_ALIGNED_REQUIRED */

/* Define to 1 if you have the <alloca.h> header file. */
#define HAVE_ALLOCA_H 1

/* Define this if your time.h defines altzone. */
/* #undef HAVE_ALTZONE */

/* Define to 1 if you have the 'asinh' function. */
#define HAVE_ASINH 1

/* Define to 1 if you have the <asm/types.h> header file. */
/* #undef HAVE_ASM_TYPES_H */

/* Define to 1 if you have the 'atanh' function. */
#define HAVE_ATANH 1

/* Define to 1 if you have the 'backtrace' function. */
#define HAVE_BACKTRACE 1

/* Define if you have the 'bind' function. */
#define HAVE_BIND 1

/* Define to 1 if you have the 'bind_textdomain_codeset' function. */
/* #undef HAVE_BIND_TEXTDOMAIN_CODESET */

/* Define to 1 if you have the <bluetooth/bluetooth.h> header file. */
/* #undef HAVE_BLUETOOTH_BLUETOOTH_H */

/* Define to 1 if you have the <bluetooth.h> header file. */
/* #undef HAVE_BLUETOOTH_H */

/* Define if mbstowcs(NULL, "text", 0) does not return the number of wide
   chars that would be converted. */
/* #undef HAVE_BROKEN_MBSTOWCS */

/* Define if nice() returns success/failure instead of the new priority. */
/* #undef HAVE_BROKEN_NICE */

/* Define if the system reports an invalid PIPE_BUF value. */
/* #undef HAVE_BROKEN_PIPE_BUF */

/* Define if poll() sets errno on invalid file descriptors. */
/* #undef HAVE_BROKEN_POLL */

/* Define if the Posix semaphores do not work on your system */
/* #undef HAVE_BROKEN_POSIX_SEMAPHORES */

/* Define if pthread_sigmask() does not work on your system. */
/* #undef HAVE_BROKEN_PTHREAD_SIGMASK */

/* define to 1 if your sem_getvalue is broken. */
#define HAVE_BROKEN_SEM_GETVALUE 1

/* Define if 'unsetenv' does not return an int. */
/* #undef HAVE_BROKEN_UNSETENV */

/* Has builtin __atomic_load_n() and __atomic_store_n() functions */
#define HAVE_BUILTIN_ATOMIC 1

/* Define to 1 if you have the <bzlib.h> header file. */
#define HAVE_BZLIB_H 1

/* Define to 1 if you have the 'chflags' function. */
#define HAVE_CHFLAGS 1

/* Define to 1 if you have the 'chmod' function. */
#define HAVE_CHMOD 1

/* Define to 1 if you have the 'chown' function. */
#define HAVE_CHOWN 1

/* Define if you have the 'chroot' function. */
#define HAVE_CHROOT 1

/* Define to 1 if you have the 'clock' function. */
#define HAVE_CLOCK 1

/* Define to 1 if you have the 'clock_getres' function. */
#define HAVE_CLOCK_GETRES 1

/* Define to 1 if you have the 'clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the 'clock_nanosleep' function. */
/* #undef HAVE_CLOCK_NANOSLEEP */

/* Define to 1 if you have the 'clock_settime' function. */
#define HAVE_CLOCK_SETTIME 1

/* Define to 1 if the system has the type 'clock_t'. */
#define HAVE_CLOCK_T 1

/* Define to 1 if you have the 'closefrom' function. */
/* #undef HAVE_CLOSEFROM */

/* Define to 1 if you have the 'close_range' function. */
/* #undef HAVE_CLOSE_RANGE */

/* Define if the C compiler supports computed gotos. */
#define HAVE_COMPUTED_GOTOS 1

/* Define to 1 if you have the 'confstr' function. */
#define HAVE_CONFSTR 1

/* Define to 1 if you have the <conio.h> header file. */
/* #undef HAVE_CONIO_H */

/* Define if you have the 'connect' function. */
#define HAVE_CONNECT 1

/* Define to 1 if you have the 'copy_file_range' function. */
/* #undef HAVE_COPY_FILE_RANGE */

/* Define to 1 if you have the 'ctermid' function. */
#define HAVE_CTERMID 1

/* Define if you have the 'ctermid_r' function. */
#define HAVE_CTERMID_R 1

/* Define if you have the 'ESCDELAY' variable. */
#define HAVE_CURSES_ESCDELAY 1

/* Define if you have the 'filter' function. */
#define HAVE_CURSES_FILTER 1

/* Define if you have the 'getmouse' function with the X/Open signature. */
#define HAVE_CURSES_GETMOUSE 1

/* Define to 1 if you have the <curses.h> header file. */
#define HAVE_CURSES_H 1

/* Define if you have the 'has_key' function. */
#define HAVE_CURSES_HAS_KEY 1

/* Define if you have the 'immedok' function. */
#define HAVE_CURSES_IMMEDOK 1

/* Define if you have the 'is_pad' function. */
#define HAVE_CURSES_IS_PAD 1

/* Define if you have the 'is_term_resized' function. */
#define HAVE_CURSES_IS_TERM_RESIZED 1

/* Define if you have the 'resizeterm' function. */
#define HAVE_CURSES_RESIZETERM 1

/* Define if you have the 'resize_term' function. */
#define HAVE_CURSES_RESIZE_TERM 1

/* Define if you have the 'set_escdelay' function. */
#define HAVE_CURSES_SET_ESCDELAY 1

/* Define if you have the 'set_tabsize' function. */
#define HAVE_CURSES_SET_TABSIZE 1

/* Define if you have the 'syncok' function. */
#define HAVE_CURSES_SYNCOK 1

/* Define if you have the 'TABSIZE' variable. */
#define HAVE_CURSES_TABSIZE 1

/* Define if you have the 'typeahead' function. */
#define HAVE_CURSES_TYPEAHEAD 1

/* Define if you have the 'use_env' function. */
#define HAVE_CURSES_USE_ENV 1

/* Define if you have the 'wchgat' function. */
#define HAVE_CURSES_WCHGAT 1

/* Define to 1 if you have the <db.h> header file. */
#define HAVE_DB_H 1

/* Define to 1 if you have the declaration of 'RTLD_DEEPBIND', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_DEEPBIND 0

/* Define to 1 if you have the declaration of 'RTLD_GLOBAL', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_GLOBAL 1

/* Define to 1 if you have the declaration of 'RTLD_LAZY', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_LAZY 1

/* Define to 1 if you have the declaration of 'RTLD_LOCAL', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_LOCAL 1

/* Define to 1 if you have the declaration of 'RTLD_MEMBER', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_MEMBER 0

/* Define to 1 if you have the declaration of 'RTLD_NODELETE', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_NODELETE 1

/* Define to 1 if you have the declaration of 'RTLD_NOLOAD', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_NOLOAD 1

/* Define to 1 if you have the declaration of 'RTLD_NOW', and to 0 if you
   don't. */
#define HAVE_DECL_RTLD_NOW 1

/* Define to 1 if you have the declaration of 'tzname', and to 0 if you don't.
   */
/* #undef HAVE_DECL_TZNAME */

/* Define to 1 if you have the declaration of 'UT_NAMESIZE', and to 0 if you
   don't. */
#define HAVE_DECL_UT_NAMESIZE 1

/* Define to 1 if you have the device macros. */
#define HAVE_DEVICE_MACROS 1

/* Define to 1 if you have the /dev/ptc device file. */
/* #undef HAVE_DEV_PTC */

/* Define to 1 if you have the /dev/ptmx device file. */
#define HAVE_DEV_PTMX 1

/* Define to 1 if you have the <direct.h> header file. */
/* #undef HAVE_DIRECT_H */

/* Define to 1 if the dirent structure has a d_type field */
#define HAVE_DIRENT_D_TYPE 1

/* Define to 1 if you have the <dirent.h> header file, and it defines 'DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define if you have the 'dirfd' function or macro. */
#define HAVE_DIRFD 1

/* Define to 1 if you have the 'dladdr' function. */
#define HAVE_DLADDR 1

/* Define to 1 if you have the 'dladdr1' function. */
/* #undef HAVE_DLADDR1 */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the 'dlopen' function. */
#define HAVE_DLOPEN 1

/* Define to 1 if you have the 'dl_iterate_phdr' function. */
/* #undef HAVE_DL_ITERATE_PHDR */

/* Define to 1 if you have the 'dup' function. */
#define HAVE_DUP 1

/* Define to 1 if you have the 'dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the 'dup3' function. */
/* #undef HAVE_DUP3 */

/* Define if you have the '_dyld_shared_cache_contains_path' function. */
#define HAVE_DYLD_SHARED_CACHE_CONTAINS_PATH 1

/* Defined when any dynamic module loading is enabled. */
#define HAVE_DYNAMIC_LOADING 1

/* Define to 1 if you have the <editline/readline.h> header file. */
/* #undef HAVE_EDITLINE_READLINE_H */

/* Define to 1 if you have the <endian.h> header file. */
/* #undef HAVE_ENDIAN_H */

/* Define if you have the 'epoll_create' function. */
/* #undef HAVE_EPOLL */

/* Define if you have the 'epoll_create1' function. */
/* #undef HAVE_EPOLL_CREATE1 */

/* Define to 1 if you have the 'erf' function. */
#define HAVE_ERF 1

/* Define to 1 if you have the 'erfc' function. */
#define HAVE_ERFC 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define if you have the 'eventfd' function. */
/* #undef HAVE_EVENTFD */

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* Define to 1 if you have the 'execv' function. */
#define HAVE_EXECV 1

/* Define to 1 if you have the 'explicit_bzero' function. */
/* #undef HAVE_EXPLICIT_BZERO */

/* Define to 1 if you have the 'explicit_memset' function. */
/* #undef HAVE_EXPLICIT_MEMSET */

/* Define to 1 if you have the 'expm1' function. */
#define HAVE_EXPM1 1

/* Define to 1 if you have the 'faccessat' function. */
#define HAVE_FACCESSAT 1

/* Define if you have the 'fchdir' function. */
#define HAVE_FCHDIR 1

/* Define to 1 if you have the 'fchmod' function. */
#define HAVE_FCHMOD 1

/* Define to 1 if you have the 'fchmodat' function. */
#define HAVE_FCHMODAT 1

/* Define to 1 if you have the 'fchown' function. */
#define HAVE_FCHOWN 1

/* Define to 1 if you have the 'fchownat' function. */
#define HAVE_FCHOWNAT 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define if you have the 'fdatasync' function. */
/* #undef HAVE_FDATASYNC */

/* Define to 1 if you have the 'fdopendir' function. */
#define HAVE_FDOPENDIR 1

/* Define to 1 if you have the 'fdwalk' function. */
/* #undef HAVE_FDWALK */

/* Define to 1 if you have the 'fexecve' function. */
/* #undef HAVE_FEXECVE */

/* Define if you have the 'ffi_closure_alloc' function. */
#define HAVE_FFI_CLOSURE_ALLOC 1

/* Define if you have the 'ffi_prep_cif_var' function. */
#define HAVE_FFI_PREP_CIF_VAR 1

/* Define if you have the 'ffi_prep_closure_loc' function. */
#define HAVE_FFI_PREP_CLOSURE_LOC 1

/* Define to 1 if you have the 'flock' function. */
#define HAVE_FLOCK 1

/* Define to 1 if you have the 'fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the 'fork1' function. */
/* #undef HAVE_FORK1 */

/* Define to 1 if you have the 'forkpty' function. */
#define HAVE_FORKPTY 1

/* Define to 1 if you have the 'fpathconf' function. */
#define HAVE_FPATHCONF 1

/* Define to 1 if you have the 'fseek64' function. */
/* #undef HAVE_FSEEK64 */

/* Define to 1 if you have the 'fseeko' function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the 'fstatat' function. */
#define HAVE_FSTATAT 1

/* Define to 1 if you have the 'fstatvfs' function. */
#define HAVE_FSTATVFS 1

/* Define if you have the 'fsync' function. */
#define HAVE_FSYNC 1

/* Define to 1 if you have the 'ftell64' function. */
/* #undef HAVE_FTELL64 */

/* Define to 1 if you have the 'ftello' function. */
#define HAVE_FTELLO 1

/* Define to 1 if you have the 'ftime' function. */
#define HAVE_FTIME 1

/* Define to 1 if you have the 'ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the 'futimens' function. */
#define HAVE_FUTIMENS 1

/* Define to 1 if you have the 'futimes' function. */
#define HAVE_FUTIMES 1

/* Define to 1 if you have the 'futimesat' function. */
/* #undef HAVE_FUTIMESAT */

/* Define to 1 if you have the 'gai_strerror' function. */
#define HAVE_GAI_STRERROR 1

/* Define if we can use gcc inline assembler to get and set mc68881 fpcr */
/* #undef HAVE_GCC_ASM_FOR_MC68881 */

/* Define if we can use x64 gcc inline assembler */
/* #undef HAVE_GCC_ASM_FOR_X64 */

/* Define if we can use gcc inline assembler to get and set x87 control word
   */
/* #undef HAVE_GCC_ASM_FOR_X87 */

/* Define if your compiler provides __uint128_t */
#define HAVE_GCC_UINT128_T 1

/* Define to 1 if you have the <gdbm-ndbm.h> header file. */
/* #undef HAVE_GDBM_DASH_NDBM_H */

/* Define to 1 if you have the <gdbm.h> header file. */
/* #undef HAVE_GDBM_H */

/* Define to 1 if you have the <gdbm/ndbm.h> header file. */
/* #undef HAVE_GDBM_NDBM_H */

/* Define if you have the getaddrinfo function. */
#define HAVE_GETADDRINFO 1

/* Define this if you have flockfile(), getc_unlocked(), and funlockfile() */
#define HAVE_GETC_UNLOCKED 1

/* Define to 1 if you have the 'getegid' function. */
#define HAVE_GETEGID 1

/* Define to 1 if you have the 'getentropy' function. */
#define HAVE_GETENTROPY 1

/* Define to 1 if you have the 'geteuid' function. */
#define HAVE_GETEUID 1

/* Define to 1 if you have the 'getgid' function. */
#define HAVE_GETGID 1

/* Define to 1 if you have the 'getgrent' function. */
#define HAVE_GETGRENT 1

/* Define to 1 if you have the 'getgrgid' function. */
#define HAVE_GETGRGID 1

/* Define to 1 if you have the 'getgrgid_r' function. */
#define HAVE_GETGRGID_R 1

/* Define to 1 if you have the 'getgrnam_r' function. */
#define HAVE_GETGRNAM_R 1

/* Define to 1 if you have the 'getgrouplist' function. */
#define HAVE_GETGROUPLIST 1

/* Define to 1 if you have the 'getgroups' function. */
#define HAVE_GETGROUPS 1

/* Define if you have the 'gethostbyaddr' function. */
#define HAVE_GETHOSTBYADDR 1

/* Define to 1 if you have the 'gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* Define this if you have some version of gethostbyname_r() */
/* #undef HAVE_GETHOSTBYNAME_R */

/* Define this if you have the 3-arg version of gethostbyname_r(). */
/* #undef HAVE_GETHOSTBYNAME_R_3_ARG */

/* Define this if you have the 5-arg version of gethostbyname_r(). */
/* #undef HAVE_GETHOSTBYNAME_R_5_ARG */

/* Define this if you have the 6-arg version of gethostbyname_r(). */
/* #undef HAVE_GETHOSTBYNAME_R_6_ARG */

/* Define to 1 if you have the 'gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the 'getitimer' function. */
#define HAVE_GETITIMER 1

/* Define to 1 if you have the 'getloadavg' function. */
#define HAVE_GETLOADAVG 1

/* Define to 1 if you have the 'getlogin' function. */
#define HAVE_GETLOGIN 1

/* Define to 1 if you have the 'getlogin_r' function. */
#define HAVE_GETLOGIN_R 1

/* Define to 1 if you have the 'getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define if you have the 'getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define if you have the 'getpeername' function. */
#define HAVE_GETPEERNAME 1

/* Define to 1 if you have the 'getpgid' function. */
#define HAVE_GETPGID 1

/* Define to 1 if you have the 'getpgrp' function. */
#define HAVE_GETPGRP 1

/* Define to 1 if you have the 'getpid' function. */
#define HAVE_GETPID 1

/* Define to 1 if you have the 'getppid' function. */
#define HAVE_GETPPID 1

/* Define to 1 if you have the 'getpriority' function. */
#define HAVE_GETPRIORITY 1

/* Define if you have the 'getprotobyname' function. */
#define HAVE_GETPROTOBYNAME 1

/* Define to 1 if you have the 'getpwent' function. */
#define HAVE_GETPWENT 1

/* Define to 1 if you have the 'getpwnam_r' function. */
#define HAVE_GETPWNAM_R 1

/* Define to 1 if you have the 'getpwuid' function. */
#define HAVE_GETPWUID 1

/* Define to 1 if you have the 'getpwuid_r' function. */
#define HAVE_GETPWUID_R 1

/* Define to 1 if the getrandom() function is available */
/* #undef HAVE_GETRANDOM */

/* Define to 1 if the Linux getrandom() syscall is available */
/* #undef HAVE_GETRANDOM_SYSCALL */

/* Define to 1 if you have the 'getresgid' function. */
/* #undef HAVE_GETRESGID */

/* Define to 1 if you have the 'getresuid' function. */
/* #undef HAVE_GETRESUID */

/* Define to 1 if you have the 'getrusage' function. */
#define HAVE_GETRUSAGE 1

/* Define if you have the 'getservbyname' function. */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the 'getservbyport' function. */
#define HAVE_GETSERVBYPORT 1

/* Define to 1 if you have the 'getsid' function. */
#define HAVE_GETSID 1

/* Define if you have the 'getsockname' function. */
#define HAVE_GETSOCKNAME 1

/* Define to 1 if you have the 'getspent' function. */
/* #undef HAVE_GETSPENT */

/* Define to 1 if you have the 'getspnam' function. */
/* #undef HAVE_GETSPNAM */

/* Define to 1 if you have the 'getuid' function. */
#define HAVE_GETUID 1

/* Define to 1 if you have the 'getwd' function. */
#define HAVE_GETWD 1

/* Define if glibc has incorrect _FORTIFY_SOURCE wrappers for memmove and
   bcopy. */
/* #undef HAVE_GLIBC_MEMMOVE_BUG */

/* Define to 1 if you have the 'grantpt' function. */
#define HAVE_GRANTPT 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define if you have the 'hstrerror' function. */
#define HAVE_HSTRERROR 1

/* Define this if you have le64toh() */
#define HAVE_HTOLE64 1

/* Define to 1 if you have the 'if_nameindex' function. */
#define HAVE_IF_NAMEINDEX 1

/* Define if you have the 'inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define if you have the 'inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define if you have the 'inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the 'initgroups' function. */
#define HAVE_INITGROUPS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* Define if gcc has the ipa-pure-const bug. */
/* #undef HAVE_IPA_PURE_CONST_BUG */

/* Define to 1 if you have the 'kill' function. */
#define HAVE_KILL 1

/* Define to 1 if you have the 'killpg' function. */
#define HAVE_KILLPG 1

/* Define if you have the 'kqueue' function. */
#define HAVE_KQUEUE 1

/* Define to 1 if you have the <langinfo.h> header file. */
#define HAVE_LANGINFO_H 1

/* Defined to enable large file support when an off_t is bigger than a long
   and long long is at least as big as an off_t. You may need to add some
   flags for configuration and compilation to enable this mode. (For Solaris
   and Linux, the necessary defines are already defined.) */
/* #undef HAVE_LARGEFILE_SUPPORT */

/* Define to 1 if you have the 'lchflags' function. */
#define HAVE_LCHFLAGS 1

/* Define to 1 if you have the 'lchmod' function. */
#define HAVE_LCHMOD 1

/* Define to 1 if you have the 'lchown' function. */
#define HAVE_LCHOWN 1

/* Define to 1 if you have the `db' library (-ldb). */
/* #undef HAVE_LIBDB */

/* Define to 1 if you have the 'dl' library (-ldl). */
#define HAVE_LIBDL 1

/* Define to 1 if you have the 'dld' library (-ldld). */
/* #undef HAVE_LIBDLD */

/* Define to 1 if you have the 'ieee' library (-lieee). */
/* #undef HAVE_LIBIEEE */

/* Define to 1 if you have the <libintl.h> header file. */
/* #undef HAVE_LIBINTL_H */

/* Define to 1 if you have the 'sendfile' library (-lsendfile). */
/* #undef HAVE_LIBSENDFILE */

/* Define to 1 if you have the 'sqlite3' library (-lsqlite3). */
#define HAVE_LIBSQLITE3 1

/* Define to 1 if you have the <libutil.h> header file. */
/* #undef HAVE_LIBUTIL_H */

/* Define if you have the 'link' function. */
#define HAVE_LINK 1

/* Define to 1 if you have the 'linkat' function. */
#define HAVE_LINKAT 1

/* Define to 1 if you have the <link.h> header file. */
/* #undef HAVE_LINK_H */

/* Define to 1 if you have the <linux/auxvec.h> header file. */
/* #undef HAVE_LINUX_AUXVEC_H */

/* Define to 1 if you have the <linux/can/bcm.h> header file. */
/* #undef HAVE_LINUX_CAN_BCM_H */

/* Define to 1 if you have the <linux/can.h> header file. */
/* #undef HAVE_LINUX_CAN_H */

/* Define to 1 if you have the <linux/can/j1939.h> header file. */
/* #undef HAVE_LINUX_CAN_J1939_H */

/* Define if compiling using Linux 3.6 or later. */
/* #undef HAVE_LINUX_CAN_RAW_FD_FRAMES */

/* Define to 1 if you have the <linux/can/raw.h> header file. */
/* #undef HAVE_LINUX_CAN_RAW_H */

/* Define if compiling using Linux 4.1 or later. */
/* #undef HAVE_LINUX_CAN_RAW_JOIN_FILTERS */

/* Define to 1 if you have the <linux/fs.h> header file. */
/* #undef HAVE_LINUX_FS_H */

/* Define to 1 if you have the <linux/limits.h> header file. */
/* #undef HAVE_LINUX_LIMITS_H */

/* Define to 1 if you have the <linux/memfd.h> header file. */
/* #undef HAVE_LINUX_MEMFD_H */

/* Define to 1 if you have the <linux/netfilter_ipv4.h> header file. */
/* #undef HAVE_LINUX_NETFILTER_IPV4_H */

/* Define to 1 if you have the <linux/netlink.h> header file. */
/* #undef HAVE_LINUX_NETLINK_H */

/* Define to 1 if you have the <linux/qrtr.h> header file. */
/* #undef HAVE_LINUX_QRTR_H */

/* Define to 1 if you have the <linux/random.h> header file. */
/* #undef HAVE_LINUX_RANDOM_H */

/* Define to 1 if you have the <linux/sched.h> header file. */
/* #undef HAVE_LINUX_SCHED_H */

/* Define to 1 if you have the <linux/soundcard.h> header file. */
/* #undef HAVE_LINUX_SOUNDCARD_H */

/* Define to 1 if you have the <linux/tipc.h> header file. */
/* #undef HAVE_LINUX_TIPC_H */

/* Define to 1 if you have the <linux/vm_sockets.h> header file. */
/* #undef HAVE_LINUX_VM_SOCKETS_H */

/* Define to 1 if you have the <linux/wait.h> header file. */
/* #undef HAVE_LINUX_WAIT_H */

/* Define if you have the 'listen' function. */
#define HAVE_LISTEN 1

/* Define to 1 if you have the 'lockf' function. */
#define HAVE_LOCKF 1

/* Define to 1 if you have the 'log1p' function. */
#define HAVE_LOG1P 1

/* Define to 1 if you have the 'log2' function. */
#define HAVE_LOG2 1

/* Define to 1 if you have the `login_tty' function. */
#define HAVE_LOGIN_TTY 1

/* Define to 1 if the system has the type 'long double'. */
#define HAVE_LONG_DOUBLE 1

/* Define to 1 if you have the 'lstat' function. */
#define HAVE_LSTAT 1

/* Define to 1 if you have the 'lutimes' function. */
#define HAVE_LUTIMES 1

/* Define to 1 if you have the <lzma.h> header file. */
/* #undef HAVE_LZMA_H */

/* Define to 1 if you have the 'madvise' function. */
#define HAVE_MADVISE 1

/* Define this if you have the makedev macro. */
#define HAVE_MAKEDEV 1

/* Define if you have the 'MAXLOGNAME' constant. */
#define HAVE_MAXLOGNAME 1

/* Define to 1 if you have the 'mbrtowc' function. */
#define HAVE_MBRTOWC 1

/* Define if you have the 'memfd_create' function. */
/* #undef HAVE_MEMFD_CREATE */

/* Define to 1 if you have the 'memrchr' function. */
/* #undef HAVE_MEMRCHR */

/* Define to 1 if you have the <minix/config.h> header file. */
/* #undef HAVE_MINIX_CONFIG_H */

/* Define to 1 if you have the 'mkdirat' function. */
#define HAVE_MKDIRAT 1

/* Define to 1 if you have the 'mkfifo' function. */
#define HAVE_MKFIFO 1

/* Define to 1 if you have the 'mkfifoat' function. */
#define HAVE_MKFIFOAT 1

/* Define to 1 if you have the 'mknod' function. */
#define HAVE_MKNOD 1

/* Define to 1 if you have the 'mknodat' function. */
#define HAVE_MKNODAT 1

/* Define to 1 if you have the 'mktime' function. */
#define HAVE_MKTIME 1

/* Define to 1 if you have the 'mmap' function. */
#define HAVE_MMAP 1

/* Define to 1 if you have the 'mremap' function. */
/* #undef HAVE_MREMAP */

/* Define to 1 if you have the 'nanosleep' function. */
#define HAVE_NANOSLEEP 1

/* Define if you have the 'ncurses' library */
/* #undef HAVE_NCURSES */

/* Define if you have the 'ncursesw' library */
#define HAVE_NCURSESW 1

/* Define to 1 if you have the <ncursesw/curses.h> header file. */
/* #undef HAVE_NCURSESW_CURSES_H */

/* Define to 1 if you have the <ncursesw/ncurses.h> header file. */
/* #undef HAVE_NCURSESW_NCURSES_H */

/* Define to 1 if you have the <ncursesw/panel.h> header file. */
/* #undef HAVE_NCURSESW_PANEL_H */

/* Define to 1 if you have the <ncurses/curses.h> header file. */
/* #undef HAVE_NCURSES_CURSES_H */

/* Define to 1 if you have the <ncurses.h> header file. */
#define HAVE_NCURSES_H 1

/* Define to 1 if you have the <ncurses/ncurses.h> header file. */
/* #undef HAVE_NCURSES_NCURSES_H */

/* Define to 1 if you have the <ncurses/panel.h> header file. */
/* #undef HAVE_NCURSES_PANEL_H */

/* Define to 1 if you have the <ndbm.h> header file. */
#define HAVE_NDBM_H 1

/* Define to 1 if you have the <ndir.h> header file, and it defines 'DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netcan/can.h> header file. */
/* #undef HAVE_NETCAN_CAN_H */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netlink/netlink.h> header file. */
/* #undef HAVE_NETLINK_NETLINK_H */

/* Define to 1 if you have the <netpacket/packet.h> header file. */
/* #undef HAVE_NETPACKET_PACKET_H */

/* Define to 1 if you have the <net/ethernet.h> header file. */
#define HAVE_NET_ETHERNET_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the 'nice' function. */
#define HAVE_NICE 1

/* Define if the internal form of wchar_t in non-Unicode locales is not
   Unicode. */
/* #undef HAVE_NON_UNICODE_WCHAR_T_REPRESENTATION */

/* Define to 1 if you have the 'openat' function. */
#define HAVE_OPENAT 1

/* Define to 1 if you have the 'opendir' function. */
#define HAVE_OPENDIR 1

/* Define to 1 if you have the 'openpty' function. */
#define HAVE_OPENPTY 1

/* Define if you have the 'panel' library */
/* #undef HAVE_PANEL */

/* Define if you have the 'panelw' library */
/* #undef HAVE_PANELW */

/* Define to 1 if you have the <panel.h> header file. */
#define HAVE_PANEL_H 1

/* Define to 1 if you have the 'pathconf' function. */
#define HAVE_PATHCONF 1

/* Define to 1 if you have the 'pause' function. */
#define HAVE_PAUSE 1

/* Define to 1 if you have the 'pipe' function. */
#define HAVE_PIPE 1

/* Define to 1 if you have the 'pipe2' function. */
/* #undef HAVE_PIPE2 */

/* Define to 1 if you have the 'plock' function. */
/* #undef HAVE_PLOCK */

/* Define to 1 if you have the 'poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the 'posix_fadvise' function. */
/* #undef HAVE_POSIX_FADVISE */

/* Define to 1 if you have the 'posix_fallocate' function. */
/* #undef HAVE_POSIX_FALLOCATE */

/* Define to 1 if you have the 'posix_openpt' function. */
#define HAVE_POSIX_OPENPT 1

/* Define to 1 if you have the 'posix_spawn' function. */
#define HAVE_POSIX_SPAWN 1

/* Define to 1 if you have the 'posix_spawnp' function. */
#define HAVE_POSIX_SPAWNP 1

/* Define to 1 if you have the 'posix_spawn_file_actions_addclosefrom_np'
   function. */
/* #undef HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP */

/* Define to 1 if you have the 'pread' function. */
#define HAVE_PREAD 1

/* Define to 1 if you have the 'preadv' function. */
#define HAVE_PREADV 1

/* Define to 1 if you have the 'preadv2' function. */
/* #undef HAVE_PREADV2 */

/* Define if you have the 'prlimit' function. */
/* #undef HAVE_PRLIMIT */

/* Define to 1 if you have the <process.h> header file. */
/* #undef HAVE_PROCESS_H */

/* Define to 1 if you have the 'process_vm_readv' function. */
/* #undef HAVE_PROCESS_VM_READV */

/* Define if your compiler supports function prototype */
#define HAVE_PROTOTYPES 1

/* Define to 1 if you have the 'pthread_condattr_setclock' function. */
/* #undef HAVE_PTHREAD_CONDATTR_SETCLOCK */

/* Define to 1 if you have the 'pthread_cond_timedwait_relative_np' function.
   */
#define HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE_NP 1

/* Defined for Solaris 2.6 bug in pthread header. */
/* #undef HAVE_PTHREAD_DESTRUCTOR */

/* Define to 1 if you have the 'pthread_getattr_np' function. */
/* #undef HAVE_PTHREAD_GETATTR_NP */

/* Define to 1 if you have the 'pthread_getcpuclockid' function. */
/* #undef HAVE_PTHREAD_GETCPUCLOCKID */

/* Define to 1 if you have the 'pthread_getname_np' function. */
#define HAVE_PTHREAD_GETNAME_NP 1

/* Define to 1 if you have the 'pthread_get_name_np' function. */
/* #undef HAVE_PTHREAD_GET_NAME_NP */

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the 'pthread_init' function. */
/* #undef HAVE_PTHREAD_INIT */

/* Define to 1 if you have the 'pthread_kill' function. */
#define HAVE_PTHREAD_KILL 1

/* Define to 1 if you have the 'pthread_setname_np' function. */
#define HAVE_PTHREAD_SETNAME_NP 1

/* Define to 1 if you have the 'pthread_set_name_np' function. */
/* #undef HAVE_PTHREAD_SET_NAME_NP */

/* Define to 1 if you have the 'pthread_sigmask' function. */
#define HAVE_PTHREAD_SIGMASK 1

/* Define if platform requires stubbed pthreads support */
/* #undef HAVE_PTHREAD_STUBS */

/* Define to 1 if you have the 'ptsname' function. */
#define HAVE_PTSNAME 1

/* Define to 1 if you have the 'ptsname_r' function. */
#define HAVE_PTSNAME_R 1

/* Define to 1 if you have the <pty.h> header file. */
/* #undef HAVE_PTY_H */

/* Define to 1 if you have the 'pwrite' function. */
#define HAVE_PWRITE 1

/* Define to 1 if you have the 'pwritev' function. */
#define HAVE_PWRITEV 1

/* Define to 1 if you have the 'pwritev2' function. */
/* #undef HAVE_PWRITEV2 */

/* Define to 1 if you have the <readline/readline.h> header file. */
#define HAVE_READLINE_READLINE_H 1

/* Define to 1 if you have the 'readlink' function. */
#define HAVE_READLINK 1

/* Define to 1 if you have the 'readlinkat' function. */
#define HAVE_READLINKAT 1

/* Define to 1 if you have the 'readv' function. */
#define HAVE_READV 1

/* Define to 1 if you have the 'realpath' function. */
#define HAVE_REALPATH 1

/* Define if you have the 'recvfrom' function. */
#define HAVE_RECVFROM 1

/* Define to 1 if you have the 'renameat' function. */
#define HAVE_RENAMEAT 1

/* Define if readline supports append_history */
/* #undef HAVE_RL_APPEND_HISTORY */

/* Define if you can turn off readline's signal handling. */
/* #undef HAVE_RL_CATCH_SIGNAL */

/* Define to 1 if the system has the type 'rl_compdisp_func_t'. */
/* #undef HAVE_RL_COMPDISP_FUNC_T */

/* Define if you have readline 2.2 */
#define HAVE_RL_COMPLETION_APPEND_CHARACTER 1

/* Define if you have readline 4.0 */
#define HAVE_RL_COMPLETION_DISPLAY_MATCHES_HOOK 1

/* Define if you have readline 4.2 */
#define HAVE_RL_COMPLETION_MATCHES 1

/* Define if you have rl_completion_suppress_append */
/* #undef HAVE_RL_COMPLETION_SUPPRESS_APPEND */

/* Define if you have readline 4.0 */
#define HAVE_RL_PRE_INPUT_HOOK 1

/* Define if you have readline 4.0 */
/* #undef HAVE_RL_RESIZE_TERMINAL */

/* Define to 1 if you have the 'rtpSpawn' function. */
/* #undef HAVE_RTPSPAWN */

/* Define to 1 if you have the 'sched_get_priority_max' function. */
#define HAVE_SCHED_GET_PRIORITY_MAX 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* Define to 1 if you have the 'sched_rr_get_interval' function. */
/* #undef HAVE_SCHED_RR_GET_INTERVAL */

/* Define to 1 if you have the 'sched_setaffinity' function. */
/* #undef HAVE_SCHED_SETAFFINITY */

/* Define to 1 if you have the 'sched_setparam' function. */
/* #undef HAVE_SCHED_SETPARAM */

/* Define to 1 if you have the 'sched_setscheduler' function. */
/* #undef HAVE_SCHED_SETSCHEDULER */

/* Define to 1 if you have the 'sem_clockwait' function. */
/* #undef HAVE_SEM_CLOCKWAIT */

/* Define to 1 if you have the 'sem_getvalue' function. */
#define HAVE_SEM_GETVALUE 1

/* Define to 1 if you have the 'sem_open' function. */
#define HAVE_SEM_OPEN 1

/* Define to 1 if you have the 'sem_timedwait' function. */
/* #undef HAVE_SEM_TIMEDWAIT */

/* Define to 1 if you have the 'sem_unlink' function. */
#define HAVE_SEM_UNLINK 1

/* Define to 1 if you have the 'sendfile' function. */
#define HAVE_SENDFILE 1

/* Define if you have the 'sendto' function. */
#define HAVE_SENDTO 1

/* Define to 1 if you have the 'setegid' function. */
#define HAVE_SETEGID 1

/* Define to 1 if you have the 'seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the 'setgid' function. */
#define HAVE_SETGID 1

/* Define if you have the 'setgroups' function. */
#define HAVE_SETGROUPS 1

/* Define to 1 if you have the 'sethostname' function. */
#define HAVE_SETHOSTNAME 1

/* Define to 1 if you have the 'setitimer' function. */
#define HAVE_SETITIMER 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the 'setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the 'setns' function. */
/* #undef HAVE_SETNS */

/* Define to 1 if you have the 'setpgid' function. */
#define HAVE_SETPGID 1

/* Define to 1 if you have the 'setpgrp' function. */
#define HAVE_SETPGRP 1

/* Define to 1 if you have the 'setpriority' function. */
#define HAVE_SETPRIORITY 1

/* Define to 1 if you have the 'setregid' function. */
#define HAVE_SETREGID 1

/* Define to 1 if you have the 'setresgid' function. */
/* #undef HAVE_SETRESGID */

/* Define to 1 if you have the 'setresuid' function. */
/* #undef HAVE_SETRESUID */

/* Define to 1 if you have the 'setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the 'setsid' function. */
#define HAVE_SETSID 1

/* Define if you have the 'setsockopt' function. */
#define HAVE_SETSOCKOPT 1

/* Define to 1 if you have the 'setuid' function. */
#define HAVE_SETUID 1

/* Define to 1 if you have the 'setvbuf' function. */
#define HAVE_SETVBUF 1

/* Define to 1 if you have the <shadow.h> header file. */
/* #undef HAVE_SHADOW_H */

/* Define to 1 if you have the 'shm_open' function. */
#define HAVE_SHM_OPEN 1

/* Define to 1 if you have the 'shm_unlink' function. */
#define HAVE_SHM_UNLINK 1

/* Define to 1 if you have the 'shutdown' function. */
#define HAVE_SHUTDOWN 1

/* Define to 1 if you have the 'sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 1 if you have the 'sigaltstack' function. */
#define HAVE_SIGALTSTACK 1

/* Define to 1 if you have the 'sigfillset' function. */
#define HAVE_SIGFILLSET 1

/* Define to 1 if 'si_band' is a member of 'siginfo_t'. */
#define HAVE_SIGINFO_T_SI_BAND 1

/* Define to 1 if you have the 'siginterrupt' function. */
#define HAVE_SIGINTERRUPT 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the 'sigpending' function. */
#define HAVE_SIGPENDING 1

/* Define to 1 if you have the 'sigrelse' function. */
#define HAVE_SIGRELSE 1

/* Define to 1 if you have the 'sigtimedwait' function. */
/* #undef HAVE_SIGTIMEDWAIT */

/* Define to 1 if you have the 'sigwait' function. */
#define HAVE_SIGWAIT 1

/* Define to 1 if you have the 'sigwaitinfo' function. */
/* #undef HAVE_SIGWAITINFO */

/* Define to 1 if you have the 'snprintf' function. */
#define HAVE_SNPRINTF 1

/* struct sockaddr_alg (linux/if_alg.h) */
/* #undef HAVE_SOCKADDR_ALG */

/* Define if sockaddr has sa_len member */
#define HAVE_SOCKADDR_SA_LEN 1

/* struct sockaddr_storage (sys/socket.h) */
#define HAVE_SOCKADDR_STORAGE 1

/* Define if you have the 'socket' function. */
#define HAVE_SOCKET 1

/* Define if you have the 'socketpair' function. */
#define HAVE_SOCKETPAIR 1

/* Define to 1 if the system has the type 'socklen_t'. */
#define HAVE_SOCKLEN_T 1

/* Define to 1 if you have the <spawn.h> header file. */
#define HAVE_SPAWN_H 1

/* Define to 1 if you have the 'splice' function. */
/* #undef HAVE_SPLICE */

/* Define to 1 if the system has the type 'ssize_t'. */
#define HAVE_SSIZE_T 1

/* Define to 1 if you have the 'statvfs' function. */
#define HAVE_STATVFS 1

/* Define if you have struct stat.st_mtim.tv_nsec */
/* #undef HAVE_STAT_TV_NSEC */

/* Define if you have struct stat.st_mtimensec */
#define HAVE_STAT_TV_NSEC2 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Has stdatomic.h with atomic_int and atomic_uintptr_t */
#define HAVE_STD_ATOMIC 1

/* Define to 1 if you have the 'strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the 'strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the <stropts.h> header file. */
/* #undef HAVE_STROPTS_H */

/* Define to 1 if you have the 'strsignal' function. */
#define HAVE_STRSIGNAL 1

/* Define to 1 if 'pw_gecos' is a member of 'struct passwd'. */
#define HAVE_STRUCT_PASSWD_PW_GECOS 1

/* Define to 1 if 'pw_passwd' is a member of 'struct passwd'. */
#define HAVE_STRUCT_PASSWD_PW_PASSWD 1

/* Define to 1 if 'st_birthtime' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_BIRTHTIME 1

/* Define to 1 if 'st_blksize' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1

/* Define to 1 if 'st_blocks' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLOCKS 1

/* Define to 1 if 'st_flags' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_FLAGS 1

/* Define to 1 if 'st_gen' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_GEN 1

/* Define to 1 if 'st_rdev' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_RDEV 1

/* Define to 1 if 'tm_zone' is a member of 'struct tm'. */
#define HAVE_STRUCT_TM_TM_ZONE 1

/* Define if you have the 'symlink' function. */
#define HAVE_SYMLINK 1

/* Define to 1 if you have the 'symlinkat' function. */
#define HAVE_SYMLINKAT 1

/* Define to 1 if you have the 'sync' function. */
#define HAVE_SYNC 1

/* Define to 1 if you have the 'sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the 'sysctlbyname' function. */
#define HAVE_SYSCTLBYNAME 1

/* Define to 1 if you have the <sysexits.h> header file. */
#define HAVE_SYSEXITS_H 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the 'system' function. */
#define HAVE_SYSTEM 1

/* Define to 1 if you have the <sys/audioio.h> header file. */
/* #undef HAVE_SYS_AUDIOIO_H */

/* Define to 1 if you have the <sys/auxv.h> header file. */
/* #undef HAVE_SYS_AUXV_H */

/* Define to 1 if you have the <sys/bsdtty.h> header file. */
/* #undef HAVE_SYS_BSDTTY_H */

/* Define to 1 if you have the <sys/devpoll.h> header file. */
/* #undef HAVE_SYS_DEVPOLL_H */

/* Define to 1 if you have the <sys/dir.h> header file, and it defines 'DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/endian.h> header file. */
#define HAVE_SYS_ENDIAN_H 1

/* Define to 1 if you have the <sys/epoll.h> header file. */
/* #undef HAVE_SYS_EPOLL_H */

/* Define to 1 if you have the <sys/eventfd.h> header file. */
/* #undef HAVE_SYS_EVENTFD_H */

/* Define to 1 if you have the <sys/event.h> header file. */
#define HAVE_SYS_EVENT_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/kern_control.h> header file. */
#define HAVE_SYS_KERN_CONTROL_H 1

/* Define to 1 if you have the <sys/loadavg.h> header file. */
/* #undef HAVE_SYS_LOADAVG_H */

/* Define to 1 if you have the <sys/lock.h> header file. */
#define HAVE_SYS_LOCK_H 1

/* Define to 1 if you have the <sys/memfd.h> header file. */
/* #undef HAVE_SYS_MEMFD_H */

/* Define to 1 if you have the <sys/mkdev.h> header file. */
/* #undef HAVE_SYS_MKDEV_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/modem.h> header file. */
/* #undef HAVE_SYS_MODEM_H */

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines 'DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/pidfd.h> header file. */
/* #undef HAVE_SYS_PIDFD_H */

/* Define to 1 if you have the <sys/poll.h> header file. */
#define HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/random.h> header file. */
#define HAVE_SYS_RANDOM_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/sendfile.h> header file. */
/* #undef HAVE_SYS_SENDFILE_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/soundcard.h> header file. */
/* #undef HAVE_SYS_SOUNDCARD_H */

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syscall.h> header file. */
#define HAVE_SYS_SYSCALL_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#define HAVE_SYS_SYSCTL_H 1

/* Define to 1 if you have the <sys/sysmacros.h> header file. */
/* #undef HAVE_SYS_SYSMACROS_H */

/* Define to 1 if you have the <sys/sys_domain.h> header file. */
#define HAVE_SYS_SYS_DOMAIN_H 1

/* Define to 1 if you have the <sys/termio.h> header file. */
/* #undef HAVE_SYS_TERMIO_H */

/* Define to 1 if you have the <sys/timerfd.h> header file. */
/* #undef HAVE_SYS_TIMERFD_H */

/* Define to 1 if you have the <sys/times.h> header file. */
#define HAVE_SYS_TIMES_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <sys/xattr.h> header file. */
#define HAVE_SYS_XATTR_H 1

/* Define to 1 if you have the 'tcgetpgrp' function. */
#define HAVE_TCGETPGRP 1

/* Define to 1 if you have the 'tcsetpgrp' function. */
#define HAVE_TCSETPGRP 1

/* Define to 1 if you have the 'tempnam' function. */
#define HAVE_TEMPNAM 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the <term.h> header file. */
#define HAVE_TERM_H 1

/* Define to 1 if you have the 'timegm' function. */
#define HAVE_TIMEGM 1

/* Define if you have the 'timerfd_create' function. */
/* #undef HAVE_TIMERFD_CREATE */

/* Define to 1 if you have the 'times' function. */
#define HAVE_TIMES 1

/* Define to 1 if you have the 'tmpfile' function. */
#define HAVE_TMPFILE 1

/* Define to 1 if you have the 'tmpnam' function. */
#define HAVE_TMPNAM 1

/* Define to 1 if you have the 'tmpnam_r' function. */
/* #undef HAVE_TMPNAM_R */

/* Define to 1 if your 'struct tm' has 'tm_zone'. Deprecated, use
   'HAVE_STRUCT_TM_TM_ZONE' instead. */
#define HAVE_TM_ZONE 1

/* Define to 1 if you have the 'truncate' function. */
#define HAVE_TRUNCATE 1

/* Define to 1 if you have the 'ttyname_r' function. */
#define HAVE_TTYNAME_R 1

/* Define to 1 if you don't have 'tm_zone' but do have the external array
   'tzname'. */
/* #undef HAVE_TZNAME */

/* Define to 1 if you have the 'umask' function. */
#define HAVE_UMASK 1

/* Define to 1 if you have the 'uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the 'unlinkat' function. */
#define HAVE_UNLINKAT 1

/* Define to 1 if you have the 'unlockpt' function. */
#define HAVE_UNLOCKPT 1

/* Define to 1 if you have the 'unshare' function. */
/* #undef HAVE_UNSHARE */

/* Define if you have a useable wchar_t type defined in wchar.h; useable means
   wchar_t must be an unsigned type with at least 16 bits. (see
   Include/unicodeobject.h). */
/* #undef HAVE_USABLE_WCHAR_T */

/* Define to 1 if you have the <util.h> header file. */
#define HAVE_UTIL_H 1

/* Define to 1 if you have the 'utimensat' function. */
#define HAVE_UTIMENSAT 1

/* Define to 1 if you have the 'utimes' function. */
#define HAVE_UTIMES 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the <utmp.h> header file. */
#define HAVE_UTMP_H 1

/* Define if you have the 'HAVE_UT_NAMESIZE' constant. */
#define HAVE_UT_NAMESIZE 1

/* Define to 1 if you have the 'uuid_create' function. */
/* #undef HAVE_UUID_CREATE */

/* Define to 1 if you have the 'uuid_enc_be' function. */
/* #undef HAVE_UUID_ENC_BE */

/* Define if uuid_generate_time_safe() exists. */
/* #undef HAVE_UUID_GENERATE_TIME_SAFE */

/* Define if uuid_generate_time_safe() is able to deduce a MAC address. */
/* #undef HAVE_UUID_GENERATE_TIME_SAFE_STABLE_MAC */

/* Define to 1 if you have the <uuid.h> header file. */
/* #undef HAVE_UUID_H */

/* Define to 1 if you have the <uuid/uuid.h> header file. */
#define HAVE_UUID_UUID_H 1

/* Define to 1 if you have the 'vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the 'wait' function. */
#define HAVE_WAIT 1

/* Define to 1 if you have the 'wait3' function. */
#define HAVE_WAIT3 1

/* Define to 1 if you have the 'wait4' function. */
#define HAVE_WAIT4 1

/* Define to 1 if you have the 'waitid' function. */
#define HAVE_WAITID 1

/* Define to 1 if you have the 'waitpid' function. */
#define HAVE_WAITPID 1

/* Define if the compiler provides a wchar.h header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if you have the 'wcscoll' function. */
#define HAVE_WCSCOLL 1

/* Define to 1 if you have the 'wcsftime' function. */
#define HAVE_WCSFTIME 1

/* Define to 1 if you have the 'wcsxfrm' function. */
#define HAVE_WCSXFRM 1

/* Define to 1 if you have the 'wmemcmp' function. */
#define HAVE_WMEMCMP 1

/* Define if tzset() actually switches the local timezone in a meaningful way.
   */
#define HAVE_WORKING_TZSET 1

/* Define to 1 if you have the 'writev' function. */
#define HAVE_WRITEV 1

/* Define to 1 if you have the <zdict.h> header file. */
/* #undef HAVE_ZDICT_H */

/* Define if the zlib library has inflateCopy */
#define HAVE_ZLIB_COPY 1

/* Define to 1 if you have the <zlib.h> header file. */
/* #undef HAVE_ZLIB_H */

/* Define to 1 if you have the <zstd.h> header file. */
/* #undef HAVE_ZSTD_H */

/* Define to 1 if you have the '_getpty' function. */
/* #undef HAVE__GETPTY */

/* Define to 1 if the system has the type '__uint128_t'. */
#define HAVE___UINT128_T 1

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in
   <sysmacros.h>. */
/* #undef MAJOR_IN_SYSMACROS */

/* Define if mvwdelch in curses.h is an expression. */
#define MVWDELCH_IS_EXPRESSION 1

/* Define to the address where bug reports for this package should be sent. */
/* #undef PACKAGE_BUGREPORT */

/* Define to the full name of this package. */
/* #undef PACKAGE_NAME */

/* Define to the full name and version of this package. */
/* #undef PACKAGE_STRING */

/* Define to the one symbol short name of this package. */
/* #undef PACKAGE_TARNAME */

/* Define to the home page for this package. */
/* #undef PACKAGE_URL */

/* Define to the version of this package. */
/* #undef PACKAGE_VERSION */

/* Define if POSIX semaphores aren't enabled on your system */
/* #undef POSIX_SEMAPHORES_NOT_ENABLED */

/* Define if pthread_key_t is compatible with int. */
/* #undef PTHREAD_KEY_T_IS_COMPATIBLE_WITH_INT */

/* Defined if PTHREAD_SCOPE_SYSTEM supported. */
#define PTHREAD_SYSTEM_SCHED_SUPPORTED 1

/* Define as the preferred size in bits of long digits */
/* #undef PYLONG_BITS_IN_DIGIT */

/* enabled builtin hash modules */
#define PY_BUILTIN_HASHLIB_HASHES "md5,sha1,sha2,sha3,blake2"

/* Define if you want to coerce the C locale to a UTF-8 based locale */
#define PY_COERCE_C_LOCALE 1

/* Define to 1 if you have the perf trampoline. */
/* #undef PY_HAVE_PERF_TRAMPOLINE */

/* Define to 1 to build the sqlite module with loadable extensions support. */
/* #undef PY_SQLITE_ENABLE_LOAD_EXTENSION */

/* Define if SQLite was compiled with the serialize API */
#define PY_SQLITE_HAVE_SERIALIZE 1

/* Default cipher suites list for ssl module. 1: Python's preferred selection,
   2: leave OpenSSL defaults untouched, 0: custom string */
#define PY_SSL_DEFAULT_CIPHERS 1

/* Cipher suite string for PY_SSL_DEFAULT_CIPHERS=0 */
/* #undef PY_SSL_DEFAULT_CIPHER_STRING */

/* PEP 11 Support tier (1, 2, 3 or 0 for unsupported) */
#define PY_SUPPORT_TIER 1

/* Define if you want to build an interpreter with many run-time checks. */
/* #undef Py_DEBUG */

/* Defined if Python is built as a shared library. */
/* #undef Py_ENABLE_SHARED */

/* Define if you want to disable the GIL */
/* #undef Py_GIL_DISABLED */

/* Define hash algorithm for str, bytes and memoryview. SipHash24: 1, FNV: 2,
   SipHash13: 3, externally defined: 0 */
/* #undef Py_HASH_ALGORITHM */

/* Define if you want to enable remote debugging support. */
#define Py_REMOTE_DEBUG 1

/* Define if rl_startup_hook takes arguments */
#define Py_RL_STARTUP_HOOK_TAKES_ARGS 1

/* Define if you want to enable internal statistics gathering. */
/* #undef Py_STATS */

/* The version of SunOS/Solaris as reported by `uname -r' without the dot. */
/* #undef Py_SUNOS_VERSION */

/* Define if you want to use tail-calling interpreters in CPython. */
/* #undef Py_TAIL_CALL_INTERP */

/* Define if you want to enable tracing references for debugging purpose */
/* #undef Py_TRACE_REFS */

/* assume C89 semantics that RETSIGTYPE is always void */
#define RETSIGTYPE void

/* Define if setpgrp() must be called as setpgrp(0, 0). */
/* #undef SETPGRP_HAVE_ARG */

/* Define if i>>j for signed int i does not extend the sign bit when i < 0 */
/* #undef SIGNED_RIGHT_SHIFT_ZERO_FILLS */

/* The size of 'double', as computed by sizeof. */
#define SIZEOF_DOUBLE 8

/* The size of 'float', as computed by sizeof. */
#define SIZEOF_FLOAT 4

/* The size of 'fpos_t', as computed by sizeof. */
#define SIZEOF_FPOS_T 8

/* The size of 'int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of 'long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of 'long double', as computed by sizeof. */
#define SIZEOF_LONG_DOUBLE 8

/* The size of 'long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of 'off_t', as computed by sizeof. */
#define SIZEOF_OFF_T 8

/* The size of 'pid_t', as computed by sizeof. */
#define SIZEOF_PID_T 4

/* The size of 'pthread_key_t', as computed by sizeof. */
#define SIZEOF_PTHREAD_KEY_T 8

/* The size of 'pthread_t', as computed by sizeof. */
#define SIZEOF_PTHREAD_T 8

/* The size of 'short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of 'size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 8

/* The size of 'time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of 'uintptr_t', as computed by sizeof. */
#define SIZEOF_UINTPTR_T 8

/* The size of 'void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* The size of 'wchar_t', as computed by sizeof. */
#define SIZEOF_WCHAR_T 4

/* The size of '_Bool', as computed by sizeof. */
#define SIZEOF__BOOL 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/select.h> and <sys/time.h>
   (which you can't on SCO ODT 3.0). */
#define SYS_SELECT_WITH_SYS_TIME 1

/* Custom thread stack size depending on chosen sanitizer runtimes. */
#define THREAD_STACK_SIZE 0x1000000

/* Library needed by timemodule.c: librt may be needed for clock_gettime() */
/* #undef TIMEMODULE_LIB */

/* Define to 1 if your <sys/time.h> declares 'struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define if you want to use computed gotos in ceval.c. */
/* #undef USE_COMPUTED_GOTOS */

/* Enable extensions on AIX, Interix, z/OS.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# define _DARWIN_C_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# define _HPUX_ALT_XOPEN_SOCKET_API 1
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
/* # undef _MINIX */
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# define _NETBSD_SOURCE 1
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
/* # undef _POSIX_SOURCE */
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
/* # undef _POSIX_1_SOURCE */
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex F.  */
#ifndef __STDC_WANT_IEC_60559_EXT__
# define __STDC_WANT_IEC_60559_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex H and ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# define __STDC_WANT_LIB_EXT2__ 1
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
/* # undef _XOPEN_SOURCE */
#endif


/* Define if WINDOW in curses.h offers a field _flags. */
#define WINDOW_HAS_FLAGS 1

/* Define if you want build the _decimal module using a coroutine-local rather
   than a thread-local context */
#define WITH_DECIMAL_CONTEXTVAR 1

/* Define if you want documentation strings in extension modules */
#define WITH_DOC_STRINGS 1

/* Define if you want to compile in DTrace support */
/* #undef WITH_DTRACE */

/* Define if you want to use the new-style (Openstep, Rhapsody, MacOS) dynamic
   linker (dyld) instead of the old-style (NextStep) dynamic linker (rld).
   Dyld is necessary to support frameworks. */
#define WITH_DYLD 1

/* Define to build the readline module against libedit. */
/* #undef WITH_EDITLINE */

/* Define to 1 if libintl is needed for locale functions. */
/* #undef WITH_LIBINTL */

/* Define if you want to compile in mimalloc memory allocator. */
/* #undef WITH_MIMALLOC */

/* Define if you want to produce an OpenStep/Rhapsody framework (shared
   library plus accessory files). */
/* #undef WITH_NEXT_FRAMEWORK */

/* Define if you want to compile in Python-specific mallocs */
#define WITH_PYMALLOC 1

/* Define if you want pymalloc to be disabled when running under valgrind */
/* #undef WITH_VALGRIND */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define if arithmetic is subject to x87-style double rounding issue */
/* #undef X87_DOUBLE_ROUNDING */

/* Define on OpenBSD to activate all library features */
/* #undef _BSD_SOURCE */

/* Define on Darwin to activate all library features */
#define _DARWIN_C_SOURCE 1

/* This must be set to 64 on some systems to enable large file support. */
#define _FILE_OFFSET_BITS 64

/* Define to include mbstate_t for mbrtowc */
/* #undef _INCLUDE__STDC_A1_SOURCE */

/* This must be defined on some systems to enable large file support. */
#define _LARGEFILE_SOURCE 1

/* This must be defined on AIX systems to enable large file support. */
/* #undef _LARGE_FILES */

/* Define on NetBSD to activate all library features */
#define _NETBSD_SOURCE 1

/* Define to activate features from IEEE Stds 1003.1-2008 */
/* #undef _POSIX_C_SOURCE */

/* Define if you have POSIX threads, and your system does not define that. */
/* #undef _POSIX_THREADS */

/* framework name */
#define _PYTHONFRAMEWORK ""

/* Maximum length in bytes of a thread name */
#define _PYTHREAD_NAME_MAXLEN 63

/* Defined if _Complex C type can be used with libffi. */
#define _Py_FFI_SUPPORT_C_COMPLEX 1

/* HACL* library can compile SIMD128 implementations */
/* #undef _Py_HACL_CAN_COMPILE_VEC128 */

/* HACL* library can compile SIMD256 implementations */
/* #undef _Py_HACL_CAN_COMPILE_VEC256 */

/* Thread stack size set by the linker (in bytes). */
/* #undef _Py_LINKER_THREAD_STACK_SIZE */

/* Define to 1 if the machine stack grows down (default); 0 if it grows up. */
#define _Py_STACK_GROWS_DOWN 1

/* Define to force use of thread-safe errno, h_errno, and other functions */
#define _REENTRANT 1

/* Define to 1 if you want to emulate getpid() on WASI */
/* #undef _WASI_EMULATED_GETPID */

/* Define to 1 if you want to emulate process clocks on WASI */
/* #undef _WASI_EMULATED_PROCESS_CLOCKS */

/* Define to 1 if you want to emulate signals on WASI */
/* #undef _WASI_EMULATED_SIGNAL */

/* Define to the level of X/Open that your system supports */
/* #undef _XOPEN_SOURCE */

/* Define to activate Unix95-and-earlier features */
/* #undef _XOPEN_SOURCE_EXTENDED */

/* Define on FreeBSD to activate all library features */
#define __BSD_VISIBLE 1

/* Define to 'long' if <time.h> does not define clock_t. */
/* #undef clock_t */

/* Define to empty if 'const' does not conform to ANSI C. */
/* #undef const */

/* Define as 'int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to 'int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to 'long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define as a signed integer type capable of holding a process identifier. */
/* #undef pid_t */

/* Define to empty if the keyword does not work. */
/* #undef signed */

/* Define as 'unsigned int' if <stddef.h> doesn't define. */
/* #undef size_t */

/* Define to 'int' if <sys/socket.h> does not define. */
/* #undef socklen_t */

/* Define as 'int' if <sys/types.h> doesn't define. */
/* #undef uid_t */


/* Define the macros needed if on a UnixWare 7.x system. */
#if defined(__USLC__) && defined(__SCO_VERSION__)
#define STRICT_SYSV_CURSES /* Don't use ncurses extensions */
#endif

#endif /*Py_PYCONFIG_H*/

""",
        'Modules/config.c': rb"""/* Generated automatically from /private/task/sources/cpython/Modules/config.c.in by makesetup. */
/* Module configuration */

/* !!! !!! !!! This file is edited by the makesetup script !!! !!! !!! */

/* This file contains the table of built-in modules.
   See create_builtin() in import.c. */

#include "Python.h"

#ifdef __cplusplus
extern "C" {
#endif


extern PyObject* PyInit__bisect(void);
extern PyObject* PyInit__heapq(void);
extern PyObject* PyInit__json(void);
extern PyObject* PyInit__random(void);
extern PyObject* PyInit__struct(void);
extern PyObject* PyInit_math(void);
extern PyObject* PyInit_binascii(void);
extern PyObject* PyInit_zlib(void);
extern PyObject* PyInit_fcntl(void);
extern PyObject* PyInit__posixsubprocess(void);
extern PyObject* PyInit_select(void);
extern PyObject* PyInit_unicodedata(void);
extern PyObject* PyInit__ctypes(void);
extern PyObject* PyInit__socket(void);
extern PyObject* PyInit__ssl(void);
extern PyObject* PyInit_pyexpat(void);
extern PyObject* PyInit_resource(void);
extern PyObject* PyInit__scproxy(void);
extern PyObject* PyInit__md5(void);
extern PyObject* PyInit__sha1(void);
extern PyObject* PyInit__sha2(void);
extern PyObject* PyInit__sha3(void);
extern PyObject* PyInit__blake2(void);
extern PyObject* PyInit__hmac(void);
extern PyObject* PyInit_atexit(void);
extern PyObject* PyInit_faulthandler(void);
extern PyObject* PyInit_posix(void);
extern PyObject* PyInit__signal(void);
extern PyObject* PyInit__tracemalloc(void);
extern PyObject* PyInit__suggestions(void);
extern PyObject* PyInit__datetime(void);
extern PyObject* PyInit__codecs(void);
extern PyObject* PyInit__collections(void);
extern PyObject* PyInit_errno(void);
extern PyObject* PyInit__io(void);
extern PyObject* PyInit_itertools(void);
extern PyObject* PyInit__sre(void);
extern PyObject* PyInit__sysconfig(void);
extern PyObject* PyInit__thread(void);
extern PyObject* PyInit_time(void);
extern PyObject* PyInit__types(void);
extern PyObject* PyInit__typing(void);
extern PyObject* PyInit__weakref(void);
extern PyObject* PyInit__abc(void);
extern PyObject* PyInit__functools(void);
extern PyObject* PyInit__locale(void);
extern PyObject* PyInit__opcode(void);
extern PyObject* PyInit__operator(void);
extern PyObject* PyInit__stat(void);
extern PyObject* PyInit__symtable(void);
extern PyObject* PyInit_pwd(void);

/* -- ADDMODULE MARKER 1 -- */

extern PyObject* PyMarshal_Init(void);
extern PyObject* PyInit__imp(void);
extern PyObject* PyInit_gc(void);
extern PyObject* PyInit__ast(void);
extern PyObject* PyInit__tokenize(void);
extern PyObject* PyInit__contextvars(void);
extern PyObject* _PyWarnings_Init(void);
extern PyObject* PyInit__string(void);

struct _inittab _PyImport_Inittab[] = {

    {"_bisect", PyInit__bisect},
    {"_heapq", PyInit__heapq},
    {"_json", PyInit__json},
    {"_random", PyInit__random},
    {"_struct", PyInit__struct},
    {"math", PyInit_math},
    {"binascii", PyInit_binascii},
    {"zlib", PyInit_zlib},
    {"fcntl", PyInit_fcntl},
    {"_posixsubprocess", PyInit__posixsubprocess},
    {"select", PyInit_select},
    {"unicodedata", PyInit_unicodedata},
    {"_ctypes", PyInit__ctypes},
    {"_socket", PyInit__socket},
    {"_ssl", PyInit__ssl},
    {"pyexpat", PyInit_pyexpat},
    {"resource", PyInit_resource},
    {"_scproxy", PyInit__scproxy},
    {"_md5", PyInit__md5},
    {"_sha1", PyInit__sha1},
    {"_sha2", PyInit__sha2},
    {"_sha3", PyInit__sha3},
    {"_blake2", PyInit__blake2},
    {"_hmac", PyInit__hmac},
    {"atexit", PyInit_atexit},
    {"faulthandler", PyInit_faulthandler},
    {"posix", PyInit_posix},
    {"_signal", PyInit__signal},
    {"_tracemalloc", PyInit__tracemalloc},
    {"_suggestions", PyInit__suggestions},
    {"_datetime", PyInit__datetime},
    {"_codecs", PyInit__codecs},
    {"_collections", PyInit__collections},
    {"errno", PyInit_errno},
    {"_io", PyInit__io},
    {"itertools", PyInit_itertools},
    {"_sre", PyInit__sre},
    {"_sysconfig", PyInit__sysconfig},
    {"_thread", PyInit__thread},
    {"time", PyInit_time},
    {"_types", PyInit__types},
    {"_typing", PyInit__typing},
    {"_weakref", PyInit__weakref},
    {"_abc", PyInit__abc},
    {"_functools", PyInit__functools},
    {"_locale", PyInit__locale},
    {"_opcode", PyInit__opcode},
    {"_operator", PyInit__operator},
    {"_stat", PyInit__stat},
    {"_symtable", PyInit__symtable},
    {"pwd", PyInit_pwd},

/* -- ADDMODULE MARKER 2 -- */

    /* This module lives in marshal.c */
    {"marshal", PyMarshal_Init},

    /* This lives in import.c */
    {"_imp", PyInit__imp},

    /* This lives in Python/Python-ast.c */
    {"_ast", PyInit__ast},

    /* This lives in Python/Python-tokenize.c */
    {"_tokenize", PyInit__tokenize},

    /* These entries are here for sys.builtin_module_names */
    {"builtins", NULL},
    {"sys", NULL},

    /* This lives in gcmodule.c */
    {"gc", PyInit_gc},

    /* This lives in Python/_contextvars.c */
    {"_contextvars", PyInit__contextvars},

    /* This lives in _warnings.c */
    {"_warnings", _PyWarnings_Init},

    /* This lives in Objects/unicodeobject.c */
    {"_string", PyInit__string},

    /* Sentinel */
    {0, 0}
};


#ifdef __cplusplus
}
#endif
""",
        'Modules/Setup.local': rb"""# CPython 3.14.7 / macOS 26 ARM64 or x86_64. Not an execution grant.
# 24 optional + 27 bootstrap + 10 intrinsic; no shared extensions.
# /private/task/prefix is replaced only by the fixed private build prefix.
*static*
_bisect _bisectmodule.c
_heapq _heapqmodule.c
_json _json.c
_random _randommodule.c
_struct _struct.c
math mathmodule.c
binascii binascii.c $(MODULE_BINASCII_CFLAGS) /private/task/prefix/lib/libz.a
zlib zlibmodule.c $(MODULE_ZLIB_CFLAGS) /private/task/prefix/lib/libz.a
fcntl fcntlmodule.c
_posixsubprocess _posixsubprocess.c
select selectmodule.c
unicodedata unicodedata.c
# No explicit flags: retain Darwin's SDK ffi flags and system -lffi.
_ctypes _ctypes/_ctypes.c _ctypes/callbacks.c _ctypes/callproc.c _ctypes/stgdict.c _ctypes/cfield.c _ctypes/malloc_closure.c
_socket socketmodule.c
# AX_CHECK_OPENSSL checks the static-only prefix; final operands are explicit.
_ssl _ssl.c $(MODULE__SSL_CFLAGS) /private/task/prefix/lib/libssl.a /private/task/prefix/lib/libcrypto.a
# Retain configured internal Expat and Darwin framework flags.
pyexpat pyexpat.c
resource resource.c
_scproxy _scproxy.c
_md5 md5module.c $(MODULE__MD5_CFLAGS) Modules/_hacl/libHacl_Hash_MD5.a
_sha1 sha1module.c $(MODULE__SHA1_CFLAGS) Modules/_hacl/libHacl_Hash_SHA1.a
_sha2 sha2module.c $(MODULE__SHA2_CFLAGS) Modules/_hacl/libHacl_Hash_SHA2.a
_sha3 sha3module.c $(MODULE__SHA3_CFLAGS) Modules/_hacl/libHacl_Hash_SHA3.a
_blake2 blake2module.c $(MODULE__BLAKE2_CFLAGS) Modules/_hacl/libHacl_Hash_BLAKE2.a
_hmac hmacmodule.c $(MODULE__HMAC_CFLAGS) Modules/_hacl/libHacl_HMAC.a
*disabled*
_asyncio
_bz2
_codecs_cn
_codecs_hk
_codecs_iso2022
_codecs_jp
_codecs_kr
_codecs_tw
_csv
_ctypes_test
_curses
_curses_panel
_dbm
_decimal
_elementtree
_gdbm
_hashlib
_interpchannels
_interpqueues
_interpreters
_lsprof
_lzma
_multibytecodec
_multiprocessing
_pickle
_posixshmem
_queue
_remote_debugging
_sqlite3
_statistics
_testbuffer
_testcapi
_testclinic
_testclinic_limited
_testimportmultiple
_testinternalcapi
_testlimitedcapi
_testmultiphase
_testsinglephase
_tkinter
_uuid
_xxtestfuzz
_zoneinfo
_zstd
array
cmath
grp
mmap
readline
syslog
termios
xxlimited
xxlimited_35
xxsubtype
""",
    }
    return files, Path("/private/task/prefix"), Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")


def mach_o(*, dylib=b"/usr/lib/libSystem.B.dylib", minimum=26 << 16, extra=b"",
           cpu=0x100000C, subtype=0):
    def named(command, header_size, name):
        size = (header_size + len(name) + 1 + 7) & ~7
        head = struct.pack("<III", command, size, header_size)
        return head + b"\0" * (header_size - len(head)) + name + b"\0" * (size - header_size - len(name))

    commands = [named(0xE, 12, b"/usr/lib/dyld"), named(0xC, 24, dylib),
        struct.pack("<IIIIII", 0x32, 24, 1, minimum, 26 << 16, 0),
        struct.pack("<IIQQ", 0x80000028, 24, 0, 0),
        struct.pack("<IIII", 0x1D, 16, 0, 0)]
    if extra:
        commands.append(extra)
    body = b"".join(commands)
    return struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, subtype, 2, len(commands), len(body), 0, 0) + body


def archive_fixture(component="zlib", *, trailer=b"", compression_trailer=b"", body=b"public source\n"):
    prefix, logical = "Fixture-1", "/work/inputs/sources/" + component + "/"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in (prefix, prefix + "/Lib"):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(item)
        item = tarfile.TarInfo(prefix + "/Lib/source with spaces.py")
        item.size, item.mode, item.mtime = len(body), 0o644, 1700000000
        archive.addfile(item, io.BytesIO(body))
    raw = buffer.getvalue() + trailer
    compressed = (lzma.compress(raw) if component == "cpython" else gzip.compress(raw, mtime=0)) + compression_trailer
    source = SimpleNamespace(component=component, size=len(compressed), sha256=BUILD.digest(compressed), original_prefix=logical)
    rows = {"Lib/source with spaces.py": {"path": logical + "Lib/source with spaces.py", "size": len(body),
                                            "sha256": BUILD.digest(body), "mode": 0o644}}
    provenance = {"archiveRoot": prefix, "archive": {"size": len(compressed), "sha256": source.sha256},
        "decodedTar": {"size": len(raw), "sha256": BUILD.digest(raw)},
        "directories": [{"path": logical.rstrip("/")}, {"path": logical + "Lib"}],
        "modeProjection": {"directories": {str(0o755): 0o755}, "files": {str(0o644): 0o644}}}
    return source, compressed, rows, provenance


def parser_instance(path, source, rows, provenance):
    instance = BUILD.Build.__new__(BUILD.Build)  # No native host/owner acquisition.
    instance.private = path
    (path / "archives").mkdir(mode=0o700)
    (path / "sources").mkdir(mode=0o700)
    instance.check = lambda: None
    instance.deadline = time.monotonic() + 10
    instance.source_rows = {source.component: rows}
    instance.source_trees = {}
    instance.provenance = {source.component: provenance}
    return instance


class MacPythonSourceBuildTests(unittest.TestCase):
    def test_configuration_keeps_darwin_ffi_scproxy_static_archives_and_generated_names(self):
        for target in (BUILD.ARM_TARGET, BUILD.INTEL_TARGET):
            for suffix, multiarch in ((".exe", "darwin"), ("", "")):
                files, prefix, sdk = make_configuration(suffix, multiarch, target)
                result = BUILD.python_configuration(files, prefix, sdk, "/Apple/clang", "/chosen/python3", target)
                self.assertEqual(result["executable"], "python" + suffix)
                self.assertEqual(result["generated"], ["_sysconfigdata__darwin_" + multiarch + ".py",
                    "_sysconfig_vars__darwin_" + multiarch + ".json", "build-details.json"])
                self.assertEqual(len(result["builtins"]), 61)
            other = BUILD.INTEL_TARGET if target == BUILD.ARM_TARGET else BUILD.ARM_TARGET
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.python_configuration(files, prefix, sdk, "/Apple/clang", "/chosen/python3", other)
        files, prefix, sdk = make_configuration()
        mutations = [
            ("Makefile", b"BUILDEXE=.exe", b"BUILDEXE=/other/python"),
            ("Makefile", b"MODSHARED_NAMES=", b"MODSHARED_NAMES=_ssl"),
            ("Makefile", b"-DUSING_APPLE_OS_LIBFFI=1", b"-DWRONG_FFI=1"),
            ("Makefile", b"-fno-strict-overflow -I", b"-fstrict-overflow -I"),
            ("Makefile", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl -lprivate"),
            ("Makefile", b"MACOSX_DEPLOYMENT_TARGET=26.0", b"MACOSX_DEPLOYMENT_TARGET=15.0"),
            ("Makefile", b"-lm $(LIBEXPAT_A)", b"-lexpat"),
            ("Makefile", b"-framework SystemConfiguration", b"-framework Unselected"),
            ("Makefile", b"PYTHON_FOR_REGEN?=/chosen/python3", b"PYTHON_FOR_REGEN?=python3"),
            ("pyconfig.h", b"#define HAVE_FFI_PREP_CIF_VAR 1", b"/* feature absent */"),
            ("Modules/Setup.local", b"/lib/libssl.a", b"/lib/libssl.dylib"),
            ("Modules/Setup.local", b"_ctypes/malloc_closure.c", b""),
        ]
        for name, old, new in mutations:
            with self.subTest(name=name, mutation=old):
                changed = {**files, name: files[name].replace(old, new)}
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration(changed, prefix, sdk, "/Apple/clang", "/chosen/python3")

        # All configuration predicates are exercised on the source-derived
        # native checkpoint, not a fixture manufactured from BUILD constants.
        observed, prefix, sdk = observed_arm_configuration()
        expected = BUILD.python_configuration(observed, prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        self.assertEqual(expected["executable"], "python.exe")
        self.assertEqual(expected["generated"], ["_sysconfigdata__darwin_darwin.py",
                                              "_sysconfig_vars__darwin_darwin.json", "build-details.json"])
        self.assertEqual(len(expected["builtins"]), 61)
        self.assertEqual(len(set(expected["builtins"])), 61)
        make = observed["Makefile"]
        # Full native inputs, not a queried-line projection: the old raw CC
        # matcher sees three rows, two of which are genuine upstream recipes.
        self.assertEqual({name: (len(body), hashlib.sha256(body).hexdigest()) for name, body in observed.items()},
                         {'Makefile': (169157, '466f661314c37c7dd60a9fc045f69b0f33d640d2c6fef55e9c42194be74316b1'), 'pyconfig.h': (61493, '9c567e7631b61240ec54ad6c4c342e59cabbf5881b8b441c13041102aaa703c3'), 'Modules/config.c': (5217, 'c2934babf5569ea22f0c4631ee6f26e1acf9daed64fbe150fd0685c0cd3dd620'), 'Modules/Setup.local': (2169, '52dc051aae4aa3ab4c41125d55747609407a057377f5bf1c8f9cab1a0e8bc641')})
        self.assertEqual(len(make.splitlines()), 3696)
        self.assertEqual(sum(line.lstrip(b" \t").startswith(b"CC=") for line in make.splitlines()), 3)
        contexts = ((b'Include/pydtrace_probes.h: $(srcdir)/Include/pydtrace.d\n\t$(MKDIR_P) Include\n', b'\tCC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -h -s $(srcdir)/Include/pydtrace.d\n\t: sed in-place edit with POSIX-only tools\n\tsed \'s/PYTHON_/PyDTrace_/\' $@ > $@.tmp\n\tmv $@.tmp $@\n'), (b'Python/pydtrace.o: $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)\n', b'\tCC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -G -s $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)\n'))
        for prefix_bytes, command in contexts:
            block = prefix_bytes + command
            self.assertEqual(make.count(block), 1)
            cases = {
                "duplicate-block": make + b"\n" + block,
                "changed-rule": make.replace(prefix_bytes, prefix_bytes.replace(b": ", b": unselected ", 1), 1),
                "changed-command": make.replace(command, command.replace(b"$(DFLAGS)", b"$(DFLAGS) -unselected", 1), 1),
                "orphaned-command": make.replace(prefix_bytes, b"", 1),
                "moved-command": make.replace(command, b"", 1) + b"\n" + command,
                "continued-assignment": make.replace(prefix_bytes, b"UNSELECTED = continued\\\n" + prefix_bytes, 1),
            }
            for mutation, changed_make in cases.items():
                with self.subTest(recipe=prefix_bytes, mutation=mutation), self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration({**observed, "Makefile": changed_make}, prefix, sdk,
                                               "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        # The full first upstream rule includes its sed/mv tail. A changed
        # tail must not grant the otherwise-identical CC recipe exemption.
        tail = b"\tmv $@.tmp $@\n"
        self.assertEqual(make.count(tail), 1)
        with self.subTest(mutation="changed-first-rule-tail"), self.assertRaisesRegex(BUILD.BuildRefused, "make-assignment-missing-or-repeated"):
            BUILD.python_configuration({**observed, "Makefile": make.replace(tail, b"\tmv $@.tmp $@.unselected\n", 1)}, prefix, sdk,
                                       "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        for custom in (b".RECIPEPREFIX = >\n", b"override .RECIPEPREFIX := !\n", b"# .RECIPEPREFIX customization\n"):
            with self.subTest(recipe_prefix=custom), self.assertRaisesRegex(BUILD.BuildRefused, "make-assignment-missing-or-repeated"):
                BUILD.python_configuration({**observed, "Makefile": make + custom}, prefix, sdk,
                                           "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        self.assertEqual(make.count(b"PYTHON_FOR_REGEN?=/chosen/python3\n"), 1)
        self.assertEqual(BUILD.make_value(make, "PYTHON_FOR_REGEN"), "/chosen/python3")
        self.assertEqual(BUILD.make_value(make, "CC"), "/Apple/clang")
        self.assertEqual(BUILD.make_value(make, "CONFIGURE_CPPFLAGS"), "")
        original_regen = next(line for line in make.splitlines(keepends=True) if line.startswith(b"PYTHON_FOR_REGEN"))
        original_cc = next(line for line in make.splitlines(keepends=True) if line.startswith(b"CC" ) and line[2:3] in (b"=", b" ", b"\t"))
        for key, original, value, required_operator in (
                (b"PYTHON_FOR_REGEN", original_regen, b"/chosen/python3", b"?="),
                (b"CC", original_cc, b"/Apple/clang", b"=")):
            for operator in (b"=", b"?=", b":=", b"::=", b":::=", b"+=", b"!=", b"??="):
                declaration = key + operator + value + b"\n"
                with self.subTest(key=key, duplicate_operator=operator), self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration({**observed, "Makefile": make + declaration}, prefix, sdk,
                                               "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
                if operator != required_operator:
                    with self.subTest(key=key, replacement_operator=operator), self.assertRaises(BUILD.BuildRefused):
                        BUILD.python_configuration({**observed, "Makefile": make.replace(original, declaration)}, prefix, sdk,
                                                   "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            for modifier in (b" ", b"\t", b"override ", b"export ", b"private ", b"override export "):
                declaration = modifier + key + required_operator + value + b"\n"
                for changed in (make + declaration, make.replace(original, declaration)):
                    with self.subTest(key=key, modifier=modifier), self.assertRaises(BUILD.BuildRefused):
                        BUILD.python_configuration({**observed, "Makefile": changed}, prefix, sdk,
                                                   "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            for declaration in (b"define " + key + b"\n" + value + b"\nendef\n",
                                b"override define " + key + b" :=\n" + value + b"\nendef\n"):
                with self.subTest(key=key, definition=True), self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration({**observed, "Makefile": make + declaration}, prefix, sdk,
                                               "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            with self.subTest(key=key, missing=True), self.assertRaises(BUILD.BuildRefused):
                BUILD.python_configuration({**observed, "Makefile": make.replace(original, b"")}, prefix, sdk,
                                           "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.python_configuration({**observed, "Makefile": make.replace(original_regen, b"PYTHON_FOR_REGEN?=python3\n")},
                                       prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.python_configuration(observed, prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.INTEL_TARGET)
        # Conditional Make syntax is not authority to inherit a different tool.
        source = (ROOT / "desktop/tools/macos_cpython_source_build.py").read_text()
        prepare = source.split("    def prepare(self):", 1)[1].split("\n    def sources(", 1)[0]
        build = source.split("    def build_python(self):", 1)[1].split("\n    def project(", 1)[0]
        self.assertIn('CONFIG_SHELL=self.shell, PYTHON_FOR_REGEN=self.orchestrator,', prepare)
        self.assertIn('self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",', prepare)
        self.assertNotIn("os.environ", prepare)
        for name in ("MAKEFLAGS", "MAKEFILES", "MFLAGS"):
            self.assertNotIn(name, prepare + build)
        self.assertIn('make_args = [self.make, "-j2", "PYTHON_FOR_REGEN=" + self.orchestrator,', build)
        self.assertIn('"PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B"]', build)
        self.assertEqual(build.count('[*make_args,'), 2)
        self.assertIn('environment = {**self.environment, **self.orchestration_config,', build)
        self.assertNotIn('"-e"', build)

    def test_macho_refuses_foreign_deployment_loader_injection_and_truncation(self):
        self.assertEqual(PROBE.macho(mach_o())["architecture"], "arm64")
        for target, machine, cpu, subtype in ((BUILD.ARM_TARGET, "arm64", 0x100000C, 0),
                                              (BUILD.INTEL_TARGET, "x86_64", 0x1000007, 3)):
            options = {"cpu": cpu, "subtype": subtype}
            native = mach_o(**options)
            self.assertEqual(PROBE.macho(native, target)["architecture"], machine)
            foreign = mach_o(cpu=0x1000007, subtype=3) if target == BUILD.ARM_TARGET else mach_o()
            for body in (foreign, mach_o(cpu=cpu, subtype=subtype + 1),
                         mach_o(**options, minimum=25 << 16), mach_o(**options, dylib=b"@rpath/libssl.dylib"),
                         mach_o(**options, extra=struct.pack("<IIQ", 0x8000001C, 16, 0)), native[:-1],
                         b"\xca\xfe\xba\xbe" + native[4:]):
                with self.subTest(target=target, prefix=body[:12]), self.assertRaises(PROBE.ProbeRefused):
                    PROBE.macho(body, target)

        # Provider-only Go12 policy uses the existing load-table parser; old
        # CPython/Seal26 above is unchanged. These are tiny inert headers.
        seal_name, macho_name = "_mrk_provider_macho_data", "_mrk_provider_load_table_data"
        self.assertNotIn(seal_name, sys.modules)
        self.assertNotIn(macho_name, sys.modules)
        seal = load(seal_name, "macos_github_seal_build.py")
        parser = load(macho_name, "macos_cpython_orchestrator.py")
        try:
            def string_command(command, text):
                raw = text.encode("ascii") + b"\0"
                offset = 24 if command == 0xC else 12
                size = (offset + len(raw) + 7) // 8 * 8
                return struct.pack("<III", command, size, offset) + b"\0" * (offset - 12) + raw + b"\0" * (size - offset - len(raw))
            def provider_header(target, *, minimum=12 << 16, loads=None, extra=b"", signed=None):
                cpu, subtype = seal.TARGETS[target][3:]
                commands = [struct.pack("<6I", 0x32, 24, 1, minimum, 12 << 16, 0),
                            string_command(0xE, "/usr/lib/dyld")]
                commands.extend(string_command(0xC, name) for name in (seal.PROVIDER_LOADS if loads is None else loads))
                if extra:
                    commands.append(extra)
                if signed is None:
                    signed = target == "aarch64-apple-darwin"
                if signed:
                    start = 32 + sum(map(len, commands)) + 16
                    commands.append(struct.pack("<4I", 0x1D, 16, start, 8))
                table = b"".join(commands)
                return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, len(commands), len(table), 0, 0) + table + (b"signature"[:8] if signed else b"")
            for target in seal.PROVIDER_PINS:
                body = provider_header(target)
                got = seal.provider_macho_data(body, len(body), target, parser)
                self.assertEqual(got["minimumMacOS"], "12.0")
                self.assertEqual(got["sdk"], "12.0")
                self.assertEqual(tuple(got["loadDylibs"]), seal.PROVIDER_LOADS)
                self.assertEqual(got["GoAdHocSignatureCommand"], target == "aarch64-apple-darwin")
                self.assertIs(got["DeveloperIdQualified"], False)
                other = next(name for name in seal.PROVIDER_PINS if name != target)
                bad = [provider_header(other), provider_header(target, minimum=26 << 16),
                       provider_header(target, loads=seal.PROVIDER_LOADS[:-1]),
                       provider_header(target, loads=(*seal.PROVIDER_LOADS, seal.PROVIDER_LOADS[0])),
                       provider_header(target, loads=("@rpath/foreign.dylib", *seal.PROVIDER_LOADS[1:])),
                       provider_header(target, signed=target != "aarch64-apple-darwin"),
                       provider_header(target, extra=struct.pack("<IIQ", 0x8000001C, 16, 0)),
                       b"\xca\xfe\xba\xbe" + body[4:], body[:31]]
                for changed in bad:
                    with self.subTest(provider=target, mutated=changed[:16]), self.assertRaises(ValueError):
                        seal.provider_macho_data(changed, len(changed), target, parser)
                with self.assertRaises(ValueError):
                    seal.provider_macho_data(body[:-1], len(body) - 1, target, parser)
                # Provider12 acceptance is not permission for the old26 role.
                with self.assertRaises(PROBE.ProbeRefused):
                    PROBE.macho(body, target)
        finally:
            self.assertIs(sys.modules.pop(macho_name), parser)
            self.assertIs(sys.modules.pop(seal_name), seal)

    def test_paired_native_host_and_report_data_do_not_cross_target_or_translation(self):
        # These are scalar observations only: no ctypes/sysctl/process or
        # simulated native receipt is executed or admitted by this DATA test.
        for target, machine, openssl in ((BUILD.ARM_TARGET, "arm64", "darwin64-arm64-cc"),
                                         (BUILD.INTEL_TARGET, "x86_64", "darwin64-x86_64-cc")):
            host = {"sysname": "Darwin", "machine": machine, "returned": 0,
                    "observed_errno": errno.EACCES, "length": 4, "translated": 0}
            self.assertTrue(PROBE.native_host_data(target, **host))  # errno ignored on success.
            absent = {**host, "returned": -1, "observed_errno": errno.ENOENT,
                      "length": None, "translated": None}
            self.assertTrue(PROBE.native_host_data(target, **absent))
            self.assertTrue(PROBE.native_host_data(target, **{**absent, "length": 99, "translated": 1}))
            for change in ({"translated": 1}, {"translated": True}, {"length": 8}, {"length": True},
                           {"returned": True}, {"returned": 1}, {"returned": -1, "observed_errno": errno.EACCES},
                           {"returned": -1, "observed_errno": True}, {"sysname": "Linux"},
                           {"machine": "x86_64" if machine == "arm64" else "arm64"}):
                with self.subTest(target=target, change=change):
                    self.assertFalse(PROBE.native_host_data(target, **{**host, **change}))
            profile = BUILD.target_profile(target)
            workflow_ref = BUILD.REPOSITORY + "/" + profile["workflow"] + "@" + profile["reference"]
            self.assertEqual(BUILD.target_for_route(workflow_ref, profile["reference"]), target)
            self.assertEqual(BUILD.openssl_configuration(target), (openssl, *BUILD.OPENSSL_CONFIGURE[1:]))
            other = BUILD.INTEL_TARGET if target == BUILD.ARM_TARGET else BUILD.ARM_TARGET
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.target_for_route(workflow_ref, BUILD.target_profile(other)["reference"])
            context = {"target": target, "fixture": "DATA only"}
            self.assertEqual(PROBE.decode_context(BUILD.canonical(context), target), context)
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-probe-context-target$"):
                PROBE.decode_context(BUILD.canonical(context), other)
            report = {"schemaVersion": 1, "target": target, "role": "network",
                      "result": {"nativeHost": host, "errno": errno.EPERM}}
            self.assertEqual(BUILD.probe_result(BUILD.canonical(report), "network", target, PROBE), report["result"])
            for changed in ({**report, "target": other}, {**report, "role": "loader"},
                            {**report, "schemaVersion": True},
                            {**report, "result": {"nativeHost": {**host, "translated": 1}}},
                            {**report, "result": {"nativeHost": {**host, "extra": 0}}}):
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.probe_result(BUILD.canonical(changed), "network", target, PROBE)
        for unknown in ("arm64-apple-darwin", "x86_64-unknown-linux-gnu", True, None):
            self.assertFalse(PROBE.native_host_data(unknown, **host))
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.target_profile(unknown)
            context = {"schemaVersion": 1, "target": unknown, "payload": None, "checkout": None,
                       "builtins": [], "files": [], "sourceFiles": {}, "scratch": None, "sourceCommit": ""}
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^probe-target$"):
                PROBE.configuration(context)  # Refuses before any filesystem access.

    def test_inventory_does_not_admit_aliases_modes_or_unbound_shapes(self):
        source = SimpleNamespace(original_prefix="/work/inputs/sources/cpython/")
        row = {"path": source.original_prefix + "Lib/source with spaces.py", "size": 1,
               "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o644}
        self.assertEqual(list(BUILD.inventory(BUILD.canonical({"files": [row]}), source)), ["Lib/source with spaces.py"])
        bad = [[{**row, "path": source.original_prefix + "../escape"}], [{**row, "mode": 0o777}],
               [{**row, "size": True}], [row, row], [row, {**row, "path": row["path"].upper()}]]
        for rows in bad:
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.inventory(BUILD.canonical({"files": rows}), source)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.decode(b'{"files":[],"files":[]}')


        # The complete native object table, not a projection of a few accepted rows.
        prefix = Path("/private/test/prefix")
        build = Path("/private/test/build/cpython")
        sdk = Path("/Apple/SDK/MacOSX26.sdk")
        body = (b"# Path: /private/test/build/cpython/python.exe\n# Arch: arm64\n# Object files:\n"
                + NATIVE_LINK_MAP_OBJECTS + b"# Sections:\n# Address\tSize\tSegment\tSection\n"
                + b"# Symbols:\n0x0\t0x2\t[1] literal string: \x80\xff\n")
        objects, incorporated = BUILD.link_map_objects(body, prefix, build, sdk)
        self.assertEqual(len(objects), 1159)
        self.assertEqual(objects[0], "linker synthesized")
        self.assertEqual(incorporated, ["cpython", "expat", "hacl", "openssl", "zlib"])
        expected_interfaces = NATIVE_LINK_MAP_SDK_INTERFACES
        self.assertEqual(BUILD.SDK_INTERFACE_PATHS, expected_interfaces)
        self.assertEqual({name[len(str(sdk)) + 1:] for name in objects if name.startswith(str(sdk) + "/")},
                         set(expected_interfaces))
        self.assertEqual(sum(name.startswith(str(sdk) + "/") for name in objects), 18)
        caller = BUILD.Build.__new__(BUILD.Build)
        caller.private, caller.python_build, caller.sdk = Path("/private/test"), build, sdk
        caller.evidence, caller.notice_evidence = {"python-link.map": body}, {}
        BUILD.Build.notices(caller)
        notice = BUILD.decode(caller.evidence["notices.json"])
        self.assertIs(caller.evidence["python-link.map"], body)
        self.assertEqual(notice["linkMapSha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(notice["objects"], objects)
        self.assertEqual(notice["incorporated"], incorporated)

        first = NATIVE_LINK_MAP_OBJECTS.split(b"\n", 1)[0]
        self.assertEqual(NATIVE_LINK_MAP_OBJECTS.count(b"linker synthesized"), 1)
        malformed = (
            body.replace(b"# Object files:\n", b"# Not object files:\n", 1),
            body.replace(b"# Sections:\n", b"# Not sections:\n", 1),
            b"# Object files:\n" + body,
            body + b"# Sections:\n",
            b"# Sections:\n# Object files:\n" + NATIVE_LINK_MAP_OBJECTS,
            body.replace(b"linker synthesized", b"linker \xffsynthesized", 1),
            body.replace(first + b"\n", first + b"\r\n", 1),
            body.replace(first + b"\n", first + b"\0\n", 1),
            body.replace(first + b"\n", b"", 1),
            body.replace(first + b"\n", first + b"\n" + first + b"\n", 1),
        )
        for value in malformed:
            with self.subTest(map_shape=hashlib.sha256(value).hexdigest()):
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.link_map_objects(value, prefix, build, sdk)

        def small_map(names):
            rows = ["linker synthesized", *names]
            return (b"# Object files:\n" + "".join(f"[{i:3}] {name}\n" for i, name in enumerate(rows)).encode()
                    + b"# Sections:\n# Symbols:\n\x80")

        native_names = ["Programs/python.o", str(prefix / "lib/libssl.a(ssl.o)"),
                        str(prefix / "lib/libz.a(adler32.o)"), "Modules/_hacl/hash.o", "Modules/expat/xmlparse.o"]
        for interface in expected_interfaces:
            self.assertEqual(BUILD.link_map_objects(small_map([*native_names, str(sdk / interface)]),
                                                   prefix, build, sdk)[1], incorporated)
        foreign = (str(sdk / "usr/lib/unknown.tbd"), str(Path("/ForeignSDK") / expected_interfaces[0]),
                   expected_interfaces[0], str(prefix / "lib/libSystem.tbd"),
                   str(sdk) + "/usr/lib/../lib/libSystem.tbd",
                   str(prefix / "lib/libcompiler_rt.a(runtime.o)"))
        for name in foreign:
            with self.subTest(foreign_object=name):
                with self.assertRaisesRegex(BUILD.BuildRefused, "native-unaccounted-static-object"):
                    BUILD.link_map_objects(small_map([*native_names, name]), prefix, build, sdk)
        with self.assertRaisesRegex(BUILD.BuildRefused, "native-incorporation-roster"):
            BUILD.link_map_objects(small_map(native_names[:-1]), prefix, build, sdk)
        with self.assertRaisesRegex(BUILD.BuildRefused, "native-link-map-bound"):
            BUILD.link_map_objects(b"x" * (8 * BUILD.MIB + 1), prefix, build, sdk)

    def test_original_result_deadline_and_finality_are_not_success_defaults(self):
        self.assertEqual(BUILD.remaining(10.9, 5.2, 9), 5)
        for deadline, now in ((10.0, 10.0), (10.0, 9.1), (float("nan"), 1)):
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.remaining(deadline, now)
        argv = ["fixed", "argument"]
        self.assertTrue(BUILD.original_result(subprocess.CompletedProcess(argv, 0, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, False, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, 0, "", b""), argv))
        good = dict(failure=None, entered=2, returned=2, ledger={"complete": True, "fatal": False, "contained": True},
                    handlers="RESTORED", scratch_retired=True, data_finality=True)
        self.assertTrue(BUILD.public_eligible(**good))
        for changes in (dict(failure={"type": "earlier-failure"}), dict(returned=1), dict(entered=True),
                        dict(handlers="UNKNOWN"), dict(scratch_retired=False), dict(data_finality=False),
                        dict(ledger={"complete": 1, "fatal": False, "contained": True}),
                        dict(ledger={"complete": True, "fatal": False, "contained": None})):
            self.assertFalse(BUILD.public_eligible(**{**good, **changes}))
        state, closes, original = BUILD.DataFinality(), [], object()
        with self.assertRaises(ValueError):
            with state.acquiring(lambda: original, closes.append) as captured:
                self.assertIs(captured, original)
                self.assertFalse(state.known)
                raise ValueError("known failed read")
        self.assertTrue(state.known)
        self.assertEqual(closes, [original])

        def ambiguous_close(captured):
            self.assertIs(captured, original)
            raise OSError("injected original close failure")

        with self.assertRaises(OSError):
            with state.acquiring(lambda: original, ambiguous_close):
                pass
        state.close(lambda: closes.append("unrelated-close"))
        self.assertFalse(state.known)  # A later successful close cannot repair it.
        self.assertFalse(BUILD.public_eligible(**{**good, "data_finality": state.known}))
        lost = BUILD.DataFinality()

        def constructor_result_loss():
            self.assertFalse(lost.known)  # Armed before constructor dispatch.
            raise OSError("injected acquisition result loss")

        with self.assertRaises(OSError):
            with lost.acquiring(constructor_result_loss, closes.append):
                self.fail("unreturned acquisition entered body")
        with lost.acquiring(lambda: original, closes.append):
            pass
        self.assertFalse(lost.known)  # No repair by an independent acquisition.
        self.assertTrue(BUILD.DATA.known)  # Faults used separate inert DATA state.


        # Exercise the actual probe boundary without signals, threads, processes,
        # filesystem work or importing the native core owner. This inert scope
        # models cancellation.py CleanupScope's cited first_primary contract:
        # incoming primary survives; a normal cancelled exit rechecks after
        # restoration; cleanup faults poison the verdict even with a primary.
        class ProcessError(Exception):
            def __init__(self, **changes):
                super().__init__("inert original timeout")
                self.dispatched = self.contained = self.cleanup_complete = True
                self.fatal = False
                self.__dict__.update(changes)

        class FirstPrimaryScope:
            def __init__(self, guard, verdict, events, *, exit_error=None,
                         cleanup_error=None, handlers="RESTORED", suppress=False):
                self.guard, self.verdict, self.events = guard, verdict, events
                self.exit_error, self.cleanup_error = exit_error, cleanup_error
                self.handlers, self.suppress = handlers, suppress
                self.claimed, self.primary, self.exits = False, None, []

            def __enter__(self):
                self.events.append("enter")
                return self

            def __exit__(self, kind, error, traceback):
                self.exits.append(error)
                if self.claimed:
                    return False
                self.claimed, self.primary = True, error
                self.events.append("cleanup")
                if self.cleanup_error is not None:
                    self.verdict.fatal = True
                    self.verdict.cleanup_complete = False
                self.events.append("restore")
                self.guard.handler_state = self.handlers
                if self.exit_error is not None:
                    raise self.exit_error
                if self.cleanup_error is not None and error is None:
                    raise self.cleanup_error
                if error is not None:
                    return self.suppress
                if self.guard.cancelled:
                    raise KeyboardInterrupt("inert post-restore cancellation check")
                return False

        def boundary_case(raised, *, kind="cancellation", cancelled=True,
                          begin_error=None, ledger=None, sent=None, errors=None,
                          invoke_fixed=None, **scope_options):
            verdict = SimpleNamespace(complete=True, fatal=False, contained=True,
                                      cleanup_complete=True, commands=1, command_dispatched=True)
            verdict.__dict__.update(ledger or {})
            guard = SimpleNamespace(cancelled=cancelled, handler_state="ACTIVE",
                                    lifetime_ledger=SimpleNamespace(verdict=lambda: verdict))
            events = []
            scope = FirstPrimaryScope(guard, verdict, events, **scope_options)

            def begin():
                events.append("begin")
                if begin_error is not None:
                    raise begin_error

            def invoke():
                events.append("invoke")
                if invoke_fixed is not None:
                    return invoke_fixed(guard)
                if raised is not None:
                    raise raised

            def observe():
                return PROBE._negative_lifecycle(kind, guard, scope, begin, invoke, ProcessError,
                                                 [True] if sent is None else sent,
                                                 [] if errors is None else errors)

            return observe, scope, verdict, events

        interruption = KeyboardInterrupt("inert original interruption")
        observe, scope, verdict, events = boundary_case(interruption)
        outcome, returned = observe()
        self.assertEqual(outcome, "original-interruption")
        self.assertIs(returned, verdict)
        self.assertIs(scope.primary, interruption)
        self.assertEqual(scope.exits, [interruption, interruption])
        self.assertEqual(events, ["enter", "begin", "invoke", "cleanup", "restore"])
        self.assertEqual(scope.guard.handler_state, "RESTORED")

        timeout = ProcessError()
        observe, scope, verdict, events = boundary_case(timeout, kind="timeout", cancelled=False, sent=[])
        self.assertEqual(observe(), ("typed-timeout", verdict))
        self.assertEqual(scope.exits, [None, None])
        self.assertEqual(events, ["enter", "begin", "invoke", "cleanup", "restore"])

        # The actual fixed invocation gives the existing native owner its full
        # 12s startup+target allowance. This is not a new endpoint at readiness,
        # a retry, or permission to pass the observed Intel pre-dispatch timeout.
        calls = []
        executable = "/inert payload/python/bin/python3"
        scratch = Path("/inert scratch")
        ready = scratch / "timeout.ready"
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LANG": "C"}

        def record_original(argv, **options):
            calls.append((argv, options))
            if isinstance(response, BaseException):
                raise response
            return response

        original_owner = SimpleNamespace(run_owned=record_original)

        def invoke_fixed(guard):
            return PROBE._invoke_lifecycle_original(original_owner, executable, ready,
                                                    environment, scratch, guard)

        for response, refusal in (
                (ProcessError(dispatched=False), "native-timeout-lifetime"),
                (ProcessError(), None),
                (object(), "native-lifecycle-negative-returned")):
            calls.clear()
            observe, scope, verdict, events = boundary_case(
                None, kind="timeout", cancelled=False, sent=[], invoke_fixed=invoke_fixed)
            if refusal is None:
                self.assertEqual(observe(), ("typed-timeout", verdict))
            else:
                with self.assertRaisesRegex(PROBE.ProbeRefused, "^" + refusal + "$"):
                    observe()
            self.assertEqual(len(calls), 1)
            argv, options = calls[0]
            self.assertEqual(argv, [executable, "-I", "-S", "-B", "-c", PROBE.CHILD, str(ready)])
            self.assertEqual(set(options), {"environ", "cwd", "timeout", "capture", "text",
                                            "output_limit", "cancellation"})
            self.assertIs(options["environ"], environment)
            self.assertIs(options["cwd"], scratch)
            self.assertIs(options["cancellation"], scope.guard)
            self.assertIs(type(options["timeout"]), int)
            self.assertEqual(options["timeout"], 12)
            self.assertIs(options["capture"], True)
            self.assertIs(options["text"], False)
            self.assertEqual(options["output_limit"], 4096)
            self.assertEqual(events, ["enter", "begin", "invoke", "cleanup", "restore"])
            self.assertEqual(scope.guard.handler_state, "RESTORED")
        self.assertIn("time.sleep(30)", PROBE.CHILD)  # Not a normal-return probe.

        # An interruption outside the actual run is never adopted as its result.
        for where in ("begin_error", "exit_error"):
            foreign = KeyboardInterrupt("inert foreign interruption")
            observe, scope, _, events = boundary_case(interruption, **{where: foreign})
            with self.assertRaises(KeyboardInterrupt) as caught:
                observe()
            self.assertIs(caught.exception, foreign)
            self.assertIs(scope.exits[-1], foreign)
            self.assertEqual(events.count("cleanup"), 1)
            self.assertEqual(events.count("restore"), 1)
            self.assertEqual(events.count("invoke"), int(where != "begin_error"))

        for options in ({"kind": "timeout"}, {"cancelled": False}):
            observe, _, _, _ = boundary_case(interruption, **options)
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-cancellation-kind$"):
                observe()

        for changes in ({"dispatched": False}, {"contained": False},
                        {"cleanup_complete": False}, {"fatal": True}):
            observe, _, _, _ = boundary_case(ProcessError(**changes), kind="timeout", cancelled=False)
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-timeout-lifetime$"):
                observe()
        observe, _, _, _ = boundary_case(ProcessError())
        with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-timeout-lifetime$"):
            observe()
        observe, _, _, _ = boundary_case(None)
        with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-lifecycle-negative-returned$"):
            observe()
        original_error = OSError("inert original failure")
        observe, scope, _, _ = boundary_case(original_error)
        with self.assertRaises(OSError) as caught:
            observe()
        self.assertIs(caught.exception, original_error)
        self.assertEqual(scope.exits, [original_error, original_error])

        cleanup_error = RuntimeError("inert cleanup failure")
        observe, scope, verdict, _ = boundary_case(interruption, cleanup_error=cleanup_error)
        with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-original-lifecycle-finality$"):
            observe()
        self.assertIs(scope.primary, interruption)
        self.assertIs(scope.cleanup_error, cleanup_error)
        self.assertTrue(verdict.fatal)
        self.assertFalse(verdict.cleanup_complete)
        observe, _, _, _ = boundary_case(timeout, kind="timeout", cancelled=False, cleanup_error=cleanup_error)
        with self.assertRaises(RuntimeError) as caught:
            observe()
        self.assertIs(caught.exception, cleanup_error)

        for options in ({"ledger": {"complete": False}}, {"ledger": {"fatal": True}},
                        {"ledger": {"contained": False}}, {"ledger": {"cleanup_complete": False}},
                        {"ledger": {"commands": 0}}, {"ledger": {"command_dispatched": False}},
                        {"handlers": "UNKNOWN"}, {"sent": []}, {"sent": [True, True]},
                        {"errors": ["inert watcher failure"]}, {"suppress": True}):
            observe, _, _, _ = boundary_case(interruption, **options)
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-original-lifecycle-finality$"):
                observe()
        self.assertTrue(BUILD.DATA.known)  # Local doubles never mutate shared DATA.

    def test_input_admission_refusals_keep_exact_predicates_and_tool_roles(self):
        # Inert originals only. No real tool, descriptor, native call or file is
        # opened. Exercise actual read/close sequencing and contextual refusal.
        info = dict(st_dev=1, st_ino=2, st_mode=BUILD.stat.S_IFREG | 0o555,
                    st_uid=0, st_gid=0, st_nlink=1, st_size=3, st_mtime_ns=1, st_ctime_ns=1)
        self.assertEqual(BUILD.INPUT_BOUND_FAILURES,
                         ("ordinary-input-kind", "ordinary-input-links", "ordinary-input-size"))
        for change, reason in (({"st_mode": BUILD.stat.S_IFLNK | 0o777}, "ordinary-input-kind"),
                               ({"st_nlink": 2}, "ordinary-input-links"),
                               ({"st_nlink": 0}, "ordinary-input-links"),
                               ({"st_size": -1}, "ordinary-input-size"),
                               ({"st_size": 4}, "ordinary-input-size")):
            original = SimpleNamespace(**{**info, **change})
            selected = SimpleNamespace(lstat=lambda: original)
            with patch.object(BUILD.os, "open") as opened:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    BUILD.read(selected, 3)
                opened.assert_not_called()
            self.assertTrue(BUILD.DATA.known)

        original = SimpleNamespace(**info)
        selected = SimpleNamespace(lstat=lambda: original)
        with patch.object(BUILD.os, "open", return_value=713) as opened, \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]) as reads, \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "close") as closed:
            self.assertEqual(BUILD.read(selected, 3), b"abc")
            opened.assert_called_once_with(selected, BUILD.os.O_RDONLY | BUILD.os.O_NOFOLLOW
                                           | BUILD.os.O_CLOEXEC | BUILD.os.O_NONBLOCK)
            self.assertEqual(reads.call_args_list, [call(713, 3), call(713, 1)])
            closed.assert_called_once_with(713)
        self.assertTrue(BUILD.DATA.known)

        parent = SimpleNamespace(parents=(), stat=lambda: SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=0))
        class ToolPath:
            def resolve(self, *, strict):
                if strict is not True:
                    raise AssertionError("original strict resolution changed")
                return self
            def is_absolute(self):
                return True
            def lstat(self):
                return original
            def __str__(self):
                return "/usr/bin/synthetic-admission-only"
        ToolPath.parent = parent
        selected = ToolPath()
        owner = object.__new__(BUILD.Build)
        owner.tools = {}
        for role in BUILD.TOOL_ROLES:
            for reason in BUILD.INPUT_BOUND_FAILURES:
                with patch.object(BUILD, "read", side_effect=BUILD.BuildRefused(reason)) as reading:
                    with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-" + role + "-" + reason + "$"):
                        owner.protected_tool(selected, role=role)
                    reading.assert_called_once_with(selected, 512 * BUILD.MIB, expected_links=1)
                self.assertEqual(owner.tools, {})
        for role in (True, None, "unknown", "make/other"):
            with patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-diagnostic-role$"):
                    owner.protected_tool(selected, role=role)
                reading.assert_not_called()
        class OtherRefused(BUILD.BuildRefused):
            pass
        for error in (BUILD.BuildRefused("input-post-correspondence"),
                      OtherRefused("ordinary-input-links"), OSError("inert read failure")):
            with patch.object(BUILD, "read", side_effect=error):
                with self.assertRaises(type(error)) as caught:
                    owner.protected_tool(selected, role="make")
                self.assertIs(caught.exception, error)
            self.assertEqual(owner.tools, {})
        # Preserve each selected-original predicate and its short-circuit
        # result, while retaining finite scalar diagnostics without any path.
        for change, system, condition in (
                ({"st_mode": BUILD.stat.S_IFDIR | 0o755}, True, "kind"),
                ({"st_uid": 501}, True, "owner"),
                ({"st_uid": 502}, False, "owner"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o444}, True, "executable"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o575}, True, "mode"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o557}, False, "mode")):
            original = SimpleNamespace(**{**info, **change})
            diagnostic = object.__new__(BUILD.Build)
            diagnostic.tools, diagnostic.evidence = {}, {}
            with patch.object(BUILD.os, "getuid", return_value=501), \
                    patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused,
                        "^tool-make-unprotected-selected-tool-" + condition + "$"):
                    diagnostic.protected_tool(selected, role="make", system=system)
                reading.assert_not_called()
            self.assertEqual(diagnostic.tools, {})
            self.assertEqual(set(diagnostic.evidence), {"tool-admission-failure.json"})
            detail = json.loads(diagnostic.evidence["tool-admission-failure.json"])
            self.assertEqual(detail, {"schemaVersion": 1, "role": "make", "condition": condition,
                "AppleSystem": system, "executableRequired": True, "uid": original.st_uid,
                "gid": original.st_gid, "mode": original.st_mode, "nlink": original.st_nlink,
                "hostUid": 501})
            self.assertNotIn(str(selected).encode(), diagnostic.evidence["tool-admission-failure.json"])

        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o444})
        diagnostic = object.__new__(BUILD.Build)
        diagnostic.tools, diagnostic.evidence = {}, {}
        with patch.object(BUILD, "read", return_value=b"abc") as reading:
            self.assertEqual(diagnostic.protected_tool(selected, role="sdk-settings", executable=False), str(selected))
            reading.assert_called_once_with(selected, 512 * BUILD.MIB, expected_links=1)
        self.assertEqual(diagnostic.evidence, {})

        # An accounting/shape failure is still a refusal, never tool authority.
        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o575})
        diagnostic = object.__new__(BUILD.Build)
        diagnostic.tools = {}
        diagnostic.evidence = {"tool-admission-failure.json": b"retained-original"}
        with patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^retained-evidence-bound$"):
                diagnostic.protected_tool(selected, role="make")
            reading.assert_not_called()
        self.assertEqual(diagnostic.tools, {})
        self.assertEqual(diagnostic.evidence, {"tool-admission-failure.json": b"retained-original"})
        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o575, "st_gid": True})
        diagnostic.evidence = {}
        with patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-diagnostic-scalar$"):
                diagnostic.protected_tool(selected, role="make")
            reading.assert_not_called()
        self.assertEqual(diagnostic.tools, {})
        self.assertEqual(diagnostic.evidence, {})
        self.assertTrue(BUILD.DATA.known)

    def test_protected_system_tool_pins_original_link_count_only_after_admission(self):
        # Synthetic original identities only: no link, tool, native call or real
        # descriptor is created. The same actual read/admission/recheck executes.
        values = dict(st_dev=1, st_ino=2, st_mode=BUILD.stat.S_IFREG | 0o555,
                      st_uid=0, st_gid=0, st_nlink=3, st_size=3, st_mtime_ns=1, st_ctime_ns=1)
        original = SimpleNamespace(**values)
        changed_count = SimpleNamespace(**{**values, "st_nlink": 4})
        protected_parent = SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=0)

        class ToolPath:
            def __init__(self, info=original, parent=protected_parent, text="/usr/bin/synthetic-links-only"):
                self.info, self.text = info, text
                self.parent = SimpleNamespace(parents=(), stat=lambda: parent)
            def resolve(self, *, strict):
                if strict is not True:
                    raise AssertionError("strict original resolution changed")
                return self
            def is_absolute(self):
                return self.text.startswith("/")
            def lstat(self):
                return self.info
            def __str__(self):
                return self.text

        selected = ToolPath()
        for expected in (0, -1, True, False, 3.0, None, "3", 1, 4):
            with self.subTest(expected=expected), patch.object(BUILD.os, "open") as opened:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^ordinary-input-links$"):
                    BUILD.read(selected, 3, expected_links=expected)
                opened.assert_not_called()
        with patch.object(BUILD.os, "open") as opened:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^ordinary-input-links$"):
                BUILD.read(selected, 3)  # Generic SOURCE/archive/output default stays1.
            opened.assert_not_called()

        def owner():
            result = object.__new__(BUILD.Build)
            result.tools, result.evidence = {}, {}
            return result

        admitted = owner()
        with patch.object(BUILD.os, "open", return_value=714) as opened, \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]) as reads, \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "close") as closed:
            self.assertEqual(admitted.protected_tool(selected, role="make"), str(selected))
            opened.assert_called_once_with(selected, BUILD.os.O_RDONLY | BUILD.os.O_NOFOLLOW
                                           | BUILD.os.O_CLOEXEC | BUILD.os.O_NONBLOCK)
            self.assertEqual(reads.call_args_list, [call(714, 3), call(714, 1)])
            closed.assert_called_once_with(714)
        row = admitted.tools[str(selected)]
        self.assertEqual(row, {"path": str(selected), "selectedPath": str(selected), "size": 3,
                              "sha256": BUILD.digest(b"abc"), "identity": BUILD.identity(original),
                              "AppleSystem": True, "executable": True})
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(BUILD, "read", return_value=b"abc") as reading:
            admitted.recheck_tools(full=True)
            reading.assert_called_once_with(selected, 3, expected_links=3)
        for delta in ({"st_nlink": 4}, {"st_uid": 501}, {"st_mode": BUILD.stat.S_IFREG | 0o575},
                      {"st_size": 4}, {"st_mtime_ns": 2}):
            selected.info = SimpleNamespace(**{**values, **delta})
            with self.subTest(delta=delta), patch.object(BUILD, "Path", return_value=selected), \
                    patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-changed$"):
                    admitted.recheck_tools(full=True)
                reading.assert_not_called()
        selected.info = original
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(BUILD, "read", return_value=b"xyz"):
            with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-content-changed$"):
                admitted.recheck_tools(full=True)
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(selected, "resolve", return_value=ToolPath(text="/usr/bin/other")), \
                patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-changed$"):
                admitted.recheck_tools(full=True)
            reading.assert_not_called()

        # Action/user-controlled tools do not inherit the system exception.
        non_system = owner()
        with patch.object(BUILD.os, "open") as opened:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-orchestrator-ordinary-input-links$"):
                non_system.protected_tool(selected, role="orchestrator", system=False)
            opened.assert_not_called()
        self.assertEqual(non_system.tools, {})
        single = ToolPath(info=SimpleNamespace(**{**values, "st_nlink": 1}))
        with patch.object(BUILD, "read", return_value=b"abc") as reading:
            non_system.protected_tool(single, role="orchestrator", system=False)
            reading.assert_called_once_with(single, 512 * BUILD.MIB, expected_links=1)
        with patch.object(BUILD, "Path", return_value=single), \
                patch.object(BUILD, "read", return_value=b"abc") as reading:
            non_system.recheck_tools(full=True)
            reading.assert_called_once_with(single, 3, expected_links=1)

        for bad, reason in (
                (ToolPath(info=SimpleNamespace(**{**values, "st_uid": 501})), "tool-make-unprotected-selected-tool-owner"),
                (ToolPath(info=SimpleNamespace(**{**values, "st_mode": BUILD.stat.S_IFREG | 0o575})), "tool-make-unprotected-selected-tool-mode"),
                (ToolPath(parent=SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o777, st_uid=0)), "unprotected-Apple-tool-parent"),
                (ToolPath(parent=SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=501)), "unprotected-Apple-tool-parent"),
                (ToolPath(text="/work/unprotected"), "non-Apple-tool-route")):
            rejected = owner()
            with self.subTest(reason=reason), patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    rejected.protected_tool(bad, role="make")
                reading.assert_not_called()
            self.assertEqual(rejected.tools, {})

        # Every observation stays bound to the original count, including inside
        # the consuming read. Late count changes must close only that original.
        for fstats, lstats, reads, reason in (
                ([changed_count], [original], [], "input-open-correspondence"),
                ([original, changed_count], [original], [b"abc", b""], "input-post-correspondence"),
                ([original, original], [original, changed_count], [b"abc", b""], "input-post-correspondence"),
                ([original], [original], [b"abc", b"x"], "input-post-correspondence")):
            with self.subTest(reason=reason), patch.object(selected, "lstat", side_effect=lstats), \
                    patch.object(BUILD.os, "open", return_value=714), \
                    patch.object(BUILD.os, "fstat", side_effect=fstats), \
                    patch.object(BUILD.os, "read", side_effect=reads), \
                    patch.object(BUILD.os, "close") as closed:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    BUILD.read(selected, 3, expected_links=3)
                closed.assert_called_once_with(714)
            self.assertTrue(BUILD.DATA.known)
        with patch.object(BUILD.os, "open", return_value=714), \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]), \
                patch.object(BUILD.os, "close") as closed:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^input-byte-binding$"):
                BUILD.read(selected, 3, expected_links=3, expected=(3, BUILD.digest(b"xyz")))
            closed.assert_called_once_with(714)
        self.assertTrue(BUILD.DATA.known)

    def test_real_small_source_projection_preserves_bytes_modes_and_inventory(self):
        for component in ("cpython", "zlib"):
            source, compressed, rows, provenance = archive_fixture(component)
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                parser.extract(source, compressed)
                projected = root / "sources" / component / "Lib/source with spaces.py"
                self.assertEqual(projected.read_bytes(), b"public source\n")
                self.assertEqual(projected.stat().st_mode & 0o777, 0o444)
                self.assertEqual(projected.stat().st_mtime_ns, 1700000000 * 1000000000)
                self.assertEqual((projected.parent.stat().st_mode & 0o777), 0o555)


        original_data = BUILD.DATA
        self.assertTrue(original_data.known)

        def payload_case(root):
            work = root / "work"
            work.mkdir(mode=0o700)
            private = work / "private"
            private.mkdir(mode=0o700)
            payload = private / "supplier"
            (payload / "python/bin").mkdir(parents=True, mode=0o700)
            (payload / "python/lib/python3.14").mkdir(parents=True, mode=0o700)
            BUILD.write(payload / "python/bin/python3", b"inert; never an executable probe\n", 0o555)
            BUILD.write(payload / "python/lib/python3.14/data.py", b"public DATA\n", 0o444)
            BUILD.seal(payload)
            relocated_parent = private / "relocated parent with spaces"
            relocated_parent.mkdir(mode=0o700)
            operation = BUILD.Build.__new__(BUILD.Build)
            operation.work, operation.private, operation.payload = work, private, payload
            operation.work_identity = BUILD.custody(work.lstat())
            operation.private_identity = BUILD.custody(private.lstat())
            operation.relocation_parent_identity = BUILD.custody(relocated_parent.lstat())
            operation.export_identity = None
            operation.inflight = False
            operation.deadline = time.monotonic() + 20
            operation.guard = SimpleNamespace(lifetime_ledger=SimpleNamespace(verdict=lambda:
                SimpleNamespace(complete=True, fatal=False, contained=True)))
            operation.files = list(BUILD.tree_rows(payload, maximum=BUILD.MIB, max_files=8).values())
            operation.run = lambda *args, **kwargs: self.fail("a filesystem move must not dispatch a native command")
            return operation

        with scratch() as root:
            operation = payload_case(root)
            inode = (operation.payload.stat().st_dev, operation.payload.stat().st_ino)
            data = BUILD.DataFinality()
            moves = []
            real_os = SimpleNamespace(**vars(os))

            def darwin_ordering(source, destination, **kwargs):
                # Inert policy double around a REAL move; not Darwin execution.
                mode = real_os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False).st_mode & 0o777
                if mode != 0o755:
                    raise PermissionError(errno.EACCES, "synthetic Darwin sealed-directory refusal")
                self.assertEqual(data._pending, 3)
                moves.append((source, destination))
                return real_os.rename(source, destination, **kwargs)

            proxy = SimpleNamespace(**vars(os))
            proxy.rename = darwin_ordering
            with patch.object(BUILD, "DATA", data), patch.object(BUILD, "os", proxy):
                for role in ("relocation", "retention", "export"):
                    if role == "export":
                        export = operation.work / "export"
                        export.mkdir(mode=0o700)
                        operation.export_identity = BUILD.custody(export.lstat())
                    previous = operation.payload
                    operation._move_payload(role, deadline=operation.deadline)
                    self.assertFalse(previous.exists())
                    self.assertEqual((operation.payload.stat().st_dev, operation.payload.stat().st_ino), inode)
                    self.assertEqual(operation.payload.stat().st_mode & 0o777, 0o555)
                    self.assertEqual(list(BUILD.tree_rows(operation.payload, maximum=BUILD.MIB, max_files=8).values()),
                                     operation.files)
                    self.assertEqual(operation.phase, "supplier-" + role + "-payload-post")
                    self.assertEqual(operation.payload_move_errors, [])
                    self.assertTrue(data.known)
                    self.assertEqual(data._pending, 0)
            self.assertEqual(len(moves), 3)

        # Each fault uses the same real small original tree and local DATA only.
        # Scoped os proxies never replace the shared stdlib module's functions.
        for case in ("rename", "restore", "close", "multiple-faults", "rename-result-gap", "open-result-gap",
                     "root-replaced", "closed-root-replaced", "collision"):
            with self.subTest(move_failure=case), scratch() as root:
                operation = payload_case(root)
                source = operation.payload
                destination = operation.private / "relocated parent with spaces/release kit runtime"
                original_inode = (source.stat().st_dev, source.stat().st_ino)
                data = BUILD.DataFinality()
                real_os, proxy = SimpleNamespace(**vars(os)), SimpleNamespace(**vars(os))
                first = PermissionError(errno.EACCES, "synthetic original rename refusal")
                restore_error = OSError(errno.EIO, "synthetic original mode-restore failure")
                close_error = OSError(errno.EIO, "synthetic original close uncertainty")
                parent_close_errors = {label: OSError(errno.EIO, "synthetic original parent close uncertainty")
                                       for label in ("source-parent", "destination-parent")}
                gap = KeyboardInterrupt("synthetic original result-publication gap")
                held_root, close_failed, rename_entered = [None], [False], []
                move_descriptors, close_events = {}, []
                displaced = operation.work / "displaced-original"

                def opened(path, flags, *args, **kwargs):
                    is_root = path == source.name and "dir_fd" in kwargs
                    if is_root and case == "root-replaced":
                        real_os.chmod(source, 0o755)
                        real_os.rename(source, displaced)
                        real_os.chmod(displaced, 0o555)
                        source.mkdir(mode=0o555)
                        real_os.chmod(source, 0o555)
                    fd = real_os.open(path, flags, *args, **kwargs)
                    if is_root:
                        if case == "open-result-gap":
                            # The double consumes its real fd; production must not
                            # guess that lost result or claim the constructor known.
                            real_os.close(fd)
                            raise gap
                        held_root[0] = fd
                        move_descriptors[fd] = "payload-root"
                    elif path in {source.parent, destination.parent}:
                        move_descriptors[fd] = "source-parent" if path == source.parent else "destination-parent"
                    return fd

                def changed_mode(fd, mode):
                    self.assertEqual(fd, held_root[0])
                    if case in {"restore", "multiple-faults"} and mode == 0o555:
                        raise restore_error
                    return real_os.fchmod(fd, mode)

                def renamed(old, new, **kwargs):
                    rename_entered.append(True)
                    self.assertEqual(real_os.fstat(held_root[0]).st_mode & 0o777, 0o755)
                    if case in {"rename", "restore", "multiple-faults"}:
                        raise first
                    result = real_os.rename(old, new, **kwargs)
                    if case == "rename-result-gap":
                        raise gap
                    return result

                def closed(fd):
                    result = real_os.close(fd)
                    label = move_descriptors.pop(fd, None)
                    if label is not None:
                        close_events.append(label)
                        if case == "multiple-faults":
                            raise close_error if label == "payload-root" else parent_close_errors[label]
                    if fd == held_root[0] and not close_failed[0]:
                        close_failed[0] = True
                        if case == "close":
                            raise close_error
                        if case == "closed-root-replaced":
                            real_os.chmod(destination, 0o755)
                            real_os.rename(destination, displaced)
                            real_os.chmod(displaced, 0o555)
                            destination.mkdir(mode=0o555)
                            real_os.chmod(destination, 0o555)
                    return result

                proxy.open, proxy.fchmod, proxy.rename, proxy.close = opened, changed_mode, renamed, closed
                if case == "collision":
                    destination.mkdir(mode=0o555)
                    real_os.chmod(destination, 0o555)
                with patch.object(BUILD, "DATA", data), patch.object(BUILD, "os", proxy):
                    with self.assertRaises(BaseException) as caught:
                        operation._move_payload("relocation", deadline=operation.deadline)
                error = caught.exception
                if case in {"rename", "restore", "multiple-faults"}:
                    self.assertIs(error, first)
                    self.assertEqual(operation.phase, "supplier-relocation-rename")
                    self.assertEqual(source.stat().st_mode & 0o777,
                                     0o755 if case in {"restore", "multiple-faults"} else 0o555)
                    self.assertFalse(destination.exists())
                elif case == "close":
                    self.assertIs(error, close_error)
                    self.assertEqual(operation.phase, "supplier-relocation-close-payload-root")
                    self.assertEqual(destination.stat().st_mode & 0o777, 0o555)
                elif case in {"rename-result-gap", "open-result-gap"}:
                    self.assertIs(error, gap)
                    self.assertIs(operation.payload, source)
                    selected = destination if case == "rename-result-gap" else source
                    self.assertEqual((selected.stat().st_dev, selected.stat().st_ino), original_inode)
                    self.assertEqual(selected.stat().st_mode & 0o777, 0o555)
                elif case in {"root-replaced", "closed-root-replaced"}:
                    self.assertIs(type(error), BUILD.BuildRefused)
                    selected = source if case == "root-replaced" else destination
                    self.assertNotEqual((selected.stat().st_dev, selected.stat().st_ino), original_inode)
                    self.assertEqual((displaced.stat().st_dev, displaced.stat().st_ino), original_inode)
                    self.assertEqual(selected.stat().st_mode & 0o777, 0o555)
                else:
                    self.assertIs(type(error), BUILD.BuildRefused)
                    self.assertEqual(str(error), "supplier-move-destination-collision")
                    self.assertEqual(source.stat().st_mode & 0o777, 0o555)
                self.assertEqual(bool(rename_entered), case not in {"open-result-gap", "root-replaced", "collision"})
                self.assertEqual(data.known, case in {"rename", "collision"})
                if case == "multiple-faults":
                    events = operation.payload_move_errors
                    self.assertEqual(len(events), 6)
                    self.assertEqual([label for label, _ in events], ["supplier-relocation-" + suffix for suffix in
                        ("rename", "restore-root-mode", "named-post", "close-payload-root",
                         "close-destination-parent", "close-source-parent")])
                    self.assertIs(events[0][1], first)
                    self.assertIs(events[1][1], restore_error)
                    self.assertIs(type(events[2][1]), BUILD.BuildRefused)
                    self.assertIs(events[3][1], close_error)
                    self.assertIs(events[4][1], parent_close_errors["destination-parent"])
                    self.assertIs(events[5][1], parent_close_errors["source-parent"])
                    self.assertEqual(close_events, ["payload-root", "destination-parent", "source-parent"])
                    self.assertEqual(move_descriptors, {})
                    self.assertEqual(data._pending, 3)
                self.assertTrue(source.exists() or destination.exists() or displaced.exists())
                self.assertIs(BUILD.DATA, original_data)
                self.assertTrue(original_data.known)

    def test_real_small_source_projection_refuses_crc_tail_and_body_mismatch(self):
        cases = [archive_fixture(compression_trailer=gzip.compress(b"unselected")),
                 archive_fixture(trailer=b"x" * 512), archive_fixture()]
        source, compressed, rows, provenance = cases[-1]
        cases[-1] = (source, compressed, {name: {**row, "sha256": "0" * 64} for name, row in rows.items()}, provenance)
        for source, compressed, rows, provenance in cases:
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                with self.assertRaises((BUILD.BuildRefused, zlib.error)):
                    parser.extract(source, compressed)
        source, compressed, rows, provenance = archive_fixture()
        changed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
        source.size, source.sha256 = len(changed), BUILD.digest(changed)
        provenance["archive"] = {"size": len(changed), "sha256": source.sha256}
        with scratch() as root:
            with self.assertRaises(zlib.error):
                parser_instance(root, source, rows, provenance).extract(source, changed)

    def test_retained_tar_preserves_exact_supplier_modes_and_readback(self):
        with scratch() as root:
            supplier = root / "supplier"
            (supplier / "python/bin").mkdir(mode=0o700, parents=True)
            (supplier / "python/lib").mkdir(mode=0o700)
            rows = []
            for name, body, mode in (("python/bin/python3", b"not-executable-test-data", 0o555),
                                     ("python/lib/fixture.txt", b"public fixture", 0o444)):
                rows.append({"path": name, **BUILD.write(supplier / name, body, mode)})
            BUILD.seal(supplier)
            result = BUILD.supplier_tar(supplier, root / "supplier.tar", rows, deadline=time.monotonic() + 10)
            self.assertEqual(result["files"], 2)
            self.assertTrue(result["modePreservation"])
            self.assertEqual(BUILD.digest((root / "supplier.tar").read_bytes()), result["sha256"])
            self.assertEqual(list(BUILD.tree_rows(supplier, maximum=1024, max_files=3).values()), rows)

    def test_canonical_seal_generated_alias_is_exact_and_never_source_authority(self):
        # Only a tiny generated-work alias is exercised. No source archive,
        # compiler, crypto, native child or complete build owner is entered.
        name = "_mrk_canonical_seal_alias_contract"
        self.assertNotIn(name, sys.modules)
        seal = load(name, "macos_github_seal_build.py")
        try:
            seal.B = BUILD
            # Run only the actual initial clean-environment assignment. The first
            # tool admission is an inert stop, before any native/tool/source call.
            receiver = SimpleNamespace(work=Path("/fixed-work"), private=Path("/fixed-work/private"),
                mkdir=lambda path: object(),
                protected_tool=lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("environment-only-stop")))
            with patch.dict(seal.os.environ, {"ZERO_AR_DATE": "0", "AR": "not-inherited"}):
                with self.assertRaisesRegex(ValueError, "^environment-only-stop$"):
                    seal.SealBuild.prepare(receiver)
            self.assertEqual(receiver.environment, {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/fixed-work/private/home",
                "TMPDIR": "/fixed-work/private/tmp/", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                "ZERO_AR_DATE": "1", "DEVELOPER_DIR": str(seal.DEVELOPER),
                "CONFIG_SITE": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1"})
            source_text = (ROOT / "desktop/tools/macos_github_seal_build.py").read_text()
            self.assertIn('B.need(B.read(build / "src/libsodium/.libs/libsodium.a", 64 * MIB) == archive, "canonical-installed-build-library")', source_text)
            # Actual pure command constructor is used by the unchanged owner.
            # No nm/tool/native invocation; ARM retains the original argv.
            library = Path("/fixed-work/private/prefix/lib/libsodium.a")
            nm = "/Library/Developer/CommandLineTools/usr/bin/nm"
            for target, expected in (
                    ("aarch64-apple-darwin", [nm, "-gU", str(library)]),
                    ("x86_64-apple-darwin", [nm, "--quiet", "-gU", str(library)])):
                with self.subTest(nm_target=target):
                    actual = seal._static_symbol_argv(target, nm, library)
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual.count("--quiet"), int(target == "x86_64-apple-darwin"))
            self.assertIn('symbols = self.run("static-four-symbols", _static_symbol_argv(self.target, self.nm, self.library))', source_text)
            # Pin the complete existing strict result-validation block: no
            # stderr filtering, symbol-count weakening or fallback option.
            self.assertIn('        B.need(symbols.stderr == b"", "static-symbol-query")\n        lines = symbols.stdout.decode("ascii", "strict").splitlines()\n        for name in ("_sodium_init", "_crypto_box_seal", "_sodium_memzero", "_randombytes_close"):\n            B.need(sum(bool(re.fullmatch(r"[0-9a-fA-F]+ [A-Z] " + re.escape(name), line.strip())) for line in lines) == 1,\n                   "canonical-four-symbol-definition")\n', source_text)
            # New checks are SOURCE-only here; actual process/entropy/crypto
            # evidence requires both fixed selected native originals on each Mac.
            helper_root = ROOT / "desktop/helpers/macos-github-seal"
            for helper_leaf, expected_pin in seal.HELPER_PINS.items():
                helper_body = (helper_root / helper_leaf).read_bytes()
                self.assertEqual((len(helper_body), hashlib.sha256(helper_body).hexdigest()), expected_pin)
            self.assertEqual(len(seal.ROLE_LIMITS), 23)
            self.assertEqual(seal.ROLE_LIMITS[-2:], (("helper-native-test", 10, seal.QUERY_LIMIT),
                ("helper-entropy-test", 10, seal.QUERY_LIMIT)))
            self.assertEqual(seal.NATIVE_TEST, "macos::tests::canonical_return_paths_wipe_input_and_refuse_low_order_key")
            native_source = (helper_root / "src/macos_tests.rs").read_text()
            self.assertEqual(native_source.count("#[test]"), 2)
            self.assertIn("framed_build_parent_and_entropy_denial(phase);", native_source)
            self.assertIn("Case::Good(0), Case::Good(3), Case::Good(protocol::MAX_PLAINTEXT)", native_source)
            self.assertIn("Case::Trailing, Case::LowOrder, Case::DeviceControl]", native_source)
            self.assertIn("TestPhase::Denied => &[Case::DeviceDenied, Case::EntropyDenied]", native_source)
            self.assertIn("assert_eq!(closed_originals, match phase { TestPhase::Ordinary => 6, TestPhase::Denied => 2 });", native_source)
            self.assertNotIn('Command::new("/usr/bin/sandbox-exec")', native_source)
            self.assertIn('if phase == TestPhase::Ordinary { returned_canonical_checks(); }', native_source)
            self.assertIn('Ok("ordinary6") => TestPhase::Ordinary', native_source)
            self.assertIn('Ok("denied2") => TestPhase::Denied', native_source)
            self.assertIn('_ => panic!("closed test-only owner phase")', native_source)
            # Canonical name lookup also initializes/stirs the RNG: the denied
            # parent must reach its children, not abort in this observation.
            backend_observer = native_source.split('fn framed_build_parent_and_entropy_denial(phase: TestPhase) {', 1)[1].split('    let current =', 1)[0]
            self.assertEqual(backend_observer, '\n    use std::os::unix::process::ExitStatusExt;\n    if phase == TestPhase::Ordinary {\n        // This API initializes/stirs the RNG. Only ordinary may call it;\n        // denied must reach its actual device probe before any entropy use.\n        let name = unsafe { randombytes_implementation_name() };\n        assert!(!name.is_null());\n        let mut backend = [0u8; 10];\n        for (offset, slot) in backend.iter_mut().enumerate() {\n            // Canonical API returns a static NUL-terminated C string. Stop at its\n            // actual NUL; never read beyond a shorter unexpected backend name.\n            *slot = unsafe { name.add(offset).read() } as u8;\n            if *slot == 0 { break; }\n        }\n        assert_eq!(&backend, b"sysrandom\\0");\n    }\n')
            self.assertEqual(native_source.count('unsafe { randombytes_implementation_name() }'), 1)
            # Fixed diagnostic SOURCE only; no child/native/panic is executed.
            captured_at = native_source.index('let captured = capture_case(case, &current, &helper).expect("actual child IO/close/wait");')
            report_at = native_source.index('report_captured(case, &captured);')
            refusal_at = native_source.index('assert!(captured.error.is_empty(), "no child diagnostic accepted");')
            self.assertLess(captured_at, report_at); self.assertLess(report_at, refusal_at)
            self.assertEqual(native_source.count('report_captured(case, &captured);'), 1)
            reporter = native_source.split('fn report_captured(case: Case, captured: &Capture) {', 1)[1].split('fn pipe_original<', 1)[0]
            self.assertEqual(reporter.count('eprintln!('), 1)
            self.assertIn('MRK_SEAL_CHILD_DIAGNOSTIC_V1 case={} code={} signal={} stdoutBytes={} stderrBytes={} tokenMask={:03x} parentPipesAndWait=returned', reporter)
            self.assertIn('captured.status.code().unwrap_or(-1)', reporter)
            self.assertIn('captured.status.signal().unwrap_or(0)', reporter)
            self.assertIn('captured.output.len(), captured.error.len(), diagnostic_tokens(&captured.error)', reporter)
            for forbidden in ('from_utf8', 'from_utf8_lossy', 'Debug', '{:?}', 'std::env', 'as_os_str'):
                self.assertNotIn(forbidden, reporter)
            classifier = native_source.split('fn diagnostic_tokens(error: &[u8]) -> u16 {', 1)[1].split('fn diagnostic_data_checks()', 1)[0]
            self.assertIn('if error.len() > 1024 { return 0; }', classifier)
            for token in ('sandbox-exec:', 'sandbox_apply', 'sandbox_init', 'Operation not permitted', 'Permission denied',
                          'dyld:', 'dyld[', 'Library not loaded:', 'Symbol not found:', 'panicked at', 'fatal runtime error:', 'memory allocation of'):
                self.assertIn('b"' + token + '"', classifier)
            self.assertIn('diagnostic_data_checks();', native_source)
            # Worst fixed case/i32/length formatting is below the promised bound.
            longest = ('MRK_SEAL_CHILD_DIAGNOSTIC_V1 case=device-control code=-2147483648 signal=-2147483648 '
                       'stdoutBytes=49212 stderrBytes=1024 tokenMask=3ff parentPipesAndWait=returned\n')
            self.assertLessEqual(len(longest.encode('ascii')), 256)

            self.assertIn("assert_eq!(captured.status.signal(), Some(6));", native_source)
            self.assertIn("matches!(error.raw_os_error(), Some(1 | 13))", native_source)
            self.assertIn('command.env_clear().env("LANG", "C").env("LC_ALL", "C");', native_source)
            self.assertIn('"/dev/urandom", "/dev/random"', native_source)
            self.assertIn("let closed = original.consume_close();", native_source)
            self.assertIn("crypto_box_seal_open", native_source)
            self.assertLess(native_source.index('Err("input-close")'), native_source.index("read_bounded(pipe, &mut output"))
            self.assertLess(native_source.index('Err("error-close")'), native_source.index("match child.wait()"))
            for forbidden in ("randombytes_set_implementation", "sodium_set_misuse_handler", "Command::output", "read_to_end", "setsid", "setpgid"):
                self.assertNotIn(forbidden, native_source)
            self.assertIn('"framedBuildParentRoundTrip": True', source_text)
            self.assertIn('"installedDesktopParentQualified": False', source_text)
            self.assertIn('"abortReturnedWipeClaim": False', source_text)
            # Exercise the real fixed caller + run/remaining/parser bodies.
            # The sole process port returns inert CompletedProcess DATA: this
            # proves routing/refusal, NOT a sandbox, entropy or native receipt.
            exact_output = ("running 1 test\ntest " + seal.NATIVE_TEST + " ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.01s\n").encode("ascii")
            self.assertEqual(seal.NATIVE_PHASES, (("helper-native-test", "ordinary6", 6),
                ("helper-entropy-test", "denied2", 2)))
            self.assertEqual(seal.NATIVE_DENIED_POLICY,
                '(version 1)(allow default)(deny network*)(deny file-read-data (literal "/dev/urandom") (literal "/dev/random"))')
            for scenario in ("success", "first-nonzero", "second-nonzero", "first-stderr", "second-stderr",
                             "second-bad-count", "expired-first", "capture-empty", "capture-overflow", "unknown-original"):
                with self.subTest(native_pair=scenario):
                    clock, calls, events = [100.0], [], []
                    base_environment = {"LANG": "C", "LC_ALL": "C", "ZERO_AR_DATE": "1"}
                    original_environment = dict(base_environment)
                    verdict = SimpleNamespace(complete=True, fatal=False, contained=True)
                    failure = OSError("inert original uncertainty")
                    def returned(argv, **kwargs):
                        calls.append((list(argv), kwargs))
                        index = len(calls)
                        if scenario == "unknown-original":
                            verdict.complete = False
                            raise failure
                        clock[0] += 3 if index == 1 else 2
                        if scenario == "expired-first" and index == 1: clock[0] = 110.0
                        output, error, code = exact_output, b"", 0
                        if scenario == "first-nonzero" and index == 1 or scenario == "second-nonzero" and index == 2: code = 1
                        if scenario == "first-stderr" and index == 1 or scenario == "second-stderr" and index == 2: error = b"inert refusal"
                        if scenario == "second-bad-count" and index == 2: output = output.replace(b"4 filtered", b"3 filtered")
                        if scenario == "capture-empty" and index == 1: output += b"\n" * (seal.QUERY_LIMIT - len(output))
                        if scenario == "capture-overflow" and index == 2: output = b"x" * (kwargs["output_limit"] + 1)
                        return subprocess.CompletedProcess(argv, code, output, error)
                    receiver = SimpleNamespace(deadline=200.0, native_deadline=None, native_capture_remaining=0,
                        provider_mode=False, role_limits=seal.ROLE_LIMITS, entered=21, returned=21,
                        native={}, commands=[], environment=base_environment, private=Path("/inert/private"),
                        sandbox="/usr/bin/sandbox-exec", inflight=False, phase="inert",
                        check=lambda: None, recheck_tools=lambda: events.append("tools-post"),
                        census=lambda: {"inert": True}, evidence_bytes=lambda name, data: BUILD.digest(data),
                        owner=SimpleNamespace(run_owned=returned),
                        guard=SimpleNamespace(lifetime_ledger=SimpleNamespace(verdict=lambda: verdict)))
                    receiver.run = lambda *args, **kwargs: seal.SealBuild.run(receiver, *args, **kwargs)
                    with patch.object(seal.time, "monotonic", side_effect=lambda: clock[0]):
                        if scenario == "success":
                            seal.SealBuild.native_tests(receiver, Path("/inert/test"))
                        elif scenario == "unknown-original":
                            with self.assertRaises(OSError) as caught:
                                seal.SealBuild.native_tests(receiver, Path("/inert/test"))
                            self.assertIs(caught.exception, failure)
                        else:
                            with self.assertRaises(BUILD.BuildRefused):
                                seal.SealBuild.native_tests(receiver, Path("/inert/test"))
                        # The pair cannot be restarted even after a known failure.
                        count = len(calls)
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^native-pair-admission$"):
                            seal.SealBuild.native_tests(receiver, Path("/inert/test"))
                        self.assertEqual(len(calls), count)
                    self.assertIs(receiver.environment, base_environment)
                    self.assertEqual(base_environment, original_environment)
                    self.assertEqual(receiver.native_deadline, 110.0)
                    for index, (argv, kwargs) in enumerate(calls):
                        self.assertEqual(argv, ["/usr/bin/sandbox-exec", "-p",
                            BUILD.NETWORK_POLICY if index == 0 else seal.NATIVE_DENIED_POLICY,
                            "/inert/test", seal.NATIVE_TEST, "--exact", "--test-threads=1"])
                        self.assertEqual(kwargs["environ"], {**base_environment, seal.NATIVE_PHASE_ENV: "ordinary6" if index == 0 else "denied2"})
                        self.assertIsNot(kwargs["environ"], base_environment)
                        self.assertIs(kwargs["cancellation"], receiver.guard)
                        self.assertEqual(kwargs["timeout"], 10 if index == 0 else 7)
                        self.assertEqual(kwargs["output_limit"], seal.QUERY_LIMIT - index * len(exact_output))
                        self.assertTrue(kwargs["capture"]); self.assertFalse(kwargs["text"])
                        self.assertEqual(receiver.commands[index]["environmentSha256"], BUILD.digest(BUILD.canonical(kwargs["environ"])))
                    if scenario == "success":
                        self.assertEqual((receiver.entered, receiver.returned), (23, 23))
                        self.assertEqual(receiver.native_capture_remaining, seal.QUERY_LIMIT - 2 * len(exact_output))
                        combined = receiver.native["helperNativeTest"]
                        self.assertEqual((combined["passed"], combined["selectedInvocations"], combined["nestedOriginalsClosed"]), (2, 2, 8))
                        self.assertEqual(combined["phases"], [{"phase": "ordinary6", "passed": 1, "nestedOriginalsClosed": 6},
                            {"phase": "denied2", "passed": 1, "nestedOriginalsClosed": 2}])
                        self.assertFalse(combined["abortReturnedWipeClaim"])
                        self.assertFalse(combined["installedDesktopParentQualified"])
                        self.assertFalse(receiver.inflight)
                    else:
                        self.assertNotIn("helperNativeTest", receiver.native)
                        if scenario in {"expired-first", "capture-empty", "unknown-original", "first-nonzero", "first-stderr"}:
                            self.assertEqual(len(calls), 1)
                        if scenario == "unknown-original":
                            self.assertTrue(receiver.inflight)
                            self.assertEqual((receiver.entered, receiver.returned), (22, 21))
            # Other recipe/provider modes retain the original sandbox/env/limit.
            for provider in (False, True):
                role = "provider-version" if provider else "compiler-version"
                calls, events = [], []
                environment = {"LANG": "C"}
                def other_returned(argv, **kwargs):
                    calls.append((argv, kwargs))
                    return subprocess.CompletedProcess(argv, 0, seal.PROVIDER_VERSION if provider else b"inert\n", b"")
                receiver = SimpleNamespace(deadline=120.0, role_limits=((role, 30, seal.QUERY_LIMIT),),
                    entered=0, returned=0, provider_mode=provider, environment=environment,
                    sandbox="/usr/bin/sandbox-exec", private=Path("/inert/private"), commands=[],
                    check=lambda: None, recheck_tools=lambda: None,
                    provider_post=lambda: events.append("provider-post"), census=lambda: {},
                    evidence_bytes=lambda name, data: BUILD.digest(data),
                    owner=SimpleNamespace(run_owned=other_returned), guard=object())
                with patch.object(seal.time, "monotonic", return_value=100.0):
                    seal.SealBuild.run(receiver, role, ["/inert/program"])
                self.assertEqual(calls[0][0], ["/usr/bin/sandbox-exec", "-p", BUILD.NETWORK_POLICY, "/inert/program"])
                self.assertIs(calls[0][1]["environ"], environment)
                self.assertEqual((calls[0][1]["timeout"], calls[0][1]["output_limit"]), (20, seal.QUERY_LIMIT))
                self.assertEqual(events, ["provider-post", "provider-post"] if provider else [])

            # Production helper and binary wire source remain exactly unchanged.
            for fixed, fixed_digest in {
                "src/main.rs": "14392210ce19e06e91da0a93ad6ac5a6ac142bc658cf0d25a838f9cec3261310",
                "src/macos.rs": "a50d8977991a273ccaf1c50a8d6629361a5b05fcff32aac97121ef165258dc62",
                "src/protocol.rs": "5441b4fd3d1eae80cb7f8d70ee79341eb8a47123177d8a72e152c6f7109b0c71",
            }.items():
                self.assertEqual(hashlib.sha256((helper_root / fixed).read_bytes()).hexdigest(), fixed_digest)
            for mode in ("ordinary", "wrong-target", "same-target-replaced", "post-target-changed", "unknown-child", "unknown-data", "other-name"):
                with self.subTest(mode=mode), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    parent = root / "build/src/libsodium/.libs"
                    parent.mkdir(parents=True)
                    target = parent.parent / "libsodium.la"
                    target.write_bytes(b"actual generated metadata; not linker authority")
                    path = parent / "libsodium.la"
                    path.symlink_to("wrong.la" if mode == "wrong-target" else "../libsodium.la")
                    verdict = SimpleNamespace(complete=True, fatal=False, contained=True)
                    receiver = SimpleNamespace(private=root, check=lambda: None, libtool_alias_originals={},
                        guard=SimpleNamespace(lifetime_ledger=SimpleNamespace(verdict=lambda: verdict)),
                        cleaning=False, inflight=False)
                    invoke = lambda chosen=path, retire=False: seal.SealBuild.libtool_alias(receiver, chosen, retire=retire)
                    if mode == "wrong-target":
                        with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-pre"):
                            invoke()
                        self.assertEqual(receiver.libtool_alias_originals, {})
                    elif mode == "other-name":
                        other = parent / "foreign.la"
                        other.symlink_to("../libsodium.la")
                        with self.assertRaisesRegex(BUILD.BuildRefused, "unexpected-generated-alias"):
                            invoke(other)
                        self.assertTrue(other.is_symlink())
                    elif mode == "post-target-changed":
                        original = os.readlink
                        calls = []
                        def changed(*args, **kwargs):
                            actual = original(*args, **kwargs)
                            calls.append(actual)
                            return actual if len(calls) == 1 else "different.la"
                        with patch.object(seal.os, "readlink", changed):
                            with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-post"):
                                invoke()
                        self.assertEqual(calls, ["../libsodium.la", "../libsodium.la"])
                        self.assertEqual(receiver.libtool_alias_originals, {})
                    else:
                        invoke()
                        self.assertEqual(set(receiver.libtool_alias_originals), {"libsodium.la"})
                        if mode == "same-target-replaced":
                            old = parent / "saved-original.la"
                            path.rename(old)
                            path.symlink_to("../libsodium.la")
                            self.assertNotEqual(path.lstat().st_ino, old.lstat().st_ino)
                            receiver.cleaning = True
                            with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-changed"):
                                invoke(retire=True)
                            self.assertTrue(old.is_symlink())
                        elif mode == "unknown-child":
                            receiver.cleaning = True
                            verdict.complete = False
                            with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-unsettled"):
                                invoke(retire=True)
                        elif mode == "unknown-data":
                            receiver.cleaning = True
                            BUILD.DATA.unknown()
                            # Refuse the actual prior unknown before acquiring
                            # a new parent original or touching the alias.
                            with patch.object(seal.os, "open", side_effect=AssertionError("unexpected acquisition")) as opened:
                                with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-unsettled"):
                                    invoke(retire=True)
                                opened.assert_not_called()
                            self.assertFalse(BUILD.DATA.known)
                        else:
                            # A returned name is not permission to remove it
                            # until this SAME caller has actual settlement.
                            with self.assertRaisesRegex(BUILD.BuildRefused, "generated-alias-unsettled"):
                                invoke(retire=True)
                            self.assertTrue(path.is_symlink())
                            receiver.cleaning = True
                            invoke(retire=True)
                            self.assertFalse(path.exists() or path.is_symlink())
                    if mode != "ordinary":
                        self.assertTrue(path.is_symlink())
                    self.assertEqual(target.read_bytes(), b"actual generated metadata; not linker authority")
                    self.assertEqual(BUILD.DATA.known, mode != "unknown-data")
                    self.assertEqual(BUILD.DATA._pending, 0)
            # Four closed entry forms, not a purpose/path/run selector. The
            # two old modes retain their exact probe_mode contract below.
            for arguments, reference, expected in (
                    ([], seal.REFERENCE, False),
                    (["--history-provider-probe"], seal.PROVIDER_REFERENCE, False),
                    (["--publish-build-capsule"], seal.REFERENCE, True),
                    (["--history-provider-probe", "--publish-build-capsule"], seal.PROVIDER_REFERENCE, True)):
                with self.subTest(capsule_entry=(arguments, reference)):
                    self.assertIs(seal.capsule_mode(arguments, reference), expected)
            for arguments, reference in (
                    (["--publish-build-capsule"], seal.PROVIDER_REFERENCE),
                    (["--history-provider-probe", "--publish-build-capsule"], seal.REFERENCE),
                    (["--publish-build-capsule", "--history-provider-probe"], seal.PROVIDER_REFERENCE),
                    (["--publish-build-capsule", "--publish-build-capsule"], seal.REFERENCE),
                    (["--publish-build-capsule", "extra"], seal.REFERENCE),
                    (["--publish-build-capsule"], "refs/heads/main"),
                    ("--publish-build-capsule", seal.REFERENCE),
                    (("--publish-build-capsule",), seal.REFERENCE)):
                with self.subTest(capsule_entry_refusal=(arguments, reference)), self.assertRaises(ValueError):
                    seal.capsule_mode(arguments, reference)
            self.assertEqual(seal.CAPSULE_PURPOSES, {
                "history-provider": ("gh", 64 * 1024 * 1024),
                "github-seal": ("mrk-github-seal", 16 * 1024 * 1024)})
            self.assertEqual(seal.CAPSULE_RECEIPT_LIMIT, 16384)
            # Exact public prepared DATA returned by the genuine LOCAL owner;
            # no raw LOCAL reports, copied products or invented publication IDs.
            # Embedded bytes keep this SOURCE group independent of a binary-
            # bearing verification branch. Production pins are NOT patched here.
            prepared_bodies = {'aarch64-apple-darwin': b'{"facts":{"binary":{"bytes":37471938,"sha256":"a704813e4e64f8814e5fa21677f7dab51d9b77d045ded75dd11bcdc1a53d5516"},"buildOrigin":{"allJoinedZeroAndPipesClosed":true,"buildInfo":{"bytes":15522,"sha256":"964a1f69d320598576c66cd488fdde3263d086ce4585ec8bd2d27acd07805a27"},"childOriginals":5,"closedSummary":{"bytes":1305,"sha256":"08097318d2bf066e92d605a2c56b250e4232685986b32cf882ca8b32884f8602"},"crossbuild":{"bytes":9544,"sha256":"4f52eddccf96170bf27d6f217e820279a893e4dd711b49cafae783387bc4016f"},"dependencyInventorySha256":"b89f11a408a83d5447361c297940da11b9f7b86e7426d4416e4bf0ed7592155b","dependencyPost":true,"developerIdSigned":false,"embeddedNoticesComplete":true,"kind":"offline-owned-crossbuild","namespaceOriginals":1,"nativeExecuted":false,"notarized":false,"noticeContentRuntimeExecuted":false,"result":{"bytes":144446,"sha256":"b0163a148c227bc6973790d96cd2171f44c1d204560c8a9378322634e7a3b8fd"},"sourceInventory":{"bytes":624960,"fileBytes":24177947,"fileCount":1918,"sha256":"8b255198a701d0cc48a53ec76c226231689d5ab2c528ce8599b694da8434914d"},"sourcePost":true,"toolchainInventorySha256":"ed83e96ad8c3327bb6056086809e97f07a3419690a5b601b04f552126b8d824e","toolchainPost":true},"notices":{"contentSha256":"3dc7d2cd021d654387e5be71603869a039a3d2adf8b97a6fd0dda4ef3743a44d","files":333,"manifestSha256":"ed34b914139709ddccdedc1d3cd779b28eab05c55f7575266a479af858235294","modules":162},"sourceManifestSha256":"d7587f1290e72781bd65cfce96c397e1e37850c62b50d2cb4259ca006e9332dd","target":"aarch64-apple-darwin"},"nativeAuthority":false,"schemaVersion":1,"state":"unconfigured-publication","uploadAuthorized":false}\n', 'x86_64-apple-darwin': b'{"facts":{"binary":{"bytes":39889552,"sha256":"aca3bcfd4fc35d9bcd800f06fe09f7d6c50ab4d2428f04c4ba081a32bfebbe4e"},"buildOrigin":{"allJoinedZeroAndPipesClosed":true,"buildInfo":{"bytes":15520,"sha256":"cc3137dcf5ad6a9092a525d3ca8eacdcb8899f3256194b67c7f7e190c0731102"},"childOriginals":5,"closedSummary":{"bytes":1305,"sha256":"08097318d2bf066e92d605a2c56b250e4232685986b32cf882ca8b32884f8602"},"crossbuild":{"bytes":9544,"sha256":"4f52eddccf96170bf27d6f217e820279a893e4dd711b49cafae783387bc4016f"},"dependencyInventorySha256":"b89f11a408a83d5447361c297940da11b9f7b86e7426d4416e4bf0ed7592155b","dependencyPost":true,"developerIdSigned":false,"embeddedNoticesComplete":true,"kind":"offline-owned-crossbuild","namespaceOriginals":1,"nativeExecuted":false,"notarized":false,"noticeContentRuntimeExecuted":false,"result":{"bytes":144446,"sha256":"b0163a148c227bc6973790d96cd2171f44c1d204560c8a9378322634e7a3b8fd"},"sourceInventory":{"bytes":624960,"fileBytes":24177947,"fileCount":1918,"sha256":"8b255198a701d0cc48a53ec76c226231689d5ab2c528ce8599b694da8434914d"},"sourcePost":true,"toolchainInventorySha256":"ed83e96ad8c3327bb6056086809e97f07a3419690a5b601b04f552126b8d824e","toolchainPost":true},"notices":{"contentSha256":"087592d4d366fcf2c49851571542959bb91607408c6e677ffdc2484fd7293c2e","files":333,"manifestSha256":"ed34b914139709ddccdedc1d3cd779b28eab05c55f7575266a479af858235294","modules":162},"sourceManifestSha256":"d7587f1290e72781bd65cfce96c397e1e37850c62b50d2cb4259ca006e9332dd","target":"x86_64-apple-darwin"},"nativeAuthority":false,"schemaVersion":1,"state":"unconfigured-publication","uploadAuthorized":false}\n'}
            expected_records = tuple((seal.PROVIDER_INPUT_ROOT + "/" + target + "/build-facts.json",
                                      seal.PROVIDER_FACTS_PINS[target]) for target in seal.TARGETS)
            self.assertEqual(seal.provider_fact_records(), expected_records)
            for target, body in prepared_bodies.items():
                with self.subTest(prepared_target=target):
                    self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), seal.PROVIDER_FACTS_PINS[target])
                    decoded = json.loads(body)
                    actual = seal.capsule_prepared(body, target)
                    self.assertEqual(actual, decoded["facts"])
                    self.assertEqual(actual["target"], target)
                    self.assertEqual(actual["binary"], {"bytes": seal.PROVIDER_PINS[target][0],
                                                       "sha256": seal.PROVIDER_PINS[target][1]})
                    self.assertIsNone(seal.capsule_origin(actual["buildOrigin"]))
                    self.assertEqual(actual["buildOrigin"]["childOriginals"], 5)
                    self.assertEqual(actual["buildOrigin"]["namespaceOriginals"], 1)
                    self.assertIs(decoded["nativeAuthority"], False)
                    self.assertIs(decoded["uploadAuthorized"], False)
                    self.assertNotIn("sourceCommit", actual)
                    self.assertNotIn("runId", actual)
                    other = next(t for t in prepared_bodies if t != target)
                    for changed in (body + b" ", body[:-1], bytearray(body), b"{}\n"):
                        with self.assertRaisesRegex(ValueError, "^capsule-facts-pin$"):
                            seal.capsule_prepared(changed, target)
                    with self.assertRaisesRegex(ValueError, "^capsule-facts-pin$"):
                        seal.capsule_prepared(body, other)
            with self.assertRaisesRegex(ValueError, "^capsule-facts-target$"):
                seal.capsule_prepared(next(iter(prepared_bodies.values())), "other-target")
            target = next(iter(prepared_bodies))
            for pin in (None, [1, "a" * 64], (True, "a" * 64), (0, "a" * 64),
                        (16385, "a" * 64), (1, "0" * 64), (1, "A" * 64), (1, "a" * 63)):
                with self.subTest(unbound_facts=pin), patch.dict(seal.PROVIDER_FACTS_PINS, {target: pin}):
                    with self.assertRaisesRegex(ValueError, "^capsule-facts-unbound$"):
                        seal.provider_fact_records()
            # Rebind ONLY an inert mutated fixture's whole SOURCE hash so these
            # cases reach the real closed parser instead of stopping at hash.
            # This is not a successful production SOURCE or publication grant.
            for path, replacement in (
                    (("schemaVersion",), True), (("nativeAuthority",), 0),
                    (("uploadAuthorized",), True), (("state",), "published"),
                    (("extra",), None), (("facts", "target"), "wrong-target"),
                    (("facts", "sourceManifestSha256"), "0" * 64),
                    (("facts", "binary", "bytes"), True),
                    (("facts", "notices", "files"), True),
                    (("facts", "notices", "extra"), None),
                    (("facts", "buildOrigin", "childOriginals"), 6),
                    (("facts", "buildOrigin", "namespaceOriginals"), True),
                    (("facts", "buildOrigin", "sourcePost"), 1),
                    (("facts", "buildOrigin", "nativeExecuted"), 0),
                    (("facts", "buildOrigin", "result", "bytes"), 262145),
                    (("facts", "buildOrigin", "result", "sha256"), "0" * 64),
                    (("facts", "buildOrigin", "sourceInventory", "fileCount"), 2049),
                    (("facts", "buildOrigin", "runId"), "123")):
                with self.subTest(prepared_shape=path):
                    value = json.loads(prepared_bodies[target])
                    node = value
                    for key in path[:-1]: node = node[key]
                    node[path[-1]] = replacement
                    changed = BUILD.canonical(value) + b"\n"
                    with patch.dict(seal.PROVIDER_FACTS_PINS, {target: (len(changed), hashlib.sha256(changed).hexdigest())}):
                        with self.assertRaises(ValueError): seal.capsule_prepared(changed, target)
            # Same fixed owner route, not a second native/process test. The
            # expected rc1 is accepted only for one exact provider observation.
            self.assertIs(seal.probe_mode([], seal.REFERENCE), False)
            self.assertIs(seal.probe_mode(["--history-provider-probe"], seal.PROVIDER_REFERENCE), True)
            for args, reference in (([], seal.PROVIDER_REFERENCE), (["--history-provider-probe"], seal.REFERENCE),
                                    (["--history-provider-probe", "extra"], seal.PROVIDER_REFERENCE), ([], "refs/heads/main")):
                with self.assertRaises(ValueError):
                    seal.probe_mode(args, reference)
            self.assertEqual(len(seal.ROLE_LIMITS), 23)
            self.assertEqual(seal.PROVIDER_ROLES, (("network-denial", 15, 65536),
                ("provider-version", 15, 65536), ("provider-invalid-controls", 15, 65536)))
            self.assertEqual((seal.WORK_SECONDS, seal.CLEANUP_SECONDS, seal.WORK_ENTRIES, seal.WORK_BYTES),
                             (900, 60, 8192, 512 * 1024 * 1024))
            # Actual both-architecture output and the unchanged upstream
            # changelogURL rule: the modified version's second hyphen chooses
            # /latest, not a fabricated upstream release tag. Keep every byte.
            observed_version = (b"gh version 2.88.1-mrk-history.1 (2026-10-09)\n"
                                b"https://github.com/cli/cli/releases/latest\n")
            self.assertEqual(len(observed_version), 88)
            self.assertEqual(seal.PROVIDER_VERSION, observed_version)
            self.assertTrue(seal.provider_output("provider-version", 0, observed_version, b""))
            for changed_version_output in (
                    observed_version.replace(b"releases/latest", b"releases/tag/v2.88.1-mrk-history.1"),
                    observed_version.replace(b"2.88.1-mrk-history.1", b"2.88.1"),
                    observed_version.replace(b"2026-10-09", b"2026-10-10"),
                    observed_version + b"extra\n"):
                self.assertFalse(seal.provider_output("provider-version", 0, changed_version_output, b""))
            self.assertFalse(seal.provider_output("provider-version", 0, observed_version, b"unexpected\n"))
            self.assertTrue(seal.provider_output("provider-invalid-controls", 1, b"", seal.PROVIDER_REFUSAL))
            for role, code, stdout, stderr in (("provider-version", 1, seal.PROVIDER_VERSION, b""),
                    ("provider-invalid-controls", 0, b"", seal.PROVIDER_REFUSAL),
                    ("provider-invalid-controls", True, b"", seal.PROVIDER_REFUSAL),
                    ("provider-invalid-controls", -9, b"", seal.PROVIDER_REFUSAL),
                    ("provider-invalid-controls", 1, b"", b"authentication required\n"),
                    ("provider-invalid-controls", 1, b"", seal.PROVIDER_REFUSAL + b"extra"),
                    ("provider-invalid-controls", 1, b"unexpected", seal.PROVIDER_REFUSAL),
                    ("helper-native-test", 1, b"", seal.PROVIDER_REFUSAL)):
                self.assertFalse(seal.provider_output(role, code, stdout, stderr))
            # Actual streaming/copy/POST over tiny test-owned inert bytes. A
            # replaced same-content name is not the retained source original.
            with scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                original = root / "input"
                original.write_bytes(b"inert provider bytes; never launched")
                pin = (original.stat().st_size, hashlib.sha256(original.read_bytes()).hexdigest())
                receiver = SimpleNamespace(check=lambda: None, provider_private_retired=False, provider_parents={str(root): BUILD.custody(root.lstat())})
                receiver.provider_parents_post = lambda: seal.SealBuild.provider_parents_post(receiver)
                invoke = lambda **kw: seal.SealBuild.provider_stream(receiver, original, pin, **kw)
                identity, prefix, no_copy = invoke()
                self.assertIsNone(no_copy)
                self.assertEqual(prefix, original.read_bytes())
                copy_path = root / "copied"
                sentinel = object()
                receiver.provider_copy_identity = sentinel
                same_original, copy_prefix, private_copy = invoke(original=identity, destination=copy_path)
                self.assertEqual((same_original, copy_prefix), (identity, prefix))
                self.assertEqual(private_copy, BUILD.identity(copy_path.stat()))
                self.assertIs(receiver.provider_copy_identity, sentinel)
                self.assertEqual(copy_path.read_bytes(), prefix)
                self.assertEqual(copy_path.stat().st_mode & 0o777, 0o555)
                seal.SealBuild.provider_stream(receiver, copy_path, pin, original=private_copy)
                capsule_copy_path = root / "capsule-copy"
                _, _, capsule_copy = invoke(original=identity, destination=capsule_copy_path)
                self.assertNotEqual(capsule_copy, private_copy)
                self.assertEqual(capsule_copy, BUILD.identity(capsule_copy_path.stat()))
                self.assertIs(receiver.provider_copy_identity, sentinel)
                seal.SealBuild.provider_stream(receiver, capsule_copy_path, pin, original=capsule_copy)
                with self.assertRaisesRegex(BUILD.BuildRefused, "provider-input-pin"):
                    seal.SealBuild.provider_stream(receiver, original, (pin[0], "0" * 64))
                saved = root / "saved"
                original.rename(saved)
                original.write_bytes(saved.read_bytes())
                with self.assertRaisesRegex(BUILD.BuildRefused, "provider-input-original"):
                    invoke(original=identity)
                saved.unlink()
                self.assertTrue(BUILD.DATA.known)
                self.assertEqual(BUILD.DATA._pending, 0)
            # A dispatched failed create has no returned original: the SAME
            # existing DATA ledger conservatively remains unknown, even though
            # O_EXCL preserved the prior destination bytes. Never reset it just
            # to continue positive tests in this isolated fixture.
            with scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                original, existing = root / "input", root / "existing"
                original.write_bytes(b"abc"); existing.write_bytes(b"kept")
                pin = (3, hashlib.sha256(b"abc").hexdigest())
                receiver = SimpleNamespace(check=lambda: None, provider_private_retired=False,
                    provider_parents={str(root): BUILD.custody(root.lstat())})
                receiver.provider_parents_post = lambda: seal.SealBuild.provider_parents_post(receiver)
                with self.assertRaises(FileExistsError):
                    seal.SealBuild.provider_stream(receiver, original, pin, destination=existing)
                self.assertEqual(existing.read_bytes(), b"kept")
                self.assertFalse(BUILD.DATA.known)
                self.assertEqual(BUILD.DATA._pending, 1)
            for fault in ("named-post", "close-unknown"):
                with self.subTest(provider_stream=fault), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    path = root / "input"
                    path.write_bytes(b"post-bound inert bytes")
                    pin = (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
                    receiver = SimpleNamespace(check=lambda: None, provider_private_retired=False, provider_parents={str(root): BUILD.custody(root.lstat())})
                    receiver.provider_parents_post = lambda: seal.SealBuild.provider_parents_post(receiver)
                    real_read, real_close = os.read, os.close
                    if fault == "named-post":
                        def changed(fd, size):
                            value = real_read(fd, size)
                            if value == b"":
                                path.rename(root / "retained")
                                path.write_bytes(b"post-bound inert bytes")
                            return value
                        with patch.object(seal.os, "read", changed), self.assertRaisesRegex(BUILD.BuildRefused, "provider-input-post"):
                            seal.SealBuild.provider_stream(receiver, path, pin)
                        self.assertTrue(BUILD.DATA.known)
                    else:
                        def closed_unknown(fd):
                            real_close(fd)  # Real consuming close; no descriptor leak or retry.
                            raise OSError("inert close-observation failure")
                        with patch.object(seal.os, "close", closed_unknown), self.assertRaises(OSError):
                            seal.SealBuild.provider_stream(receiver, path, pin)
                        self.assertFalse(BUILD.DATA.known)
                        self.assertEqual(BUILD.DATA._pending, 1)
                        self.assertFalse(BUILD.public_eligible(failure=None, entered=3, returned=3,
                            ledger={"complete": True, "fatal": False, "contained": True}, handlers="RESTORED",
                            scratch_retired=True, data_finality=BUILD.DATA.known))
            # Exactly two descriptive sidecars use the actual existing stream
            # originals; neither byte equality nor a replacement name is custody.
            for scenario in ("ordinary", "wrong-hash", "replaced", "symlink", "missing", "read-fault", "close-fault"):
                with self.subTest(provider_notices=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    directory = root / "provider-inputs"
                    directory.mkdir()
                    notice_pins, notice_originals = {}, {}
                    parents = {str(root): BUILD.custody(root.lstat()), str(directory): BUILD.custody(directory.lstat())}
                    for target in seal.PROVIDER_PINS:
                        target_dir = directory / target
                        target_dir.mkdir()
                        path = target_dir / "NOTICES.txt"
                        path.write_bytes(b"Complete inert notice bytes; not executable\n")
                        notice_pins[target] = (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
                        notice_originals[target] = BUILD.identity(path.stat())
                        parents[str(target_dir)] = BUILD.custody(target_dir.lstat())
                    receiver = SimpleNamespace(check=lambda: None, provider_private_retired=False, provider_parents=parents,
                                               provider_notice_originals=notice_originals)
                    receiver.provider_parents_post = lambda: seal.SealBuild.provider_parents_post(receiver)
                    receiver.provider_stream = lambda path, pin, **kw: seal.SealBuild.provider_stream(receiver, path, pin, **kw)
                    invoke = lambda: seal.SealBuild.provider_notices_post(receiver)
                    target = next(iter(seal.PROVIDER_PINS))
                    path = directory / target / "NOTICES.txt"
                    original_identity = notice_originals[target]
                    with patch.object(seal, "CHECKOUT", root), patch.object(seal, "PROVIDER_INPUT_ROOT", "provider-inputs"), patch.object(seal, "PROVIDER_NOTICE_PINS", notice_pins):
                        if scenario == "ordinary":
                            invoke()
                            self.assertEqual(notice_originals[target], original_identity)
                        elif scenario == "wrong-hash":
                            notice_pins[target] = (notice_pins[target][0], "0" * 64)
                            with self.assertRaisesRegex(BUILD.BuildRefused, "provider-input-pin"): invoke()
                        elif scenario in {"replaced", "symlink"}:
                            kept = path.with_name("retained")
                            path.rename(kept)
                            if scenario == "replaced": path.write_bytes(kept.read_bytes())
                            else: path.symlink_to("retained")
                            with self.assertRaisesRegex(BUILD.BuildRefused, "provider-input-original"): invoke()
                        elif scenario == "missing":
                            path.unlink()
                            with self.assertRaises(FileNotFoundError): invoke()
                        elif scenario == "read-fault":
                            with patch.object(seal.os, "read", side_effect=OSError("inert read refusal")), self.assertRaises(OSError): invoke()
                        else:
                            actual_close = os.close
                            def notice_close_unknown(fd):
                                actual_close(fd)
                                raise OSError("inert consuming close uncertainty")
                            with patch.object(seal.os, "close", notice_close_unknown), self.assertRaises(OSError): invoke()
                    self.assertEqual(BUILD.DATA.known, scenario != "close-fault")
                    self.assertEqual(BUILD.DATA._pending, 1 if scenario == "close-fault" else 0)
                    self.assertEqual(notice_originals[target], original_identity)
                    if scenario == "close-fault":
                        self.assertFalse(BUILD.public_eligible(failure=None, entered=3, returned=3,
                            ledger={"complete": True, "fatal": False, "contained": True}, handlers="RESTORED",
                            scratch_retired=True, data_finality=BUILD.DATA.known))
            # Real production input roster refuses before the intentionally
            # unavailable stream port; no dummy binary is admitted or launched.
            for scenario in ("missing-notice", "unexpected-leaf"):
                with self.subTest(provider_notice_roster=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    inputs = root / "provider-inputs"
                    inputs.mkdir()
                    for fixture_name in ("source-manifest.json", "crossbuild.json"): (inputs / fixture_name).write_bytes(b"inert")
                    for target in seal.PROVIDER_PINS:
                        target_dir = inputs / target
                        target_dir.mkdir()
                        (target_dir / "gh").write_bytes(b"inert-not-launched")
                        (target_dir / "NOTICES.txt").write_bytes(b"inert")
                    target = next(iter(seal.PROVIDER_PINS))
                    if scenario == "missing-notice": (inputs / target / "NOTICES.txt").unlink()
                    else: (inputs / target / "unexpected").write_bytes(b"refuse")
                    receiver = SimpleNamespace(check=lambda: None, target=target, capsule_mode=False)
                    with patch.object(seal, "CHECKOUT", root), patch.object(seal, "PROVIDER_INPUT_ROOT", "provider-inputs"), patch.object(receiver, "provider_stream", create=True, side_effect=AssertionError("unexpected stream")) as stream:
                        with self.assertRaises(BUILD.BuildRefused): seal.SealBuild.provider_input(receiver)
                        stream.assert_not_called()
                    self.assertTrue(BUILD.DATA.known)
                    self.assertEqual(BUILD.DATA._pending, 0)
            # Capsule inputs have exactly two target directories and exactly
            # gh/NOTICES/facts within each: no old compact-record fallback. The
            # first stream is deliberately unavailable, so malformed rosters
            # must refuse before any binary or native-tool admission.
            for scenario in ("missing-facts", "extra-target-file", "old-root-record"):
                with self.subTest(capsule_input_roster=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    inputs = root / "provider-inputs"
                    inputs.mkdir()
                    for target in seal.TARGETS:
                        target_dir = inputs / target
                        target_dir.mkdir()
                        (target_dir / "gh").write_bytes(b"inert-not-launched")
                        (target_dir / "NOTICES.txt").write_bytes(b"inert")
                        (target_dir / "build-facts.json").write_bytes(prepared_bodies[target])
                    target = next(iter(seal.TARGETS))
                    if scenario == "missing-facts": (inputs / target / "build-facts.json").unlink()
                    elif scenario == "extra-target-file": (inputs / target / "extra").write_bytes(b"refuse")
                    else: (inputs / "crossbuild.json").write_bytes(b"no raw evidence fallback")
                    receiver = SimpleNamespace(check=lambda: None, target=target, capsule_mode=True)
                    with patch.object(seal, "CHECKOUT", root), patch.object(seal, "PROVIDER_INPUT_ROOT", "provider-inputs"), patch.object(receiver, "provider_stream", create=True, side_effect=AssertionError("unexpected stream")) as stream:
                        with self.assertRaises(BUILD.BuildRefused): seal.SealBuild.provider_input(receiver)
                        stream.assert_not_called()
                    self.assertTrue(BUILD.DATA.known)
                    self.assertEqual(BUILD.DATA._pending, 0)
            # Production run loop with an inert returned-value port, never a
            # subprocess. Wrong role refuses before that port, wrong return
            # shape cannot increment a successful command observation.
            for scenario in ("exact", "wrong-role", "wrong-exit", "wrong-output", "wrong-original"):
                trace = []
                receiver = SimpleNamespace(provider_mode=True, role_limits=seal.PROVIDER_ROLES, entered=2, returned=2,
                    sandbox="/fixed/sandbox", private=Path("/fixed/private"), environment={}, commands=[],
                    check=lambda: None, provider_post=lambda: trace.append("post"), recheck_tools=lambda: None,
                    evidence_bytes=lambda n, b: hashlib.sha256(b).hexdigest(), census=lambda: {"entries": 0, "bytes": 0},
                    deadline=time.monotonic() + 60, guard=SimpleNamespace(lifetime_ledger=SimpleNamespace(verdict=lambda:
                        SimpleNamespace(complete=True, fatal=False, contained=True))))
                def returned(argv, **kwargs):
                    trace.append("run")
                    return subprocess.CompletedProcess(argv if scenario != "wrong-original" else [],
                        0 if scenario == "wrong-exit" else 1, b"", b"wrong" if scenario == "wrong-output" else seal.PROVIDER_REFUSAL)
                receiver.owner = SimpleNamespace(run_owned=returned)
                if scenario == "exact":
                    result = seal.SealBuild.run(receiver, "provider-invalid-controls", ["/fixed/gh", "api"])
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual((receiver.entered, receiver.returned), (3, 3))
                    self.assertEqual(trace, ["post", "run", "post"])
                else:
                    with self.assertRaises(BUILD.BuildRefused):
                        seal.SealBuild.run(receiver, "provider-version" if scenario == "wrong-role" else "provider-invalid-controls", ["/fixed/gh", "api"])
                    if scenario == "wrong-role":
                        self.assertEqual(trace, [])
                # No parser return is an actual entry/publication grant.
                self.assertFalse(BUILD.public_eligible(failure=None, entered=3, returned=3,
                    ledger={"complete": False, "fatal": False, "contained": True}, handlers="RESTORED",
                    scratch_retired=True, data_finality=True))
            workflow = (ROOT / ".github/workflows/desktop-macos-github-seal.yml").read_text()
            self.assertIn("      - verify/desktop-macos-github-seal\n      - verify/desktop-macos-history-provider-probe\n", workflow)
            self.assertEqual(workflow.count("--history-provider-probe --publish-build-capsule\n"), 1)
            self.assertEqual(workflow.count("macos_github_seal_build.py --publish-build-capsule\n"), 1)
            self.assertIn("test \"$GITHUB_REF\" = refs/heads/verify/desktop-macos-github-seal", workflow)
            self.assertIn("timeout-minutes: 25", workflow)
            self.assertIn("if-no-files-found: ignore", workflow)
            self.assertNotIn("workflow_dispatch", workflow)
            # Only two success-gated capsules; diagnostic upload remains
            # separate and cannot turn an original failure into product evidence.
            for title, purpose, ref, prefix, binary in (
                    ("History provider", "history-provider", seal.PROVIDER_REFERENCE, "mrk-history-provider", "gh"),
                    ("sealed-box helper", "github-seal", seal.REFERENCE, "mrk-github-seal", "mrk-github-seal")):
                marker = "      - name: Publish finalized " + title + " build capsule\n"
                self.assertEqual(workflow.count(marker), 1)
                step = workflow.split(marker, 1)[1].split("      - name:", 1)[0]
                self.assertIn("        if: success() && github.ref == '" + ref
                    + "' && steps.build.outcome == 'success' && steps.sourcepost.outcome == 'success'\n", step)
                self.assertIn("        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", step)
                self.assertIn("          name: tool-build-" + purpose
                    + "-${{ matrix.target }}-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}\n", step)
                directory = "/Users/runner/work/_temp/" + prefix + "-${{ matrix.target }}-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}/capsule/"
                self.assertIn("          path: |\n            " + directory + binary
                    + "\n            " + directory + "tool-build-receipt.json\n", step)
                self.assertEqual(step.count(directory), 2)
                for line in ("if-no-files-found: error", "compression-level: 0", "retention-days: 7"):
                    self.assertIn("          " + line + "\n", step)
                self.assertNotIn("/public/", step)
                self.assertNotIn("always()", step)
            self.assertEqual(workflow.count("          if-no-files-found: error\n"), 2)
            # Receipt DATA comes from the actual method, with checked publication
            # IDs distinct from the offline provider build origin. No receipt
            # by itself proves the enclosing original returned successfully.
            receipt_fields = {"schemaVersion", "kind", "purpose", "target", "sourceCommit",
                "sourceManifestSha256", "binary", "notices", "runId", "runAttempt",
                "sourcePost", "originalsClosed", "productsFinal"}
            source_rows = {"inert-source.py": {"size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}}
            source_commit = "a" * 40
            source_evidence = BUILD.canonical({"sourceCommit": source_commit, "rows": source_rows})
            for purpose in seal.CAPSULE_PURPOSES:
                provider = purpose == "history-provider"
                facts = json.loads(prepared_bodies[target])["facts"]
                pin = (facts["binary"]["bytes"], facts["binary"]["sha256"]) if provider else (3, hashlib.sha256(b"abc").hexdigest())
                receiver = SimpleNamespace(target=target, source=source_commit, run_id="9007199254740991", attempt="9007199254740991",
                    source_binding=source_rows, evidence={"source-binding.json": source_evidence},
                    capsule_purpose=purpose, provider_mode=provider, capsule_pin=pin, provider_prepared={target: facts})
                body = seal.SealBuild.capsule_receipt(receiver)
                value = json.loads(body)
                self.assertLessEqual(len(body), 16384)
                self.assertEqual(set(value), receipt_fields | ({"buildOrigin"} if provider else set()))
                self.assertEqual((value["sourceCommit"], value["runId"], value["runAttempt"]),
                                 (source_commit, "9007199254740991", "9007199254740991"))
                self.assertEqual(value["purpose"], purpose)
                self.assertTrue(all(value[key] is True for key in ("sourcePost", "originalsClosed", "productsFinal")))
                if provider:
                    self.assertEqual(value["buildOrigin"], facts["buildOrigin"])
                    self.assertEqual(value["notices"], facts["notices"])
                    self.assertEqual(value["sourceManifestSha256"], facts["sourceManifestSha256"])
                else:
                    self.assertIsNone(value["notices"])
                    self.assertNotIn("buildOrigin", value)
                    self.assertEqual(value["sourceManifestSha256"], hashlib.sha256(source_evidence).hexdigest())
                for field, bad in (("run_id", "0"), ("run_id", "01"), ("run_id", "1" * 17),
                        ("run_id", 1), ("attempt", True), ("attempt", "1" * 17),
                        ("run_id", "9007199254740992"), ("attempt", "9007199254740992"),
                        ("source", "0" * 40), ("source", "A" * 40), ("target", "wrong-target")):
                    with self.subTest(capsule_context=(purpose, field, bad)), patch.object(receiver, field, bad):
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-publication-context$"):
                            seal.SealBuild.capsule_receipt(receiver)
                for changed_source in (BUILD.canonical({"sourceCommit": source_commit, "rows": {}}),
                                       source_evidence + b" ", BUILD.canonical(source_rows)):
                    with patch.object(receiver, "evidence", {"source-binding.json": changed_source}):
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-full-source-binding$"):
                            seal.SealBuild.capsule_receipt(receiver)

            # Tiny real files exercise the existing streaming/copy/readback,
            # parent originals, same-task census and consuming retirement. No
            # executable or native build is admitted; only prerequisite source
            # and provider observations are inert ports, kept explicit here.
            def capsule_fixture(root, purpose):
                work = root / "work"
                work.mkdir(mode=0o700)
                private = work / "private"
                private.mkdir(mode=0o700)
                (private / "bounded-work").write_bytes(b"five!")
                export = work / "export-pending"
                export.mkdir(mode=0o700)
                provider = purpose == "history-provider"
                if provider:
                    original = root / "inert-provider"
                else:
                    (export / "helper").mkdir(mode=0o700)
                    original = export / "helper/mrk-github-seal"
                original.write_bytes(b"abc")
                original.chmod(0o555)
                pin = (3, hashlib.sha256(b"abc").hexdigest())
                receiver = SimpleNamespace(work=work, private=private, public=work / "public", export=export,
                    work_identity=BUILD.custody(work.lstat()), private_identity=BUILD.custody(private.lstat()),
                    export_identity=BUILD.custody(export.lstat()),
                    export_helper_identity=None if provider else BUILD.custody((export / "helper").lstat()),
                    export_promoted=False, capsule_promoted=False, capsule_mode=True, capsule_purpose=purpose,
                    capsule_pending=work / "capsule-pending", capsule_public=work / "capsule",
                    capsule_identity=None, capsule_copy_identity=None, capsule_receipt_identity=None,
                    provider_mode=provider, provider_private_retired=False, provider_parents={}, provider_source_parents={},
                    provider_original=original, provider_pin=pin, provider_identity=BUILD.identity(original.lstat()),
                    success_ready=True, failure=None, source_post=True, inflight=False, cleaning=True,
                    deadline=time.monotonic() + 60, cleanup_deadline=time.monotonic() + 60,
                    source=source_commit, target=target, run_id="123", attempt="1", source_binding=source_rows,
                    native={"helperExecutable": {"bytes": 3, "sha256": pin[1]}},
                    export_rows={} if provider else {"helper/mrk-github-seal": {"size": 3, "sha256": pin[1]}},
                    evidence={"source-binding.json": source_evidence}, commands=[], cleanup_errors=[], scratch_retired=False,
                    entered=3 if provider else 23, returned=3 if provider else 23,
                    role_limits=seal.PROVIDER_ROLES if provider else seal.ROLE_LIMITS,
                    guard=SimpleNamespace(handler_state="RESTORED", lifetime_ledger=SimpleNamespace(
                        verdict=lambda: SimpleNamespace(complete=True, fatal=False, contained=True))))
                receiver.provider_post = lambda **kwargs: None  # Previously admitted provider observation, not a probe.
                for method in ("check", "final_check", "mkdir", "census", "evidence_bytes", "evidence_json",
                        "provider_parents_post", "provider_stream", "capsule_reserve", "capsule_parents_post",
                        "capsule_products_post", "capsule_source_post", "prepare_capsule", "capsule_receipt",
                        "retire_capsule", "publish_capsule", "publish"):
                    setattr(receiver, method, getattr(seal.SealBuild, method).__get__(receiver))
                return receiver

            # Positive tiny-file cases supply bounded free-space DATA for the
            # unchanged full-size production reservation; they do not allocate
            # that capacity in the 32MiB scratch. Zero-space refusal stays below.
            for purpose in seal.CAPSULE_PURPOSES:
                with self.subTest(capsule_copy=purpose), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    receiver = capsule_fixture(root, purpose)
                    with patch.object(seal, "source_snapshot", return_value=source_rows) as snapshot, \
                            patch.object(seal.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * seal.WORK_BYTES)) as storage:
                        receiver.prepare_capsule()
                        storage.assert_called_once_with(receiver.work)
                        self.assertEqual(receiver.capsule_reservation["bytes"], seal.CAPSULE_PURPOSES[purpose][1] + 16384)
                        expected = (sum(row["size"] for row in receiver.export_rows.values())
                            + sum(map(len, receiver.evidence.values())) + seal.QUERY_LIMIT
                            + seal.CAPSULE_PURPOSES[purpose][1] + 16384)
                        self.assertEqual(receiver.capsule_reservation["combinedBytes"], expected)
                        self.assertEqual(receiver.capsule_reservation["combinedEntries"],
                            1 + len(receiver.export_rows) + len(receiver.evidence)
                            + (2 if receiver.provider_mode else 3) + 6)
                        self.assertEqual(snapshot.call_args.kwargs, {"provider": receiver.provider_mode, "capsule": True})
                        self.assertNotEqual(receiver.capsule_copy_identity, receiver.provider_identity)
                        binary = receiver.capsule_pending / seal.CAPSULE_PURPOSES[purpose][0]
                        self.assertEqual(binary.read_bytes(), b"abc")
                        self.assertEqual(binary.stat().st_mode & 0o777, 0o555)
                        self.assertEqual(receiver.capsule_copy_identity, BUILD.identity(binary.lstat()))
                        self.assertEqual(sorted(p.name for p in receiver.capsule_pending.iterdir()), [binary.name])
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-output-collision$"):
                            receiver.prepare_capsule()
                        receiver.capsule_products_post()
                        if purpose == "github-seal":
                            BUILD.retire_tree(receiver.private, receiver.cleanup_deadline)
                            receiver.scratch_retired = True
                            receiver.publish(receiver.guard.lifetime_ledger.verdict())
                            self.assertFalse(receiver.capsule_pending.exists())
                            self.assertTrue(receiver.capsule_promoted)
                            self.assertEqual(sorted(p.name for p in receiver.capsule_public.iterdir()),
                                ["mrk-github-seal", "tool-build-receipt.json"])
                            receipt = receiver.capsule_public / "tool-build-receipt.json"
                            self.assertEqual(receipt.stat().st_mode & 0o777, 0o444)
                            self.assertEqual(json.loads(receipt.read_bytes())["sourceManifestSha256"], hashlib.sha256(source_evidence).hexdigest())
                            receiver.capsule_products_post(receipt=True)
                        receiver.retire_capsule()
                        self.assertIsNone(receiver.capsule_identity)
                        self.assertFalse(receiver.capsule_pending.exists() or receiver.capsule_public.exists())
                    self.assertTrue(BUILD.DATA.known)
                    self.assertEqual(BUILD.DATA._pending, 0)

            # Budget refusals happen before mkdir/copy. Large amounts are scalar
            # DATA, never giant fixture allocations or independent quota pools.
            for scenario in ("public", "combined-work", "combined-entries", "space", "census-bool"):
                with self.subTest(capsule_quota=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    receiver = capsule_fixture(root, "github-seal")
                    if scenario == "public": receiver.export_rows["oversized"] = {"size": seal.PUBLIC_BYTES}
                    if scenario == "combined-work": receiver.census = lambda: {"entries": 0, "bytes": seal.WORK_BYTES}
                    if scenario == "combined-entries": receiver.census = lambda: {"entries": seal.WORK_ENTRIES, "bytes": 0}
                    if scenario == "census-bool": receiver.census = lambda: {"entries": True, "bytes": 0}
                    usage = SimpleNamespace(free=0 if scenario == "space" else 2 * seal.WORK_BYTES)
                    with patch.object(seal.shutil, "disk_usage", return_value=usage), patch.object(receiver, "mkdir", side_effect=AssertionError("copy must not start")) as mkdir:
                        with self.assertRaises(BUILD.BuildRefused): receiver.prepare_capsule()
                        mkdir.assert_not_called()
                    self.assertFalse(receiver.capsule_pending.exists())
                    self.assertIsNone(receiver.capsule_identity)
                    self.assertTrue(BUILD.DATA.known)

            for scenario in ("binary-substitute", "parent-substitute", "unexpected-member", "source-post", "close-unknown"):
                with self.subTest(capsule_refusal=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    receiver = capsule_fixture(root, "github-seal")
                    with patch.object(seal, "source_snapshot", return_value=source_rows), \
                            patch.object(seal.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * seal.WORK_BYTES)):
                        receiver.prepare_capsule()
                    binary = receiver.capsule_pending / "mrk-github-seal"
                    if scenario == "binary-substitute":
                        binary.rename(root / "kept-original")
                        binary.write_bytes(b"abc"); binary.chmod(0o555)
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^provider-input-original$"):
                            receiver.capsule_products_post()
                    elif scenario == "parent-substitute":
                        receiver.capsule_pending.rename(receiver.work / "kept-directory")
                        receiver.capsule_pending.mkdir(mode=0o700)
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-directory-original$"):
                            receiver.capsule_products_post()
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-directory-original$"):
                            receiver.retire_capsule()
                    elif scenario == "unexpected-member":
                        (receiver.capsule_pending / "extra").write_bytes(b"x")
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-member-roster$"):
                            receiver.capsule_products_post()
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-member-roster$"):
                            receiver.retire_capsule()
                    elif scenario == "source-post":
                        with patch.object(seal, "source_snapshot", return_value={}):
                            with self.assertRaisesRegex(BUILD.BuildRefused, "^verification-source-final-post$"):
                                receiver.capsule_source_post()
                    else:
                        actual_close = os.close
                        def capsule_close_unknown(fd):
                            actual_close(fd)
                            raise OSError("inert consuming close uncertainty")
                        with patch.object(seal.os, "close", capsule_close_unknown), self.assertRaises(OSError):
                            receiver.capsule_products_post()
                        self.assertFalse(BUILD.DATA.known)
                        with patch.object(receiver, "final_check", side_effect=AssertionError("unknown cannot retire")) as check:
                            receiver.retire_capsule()
                            check.assert_not_called()
                        self.assertTrue(binary.exists())
                    self.assertFalse(receiver.capsule_public.exists())

            # Exercise the actual cleanup branch after a real copy failure.
            # Retained export bytes are already represented by the tiny fixture;
            # only the earlier compiler/product-retention stage is an inert port.
            # Known custody permits exact retirement before rethrowing the first
            # failure. Unknown close cannot claim scratch retirement or discover
            # a new cleanup capability from the visible pending path.
            for scenario in ("known-copy", "unknown-close", "pending-retirement", "export-retirement"):
                with self.subTest(capsule_cleanup=scenario), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    receiver = capsule_fixture(root, "github-seal")
                    receiver.libtool_alias_originals = {}
                    receiver.retain_products = lambda: None
                    observed = []
                    actual_prepare = receiver.prepare_capsule
                    def observed_prepare():
                        try: actual_prepare()
                        except BaseException as error:
                            observed.append(error)
                            raise
                    receiver.prepare_capsule = observed_prepare
                    retired = []
                    actual_retire = BUILD.retire_tree
                    retirement_error = OSError("inert consuming retirement failure")
                    def retiring(path, deadline):
                        retired.append(path)
                        if (scenario == "pending-retirement" and path == receiver.capsule_pending
                                or scenario == "export-retirement" and path == receiver.export):
                            raise retirement_error
                        return actual_retire(path, deadline)
                    actual_close = os.close
                    close_error = OSError("inert consuming close uncertainty")
                    close_failed = [False]
                    def closing(fd):
                        actual_close(fd)
                        if scenario == "unknown-close" and not close_failed[0]:
                            close_failed[0] = True
                            raise close_error
                    actual_write = os.write
                    def writing(fd, data):
                        return actual_write(fd, data) if scenario == "unknown-close" else 0
                    with patch.object(seal, "source_snapshot", return_value=source_rows), \
                            patch.object(seal.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * seal.WORK_BYTES)), \
                            patch.object(seal.os, "write", side_effect=writing), \
                            patch.object(seal.os, "close", side_effect=closing), \
                            patch.object(BUILD, "retire_tree", side_effect=retiring):
                        with self.assertRaises((BUILD.BuildRefused, OSError)) as raised:
                            seal.SealBuild.cleanup(receiver)
                    self.assertEqual(len(observed), 1)
                    self.assertIs(raised.exception, observed[0])
                    self.assertFalse(receiver.capsule_public.exists())
                    if scenario == "unknown-close":
                        self.assertIs(raised.exception, close_error)
                        self.assertFalse(BUILD.DATA.known)
                        self.assertFalse(receiver.scratch_retired)
                        self.assertEqual(retired, [])
                        self.assertTrue(receiver.private.exists())
                        self.assertTrue(receiver.export.exists())
                        self.assertTrue(receiver.capsule_pending.exists())
                        self.assertIsNotNone(receiver.capsule_identity)
                    else:
                        self.assertEqual(str(raised.exception), "provider-copy-short")
                        self.assertTrue(BUILD.DATA.known)
                        self.assertEqual(BUILD.DATA._pending, 0)
                        self.assertTrue(receiver.scratch_retired)
                        self.assertFalse(receiver.private.exists())
                        if scenario == "known-copy":
                            self.assertEqual(retired, [receiver.private, receiver.capsule_pending, receiver.export])
                            self.assertFalse(receiver.capsule_pending.exists() or receiver.export.exists())
                            self.assertIsNone(receiver.capsule_identity)
                            self.assertIsNone(receiver.export_identity)
                            self.assertIsNone(receiver.export_helper_identity)
                            self.assertEqual(receiver.export_rows, {})
                        else:
                            self.assertIs(raised.exception.__cause__, retirement_error)
                            self.assertTrue(receiver.export.exists())
                            if scenario == "pending-retirement":
                                self.assertEqual(retired, [receiver.private, receiver.capsule_pending])
                                self.assertTrue(receiver.capsule_pending.exists())
                                self.assertIsNotNone(receiver.capsule_identity)
                            else:
                                self.assertEqual(retired, [receiver.private, receiver.capsule_pending, receiver.export])
                                self.assertFalse(receiver.capsule_pending.exists())
                                self.assertIsNone(receiver.capsule_identity)
                            self.assertIsNotNone(receiver.export_identity)
                            self.assertTrue(receiver.export_rows)
            # A late capsule refusal AFTER the real evidence directory was
            # promoted still raises. A diagnostic report that says passed is
            # not the enclosing original's exit and cannot permit an upload.
            with scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                receiver = capsule_fixture(root, "github-seal")
                with patch.object(seal, "source_snapshot", return_value=source_rows), \
                        patch.object(seal.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * seal.WORK_BYTES)):
                    receiver.prepare_capsule()
                BUILD.retire_tree(receiver.private, receiver.cleanup_deadline)
                receiver.scratch_retired = True
                def late_source(*args, **kwargs):
                    return {} if receiver.export_promoted else source_rows
                with patch.object(seal, "source_snapshot", side_effect=late_source):
                    with self.assertRaisesRegex(BUILD.BuildRefused, "^verification-source-final-post$"):
                        receiver.publish(receiver.guard.lifetime_ledger.verdict())
                self.assertTrue(receiver.export_promoted)
                report = json.loads((receiver.public / "report.json").read_bytes())
                self.assertEqual(report["status"], "passed")
                self.assertEqual(report["transportState"], "pending-original-entry-exit")
                self.assertFalse(receiver.capsule_public.exists())
                self.assertTrue(receiver.capsule_pending.exists())
                receiver.retire_capsule()
                self.assertFalse(receiver.capsule_pending.exists())
                self.assertTrue(BUILD.DATA.known)
                self.assertEqual(BUILD.DATA._pending, 0)
            # No later SOURCE/copy/receipt port is entered unless the SAME
            # original has all required finality observations, including bools.
            for scenario in ("passed-false", "passed-int", "failure", "source", "inflight", "counts",
                             "ledger", "fatal", "contained", "handlers", "scratch", "data"):
                with self.subTest(capsule_finality=scenario), patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    verdict = SimpleNamespace(complete=scenario != "ledger", fatal=scenario == "fatal", contained=scenario != "contained")
                    receiver = SimpleNamespace(success_ready=True, source_post=scenario != "source", inflight=scenario == "inflight",
                        entered=3, returned=2 if scenario == "counts" else 3, role_limits=seal.PROVIDER_ROLES,
                        failure={} if scenario == "failure" else None, scratch_retired=scenario != "scratch",
                        guard=SimpleNamespace(handler_state="OWNED" if scenario == "handlers" else "RESTORED",
                            lifetime_ledger=SimpleNamespace(verdict=lambda: verdict)))
                    if scenario == "data": BUILD.DATA.unknown()
                    passed = False if scenario == "passed-false" else 1 if scenario == "passed-int" else True
                    with patch.object(receiver, "capsule_source_post", create=True, side_effect=AssertionError("no source port")) as post:
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^capsule-original-finality$"):
                            seal.SealBuild.publish_capsule(receiver, passed)
                        post.assert_not_called()
            # All nine fixed official metadata aliases are ordinary generated
            # work, including eight convenience archives on both Darwin CPUs.
            self.assertEqual(set(seal.LIBTOOL_ARCHIVES), {
                "libsodium.la", "libaesni.la", "libarmcrypto.la", "libsse2.la",
                "libssse3.la", "libsse41.la", "libavx2.la", "libavx512f.la", "librdrand.la",
            })
            with scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                parent = root / "build/src/libsodium/.libs"
                parent.mkdir(parents=True)
                verdict = SimpleNamespace(complete=True, fatal=False, contained=True)
                receiver = SimpleNamespace(private=root, check=lambda: None, libtool_alias_originals={},
                    guard=SimpleNamespace(lifetime_ledger=SimpleNamespace(verdict=lambda: verdict)),
                    cleaning=True, inflight=False)
                for alias_name in seal.LIBTOOL_ARCHIVES:
                    (parent.parent / alias_name).write_bytes(b"fixed generated metadata")
                    (parent / alias_name).symlink_to("../" + alias_name)
                first = parent / "libaesni.la"
                with self.assertRaisesRegex(BUILD.BuildRefused, "^generated-alias-unrecorded$"):
                    seal.SealBuild.libtool_alias(receiver, first, retire=True)
                self.assertTrue(first.is_symlink())
                self.assertEqual(receiver.libtool_alias_originals, {})
                for alias_name in seal.LIBTOOL_ARCHIVES:
                    seal.SealBuild.libtool_alias(receiver, parent / alias_name)
                self.assertEqual(set(receiver.libtool_alias_originals), set(seal.LIBTOOL_ARCHIVES))
                receiver.libtool_alias = lambda path, retire=False: seal.SealBuild.libtool_alias(receiver, path, retire=retire)
                for alias_name in seal.LIBTOOL_ARCHIVES:
                    receiver.libtool_alias(parent / alias_name, retire=True)
                    self.assertFalse((parent / alias_name).is_symlink())
                    self.assertEqual((parent.parent / alias_name).read_bytes(), b"fixed generated metadata")
                self.assertEqual(set(receiver.libtool_alias_originals), set(seal.LIBTOOL_ARCHIVES))
                self.assertTrue(BUILD.DATA.known)
                self.assertEqual(BUILD.DATA._pending, 0)
            # Real private files and symlinked DIRECTORY spellings exercise
            # original identity and the production tool admission/POST. These
            # tiny executable-mode text fixtures are NEVER executed as tools.
            for mode in ("same-spelling", "directory-alias", "wrong-file", "not-executable",
                         "before-admission-change", "after-admission-change", "content-change"):
                with self.subTest(python_entry=mode), scratch() as root, patch.object(BUILD, "DATA", BUILD.DataFinality()):
                    actual = root / "actual"
                    actual.mkdir()
                    binary = actual / "python"
                    binary.write_bytes(b"inert fixed interpreter fixture")
                    binary.chmod(0o700 if mode != "not-executable" else 0o600)
                    alias = root / "alias"
                    alias.symlink_to("actual", target_is_directory=True)
                    other = root / "other"
                    other.mkdir()
                    replacement = other / "python"
                    replacement.write_bytes(binary.read_bytes())
                    replacement.chmod(0o700)
                    chosen = str(binary if mode == "same-spelling" else alias / "python")
                    reported = str(replacement if mode == "wrong-file" else binary)
                    if mode in {"wrong-file", "not-executable"}:
                        with self.assertRaisesRegex(ValueError, "actual-setup-python-entry"):
                            seal.python_entry_binding(chosen, reported)
                        continue
                    binding = seal.python_entry_binding(chosen, reported)
                    self.assertEqual(binding[1], str(binary.resolve(strict=True)))
                    self.assertEqual(binding[2], BUILD.identity(binary.lstat()))
                    receiver = SimpleNamespace(python_binding=binding, tools={}, tool_parents={},
                                               runtime_rosters={}, check=lambda: None)
                    receiver.protected_tool = lambda path, **kw: seal.SealBuild.protected_tool(receiver, path, **kw)
                    if mode == "before-admission-change":
                        alias.unlink()
                        alias.symlink_to("other", target_is_directory=True)
                        with self.assertRaisesRegex(ValueError, "actual-setup-python-entry"):
                            seal.SealBuild.python_tools(receiver)
                        self.assertEqual(receiver.tools, {})
                        continue
                    self.assertEqual(seal.SealBuild.python_tools(receiver), chosen)
                    self.assertEqual(set(receiver.tools), {chosen, reported})
                    self.assertEqual(receiver.tools[chosen]["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
                    seal.SealBuild.recheck_tools(receiver, full=True)
                    if mode == "after-admission-change":
                        alias.unlink()
                        alias.symlink_to("other", target_is_directory=True)
                    elif mode == "content-change":
                        binary.write_bytes(b"different interpreter bytes")
                    if mode in {"after-admission-change", "content-change"}:
                        expected_reason = ("original-tool-parent-changed" if mode == "after-admission-change"
                                           else "original-tool-changed")
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^" + expected_reason + "$"):
                            seal.SealBuild.recheck_tools(receiver, full=True)
                    self.assertTrue(BUILD.DATA.known)
                    self.assertEqual(BUILD.DATA._pending, 0)
            # Dedicated hosted preparation uses a real tiny file/FD/chmod;
            # only root/platform identity is synthetic. Never elevate a test.
            for scenario in ("tighten", "already-protected", "foreign-owner", "wrong-mode", "chmod-failed", "alias-changed"):
                with self.subTest(python_mode=scenario), scratch() as root:
                    target = root / "python"
                    target.write_bytes(b"inert Python fixture; never executable code")
                    target.chmod(0o755 if scenario == "already-protected" else 0o777 if scenario == "wrong-mode" else 0o775)
                    selected = root / "action-python"
                    selected.symlink_to(target.name)
                    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                    real_stat, real_lstat, real_fstat, real_chmod = Path.stat, Path.lstat, os.fstat, os.fchmod
                    def root_facts(value):
                        data = {key: getattr(value, key) for key in fields}
                        if BUILD.stat.S_ISREG(value.st_mode):
                            data["st_uid"] = 1 if scenario == "foreign-owner" else 0
                        return SimpleNamespace(**data)
                    def named_stat(path, *args, **kwargs):
                        return root_facts(real_stat(path, *args, **kwargs))
                    def named_lstat(path, *args, **kwargs):
                        return root_facts(real_lstat(path, *args, **kwargs))
                    def chmod(fd, mode):
                        if scenario == "chmod-failed":
                            raise PermissionError("synthetic denied mode change")
                        real_chmod(fd, mode)
                        if scenario == "alias-changed":
                            selected.unlink(); selected.symlink_to("missing")
                    with patch.object(seal, "B", None), patch.object(sys, "platform", "darwin"), \
                         patch.object(sys, "version_info", (3, 14, 7)), patch.object(sys, "executable", str(target)), \
                         patch.object(os, "getuid", return_value=0), patch.object(os, "geteuid", return_value=0), \
                         patch.object(Path, "stat", named_stat), patch.object(Path, "lstat", named_lstat), \
                         patch.object(os, "fstat", lambda fd: root_facts(real_fstat(fd))), \
                         patch.object(os, "fchmod", side_effect=chmod) as changed:
                        if scenario in {"foreign-owner", "wrong-mode"}:
                            with self.assertRaisesRegex(ValueError, "^hosted-python-preparation-original$"):
                                seal.prepare_hosted_python(str(selected))
                            changed.assert_not_called()
                        elif scenario == "chmod-failed":
                            with self.assertRaises(PermissionError):
                                seal.prepare_hosted_python(str(selected))
                            changed.assert_called_once()
                        elif scenario == "alias-changed":
                            with self.assertRaises(FileNotFoundError):
                                seal.prepare_hosted_python(str(selected))
                            changed.assert_called_once()
                        else:
                            seal.prepare_hosted_python(str(selected))
                            self.assertEqual(changed.call_count, 0 if scenario == "already-protected" else 1)
                    self.assertEqual(target.read_bytes(), b"inert Python fixture; never executable code")
                    if scenario in {"tighten", "already-protected", "alias-changed"}:
                        self.assertEqual(BUILD.stat.S_IMODE(target.stat().st_mode), 0o755)
            with patch.object(seal, "B", None), patch.object(os, "open", side_effect=AssertionError("context must refuse before open")) as opened:
                with self.assertRaisesRegex(ValueError, "^hosted-python-preparation-context$"):
                    seal.prepare_hosted_python("/unadmitted")
                opened.assert_not_called()
            # The actual protected_tool leaf gate emits only the reused
            # bounded scalar/role envelope. Inert lstat facts force each
            # predicate in its ORIGINAL order; no tool read/run is admitted.
            for condition in ("kind", "owner", "executable", "mode", "bad-scalar"):
                with self.subTest(tool_admission=condition), scratch() as root:
                    path = root / "private-tool-name-not-for-evidence"
                    path.write_bytes(b"inert-never-executed")
                    path.chmod(0o700)
                    actual = path.lstat()
                    foreign_uid = os.getuid() + 1 or 1
                    fields = dict(st_mode=actual.st_mode, st_uid=actual.st_uid,
                                  st_gid=actual.st_gid, st_nlink=actual.st_nlink)
                    if condition == "kind":
                        fields.update(st_mode=BUILD.stat.S_IFDIR | 0o622, st_uid=foreign_uid)
                    elif condition in {"owner", "bad-scalar"}:
                        fields.update(st_uid=-1 if condition == "bad-scalar" else foreign_uid,
                                      st_mode=BUILD.stat.S_IFREG | 0o622)
                    elif condition == "executable":
                        fields.update(st_mode=BUILD.stat.S_IFREG | 0o622)
                    else:
                        fields.update(st_mode=BUILD.stat.S_IFREG | 0o722)
                    records = []
                    receiver = SimpleNamespace(check=lambda: None, tools={}, tool_parents={},
                        evidence_json=lambda name, value: records.append((name, value)))
                    original_lstat = Path.lstat
                    def selected_lstat(selected, *args, **kwargs):
                        return SimpleNamespace(**fields) if selected == path else original_lstat(selected, *args, **kwargs)
                    with patch.object(Path, "lstat", selected_lstat), \
                         patch.object(BUILD, "read", side_effect=AssertionError("unadmitted tool read")) as read:
                        reason = "tool-diagnostic-scalar" if condition == "bad-scalar" else "unprotected-selected-tool"
                        with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                            seal.SealBuild.protected_tool(receiver, path, role="python", system=False)
                        read.assert_not_called()
                    self.assertEqual(receiver.tools, {})
                    if condition == "bad-scalar":
                        self.assertEqual(records, [])
                    else:
                        expected = {"schemaVersion": 1, "role": "python", "condition": condition,
                            "AppleSystem": False, "executableRequired": True, "uid": fields["st_uid"],
                            "gid": fields["st_gid"], "mode": fields["st_mode"], "nlink": fields["st_nlink"],
                            "hostUid": os.getuid()}
                        self.assertEqual(records, [("tool-admission-failure.json", expected)])
                        encoded = BUILD.canonical(expected)
                        self.assertLessEqual(len(encoded), 512)
                        self.assertNotIn(str(root).encode(), encoded)
                        self.assertNotIn(path.name.encode(), encoded)
            for invalid in (None, "", "relative/python", "/a/../python", "/" + "a" * 4096,
                            "/" + "a/" * 128 + "python", "/python\0bad"):
                with self.subTest(invalid_python_entry=repr(invalid)):
                    with self.assertRaisesRegex(ValueError, "actual-setup-python-entry"):
                        seal.python_entry_binding(invalid, "/not-read")
            # SOURCE/host facts below are inert DATA to enter only the actual
            # early main guards. No builder bootstrap, file IO or native runs.
            with ExitStack() as host_patches:
                host_patches.enter_context(patch.object(seal.os, "environ", {
                "MRK_SEAL_TARGET": "aarch64-apple-darwin",
                "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_REPOSITORY": seal.REPOSITORY, "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": seal.REFERENCE, "GITHUB_WORKFLOW_SHA": "a" * 40,
                "GITHUB_JOB": "seal-build",
                "GITHUB_WORKFLOW_REF": seal.REPOSITORY + "/" + seal.WORKFLOW + "@" + seal.REFERENCE,
                "GITHUB_WORKSPACE": str(seal.CHECKOUT), "RUNNER_TEMP": str(seal.WORK_PARENT),
                "DEVELOPER_DIR": str(seal.DEVELOPER), "MRK_SEAL_PYTHON": "/fixture/python",
            }))
                host_patches.enter_context(patch.object(seal.sys, "argv", ["fixed-entry"]))
                host_patches.enter_context(patch.object(seal.sys, "platform", "darwin"))
                host_patches.enter_context(patch.object(seal.sys, "version_info", (3, 14, 7)))
                host_patches.enter_context(patch.object(seal.sys, "flags", SimpleNamespace(isolated=True, no_site=True)))
                host_patches.enter_context(patch.object(seal.sys, "dont_write_bytecode", True))
                host_patches.enter_context(patch.object(seal.sys, "executable", "/fixture/python"))
                host_patches.enter_context(patch.object(seal.os, "uname", return_value=SimpleNamespace(machine="arm64")))
                host_patches.enter_context(patch.object(seal.platform, "mac_ver", return_value=("26.6.2", (), "arm64")))
                host_patches.enter_context(patch.object(seal.os, "getuid", return_value=65534))
                host_patches.enter_context(patch.object(seal.os, "geteuid", return_value=65534))
                host_patches.enter_context(patch.object(seal.os, "getgid", return_value=65534))
                host_patches.enter_context(patch.object(seal.os, "getegid", return_value=65534))
                host_patches.enter_context(patch.object(seal, "python_entry_binding", side_effect=lambda selected, reported:
                     seal.need(selected == reported, "actual-setup-python-entry")))
                bootstrap = host_patches.enter_context(patch.object(seal, "bootstrap_builder", side_effect=ValueError("builder-source-hash")))
                cases = (("MRK_SEAL_TARGET", "bad", "target", "fixed-seal-target"),
                         ("GITHUB_SHA", "0" * 40, "run", "fixed-seal-run"),
                         ("GITHUB_JOB", "bad", "context", "fixed-seal-workflow-context"),
                         ("MRK_SEAL_PYTHON", "/other", "python-entry", "actual-setup-python-entry"))
                for key, value, stage, reason in cases:
                    with self.subTest(diagnostic=stage), patch.dict(seal.os.environ, {key: value}):
                        with self.assertRaises(ValueError) as caught:
                            seal.main()
                        bootstrap.assert_not_called()
                        self.assertIn("stage=" + stage + " reason=" + reason + " category=refused", seal.failure_diagnostic(caught.exception))
                with patch.object(seal.sys, "platform", "linux"):
                    with self.assertRaises(ValueError) as caught:
                        seal.main()
                    bootstrap.assert_not_called()
                    self.assertIn("stage=host reason=fixed-seal-native-host", seal.failure_diagnostic(caught.exception))
                with self.assertRaises(ValueError) as caught:
                    seal.main()
                bootstrap.assert_called_once_with()
                self.assertIn("stage=bootstrap reason=builder-source-hash", seal.failure_diagnostic(caught.exception))
                # Drive the actual early main guards for all four modes under
                # the same inert pre-bootstrap stop. New receipts cap IDs at
                # 9007199254740991; legacy modes keep their original20 digits. No host,
                # filesystem, source/bootstrap or native action actually runs.
                for flags, reference, digits in (
                        ([], seal.REFERENCE, 20),
                        (["--history-provider-probe"], seal.PROVIDER_REFERENCE, 20),
                        (["--publish-build-capsule"], seal.REFERENCE, 16),
                        (["--history-provider-probe", "--publish-build-capsule"], seal.PROVIDER_REFERENCE, 16)):
                    for field in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
                        for identifier, admitted in (("1", True), ("9" * digits if digits == 20 else "9007199254740991", True),
                                ("1" * (digits + 1), False), ("0", False), ("01", False), ("", False)) + (
                                    (("9007199254740992", False),) if digits == 16 else ()):
                            with self.subTest(capsule_main=(flags, field, identifier)), \
                                    patch.object(seal.sys, "argv", ["fixed-entry", *flags]), \
                                    patch.dict(seal.os.environ, {"GITHUB_REF": reference,
                                        "GITHUB_WORKFLOW_REF": seal.REPOSITORY + "/" + seal.WORKFLOW + "@" + reference,
                                        field: identifier}):
                                bootstrap.reset_mock()
                                with self.assertRaisesRegex(ValueError, "^" + ("builder-source-hash" if admitted else "fixed-seal-run") + "$"):
                                    seal.main()
                                self.assertEqual(bootstrap.call_count, int(admitted))
            # Formatting never stringifies an exception, prints a path/message,
            # adopts a fake build owner or upgrades unknown DATA finality.
            class HostileError(Exception):
                def __str__(self):
                    raise AssertionError("must not stringify")
            with patch.object(BUILD, "DATA", BUILD.DataFinality()):
                for error, category in ((HostileError("private-data"), "other"),
                                        (OSError("/private/path"), "io"),
                                        (ImportError("private-module"), "import"),
                                        (KeyboardInterrupt(), "interrupted"),
                                        (ValueError("private-data"), "refused"),
                                        (BUILD.BuildRefused("builder-source-hash"), "refused")):
                    line = seal.failure_diagnostic(error)
                    self.assertLessEqual(len(line.encode("ascii")), 512)
                    self.assertIn("category=" + category, line)
                    self.assertIn("phase=unavailable calls=unavailable data=known lastRc=unavailable inflight=unavailable scratchRetired=unavailable sourcePost=unavailable nonAtomic=true", line)
                    self.assertNotIn("private", line)
                BUILD.DATA.unknown()
                with patch.object(seal, "_DIAGNOSTIC_STAGE", "/private/path"), \
                     patch.object(seal, "_DIAGNOSTIC_BUILD", SimpleNamespace(phase="sdk-path", entered=1, returned=1)):
                    self.assertEqual(seal.failure_diagnostic(HostileError()),
                        "MRK_SEAL_DIAGNOSTIC_V1 stage=unknown reason=unclassified category=other phase=unavailable calls=unavailable data=unknown lastRc=unavailable inflight=unavailable scratchRetired=unavailable sourcePost=unavailable nonAtomic=true")
                # Unentered exact-class DATA receiver tests only diagnostic
                # field bounding, not a native lifetime or cleanup claim.
                receiver = object.__new__(seal.SealBuild)
                receiver.phase, receiver.entered, receiver.returned = "helper-native-test", 22, 21
                with patch.object(seal, "_DIAGNOSTIC_BUILD", receiver):
                    self.assertIn("phase=helper-native-test calls=22/21 data=unknown", seal.failure_diagnostic(HostileError()))
                    receiver.inflight, receiver.scratch_retired, receiver.source_post = False, True, False
                    receiver.commands = [{"returned": True, "returncode": 2}, {"returned": False}]
                    line = seal.failure_diagnostic(BUILD.BuildRefused("original-command-failed"))
                    self.assertIn("reason=original-command-failed", line)
                    self.assertIn("lastRc=2 inflight=false scratchRetired=true sourcePost=false nonAtomic=true", line)
                    for value in (0, -1, -(2 ** 31), 2 ** 31 - 1):
                        receiver.commands = [{"returned": True, "returncode": value}]
                        self.assertIn("lastRc=" + str(value) + " ", seal.failure_diagnostic(HostileError()))
                    for value in (True, False, "private-value", None, -(2 ** 31) - 1, 2 ** 31):
                        receiver.commands = [{"returned": True, "returncode": value}]
                        self.assertIn("lastRc=unavailable ", seal.failure_diagnostic(HostileError()))
                    for commands in ([{"returned": 1, "returncode": 0}], [{"returned": True, "returncode": 0}] * 24, (), None):
                        receiver.commands = commands
                        self.assertIn("lastRc=unavailable ", seal.failure_diagnostic(HostileError()))
                    receiver.inflight, receiver.scratch_retired, receiver.source_post = 1, 0, "private-value"
                    self.assertIn("inflight=unavailable scratchRetired=unavailable sourcePost=unavailable", seal.failure_diagnostic(HostileError()))
                    for reason in ("original-command-failed", "work-entry", "static-libtool-metadata", "capsule-combined-bound"):
                        line = seal.failure_diagnostic(BUILD.BuildRefused(reason))
                        self.assertIn("reason=" + reason + " ", line)
                        self.assertLessEqual(len(line.encode("ascii")), 512)
                    self.assertIn("reason=unclassified ", seal.failure_diagnostic(BUILD.BuildRefused("/private/unknown")))
                    receiver.phase, receiver.entered, receiver.returned = "helper-entropy-test", 23, 23
                    receiver.commands = [{"returned": True, "returncode": 0}] * 23
                    line = seal.failure_diagnostic(HostileError())
                    self.assertIn("phase=helper-entropy-test calls=23/23", line)
                    self.assertIn("lastRc=0 ", line)
                    self.assertLessEqual(len(line.encode("ascii")), 512)
                    receiver.entered = 22
                    receiver.phase, receiver.returned = "private-value", 23
                    self.assertIn("phase=unknown calls=unavailable data=unknown", seal.failure_diagnostic(HostileError()))
                    receiver.entered, receiver.returned = True, False
                    self.assertIn("calls=unavailable data=unknown", seal.failure_diagnostic(HostileError()))
        finally:
            self.assertIs(sys.modules.pop(name), seal)


if __name__ == "__main__":
    unittest.main()
