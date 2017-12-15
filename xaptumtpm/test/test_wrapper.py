# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

import xaptumtpm

class TCTIException(Exception):
    pass

class SAPIException(Exception):
    pass

class Connection(object):
    def create_ecdaa_keypair(self):
        hierarchy = xaptumtpm.TPM_RH_ENDORSEMENT

        session_data = xaptumtpm.TPMS_AUTH_COMMAND(sessionHandle = xaptumtpm.TPMI_SH_AUTH_SESSION(xaptumtpm.TPM_RS_PW),
                                                   nonce = xaptumtpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptumtpm.TPMA_SESSION(0),
                                                   hmac = xaptumtpm.TPM2B_AUTH(0))

        session_data_out = xaptumtpm.TPMS_AUTH_RESPONSE(nonce = xaptumtpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptumtpm.TPMA_SESSION(0),
                                                        hmac = xaptumtpm.TPM2B_AUTH(0))

        sessions_data_out = xaptumtpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptumtpm.pointer(xaptumtpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptumtpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptumtpm.pointer(xaptumtpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        in_sensitive = xaptumtpm.TPM2B_SENSITIVE_CREATE(sensitive=xaptumtpm.TPMS_SENSITIVE_CREATE(data = xaptumtpm.TPM2B_SENSITIVE_DATA(size=0),
                                                                                                  userAuth = xaptumtpm.TPM2B_AUTH(size=0)))

        obj_attrs = xaptumtpm.TPMA_OBJECT(fixedTPM=1, fixedParent=1, sensitiveDataOrigin=1, userWithAuth=1, sign=1)
        in_public = xaptumtpm.TPM2B_PUBLIC(publicArea = xaptumtpm.TPMT_PUBLIC(type=xaptumtpm.TPM_ALG_ECC, nameAlg=xaptumtpm.TPM_ALG_SHA256, objectAttributes=obj_attrs))
        in_public.publicArea.parameters.eccDetail.symmetric.algorithm = xaptumtpm.TPM_ALG_NULL;
        in_public.publicArea.parameters.eccDetail.scheme.scheme = xaptumtpm.TPM_ALG_ECDAA;
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = xaptumtpm.TPM_ALG_SHA256;
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
        in_public.publicArea.parameters.eccDetail.curveID = xaptumtpm.TPM_ECC_BN_P256;
        in_public.publicArea.parameters.eccDetail.kdf.scheme = xaptumtpm.TPM_ALG_NULL;
        in_public.publicArea.unique.ecc.x.size = 0;
        in_public.publicArea.unique.ecc.y.size = 0;

        outside_info = xaptumtpm.TPM2B_DATA(size=0)

        creation_pcr = xaptumtpm.TPML_PCR_SELECTION(count=0)

        creation_data = xaptumtpm.TPM2B_CREATION_DATA(size=0)

        creation_hash = xaptumtpm.TPM2B_DIGEST(size=xaptumtpm.sizeof(xaptumtpm.TPMU_HA))

        creation_ticket = xaptumtpm.TPMT_TK_CREATION(tag=0, hierarchy=0, digest=xaptumtpm.TPM2B_DIGEST(size=0))

        name = xaptumtpm.TPM2B_NAME(size=xaptumtpm.sizeof(xaptumtpm.TPMU_NAME))

        public_key = xaptumtpm.TPM2B_PUBLIC()

        key_handle = xaptumtpm.TPM_HANDLE()

        ret = xaptumtpm.Tss2_Sys_CreatePrimary(self.sapi_ctx,
                                               hierarchy,
                                               xaptumtpm.pointer(sessions_data),
                                               xaptumtpm.pointer(in_sensitive),
                                               xaptumtpm.pointer(in_public),
                                               xaptumtpm.pointer(outside_info),
                                               xaptumtpm.pointer(creation_pcr),
                                               xaptumtpm.pointer(key_handle),
                                               xaptumtpm.pointer(public_key),
                                               xaptumtpm.pointer(creation_data),
                                               xaptumtpm.pointer(creation_hash),
                                               xaptumtpm.pointer(creation_ticket),
                                               xaptumtpm.pointer(name),
                                               xaptumtpm.pointer(sessions_data_out));

        if 0 != ret:
            raise SAPIException('error from CreatePrimary: 0x%X' % ret)

        self.key_handle = key_handle.value
        self.public_key = (list(public_key.publicArea.unique.ecc.x.buffer),
                           list(public_key.publicArea.unique.ecc.x.buffer))

class SocketConnection(Connection):
    def __init__(self, hostname, port):
        tcti_ctx_size = xaptumtpm.tss2_tcti_getsize_socket()
        self.tcti_ctx = xaptumtpm.cast((xaptumtpm.c_byte * tcti_ctx_size)(), xaptumtpm.POINTER(xaptumtpm.TSS2_TCTI_CONTEXT))
        init_ret = xaptumtpm.tss2_tcti_init_socket(hostname, port, self.tcti_ctx)
        if (0 != init_ret):
            raise TCTIException('error with tss2_tcti_init_socket: ' + str(init_ret))

        sapi_ctx_size = xaptumtpm.Tss2_Sys_GetContextSize(0)
        self.sapi_ctx = xaptumtpm.cast((xaptumtpm.c_byte * sapi_ctx_size)(), xaptumtpm.POINTER(xaptumtpm.TSS2_SYS_CONTEXT))
        abi_version = xaptumtpm.TSS2_ABI_CURRENT_VERSION
        init_ret = xaptumtpm.Tss2_Sys_Initialize(self.sapi_ctx, sapi_ctx_size, self.tcti_ctx, xaptumtpm.pointer(abi_version))
        if (0 != init_ret):
            raise SAPIException('error with Tss2_Sys_Initialize: ' + str(init_ret))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # TODO: Look into making finalize a function rather than a macro
        # (or maybe it should just always be called in Sys_Finalize?)
        # xaptumtpm.tss2_tcti_finalize(self.tcti_context)
        xaptumtpm.Tss2_Sys_Finalize(self.sapi_ctx)

def test_create_ecdaa_keypair():
    with SocketConnection('localhost', '2321') as conn:
        conn.create_ecdaa_keypair()

        assert len(conn.public_key[0]) != 0
        assert len(conn.public_key[1]) != 0
        assert conn.key_handle != 0
