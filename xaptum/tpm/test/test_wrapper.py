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

import xaptum.tpm

import ctypes

class TCTIException(Exception):
    pass

class SAPIException(Exception):
    pass

class Connection(object):
    def create_ecdaa_keypair(self):
        hierarchy = xaptum.tpm.TPM_RH_ENDORSEMENT

        session_data = xaptum.tpm.TPMS_AUTH_COMMAND(sessionHandle = xaptum.tpm.TPMI_SH_AUTH_SESSION(xaptum.tpm.TPM_RS_PW),
                                                   nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                   hmac = xaptum.tpm.TPM2B_AUTH(0))

        session_data_out = xaptum.tpm.TPMS_AUTH_RESPONSE(nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                        hmac = xaptum.tpm.TPM2B_AUTH(0))

        sessions_data_out = xaptum.tpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptum.tpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        in_sensitive = xaptum.tpm.TPM2B_SENSITIVE_CREATE(sensitive=xaptum.tpm.TPMS_SENSITIVE_CREATE(data = xaptum.tpm.TPM2B_SENSITIVE_DATA(size=0),
                                                                                                  userAuth = xaptum.tpm.TPM2B_AUTH(size=0)))

        obj_attrs = xaptum.tpm.TPMA_OBJECT(fixedTPM=1, fixedParent=1, sensitiveDataOrigin=1, userWithAuth=1, sign=1)
        in_public = xaptum.tpm.TPM2B_PUBLIC(publicArea = xaptum.tpm.TPMT_PUBLIC(type=xaptum.tpm.TPM_ALG_ECC, nameAlg=xaptum.tpm.TPM_ALG_SHA256, objectAttributes=obj_attrs))
        in_public.publicArea.parameters.eccDetail.symmetric.algorithm = xaptum.tpm.TPM_ALG_NULL;
        in_public.publicArea.parameters.eccDetail.scheme.scheme = xaptum.tpm.TPM_ALG_ECDAA;
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = xaptum.tpm.TPM_ALG_SHA256;
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
        in_public.publicArea.parameters.eccDetail.curveID = xaptum.tpm.TPM_ECC_BN_P256;
        in_public.publicArea.parameters.eccDetail.kdf.scheme = xaptum.tpm.TPM_ALG_NULL;
        in_public.publicArea.unique.ecc.x.size = 0;
        in_public.publicArea.unique.ecc.y.size = 0;

        outside_info = xaptum.tpm.TPM2B_DATA(size=0)

        creation_pcr = xaptum.tpm.TPML_PCR_SELECTION(count=0)

        creation_data = xaptum.tpm.TPM2B_CREATION_DATA(size=0)

        creation_hash = xaptum.tpm.TPM2B_DIGEST(size=xaptum.tpm.sizeof(xaptum.tpm.TPMU_HA))

        creation_ticket = xaptum.tpm.TPMT_TK_CREATION(tag=0, hierarchy=0, digest=xaptum.tpm.TPM2B_DIGEST(size=0))

        name = xaptum.tpm.TPM2B_NAME(size=xaptum.tpm.sizeof(xaptum.tpm.TPMU_NAME))

        public_key = xaptum.tpm.TPM2B_PUBLIC()

        key_handle = xaptum.tpm.TPM_HANDLE()

        ret = xaptum.tpm.Tss2_Sys_CreatePrimary(self.sapi_ctx,
                                               hierarchy,
                                               xaptum.tpm.pointer(sessions_data),
                                               xaptum.tpm.pointer(in_sensitive),
                                               xaptum.tpm.pointer(in_public),
                                               xaptum.tpm.pointer(outside_info),
                                               xaptum.tpm.pointer(creation_pcr),
                                               xaptum.tpm.pointer(key_handle),
                                               xaptum.tpm.pointer(public_key),
                                               xaptum.tpm.pointer(creation_data),
                                               xaptum.tpm.pointer(creation_hash),
                                               xaptum.tpm.pointer(creation_ticket),
                                               xaptum.tpm.pointer(name),
                                               xaptum.tpm.pointer(sessions_data_out));

        if 0 != ret:
            raise SAPIException('error from CreatePrimary: 0x%X' % ret)

        self.key_handle = key_handle.value
        self.public_key = (list(public_key.publicArea.unique.ecc.x.buffer),
                           list(public_key.publicArea.unique.ecc.x.buffer))

    def define_nvram(self, index, size):
        session_data = xaptum.tpm.TPMS_AUTH_COMMAND(sessionHandle = xaptum.tpm.TPMI_SH_AUTH_SESSION(xaptum.tpm.TPM_RS_PW),
                                                   nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                   hmac = xaptum.tpm.TPM2B_AUTH(0))

        session_data_out = xaptum.tpm.TPMS_AUTH_RESPONSE(nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                        hmac = xaptum.tpm.TPM2B_AUTH(0))

        sessions_data_out = xaptum.tpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptum.tpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        public_info = xaptum.tpm.TPM2B_NV_PUBLIC(nvPublic=xaptum.tpm.TPMS_NV_PUBLIC(nvIndex=index,
                                                                                  nameAlg=xaptum.tpm.TPM_ALG_SHA256,
                                                                                  authPolicy=xaptum.tpm.TPM2B_DIGEST(size=0),
                                                                                  dataSize=size))
        public_info.nvPublic.attributes.TPMA_OWNERWRITE = 1;
        public_info.nvPublic.attributes.TPMA_POLICYWRITE = 1;
        public_info.nvPublic.attributes.TPMA_OWNERREAD = 1;

        auth_handle = xaptum.tpm.TPM_RH_OWNER

        nv_auth = xaptum.tpm.TPM2B_AUTH(size=0)

        ret = xaptum.tpm.Tss2_Sys_NV_DefineSpace(self.sapi_ctx,
                                                auth_handle,
                                                xaptum.tpm.pointer(sessions_data),
                                                xaptum.tpm.pointer(nv_auth),
                                                xaptum.tpm.pointer(public_info),
                                                xaptum.tpm.pointer(sessions_data_out))

        if 0 != ret:
            raise SAPIException('error from NV_Define: 0x%X' % ret)

    def undefine_nvram(self, index):
        session_data = xaptum.tpm.TPMS_AUTH_COMMAND(sessionHandle = xaptum.tpm.TPMI_SH_AUTH_SESSION(xaptum.tpm.TPM_RS_PW),
                                                   nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                   hmac = xaptum.tpm.TPM2B_AUTH(0))

        session_data_out = xaptum.tpm.TPMS_AUTH_RESPONSE(nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                        hmac = xaptum.tpm.TPM2B_AUTH(0))

        sessions_data_out = xaptum.tpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptum.tpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        auth_handle = xaptum.tpm.TPM_RH_OWNER

        ret = xaptum.tpm.Tss2_Sys_NV_UndefineSpace(self.sapi_ctx,
                                                  auth_handle,
                                                  index,
                                                  xaptum.tpm.pointer(sessions_data),
                                                  xaptum.tpm.pointer(sessions_data_out))

        if 0 != ret:
            raise SAPIException('error from NV_Undefine: 0x%X' % ret)

    def write_nvram(self, index, data):
        session_data = xaptum.tpm.TPMS_AUTH_COMMAND(sessionHandle = xaptum.tpm.TPMI_SH_AUTH_SESSION(xaptum.tpm.TPM_RS_PW),
                                                   nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                   hmac = xaptum.tpm.TPM2B_AUTH(0))

        session_data_out = xaptum.tpm.TPMS_AUTH_RESPONSE(nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                        hmac = xaptum.tpm.TPM2B_AUTH(0))

        sessions_data_out = xaptum.tpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptum.tpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        auth_handle = xaptum.tpm.TPM_RH_OWNER

        nv_write_data = xaptum.tpm.TPM2B_MAX_NV_BUFFER(size=len(data));

        ctypes.memmove(nv_write_data.buffer, data, len(data))

        ret = xaptum.tpm.Tss2_Sys_NV_Write(self.sapi_ctx,
                                          auth_handle,
                                          index,
                                          xaptum.tpm.pointer(sessions_data),
                                          xaptum.tpm.pointer(nv_write_data),
                                          0,
                                          xaptum.tpm.pointer(sessions_data_out))

        if 0 != ret:
            raise SAPIException('error from NV_Write: 0x%X' % ret)

    def read_nvram(self, index, size):
        session_data = xaptum.tpm.TPMS_AUTH_COMMAND(sessionHandle = xaptum.tpm.TPMI_SH_AUTH_SESSION(xaptum.tpm.TPM_RS_PW),
                                                   nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                   sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                   hmac = xaptum.tpm.TPM2B_AUTH(0))

        session_data_out = xaptum.tpm.TPMS_AUTH_RESPONSE(nonce = xaptum.tpm.TPM2B_NONCE(0),
                                                        sessionAttributes = xaptum.tpm.TPMA_SESSION(0),
                                                        hmac = xaptum.tpm.TPM2B_AUTH(0))

        sessions_data_out = xaptum.tpm.TSS2_SYS_RSP_AUTHS(rspAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data_out)),
                                                         rspAuthsCount = 1)

        sessions_data = xaptum.tpm.TSS2_SYS_CMD_AUTHS(cmdAuths = xaptum.tpm.pointer(xaptum.tpm.pointer(session_data)),
                                                     cmdAuthsCount = 1)

        auth_handle = xaptum.tpm.TPM_RH_OWNER

        nv_data = xaptum.tpm.TPM2B_MAX_NV_BUFFER(size=0);

        ret = xaptum.tpm.Tss2_Sys_NV_Read(self.sapi_ctx,
                                          auth_handle,
                                          index,
                                          xaptum.tpm.pointer(sessions_data),
                                          size,
                                          0,
                                          xaptum.tpm.pointer(nv_data),
                                          xaptum.tpm.pointer(sessions_data_out))

        if 0 != ret:
            raise SAPIException('error from NV_Read: 0x%X' % ret)

        return nv_data.buffer

class SocketConnection(Connection):
    def __init__(self, hostname, port):
        tcti_ctx_size = xaptum.tpm.tss2_tcti_getsize_socket()
        self.tcti_ctx = xaptum.tpm.cast((xaptum.tpm.c_byte * tcti_ctx_size)(), xaptum.tpm.POINTER(xaptum.tpm.TSS2_TCTI_CONTEXT))
        init_ret = xaptum.tpm.tss2_tcti_init_socket(hostname, port, self.tcti_ctx)
        if (0 != init_ret):
            raise TCTIException('error with tss2_tcti_init_socket: ' + str(init_ret))

        sapi_ctx_size = xaptum.tpm.Tss2_Sys_GetContextSize(0)
        self.sapi_ctx = xaptum.tpm.cast((xaptum.tpm.c_byte * sapi_ctx_size)(), xaptum.tpm.POINTER(xaptum.tpm.TSS2_SYS_CONTEXT))
        abi_version = xaptum.tpm.TSS2_ABI_CURRENT_VERSION
        init_ret = xaptum.tpm.Tss2_Sys_Initialize(self.sapi_ctx, sapi_ctx_size, self.tcti_ctx, xaptum.tpm.pointer(abi_version))
        if (0 != init_ret):
            raise SAPIException('error with Tss2_Sys_Initialize: ' + str(init_ret))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        xaptum.tpm.tss2_tcti_finalize(self.tcti_ctx)
        xaptum.tpm.Tss2_Sys_Finalize(self.sapi_ctx)

def test_create_ecdaa_keypair():
    with SocketConnection('localhost', '2321') as conn:
        conn.create_ecdaa_keypair()

        assert len(conn.public_key[0]) != 0
        assert len(conn.public_key[1]) != 0
        assert conn.key_handle != 0

def test_nvram():
    index = 0x1600001
    data = 'test data 111111111111111111111111111111111111'
    with SocketConnection('localhost', '2321') as conn:
        try:
            conn.undefine_nvram(index)
        except Exception as e:
            if '0x28b' in str(e).lower():
                print('attempted to undefine an undefined NVRAM index')
            else:
                raise e

        conn.define_nvram(index, len(data))

        conn.write_nvram(index, data)

        out_data = conn.read_nvram(index, len(data))

        print('input: ' + str(data))
        print('output: ' + str(ctypes.c_char_p(ctypes.addressof(out_data)).value))

        assert ctypes.c_char_p(ctypes.addressof(out_data)).value == data
