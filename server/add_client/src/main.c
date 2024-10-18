#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "DeviceConnect_Core.h"

// Should take as input a json-encoded DIDDoc containing a jwk, and create a file containing the associated public key
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <DIDDoc>\n", argv[0]);
        return 1;
    }

    char *did_doc = argv[1];

    DIDDoc *parsed_diddoc = iotex_diddoc_parse(did_doc);
    if (parsed_diddoc == NULL)
    {
        printf("Failed to parse DIDDoc\n");
        return 1;
    }

    VerificationMethod_Info *vm_info = iotex_diddoc_verification_method_get(parsed_diddoc, VM_PURPOSE_VERIFICATION_METHOD, 0);
    if (vm_info == NULL)
    {
        printf("Failed to get verification method\n");
        return 1;
    }

    JWK *jwk = vm_info->pk_u.jwk;

    char public_key[64] = {0};
    size_t outlen = 0;

    int ret = iotex_jwk_get_pubkey_from_jwk(jwk, public_key, &outlen);
    if (ret != 0)
    {
        printf("Failed to get public key\n");
        return 1;
    }

    printf("%s", public_key);
}
