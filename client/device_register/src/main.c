#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "DeviceConnect_Core.h"
#include "dotenv.h"

uint8_t *datahex(char *hex);

int main(void)
{

    env_load("../../..", false);

    char *secret_hex = getenv("SECRET_KEY_HEX");
    if (NULL == secret_hex)
    {
        printf("Please set the SECRET_KEY_HEX environment variable\n");
    }

    psa_status_t status = psa_crypto_init();
    if (PSA_SUCCESS != status)
        return 0;

    //************************ STEP. 1 ******************************//
    // Generate a JWK, and a DID from that JWK

    unsigned int mySignKeyID;

    // 32-bytes secret
    uint8_t *secret = datahex(secret_hex);

    unsigned int peerSignKeyID;

    JWK *peerSignJWK = iotex_jwk_generate_by_secret(secret, 32, JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                                                    IOTEX_JWK_LIFETIME_VOLATILE,
                                                    PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                                                    PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                                    &peerSignKeyID);
    if (NULL == peerSignJWK)
    {
        printf("Failed to Generate a peer Sign JWK\n");
        goto exit;
    }

    char *peerSignDID = iotex_did_generate("io", peerSignJWK);
    if (peerSignDID)
        printf("Peer DID : \t\t\t%s\n", peerSignDID);
    else
        goto exit;

    char *peerSignKID = iotex_jwk_generate_kid("io", peerSignJWK);
    if (NULL == peerSignKID)
        goto exit;

    //************************ STEP. 4 ******************************//
    // Create the DID to be sent to register the device

    did_status_t did_status;

    DIDDoc *peerDIDDoc = iotex_diddoc_new();
    if (NULL == peerDIDDoc)
    {
        printf("Failed to new a peerDIDDoc\n");
        goto exit;
    }

    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL, "https://w3id.org/security#keyAgreementMethod");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, peerSignDID);
    if (DID_SUCCESS != did_status)
    {
        printf("iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        goto exit;
    }

    // 4.1 Make a verification method [type : authentication]
    DIDDoc_VerificationMethod *vm_authentication = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);
    if (NULL == vm_authentication)
    {
        printf("Failed to iotex_diddoc_verification_method_new()\n");
    }

    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, peerSignKID);
    if (DID_SUCCESS != did_status)
    {
        printf("iotex_diddoc_verification_method_set ret %d\n", did_status);
        goto exit;
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerSignKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE, "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerSignJWK));

    DIDDoc_VerificationMethod *vm_vm = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);

    char *peerDIDDoc_Serialize = iotex_diddoc_serialize(peerDIDDoc, true);
    if (peerDIDDoc_Serialize)
        printf("DIDdoc : \n%s\n", peerDIDDoc_Serialize);

    FILE *fp = fopen("../../peerDIDDoc.json", "w");

    if (fp)
    {
        fwrite(peerDIDDoc_Serialize, strlen(peerDIDDoc_Serialize), 1, fp);
        fclose(fp);
    }

    iotex_diddoc_destroy(peerDIDDoc);

    //************************ Free Res ****************************//

    if (peerDIDDoc_Serialize)
        free(peerDIDDoc_Serialize);

    if (peerSignDID)
        free(peerSignDID);

    if (peerSignKID)
        free(peerSignKID);

    iotex_jwk_destroy(peerSignJWK);

exit:
    // while(1) {
    //     sleep(1000);
    // }

    return 0;
}

// Convert hex string to byte array
uint8_t *datahex(char *string)
{

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    size_t dlength = slength / 2;

    uint8_t *data = malloc(dlength);
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength)
    {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
        {
            free(data);
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}