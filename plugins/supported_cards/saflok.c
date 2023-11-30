// From: https://gitee.com/jadenwu/Saflok_KDF/blob/master/saflok.c

#include "nfc_supported_card_plugin.h"
#include <flipper_application/flipper_application.h>
#include <nfc/nfc_device.h>
#include <nfc/helpers/nfc_util.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <stdint.h>

#define TAG "Saflok"
#define MAGIC_TABLE_SIZE 192
#define KEY_LENGTH 6
#define UID_LENGTH 4

typedef struct {
    uint64_t a;
    uint64_t b;
} MfClassicKeyPair;

typedef struct {
    const MfClassicKeyPair* keys;
    uint32_t data_sector;
} SaflokCardConfig;

void generate_saflok_key(uint8_t *uid, uint8_t *key) {
    static const uint8_t magic_table[MAGIC_TABLE_SIZE] = {
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xF0, 0x57, 0xB3, 0x9E, 0xE3, 0xD8,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x96, 0x9D, 0x95, 0x4A, 0xC1, 0x57,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x43, 0x58, 0x0D, 0x2C, 0x9D,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFF, 0xCC, 0xE0, 0x05, 0x0C, 0x43,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x1B, 0x15, 0xA6, 0x90, 0xCC,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x89, 0x58, 0x56, 0x12, 0xE7, 0x1B,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xBB, 0x74, 0xB0, 0x95, 0x36, 0x58,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFB, 0x97, 0xF8, 0x4B, 0x5B, 0x74,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xC9, 0xD1, 0x88, 0x35, 0x9F, 0x92,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x92, 0xE9, 0x7F, 0x58, 0x97,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x16, 0x6C, 0xA2, 0xB0, 0x9F, 0xD1,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x27, 0xDD, 0x93, 0x10, 0x1C, 0x6C,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xDA, 0x3E, 0x3F, 0xD6, 0x49, 0xDD,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x58, 0xDD, 0xED, 0x07, 0x8E, 0x3E,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x5C, 0xD0, 0x05, 0xCF, 0xD9, 0x07,
                    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x11, 0x8D, 0xD0, 0x01, 0x87, 0xD0
    };

    uint8_t magic_byte = (uid[3] >> 4) + (uid[2] >> 4) + (uid[0] & 0x0F);
    uint8_t magickal_index = (magic_byte & 0x0F) * 12 + 11;

    uint8_t temp_key[KEY_LENGTH] = {magic_byte, uid[0], uid[1], uid[2], uid[3], magic_byte};
    uint8_t carry_sum = 0;

    for (int i = KEY_LENGTH - 1; i >= 0 && magickal_index >= 0; i--, magickal_index--) {
        uint16_t keysum = temp_key[i] + magic_table[magickal_index];
        temp_key[i] = (keysum & 0xFF) + carry_sum;
        carry_sum = keysum >> 8;
    }

    memcpy(key, temp_key, KEY_LENGTH);
}

static bool saflok_verify(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool verified = false; // I think we keep this set to false, so it doesn't attempt to read/parse the card
                           // All we need the plugin to do is to store the key if it is verified

    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);

    do {
        MfClassicType type = MfClassicTypeMini;
        MfClassicError error = mf_classic_poller_sync_detect_type(nfc, &type);
        if (error != MfClassicErrorNone) break;

        data->type = type;
        uint8_t uid[UID_LENGTH];
        memcpy(uid, data->uid.data, UID_LENGTH);

        uint8_t key[KEY_LENGTH];
        generate_saflok_key(uid, key);

        for (size_t i = 0; i < mf_classic_get_total_sectors_num(data->type); i++) {
            const uint8_t block_num = mf_classic_get_first_block_num_of_sector(i);
            MfClassicKey mf_key = {0};
            memcpy(mf_key.data, key, KEY_LENGTH);

            MfClassicAuthContext auth_context;
            error = mf_classic_poller_sync_auth(nfc, block_num, &mf_key, MfClassicKeyTypeA, &auth_context);
            if (error == MfClassicErrorNone) {
                verified = false;
                break;
            }

            error = mf_classic_poller_sync_auth(nfc, block_num, &mf_key, MfClassicKeyTypeB, &auth_context);
            if (error == MfClassicErrorNone) {
                verified = false;
                break;
            }
        }
    } while (false);

    mf_classic_free(data);

    return verified;
}

/* Actual implementation of app<>plugin interface */
static const NfcSupportedCardsPlugin saflok_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = saflok_verify,
    // KDF mode
    // If this ends up crashing we'll use empty functions (no official KDF interface yet)
    .read = NULL,
    .parse = NULL,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor saflok_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &saflok_plugin,
};

/* Plugin entry point - must return a pointer to const descriptor  */
const FlipperAppPluginDescriptor* saflok_plugin_ep() {
    return &saflok_plugin_descriptor;
}
