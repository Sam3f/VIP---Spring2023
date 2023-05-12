// NimBLE Client - Scan

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "services/gap/ble_svc_gap.h"
#include "sdkconfig.h"
#include "xtensa/config/specreg.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"

struct encrypted_packet {
    uint8_t ctr_nonce[16];
    uint8_t length;
    uint8_t data[5];
};

char *TAG = "BLE Client Scan";
uint8_t ble_addr_type;
struct ble_gap_conn_desc connection_description;
void ble_app_scan(void);
bool recieved1 = false;
bool recieved2 = false;
mbedtls_ecdh_context ctxc;
uint8_t peer_public_raw[32];
mbedtls_ecp_point peer_public;
unsigned char public_key_buf[MBEDTLS_ECP_MAX_BYTES];
size_t public_key_len;
uint16_t comms_conn_handle;
uint16_t comms_attr_val_handle;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes_ctx;

ble_uuid_t *server_uuid = BLE_UUID128_DECLARE(0x22, 0x2b, 0x9a, 0xd9, 0x9a, 0xf8, 0xd5, 0x96, 0x7e, 0x47, 0x0c, 0x96, 0xc2, 0xab, 0x5a, 0x81);
ble_uuid_t *read1_uuid = BLE_UUID128_DECLARE(0xce, 0xd6, 0x73, 0xf7, 0xbb, 0xc6, 0x42, 0xc9, 0x8f, 0xe0, 0xdb, 0xad, 0x44, 0x06, 0xb5, 0xb2);
ble_uuid_t *read2_uuid = BLE_UUID128_DECLARE(0xa1, 0x2d, 0x94, 0xde, 0xa9, 0xf8, 0x44, 0xc0, 0xa6, 0xf9, 0x4f, 0x59, 0xdf, 0xa8, 0x77, 0x87);
ble_uuid_t *write1_uuid = BLE_UUID128_DECLARE(0x61, 0x9a, 0x26, 0xbb, 0x32, 0x02, 0x44, 0x8c, 0x8e, 0x14, 0x94, 0x22, 0xbd, 0xac, 0x6b, 0x55);
ble_uuid_t *write2_uuid = BLE_UUID128_DECLARE(0xf5, 0xe3, 0xf6, 0xb6, 0xb5, 0x26, 0x4f, 0xb0, 0xb5, 0xdd, 0xfb, 0x3f, 0x36, 0xc5, 0x72, 0x3b);
ble_uuid_t *comms_uuid = BLE_UUID128_DECLARE(0x4d, 0x2e, 0xd7, 0x55, 0xbd, 0xb2, 0x43, 0xf7, 0x80, 0xdd, 0x17, 0xa7, 0xb1, 0x50, 0x9f, 0xb1);

void print_hex(const uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02hhx", buf[i]);
}

void gen_enc_packet(struct encrypted_packet *packet) {
    uint8_t rand_len;
    uint8_t rand_data[5];
    uint8_t temp_ctr[16];
    size_t off = 0;
    uint8_t block[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, &rand_len, 1);
    rand_len %= 2;
    rand_len++;
    packet->length = rand_len;
    rand_data[rand_len] = 0;
    mbedtls_ctr_drbg_random(&ctr_drbg, rand_data, rand_len);
    for (int i = 0; i < rand_len; i++) {
        rand_data[i] = rand_data[i] % 26 + 97;
    }
    mbedtls_ctr_drbg_random(&ctr_drbg, packet->ctr_nonce, 16);
    memcpy(temp_ctr, packet->ctr_nonce, 16);
    mbedtls_aes_crypt_ctr(&aes_ctx, rand_len + 1, &off, temp_ctr, block, rand_data, packet->data);
    printf("Sent packet with ctr: ");
    print_hex(packet->ctr_nonce, 16);
    printf("\nLength: %d\n", rand_len);
    printf("And data: %s\n", rand_data);
    printf("And encrypted data: ");
    print_hex(packet->data, rand_len + 1);
    printf("\n");
}

static int recieve_enc_packet(uint16_t conn_handle, const struct ble_gatt_error *error, struct ble_gatt_attr *attr, void *arg) {
    if (error->status == 0) {
        struct encrypted_packet *packet = (struct encrypted_packet*)attr->om->om_data; 
        uint8_t dec_data[5];
        size_t off = 0;
        uint8_t block[16];
        printf("Recieved packet with ctr: ");
        print_hex(packet->ctr_nonce, 16);
        mbedtls_aes_crypt_ctr(&aes_ctx, packet->length + 1, &off, packet->ctr_nonce, block, packet->data, dec_data);
        printf("\nLength: %d\n", packet->length);
        printf("Encrypted data: ");
        print_hex(packet->data, packet->length + 1);
        printf("\n");
        printf("And decrypted data: %s\n", dec_data);
        printf("\n\n\n\n\n\n");
    }
    return 0;
}

static int ble_disc_read_cb(uint16_t conn_handle, const struct ble_gatt_error *error, struct ble_gatt_attr *attr, void *arg) {
    if (error->status == 0) {
        for (int i = 0; i < attr->om->om_len; i++) {
            peer_public_raw[i] = attr->om->om_data[i];
            recieved1 = true;
        }
    }
    return 0;
}

static int ble_disc_read2_cb(uint16_t conn_handle, const struct ble_gatt_error *error, struct ble_gatt_attr *attr, void *arg) {
    if (error->status == 0) {
        for (int i = 0; i < attr->om->om_len; i++) {
            peer_public_raw[i + 16] = attr->om->om_data[i];
            recieved2 = true;
        }
    }
    return 0;
}

static int ble_disc_chr_cb(uint16_t conn_handle, const struct ble_gatt_error *error, const struct ble_gatt_chr *chr, void *arg) {
    if (error->status == 0) {
        if (ble_uuid_cmp((ble_uuid_t*)&chr->uuid, read1_uuid) == 0) {
            ble_gattc_read(conn_handle, chr->val_handle, ble_disc_read_cb, NULL);
        }
        else if (ble_uuid_cmp((ble_uuid_t*)&chr->uuid, read2_uuid) == 0) {
            ble_gattc_read(conn_handle, chr->val_handle, ble_disc_read2_cb, NULL);
        }
        else if (ble_uuid_cmp((ble_uuid_t*)&chr->uuid, write1_uuid) == 0) {
            ble_gattc_write_flat(conn_handle, chr->val_handle, public_key_buf, public_key_len / 2, NULL, NULL);
        }
        else if (ble_uuid_cmp((ble_uuid_t*)&chr->uuid, write2_uuid) == 0) {
            ble_gattc_write_flat(conn_handle, chr->val_handle, &public_key_buf[public_key_len / 2], public_key_len / 2, NULL, NULL);
        }
        else if (ble_uuid_cmp((ble_uuid_t*)&chr->uuid, comms_uuid) == 0) {
            comms_conn_handle = conn_handle;
            comms_attr_val_handle = chr->val_handle;
        }
    }
    return 0;
}

static int ble_svc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error, const struct ble_gatt_svc *service, void *arg) {
    if (error->status == 0) {
        if (ble_gattc_disc_all_chrs(conn_handle, service->start_handle, service->end_handle, ble_disc_chr_cb, NULL) != 0) {
            printf("disc chrs failed\n");
        }
    }
    return 0;    
}

// BLE event handling
static int ble_gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_hs_adv_fields fields;

    switch (event->type)
    {
    // NimBLE event discovery
    case BLE_GAP_EVENT_DISC:
        ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);
        if (fields.name_len > 0) {
            printf("Name: %.*s\n", fields.name_len, fields.name);
            if (strncmp((char*)fields.name, "VIP-BLE-Server", fields.name_len) == 0) {
                printf("Trying to connect!\n");
                ble_gap_disc_cancel();
                int ret = ble_gap_connect(ble_addr_type, &event->disc.addr, BLE_HS_FOREVER, NULL, ble_gap_event, NULL);
                if (ret != 0) {
                    ble_app_scan();
                }
            }
        }
        break;
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            ble_gap_conn_find(event->connect.conn_handle, &connection_description);
            if (ble_gattc_disc_svc_by_uuid(event->connect.conn_handle, server_uuid, ble_svc_disc_cb, NULL) != 0) {
                printf("Error while discovering service!");
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

void ble_app_scan(void)
{
    printf("Start scanning ...\n");

    struct ble_gap_disc_params disc_params;
    disc_params.filter_duplicates = 1;
    disc_params.passive = 0;
    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;

    ble_gap_disc(ble_addr_type, BLE_HS_FOREVER, &disc_params, ble_gap_event, NULL);
}

// The application
void ble_app_on_sync(void)
{
    ble_hs_id_infer_auto(0, &ble_addr_type); // Determines the best address type automatically
    ble_app_scan();
}

// The infinite task
void host_task(void *param)
{
    nimble_port_run(); // This function will return only when nimble_port_stop() is executed
}

void app_main()
{
    nvs_flash_init();
    nimble_port_init();

    ble_svc_gap_device_name_set("VIP-BLE-Client");
    ble_svc_gap_init();
    ble_hs_cfg.sync_cb = ble_app_on_sync;

    memset(&connection_description, 0, sizeof(struct ble_gap_conn_desc));

    mbedtls_aes_init(&aes_ctx);

    mbedtls_entropy_context entropy;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_ecdh_init( &ctxc );
    mbedtls_ecdh_setup( &ctxc, MBEDTLS_ECP_DP_CURVE25519 );

    mbedtls_ecdh_gen_public(&ctxc.private_grp, &ctxc.private_d, &ctxc.private_Q, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ecp_point_write_binary(&ctxc.private_grp, &ctxc.private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_key_len, public_key_buf, sizeof(public_key_buf)); 

    printf("Generated public key: ");
    print_hex(public_key_buf, public_key_len);
    printf("\n");

    nimble_port_freertos_init(host_task);

    while (!recieved1 && !recieved2) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    printf("Recieved public key: ");
    print_hex(peer_public_raw, 32);
    printf("\n");

    mbedtls_ecp_point_read_binary(&ctxc.private_grp, &peer_public, peer_public_raw, public_key_len);

    mbedtls_ecdh_compute_shared(&ctxc.private_grp, &ctxc.private_z, &peer_public, &ctxc.private_d, mbedtls_ctr_drbg_random, &ctr_drbg);

    char shared_secret_str[200];
    size_t shared_secret_len;
    int ret = mbedtls_mpi_write_string(&ctxc.private_z, 16, shared_secret_str, sizeof(shared_secret_str), &shared_secret_len);
    if (ret != 0) {
        printf("Couldn't write shared secret string.\n");
    }
    else {
        printf("Shared secret: %s\n", shared_secret_str);
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    uint8_t shared_key[128];

    mbedtls_hkdf(md_info, NULL, 0, (uint8_t*)shared_secret_str, shared_secret_len, NULL, 0, shared_key, 128);

    printf("Derived shared key: ");
    print_hex(shared_key, 128);
    printf("\n");

    mbedtls_aes_setkey_enc(&aes_ctx, shared_key, 128);
    mbedtls_aes_setkey_dec(&aes_ctx, shared_key, 128);

    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        ble_gattc_read(comms_conn_handle, comms_attr_val_handle, recieve_enc_packet, NULL);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        struct encrypted_packet send;
        gen_enc_packet(&send);
        ble_gattc_write_flat(comms_conn_handle, comms_attr_val_handle, &send, sizeof(struct encrypted_packet), NULL, NULL);
    }

}

