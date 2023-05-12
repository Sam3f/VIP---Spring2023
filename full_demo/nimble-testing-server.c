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
#include "services/gatt/ble_svc_gatt.h"
#include "sdkconfig.h"
#include "mbedtls/aes.h"
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

char *TAG = "BLE-Server";
uint8_t ble_addr_type;
uint8_t dsc_read_val = 0x99;
void ble_app_advertise(void);
bool recieved1 = false;
bool recieved2 = false;
mbedtls_ecdh_context ctxc;
mbedtls_ecp_point peer_public;
uint8_t peer_public_raw[32];
unsigned char public_key_buf[MBEDTLS_ECP_MAX_BYTES];
size_t public_key_len;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes_ctx;
bool keyset = false;

void print_hex(const uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02hhx", buf[i]);
}

void gen_enc_packet(struct encrypted_packet *packet) {
    if (keyset) {
        uint8_t rand_len;
        uint8_t rand_data[5];
        uint8_t temp_ctr[16];
        size_t off = 0;
        uint8_t block[16];
        mbedtls_ctr_drbg_random(&ctr_drbg, &rand_len, 1);
        rand_len %= 4;
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
        printf("\n\n\n\n\n\n\n");
    }
    else {
        memset(packet, 0, sizeof(struct encrypted_packet));
    }
}

// Write data to ESP32 defined as server
static int device_write(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    for (int i = 0; i < ctxt->om->om_len; i++) {
        peer_public_raw[i] = ctxt->om->om_data[i];
    }
    recieved1 = true;
    return 0;
}

static int device_write_two(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    for (int i = 0; i < ctxt->om->om_len; i++) {
        peer_public_raw[i + 16] = ctxt->om->om_data[i];
    }
    recieved2 = true;
    return 0;
}

// Read data from ESP32 defined as server
static int device_read(uint16_t con_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    os_mbuf_append(ctxt->om, public_key_buf, public_key_len / 2);
    return 0;
}

static int device_read_two(uint16_t con_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    os_mbuf_append(ctxt->om, &public_key_buf[public_key_len / 2], public_key_len / 2);
    return 0;
}

static int device_comms(uint16_t con_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    struct encrypted_packet send;
    struct encrypted_packet *packet = (struct encrypted_packet*)ctxt->om->om_data; 
    uint8_t dec_data[5];
    size_t off = 0;
    uint8_t block[16];
    switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            gen_enc_packet(&send);
            os_mbuf_append(ctxt->om, &send, sizeof(struct encrypted_packet));
            break;
        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            printf("Recieved packet with ctr: ");
            print_hex(packet->ctr_nonce, 16);
            mbedtls_aes_crypt_ctr(&aes_ctx, packet->length + 1, &off, packet->ctr_nonce, block, packet->data, dec_data);
            printf("\nLength: %d\n", packet->length);
            printf("Encrypted data: ");
            print_hex(packet->data, packet->length + 1);
            printf("\n");
            printf("And decrypted data: %s\n", dec_data);
            printf("\n\n\n\n\n\n");
            break;
    }
    return 0;
}

// Array of pointers to other service definitions
// UUID - Universal Unique Identifier
static const struct ble_gatt_svc_def gatt_svcs[] = {
    {.type = BLE_GATT_SVC_TYPE_PRIMARY,
     .uuid = BLE_UUID128_DECLARE(0x22, 0x2b, 0x9a, 0xd9, 0x9a, 0xf8, 0xd5, 0x96, 0x7e, 0x47, 0x0c, 0x96, 0xc2, 0xab, 0x5a, 0x81),
     .characteristics = (struct ble_gatt_chr_def[]){
         {.uuid = BLE_UUID128_DECLARE(0xce, 0xd6, 0x73, 0xf7, 0xbb, 0xc6, 0x42, 0xc9, 0x8f, 0xe0, 0xdb, 0xad, 0x44, 0x06, 0xb5, 0xb2),           // Define UUID for reading first part of pubkey
          .flags = BLE_GATT_CHR_F_READ,
          .access_cb = device_read},
         {.uuid = BLE_UUID128_DECLARE(0xa1, 0x2d, 0x94, 0xde, 0xa9, 0xf8, 0x44, 0xc0, 0xa6, 0xf9, 0x4f, 0x59, 0xdf, 0xa8, 0x77, 0x87),
          .flags = BLE_GATT_CHR_F_READ,
          .access_cb = device_read_two},
         {.uuid = BLE_UUID128_DECLARE(0x61, 0x9a, 0x26, 0xbb, 0x32, 0x02, 0x44, 0x8c, 0x8e, 0x14, 0x94, 0x22, 0xbd, 0xac, 0x6b, 0x55),           // Define UUID for writing
          .flags = BLE_GATT_CHR_F_WRITE,
          .access_cb = device_write},
         {.uuid = BLE_UUID128_DECLARE(0xf5, 0xe3, 0xf6, 0xb6, 0xb5, 0x26, 0x4f, 0xb0, 0xb5, 0xdd, 0xfb, 0x3f, 0x36, 0xc5, 0x72, 0x3b),
          .flags = BLE_GATT_CHR_F_WRITE,
          .access_cb = device_write_two},
         {.uuid = BLE_UUID128_DECLARE(0x4d, 0x2e, 0xd7, 0x55, 0xbd, 0xb2, 0x43, 0xf7, 0x80, 0xdd, 0x17, 0xa7, 0xb1, 0x50, 0x9f, 0xb1),
          .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_READ,
          .access_cb = device_comms},
         {0}}},
    {0}};

// BLE event handling
static int ble_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type)
    {
    // Advertise if connected
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI("GAP", "BLE GAP EVENT CONNECT %s", event->connect.status == 0 ? "OK!" : "FAILED!");
        if (event->connect.status != 0)
        {
            ble_app_advertise();
        }
        break;
    // Advertise again after completion of the event
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI("GAP", "BLE GAP EVENT");
        ble_app_advertise();
        break;
    default:
        break;
    }
    return 0;
}

// Define the BLE connection
void ble_app_advertise(void)
{
    // GAP - device name definition
    struct ble_hs_adv_fields fields;
    const char *device_name;
    memset(&fields, 0, sizeof(fields));
    device_name = ble_svc_gap_device_name(); // Read the BLE device name
    fields.name = (uint8_t *)device_name;
    fields.name_len = strlen(device_name);
    fields.name_is_complete = 1;
    ble_gap_adv_set_fields(&fields);

    // GAP - device connectivity definition
    struct ble_gap_adv_params adv_params;
    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND; // connectable or non-connectable
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN; // discoverable or non-discoverable
    ble_gap_adv_start(ble_addr_type, NULL, BLE_HS_FOREVER, &adv_params, ble_gap_event, NULL);
}

// The application
void ble_app_on_sync(void)
{
    ble_hs_id_infer_auto(0, &ble_addr_type); // Determines the best address type automatically
    ble_app_advertise();                     // Define the BLE connection
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

    ble_svc_gap_device_name_set("VIP-BLE-Server");
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_gatts_count_cfg(gatt_svcs);
    ble_gatts_add_svcs(gatt_svcs);
    ble_hs_cfg.sync_cb = ble_app_on_sync;

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
    keyset = true;
}

