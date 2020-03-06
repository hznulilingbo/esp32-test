/* MQTT (over TCP) Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "esp_log.h"
#include "mqtt_client.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"
#include "onenet.h"
#include "sniffer.h"

static const uint8_t esp_module_mac[32][3] = {
    {0x54, 0x5A, 0xA6}, {0x24, 0x0A, 0xC4}, {0xD8, 0xA0, 0x1D}, {0xEC, 0xFA, 0xBC},
    {0xA0, 0x20, 0xA6}, {0x90, 0x97, 0xD5}, {0x18, 0xFE, 0x34}, {0x60, 0x01, 0x94},
    {0x2C, 0x3A, 0xE8}, {0xA4, 0x7B, 0x9D}, {0xDC, 0x4F, 0x22}, {0x5C, 0xCF, 0x7F},
    {0xAC, 0xD0, 0x74}, {0x30, 0xAE, 0xA4}, {0x24, 0xB2, 0xDE}, {0x68, 0xC6, 0x3A},
};

int s_device_info_num           = 0;
station_info_t *station_info    = NULL;
station_info_t *g_station_list  = NULL;

static const char *TAG = "MQTT_EXAMPLE";

static inline uint32_t sniffer_timestamp()
{
    return xTaskGetTickCount() * (1000 / configTICK_RATE_HZ);
}

/* The callback function of sniffer */
void wifi_sniffer_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;
    sniffer_payload_t *sniffer_payload = (sniffer_payload_t *)sniffer->payload;

    /* Check if the packet is Probo Request  */
    if (sniffer_payload->header[0] != 0x40) {
        return;
    }

    if (!g_station_list) {
        g_station_list = malloc(sizeof(station_info_t));
        g_station_list->next = NULL;
    }

    /* Check if there is enough memoory to use */
    if (esp_get_free_heap_size() < 60 * 1024) {
        s_device_info_num = 0;

        for (station_info = g_station_list->next; station_info; station_info = g_station_list->next) {
            g_station_list->next = station_info->next;
            free(station_info);
        }
    }
    /* Filter out some useless packet  */
    for (int i = 0; i < 32; ++i) {
        if (!memcmp(sniffer_payload->source_mac, esp_module_mac[i], 3)) {
            return;
        }
    }
    /* Traversing the chain table to check the presence of the device */
    for (station_info = g_station_list->next; station_info; station_info = station_info->next) {
        if (!memcmp(station_info->bssid, sniffer_payload->source_mac, sizeof(station_info->bssid))) {
            return;
        }
    }
    /* Add the device information to chain table */
    if (!station_info) {
        station_info = malloc(sizeof(station_info_t));
        station_info->next = g_station_list->next;
        g_station_list->next = station_info;
    }

    station_info->rssi = sniffer->rx_ctrl.rssi;
    station_info->channel = sniffer->rx_ctrl.channel;
    station_info->timestamp = sniffer_timestamp();
    memcpy(station_info->bssid, sniffer_payload->source_mac, sizeof(station_info->bssid));
    s_device_info_num++;
    printf("\nCurrent device num = %d\n", s_device_info_num);
    printf("MAC: 0x%02X.0x%02X.0x%02X.0x%02X.0x%02X.0x%02X, The time is: %d, The rssi = %d\n", station_info->bssid[0], station_info->bssid[1], station_info->bssid[2], station_info->bssid[3], station_info->bssid[4], station_info->bssid[5], station_info->timestamp, station_info->rssi);
}

static esp_err_t mqtt_event_handler_cb(esp_mqtt_event_handle_t event)
{
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    // your_context_t *context = event->context;
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            esp_mqtt_client_subscribe(client, "$sys/322674/dev-001/dp/post/json/+", 0);
            onenet_start(client);
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;
        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
    }
    return ESP_OK;
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);
    mqtt_event_handler_cb(event_data);
}

static bool onenet_token(unsigned char *basetoken)
{
    int i, j;
    unsigned char basekey[] = "PBA+6/QSINrOuneGgr9+98Zc/Bml5DWEOVbWkyEH8dM=";
    unsigned char key[64] = {0};
    unsigned int key_len = 0;
    unsigned char signature[128] = {0};
    unsigned char token[64] = {0};
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t ctx;

    if(mbedtls_base64_decode(key, 64, &key_len, basekey, strlen((char *)basekey)) != 0)
    {
        return false;
    }
    sprintf((char *)signature, "%s\n%s\n%s\n%s", "1640970061", "sha1", "products/322674/devices/dev-001", "2018-10-31");

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
        return false;
    }
    if (mbedtls_md_hmac_starts(&ctx, key, strlen((char *)key)) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_update(&ctx, signature, strlen((char *)signature)) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_finish(&ctx, token) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    mbedtls_md_free(&ctx);

    memset(key, 0, 64);
    mbedtls_base64_encode(key, 64, &key_len, token, strlen((char *)token));
    printf("key %s\n", key);
    memset(token, 0, 64);
    for(i=0, j=0; i < strlen((char *)key); i++)
    {
        switch (key[i])
        {
            case '+':
            memcpy(token + j, "%2B", 3);
            j = j + 3;
            break;
            case ' ':
            memcpy(token + j, "%20", 3);
            j = j + 3;
            break;
            case '/':
            memcpy(token + j, "%2F", 3);
            j = j + 3;
            break;
            case '?':
            memcpy(token + j, "%3F", 3);
            j = j + 3;
            break;
            case '%':
            memcpy(token + j, "%25", 3);
            j = j + 3;
            break;
            case '#':
            memcpy(token + j, "%23", 3);
            j = j + 3;
            break;
            case '&':
            memcpy(token + j, "%26", 3);
            j = j + 3;
            break;
            case '=':
            memcpy(token + j, "%3D", 3);
            j = j + 3;
            break;
            default:
            token[j] = key[i];
            j++;
            break;
        }
    }
    printf("token %s\n", token);
    snprintf((char *)basetoken, 256, "version=2018-10-31&res=%s&et=%s&method=%s&sign=%s", "products%2F322674%2Fdevices%2Fdev-001", "1640970061", "sha1", token);
    printf("basetoken %s\n", basetoken);
    return true;
}

static void mqtt_app_start(void)
{
    unsigned char base64_token[256] = {0};
    if( onenet_token(base64_token) == false)
    {
        printf("onenet_token error\n");
        return;
    }
    printf("base64 encode %s\n", base64_token);
#if 1
    esp_mqtt_client_config_t mqtt_cfg = {
        .host = "183.230.40.96",
        .port = 1883,
        .client_id = "dev-001",
        .username = "322674",
        .password = (char *)base64_token,
    };
#if CONFIG_BROKER_URL_FROM_STDIN
    char line[128];

    if (strcmp(mqtt_cfg.uri, "FROM_STDIN") == 0) {
        int count = 0;
        printf("Please enter url of mqtt broker\n");
        while (count < 128) {
            int c = fgetc(stdin);
            if (c == '\n') {
                line[count] = '\0';
                break;
            } else if (c > 0 && c < 127) {
                line[count] = c;
                ++count;
            }
            vTaskDelay(10 / portTICK_PERIOD_MS);
        }
        mqtt_cfg.uri = line;
        printf("Broker url: %s\n", line);
    } else {
        ESP_LOGE(TAG, "Configuration mismatch: wrong broker url");
        abort();
    }
#endif /* CONFIG_BROKER_URL_FROM_STDIN */

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, client);
    esp_mqtt_client_start(client);
#endif
}

void app_main(void)
{
    ESP_LOGI(TAG, "[APP] Startup..");
    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
    esp_log_level_set("MQTT_EXAMPLE", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT_TCP", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT_SSL", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
    esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    g_station_list = malloc(sizeof(station_info_t));
    g_station_list->next = NULL;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(1));

    mqtt_app_start();
}
