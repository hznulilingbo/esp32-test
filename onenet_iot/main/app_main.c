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

static const char *TAG = "MQTT_EXAMPLE";


static esp_err_t mqtt_event_handler_cb(esp_mqtt_event_handle_t event)
{
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    // your_context_t *context = event->context;
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            /*
            msg_id = esp_mqtt_client_publish(client, "/topic/qos1", "data_3", 0, 1, 0);
            ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);

            msg_id = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
            ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

            msg_id = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
            ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

            msg_id = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
            ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);
            */
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            /*
            msg_id = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
            ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
            */
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

    mqtt_app_start();
}
