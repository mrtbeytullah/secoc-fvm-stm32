#ifndef SECOC_H
#define SECOC_H

#include <stdint.h>
#include <stdbool.h>
#include "aes128_cmac.h"
#include "mcp2515.h"

#define SECOC_CAN_ID             0x120
#define SECOC_CAN_DLC            8
#define SECOC_DATA_ID            0x10A2
#define SECOC_ACCEPTANCE_WINDOW  16

typedef struct {
    uint8_t speed_kmh;
    uint8_t throttle_percent;
    uint8_t engine_status;
} secoc_payload_t;

typedef struct {
    uint16_t trip_counter;
    uint16_t reset_counter;
    uint32_t message_counter;
} secoc_fvm_t;

typedef enum {
    SECOC_VERIFY_ACCEPTED = 0,
    SECOC_VERIFY_REPLAY,
    SECOC_VERIFY_MAC_INVALID,
    SECOC_VERIFY_OUT_OF_SYNC
} secoc_verify_result_t;

typedef struct {
    aes128_cmac_ctx_t cmac_ctx;
    secoc_fvm_t fvm;
    uint16_t data_id;
} secoc_node_t;

void secoc_init(secoc_node_t *node, const uint8_t *key, uint16_t data_id);
uint64_t secoc_get_full_fv(const secoc_fvm_t *fvm);
void secoc_set_full_fv(secoc_fvm_t *fvm, uint64_t full_fv);

void secoc_build_pdu(secoc_node_t *node, const secoc_payload_t *payload, can_message_t *can_msg);
void secoc_build_replay_pdu(secoc_node_t *node, const secoc_payload_t *payload, uint32_t rollback_offset, can_message_t *can_msg);

secoc_verify_result_t secoc_verify_pdu(secoc_node_t *node, const can_message_t *can_msg, secoc_payload_t *payload_out, uint8_t *rx_truncated_fv, uint32_t *rx_mac);

#endif
