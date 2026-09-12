#include "secoc.h"
#include <string.h>

void secoc_init(secoc_node_t *node, const uint8_t *key, uint16_t data_id)
{
    aes128_cmac_init(&node->cmac_ctx, key);
    node->data_id = data_id;
    node->fvm.trip_counter = 1;
    node->fvm.reset_counter = 1;
    node->fvm.message_counter = 0;
}

uint64_t secoc_get_full_fv(const secoc_fvm_t *fvm)
{
    return ((uint64_t)fvm->trip_counter << 48) |
           ((uint64_t)fvm->reset_counter << 32) |
           (uint64_t)fvm->message_counter;
}

void secoc_set_full_fv(secoc_fvm_t *fvm, uint64_t full_fv)
{
    fvm->trip_counter = (uint16_t)(full_fv >> 48);
    fvm->reset_counter = (uint16_t)(full_fv >> 32);
    fvm->message_counter = (uint32_t)(full_fv & 0xFFFFFFFFULL);
}

static void secoc_build_auth_buffer(uint16_t data_id, const secoc_payload_t *payload, uint64_t full_fv, uint8_t *buf)
{
    buf[0] = (uint8_t)(data_id >> 8);
    buf[1] = (uint8_t)(data_id & 0xFF);
    buf[2] = payload->speed_kmh;
    buf[3] = payload->throttle_percent;
    buf[4] = payload->engine_status;

    for (uint8_t i = 0; i < 8; i++) {
        buf[5 + i] = (uint8_t)(full_fv >> (56 - (i * 8)));
    }
}

void secoc_build_pdu(secoc_node_t *node, const secoc_payload_t *payload, can_message_t *can_msg)
{
    node->fvm.message_counter++;
    uint64_t full_fv = secoc_get_full_fv(&node->fvm);

    uint8_t auth_buf[13];
    secoc_build_auth_buffer(node->data_id, payload, full_fv, auth_buf);

    uint32_t mac32 = aes128_cmac_compute_tag32(&node->cmac_ctx, auth_buf, sizeof(auth_buf));

    can_msg->id = SECOC_CAN_ID;
    can_msg->dlc = SECOC_CAN_DLC;
    can_msg->data[0] = payload->speed_kmh;
    can_msg->data[1] = payload->throttle_percent;
    can_msg->data[2] = payload->engine_status;
    can_msg->data[3] = (uint8_t)(node->fvm.message_counter & 0xFF);
    can_msg->data[4] = (uint8_t)(mac32 >> 24);
    can_msg->data[5] = (uint8_t)(mac32 >> 16);
    can_msg->data[6] = (uint8_t)(mac32 >> 8);
    can_msg->data[7] = (uint8_t)(mac32 & 0xFF);
}

void secoc_build_replay_pdu(secoc_node_t *node, const secoc_payload_t *payload, uint32_t rollback_offset, can_message_t *can_msg)
{
    uint32_t replayed_msg_cnt = (node->fvm.message_counter > rollback_offset) ?
                                (node->fvm.message_counter - rollback_offset) : 1;

    uint64_t full_fv = ((uint64_t)node->fvm.trip_counter << 48) |
                       ((uint64_t)node->fvm.reset_counter << 32) |
                       (uint64_t)replayed_msg_cnt;

    uint8_t auth_buf[13];
    secoc_build_auth_buffer(node->data_id, payload, full_fv, auth_buf);

    uint32_t mac32 = aes128_cmac_compute_tag32(&node->cmac_ctx, auth_buf, sizeof(auth_buf));

    can_msg->id = SECOC_CAN_ID;
    can_msg->dlc = SECOC_CAN_DLC;
    can_msg->data[0] = payload->speed_kmh;
    can_msg->data[1] = payload->throttle_percent;
    can_msg->data[2] = payload->engine_status;
    can_msg->data[3] = (uint8_t)(replayed_msg_cnt & 0xFF);
    can_msg->data[4] = (uint8_t)(mac32 >> 24);
    can_msg->data[5] = (uint8_t)(mac32 >> 16);
    can_msg->data[6] = (uint8_t)(mac32 >> 8);
    can_msg->data[7] = (uint8_t)(mac32 & 0xFF);
}

secoc_verify_result_t secoc_verify_pdu(secoc_node_t *node, const can_message_t *can_msg, secoc_payload_t *payload_out, uint8_t *rx_truncated_fv, uint32_t *rx_mac)
{
    payload_out->speed_kmh = can_msg->data[0];
    payload_out->throttle_percent = can_msg->data[1];
    payload_out->engine_status = can_msg->data[2];

    uint8_t tfv = can_msg->data[3];
    *rx_truncated_fv = tfv;

    uint32_t mac_rx = ((uint32_t)can_msg->data[4] << 24) |
                      ((uint32_t)can_msg->data[5] << 16) |
                      ((uint32_t)can_msg->data[6] << 8)  |
                      (uint32_t)can_msg->data[7];
    *rx_mac = mac_rx;

    uint64_t local_fv = secoc_get_full_fv(&node->fvm);
    uint8_t local_lsb = (uint8_t)(node->fvm.message_counter & 0xFF);

    if (node->fvm.message_counter == 0) {
        uint64_t candidate_fv = (local_fv & ~0xFFULL) | tfv;
        uint8_t auth_buf[13];
        secoc_build_auth_buffer(node->data_id, payload_out, candidate_fv, auth_buf);

        uint32_t calc_mac = aes128_cmac_compute_tag32(&node->cmac_ctx, auth_buf, sizeof(auth_buf));
        if (calc_mac != mac_rx) {
            return SECOC_VERIFY_MAC_INVALID;
        }

        secoc_set_full_fv(&node->fvm, candidate_fv);
        return SECOC_VERIFY_ACCEPTED;
    }

    int8_t signed_delta = (int8_t)(tfv - local_lsb);
    uint8_t unsigned_delta = (uint8_t)(tfv - local_lsb);

    if (signed_delta <= 0) {
        return SECOC_VERIFY_REPLAY;
    }

    if (unsigned_delta > SECOC_ACCEPTANCE_WINDOW) {
        return SECOC_VERIFY_OUT_OF_SYNC;
    }

    uint64_t candidate_fv = local_fv + unsigned_delta;
    uint8_t auth_buf[13];
    secoc_build_auth_buffer(node->data_id, payload_out, candidate_fv, auth_buf);

    uint32_t calc_mac = aes128_cmac_compute_tag32(&node->cmac_ctx, auth_buf, sizeof(auth_buf));
    if (calc_mac != mac_rx) {
        return SECOC_VERIFY_MAC_INVALID;
    }

    secoc_set_full_fv(&node->fvm, candidate_fv);
    return SECOC_VERIFY_ACCEPTED;
}
