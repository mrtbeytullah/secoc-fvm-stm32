#ifndef MCP2515_H
#define MCP2515_H

#include "stm32f3xx_hal.h"
#include <stdint.h>
#include <stdbool.h>

#define MCP2515_CMD_RESET         0xC0
#define MCP2515_CMD_READ          0x03
#define MCP2515_CMD_WRITE         0x02
#define MCP2515_CMD_RTS_TXB0      0x81
#define MCP2515_CMD_RTS_TXB1      0x82
#define MCP2515_CMD_RTS_TXB2      0x84
#define MCP2515_CMD_READ_STATUS   0xA0
#define MCP2515_CMD_RX_STATUS     0xB0
#define MCP2515_CMD_BIT_MODIFY    0x05

#define MCP2515_REG_CANSTAT       0x0E
#define MCP2515_REG_CANCTRL       0x0F
#define MCP2515_REG_BFPCTRL       0x0C
#define MCP2515_REG_TEC           0x1C
#define MCP2515_REG_REC           0x1D
#define MCP2515_REG_CNF3          0x28
#define MCP2515_REG_CNF2          0x29
#define MCP2515_REG_CNF1          0x2A
#define MCP2515_REG_CANINTE       0x2B
#define MCP2515_REG_CANINTF       0x2C
#define MCP2515_REG_EFLG          0x2D

#define MCP2515_REG_TXB0CTRL      0x30
#define MCP2515_REG_TXB0SIDH      0x31
#define MCP2515_REG_TXB0SIDL      0x32
#define MCP2515_REG_TXB0DLC       0x35
#define MCP2515_REG_TXB0D0        0x36

#define MCP2515_REG_RXB0CTRL      0x60
#define MCP2515_REG_RXB0SIDH      0x61
#define MCP2515_REG_RXB0SIDL      0x62
#define MCP2515_REG_RXB0DLC       0x65
#define MCP2515_REG_RXB0D0        0x66

#define MCP2515_MODE_NORMAL       0x00
#define MCP2515_MODE_SLEEP        0x20
#define MCP2515_MODE_LOOPBACK     0x40
#define MCP2515_MODE_LISTENONLY   0x60
#define MCP2515_MODE_CONFIG       0x80

#define MCP2515_CANINTF_RX0IF     0x01
#define MCP2515_CANINTF_RX1IF     0x02
#define MCP2515_CANINTF_TX0IF     0x04

typedef struct {
    uint16_t id;
    uint8_t dlc;
    uint8_t data[8];
} can_message_t;

typedef struct {
    SPI_HandleTypeDef *hspi;
    GPIO_TypeDef *cs_port;
    uint16_t cs_pin;
} mcp2515_handle_t;

bool mcp2515_init(mcp2515_handle_t *hdev, SPI_HandleTypeDef *hspi, GPIO_TypeDef *cs_port, uint16_t cs_pin);
void mcp2515_reset(mcp2515_handle_t *hdev);
uint8_t mcp2515_read_reg(mcp2515_handle_t *hdev, uint8_t reg);
void mcp2515_write_reg(mcp2515_handle_t *hdev, uint8_t reg, uint8_t val);
void mcp2515_bit_modify(mcp2515_handle_t *hdev, uint8_t reg, uint8_t mask, uint8_t val);
bool mcp2515_set_mode(mcp2515_handle_t *hdev, uint8_t mode);
bool mcp2515_transmit(mcp2515_handle_t *hdev, const can_message_t *msg);
bool mcp2515_receive(mcp2515_handle_t *hdev, can_message_t *msg);
uint8_t mcp2515_get_interrupts(mcp2515_handle_t *hdev);
void mcp2515_clear_rx_interrupt(mcp2515_handle_t *hdev);

#endif
