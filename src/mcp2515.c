#include "mcp2515.h"

static inline void mcp2515_select(mcp2515_handle_t *hdev)
{
    HAL_GPIO_WritePin(hdev->cs_port, hdev->cs_pin, GPIO_PIN_RESET);
}

static inline void mcp2515_deselect(mcp2515_handle_t *hdev)
{
    HAL_GPIO_WritePin(hdev->cs_port, hdev->cs_pin, GPIO_PIN_SET);
}

static uint8_t spi_transfer(mcp2515_handle_t *hdev, uint8_t data)
{
    uint8_t rx = 0;
    HAL_SPI_TransmitReceive(hdev->hspi, &data, &rx, 1, HAL_MAX_DELAY);
    return rx;
}

void mcp2515_reset(mcp2515_handle_t *hdev)
{
    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_RESET);
    mcp2515_deselect(hdev);
    HAL_Delay(10);
}

uint8_t mcp2515_read_reg(mcp2515_handle_t *hdev, uint8_t reg)
{
    uint8_t val;
    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_READ);
    spi_transfer(hdev, reg);
    val = spi_transfer(hdev, 0xFF);
    mcp2515_deselect(hdev);
    return val;
}

void mcp2515_write_reg(mcp2515_handle_t *hdev, uint8_t reg, uint8_t val)
{
    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_WRITE);
    spi_transfer(hdev, reg);
    spi_transfer(hdev, val);
    mcp2515_deselect(hdev);
}

void mcp2515_bit_modify(mcp2515_handle_t *hdev, uint8_t reg, uint8_t mask, uint8_t val)
{
    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_BIT_MODIFY);
    spi_transfer(hdev, reg);
    spi_transfer(hdev, mask);
    spi_transfer(hdev, val);
    mcp2515_deselect(hdev);
}

bool mcp2515_set_mode(mcp2515_handle_t *hdev, uint8_t mode)
{
    mcp2515_bit_modify(hdev, MCP2515_REG_CANCTRL, 0xE0, mode);
    for (uint32_t i = 0; i < 1000; i++) {
        if ((mcp2515_read_reg(hdev, MCP2515_REG_CANSTAT) & 0xE0) == mode) {
            return true;
        }
    }
    return false;
}

bool mcp2515_init(mcp2515_handle_t *hdev, SPI_HandleTypeDef *hspi, GPIO_TypeDef *cs_port, uint16_t cs_pin)
{
    hdev->hspi = hspi;
    hdev->cs_port = cs_port;
    hdev->cs_pin = cs_pin;

    mcp2515_deselect(hdev);
    mcp2515_reset(hdev);

    if (!mcp2515_set_mode(hdev, MCP2515_MODE_CONFIG)) {
        return false;
    }

    mcp2515_write_reg(hdev, MCP2515_REG_CNF1, 0x00);
    mcp2515_write_reg(hdev, MCP2515_REG_CNF2, 0x90);
    mcp2515_write_reg(hdev, MCP2515_REG_CNF3, 0x02);

    mcp2515_write_reg(hdev, MCP2515_REG_RXB0CTRL, 0x60);
    mcp2515_write_reg(hdev, MCP2515_REG_CANINTE, MCP2515_CANINTF_RX0IF);

    return mcp2515_set_mode(hdev, MCP2515_MODE_NORMAL);
}

bool mcp2515_transmit(mcp2515_handle_t *hdev, const can_message_t *msg)
{
    uint8_t status = mcp2515_read_reg(hdev, MCP2515_REG_TXB0CTRL);
    if (status & 0x08) {
        return false;
    }

    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_WRITE);
    spi_transfer(hdev, MCP2515_REG_TXB0SIDH);
    spi_transfer(hdev, (uint8_t)(msg->id >> 3));
    spi_transfer(hdev, (uint8_t)((msg->id & 0x07) << 5));
    spi_transfer(hdev, 0x00);
    spi_transfer(hdev, 0x00);
    spi_transfer(hdev, msg->dlc & 0x0F);

    for (uint8_t i = 0; i < msg->dlc; i++) {
        spi_transfer(hdev, msg->data[i]);
    }
    mcp2515_deselect(hdev);

    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_RTS_TXB0);
    mcp2515_deselect(hdev);

    return true;
}

bool mcp2515_receive(mcp2515_handle_t *hdev, can_message_t *msg)
{
    uint8_t intf = mcp2515_read_reg(hdev, MCP2515_REG_CANINTF);
    if (!(intf & MCP2515_CANINTF_RX0IF)) {
        return false;
    }

    mcp2515_select(hdev);
    spi_transfer(hdev, MCP2515_CMD_READ);
    spi_transfer(hdev, MCP2515_REG_RXB0SIDH);
    uint8_t sidh = spi_transfer(hdev, 0xFF);
    uint8_t sidl = spi_transfer(hdev, 0xFF);
    spi_transfer(hdev, 0xFF);
    spi_transfer(hdev, 0xFF);
    msg->dlc = spi_transfer(hdev, 0xFF) & 0x0F;
    if (msg->dlc > 8) {
        msg->dlc = 8;
    }

    for (uint8_t i = 0; i < msg->dlc; i++) {
        msg->data[i] = spi_transfer(hdev, 0xFF);
    }
    mcp2515_deselect(hdev);

    msg->id = ((uint16_t)sidh << 3) | (sidl >> 5);
    mcp2515_bit_modify(hdev, MCP2515_REG_CANINTF, MCP2515_CANINTF_RX0IF, 0x00);

    return true;
}

uint8_t mcp2515_get_interrupts(mcp2515_handle_t *hdev)
{
    return mcp2515_read_reg(hdev, MCP2515_REG_CANINTF);
}

void mcp2515_clear_rx_interrupt(mcp2515_handle_t *hdev)
{
    mcp2515_bit_modify(hdev, MCP2515_REG_CANINTF, MCP2515_CANINTF_RX0IF, 0x00);
}
