#include "stm32f3xx_hal.h"
#include "cmsis_os2.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "mcp2515.h"
#include "secoc.h"

SPI_HandleTypeDef hspi1;
UART_HandleTypeDef huart2;

mcp2515_handle_t mcp_dev;
secoc_node_t secoc_rx_node;

static const uint8_t secoc_key[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

osSemaphoreId_t sem_mcp_rx;
osMessageQueueId_t queue_can_rx;

osThreadId_t tid_mcp_rx;
osThreadId_t tid_verify;

void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI1_Init(void);
static void MX_USART2_UART_Init(void);

static void uart_log(const char *fmt, ...)
{
    char buf[128];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        HAL_UART_Transmit(&huart2, (uint8_t *)buf, (uint16_t)len, HAL_MAX_DELAY);
    }
}

void Task_MCP2515_Rx(void *argument)
{
    (void)argument;
    can_message_t rx_msg;

    for (;;) {
        if (osSemaphoreAcquire(sem_mcp_rx, osWaitForever) == osOK) {
            while (mcp2515_receive(&mcp_dev, &rx_msg)) {
                osMessageQueuePut(queue_can_rx, &rx_msg, 0, 10);
            }
            mcp2515_clear_rx_interrupt(&mcp_dev);
        }
    }
}

void Task_SecOC_Verify(void *argument)
{
    (void)argument;
    can_message_t msg;
    secoc_payload_t payload;
    uint8_t rx_fv = 0;
    uint32_t rx_mac = 0;

    for (;;) {
        if (osMessageQueueGet(queue_can_rx, &msg, NULL, osWaitForever) == osOK) {
            if (msg.id != SECOC_CAN_ID || msg.dlc != SECOC_CAN_DLC) {
                continue;
            }

            secoc_verify_result_t res = secoc_verify_pdu(&secoc_rx_node, &msg, &payload, &rx_fv, &rx_mac);

            switch (res) {
            case SECOC_VERIFY_ACCEPTED:
                HAL_GPIO_TogglePin(GPIOB, GPIO_PIN_13);
                uart_log("[RX] PDU:0x%03X | FV:%u (SYNC) | MAC:VALID -> PDU_ACCEPTED\r\n",
                         msg.id, rx_fv);
                break;

            case SECOC_VERIFY_REPLAY:
                HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);
                uart_log("[RX] PDU:0x%03X | FV:%u (OLD) -> REPLAY DETECTED! PDU_DROPPED\r\n",
                         msg.id, rx_fv);
                break;

            case SECOC_VERIFY_MAC_INVALID:
                HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);
                uart_log("[RX] PDU:0x%03X | FV:%u | MAC:INVALID -> PDU_DROPPED\r\n",
                         msg.id, rx_fv);
                break;

            case SECOC_VERIFY_OUT_OF_SYNC:
                HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);
                uart_log("[RX] PDU:0x%03X | FV:%u (DESYNC) -> OUT OF WINDOW! PDU_DROPPED\r\n",
                         msg.id, rx_fv);
                break;
            }
        }
    }
}

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
    if (GPIO_Pin == GPIO_PIN_0) {
        if (sem_mcp_rx != NULL) {
            osSemaphoreRelease(sem_mcp_rx);
        }
    }
}

int main(void)
{
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART2_UART_Init();
    MX_SPI1_Init();

    uart_log("\r\n=== AUTOSAR SecOC Node B (Receiver) Initializing ===\r\n");

    secoc_init(&secoc_rx_node, secoc_key, SECOC_DATA_ID);

    if (!mcp2515_init(&mcp_dev, &hspi1, GPIOB, GPIO_PIN_6)) {
        uart_log("[ERROR] MCP2515 init failed on Node B!\r\n");
        for (;;);
    }

    uart_log("[INFO] MCP2515 initialized (500 kbps, Normal Mode, Interrupts Enabled)\r\n");

    osKernelInitialize();

    sem_mcp_rx = osSemaphoreNew(1, 0, NULL);
    queue_can_rx = osMessageQueueNew(16, sizeof(can_message_t), NULL);

    const osThreadAttr_t attr_rx = { .name = "Task_MCP2515_Rx", .priority = osPriorityHigh, .stack_size = 512 * 4 };
    const osThreadAttr_t attr_verify = { .name = "Task_SecOC_Verify", .priority = osPriorityNormal, .stack_size = 512 * 4 };

    tid_mcp_rx = osThreadNew(Task_MCP2515_Rx, NULL, &attr_rx);
    tid_verify = osThreadNew(Task_SecOC_Verify, NULL, &attr_verify);

    osKernelStart();

    for (;;);
}

void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL16;
    HAL_RCC_OscConfig(&RCC_OscInitStruct);

    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                                  RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2);

    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART2;
    PeriphClkInit.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
    HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit);
}

static void MX_SPI1_Init(void)
{
    hspi1.Instance = SPI1;
    hspi1.Init.Mode = SPI_MODE_MASTER;
    hspi1.Init.Direction = SPI_DIRECTION_2LINES;
    hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
    hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
    hspi1.Init.NSS = SPI_NSS_SOFT;
    hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;
    hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    hspi1.Init.CRCPolynomial = 7;
    hspi1.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
    hspi1.Init.NSSPMode = SPI_NSS_PULSE_DISABLE;
    HAL_SPI_Init(&hspi1);
}

static void MX_USART2_UART_Init(void)
{
    huart2.Instance = USART2;
    huart2.Init.BaudRate = 115200;
    huart2.Init.WordLength = UART_WORDLENGTH_8B;
    huart2.Init.StopBits = UART_STOPBITS_1;
    huart2.Init.Parity = UART_PARITY_NONE;
    huart2.Init.Mode = UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart2.Init.OverSampling = UART_OVERSAMPLING_16;
    huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    HAL_UART_Init(&huart2);
}

static void MX_GPIO_Init(void)
{
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();

    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_6, GPIO_PIN_SET);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);

    GPIO_InitStruct.Pin = GPIO_PIN_0;
    GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_6;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_5 | GPIO_PIN_6 | GPIO_PIN_7;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF5_SPI1;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_2 | GPIO_PIN_3;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    HAL_NVIC_SetPriority(EXTI0_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(EXTI0_IRQn);
}

void EXTI0_IRQHandler(void)
{
    HAL_GPIO_EXTI_IRQHandler(GPIO_PIN_0);
}
