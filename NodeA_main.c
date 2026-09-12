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
secoc_node_t secoc_tx_node;

static const uint8_t secoc_key[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

static secoc_payload_t current_telemetry = {
    .speed_kmh = 30,
    .throttle_percent = 20,
    .engine_status = 1
};

static volatile bool replay_attack_pending = false;
osSemaphoreId_t sem_button;
osMutexId_t mtx_telemetry;

osThreadId_t tid_sensor;
osThreadId_t tid_secoc_tx;
osThreadId_t tid_button;

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

void Task_SensorSim(void *argument)
{
    (void)argument;
    uint8_t speed_dir = 1;

    for (;;) {
        osDelay(50);

        if (osMutexAcquire(mtx_telemetry, 10) == osOK) {
            if (speed_dir) {
                current_telemetry.speed_kmh += 2;
                if (current_telemetry.speed_kmh >= 130) {
                    speed_dir = 0;
                }
            } else {
                current_telemetry.speed_kmh -= 2;
                if (current_telemetry.speed_kmh <= 20) {
                    speed_dir = 1;
                }
            }
            current_telemetry.throttle_percent = (uint8_t)((current_telemetry.speed_kmh * 100) / 140);
            osMutexRelease(mtx_telemetry);
        }
    }
}

void Task_SecOC_Tx(void *argument)
{
    (void)argument;
    can_message_t can_tx;
    secoc_payload_t snap;

    for (;;) {
        osDelay(100);

        if (osMutexAcquire(mtx_telemetry, 10) == osOK) {
            snap = current_telemetry;
            osMutexRelease(mtx_telemetry);
        }

        if (replay_attack_pending) {
            replay_attack_pending = false;
            secoc_build_replay_pdu(&secoc_tx_node, &snap, 10, &can_tx);
            mcp2515_transmit(&mcp_dev, &can_tx);

            uint32_t mac = ((uint32_t)can_tx.data[4] << 24) |
                           ((uint32_t)can_tx.data[5] << 16) |
                           ((uint32_t)can_tx.data[6] << 8)  |
                           (uint32_t)can_tx.data[7];

            uart_log("[TX_ATTACK] Replay injected on PC13 press!\r\n");
            uart_log("[TX] PDU:0x%03X | CNT:%u | DATA:%u km/h | MAC:0x%08X\r\n",
                     can_tx.id, can_tx.data[3], snap.speed_kmh, mac);
        } else {
            secoc_build_pdu(&secoc_tx_node, &snap, &can_tx);
            mcp2515_transmit(&mcp_dev, &can_tx);

            uint32_t mac = ((uint32_t)can_tx.data[4] << 24) |
                           ((uint32_t)can_tx.data[5] << 16) |
                           ((uint32_t)can_tx.data[6] << 8)  |
                           (uint32_t)can_tx.data[7];

            uart_log("[TX] PDU:0x%03X | CNT:%u | DATA:%u km/h | MAC:0x%08X\r\n",
                     can_tx.id, can_tx.data[3], snap.speed_kmh, mac);
        }

        HAL_GPIO_TogglePin(GPIOB, GPIO_PIN_13);
    }
}

void Task_Button(void *argument)
{
    (void)argument;

    for (;;) {
        if (osSemaphoreAcquire(sem_button, osWaitForever) == osOK) {
            osDelay(50);
            if (HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) == GPIO_PIN_RESET) {
                replay_attack_pending = true;
            }
        }
    }
}

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
    if (GPIO_Pin == GPIO_PIN_13) {
        if (sem_button != NULL) {
            osSemaphoreRelease(sem_button);
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

    uart_log("\r\n=== AUTOSAR SecOC Node A (Sender) Initializing ===\r\n");

    secoc_init(&secoc_tx_node, secoc_key, SECOC_DATA_ID);

    if (!mcp2515_init(&mcp_dev, &hspi1, GPIOB, GPIO_PIN_6)) {
        uart_log("[ERROR] MCP2515 init failed on Node A!\r\n");
        for (;;);
    }

    uart_log("[INFO] MCP2515 initialized (500 kbps, Normal Mode)\r\n");

    osKernelInitialize();

    sem_button = osSemaphoreNew(1, 0, NULL);
    mtx_telemetry = osMutexNew(NULL);

    const osThreadAttr_t attr_sensor = { .name = "Task_SensorSim", .priority = osPriorityNormal, .stack_size = 512 * 4 };
    const osThreadAttr_t attr_tx = { .name = "Task_SecOC_Tx", .priority = osPriorityAboveNormal, .stack_size = 512 * 4 };
    const osThreadAttr_t attr_btn = { .name = "Task_Button", .priority = osPriorityHigh, .stack_size = 256 * 4 };

    tid_sensor = osThreadNew(Task_SensorSim, NULL, &attr_sensor);
    tid_secoc_tx = osThreadNew(Task_SecOC_Tx, NULL, &attr_tx);
    tid_button = osThreadNew(Task_Button, NULL, &attr_btn);

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

    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();

    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_6, GPIO_PIN_SET);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);

    GPIO_InitStruct.Pin = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

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

    HAL_NVIC_SetPriority(EXTI15_10_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(EXTI15_10_IRQn);
}

void EXTI15_10_IRQHandler(void)
{
    HAL_GPIO_EXTI_IRQHandler(GPIO_PIN_13);
}
