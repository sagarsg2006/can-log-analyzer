/*
 * Multi-sensor SD logger  (STM32F103 BluePill, libopencm3 + FatFS over SPI)
 *
 * Upgrades over the first version:
 *   1. 1 ms SysTick timebase -> every record carries a timestamp, and sampling
 *      is scheduled against time instead of a busy-wait delay().
 *   2. Interrupt-safe ring buffer between data producers (CAN RX handler / sensor
 *      reads) and the SD writer, so a slow SD write never blocks data capture.
 *      Overflows are counted instead of silently lost.
 *   3. Files stay open; f_sync() runs once per second instead of open/write/
 *      sync/close on every sample (far fewer SD operations, much higher throughput).
 *   4. CSV header row written to each new file.
 *   5. SD errors trigger unmount/remount recovery before giving up, instead of
 *      halting on the first fault. Blink-code halt kept as the last resort.
 *
 * Producers call record_push(id, value). Right now sample_sensors() feeds it
 * simulated values; to log real CAN data, call record_push() from your CAN
 * receive handler instead (id = CAN ID or sensor index 1..SENSOR_COUNT).
 */
#include "ff.h"
#include "sd_spi.h"
#include "uart.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libopencm3/cm3/systick.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rcc.h>

#define SENSOR_COUNT       3
#define SAMPLE_PERIOD_MS   100u
#define SYNC_PERIOD_MS     1000u
#define RING_SIZE          64u              /* must be a power of two */
#define RING_MASK          (RING_SIZE - 1u)
#define REMOUNT_TRIES      3

/* ---------------- TIMEBASE (1 ms SysTick) ---------------- */
static volatile uint32_t ms_ticks;

void sys_tick_handler(void)     /* name is fixed by libopencm3's vector table */
{
    ms_ticks++;
}

static void timebase_setup(void)
{
    systick_set_clocksource(STK_CSR_CLKSOURCE_AHB);
    systick_set_reload(rcc_ahb_frequency / 1000u - 1u);
    systick_interrupt_enable();
    systick_counter_enable();
}

static uint32_t millis(void) { return ms_ticks; }

static void delay_ms(uint32_t ms)
{
    uint32_t start = millis();
    while ((uint32_t)(millis() - start) < ms) { }
}

/* ---------------- LED ---------------- */
static void led_setup(void)
{
    rcc_periph_clock_enable(RCC_GPIOC);
    gpio_set_mode(GPIOC, GPIO_MODE_OUTPUT_2_MHZ,
                  GPIO_CNF_OUTPUT_PUSHPULL, GPIO13);
}
static void led_on(void)  { gpio_clear(GPIOC, GPIO13); }
static void led_off(void) { gpio_set(GPIOC, GPIO13); }

/* ---------------- ERROR HALT (last resort) ---------------- */
static void halt_with_error(const char *stage, int code)
{
    uart_send_string("FATAL at: ");
    uart_send_string(stage);
    uart_send_string(" | FRESULT: ");
    if (code >= 10) uart_send_char((char)('0' + (code / 10)));
    uart_send_char((char)('0' + (code % 10)));
    uart_send_string("\r\n");

    while (1) {
        for (int i = 0; i < code; i++) {
            led_on();  delay_ms(200);
            led_off(); delay_ms(200);
        }
        delay_ms(1000);
    }
}

/* ---------------- RECORD RING BUFFER (single producer, single consumer) ---- */
typedef struct {
    uint32_t t_ms;
    uint8_t  id;
    uint32_t value;
} Record;

static Record ring[RING_SIZE];
static volatile uint16_t ring_head;        /* written only by the producer */
static volatile uint16_t ring_tail;        /* written only by the consumer */
static volatile uint32_t ring_overflows;

bool record_push(uint8_t id, uint32_t value)   /* safe to call from an ISR */
{
    uint16_t next = (uint16_t)((ring_head + 1u) & RING_MASK);
    if (next == ring_tail) {                   /* full: count it, don't block */
        ring_overflows++;
        return false;
    }
    ring[ring_head].t_ms  = millis();
    ring[ring_head].id    = id;
    ring[ring_head].value = value;
    __asm__ volatile("" ::: "memory");         /* data must land before head moves */
    ring_head = next;
    return true;
}

static bool record_pop(Record *out)
{
    if (ring_tail == ring_head) return false;
    *out = ring[ring_tail];
    __asm__ volatile("" ::: "memory");
    ring_tail = (uint16_t)((ring_tail + 1u) & RING_MASK);
    return true;
}

/* ---------------- SENSORS ---------------- */
typedef struct {
    uint8_t     id;
    const char *filename;
    FIL         fil;
    uint32_t    value;        /* simulated for now */
} Sensor;

static Sensor sensors[SENSOR_COUNT] = {
    {1, "sensor1.csv", {0}, 0},
    {2, "sensor2.csv", {0}, 100},
    {3, "sensor3.csv", {0}, 1000},
};

static void sample_sensors(void)
{
    /* SIMULATED VALUES - replace with real data (e.g. record_push() from the
     * CAN RX handler). */
    sensors[0].value += 1;
    sensors[1].value += 10;
    sensors[2].value += 100;
    for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
        record_push(sensors[i].id, sensors[i].value);
    }
}

/* ---------------- SD LOGGER ---------------- */
static FATFS fs;
static uint32_t recoveries;

static const char CSV_HEADER[] = "timestamp_ms,sensor_id,value\r\n";

static FRESULT open_log_files(void)
{
    for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
        FRESULT r = f_open(&sensors[i].fil, sensors[i].filename,
                           FA_OPEN_APPEND | FA_WRITE);
        if (r != FR_OK) return r;

        if (f_size(&sensors[i].fil) == 0) {            /* brand-new file */
            UINT bw;
            r = f_write(&sensors[i].fil, CSV_HEADER, sizeof(CSV_HEADER) - 1, &bw);
            if (r != FR_OK) return r;
            if (bw != sizeof(CSV_HEADER) - 1) return FR_DISK_ERR;
        }
    }
    return FR_OK;
}

static FRESULT logger_start(void)
{
    FRESULT r = f_mount(&fs, "", 1);       /* runs disk_initialize -> sd_init */
    if (r != FR_OK) return r;
    return open_log_files();
}

static void logger_stop(void)
{
    for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
        f_close(&sensors[i].fil);          /* result ignored: may be invalid already */
    }
    f_mount(NULL, "", 0);
}

/* Try to bring the card back; give up (blink code) only if that fails. */
static void logger_recover(const char *stage, FRESULT err)
{
    uart_send_string("WARN: SD error at ");
    uart_send_string(stage);
    uart_send_string(", remounting\r\n");

    logger_stop();
    for (int attempt = 0; attempt < REMOUNT_TRIES; attempt++) {
        delay_ms(200);
        if (logger_start() == FR_OK) {
            recoveries++;
            return;
        }
    }
    halt_with_error(stage, (int)err);
}

static FRESULT write_record(const Record *rec)
{
    if (rec->id < 1 || rec->id > SENSOR_COUNT) return FR_OK;   /* ignore unknown ids */

    char line[48];
    int len = snprintf(line, sizeof(line), "%lu,%u,%lu\r\n",
                       (unsigned long)rec->t_ms, (unsigned)rec->id,
                       (unsigned long)rec->value);
    if (len <= 0 || len >= (int)sizeof(line)) return FR_INT_ERR;

    UINT bw;
    FRESULT r = f_write(&sensors[rec->id - 1].fil, line, (UINT)len, &bw);
    if (r != FR_OK) return r;
    if (bw != (UINT)len) return FR_DISK_ERR;                    /* short write = card full */

    uart_send_string(line);                                     /* live view */
    return FR_OK;
}

static FRESULT sync_all(void)
{
    for (uint8_t i = 0; i < SENSOR_COUNT; i++) {
        FRESULT r = f_sync(&sensors[i].fil);
        if (r != FR_OK) return r;
    }
    return FR_OK;
}

/* ---------------- MAIN ---------------- */
int main(void)
{
    led_setup();
    led_off();
    timebase_setup();

    uart_setup();
    uart_send_string("UART ready\r\n");

    spi_setup();
    uart_send_string("SPI ready\r\n");

    FRESULT r = logger_start();
    if (r != FR_OK) halt_with_error("startup", (int)r);
    uart_send_string("SD mounted, logging\r\n");
    led_on();

    uint32_t next_sample = millis();
    uint32_t next_sync   = millis() + SYNC_PERIOD_MS;

    while (1) {
        uint32_t now = millis();

        if ((int32_t)(now - next_sample) >= 0) {       /* wrap-safe compare */
            next_sample += SAMPLE_PERIOD_MS;
            sample_sensors();
        }

        Record rec;
        while (record_pop(&rec)) {
            r = write_record(&rec);
            if (r != FR_OK) {                          /* this record is dropped */
                logger_recover("f_write", r);
                break;
            }
        }

        if ((int32_t)(now - next_sync) >= 0) {
            next_sync += SYNC_PERIOD_MS;
            r = sync_all();
            if (r != FR_OK) logger_recover("f_sync", r);

            char stat[64];
            snprintf(stat, sizeof(stat), "# overflows=%lu recoveries=%lu\r\n",
                     (unsigned long)ring_overflows, (unsigned long)recoveries);
            uart_send_string(stat);
        }
    }
}
