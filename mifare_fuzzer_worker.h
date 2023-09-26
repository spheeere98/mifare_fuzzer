#pragma once
#include <furi.h>
#include <furi_hal.h>
#include <lib/nfc/nfc_worker.h>

typedef enum MifareFuzzerWorkerState {
    MifareFuzzerWorkerStateEmulateUid,
    MifareFuzzerWorkerStateEmulateClassic,
    MifareFuzzerWorkerStateEmulateUltralight,
    MifareFuzzerWorkerStateStop,
} MifareFuzzerWorkerState;

#define UID_LEN 7
#define ATQA_LEN 2

typedef struct MifareFuzzerWorker {
    FuriThread* thread;
    NfcWorker* nfc_worker;
    NfcDevice* nfc_device;
    MifareFuzzerWorkerState state;
    FuriHalNfcDevData nfc_dev_data;
} MifareFuzzerWorker;

// worker
MifareFuzzerWorker* mifare_fuzzer_worker_alloc();
void mifare_fuzzer_worker_free(MifareFuzzerWorker* mifare_fuzzer_worker);
void mifare_fuzzer_worker_stop(MifareFuzzerWorker* mifare_fuzzer_worker);
void mifare_fuzzer_worker_start(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    MifareFuzzerWorkerState initial_state);
// task
int32_t mifare_fuzzer_worker_task(void* context);
//
bool mifare_fuzzer_worker_is_emulating(MifareFuzzerWorker* mifare_fuzzer_worker);

void mifare_fuzzer_worker_set_nfc_dev_data(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    FuriHalNfcDevData nfc_dev_data);
FuriHalNfcDevData mifare_fuzzer_worker_get_nfc_dev_data(MifareFuzzerWorker* mifare_fuzzer_worker);

void mifare_fuzzer_worker_set_nfc_device(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    NfcDevice* nfc_device);
NfcDevice* mifare_fuzzer_worker_get_nfc_device(MifareFuzzerWorker* mifare_fuzzer_worker);