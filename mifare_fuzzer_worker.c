
#include <lib/nfc/nfc_worker.h>
#include "mifare_fuzzer_worker.h"
#include <furi.h>
#include <storage/storage.h>

/// @brief mifare_fuzzer_worker_alloc()
/// @return
MifareFuzzerWorker* mifare_fuzzer_worker_alloc() {
    MifareFuzzerWorker* mifare_fuzzer_worker = malloc(sizeof(MifareFuzzerWorker));
    // Worker thread attributes
    mifare_fuzzer_worker->thread = furi_thread_alloc_ex(
        "MifareFuzzerWorker", 8192, mifare_fuzzer_worker_task, mifare_fuzzer_worker);
    mifare_fuzzer_worker->nfc_worker = nfc_worker_alloc();
    mifare_fuzzer_worker->state = MifareFuzzerWorkerStateStop;
    return mifare_fuzzer_worker;
}

/// @brief mifare_fuzzer_worker_free()
/// @param mifare_fuzzer_worker
void mifare_fuzzer_worker_free(MifareFuzzerWorker* mifare_fuzzer_worker) {
    furi_assert(mifare_fuzzer_worker);
    furi_thread_free(mifare_fuzzer_worker->thread);
    nfc_worker_free(mifare_fuzzer_worker->nfc_worker);
    free(mifare_fuzzer_worker);
}

static bool nfc_mf_classic_emulate_worker_callback(NfcWorkerEvent event, void* context) {
    MifareFuzzerWorker* mifare_fuzzer_worker = context;
    if(event == NfcWorkerEventSuccess) {
        mifare_fuzzer_worker_stop(mifare_fuzzer_worker);
    }
    return true;
}

/// @brief mifare_fuzzer_worker_stop()
/// @param mifare_fuzzer_worker
void mifare_fuzzer_worker_stop(MifareFuzzerWorker* mifare_fuzzer_worker) {
    furi_assert(mifare_fuzzer_worker);
    if(mifare_fuzzer_worker->state != MifareFuzzerWorkerStateStop) {
        mifare_fuzzer_worker->state = MifareFuzzerWorkerStateStop;
        furi_thread_join(mifare_fuzzer_worker->thread);
        nfc_worker_stop(mifare_fuzzer_worker->nfc_worker);
    }
}

/// @brief mifare_fuzzer_worker_start()
/// @param mifare_fuzzer_worker
void mifare_fuzzer_worker_start(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    MifareFuzzerWorkerState initial_state) {
    furi_assert(mifare_fuzzer_worker);
    mifare_fuzzer_worker->state = initial_state;
    furi_thread_start(mifare_fuzzer_worker->thread);
}

/// @brief mifare_fuzzer_worker_task()
/// @param context
/// @return
int32_t mifare_fuzzer_worker_task(void* context) {
    MifareFuzzerWorker* mifare_fuzzer_worker = context;

    if(mifare_fuzzer_worker->state == MifareFuzzerWorkerStateEmulateUid) {
        FuriHalNfcDevData params = mifare_fuzzer_worker->nfc_dev_data;

        furi_hal_nfc_exit_sleep();
        while(mifare_fuzzer_worker->state == MifareFuzzerWorkerStateEmulateUid) {
            furi_hal_nfc_listen(params.uid, params.uid_len, params.atqa, params.sak, false, 500);
            furi_delay_ms(50);
        }
        furi_hal_nfc_sleep();
    } else if(
        mifare_fuzzer_worker->state == MifareFuzzerWorkerStateEmulateClassic &&
        nfc_worker_get_state(mifare_fuzzer_worker->nfc_worker) != NfcWorkerStateMfClassicEmulate) {
        nfc_worker_stop(mifare_fuzzer_worker->nfc_worker);
        nfc_worker_start(
            mifare_fuzzer_worker->nfc_worker,
            NfcWorkerStateMfClassicEmulate,
            &mifare_fuzzer_worker->dev->dev_data,
            nfc_mf_classic_emulate_worker_callback,
            NULL);
    } else if(
        mifare_fuzzer_worker->state == MifareFuzzerWorkerStateEmulateUltralight &&
        nfc_worker_get_state(mifare_fuzzer_worker->nfc_worker) !=
            NfcWorkerStateMfUltralightEmulate) {
        nfc_worker_stop(mifare_fuzzer_worker->nfc_worker);
        nfc_worker_start(
            mifare_fuzzer_worker->nfc_worker,
            NfcWorkerStateMfUltralightEmulate,
            &mifare_fuzzer_worker->dev->dev_data,
            nfc_mf_classic_emulate_worker_callback,
            NULL);
    }

    mifare_fuzzer_worker->state = MifareFuzzerWorkerStateStop;

    return 0;
}

/// @brief mifare_fuzzer_worker_is_emulating()
/// @param mifare_fuzzer_worker
/// @return
bool mifare_fuzzer_worker_is_emulating(MifareFuzzerWorker* mifare_fuzzer_worker) {
    if(mifare_fuzzer_worker->state != MifareFuzzerWorkerStateStop) {
        return true;
    }
    return false;
}

/// @brief mifare_fuzzer_worker_set_nfc_dev_data()
/// @param mifare_fuzzer_worker
/// @param nfc_dev_data
void mifare_fuzzer_worker_set_nfc_dev_data(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    FuriHalNfcDevData nfc_dev_data) {
    mifare_fuzzer_worker->nfc_dev_data = nfc_dev_data;
}

/// @brief mifare_fuzzer_worker_get_nfc_dev_data()
/// @param mifare_fuzzer_worker
/// @return
FuriHalNfcDevData mifare_fuzzer_worker_get_nfc_dev_data(MifareFuzzerWorker* mifare_fuzzer_worker) {
    return mifare_fuzzer_worker->nfc_dev_data;
}

/// @brief mifare_fuzzer_worker_set_nfc_dev_data()
/// @param mifare_fuzzer_worker
/// @param nfc_dev_data
void mifare_fuzzer_worker_set_nfc_device(
    MifareFuzzerWorker* mifare_fuzzer_worker,
    NfcDevice* nfc_device) {
    mifare_fuzzer_worker->dev = nfc_device;
}

/// @brief mifare_fuzzer_worker_get_nfc_dev_data()
/// @param mifare_fuzzer_worker
/// @return
NfcDevice* mifare_fuzzer_worker_get_nfc_device(MifareFuzzerWorker* mifare_fuzzer_worker) {
    return mifare_fuzzer_worker->dev;
}
