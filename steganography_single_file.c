/*
Add this to your C project to extract steganographic data from a PNG image.
Make sure to update the `png_path` and `MAGIC_HEADER` constants as needed.
Also don't forget to include `stb_image.h` in your project.
Uncomment VERBOSE_MODE to enable debugging through MessageBox popups
*/

//#define VERBOSE_MODE
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h" // https://github.com/nothings/stb/blob/master/stb_image.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <windows.h>

static const char* png_path = ".\\path\\to\\file.png"; ///// Update this path as needed
static const char* MAGIC_HEADER = "X9K7Q2M8"; ///// Update this as needed

unsigned char Payload[10000000] = {0};
size_t Payload_size = 0;
int extraction_success = 0;
char extraction_error[256] = "";

unsigned char* g_extracted_data = NULL;
size_t g_extracted_size = 0;
int g_extraction_success = 0;
char g_error_message[256] = "";

static const int MAGIC_LENGTH = 8;

// Verbose output macro - shows MessageBox only if VERBOSE_MODE is defined
#ifdef VERBOSE_MODE
    #define SHOW_MESSAGE(text, title, type) MessageBoxA(NULL, text, title, type)
    #define SET_ERROR_MSG(dest, size, msg) strcpy_s(dest, size, msg)
    #define SET_G_ERROR_MSG(msg) strcpy_s(g_error_message, sizeof(g_error_message), msg)
    #define APPEND_ERROR_MSG(dest, size, msg) strcat_s(dest, size, msg)
    #define FORMAT_MSG(dest, size, format, ...) sprintf_s(dest, size, format, __VA_ARGS__)
#else
    #define SHOW_MESSAGE(text, title, type) // Silent mode - no popups
    #define SET_ERROR_MSG(dest, size, msg) // Silent mode - no error strings
    #define SET_G_ERROR_MSG(msg) // Silent mode - no error strings
    #define APPEND_ERROR_MSG(dest, size, msg) // Silent mode - no error strings
    #define FORMAT_MSG(dest, size, format, ...) // Silent mode - no formatted strings
#endif

int extract_steganography_data(void);
//int write_extracted_payload_to_file(void);

static int verify_magic_header(unsigned char* data, const char* expected) {
    return memcmp(data, expected, strlen(expected)) == 0;
}

static uint32_t read_uint32_le(unsigned char* data) {
    return (uint32_t)data[0] | 
           ((uint32_t)data[1] << 8) | 
           ((uint32_t)data[2] << 16) | 
           ((uint32_t)data[3] << 24);
}

int extract_steganography_data(void) {
    // Reset payload array and variables
    memset(Payload, 0, sizeof(Payload));
    Payload_size = 0;
    extraction_success = 0;
    extraction_error[0] = '\0';
    g_extracted_data = NULL;
    g_extracted_size = 0;
    g_extraction_success = 0;
    g_error_message[0] = '\0';
    
    int width, height, channels;
    unsigned char* rgb_pixels = stbi_load(png_path, &width, &height, &channels, 3);
    
    if (!rgb_pixels) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Failed to load PNG image - file may be corrupted or invalid format");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    if (channels < 3) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "PNG image must be RGB format (3 channels minimum)");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        stbi_image_free(rgb_pixels);
        return 0;
    }
    
    int total_pixels = width * height;
    int bits_per_pixel = 12;
    long long total_bits = (long long)total_pixels * bits_per_pixel;
    long long total_bytes = total_bits / 8;
    
    if (total_bytes > INT_MAX) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Image too large to process");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    unsigned char* extracted_bytes = (unsigned char*)calloc((size_t)total_bytes, 1);
    if (!extracted_bytes) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Memory allocation failed");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    int bit_index = 0;
    // Process pixels in row-major order to match Python (y, then x)
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            int pixel_offset = (y * width + x) * 3;
            
            // Process channels R, G, B
            for (int channel = 0; channel < 3; channel++) {
                unsigned char pixel_value = rgb_pixels[pixel_offset + channel];
                
                // Extract 4 bits from each channel (bits 0, 1, 2, 3)
                for (int bit_pos = 0; bit_pos < 4; bit_pos++) {
                    if (bit_index < total_bits) {
                        int byte_index = bit_index / 8;
                        int bit_in_byte = 7 - (bit_index % 8);  // Try reverse bit order
                        
                        if (byte_index < total_bytes) {
                            if (pixel_value & (1 << bit_pos)) {
                                extracted_bytes[byte_index] |= (1 << bit_in_byte);
                            }
                        }
                        bit_index++;
                    }
                }
            }
        }
    }
    if (total_bytes < MAGIC_LENGTH) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Image too small to contain steganographic data");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    if (!verify_magic_header(extracted_bytes, MAGIC_HEADER)) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "No steganographic signature found - not a steganographic image");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    if (total_bytes < MAGIC_LENGTH + 4) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Invalid steganographic format - missing length field");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    uint32_t data_length = read_uint32_le(extracted_bytes + MAGIC_LENGTH);
    int min_total_size = MAGIC_LENGTH + 4 + 32 + data_length + MAGIC_LENGTH;
    if (data_length == 0) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Data length is zero");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    if (data_length > sizeof(Payload)) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Data length exceeds Payload buffer size");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    if (min_total_size > total_bytes) {
        SET_ERROR_MSG(extraction_error, sizeof(extraction_error), "Data length exceeds available space in image");
        SET_G_ERROR_MSG(extraction_error);
        SHOW_MESSAGE(extraction_error, "Extraction Error", MB_OK | MB_ICONERROR);
        free(extracted_bytes);
        return 0;
    }
    
    int data_start_offset = MAGIC_LENGTH + 4 + 32;
    
    // Copy extracted data directly into the static Payload array
    memcpy(Payload, extracted_bytes + data_start_offset, data_length);
    Payload_size = data_length;
    g_extracted_data = Payload;
    g_extracted_size = Payload_size;
    
    int footer_offset = data_start_offset + data_length;
    if (footer_offset + MAGIC_LENGTH <= total_bytes) {
        if (!verify_magic_header(extracted_bytes + footer_offset, MAGIC_HEADER)) {
            APPEND_ERROR_MSG(extraction_error, sizeof(extraction_error), " (footer verification failed but data extracted)");
            SET_G_ERROR_MSG(extraction_error);
        }
    }
    
    free(extracted_bytes);
    stbi_image_free(rgb_pixels);
    extraction_success = 1;
    g_extraction_success = 1;
    
    char success_msg[256];
    FORMAT_MSG(success_msg, sizeof(success_msg), "Successfully extracted %zu bytes of hidden data!", Payload_size);
    SHOW_MESSAGE(success_msg, "Extraction Success!", MB_OK | MB_ICONINFORMATION);
    
    return 1;
}

/*
int write_extracted_payload_to_file(void) {
    const char* filename = "data.bin";
    
    if (!Payload || Payload_size == 0) {
        SHOW_MESSAGE("No payload data available to write", "Write Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    FILE* file = fopen(filename, "wb");
    if (!file) {
        char error_msg[512];
        FORMAT_MSG(error_msg, sizeof(error_msg), "Failed to create file: %s", filename);
        SHOW_MESSAGE(error_msg, "Write Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    size_t bytes_written = fwrite(Payload, 1, Payload_size, file);
    fclose(file);
    
    if (bytes_written != Payload_size) {
        char error_msg[512];
        FORMAT_MSG(error_msg, sizeof(error_msg), "Failed to write complete data. Expected: %zu, Written: %zu", 
                 Payload_size, bytes_written);
        SHOW_MESSAGE(error_msg, "Write Error", MB_OK | MB_ICONWARNING);
        return 0;
    }
    
    char success_msg[512];
    FORMAT_MSG(success_msg, sizeof(success_msg), "Successfully wrote %zu bytes to: %s", 
             Payload_size, filename);
    SHOW_MESSAGE(success_msg, "Write Success!", MB_OK | MB_ICONINFORMATION);
    
    return 1;
}

*/