#ifndef ONYX_PLUGIN_H
#define ONYX_PLUGIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ONYX_PLUGIN_API_VERSION 1

#ifdef _WIN32
  #define ONYX_PLUGIN_EXPORT __declspec(dllexport)
  #define ONYX_PLUGIN_CALL __stdcall
#else
  #define ONYX_PLUGIN_EXPORT __attribute__((visibility("default")))
  #define ONYX_PLUGIN_CALL
#endif

#define ONYX_PLUGIN_OK                 0
#define ONYX_PLUGIN_ERR_INVALID_PARAM -1
#define ONYX_PLUGIN_ERR_NOT_FOUND     -2
#define ONYX_PLUGIN_ERR_BUFFER_SMALL  -3
#define ONYX_PLUGIN_ERR_EXECUTION     -4
#define ONYX_PLUGIN_ERR_NOT_SUPPORTED -5

#pragma pack(push, 8)
typedef struct OnyxPluginInfo {
    uint32_t api_version;
    const char* name;
    const char* version;
    const char* author;
    const char* description;
} OnyxPluginInfo;

typedef struct OnyxAobMatchResult {
    uint64_t address;
    uint32_t match_count;
    uint32_t is_unique;
    char module_name[128];
    uint64_t module_base;
    uint64_t module_offset;
    char function_name[256];
    uint64_t function_start;
    int64_t function_offset;
    char disasm_preview[512];
} OnyxAobMatchResult;

typedef struct OnyxPluginHostAPI {
    uint32_t struct_size;
    uint32_t (ONYX_PLUGIN_CALL *get_target_pid)(void);
    void*    (ONYX_PLUGIN_CALL *get_target_handle)(void);
    int32_t  (ONYX_PLUGIN_CALL *read_memory)(uint64_t address, void* buffer, size_t size, size_t* bytes_read);
    int32_t  (ONYX_PLUGIN_CALL *write_memory)(uint64_t address, const void* buffer, size_t size, size_t* bytes_written);
    int32_t  (ONYX_PLUGIN_CALL *resolve_symbol)(uint64_t address, char* out_name, size_t max_name_len, uint64_t* out_displacement);
    void     (ONYX_PLUGIN_CALL *log_message)(int level, const char* message);
} OnyxPluginHostAPI;
#pragma pack(pop)

ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_GetInfo(OnyxPluginInfo* out_info);
ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_Init(const OnyxPluginHostAPI* host_api);
ONYX_PLUGIN_EXPORT void    ONYX_PLUGIN_CALL OnyxPlugin_Shutdown(void);

ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_ValidateAOB(
    uint32_t pid,
    const char* pattern,
    const char* module_filter,
    OnyxAobMatchResult* out_result
);

ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_GenerateAOB(
    uint32_t pid,
    uint64_t target_address,
    uint32_t max_len,
    char* out_pattern_buf,
    uint32_t buf_size
);

#ifdef __cplusplus
}
#endif

#endif
