#ifndef ONYX_PLUGIN_H
#define ONYX_PLUGIN_H

/**
 * OnyxEngine Native Plugin SDK (C-ABI)
 * Compatible with Visual Studio 2022+ (MSVC), GCC, Clang, and Rust cdylib
 * 
 * Header Version: 1.0.0
 */

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

/* Result / Error Codes */
#define ONYX_PLUGIN_OK                 0
#define ONYX_PLUGIN_ERR_INVALID_PARAM -1
#define ONYX_PLUGIN_ERR_NOT_FOUND     -2
#define ONYX_PLUGIN_ERR_BUFFER_SMALL  -3
#define ONYX_PLUGIN_ERR_EXECUTION     -4
#define ONYX_PLUGIN_ERR_NOT_SUPPORTED -5

/* Plugin Metadata Structure */
#pragma pack(push, 8)
typedef struct OnyxPluginInfo {
    uint32_t api_version;       /* Must be ONYX_PLUGIN_API_VERSION */
    const char* name;           /* Plugin Name (UTF-8) */
    const char* version;        /* Plugin Version string, e.g. "1.0.0" */
    const char* author;         /* Plugin Author */
    const char* description;    /* Short description */
} OnyxPluginInfo;

/* AOB Match / Validation Result Structure */
typedef struct OnyxAobMatchResult {
    uint64_t address;           /* Resolved absolute address of first match */
    uint32_t match_count;       /* Total number of matches in target process */
    uint32_t is_unique;         /* 1 if exactly 1 match found, 0 otherwise */
    char module_name[128];      /* Name of module containing match, e.g. "game.exe" */
    uint64_t module_base;       /* Base address of the containing module */
    uint64_t module_offset;     /* Offset from module base */
    char function_name[256];    /* Closest export / PDB symbol / function name */
    uint64_t function_start;    /* Entry address of the enclosing function */
    int64_t function_offset;    /* Displacement in bytes from function start */
    char disasm_preview[512];   /* Disassembly lines preview around match */
} OnyxAobMatchResult;

/* Host Engine API passed to plugin on initialization */
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

/* Standard Plugin Exports (must be exported by plugin DLL) */
ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_GetInfo(OnyxPluginInfo* out_info);
ONYX_PLUGIN_EXPORT int32_t ONYX_PLUGIN_CALL OnyxPlugin_Init(const OnyxPluginHostAPI* host_api);
ONYX_PLUGIN_EXPORT void    ONYX_PLUGIN_CALL OnyxPlugin_Shutdown(void);

/* Optional Specific Capability Exports for SigMaker / AOB Validator */
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

#endif /* ONYX_PLUGIN_H */
