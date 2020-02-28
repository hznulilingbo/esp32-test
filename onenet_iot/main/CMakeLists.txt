set(srcs
    "app_main.c"
    "src/base64.c"
    "src/hmac_sha1.c"
    "src/sha1.c")
idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "include")