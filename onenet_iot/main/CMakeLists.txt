set(srcs
    "app_main.c"
    "src/base64.c")
idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "include")