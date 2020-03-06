set(srcs
    "app_main.c"
    "src/onenet.c")
idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "include")