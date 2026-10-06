idf_component_register(
    SRCS "mp_cfg.c" "mp_cfg_esp.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash
)
