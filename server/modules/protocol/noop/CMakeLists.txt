add_library(noop SHARED noop.c)
target_link_libraries(noop maxscale-common)
set_target_properties(noop PROPERTIES VERSION "1.0.0")
install_module(noop core)
