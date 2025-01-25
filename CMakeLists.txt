# TODO: Unexpectly, it seems changing the output directory to generate,
# is very problematic. We want to solve that at some point! 

add_custom_target(
   nexus
   COMMAND make M=${CMAKE_BINARY_DIR}
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
