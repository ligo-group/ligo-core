# Add compile options to all targets added in the subdirectory.
function(all_targets_compile_options dir options)
  get_directory_property(targets DIRECTORY ${dir} BUILDSYSTEM_TARGETS)
  separate_arguments(options)
  set(compiled_target_types STATIC_LIBRARY SHARED_LIBRARY OBJECT_LIBRARY EXECUTABLE)
  foreach(target ${targets})
    get_target_property(type ${target} TYPE)
    if(type IN_LIST compiled_target_types)
      target_compile_options(${target} PRIVATE ${options})
    endif()
  endforeach()
endfunction()
