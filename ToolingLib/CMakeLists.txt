

add_library (tooling_lib STATIC 
	"ToolingLib.cpp" 
	"ToolingLib.hpp"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET tooling_lib PROPERTY CXX_STANDARD 20)
endif()
