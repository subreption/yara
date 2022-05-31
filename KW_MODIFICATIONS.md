### Modifications to libyara for Kevin Weatherman's https://github.com/kweatherman/yara4ida project

All patches can be located by text grepping the YARA repo for "KW:"

##### Patch to make the namespace equal the rule file source during rule compilation

* Patches in: *libyara/lexer.c* and *libyara/compiler.c*

##### Added a custom AREA_MODULE to YARA's default module list

This module allows for searching for a number of 32 or 64bit values within a small address range.

* Modified: *libyara/modules/module_list*, *libyara/Makefile.am*
* Added: *libyara/modules/area*

* Added *AREA_MODULE* "Preprocessor Definitions" to Release and Debug configurations to: *windows/vs2017/libyara/libyara.vcxproj*

##### Build

* Converted the "vs2017" Windows project to use Microsoft Visual Studio 2022.

