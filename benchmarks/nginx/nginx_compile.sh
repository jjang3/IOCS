./configure --with-cc-opt="-O0 -W -Wpointer-arith -Wno-unused -g -gdwarf-2 -save-temps=obj -gno-variable-location-views -masm=intel"
sed -i '/-Werror/d' ./objs/Makefile
make -j4
# Run from the nginx-1.3.9 source root. Superseded by build_nginx.sh, which also fixes the -Werror handling.
find "$PWD/objs" -type f -name "*.s" -exec sh -c 'mv "$0" "${0%.s}.intel"' {} \;