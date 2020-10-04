export PATH="$PATH:/root/cheri/output/sdk/bin"
export PYTHONPATH="$PYTHONPATH:/root/cheri/cheriplot/cheriplot/cheriverify"
/root/cheri/output/sdk/bin/gdb -iex "set sysroot /root/cheri/output/rootfs-purecap128" -q -x /root/cheri/cheriplot/cheriplot/cheriverify/static_analysis.py -ex "quit" $1 $2
