gdb-multiarch \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file babypwn" \
    -ex 'target remote localhost:1234' \
    -ex 'b *0x00000000040087C' \

