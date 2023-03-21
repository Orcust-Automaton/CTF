cp *.cpio fs.cpio
mkdir fs
cd fs
cp ../fs.cpio ./fs.cpio
cpio -idmv < fs.cpio
rm fs.cpio

cd ..
cp ../scripts/getfunc.py getfunc.py
cp ../scripts/exp.c exp.c
cp ../scripts/gdb_kernel.sh gdb_kernel.sh
cat ../scripts/pack.sh $1 > boot.sh
vmlinux-to-elf bzImage vmlinux

