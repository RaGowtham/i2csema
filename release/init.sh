cp lib/libsema.so /usr/lib64
cp app/* /usr/bin

insmod modules/i2c-i801.ko
insmod modules/mfd-core.ko
insmod modules/nvmem-core.ko

insmod modules/adl-bmc.ko

for m in `ls modules/adl-bmc-*`
do
	insmod $m
done
