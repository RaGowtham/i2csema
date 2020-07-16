rm /usr/lib64/libsema.so
rm /usr/bin/semautil /usr/bin/wdogtest

for m in `ls modules/adl-bmc-*`
do
	rmmod `echo $m | cut -d'/' -f 2 | cut -d'.' -f 1`
done

rmmod modules/adl-bmc.ko

rmmod modules/mfd-core
rmmod modules/nvmem-core
rmmod modules/i2c-i801
