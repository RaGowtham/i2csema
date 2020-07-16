echo ---------------------------------------
echo "board-information"
echo ---------------------------------------

echo manufacturer_name
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/manufacturer_name
echo board_name
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/board_name
echo serial_number
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/serial_number
echo bios_version
cat /sys/class/dmi/id/bios_version
echo bmc_boot_version
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/bmc_boot_version
echo mac_address
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/mac_address
echo manufactured_date
cat /sys/bus/platform/devices/adl-bmc-boardinfo/information/manufactured_date

echo ***************************************

echo ---------------------------------------
echo backlight
echo ---------------------------------------

echo bl_power
cat /sys/class/backlight/adl-bmc-bklight/bl_power
echo actual_brightness
cat /sys/class/backlight/adl-bmc-bklight/actual_brightness
echo brightness
cat /sys/class/backlight/adl-bmc-bklight/brightness

echo ***************************************

echo ---------------------------------------
echo hw_monitor
echo ---------------------------------------

echo sys1_min_temp
cat /sys/class/hwmon/hwmon2/device/sys1_min_temp

echo ***************************************

echo ---------------------------------------
echo vm
echo ---------------------------------------

for i in `ls /sys/class/regulator/`
do 
	cat /sys/class/regulator/$i/name
	cat /sys/class/regulator/$i/microvolts
done
