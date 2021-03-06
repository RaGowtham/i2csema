/* Driver for ADLINK SMBUS or I2C connected Board management controllers (BMC) devices */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/i2c.h>
#include <linux/mfd/core.h>
#include "adl-bmc.h"

#define	CAPABILITY_BYTE_UNIT	4
#define	ONE_BYTE		1
#define	ZERO_BYTE		0
#define	MAX_BUFFER_SIZE		32
#define	CAPABILITY_INDEX( COUNT )	( unsigned char )( COUNT - 1 )
#define	SHIFT( NUMBER )			( unsigned char )NUMBER
#define	SHIFT_INDEX( DATA_COUNT )	( unsigned char )( 4 - ( DATA_COUNT % 4 ? DATA_COUNT % 4 : 4 ) )

static struct adl_bmc_dev *adl_bmc_dev;

static const struct mfd_cell adl_bmc_devs[] = {
        {
                .name = "adl-bmc-wdt",
        },

        {
                .name = "adl-bmc-boardinfo",
        },
	{ 
		.name = "adl-bmc-nvmem",
	},
	{ 
		.name = "adl-bmc-bklight",
		//low priority 
	},
	{ 
		.name = "adl-bmc-vm",
	},
	{ 
		.name = "adl-bmc-hwmon",
	},
	{
		.name = "adl-bmc-i2c",
	},
};

void CollectCapabilities(unsigned int *Capabilities, unsigned DataCount, unsigned char *SMBusDatas)
{
	unsigned char	ShiftNumbers[] = { SHIFT( 24 ), SHIFT( 16 ), SHIFT( 8 ), SHIFT( 0 ) };
	unsigned	CapabilityCount = DataCount / CAPABILITY_BYTE_UNIT + ( DataCount % CAPABILITY_BYTE_UNIT ? ONE_BYTE : ZERO_BYTE );
	unsigned	RemainderData = DataCount;
	unsigned	Loop, Loop1;
	unsigned	CapabilityIndex = CAPABILITY_INDEX( CapabilityCount ), ShiftIndex = SHIFT_INDEX( DataCount ), DataIndex = 0;
	if( !CapabilityCount || DataCount > MAX_BUFFER_SIZE )
		return;

	for( Loop = 0 ; Loop < CapabilityCount ; ++Loop, --CapabilityIndex )
	{ // Collect all
		unsigned	CheckDataCount = RemainderData % CAPABILITY_BYTE_UNIT;
		unsigned	CombineData = CheckDataCount ? CheckDataCount : CAPABILITY_BYTE_UNIT;
		RemainderData -= CombineData;
		for( Loop1 = 0 ; Loop1 < CombineData ; ++Loop1, ++DataIndex )
		{ // Combine all
			*( Capabilities + CapabilityIndex ) |= ((unsigned int)(*( SMBusDatas + DataIndex )) << (*( ShiftNumbers + ShiftIndex )));
			ShiftIndex = (unsigned char)( (ShiftIndex + 1) % 4);
		} // Combine all
	} // Collect all

}
EXPORT_SYMBOL_GPL (CollectCapabilities);



int adl_bmc_i2c_read_device(struct adl_bmc_dev *adl_bmc, char reg,
                                  int bytes, void *dest)
{
        struct i2c_client *i2c = (adl_bmc == NULL) ? adl_bmc_dev->i2c_client : adl_bmc->i2c_client;
        int ret;
	printk("==> %s \n", __func__); 

	ret = i2c_smbus_read_block_data(i2c, reg, dest);
	if (ret < 0)
		printk("return value is  %d\n", ret);

	printk("<== %s \n", __func__); 

        return ret;
}

EXPORT_SYMBOL_GPL (adl_bmc_i2c_read_device);

int adl_bmc_i2c_write_device(struct adl_bmc_dev *adl_bmc, int reg,
                                   int bytes, void *src)
{
        struct i2c_client *i2c = (adl_bmc == NULL) ? adl_bmc_dev->i2c_client : adl_bmc->i2c_client;
        int ret;

	printk("==> %s \n", __func__); 

	ret = i2c_smbus_write_block_data(i2c, reg, bytes , src);
	if (ret < 0)
		printk("return value is  %d\n", ret);

	printk("<== %s \n", __func__); 

        return ret;
}

EXPORT_SYMBOL_GPL (adl_bmc_i2c_write_device);

/* List of possible BMC addresses in ADLINK */
static const unsigned short bmc_address_list[] = { 0x28, I2C_CLIENT_END };

static int adl_bmc_detect ( struct i2c_client *client, int kind, struct i2c_board_info *info) 
{

	struct i2c_adapter *adapter = client->adapter;
	int man_id;
	printk("==> %s \n", __func__); 

	printk("Detect of device address %x \n", client->addr); 

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
                //return -ENODEV;
		debug_printk("Weird problems: adapter not supported \n");
	}

	//TODO check if this is a BMC , somehow 
	//i2cdump <bus> 0x28 s 0x31 , first 3 characters are BMC 
	man_id = i2c_smbus_read_byte_data(client, 0x00);
	printk("Manufacturer ID: %x \n", man_id);

	/* This really determines the device is found, and then calls .probe */
	strlcpy(info->type, "adl-bmc", I2C_NAME_SIZE);

	printk("<== %s \n", __func__); 

	return 0;
}

static int adl_bmc_probe ( struct i2c_client *client, const struct i2c_device_id *id) 
{
	unsigned char buf[32]; 
	int ret, i;
	printk("==> %s \n", __func__); 

	printk("Probing...\n");

	adl_bmc_dev = devm_kzalloc(&client->dev, sizeof(struct adl_bmc_dev), GFP_KERNEL);

        if (adl_bmc_dev == NULL)
                return -ENOMEM;

        i2c_set_clientdata(client, adl_bmc_dev);
        adl_bmc_dev->dev = &client->dev;
        adl_bmc_dev->i2c_client = client;

	memset(buf, 0, sizeof(buf));
        ret = i2c_smbus_read_block_data(client, ADL_BMC_CMD_CAPABILITIES, buf);
	if (ret < 0)
		return ret;

	for (i=0; i< 32; i++) {
		debug_printk( "%d-> %x: \n", i, buf[i] );
	}

	CollectCapabilities(adl_bmc_dev->Bmc_Capabilities, ret, buf);

	printk("<== %s \n", __func__); 
	
	return mfd_add_devices(&client->dev, -1, adl_bmc_devs, ARRAY_SIZE(adl_bmc_devs), NULL, 0);
}

static int adl_bmc_remove ( struct i2c_client *client) 
{
	struct adl_bmc_dev *adl_bmc_dev;
	printk("==> %s \n", __func__); 

	printk("remove............\n");

	mfd_remove_devices(&client->dev);
	adl_bmc_dev = i2c_get_clientdata(client);
	kfree(i2c_get_clientdata(client));

	printk("<== %s \n", __func__); 

	return 0;
}

/* Addresses to scan */
static const unsigned short normal_i2c[] = { 0x28, 0x29, I2C_CLIENT_END };

/* Insmod parameters */
I2C_CLIENT_INSMOD_1(adl_bmc);


static const struct i2c_device_id adl_bmc_id[] = {
        { "adl-bmc", adl_bmc },
        { }
};
 
MODULE_DEVICE_TABLE(i2c, adl_bmc_id);


static struct i2c_driver adl_bmc_driver = { 
	.class = I2C_CLASS_HWMON,
	.driver = {
		.name = "adl-bmc",
	}, 
       .probe = adl_bmc_probe,
       .remove = adl_bmc_remove,
       .id_table = adl_bmc_id,
       .detect = adl_bmc_detect,
       .address_data = &addr_data,
};

static int __init adl_bmc_init(void)
{
	printk("==> %s \n", __func__); 
	printk("<== %s \n", __func__); 
	return i2c_add_driver(&adl_bmc_driver);
}

static void __exit adl_bmc_exit(void)
{
	printk("==> %s \n", __func__); 
	printk("<== %s \n", __func__); 
	i2c_del_driver(&adl_bmc_driver);
}

module_init(adl_bmc_init);
module_exit(adl_bmc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adlink ");
MODULE_DESCRIPTION("Board Management Controller driver");
MODULE_VERSION(DRIVER_VERSION);
