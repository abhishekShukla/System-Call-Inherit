make
insmod reg_unreg.ko
cd file_ops_vector
make
insmod file_ops_vector.ko
cd ../link_vector
make
insmod link_vector.ko
cd ../ioctl_module
make
insmod ioctl_module.ko 
mknod /dev/ioctl_device c 121 212
cd ../tests_demo
make
