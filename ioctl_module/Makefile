obj-m += ioctl_module.o

all:  module

module:
	make -C /lib/modules/$(shell uname -r)/build -I/usr/src/hw3-cse506g12/include M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
