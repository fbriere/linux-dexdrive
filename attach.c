#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <string.h>

#define DEX_LDISC N_X25
#define DEX_BAUD  B38400
#define DEX_TIMEOUT 50000
#define DEX_GARBAGE "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

#define DEX_IOC_MAGIC 0xfb
#define DEX_IOCGMAJOR	_IOR(DEX_IOC_MAGIC, 1, sizeof(int))
#define DEX_IOCGMINOR	_IOR(DEX_IOC_MAGIC, 2, sizeof(int))
#define DEX_IOCSMINOR	_IOW(DEX_IOC_MAGIC, 3, sizeof(int))

#define Wrap(x) if((x) < 0) { fflush(stdout); perror(devname); return 1; }

char *devname;

int Read(int fd, char *buf, int count) {
	int i, tmp;
	fd_set set;
	struct timeval timeout;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	i = 0;
	while (i < count) {
		timeout.tv_sec = 0;
		timeout.tv_usec = DEX_TIMEOUT;
		Wrap(tmp = select(fd+1, &set, NULL, NULL, &timeout));
		if (tmp == 0) break;
		Wrap(tmp = read(fd, buf+i, (count - i)));
		i += tmp;
	}

	return i;
}


int setup(int fd, int minor) {
	struct termios newtio;
	int ldisc;
	char buf[5];
	int tmp;

	memset(&newtio, 0, sizeof(newtio));
	newtio.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
	newtio.c_iflag = IGNPAR;
	newtio.c_oflag = 0;
        newtio.c_lflag = 0;

	printf("Setting up tty... ");
	Wrap(cfsetospeed(&newtio, DEX_BAUD));
	Wrap(cfsetispeed(&newtio, DEX_BAUD));
	Wrap(tcflush(fd, TCIOFLUSH));
	Wrap(tcsetattr(fd, TCSANOW, &newtio));
	printf("done\n");

	Wrap(write(fd, DEX_GARBAGE, sizeof(DEX_GARBAGE)));
	tmp = Read(fd, buf, 5);

	if (tmp != 4 || memcmp(buf, "IAI\x021", 4) != 0) {
		fprintf(stderr, "%s: Failed to initialize dexdrive\n", devname);
		return 1;
	}
	
	printf("Setting line discipline... ");
	ldisc = DEX_LDISC;
	Wrap(ioctl(fd, TIOCSETD, &ldisc));
	printf("done\n");

	printf("Setting minor device number... ");
	Wrap(ioctl(fd, DEX_IOCSMINOR, &minor));
	printf("done\n");

	for(;;) {
		sleep(10000);
	}

	return 0;
}

int main(int argc, char **argv) {
	struct termios oldtio;
	int fd;
	int minor;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s minor devicename\n", argv[0]);
		return 1;
	}

	devname = argv[2];
	minor = atoi(argv[1]);

	printf("Opening %s... ", devname);
        Wrap(fd = open(devname, O_RDWR | O_NOCTTY | O_NONBLOCK));
	printf("done\n");

	Wrap(tcgetattr(fd, &oldtio));

	setup(fd, minor);

	printf("Restoring tty settings... ");
	Wrap(tcflush(fd, TCIOFLUSH));
	Wrap(tcsetattr(fd, TCSANOW, &oldtio));
	Wrap(close(fd));
	printf("done\n");

	return 0;
}




