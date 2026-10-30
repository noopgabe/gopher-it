//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package trace

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// structure the ifreq on BSDs. 16 byte for a name and 16 byte for the address union
const bpfIfreqSize = 32

// openFreeBPF returns the first open /dev/bpfX device that isn't busy
func openFreeBPF() (int, error) { // i dont know wtf im doing with this. i hate BSDeez
	var last error
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		last = err
		if err == unix.EACCES {
			return -1, fmt.Errorf("Opening /dev/bpf: permission denied. Try running with --sudo.")
		}
		if err == unix.ENOENT {
			break
		}
	}
	return -1, fmt.Errorf("No free /dev/bpf device: %w", last)
}

func bpfIoctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

func bpfSetUint(fd int, req uint, v uint32) error {
	return bpfIoctl(fd, req, unsafe.Pointer(&v))
}

func bpfGetUint(fd int, req uint) (uint32, error) {
	var v uint32
	err := bpfIoctl(fd, req, unsafe.Pointer(&v))
	return v, err
}

// openBPF opens a BPF device bound to iface ready to read or write frames
func openBPF(iface string) (int, layers.LinkType, error) {
	if len(iface) == 0 || len(iface) >= 16 {
		return -1, 0, fmt.Errorf("Bad interface name: %q", iface)
	}
	fd, err := openFreeBPF()
	if err != nil {
		return -1, 0, err
	}
	fail := func(err error) (int, layers.LinkType, error) {
		unix.Close(fd)
		return -1, 0, err
	}
	// buffer size HAS to be et before BIOCSETIF
	if err := bpfSetUint(fd, unix.BIOCSBLEN, 1<<20); err != nil {
		return fail(fmt.Errorf("BIOCSBLEN: %w", err))
	}
	var ifr [bpfIfreqSize]byte
	copy(ifr[:], iface)
	if err := bpfIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); err != nil {
		return fail(fmt.Errorf("BIOCSETIF %s: %w", iface, err))
	}
	if err := bpfSetUint(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fail(fmt.Errorf("BIOCIMMEDIATE: %w", err))
	}
	// we supply the link layer header on write so the kernel musn't rewrite it
	if err := bpfSetUint(fd, unix.BIOCSHDRCMPLT, 1); err != nil { // this is just gibberish
		return fail(fmt.Errorf("BIOCSHDRCMPLT: %w", err))
	}
	dlt, err := bpfGetUint(fd, unix.BIOCGDLT)
	if err != nil {
		return fail(fmt.Errorf("BIOCGDLT: %w", err))
	}
	return fd, dltToLinkType(dlt), nil
}

func dltToLinkType(dlt uint32) layers.LinkType {
	switch dlt {
	case 1:
		return layers.LinkTypeEthernet // DLT_EN10MB
	case 0:
		return layers.LinkTypeNull // DLT_NULL
	case 12:
		return layers.LinkTypeRaw // take a hint
	}
	return layers.LinkType(dlt)
}

// bpfEach walks one read() buffer i think
// each record is bpf_hdr + captured bytes
// layout assumes 64-bit little endian where
// the struct timeval is 16 bytes
func bpfEach(buf []byte, fn func(ts time.Time, frame []byte)) {
	const word = 8
	for off := 0; off+26 <= len(buf); {
		sec := int64(binary.LittleEndian.Uint64(buf[off:]))
		usec := int64(binary.LittleEndian.Uint64(buf[off+8:]))
		caplen := int(binary.LittleEndian.Uint32(buf[off+16:]))
		hdrlen := int(binary.LittleEndian.Uint16(buf[off+24:]))
		start := off + hdrlen
		if hdrlen == 0 || start+caplen > len(buf) {
			return // i HATE intellisense. why is that when i type return it suggests unix.ATTR_CMN_RETURNED_ATTRS
		} // and when i need to go to a new line i hit enter and it autocompletes WHEN I DONT WANT IT
		fn(time.Unix(sec, usec*1000), buf[start:start+caplen])
		off += (hdrlen + caplen + word - 1) &^ (word - 1)
	}
}
