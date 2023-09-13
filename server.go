package main

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/hemanthmalla/reuseport_ebpf/compile"
	"github.com/prometheus/procfs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

func loadReuseportSelect(s *zap.SugaredLogger) *ebpf.Program {
	stateDir := "/sys/fs/bpf/tc/globals"
	collectionLocation := "./bpf/"

	if _, err := os.Stat(filepath.Join("./bpf/", "reuseport_select.o")); err != nil {
		if err := compile.CompileWithOptions(context.TODO(), "./bpf/reuseport_select.c", "./bpf/reuseport_select.o", []string{"-v", "-I", "./bpf/", "-I", "./bpf/include/"}); err != nil {
			s.Errorf("failed to compile bpf_reuseport_select.c %w", err)
		} else {
			s.Info("Compiled bpf_reuseport_select.o successfully !")
		}
	}
	var prog *ebpf.Program
	var coll *ebpf.Collection

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: stateDir,
		},
		Programs: ebpf.ProgramOptions{
			LogDisabled: false,
			LogSize:     ebpf.DefaultVerifierLogSize,
			LogLevel:    ebpf.LogLevelInstruction,
		},
	}

	spec, err := ebpf.LoadCollectionSpec(filepath.Join(collectionLocation, "reuseport_select.o"))
	if err != nil {
		s.Errorf("Unable to load at %s: %w", filepath.Join(collectionLocation, "reuseport_select.o"), err)
		return nil
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			s.Errorf("failed to create eBPF collection: %w", err)
			return nil
		}
		prog = coll.Programs["hot_standby_selector"]
		if prog == nil {
			s.Error("program not found in collection\n")
			return nil
		}
	}
	return prog
}

func getListenConfig(prog *ebpf.Program, mode string, otherInstancesRunning bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// Set SO_REUSEPORT on the socket
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// Set eBPF program to be invoked for socket selection
			if prog != nil && mode == "primary" && !otherInstancesRunning {
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					opErr = fmt.Errorf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %w", err)
				} else {
					zap.S().Info("SO_REUSEPORT bpf prog attach completed successfully")
				}
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}}
	return lc
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	zap.S().Info("got /hello request\n")
	io.WriteString(w, fmt.Sprintf("Hello eBPF Summit 2023 - %s!\n", os.Args[1]))
}

// GetFdFromListener get net.Listener's file descriptor.
func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func main() {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig = zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "level",
		TimeKey:        "time",
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller: func(caller zapcore.EntryCaller, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString("")
		}}
	logger, _ := cfg.Build()
	s := logger.Sugar()
	mode := os.Args[1]
	if mode != "primary" && mode != "standby" {
		s.Infof("Server mode should either be primary or standy")
		return
	}
	s.Infof("Starting server in %s mode", mode)
	prog := loadReuseportSelect(s)

	http.HandleFunc("/hello", handleHello)
	server := http.Server{Addr: "127.0.0.1:8080", Handler: nil}
	fs, _ := procfs.NewDefaultFS()
	netTCP, _ := fs.NetTCP()

	otherInstancesRunning := false
	for _, i := range netTCP {
		if i.LocalPort == 8080 {
			otherInstancesRunning = true
			break
		}
	}

	lc := getListenConfig(prog, mode, otherInstancesRunning)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		s.Fatalf("Unable to listen of specified addr %w", err)
	} else {
		s.Infof("Started listening in 127.0.0.1:8080 successfully !")
	}

	stateDir := "/sys/fs/bpf/tc/globals"
	mapName := "tcp_balancing_targets"

	var k uint32
	if mode == "primary" {
		k = uint32(0)
	} else {
		k = uint32(1)
	}
	v := uint64(GetFdFromListener(ln))
	s.Infof("Updating with k=%d v=%d", k, v)
	m, err := ebpf.LoadPinnedMap(filepath.Join(stateDir, mapName), nil)
	if err != nil {
		s.Errorf("Unable to load map at %s : %w", filepath.Join(stateDir, mapName), err)
	} else {
		err = m.Put(k, v)
		if err != nil {
			s.Errorf("Map update for %s failed : %w", mapName, err)
		} else {
			s.Infof("Map update for %s succeeded", mapName)
		}
	}

	err = server.Serve(ln)
	if err != nil {
		s.Fatalf("Unable to start HTTP server %w", err)
	}
}
