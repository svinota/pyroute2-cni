package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"net"
	"time"
	"syscall"
	"golang.org/x/sys/unix"
)

const socketPathMain = "/var/run/pyroute2/main"
const socketPathResponse = "/var/run/pyroute2/response"
const lockFile = "/var/run/pyroute2/plugin-lock"

type RequestPayload struct {
	CNI map[string]interface{} `json:"cni"`
	Env map[string]string      `json:"env"`
}

type PluginResponse struct {
	CNIVersion string `json:"cniVersion"`
	IPs        []struct {
		Version string `json:"version"`
		Address string `json:"address"`
	} `json:"ips"`
}

func forwardRequestToServer(input []byte, nameSpaceFD int) ([]byte, error) {
	sock, err := net.Dial("unixgram", socketPathMain)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to UNIX socket: %w", err)
	}
	defer sock.Close()

	unixSock, err := sock.(*net.UnixConn).File()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw socket descriptor: %w", err)
	}
	defer unixSock.Close()

	var rights []byte
	if nameSpaceFD > 0 {
		rights = syscall.UnixRights(nameSpaceFD)
	}

	err = unix.Sendmsg(int(unixSock.Fd()), input, rights, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}
	// 8<------------------------------------------------------------------

	streamSock, err := net.Dial("unix", socketPathResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to UNIX socket: %w", err)
	}
	defer streamSock.Close()

	buffer := make([]byte, 4096)
	n, err := streamSock.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	return buffer[:n], nil
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	flock, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open lock file: %v\n", err)
		os.Exit(1)
	}
	defer flock.Close()

	for {
		err := syscall.Flock(int(flock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	var cniData map[string]interface{}
	if err := json.Unmarshal(input, &cniData); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse stdin JSON: %v\n", err)
		os.Exit(1)
	}

	env := make(map[string]string)
	var nameSpace *os.File
	nameSpaceFD := -1
	for _, e := range os.Environ() {
		parts := bytes.SplitN([]byte(e), []byte("="), 2)
		if len(parts) == 2 {
			env[string(parts[0])] = string(parts[1])
			if string(parts[0]) == "CNI_NETNS" {
				nameSpace, err = os.Open(string(parts[1]))
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to open netns: %v\n", err)
				}
				nameSpaceFD = int(nameSpace.Fd())
				defer nameSpace.Close()
			}
		}
	}

	if nameSpaceFD == -1 {
		fmt.Fprintf(os.Stderr, "no CNI_NETNS received\n")
	}

	payload := RequestPayload{
		CNI: cniData,
		Env: env,
	}

	payloadBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize payload: %v\n", err)
		os.Exit(1)
	}

	// responseBody, err := sendToHTTPServer(payloadBytes)
	responseBody, err := forwardRequestToServer(payloadBytes, nameSpaceFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send to HTTP server: %v\n", err)
		os.Exit(1)
	}

	var response PluginResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode server response: %v\n", err)
		os.Exit(1)
	}

	output, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode response: %v\n", err)
		os.Exit(1)
	}
	syscall.Flock(int(flock.Fd()), syscall.LOCK_UN)
	fmt.Println(string(output))
}
