// contained: A simple Docker service for running files in a container.

// (c) Copyright Nicko van Someren, 2024
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types/container"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/mattn/go-shellwords"
)

type Output struct {
	Stream    string  `json:"stream"`
	TimeSince float64 `json:"ts"`
	Line      string  `json:"text"`
}

type OutputJSON struct {
	Outputs  []Output `json:"outputs"`
	ExitCode int      `json:"exitCode"`
	Errors   []string `json:"errors"`
}

// DockerJob represents a job for the Docker executor.

type JobFileItem struct {
	Name string `json:"name" valid:"required"`
	Text string `json:"text" valid:"required"`
}

type DockerJob struct {
	Files []JobFileItem `json:"files" valid:"required"`
	Args  []string      `json:"args"`
}

var tempMountDir string
var tempMountVolume string
var dockerImageName string
var commandPrefix []string
var runAsUser int
var runAsGroup int

//  Why doesn't Go have a ternary operator?

func If[T any](cond bool, trueValue, falseValue T) T {
	if cond {
		return trueValue
	}
	return falseValue
}

func findMount(targetPath string) (string, error) {
	fh, err := os.Open("/etc/hostname")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = fh.Close()
	}()

	text, err := io.ReadAll(fh)
	if err != nil {
		return "", err
	}

	containerID := strings.TrimSpace(string(text))

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = cli.Close()
	}()

	containerInfo, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return "", err
	}

	for _, mountInfo := range containerInfo.Mounts {
		if mountInfo.Destination == targetPath {
			if mountInfo.Type == "bind" {
				return mountInfo.Source, nil
			} else if mountInfo.Type == "volume" {
				volumeInfo, err := cli.VolumeInspect(context.Background(), mountInfo.Name)
				if err != nil {
					return "", err
				}
				dir, _ := filepath.Split(volumeInfo.Mountpoint)
				dir = filepath.Clean(dir)
				_, endDir := filepath.Split(dir)
				return endDir, nil
			} else {
				return "", errors.New("mountInfo must be of type 'bind' or 'volume'")
			}
		}
	}

	return "", errors.New("mountInfo directory not found")
}

func runDocker(imageName string, files []JobFileItem, timeout int, args []string) (OutputJSON, error) {
	var outputs []Output
	var errorStack []string
	var err error = nil
	rc := -1

	{
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return OutputJSON{outputs, rc, []string{err.Error()}}, err
		}
		defer func() {
			_ = cli.Close()
		}()

		tmpDir, err := os.MkdirTemp(tempMountDir, "tmp")
		if err != nil {
			goto DONE
		}
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()

		tempRelPath, _ := filepath.Rel(tempMountDir, tmpDir)

		for itemIndex := range files {
			item := files[itemIndex]
			name := filepath.Clean(item.Name)
			if name[:2] == ".." {
				err = errors.New("invalid file path")
			}
			err = os.WriteFile(filepath.Join(tmpDir, name), []byte(item.Text), 0644)
			if err != nil {
				goto DONE
			}
		}

		err = filepath.Walk(tmpDir, func(filePath string, f os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(filePath, runAsUser, runAsGroup)
		})
		if err != nil {
			goto DONE
		}

		containerConfig := &container.Config{
			Image:      imageName,
			Cmd:        args,
			Tty:        false,
			WorkingDir: "/workdir",
			User:       strconv.Itoa(runAsUser) + ":" + strconv.Itoa(runAsGroup),
		}
		hostConfig := &container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeVolume,
					Source: tempMountVolume,
					Target: "/workdir",
					VolumeOptions: &mount.VolumeOptions{
						NoCopy:  true,
						Subpath: tempRelPath,
					},
				},
			},
		}

		resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, &network.NetworkingConfig{}, nil, "")
		if err != nil {
			return OutputJSON{outputs, rc, []string{err.Error()}}, err
		}

		defer func() {
			_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		}()

		startTime := time.Now()

		if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
			return OutputJSON{outputs, rc, []string{err.Error()}}, err
		}

		outReader, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true})
		if err != nil {
			return OutputJSON{outputs, rc, []string{err.Error()}}, err
		}
		defer func() {
			_ = outReader.Close()
		}()

		wg := sync.WaitGroup{}
		wg.Add(1)
		var readerErr error

		go func() {
			buf := make([]byte, 8)
			for {
				_, err := io.ReadFull(outReader, buf)
				if err != nil && err != io.EOF {
					readerErr = err
					return
				}

				if err == io.EOF {
					break
				}

				header := binary.BigEndian.Uint64(buf)
				length := header & 0xFFFFFFFF
				isStdErr := (header >> 56) == 2
				now := time.Now()
				elapsed := now.Sub(startTime)

				data := make([]byte, length)
				_, err = io.ReadFull(outReader, data)
				if err != nil {
					readerErr = err
					return
				}

				output := Output{
					Stream:    If(isStdErr, "err", "out"),
					TimeSince: elapsed.Seconds(),
					Line:      string(data),
				}
				outputs = append(outputs, output)
			}

			wg.Done()
		}()

		completionWaiter, errorWaiter := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)

		select {
		case <-time.After(time.Duration(timeout) * time.Second):
			errorStack = append(errorStack, "Process timed out")
			_ = cli.ContainerKill(ctx, resp.ID, "SIGKILL")

		case response := <-completionWaiter:
			rc = int(response.StatusCode)

		case err = <-errorWaiter:
			if err != nil {
				errorStack = append(errorStack, err.Error())
			}
		}

		wg.Wait()

		if readerErr != nil {
			errorStack = append(errorStack, readerErr.Error())
		}

		inspect, err := cli.ContainerInspect(ctx, resp.ID)
		if err != nil {
			errorStack = append(errorStack, err.Error())
		} else {
			rc = inspect.State.ExitCode
		}
	}

DONE:
	if err != nil {
		errorStack = append(errorStack, err.Error())
	}

	return OutputJSON{outputs, rc, errorStack}, err
}

func DockerJobHandler(w http.ResponseWriter, r *http.Request) {
	var job DockerJob
	var err error

	if r.Method != "POST" {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&job)
	if err == nil {
		_, err = govalidator.ValidateStruct(job)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Default to the name of the first file if no arguments are given
	args := job.Args
	if len(args) == 0 {
		firstFileName := job.Files[0].Name
		args = append(args, firstFileName)
	}
	args = append(commandPrefix, args...)

	result, err := runDocker(dockerImageName, job.Files, 30, args)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	_ = json.NewEncoder(w).Encode(result)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	var err error
	http.HandleFunc("/", DockerJobHandler)

	port := getEnv("SERVICE_PORT", "8080")
	dockerImageName = getEnv("DOCKER_IMAGE", "python:alpine")
	commandPrefixString := getEnv("COMMAND_PREFIX", "python")
	tempMountDir = "/uploads"
	runAsUserString := getEnv("CONTAINED_USER", "65534")

	runUserParts := strings.Split(runAsUserString, ":")

	partCount := len(runUserParts)
	if partCount < 1 || partCount > 2 {
		log.Fatalf("Invalid container user: %s", runUserParts)
	}

	runAsUser, err = strconv.Atoi(runUserParts[0])
	if err != nil || runAsUser < 0 || runAsUser > 65534 {
		log.Fatalf("User ID must be a valid number: %v", err)
	}
	if partCount == 2 {
		runAsGroup, err = strconv.Atoi(runUserParts[1])
		if err != nil || runAsGroup < 0 || runAsGroup > 65534 {
			log.Fatalf("Group ID must be a valid number: %v", err)
		}
	} else {
		runAsGroup = runAsUser
	}

	commandPrefix, err = shellwords.Parse(commandPrefixString)
	if err != nil {
		log.Fatalf("Malformed command prefix: %v", err)
	}

	tempMountVolume, err = findMount(tempMountDir)
	if err != nil {
		log.Fatalf("Failed to find mount: %v", err)
	}

	_, err = strconv.Atoi(port) // add this line to validate port is a valid integer.
	if err != nil {
		log.Fatalf("Invalid Port Number")
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
