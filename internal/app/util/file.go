package util

import (
	"fmt"
	"github.com/pkg/sftp"
	"io"
	"os"
)

func FormatSizeUnits(bytes int64) (size string) {
	if bytes >= 1073741824 {
		gb := bytes / 1073741824
		size = fmt.Sprintf("%d GB", gb)
	} else if bytes >= 1048576 {
		mb := bytes / 1048576
		size = fmt.Sprintf("%d MB", mb)
	} else if bytes >= 1024 {
		kb := bytes / 1024
		size = fmt.Sprintf("%d KB", kb)
	} else if bytes > 1 {
		size = fmt.Sprintf("%d bytes", bytes)
	} else if bytes == 1 {
		size = fmt.Sprintf("%d byte", bytes)
	} else {
		size = "0 bytes"
	}

	return
}

func CreateDirectoryIfNotExist(path string) (err error) {
	err = os.MkdirAll(path, os.ModePerm)
	return
}

func SftpMkdir(path string, client *sftp.Client) (err error) {
	if err = client.Mkdir(path); err != nil {
		// Do not consider it an error if the directory existed
		remoteFi, fiErr := client.Lstat(path)
		if fiErr != nil || !remoteFi.IsDir() {
			return
		}
	}
	if err = client.Chmod(path, os.ModePerm); err != nil {
		return
	}
	return
}

func SftpUploadFile(client *sftp.Client, localFile, remoteFile string) (err error) {
	// create destination file
	dstFile, err := client.Create(remoteFile)
	if err != nil {
		return
	}
	defer dstFile.Close()

	// create source file
	srcFile, err := os.Open(localFile)
	if err != nil {
		return
	}
	defer srcFile.Close()

	// copy source file to destination file
	_, err = io.Copy(dstFile, srcFile)

	return
}

func MoveFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't open source file: %s", err)
	}
	outputFile, err := os.Create(destPath)
	if err != nil {
		inputFile.Close()
		return fmt.Errorf("Couldn't open dest file: %s", err)
	}
	defer outputFile.Close()
	_, err = io.Copy(outputFile, inputFile)
	inputFile.Close()
	if err != nil {
		return fmt.Errorf("Writing to output file failed: %s", err)
	}
	// The copy was successful, so now delete the original file
	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("Failed removing original file: %s", err)
	}
	return nil
}
