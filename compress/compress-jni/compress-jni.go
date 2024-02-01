package main

import "C"
import (
	"os"
	"sync"
	"unsafe"

	"github.com/consensys/compress/lzss"
)

var (
	compressor *lzss.Compressor
	lastError  error      // last error that occurred
	lock       sync.Mutex // for the moment, we only allow one compression at a time
)

const compressionLevel = lzss.BestCompression

// Init initializes the compressor.
// Returns true if the compressor was initialized, false otherwise.
// If false is returned, the Error() method will return a string describing the error.
//
//export Init
func Init(dictPath *C.char) bool {
	fPath := C.GoString(dictPath)
	return initGo(fPath)
}

func initGo(dictPath string) bool {
	lock.Lock()
	defer lock.Unlock()

	// read the dictionary
	dict, err := os.ReadFile(dictPath)
	if err != nil {
		lastError = err
		return false
	}

	compressor, lastError = lzss.NewCompressor(dict, compressionLevel)

	return lastError == nil
}

// Compress compresses the input and returns the length of the compressed data.
// If an error occurred, returns -1.
// User must call Error() to get the error message.
//
//export CompressedSize
func CompressedSize(input *C.char, inputLength C.int) C.int {
	inputSlice := C.GoBytes(unsafe.Pointer(input), inputLength)
	lock.Lock()
	defer lock.Unlock()
	if lastError != nil {
		return -1
	}

	// TODO future version of consensys/compress should export
	// a more efficient method (threadsafe + no need to actually write the result to estimate the size.)
	c, err := compressor.Compress(inputSlice)
	if err != nil {
		lastError = err
		return -1
	}

	return C.int(len(c))
}

// Error returns the last encountered error.
// If no error was encountered, returns nil.
//
//export Error
func Error() *C.char {
	lock.Lock()
	defer lock.Unlock()
	if lastError != nil {
		// this leaks memory, but since this represents a fatal error, it's probably ok.
		return C.CString(lastError.Error())
	}
	return nil
}

func main() {}
