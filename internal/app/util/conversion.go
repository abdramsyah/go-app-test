package util

import (
	"bytes"
	"encoding/binary"
	"math"
)

func Float64frombytes(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	float := math.Float64frombits(bits)
	return float
}

func Float64ToByte(f float64) (byDate []byte, err error) {
	var buf bytes.Buffer
	err = binary.Write(&buf, binary.LittleEndian, f)
	if err != nil {
		return
	}
	byDate = buf.Bytes()
	return
}
