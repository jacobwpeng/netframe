package netframe

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jacobwpeng/goutil"
)

const (
	MAGIC         = 0xdead9001
	MAX_SIZE      = 65536
	HEADER_SIZE   = 104
	MAX_BODY_SIZE = MAX_SIZE - HEADER_SIZE
)

type Frame struct {
	Magic    uint32
	Cmd      uint32
	Ctx      uint64
	Uid      uint64
	ErrCode  int32
	BodySize uint32
	Reserved [4]uint32
	Body     []byte
}

func New() *Frame {
	return &Frame{
		Magic: MAGIC,
	}
}

func (f *Frame) ReadFrom(reader io.Reader) (int64, error) {
	cr := goutil.NewCountReader(reader)
	sr := goutil.NewStrickyReader(cr)
	binary.Read(reader, binary.LittleEndian, &f.Magic)
	binary.Read(reader, binary.LittleEndian, &f.Cmd)
	binary.Read(reader, binary.LittleEndian, &f.Ctx)
	binary.Read(reader, binary.LittleEndian, &f.Uid)
	binary.Read(reader, binary.LittleEndian, &f.ErrCode)
	binary.Read(reader, binary.LittleEndian, &f.BodySize)
	binary.Read(reader, binary.LittleEndian, &f.Reserved)
	binary.Read(reader, binary.LittleEndian, &f.BodySize)
	if sr.Err != nil {
		return cr.Count(), sr.Err
	}
	if err := f.checkHeader(); err != nil {
		return cr.Count(), err
	}
	f.Body = make([]byte, f.BodySize)
	sr.Read(f.Body)
	return cr.Count(), sr.Err
}

func (f *Frame) WriteTo(w io.Writer) (n int64, err error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	cw := goutil.NewCountWriter(w)
	sw := goutil.NewStrickyWriter(cw)
	binary.Write(sw, binary.LittleEndian, f.Magic)
	binary.Write(sw, binary.LittleEndian, f.Cmd)
	binary.Write(sw, binary.LittleEndian, f.Ctx)
	binary.Write(sw, binary.LittleEndian, f.Uid)
	binary.Write(sw, binary.LittleEndian, f.ErrCode)
	binary.Write(sw, binary.LittleEndian, f.BodySize)
	binary.Write(sw, binary.LittleEndian, f.Reserved)
	binary.Write(sw, binary.LittleEndian, f.BodySize)
	sw.Write(f.Body[:f.BodySize])
	return cw.Count(), sw.Err
}

func (f *Frame) checkHeader() error {
	if f.Magic != MAGIC {
		return fmt.Errorf("Expect magic %d, got %d", MAGIC, f.Magic)
	}
	if f.BodySize > MAX_BODY_SIZE {
		return fmt.Errorf("Max body size %d, got %d", MAX_BODY_SIZE, f.BodySize)
	}
	return nil
}

func (f *Frame) check() error {
	if err := f.checkHeader(); err != nil {
		return err
	}
	if int(f.BodySize) > len(f.Body) {
		return fmt.Errorf("BodySize %d is large than len(Body) %d",
			f.BodySize, len(f.Body))
	}
	return nil
}
