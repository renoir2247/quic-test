package fecexp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// fakePacketConn — минимальная реализация net.PacketConn для тестов.
type fakePacketConn struct {
	out [][]byte
}

func (f *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.out = append(f.out, append([]byte(nil), b...))
	return len(b), nil
}
func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (f *fakePacketConn) Close() error                       { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error         { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error     { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error    { return nil }

// TestInjectorGroupAligned — детерминизм и выравнивание паттерна потерь.
func TestInjectorGroupAligned(t *testing.T) {
	fc := &fakePacketConn{}
	inj := NewLossPacketConn(fc, LossConfig{
		Model: LossGroupAligned, GroupN: 11, GroupM: 1, GroupOff: 2,
		Seed: 1, MinSymbol: 1000,
	})
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	symbol := make([]byte, 1197) // 24+1173
	ack := make([]byte, 64)
	for g := 0; g < 5; g++ {
		for i := 0; i < 10; i++ {
			_, _ = inj.WriteTo(symbol, addr)
		}
		_, _ = inj.WriteTo(symbol, addr) // repair
		_, _ = inj.WriteTo(ack, addr)    // ACK-пакет
	}
	seen, dropped, symSeen, symDropped := inj.Stats()
	if seen != 60 || symSeen != 55 {
		t.Fatalf("seen=%d symSeen=%d, want 60/55", seen, symSeen)
	}
	if dropped != 5 || symDropped != 5 {
		t.Fatalf("dropped=%d symDropped=%d, want 5/5 (по одной потере на группу)", dropped, symDropped)
	}
	if got := len(fc.out); got != 55 {
		t.Fatalf("прошло %d пакетов, want 55", got)
	}
}

// TestAssemblerXORRecovery — восстановление одиночной потери XOR-группой.
func TestAssemblerXORRecovery(t *testing.T) {
	a := NewGroupAssembler(time.Second)
	k, r, sl := 10, 1, 32
	mk := func(typ byte, gid uint64, idx int) []byte {
		f := make([]byte, SymHdrLen+sl)
		EncodeSymbolHeader(f, typ, gid, idx, k, r, time.Now().UnixNano())
		for i := range f[SymHdrLen:] {
			f[SymHdrLen+i] = byte(gid*10 + uint64(idx))
		}
		return f
	}
	const gid = 7
	for i := 0; i < k; i++ {
		if i == 2 {
			continue // потеря
		}
		a.Add(mk(SymTypeData, gid, i), time.Now())
	}
	// корректный repair = XOR всех k data-символов (как строит GroupEncoder)
	repPayload := make([]byte, sl)
	for i := 0; i < k; i++ {
		s := mk(SymTypeData, gid, i)
		for j := range repPayload {
			repPayload[j] ^= s[SymHdrLen+j]
		}
	}
	repFrame := make([]byte, SymHdrLen+sl)
	EncodeSymbolHeader(repFrame, SymTypeRep, gid, 0, k, r, time.Now().UnixNano())
	copy(repFrame[SymHdrLen:], repPayload)
	rec := a.Add(repFrame, time.Now())
	if len(rec) != 1 {
		t.Fatalf("восстановлено %d символов, want 1", len(rec))
	}
	want := mk(SymTypeData, gid, 2)
	if !bytes.Equal(rec[0], want[SymHdrLen:]) {
		t.Fatal("восстановленный payload не совпал с потерянным")
	}
	rc, un, gr := a.Stats()
	if rc != 1 || un != 0 || gr != 1 {
		t.Fatalf("stats recovered=%d unrecovered=%d groups=%d, want 1/0/1", rc, un, gr)
	}
}

// TestAssemblerRSRecovery — восстановление двух потерь RS(12,10).
func TestAssemblerRSRecovery(t *testing.T) {
	a := NewGroupAssembler(time.Second)
	k, r, sl := 10, 2, 64
	mk := func(typ byte, gid uint64, idx int) []byte {
		f := make([]byte, SymHdrLen+sl)
		EncodeSymbolHeader(f, typ, gid, idx, k, r, time.Now().UnixNano())
		for i := range f[SymHdrLen:] {
			f[SymHdrLen+i] = byte(gid*7 + uint64(idx) + uint64(i)%13)
		}
		return f
	}
	const gid = 3
	for i := 0; i < k; i++ {
		if i == 1 || i == 6 {
			continue // две потери
		}
		a.Add(mk(SymTypeData, gid, i), time.Now())
	}
	var rec [][]byte
	for ri := 0; ri < r; ri++ {
		rec = append(rec, a.Add(mk(SymTypeRep, gid, ri), time.Now())...)
	}
	if len(rec) != 2 {
		t.Fatalf("восстановлено %d, want 2", len(rec))
	}
	rc, un, gr := a.Stats()
	if rc != 2 || un != 0 || gr != 1 {
		t.Fatalf("stats=%d/%d/%d, want 2/0/1", rc, un, gr)
	}
}
