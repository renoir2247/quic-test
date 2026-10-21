// rscodec.go — FEC-кодек fecexp: RS(n,k) над GF(2^8) [klauspost/reedsolomon]
// и XOR-базлайн (r=1, эквивалент схемы исходного отчёта quic-test).
//
// Фрейм символа fecexp (24 байта заголовка + payload фиксированной длины):
//
//	[0]     0xFD (магия fecexp)
//	[1]     тип: 0x01 data | 0x02 repair
//	[2:10]  groupID LE64
//	[10]    symbolIndex (0..k-1 data; 0..r-1 repair)
//	[11]    k
//	[12]    r
//	[13:21] sendT unix-nano LE64 (для односторонних задержек)
//	[21:24] reserved
package fecexp

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	SymMagic    = 0xFD
	SymTypeData = 0x01
	SymTypeRep  = 0x02
	SymHdrLen   = 24
)

// Codec — тип кодека.
type Codec string

const (
	CodecXOR Codec = "xor" // 1 repair-символ = XOR группы (базлайн отчёта)
	CodecRS  Codec = "rs"  // Рид–Соломон, r repair-символов
)

// EncodeSymbolHeader строит заголовок символа.
func EncodeSymbolHeader(dst []byte, typ byte, groupID uint64, symIdx, k, r int, sendT int64) {
	dst[0] = SymMagic
	dst[1] = typ
	binary.LittleEndian.PutUint64(dst[2:10], groupID)
	dst[10] = byte(symIdx)
	dst[11] = byte(k)
	dst[12] = byte(r)
	binary.LittleEndian.PutUint64(dst[13:21], uint64(sendT))
	dst[21], dst[22], dst[23] = 0, 0, 0
}

// SymbolHeader — разобранный заголовок.
type SymbolHeader struct {
	IsRepair bool
	GroupID  uint64
	SymIdx   int
	K        int
	R        int
	SendT    int64
}

// ParseSymbolHeader разбирает заголовок; ok=false если это не символ fecexp.
func ParseSymbolHeader(b []byte) (SymbolHeader, bool) {
	var h SymbolHeader
	if len(b) < SymHdrLen || b[0] != SymMagic || (b[1] != SymTypeData && b[1] != SymTypeRep) {
		return h, false
	}
	h.IsRepair = b[1] == SymTypeRep
	h.GroupID = binary.LittleEndian.Uint64(b[2:10])
	h.SymIdx = int(b[10])
	h.K = int(b[11])
	h.R = int(b[12])
	h.SendT = int64(binary.LittleEndian.Uint64(b[13:21]))
	return h, true
}

// GroupEncoder — кодирует группы данных в repair-символы (отправитель).
type GroupEncoder struct {
	codec     Codec
	k, r      int
	symbolLen int

	mu        sync.Mutex
	groupID   uint64
	cur       [][]byte // буфер data-символов текущей группы
}

// NewGroupEncoder создаёт кодировщик; symbolLen — длина data-символа (payload).
func NewGroupEncoder(codec Codec, k, r, symbolLen int) (*GroupEncoder, error) {
	if codec == CodecXOR && r != 1 {
		return nil, fmt.Errorf("xor-кодек поддерживает только r=1, дано r=%d", r)
	}
	if k < 1 || k > 200 || r < 0 || k+r > 255 {
		return nil, fmt.Errorf("недопустимые (k=%d, r=%d)", k, r)
	}
	if symbolLen <= 0 {
		symbolLen = 1200
	}
	return &GroupEncoder{codec: codec, k: k, r: r, symbolLen: symbolLen,
		cur: make([][]byte, 0, k)}, nil
}

// Scheme возвращает текущие (k, r).
func (e *GroupEncoder) Scheme() (int, int) { return e.k, e.r }

// SetScheme меняет (k, r) — применяется с начала следующей группы (адаптация).
func (e *GroupEncoder) SetScheme(codec Codec, k, r int) error {
	if codec == CodecXOR && r != 1 {
		return fmt.Errorf("xor: r=1 обязателен")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.codec, e.k, e.r = codec, k, r
	return nil
}

// AddData — добавить data-символ (payload длиной symbolLen).
// Возвращает (groupID, symIdx, repairs, groupDone): repairs НЕ пуст только при
// завершении группы. Вызывающий отправляет repairs после data-символа.
func (e *GroupEncoder) AddData(payload []byte) (groupID uint64, symIdx int, repairs [][]byte, groupDone bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(payload) != e.symbolLen {
		return 0, 0, nil, false, fmt.Errorf("payload %d != symbolLen %d", len(payload), e.symbolLen)
	}
	symIdx = len(e.cur)
	e.cur = append(e.cur, append([]byte(nil), payload...))
	if len(e.cur) < e.k {
		return e.groupID, symIdx, nil, false, nil
	}
	// группа заполнена
	groupID = e.groupID
	switch e.codec {
	case CodecXOR:
		xor := make([]byte, e.symbolLen)
		for _, p := range e.cur {
			for i := range xor {
				xor[i] ^= p[i]
			}
		}
		repairs = [][]byte{xor}
	case CodecRS:
		enc, err := reedsolomon.New(e.k, e.r)
		if err != nil {
			return groupID, symIdx, nil, true, err
		}
		shards := make([][]byte, e.k+e.r)
		copy(shards, e.cur)
		for i := e.k; i < len(shards); i++ {
			shards[i] = make([]byte, e.symbolLen)
		}
		if err := enc.Encode(shards); err != nil {
			return groupID, symIdx, nil, true, err
		}
		repairs = shards[e.k:]
	}
	e.cur = e.cur[:0]
	e.groupID++
	return groupID, symIdx, repairs, true, nil
}

// Flush — завершить неполную группу без repair (хвост).
func (e *GroupEncoder) Flush() (dropped int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	dropped = len(e.cur)
	e.cur = e.cur[:0]
	e.groupID++
	return dropped
}

// -----------------------------------------------------------------------
// Приёмная сторона: сборка групп и восстановление
// -----------------------------------------------------------------------

// GroupAssembler — собирает группы символов, восстанавливает потери.
type GroupAssembler struct {
	mu        sync.Mutex
	groups    map[uint64]*groupState
	ttl       time.Duration
	recovered atomic.Int64
	unrec     atomic.Int64
	groupsDone atomic.Int64
}

type groupState struct {
	k, r      int
	data      map[int][]byte // полученные data
	repair    map[int][]byte // полученные repair
	sendTs    map[int]int64  // sendT по symbolIndex (data)
	created   time.Time
	finalized bool
}

// NewGroupAssembler создаёт сборщик (ttl — время жизни «зависшей» группы).
func NewGroupAssembler(ttl time.Duration) *GroupAssembler {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &GroupAssembler{groups: map[uint64]*groupState{}, ttl: ttl}
}

// Add — принять символ (полный кадр: заголовок+payload).
// Возвращает список восстановленных data-символов (payload), если группа
// стала восстановимой в этом вызове.
func (a *GroupAssembler) Add(frame []byte, now time.Time) [][]byte {
	h, ok := ParseSymbolHeader(frame)
	if !ok {
		return nil
	}
	payload := frame[SymHdrLen:]

	a.mu.Lock()
	g := a.groups[h.GroupID]
	if g == nil {
		g = &groupState{k: h.K, r: h.R,
			data: map[int][]byte{}, repair: map[int][]byte{}, sendTs: map[int]int64{},
			created: now}
		a.groups[h.GroupID] = g
	}
	if h.IsRepair {
		if _, dup := g.repair[h.SymIdx]; !dup && h.SymIdx < g.r {
			g.repair[h.SymIdx] = append([]byte(nil), payload...)
		}
	} else {
		if _, dup := g.data[h.SymIdx]; !dup && h.SymIdx < g.k {
			g.data[h.SymIdx] = append([]byte(nil), payload...)
			g.sendTs[h.SymIdx] = h.SendT
		}
	}

	var recovered [][]byte
	if !g.finalized && len(g.data) < g.k && len(g.data)+len(g.repair) >= g.k {
		recovered = a.tryReconstruct(g, now)
	}
	if !g.finalized && len(g.data) == g.k {
		a.finalize(g, 0)
	}
	a.mu.Unlock()
	return recovered
}

// tryReconstruct — попытка восстановления недостающих data-символов.
func (a *GroupAssembler) tryReconstruct(g *groupState, now time.Time) [][]byte {
	if g.r == 0 {
		return nil
	}
	missing := g.k - len(g.data)
	var recovered [][]byte

	if g.r == 1 && len(g.repair) >= 1 && missing == 1 {
		// XOR-путь: восстановление единственной потери
		rep := firstValue(g.repair)
		rec := append([]byte(nil), rep...)
		for _, p := range g.data {
			for i := range rec {
				rec[i] ^= p[i]
			}
		}
		// найти пропавший индекс и зарегистрировать
		missIdx := -1
		for i := 0; i < g.k; i++ {
			if _, ok := g.data[i]; !ok {
				missIdx = i
				break
			}
		}
		if missIdx >= 0 {
			g.data[missIdx] = rec
			a.recovered.Add(1)
			recovered = [][]byte{rec}
		}
		a.finalize(g, 0)
		return recovered
	}

	// RS-путь: нужно >= k осколков из n
	if len(g.data)+len(g.repair) < g.k {
		return nil
	}
	shards := make([][]byte, g.k+g.r)
	for i, p := range g.data {
		shards[i] = p
	}
	for i, p := range g.repair {
		shards[g.k+i] = p
	}
	enc, err := reedsolomon.New(g.k, g.r)
	if err != nil {
		return nil
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil
	}
	// собираем восстановленные (те, чего не было в g.data)
	recoveredIdx := []int{}
	for i := 0; i < g.k; i++ {
		if _, ok := g.data[i]; !ok && shards[i] != nil {
			recoveredIdx = append(recoveredIdx, i)
		}
	}
	for _, i := range recoveredIdx {
		g.data[i] = shards[i]
		a.recovered.Add(1)
		recovered = append(recovered, shards[i])
	}
	a.finalize(g, 0)
	return recovered
}

func (a *GroupAssembler) finalize(g *groupState, unrecoveredData int) {
	if g.finalized {
		return
	}
	g.finalized = true
	a.groupsDone.Add(1)
	a.unrec.Add(int64(g.k - len(g.data)))
}

// Cleanup — удалить протухшие группы, зафиксировав невосстановленные потери.
// Возвращает число только что зафиксированных невосстановленных data-символов.
func (a *GroupAssembler) Cleanup(now time.Time) int {
	a.mu.Lock()
	fixed := 0
	for id, g := range a.groups {
		if !g.finalized && now.Sub(g.created) > a.ttl {
			fixed += g.k - len(g.data)
			a.finalize(g, 0)
		}
		if g.finalized && now.Sub(g.created) > a.ttl {
			delete(a.groups, id)
		}
	}
	a.mu.Unlock()
	return fixed
}

// Stats — (recovered, unrecovered, groupsDone).
func (a *GroupAssembler) Stats() (int64, int64, int64) {
	return a.recovered.Load(), a.unrec.Load(), a.groupsDone.Load()
}

func firstValue(m map[int][]byte) []byte {
	for _, v := range m {
		return v
	}
	return nil
}
