// transparent.go — CC-прозрачный режим fecexp (исследование, не RFC 9265).
//
// Механизм: получатель при восстановлении потерянных data-символов группы
// отправляет feedback-датаграмму (0xFC + groupID); отправитель отображает
// groupID -> номера QUIC-пакетов (колбэк quic.Config.DatagramSent из форка
// quic-go-fec) и добавляет их в набор подавления; пропатченный loss detection
// (quic-go-fec, sent_packet_handler.go) пропускает реакцию контроллера
// перегрузки для этих номеров.
//
// Свойства:
//   - подавление точечное (per-packet-number), учёт bytes-in-flight сохраняется;
//   - feedback приходит ~1 RTT после потери, реакция CC может успеть раньше —
//     тогда подавление пропускается и эффект занижается (нижняя граница);
//   - записи автоснимаются по TTL (30 с) и по факту срабатывания.
package fecexp

import (
	"encoding/binary"
	"sync"
	"time"
)

// FeedbackMagic — магия feedback-датаграммы (отличие от fecexp-символа 0xFD).
const FeedbackMagic = 0xFC

// FeedbackLen — длина feedback-датаграммы: magic + groupID.
const FeedbackLen = 9

// EncodeFeedback строит feedback-датаграмму «группа восстановлена».
func EncodeFeedback(dst []byte, groupID uint64) {
	dst[0] = FeedbackMagic
	binary.LittleEndian.PutUint64(dst[1:9], groupID)
}

// ParseFeedback разбирает feedback-датаграмму; ok=false если это не feedback.
func ParseFeedback(b []byte) (groupID uint64, ok bool) {
	if len(b) < FeedbackLen || b[0] != FeedbackMagic {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[1:9]), true
}

// suppressTTL — время жизни записи подавления.
const suppressTTL = 30 * time.Second

// SuppressSet — потокобезопасный набор номеров пакетов с подавленной
// реакцией CC. Contains потребляет запись (одноразовое подавление).
type SuppressSet struct {
	mu    sync.Mutex
	m     map[int64]time.Time
	hits  int64
	armed int64
	calls int64 // вызовов фильтра (диагностика)
}

// NewSuppressSet — конструктор.
func NewSuppressSet() *SuppressSet {
	return &SuppressSet{m: make(map[int64]time.Time)}
}

// Add — добавить номер пакета.
func (s *SuppressSet) Add(pn int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[pn] = time.Now()
	s.armed++
}

// Calls — суммарное число вызовов фильтра (диагностика).
func (s *SuppressSet) Calls() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Tracked — суммарное число зарегистрированных data-символов (диагностика).
func (t *RecoveryTracker) Tracked() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tracked
}

// Armed — суммарное число добавленных в набор номеров.
func (s *SuppressSet) Armed() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.armed
}

// Contains — проверить и потребить запись; параллельно чистит протухшие.
func (s *SuppressSet) Contains(pn int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if _, ok := s.m[pn]; ok {
		delete(s.m, pn)
		s.hits++
		return true
	}
	if len(s.m) > 4096 {
		deadline := time.Now().Add(-suppressTTL)
		for k, t := range s.m {
			if t.Before(deadline) {
				delete(s.m, k)
			}
		}
	}
	return false
}

// Hits — суммарное число подавленных реакций CC.
func (s *SuppressSet) Hits() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// RecoveryTracker — сопоставление groupID -> номера пакетов на отправителе.
type RecoveryTracker struct {
	mu       sync.Mutex
	pending  map[uint64][]int64
	created  map[uint64]time.Time
	set      *SuppressSet
	tracked  int64 // зарегистрировано data-символов (диагностика)
}

// NewRecoveryTracker — конструктор.
func NewRecoveryTracker(set *SuppressSet) *RecoveryTracker {
	return &RecoveryTracker{
		pending: make(map[uint64][]int64),
		created: make(map[uint64]time.Time),
		set:     set,
	}
}

// OnDatagramSent — колбэк quic.Config.DatagramSent: запомнить, в каких
// пакетах ушли символы fecexp (и data, и repair: потеря repair при
// восстановимой группе тоже должна быть невидима для CC).
func (t *RecoveryTracker) OnDatagramSent(pn int64, payloads [][]byte) {
	for _, p := range payloads {
		h, ok := ParseSymbolHeader(p)
		if !ok {
			continue
		}
		t.mu.Lock()
		t.pending[h.GroupID] = append(t.pending[h.GroupID], pn)
		t.created[h.GroupID] = time.Now()
		t.tracked++
		t.mu.Unlock()
	}
	if len(t.pending) > 8192 {
		t.prune()
	}
}

// SuppressPending — инкрементальное подавление: урон группы пока меньше r,
// поэтому все уже отправленные символы группы гарантированно восстановимы;
// подавить их PN-ы, не закрывая группу (будущие символы добавятся в pending).
func (t *RecoveryTracker) SuppressPending(groupID uint64) {
	t.mu.Lock()
	pns := t.pending[groupID]
	t.pending[groupID] = nil
	t.mu.Unlock()
	for _, pn := range pns {
		t.set.Add(pn)
	}
}

// OnRecovered — feedback от получателя: группа восстановлена.
func (t *RecoveryTracker) OnRecovered(groupID uint64) {
	t.SuppressGroup(groupID)
}

// SuppressGroup — sender-side предсказание: уронено ≤ r символов группы,
// MDS гарантирует восстановление — подавить реакцию CC, не дожидаясь
// feedback (регистрация происходит в момент отправки группы, реакция CC
// — только через RTT, поэтому гонка выигрывается).
func (t *RecoveryTracker) SuppressGroup(groupID uint64) {
	t.mu.Lock()
	pns := t.pending[groupID]
	delete(t.pending, groupID)
	delete(t.created, groupID)
	t.mu.Unlock()
	for _, pn := range pns {
		t.set.Add(pn)
	}
}

func (t *RecoveryTracker) prune() {
	deadline := time.Now().Add(-suppressTTL)
	for gid, ts := range t.created {
		if ts.Before(deadline) {
			delete(t.pending, gid)
			delete(t.created, gid)
		}
	}
}
