// Package fecexp — экспериментальное расширение quic-test для исследования
// CC-управляемого адаптивного RS-FEC в QUIC (форк research-fecexp).
//
// lossinject.go — инжектор потерь на уровне net.PacketConn: оборачивает UDP-сокет
// клиента (quic.Transport.Conn), дропает исходящие пакеты ДО попадания в сеть.
// Потери видимы транспорту (CC, ARQ) и FEC-декодеру датаграммного пути.
//
// Модели:
//   - bernoulli: независимые потери с вероятностью p;
//   - gilbert:   чистый Гилберт (пачки, средняя длина L);
//   - groupaligned: детерминированно m потерь на группу из n «символьных»
//     пакетов (счётчик ведётся только по пакетам >= minSymbolBytes, чтобы
//     ACK-only пакеты не сбивали выравнивание).
package fecexp

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

// LossModel — модель канала.
type LossModel string

const (
	LossNone         LossModel = "none"
	LossBernoulli    LossModel = "bernoulli"
	LossGilbert      LossModel = "gilbert"
	LossGroupAligned LossModel = "groupaligned"
)

// LossConfig — параметры инжектора.
type LossConfig struct {
	Model     LossModel `json:"model"`
	P         float64   `json:"p"`         // средняя доля потерь
	BurstLen  float64   `json:"burst_len"` // средняя длина пачки (Гилберт)
	GroupN    int       `json:"group_n"`   // размер группы (groupaligned)
	GroupM    int       `json:"group_m"`   // потерь на группу
	GroupOff  int       `json:"group_off"` // смещение позиции потери в группе
	Seed      int64     `json:"seed"`
	MinSymbol int       `json:"min_symbol_bytes"` // порог «символьного» пакета
}

// LossStats — статистика инжектора.
type LossStats struct {
	PacketsSeen     atomic.Int64
	PacketsDropped  atomic.Int64
	SymbolPackets   atomic.Int64 // пакеты >= MinSymbol (кандидаты групп)
	SymbolDropped   atomic.Int64
}

// LossPacketConn — обёртка net.PacketConn с инжекцией потерь исходящих пакетов.
type LossPacketConn struct {
	net.PacketConn
	cfg   LossConfig
	stats LossStats

	mu      sync.Mutex
	rng     *rand.Rand
	inBad   bool // состояние Гилберта
	runLen  int
	runSum  int64
	runCnt  int64
	symPos  int // позиция внутри группы (по символьным пакетам)
	groupIdx int64
}

// NewLossPacketConn оборачивает conn согласно cfg.
func NewLossPacketConn(conn net.PacketConn, cfg LossConfig) *LossPacketConn {
	if cfg.MinSymbol <= 0 {
		cfg.MinSymbol = 1000
	}
	if cfg.Model == LossGilbert && cfg.BurstLen <= 1.0 {
		cfg.Model = LossBernoulli
	}
	return &LossPacketConn{
		PacketConn: conn,
		cfg:        cfg,
		rng:        rand.New(rand.NewSource(cfg.Seed)),
	}
}

// Config возвращает копию конфигурации.
func (l *LossPacketConn) Config() LossConfig { return l.cfg }

// Stats возвращает снапшот статистики.
func (l *LossPacketConn) Stats() (seen, dropped, symSeen, symDropped int64) {
	return l.stats.PacketsSeen.Load(), l.stats.PacketsDropped.Load(),
		l.stats.SymbolPackets.Load(), l.stats.SymbolDropped.Load()
}

// MeanBurstLen возвращает среднюю длину наблюдаемых серий потерь (для калибровки).
func (l *LossPacketConn) MeanBurstLen() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runCnt == 0 {
		return 1.0
	}
	return float64(l.runSum) / float64(l.runCnt)
}

// ResetGroupCounter — синхронизирует group-aligned-счётчик с границей FEC-группы.
// Вызывается отправителем перед ПЕРВЫМ data-символом каждой группы: пакеты
// рукопожатия (паддированные до ~1200 Б) иначе сдвигают фазу паттерна.
func (l *LossPacketConn) ResetGroupCounter() {
	l.mu.Lock()
	l.symPos = 0
	l.mu.Unlock()
}

// WriteTo — инжекция потерь в исходящем направлении.
func (l *LossPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	l.stats.PacketsSeen.Add(1)
	drop := false
	isSymbol := len(b) >= l.cfg.MinSymbol

	l.mu.Lock()
	switch l.cfg.Model {
	case LossBernoulli:
		drop = l.rng.Float64() < l.cfg.P
	case LossGilbert:
		// чистый Гилберт: pB=1, pG=0; b=1/L; a из p̄
		b := 1.0 / l.cfg.BurstLen
		a := l.cfg.P * b / (1.0 - l.cfg.P)
		if l.inBad {
			if l.rng.Float64() < b {
				l.inBad = false
			}
		} else {
			if l.rng.Float64() < a {
				l.inBad = true
			}
		}
		drop = l.inBad
	case LossGroupAligned:
		if isSymbol {
			pos := l.symPos
			l.symPos++
			if l.symPos >= l.cfg.GroupN {
				l.symPos = 0
				l.groupIdx++
			}
			// ровно m позиций на группу: off, off+n/2 (при m=2) и т.д.
			for i := 0; i < l.cfg.GroupM; i++ {
				target := (l.cfg.GroupOff + i*l.cfg.GroupN/max(l.cfg.GroupM, 1)) % l.cfg.GroupN
				if pos == target {
					drop = true
					break
				}
			}
		}
	}
	if drop {
		if l.runLen == 0 {
			// начало серии
		}
		l.runLen++
	} else if l.runLen > 0 {
		l.runSum += int64(l.runLen)
		l.runCnt++
		l.runLen = 0
	}
	l.mu.Unlock()

	if isSymbol {
		l.stats.SymbolPackets.Add(1)
	}
	if drop {
		l.stats.PacketsDropped.Add(1)
		if isSymbol {
			l.stats.SymbolDropped.Add(1)
		}
		return 0, nil // молча «теряем» пакет
	}
	return l.PacketConn.WriteTo(b, addr)
}

// String — человекочитаемое описание.
func (l *LossPacketConn) String() string {
	return fmt.Sprintf("lossinject(%s p=%g L=%g n=%d m=%d off=%d seed=%d)",
		l.cfg.Model, l.cfg.P, l.cfg.BurstLen, l.cfg.GroupN, l.cfg.GroupM, l.cfg.GroupOff, l.cfg.Seed)
}
