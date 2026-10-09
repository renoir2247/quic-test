// adaptive.go — адаптивный контроллер (n,k) по сигналам CC (трейсер quic-go).
//
// Сигналы (Case A, RFC 9265 «восстановленный = потерянный»):
//   - LostPacket(el, pn, reason) — события потерь транспорта (сырые, без
//     вычитания восстановленных);
//   - SentPacket/учёт отправленных символов — знаменатель оценки p̂;
//   - UpdatedMetrics(rttStats, cwnd, bytesInFlight, packetsInFlight) — RTT/cwnd.
//
// Оценки: p̂ — EWMA CC-видимых потерь; L̂ — средняя длина серии последовательных
// потерь (по номерам пакетов). Решение: lookup в встроенной политике
// policy_eps10.csv (сгенерирована аналитической моделью, eps_max=0.10),
// с гистерезисом (мин. время удержания схемы) и защитой от частых переключений.
package fecexp

import (
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

//go:embed policy_eps10.csv
var policyCSV string

type policyRow struct {
	path       string
	cc         string
	pBar       float64
	burst      float64
	k, r       int
}

var (
	policyOnce  sync.Once
	policyRows  []policyRow
)

func loadPolicy() {
	policyOnce.Do(func() {
		rd := csv.NewReader(strings.NewReader(policyCSV))
		_, _ = rd.Read() // header
		for {
			rec, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil || len(rec) < 6 {
				continue
			}
			policyRows = append(policyRows, policyRow{
				path: rec[0], cc: rec[1],
				pBar: parseFloat(rec[2]), burst: parseFloat(rec[3]),
				k: int(parseFloat(rec[4])), r: int(parseFloat(rec[5])),
			})
		}
	})
}

func parseFloat(s string) float64 {
	var v float64
	fmt.Sscanf(s, "%g", &v)
	return v
}

// CCSignals — потокобезопасный сборщик CC-сигналов из трейсера.
type CCSignals struct {
	mu           sync.Mutex
	lossEvents   int64
	sentPkts     int64
	lastLostPN   int64
	runLen       int
	runSum       int64
	runCnt       int64
	rttSum       time.Duration
	rttN         int64
	rttMin       time.Duration
	rttMax       time.Duration
	srtt         time.Duration
	cwndLast     int64
	inFlightLast int64
}

// NewCCSignals — конструктор.
func NewCCSignals() *CCSignals { return &CCSignals{rttMin: math.MaxInt64, lastLostPN: -1} }

// OnLostPacket — колбэк трейсера LostPacket.
func (c *CCSignals) OnLostPacket(pn int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lossEvents++
	if c.lastLostPN >= 0 && pn == c.lastLostPN+1 {
		c.runLen++
	} else {
		if c.runLen > 0 {
			c.runSum += int64(c.runLen)
			c.runCnt++
		}
		c.runLen = 1
	}
	c.lastLostPN = pn
}

// OnSent — учёт отправленного пакета (знаменатель p̂).
func (c *CCSignals) OnSent() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sentPkts++
}

// OnMetrics — колбэк UpdatedMetrics (RTT/cwnd/in-flight).
func (c *CCSignals) OnMetrics(srtt, minRTT time.Duration, cwnd, inFlight int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.srtt = srtt
	c.rttSum += srtt
	c.rttN++
	if srtt < c.rttMin {
		c.rttMin = srtt
	}
	if srtt > c.rttMax {
		c.rttMax = srtt
	}
	c.cwndLast = cwnd
	c.inFlightLast = inFlight
}

// Snapshot — (p_hat, burst_hat, rttStats...).
func (c *CCSignals) Snapshot() (pHat, burstHat float64, srtt time.Duration, losses, sent int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runLen > 0 {
		c.runSum += int64(c.runLen)
		c.runCnt++
		c.runLen = 0
	}
	pHat = 0
	if c.sentPkts > 100 {
		pHat = float64(c.lossEvents) / float64(c.sentPkts)
	}
	burstHat = 1.0
	if c.runCnt > 0 {
		burstHat = float64(c.runSum) / float64(c.runCnt)
	}
	return pHat, burstHat, c.srtt, c.lossEvents, c.sentPkts
}

// AdaptiveController — периодически пересчитывает (codec, k, r).
type AdaptiveController struct {
	mu        sync.Mutex
	signals   *CCSignals
	path      string // "datagram" | "stream"
	ccModel   string // "bbr" | "cubic" — модель критерия
	curK      int
	curR      int
	curCodec  Codec
	switches  int
	minDwell  time.Duration
	lastSw    time.Time
	history   []string
}

// NewAdaptiveController — стартует консервативно (FEC off).
func NewAdaptiveController(sig *CCSignals, path string, k0 int) *AdaptiveController {
	return &AdaptiveController{
		signals: sig, path: path, ccModel: "bbr",
		curK: k0, curR: 0, curCodec: CodecRS,
		minDwell: 3 * time.Second, lastSw: time.Now(),
	}
}

// Scheme — текущая схема.
func (a *AdaptiveController) Scheme() (Codec, int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.curCodec, a.curK, a.curR
}

// Switches — число переключений.
func (a *AdaptiveController) Switches() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.switches
}

// History — журнал решений.
func (a *AdaptiveController) History() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.history...)
}

// Update — пересчёт схемы; вызывается на границе группы.
// warmup: не переключаться первые ~2 с (накопление статистики).
func (a *AdaptiveController) Update(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastSw) < a.minDwell {
		return
	}
	pHat, burstHat, _, losses, sent := a.signals.Snapshot()
	if sent < 200 || losses == 0 && pHat == 0 {
		// недостаточно данных: FEC off
		if a.curR != 0 {
			a.curR = 0
			a.switches++
			a.lastSw = now
			a.history = append(a.history, fmt.Sprintf("t=%v p̂=%.4f L̂=%.1f -> r=0 (warmup)", now.Unix(), pHat, burstHat))
		}
		return
	}
	k, r := lookupPolicy(a.path, a.ccModel, pHat, burstHat)
	if k != a.curK || r != a.curR {
		a.history = append(a.history, fmt.Sprintf("t=%d p̂=%.4f L̂=%.1f -> (%d,%d)", now.Unix(), pHat, burstHat, k, r))
		a.curK, a.curR = k, r
		a.switches++
		a.lastSw = now
	}
}

func lookupPolicy(path, cc string, pHat, burstHat float64) (int, int) {
	loadPolicy()
	// гейт случая A: FEC включать только когда это может окупиться
	// (p_res >= 0 при идеальном восстановлении: p̂ > eps/(1+eps) с запасом)
	const eps = 0.10
	if pHat < eps/(1+eps)*0.75 {
		return 16, 0
	}
	bestD := math.Inf(1)
	bk, br := 16, 0
	for _, row := range policyRows {
		if row.path != path || row.cc != cc {
			continue
		}
		d := math.Abs(math.Log((pHat+1e-6)/(row.pBar+1e-6)))*2.0 + math.Abs(burstHat-row.burst)
		if d < bestD {
			bestD, bk, br = d, row.k, row.r
		}
	}
	return bk, br
}
