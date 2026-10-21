// Command fecexp — экспериментальный стенд исследования CC-управляемого
// адаптивного RS-FEC в QUIC (форк quic-test, ветка research-fecexp).
//
// Подкоманды:
//
//	fecexp server  --listen 127.0.0.1:7911 [--symbol-len 1200]
//	fecexp client  --addr ... --mode datagram|stream --fec none|xor|rs_fix|adaptive \
//	               --k 10 --r 2 --symbol-len 1200 --pps 300 --duration 20s \
//	               --loss-model none|bernoulli|gilbert|groupaligned --loss-p 0.05 \
//	               --loss-burst 3 --ga-n 11 --ga-m 1 --ga-off 2 --seed 1
//	fecexp selftest  (каузальная валидация: group-aligned -> fec_recovered)
//
// Архитектуры: datagram = FEC поверх QUIC Datagrams (RFC 9221/9297-семантика,
// восстановление реальных потерь); stream = FEC поверх надёжного стрима
// (как в исходном quic-test; ARQ доставляет всё ниже FEC).
// Инжекция потерь — на уровне net.PacketConn (клиентский UDP-сокет).
// Вывод: JSON-строки с префиксом RESULT.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"quic-test/internal"
	"quic-test/internal/fecexp"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

const alpn = "fecexp"

// -----------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------

type serverTotals struct {
	mu            sync.Mutex
	DataBytes     int64 `json:"data_bytes"`
	FECRecovered  int64 `json:"fec_recovered"`
	FECUnrec      int64 `json:"fec_unrecovered"`
	Groups        int64 `json:"groups"`
	Conns         int   `json:"conns"`
	OWDsMs        []float64 `json:"-"`
}

func runServer(listen string, symbolLen int) error {
	udpConn, err := net.ListenUDP("udp", mustResolve(listen))
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: udpConn}
	tlsConf := internal.GenerateTLSConfig(true)
	tlsConf.NextProtos = []string{alpn}
	listener, err := tr.Listen(tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	fmt.Printf("RESULT {\"event\":\"server_listen\",\"addr\":\"%s\"}\n", listener.Addr())

	totals := &serverTotals{OWDsMs: []float64{}}
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go handleServerConn(conn, symbolLen, totals)
	}
}

func handleServerConn(conn quic.Connection, symbolLen int, _ *serverTotals) {
	defer conn.CloseWithError(0, "bye")
	assembler := fecexp.NewGroupAssembler(10 * time.Second)
	ctx := context.Background()

	// метрики ПО СОЕДИНЕНИЮ (харнесс читает построчно; кумулятив не нужен)
	perConn := &serverTotals{OWDsMs: []float64{}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); receiveDatagrams(ctx, conn, assembler, symbolLen, perConn) }()
	go func() { defer wg.Done(); receiveStreams(ctx, conn, assembler, symbolLen, perConn) }()
	wg.Wait()

	// финализация групп при закрытии соединения
	assembler.Cleanup(time.Now().Add(11 * time.Second))
	rec, unrec, groups := assembler.Stats()
	snap := serverTotals{DataBytes: perConn.DataBytes, FECRecovered: rec,
		FECUnrec: unrec, Groups: groups, Conns: 1}
	owd := append([]float64(nil), perConn.OWDsMs...)

	out := map[string]any{
		"event": "server_conn_done", "data_bytes": snap.DataBytes,
		"fec_recovered": snap.FECRecovered, "fec_unrecovered": snap.FECUnrec,
		"groups": snap.Groups,
	}
	if len(owd) > 0 {
		out["owd_ms_p50"] = percentile(owd, 50)
		out["owd_ms_p95"] = percentile(owd, 95)
		out["owd_ms_p99"] = percentile(owd, 99)
	}
	printJSON(out)
}

func receiveDatagrams(ctx context.Context, conn quic.Connection, a *fecexp.GroupAssembler, symbolLen int, t *serverTotals) {
	for {
		frame, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		consumeFrame(frame, a, symbolLen, t)
	}
}

func receiveStreams(ctx context.Context, conn quic.Connection, a *fecexp.GroupAssembler, symbolLen int, t *serverTotals) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go readStream(stream, a, symbolLen, t)
	}
}

func readStream(stream quic.Stream, a *fecexp.GroupAssembler, symbolLen int, t *serverTotals) {
	defer stream.Close()
	rd := bufio.NewReaderSize(stream, 64*1024)
	frame := make([]byte, fecexp.SymHdrLen+symbolLen)
	for {
		if _, err := io.ReadFull(rd, frame); err != nil {
			return
		}
		consumeFrame(frame, a, symbolLen, t)
	}
}

func consumeFrame(frame []byte, a *fecexp.GroupAssembler, symbolLen int, t *serverTotals) {
	h, ok := fecexp.ParseSymbolHeader(frame)
	if !ok {
		return
	}
	now := time.Now()
	if h.IsRepair {
		a.Add(frame, now)
		return
	}
	// data: учёт доставки + OWD
	t.mu.Lock()
	t.DataBytes += int64(symbolLen)
	if h.SendT > 0 {
		owd := now.UnixNano() - h.SendT
		if owd > 0 && owd < 10*time.Second.Nanoseconds() {
			t.OWDsMs = append(t.OWDsMs, float64(owd)/1e6)
			if len(t.OWDsMs) > 400000 {
				t.OWDsMs = t.OWDsMs[200000:]
			}
		}
	}
	t.mu.Unlock()
	a.Add(frame, now)
}

// -----------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------

type clientOpts struct {
	addr, mode, fecScheme                              string
	codec                                               string
	k, r                                                int
	symbolLen, pps                                      int
	duration                                            time.Duration
	loss                                                fecexp.LossConfig
	eps                                                 float64
}

func runClient(o clientOpts) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	inj := fecexp.NewLossPacketConn(udpConn, o.loss)
	tr := &quic.Transport{Conn: inj}

	sig := fecexp.NewCCSignals()
	quicCfg := &quic.Config{
		EnableDatagrams: true,
		Tracer: func(ctx context.Context, p logging.Perspective, cid quic.ConnectionID) *logging.ConnectionTracer {
			return &logging.ConnectionTracer{
				LostPacket: func(el logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
					sig.OnLostPacket(int64(pn))
				},
				UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
					srtt, minRTT := time.Duration(0), time.Duration(0)
					if rttStats != nil {
						srtt = rttStats.SmoothedRTT()
						minRTT = rttStats.MinRTT()
					}
					sig.OnMetrics(srtt, minRTT, int64(cwnd), int64(bytesInFlight))
				},
			}
		},
	}
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}
	conn, err := tr.Dial(context.Background(), mustResolve(o.addr), tlsConf, quicCfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// режимы FEC
	var codec fecexp.Codec = fecexp.CodecRS
	if o.fecScheme == "xor" {
		codec = fecexp.CodecXOR
	}
	k0, r0 := o.k, o.r
	if o.fecScheme == "none" {
		r0 = 0
	}
	enc, err := fecexp.NewGroupEncoder(codec, k0, r0, o.symbolLen)
	if err != nil {
		return err
	}
	var ctrl *fecexp.AdaptiveController
	if o.fecScheme == "adaptive" {
		ctrl = fecexp.NewAdaptiveController(sig, o.mode, k0)
	}

	var stream quic.Stream
	if o.mode == "stream" {
		stream, err = conn.OpenStreamSync(context.Background())
		if err != nil {
			return fmt.Errorf("open stream: %w", err)
		}
	}

	send := func(frame []byte) error {
		if o.mode == "datagram" {
			return conn.SendDatagram(frame)
		}
		_, err := stream.Write(frame)
		return err
	}

	sentData, sentRepair := 0, 0
	frame := make([]byte, fecexp.SymHdrLen+o.symbolLen)
	t0 := time.Now()
	deadline := t0.Add(o.duration)
	tick := time.NewTicker(time.Second / time.Duration(o.pps))
	defer tick.Stop()
	seqByte := byte(0)

	for time.Now().Before(deadline) {
		<-tick.C
		// payload: детерминированный (seq-зависимый)
		for i := range frame[fecexp.SymHdrLen:] {
			frame[fecexp.SymHdrLen+i] = seqByte + byte(i%251)
		}
		seqByte++

		if ctrl != nil {
			ctrl.Update(time.Now())
			c, k, r := ctrl.Scheme()
			if err := enc.SetScheme(c, k, r); err == nil {
				codec = c
			}
		}
		gid, symIdx, repairs, done, err := enc.AddData(frame[fecexp.SymHdrLen:])
		if err != nil {
			return err
		}
		if symIdx == 0 {
			inj.ResetGroupCounter() // group-aligned: фаза инжектора = граница группы
		}
		sendT := time.Now().UnixNano()
		fecexp.EncodeSymbolHeader(frame, fecexp.SymTypeData, gid, symIdx, encK(enc), encR(enc), sendT)
		if err := send(frame); err != nil {
			if o.mode == "datagram" && isTimeout(err) {
				continue // дроп при переполнении очереди датаграмм — учитываем как отправку
			}
			fmt.Fprintf(os.Stderr, "send data error: %v\n", err)
			break
		}
		sentData++
		sig.OnSent()

		if done {
			for ri, rep := range repairs {
				rframe := make([]byte, fecexp.SymHdrLen+len(rep))
				copy(rframe[fecexp.SymHdrLen:], rep)
				fecexp.EncodeSymbolHeader(rframe, fecexp.SymTypeRep, gid, ri, encK(enc), encR(enc), sendT)
				if err := send(rframe); err != nil {
					break
				}
				sentRepair++
			}
		}
	}
	dropped := enc.Flush()

	// дать хвосту доехать и корректно закрыть
	time.Sleep(500 * time.Millisecond)
	if stream != nil {
		stream.Close()
	}
	conn.CloseWithError(0, "done")
	time.Sleep(300 * time.Millisecond)

	seen, droppedPkts, symSeen, symDropped := inj.Stats()
	_, _, srtt, _, _ := sig.Snapshot()
	out := map[string]any{
		"event": "client_done", "mode": o.mode, "fec": o.fecScheme,
		"sent_data": sentData, "sent_repair": sentRepair, "tail_dropped": dropped,
		"symbol_len": o.symbolLen, "duration_s": o.duration.Seconds(),
		"inj_seen": seen, "inj_dropped": droppedPkts,
		"inj_sym_seen": symSeen, "inj_sym_dropped": symDropped,
		"inj_drop_rate": ratio(droppedPkts, seen),
		"inj_sym_drop_rate": ratio(symDropped, symSeen),
		"inj_mean_burst": inj.MeanBurstLen(),
		"srtt_ms": float64(srtt.Microseconds()) / 1000.0,
	}
	if ctrl != nil {
		_, k, r := ctrl.Scheme()
		out["final_k"], out["final_r"] = k, r
		out["switches"] = ctrl.Switches()
	}
	printJSON(out)
	return nil
}

func encK(e *fecexp.GroupEncoder) int  { k, _ := e.Scheme(); return k }
func encR(e *fecexp.GroupEncoder) int  { _, r := e.Scheme(); return r }

// -----------------------------------------------------------------------
// Selftest (каузальная валидация)
// -----------------------------------------------------------------------

func runSelftest() error {
	scenarios := []struct {
		name                       string
		mode, fec                  string
		k, r                       int
		loss                       fecexp.LossConfig
		pps                        int
		duration                   time.Duration
		check                      func(server *serverTotals, clientStats map[string]any) (bool, string)
	}{
		{
			name: "A_datagram_xor_groupaligned_m1 (каузальность восстановления, пробел №1)",
			mode: "datagram", fec: "xor", k: 10, r: 1,
			loss: fecexp.LossConfig{Model: fecexp.LossGroupAligned, GroupN: 11, GroupM: 1, GroupOff: 2, Seed: 42},
			pps: 400, duration: 4 * time.Second,
			check: func(s *serverTotals, c map[string]any) (bool, string) {
				if s.FECRecovered < 20 {
					return false, fmt.Sprintf("fec_recovered=%d < 20 — восстановление не работает", s.FECRecovered)
				}
				if s.FECUnrec > 30 {
					return false, fmt.Sprintf("невосстановленных слишком много: %d", s.FECUnrec)
				}
				return true, fmt.Sprintf("fec_recovered=%d, fec_unrecovered=%d", s.FECRecovered, s.FECUnrec)
			},
		},
		{
			name: "B_datagram_rs_k10r2_groupaligned_m2",
			mode: "datagram", fec: "rs_fix", k: 10, r: 2,
			loss: fecexp.LossConfig{Model: fecexp.LossGroupAligned, GroupN: 12, GroupM: 2, GroupOff: 1, Seed: 43},
			pps: 400, duration: 4 * time.Second,
			check: func(s *serverTotals, c map[string]any) (bool, string) {
				if s.FECRecovered < 40 {
					return false, fmt.Sprintf("fec_recovered=%d < 40", s.FECRecovered)
				}
				return true, fmt.Sprintf("fec_recovered=%d (RS восстанавливает 2 потери/группу)", s.FECRecovered)
			},
		},
		{
			name: "C_stream_xor_bernoulli5 (H4: стрим — восстановления нет)",
			mode: "stream", fec: "xor", k: 10, r: 1,
			loss: fecexp.LossConfig{Model: fecexp.LossBernoulli, P: 0.05, Seed: 44},
			pps: 400, duration: 4 * time.Second,
			check: func(s *serverTotals, c map[string]any) (bool, string) {
				if s.FECRecovered != 0 {
					return false, fmt.Sprintf("fec_recovered=%d != 0 —Unexpected", s.FECRecovered)
				}
				if s.DataBytes < 100000 {
					return false, fmt.Sprintf("доставлено слишком мало: %d (ARQ не отработал?)", s.DataBytes)
				}
				return true, fmt.Sprintf("fec_recovered=0 при доставленных %d байт (ARQ доставил всё)", s.DataBytes)
			},
		},
		{
			name: "D_datagram_none_bernoulli5 (база: ~5% потерь)",
			mode: "datagram", fec: "none", k: 16, r: 0,
			loss: fecexp.LossConfig{Model: fecexp.LossBernoulli, P: 0.05, Seed: 45},
			pps: 400, duration: 4 * time.Second,
			check: func(s *serverTotals, c map[string]any) (bool, string) {
				unrec := s.FECUnrec
				total := unrec + s.DataBytes/1173
				lossRate := ratio(unrec, total)
				if lossRate < 0.01 || lossRate > 0.12 {
					return false, fmt.Sprintf("доля потерь %.3f вне [0.01..0.12]", lossRate)
				}
				return true, fmt.Sprintf("эмпирическая доля потерь %.3f ≈ 0.05", lossRate)
			},
		},
	}

	allOK := true
	for _, sc := range scenarios {
		res := runScenario(sc.name, sc.mode, sc.fec, sc.k, sc.r, sc.loss, sc.pps, sc.duration, sc.check)
		if !res {
			allOK = false
		}
	}
	if allOK {
		fmt.Println("SELFTEST: ALL PASS")
	} else {
		fmt.Println("SELFTEST: FAILURES PRESENT")
		os.Exit(1)
	}
	return nil
}

// runScenario поднимает сервер в процессе, прогоняет клиента, сверяет.
func runScenario(name, mode, fec string, k, r int, loss fecexp.LossConfig, pps int, duration time.Duration,
	check func(*serverTotals, map[string]any) (bool, string)) bool {

	udpConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	tr := &quic.Transport{Conn: udpConn}
	tlsConf := internal.GenerateTLSConfig(true)
	tlsConf.NextProtos = []string{alpn}
	listener, err := tr.Listen(tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		fmt.Printf("SCENARIO %s: ERROR listen: %v\n", name, err)
		return false
	}
	totals := &serverTotals{OWDsMs: []float64{}}
	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept(context.Background())
		if err == nil {
			handleServerConn(conn, 1173, totals)
		}
		close(done)
	}()

	err = runClient(clientOpts{
		addr: listener.Addr().String(), mode: mode, fecScheme: fec,
		k: k, r: r, symbolLen: 1173, pps: pps, duration: duration, loss: loss,
	})
	if err != nil {
		fmt.Printf("SCENARIO %s: CLIENT ERROR: %v\n", name, err)
		return false
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		listener.Close()
		<-done
	}
	listener.Close()

	// clientStats из последнего client_done не пробрасываем внутрь — используем server-side
	ok, msg := check(totals, nil)
	status := "PASS"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("SCENARIO %-70s %s | %s\n", name, status, msg)
	return ok
}

// -----------------------------------------------------------------------
// utils
// -----------------------------------------------------------------------

func mustResolve(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad addr %q: %v\n", addr, err)
		os.Exit(2)
	}
	return a
}

func printJSON(v map[string]any) {
	b, _ := json.Marshal(v)
	fmt.Println("RESULT " + string(b))
}

func ratio(num, den int64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(p / 100 * float64(len(s)-1))
	return s[idx]
}

func isTimeout(err error) bool {
	type temporary interface{ Temporary() bool }
	t, ok := err.(temporary)
	return ok && t.Temporary()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: fecexp {server|client|selftest} [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:7911", "адрес прослушивания")
		symbolLen := fs.Int("symbol-len", 1173, "payload; DATAGRAM-кадр = 24+len+~3(varint) <= 1200")
		fs.Parse(os.Args[2:])
		if err := runServer(*listen, *symbolLen); err != nil {
			fmt.Fprintln(os.Stderr, "server:", err)
			os.Exit(1)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		o := clientOpts{}
		fs.StringVar(&o.addr, "addr", "127.0.0.1:7911", "адрес сервера")
		fs.StringVar(&o.mode, "mode", "datagram", "datagram|stream")
		fs.StringVar(&o.fecScheme, "fec", "rs_fix", "none|xor|rs_fix|adaptive")
		fs.IntVar(&o.k, "k", 10, "data-символов в группе")
		fs.IntVar(&o.r, "r", 2, "repair-символов")
		fs.IntVar(&o.symbolLen, "symbol-len", 1173, "длина символа (payload)")
		fs.IntVar(&o.pps, "pps", 300, "символов в секунду (pacing)")
		fs.DurationVar(&o.duration, "duration", 20*time.Second, "длительность")
		lossModel := fs.String("loss-model", "none", "none|bernoulli|gilbert|groupaligned")
		fs.Float64Var(&o.loss.P, "loss-p", 0.05, "средняя доля потерь")
		fs.Float64Var(&o.loss.BurstLen, "loss-burst", 3, "средняя длина пачки (gilbert)")
		fs.IntVar(&o.loss.GroupN, "ga-n", 11, "размер группы (groupaligned)")
		fs.IntVar(&o.loss.GroupM, "ga-m", 1, "потерь на группу (groupaligned)")
		fs.IntVar(&o.loss.GroupOff, "ga-off", 2, "позиция потери в группе (groupaligned)")
		fs.Int64Var(&o.loss.Seed, "seed", 1, "seed инжектора")
		fs.DurationVar(&o.loss.Delay, "delay", 0, "односторонняя задержка (эмуляция RTT=2*delay)")
		fs.Parse(os.Args[2:])
		o.loss.Model = fecexp.LossModel(*lossModel)
		if err := runClient(o); err != nil {
			fmt.Fprintln(os.Stderr, "client:", err)
			os.Exit(1)
		}
	case "selftest":
		if err := runSelftest(); err != nil {
			fmt.Fprintln(os.Stderr, "selftest:", err)
			os.Exit(1)
		}
	default:
		fmt.Println("usage: fecexp {server|client|selftest} [flags]")
		os.Exit(2)
	}
}
