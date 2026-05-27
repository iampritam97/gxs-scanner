package main

import (
	"context"
	"fmt"
	"sync"
)

// ─── Scanner ──────────────────────────────────────────────────────────────────
type Scanner struct {
	cfg       *Config
	oob       *OOBServer
	progress  *Progress
	store     *FindingStore
	requester *Requester
}

func NewScanner(cfg *Config, oob *OOBServer, progress *Progress) *Scanner {
	return &Scanner{
		cfg:       cfg,
		oob:       oob,
		progress:  progress,
		store:     NewFindingStore(cfg.Silent, cfg.Verbose),
		requester: NewRequester(cfg),
	}
}

func (s *Scanner) Findings() []Finding {
	return s.store.All()
}

func (s *Scanner) Run(ctx context.Context, urls []string) {
	type job struct {
		url    string
		module string
		fn     func(context.Context, string)
	}

	jobs := make(chan job, len(urls)*6)

	// Queue all jobs
	for _, u := range urls {
		u := u
		if s.cfg.ScanXXE {
			jobs <- job{u, "XXE", s.scanXXE}
		}
		if s.cfg.ScanGQL {
			jobs <- job{u, "GraphQL", s.scanGraphQL}
		}
		if s.cfg.ScanSSTI {
			jobs <- job{u, "SSTI", s.scanSSTI}
		}
		if s.cfg.ScanSSRF {
			jobs <- job{u, "SSRF", s.scanSSRF}
		}
		if s.cfg.ScanLog4j {
			jobs <- job{u, "Log4Shell", s.scanLog4j}
		}
		if s.cfg.ScanProto {
			jobs <- job{u, "ProtoPollution", s.scanProtoPollution}
		}
	}
	close(jobs)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.cfg.Workers)

	doneSets := make(map[string]int) // track completed modules per URL
	var doneSetsMu sync.Mutex

	for j := range jobs {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		j := j

		go func() {
			defer func() {
				<-sem
				wg.Done()
				if r := recover(); r != nil {
					logWarn(fmt.Sprintf("Panic in %s scanner on %s: %v", j.module, j.url, r))
				}
			}()

			select {
			case <-ctx.Done():
				return
			default:
			}

			if !s.cfg.Silent {
				fmt.Printf("%s[%s]%s → %s\n", Cyan, j.module, Reset, j.url)
			}

			j.fn(ctx, j.url)

			// Track progress: mark URL done when all enabled modules complete
			doneSetsMu.Lock()
			doneSets[j.url]++
			totalModules := 0
			if s.cfg.ScanXXE {
				totalModules++
			}
			if s.cfg.ScanGQL {
				totalModules++
			}
			if s.cfg.ScanSSTI {
				totalModules++
			}
			if s.cfg.ScanSSRF {
				totalModules++
			}
			if s.cfg.ScanLog4j {
				totalModules++
			}
			if s.cfg.ScanProto {
				totalModules++
			}
			if doneSets[j.url] >= totalModules {
				s.progress.Mark(j.url)
			}
			doneSetsMu.Unlock()
		}()
	}

done:
	wg.Wait()
}
