// Package crypto looks up a Bitcoin or Ethereum/EVM wallet address on public
// block explorers (no keys): balance, activity window, transaction counts,
// contract status and ENS name. Everything on a public blockchain is public
// by design; rectool only reads it.
package crypto

import (
	"context"
	"encoding/json"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the wallet module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "crypto" }
func (s *Scanner) Description() string {
	return "Bitcoin / Ethereum wallet activity, balance, ENS name"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.Wallet != "" }

var (
	btcRe = regexp.MustCompile(`^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,87})$`)
	ethRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); f() }); err != nil {
			wg.Done()
		}
	}
	switch {
	case btcRe.MatchString(t.Wallet):
		run(func() { bitcoin(ctx, d.HTTP, t.Wallet, emit) })
	case ethRe.MatchString(t.Wallet):
		run(func() { ethereum(ctx, d.HTTP, t.Wallet, emit) })
	}
	wg.Wait()
	return ctx.Err()
}

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func btc(sats int64) string {
	return strconv.FormatFloat(float64(sats)/1e8, 'f', 8, 64) + " BTC"
}

func bitcoin(ctx context.Context, c *httpx.Client, addr string, emit func(models.Finding)) {
	var a struct {
		ChainStats struct {
			Funded int64 `json:"funded_txo_sum"`
			Spent  int64 `json:"spent_txo_sum"`
			TxCnt  int   `json:"tx_count"`
		} `json:"chain_stats"`
		MempoolStats struct {
			TxCnt int `json:"tx_count"`
		} `json:"mempool_stats"`
	}
	if !getJSON(ctx, c, "https://mempool.space/api/address/"+addr, &a) {
		emit(models.Finding{Source: "Bitcoin address", Category: "crypto", Status: models.StatusError,
			Details: map[string]string{"error": "mempool.space did not answer"}})
		return
	}
	d := map[string]string{
		"type":            "Bitcoin",
		"balance":         btc(a.ChainStats.Funded - a.ChainStats.Spent),
		"total received":  btc(a.ChainStats.Funded),
		"total sent":      btc(a.ChainStats.Spent),
		"confirmed txs":   strconv.Itoa(a.ChainStats.TxCnt),
		"unconfirmed txs": strconv.Itoa(a.MempoolStats.TxCnt),
	}
	if strings.HasPrefix(addr, "bc1") {
		d["format"] = "native SegWit (bech32)"
	} else if strings.HasPrefix(addr, "3") {
		d["format"] = "P2SH (often multisig / exchange)"
	} else {
		d["format"] = "legacy P2PKH"
	}
	if a.ChainStats.TxCnt > 5000 {
		d["note"] = "very high activity: likely an exchange, service or mixer, not an individual"
	}
	// activity window from the latest page of transactions
	var txs []struct {
		Status struct {
			BlockTime int64 `json:"block_time"`
		} `json:"status"`
	}
	if getJSON(ctx, c, "https://mempool.space/api/address/"+addr+"/txs", &txs) && len(txs) > 0 {
		var newest, oldest int64
		for _, tx := range txs {
			bt := tx.Status.BlockTime
			if bt == 0 {
				continue
			}
			if newest == 0 || bt > newest {
				newest = bt
			}
			if oldest == 0 || bt < oldest {
				oldest = bt
			}
		}
		if newest > 0 {
			d["latest transaction"] = time.Unix(newest, 0).UTC().Format("2006-01-02")
			if a.ChainStats.TxCnt <= len(txs) {
				d["first transaction"] = time.Unix(oldest, 0).UTC().Format("2006-01-02")
			}
		}
	}
	d["explorers"] = "https://mempool.space/address/" + addr + "  ·  https://www.blockchain.com/explorer/addresses/btc/" + addr
	emit(models.Finding{Source: "Bitcoin address", Category: "crypto", URL: "https://mempool.space/address/" + addr,
		Status: models.StatusFound, Confidence: 0.95, Details: d})
}

func wei(s string) string {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return s
	}
	f := new(big.Float).Quo(new(big.Float).SetInt(v), big.NewFloat(1e18))
	return f.Text('f', 6) + " ETH"
}

func ethereum(ctx context.Context, c *httpx.Client, addr string, emit func(models.Finding)) {
	var a struct {
		CoinBalance     string `json:"coin_balance"`
		IsContract      bool   `json:"is_contract"`
		IsVerified      bool   `json:"is_verified"`
		Name            string `json:"name"`
		ENS             string `json:"ens_domain_name"`
		HasTokens       bool   `json:"has_tokens"`
		Creator         string `json:"creator_address_hash"`
		Implementations []struct {
			Name string `json:"name"`
		} `json:"implementations"`
	}
	if !getJSON(ctx, c, "https://eth.blockscout.com/api/v2/addresses/"+addr, &a) {
		emit(models.Finding{Source: "Ethereum address", Category: "crypto", Status: models.StatusError,
			Details: map[string]string{"error": "Blockscout did not answer"}})
		return
	}
	d := map[string]string{"type": "Ethereum / EVM", "balance": wei(a.CoinBalance)}
	put := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			d[k] = v
		}
	}
	put("label", a.Name)
	put("ENS name", a.ENS)
	if a.IsContract {
		d["kind"] = "smart contract"
		put("creator", a.Creator)
		if a.IsVerified {
			d["contract source"] = "verified"
		}
	} else {
		d["kind"] = "externally owned account (EOA)"
	}
	if a.HasTokens {
		d["tokens"] = "holds ERC-20 / NFT tokens"
	}
	var cnt struct {
		Tx        string `json:"transactions_count"`
		Transfers string `json:"token_transfers_count"`
	}
	if getJSON(ctx, c, "https://eth.blockscout.com/api/v2/addresses/"+addr+"/counters", &cnt) {
		put("transactions", cnt.Tx)
		put("token transfers", cnt.Transfers)
	}
	d["explorers"] = "https://etherscan.io/address/" + addr + "  ·  https://eth.blockscout.com/address/" + addr
	d["note"] = "the same address is valid on other EVM chains (BNB, Polygon, Arbitrum…): check those explorers too"

	var ents []models.Entity
	if a.ENS != "" {
		ents = append(ents, models.Entity{Type: models.EntUsername, Value: a.ENS}) // owner-set name: weak (not followed)
	}
	emit(models.Finding{Source: "Ethereum address", Category: "crypto", URL: "https://etherscan.io/address/" + addr,
		Status: models.StatusFound, Confidence: 0.95, Details: d, Entities: ents})
}
