package split

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/tacyhq/tacy/kms"
)

// Admin-key containment (privacy review 2026-11-20): everything a policy lets in that an earlier one didn't waits
// 24 h at each holder (and, by the same rule, at each client for trust-list additions), while anything it takes
// away applies at once. A policy is reduced to items, one per thing it allows; the holder's PolicyStore remembers
// when each item was first seen and when it was withdrawn, so an item that reappears after a withdrawal waits again,
// and a lowered floor keeps the old floor in force for the delay.
//
// Items (Item* prefixes):
//
//	release:<sha256 of the whole pin>  a release pin: app, version, compose and app-compose sha256, app id (ReleaseItem),
//	                                   so relabelling a pin's version is a new item
//	os:<os-image-hash>                 an OS image (when the policy lists its own; nil = the holder's built-in list)
//	boot:<sha256 of the set>           a boot measurement set (likewise)
//	prelaunch:<sha256>                 a pre-launch script (likewise)
//	kmsroot:<hex>                      a dstack KMS root (likewise)
//	flag:kms-fallback                  the KMS fallback key mode
//	platform:<name>                    an attestation platform (when the policy names platforms)
//	tcb-grace:<sha256 of the grace>    a TCB grace
//	floor:<scope>:<vX.Y.Z>             a floor: scope "*" (the policy's) or an app; lowering one is an expansion
//	mrevoked:<sha256>                  a revoked machine certificate (machines_revoked): permanent, a store never
//	                                   marks one withdrawn (so never prunes it); not something a VM relies on
//	other:<sha256>                     the catch-all: every field that has no item of its own (OtherItem); every
//	                                   VM relies on it, so a change to any of them waits too (by construction, not
//	                                   one item per field found)
const (
	ItemRelease   = "release:"
	ItemOS        = "os:"
	ItemBoot      = "boot:"
	ItemPreLaunch = "prelaunch:"
	ItemKMSRoot   = "kmsroot:"
	ItemFlag      = "flag:"
	ItemPlatform  = "platform:"
	ItemTCBGrace  = "tcb-grace:"
	ItemFloor     = "floor:"
	ItemOther     = "other:"
	// ItemMachineRevoked items are permanent in every PolicyStore: Apply never marks one withdrawn.
	ItemMachineRevoked = "mrevoked:"
)

// PolicyItems are the items policy p allows, sorted.
func PolicyItems(p *UnlockPolicy) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	for _, r := range p.Releases {
		add(ReleaseItem(r))
	}
	for h := range p.OSImages {
		add(ItemOS + h)
	}
	for _, b := range p.Boot {
		add(ItemBoot + BootItem(b))
	}
	for h := range p.PreLaunch {
		add(ItemPreLaunch + h)
	}
	for h := range p.KMSRoots {
		add(ItemKMSRoot + h)
	}
	if p.KMSFallback {
		add(ItemFlag + "kms-fallback")
	}
	for _, pl := range p.Platforms {
		add(ItemPlatform + pl)
	}
	if p.TCBGrace != nil {
		add(ItemTCBGrace + TCBGraceItem(p))
	}
	add(FloorItem("*", p.Floor))
	for name, a := range p.Apps {
		if a.Floor != "" {
			add(FloorItem(name, a.Floor))
		}
	}
	for _, h := range p.MachinesRevoked {
		add(ItemMachineRevoked + h)
	}
	add(OtherItem(p))
	sort.Strings(out)
	return slices.Compact(out)
}

// ReleaseItem is a release pin's item: the sha256 of the whole pin.
func ReleaseItem(r kms.ReleasePin) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return ItemRelease + hex.EncodeToString(h[:])
}

// OtherItem is the catch-all item: the sha256 of the policy with every field that has its own item, or that can't
// widen what unlocks, taken out (seq, issued_at; the KMS id and epoch; the share sets and epoch certificates, signed
// by the KMS id; the holders and the break-glass relay, which can only refuse; the emergency override, checked on its
// own; the machine certificates, signed by the KMS id, and their revocations, which only narrow; release pins, OS
// images, boot sets, pre-launch scripts, KMS roots, the fallback flag, platforms, the TCB grace
// and floors, which have items). Everything else (apps and their grants, the key service pins, secrets_floor,
// worker keys, e2e overlays, start-ticket keys, witnesses, next admin keys, and any field added later) is in it.
func OtherItem(p *UnlockPolicy) string {
	q := *p
	q.Seq, q.IssuedAt, q.KMSID, q.Epoch = 0, time.Time{}, "", 0
	q.ShareSets, q.EpochCerts, q.Holders, q.BreakGlass, q.Emergency = nil, nil, nil, "", nil
	q.MachineCerts, q.MachinesRevoked = nil, nil // KMS-id signed, and revocations only narrow (no delay, F3)
	q.Releases, q.OSImages, q.Boot, q.PreLaunch, q.KMSRoots, q.KMSFallback, q.Platforms, q.TCBGrace, q.Floor = nil, nil, nil, nil, nil, false, nil, nil, ""
	if p.Apps != nil {
		q.Apps = map[string]kms.AppPolicy{}
		for name, a := range p.Apps {
			a.Floor = ""
			q.Apps[name] = a
		}
	}
	b, _ := json.Marshal(q)
	h := sha256.Sum256(b)
	return ItemOther + hex.EncodeToString(h[:])
}

// BootItem names a boot set by the sha256 of its registers.
func BootItem(b kms.BootSet) string {
	h := sha256.Sum256([]byte(strings.Join([]string{b.OSImage, b.MRTD, b.RTMR0, b.RTMR1, b.RTMR2}, "|")))
	return hex.EncodeToString(h[:])
}

// TCBGraceItem names a policy's TCB grace by the sha256 of its JSON.
func TCBGraceItem(p *UnlockPolicy) string {
	b, _ := json.Marshal(p.TCBGrace)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FloorItem is scope's floor item ("*" for the policy's floor).
func FloorItem(scope, version string) string { return ItemFloor + scope + ":" + version }

// ParseFloorItem reads a floor item: its scope and version.
func ParseFloorItem(item string) (scope, version string, ok bool) {
	rest, ok := strings.CutPrefix(item, ItemFloor)
	if !ok {
		return "", "", false
	}
	scope, version, ok = strings.Cut(rest, ":")
	return scope, version, ok
}

// PolicyHash is the sha256 of a policy's payload: two different documents with one seq (an admin key signing twice)
// are told apart by it.
func PolicyHash(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}
