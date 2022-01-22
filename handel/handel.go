package handel

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"time"

	"github.com/relab/gorums"
	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/backend"
	"github.com/relab/hotstuff/consensus"
	"github.com/relab/hotstuff/crypto/bls12"
	"github.com/relab/hotstuff/internal/proto/handelpb"
)

type Handel struct {
	mods     *consensus.Modules
	cfg      *handelpb.Configuration
	maxLevel int
	sessions map[consensus.Hash]*session
}

// InitConsensusModule gives the module a reference to the Modules object.
// It also allows the module to set module options using the OptionsBuilder.
func (h *Handel) InitConsensusModule(mods *consensus.Modules, _ *consensus.OptionsBuilder) {
	h.mods = mods
}

func (h *Handel) Init() error {
	h.sessions = make(map[consensus.Hash]*session)

	var cfg *backend.Config
	var srv *backend.Server

	if !h.mods.GetModuleByType(&srv) {
		return errors.New("could not get gorums server")
	}
	if !h.mods.GetModuleByType(&cfg) {
		return errors.New("could not get gorums configuration")
	}

	handelpb.RegisterHandelServer(srv.GetGorumsServer(), serviceImpl{h})
	h.cfg = handelpb.ConfigurationFromRaw(cfg.GetRawConfiguration(), nil)

	h.maxLevel = int(math.Ceil(math.Log2(float64(h.mods.Configuration().Len()))))

	return nil
}

// Begin commissions the aggregation of a new signature.
func (h *Handel) Begin(ctx context.Context, s consensus.PartialCert) {

}

func rangeLevel(ids []hotstuff.ID, id hotstuff.ID, level int) (min int, max int) {
	selfIndex := -1
	for i, v := range ids {
		if id == v {
			selfIndex = i
			break
		}
	}

	maxLevel := int(math.Ceil(math.Log2(float64(len(ids)))))

	if level < 0 || level > maxLevel {
		panic("handel: invalid level")
	}

	max = len(ids) - 1

	for curLevel := maxLevel; curLevel >= level; curLevel-- {
		mid := (min + max) / 2

		if curLevel == level {
			// if we are at the target level, we want the half not containing the self
			if selfIndex > mid {
				max = mid
			} else {
				min = mid + 1
			}
		} else {
			// otherwise, we want the half containing the self
			if selfIndex > mid {
				min = mid + 1
			} else {
				max = mid
			}
		}
	}

	return min, max
}

// verificationPriority returns a pseudorandom permutation of 0..n-1 where n is the number of nodes,
// seed is a random number, self is the id of the local node, and level is the verification level.
// The verification priority (vp) is used to determine whose contributions can be verified.
func verificationPriority(ids []hotstuff.ID, seed int64, self hotstuff.ID, level int) (vp map[hotstuff.ID]int) {
	vp = make(map[hotstuff.ID]int)

	// create a slice of numbers [0, n-1) and shuffle it
	numbers := make([]int, len(ids)-1)
	for i := range numbers {
		numbers[i] = i
	}
	rnd := rand.New(rand.NewSource(seed + int64(level)))
	rnd.Shuffle(len(numbers), reflect.Swapper(numbers))

	// assign ids to numbers
	i := 0
	for _, id := range ids {
		if id == self {
			continue
		}
		vp[id] = numbers[i]
		i++
	}

	return vp
}

// contributionPriority returns a map of each remote node's verification priority for the local node.
// The contribution priority (cp) is used to determine which nodes should be contacted first.
func contributionPriority(ids []hotstuff.ID, seed int64, self hotstuff.ID, level int) (cp map[hotstuff.ID]int) {
	cp = make(map[hotstuff.ID]int)

	for _, id := range ids {
		if id == self {
			continue
		}
		vp := verificationPriority(ids, seed, id, level)
		cp[id] = vp[self]
	}

	return cp
}

func (s *session) score(contribution *handelpb.Contribution) int {
	if contribution.GetLevel() < 1 || int(contribution.GetLevel()) > s.h.maxLevel {
		// invalid level
		return 0
	}

}

// session
type session struct {
	h      *Handel
	seed   int64
	ids    []hotstuff.ID
	levels []level
}

func (h *Handel) newSession(hash consensus.Hash) *session {
	s := &session{}
	s.h = h
	s.seed = h.mods.Options().SharedRandomSeed() + int64(binary.LittleEndian.Uint64(hash[:]))

	// Get a sorted list of IDs for all replicas.
	// The configuration should also contain our own ID.
	s.ids = make([]hotstuff.ID, 0, h.mods.Configuration().Len())
	for id := range h.mods.Configuration().Replicas() {
		s.ids = append(s.ids, id)
	}
	sort.Slice(s.ids, func(i, j int) bool { return s.ids[i] < s.ids[j] })

	// Shuffle the list of IDs using the shared random seed + the first 8 bytes of the hash.
	rnd := rand.New(rand.NewSource(s.seed))
	rnd.Shuffle(len(s.ids), reflect.Swapper(s.ids))

	h.mods.Logger().Debug("Handel session ids: %v", s.ids)

	// compute verification priority and

	return s
}

type level struct {
	vp        map[hotstuff.ID]int
	cp        map[hotstuff.ID]int
	in        bls12.AggregateSignature
	out       bls12.AggregateSignature
	pending   map[hotstuff.ID]bls12.AggregateSignature
	startTime time.Time
	window    int
}

type serviceImpl struct {
	h *Handel
}

func (impl serviceImpl) Contribute(ctx gorums.ServerCtx, msg *handelpb.Contribution) {

}
