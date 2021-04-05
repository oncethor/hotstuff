// Package testutil provides helper methods that are useful for implementing tests.
package testutil

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/relab/hotstuff/blockchain"
	"github.com/relab/hotstuff/leaderrotation"

	"github.com/golang/mock/gomock"
	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/crypto"
	ecdsacrypto "github.com/relab/hotstuff/crypto/ecdsa"
	"github.com/relab/hotstuff/internal/logging"
	"github.com/relab/hotstuff/internal/mocks"
)

// TestModules returns a builder containing default modules for testing.
func TestModules(t *testing.T, ctrl *gomock.Controller, id hotstuff.ID, privkey hotstuff.PrivateKey) hotstuff.Builder {
	t.Helper()
	builder := hotstuff.NewBuilder(id, privkey)

	acceptor := mocks.NewMockAcceptor(ctrl)
	acceptor.EXPECT().Accept(gomock.AssignableToTypeOf(hotstuff.Command(""))).AnyTimes().Return(true)

	executor := mocks.NewMockExecutor(ctrl)
	executor.EXPECT().Exec(gomock.AssignableToTypeOf(hotstuff.Command(""))).AnyTimes()

	commandQ := mocks.NewMockCommandQueue(ctrl)
	commandQ.EXPECT().Get(gomock.Any()).AnyTimes().Return(hotstuff.Command("foo"), true)

	signer, verifier := ecdsacrypto.NewWithCache(10)

	config := mocks.NewMockConfig(ctrl)
	config.EXPECT().Len().AnyTimes().Return(1)
	config.EXPECT().QuorumSize().AnyTimes().Return(3)

	replica := CreateMockReplica(t, ctrl, id, privkey.Public())
	ConfigAddReplica(t, config, replica)
	config.EXPECT().Replicas().AnyTimes().Return((map[hotstuff.ID]hotstuff.Replica{1: replica}))

	synchronizer := mocks.NewMockViewSynchronizer(ctrl)
	synchronizer.EXPECT().Start().AnyTimes()
	synchronizer.EXPECT().Stop().AnyTimes()
	synchronizer.EXPECT().ViewContext().AnyTimes().Return(context.Background())

	builder.Register(
		logging.New(fmt.Sprintf("hs%d", id)),
		blockchain.New(100),
		mocks.NewMockConsensus(ctrl),
		leaderrotation.NewFixed(1),
		synchronizer,
		config,
		signer,
		verifier,
		acceptor,
		executor,
		commandQ,
	)
	return builder
}

// BuilderList is a helper type to perform actions on a set of builders.
type BuilderList []hotstuff.Builder

// HotStuffList is a helper type to perform actions on a set of HotStuff instances.
type HotStuffList []*hotstuff.HotStuff

// Build calls Build() for all of the builders.
func (bl BuilderList) Build() HotStuffList {
	hl := HotStuffList{}
	for _, hs := range bl {
		hl = append(hl, hs.Build())
	}
	return hl
}

// Signers returns the set of signers from all of the HotStuff instances.
func (hl HotStuffList) Signers() (signers []hotstuff.Signer) {
	signers = make([]hotstuff.Signer, len(hl))
	for i, hs := range hl {
		signers[i] = hs.Signer()
	}
	return signers
}

// Verifiers returns the set of verifiers from all of the HotStuff instances.
func (hl HotStuffList) Verifiers() (verifiers []hotstuff.Verifier) {
	verifiers = make([]hotstuff.Verifier, len(hl))
	for i, hs := range hl {
		verifiers[i] = hs.Verifier()
	}
	return verifiers
}

// Keys returns the set of private keys from all of the HotStuff instances.
func (hl HotStuffList) Keys() (keys []hotstuff.PrivateKey) {
	keys = make([]hotstuff.PrivateKey, len(hl))
	for i, hs := range hl {
		keys[i] = hs.PrivateKey()
	}
	return keys
}

// CreateBuilders creates n builders with default modules. Configurations are initialized with replicas.
func CreateBuilders(t *testing.T, ctrl *gomock.Controller, n int, keys ...hotstuff.PrivateKey) (builders BuilderList) {
	t.Helper()
	builders = make([]hotstuff.Builder, n)
	replicas := make([]*mocks.MockReplica, n)
	configs := make([]*mocks.MockConfig, n)
	for i := 0; i < n; i++ {
		id := hotstuff.ID(i + 1)
		var key hotstuff.PrivateKey
		if i < len(keys) {
			key = keys[i]
		} else {
			key = GenerateKey(t)
		}
		configs[i] = mocks.NewMockConfig(ctrl)
		replicas[i] = CreateMockReplica(t, ctrl, id, key.Public())
		builders[i] = TestModules(t, ctrl, id, key)
		builders[i].Register(configs[i]) // replaces the config registered by TestModules()
	}
	for _, config := range configs {
		for _, replica := range replicas {
			ConfigAddReplica(t, config, replica)
		}
		config.EXPECT().Len().AnyTimes().Return(len(replicas))
		config.EXPECT().QuorumSize().AnyTimes().Return(hotstuff.QuorumSize(len(replicas)))
		config.EXPECT().Replicas().AnyTimes().DoAndReturn(func() map[hotstuff.ID]hotstuff.Replica {
			m := make(map[hotstuff.ID]hotstuff.Replica)
			for _, replica := range replicas {
				m[replica.ID()] = replica
			}
			return m
		})
	}
	return builders
}

// CreateMockConfigWithReplicas creates a configuration with n replicas.
func CreateMockConfigWithReplicas(t *testing.T, ctrl *gomock.Controller, n int, keys ...hotstuff.PrivateKey) (*mocks.MockConfig, []*mocks.MockReplica) {
	t.Helper()
	cfg := mocks.NewMockConfig(ctrl)
	replicas := make([]*mocks.MockReplica, n)
	if len(keys) == 0 {
		keys = make([]hotstuff.PrivateKey, 0, n)
	}
	for i := 0; i < n; i++ {
		if len(keys) <= i {
			keys = append(keys, GenerateKey(t))
		}
		replicas[i] = CreateMockReplica(t, ctrl, hotstuff.ID(i+1), keys[i].Public())
		ConfigAddReplica(t, cfg, replicas[i])
	}
	cfg.EXPECT().Len().AnyTimes().Return(len(replicas))
	cfg.EXPECT().QuorumSize().AnyTimes().Return(hotstuff.QuorumSize(len(replicas)))
	return cfg, replicas
}

// CreateMockReplica returns a mock of a hotstuff.Replica.
func CreateMockReplica(t *testing.T, ctrl *gomock.Controller, id hotstuff.ID, key hotstuff.PublicKey) *mocks.MockReplica {
	t.Helper()

	replica := mocks.NewMockReplica(ctrl)
	replica.
		EXPECT().
		ID().
		AnyTimes().
		Return(id)
	replica.
		EXPECT().
		PublicKey().
		AnyTimes().
		Return(key)

	return replica
}

// ConfigAddReplica adds a mock replica to a mock configuration.
func ConfigAddReplica(t *testing.T, cfg *mocks.MockConfig, replica *mocks.MockReplica) {
	t.Helper()

	cfg.
		EXPECT().
		Replica(replica.ID()).
		AnyTimes().
		Return(replica, true)
}

// CreateTCPListener creates a net.Listener on a random port.
func CreateTCPListener(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	return lis
}

// Sign creates a signature using the given signer.
func Sign(t *testing.T, hash hotstuff.Hash, signer hotstuff.Signer) hotstuff.Signature {
	t.Helper()
	sig, err := signer.Sign(hash)
	if err != nil {
		t.Fatalf("Failed to sign block: %v", err)
	}
	return sig
}

// CreateSignatures creates partial certificates from multiple signers.
func CreateSignatures(t *testing.T, hash hotstuff.Hash, signers []hotstuff.Signer) []hotstuff.Signature {
	t.Helper()
	sigs := make([]hotstuff.Signature, 0, len(signers))
	for _, signer := range signers {
		sigs = append(sigs, Sign(t, hash, signer))
	}
	return sigs
}

// CreateTimeouts creates a set of TimeoutMsg messages from the given signers.
func CreateTimeouts(t *testing.T, view hotstuff.View, signers []hotstuff.Signer) (timeouts []hotstuff.TimeoutMsg) {
	t.Helper()
	timeouts = make([]hotstuff.TimeoutMsg, 0, len(signers))
	sigs := CreateSignatures(t, view.ToHash(), signers)
	for _, sig := range sigs {
		timeouts = append(timeouts, hotstuff.TimeoutMsg{
			ID:        sig.Signer(),
			View:      view,
			Signature: sig,
		})
	}
	return timeouts
}

// CreatePC creates a partial certificate using the given signer.
func CreatePC(t *testing.T, block *hotstuff.Block, signer hotstuff.Signer) hotstuff.PartialCert {
	t.Helper()
	pc, err := signer.CreatePartialCert(block)
	if err != nil {
		t.Fatalf("Failed to create partial certificate: %v", err)
	}
	return pc
}

// CreatePCs creates one partial certificate using each of the given signers.
func CreatePCs(t *testing.T, block *hotstuff.Block, signers []hotstuff.Signer) []hotstuff.PartialCert {
	t.Helper()
	pcs := make([]hotstuff.PartialCert, 0, len(signers))
	for _, signer := range signers {
		pcs = append(pcs, CreatePC(t, block, signer))
	}
	return pcs
}

// CreateQC creates a QC using the given signers.
func CreateQC(t *testing.T, block *hotstuff.Block, signers []hotstuff.Signer) hotstuff.QuorumCert {
	t.Helper()
	if len(signers) == 0 {
		return nil
	}
	qc, err := signers[0].CreateQuorumCert(block, CreatePCs(t, block, signers))
	if err != nil {
		t.Fatalf("Failed to create QC: %v", err)
	}
	return qc
}

// CreateTC generates a TC using the given signers.
func CreateTC(t *testing.T, view hotstuff.View, signers []hotstuff.Signer) hotstuff.TimeoutCert {
	t.Helper()
	if len(signers) == 0 {
		return nil
	}
	tc, err := signers[0].CreateTimeoutCert(view, CreateTimeouts(t, view, signers))
	if err != nil {
		t.Fatalf("Failed to create TC: %v", err)
	}
	return tc
}

// GenerateKey generates an ECDSA private key for use in tests.
func GenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateECDSAPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	return key
}

// GenerateKeys generates n keys.
func GenerateKeys(t *testing.T, n int) (keys []hotstuff.PrivateKey) {
	keys = make([]hotstuff.PrivateKey, n)
	for i := 0; i < n; i++ {
		keys[i] = GenerateKey(t)
	}
	return keys
}

// NewProposeMsg wraps a new block in a ProposeMsg.
func NewProposeMsg(parent hotstuff.Hash, qc hotstuff.QuorumCert, cmd hotstuff.Command, view hotstuff.View, id hotstuff.ID) hotstuff.ProposeMsg {
	return hotstuff.ProposeMsg{ID: id, Block: hotstuff.NewBlock(parent, qc, cmd, view, id)}
}

type leaderRotation struct {
	t     *testing.T
	order []hotstuff.ID
}

// GetLeader returns the id of the leader in the given view.
func (l leaderRotation) GetLeader(v hotstuff.View) hotstuff.ID {
	l.t.Helper()
	if v == 0 {
		l.t.Fatalf("attempt to get leader for view 0")
	}
	if v > hotstuff.View(len(l.order)) {
		l.t.Fatalf("leader rotation only defined up to view: %v", len(l.order))
	}
	return l.order[v-1]
}

// NewLeaderRotation returns a leader rotation implementation that will return leaders in the specified order.
func NewLeaderRotation(t *testing.T, order ...hotstuff.ID) hotstuff.LeaderRotation {
	t.Helper()
	return leaderRotation{t, order}
}

// FixedTimeout returns an ExponentialTimeout with a max exponent of 0.
func FixedTimeout(timeout time.Duration) hotstuff.ExponentialTimeout {
	return hotstuff.ExponentialTimeout{
		Base:         timeout,
		ExponentBase: 1,
		MaxExponent:  0,
	}
}
