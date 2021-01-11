package hotstuff

// ID uniquely identifies a replica
type ID uint32

// View uniquely identifies a view
type View uint64

// Hash is a SHA256 hash
type Hash [32]byte

// Command is a client request to be executed by the consensus protocol
type Command string

type ToBytes interface {
	ToBytes() []byte
}

// PublicKey is the public part of a replica's key pair
type PublicKey interface{}

// Credentials are used to authenticate communication between replicas
type Credentials interface{}

// PrivateKey is the private part of a replica's key pair
type PrivateKey interface {
	PublicKey() PublicKey
}

// Signature is a signature of a block
type Signature interface {
	ToBytes
	// Signer returns the ID of the replica that generated the signature.
	Signer() ID
}

// PartialCert is a certificate for a block created by a single replica
type PartialCert interface {
	ToBytes
	// Signature returns the signature
	Signature() Signature
	// BlockHash returns the hash of the block that was signed
	BlockHash() Hash
}

// QuorumCert is a certificate for a Block created by a quorum of replicas
type QuorumCert interface {
	ToBytes
	// BlockHash returns the hash of the block for which the certificate was created
	BlockHash() Hash
}

// Signer implements the methods requried to create signatures and certificates
type Signer interface {
	// Sign signs a single block and returns the signature
	Sign(block Block) (cert PartialCert, err error)
	// CreateQuourmCert creates a from a list of partial certificates
	CreateQuorumCert(block Block, signatures []PartialCert) (cert QuorumCert, err error)
}

// Verifier implements the methods required to verify partial and quorum certificates
type Verifier interface {
	// VerifyPartialCert verifies a single partial certificate
	VerifyPartialCert(cert PartialCert) bool
	// VerifyQuorumCert verifies a quorum certificate
	VerifyQuorumCert(qc QuorumCert) bool
}

// Replica implements the methods that communicate with another replica
type Replica interface {
	// ID returns the replica's id
	ID() ID
	// PublicKey returns the replica's public key
	PublicKey() PublicKey
	// Vote sends the partial certificate to the other replica
	Vote(cert PartialCert)
	// NewView sends the quorum certificate to the other replica
	NewView(qc QuorumCert)
}

// Block is a proposal that is made during the consensus protocol
type Block interface {
	ToBytes
	// Hash returns the hash of the block
	Hash() Hash
	// Proposer returns the id of the proposer
	Proposer() ID
	// Parent returns the hash of the parent block
	Parent() Hash
	// Command returns the command
	Command() Command
	// Certificate returns the certificate that this block references
	QuorumCert() QuorumCert
	// View returns the view in which the block was proposed
	View() View
}

// BlockChain is a datastructure that stores a chain of blocks
type BlockChain interface {
	// Store stores a block in the blockchain
	Store(Block)
	// Get retrieves a block given its hash
	Get(Hash) (Block, bool)
}

// Consensus implements a consensus protocol
type Consensus interface {
	// Config returns the configuration of this replica
	Config() Config
	// View returns the current view
	View() View
	// HighQC returns the highest QC known to the replica
	HighQC() QuorumCert
	// Leaf returns the last proposed block
	Leaf() Block
	// Propose proposes the given command
	Propose(cmd Command)
	// OnPropose handles an incoming proposal
	OnPropose(block Block)
	// OnVote handles an incoming vote
	OnVote(cert PartialCert)
	// OnVote handles an incoming NewView
	OnNewView(qc QuorumCert)
}

type Config interface {
	// ID returns the id of this replica
	ID() ID
	// PrivateKey returns the id of this replica
	PrivateKey() PrivateKey
	// Replicas returns all of the replicas in the configuration
	Replicas() map[ID]Replica
	// QuorumSize returns the size of a quorum
	QuorumSize() int
	// Propose sends the block to all replicas in the configuration
	Propose(block Block)
}

// LeaderRotation implements a leader rotation scheme
type LeaderRotation interface {
	// GetLeader returns the id of the leader in the given view
	GetLeader(View) ID
}

// Executor executes a command
type Executor interface {
	// Exec executes the given command
	Exec(Command)
}

// ViewSynchronizer TODO
type ViewSynchronizer interface {
}
