package verify

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var waveconn pb.WAVEClient
var Src *pb.CreateEntityResponse
var Dst *pb.CreateEntityResponse
var Proof []byte

// initializes waved connection, enclave, two default entities with no expiry, and an attestation
func init() {
	conn, err := grpc.Dial("127.0.0.1:410", grpc.WithInsecure(), grpc.FailOnNonTempDialError(true), grpc.WithBlock())
	if err != nil {
		fmt.Printf("failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	waveconn = pb.NewWAVEClient(conn)
	Src, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if Src.Error != nil {
		panic(Src.Error.Message)
	}
	Dst, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if Dst.Error != nil {
		panic(Dst.Error.Message)
	}
	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: Src.PublicDER,
	})
	if err != nil {
		panic(err)
	}
	if srcresp.Error != nil {
		panic(srcresp.Error.Message)
	}
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: Dst.PublicDER,
	})
	if err != nil {
		panic(err)
	}
	if dstresp.Error != nil {
		panic(dstresp.Error.Message)
	}
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    Src.Hash,
				Indirections: 20,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      "default",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	Proof = proofresp.ProofDER
}

func checkVerification(t *testing.T, DER []byte, subjectHash []byte, pbPol *pb.RTreePolicy) {
	var proofTime time.Time
	verifyresp, err := waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER:            DER,
		Subject:             subjectHash,
		RequiredRTreePolicy: pbPol,
	})
	require.NoError(t, err)
	waveTime := time.Unix(verifyresp.Result.GetExpiry()/1e3, 0)

	CExpiry, err := VerifyProof(DER, subjectHash, pbPol)
	if verifyresp.Error == nil {
		require.NoError(t, err)
	} else {
		fmt.Println(verifyresp.Error.Message)
		require.Error(t, err)
	}
	if err == nil {
		expiryStr := strconv.FormatInt(CExpiry, 10)
		proofExpiry := fmt.Sprintf("20%s-%s-%sT%s:%s:%sZ", expiryStr[0:2], expiryStr[2:4],
			expiryStr[4:6], expiryStr[6:8], expiryStr[8:10], expiryStr[10:12])
		proofTime, _ = time.Parse(time.RFC3339, proofExpiry)
		require.True(t, waveTime.Equal(proofTime))
	}
}

// tests basic attestation
func TestBasic(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests policy permission which doesn't match proof
func TestBadPolicyPermission(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"garbage"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests policy resource which doesn't match proof
func TestBadPolicyResource(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "garbage",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests policy pset which doesn't match proof
func TestBadPolicyPset(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Dst.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests policy namespace which doesn't match proof
func TestBadPolicyNamespace(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Dst.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests policy subject which doesn't match proof
func TestBadPolicySubject(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests proof which doesn't contain a superset of the needed permissions
func TestBadPolicy(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default", "extra"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests verifying policy of no permissions with proof
func TestNoPermissions(t *testing.T) {
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests interesting resource paths and regex patterns
func TestResourcePaths(t *testing.T) {
	resource := "default/foo/bar"
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
	}
	checkVerification(t, proofresp.ProofDER, Dst.Hash, &pbPol)

	resource = "default/foo/*"
	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	resource = "default/foo/bazbar"
	proofresp, err = waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)
	pbPol.Statements[0].Resource = resource
	checkVerification(t, proofresp.ProofDER, Dst.Hash, &pbPol)

	resource = "default/*"
	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	resource = "default/baz/bar/foo"
	proofresp, err = waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)
	pbPol.Statements[0].Resource = resource
	checkVerification(t, proofresp.ProofDER, Dst.Hash, &pbPol)
}

// tests proof which contains multiple policy statements
// WAVE has not yet implemented proof verification with multiple statements
func TestMultipleStatements(t *testing.T) {
	const pset = "\x1b\x20\x14\x33\x74\xb3\x2f\xd2\x74\x39\x54\xfe\x47\x86\xf6\xcf\x86\xd4\x03\x72\x0f\x5e\xc4\x42\x36\xb6\x58\xc2\x6a\x1e\x68\x0f\x6e\x01"
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: []byte(pset),
						Permissions:   []string{"bar"},
						Resource:      "baz",
					},
				},
			},
		},
		Publish: true,
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	// 	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
	// 		Perspective: &pb.Perspective{
	// 			EntitySecret: &pb.EntitySecret{
	// 				DER: Src.SecretDER,
	// 			},
	// 		},
	// 		SubjectHash: Dst.Hash,
	// 		Policy: &pb.Policy{
	// 			RTreePolicy: &pb.RTreePolicy{
	// 				Namespace: Src.Hash,
	// 				Statements: []*pb.RTreePolicyStatement{
	// 					&pb.RTreePolicyStatement{
	// 						PermissionSet: Src.Hash,
	// 						Permissions:   []string{"default3"},
	// 						Resource:      "default",
	// 					},
	// 				},
	// 			},
	// 		},
	// 		Publish: true,
	// 	})
	// require.NoError(t, err)
	// require.Nil(t, attresp.Error)
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: []byte(pset),
				Permissions:   []string{"bar"},
				Resource:      "baz",
			},
			// &pb.RTreePolicyStatement{
			// 	PermissionSet: Src.Hash,
			// 	Permissions:   []string{"default3"},
			// 	Resource:      "default",
			// },
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: []byte(pset),
				Permissions:   []string{"bar"},
				Resource:      "baz",
			},
			// &pb.RTreePolicyStatement{
			// 	PermissionSet: Src.Hash,
			// 	Permissions:   []string{"default3"},
			// 	Resource:      "default",
			// },
		},
	}
	checkVerification(t, proofresp.ProofDER, Dst.Hash, &pbPol)
}

// tests proof which contains multiple attestations
func TestAttestationChain(t *testing.T) {
	prevEnt := Dst
	var ent *pb.CreateEntityResponse
	var err error
	for i := 0; i < 1; i++ {
		ent, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
		require.NoError(t, err)
		require.Nil(t, ent.Error)
		entresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
			DER: ent.PublicDER,
		})
		require.NoError(t, err)
		require.Nil(t, entresp.Error)
		attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: prevEnt.SecretDER,
				},
			},
			SubjectHash: ent.Hash,
			Policy: &pb.Policy{
				RTreePolicy: &pb.RTreePolicy{
					Namespace:    Src.Hash,
					Indirections: 20,
					Statements: []*pb.RTreePolicyStatement{
						&pb.RTreePolicyStatement{
							PermissionSet: Src.Hash,
							Permissions:   []string{"default"},
							Resource:      "default",
						},
					},
				},
			},
			Publish: true,
		})
		require.NoError(t, err)
		require.Nil(t, attresp.Error)
		prevEnt = ent
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ent.SecretDER,
			},
		},
		SubjectHash: ent.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)
	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	checkVerification(t, proofresp.ProofDER, ent.Hash, &pbPol)
}

// tests entities and attestations with optional fields
func TestBasicWithOptionals(t *testing.T) {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidFrom:  time.Now().Add(time.Second).UnixNano() / 1e6,
		ValidUntil: time.Now().Add(time.Minute*10).UnixNano() / 1e6,
	})
	require.NoError(t, err)
	require.Nil(t, src.Error)
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidUntil:       time.Now().Add(time.Minute*20).UnixNano() / 1e6,
		SecretPassphrase: "wave",
	})
	require.NoError(t, err)
	require.Nil(t, dst.Error)
	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: src.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	require.NoError(t, err)
	require.Nil(t, srcresp.Error)
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: dst.PublicDER,
	})
	require.NoError(t, err)
	require.Nil(t, dstresp.Error)
	time.Sleep(time.Second)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidFrom:   time.Now().Add(time.Second).UnixNano() / 1e6,
		ValidUntil:  time.Now().Add(24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: dst.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 4,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
		Publish: true,
	})
	require.NoError(t, err)
	require.Nil(t, attresp.Error)
	time.Sleep(time.Second)
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        dst.SecretDER,
				Passphrase: []byte{'w', 'a', 'v', 'e'},
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		SubjectHash: dstresp.Hash,
		Namespace:   srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
		ResyncFirst: true,
	})
	require.NoError(t, err)
	require.Nil(t, proofresp.Error)
	pbPol := pb.RTreePolicy{
		Namespace: srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
	}
	checkVerification(t, proofresp.ProofDER, dst.Hash, &pbPol)
}
