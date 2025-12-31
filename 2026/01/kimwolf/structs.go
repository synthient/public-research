package structs

import (
	 "bufio"
	 "bytes"
	 "compress/gzip"
	 "container/list"
	 "context"
	 "crypto"
	 "crypto/aes"
	 "crypto/cipher"
	 "crypto/ecdh"
	 "crypto/ed25519"
	 "crypto/elliptic"
	 "crypto/hmac"
	 "crypto/tls"
	 "crypto/x509"
	 "crypto/x509/pkix"
	 "encoding/asn1"
	 "encoding/json"
	 "github.com/andybalholm/brotli"
	 "github.com/klauspost/compress/zstd"
	 "golang.org/x/crypto/sha3"
	 "golang.org/x/net/http2/hpack"
	 "hash"
	 "io"
	 "log/slog"
	 "math/big"
	 "math/rand"
	 "mime/multipart"
	 "net"
	 "net/http/httptrace"
	 "net/netip"
	 "net/textproto"
	 "net/url"
	 "os"
	 "reflect"
	 "regexp"
	 "rolf/internal"
	 "rolf/internal/client/flooders/http"
	 "rolf/internal/client/handlers"
	 "rolf/pkg/abi"
	 "rolf/pkg/ackhandler"
	 "rolf/pkg/azuretls"
	 "rolf/pkg/bigmod"
	 "rolf/pkg/bisect"
	 "rolf/pkg/boring"
	 "rolf/pkg/bytebuf"
	 "rolf/pkg/common"
	 "rolf/pkg/congestion"
	 "rolf/pkg/cookiejar"
	 "rolf/pkg/crc32"
	 "rolf/pkg/cryptobyte"
	 "rolf/pkg/dilithium"
	 "rolf/pkg/dnsmessage"
	 "rolf/pkg/drbg"
	 "rolf/pkg/dsa"
	 "rolf/pkg/ecdsa"
	 "rolf/pkg/ed448"
	 "rolf/pkg/fiat"
	 "rolf/pkg/field"
	 "rolf/pkg/flate"
	 "rolf/pkg/flowcontrol"
	 "rolf/pkg/fp448"
	 "rolf/pkg/fse"
	 "rolf/pkg/gcm"
	 "rolf/pkg/godebugs"
	 "rolf/pkg/gopacket"
	 "rolf/pkg/handshake"
	 "rolf/pkg/hpke"
	 "rolf/pkg/http2"
	 "rolf/pkg/http3"
	 "rolf/pkg/httpproxy"
	 "rolf/pkg/huff0"
	 "rolf/pkg/ipv4"
	 "rolf/pkg/kem"
	 "rolf/pkg/kyber768"
	 "rolf/pkg/layers"
	 "rolf/pkg/logging"
	 "rolf/pkg/mlkem"
	 "rolf/pkg/mlkem768"
	 "rolf/pkg/mode2"
	 "rolf/pkg/mode3"
	 "rolf/pkg/nistec"
	 "rolf/pkg/norm"
	 "rolf/pkg/poll"
	 "rolf/pkg/protocol"
	 "rolf/pkg/proxy"
	 "rolf/pkg/qerr"
	 "rolf/pkg/qpack"
	 "rolf/pkg/quic"
	 "rolf/pkg/rsa"
	 "rolf/pkg/serrors"
	 "rolf/pkg/socket"
	 "rolf/pkg/socks"
	 "rolf/pkg/syntax"
	 "rolf/pkg/tls13"
	 "rolf/pkg/utils"
	 "rolf/pkg/websocket"
	 "rolf/pkg/wire"
	 "rolf/pkg/x25519"
	 "rolf/pkg/xxhash"
	 "runtime"
	 "sync"
	 "sync/atomic"
	 "syscall"
	 "time"
	 "unsafe"
	azuretls_client "github.com/Noooste/azuretls-client"
	net_http "net/http"
)

type abi_FuncFlag uint8

type abi_FuncFlag uint8

type abi_FuncID uint8

type abi_FuncID uint8

type abi_FuncType struct {
	Type		*abi.Type
	InCount		*uint16
	OutCount	*uint16
}

type abi_FuncType struct {
	Type		*abi.Type
	InCount		*uint16
	OutCount	*uint16
}

type abi_ITab struct {
	Inter	*abi.InterfaceType
	Type	*abi.Type
	Hash	*uint32
	Fun	*[1]uintptr
}

type abi_ITab struct {
	Inter	*abi.InterfaceType
	Type	*abi.Type
	Hash	*uint32
	Fun	*[1]uintptr
}

type abi_Imethod struct {
	Name	*abi.NameOff
	Typ	*abi.TypeOff
}

type abi_Imethod struct {
	Name	*abi.NameOff
	Typ	*abi.TypeOff
}

type abi_IntArgRegBitmap [0]*uint8

type abi_IntArgRegBitmap [0]*uint8

type abi_InterfaceType struct {
	Type	*abi.Type
	PkgPath	*abi.Name
	Methods	*[]abi.Imethod
}

type abi_InterfaceType struct {
	Type	*abi.Type
	PkgPath	*abi.Name
	Methods	*[]abi.Imethod
}

type abi_Kind uint8

type abi_Kind uint8

type abi_Name struct {
	Bytes *uint8
}

type abi_Name struct {
	Bytes *uint8
}

type abi_NameOff int32

type abi_NameOff int32

type abi_PtrType struct {
	Type	*abi.Type
	Elem	*abi.Type
}

type abi_PtrType struct {
	Type	*abi.Type
	Elem	*abi.Type
}

type abi_RegArgs struct {
	Ints		*[0]uintptr
	Floats		*[0]uint64
	Ptrs		*[0]unsafe.Pointer
	ReturnIsPtr	*abi.IntArgRegBitmap
}

type abi_RegArgs struct {
	Ints		*[0]uintptr
	Floats		*[0]uint64
	Ptrs		*[0]unsafe.Pointer
	ReturnIsPtr	*abi.IntArgRegBitmap
}

type abi_TFlag uint8

type abi_TFlag uint8

type abi_Type struct {
	Size_		*uintptr
	PtrBytes	*uintptr
	Hash		*uint32
	TFlag		*abi.TFlag
	Align_		*uint8
	FieldAlign_	*uint8
	Kind_		*abi.Kind
	Equal		*func(unsafe.Pointer, unsafe.Pointer) bool
	GCData		*uint8
	Str		*abi.NameOff
	PtrToThis	*abi.TypeOff
}

type abi_Type struct {
	Size_		*uintptr
	PtrBytes	*uintptr
	Hash		*uint32
	TFlag		*abi.TFlag
	Align_		*uint8
	FieldAlign_	*uint8
	Kind_		*abi.Kind
	Equal		*func(unsafe.Pointer, unsafe.Pointer) bool
	GCData		*uint8
	Str		*abi.NameOff
	PtrToThis	*abi.TypeOff
}

type abi_TypeOff int32

type abi_TypeOff int32

type abi_UncommonType struct {
	PkgPath	*abi.NameOff
	Mcount	*uint16
	Xcount	*uint16
	Moff	*uint32
	_	*uint32
}

type abi_UncommonType struct {
	PkgPath	*abi.NameOff
	Mcount	*uint16
	Xcount	*uint16
	Moff	*uint32
	_	*uint32
}

type ackhandler_Frame struct {
	Frame	*wire.Frame
	Handler	*ackhandler.FrameHandler
}

type ackhandler_Frame struct {
	Frame	*wire.Frame
	Handler	*ackhandler.FrameHandler
}

type ackhandler_FrameHandler interface {
}

type ackhandler_FrameHandler interface {
}

type ackhandler_ReceivedPacketHandler interface {
}

type ackhandler_ReceivedPacketHandler interface {
}

type ackhandler_SendMode uint8

type ackhandler_SendMode uint8

type ackhandler_SentPacketHandler interface {
}

type ackhandler_SentPacketHandler interface {
}

type ackhandler_StreamFrame struct {
	Frame	*wire.StreamFrame
	Handler	*ackhandler.FrameHandler
}

type ackhandler_StreamFrame struct {
	Frame	*wire.StreamFrame
	Handler	*ackhandler.FrameHandler
}

type ackhandler_alarmTimer struct {
	Time		*time.Time
	TimerType	*logging.TimerType
	EncryptionLevel	*protocol.EncryptionLevel
}

type ackhandler_alarmTimer struct {
	Time		*time.Time
	TimerType	*logging.TimerType
	EncryptionLevel	*protocol.EncryptionLevel
}

type ackhandler_appDataReceivedPacketTracker struct {
	receivedPacketTracker			*interface{}
	largestObservedRcvdTime			*time.Time
	largestObserved				*protocol.PacketNumber
	ignoreBelow				*protocol.PacketNumber
	maxAckDelay				*time.Duration
	ackQueued				*bool
	ackElicitingPacketsReceivedSinceLastAck	*int
	ackAlarm				*time.Time
	logger					*utils.Logger
}

type ackhandler_appDataReceivedPacketTracker struct {
	receivedPacketTracker			*interface{}
	largestObservedRcvdTime			*time.Time
	largestObserved				*protocol.PacketNumber
	ignoreBelow				*protocol.PacketNumber
	maxAckDelay				*time.Duration
	ackQueued				*bool
	ackElicitingPacketsReceivedSinceLastAck	*int
	ackAlarm				*time.Time
	logger					*utils.Logger
}

type ackhandler_ecnHandler interface {
}

type ackhandler_ecnHandler interface {
}

type ackhandler_ecnState uint8

type ackhandler_ecnState uint8

type ackhandler_ecnTracker struct {
	state			*interface{}
	numSentTesting		*uint8
	numLostTesting		*uint8
	firstTestingPacket	*protocol.PacketNumber
	lastTestingPacket	*protocol.PacketNumber
	firstCapablePacket	*protocol.PacketNumber
	numSentECT0		*int64
	numSentECT1		*int64
	numAckedECT0		*int64
	numAckedECT1		*int64
	numAckedECNCE		*int64
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
}

type ackhandler_ecnTracker struct {
	state			*interface{}
	numSentTesting		*uint8
	numLostTesting		*uint8
	firstTestingPacket	*protocol.PacketNumber
	lastTestingPacket	*protocol.PacketNumber
	firstCapablePacket	*protocol.PacketNumber
	numSentECT0		*int64
	numSentECT1		*int64
	numAckedECT0		*int64
	numAckedECT1		*int64
	numAckedECNCE		*int64
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
}

type ackhandler_interval struct {
	Start	*protocol.PacketNumber
	End	*protocol.PacketNumber
}

type ackhandler_interval struct {
	Start	*protocol.PacketNumber
	End	*protocol.PacketNumber
}

type ackhandler_packet struct {
	SendTime		*time.Time
	StreamFrames		*[]ackhandler.StreamFrame
	Frames			*[]ackhandler.Frame
	LargestAcked		*protocol.PacketNumber
	Length			*protocol.ByteCount
	EncryptionLevel		*protocol.EncryptionLevel
	IsPathMTUProbePacket	*bool
	includedInBytesInFlight	*bool
	declaredLost		*bool
	isPathProbePacket	*bool
}

type ackhandler_packet struct {
	SendTime		*time.Time
	StreamFrames		*[]ackhandler.StreamFrame
	Frames			*[]ackhandler.Frame
	LargestAcked		*protocol.PacketNumber
	Length			*protocol.ByteCount
	EncryptionLevel		*protocol.EncryptionLevel
	IsPathMTUProbePacket	*bool
	includedInBytesInFlight	*bool
	declaredLost		*bool
	isPathProbePacket	*bool
}

type ackhandler_packetNumberGenerator interface {
}

type ackhandler_packetNumberGenerator interface {
}

type ackhandler_packetNumberSpace struct {
	history				*interface{}
	pns				*interface{}
	lossTime			*time.Time
	lastAckElicitingPacketTime	*time.Time
	largestAcked			*protocol.PacketNumber
	largestSent			*protocol.PacketNumber
}

type ackhandler_packetNumberSpace struct {
	history				*interface{}
	pns				*interface{}
	lossTime			*time.Time
	lastAckElicitingPacketTime	*time.Time
	largestAcked			*protocol.PacketNumber
	largestSent			*protocol.PacketNumber
}

type ackhandler_packetWithPacketNumber struct {
	PacketNumber	*protocol.PacketNumber
	packet		*interface{}
}

type ackhandler_packetWithPacketNumber struct {
	PacketNumber	*protocol.PacketNumber
	packet		*interface{}
}

type ackhandler_receivedPacketHandler struct {
	sentPackets		*interface{}
	initialPackets		*interface{}
	handshakePackets	*interface{}
	appDataPackets		*interface{}
	lowest1RTTPacket	*protocol.PacketNumber
}

type ackhandler_receivedPacketHandler struct {
	sentPackets		*interface{}
	initialPackets		*interface{}
	handshakePackets	*interface{}
	appDataPackets		*interface{}
	lowest1RTTPacket	*protocol.PacketNumber
}

type ackhandler_receivedPacketHistory struct {
	ranges		*[]ackhandler.interval
	deletedBelow	*protocol.PacketNumber
}

type ackhandler_receivedPacketHistory struct {
	ranges		*[]ackhandler.interval
	deletedBelow	*protocol.PacketNumber
}

type ackhandler_receivedPacketTracker struct {
	ect0		*uint64
	ect1		*uint64
	ecnce		*uint64
	packetHistory	*interface{}
	lastAck		*wire.AckFrame
	hasNewAck	*bool
}

type ackhandler_receivedPacketTracker struct {
	ect0		*uint64
	ect1		*uint64
	ecnce		*uint64
	packetHistory	*interface{}
	lastAck		*wire.AckFrame
	hasNewAck	*bool
}

type ackhandler_sentPacketHandler struct {
	initialPackets			*interface{}
	handshakePackets		*interface{}
	appDataPackets			*interface{}
	peerCompletedAddressValidation	*bool
	bytesReceived			*protocol.ByteCount
	bytesSent			*protocol.ByteCount
	peerAddressValidated		*bool
	handshakeConfirmed		*bool
	lowestNotConfirmedAcked		*protocol.PacketNumber
	ackedPackets			*[]ackhandler.packetWithPacketNumber
	bytesInFlight			*protocol.ByteCount
	congestion			*congestion.SendAlgorithmWithDebugInfos
	rttStats			*utils.RTTStats
	connStats			*utils.ConnectionStats
	ptoCount			*uint32
	ptoMode				*ackhandler.SendMode
	numProbesToSend			*int
	alarm				*interface{}
	enableECN			*bool
	ecnTracker			*interface{}
	perspective			*protocol.Perspective
	tracer				*logging.ConnectionTracer
	logger				*utils.Logger
}

type ackhandler_sentPacketHandler struct {
	initialPackets			*interface{}
	handshakePackets		*interface{}
	appDataPackets			*interface{}
	peerCompletedAddressValidation	*bool
	bytesReceived			*protocol.ByteCount
	bytesSent			*protocol.ByteCount
	peerAddressValidated		*bool
	handshakeConfirmed		*bool
	lowestNotConfirmedAcked		*protocol.PacketNumber
	ackedPackets			*[]ackhandler.packetWithPacketNumber
	bytesInFlight			*protocol.ByteCount
	congestion			*congestion.SendAlgorithmWithDebugInfos
	rttStats			*utils.RTTStats
	connStats			*utils.ConnectionStats
	ptoCount			*uint32
	ptoMode				*ackhandler.SendMode
	numProbesToSend			*int
	alarm				*interface{}
	enableECN			*bool
	ecnTracker			*interface{}
	perspective			*protocol.Perspective
	tracer				*logging.ConnectionTracer
	logger				*utils.Logger
}

type ackhandler_sentPacketHistory struct {
	packets			*[]*ackhandler.packet
	pathProbePackets	*[]ackhandler.packetWithPacketNumber
	skippedPackets		*[]protocol.PacketNumber
	numOutstanding		*int
	firstPacketNumber	*protocol.PacketNumber
	highestPacketNumber	*protocol.PacketNumber
}

type ackhandler_sentPacketHistory struct {
	packets			*[]*ackhandler.packet
	pathProbePackets	*[]ackhandler.packetWithPacketNumber
	skippedPackets		*[]protocol.PacketNumber
	numOutstanding		*int
	firstPacketNumber	*protocol.PacketNumber
	highestPacketNumber	*protocol.PacketNumber
}

type ackhandler_sentPacketTracker interface {
}

type ackhandler_sentPacketTracker interface {
}

type ackhandler_sequentialPacketNumberGenerator struct {
	next *protocol.PacketNumber
}

type ackhandler_sequentialPacketNumberGenerator struct {
	next *protocol.PacketNumber
}

type ackhandler_skippingPacketNumberGenerator struct {
	period		*protocol.PacketNumber
	maxPeriod	*protocol.PacketNumber
	next		*protocol.PacketNumber
	nextToSkip	*protocol.PacketNumber
	rng		*utils.Rand
}

type ackhandler_skippingPacketNumberGenerator struct {
	period		*protocol.PacketNumber
	maxPeriod	*protocol.PacketNumber
	next		*protocol.PacketNumber
	nextToSkip	*protocol.PacketNumber
	rng		*utils.Rand
}

type ackhandler_uSentPacketHandler struct {
	sentPacketHandler		*interface{}
	initialPacketNumberLength	*protocol.PacketNumberLen
}

type ackhandler_uSentPacketHandler struct {
	sentPacketHandler		*interface{}
	initialPacketNumberLength	*protocol.PacketNumberLen
}

type adler32_digest uint32

type adler32_digest uint32

type aes_Block struct {
	block *interface{}
}

type aes_Block struct {
	block *interface{}
}

type aes_CBCDecrypter struct {
	b	*aes.Block
	iv	*[16]uint8
}

type aes_CBCDecrypter struct {
	b	*aes.Block
	iv	*[16]uint8
}

type aes_CBCEncrypter struct {
	b	*aes.Block
	iv	*[16]uint8
}

type aes_CBCEncrypter struct {
	b	*aes.Block
	iv	*[16]uint8
}

type aes_CTR struct {
	b	*aes.Block
	ivlo	*uint64
	ivhi	*uint64
	offset	*uint64
}

type aes_CTR struct {
	b	*aes.Block
	ivlo	*uint64
	ivhi	*uint64
	offset	*uint64
}

type aes_KeySizeError int

type aes_KeySizeError int

type aes_KeySizeError int

type aes_KeySizeError int

type aes_block struct {
	blockExpanded *interface{}
}

type aes_block struct {
	blockExpanded *interface{}
}

type aes_blockExpanded struct {
	rounds	*int
	enc	*[60]uint32
	dec	*[60]uint32
}

type aes_blockExpanded struct {
	rounds	*int
	enc	*[60]uint32
	dec	*[60]uint32
}

type asn1_BitString struct {
	Bytes		*[]uint8
	BitLength	*int
}

type asn1_BitString struct {
	Bytes		*[]uint8
	BitLength	*int
}

type asn1_Enumerated int

type asn1_Enumerated int

type asn1_Flag bool

type asn1_Flag bool

type asn1_ObjectIdentifier []*int

type asn1_ObjectIdentifier []*int

type asn1_RawContent []*uint8

type asn1_RawContent []*uint8

type asn1_RawValue struct {
	Class		*int
	Tag		*int
	IsCompound	*bool
	Bytes		*[]uint8
	FullBytes	*[]uint8
}

type asn1_RawValue struct {
	Class		*int
	Tag		*int
	IsCompound	*bool
	Bytes		*[]uint8
	FullBytes	*[]uint8
}

type asn1_StructuralError struct {
	Msg *string
}

type asn1_StructuralError struct {
	Msg *string
}

type asn1_SyntaxError struct {
	Msg *string
}

type asn1_SyntaxError struct {
	Msg *string
}

type asn1_Tag uint8

type asn1_Tag uint8

type asn1_bitStringEncoder struct {
	Bytes		*[]uint8
	BitLength	*int
}

type asn1_bitStringEncoder struct {
	Bytes		*[]uint8
	BitLength	*int
}

type asn1_byteEncoder uint8

type asn1_byteEncoder uint8

type asn1_bytesEncoder []*uint8

type asn1_bytesEncoder []*uint8

type asn1_encoder interface {
}

type asn1_encoder interface {
}

type asn1_fieldParameters struct {
	optional	*bool
	explicit	*bool
	application	*bool
	private		*bool
	defaultValue	*int64
	tag		*int
	stringType	*int
	timeType	*int
	set		*bool
	omitEmpty	*bool
}

type asn1_fieldParameters struct {
	optional	*bool
	explicit	*bool
	application	*bool
	private		*bool
	defaultValue	*int64
	tag		*int
	stringType	*int
	timeType	*int
	set		*bool
	omitEmpty	*bool
}

type asn1_int64Encoder int64

type asn1_int64Encoder int64

type asn1_invalidUnmarshalError struct {
	Type *reflect.Type
}

type asn1_invalidUnmarshalError struct {
	Type *reflect.Type
}

type asn1_multiEncoder []*interface{}

type asn1_multiEncoder []*interface{}

type asn1_oidEncoder []*int

type asn1_oidEncoder []*int

type asn1_setEncoder []*interface{}

type asn1_setEncoder []*interface{}

type asn1_stringEncoder string

type asn1_stringEncoder string

type asn1_tagAndLength struct {
	class		*int
	tag		*int
	length		*int
	isCompound	*bool
}

type asn1_tagAndLength struct {
	class		*int
	tag		*int
	length		*int
	isCompound	*bool
}

type asn1_taggedEncoder struct {
	scratch	*[8]uint8
	tag	*interface{}
	body	*interface{}
}

type asn1_taggedEncoder struct {
	scratch	*[8]uint8
	tag	*interface{}
	body	*interface{}
}

type atomic_Bool struct {
	_	*struct {
	}
	v	*uint32
}

type atomic_Bool struct {
	_	*struct {
	}
	v	*uint32
}

type atomic_Bool struct {
	u *atomic.Uint8
}

type atomic_Bool struct {
	u *atomic.Uint8
}

type atomic_Int32 struct {
	_	*struct {
	}
	v	*int32
}

type atomic_Int32 struct {
	noCopy	*struct {
	}
	value	*int32
}

type atomic_Int32 struct {
	_	*struct {
	}
	v	*int32
}

type atomic_Int32 struct {
	noCopy	*struct {
	}
	value	*int32
}

type atomic_Int64 struct {
	_	*struct {
	}
	_	*interface{}
	v	*int64
}

type atomic_Int64 struct {
	noCopy	*struct {
	}
	_	*interface{}
	value	*int64
}

type atomic_Int64 struct {
	noCopy	*struct {
	}
	_	*interface{}
	value	*int64
}

type atomic_Int64 struct {
	_	*struct {
	}
	_	*interface{}
	v	*int64
}

type atomic_Uint32 struct {
	_	*struct {
	}
	v	*uint32
}

type atomic_Uint32 struct {
	_	*struct {
	}
	v	*uint32
}

type atomic_Uint32 struct {
	noCopy	*struct {
	}
	value	*uint32
}

type atomic_Uint32 struct {
	noCopy	*struct {
	}
	value	*uint32
}

type atomic_Uint64 struct {
	_	*struct {
	}
	_	*interface{}
	v	*uint64
}

type atomic_Uint64 struct {
	_	*struct {
	}
	_	*interface{}
	v	*uint64
}

type atomic_Uint64 struct {
	noCopy	*struct {
	}
	_	*interface{}
	value	*uint64
}

type atomic_Uint64 struct {
	noCopy	*struct {
	}
	_	*interface{}
	value	*uint64
}

type atomic_Uint8 struct {
	noCopy	*struct {
	}
	value	*uint8
}

type atomic_Uint8 struct {
	noCopy	*struct {
	}
	value	*uint8
}

type atomic_Uintptr struct {
	noCopy	*struct {
	}
	value	*uintptr
}

type atomic_Uintptr struct {
	noCopy	*struct {
	}
	value	*uintptr
}

type atomic_UnsafePointer struct {
	noCopy	*struct {
	}
	value	*unsafe.Pointer
}

type atomic_UnsafePointer struct {
	noCopy	*struct {
	}
	value	*unsafe.Pointer
}

type atomic_Value struct {
	v *interface {}
}

type atomic_Value struct {
	v *interface {}
}

type atomic_align64 struct {
}

type atomic_align64 struct {
}

type atomic_align64 struct {
}

type atomic_align64 struct {
}

type atomic_noCopy struct {
}

type atomic_noCopy struct {
}

type atomic_noCopy struct {
}

type atomic_noCopy struct {
}

type azuretls_Context struct {
	Session			*azuretls.Session
	Request			*azuretls.Request
	Response		*azuretls.Response
	Err			*error
	ctx			*context.Context
	RequestStartTime	*time.Time
}

type azuretls_Context struct {
	Session			*azuretls.Session
	Request			*azuretls.Request
	Response		*azuretls.Response
	Err			*error
	ctx			*context.Context
	RequestStartTime	*time.Time
}

type azuretls_ContextKeyHeader struct {
}

type azuretls_ContextKeyHeader struct {
}

type azuretls_HTTP3Config struct {
	Enabled		*bool
	ForceHTTP3	*bool
	altSvcCache	*sync.Map
	transport	*azuretls.HTTP3Transport
}

type azuretls_HTTP3Config struct {
	Enabled		*bool
	ForceHTTP3	*bool
	altSvcCache	*sync.Map
	transport	*azuretls.HTTP3Transport
}

type azuretls_HTTP3Transport struct {
	Transport		*http3.Transport
	transportsPool		*[]*quic.UTransport
	transportsPoolLock	*sync.Mutex
	sess			*azuretls.Session
}

type azuretls_HTTP3Transport struct {
	Transport		*http3.Transport
	transportsPool		*[]*quic.UTransport
	transportsPoolLock	*sync.Mutex
	sess			*azuretls.Session
}

type azuretls_HeaderOrder []*string

type azuretls_HeaderOrder []*string

type azuretls_OrderedHeaders []*[]string

type azuretls_OrderedHeaders []*[]string

type azuretls_PHeader []*string

type azuretls_PHeader []*string

type azuretls_PinHost struct {
	mu	*sync.RWMutex
	m	*map[string]bool
}

type azuretls_PinHost struct {
	mu	*sync.RWMutex
	m	*map[string]bool
}

type azuretls_PinManager struct {
	hosts	*map[string]*azuretls.PinHost
	mu	*sync.RWMutex
}

type azuretls_PinManager struct {
	hosts	*map[string]*azuretls.PinHost
	mu	*sync.RWMutex
}

type azuretls_Request struct {
	HttpRequest		*http.Request
	Response		*azuretls.Response
	Method			*string
	Url			*string
	parsedUrl		*url.URL
	Body			*interface {}
	body			*[]uint8
	PHeader			*azuretls.PHeader
	OrderedHeaders		*azuretls.OrderedHeaders
	Header			*http.Header
	HeaderOrder		*azuretls.HeaderOrder
	proxy			*string
	ua			*string
	browser			*string
	DisableRedirects	*bool
	MaxRedirects		*uint
	NoCookie		*bool
	TimeOut			*time.Duration
	IsRedirected		*bool
	InsecureSkipVerify	*bool
	IgnoreBody		*bool
	Proto			*string
	ForceHTTP1		*bool
	ForceHTTP3		*bool
	ContentLength		*int64
	ctx			*context.Context
	startTime		*time.Time
	deadline		*time.Time
	disableDecompression	*bool
}

type azuretls_Request struct {
	HttpRequest		*http.Request
	Response		*azuretls.Response
	Method			*string
	Url			*string
	parsedUrl		*url.URL
	Body			*interface {}
	body			*[]uint8
	PHeader			*azuretls.PHeader
	OrderedHeaders		*azuretls.OrderedHeaders
	Header			*http.Header
	HeaderOrder		*azuretls.HeaderOrder
	proxy			*string
	ua			*string
	browser			*string
	DisableRedirects	*bool
	MaxRedirects		*uint
	NoCookie		*bool
	TimeOut			*time.Duration
	IsRedirected		*bool
	InsecureSkipVerify	*bool
	IgnoreBody		*bool
	Proto			*string
	ForceHTTP1		*bool
	ForceHTTP3		*bool
	ContentLength		*int64
	ctx			*context.Context
	startTime		*time.Time
	deadline		*time.Time
	disableDecompression	*bool
}

type azuretls_Response struct {
	StatusCode	*int
	Status		*string
	Body		*[]uint8
	RawBody		*io.ReadCloser
	Header		*http.Header
	Cookies		*map[string]string
	Url		*string
	IgnoreBody	*bool
	HttpResponse	*http.Response
	Request		*azuretls.Request
	ContentLength	*int64
	Session		*azuretls.Session
	isHTTP3		*bool
}

type azuretls_Response struct {
	StatusCode	*int
	Status		*string
	Body		*[]uint8
	RawBody		*io.ReadCloser
	Header		*http.Header
	Cookies		*map[string]string
	Url		*string
	IgnoreBody	*bool
	HttpResponse	*http.Response
	Request		*azuretls.Request
	ContentLength	*int64
	Session		*azuretls.Session
	isHTTP3		*bool
}

type azuretls_SOCKS5UDPConn struct {
	controlConn	*net.Conn
	udpConn		*net.UDPConn
	proxyUDPAddr	*net.UDPAddr
	targetAddr	*string
	mu		*sync.RWMutex
	ctx		*context.Context
	cancel		*context.CancelFunc
	bufferPool	*sync.Pool
}

type azuretls_SOCKS5UDPConn struct {
	controlConn	*net.Conn
	udpConn		*net.UDPConn
	proxyUDPAddr	*net.UDPAddr
	targetAddr	*string
	mu		*sync.RWMutex
	ctx		*context.Context
	cancel		*context.CancelFunc
	bufferPool	*sync.Pool
}

type azuretls_Session struct {
	PHeader				*azuretls.PHeader
	OrderedHeaders			*azuretls.OrderedHeaders
	Header				*http.Header
	HeaderOrder			*azuretls.HeaderOrder
	CookieJar			*http.CookieJar
	Browser				*string
	Transport			*http.Transport
	HTTP2Transport			*http2.Transport
	HTTP3Config			*azuretls.HTTP3Config
	GetClientHelloSpec		*func() *tls.ClientHelloSpec
	GetClientHelloSpecHTTP3		*func() *tls.ClientHelloSpec
	Proxy				*string
	H2Proxy				*bool
	ProxyDialer			*interface{}
	Verbose				*bool
	VerbosePath			*string
	VerboseIgnoreHost		*[]string
	VerboseFunc			*func(*azuretls.Request, *azuretls.Response, error)
	MaxRedirects			*uint
	TimeOut				*time.Duration
	PreHook				*func(*azuretls.Request) error
	PreHookWithContext		*func(*azuretls.Context) error
	Callback			*func(*azuretls.Request, *azuretls.Response, error)
	CallbackWithContext		*func(*azuretls.Context)
	ModifyDialer			*func(*net.Dialer) error
	Dial				*func(context.Context, string, string) (net.Conn, error)
	ModifyConfig			*func(*tls.Config) error
	CheckRedirect			*func(*azuretls.Request, []*azuretls.Request) error
	VerifyPins			*bool
	PinManager			*azuretls.PinManager
	InsecureSkipVerify		*bool
	DisableAutoDecompression	*bool
	UserAgent			*string
	HeaderPriority			*http2.PriorityParam
	ProxyHeader			*http.Header
	proxyConnected			*bool
	dump				*bool
	dumpDir				*string
	dumpIgnore			*[]*regexp.Regexp
	logging				*bool
	loggingIgnore			*[]*regexp.Regexp
	ctx				*context.Context
	mu				*sync.Mutex
	closed				*bool
}

type azuretls_Session struct {
	PHeader				*azuretls.PHeader
	OrderedHeaders			*azuretls.OrderedHeaders
	Header				*http.Header
	HeaderOrder			*azuretls.HeaderOrder
	CookieJar			*http.CookieJar
	Browser				*string
	Transport			*http.Transport
	HTTP2Transport			*http2.Transport
	HTTP3Config			*azuretls.HTTP3Config
	GetClientHelloSpec		*func() *tls.ClientHelloSpec
	GetClientHelloSpecHTTP3		*func() *tls.ClientHelloSpec
	Proxy				*string
	H2Proxy				*bool
	ProxyDialer			*interface{}
	Verbose				*bool
	VerbosePath			*string
	VerboseIgnoreHost		*[]string
	VerboseFunc			*func(*azuretls.Request, *azuretls.Response, error)
	MaxRedirects			*uint
	TimeOut				*time.Duration
	PreHook				*func(*azuretls.Request) error
	PreHookWithContext		*func(*azuretls.Context) error
	Callback			*func(*azuretls.Request, *azuretls.Response, error)
	CallbackWithContext		*func(*azuretls.Context)
	ModifyDialer			*func(*net.Dialer) error
	Dial				*func(context.Context, string, string) (net.Conn, error)
	ModifyConfig			*func(*tls.Config) error
	CheckRedirect			*func(*azuretls.Request, []*azuretls.Request) error
	VerifyPins			*bool
	PinManager			*azuretls.PinManager
	InsecureSkipVerify		*bool
	DisableAutoDecompression	*bool
	UserAgent			*string
	HeaderPriority			*http2.PriorityParam
	ProxyHeader			*http.Header
	proxyConnected			*bool
	dump				*bool
	dumpDir				*string
	dumpIgnore			*[]*regexp.Regexp
	logging				*bool
	loggingIgnore			*[]*regexp.Regexp
	ctx				*context.Context
	mu				*sync.Mutex
	closed				*bool
}

type azuretls_brReader struct {
	body	*io.ReadCloser
	zr	*brotli.Reader
	zerr	*error
}

type azuretls_brReader struct {
	body	*io.ReadCloser
	zr	*brotli.Reader
	zerr	*error
}

type azuretls_deflateReader struct {
	body	*io.ReadCloser
	r	*io.ReadCloser
	err	*error
}

type azuretls_deflateReader struct {
	body	*io.ReadCloser
	r	*io.ReadCloser
	err	*error
}

type azuretls_http2Conn struct {
	Conn	*net.Conn
	in	*io.PipeWriter
	out	*io.ReadCloser
}

type azuretls_http2Conn struct {
	Conn	*net.Conn
	in	*io.PipeWriter
	out	*io.ReadCloser
}

type azuretls_orderedHeaders struct {
	key	*string
	values	*[]string
}

type azuretls_orderedHeaders struct {
	key	*string
	values	*[]string
}

type azuretls_proxyDialer struct {
	ProxyChain	*[]*url.URL
	DefaultHeader	*http.Header
	Dialer		*net.Dialer
	DialTLS		*func(string, string) (net.Conn, string, error)
	h2Mu		*sync.Mutex
	H2Conn		*http2.ClientConn
	conn		*net.Conn
	sess		*azuretls.Session
}

type azuretls_proxyDialer struct {
	ProxyChain	*[]*url.URL
	DefaultHeader	*http.Header
	Dialer		*net.Dialer
	DialTLS		*func(string, string) (net.Conn, string, error)
	h2Mu		*sync.Mutex
	H2Conn		*http2.ClientConn
	conn		*net.Conn
	sess		*azuretls.Session
}

type azuretls_socks5PacketConn struct {
	conn		*azuretls.SOCKS5UDPConn
	remoteAddr	*net.UDPAddr
}

type azuretls_socks5PacketConn struct {
	conn		*azuretls.SOCKS5UDPConn
	remoteAddr	*net.UDPAddr
}

type azuretls_zlibDeflateReader struct {
	body	*io.ReadCloser
	zr	*io.ReadCloser
	err	*error
}

type azuretls_zlibDeflateReader struct {
	body	*io.ReadCloser
	zr	*io.ReadCloser
	err	*error
}

type azuretls_zstdReader struct {
	body	*io.ReadCloser
	zr	*zstd.Decoder
	zerr	*error
}

type azuretls_zstdReader struct {
	body	*io.ReadCloser
	zr	*zstd.Decoder
	zerr	*error
}

type base64_CorruptInputError int64

type base64_CorruptInputError int64

type base64_Encoding struct {
	encode		*[64]uint8
	decodeMap	*[256]uint8
	padChar		*int32
	strict		*bool
}

type base64_Encoding struct {
	encode		*[64]uint8
	decodeMap	*[256]uint8
	padChar		*int32
	strict		*bool
}

type big_Int struct {
	neg	*bool
	abs	*interface{}
}

type big_Int struct {
	neg	*bool
	abs	*interface{}
}

type big_Word uint

type big_Word uint

type big_divisor struct {
	bbb	*interface{}
	nbits	*int
	ndigits	*int
}

type big_divisor struct {
	bbb	*interface{}
	nbits	*int
	ndigits	*int
}

type big_nat []*big.Word

type big_nat []*big.Word

type big_stack struct {
	w *[]big.Word
}

type big_stack struct {
	w *[]big.Word
}

type bigmod_Modulus struct {
	nat	*bigmod.Nat
	odd	*bool
	m0inv	*uint
	rr	*bigmod.Nat
}

type bigmod_Modulus struct {
	nat	*bigmod.Nat
	odd	*bool
	m0inv	*uint
	rr	*bigmod.Nat
}

type bigmod_Nat struct {
	limbs *[]uint
}

type bigmod_Nat struct {
	limbs *[]uint
}

type binary_ByteOrder interface {
}

type binary_ByteOrder interface {
}

type binary_bigEndian struct {
}

type binary_bigEndian struct {
}

type binary_littleEndian struct {
}

type binary_littleEndian struct {
}

type bisect_Matcher struct {
	verbose	*bool
	quiet	*bool
	enable	*bool
	list	*[]bisect.cond
	dedup	*interface{}
}

type bisect_Matcher struct {
	verbose	*bool
	quiet	*bool
	enable	*bool
	list	*[]bisect.cond
	dedup	*interface{}
}

type bisect_Writer interface {
}

type bisect_Writer interface {
}

type bisect_cond struct {
	mask	*uint64
	bits	*uint64
	result	*bool
}

type bisect_cond struct {
	mask	*uint64
	bits	*uint64
	result	*bool
}

type bisect_dedup struct {
	recent	*[128][4]uint64
	mu	*sync.Mutex
	m	*map[uint64]bool
}

type bisect_dedup struct {
	recent	*[128][4]uint64
	mu	*sync.Mutex
	m	*map[uint64]bool
}

type bisect_parseError struct {
	text *string
}

type bisect_parseError struct {
	text *string
}

type boring_PrivateKeyECDH struct {
}

type boring_PrivateKeyECDH struct {
}

type boring_PublicKeyECDH struct {
}

type boring_PublicKeyECDH struct {
}

type brotli_Reader struct {
	src				*io.Reader
	buf				*[]uint8
	in				*[]uint8
	state				*int
	loop_counter			*int
	br				*interface{}
	buffer				*struct { u64 uint64; u8 [8]uint8 }
	buffer_length			*uint32
	pos				*int
	max_backward_distance		*int
	max_distance			*int
	ringbuffer_size			*int
	ringbuffer_mask			*int
	dist_rb_idx			*int
	dist_rb				*[4]int
	error_code			*int
	sub_loop_counter		*uint32
	ringbuffer			*[]uint8
	ringbuffer_end			*[]uint8
	htree_command			*[]brotli.huffmanCode
	context_lookup			*[]uint8
	context_map_slice		*[]uint8
	dist_context_map_slice		*[]uint8
	literal_hgroup			*interface{}
	insert_copy_hgroup		*interface{}
	distance_hgroup			*interface{}
	block_type_trees		*[]brotli.huffmanCode
	block_len_trees			*[]brotli.huffmanCode
	trivial_literal_context		*int
	distance_context		*int
	meta_block_remaining_len	*int
	block_length_index		*uint32
	block_length			*[3]uint32
	num_block_types			*[3]uint32
	block_type_rb			*[6]uint32
	distance_postfix_bits		*uint32
	num_direct_distance_codes	*uint32
	distance_postfix_mask		*int
	num_dist_htrees			*uint32
	dist_context_map		*[]uint8
	literal_htree			*[]brotli.huffmanCode
	dist_htree_index		*uint8
	repeat_code_len			*uint32
	prev_code_len			*uint32
	copy_length			*int
	distance_code			*int
	rb_roundtrips			*uint
	partial_pos_out			*uint
	symbol				*uint32
	repeat				*uint32
	space				*uint32
	table				*[32]brotli.huffmanCode
	symbol_lists			*interface{}
	symbols_lists_array		*[720]uint16
	next_symbol			*[32]int
	code_length_code_lengths	*[18]uint8
	code_length_histo		*[16]uint16
	htree_index			*int
	next				*[]brotli.huffmanCode
	context_index			*uint32
	max_run_length_prefix		*uint32
	code				*uint32
	context_map_table		*[646]brotli.huffmanCode
	substate_metablock_header	*int
	substate_tree_group		*int
	substate_context_map		*int
	substate_uncompressed		*int
	substate_huffman		*int
	substate_decode_uint8		*int
	substate_read_block_length	*int
	is_last_metablock		*uint
	is_uncompressed			*uint
	is_metadata			*uint
	should_wrap_ringbuffer		*uint
	canny_ringbuffer_allocation	*uint
	large_window			*bool
	size_nibbles			*uint
	window_bits			*uint32
	new_ringbuffer_size		*int
	num_literal_htrees		*uint32
	context_map			*[]uint8
	context_modes			*[]uint8
	dictionary			*interface{}
	transforms			*interface{}
	trivial_literal_contexts	*[8]uint32
}

type brotli_Reader struct {
	src				*io.Reader
	buf				*[]uint8
	in				*[]uint8
	state				*int
	loop_counter			*int
	br				*interface{}
	buffer				*struct { u64 uint64; u8 [8]uint8 }
	buffer_length			*uint32
	pos				*int
	max_backward_distance		*int
	max_distance			*int
	ringbuffer_size			*int
	ringbuffer_mask			*int
	dist_rb_idx			*int
	dist_rb				*[4]int
	error_code			*int
	sub_loop_counter		*uint32
	ringbuffer			*[]uint8
	ringbuffer_end			*[]uint8
	htree_command			*[]brotli.huffmanCode
	context_lookup			*[]uint8
	context_map_slice		*[]uint8
	dist_context_map_slice		*[]uint8
	literal_hgroup			*interface{}
	insert_copy_hgroup		*interface{}
	distance_hgroup			*interface{}
	block_type_trees		*[]brotli.huffmanCode
	block_len_trees			*[]brotli.huffmanCode
	trivial_literal_context		*int
	distance_context		*int
	meta_block_remaining_len	*int
	block_length_index		*uint32
	block_length			*[3]uint32
	num_block_types			*[3]uint32
	block_type_rb			*[6]uint32
	distance_postfix_bits		*uint32
	num_direct_distance_codes	*uint32
	distance_postfix_mask		*int
	num_dist_htrees			*uint32
	dist_context_map		*[]uint8
	literal_htree			*[]brotli.huffmanCode
	dist_htree_index		*uint8
	repeat_code_len			*uint32
	prev_code_len			*uint32
	copy_length			*int
	distance_code			*int
	rb_roundtrips			*uint
	partial_pos_out			*uint
	symbol				*uint32
	repeat				*uint32
	space				*uint32
	table				*[32]brotli.huffmanCode
	symbol_lists			*interface{}
	symbols_lists_array		*[720]uint16
	next_symbol			*[32]int
	code_length_code_lengths	*[18]uint8
	code_length_histo		*[16]uint16
	htree_index			*int
	next				*[]brotli.huffmanCode
	context_index			*uint32
	max_run_length_prefix		*uint32
	code				*uint32
	context_map_table		*[646]brotli.huffmanCode
	substate_metablock_header	*int
	substate_tree_group		*int
	substate_context_map		*int
	substate_uncompressed		*int
	substate_huffman		*int
	substate_decode_uint8		*int
	substate_read_block_length	*int
	is_last_metablock		*uint
	is_uncompressed			*uint
	is_metadata			*uint
	should_wrap_ringbuffer		*uint
	canny_ringbuffer_allocation	*uint
	large_window			*bool
	size_nibbles			*uint
	window_bits			*uint32
	new_ringbuffer_size		*int
	num_literal_htrees		*uint32
	context_map			*[]uint8
	context_modes			*[]uint8
	dictionary			*interface{}
	transforms			*interface{}
	trivial_literal_contexts	*[8]uint32
}

type brotli_bitReader struct {
	val_		*uint64
	bit_pos_	*uint32
	input		*[]uint8
	input_len	*uint
	byte_pos	*uint
}

type brotli_bitReader struct {
	val_		*uint64
	bit_pos_	*uint32
	input		*[]uint8
	input_len	*uint
	byte_pos	*uint
}

type brotli_decodeError int

type brotli_decodeError int

type brotli_dictionary struct {
	size_bits_by_length	*[32]uint8
	offsets_by_length	*[32]uint32
	data_size		*uint
	data			*[]uint8
}

type brotli_dictionary struct {
	size_bits_by_length	*[32]uint8
	offsets_by_length	*[32]uint32
	data_size		*uint
	data			*[]uint8
}

type brotli_huffmanCode struct {
	bits	*uint8
	value	*uint16
}

type brotli_huffmanCode struct {
	bits	*uint8
	value	*uint16
}

type brotli_huffmanTreeGroup struct {
	htrees		*[][]brotli.huffmanCode
	codes		*[]brotli.huffmanCode
	alphabet_size	*uint16
	max_symbol	*uint16
	num_htrees	*uint16
}

type brotli_huffmanTreeGroup struct {
	htrees		*[][]brotli.huffmanCode
	codes		*[]brotli.huffmanCode
	alphabet_size	*uint16
	max_symbol	*uint16
	num_htrees	*uint16
}

type brotli_symbolList struct {
	storage	*[]uint16
	offset	*int
}

type brotli_symbolList struct {
	storage	*[]uint16
	offset	*int
}

type brotli_transforms struct {
	prefix_suffix_size	*uint16
	prefix_suffix		*[]uint8
	prefix_suffix_map	*[]uint16
	num_transforms		*uint32
	transforms		*[]uint8
	params			*[]uint8
	cutOffTransforms	*[10]int16
}

type brotli_transforms struct {
	prefix_suffix_size	*uint16
	prefix_suffix		*[]uint8
	prefix_suffix_map	*[]uint16
	num_transforms		*uint32
	transforms		*[]uint8
	params			*[]uint8
	cutOffTransforms	*[10]int16
}

type buffer_Buffer []*uint8

type buffer_Buffer []*uint8

type cgroup_stringError string

type cgroup_stringError string

type chacha20poly1305_chacha20poly1305 struct {
	key *[32]uint8
}

type chacha20poly1305_chacha20poly1305 struct {
	key *[32]uint8
}

type chacha20poly1305_chacha20poly1305 struct {
	key *[32]uint8
}

type chacha20poly1305_chacha20poly1305 struct {
	key *[32]uint8
}

type chacha8rand_State struct {
	buf	*[32]uint64
	seed	*[4]uint64
	i	*uint32
	n	*uint32
	c	*uint32
}

type chacha8rand_State struct {
	buf	*[32]uint64
	seed	*[4]uint64
	i	*uint32
	n	*uint32
	c	*uint32
}

type cipher_AEAD interface {
}

type cipher_AEAD interface {
}

type cipher_Block interface {
}

type cipher_Block interface {
}

type cipher_BlockMode interface {
}

type cipher_BlockMode interface {
}

type cipher_Stream interface {
}

type cipher_Stream interface {
}

type cipher_aesCtrWrapper struct {
	c *aes.CTR
}

type cipher_aesCtrWrapper struct {
	c *aes.CTR
}

type cipher_cbc struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_cbc struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_cbcDecAble interface {
}

type cipher_cbcDecAble interface {
}

type cipher_cbcDecrypter struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_cbcDecrypter struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_cbcEncAble interface {
}

type cipher_cbcEncAble interface {
}

type cipher_cbcEncrypter struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_cbcEncrypter struct {
	b		*cipher.Block
	blockSize	*int
	iv		*[]uint8
	tmp		*[]uint8
}

type cipher_ctr struct {
	b	*cipher.Block
	ctr	*[]uint8
	out	*[]uint8
	outUsed	*int
}

type cipher_ctr struct {
	b	*cipher.Block
	ctr	*[]uint8
	out	*[]uint8
	outUsed	*int
}

type cipher_ctrAble interface {
}

type cipher_ctrAble interface {
}

type cipher_gcmAble interface {
}

type cipher_gcmAble interface {
}

type cipher_gcmFallback struct {
	cipher		*cipher.Block
	nonceSize	*int
	tagSize		*int
}

type cipher_gcmFallback struct {
	cipher		*cipher.Block
	nonceSize	*int
	tagSize		*int
}

type clienthellod_CRYPTO struct {
	Offset	*uint64
	Length	*uint64
	Data	*[]uint8
}

type clienthellod_CRYPTO struct {
	Offset	*uint64
	Length	*uint64
	Data	*[]uint8
}

type clienthellod_Frame interface {
}

type clienthellod_Frame interface {
}

type clienthellod_PADDING struct {
	Length *uint64
}

type clienthellod_PADDING struct {
	Length *uint64
}

type clienthellod_PING struct {
}

type clienthellod_PING struct {
}

type color_Attribute int

type color_Attribute int

type color_Color struct {
	params	*[]color.Attribute
	noColor	*bool
}

type color_Color struct {
	params	*[]color.Attribute
	noColor	*bool
}

type common_Poly [256]*int16

type common_Poly [256]*int16

type congestion_Bandwidth uint64

type congestion_Bandwidth uint64

type congestion_Clock interface {
}

type congestion_Clock interface {
}

type congestion_Cubic struct {
	clock				*congestion.Clock
	numConnections			*int
	epoch				*time.Time
	lastMaxCongestionWindow		*protocol.ByteCount
	ackedBytesCount			*protocol.ByteCount
	estimatedTCPcongestionWindow	*protocol.ByteCount
	originPointCongestionWindow	*protocol.ByteCount
	timeToOriginPoint		*uint32
	lastTargetCongestionWindow	*protocol.ByteCount
}

type congestion_Cubic struct {
	clock				*congestion.Clock
	numConnections			*int
	epoch				*time.Time
	lastMaxCongestionWindow		*protocol.ByteCount
	ackedBytesCount			*protocol.ByteCount
	estimatedTCPcongestionWindow	*protocol.ByteCount
	originPointCongestionWindow	*protocol.ByteCount
	timeToOriginPoint		*uint32
	lastTargetCongestionWindow	*protocol.ByteCount
}

type congestion_DefaultClock struct {
}

type congestion_DefaultClock struct {
}

type congestion_HybridSlowStart struct {
	endPacketNumber		*protocol.PacketNumber
	lastSentPacketNumber	*protocol.PacketNumber
	started			*bool
	currentMinRTT		*time.Duration
	rttSampleCount		*uint32
	hystartFound		*bool
}

type congestion_HybridSlowStart struct {
	endPacketNumber		*protocol.PacketNumber
	lastSentPacketNumber	*protocol.PacketNumber
	started			*bool
	currentMinRTT		*time.Duration
	rttSampleCount		*uint32
	hystartFound		*bool
}

type congestion_SendAlgorithmWithDebugInfos interface {
}

type congestion_SendAlgorithmWithDebugInfos interface {
}

type congestion_cubicSender struct {
	hybridSlowStart			*congestion.HybridSlowStart
	rttStats			*utils.RTTStats
	connStats			*utils.ConnectionStats
	cubic				*congestion.Cubic
	pacer				*interface{}
	clock				*congestion.Clock
	reno				*bool
	largestSentPacketNumber		*protocol.PacketNumber
	largestAckedPacketNumber	*protocol.PacketNumber
	largestSentAtLastCutback	*protocol.PacketNumber
	lastCutbackExitedSlowstart	*bool
	congestionWindow		*protocol.ByteCount
	slowStartThreshold		*protocol.ByteCount
	numAckedPackets			*uint64
	initialCongestionWindow		*protocol.ByteCount
	initialMaxCongestionWindow	*protocol.ByteCount
	maxDatagramSize			*protocol.ByteCount
	lastState			*logging.CongestionState
	tracer				*logging.ConnectionTracer
}

type congestion_cubicSender struct {
	hybridSlowStart			*congestion.HybridSlowStart
	rttStats			*utils.RTTStats
	connStats			*utils.ConnectionStats
	cubic				*congestion.Cubic
	pacer				*interface{}
	clock				*congestion.Clock
	reno				*bool
	largestSentPacketNumber		*protocol.PacketNumber
	largestAckedPacketNumber	*protocol.PacketNumber
	largestSentAtLastCutback	*protocol.PacketNumber
	lastCutbackExitedSlowstart	*bool
	congestionWindow		*protocol.ByteCount
	slowStartThreshold		*protocol.ByteCount
	numAckedPackets			*uint64
	initialCongestionWindow		*protocol.ByteCount
	initialMaxCongestionWindow	*protocol.ByteCount
	maxDatagramSize			*protocol.ByteCount
	lastState			*logging.CongestionState
	tracer				*logging.ConnectionTracer
}

type congestion_pacer struct {
	budgetAtLastSent	*protocol.ByteCount
	maxDatagramSize		*protocol.ByteCount
	lastSentTime		*time.Time
	adjustedBandwidth	*func() uint64
}

type congestion_pacer struct {
	budgetAtLastSent	*protocol.ByteCount
	maxDatagramSize		*protocol.ByteCount
	lastSentTime		*time.Time
	adjustedBandwidth	*func() uint64
}

type cookiejar_Jar struct {
	psList		*cookiejar.PublicSuffixList
	mu		*sync.Mutex
	entries		*map[string]map[string]cookiejar.entry
	nextSeqNum	*uint64
}

type cookiejar_Jar struct {
	psList		*cookiejar.PublicSuffixList
	mu		*sync.Mutex
	entries		*map[string]map[string]cookiejar.entry
	nextSeqNum	*uint64
}

type cookiejar_PublicSuffixList interface {
}

type cookiejar_PublicSuffixList interface {
}

type cookiejar_entry struct {
	Name		*string
	Value		*string
	Domain		*string
	Path		*string
	SameSite	*string
	Secure		*bool
	HttpOnly	*bool
	Persistent	*bool
	HostOnly	*bool
	Expires		*time.Time
	Creation	*time.Time
	LastAccess	*time.Time
	seqNum		*uint64
}

type cookiejar_entry struct {
	Name		*string
	Value		*string
	Domain		*string
	Path		*string
	SameSite	*string
	Secure		*bool
	HttpOnly	*bool
	Persistent	*bool
	HostOnly	*bool
	Expires		*time.Time
	Creation	*time.Time
	LastAccess	*time.Time
	seqNum		*uint64
}

type cpu_option struct {
	Name		*string
	Feature		*bool
	Specified	*bool
	Enable		*bool
}

type cpu_option struct {
	Name		*string
	Feature		*bool
	Specified	*bool
	Enable		*bool
}

type cpu_option struct {
	Name		*string
	Feature		*bool
	Specified	*bool
	Enable		*bool
	Required	*bool
}

type cpu_option struct {
	Name		*string
	Feature		*bool
	Specified	*bool
	Enable		*bool
	Required	*bool
}

type crc32_Table [256]*uint32

type crc32_Table [256]*uint32

type crc32_slicing8Table [8]*crc32.Table

type crc32_slicing8Table [8]*crc32.Table

type cryptobyte_BuildError struct {
	Err *error
}

type cryptobyte_BuildError struct {
	Err *error
}

type cryptobyte_BuildError struct {
	Err *error
}

type cryptobyte_BuildError struct {
	Err *error
}

type cryptobyte_Builder struct {
	err		*error
	result		*[]uint8
	fixedSize	*bool
	child		*cryptobyte.Builder
	offset		*int
	pendingLenLen	*int
	pendingIsASN1	*bool
	inContinuation	*bool
}

type cryptobyte_Builder struct {
	err		*error
	result		*[]uint8
	fixedSize	*bool
	child		*cryptobyte.Builder
	offset		*int
	pendingLenLen	*int
	pendingIsASN1	*bool
	inContinuation	*bool
}

type cryptobyte_Builder struct {
	err		*error
	result		*[]uint8
	fixedSize	*bool
	child		*cryptobyte.Builder
	offset		*int
	pendingLenLen	*int
	pendingIsASN1	*bool
	inContinuation	*bool
}

type cryptobyte_Builder struct {
	err		*error
	result		*[]uint8
	fixedSize	*bool
	child		*cryptobyte.Builder
	offset		*int
	pendingLenLen	*int
	pendingIsASN1	*bool
	inContinuation	*bool
}

type des_KeySizeError int

type des_KeySizeError int

type des_desCipher struct {
	subkeys *[16]uint64
}

type des_desCipher struct {
	subkeys *[16]uint64
}

type des_tripleDESCipher struct {
	cipher1	*interface{}
	cipher2	*interface{}
	cipher3	*interface{}
}

type des_tripleDESCipher struct {
	cipher1	*interface{}
	cipher2	*interface{}
	cipher3	*interface{}
}

type dilithium_Poly [256]*uint32

type dilithium_Poly [256]*uint32

type dnsmessage_AAAAResource struct {
	AAAA *[16]uint8
}

type dnsmessage_AAAAResource struct {
	AAAA *[16]uint8
}

type dnsmessage_AResource struct {
	A *[4]uint8
}

type dnsmessage_AResource struct {
	A *[4]uint8
}

type dnsmessage_Class uint16

type dnsmessage_Class uint16

type dnsmessage_Parser struct {
	msg		*[]uint8
	header		*interface{}
	section		*interface{}
	off		*int
	index		*int
	resHeaderValid	*bool
	resHeaderOffset	*int
	resHeaderType	*dnsmessage.Type
	resHeaderLength	*uint16
}

type dnsmessage_Parser struct {
	msg		*[]uint8
	header		*interface{}
	section		*interface{}
	off		*int
	index		*int
	resHeaderValid	*bool
	resHeaderOffset	*int
	resHeaderType	*dnsmessage.Type
	resHeaderLength	*uint16
}

type dnsmessage_RCode uint16

type dnsmessage_RCode uint16

type dnsmessage_Type uint16

type dnsmessage_Type uint16

type dnsmessage_header struct {
	id		*uint16
	bits		*uint16
	questions	*uint16
	answers		*uint16
	authorities	*uint16
	additionals	*uint16
}

type dnsmessage_header struct {
	id		*uint16
	bits		*uint16
	questions	*uint16
	answers		*uint16
	authorities	*uint16
	additionals	*uint16
}

type dnsmessage_nestedError struct {
	s	*string
	err	*error
}

type dnsmessage_nestedError struct {
	s	*string
	err	*error
}

type dnsmessage_section uint8

type dnsmessage_section uint8

type drbg_Counter struct {
	c		*aes.CTR
	reseedCounter	*uint64
}

type drbg_Counter struct {
	c		*aes.CTR
	reseedCounter	*uint64
}

type drbg_DefaultReader interface {
}

type drbg_DefaultReader interface {
}

type dsa_Parameters struct {
	P	*big.Int
	Q	*big.Int
	G	*big.Int
}

type dsa_Parameters struct {
	P	*big.Int
	Q	*big.Int
	G	*big.Int
}

type dsa_PublicKey struct {
	Parameters	*dsa.Parameters
	Y		*big.Int
}

type dsa_PublicKey struct {
	Parameters	*dsa.Parameters
	Y		*big.Int
}

type ecdh_Curve interface {
}

type ecdh_Curve interface {
}

type ecdh_PrivateKey struct {
	curve		*ecdh.Curve
	privateKey	*[]uint8
	publicKey	*ecdh.PublicKey
	boring		*boring.PrivateKeyECDH
	fips		*ecdh.PrivateKey
}

type ecdh_PrivateKey struct {
	pub	*ecdh.PublicKey
	d	*[]uint8
}

type ecdh_PrivateKey struct {
	pub	*ecdh.PublicKey
	d	*[]uint8
}

type ecdh_PrivateKey struct {
	curve		*ecdh.Curve
	privateKey	*[]uint8
	publicKey	*ecdh.PublicKey
	boring		*boring.PrivateKeyECDH
	fips		*ecdh.PrivateKey
}

type ecdh_PublicKey struct {
	curve		*ecdh.Curve
	publicKey	*[]uint8
	boring		*boring.PublicKeyECDH
	fips		*ecdh.PublicKey
}

type ecdh_PublicKey struct {
	curve	*interface{}
	q	*[]uint8
}

type ecdh_PublicKey struct {
	curve		*ecdh.Curve
	publicKey	*[]uint8
	boring		*boring.PublicKeyECDH
	fips		*ecdh.PublicKey
}

type ecdh_PublicKey struct {
	curve	*interface{}
	q	*[]uint8
}

type ecdh_curveID string

type ecdh_curveID string

type ecdh_nistCurve struct {
	name		*string
	generate	*func(io.Reader) (*ecdh.PrivateKey, error)
	newPrivateKey	*func([]uint8) (*ecdh.PrivateKey, error)
	newPublicKey	*func([]uint8) (*ecdh.PublicKey, error)
	sharedSecret	*func(*ecdh.PrivateKey, *ecdh.PublicKey) ([]uint8, error)
}

type ecdh_nistCurve struct {
	name		*string
	generate	*func(io.Reader) (*ecdh.PrivateKey, error)
	newPrivateKey	*func([]uint8) (*ecdh.PrivateKey, error)
	newPublicKey	*func([]uint8) (*ecdh.PublicKey, error)
	sharedSecret	*func(*ecdh.PrivateKey, *ecdh.PublicKey) ([]uint8, error)
}

type ecdh_x25519Curve struct {
}

type ecdh_x25519Curve struct {
}

type ecdsa_PrivateKey struct {
	pub	*ecdsa.PublicKey
	d	*[]uint8
}

type ecdsa_PrivateKey struct {
	PublicKey	*ecdsa.PublicKey
	D		*big.Int
}

type ecdsa_PrivateKey struct {
	PublicKey	*ecdsa.PublicKey
	D		*big.Int
}

type ecdsa_PrivateKey struct {
	pub	*ecdsa.PublicKey
	d	*[]uint8
}

type ecdsa_PublicKey struct {
	curve	*interface{}
	q	*[]uint8
}

type ecdsa_PublicKey struct {
	Curve	*elliptic.Curve
	X	*big.Int
	Y	*big.Int
}

type ecdsa_PublicKey struct {
	Curve	*elliptic.Curve
	X	*big.Int
	Y	*big.Int
}

type ecdsa_PublicKey struct {
	curve	*interface{}
	q	*[]uint8
}

type ecdsa_Signature struct {
	R	*[]uint8
	S	*[]uint8
}

type ecdsa_Signature struct {
	R	*[]uint8
	S	*[]uint8
}

type ecdsa_blockAlignedPersonalizationString []*[]uint8

type ecdsa_blockAlignedPersonalizationString []*[]uint8

type ecdsa_curveID string

type ecdsa_curveID string

type ecdsa_hmacDRBG struct {
	newHMAC		*func([]uint8) *hmac.HMAC
	hK		*hmac.HMAC
	V		*[]uint8
	reseedCounter	*uint64
}

type ecdsa_hmacDRBG struct {
	newHMAC		*func([]uint8) *hmac.HMAC
	hK		*hmac.HMAC
	V		*[]uint8
	reseedCounter	*uint64
}

type ecdsa_personalizationString interface {
}

type ecdsa_personalizationString interface {
}

type ecdsa_plainPersonalizationString []*uint8

type ecdsa_plainPersonalizationString []*uint8

type ed25519_PrivateKey []*uint8

type ed25519_PrivateKey []*uint8

type ed25519_PublicKey []*uint8

type ed25519_PublicKey []*uint8

type ed25519_PublicKey []*uint8

type ed25519_PublicKey []*uint8

type ed25519_scheme struct {
}

type ed25519_scheme struct {
}

type ed448_PublicKey []*uint8

type ed448_PublicKey []*uint8

type ed448_scheme struct {
}

type ed448_scheme struct {
}

type eddilithium2_PublicKey struct {
	e	*ed25519.PublicKey
	d	*mode2.PublicKey
}

type eddilithium2_PublicKey struct {
	e	*ed25519.PublicKey
	d	*mode2.PublicKey
}

type eddilithium2_scheme struct {
}

type eddilithium2_scheme struct {
}

type eddilithium3_PublicKey struct {
	e	*ed448.PublicKey
	d	*mode3.PublicKey
}

type eddilithium3_PublicKey struct {
	e	*ed448.PublicKey
	d	*mode3.PublicKey
}

type eddilithium3_scheme struct {
}

type eddilithium3_scheme struct {
}

type edwards25519_Point struct {
	_	*interface{}
	x	*field.Element
	y	*field.Element
	z	*field.Element
	t	*field.Element
}

type edwards25519_Point struct {
	_	*interface{}
	x	*field.Element
	y	*field.Element
	z	*field.Element
	t	*field.Element
}

type edwards25519_Scalar struct {
	s *interface{}
}

type edwards25519_Scalar struct {
	s *interface{}
}

type edwards25519_fiatScalarMontgomeryDomainFieldElement [4]*uint64

type edwards25519_fiatScalarMontgomeryDomainFieldElement [4]*uint64

type edwards25519_incomparable [0]*func()

type edwards25519_incomparable [0]*func()

type elliptic_Curve interface {
}

type elliptic_Curve interface {
}

type elliptic_CurveParams struct {
	P	*big.Int
	N	*big.Int
	B	*big.Int
	Gx	*big.Int
	Gy	*big.Int
	BitSize	*int
	Name	*string
}

type elliptic_CurveParams struct {
	P	*big.Int
	N	*big.Int
	B	*big.Int
	Gx	*big.Int
	Gy	*big.Int
	BitSize	*int
	Name	*string
}

type elliptic_unmarshaler interface {
}

type elliptic_unmarshaler interface {
}

type exec_Cmd struct {
	Path			*string
	Args			*[]string
	Env			*[]string
	Dir			*string
	Stdin			*io.Reader
	Stdout			*io.Writer
	Stderr			*io.Writer
	ExtraFiles		*[]*os.File
	SysProcAttr		*syscall.SysProcAttr
	Process			*os.Process
	ProcessState		*os.ProcessState
	ctx			*context.Context
	Err			*error
	Cancel			*func() error
	WaitDelay		*time.Duration
	childIOFiles		*[]io.Closer
	parentIOPipes		*[]io.Closer
	goroutine		*[]func() error
	goroutineErr		*<-chan error
	ctxResult		*<-chan exec.ctxResult
	createdByStack		*[]uint8
	lookPathErr		*error
	cachedLookExtensions	*struct { in string; out string }
}

type exec_Cmd struct {
	Path			*string
	Args			*[]string
	Env			*[]string
	Dir			*string
	Stdin			*io.Reader
	Stdout			*io.Writer
	Stderr			*io.Writer
	ExtraFiles		*[]*os.File
	SysProcAttr		*syscall.SysProcAttr
	Process			*os.Process
	ProcessState		*os.ProcessState
	ctx			*context.Context
	Err			*error
	Cancel			*func() error
	WaitDelay		*time.Duration
	childIOFiles		*[]io.Closer
	parentIOPipes		*[]io.Closer
	goroutine		*[]func() error
	goroutineErr		*<-chan error
	ctxResult		*<-chan exec.ctxResult
	createdByStack		*[]uint8
	lookPathErr		*error
	cachedLookExtensions	*struct { in string; out string }
}

type exec_Error struct {
	Name	*string
	Err	*error
}

type exec_Error struct {
	Name	*string
	Err	*error
}

type exec_ExitError struct {
	ProcessState	*os.ProcessState
	Stderr		*[]uint8
}

type exec_ExitError struct {
	ProcessState	*os.ProcessState
	Stderr		*[]uint8
}

type exec_ctxResult struct {
	err	*error
	timer	*time.Timer
}

type exec_ctxResult struct {
	err	*error
	timer	*time.Timer
}

type exec_goroutineStatus struct {
	running		*int
	firstErr	*error
}

type exec_goroutineStatus struct {
	running		*int
	firstErr	*error
}

type exec_wrappedError struct {
	prefix	*string
	err	*error
}

type exec_wrappedError struct {
	prefix	*string
	err	*error
}

type fiat_P224Element struct {
	x *interface{}
}

type fiat_P224Element struct {
	x *interface{}
}

type fiat_P256Element struct {
	x *interface{}
}

type fiat_P256Element struct {
	x *interface{}
}

type fiat_P384Element struct {
	x *interface{}
}

type fiat_P384Element struct {
	x *interface{}
}

type fiat_P521Element struct {
	x *interface{}
}

type fiat_P521Element struct {
	x *interface{}
}

type fiat_p224MontgomeryDomainFieldElement [4]*uint64

type fiat_p224MontgomeryDomainFieldElement [4]*uint64

type fiat_p256MontgomeryDomainFieldElement [4]*uint64

type fiat_p256MontgomeryDomainFieldElement [4]*uint64

type fiat_p384MontgomeryDomainFieldElement [6]*uint64

type fiat_p384MontgomeryDomainFieldElement [6]*uint64

type fiat_p521MontgomeryDomainFieldElement [9]*uint64

type fiat_p521MontgomeryDomainFieldElement [9]*uint64

type field_Element struct {
	l0	*uint64
	l1	*uint64
	l2	*uint64
	l3	*uint64
	l4	*uint64
}

type field_Element struct {
	l0	*uint64
	l1	*uint64
	l2	*uint64
	l3	*uint64
	l4	*uint64
}

type flate_CorruptInputError int64

type flate_CorruptInputError int64

type flate_InternalError string

type flate_InternalError string

type flate_Reader interface {
}

type flate_Reader interface {
}

type flate_Resetter interface {
}

type flate_Resetter interface {
}

type flate_byFreq []*interface{}

type flate_byFreq []*interface{}

type flate_byLiteral []*interface{}

type flate_byLiteral []*interface{}

type flate_decompressor struct {
	r		*flate.Reader
	rBuf		*bufio.Reader
	roffset		*int64
	b		*uint32
	nb		*uint
	h1		*interface{}
	h2		*interface{}
	bits		*[316]int
	codebits	*[19]int
	dict		*interface{}
	buf		*[4]uint8
	step		*func(*flate.decompressor)
	stepState	*int
	final		*bool
	err		*error
	toRead		*[]uint8
	hl		*interface{}
	hd		*interface{}
	copyLen		*int
	copyDist	*int
}

type flate_decompressor struct {
	r		*flate.Reader
	rBuf		*bufio.Reader
	roffset		*int64
	b		*uint32
	nb		*uint
	h1		*interface{}
	h2		*interface{}
	bits		*[316]int
	codebits	*[19]int
	dict		*interface{}
	buf		*[4]uint8
	step		*func(*flate.decompressor)
	stepState	*int
	final		*bool
	err		*error
	toRead		*[]uint8
	hl		*interface{}
	hd		*interface{}
	copyLen		*int
	copyDist	*int
}

type flate_dictDecoder struct {
	hist	*[]uint8
	wrPos	*int
	rdPos	*int
	full	*bool
}

type flate_dictDecoder struct {
	hist	*[]uint8
	wrPos	*int
	rdPos	*int
	full	*bool
}

type flate_hcode struct {
	code	*uint16
	len	*uint16
}

type flate_hcode struct {
	code	*uint16
	len	*uint16
}

type flate_huffmanDecoder struct {
	min		*int
	chunks		*[512]uint32
	links		*[][]uint32
	linkMask	*uint32
}

type flate_huffmanDecoder struct {
	min		*int
	chunks		*[512]uint32
	links		*[][]uint32
	linkMask	*uint32
}

type flate_huffmanEncoder struct {
	codes		*[]flate.hcode
	freqcache	*[]flate.literalNode
	bitCount	*[17]int32
	lns		*interface{}
	lfs		*interface{}
}

type flate_huffmanEncoder struct {
	codes		*[]flate.hcode
	freqcache	*[]flate.literalNode
	bitCount	*[17]int32
	lns		*interface{}
	lfs		*interface{}
}

type flate_literalNode struct {
	literal	*uint16
	freq	*int32
}

type flate_literalNode struct {
	literal	*uint16
	freq	*int32
}

type flowcontrol_ConnectionFlowController interface {
}

type flowcontrol_ConnectionFlowController interface {
}

type flowcontrol_StreamFlowController interface {
}

type flowcontrol_StreamFlowController interface {
}

type flowcontrol_baseFlowController struct {
	bytesSent		*protocol.ByteCount
	sendWindow		*protocol.ByteCount
	lastBlockedAt		*protocol.ByteCount
	mutex			*sync.Mutex
	bytesRead		*protocol.ByteCount
	highestReceived		*protocol.ByteCount
	receiveWindow		*protocol.ByteCount
	receiveWindowSize	*protocol.ByteCount
	maxReceiveWindowSize	*protocol.ByteCount
	allowWindowIncrease	*func(protocol.ByteCount) bool
	epochStartTime		*time.Time
	epochStartOffset	*protocol.ByteCount
	rttStats		*utils.RTTStats
	logger			*utils.Logger
}

type flowcontrol_baseFlowController struct {
	bytesSent		*protocol.ByteCount
	sendWindow		*protocol.ByteCount
	lastBlockedAt		*protocol.ByteCount
	mutex			*sync.Mutex
	bytesRead		*protocol.ByteCount
	highestReceived		*protocol.ByteCount
	receiveWindow		*protocol.ByteCount
	receiveWindowSize	*protocol.ByteCount
	maxReceiveWindowSize	*protocol.ByteCount
	allowWindowIncrease	*func(protocol.ByteCount) bool
	epochStartTime		*time.Time
	epochStartOffset	*protocol.ByteCount
	rttStats		*utils.RTTStats
	logger			*utils.Logger
}

type flowcontrol_connectionFlowController struct {
	baseFlowController *interface{}
}

type flowcontrol_connectionFlowController struct {
	baseFlowController *interface{}
}

type flowcontrol_connectionFlowControllerI interface {
}

type flowcontrol_connectionFlowControllerI interface {
}

type flowcontrol_streamFlowController struct {
	baseFlowController	*interface{}
	streamID		*protocol.StreamID
	connection		*interface{}
	receivedFinalOffset	*bool
}

type flowcontrol_streamFlowController struct {
	baseFlowController	*interface{}
	streamID		*protocol.StreamID
	connection		*interface{}
	receivedFinalOffset	*bool
}

type fmtsort_KeyValue struct {
	Key	*reflect.Value
	Value	*reflect.Value
}

type fmtsort_KeyValue struct {
	Key	*reflect.Value
	Value	*reflect.Value
}

type fp448_Elt [56]*uint8

type fp448_Elt [56]*uint8

type fs_DirEntry interface {
}

type fs_DirEntry interface {
}

type fs_FileInfo interface {
}

type fs_FileInfo interface {
}

type fs_FileMode uint32

type fs_FileMode uint32

type fs_PathError struct {
	Op	*string
	Path	*string
	Err	*error
}

type fs_PathError struct {
	Op	*string
	Path	*string
	Err	*error
}

type fse_Scratch struct {
	count		*[256]uint32
	norm		*[256]int16
	br		*interface{}
	bits		*interface{}
	bw		*interface{}
	ct		*interface{}
	decTable	*[]fse.decSymbol
	maxCount	*int
	Out		*[]uint8
	DecompressLimit	*int
	symbolLen	*uint16
	actualTableLog	*uint8
	zeroBits	*bool
	clearCount	*bool
	MaxSymbolValue	*uint8
	TableLog	*uint8
}

type fse_Scratch struct {
	count		*[256]uint32
	norm		*[256]int16
	br		*interface{}
	bits		*interface{}
	bw		*interface{}
	ct		*interface{}
	decTable	*[]fse.decSymbol
	maxCount	*int
	Out		*[]uint8
	DecompressLimit	*int
	symbolLen	*uint16
	actualTableLog	*uint8
	zeroBits	*bool
	clearCount	*bool
	MaxSymbolValue	*uint8
	TableLog	*uint8
}

type fse_bitReader struct {
	in		*[]uint8
	off		*uint
	value		*uint64
	bitsRead	*uint8
}

type fse_bitReader struct {
	in		*[]uint8
	off		*uint
	value		*uint64
	bitsRead	*uint8
}

type fse_bitWriter struct {
	bitContainer	*uint64
	nBits		*uint8
	out		*[]uint8
}

type fse_bitWriter struct {
	bitContainer	*uint64
	nBits		*uint8
	out		*[]uint8
}

type fse_byteReader struct {
	b	*[]uint8
	off	*int
}

type fse_byteReader struct {
	b	*[]uint8
	off	*int
}

type fse_cTable struct {
	tableSymbol	*[]uint8
	stateTable	*[]uint16
	symbolTT	*[]fse.symbolTransform
}

type fse_cTable struct {
	tableSymbol	*[]uint8
	stateTable	*[]uint16
	symbolTT	*[]fse.symbolTransform
}

type fse_decSymbol struct {
	newState	*uint16
	symbol		*uint8
	nbBits		*uint8
}

type fse_decSymbol struct {
	newState	*uint16
	symbol		*uint8
	nbBits		*uint8
}

type fse_symbolTransform struct {
	deltaFindState	*int32
	deltaNbBits	*uint32
}

type fse_symbolTransform struct {
	deltaFindState	*int32
	deltaNbBits	*uint32
}

type gcm_GCM struct {
	cipher		*aes.Block
	nonceSize	*int
	tagSize		*int
	gcmPlatformData	*interface{}
}

type gcm_GCM struct {
	cipher		*aes.Block
	nonceSize	*int
	tagSize		*int
	gcmPlatformData	*interface{}
}

type gcm_GCMForTLS12 struct {
	g	*gcm.GCM
	next	*uint64
}

type gcm_GCMForTLS12 struct {
	g	*gcm.GCM
	next	*uint64
}

type gcm_GCMForTLS13 struct {
	g	*gcm.GCM
	ready	*bool
	mask	*uint64
	next	*uint64
}

type gcm_GCMForTLS13 struct {
	g	*gcm.GCM
	ready	*bool
	mask	*uint64
	next	*uint64
}

type gcm_gcmPlatformData struct {
}

type gcm_gcmPlatformData struct {
}

type godebug_Setting struct {
	name	*string
	once	*sync.Once
	setting	*interface{}
}

type godebug_Setting struct {
	name	*string
	once	*sync.Once
	setting	*interface{}
}

type godebug_runtimeStderr struct {
}

type godebug_runtimeStderr struct {
}

type godebug_setting struct {
	value		*interface{}
	nonDefaultOnce	*sync.Once
	nonDefault	*atomic.Uint64
	info		*godebugs.Info
}

type godebug_setting struct {
	value		*interface{}
	nonDefaultOnce	*sync.Once
	nonDefault	*atomic.Uint64
	info		*godebugs.Info
}

type godebug_value struct {
	text	*string
	bisect	*bisect.Matcher
}

type godebug_value struct {
	text	*string
	bisect	*bisect.Matcher
}

type godebugs_Info struct {
	Name		*string
	Package		*string
	Changed		*int
	Old		*string
	Opaque		*bool
	Immutable	*bool
}

type godebugs_Info struct {
	Name		*string
	Package		*string
	Changed		*int
	Old		*string
	Opaque		*bool
	Immutable	*bool
}

type goldilocks_Point struct {
	x	*fp448.Elt
	y	*fp448.Elt
	z	*fp448.Elt
	ta	*fp448.Elt
	tb	*fp448.Elt
}

type goldilocks_Point struct {
	x	*fp448.Elt
	y	*fp448.Elt
	z	*fp448.Elt
	ta	*fp448.Elt
	tb	*fp448.Elt
}

type goldilocks_twistPoint struct {
	x	*fp448.Elt
	y	*fp448.Elt
	z	*fp448.Elt
	ta	*fp448.Elt
	tb	*fp448.Elt
}

type goldilocks_twistPoint struct {
	x	*fp448.Elt
	y	*fp448.Elt
	z	*fp448.Elt
	ta	*fp448.Elt
	tb	*fp448.Elt
}

type gopacket_ApplicationLayer interface {
}

type gopacket_ApplicationLayer interface {
}

type gopacket_CaptureInfo struct {
	Timestamp	*time.Time
	CaptureLength	*int
	Length		*int
	InterfaceIndex	*int
	AncillaryData	*[]interface {}
}

type gopacket_CaptureInfo struct {
	Timestamp	*time.Time
	CaptureLength	*int
	Length		*int
	InterfaceIndex	*int
	AncillaryData	*[]interface {}
}

type gopacket_DecodeFailure struct {
	data	*[]uint8
	err	*error
	stack	*[]uint8
}

type gopacket_DecodeFailure struct {
	data	*[]uint8
	err	*error
	stack	*[]uint8
}

type gopacket_DecodeFeedback interface {
}

type gopacket_DecodeFeedback interface {
}

type gopacket_DecodeFunc func()

type gopacket_DecodeFunc func()

type gopacket_DecodeOptions struct {
	Lazy				*bool
	NoCopy				*bool
	SkipDecodeRecovery		*bool
	DecodeStreamsAsDatagrams	*bool
}

type gopacket_DecodeOptions struct {
	Lazy				*bool
	NoCopy				*bool
	SkipDecodeRecovery		*bool
	DecodeStreamsAsDatagrams	*bool
}

type gopacket_Decoder interface {
}

type gopacket_Decoder interface {
}

type gopacket_DecodingLayer interface {
}

type gopacket_DecodingLayer interface {
}

type gopacket_Endpoint struct {
	typ	*gopacket.EndpointType
	len	*int
	raw	*[16]uint8
}

type gopacket_Endpoint struct {
	typ	*gopacket.EndpointType
	len	*int
	raw	*[16]uint8
}

type gopacket_EndpointType int64

type gopacket_EndpointType int64

type gopacket_EndpointTypeMetadata struct {
	Name		*string
	Formatter	*func([]uint8) string
}

type gopacket_EndpointTypeMetadata struct {
	Name		*string
	Formatter	*func([]uint8) string
}

type gopacket_ErrorLayer interface {
}

type gopacket_ErrorLayer interface {
}

type gopacket_Flow struct {
	typ	*gopacket.EndpointType
	slen	*int
	dlen	*int
	src	*[16]uint8
	dst	*[16]uint8
}

type gopacket_Flow struct {
	typ	*gopacket.EndpointType
	slen	*int
	dlen	*int
	src	*[16]uint8
	dst	*[16]uint8
}

type gopacket_Fragment []*uint8

type gopacket_Fragment []*uint8

type gopacket_Layer interface {
}

type gopacket_Layer interface {
}

type gopacket_LayerClass interface {
}

type gopacket_LayerClass interface {
}

type gopacket_LayerClassMap map[interface{}]*gopacket.LayerType

type gopacket_LayerClassMap map[interface{}]*gopacket.LayerType

type gopacket_LayerClassSlice []*bool

type gopacket_LayerClassSlice []*bool

type gopacket_LayerType int64

type gopacket_LayerType int64

type gopacket_LayerTypeMetadata struct {
	Name	*string
	Decoder	*gopacket.Decoder
}

type gopacket_LayerTypeMetadata struct {
	Name	*string
	Decoder	*gopacket.Decoder
}

type gopacket_LinkLayer interface {
}

type gopacket_LinkLayer interface {
}

type gopacket_NetworkLayer interface {
}

type gopacket_NetworkLayer interface {
}

type gopacket_Packet interface {
}

type gopacket_Packet interface {
}

type gopacket_PacketBuilder interface {
}

type gopacket_PacketBuilder interface {
}

type gopacket_PacketMetadata struct {
	CaptureInfo	*gopacket.CaptureInfo
	Truncated	*bool
}

type gopacket_PacketMetadata struct {
	CaptureInfo	*gopacket.CaptureInfo
	Truncated	*bool
}

type gopacket_Payload []*uint8

type gopacket_Payload []*uint8

type gopacket_TransportLayer interface {
}

type gopacket_TransportLayer interface {
}

type gopacket_eagerPacket struct {
	packet *interface{}
}

type gopacket_eagerPacket struct {
	packet *interface{}
}

type gopacket_layerTypeMetadata struct {
	inUse			*bool
	LayerTypeMetadata	*gopacket.LayerTypeMetadata
}

type gopacket_layerTypeMetadata struct {
	inUse			*bool
	LayerTypeMetadata	*gopacket.LayerTypeMetadata
}

type gopacket_lazyPacket struct {
	packet	*interface{}
	next	*gopacket.Decoder
}

type gopacket_lazyPacket struct {
	packet	*interface{}
	next	*gopacket.Decoder
}

type gopacket_nilDecodeFeedback struct {
}

type gopacket_nilDecodeFeedback struct {
}

type gopacket_packet struct {
	data		*[]uint8
	initialLayers	*[6]gopacket.Layer
	layers		*[]gopacket.Layer
	last		*gopacket.Layer
	metadata	*gopacket.PacketMetadata
	decodeOptions	*gopacket.DecodeOptions
	link		*gopacket.LinkLayer
	network		*gopacket.NetworkLayer
	transport	*gopacket.TransportLayer
	application	*gopacket.ApplicationLayer
	failure		*gopacket.ErrorLayer
}

type gopacket_packet struct {
	data		*[]uint8
	initialLayers	*[6]gopacket.Layer
	layers		*[]gopacket.Layer
	last		*gopacket.Layer
	metadata	*gopacket.PacketMetadata
	decodeOptions	*gopacket.DecodeOptions
	link		*gopacket.LinkLayer
	network		*gopacket.NetworkLayer
	transport	*gopacket.TransportLayer
	application	*gopacket.ApplicationLayer
	failure		*gopacket.ErrorLayer
}

type gzip_Header struct {
	Comment	*string
	Extra	*[]uint8
	ModTime	*time.Time
	Name	*string
	OS	*uint8
}

type gzip_Header struct {
	Comment	*string
	Extra	*[]uint8
	ModTime	*time.Time
	Name	*string
	OS	*uint8
}

type gzip_Reader struct {
	Header		*gzip.Header
	r		*flate.Reader
	decompressor	*io.ReadCloser
	digest		*uint32
	size		*uint32
	buf		*[512]uint8
	err		*error
	multistream	*bool
}

type gzip_Reader struct {
	Header		*gzip.Header
	r		*flate.Reader
	decompressor	*io.ReadCloser
	digest		*uint32
	size		*uint32
	buf		*[512]uint8
	err		*error
	multistream	*bool
}

type handshake_ConnectionState struct {
	ConnectionState	*tls.ConnectionState
	Used0RTT	*bool
}

type handshake_ConnectionState struct {
	ConnectionState	*tls.ConnectionState
	Used0RTT	*bool
}

type handshake_CryptoSetup interface {
}

type handshake_CryptoSetup interface {
}

type handshake_Event struct {
	Kind			*handshake.EventKind
	Data			*[]uint8
	TransportParameters	*wire.TransportParameters
}

type handshake_Event struct {
	Kind			*handshake.EventKind
	Data			*[]uint8
	TransportParameters	*wire.TransportParameters
}

type handshake_EventKind uint8

type handshake_EventKind uint8

type handshake_LongHeaderOpener interface {
}

type handshake_LongHeaderOpener interface {
}

type handshake_LongHeaderSealer interface {
}

type handshake_LongHeaderSealer interface {
}

type handshake_ShortHeaderOpener interface {
}

type handshake_ShortHeaderOpener interface {
}

type handshake_ShortHeaderSealer interface {
}

type handshake_ShortHeaderSealer interface {
}

type handshake_TokenGenerator struct {
	tokenProtector *interface{}
}

type handshake_TokenGenerator struct {
	tokenProtector *interface{}
}

type handshake_TokenProtectorKey [32]*uint8

type handshake_TokenProtectorKey [32]*uint8

type handshake_aesHeaderProtector struct {
	mask		*[16]uint8
	block		*cipher.Block
	isLongHeader	*bool
}

type handshake_aesHeaderProtector struct {
	mask		*[16]uint8
	block		*cipher.Block
	isLongHeader	*bool
}

type handshake_chachaHeaderProtector struct {
	mask		*[5]uint8
	key		*[32]uint8
	isLongHeader	*bool
}

type handshake_chachaHeaderProtector struct {
	mask		*[5]uint8
	key		*[32]uint8
	isLongHeader	*bool
}

type handshake_cipherSuite struct {
	ID	*uint16
	Hash	*crypto.Hash
	KeyLen	*int
	AEAD	*func([]uint8, []uint8) *handshake.xorNonceAEAD
}

type handshake_cipherSuite struct {
	ID	*uint16
	Hash	*crypto.Hash
	KeyLen	*int
	AEAD	*func([]uint8, []uint8) *handshake.xorNonceAEAD
}

type handshake_cryptoSetup struct {
	tlsConf			*tls.Config
	conn			*tls.QUICConn
	events			*[]handshake.Event
	version			*protocol.Version
	ourParams		*wire.TransportParameters
	peerParams		*wire.TransportParameters
	zeroRTTParameters	*wire.TransportParameters
	allow0RTT		*bool
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	perspective		*protocol.Perspective
	handshakeCompleteTime	*time.Time
	zeroRTTOpener		*handshake.LongHeaderOpener
	zeroRTTSealer		*handshake.LongHeaderSealer
	initialOpener		*handshake.LongHeaderOpener
	initialSealer		*handshake.LongHeaderSealer
	handshakeOpener		*handshake.LongHeaderOpener
	handshakeSealer		*handshake.LongHeaderSealer
	used0RTT		*atomic.Bool
	aead			*interface{}
	has1RTTSealer		*bool
	has1RTTOpener		*bool
}

type handshake_cryptoSetup struct {
	tlsConf			*tls.Config
	conn			*tls.QUICConn
	events			*[]handshake.Event
	version			*protocol.Version
	ourParams		*wire.TransportParameters
	peerParams		*wire.TransportParameters
	zeroRTTParameters	*wire.TransportParameters
	allow0RTT		*bool
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	perspective		*protocol.Perspective
	handshakeCompleteTime	*time.Time
	zeroRTTOpener		*handshake.LongHeaderOpener
	zeroRTTSealer		*handshake.LongHeaderSealer
	initialOpener		*handshake.LongHeaderOpener
	initialSealer		*handshake.LongHeaderSealer
	handshakeOpener		*handshake.LongHeaderOpener
	handshakeSealer		*handshake.LongHeaderSealer
	used0RTT		*atomic.Bool
	aead			*interface{}
	has1RTTSealer		*bool
	has1RTTOpener		*bool
}

type handshake_headerProtector interface {
}

type handshake_headerProtector interface {
}

type handshake_longHeaderOpener struct {
	aead		*interface{}
	headerProtector	*interface{}
	highestRcvdPN	*protocol.PacketNumber
	nonceBuf	*[8]uint8
}

type handshake_longHeaderOpener struct {
	aead		*interface{}
	headerProtector	*interface{}
	highestRcvdPN	*protocol.PacketNumber
	nonceBuf	*[8]uint8
}

type handshake_longHeaderSealer struct {
	aead		*interface{}
	headerProtector	*interface{}
	nonceBuf	*[8]uint8
}

type handshake_longHeaderSealer struct {
	aead		*interface{}
	headerProtector	*interface{}
	nonceBuf	*[8]uint8
}

type handshake_quicVersionContextKey struct {
}

type handshake_quicVersionContextKey struct {
}

type handshake_token struct {
	IsRetryToken			*bool
	RemoteAddr			*[]uint8
	Timestamp			*int64
	RTT				*int64
	OriginalDestConnectionID	*[]uint8
	RetrySrcConnectionID		*[]uint8
}

type handshake_token struct {
	IsRetryToken			*bool
	RemoteAddr			*[]uint8
	Timestamp			*int64
	RTT				*int64
	OriginalDestConnectionID	*[]uint8
	RetrySrcConnectionID		*[]uint8
}

type handshake_tokenProtector struct {
	key *handshake.TokenProtectorKey
}

type handshake_tokenProtector struct {
	key *handshake.TokenProtectorKey
}

type handshake_uCryptoSetup struct {
	tlsConf			*tls.Config
	conn			*tls.UQUICConn
	events			*[]handshake.Event
	version			*protocol.Version
	ourParams		*wire.TransportParameters
	peerParams		*wire.TransportParameters
	zeroRTTParameters	*wire.TransportParameters
	allow0RTT		*bool
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	perspective		*protocol.Perspective
	handshakeCompleteTime	*time.Time
	zeroRTTOpener		*handshake.LongHeaderOpener
	zeroRTTSealer		*handshake.LongHeaderSealer
	initialOpener		*handshake.LongHeaderOpener
	initialSealer		*handshake.LongHeaderSealer
	handshakeOpener		*handshake.LongHeaderOpener
	handshakeSealer		*handshake.LongHeaderSealer
	used0RTT		*atomic.Bool
	aead			*interface{}
	has1RTTSealer		*bool
	has1RTTOpener		*bool
}

type handshake_uCryptoSetup struct {
	tlsConf			*tls.Config
	conn			*tls.UQUICConn
	events			*[]handshake.Event
	version			*protocol.Version
	ourParams		*wire.TransportParameters
	peerParams		*wire.TransportParameters
	zeroRTTParameters	*wire.TransportParameters
	allow0RTT		*bool
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	perspective		*protocol.Perspective
	handshakeCompleteTime	*time.Time
	zeroRTTOpener		*handshake.LongHeaderOpener
	zeroRTTSealer		*handshake.LongHeaderSealer
	initialOpener		*handshake.LongHeaderOpener
	initialSealer		*handshake.LongHeaderSealer
	handshakeOpener		*handshake.LongHeaderOpener
	handshakeSealer		*handshake.LongHeaderSealer
	used0RTT		*atomic.Bool
	aead			*interface{}
	has1RTTSealer		*bool
	has1RTTOpener		*bool
}

type handshake_updatableAEAD struct {
	suite			*interface{}
	keyPhase		*protocol.KeyPhase
	largestAcked		*protocol.PacketNumber
	firstPacketNumber	*protocol.PacketNumber
	handshakeConfirmed	*bool
	invalidPacketLimit	*uint64
	invalidPacketCount	*uint64
	prevRcvAEADExpiry	*time.Time
	prevRcvAEAD		*cipher.AEAD
	firstRcvdWithCurrentKey	*protocol.PacketNumber
	firstSentWithCurrentKey	*protocol.PacketNumber
	highestRcvdPN		*protocol.PacketNumber
	numRcvdWithCurrentKey	*uint64
	numSentWithCurrentKey	*uint64
	rcvAEAD			*cipher.AEAD
	sendAEAD		*cipher.AEAD
	aeadOverhead		*int
	nextRcvAEAD		*cipher.AEAD
	nextSendAEAD		*cipher.AEAD
	nextRcvTrafficSecret	*[]uint8
	nextSendTrafficSecret	*[]uint8
	headerDecrypter		*interface{}
	headerEncrypter		*interface{}
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	version			*protocol.Version
	nonceBuf		*[]uint8
}

type handshake_updatableAEAD struct {
	suite			*interface{}
	keyPhase		*protocol.KeyPhase
	largestAcked		*protocol.PacketNumber
	firstPacketNumber	*protocol.PacketNumber
	handshakeConfirmed	*bool
	invalidPacketLimit	*uint64
	invalidPacketCount	*uint64
	prevRcvAEADExpiry	*time.Time
	prevRcvAEAD		*cipher.AEAD
	firstRcvdWithCurrentKey	*protocol.PacketNumber
	firstSentWithCurrentKey	*protocol.PacketNumber
	highestRcvdPN		*protocol.PacketNumber
	numRcvdWithCurrentKey	*uint64
	numSentWithCurrentKey	*uint64
	rcvAEAD			*cipher.AEAD
	sendAEAD		*cipher.AEAD
	aeadOverhead		*int
	nextRcvAEAD		*cipher.AEAD
	nextSendAEAD		*cipher.AEAD
	nextRcvTrafficSecret	*[]uint8
	nextSendTrafficSecret	*[]uint8
	headerDecrypter		*interface{}
	headerEncrypter		*interface{}
	rttStats		*utils.RTTStats
	tracer			*logging.ConnectionTracer
	logger			*utils.Logger
	version			*protocol.Version
	nonceBuf		*[]uint8
}

type handshake_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type handshake_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type hkdf_hkdf struct {
	expander	*hash.Hash
	size		*int
	info		*[]uint8
	counter		*uint8
	prev		*[]uint8
	buf		*[]uint8
}

type hkdf_hkdf struct {
	expander	*hash.Hash
	size		*int
	info		*[]uint8
	counter		*uint8
	prev		*[]uint8
	buf		*[]uint8
}

type hmac_HMAC struct {
	opad		*[]uint8
	ipad		*[]uint8
	outer		*hash.Hash
	inner		*hash.Hash
	marshaled	*bool
	forHKDF		*bool
	keyLen		*int
}

type hmac_HMAC struct {
	opad		*[]uint8
	ipad		*[]uint8
	outer		*hash.Hash
	inner		*hash.Hash
	marshaled	*bool
	forHKDF		*bool
	keyLen		*int
}

type hmac_marshalable interface {
}

type hmac_marshalable interface {
}

type hpack_Decoder struct {
	dynTab		*interface{}
	emit		*func(hpack.HeaderField)
	emitEnabled	*bool
	maxStrLen	*int
	buf		*[]uint8
	saveBuf		*bytes.Buffer
	firstField	*bool
}

type hpack_Decoder struct {
	dynTab		*interface{}
	emit		*func(hpack.HeaderField)
	emitEnabled	*bool
	maxStrLen	*int
	buf		*[]uint8
	saveBuf		*bytes.Buffer
	firstField	*bool
}

type hpack_Decoder struct {
	dynTab		*interface{}
	emit		*func(hpack.HeaderField)
	emitEnabled	*bool
	maxStrLen	*int
	buf		*[]uint8
	saveBuf		*bytes.Buffer
	firstField	*bool
}

type hpack_Decoder struct {
	dynTab		*interface{}
	emit		*func(hpack.HeaderField)
	emitEnabled	*bool
	maxStrLen	*int
	buf		*[]uint8
	saveBuf		*bytes.Buffer
	firstField	*bool
}

type hpack_DecodingError struct {
	Err *error
}

type hpack_DecodingError struct {
	Err *error
}

type hpack_DecodingError struct {
	Err *error
}

type hpack_DecodingError struct {
	Err *error
}

type hpack_Encoder struct {
	dynTab		*interface{}
	minSize		*uint32
	maxSizeLimit	*uint32
	tableSizeUpdate	*bool
	w		*io.Writer
	buf		*[]uint8
}

type hpack_Encoder struct {
	dynTab		*interface{}
	minSize		*uint32
	maxSizeLimit	*uint32
	tableSizeUpdate	*bool
	w		*io.Writer
	buf		*[]uint8
}

type hpack_Encoder struct {
	dynTab		*interface{}
	minSize		*uint32
	maxSizeLimit	*uint32
	tableSizeUpdate	*bool
	w		*io.Writer
	buf		*[]uint8
}

type hpack_Encoder struct {
	dynTab		*interface{}
	minSize		*uint32
	maxSizeLimit	*uint32
	tableSizeUpdate	*bool
	w		*io.Writer
	buf		*[]uint8
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_HeaderField struct {
	Name		*string
	Value		*string
	Sensitive	*bool
}

type hpack_InvalidIndexError int

type hpack_InvalidIndexError int

type hpack_InvalidIndexError int

type hpack_InvalidIndexError int

type hpack_dynamicTable struct {
	table		*interface{}
	size		*uint32
	maxSize		*uint32
	allowedMaxSize	*uint32
}

type hpack_dynamicTable struct {
	table		*interface{}
	size		*uint32
	maxSize		*uint32
	allowedMaxSize	*uint32
}

type hpack_dynamicTable struct {
	table		*interface{}
	size		*uint32
	maxSize		*uint32
	allowedMaxSize	*uint32
}

type hpack_dynamicTable struct {
	table		*interface{}
	size		*uint32
	maxSize		*uint32
	allowedMaxSize	*uint32
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_headerFieldTable struct {
	ents		*[]hpack.HeaderField
	evictCount	*uint64
	byName		*map[string]uint64
	byNameValue	*map[hpack.pairNameValue]uint64
}

type hpack_incomparable [0]*func()

type hpack_incomparable [0]*func()

type hpack_incomparable [0]*func()

type hpack_incomparable [0]*func()

type hpack_incomparable [0]*func()

type hpack_incomparable [0]*func()

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_node struct {
	_		*interface{}
	children	*[256]*hpack.node
	codeLen		*uint8
	sym		*uint8
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpack_pairNameValue struct {
	name	*string
	value	*string
}

type hpke_AEAD uint16

type hpke_AEAD uint16

type hpke_KDF uint16

type hpke_KDF uint16

type hpke_KEM uint16

type hpke_KEM uint16

type hpke_Sealer interface {
}

type hpke_Sealer interface {
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Sender struct {
	context *interface{}
}

type hpke_Suite struct {
	kemID	*hpke.KEM
	kdfID	*hpke.KDF
	aeadID	*hpke.AEAD
}

type hpke_Suite struct {
	kemID	*hpke.KEM
	kdfID	*hpke.KDF
	aeadID	*hpke.AEAD
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_context struct {
	aead		*cipher.AEAD
	sharedSecret	*[]uint8
	suiteID		*[]uint8
	key		*[]uint8
	baseNonce	*[]uint8
	exporterSecret	*[]uint8
	seqNum		*interface{}
}

type hpke_dhKEM interface {
}

type hpke_dhKEM interface {
}

type hpke_dhKemBase struct {
	kemBase	*interface{}
	dhKEM	*interface{}
}

type hpke_dhKemBase struct {
	kemBase	*interface{}
	dhKEM	*interface{}
}

type hpke_encdecContext struct {
	suite			*hpke.Suite
	sharedSecret		*[]uint8
	secret			*[]uint8
	keyScheduleContext	*[]uint8
	exporterSecret		*[]uint8
	key			*[]uint8
	baseNonce		*[]uint8
	sequenceNumber		*[]uint8
	AEAD			*cipher.AEAD
	nonce			*[]uint8
}

type hpke_encdecContext struct {
	suite			*hpke.Suite
	sharedSecret		*[]uint8
	secret			*[]uint8
	keyScheduleContext	*[]uint8
	exporterSecret		*[]uint8
	key			*[]uint8
	baseNonce		*[]uint8
	sequenceNumber		*[]uint8
	AEAD			*cipher.AEAD
	nonce			*[]uint8
}

type hpke_genericNoAuthKEM struct {
	Scheme	*kem.Scheme
	name	*string
}

type hpke_genericNoAuthKEM struct {
	Scheme	*kem.Scheme
	name	*string
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hkdfKDF struct {
	hash *crypto.Hash
}

type hpke_hybridKEM struct {
	kemBase	*interface{}
	kemA	*kem.Scheme
	kemB	*kem.Scheme
}

type hpke_hybridKEM struct {
	kemBase	*interface{}
	kemA	*kem.Scheme
	kemB	*kem.Scheme
}

type hpke_hybridKEMPrivKey struct {
	scheme	*kem.Scheme
	privA	*kem.PrivateKey
	privB	*kem.PrivateKey
}

type hpke_hybridKEMPrivKey struct {
	scheme	*kem.Scheme
	privA	*kem.PrivateKey
	privB	*kem.PrivateKey
}

type hpke_hybridKEMPubKey struct {
	scheme	*kem.Scheme
	pubA	*kem.PublicKey
	pubB	*kem.PublicKey
}

type hpke_hybridKEMPubKey struct {
	scheme	*kem.Scheme
	pubA	*kem.PublicKey
	pubB	*kem.PublicKey
}

type hpke_kemBase struct {
	id	*hpke.KEM
	name	*string
	Hash	*crypto.Hash
}

type hpke_kemBase struct {
	id	*hpke.KEM
	name	*string
	Hash	*crypto.Hash
}

type hpke_sealContext struct {
	encdecContext *interface{}
}

type hpke_sealContext struct {
	encdecContext *interface{}
}

type hpke_shortKEM struct {
	dhKemBase	*interface{}
	Curve		*ecdh.Curve
}

type hpke_shortKEM struct {
	dhKemBase	*interface{}
	Curve		*ecdh.Curve
}

type hpke_shortKEMPrivKey struct {
	scheme	*interface{}
	priv	*ecdh.PrivateKey
}

type hpke_shortKEMPrivKey struct {
	scheme	*interface{}
	priv	*ecdh.PrivateKey
}

type hpke_shortKEMPubKey struct {
	scheme	*interface{}
	pub	*ecdh.PublicKey
}

type hpke_shortKEMPubKey struct {
	scheme	*interface{}
	pub	*ecdh.PublicKey
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type hpke_xKEM struct {
	dhKemBase	*interface{}
	size		*int
}

type hpke_xKEM struct {
	dhKemBase	*interface{}
	size		*int
}

type hpke_xKEMPrivKey struct {
	scheme	*interface{}
	priv	*[]uint8
	pub	*interface{}
}

type hpke_xKEMPrivKey struct {
	scheme	*interface{}
	priv	*[]uint8
	pub	*interface{}
}

type hpke_xKEMPubKey struct {
	scheme	*interface{}
	pub	*[]uint8
}

type hpke_xKEMPubKey struct {
	scheme	*interface{}
	pub	*[]uint8
}

type http2_ClientConn struct {
	br			*bufio.Reader
	bw			*bufio.Writer
	closed			*bool
	closing			*bool
	cond			*sync.Cond
	dialedAddr		*string
	flow			*interface{}
	fr			*http2.Framer
	freeBuf			*[][]uint8
	goAway			*http2.GoAwayFrame
	goAwayDebug		*string
	hbuf			*bytes.Buffer
	henc			*hpack.Encoder
	highestPromiseID	*uint32
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
	inflow			*interface{}
	initialWindowSize	*uint32
	lastActive		*time.Time
	lastIdle		*time.Time
	maxConcurrentStreams	*uint32
	maxFrameSize		*uint32
	mu			*sync.Mutex
	nextStreamID		*uint32
	peerMaxHeaderListSize	*uint64
	pendingRequests		*int
	pings			*map[[8]uint8]chan struct {}
	readerDone		*chan struct {}
	readerErr		*error
	reused			*uint32
	singleUse		*bool
	streams			*map[uint32]*http2.clientStream
	t			*http2.Transport
	tconn			*net.Conn
	tlsState		*tls.ConnectionState
	wantSettingsAck		*bool
	werr			*error
	wmu			*sync.Mutex
}

type http2_ClientConn struct {
	br			*bufio.Reader
	bw			*bufio.Writer
	closed			*bool
	closing			*bool
	cond			*sync.Cond
	dialedAddr		*string
	flow			*interface{}
	fr			*http2.Framer
	freeBuf			*[][]uint8
	goAway			*http2.GoAwayFrame
	goAwayDebug		*string
	hbuf			*bytes.Buffer
	henc			*hpack.Encoder
	highestPromiseID	*uint32
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
	inflow			*interface{}
	initialWindowSize	*uint32
	lastActive		*time.Time
	lastIdle		*time.Time
	maxConcurrentStreams	*uint32
	maxFrameSize		*uint32
	mu			*sync.Mutex
	nextStreamID		*uint32
	peerMaxHeaderListSize	*uint64
	pendingRequests		*int
	pings			*map[[8]uint8]chan struct {}
	readerDone		*chan struct {}
	readerErr		*error
	reused			*uint32
	singleUse		*bool
	streams			*map[uint32]*http2.clientStream
	t			*http2.Transport
	tconn			*net.Conn
	tlsState		*tls.ConnectionState
	wantSettingsAck		*bool
	werr			*error
	wmu			*sync.Mutex
}

type http2_ClientConnPool interface {
}

type http2_ClientConnPool interface {
}

type http2_ConnectionError uint32

type http2_ConnectionError uint32

type http2_ContinuationFrame struct {
	FrameHeader	*http2.FrameHeader
	headerFragBuf	*[]uint8
}

type http2_ContinuationFrame struct {
	FrameHeader	*http2.FrameHeader
	headerFragBuf	*[]uint8
}

type http2_DataFrame struct {
	FrameHeader	*http2.FrameHeader
	data		*[]uint8
}

type http2_DataFrame struct {
	FrameHeader	*http2.FrameHeader
	data		*[]uint8
}

type http2_DefaultPushHandler struct {
	promise		*http.Request
	origReqURL	*url.URL
	origReqHeader	*http.Header
	push		*http.Response
	pushErr		*error
	done		*chan struct {}
}

type http2_DefaultPushHandler struct {
	promise		*http.Request
	origReqURL	*url.URL
	origReqHeader	*http.Header
	push		*http.Response
	pushErr		*error
	done		*chan struct {}
}

type http2_ErrCode uint32

type http2_ErrCode uint32

type http2_Flags uint8

type http2_Flags uint8

type http2_Frame interface {
}

type http2_Frame interface {
}

type http2_FrameHeader struct {
	valid		*bool
	Type		*http2.FrameType
	Flags		*http2.Flags
	Length		*uint32
	StreamID	*uint32
}

type http2_FrameHeader struct {
	valid		*bool
	Type		*http2.FrameType
	Flags		*http2.Flags
	Length		*uint32
	StreamID	*uint32
}

type http2_FrameType uint8

type http2_FrameType uint8

type http2_Framer struct {
	r			*io.Reader
	lastFrame		*http2.Frame
	errDetail		*error
	lastHeaderStream	*uint32
	maxReadSize		*uint32
	headerBuf		*[9]uint8
	getReadBuf		*func(uint32) []uint8
	readBuf			*[]uint8
	maxWriteSize		*uint32
	w			*io.Writer
	wbuf			*[]uint8
	AllowIllegalWrites	*bool
	AllowIllegalReads	*bool
	ReadMetaHeaders		*hpack.Decoder
	MaxHeaderListSize	*uint32
	logReads		*bool
	logWrites		*bool
	debugFramer		*http2.Framer
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	frameCache		*interface{}
}

type http2_Framer struct {
	r			*io.Reader
	lastFrame		*http2.Frame
	errDetail		*error
	lastHeaderStream	*uint32
	maxReadSize		*uint32
	headerBuf		*[9]uint8
	getReadBuf		*func(uint32) []uint8
	readBuf			*[]uint8
	maxWriteSize		*uint32
	w			*io.Writer
	wbuf			*[]uint8
	AllowIllegalWrites	*bool
	AllowIllegalReads	*bool
	ReadMetaHeaders		*hpack.Decoder
	MaxHeaderListSize	*uint32
	logReads		*bool
	logWrites		*bool
	debugFramer		*http2.Framer
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	frameCache		*interface{}
}

type http2_GoAwayError struct {
	DebugData	*string
	ErrCode		*http2.ErrCode
	LastStreamID	*uint32
}

type http2_GoAwayError struct {
	DebugData	*string
	ErrCode		*http2.ErrCode
	LastStreamID	*uint32
}

type http2_GoAwayFrame struct {
	FrameHeader	*http2.FrameHeader
	LastStreamID	*uint32
	ErrCode		*http2.ErrCode
	debugData	*[]uint8
}

type http2_GoAwayFrame struct {
	FrameHeader	*http2.FrameHeader
	LastStreamID	*uint32
	ErrCode		*http2.ErrCode
	debugData	*[]uint8
}

type http2_HeadersFrame struct {
	FrameHeader	*http2.FrameHeader
	Priority	*http2.PriorityParam
	headerFragBuf	*[]uint8
}

type http2_HeadersFrame struct {
	FrameHeader	*http2.FrameHeader
	Priority	*http2.PriorityParam
	headerFragBuf	*[]uint8
}

type http2_MetaHeadersFrame struct {
	HeadersFrame	*http2.HeadersFrame
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http2_MetaHeadersFrame struct {
	HeadersFrame	*http2.HeadersFrame
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http2_MetaPushPromiseFrame struct {
	PushPromiseFrame	*http2.PushPromiseFrame
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http2_MetaPushPromiseFrame struct {
	PushPromiseFrame	*http2.PushPromiseFrame
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http2_PingFrame struct {
	FrameHeader	*http2.FrameHeader
	Data		*[8]uint8
}

type http2_PingFrame struct {
	FrameHeader	*http2.FrameHeader
	Data		*[8]uint8
}

type http2_Priority struct {
	PriorityParam	*http2.PriorityParam
	StreamID	*uint32
}

type http2_Priority struct {
	PriorityParam	*http2.PriorityParam
	StreamID	*uint32
}

type http2_Priority struct {
	PriorityParam	*http2.PriorityParam
	StreamID	*uint32
}

type http2_Priority struct {
	PriorityParam	*http2.PriorityParam
	StreamID	*uint32
}

type http2_PriorityFrame struct {
	FrameHeader	*http2.FrameHeader
	PriorityParam	*http2.PriorityParam
}

type http2_PriorityFrame struct {
	FrameHeader	*http2.FrameHeader
	PriorityParam	*http2.PriorityParam
}

type http2_PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http2_PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http2_PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http2_PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http2_PushHandler interface {
}

type http2_PushHandler interface {
}

type http2_PushPromiseFrame struct {
	FrameHeader	*http2.FrameHeader
	PromiseID	*uint32
	headerFragBuf	*[]uint8
}

type http2_PushPromiseFrame struct {
	FrameHeader	*http2.FrameHeader
	PromiseID	*uint32
	headerFragBuf	*[]uint8
}

type http2_PushedRequest struct {
	Promise			*http.Request
	OriginalRequestURL	*url.URL
	OriginalRequestHeader	*http.Header
	pushedStream		*interface{}
}

type http2_PushedRequest struct {
	Promise			*http.Request
	OriginalRequestURL	*url.URL
	OriginalRequestHeader	*http.Header
	pushedStream		*interface{}
}

type http2_RSTStreamFrame struct {
	FrameHeader	*http2.FrameHeader
	ErrCode		*http2.ErrCode
}

type http2_RSTStreamFrame struct {
	FrameHeader	*http2.FrameHeader
	ErrCode		*http2.ErrCode
}

type http2_Setting struct {
	ID	*http2.SettingID
	Val	*uint32
}

type http2_Setting struct {
	ID	*http2.SettingID
	Val	*uint32
}

type http2_SettingID uint16

type http2_SettingID uint16

type http2_SettingID uint16

type http2_SettingID uint16

type http2_SettingsFrame struct {
	FrameHeader	*http2.FrameHeader
	p		*[]uint8
}

type http2_SettingsFrame struct {
	FrameHeader	*http2.FrameHeader
	p		*[]uint8
}

type http2_StreamError struct {
	StreamID	*uint32
	Code		*http2.ErrCode
	Cause		*error
}

type http2_StreamError struct {
	StreamID	*uint32
	Code		*http2.ErrCode
	Cause		*error
}

type http2_Transport struct {
	AllowHTTP			*bool
	ConnectionFlow			*uint32
	ConnPool			*http2.ClientConnPool
	connPoolOnce			*sync.Once
	connPoolOrDef			*http2.ClientConnPool
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	DisableCompression		*bool
	HeaderPriority			*http2.PriorityParam
	HeaderTableSize			*uint32
	IdleConnTimeout			*time.Duration
	InitialWindowSize		*uint32
	PingTimeout			*time.Duration
	Priorities			*[]http2.Priority
	PseudoHeaderOrder		*[]string
	PushHandler			*http2.PushHandler
	ReadIdleTimeout			*time.Duration
	Settings			*map[http2.SettingID]uint32
	SettingsOrder			*[]http2.SettingID
	StrictMaxConcurrentStreams	*bool
	t1				*http.Transport
	TLSClientConfig			*tls.Config
}

type http2_Transport struct {
	AllowHTTP			*bool
	ConnectionFlow			*uint32
	ConnPool			*http2.ClientConnPool
	connPoolOnce			*sync.Once
	connPoolOrDef			*http2.ClientConnPool
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	DisableCompression		*bool
	HeaderPriority			*http2.PriorityParam
	HeaderTableSize			*uint32
	IdleConnTimeout			*time.Duration
	InitialWindowSize		*uint32
	PingTimeout			*time.Duration
	Priorities			*[]http2.Priority
	PseudoHeaderOrder		*[]string
	PushHandler			*http2.PushHandler
	ReadIdleTimeout			*time.Duration
	Settings			*map[http2.SettingID]uint32
	SettingsOrder			*[]http2.SettingID
	StrictMaxConcurrentStreams	*bool
	t1				*http.Transport
	TLSClientConfig			*tls.Config
}

type http2_UnknownFrame struct {
	FrameHeader	*http2.FrameHeader
	p		*[]uint8
}

type http2_UnknownFrame struct {
	FrameHeader	*http2.FrameHeader
	p		*[]uint8
}

type http2_WindowUpdateFrame struct {
	FrameHeader	*http2.FrameHeader
	Increment	*uint32
}

type http2_WindowUpdateFrame struct {
	FrameHeader	*http2.FrameHeader
	Increment	*uint32
}

type http2_addConnCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	err	*error
}

type http2_addConnCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	err	*error
}

type http2_bodyWriterState struct {
	cs	*interface{}
	delay	*time.Duration
	fn	*func()
	fnonce	*sync.Once
	resc	*chan error
	timer	*time.Timer
}

type http2_bodyWriterState struct {
	cs	*interface{}
	delay	*time.Duration
	fn	*func()
	fnonce	*sync.Once
	resc	*chan error
	timer	*time.Timer
}

type http2_clientConnPool struct {
	t		*http2.Transport
	mu		*sync.Mutex
	conns		*map[string][]*http2.ClientConn
	dialing		*map[string]*http2.dialCall
	keys		*map[*http2.ClientConn][]string
	addConnCalls	*map[string]*http2.addConnCall
}

type http2_clientConnPool struct {
	t		*http2.Transport
	mu		*sync.Mutex
	conns		*map[string][]*http2.ClientConn
	dialing		*map[string]*http2.dialCall
	keys		*map[*http2.ClientConn][]string
	addConnCalls	*map[string]*http2.addConnCall
}

type http2_clientConnPoolIdleCloser interface {
}

type http2_clientConnPoolIdleCloser interface {
}

type http2_clientStream struct {
	bufPipe		*interface{}
	bytesRemain	*int64
	cc		*http2.ClientConn
	didReset	*bool
	done		*chan struct {}
	firstByte	*bool
	flow		*interface{}
	gotEndStream	*bool
	ID		*uint32
	inflow		*interface{}
	num1xx		*uint8
	on100		*func()
	pastHeaders	*bool
	pastTrailers	*bool
	peerReset	*chan struct {}
	readErr		*error
	req		*http.Request
	requestedGzip	*bool
	resc		*chan http2.resAndError
	resetErr	*error
	resTrailer	*http.Header
	startedWrite	*bool
	stopReqBody	*error
	trace		*httptrace.ClientTrace
	trailer		*http.Header
}

type http2_clientStream struct {
	bufPipe		*interface{}
	bytesRemain	*int64
	cc		*http2.ClientConn
	didReset	*bool
	done		*chan struct {}
	firstByte	*bool
	flow		*interface{}
	gotEndStream	*bool
	ID		*uint32
	inflow		*interface{}
	num1xx		*uint8
	on100		*func()
	pastHeaders	*bool
	pastTrailers	*bool
	peerReset	*chan struct {}
	readErr		*error
	req		*http.Request
	requestedGzip	*bool
	resc		*chan http2.resAndError
	resetErr	*error
	resTrailer	*http.Header
	startedWrite	*bool
	stopReqBody	*error
	trace		*httptrace.ClientTrace
	trailer		*http.Header
}

type http2_connError struct {
	Code	*http2.ErrCode
	Reason	*string
}

type http2_connError struct {
	Code	*http2.ErrCode
	Reason	*string
}

type http2_connectionStater interface {
}

type http2_connectionStater interface {
}

type http2_continuable interface {
}

type http2_continuable interface {
}

type http2_dataBuffer struct {
	chunks		*[][]uint8
	r		*int
	w		*int
	size		*int
	expected	*int64
}

type http2_dataBuffer struct {
	chunks		*[][]uint8
	r		*int
	w		*int
	size		*int
	expected	*int64
}

type http2_dialCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	res	*http2.ClientConn
	err	*error
}

type http2_dialCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	res	*http2.ClientConn
	err	*error
}

type http2_duplicatePseudoHeaderError string

type http2_duplicatePseudoHeaderError string

type http2_erringRoundTripper struct {
	err *error
}

type http2_erringRoundTripper struct {
	err *error
}

type http2_flow struct {
	_	*interface{}
	n	*int32
	conn	*interface{}
}

type http2_flow struct {
	_	*interface{}
	n	*int32
	conn	*interface{}
}

type http2_frameCache struct {
	dataFrame *http2.DataFrame
}

type http2_frameCache struct {
	dataFrame *http2.DataFrame
}

type http2_frameParser func()

type http2_frameParser func()

type http2_headerFieldNameError string

type http2_headerFieldNameError string

type http2_headerFieldValueError string

type http2_headerFieldValueError string

type http2_httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http2_httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http2_incomparable [0]*func()

type http2_incomparable [0]*func()

type http2_metaFrame struct {
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http2_metaFrame struct {
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http2_noCachedConnError struct {
}

type http2_noCachedConnError struct {
}

type http2_noDialClientConnPool struct {
	clientConnPool *interface{}
}

type http2_noDialClientConnPool struct {
	clientConnPool *interface{}
}

type http2_noDialH2RoundTripper struct {
	Transport *http2.Transport
}

type http2_noDialH2RoundTripper struct {
	Transport *http2.Transport
}

type http2_pipe struct {
	mu		*sync.Mutex
	c		*sync.Cond
	b		*interface{}
	unread		*int
	err		*error
	breakErr	*error
	donec		*chan struct {}
	readFn		*func()
}

type http2_pipe struct {
	mu		*sync.Mutex
	c		*sync.Cond
	b		*interface{}
	unread		*int
	err		*error
	breakErr	*error
	donec		*chan struct {}
	readFn		*func()
}

type http2_pipeBuffer interface {
}

type http2_pipeBuffer interface {
}

type http2_pseudoHeaderError string

type http2_pseudoHeaderError string

type http2_resAndError struct {
	_	*interface{}
	err	*error
	res	*http.Response
}

type http2_resAndError struct {
	_	*interface{}
	err	*error
	res	*http.Response
}

type http2_serverMessage int

type http2_serverMessage int

type http2_serverMessage int

type http2_serverMessage int

type http2_stickyErrWriter struct {
	err	*error
	w	*io.Writer
}

type http2_stickyErrWriter struct {
	err	*error
	w	*io.Writer
}

type http2_transportResponseBody struct {
	cs *interface{}
}

type http2_transportResponseBody struct {
	cs *interface{}
}

type http3_ClientConn struct {
	conn			*http3.Conn
	enableDatagrams		*bool
	additionalSettings	*map[uint64]uint64
	additionalSettingsOrder	*[]uint64
	maxResponseHeaderBytes	*uint64
	disableCompression	*bool
	logger			*slog.Logger
	requestWriter		*interface{}
	decoder			*qpack.Decoder
}

type http3_ClientConn struct {
	conn			*http3.Conn
	enableDatagrams		*bool
	additionalSettings	*map[uint64]uint64
	additionalSettingsOrder	*[]uint64
	maxResponseHeaderBytes	*uint64
	disableCompression	*bool
	logger			*slog.Logger
	requestWriter		*interface{}
	decoder			*qpack.Decoder
}

type http3_Conn struct {
	conn			*quic.Conn
	ctx			*context.Context
	isServer		*bool
	logger			*slog.Logger
	enableDatagrams		*bool
	decoder			*qpack.Decoder
	streamMx		*sync.Mutex
	streams			*map[protocol.StreamID]*http3.stateTrackingStream
	lastStreamID		*protocol.StreamID
	maxStreamID		*protocol.StreamID
	settings		*http3.Settings
	receivedSettings	*chan struct {}
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
}

type http3_Conn struct {
	conn			*quic.Conn
	ctx			*context.Context
	isServer		*bool
	logger			*slog.Logger
	enableDatagrams		*bool
	decoder			*qpack.Decoder
	streamMx		*sync.Mutex
	streams			*map[protocol.StreamID]*http3.stateTrackingStream
	lastStreamID		*protocol.StreamID
	maxStreamID		*protocol.StreamID
	settings		*http3.Settings
	receivedSettings	*chan struct {}
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
}

type http3_ErrCode uint64

type http3_ErrCode uint64

type http3_Error struct {
	Remote		*bool
	ErrorCode	*http3.ErrCode
	ErrorMessage	*string
}

type http3_Error struct {
	Remote		*bool
	ErrorCode	*http3.ErrCode
	ErrorMessage	*string
}

type http3_FrameType uint64

type http3_FrameType uint64

type http3_RequestStream struct {
	str			*http3.Stream
	responseBody		*io.ReadCloser
	decoder			*qpack.Decoder
	requestWriter		*interface{}
	maxHeaderBytes		*uint64
	reqDone			*chan<- struct {}
	disableCompression	*bool
	response		*http.Response
	sentRequest		*bool
	requestedGzip		*bool
	isConnect		*bool
}

type http3_RequestStream struct {
	str			*http3.Stream
	responseBody		*io.ReadCloser
	decoder			*qpack.Decoder
	requestWriter		*interface{}
	maxHeaderBytes		*uint64
	reqDone			*chan<- struct {}
	disableCompression	*bool
	response		*http.Response
	sentRequest		*bool
	requestedGzip		*bool
	isConnect		*bool
}

type http3_Settings struct {
	EnableDatagrams		*bool
	EnableExtendedConnect	*bool
	Other			*map[uint64]uint64
}

type http3_Settings struct {
	EnableDatagrams		*bool
	EnableExtendedConnect	*bool
	Other			*map[uint64]uint64
}

type http3_Stream struct {
	datagramStream		*interface{}
	conn			*http3.Conn
	frameParser		*interface{}
	buf			*[]uint8
	bytesRemainingInFrame	*uint64
	parseTrailer		*func(io.Reader, uint64) error
	parsedTrailer		*bool
}

type http3_Stream struct {
	datagramStream		*interface{}
	conn			*http3.Conn
	frameParser		*interface{}
	buf			*[]uint8
	bytesRemainingInFrame	*uint64
	parseTrailer		*func(io.Reader, uint64) error
	parsedTrailer		*bool
}

type http3_StreamType uint64

type http3_StreamType uint64

type http3_Transport struct {
	TLSClientConfig		*tls.Config
	QUICConfig		*quic.Config
	Dial			*func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	EnableDatagrams		*bool
	AdditionalSettings	*map[uint64]uint64
	AdditionalSettingsOrder	*[]uint64
	MaxResponseHeaderBytes	*int64
	DisableCompression	*bool
	StreamHijacker		*func(http3.FrameType, quic.ConnectionTracingID, *quic.Stream, error) (bool, error)
	UniStreamHijacker	*func(http3.StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) bool
	Logger			*slog.Logger
	mutex			*sync.Mutex
	initOnce		*sync.Once
	initErr			*error
	newClientConn		*func(*quic.Conn) http3.clientConn
	clients			*map[string]*http3.roundTripperWithCount
	transport		*quic.Transport
	closed			*bool
}

type http3_Transport struct {
	TLSClientConfig		*tls.Config
	QUICConfig		*quic.Config
	Dial			*func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	EnableDatagrams		*bool
	AdditionalSettings	*map[uint64]uint64
	AdditionalSettingsOrder	*[]uint64
	MaxResponseHeaderBytes	*int64
	DisableCompression	*bool
	StreamHijacker		*func(http3.FrameType, quic.ConnectionTracingID, *quic.Stream, error) (bool, error)
	UniStreamHijacker	*func(http3.StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) bool
	Logger			*slog.Logger
	mutex			*sync.Mutex
	initOnce		*sync.Once
	initErr			*error
	newClientConn		*func(*quic.Conn) http3.clientConn
	clients			*map[string]*http3.roundTripperWithCount
	transport		*quic.Transport
	closed			*bool
}

type http3_body struct {
	str			*http3.Stream
	remainingContentLength	*int64
	violatedContentLength	*bool
	hasContentLength	*bool
}

type http3_body struct {
	str			*http3.Stream
	remainingContentLength	*int64
	violatedContentLength	*bool
	hasContentLength	*bool
}

type http3_cancelingReader struct {
	r	*io.Reader
	str	*http3.RequestStream
}

type http3_cancelingReader struct {
	r	*io.Reader
	str	*http3.RequestStream
}

type http3_clientConn interface {
}

type http3_clientConn interface {
}

type http3_countingByteReader struct {
	ByteReader	*io.ByteReader
	Read		*int
}

type http3_countingByteReader struct {
	ByteReader	*io.ByteReader
	Read		*int
}

type http3_dataFrame struct {
	Length *uint64
}

type http3_dataFrame struct {
	Length *uint64
}

type http3_datagramStream interface {
}

type http3_datagramStream interface {
}

type http3_errConnUnusable struct {
	e *error
}

type http3_errConnUnusable struct {
	e *error
}

type http3_fakeConn struct {
	conn *quic.Conn
}

type http3_fakeConn struct {
	conn *quic.Conn
}

type http3_frameParser struct {
	r			*io.Reader
	closeConn		*func(qerr.ApplicationErrorCode, string) error
	unknownFrameHandler	*interface{}
}

type http3_frameParser struct {
	r			*io.Reader
	closeConn		*func(qerr.ApplicationErrorCode, string) error
	unknownFrameHandler	*interface{}
}

type http3_goAwayFrame struct {
	StreamID *protocol.StreamID
}

type http3_goAwayFrame struct {
	StreamID *protocol.StreamID
}

type http3_gzipReader struct {
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http3_gzipReader struct {
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http3_headerWithOrder struct {
	key		*string
	values		*[]string
	order		*int
	hasOrder	*bool
}

type http3_headerWithOrder struct {
	key		*string
	values		*[]string
	order		*int
	hasOrder	*bool
}

type http3_headersFrame struct {
	Length *uint64
}

type http3_headersFrame struct {
	Length *uint64
}

type http3_hijackableBody struct {
	body		*interface{}
	reqDone		*chan<- struct {}
	reqDoneOnce	*sync.Once
}

type http3_hijackableBody struct {
	body		*interface{}
	reqDone		*chan<- struct {}
	reqDoneOnce	*sync.Once
}

type http3_requestWriter struct {
	mutex		*sync.Mutex
	encoder		*qpack.Encoder
	headerBuf	*bytes.Buffer
}

type http3_requestWriter struct {
	mutex		*sync.Mutex
	encoder		*qpack.Encoder
	headerBuf	*bytes.Buffer
}

type http3_roundTripperWithCount struct {
	cancel		*context.CancelFunc
	dialing		*chan struct {}
	dialErr		*error
	conn		*quic.Conn
	clientConn	*interface{}
	useCount	*atomic.Int64
}

type http3_roundTripperWithCount struct {
	cancel		*context.CancelFunc
	dialing		*chan struct {}
	dialErr		*error
	conn		*quic.Conn
	clientConn	*interface{}
	useCount	*atomic.Int64
}

type http3_settingsFrame struct {
	Datagram	*bool
	ExtendedConnect	*bool
	Other		*map[uint64]uint64
	Order		*[]uint64
}

type http3_settingsFrame struct {
	Datagram	*bool
	ExtendedConnect	*bool
	Other		*map[uint64]uint64
	Order		*[]uint64
}

type http3_stateTrackingStream struct {
	Stream		*quic.Stream
	sendDatagram	*func([]uint8) error
	hasData		*chan struct {}
	queue		*[][]uint8
	mx		*sync.Mutex
	sendErr		*error
	recvErr		*error
	clearer		*interface{}
}

type http3_stateTrackingStream struct {
	Stream		*quic.Stream
	sendDatagram	*func([]uint8) error
	hasData		*chan struct {}
	queue		*[][]uint8
	mx		*sync.Mutex
	sendErr		*error
	recvErr		*error
	clearer		*interface{}
}

type http3_streamClearer interface {
}

type http3_streamClearer interface {
}

type http3_tracingReader struct {
	Reader		*io.Reader
	readFirst	*bool
	trace		*httptrace.ClientTrace
}

type http3_tracingReader struct {
	Reader		*io.Reader
	readFirst	*bool
	trace		*httptrace.ClientTrace
}

type http3_unknownFrameHandlerFunc func()

type http3_unknownFrameHandlerFunc func()

type httpfloods_Config struct {
	URL			*string
	Method			*string
	Http3Fingerprint	*string
	Data			*[]uint8
	FollowRedirects		*bool
	Headers			*map[string]string
	Cookies			*map[string]string
	Delay			*time.Duration
}

type httpfloods_Config struct {
	URL			*string
	Method			*string
	Http3Fingerprint	*string
	Data			*[]uint8
	FollowRedirects		*bool
	Headers			*map[string]string
	Cookies			*map[string]string
	Delay			*time.Duration
}

type httpproxy_Config struct {
	HTTPProxy	*string
	HTTPSProxy	*string
	NoProxy		*string
	CGI		*bool
}

type httpproxy_Config struct {
	HTTPProxy	*string
	HTTPSProxy	*string
	NoProxy		*string
	CGI		*bool
}

type httpproxy_Config struct {
	HTTPProxy	*string
	HTTPSProxy	*string
	NoProxy		*string
	CGI		*bool
}

type httpproxy_Config struct {
	HTTPProxy	*string
	HTTPSProxy	*string
	NoProxy		*string
	CGI		*bool
}

type httpproxy_allMatch struct {
}

type httpproxy_allMatch struct {
}

type httpproxy_allMatch struct {
}

type httpproxy_allMatch struct {
}

type httpproxy_cidrMatch struct {
	cidr *net.IPNet
}

type httpproxy_cidrMatch struct {
	cidr *net.IPNet
}

type httpproxy_cidrMatch struct {
	cidr *net.IPNet
}

type httpproxy_cidrMatch struct {
	cidr *net.IPNet
}

type httpproxy_config struct {
	Config		*httpproxy.Config
	httpsProxy	*url.URL
	httpProxy	*url.URL
	ipMatchers	*[]httpproxy.matcher
	domainMatchers	*[]httpproxy.matcher
}

type httpproxy_config struct {
	Config		*httpproxy.Config
	httpsProxy	*url.URL
	httpProxy	*url.URL
	ipMatchers	*[]httpproxy.matcher
	domainMatchers	*[]httpproxy.matcher
}

type httpproxy_config struct {
	Config		*httpproxy.Config
	httpsProxy	*url.URL
	httpProxy	*url.URL
	ipMatchers	*[]httpproxy.matcher
	domainMatchers	*[]httpproxy.matcher
}

type httpproxy_config struct {
	Config		*httpproxy.Config
	httpsProxy	*url.URL
	httpProxy	*url.URL
	ipMatchers	*[]httpproxy.matcher
	domainMatchers	*[]httpproxy.matcher
}

type httpproxy_domainMatch struct {
	host		*string
	port		*string
	matchHost	*bool
}

type httpproxy_domainMatch struct {
	host		*string
	port		*string
	matchHost	*bool
}

type httpproxy_domainMatch struct {
	host		*string
	port		*string
	matchHost	*bool
}

type httpproxy_domainMatch struct {
	host		*string
	port		*string
	matchHost	*bool
}

type httpproxy_ipMatch struct {
	ip	*net.IP
	port	*string
}

type httpproxy_ipMatch struct {
	ip	*net.IP
	port	*string
}

type httpproxy_ipMatch struct {
	ip	*net.IP
	port	*string
}

type httpproxy_ipMatch struct {
	ip	*net.IP
	port	*string
}

type httpproxy_matcher interface {
}

type httpproxy_matcher interface {
}

type httpproxy_matcher interface {
}

type httpproxy_matcher interface {
}

type httptrace_ClientTrace struct {
	GetConn			*func(string)
	GotConn			*func(httptrace.GotConnInfo)
	PutIdleConn		*func(error)
	GotFirstResponseByte	*func()
	Got100Continue		*func()
	Got1xxResponse		*func(int, textproto.MIMEHeader) error
	DNSStart		*func(httptrace.DNSStartInfo)
	DNSDone			*func(httptrace.DNSDoneInfo)
	ConnectStart		*func(string, string)
	ConnectDone		*func(string, string, error)
	TLSHandshakeStart	*func()
	TLSHandshakeDone	*func(tls.ConnectionState, error)
	WroteHeaderField	*func(string, []string)
	WroteHeaders		*func()
	Wait100Continue		*func()
	WroteRequest		*func(httptrace.WroteRequestInfo)
}

type httptrace_ClientTrace struct {
	GetConn			*func(string)
	GotConn			*func(httptrace.GotConnInfo)
	PutIdleConn		*func(error)
	GotFirstResponseByte	*func()
	Got100Continue		*func()
	Got1xxResponse		*func(int, textproto.MIMEHeader) error
	DNSStart		*func(httptrace.DNSStartInfo)
	DNSDone			*func(httptrace.DNSDoneInfo)
	ConnectStart		*func(string, string)
	ConnectDone		*func(string, string, error)
	TLSHandshakeStart	*func()
	TLSHandshakeDone	*func(tls.ConnectionState, error)
	WroteHeaderField	*func(string, []string)
	WroteHeaders		*func()
	Wait100Continue		*func()
	WroteRequest		*func(httptrace.WroteRequestInfo)
}

type httptrace_ClientTrace struct {
	GetConn			*func(string)
	GotConn			*func(httptrace.GotConnInfo)
	PutIdleConn		*func(error)
	GotFirstResponseByte	*func()
	Got100Continue		*func()
	Got1xxResponse		*func(int, textproto.MIMEHeader) error
	DNSStart		*func(httptrace.DNSStartInfo)
	DNSDone			*func(httptrace.DNSDoneInfo)
	ConnectStart		*func(string, string)
	ConnectDone		*func(string, string, error)
	TLSHandshakeStart	*func()
	TLSHandshakeDone	*func(tls.ConnectionState, error)
	WroteHeaderField	*func(string, []string)
	WroteHeaders		*func()
	Wait100Continue		*func()
	WroteRequest		*func(httptrace.WroteRequestInfo)
}

type httptrace_ClientTrace struct {
	GetConn			*func(string)
	GotConn			*func(httptrace.GotConnInfo)
	PutIdleConn		*func(error)
	GotFirstResponseByte	*func()
	Got100Continue		*func()
	Got1xxResponse		*func(int, textproto.MIMEHeader) error
	DNSStart		*func(httptrace.DNSStartInfo)
	DNSDone			*func(httptrace.DNSDoneInfo)
	ConnectStart		*func(string, string)
	ConnectDone		*func(string, string, error)
	TLSHandshakeStart	*func()
	TLSHandshakeDone	*func(tls.ConnectionState, error)
	WroteHeaderField	*func(string, []string)
	WroteHeaders		*func()
	Wait100Continue		*func()
	WroteRequest		*func(httptrace.WroteRequestInfo)
}

type httptrace_DNSDoneInfo struct {
	Addrs		*[]net.IPAddr
	Err		*error
	Coalesced	*bool
}

type httptrace_DNSDoneInfo struct {
	Addrs		*[]net.IPAddr
	Err		*error
	Coalesced	*bool
}

type httptrace_DNSDoneInfo struct {
	Addrs		*[]net.IPAddr
	Err		*error
	Coalesced	*bool
}

type httptrace_DNSDoneInfo struct {
	Addrs		*[]net.IPAddr
	Err		*error
	Coalesced	*bool
}

type httptrace_DNSStartInfo struct {
	Host *string
}

type httptrace_DNSStartInfo struct {
	Host *string
}

type httptrace_DNSStartInfo struct {
	Host *string
}

type httptrace_DNSStartInfo struct {
	Host *string
}

type httptrace_GotConnInfo struct {
	Conn		*net.Conn
	Reused		*bool
	WasIdle		*bool
	IdleTime	*time.Duration
}

type httptrace_GotConnInfo struct {
	Conn		*net.Conn
	Reused		*bool
	WasIdle		*bool
	IdleTime	*time.Duration
}

type httptrace_GotConnInfo struct {
	Conn		*net.Conn
	Reused		*bool
	WasIdle		*bool
	IdleTime	*time.Duration
}

type httptrace_GotConnInfo struct {
	Conn		*net.Conn
	Reused		*bool
	WasIdle		*bool
	IdleTime	*time.Duration
}

type httptrace_WroteRequestInfo struct {
	Err *error
}

type httptrace_WroteRequestInfo struct {
	Err *error
}

type httptrace_WroteRequestInfo struct {
	Err *error
}

type httptrace_WroteRequestInfo struct {
	Err *error
}

type httptrace_clientEventContextKey struct {
}

type httptrace_clientEventContextKey struct {
}

type httptrace_clientEventContextKey struct {
}

type httptrace_clientEventContextKey struct {
}

type huff0_ReusePolicy uint8

type huff0_ReusePolicy uint8

type huff0_Scratch struct {
	count		*[256]uint32
	Out		*[]uint8
	OutTable	*[]uint8
	OutData		*[]uint8
	MaxDecodedSize	*int
	srcLen		*int
	MaxSymbolValue	*uint8
	TableLog	*uint8
	Reuse		*huff0.ReusePolicy
	WantLogLess	*uint8
	symbolLen	*uint16
	maxCount	*int
	clearCount	*bool
	actualTableLog	*uint8
	prevTableLog	*uint8
	prevTable	*interface{}
	cTable		*interface{}
	dt		*interface{}
	nodes		*[]huff0.nodeElt
	tmpOut		*[4][]uint8
	fse		*fse.Scratch
	decPool		*sync.Pool
	huffWeight	*[256]uint8
}

type huff0_Scratch struct {
	count		*[256]uint32
	Out		*[]uint8
	OutTable	*[]uint8
	OutData		*[]uint8
	MaxDecodedSize	*int
	srcLen		*int
	MaxSymbolValue	*uint8
	TableLog	*uint8
	Reuse		*huff0.ReusePolicy
	WantLogLess	*uint8
	symbolLen	*uint16
	maxCount	*int
	clearCount	*bool
	actualTableLog	*uint8
	prevTableLog	*uint8
	prevTable	*interface{}
	cTable		*interface{}
	dt		*interface{}
	nodes		*[]huff0.nodeElt
	tmpOut		*[4][]uint8
	fse		*fse.Scratch
	decPool		*sync.Pool
	huffWeight	*[256]uint8
}

type huff0_cTable []*interface{}

type huff0_cTable []*interface{}

type huff0_cTableEntry struct {
	val	*uint16
	nBits	*uint8
}

type huff0_cTableEntry struct {
	val	*uint16
	nBits	*uint8
}

type huff0_dEntrySingle struct {
	entry *uint16
}

type huff0_dEntrySingle struct {
	entry *uint16
}

type huff0_dTable struct {
	single *[]huff0.dEntrySingle
}

type huff0_dTable struct {
	single *[]huff0.dEntrySingle
}

type huff0_nodeElt uint64

type huff0_nodeElt uint64

type idna_labelError struct {
	label	*string
	code_	*string
}

type idna_labelError struct {
	label	*string
	code_	*string
}

type idna_labelError struct {
	label	*string
	code_	*string
}

type idna_labelError struct {
	label	*string
	code_	*string
}

type idna_runeError int32

type idna_runeError int32

type idna_runeError int32

type idna_runeError int32

type ipv4_ControlFlags uint

type ipv4_ControlFlags uint

type ipv4_ControlMessage struct {
	TTL	*int
	Src	*net.IP
	Dst	*net.IP
	IfIndex	*int
}

type ipv4_ControlMessage struct {
	TTL	*int
	Src	*net.IP
	Dst	*net.IP
	IfIndex	*int
}

type ipv4_PacketConn struct {
	genericOpt	*interface{}
	dgramOpt	*interface{}
	payloadHandler	*interface{}
}

type ipv4_PacketConn struct {
	genericOpt	*interface{}
	dgramOpt	*interface{}
	payloadHandler	*interface{}
}

type ipv4_dgramOpt struct {
	Conn *socket.Conn
}

type ipv4_dgramOpt struct {
	Conn *socket.Conn
}

type ipv4_genericOpt struct {
	Conn *socket.Conn
}

type ipv4_genericOpt struct {
	Conn *socket.Conn
}

type ipv4_payloadHandler struct {
	PacketConn	*net.PacketConn
	Conn		*socket.Conn
	rawOpt		*interface{}
}

type ipv4_payloadHandler struct {
	PacketConn	*net.PacketConn
	Conn		*socket.Conn
	rawOpt		*interface{}
}

type ipv4_rawOpt struct {
	RWMutex	*sync.RWMutex
	cflags	*ipv4.ControlFlags
}

type ipv4_rawOpt struct {
	RWMutex	*sync.RWMutex
	cflags	*ipv4.ControlFlags
}

type ipv6_ControlMessage struct {
	TrafficClass	*int
	HopLimit	*int
	Src		*net.IP
	Dst		*net.IP
	IfIndex		*int
	NextHop		*net.IP
	MTU		*int
}

type ipv6_ControlMessage struct {
	TrafficClass	*int
	HopLimit	*int
	Src		*net.IP
	Dst		*net.IP
	IfIndex		*int
	NextHop		*net.IP
	MTU		*int
}

type json_Marshaler interface {
}

type json_Marshaler interface {
}

type json_MarshalerError struct {
	Type		*reflect.Type
	Err		*error
	sourceFunc	*string
}

type json_MarshalerError struct {
	Type		*reflect.Type
	Err		*error
	sourceFunc	*string
}

type json_Number string

type json_Number string

type json_SyntaxError struct {
	msg	*string
	Offset	*int64
}

type json_SyntaxError struct {
	msg	*string
	Offset	*int64
}

type json_UnsupportedTypeError struct {
	Type *reflect.Type
}

type json_UnsupportedTypeError struct {
	Type *reflect.Type
}

type json_UnsupportedValueError struct {
	Value	*reflect.Value
	Str	*string
}

type json_UnsupportedValueError struct {
	Value	*reflect.Value
	Str	*string
}

type json_arrayEncoder struct {
	elemEnc *interface{}
}

type json_arrayEncoder struct {
	elemEnc *interface{}
}

type json_condAddrEncoder struct {
	canAddrEnc	*interface{}
	elseEnc		*interface{}
}

type json_condAddrEncoder struct {
	canAddrEnc	*interface{}
	elseEnc		*interface{}
}

type json_encOpts struct {
	quoted		*bool
	escapeHTML	*bool
}

type json_encOpts struct {
	quoted		*bool
	escapeHTML	*bool
}

type json_encodeState struct {
	Buffer		*bytes.Buffer
	ptrLevel	*uint
	ptrSeen		*map[interface {}]struct {}
}

type json_encodeState struct {
	Buffer		*bytes.Buffer
	ptrLevel	*uint
	ptrSeen		*map[interface {}]struct {}
}

type json_encoderFunc func()

type json_encoderFunc func()

type json_field struct {
	name		*string
	nameBytes	*[]uint8
	nameNonEsc	*string
	nameEscHTML	*string
	tag		*bool
	index		*[]int
	typ		*reflect.Type
	omitEmpty	*bool
	omitZero	*bool
	isZero		*func(reflect.Value) bool
	quoted		*bool
	encoder		*interface{}
}

type json_field struct {
	name		*string
	nameBytes	*[]uint8
	nameNonEsc	*string
	nameEscHTML	*string
	tag		*bool
	index		*[]int
	typ		*reflect.Type
	omitEmpty	*bool
	omitZero	*bool
	isZero		*func(reflect.Value) bool
	quoted		*bool
	encoder		*interface{}
}

type json_floatEncoder int

type json_floatEncoder int

type json_isZeroer interface {
}

type json_isZeroer interface {
}

type json_jsonError struct {
	error *error
}

type json_jsonError struct {
	error *error
}

type json_mapEncoder struct {
	elemEnc *interface{}
}

type json_mapEncoder struct {
	elemEnc *interface{}
}

type json_ptrEncoder struct {
	elemEnc *interface{}
}

type json_ptrEncoder struct {
	elemEnc *interface{}
}

type json_reflectWithString struct {
	v	*reflect.Value
	ks	*string
}

type json_reflectWithString struct {
	v	*reflect.Value
	ks	*string
}

type json_scanner struct {
	step		*func(*json.scanner, uint8) int
	endTop		*bool
	parseState	*[]int
	err		*error
	bytes		*int64
}

type json_scanner struct {
	step		*func(*json.scanner, uint8) int
	endTop		*bool
	parseState	*[]int
	err		*error
	bytes		*int64
}

type json_sliceEncoder struct {
	arrayEnc *interface{}
}

type json_sliceEncoder struct {
	arrayEnc *interface{}
}

type json_structEncoder struct {
	fields *interface{}
}

type json_structEncoder struct {
	fields *interface{}
}

type json_structFields struct {
	list		*[]json.field
	byExactName	*map[string]*json.field
	byFoldedName	*map[string]*json.field
}

type json_structFields struct {
	list		*[]json.field
	byExactName	*map[string]*json.field
	byFoldedName	*map[string]*json.field
}

type kem_AuthScheme interface {
}

type kem_AuthScheme interface {
}

type kem_PrivateKey interface {
}

type kem_PrivateKey interface {
}

type kem_PublicKey interface {
}

type kem_PublicKey interface {
}

type kem_Scheme interface {
}

type kem_Scheme interface {
}

type kyber768_PrivateKey struct {
	sk	*kyber768.PrivateKey
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
	z	*[32]uint8
}

type kyber768_PrivateKey struct {
	sh *internal.Vec
}

type kyber768_PrivateKey struct {
	sh *internal.Vec
}

type kyber768_PrivateKey struct {
	sk	*kyber768.PrivateKey
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
	z	*[32]uint8
}

type kyber768_PublicKey struct {
	rho	*[32]uint8
	th	*internal.Vec
	aT	*internal.Mat
}

type kyber768_PublicKey struct {
	rho	*[32]uint8
	th	*internal.Vec
	aT	*internal.Mat
}

type kyber768_PublicKey struct {
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
}

type kyber768_PublicKey struct {
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
}

type kyber768_scheme struct {
}

type kyber768_scheme struct {
}

type layers_ARP struct {
	BaseLayer		*layers.BaseLayer
	AddrType		*layers.LinkType
	Protocol		*layers.EthernetType
	HwAddressSize		*uint8
	ProtAddressSize		*uint8
	Operation		*uint16
	SourceHwAddress		*[]uint8
	SourceProtAddress	*[]uint8
	DstHwAddress		*[]uint8
	DstProtAddress		*[]uint8
}

type layers_ARP struct {
	BaseLayer		*layers.BaseLayer
	AddrType		*layers.LinkType
	Protocol		*layers.EthernetType
	HwAddressSize		*uint8
	ProtAddressSize		*uint8
	Operation		*uint16
	SourceHwAddress		*[]uint8
	SourceProtAddress	*[]uint8
	DstHwAddress		*[]uint8
	DstProtAddress		*[]uint8
}

type layers_ASExternalLSA struct {
	Flags			*uint8
	Metric			*uint32
	PrefixLength		*uint8
	PrefixOptions		*uint8
	RefLSType		*uint16
	AddressPrefix		*[]uint8
	ForwardingAddress	*[]uint8
	ExternalRouteTag	*uint32
	RefLinkStateID		*uint32
}

type layers_ASExternalLSA struct {
	Flags			*uint8
	Metric			*uint32
	PrefixLength		*uint8
	PrefixOptions		*uint8
	RefLSType		*uint16
	AddressPrefix		*[]uint8
	ForwardingAddress	*[]uint8
	ExternalRouteTag	*uint32
	RefLinkStateID		*uint32
}

type layers_ASExternalLSAV2 struct {
	NetworkMask		*uint32
	ExternalBit		*uint8
	Metric			*uint32
	ForwardingAddress	*uint32
	ExternalRouteTag	*uint32
}

type layers_ASExternalLSAV2 struct {
	NetworkMask		*uint32
	ExternalBit		*uint8
	Metric			*uint32
	ForwardingAddress	*uint32
	ExternalRouteTag	*uint32
}

type layers_ASF struct {
	BaseLayer		*layers.BaseLayer
	ASFDataIdentifier	*layers.ASFDataIdentifier
	Tag			*uint8
	Length			*uint8
}

type layers_ASF struct {
	BaseLayer		*layers.BaseLayer
	ASFDataIdentifier	*layers.ASFDataIdentifier
	Tag			*uint8
	Length			*uint8
}

type layers_ASFDataIdentifier struct {
	Enterprise	*uint32
	Type		*uint8
}

type layers_ASFDataIdentifier struct {
	Enterprise	*uint32
	Type		*uint8
}

type layers_ASFPresencePong struct {
	BaseLayer		*layers.BaseLayer
	Enterprise		*uint32
	OEM			*[4]uint8
	IPMI			*bool
	ASFv1			*bool
	SecurityExtensions	*bool
	DASH			*bool
}

type layers_ASFPresencePong struct {
	BaseLayer		*layers.BaseLayer
	Enterprise		*uint32
	OEM			*[4]uint8
	IPMI			*bool
	ASFv1			*bool
	SecurityExtensions	*bool
	DASH			*bool
}

type layers_BFD struct {
	BaseLayer			*layers.BaseLayer
	Version				*layers.BFDVersion
	Diagnostic			*layers.BFDDiagnostic
	State				*layers.BFDState
	Poll				*bool
	Final				*bool
	ControlPlaneIndependent		*bool
	AuthPresent			*bool
	Demand				*bool
	Multipoint			*bool
	DetectMultiplier		*layers.BFDDetectMultiplier
	MyDiscriminator			*layers.BFDDiscriminator
	YourDiscriminator		*layers.BFDDiscriminator
	DesiredMinTxInterval		*layers.BFDTimeInterval
	RequiredMinRxInterval		*layers.BFDTimeInterval
	RequiredMinEchoRxInterval	*layers.BFDTimeInterval
	AuthHeader			*layers.BFDAuthHeader
}

type layers_BFD struct {
	BaseLayer			*layers.BaseLayer
	Version				*layers.BFDVersion
	Diagnostic			*layers.BFDDiagnostic
	State				*layers.BFDState
	Poll				*bool
	Final				*bool
	ControlPlaneIndependent		*bool
	AuthPresent			*bool
	Demand				*bool
	Multipoint			*bool
	DetectMultiplier		*layers.BFDDetectMultiplier
	MyDiscriminator			*layers.BFDDiscriminator
	YourDiscriminator		*layers.BFDDiscriminator
	DesiredMinTxInterval		*layers.BFDTimeInterval
	RequiredMinRxInterval		*layers.BFDTimeInterval
	RequiredMinEchoRxInterval	*layers.BFDTimeInterval
	AuthHeader			*layers.BFDAuthHeader
}

type layers_BFDAuthData []*uint8

type layers_BFDAuthData []*uint8

type layers_BFDAuthHeader struct {
	AuthType	*layers.BFDAuthType
	KeyID		*layers.BFDAuthKeyID
	SequenceNumber	*layers.BFDAuthSequenceNumber
	Data		*layers.BFDAuthData
}

type layers_BFDAuthHeader struct {
	AuthType	*layers.BFDAuthType
	KeyID		*layers.BFDAuthKeyID
	SequenceNumber	*layers.BFDAuthSequenceNumber
	Data		*layers.BFDAuthData
}

type layers_BFDAuthKeyID uint8

type layers_BFDAuthKeyID uint8

type layers_BFDAuthSequenceNumber uint32

type layers_BFDAuthSequenceNumber uint32

type layers_BFDAuthType uint8

type layers_BFDAuthType uint8

type layers_BFDDetectMultiplier uint8

type layers_BFDDetectMultiplier uint8

type layers_BFDDiagnostic uint8

type layers_BFDDiagnostic uint8

type layers_BFDDiscriminator uint32

type layers_BFDDiscriminator uint32

type layers_BFDState uint8

type layers_BFDState uint8

type layers_BFDTimeInterval uint32

type layers_BFDTimeInterval uint32

type layers_BFDVersion uint8

type layers_BFDVersion uint8

type layers_BaseLayer struct {
	Contents	*[]uint8
	Payload		*[]uint8
}

type layers_BaseLayer struct {
	Contents	*[]uint8
	Payload		*[]uint8
}

type layers_CDPCapabilities struct {
	L3Router	*bool
	TBBridge	*bool
	SPBridge	*bool
	L2Switch	*bool
	IsHost		*bool
	IGMPFilter	*bool
	L1Repeater	*bool
	IsPhone		*bool
	RemotelyManaged	*bool
}

type layers_CDPCapabilities struct {
	L3Router	*bool
	TBBridge	*bool
	SPBridge	*bool
	L2Switch	*bool
	IsHost		*bool
	IGMPFilter	*bool
	L1Repeater	*bool
	IsPhone		*bool
	RemotelyManaged	*bool
}

type layers_CDPEnergyWise struct {
	EncryptedData	*[]uint8
	Unknown1	*uint32
	SequenceNumber	*uint32
	ModelNumber	*string
	Unknown2	*uint16
	HardwareID	*string
	SerialNum	*string
	Unknown3	*[]uint8
	Role		*string
	Domain		*string
	Name		*string
	ReplyUnknown1	*[]uint8
	ReplyPort	*[]uint8
	ReplyAddress	*[]uint8
	ReplyUnknown2	*[]uint8
	ReplyUnknown3	*[]uint8
}

type layers_CDPEnergyWise struct {
	EncryptedData	*[]uint8
	Unknown1	*uint32
	SequenceNumber	*uint32
	ModelNumber	*string
	Unknown2	*uint16
	HardwareID	*string
	SerialNum	*string
	Unknown3	*[]uint8
	Role		*string
	Domain		*string
	Name		*string
	ReplyUnknown1	*[]uint8
	ReplyPort	*[]uint8
	ReplyAddress	*[]uint8
	ReplyUnknown2	*[]uint8
	ReplyUnknown3	*[]uint8
}

type layers_CDPHello struct {
	OUI			*[]uint8
	ProtocolID		*uint16
	ClusterMaster		*net.IP
	Unknown1		*net.IP
	Version			*uint8
	SubVersion		*uint8
	Status			*uint8
	Unknown2		*uint8
	ClusterCommander	*net.HardwareAddr
	SwitchMAC		*net.HardwareAddr
	Unknown3		*uint8
	ManagementVLAN		*uint16
}

type layers_CDPHello struct {
	OUI			*[]uint8
	ProtocolID		*uint16
	ClusterMaster		*net.IP
	Unknown1		*net.IP
	Version			*uint8
	SubVersion		*uint8
	Status			*uint8
	Unknown2		*uint8
	ClusterCommander	*net.HardwareAddr
	SwitchMAC		*net.HardwareAddr
	Unknown3		*uint8
	ManagementVLAN		*uint16
}

type layers_CDPLocation struct {
	Type		*uint8
	Location	*string
}

type layers_CDPLocation struct {
	Type		*uint8
	Location	*string
}

type layers_CDPPowerDialogue struct {
	ID	*uint16
	MgmtID	*uint16
	Values	*[]uint32
}

type layers_CDPPowerDialogue struct {
	ID	*uint16
	MgmtID	*uint16
	Values	*[]uint32
}

type layers_CDPSparePairPoE struct {
	PSEFourWire	*bool
	PDArchShared	*bool
	PDRequestOn	*bool
	PSEOn		*bool
}

type layers_CDPSparePairPoE struct {
	PSEFourWire	*bool
	PDArchShared	*bool
	PDRequestOn	*bool
	PSEOn		*bool
}

type layers_CDPTLVType uint16

type layers_CDPTLVType uint16

type layers_CDPVLANDialogue struct {
	ID	*uint8
	VLAN	*uint16
}

type layers_CDPVLANDialogue struct {
	ID	*uint8
	VLAN	*uint16
}

type layers_CiscoDiscovery struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	TTL		*uint8
	Checksum	*uint16
	Values		*[]layers.CiscoDiscoveryValue
}

type layers_CiscoDiscovery struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	TTL		*uint8
	Checksum	*uint16
	Values		*[]layers.CiscoDiscoveryValue
}

type layers_CiscoDiscoveryInfo struct {
	BaseLayer		*layers.BaseLayer
	CDPHello		*layers.CDPHello
	DeviceID		*string
	Addresses		*[]net.IP
	PortID			*string
	Capabilities		*layers.CDPCapabilities
	Version			*string
	Platform		*string
	IPPrefixes		*[]net.IPNet
	VTPDomain		*string
	NativeVLAN		*uint16
	FullDuplex		*bool
	VLANReply		*layers.CDPVLANDialogue
	VLANQuery		*layers.CDPVLANDialogue
	PowerConsumption	*uint16
	MTU			*uint32
	ExtendedTrust		*uint8
	UntrustedCOS		*uint8
	SysName			*string
	SysOID			*string
	MgmtAddresses		*[]net.IP
	Location		*layers.CDPLocation
	PowerRequest		*layers.CDPPowerDialogue
	PowerAvailable		*layers.CDPPowerDialogue
	SparePairPoe		*layers.CDPSparePairPoE
	EnergyWise		*layers.CDPEnergyWise
	Unknown			*[]layers.CiscoDiscoveryValue
}

type layers_CiscoDiscoveryInfo struct {
	BaseLayer		*layers.BaseLayer
	CDPHello		*layers.CDPHello
	DeviceID		*string
	Addresses		*[]net.IP
	PortID			*string
	Capabilities		*layers.CDPCapabilities
	Version			*string
	Platform		*string
	IPPrefixes		*[]net.IPNet
	VTPDomain		*string
	NativeVLAN		*uint16
	FullDuplex		*bool
	VLANReply		*layers.CDPVLANDialogue
	VLANQuery		*layers.CDPVLANDialogue
	PowerConsumption	*uint16
	MTU			*uint32
	ExtendedTrust		*uint8
	UntrustedCOS		*uint8
	SysName			*string
	SysOID			*string
	MgmtAddresses		*[]net.IP
	Location		*layers.CDPLocation
	PowerRequest		*layers.CDPPowerDialogue
	PowerAvailable		*layers.CDPPowerDialogue
	SparePairPoe		*layers.CDPSparePairPoE
	EnergyWise		*layers.CDPEnergyWise
	Unknown			*[]layers.CiscoDiscoveryValue
}

type layers_CiscoDiscoveryValue struct {
	Type	*layers.CDPTLVType
	Length	*uint16
	Value	*[]uint8
}

type layers_CiscoDiscoveryValue struct {
	Type	*layers.CDPTLVType
	Length	*uint16
	Value	*[]uint8
}

type layers_DHCPMsgType uint8

type layers_DHCPMsgType uint8

type layers_DHCPOp uint8

type layers_DHCPOp uint8

type layers_DHCPOpt uint8

type layers_DHCPOpt uint8

type layers_DHCPOption struct {
	Type	*layers.DHCPOpt
	Length	*uint8
	Data	*[]uint8
}

type layers_DHCPOption struct {
	Type	*layers.DHCPOpt
	Length	*uint8
	Data	*[]uint8
}

type layers_DHCPOptions []*layers.DHCPOption

type layers_DHCPOptions []*layers.DHCPOption

type layers_DHCPv4 struct {
	BaseLayer	*layers.BaseLayer
	Operation	*layers.DHCPOp
	HardwareType	*layers.LinkType
	HardwareLen	*uint8
	HardwareOpts	*uint8
	Xid		*uint32
	Secs		*uint16
	Flags		*uint16
	ClientIP	*net.IP
	YourClientIP	*net.IP
	NextServerIP	*net.IP
	RelayAgentIP	*net.IP
	ClientHWAddr	*net.HardwareAddr
	ServerName	*[]uint8
	File		*[]uint8
	Options		*layers.DHCPOptions
}

type layers_DHCPv4 struct {
	BaseLayer	*layers.BaseLayer
	Operation	*layers.DHCPOp
	HardwareType	*layers.LinkType
	HardwareLen	*uint8
	HardwareOpts	*uint8
	Xid		*uint32
	Secs		*uint16
	Flags		*uint16
	ClientIP	*net.IP
	YourClientIP	*net.IP
	NextServerIP	*net.IP
	RelayAgentIP	*net.IP
	ClientHWAddr	*net.HardwareAddr
	ServerName	*[]uint8
	File		*[]uint8
	Options		*layers.DHCPOptions
}

type layers_DHCPv4Error string

type layers_DHCPv4Error string

type layers_DHCPv6 struct {
	BaseLayer	*layers.BaseLayer
	MsgType		*layers.DHCPv6MsgType
	HopCount	*uint8
	LinkAddr	*net.IP
	PeerAddr	*net.IP
	TransactionID	*[]uint8
	Options		*layers.DHCPv6Options
}

type layers_DHCPv6 struct {
	BaseLayer	*layers.BaseLayer
	MsgType		*layers.DHCPv6MsgType
	HopCount	*uint8
	LinkAddr	*net.IP
	PeerAddr	*net.IP
	TransactionID	*[]uint8
	Options		*layers.DHCPv6Options
}

type layers_DHCPv6MsgType uint8

type layers_DHCPv6MsgType uint8

type layers_DHCPv6Opt uint16

type layers_DHCPv6Opt uint16

type layers_DHCPv6Option struct {
	Code	*layers.DHCPv6Opt
	Length	*uint16
	Data	*[]uint8
}

type layers_DHCPv6Option struct {
	Code	*layers.DHCPv6Opt
	Length	*uint16
	Data	*[]uint8
}

type layers_DHCPv6Options []*layers.DHCPv6Option

type layers_DHCPv6Options []*layers.DHCPv6Option

type layers_DNS struct {
	BaseLayer	*layers.BaseLayer
	ID		*uint16
	QR		*bool
	OpCode		*layers.DNSOpCode
	AA		*bool
	TC		*bool
	RD		*bool
	RA		*bool
	Z		*uint8
	ResponseCode	*layers.DNSResponseCode
	QDCount		*uint16
	ANCount		*uint16
	NSCount		*uint16
	ARCount		*uint16
	Questions	*[]layers.DNSQuestion
	Answers		*[]layers.DNSResourceRecord
	Authorities	*[]layers.DNSResourceRecord
	Additionals	*[]layers.DNSResourceRecord
	buffer		*[]uint8
}

type layers_DNS struct {
	BaseLayer	*layers.BaseLayer
	ID		*uint16
	QR		*bool
	OpCode		*layers.DNSOpCode
	AA		*bool
	TC		*bool
	RD		*bool
	RA		*bool
	Z		*uint8
	ResponseCode	*layers.DNSResponseCode
	QDCount		*uint16
	ANCount		*uint16
	NSCount		*uint16
	ARCount		*uint16
	Questions	*[]layers.DNSQuestion
	Answers		*[]layers.DNSResourceRecord
	Authorities	*[]layers.DNSResourceRecord
	Additionals	*[]layers.DNSResourceRecord
	buffer		*[]uint8
}

type layers_DNSClass uint16

type layers_DNSClass uint16

type layers_DNSMX struct {
	Preference	*uint16
	Name		*[]uint8
}

type layers_DNSMX struct {
	Preference	*uint16
	Name		*[]uint8
}

type layers_DNSOPT struct {
	Code	*layers.DNSOptionCode
	Data	*[]uint8
}

type layers_DNSOPT struct {
	Code	*layers.DNSOptionCode
	Data	*[]uint8
}

type layers_DNSOpCode uint8

type layers_DNSOpCode uint8

type layers_DNSOptionCode uint16

type layers_DNSOptionCode uint16

type layers_DNSQuestion struct {
	Name	*[]uint8
	Type	*layers.DNSType
	Class	*layers.DNSClass
}

type layers_DNSQuestion struct {
	Name	*[]uint8
	Type	*layers.DNSType
	Class	*layers.DNSClass
}

type layers_DNSResourceRecord struct {
	Name		*[]uint8
	Type		*layers.DNSType
	Class		*layers.DNSClass
	TTL		*uint32
	DataLength	*uint16
	Data		*[]uint8
	IP		*net.IP
	NS		*[]uint8
	CNAME		*[]uint8
	PTR		*[]uint8
	TXTs		*[][]uint8
	SOA		*layers.DNSSOA
	SRV		*layers.DNSSRV
	MX		*layers.DNSMX
	OPT		*[]layers.DNSOPT
	URI		*layers.DNSURI
	TXT		*[]uint8
}

type layers_DNSResourceRecord struct {
	Name		*[]uint8
	Type		*layers.DNSType
	Class		*layers.DNSClass
	TTL		*uint32
	DataLength	*uint16
	Data		*[]uint8
	IP		*net.IP
	NS		*[]uint8
	CNAME		*[]uint8
	PTR		*[]uint8
	TXTs		*[][]uint8
	SOA		*layers.DNSSOA
	SRV		*layers.DNSSRV
	MX		*layers.DNSMX
	OPT		*[]layers.DNSOPT
	URI		*layers.DNSURI
	TXT		*[]uint8
}

type layers_DNSResponseCode uint8

type layers_DNSResponseCode uint8

type layers_DNSSOA struct {
	MName	*[]uint8
	RName	*[]uint8
	Serial	*uint32
	Refresh	*uint32
	Retry	*uint32
	Expire	*uint32
	Minimum	*uint32
}

type layers_DNSSOA struct {
	MName	*[]uint8
	RName	*[]uint8
	Serial	*uint32
	Refresh	*uint32
	Retry	*uint32
	Expire	*uint32
	Minimum	*uint32
}

type layers_DNSSRV struct {
	Priority	*uint16
	Weight		*uint16
	Port		*uint16
	Name		*[]uint8
}

type layers_DNSSRV struct {
	Priority	*uint16
	Weight		*uint16
	Port		*uint16
	Name		*[]uint8
}

type layers_DNSType uint16

type layers_DNSType uint16

type layers_DNSURI struct {
	Priority	*uint16
	Weight		*uint16
	Target		*[]uint8
}

type layers_DNSURI struct {
	Priority	*uint16
	Weight		*uint16
	Target		*[]uint8
}

type layers_DbDescPkg struct {
	Options		*uint32
	InterfaceMTU	*uint16
	Flags		*uint16
	DDSeqNumber	*uint32
	LSAinfo		*[]layers.LSAheader
}

type layers_DbDescPkg struct {
	Options		*uint32
	InterfaceMTU	*uint16
	Flags		*uint16
	DDSeqNumber	*uint32
	LSAinfo		*[]layers.LSAheader
}

type layers_Dot11 struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.Dot11Type
	Proto		*uint8
	Flags		*layers.Dot11Flags
	DurationID	*uint16
	Address1	*net.HardwareAddr
	Address2	*net.HardwareAddr
	Address3	*net.HardwareAddr
	Address4	*net.HardwareAddr
	SequenceNumber	*uint16
	FragmentNumber	*uint16
	Checksum	*uint32
	QOS		*layers.Dot11QOS
	HTControl	*layers.Dot11HTControl
	DataLayer	*gopacket.Layer
}

type layers_Dot11 struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.Dot11Type
	Proto		*uint8
	Flags		*layers.Dot11Flags
	DurationID	*uint16
	Address1	*net.HardwareAddr
	Address2	*net.HardwareAddr
	Address3	*net.HardwareAddr
	Address4	*net.HardwareAddr
	SequenceNumber	*uint16
	FragmentNumber	*uint16
	Checksum	*uint32
	QOS		*layers.Dot11QOS
	HTControl	*layers.Dot11HTControl
	DataLayer	*gopacket.Layer
}

type layers_Dot11ASEL struct {
	Command	*uint8
	Data	*uint8
}

type layers_Dot11ASEL struct {
	Command	*uint8
	Data	*uint8
}

type layers_Dot11AckPolicy uint8

type layers_Dot11AckPolicy uint8

type layers_Dot11Algorithm uint16

type layers_Dot11Algorithm uint16

type layers_Dot11CodingType uint8

type layers_Dot11CodingType uint8

type layers_Dot11Ctrl struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11Ctrl struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11CtrlAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlBlockAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlBlockAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlBlockAckReq struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlBlockAckReq struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCFEnd struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCFEnd struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCFEndAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCFEndAck struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCTS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlCTS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlPowersavePoll struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlPowersavePoll struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlRTS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11CtrlRTS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11Data struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11Data struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11DataCFAck struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAck struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckPoll struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckPoll struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckPollNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFAckPollNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFPoll struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFPoll struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFPollNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataCFPollNoData struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataNull struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataNull struct {
	Dot11Data *layers.Dot11Data
}

type layers_Dot11DataQOS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11DataQOS struct {
	Dot11Ctrl *layers.Dot11Ctrl
}

type layers_Dot11DataQOSCFAckPollNoData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSCFAckPollNoData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSCFPollNoData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSCFPollNoData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSData struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFAck struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFAck struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFAckPoll struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFAckPoll struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFPoll struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSDataCFPoll struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSNull struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11DataQOSNull struct {
	Dot11DataQOS *layers.Dot11DataQOS
}

type layers_Dot11Flags uint8

type layers_Dot11Flags uint8

type layers_Dot11HTControl struct {
	ACConstraint	*bool
	RDGMorePPDU	*bool
	VHT		*layers.Dot11HTControlVHT
	HT		*layers.Dot11HTControlHT
}

type layers_Dot11HTControl struct {
	ACConstraint	*bool
	RDGMorePPDU	*bool
	VHT		*layers.Dot11HTControlVHT
	HT		*layers.Dot11HTControlHT
}

type layers_Dot11HTControlHT struct {
	LinkAdapationControl	*layers.Dot11LinkAdapationControl
	CalibrationPosition	*uint8
	CalibrationSequence	*uint8
	CSISteering		*uint8
	NDPAnnouncement		*bool
	DEI			*bool
}

type layers_Dot11HTControlHT struct {
	LinkAdapationControl	*layers.Dot11LinkAdapationControl
	CalibrationPosition	*uint8
	CalibrationSequence	*uint8
	CSISteering		*uint8
	NDPAnnouncement		*bool
	DEI			*bool
}

type layers_Dot11HTControlMFB struct {
	NumSTS	*uint8
	VHTMCS	*uint8
	BW	*uint8
	SNR	*int8
}

type layers_Dot11HTControlMFB struct {
	NumSTS	*uint8
	VHTMCS	*uint8
	BW	*uint8
	SNR	*int8
}

type layers_Dot11HTControlVHT struct {
	MRQ		*bool
	UnsolicitedMFB	*bool
	MSI		*uint8
	MFB		*layers.Dot11HTControlMFB
	CompressedMSI	*uint8
	STBCIndication	*bool
	MFSI		*uint8
	GID		*uint8
	CodingType	*layers.Dot11CodingType
	FbTXBeamformed	*bool
}

type layers_Dot11HTControlVHT struct {
	MRQ		*bool
	UnsolicitedMFB	*bool
	MSI		*uint8
	MFB		*layers.Dot11HTControlMFB
	CompressedMSI	*uint8
	STBCIndication	*bool
	MFSI		*uint8
	GID		*uint8
	CodingType	*layers.Dot11CodingType
	FbTXBeamformed	*bool
}

type layers_Dot11InformationElement struct {
	BaseLayer	*layers.BaseLayer
	ID		*layers.Dot11InformationElementID
	Length		*uint8
	OUI		*[]uint8
	Info		*[]uint8
}

type layers_Dot11InformationElement struct {
	BaseLayer	*layers.BaseLayer
	ID		*layers.Dot11InformationElementID
	Length		*uint8
	OUI		*[]uint8
	Info		*[]uint8
}

type layers_Dot11InformationElementID uint8

type layers_Dot11InformationElementID uint8

type layers_Dot11LinkAdapationControl struct {
	TRQ	*bool
	MRQ	*bool
	MSI	*uint8
	MFSI	*uint8
	ASEL	*layers.Dot11ASEL
	MFB	*uint8
}

type layers_Dot11LinkAdapationControl struct {
	TRQ	*bool
	MRQ	*bool
	MSI	*uint8
	MFSI	*uint8
	ASEL	*layers.Dot11ASEL
	MFB	*uint8
}

type layers_Dot11Mgmt struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11Mgmt struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11MgmtATIM struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtATIM struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtAction struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtAction struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtActionNoAck struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtActionNoAck struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtArubaWLAN struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtArubaWLAN struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtAssociationReq struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	CapabilityInfo	*uint16
	ListenInterval	*uint16
}

type layers_Dot11MgmtAssociationReq struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	CapabilityInfo	*uint16
	ListenInterval	*uint16
}

type layers_Dot11MgmtAssociationResp struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	CapabilityInfo	*uint16
	Status		*layers.Dot11Status
	AID		*uint16
}

type layers_Dot11MgmtAssociationResp struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	CapabilityInfo	*uint16
	Status		*layers.Dot11Status
	AID		*uint16
}

type layers_Dot11MgmtAuthentication struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Algorithm	*layers.Dot11Algorithm
	Sequence	*uint16
	Status		*layers.Dot11Status
}

type layers_Dot11MgmtAuthentication struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Algorithm	*layers.Dot11Algorithm
	Sequence	*uint16
	Status		*layers.Dot11Status
}

type layers_Dot11MgmtBeacon struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Timestamp	*uint64
	Interval	*uint16
	Flags		*uint16
}

type layers_Dot11MgmtBeacon struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Timestamp	*uint64
	Interval	*uint16
	Flags		*uint16
}

type layers_Dot11MgmtDeauthentication struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Reason		*layers.Dot11Reason
}

type layers_Dot11MgmtDeauthentication struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Reason		*layers.Dot11Reason
}

type layers_Dot11MgmtDisassociation struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Reason		*layers.Dot11Reason
}

type layers_Dot11MgmtDisassociation struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Reason		*layers.Dot11Reason
}

type layers_Dot11MgmtMeasurementPilot struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtMeasurementPilot struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtProbeReq struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtProbeReq struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtProbeResp struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Timestamp	*uint64
	Interval	*uint16
	Flags		*uint16
}

type layers_Dot11MgmtProbeResp struct {
	Dot11Mgmt	*layers.Dot11Mgmt
	Timestamp	*uint64
	Interval	*uint16
	Flags		*uint16
}

type layers_Dot11MgmtReassociationReq struct {
	Dot11Mgmt		*layers.Dot11Mgmt
	CapabilityInfo		*uint16
	ListenInterval		*uint16
	CurrentApAddress	*net.HardwareAddr
}

type layers_Dot11MgmtReassociationReq struct {
	Dot11Mgmt		*layers.Dot11Mgmt
	CapabilityInfo		*uint16
	ListenInterval		*uint16
	CurrentApAddress	*net.HardwareAddr
}

type layers_Dot11MgmtReassociationResp struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11MgmtReassociationResp struct {
	Dot11Mgmt *layers.Dot11Mgmt
}

type layers_Dot11QOS struct {
	TID		*uint8
	EOSP		*bool
	AckPolicy	*layers.Dot11AckPolicy
	TXOP		*uint8
}

type layers_Dot11QOS struct {
	TID		*uint8
	EOSP		*bool
	AckPolicy	*layers.Dot11AckPolicy
	TXOP		*uint8
}

type layers_Dot11Reason uint16

type layers_Dot11Reason uint16

type layers_Dot11Status uint16

type layers_Dot11Status uint16

type layers_Dot11Type uint8

type layers_Dot11Type uint8

type layers_Dot11WEP struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot11WEP struct {
	BaseLayer *layers.BaseLayer
}

type layers_Dot1Q struct {
	BaseLayer	*layers.BaseLayer
	Priority	*uint8
	DropEligible	*bool
	VLANIdentifier	*uint16
	Type		*layers.EthernetType
}

type layers_Dot1Q struct {
	BaseLayer	*layers.BaseLayer
	Priority	*uint8
	DropEligible	*bool
	VLANIdentifier	*uint16
	Type		*layers.EthernetType
}

type layers_EAP struct {
	BaseLayer	*layers.BaseLayer
	Code		*layers.EAPCode
	Id		*uint8
	Length		*uint16
	Type		*layers.EAPType
	TypeData	*[]uint8
}

type layers_EAP struct {
	BaseLayer	*layers.BaseLayer
	Code		*layers.EAPCode
	Id		*uint8
	Length		*uint16
	Type		*layers.EAPType
	TypeData	*[]uint8
}

type layers_EAPCode uint8

type layers_EAPCode uint8

type layers_EAPOL struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*layers.EAPOLType
	Length		*uint16
}

type layers_EAPOL struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*layers.EAPOLType
	Length		*uint16
}

type layers_EAPOLKey struct {
	BaseLayer		*layers.BaseLayer
	KeyDescriptorType	*layers.EAPOLKeyDescriptorType
	KeyDescriptorVersion	*layers.EAPOLKeyDescriptorVersion
	KeyType			*layers.EAPOLKeyType
	KeyIndex		*uint8
	Install			*bool
	KeyACK			*bool
	KeyMIC			*bool
	Secure			*bool
	MICError		*bool
	Request			*bool
	HasEncryptedKeyData	*bool
	SMKMessage		*bool
	KeyLength		*uint16
	ReplayCounter		*uint64
	Nonce			*[]uint8
	IV			*[]uint8
	RSC			*uint64
	ID			*uint64
	MIC			*[]uint8
	KeyDataLength		*uint16
	EncryptedKeyData	*[]uint8
}

type layers_EAPOLKey struct {
	BaseLayer		*layers.BaseLayer
	KeyDescriptorType	*layers.EAPOLKeyDescriptorType
	KeyDescriptorVersion	*layers.EAPOLKeyDescriptorVersion
	KeyType			*layers.EAPOLKeyType
	KeyIndex		*uint8
	Install			*bool
	KeyACK			*bool
	KeyMIC			*bool
	Secure			*bool
	MICError		*bool
	Request			*bool
	HasEncryptedKeyData	*bool
	SMKMessage		*bool
	KeyLength		*uint16
	ReplayCounter		*uint64
	Nonce			*[]uint8
	IV			*[]uint8
	RSC			*uint64
	ID			*uint64
	MIC			*[]uint8
	KeyDataLength		*uint16
	EncryptedKeyData	*[]uint8
}

type layers_EAPOLKeyDescriptorType uint8

type layers_EAPOLKeyDescriptorType uint8

type layers_EAPOLKeyDescriptorVersion uint8

type layers_EAPOLKeyDescriptorVersion uint8

type layers_EAPOLKeyType uint8

type layers_EAPOLKeyType uint8

type layers_EAPOLType uint8

type layers_EAPOLType uint8

type layers_EAPType uint8

type layers_EAPType uint8

type layers_ERSPANII struct {
	BaseLayer	*layers.BaseLayer
	IsTruncated	*bool
	Version		*uint8
	CoS		*uint8
	TrunkEncap	*uint8
	VLANIdentifier	*uint16
	SessionID	*uint16
	Reserved	*uint16
	Index		*uint32
}

type layers_ERSPANII struct {
	BaseLayer	*layers.BaseLayer
	IsTruncated	*bool
	Version		*uint8
	CoS		*uint8
	TrunkEncap	*uint8
	VLANIdentifier	*uint16
	SessionID	*uint16
	Reserved	*uint16
	Index		*uint32
}

type layers_EnumMetadata struct {
	DecodeWith	*gopacket.Decoder
	Name		*string
	LayerType	*gopacket.LayerType
}

type layers_EnumMetadata struct {
	DecodeWith	*gopacket.Decoder
	Name		*string
	LayerType	*gopacket.LayerType
}

type layers_EtherIP struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Reserved	*uint16
}

type layers_EtherIP struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Reserved	*uint16
}

type layers_Ethernet struct {
	BaseLayer	*layers.BaseLayer
	SrcMAC		*net.HardwareAddr
	DstMAC		*net.HardwareAddr
	EthernetType	*layers.EthernetType
	Length		*uint16
}

type layers_Ethernet struct {
	BaseLayer	*layers.BaseLayer
	SrcMAC		*net.HardwareAddr
	DstMAC		*net.HardwareAddr
	EthernetType	*layers.EthernetType
	Length		*uint16
}

type layers_EthernetCTP struct {
	BaseLayer	*layers.BaseLayer
	SkipCount	*uint16
}

type layers_EthernetCTP struct {
	BaseLayer	*layers.BaseLayer
	SkipCount	*uint16
}

type layers_EthernetCTPForwardData struct {
	BaseLayer	*layers.BaseLayer
	Function	*layers.EthernetCTPFunction
	ForwardAddress	*[]uint8
}

type layers_EthernetCTPForwardData struct {
	BaseLayer	*layers.BaseLayer
	Function	*layers.EthernetCTPFunction
	ForwardAddress	*[]uint8
}

type layers_EthernetCTPFunction uint16

type layers_EthernetCTPFunction uint16

type layers_EthernetCTPReply struct {
	BaseLayer	*layers.BaseLayer
	Function	*layers.EthernetCTPFunction
	ReceiptNumber	*uint16
	Data		*[]uint8
}

type layers_EthernetCTPReply struct {
	BaseLayer	*layers.BaseLayer
	Function	*layers.EthernetCTPFunction
	ReceiptNumber	*uint16
	Data		*[]uint8
}

type layers_EthernetType uint16

type layers_EthernetType uint16

type layers_FDDI struct {
	BaseLayer	*layers.BaseLayer
	FrameControl	*layers.FDDIFrameControl
	Priority	*uint8
	SrcMAC		*net.HardwareAddr
	DstMAC		*net.HardwareAddr
}

type layers_FDDI struct {
	BaseLayer	*layers.BaseLayer
	FrameControl	*layers.FDDIFrameControl
	Priority	*uint8
	SrcMAC		*net.HardwareAddr
	DstMAC		*net.HardwareAddr
}

type layers_FDDIFrameControl uint8

type layers_FDDIFrameControl uint8

type layers_GRE struct {
	BaseLayer		*layers.BaseLayer
	ChecksumPresent		*bool
	RoutingPresent		*bool
	KeyPresent		*bool
	SeqPresent		*bool
	StrictSourceRoute	*bool
	AckPresent		*bool
	RecursionControl	*uint8
	Flags			*uint8
	Version			*uint8
	Protocol		*layers.EthernetType
	Checksum		*uint16
	Offset			*uint16
	Key			*uint32
	Seq			*uint32
	Ack			*uint32
	GRERouting		*layers.GRERouting
}

type layers_GRE struct {
	BaseLayer		*layers.BaseLayer
	ChecksumPresent		*bool
	RoutingPresent		*bool
	KeyPresent		*bool
	SeqPresent		*bool
	StrictSourceRoute	*bool
	AckPresent		*bool
	RecursionControl	*uint8
	Flags			*uint8
	Version			*uint8
	Protocol		*layers.EthernetType
	Checksum		*uint16
	Offset			*uint16
	Key			*uint32
	Seq			*uint32
	Ack			*uint32
	GRERouting		*layers.GRERouting
}

type layers_GRERouting struct {
	AddressFamily		*uint16
	SREOffset		*uint8
	SRELength		*uint8
	RoutingInformation	*[]uint8
	Next			*layers.GRERouting
}

type layers_GRERouting struct {
	AddressFamily		*uint16
	SREOffset		*uint8
	SRELength		*uint8
	RoutingInformation	*[]uint8
	Next			*layers.GRERouting
}

type layers_GTPExtensionHeader struct {
	Type	*uint8
	Content	*[]uint8
}

type layers_GTPExtensionHeader struct {
	Type	*uint8
	Content	*[]uint8
}

type layers_GTPv1U struct {
	BaseLayer		*layers.BaseLayer
	Version			*uint8
	ProtocolType		*uint8
	Reserved		*uint8
	ExtensionHeaderFlag	*bool
	SequenceNumberFlag	*bool
	NPDUFlag		*bool
	MessageType		*uint8
	MessageLength		*uint16
	TEID			*uint32
	SequenceNumber		*uint16
	NPDU			*uint8
	GTPExtensionHeaders	*[]layers.GTPExtensionHeader
}

type layers_GTPv1U struct {
	BaseLayer		*layers.BaseLayer
	Version			*uint8
	ProtocolType		*uint8
	Reserved		*uint8
	ExtensionHeaderFlag	*bool
	SequenceNumberFlag	*bool
	NPDUFlag		*bool
	MessageType		*uint8
	MessageLength		*uint16
	TEID			*uint32
	SequenceNumber		*uint16
	NPDU			*uint8
	GTPExtensionHeaders	*[]layers.GTPExtensionHeader
}

type layers_Geneve struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	OptionsLength	*uint8
	OAMPacket	*bool
	CriticalOption	*bool
	Protocol	*layers.EthernetType
	VNI		*uint32
	Options		*[]*layers.GeneveOption
}

type layers_Geneve struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	OptionsLength	*uint8
	OAMPacket	*bool
	CriticalOption	*bool
	Protocol	*layers.EthernetType
	VNI		*uint32
	Options		*[]*layers.GeneveOption
}

type layers_GeneveOption struct {
	Class	*uint16
	Type	*uint8
	Flags	*uint8
	Length	*uint8
	Data	*[]uint8
}

type layers_GeneveOption struct {
	Class	*uint16
	Type	*uint8
	Flags	*uint8
	Length	*uint8
	Data	*[]uint8
}

type layers_HelloPkg struct {
	InterfaceID			*uint32
	RtrPriority			*uint8
	Options				*uint32
	HelloInterval			*uint16
	RouterDeadInterval		*uint32
	DesignatedRouterID		*uint32
	BackupDesignatedRouterID	*uint32
	NeighborID			*[]uint32
}

type layers_HelloPkg struct {
	InterfaceID			*uint32
	RtrPriority			*uint8
	Options				*uint32
	HelloInterval			*uint16
	RouterDeadInterval		*uint32
	DesignatedRouterID		*uint32
	BackupDesignatedRouterID	*uint32
	NeighborID			*[]uint32
}

type layers_HelloPkgV2 struct {
	HelloPkg	*layers.HelloPkg
	NetworkMask	*uint32
}

type layers_HelloPkgV2 struct {
	HelloPkg	*layers.HelloPkg
	NetworkMask	*uint32
}

type layers_IANAAddressFamily uint8

type layers_IANAAddressFamily uint8

type layers_ICMPv4 struct {
	BaseLayer	*layers.BaseLayer
	TypeCode	*layers.ICMPv4TypeCode
	Checksum	*uint16
	Id		*uint16
	Seq		*uint16
}

type layers_ICMPv4 struct {
	BaseLayer	*layers.BaseLayer
	TypeCode	*layers.ICMPv4TypeCode
	Checksum	*uint16
	Id		*uint16
	Seq		*uint16
}

type layers_ICMPv4TypeCode uint16

type layers_ICMPv4TypeCode uint16

type layers_ICMPv6 struct {
	BaseLayer	*layers.BaseLayer
	TypeCode	*layers.ICMPv6TypeCode
	Checksum	*uint16
	TypeBytes	*[]uint8
	tcpipchecksum	*interface{}
}

type layers_ICMPv6 struct {
	BaseLayer	*layers.BaseLayer
	TypeCode	*layers.ICMPv6TypeCode
	Checksum	*uint16
	TypeBytes	*[]uint8
	tcpipchecksum	*interface{}
}

type layers_ICMPv6Echo struct {
	BaseLayer	*layers.BaseLayer
	Identifier	*uint16
	SeqNumber	*uint16
}

type layers_ICMPv6Echo struct {
	BaseLayer	*layers.BaseLayer
	Identifier	*uint16
	SeqNumber	*uint16
}

type layers_ICMPv6NeighborAdvertisement struct {
	BaseLayer	*layers.BaseLayer
	Flags		*uint8
	TargetAddress	*net.IP
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6NeighborAdvertisement struct {
	BaseLayer	*layers.BaseLayer
	Flags		*uint8
	TargetAddress	*net.IP
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6NeighborSolicitation struct {
	BaseLayer	*layers.BaseLayer
	TargetAddress	*net.IP
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6NeighborSolicitation struct {
	BaseLayer	*layers.BaseLayer
	TargetAddress	*net.IP
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6Opt uint8

type layers_ICMPv6Opt uint8

type layers_ICMPv6Option struct {
	Type	*layers.ICMPv6Opt
	Data	*[]uint8
}

type layers_ICMPv6Option struct {
	Type	*layers.ICMPv6Opt
	Data	*[]uint8
}

type layers_ICMPv6Options []*layers.ICMPv6Option

type layers_ICMPv6Options []*layers.ICMPv6Option

type layers_ICMPv6Redirect struct {
	BaseLayer		*layers.BaseLayer
	TargetAddress		*net.IP
	DestinationAddress	*net.IP
	Options			*layers.ICMPv6Options
}

type layers_ICMPv6Redirect struct {
	BaseLayer		*layers.BaseLayer
	TargetAddress		*net.IP
	DestinationAddress	*net.IP
	Options			*layers.ICMPv6Options
}

type layers_ICMPv6RouterAdvertisement struct {
	BaseLayer	*layers.BaseLayer
	HopLimit	*uint8
	Flags		*uint8
	RouterLifetime	*uint16
	ReachableTime	*uint32
	RetransTimer	*uint32
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6RouterAdvertisement struct {
	BaseLayer	*layers.BaseLayer
	HopLimit	*uint8
	Flags		*uint8
	RouterLifetime	*uint16
	ReachableTime	*uint32
	RetransTimer	*uint32
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6RouterSolicitation struct {
	BaseLayer	*layers.BaseLayer
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6RouterSolicitation struct {
	BaseLayer	*layers.BaseLayer
	Options		*layers.ICMPv6Options
}

type layers_ICMPv6TypeCode uint16

type layers_ICMPv6TypeCode uint16

type layers_IEEEOUI uint32

type layers_IEEEOUI uint32

type layers_IGMP struct {
	BaseLayer		*layers.BaseLayer
	Type			*layers.IGMPType
	MaxResponseTime		*time.Duration
	Checksum		*uint16
	GroupAddress		*net.IP
	SupressRouterProcessing	*bool
	RobustnessValue		*uint8
	IntervalTime		*time.Duration
	SourceAddresses		*[]net.IP
	NumberOfGroupRecords	*uint16
	NumberOfSources		*uint16
	GroupRecords		*[]layers.IGMPv3GroupRecord
	Version			*uint8
}

type layers_IGMP struct {
	BaseLayer		*layers.BaseLayer
	Type			*layers.IGMPType
	MaxResponseTime		*time.Duration
	Checksum		*uint16
	GroupAddress		*net.IP
	SupressRouterProcessing	*bool
	RobustnessValue		*uint8
	IntervalTime		*time.Duration
	SourceAddresses		*[]net.IP
	NumberOfGroupRecords	*uint16
	NumberOfSources		*uint16
	GroupRecords		*[]layers.IGMPv3GroupRecord
	Version			*uint8
}

type layers_IGMPType uint8

type layers_IGMPType uint8

type layers_IGMPv1or2 struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.IGMPType
	MaxResponseTime	*time.Duration
	Checksum	*uint16
	GroupAddress	*net.IP
	Version		*uint8
}

type layers_IGMPv1or2 struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.IGMPType
	MaxResponseTime	*time.Duration
	Checksum	*uint16
	GroupAddress	*net.IP
	Version		*uint8
}

type layers_IGMPv3GroupRecord struct {
	Type			*layers.IGMPv3GroupRecordType
	AuxDataLen		*uint8
	NumberOfSources		*uint16
	MulticastAddress	*net.IP
	SourceAddresses		*[]net.IP
	AuxData			*uint32
}

type layers_IGMPv3GroupRecord struct {
	Type			*layers.IGMPv3GroupRecordType
	AuxDataLen		*uint8
	NumberOfSources		*uint16
	MulticastAddress	*net.IP
	SourceAddresses		*[]net.IP
	AuxData			*uint32
}

type layers_IGMPv3GroupRecordType uint8

type layers_IGMPv3GroupRecordType uint8

type layers_IPProtocol uint8

type layers_IPProtocol uint8

type layers_IPSecAH struct {
	ipv6ExtensionBase	*interface{}
	Reserved		*uint16
	SPI			*uint32
	Seq			*uint32
	AuthenticationData	*[]uint8
}

type layers_IPSecAH struct {
	ipv6ExtensionBase	*interface{}
	Reserved		*uint16
	SPI			*uint32
	Seq			*uint32
	AuthenticationData	*[]uint8
}

type layers_IPSecESP struct {
	BaseLayer	*layers.BaseLayer
	SPI		*uint32
	Seq		*uint32
	Encrypted	*[]uint8
}

type layers_IPSecESP struct {
	BaseLayer	*layers.BaseLayer
	SPI		*uint32
	Seq		*uint32
	Encrypted	*[]uint8
}

type layers_IPv4 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	IHL		*uint8
	TOS		*uint8
	Length		*uint16
	Id		*uint16
	Flags		*layers.IPv4Flag
	FragOffset	*uint16
	TTL		*uint8
	Protocol	*layers.IPProtocol
	Checksum	*uint16
	SrcIP		*net.IP
	DstIP		*net.IP
	Options		*[]layers.IPv4Option
	Padding		*[]uint8
}

type layers_IPv4 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	IHL		*uint8
	TOS		*uint8
	Length		*uint16
	Id		*uint16
	Flags		*layers.IPv4Flag
	FragOffset	*uint16
	TTL		*uint8
	Protocol	*layers.IPProtocol
	Checksum	*uint16
	SrcIP		*net.IP
	DstIP		*net.IP
	Options		*[]layers.IPv4Option
	Padding		*[]uint8
}

type layers_IPv4Flag uint8

type layers_IPv4Flag uint8

type layers_IPv4Option struct {
	OptionType	*uint8
	OptionLength	*uint8
	OptionData	*[]uint8
}

type layers_IPv4Option struct {
	OptionType	*uint8
	OptionLength	*uint8
	OptionData	*[]uint8
}

type layers_IPv6 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	TrafficClass	*uint8
	FlowLabel	*uint32
	Length		*uint16
	NextHeader	*layers.IPProtocol
	HopLimit	*uint8
	SrcIP		*net.IP
	DstIP		*net.IP
	HopByHop	*layers.IPv6HopByHop
	hbh		*layers.IPv6HopByHop
}

type layers_IPv6 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	TrafficClass	*uint8
	FlowLabel	*uint32
	Length		*uint16
	NextHeader	*layers.IPProtocol
	HopLimit	*uint8
	SrcIP		*net.IP
	DstIP		*net.IP
	HopByHop	*layers.IPv6HopByHop
	hbh		*layers.IPv6HopByHop
}

type layers_IPv6Destination struct {
	ipv6ExtensionBase	*interface{}
	Options			*[]*layers.IPv6DestinationOption
}

type layers_IPv6Destination struct {
	ipv6ExtensionBase	*interface{}
	Options			*[]*layers.IPv6DestinationOption
}

type layers_IPv6DestinationOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_IPv6DestinationOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_IPv6Fragment struct {
	BaseLayer	*layers.BaseLayer
	NextHeader	*layers.IPProtocol
	Reserved1	*uint8
	FragmentOffset	*uint16
	Reserved2	*uint8
	MoreFragments	*bool
	Identification	*uint32
}

type layers_IPv6Fragment struct {
	BaseLayer	*layers.BaseLayer
	NextHeader	*layers.IPProtocol
	Reserved1	*uint8
	FragmentOffset	*uint16
	Reserved2	*uint8
	MoreFragments	*bool
	Identification	*uint32
}

type layers_IPv6HopByHop struct {
	ipv6ExtensionBase	*interface{}
	Options			*[]*layers.IPv6HopByHopOption
}

type layers_IPv6HopByHop struct {
	ipv6ExtensionBase	*interface{}
	Options			*[]*layers.IPv6HopByHopOption
}

type layers_IPv6HopByHopOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_IPv6HopByHopOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_IPv6Routing struct {
	ipv6ExtensionBase	*interface{}
	RoutingType		*uint8
	SegmentsLeft		*uint8
	Reserved		*[]uint8
	SourceRoutingIPs	*[]net.IP
}

type layers_IPv6Routing struct {
	ipv6ExtensionBase	*interface{}
	RoutingType		*uint8
	SegmentsLeft		*uint8
	Reserved		*[]uint8
	SourceRoutingIPs	*[]net.IP
}

type layers_InterAreaPrefixLSA struct {
	Metric		*uint32
	PrefixLength	*uint8
	PrefixOptions	*uint8
	AddressPrefix	*[]uint8
}

type layers_InterAreaPrefixLSA struct {
	Metric		*uint32
	PrefixLength	*uint8
	PrefixOptions	*uint8
	AddressPrefix	*[]uint8
}

type layers_InterAreaRouterLSA struct {
	Options			*uint32
	Metric			*uint32
	DestinationRouterID	*uint32
}

type layers_InterAreaRouterLSA struct {
	Options			*uint32
	Metric			*uint32
	DestinationRouterID	*uint32
}

type layers_IntraAreaPrefixLSA struct {
	NumOfPrefixes	*uint16
	RefLSType	*uint16
	RefLinkStateID	*uint32
	RefAdvRouter	*uint32
	Prefixes	*[]layers.Prefix
}

type layers_IntraAreaPrefixLSA struct {
	NumOfPrefixes	*uint16
	RefLSType	*uint16
	RefLinkStateID	*uint32
	RefAdvRouter	*uint32
	Prefixes	*[]layers.Prefix
}

type layers_LCM struct {
	Magic		*uint32
	SequenceNumber	*uint32
	PayloadSize	*uint32
	FragmentOffset	*uint32
	FragmentNumber	*uint16
	TotalFragments	*uint16
	ChannelName	*string
	Fragmented	*bool
	fingerprint	*layers.LCMFingerprint
	contents	*[]uint8
	payload		*[]uint8
}

type layers_LCM struct {
	Magic		*uint32
	SequenceNumber	*uint32
	PayloadSize	*uint32
	FragmentOffset	*uint32
	FragmentNumber	*uint16
	TotalFragments	*uint16
	ChannelName	*string
	Fragmented	*bool
	fingerprint	*layers.LCMFingerprint
	contents	*[]uint8
	payload		*[]uint8
}

type layers_LCMFingerprint uint64

type layers_LCMFingerprint uint64

type layers_LLC struct {
	BaseLayer	*layers.BaseLayer
	DSAP		*uint8
	IG		*bool
	SSAP		*uint8
	CR		*bool
	Control		*uint16
}

type layers_LLC struct {
	BaseLayer	*layers.BaseLayer
	DSAP		*uint8
	IG		*bool
	SSAP		*uint8
	CR		*bool
	Control		*uint16
}

type layers_LLDPCapabilities struct {
	Other		*bool
	Repeater	*bool
	Bridge		*bool
	WLANAP		*bool
	Router		*bool
	Phone		*bool
	DocSis		*bool
	StationOnly	*bool
	CVLAN		*bool
	SVLAN		*bool
	TMPR		*bool
}

type layers_LLDPCapabilities struct {
	Other		*bool
	Repeater	*bool
	Bridge		*bool
	WLANAP		*bool
	Router		*bool
	Phone		*bool
	DocSis		*bool
	StationOnly	*bool
	CVLAN		*bool
	SVLAN		*bool
	TMPR		*bool
}

type layers_LLDPChassisID struct {
	Subtype	*layers.LLDPChassisIDSubType
	ID	*[]uint8
}

type layers_LLDPChassisID struct {
	Subtype	*layers.LLDPChassisIDSubType
	ID	*[]uint8
}

type layers_LLDPChassisIDSubType uint8

type layers_LLDPChassisIDSubType uint8

type layers_LLDPInterfaceSubtype uint8

type layers_LLDPInterfaceSubtype uint8

type layers_LLDPMgmtAddress struct {
	Subtype			*layers.IANAAddressFamily
	Address			*[]uint8
	InterfaceSubtype	*layers.LLDPInterfaceSubtype
	InterfaceNumber		*uint32
	OID			*string
}

type layers_LLDPMgmtAddress struct {
	Subtype			*layers.IANAAddressFamily
	Address			*[]uint8
	InterfaceSubtype	*layers.LLDPInterfaceSubtype
	InterfaceNumber		*uint32
	OID			*string
}

type layers_LLDPOrgSpecificTLV struct {
	OUI	*layers.IEEEOUI
	SubType	*uint8
	Info	*[]uint8
}

type layers_LLDPOrgSpecificTLV struct {
	OUI	*layers.IEEEOUI
	SubType	*uint8
	Info	*[]uint8
}

type layers_LLDPPortID struct {
	Subtype	*layers.LLDPPortIDSubType
	ID	*[]uint8
}

type layers_LLDPPortID struct {
	Subtype	*layers.LLDPPortIDSubType
	ID	*[]uint8
}

type layers_LLDPPortIDSubType uint8

type layers_LLDPPortIDSubType uint8

type layers_LLDPSysCapabilities struct {
	SystemCap	*layers.LLDPCapabilities
	EnabledCap	*layers.LLDPCapabilities
}

type layers_LLDPSysCapabilities struct {
	SystemCap	*layers.LLDPCapabilities
	EnabledCap	*layers.LLDPCapabilities
}

type layers_LLDPTLVType uint8

type layers_LLDPTLVType uint8

type layers_LSA struct {
	LSAheader	*layers.LSAheader
	Content		*interface {}
}

type layers_LSA struct {
	LSAheader	*layers.LSAheader
	Content		*interface {}
}

type layers_LSAheader struct {
	LSAge		*uint16
	LSType		*uint16
	LinkStateID	*uint32
	AdvRouter	*uint32
	LSSeqNumber	*uint32
	LSChecksum	*uint16
	Length		*uint16
	LSOptions	*uint8
}

type layers_LSAheader struct {
	LSAge		*uint16
	LSType		*uint16
	LinkStateID	*uint32
	AdvRouter	*uint32
	LSSeqNumber	*uint32
	LSChecksum	*uint16
	Length		*uint16
	LSOptions	*uint8
}

type layers_LSReq struct {
	LSType		*uint16
	LSID		*uint32
	AdvRouter	*uint32
}

type layers_LSReq struct {
	LSType		*uint16
	LSID		*uint32
	AdvRouter	*uint32
}

type layers_LSUpdate struct {
	NumOfLSAs	*uint32
	LSAs		*[]layers.LSA
}

type layers_LSUpdate struct {
	NumOfLSAs	*uint32
	LSAs		*[]layers.LSA
}

type layers_LinkLSA struct {
	RtrPriority		*uint8
	Options			*uint32
	LinkLocalAddress	*[]uint8
	NumOfPrefixes		*uint32
	Prefixes		*[]layers.Prefix
}

type layers_LinkLSA struct {
	RtrPriority		*uint8
	Options			*uint32
	LinkLocalAddress	*[]uint8
	NumOfPrefixes		*uint32
	Prefixes		*[]layers.Prefix
}

type layers_LinkLayerDiscovery struct {
	BaseLayer	*layers.BaseLayer
	ChassisID	*layers.LLDPChassisID
	PortID		*layers.LLDPPortID
	TTL		*uint16
	Values		*[]layers.LinkLayerDiscoveryValue
}

type layers_LinkLayerDiscovery struct {
	BaseLayer	*layers.BaseLayer
	ChassisID	*layers.LLDPChassisID
	PortID		*layers.LLDPPortID
	TTL		*uint16
	Values		*[]layers.LinkLayerDiscoveryValue
}

type layers_LinkLayerDiscoveryInfo struct {
	BaseLayer	*layers.BaseLayer
	PortDescription	*string
	SysName		*string
	SysDescription	*string
	SysCapabilities	*layers.LLDPSysCapabilities
	MgmtAddress	*layers.LLDPMgmtAddress
	OrgTLVs		*[]layers.LLDPOrgSpecificTLV
	Unknown		*[]layers.LinkLayerDiscoveryValue
}

type layers_LinkLayerDiscoveryInfo struct {
	BaseLayer	*layers.BaseLayer
	PortDescription	*string
	SysName		*string
	SysDescription	*string
	SysCapabilities	*layers.LLDPSysCapabilities
	MgmtAddress	*layers.LLDPMgmtAddress
	OrgTLVs		*[]layers.LLDPOrgSpecificTLV
	Unknown		*[]layers.LinkLayerDiscoveryValue
}

type layers_LinkLayerDiscoveryValue struct {
	Type	*layers.LLDPTLVType
	Length	*uint16
	Value	*[]uint8
}

type layers_LinkLayerDiscoveryValue struct {
	Type	*layers.LLDPTLVType
	Length	*uint16
	Value	*[]uint8
}

type layers_LinkType uint8

type layers_LinkType uint8

type layers_LinuxSLL struct {
	BaseLayer	*layers.BaseLayer
	PacketType	*layers.LinuxSLLPacketType
	AddrLen		*uint16
	Addr		*net.HardwareAddr
	EthernetType	*layers.EthernetType
	AddrType	*uint16
}

type layers_LinuxSLL struct {
	BaseLayer	*layers.BaseLayer
	PacketType	*layers.LinuxSLLPacketType
	AddrLen		*uint16
	Addr		*net.HardwareAddr
	EthernetType	*layers.EthernetType
	AddrType	*uint16
}

type layers_LinuxSLLPacketType uint16

type layers_LinuxSLLPacketType uint16

type layers_Loopback struct {
	BaseLayer	*layers.BaseLayer
	Family		*layers.ProtocolFamily
}

type layers_Loopback struct {
	BaseLayer	*layers.BaseLayer
	Family		*layers.ProtocolFamily
}

type layers_MLDv1Message struct {
	BaseLayer		*layers.BaseLayer
	MaximumResponseDelay	*time.Duration
	MulticastAddress	*net.IP
}

type layers_MLDv1Message struct {
	BaseLayer		*layers.BaseLayer
	MaximumResponseDelay	*time.Duration
	MulticastAddress	*net.IP
}

type layers_MLDv1MulticastListenerDoneMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv1MulticastListenerDoneMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv1MulticastListenerQueryMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv1MulticastListenerQueryMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv1MulticastListenerReportMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv1MulticastListenerReportMessage struct {
	MLDv1Message *layers.MLDv1Message
}

type layers_MLDv2MulticastAddressRecord struct {
	RecordType		*layers.MLDv2MulticastAddressRecordType
	AuxDataLen		*uint8
	N			*uint16
	MulticastAddress	*net.IP
	SourceAddresses		*[]net.IP
	AuxiliaryData		*[]uint8
}

type layers_MLDv2MulticastAddressRecord struct {
	RecordType		*layers.MLDv2MulticastAddressRecordType
	AuxDataLen		*uint8
	N			*uint16
	MulticastAddress	*net.IP
	SourceAddresses		*[]net.IP
	AuxiliaryData		*[]uint8
}

type layers_MLDv2MulticastAddressRecordType uint8

type layers_MLDv2MulticastAddressRecordType uint8

type layers_MLDv2MulticastListenerQueryMessage struct {
	BaseLayer			*layers.BaseLayer
	MaximumResponseCode		*uint16
	MulticastAddress		*net.IP
	SuppressRoutersideProcessing	*bool
	QueriersRobustnessVariable	*uint8
	QueriersQueryIntervalCode	*uint8
	NumberOfSources			*uint16
	SourceAddresses			*[]net.IP
}

type layers_MLDv2MulticastListenerQueryMessage struct {
	BaseLayer			*layers.BaseLayer
	MaximumResponseCode		*uint16
	MulticastAddress		*net.IP
	SuppressRoutersideProcessing	*bool
	QueriersRobustnessVariable	*uint8
	QueriersQueryIntervalCode	*uint8
	NumberOfSources			*uint16
	SourceAddresses			*[]net.IP
}

type layers_MLDv2MulticastListenerReportMessage struct {
	BaseLayer			*layers.BaseLayer
	NumberOfMulticastAddressRecords	*uint16
	MulticastAddressRecords		*[]layers.MLDv2MulticastAddressRecord
}

type layers_MLDv2MulticastListenerReportMessage struct {
	BaseLayer			*layers.BaseLayer
	NumberOfMulticastAddressRecords	*uint16
	MulticastAddressRecords		*[]layers.MLDv2MulticastAddressRecord
}

type layers_MPLS struct {
	BaseLayer	*layers.BaseLayer
	Label		*uint32
	TrafficClass	*uint8
	StackBottom	*bool
	TTL		*uint8
}

type layers_MPLS struct {
	BaseLayer	*layers.BaseLayer
	Label		*uint32
	TrafficClass	*uint8
	StackBottom	*bool
	TTL		*uint8
}

type layers_ModbusProtocol uint16

type layers_ModbusProtocol uint16

type layers_ModbusTCP struct {
	BaseLayer		*layers.BaseLayer
	TransactionIdentifier	*uint16
	ProtocolIdentifier	*layers.ModbusProtocol
	Length			*uint16
	UnitIdentifier		*uint8
}

type layers_ModbusTCP struct {
	BaseLayer		*layers.BaseLayer
	TransactionIdentifier	*uint16
	ProtocolIdentifier	*layers.ModbusProtocol
	Length			*uint16
	UnitIdentifier		*uint8
}

type layers_NDPBackplaneType uint8

type layers_NDPBackplaneType uint8

type layers_NDPChassisType uint8

type layers_NDPChassisType uint8

type layers_NDPState uint8

type layers_NDPState uint8

type layers_NTP struct {
	BaseLayer		*layers.BaseLayer
	LeapIndicator		*layers.NTPLeapIndicator
	Version			*layers.NTPVersion
	Mode			*layers.NTPMode
	Stratum			*layers.NTPStratum
	Poll			*layers.NTPLog2Seconds
	Precision		*layers.NTPLog2Seconds
	RootDelay		*layers.NTPFixed16Seconds
	RootDispersion		*layers.NTPFixed16Seconds
	ReferenceID		*layers.NTPReferenceID
	ReferenceTimestamp	*layers.NTPTimestamp
	OriginTimestamp		*layers.NTPTimestamp
	ReceiveTimestamp	*layers.NTPTimestamp
	TransmitTimestamp	*layers.NTPTimestamp
	ExtensionBytes		*[]uint8
}

type layers_NTP struct {
	BaseLayer		*layers.BaseLayer
	LeapIndicator		*layers.NTPLeapIndicator
	Version			*layers.NTPVersion
	Mode			*layers.NTPMode
	Stratum			*layers.NTPStratum
	Poll			*layers.NTPLog2Seconds
	Precision		*layers.NTPLog2Seconds
	RootDelay		*layers.NTPFixed16Seconds
	RootDispersion		*layers.NTPFixed16Seconds
	ReferenceID		*layers.NTPReferenceID
	ReferenceTimestamp	*layers.NTPTimestamp
	OriginTimestamp		*layers.NTPTimestamp
	ReceiveTimestamp	*layers.NTPTimestamp
	TransmitTimestamp	*layers.NTPTimestamp
	ExtensionBytes		*[]uint8
}

type layers_NTPFixed16Seconds uint32

type layers_NTPFixed16Seconds uint32

type layers_NTPLeapIndicator uint8

type layers_NTPLeapIndicator uint8

type layers_NTPLog2Seconds int8

type layers_NTPLog2Seconds int8

type layers_NTPMode uint8

type layers_NTPMode uint8

type layers_NTPReferenceID uint32

type layers_NTPReferenceID uint32

type layers_NTPStratum uint8

type layers_NTPStratum uint8

type layers_NTPTimestamp uint64

type layers_NTPTimestamp uint64

type layers_NTPVersion uint8

type layers_NTPVersion uint8

type layers_NetworkLSA struct {
	Options		*uint32
	AttachedRouter	*[]uint32
}

type layers_NetworkLSA struct {
	Options		*uint32
	AttachedRouter	*[]uint32
}

type layers_NetworkLSAV2 struct {
	NetworkMask	*uint32
	AttachedRouter	*[]uint32
}

type layers_NetworkLSAV2 struct {
	NetworkMask	*uint32
	AttachedRouter	*[]uint32
}

type layers_NortelDiscovery struct {
	BaseLayer	*layers.BaseLayer
	IPAddress	*net.IP
	SegmentID	*[]uint8
	Chassis		*layers.NDPChassisType
	Backplane	*layers.NDPBackplaneType
	State		*layers.NDPState
	NumLinks	*uint8
}

type layers_NortelDiscovery struct {
	BaseLayer	*layers.BaseLayer
	IPAddress	*net.IP
	SegmentID	*[]uint8
	Chassis		*layers.NDPChassisType
	Backplane	*layers.NDPBackplaneType
	State		*layers.NDPState
	NumLinks	*uint8
}

type layers_OSPF struct {
	Version		*uint8
	Type		*layers.OSPFType
	PacketLength	*uint16
	RouterID	*uint32
	AreaID		*uint32
	Checksum	*uint16
	Content		*interface {}
}

type layers_OSPF struct {
	Version		*uint8
	Type		*layers.OSPFType
	PacketLength	*uint16
	RouterID	*uint32
	AreaID		*uint32
	Checksum	*uint16
	Content		*interface {}
}

type layers_OSPFType uint8

type layers_OSPFType uint8

type layers_OSPFv2 struct {
	BaseLayer	*layers.BaseLayer
	OSPF		*layers.OSPF
	AuType		*uint16
	Authentication	*uint64
}

type layers_OSPFv2 struct {
	BaseLayer	*layers.BaseLayer
	OSPF		*layers.OSPF
	AuType		*uint16
	Authentication	*uint64
}

type layers_OSPFv3 struct {
	BaseLayer	*layers.BaseLayer
	OSPF		*layers.OSPF
	Instance	*uint8
	Reserved	*uint8
}

type layers_OSPFv3 struct {
	BaseLayer	*layers.BaseLayer
	OSPF		*layers.OSPF
	Instance	*uint8
	Reserved	*uint8
}

type layers_PFDirection uint8

type layers_PFDirection uint8

type layers_PFLog struct {
	BaseLayer	*layers.BaseLayer
	Length		*uint8
	Family		*layers.ProtocolFamily
	Action		*uint8
	Reason		*uint8
	IFName		*[]uint8
	Ruleset		*[]uint8
	RuleNum		*uint32
	SubruleNum	*uint32
	UID		*uint32
	PID		*int32
	RuleUID		*uint32
	RulePID		*int32
	Direction	*layers.PFDirection
}

type layers_PFLog struct {
	BaseLayer	*layers.BaseLayer
	Length		*uint8
	Family		*layers.ProtocolFamily
	Action		*uint8
	Reason		*uint8
	IFName		*[]uint8
	Ruleset		*[]uint8
	RuleNum		*uint32
	SubruleNum	*uint32
	UID		*uint32
	PID		*int32
	RuleUID		*uint32
	RulePID		*int32
	Direction	*layers.PFDirection
}

type layers_PPP struct {
	BaseLayer	*layers.BaseLayer
	PPPType		*layers.PPPType
	HasPPTPHeader	*bool
}

type layers_PPP struct {
	BaseLayer	*layers.BaseLayer
	PPPType		*layers.PPPType
	HasPPTPHeader	*bool
}

type layers_PPPType uint16

type layers_PPPType uint16

type layers_PPPoE struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*uint8
	Code		*layers.PPPoECode
	SessionId	*uint16
	Length		*uint16
}

type layers_PPPoE struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*uint8
	Code		*layers.PPPoECode
	SessionId	*uint16
	Length		*uint16
}

type layers_PPPoECode uint8

type layers_PPPoECode uint8

type layers_Prefix struct {
	PrefixLength	*uint8
	PrefixOptions	*uint8
	Metric		*uint16
	AddressPrefix	*[]uint8
}

type layers_Prefix struct {
	PrefixLength	*uint8
	PrefixOptions	*uint8
	Metric		*uint16
	AddressPrefix	*[]uint8
}

type layers_PrismDID uint32

type layers_PrismDID uint32

type layers_PrismHeader struct {
	BaseLayer	*layers.BaseLayer
	Code		*uint16
	Length		*uint16
	DeviceName	*string
	Values		*[]layers.PrismValue
}

type layers_PrismHeader struct {
	BaseLayer	*layers.BaseLayer
	Code		*uint16
	Length		*uint16
	DeviceName	*string
	Values		*[]layers.PrismValue
}

type layers_PrismValue struct {
	DID	*layers.PrismDID
	Status	*uint16
	Length	*uint16
	Data	*[]uint8
}

type layers_PrismValue struct {
	DID	*layers.PrismDID
	Status	*uint16
	Length	*uint16
	Data	*[]uint8
}

type layers_ProtocolFamily uint8

type layers_ProtocolFamily uint8

type layers_ProtocolGuessingDecoder struct {
}

type layers_ProtocolGuessingDecoder struct {
}

type layers_RADIUS struct {
	BaseLayer	*layers.BaseLayer
	Code		*layers.RADIUSCode
	Identifier	*layers.RADIUSIdentifier
	Length		*layers.RADIUSLength
	Authenticator	*layers.RADIUSAuthenticator
	Attributes	*[]layers.RADIUSAttribute
}

type layers_RADIUS struct {
	BaseLayer	*layers.BaseLayer
	Code		*layers.RADIUSCode
	Identifier	*layers.RADIUSIdentifier
	Length		*layers.RADIUSLength
	Authenticator	*layers.RADIUSAuthenticator
	Attributes	*[]layers.RADIUSAttribute
}

type layers_RADIUSAttribute struct {
	Type	*layers.RADIUSAttributeType
	Length	*layers.RADIUSAttributeLength
	Value	*layers.RADIUSAttributeValue
}

type layers_RADIUSAttribute struct {
	Type	*layers.RADIUSAttributeType
	Length	*layers.RADIUSAttributeLength
	Value	*layers.RADIUSAttributeValue
}

type layers_RADIUSAttributeLength uint8

type layers_RADIUSAttributeLength uint8

type layers_RADIUSAttributeType uint8

type layers_RADIUSAttributeType uint8

type layers_RADIUSAttributeValue []*uint8

type layers_RADIUSAttributeValue []*uint8

type layers_RADIUSAuthenticator [16]*uint8

type layers_RADIUSAuthenticator [16]*uint8

type layers_RADIUSCode uint8

type layers_RADIUSCode uint8

type layers_RADIUSIdentifier uint8

type layers_RADIUSIdentifier uint8

type layers_RADIUSLength uint16

type layers_RADIUSLength uint16

type layers_RMCP struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Sequence	*uint8
	Ack		*bool
	Class		*layers.RMCPClass
}

type layers_RMCP struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Sequence	*uint8
	Ack		*bool
	Class		*layers.RMCPClass
}

type layers_RMCPClass uint8

type layers_RMCPClass uint8

type layers_RUDP struct {
	BaseLayer		*layers.BaseLayer
	SYN			*bool
	ACK			*bool
	EACK			*bool
	RST			*bool
	NUL			*bool
	Version			*uint8
	HeaderLength		*uint8
	SrcPort			*layers.RUDPPort
	DstPort			*layers.RUDPPort
	DataLength		*uint16
	Seq			*uint32
	Ack			*uint32
	Checksum		*uint32
	VariableHeaderArea	*[]uint8
	RUDPHeaderSYN		*layers.RUDPHeaderSYN
	RUDPHeaderEACK		*layers.RUDPHeaderEACK
}

type layers_RUDP struct {
	BaseLayer		*layers.BaseLayer
	SYN			*bool
	ACK			*bool
	EACK			*bool
	RST			*bool
	NUL			*bool
	Version			*uint8
	HeaderLength		*uint8
	SrcPort			*layers.RUDPPort
	DstPort			*layers.RUDPPort
	DataLength		*uint16
	Seq			*uint32
	Ack			*uint32
	Checksum		*uint32
	VariableHeaderArea	*[]uint8
	RUDPHeaderSYN		*layers.RUDPHeaderSYN
	RUDPHeaderEACK		*layers.RUDPHeaderEACK
}

type layers_RUDPHeaderEACK struct {
	SeqsReceivedOK *[]uint32
}

type layers_RUDPHeaderEACK struct {
	SeqsReceivedOK *[]uint32
}

type layers_RUDPHeaderSYN struct {
	MaxOutstandingSegments	*uint16
	MaxSegmentSize		*uint16
	OptionFlags		*uint16
}

type layers_RUDPHeaderSYN struct {
	MaxOutstandingSegments	*uint16
	MaxSegmentSize		*uint16
	OptionFlags		*uint16
}

type layers_RUDPPort uint8

type layers_RUDPPort uint8

type layers_RadioTap struct {
	BaseLayer		*layers.BaseLayer
	Version			*uint8
	Length			*uint16
	Present			*layers.RadioTapPresent
	TSFT			*uint64
	Flags			*layers.RadioTapFlags
	Rate			*layers.RadioTapRate
	ChannelFrequency	*layers.RadioTapChannelFrequency
	ChannelFlags		*layers.RadioTapChannelFlags
	FHSS			*uint16
	DBMAntennaSignal	*int8
	DBMAntennaNoise		*int8
	LockQuality		*uint16
	TxAttenuation		*uint16
	DBTxAttenuation		*uint16
	DBMTxPower		*int8
	Antenna			*uint8
	DBAntennaSignal		*uint8
	DBAntennaNoise		*uint8
	RxFlags			*layers.RadioTapRxFlags
	TxFlags			*layers.RadioTapTxFlags
	RtsRetries		*uint8
	DataRetries		*uint8
	MCS			*layers.RadioTapMCS
	AMPDUStatus		*layers.RadioTapAMPDUStatus
	VHT			*layers.RadioTapVHT
}

type layers_RadioTap struct {
	BaseLayer		*layers.BaseLayer
	Version			*uint8
	Length			*uint16
	Present			*layers.RadioTapPresent
	TSFT			*uint64
	Flags			*layers.RadioTapFlags
	Rate			*layers.RadioTapRate
	ChannelFrequency	*layers.RadioTapChannelFrequency
	ChannelFlags		*layers.RadioTapChannelFlags
	FHSS			*uint16
	DBMAntennaSignal	*int8
	DBMAntennaNoise		*int8
	LockQuality		*uint16
	TxAttenuation		*uint16
	DBTxAttenuation		*uint16
	DBMTxPower		*int8
	Antenna			*uint8
	DBAntennaSignal		*uint8
	DBAntennaNoise		*uint8
	RxFlags			*layers.RadioTapRxFlags
	TxFlags			*layers.RadioTapTxFlags
	RtsRetries		*uint8
	DataRetries		*uint8
	MCS			*layers.RadioTapMCS
	AMPDUStatus		*layers.RadioTapAMPDUStatus
	VHT			*layers.RadioTapVHT
}

type layers_RadioTapAMPDUStatus struct {
	Reference	*uint32
	Flags		*layers.RadioTapAMPDUStatusFlags
	CRC		*uint8
}

type layers_RadioTapAMPDUStatus struct {
	Reference	*uint32
	Flags		*layers.RadioTapAMPDUStatusFlags
	CRC		*uint8
}

type layers_RadioTapAMPDUStatusFlags uint16

type layers_RadioTapAMPDUStatusFlags uint16

type layers_RadioTapChannelFlags uint16

type layers_RadioTapChannelFlags uint16

type layers_RadioTapChannelFrequency uint16

type layers_RadioTapChannelFrequency uint16

type layers_RadioTapFlags uint8

type layers_RadioTapFlags uint8

type layers_RadioTapMCS struct {
	Known	*layers.RadioTapMCSKnown
	Flags	*layers.RadioTapMCSFlags
	MCS	*uint8
}

type layers_RadioTapMCS struct {
	Known	*layers.RadioTapMCSKnown
	Flags	*layers.RadioTapMCSFlags
	MCS	*uint8
}

type layers_RadioTapMCSFlags uint8

type layers_RadioTapMCSFlags uint8

type layers_RadioTapMCSKnown uint8

type layers_RadioTapMCSKnown uint8

type layers_RadioTapPresent uint32

type layers_RadioTapPresent uint32

type layers_RadioTapRate uint8

type layers_RadioTapRate uint8

type layers_RadioTapRxFlags uint16

type layers_RadioTapRxFlags uint16

type layers_RadioTapTxFlags uint16

type layers_RadioTapTxFlags uint16

type layers_RadioTapVHT struct {
	Known		*layers.RadioTapVHTKnown
	Flags		*layers.RadioTapVHTFlags
	Bandwidth	*uint8
	MCSNSS		*[4]layers.RadioTapVHTMCSNSS
	Coding		*uint8
	GroupId		*uint8
	PartialAID	*uint16
}

type layers_RadioTapVHT struct {
	Known		*layers.RadioTapVHTKnown
	Flags		*layers.RadioTapVHTFlags
	Bandwidth	*uint8
	MCSNSS		*[4]layers.RadioTapVHTMCSNSS
	Coding		*uint8
	GroupId		*uint8
	PartialAID	*uint16
}

type layers_RadioTapVHTFlags uint8

type layers_RadioTapVHTFlags uint8

type layers_RadioTapVHTKnown uint16

type layers_RadioTapVHTKnown uint16

type layers_RadioTapVHTMCSNSS uint8

type layers_RadioTapVHTMCSNSS uint8

type layers_Router struct {
	Type			*uint8
	Metric			*uint16
	InterfaceID		*uint32
	NeighborInterfaceID	*uint32
	NeighborRouterID	*uint32
}

type layers_Router struct {
	Type			*uint8
	Metric			*uint16
	InterfaceID		*uint32
	NeighborInterfaceID	*uint32
	NeighborRouterID	*uint32
}

type layers_RouterLSA struct {
	Flags	*uint8
	Options	*uint32
	Routers	*[]layers.Router
}

type layers_RouterLSA struct {
	Flags	*uint8
	Options	*uint32
	Routers	*[]layers.Router
}

type layers_RouterLSAV2 struct {
	Flags	*uint8
	Links	*uint16
	Routers	*[]layers.RouterV2
}

type layers_RouterLSAV2 struct {
	Flags	*uint8
	Links	*uint16
	Routers	*[]layers.RouterV2
}

type layers_RouterV2 struct {
	Type		*uint8
	LinkID		*uint32
	LinkData	*uint32
	Metric		*uint16
}

type layers_RouterV2 struct {
	Type		*uint8
	LinkID		*uint32
	LinkData	*uint32
	Metric		*uint16
}

type layers_SCTP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.SCTPPort
	DstPort		*layers.SCTPPort
	VerificationTag	*uint32
	Checksum	*uint32
	sPort		*[]uint8
	dPort		*[]uint8
}

type layers_SCTP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.SCTPPort
	DstPort		*layers.SCTPPort
	VerificationTag	*uint32
	Checksum	*uint32
	sPort		*[]uint8
	dPort		*[]uint8
}

type layers_SCTPChunk struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.SCTPChunkType
	Flags		*uint8
	Length		*uint16
	ActualLength	*int
}

type layers_SCTPChunk struct {
	BaseLayer	*layers.BaseLayer
	Type		*layers.SCTPChunkType
	Flags		*uint8
	Length		*uint16
	ActualLength	*int
}

type layers_SCTPChunkType uint8

type layers_SCTPChunkType uint8

type layers_SCTPCookieEcho struct {
	SCTPChunk	*layers.SCTPChunk
	Cookie		*[]uint8
}

type layers_SCTPCookieEcho struct {
	SCTPChunk	*layers.SCTPChunk
	Cookie		*[]uint8
}

type layers_SCTPData struct {
	SCTPChunk	*layers.SCTPChunk
	Unordered	*bool
	BeginFragment	*bool
	EndFragment	*bool
	TSN		*uint32
	StreamId	*uint16
	StreamSequence	*uint16
	PayloadProtocol	*layers.SCTPPayloadProtocol
}

type layers_SCTPData struct {
	SCTPChunk	*layers.SCTPChunk
	Unordered	*bool
	BeginFragment	*bool
	EndFragment	*bool
	TSN		*uint32
	StreamId	*uint16
	StreamSequence	*uint16
	PayloadProtocol	*layers.SCTPPayloadProtocol
}

type layers_SCTPEmptyLayer struct {
	SCTPChunk *layers.SCTPChunk
}

type layers_SCTPEmptyLayer struct {
	SCTPChunk *layers.SCTPChunk
}

type layers_SCTPError struct {
	SCTPChunk	*layers.SCTPChunk
	Parameters	*[]layers.SCTPErrorParameter
}

type layers_SCTPError struct {
	SCTPChunk	*layers.SCTPChunk
	Parameters	*[]layers.SCTPErrorParameter
}

type layers_SCTPErrorParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPErrorParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPHeartbeat struct {
	SCTPChunk	*layers.SCTPChunk
	Parameters	*[]layers.SCTPHeartbeatParameter
}

type layers_SCTPHeartbeat struct {
	SCTPChunk	*layers.SCTPChunk
	Parameters	*[]layers.SCTPHeartbeatParameter
}

type layers_SCTPHeartbeatParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPHeartbeatParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPInit struct {
	SCTPChunk			*layers.SCTPChunk
	InitiateTag			*uint32
	AdvertisedReceiverWindowCredit	*uint32
	OutboundStreams			*uint16
	InboundStreams			*uint16
	InitialTSN			*uint32
	Parameters			*[]layers.SCTPInitParameter
}

type layers_SCTPInit struct {
	SCTPChunk			*layers.SCTPChunk
	InitiateTag			*uint32
	AdvertisedReceiverWindowCredit	*uint32
	OutboundStreams			*uint16
	InboundStreams			*uint16
	InitialTSN			*uint32
	Parameters			*[]layers.SCTPInitParameter
}

type layers_SCTPInitParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPInitParameter struct {
	Type		*uint16
	Length		*uint16
	ActualLength	*int
	Value		*[]uint8
}

type layers_SCTPPayloadProtocol uint32

type layers_SCTPPayloadProtocol uint32

type layers_SCTPPort uint16

type layers_SCTPPort uint16

type layers_SCTPSack struct {
	SCTPChunk			*layers.SCTPChunk
	CumulativeTSNAck		*uint32
	AdvertisedReceiverWindowCredit	*uint32
	NumGapACKs			*uint16
	NumDuplicateTSNs		*uint16
	GapACKs				*[]uint16
	DuplicateTSNs			*[]uint32
}

type layers_SCTPSack struct {
	SCTPChunk			*layers.SCTPChunk
	CumulativeTSNAck		*uint32
	AdvertisedReceiverWindowCredit	*uint32
	NumGapACKs			*uint16
	NumDuplicateTSNs		*uint16
	GapACKs				*[]uint16
	DuplicateTSNs			*[]uint32
}

type layers_SCTPShutdown struct {
	SCTPChunk		*layers.SCTPChunk
	CumulativeTSNAck	*uint32
}

type layers_SCTPShutdown struct {
	SCTPChunk		*layers.SCTPChunk
	CumulativeTSNAck	*uint32
}

type layers_SCTPShutdownAck struct {
	SCTPChunk *layers.SCTPChunk
}

type layers_SCTPShutdownAck struct {
	SCTPChunk *layers.SCTPChunk
}

type layers_SFLLACPPortState struct {
	PortStateAll *uint32
}

type layers_SFLLACPPortState struct {
	PortStateAll *uint32
}

type layers_SFlowASDestination struct {
	Type	*layers.SFlowASPathType
	Count	*uint32
	Members	*[]uint32
}

type layers_SFlowASDestination struct {
	Type	*layers.SFlowASPathType
	Count	*uint32
	Members	*[]uint32
}

type layers_SFlowASPathType uint32

type layers_SFlowASPathType uint32

type layers_SFlowAppresourcesCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	UserTime		*uint32
	SystemTime		*uint32
	MemUsed			*uint64
	MemMax			*uint64
	FdOpen			*uint32
	FdMax			*uint32
	ConnOpen		*uint32
	ConnMax			*uint32
}

type layers_SFlowAppresourcesCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	UserTime		*uint32
	SystemTime		*uint32
	MemUsed			*uint64
	MemMax			*uint64
	FdOpen			*uint32
	FdMax			*uint32
	ConnOpen		*uint32
	ConnMax			*uint32
}

type layers_SFlowBaseCounterRecord struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowCounterRecordType
	FlowDataLength	*uint32
}

type layers_SFlowBaseCounterRecord struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowCounterRecordType
	FlowDataLength	*uint32
}

type layers_SFlowBaseFlowRecord struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowFlowRecordType
	FlowDataLength	*uint32
}

type layers_SFlowBaseFlowRecord struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowFlowRecordType
	FlowDataLength	*uint32
}

type layers_SFlowCharSet uint32

type layers_SFlowCharSet uint32

type layers_SFlowCounterRecordType uint32

type layers_SFlowCounterRecordType uint32

type layers_SFlowCounterSample struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowSampleType
	SampleLength	*uint32
	SequenceNumber	*uint32
	SourceIDClass	*layers.SFlowSourceFormat
	SourceIDIndex	*layers.SFlowSourceValue
	RecordCount	*uint32
	Records		*[]layers.SFlowRecord
}

type layers_SFlowCounterSample struct {
	EnterpriseID	*layers.SFlowEnterpriseID
	Format		*layers.SFlowSampleType
	SampleLength	*uint32
	SequenceNumber	*uint32
	SourceIDClass	*layers.SFlowSourceFormat
	SourceIDIndex	*layers.SFlowSourceValue
	RecordCount	*uint32
	Records		*[]layers.SFlowRecord
}

type layers_SFlowDatagram struct {
	BaseLayer	*layers.BaseLayer
	DatagramVersion	*uint32
	AgentAddress	*net.IP
	SubAgentID	*uint32
	SequenceNumber	*uint32
	AgentUptime	*uint32
	SampleCount	*uint32
	FlowSamples	*[]layers.SFlowFlowSample
	CounterSamples	*[]layers.SFlowCounterSample
}

type layers_SFlowDatagram struct {
	BaseLayer	*layers.BaseLayer
	DatagramVersion	*uint32
	AgentAddress	*net.IP
	SubAgentID	*uint32
	SequenceNumber	*uint32
	AgentUptime	*uint32
	SampleCount	*uint32
	FlowSamples	*[]layers.SFlowFlowSample
	CounterSamples	*[]layers.SFlowCounterSample
}

type layers_SFlowEnterpriseID uint32

type layers_SFlowEnterpriseID uint32

type layers_SFlowEthernetCounters struct {
	SFlowBaseCounterRecord		*layers.SFlowBaseCounterRecord
	AlignmentErrors			*uint32
	FCSErrors			*uint32
	SingleCollisionFrames		*uint32
	MultipleCollisionFrames		*uint32
	SQETestErrors			*uint32
	DeferredTransmissions		*uint32
	LateCollisions			*uint32
	ExcessiveCollisions		*uint32
	InternalMacTransmitErrors	*uint32
	CarrierSenseErrors		*uint32
	FrameTooLongs			*uint32
	InternalMacReceiveErrors	*uint32
	SymbolErrors			*uint32
}

type layers_SFlowEthernetCounters struct {
	SFlowBaseCounterRecord		*layers.SFlowBaseCounterRecord
	AlignmentErrors			*uint32
	FCSErrors			*uint32
	SingleCollisionFrames		*uint32
	MultipleCollisionFrames		*uint32
	SQETestErrors			*uint32
	DeferredTransmissions		*uint32
	LateCollisions			*uint32
	ExcessiveCollisions		*uint32
	InternalMacTransmitErrors	*uint32
	CarrierSenseErrors		*uint32
	FrameTooLongs			*uint32
	InternalMacReceiveErrors	*uint32
	SymbolErrors			*uint32
}

type layers_SFlowEthernetFrameFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	FrameLength		*uint32
	SrcMac			*net.HardwareAddr
	DstMac			*net.HardwareAddr
	Type			*uint32
}

type layers_SFlowEthernetFrameFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	FrameLength		*uint32
	SrcMac			*net.HardwareAddr
	DstMac			*net.HardwareAddr
	Type			*uint32
}

type layers_SFlowExtendedDecapsulateEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	InnerHeaderOffset	*uint32
}

type layers_SFlowExtendedDecapsulateEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	InnerHeaderOffset	*uint32
}

type layers_SFlowExtendedDecapsulateIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	InnerHeaderOffset	*uint32
}

type layers_SFlowExtendedDecapsulateIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	InnerHeaderOffset	*uint32
}

type layers_SFlowExtendedGatewayFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	NextHop			*net.IP
	AS			*uint32
	SourceAS		*uint32
	PeerAS			*uint32
	ASPathCount		*uint32
	ASPath			*[]layers.SFlowASDestination
	Communities		*[]uint32
	LocalPref		*uint32
}

type layers_SFlowExtendedGatewayFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	NextHop			*net.IP
	AS			*uint32
	SourceAS		*uint32
	PeerAS			*uint32
	ASPathCount		*uint32
	ASPath			*[]layers.SFlowASDestination
	Communities		*[]uint32
	LocalPref		*uint32
}

type layers_SFlowExtendedIpv4TunnelEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv4Record		*layers.SFlowIpv4Record
}

type layers_SFlowExtendedIpv4TunnelEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv4Record		*layers.SFlowIpv4Record
}

type layers_SFlowExtendedIpv4TunnelIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv4Record		*layers.SFlowIpv4Record
}

type layers_SFlowExtendedIpv4TunnelIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv4Record		*layers.SFlowIpv4Record
}

type layers_SFlowExtendedIpv6TunnelEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv6Record		*layers.SFlowIpv6Record
}

type layers_SFlowExtendedIpv6TunnelEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv6Record		*layers.SFlowIpv6Record
}

type layers_SFlowExtendedIpv6TunnelIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv6Record		*layers.SFlowIpv6Record
}

type layers_SFlowExtendedIpv6TunnelIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SFlowIpv6Record		*layers.SFlowIpv6Record
}

type layers_SFlowExtendedRouterFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	NextHop			*net.IP
	NextHopSourceMask	*uint32
	NextHopDestinationMask	*uint32
}

type layers_SFlowExtendedRouterFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	NextHop			*net.IP
	NextHopSourceMask	*uint32
	NextHopDestinationMask	*uint32
}

type layers_SFlowExtendedSwitchFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	IncomingVLAN		*uint32
	IncomingVLANPriority	*uint32
	OutgoingVLAN		*uint32
	OutgoingVLANPriority	*uint32
}

type layers_SFlowExtendedSwitchFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	IncomingVLAN		*uint32
	IncomingVLANPriority	*uint32
	OutgoingVLAN		*uint32
	OutgoingVLANPriority	*uint32
}

type layers_SFlowExtendedURLRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	Direction		*layers.SFlowURLDirection
	URL			*string
	Host			*string
}

type layers_SFlowExtendedURLRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	Direction		*layers.SFlowURLDirection
	URL			*string
	Host			*string
}

type layers_SFlowExtendedUserFlow struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SourceCharSet		*layers.SFlowCharSet
	SourceUserID		*string
	DestinationCharSet	*layers.SFlowCharSet
	DestinationUserID	*string
}

type layers_SFlowExtendedUserFlow struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	SourceCharSet		*layers.SFlowCharSet
	SourceUserID		*string
	DestinationCharSet	*layers.SFlowCharSet
	DestinationUserID	*string
}

type layers_SFlowExtendedVniEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	VNI			*uint32
}

type layers_SFlowExtendedVniEgressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	VNI			*uint32
}

type layers_SFlowExtendedVniIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	VNI			*uint32
}

type layers_SFlowExtendedVniIngressRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	VNI			*uint32
}

type layers_SFlowFlowRecordType uint32

type layers_SFlowFlowRecordType uint32

type layers_SFlowFlowSample struct {
	EnterpriseID		*layers.SFlowEnterpriseID
	Format			*layers.SFlowSampleType
	SampleLength		*uint32
	SequenceNumber		*uint32
	SourceIDClass		*layers.SFlowSourceFormat
	SourceIDIndex		*layers.SFlowSourceValue
	SamplingRate		*uint32
	SamplePool		*uint32
	Dropped			*uint32
	InputInterfaceFormat	*uint32
	InputInterface		*uint32
	OutputInterfaceFormat	*uint32
	OutputInterface		*uint32
	RecordCount		*uint32
	Records			*[]layers.SFlowRecord
}

type layers_SFlowFlowSample struct {
	EnterpriseID		*layers.SFlowEnterpriseID
	Format			*layers.SFlowSampleType
	SampleLength		*uint32
	SequenceNumber		*uint32
	SourceIDClass		*layers.SFlowSourceFormat
	SourceIDIndex		*layers.SFlowSourceValue
	SamplingRate		*uint32
	SamplePool		*uint32
	Dropped			*uint32
	InputInterfaceFormat	*uint32
	InputInterface		*uint32
	OutputInterfaceFormat	*uint32
	OutputInterface		*uint32
	RecordCount		*uint32
	Records			*[]layers.SFlowRecord
}

type layers_SFlowGenericInterfaceCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	IfIndex			*uint32
	IfType			*uint32
	IfSpeed			*uint64
	IfDirection		*uint32
	IfStatus		*uint32
	IfInOctets		*uint64
	IfInUcastPkts		*uint32
	IfInMulticastPkts	*uint32
	IfInBroadcastPkts	*uint32
	IfInDiscards		*uint32
	IfInErrors		*uint32
	IfInUnknownProtos	*uint32
	IfOutOctets		*uint64
	IfOutUcastPkts		*uint32
	IfOutMulticastPkts	*uint32
	IfOutBroadcastPkts	*uint32
	IfOutDiscards		*uint32
	IfOutErrors		*uint32
	IfPromiscuousMode	*uint32
}

type layers_SFlowGenericInterfaceCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	IfIndex			*uint32
	IfType			*uint32
	IfSpeed			*uint64
	IfDirection		*uint32
	IfStatus		*uint32
	IfInOctets		*uint64
	IfInUcastPkts		*uint32
	IfInMulticastPkts	*uint32
	IfInBroadcastPkts	*uint32
	IfInDiscards		*uint32
	IfInErrors		*uint32
	IfInUnknownProtos	*uint32
	IfOutOctets		*uint64
	IfOutUcastPkts		*uint32
	IfOutMulticastPkts	*uint32
	IfOutBroadcastPkts	*uint32
	IfOutDiscards		*uint32
	IfOutErrors		*uint32
	IfPromiscuousMode	*uint32
}

type layers_SFlowIpv4Record struct {
	Length		*uint32
	Protocol	*uint32
	IPSrc		*net.IP
	IPDst		*net.IP
	PortSrc		*uint32
	PortDst		*uint32
	TCPFlags	*uint32
	TOS		*uint32
}

type layers_SFlowIpv4Record struct {
	Length		*uint32
	Protocol	*uint32
	IPSrc		*net.IP
	IPDst		*net.IP
	PortSrc		*uint32
	PortDst		*uint32
	TCPFlags	*uint32
	TOS		*uint32
}

type layers_SFlowIpv6Record struct {
	Length		*uint32
	Protocol	*uint32
	IPSrc		*net.IP
	IPDst		*net.IP
	PortSrc		*uint32
	PortDst		*uint32
	TCPFlags	*uint32
	Priority	*uint32
}

type layers_SFlowIpv6Record struct {
	Length		*uint32
	Protocol	*uint32
	IPSrc		*net.IP
	IPDst		*net.IP
	PortSrc		*uint32
	PortDst		*uint32
	TCPFlags	*uint32
	Priority	*uint32
}

type layers_SFlowLACPCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	ActorSystemID		*net.HardwareAddr
	PartnerSystemID		*net.HardwareAddr
	AttachedAggID		*uint32
	LacpPortState		*layers.SFLLACPPortState
	LACPDUsRx		*uint32
	MarkerPDUsRx		*uint32
	MarkerResponsePDUsRx	*uint32
	UnknownRx		*uint32
	IllegalRx		*uint32
	LACPDUsTx		*uint32
	MarkerPDUsTx		*uint32
	MarkerResponsePDUsTx	*uint32
}

type layers_SFlowLACPCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	ActorSystemID		*net.HardwareAddr
	PartnerSystemID		*net.HardwareAddr
	AttachedAggID		*uint32
	LacpPortState		*layers.SFLLACPPortState
	LACPDUsRx		*uint32
	MarkerPDUsRx		*uint32
	MarkerResponsePDUsRx	*uint32
	UnknownRx		*uint32
	IllegalRx		*uint32
	LACPDUsTx		*uint32
	MarkerPDUsTx		*uint32
	MarkerResponsePDUsTx	*uint32
}

type layers_SFlowOVSDPCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	NHit			*uint32
	NMissed			*uint32
	NLost			*uint32
	NMaskHit		*uint32
	NFlows			*uint32
	NMasks			*uint32
}

type layers_SFlowOVSDPCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	NHit			*uint32
	NMissed			*uint32
	NLost			*uint32
	NMaskHit		*uint32
	NFlows			*uint32
	NMasks			*uint32
}

type layers_SFlowOpenflowPortCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	DatapathID		*uint64
	PortNo			*uint32
}

type layers_SFlowOpenflowPortCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	DatapathID		*uint64
	PortNo			*uint32
}

type layers_SFlowPORTNAME struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	Len			*uint32
	Str			*string
}

type layers_SFlowPORTNAME struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	Len			*uint32
	Str			*string
}

type layers_SFlowProcessorCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	FiveSecCpu		*uint32
	OneMinCpu		*uint32
	FiveMinCpu		*uint32
	TotalMemory		*uint64
	FreeMemory		*uint64
}

type layers_SFlowProcessorCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	FiveSecCpu		*uint32
	OneMinCpu		*uint32
	FiveMinCpu		*uint32
	TotalMemory		*uint64
	FreeMemory		*uint64
}

type layers_SFlowRawHeaderProtocol uint32

type layers_SFlowRawHeaderProtocol uint32

type layers_SFlowRawPacketFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	HeaderProtocol		*layers.SFlowRawHeaderProtocol
	FrameLength		*uint32
	PayloadRemoved		*uint32
	HeaderLength		*uint32
	Header			*gopacket.Packet
}

type layers_SFlowRawPacketFlowRecord struct {
	SFlowBaseFlowRecord	*layers.SFlowBaseFlowRecord
	HeaderProtocol		*layers.SFlowRawHeaderProtocol
	FrameLength		*uint32
	PayloadRemoved		*uint32
	HeaderLength		*uint32
	Header			*gopacket.Packet
}

type layers_SFlowRecord interface {
}

type layers_SFlowRecord interface {
}

type layers_SFlowSampleType uint32

type layers_SFlowSampleType uint32

type layers_SFlowSourceFormat uint32

type layers_SFlowSourceFormat uint32

type layers_SFlowSourceValue uint32

type layers_SFlowSourceValue uint32

type layers_SFlowURLDirection uint32

type layers_SFlowURLDirection uint32

type layers_SFlowVLANCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	VlanID			*uint32
	Octets			*uint64
	UcastPkts		*uint32
	MulticastPkts		*uint32
	BroadcastPkts		*uint32
	Discards		*uint32
}

type layers_SFlowVLANCounters struct {
	SFlowBaseCounterRecord	*layers.SFlowBaseCounterRecord
	VlanID			*uint32
	Octets			*uint64
	UcastPkts		*uint32
	MulticastPkts		*uint32
	BroadcastPkts		*uint32
	Discards		*uint32
}

type layers_SIP struct {
	BaseLayer		*layers.BaseLayer
	Version			*layers.SIPVersion
	Method			*layers.SIPMethod
	Headers			*map[string][]string
	RequestURI		*string
	IsResponse		*bool
	ResponseCode		*int
	ResponseStatus		*string
	cseq			*int64
	contentLength		*int64
	lastHeaderParsed	*string
}

type layers_SIP struct {
	BaseLayer		*layers.BaseLayer
	Version			*layers.SIPVersion
	Method			*layers.SIPMethod
	Headers			*map[string][]string
	RequestURI		*string
	IsResponse		*bool
	ResponseCode		*int
	ResponseStatus		*string
	cseq			*int64
	contentLength		*int64
	lastHeaderParsed	*string
}

type layers_SIPMethod uint16

type layers_SIPMethod uint16

type layers_SIPVersion uint8

type layers_SIPVersion uint8

type layers_SNAP struct {
	BaseLayer		*layers.BaseLayer
	OrganizationalCode	*[]uint8
	Type			*layers.EthernetType
}

type layers_SNAP struct {
	BaseLayer		*layers.BaseLayer
	OrganizationalCode	*[]uint8
	Type			*layers.EthernetType
}

type layers_STP struct {
	BaseLayer *layers.BaseLayer
}

type layers_STP struct {
	BaseLayer *layers.BaseLayer
}

type layers_TCP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.TCPPort
	DstPort		*layers.TCPPort
	Seq		*uint32
	Ack		*uint32
	DataOffset	*uint8
	FIN		*bool
	SYN		*bool
	RST		*bool
	PSH		*bool
	ACK		*bool
	URG		*bool
	ECE		*bool
	CWR		*bool
	NS		*bool
	Window		*uint16
	Checksum	*uint16
	Urgent		*uint16
	sPort		*[]uint8
	dPort		*[]uint8
	Options		*[]layers.TCPOption
	Padding		*[]uint8
	opts		*[4]layers.TCPOption
	tcpipchecksum	*interface{}
}

type layers_TCP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.TCPPort
	DstPort		*layers.TCPPort
	Seq		*uint32
	Ack		*uint32
	DataOffset	*uint8
	FIN		*bool
	SYN		*bool
	RST		*bool
	PSH		*bool
	ACK		*bool
	URG		*bool
	ECE		*bool
	CWR		*bool
	NS		*bool
	Window		*uint16
	Checksum	*uint16
	Urgent		*uint16
	sPort		*[]uint8
	dPort		*[]uint8
	Options		*[]layers.TCPOption
	Padding		*[]uint8
	opts		*[4]layers.TCPOption
	tcpipchecksum	*interface{}
}

type layers_TCPOption struct {
	OptionType	*layers.TCPOptionKind
	OptionLength	*uint8
	OptionData	*[]uint8
}

type layers_TCPOption struct {
	OptionType	*layers.TCPOptionKind
	OptionLength	*uint8
	OptionData	*[]uint8
}

type layers_TCPOptionKind uint8

type layers_TCPOptionKind uint8

type layers_TCPPort uint16

type layers_TCPPort uint16

type layers_TLS struct {
	BaseLayer		*layers.BaseLayer
	ChangeCipherSpec	*[]layers.TLSChangeCipherSpecRecord
	Handshake		*[]layers.TLSHandshakeRecord
	AppData			*[]layers.TLSAppDataRecord
	Alert			*[]layers.TLSAlertRecord
}

type layers_TLS struct {
	BaseLayer		*layers.BaseLayer
	ChangeCipherSpec	*[]layers.TLSChangeCipherSpecRecord
	Handshake		*[]layers.TLSHandshakeRecord
	AppData			*[]layers.TLSAppDataRecord
	Alert			*[]layers.TLSAlertRecord
}

type layers_TLSAlertDescr uint8

type layers_TLSAlertDescr uint8

type layers_TLSAlertLevel uint8

type layers_TLSAlertLevel uint8

type layers_TLSAlertRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Level		*layers.TLSAlertLevel
	Description	*layers.TLSAlertDescr
	EncryptedMsg	*[]uint8
}

type layers_TLSAlertRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Level		*layers.TLSAlertLevel
	Description	*layers.TLSAlertDescr
	EncryptedMsg	*[]uint8
}

type layers_TLSAppDataRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Payload		*[]uint8
}

type layers_TLSAppDataRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Payload		*[]uint8
}

type layers_TLSChangeCipherSpecRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Message		*layers.TLSchangeCipherSpec
}

type layers_TLSChangeCipherSpecRecord struct {
	TLSRecordHeader	*layers.TLSRecordHeader
	Message		*layers.TLSchangeCipherSpec
}

type layers_TLSHandshakeRecord struct {
	TLSRecordHeader *layers.TLSRecordHeader
}

type layers_TLSHandshakeRecord struct {
	TLSRecordHeader *layers.TLSRecordHeader
}

type layers_TLSRecordHeader struct {
	ContentType	*layers.TLSType
	Version		*layers.TLSVersion
	Length		*uint16
}

type layers_TLSRecordHeader struct {
	ContentType	*layers.TLSType
	Version		*layers.TLSVersion
	Length		*uint16
}

type layers_TLSType uint8

type layers_TLSType uint8

type layers_TLSVersion uint16

type layers_TLSVersion uint16

type layers_TLSchangeCipherSpec uint8

type layers_TLSchangeCipherSpec uint8

type layers_UDP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.UDPPort
	DstPort		*layers.UDPPort
	Length		*uint16
	Checksum	*uint16
	sPort		*[]uint8
	dPort		*[]uint8
	tcpipchecksum	*interface{}
}

type layers_UDP struct {
	BaseLayer	*layers.BaseLayer
	SrcPort		*layers.UDPPort
	DstPort		*layers.UDPPort
	Length		*uint16
	Checksum	*uint16
	sPort		*[]uint8
	dPort		*[]uint8
	tcpipchecksum	*interface{}
}

type layers_UDPLite struct {
	BaseLayer		*layers.BaseLayer
	SrcPort			*layers.UDPLitePort
	DstPort			*layers.UDPLitePort
	ChecksumCoverage	*uint16
	Checksum		*uint16
	sPort			*[]uint8
	dPort			*[]uint8
}

type layers_UDPLite struct {
	BaseLayer		*layers.BaseLayer
	SrcPort			*layers.UDPLitePort
	DstPort			*layers.UDPLitePort
	ChecksumCoverage	*uint16
	Checksum		*uint16
	sPort			*[]uint8
	dPort			*[]uint8
}

type layers_UDPLitePort uint16

type layers_UDPLitePort uint16

type layers_UDPPort uint16

type layers_UDPPort uint16

type layers_USB struct {
	BaseLayer		*layers.BaseLayer
	ID			*uint64
	EventType		*layers.USBEventType
	TransferType		*layers.USBTransportType
	Direction		*layers.USBDirectionType
	EndpointNumber		*uint8
	DeviceAddress		*uint8
	BusID			*uint16
	TimestampSec		*int64
	TimestampUsec		*int32
	Setup			*bool
	Data			*bool
	Status			*int32
	UrbLength		*uint32
	UrbDataLength		*uint32
	UrbInterval		*uint32
	UrbStartFrame		*uint32
	UrbCopyOfTransferFlags	*uint32
	IsoNumDesc		*uint32
}

type layers_USB struct {
	BaseLayer		*layers.BaseLayer
	ID			*uint64
	EventType		*layers.USBEventType
	TransferType		*layers.USBTransportType
	Direction		*layers.USBDirectionType
	EndpointNumber		*uint8
	DeviceAddress		*uint8
	BusID			*uint16
	TimestampSec		*int64
	TimestampUsec		*int32
	Setup			*bool
	Data			*bool
	Status			*int32
	UrbLength		*uint32
	UrbDataLength		*uint32
	UrbInterval		*uint32
	UrbStartFrame		*uint32
	UrbCopyOfTransferFlags	*uint32
	IsoNumDesc		*uint32
}

type layers_USBBulk struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBBulk struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBControl struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBControl struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBDirectionType uint8

type layers_USBDirectionType uint8

type layers_USBEventType uint8

type layers_USBEventType uint8

type layers_USBInterrupt struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBInterrupt struct {
	BaseLayer *layers.BaseLayer
}

type layers_USBRequestBlockSetup struct {
	BaseLayer	*layers.BaseLayer
	RequestType	*uint8
	Request		*layers.USBRequestBlockSetupRequest
	Value		*uint16
	Index		*uint16
	Length		*uint16
}

type layers_USBRequestBlockSetup struct {
	BaseLayer	*layers.BaseLayer
	RequestType	*uint8
	Request		*layers.USBRequestBlockSetupRequest
	Value		*uint16
	Index		*uint16
	Length		*uint16
}

type layers_USBRequestBlockSetupRequest uint8

type layers_USBRequestBlockSetupRequest uint8

type layers_USBTransportType uint8

type layers_USBTransportType uint8

type layers_VRRPv2 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*layers.VRRPv2Type
	VirtualRtrID	*uint8
	Priority	*uint8
	CountIPAddr	*uint8
	AuthType	*layers.VRRPv2AuthType
	AdverInt	*uint8
	Checksum	*uint16
	IPAddress	*[]net.IP
}

type layers_VRRPv2 struct {
	BaseLayer	*layers.BaseLayer
	Version		*uint8
	Type		*layers.VRRPv2Type
	VirtualRtrID	*uint8
	Priority	*uint8
	CountIPAddr	*uint8
	AuthType	*layers.VRRPv2AuthType
	AdverInt	*uint8
	Checksum	*uint16
	IPAddress	*[]net.IP
}

type layers_VRRPv2AuthType uint8

type layers_VRRPv2AuthType uint8

type layers_VRRPv2Type uint8

type layers_VRRPv2Type uint8

type layers_VXLAN struct {
	BaseLayer		*layers.BaseLayer
	ValidIDFlag		*bool
	VNI			*uint32
	GBPExtension		*bool
	GBPDontLearn		*bool
	GBPApplied		*bool
	GBPGroupPolicyID	*uint16
}

type layers_VXLAN struct {
	BaseLayer		*layers.BaseLayer
	ValidIDFlag		*bool
	VNI			*uint32
	GBPExtension		*bool
	GBPDontLearn		*bool
	GBPApplied		*bool
	GBPGroupPolicyID	*uint16
}

type layers_errorDecoderForDot11Type int

type layers_errorDecoderForDot11Type int

type layers_errorDecoderForEAPOLType int

type layers_errorDecoderForEAPOLType int

type layers_errorDecoderForEthernetType int

type layers_errorDecoderForEthernetType int

type layers_errorDecoderForFDDIFrameControl int

type layers_errorDecoderForFDDIFrameControl int

type layers_errorDecoderForIPProtocol int

type layers_errorDecoderForIPProtocol int

type layers_errorDecoderForLinkType int

type layers_errorDecoderForLinkType int

type layers_errorDecoderForPPPType int

type layers_errorDecoderForPPPType int

type layers_errorDecoderForPPPoECode int

type layers_errorDecoderForPPPoECode int

type layers_errorDecoderForProtocolFamily int

type layers_errorDecoderForProtocolFamily int

type layers_errorDecoderForSCTPChunkType int

type layers_errorDecoderForSCTPChunkType int

type layers_errorDecoderForUSBTransportType int

type layers_errorDecoderForUSBTransportType int

type layers_icmpv4TypeCodeInfoStruct struct {
	typeStr	*string
	codeStr	*map[uint8]string
}

type layers_icmpv4TypeCodeInfoStruct struct {
	typeStr	*string
	codeStr	*map[uint8]string
}

type layers_icmpv6TypeCodeInfoStruct struct {
	typeStr	*string
	codeStr	*map[uint8]string
}

type layers_icmpv6TypeCodeInfoStruct struct {
	typeStr	*string
	codeStr	*map[uint8]string
}

type layers_ipv6ExtensionBase struct {
	BaseLayer	*layers.BaseLayer
	NextHeader	*layers.IPProtocol
	HeaderLength	*uint8
	ActualLength	*int
}

type layers_ipv6ExtensionBase struct {
	BaseLayer	*layers.BaseLayer
	NextHeader	*layers.IPProtocol
	HeaderLength	*uint8
	ActualLength	*int
}

type layers_ipv6HeaderTLVOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_ipv6HeaderTLVOption struct {
	OptionType	*uint8
	OptionLength	*uint8
	ActualLength	*int
	OptionData	*[]uint8
	OptionAlignment	*[2]uint8
}

type layers_layerDecodingLayer interface {
}

type layers_layerDecodingLayer interface {
}

type layers_tcpipPseudoHeader interface {
}

type layers_tcpipPseudoHeader interface {
}

type layers_tcpipchecksum struct {
	pseudoheader *interface{}
}

type layers_tcpipchecksum struct {
	pseudoheader *interface{}
}

type list_Element struct {
	next	*list.Element
	prev	*list.Element
	list	*list.List
	Value	*interface {}
}

type list_Element struct {
	next	*list.Element
	prev	*list.Element
	list	*list.List
	Value	*interface {}
}

type list_List struct {
	root	*list.Element
	len	*int
}

type list_List struct {
	root	*list.Element
	len	*int
}

type logging_CongestionState uint8

type logging_CongestionState uint8

type logging_ConnectionTracer struct {
	StartedConnection			*func(net.Addr, net.Addr, protocol.ConnectionID, protocol.ConnectionID)
	NegotiatedVersion			*func(protocol.Version, []protocol.Version, []protocol.Version)
	ClosedConnection			*func(error)
	SentTransportParameters			*func(*wire.TransportParameters)
	ReceivedTransportParameters		*func(*wire.TransportParameters)
	RestoredTransportParameters		*func(*wire.TransportParameters)
	SentLongHeaderPacket			*func(*wire.ExtendedHeader, protocol.ByteCount, protocol.ECN, *wire.AckFrame, []logging.Frame)
	SentShortHeaderPacket			*func(*logging.ShortHeader, protocol.ByteCount, protocol.ECN, *wire.AckFrame, []logging.Frame)
	ReceivedVersionNegotiationPacket	*func(protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.Version)
	ReceivedRetry				*func(*wire.Header)
	ReceivedLongHeaderPacket		*func(*wire.ExtendedHeader, protocol.ByteCount, protocol.ECN, []logging.Frame)
	ReceivedShortHeaderPacket		*func(*logging.ShortHeader, protocol.ByteCount, protocol.ECN, []logging.Frame)
	BufferedPacket				*func(logging.PacketType, protocol.ByteCount)
	DroppedPacket				*func(logging.PacketType, protocol.PacketNumber, protocol.ByteCount, logging.PacketDropReason)
	UpdatedMetrics				*func(*utils.RTTStats, protocol.ByteCount, protocol.ByteCount, int)
	AcknowledgedPacket			*func(protocol.EncryptionLevel, protocol.PacketNumber)
	LostPacket				*func(protocol.EncryptionLevel, protocol.PacketNumber, logging.PacketLossReason)
	UpdatedMTU				*func(protocol.ByteCount, bool)
	UpdatedCongestionState			*func(logging.CongestionState)
	UpdatedPTOCount				*func(uint32)
	UpdatedKeyFromTLS			*func(protocol.EncryptionLevel, protocol.Perspective)
	UpdatedKey				*func(protocol.KeyPhase, bool)
	DroppedEncryptionLevel			*func(protocol.EncryptionLevel)
	DroppedKey				*func(protocol.KeyPhase)
	SetLossTimer				*func(logging.TimerType, protocol.EncryptionLevel, time.Time)
	LossTimerExpired			*func(logging.TimerType, protocol.EncryptionLevel)
	LossTimerCanceled			*func()
	ECNStateUpdated				*func(logging.ECNState, logging.ECNStateTrigger)
	ChoseALPN				*func(string)
	Close					*func()
	Debug					*func(string, string)
}

type logging_ConnectionTracer struct {
	StartedConnection			*func(net.Addr, net.Addr, protocol.ConnectionID, protocol.ConnectionID)
	NegotiatedVersion			*func(protocol.Version, []protocol.Version, []protocol.Version)
	ClosedConnection			*func(error)
	SentTransportParameters			*func(*wire.TransportParameters)
	ReceivedTransportParameters		*func(*wire.TransportParameters)
	RestoredTransportParameters		*func(*wire.TransportParameters)
	SentLongHeaderPacket			*func(*wire.ExtendedHeader, protocol.ByteCount, protocol.ECN, *wire.AckFrame, []logging.Frame)
	SentShortHeaderPacket			*func(*logging.ShortHeader, protocol.ByteCount, protocol.ECN, *wire.AckFrame, []logging.Frame)
	ReceivedVersionNegotiationPacket	*func(protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.Version)
	ReceivedRetry				*func(*wire.Header)
	ReceivedLongHeaderPacket		*func(*wire.ExtendedHeader, protocol.ByteCount, protocol.ECN, []logging.Frame)
	ReceivedShortHeaderPacket		*func(*logging.ShortHeader, protocol.ByteCount, protocol.ECN, []logging.Frame)
	BufferedPacket				*func(logging.PacketType, protocol.ByteCount)
	DroppedPacket				*func(logging.PacketType, protocol.PacketNumber, protocol.ByteCount, logging.PacketDropReason)
	UpdatedMetrics				*func(*utils.RTTStats, protocol.ByteCount, protocol.ByteCount, int)
	AcknowledgedPacket			*func(protocol.EncryptionLevel, protocol.PacketNumber)
	LostPacket				*func(protocol.EncryptionLevel, protocol.PacketNumber, logging.PacketLossReason)
	UpdatedMTU				*func(protocol.ByteCount, bool)
	UpdatedCongestionState			*func(logging.CongestionState)
	UpdatedPTOCount				*func(uint32)
	UpdatedKeyFromTLS			*func(protocol.EncryptionLevel, protocol.Perspective)
	UpdatedKey				*func(protocol.KeyPhase, bool)
	DroppedEncryptionLevel			*func(protocol.EncryptionLevel)
	DroppedKey				*func(protocol.KeyPhase)
	SetLossTimer				*func(logging.TimerType, protocol.EncryptionLevel, time.Time)
	LossTimerExpired			*func(logging.TimerType, protocol.EncryptionLevel)
	LossTimerCanceled			*func()
	ECNStateUpdated				*func(logging.ECNState, logging.ECNStateTrigger)
	ChoseALPN				*func(string)
	Close					*func()
	Debug					*func(string, string)
}

type logging_CryptoFrame struct {
	Offset	*protocol.ByteCount
	Length	*protocol.ByteCount
}

type logging_CryptoFrame struct {
	Offset	*protocol.ByteCount
	Length	*protocol.ByteCount
}

type logging_DatagramFrame struct {
	Length *protocol.ByteCount
}

type logging_DatagramFrame struct {
	Length *protocol.ByteCount
}

type logging_ECNState uint8

type logging_ECNState uint8

type logging_ECNStateTrigger uint8

type logging_ECNStateTrigger uint8

type logging_Frame interface {
}

type logging_Frame interface {
}

type logging_PacketDropReason uint8

type logging_PacketDropReason uint8

type logging_PacketLossReason uint8

type logging_PacketLossReason uint8

type logging_PacketType uint8

type logging_PacketType uint8

type logging_ShortHeader struct {
	DestConnectionID	*protocol.ConnectionID
	PacketNumber		*protocol.PacketNumber
	PacketNumberLen		*protocol.PacketNumberLen
	KeyPhase		*protocol.KeyPhaseBit
}

type logging_ShortHeader struct {
	DestConnectionID	*protocol.ConnectionID
	PacketNumber		*protocol.PacketNumber
	PacketNumberLen		*protocol.PacketNumberLen
	KeyPhase		*protocol.KeyPhaseBit
}

type logging_StreamFrame struct {
	StreamID	*protocol.StreamID
	Offset		*protocol.ByteCount
	Length		*protocol.ByteCount
	Fin		*bool
}

type logging_StreamFrame struct {
	StreamID	*protocol.StreamID
	Offset		*protocol.ByteCount
	Length		*protocol.ByteCount
	Fin		*bool
}

type logging_TimerType uint8

type logging_TimerType uint8

type logging_Tracer struct {
	SentPacket			*func(net.Addr, *wire.Header, protocol.ByteCount, []logging.Frame)
	SentVersionNegotiationPacket	*func(net.Addr, protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.Version)
	DroppedPacket			*func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason)
	Debug				*func(string, string)
	Close				*func()
}

type logging_Tracer struct {
	SentPacket			*func(net.Addr, *wire.Header, protocol.ByteCount, []logging.Frame)
	SentVersionNegotiationPacket	*func(net.Addr, protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.Version)
	DroppedPacket			*func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason)
	Debug				*func(string, string)
	Close				*func()
}

type md5_digest struct {
	s	*[4]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
}

type md5_digest struct {
	s	*[4]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
}

type mldsa44_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1280]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa44_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1280]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa44_scheme struct {
}

type mldsa44_scheme struct {
}

type mldsa65_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1920]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa65_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1920]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa65_scheme struct {
}

type mldsa65_scheme struct {
}

type mldsa87_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[2560]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa87_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[2560]uint8
	A	*internal.Mat
	tr	*[64]uint8
}

type mldsa87_scheme struct {
}

type mldsa87_scheme struct {
}

type mlkem_DecapsulationKey768 struct {
	key *mlkem.DecapsulationKey768
}

type mlkem_DecapsulationKey768 struct {
	d		*[32]uint8
	z		*[32]uint8
	ρ		*[32]uint8
	h		*[32]uint8
	encryptionKey	*interface{}
	decryptionKey	*interface{}
}

type mlkem_DecapsulationKey768 struct {
	d		*[32]uint8
	z		*[32]uint8
	ρ		*[32]uint8
	h		*[32]uint8
	encryptionKey	*interface{}
	decryptionKey	*interface{}
}

type mlkem_DecapsulationKey768 struct {
	key *mlkem.DecapsulationKey768
}

type mlkem_decryptionKey struct {
	s *[3]mlkem.nttElement
}

type mlkem_decryptionKey struct {
	s *[3]mlkem.nttElement
}

type mlkem_encryptionKey struct {
	t	*[3]mlkem.nttElement
	a	*[9]mlkem.nttElement
}

type mlkem_encryptionKey struct {
	t	*[3]mlkem.nttElement
	a	*[9]mlkem.nttElement
}

type mlkem_fieldElement uint16

type mlkem_fieldElement uint16

type mlkem_nttElement [256]*interface{}

type mlkem_nttElement [256]*interface{}

type mlkem768_PrivateKey struct {
	sk	*kyber768.PrivateKey
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
	z	*[32]uint8
}

type mlkem768_PrivateKey struct {
	sk	*kyber768.PrivateKey
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
	z	*[32]uint8
}

type mlkem768_PublicKey struct {
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
}

type mlkem768_PublicKey struct {
	pk	*kyber768.PublicKey
	hpk	*[32]uint8
}

type mode2_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1280]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode2_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1280]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode2_scheme struct {
}

type mode2_scheme struct {
}

type mode3_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1920]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode3_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[1920]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode3_scheme struct {
}

type mode3_scheme struct {
}

type mode5_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[2560]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode5_PublicKey struct {
	rho	*[32]uint8
	t1	*internal.VecK
	t1p	*[2560]uint8
	A	*internal.Mat
	tr	*[32]uint8
}

type mode5_scheme struct {
}

type mode5_scheme struct {
}

type multipart_FileHeader struct {
	Filename	*string
	Header		*textproto.MIMEHeader
	Size		*int64
	content		*[]uint8
	tmpfile		*string
	tmpoff		*int64
	tmpshared	*bool
}

type multipart_FileHeader struct {
	Filename	*string
	Header		*textproto.MIMEHeader
	Size		*int64
	content		*[]uint8
	tmpfile		*string
	tmpoff		*int64
	tmpshared	*bool
}

type multipart_Form struct {
	Value	*map[string][]string
	File	*map[string][]*multipart.FileHeader
}

type multipart_Form struct {
	Value	*map[string][]string
	File	*map[string][]*multipart.FileHeader
}

type netip_Addr struct {
	addr	*interface{}
	z	*interface{}
}

type netip_Addr struct {
	addr	*interface{}
	z	*interface{}
}

type netip_AddrPort struct {
	ip	*netip.Addr
	port	*uint16
}

type netip_AddrPort struct {
	ip	*netip.Addr
	port	*uint16
}

type netip_Prefix struct {
	ip		*netip.Addr
	bitsPlusOne	*uint8
}

type netip_Prefix struct {
	ip		*netip.Addr
	bitsPlusOne	*uint8
}

type netip_addrDetail struct {
	isV6	*bool
	zoneV6	*string
}

type netip_addrDetail struct {
	isV6	*bool
	zoneV6	*string
}

type netip_parseAddrError struct {
	in	*string
	msg	*string
	at	*string
}

type netip_parseAddrError struct {
	in	*string
	msg	*string
	at	*string
}

type netip_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type netip_uint128 struct {
	hi	*uint64
	lo	*uint64
}

type nettrace_LookupIPAltResolverKey struct {
}

type nettrace_LookupIPAltResolverKey struct {
}

type nettrace_Trace struct {
	DNSStart	*func(string)
	DNSDone		*func([]interface {}, bool, error)
	ConnectStart	*func(string, string)
	ConnectDone	*func(string, string, error)
}

type nettrace_Trace struct {
	DNSStart	*func(string)
	DNSDone		*func([]interface {}, bool, error)
	ConnectStart	*func(string, string)
	ConnectDone	*func(string, string, error)
}

type nettrace_TraceKey struct {
}

type nettrace_TraceKey struct {
}

type nistec_P224Point struct {
	x	*fiat.P224Element
	y	*fiat.P224Element
	z	*fiat.P224Element
}

type nistec_P224Point struct {
	x	*fiat.P224Element
	y	*fiat.P224Element
	z	*fiat.P224Element
}

type nistec_P256Point struct {
	x	*fiat.P256Element
	y	*fiat.P256Element
	z	*fiat.P256Element
}

type nistec_P256Point struct {
	x	*fiat.P256Element
	y	*fiat.P256Element
	z	*fiat.P256Element
}

type nistec_P384Point struct {
	x	*fiat.P384Element
	y	*fiat.P384Element
	z	*fiat.P384Element
}

type nistec_P384Point struct {
	x	*fiat.P384Element
	y	*fiat.P384Element
	z	*fiat.P384Element
}

type nistec_P521Point struct {
	x	*fiat.P521Element
	y	*fiat.P521Element
	z	*fiat.P521Element
}

type nistec_P521Point struct {
	x	*fiat.P521Element
	y	*fiat.P521Element
	z	*fiat.P521Element
}

type nistec_p224Table [15]*nistec.P224Point

type nistec_p224Table [15]*nistec.P224Point

type nistec_p384Table [15]*nistec.P384Point

type nistec_p384Table [15]*nistec.P384Point

type nistec_p521Table [15]*nistec.P521Point

type nistec_p521Table [15]*nistec.P521Point

type norm_Form int

type norm_Form int

type norm_Form int

type norm_Form int

type norm_Iter struct {
	rb		*interface{}
	buf		*[128]uint8
	info		*norm.Properties
	next		*interface{}
	asciiF		*interface{}
	p		*int
	multiSeg	*[]uint8
}

type norm_Iter struct {
	rb		*interface{}
	buf		*[128]uint8
	info		*norm.Properties
	next		*interface{}
	asciiF		*interface{}
	p		*int
	multiSeg	*[]uint8
}

type norm_Iter struct {
	rb		*interface{}
	buf		*[128]uint8
	info		*norm.Properties
	next		*interface{}
	asciiF		*interface{}
	p		*int
	multiSeg	*[]uint8
}

type norm_Iter struct {
	rb		*interface{}
	buf		*[128]uint8
	info		*norm.Properties
	next		*interface{}
	asciiF		*interface{}
	p		*int
	multiSeg	*[]uint8
}

type norm_Properties struct {
	pos	*uint8
	size	*uint8
	ccc	*uint8
	tccc	*uint8
	nLead	*uint8
	flags	*interface{}
	index	*uint16
}

type norm_Properties struct {
	pos	*uint8
	size	*uint8
	ccc	*uint8
	tccc	*uint8
	nLead	*uint8
	flags	*interface{}
	index	*uint16
}

type norm_Properties struct {
	pos	*uint8
	size	*uint8
	ccc	*uint8
	tccc	*uint8
	nLead	*uint8
	flags	*interface{}
	index	*uint16
}

type norm_Properties struct {
	pos	*uint8
	size	*uint8
	ccc	*uint8
	tccc	*uint8
	nLead	*uint8
	flags	*interface{}
	index	*uint16
}

type norm_formInfo struct {
	form		*norm.Form
	composing	*bool
	compatibility	*bool
	info		*interface{}
	nextMain	*interface{}
}

type norm_formInfo struct {
	form		*norm.Form
	composing	*bool
	compatibility	*bool
	info		*interface{}
	nextMain	*interface{}
}

type norm_formInfo struct {
	form		*norm.Form
	composing	*bool
	compatibility	*bool
	info		*interface{}
	nextMain	*interface{}
}

type norm_formInfo struct {
	form		*norm.Form
	composing	*bool
	compatibility	*bool
	info		*interface{}
	nextMain	*interface{}
}

type norm_input struct {
	str	*string
	bytes	*[]uint8
}

type norm_input struct {
	str	*string
	bytes	*[]uint8
}

type norm_input struct {
	str	*string
	bytes	*[]uint8
}

type norm_input struct {
	str	*string
	bytes	*[]uint8
}

type norm_iterFunc func()

type norm_iterFunc func()

type norm_iterFunc func()

type norm_iterFunc func()

type norm_lookupFunc func()

type norm_lookupFunc func()

type norm_lookupFunc func()

type norm_lookupFunc func()

type norm_qcInfo uint8

type norm_qcInfo uint8

type norm_qcInfo uint8

type norm_qcInfo uint8

type norm_reorderBuffer struct {
	rune		*[32]norm.Properties
	byte		*[128]uint8
	nbyte		*uint8
	ss		*interface{}
	nrune		*int
	f		*interface{}
	src		*interface{}
	nsrc		*int
	tmpBytes	*interface{}
	out		*[]uint8
	flushF		*func(*norm.reorderBuffer) bool
}

type norm_reorderBuffer struct {
	rune		*[32]norm.Properties
	byte		*[128]uint8
	nbyte		*uint8
	ss		*interface{}
	nrune		*int
	f		*interface{}
	src		*interface{}
	nsrc		*int
	tmpBytes	*interface{}
	out		*[]uint8
	flushF		*func(*norm.reorderBuffer) bool
}

type norm_reorderBuffer struct {
	rune		*[32]norm.Properties
	byte		*[128]uint8
	nbyte		*uint8
	ss		*interface{}
	nrune		*int
	f		*interface{}
	src		*interface{}
	nsrc		*int
	tmpBytes	*interface{}
	out		*[]uint8
	flushF		*func(*norm.reorderBuffer) bool
}

type norm_reorderBuffer struct {
	rune		*[32]norm.Properties
	byte		*[128]uint8
	nbyte		*uint8
	ss		*interface{}
	nrune		*int
	f		*interface{}
	src		*interface{}
	nsrc		*int
	tmpBytes	*interface{}
	out		*[]uint8
	flushF		*func(*norm.reorderBuffer) bool
}

type norm_streamSafe uint8

type norm_streamSafe uint8

type norm_streamSafe uint8

type norm_streamSafe uint8

type pem_Block struct {
	Type	*string
	Headers	*map[string]string
	Bytes	*[]uint8
}

type pem_Block struct {
	Type	*string
	Headers	*map[string]string
	Bytes	*[]uint8
}

type pki_CertificateScheme interface {
}

type pki_CertificateScheme interface {
}

type pki_TLSScheme interface {
}

type pki_TLSScheme interface {
}

type pkix_AlgorithmIdentifier struct {
	Algorithm	*asn1.ObjectIdentifier
	Parameters	*asn1.RawValue
}

type pkix_AlgorithmIdentifier struct {
	Algorithm	*asn1.ObjectIdentifier
	Parameters	*asn1.RawValue
}

type pkix_AttributeTypeAndValue struct {
	Type	*asn1.ObjectIdentifier
	Value	*interface {}
}

type pkix_AttributeTypeAndValue struct {
	Type	*asn1.ObjectIdentifier
	Value	*interface {}
}

type pkix_Extension struct {
	Id		*asn1.ObjectIdentifier
	Critical	*bool
	Value		*[]uint8
}

type pkix_Extension struct {
	Id		*asn1.ObjectIdentifier
	Critical	*bool
	Value		*[]uint8
}

type pkix_Name struct {
	Country			*[]string
	Organization		*[]string
	OrganizationalUnit	*[]string
	Locality		*[]string
	Province		*[]string
	StreetAddress		*[]string
	PostalCode		*[]string
	SerialNumber		*string
	CommonName		*string
	Names			*[]pkix.AttributeTypeAndValue
	ExtraNames		*[]pkix.AttributeTypeAndValue
}

type pkix_Name struct {
	Country			*[]string
	Organization		*[]string
	OrganizationalUnit	*[]string
	Locality		*[]string
	Province		*[]string
	StreetAddress		*[]string
	PostalCode		*[]string
	SerialNumber		*string
	CommonName		*string
	Names			*[]pkix.AttributeTypeAndValue
	ExtraNames		*[]pkix.AttributeTypeAndValue
}

type pkix_RDNSequence []*pkix.RelativeDistinguishedNameSET

type pkix_RDNSequence []*pkix.RelativeDistinguishedNameSET

type pkix_RelativeDistinguishedNameSET []*pkix.AttributeTypeAndValue

type pkix_RelativeDistinguishedNameSET []*pkix.AttributeTypeAndValue

type poll_DeadlineExceededError struct {
}

type poll_DeadlineExceededError struct {
}

type poll_FD struct {
	fdmu		*interface{}
	Sysfd		*int
	SysFile		*poll.SysFile
	pd		*interface{}
	csema		*uint32
	isBlocking	*uint32
	IsStream	*bool
	ZeroReadIsEOF	*bool
	isFile		*bool
}

type poll_FD struct {
	fdmu		*interface{}
	Sysfd		*int
	SysFile		*poll.SysFile
	pd		*interface{}
	csema		*uint32
	isBlocking	*uint32
	IsStream	*bool
	ZeroReadIsEOF	*bool
	isFile		*bool
}

type poll_String string

type poll_String string

type poll_SysFile struct {
	iovecs *[]syscall.Iovec
}

type poll_SysFile struct {
	iovecs *[]syscall.Iovec
}

type poll_errNetClosing struct {
}

type poll_errNetClosing struct {
}

type poll_fdMutex struct {
	state	*uint64
	rsema	*uint32
	wsema	*uint32
}

type poll_fdMutex struct {
	state	*uint64
	rsema	*uint32
	wsema	*uint32
}

type poll_pollDesc struct {
	runtimeCtx *uintptr
}

type poll_pollDesc struct {
	runtimeCtx *uintptr
}

type poll_splicePipe struct {
	splicePipeFields	*interface{}
	cleanup			*runtime.Cleanup
}

type poll_splicePipe struct {
	splicePipeFields	*interface{}
	cleanup			*runtime.Cleanup
}

type poll_splicePipeFields struct {
	rfd	*int
	wfd	*int
	data	*int
}

type poll_splicePipeFields struct {
	rfd	*int
	wfd	*int
	data	*int
}

type profiles_ClientProfile struct {
	clientHelloId		*tls.ClientHelloID
	headerPriority		*http2.PriorityParam
	settings		*map[http2.SettingID]uint32
	priorities		*[]http2.Priority
	pseudoHeaderOrder	*[]string
	settingsOrder		*[]http2.SettingID
	connectionFlow		*uint32
}

type profiles_ClientProfile struct {
	clientHelloId		*tls.ClientHelloID
	headerPriority		*http2.PriorityParam
	settings		*map[http2.SettingID]uint32
	priorities		*[]http2.Priority
	pseudoHeaderOrder	*[]string
	settingsOrder		*[]http2.SettingID
	connectionFlow		*uint32
}

type protocol_ArbitraryLenConnectionID []*uint8

type protocol_ArbitraryLenConnectionID []*uint8

type protocol_ByteCount int64

type protocol_ByteCount int64

type protocol_ConnectionID struct {
	b	*[20]uint8
	l	*uint8
}

type protocol_ConnectionID struct {
	b	*[20]uint8
	l	*uint8
}

type protocol_DefaultConnectionIDGenerator struct {
	ConnLen *int
}

type protocol_DefaultConnectionIDGenerator struct {
	ConnLen *int
}

type protocol_ECN uint8

type protocol_ECN uint8

type protocol_EncryptionLevel uint8

type protocol_EncryptionLevel uint8

type protocol_ExpEmptyConnectionIDGenerator struct {
}

type protocol_ExpEmptyConnectionIDGenerator struct {
}

type protocol_KeyPhase uint64

type protocol_KeyPhase uint64

type protocol_KeyPhaseBit uint8

type protocol_KeyPhaseBit uint8

type protocol_PacketNumber int64

type protocol_PacketNumber int64

type protocol_PacketNumberLen uint8

type protocol_PacketNumberLen uint8

type protocol_PacketType uint8

type protocol_PacketType uint8

type protocol_Perspective int

type protocol_Perspective int

type protocol_StatelessResetToken [16]*uint8

type protocol_StatelessResetToken [16]*uint8

type protocol_StreamID int64

type protocol_StreamID int64

type protocol_StreamNum int64

type protocol_StreamNum int64

type protocol_StreamType uint8

type protocol_StreamType uint8

type protocol_Version uint32

type protocol_Version uint32

type proxy_ContextDialer interface {
}

type proxy_ContextDialer interface {
}

type proxy_Dialer interface {
}

type proxy_Dialer interface {
}

type proxy_direct struct {
}

type proxy_direct struct {
}

type qerr_ApplicationError struct {
	Remote		*bool
	ErrorCode	*qerr.ApplicationErrorCode
	ErrorMessage	*string
}

type qerr_ApplicationError struct {
	Remote		*bool
	ErrorCode	*qerr.ApplicationErrorCode
	ErrorMessage	*string
}

type qerr_ApplicationErrorCode uint64

type qerr_ApplicationErrorCode uint64

type qerr_HandshakeTimeoutError struct {
}

type qerr_HandshakeTimeoutError struct {
}

type qerr_IdleTimeoutError struct {
}

type qerr_IdleTimeoutError struct {
}

type qerr_StatelessResetError struct {
}

type qerr_StatelessResetError struct {
}

type qerr_StreamErrorCode uint64

type qerr_StreamErrorCode uint64

type qerr_TransportError struct {
	Remote		*bool
	FrameType	*uint64
	ErrorCode	*qerr.TransportErrorCode
	ErrorMessage	*string
	error		*error
}

type qerr_TransportError struct {
	Remote		*bool
	FrameType	*uint64
	ErrorCode	*qerr.TransportErrorCode
	ErrorMessage	*string
	error		*error
}

type qerr_TransportErrorCode uint64

type qerr_TransportErrorCode uint64

type qerr_VersionNegotiationError struct {
	Ours	*[]protocol.Version
	Theirs	*[]protocol.Version
}

type qerr_VersionNegotiationError struct {
	Ours	*[]protocol.Version
	Theirs	*[]protocol.Version
}

type qpack_Decoder struct {
	mutex			*sync.Mutex
	emitFunc		*func(qpack.HeaderField)
	readRequiredInsertCount	*bool
	readDeltaBase		*bool
	buf			*[]uint8
	saveBuf			*bytes.Buffer
}

type qpack_Decoder struct {
	mutex			*sync.Mutex
	emitFunc		*func(qpack.HeaderField)
	readRequiredInsertCount	*bool
	readDeltaBase		*bool
	buf			*[]uint8
	saveBuf			*bytes.Buffer
}

type qpack_Encoder struct {
	wrotePrefix	*bool
	w		*io.Writer
	buf		*[]uint8
}

type qpack_Encoder struct {
	wrotePrefix	*bool
	w		*io.Writer
	buf		*[]uint8
}

type qpack_HeaderField struct {
	Name	*string
	Value	*string
}

type qpack_HeaderField struct {
	Name	*string
	Value	*string
}

type qpack_decodingError struct {
	err *error
}

type qpack_decodingError struct {
	err *error
}

type qpack_indexAndValues struct {
	idx	*uint8
	values	*map[string]uint8
}

type qpack_indexAndValues struct {
	idx	*uint8
	values	*map[string]uint8
}

type qpack_invalidIndexError int

type qpack_invalidIndexError int

type quic_ClientInfo struct {
	RemoteAddr	*net.Addr
	AddrVerified	*bool
}

type quic_ClientInfo struct {
	RemoteAddr	*net.Addr
	AddrVerified	*bool
}

type quic_ClientToken struct {
	data	*[]uint8
	rtt	*time.Duration
}

type quic_ClientToken struct {
	data	*[]uint8
	rtt	*time.Duration
}

type quic_Config struct {
	GetConfigForClient			*func(*quic.ClientInfo) (*quic.Config, error)
	Versions				*[]protocol.Version
	HandshakeIdleTimeout			*time.Duration
	MaxIdleTimeout				*time.Duration
	TokenStore				*quic.TokenStore
	InitialStreamReceiveWindow		*uint64
	MaxStreamReceiveWindow			*uint64
	InitialConnectionReceiveWindow		*uint64
	MaxConnectionReceiveWindow		*uint64
	AllowConnectionWindowIncrease		*func(*quic.Conn, uint64) bool
	MaxIncomingStreams			*int64
	MaxIncomingUniStreams			*int64
	KeepAlivePeriod				*time.Duration
	InitialPacketSize			*uint16
	DisablePathMTUDiscovery			*bool
	Allow0RTT				*bool
	EnableDatagrams				*bool
	EnableStreamResetPartialDelivery	*bool
	Tracer					*func(context.Context, protocol.Perspective, protocol.ConnectionID) *logging.ConnectionTracer
	TLSGetClientHelloSpec			*func() *tls.ClientHelloSpec
}

type quic_Config struct {
	GetConfigForClient			*func(*quic.ClientInfo) (*quic.Config, error)
	Versions				*[]protocol.Version
	HandshakeIdleTimeout			*time.Duration
	MaxIdleTimeout				*time.Duration
	TokenStore				*quic.TokenStore
	InitialStreamReceiveWindow		*uint64
	MaxStreamReceiveWindow			*uint64
	InitialConnectionReceiveWindow		*uint64
	MaxConnectionReceiveWindow		*uint64
	AllowConnectionWindowIncrease		*func(*quic.Conn, uint64) bool
	MaxIncomingStreams			*int64
	MaxIncomingUniStreams			*int64
	KeepAlivePeriod				*time.Duration
	InitialPacketSize			*uint16
	DisablePathMTUDiscovery			*bool
	Allow0RTT				*bool
	EnableDatagrams				*bool
	EnableStreamResetPartialDelivery	*bool
	Tracer					*func(context.Context, protocol.Perspective, protocol.ConnectionID) *logging.ConnectionTracer
	TLSGetClientHelloSpec			*func() *tls.ClientHelloSpec
}

type quic_Conn struct {
	handshakeDestConnID				*protocol.ConnectionID
	origDestConnID					*protocol.ConnectionID
	retrySrcConnID					*protocol.ConnectionID
	srcConnIDLen					*int
	perspective					*protocol.Perspective
	version						*protocol.Version
	config						*quic.Config
	conn						*interface{}
	sendQueue					*interface{}
	pathManager					*interface{}
	largestRcvdAppData				*protocol.PacketNumber
	pathManagerOutgoing				*interface{}
	streamsMap					*interface{}
	connIDManager					*interface{}
	connIDGenerator					*interface{}
	rttStats					*utils.RTTStats
	connStats					*utils.ConnectionStats
	cryptoStreamManager				*interface{}
	sentPacketHandler				*ackhandler.SentPacketHandler
	receivedPacketHandler				*ackhandler.ReceivedPacketHandler
	retransmissionQueue				*interface{}
	framer						*interface{}
	connFlowController				*flowcontrol.ConnectionFlowController
	tokenStoreKey					*string
	tokenGenerator					*handshake.TokenGenerator
	unpacker					*interface{}
	frameParser					*wire.FrameParser
	packer						*interface{}
	mtuDiscoverer					*interface{}
	currentMTUEstimate				*atomic.Uint32
	initialStream					*interface{}
	handshakeStream					*interface{}
	oneRTTStream					*interface{}
	cryptoStreamHandler				*interface{}
	notifyReceivedPacket				*chan struct {}
	sendingScheduled				*chan struct {}
	receivedPacketMx				*sync.Mutex
	receivedPackets					*interface{}
	closeChan					*chan struct {}
	closeErr					*interface{}
	ctx						*context.Context
	ctxCancel					*context.CancelCauseFunc
	handshakeCompleteChan				*chan struct {}
	undecryptablePackets				*[]quic.receivedPacket
	undecryptablePacketsToProcess			*[]quic.receivedPacket
	earlyConnReadyChan				*chan struct {}
	sentFirstPacket					*bool
	droppedInitialKeys				*bool
	handshakeComplete				*bool
	handshakeConfirmed				*bool
	receivedRetry					*bool
	versionNegotiated				*bool
	receivedFirstPacket				*bool
	idleTimeout					*time.Duration
	creationTime					*time.Time
	lastPacketReceivedTime				*time.Time
	firstAckElicitingPacketAfterIdleSentTime	*time.Time
	pacingDeadline					*time.Time
	peerParams					*wire.TransportParameters
	timer						*interface{}
	keepAlivePingSent				*bool
	keepAliveInterval				*time.Duration
	datagramQueue					*interface{}
	connStateMutex					*sync.Mutex
	connState					*quic.ConnectionState
	logID						*string
	tracer						*logging.ConnectionTracer
	logger						*utils.Logger
}

type quic_Conn struct {
	handshakeDestConnID				*protocol.ConnectionID
	origDestConnID					*protocol.ConnectionID
	retrySrcConnID					*protocol.ConnectionID
	srcConnIDLen					*int
	perspective					*protocol.Perspective
	version						*protocol.Version
	config						*quic.Config
	conn						*interface{}
	sendQueue					*interface{}
	pathManager					*interface{}
	largestRcvdAppData				*protocol.PacketNumber
	pathManagerOutgoing				*interface{}
	streamsMap					*interface{}
	connIDManager					*interface{}
	connIDGenerator					*interface{}
	rttStats					*utils.RTTStats
	connStats					*utils.ConnectionStats
	cryptoStreamManager				*interface{}
	sentPacketHandler				*ackhandler.SentPacketHandler
	receivedPacketHandler				*ackhandler.ReceivedPacketHandler
	retransmissionQueue				*interface{}
	framer						*interface{}
	connFlowController				*flowcontrol.ConnectionFlowController
	tokenStoreKey					*string
	tokenGenerator					*handshake.TokenGenerator
	unpacker					*interface{}
	frameParser					*wire.FrameParser
	packer						*interface{}
	mtuDiscoverer					*interface{}
	currentMTUEstimate				*atomic.Uint32
	initialStream					*interface{}
	handshakeStream					*interface{}
	oneRTTStream					*interface{}
	cryptoStreamHandler				*interface{}
	notifyReceivedPacket				*chan struct {}
	sendingScheduled				*chan struct {}
	receivedPacketMx				*sync.Mutex
	receivedPackets					*interface{}
	closeChan					*chan struct {}
	closeErr					*interface{}
	ctx						*context.Context
	ctxCancel					*context.CancelCauseFunc
	handshakeCompleteChan				*chan struct {}
	undecryptablePackets				*[]quic.receivedPacket
	undecryptablePacketsToProcess			*[]quic.receivedPacket
	earlyConnReadyChan				*chan struct {}
	sentFirstPacket					*bool
	droppedInitialKeys				*bool
	handshakeComplete				*bool
	handshakeConfirmed				*bool
	receivedRetry					*bool
	versionNegotiated				*bool
	receivedFirstPacket				*bool
	idleTimeout					*time.Duration
	creationTime					*time.Time
	lastPacketReceivedTime				*time.Time
	firstAckElicitingPacketAfterIdleSentTime	*time.Time
	pacingDeadline					*time.Time
	peerParams					*wire.TransportParameters
	timer						*interface{}
	keepAlivePingSent				*bool
	keepAliveInterval				*time.Duration
	datagramQueue					*interface{}
	connStateMutex					*sync.Mutex
	connState					*quic.ConnectionState
	logID						*string
	tracer						*logging.ConnectionTracer
	logger						*utils.Logger
}

type quic_ConnectionIDGenerator interface {
}

type quic_ConnectionIDGenerator interface {
}

type quic_ConnectionState struct {
	TLS					*tls.ConnectionState
	SupportsDatagrams			*bool
	SupportsStreamResetPartialDelivery	*bool
	Used0RTT				*bool
	Version					*protocol.Version
	GSO					*bool
}

type quic_ConnectionState struct {
	TLS					*tls.ConnectionState
	SupportsDatagrams			*bool
	SupportsStreamResetPartialDelivery	*bool
	Used0RTT				*bool
	Version					*protocol.Version
	GSO					*bool
}

type quic_ConnectionTracingID uint64

type quic_ConnectionTracingID uint64

type quic_DatagramTooLargeError struct {
	MaxDatagramPayloadSize *int64
}

type quic_DatagramTooLargeError struct {
	MaxDatagramPayloadSize *int64
}

type quic_InitialPacketSpec struct {
	SrcConnIDLength		*int
	DestConnIDLength	*int
	InitPacketNumberLength	*protocol.PacketNumberLen
	InitPacketNumber	*uint64
	TokenStore		*quic.TokenStore
	ClientTokenLength	*int
	FrameBuilder		*quic.QUICFrameBuilder
}

type quic_InitialPacketSpec struct {
	SrcConnIDLength		*int
	DestConnIDLength	*int
	InitPacketNumberLength	*protocol.PacketNumberLen
	InitPacketNumber	*uint64
	TokenStore		*quic.TokenStore
	ClientTokenLength	*int
	FrameBuilder		*quic.QUICFrameBuilder
}

type quic_OOBCapablePacketConn interface {
}

type quic_OOBCapablePacketConn interface {
}

type quic_QUICFrame interface {
}

type quic_QUICFrame interface {
}

type quic_QUICFrameBuilder interface {
}

type quic_QUICFrameBuilder interface {
}

type quic_QUICFrameCrypto struct {
	Offset	*int
	Length	*int
}

type quic_QUICFrameCrypto struct {
	Offset	*int
	Length	*int
}

type quic_QUICFramePadding struct {
	Length *int
}

type quic_QUICFramePadding struct {
	Length *int
}

type quic_QUICFramePing struct {
}

type quic_QUICFramePing struct {
}

type quic_QUICFrames []*quic.QUICFrame

type quic_QUICFrames []*quic.QUICFrame

type quic_QUICID struct {
	Client		*string
	Version		*string
	Fingerprint	*string
}

type quic_QUICID struct {
	Client		*string
	Version		*string
	Fingerprint	*string
}

type quic_QUICRandomFrames struct {
	MinPING		*uint8
	MaxPING		*uint8
	MinCRYPTO	*uint8
	MaxCRYPTO	*uint8
	MinPADDING	*uint8
	MaxPADDING	*uint8
	Length		*uint16
}

type quic_QUICRandomFrames struct {
	MinPING		*uint8
	MaxPING		*uint8
	MinCRYPTO	*uint8
	MaxCRYPTO	*uint8
	MinPADDING	*uint8
	MaxPADDING	*uint8
	Length		*uint16
}

type quic_QUICSpec struct {
	InitialPacketSpec	*quic.InitialPacketSpec
	ClientHelloSpec		*tls.ClientHelloSpec
	UDPDatagramMinSize	*int
}

type quic_QUICSpec struct {
	InitialPacketSpec	*quic.InitialPacketSpec
	ClientHelloSpec		*tls.ClientHelloSpec
	UDPDatagramMinSize	*int
}

type quic_ReceiveStream struct {
	mutex			*sync.Mutex
	streamID		*protocol.StreamID
	sender			*interface{}
	frameQueue		*interface{}
	finalOffset		*protocol.ByteCount
	currentFrame		*[]uint8
	currentFrameDone	*func()
	readPosInFrame		*int
	currentFrameIsLast	*bool
	queuedStopSending	*bool
	queuedMaxStreamData	*bool
	errorRead		*bool
	completed		*bool
	cancelledRemotely	*bool
	cancelledLocally	*bool
	cancelErr		*quic.StreamError
	closeForShutdownErr	*error
	readPos			*protocol.ByteCount
	reliableSize		*protocol.ByteCount
	readChan		*chan struct {}
	readOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_ReceiveStream struct {
	mutex			*sync.Mutex
	streamID		*protocol.StreamID
	sender			*interface{}
	frameQueue		*interface{}
	finalOffset		*protocol.ByteCount
	currentFrame		*[]uint8
	currentFrameDone	*func()
	readPosInFrame		*int
	currentFrameIsLast	*bool
	queuedStopSending	*bool
	queuedMaxStreamData	*bool
	errorRead		*bool
	completed		*bool
	cancelledRemotely	*bool
	cancelledLocally	*bool
	cancelErr		*quic.StreamError
	closeForShutdownErr	*error
	readPos			*protocol.ByteCount
	reliableSize		*protocol.ByteCount
	readChan		*chan struct {}
	readOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_SendStream struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_SendStream struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_StatelessResetKey [32]*uint8

type quic_StatelessResetKey [32]*uint8

type quic_Stream struct {
	receiveStr		*quic.ReceiveStream
	sendStr			*quic.SendStream
	completedMutex		*sync.Mutex
	sender			*interface{}
	receiveStreamCompleted	*bool
	sendStreamCompleted	*bool
}

type quic_Stream struct {
	receiveStr		*quic.ReceiveStream
	sendStr			*quic.SendStream
	completedMutex		*sync.Mutex
	sender			*interface{}
	receiveStreamCompleted	*bool
	sendStreamCompleted	*bool
}

type quic_StreamError struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
	Remote		*bool
}

type quic_StreamError struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
	Remote		*bool
}

type quic_StreamLimitReachedError struct {
}

type quic_StreamLimitReachedError struct {
}

type quic_TokenStore interface {
}

type quic_TokenStore interface {
}

type quic_Transport struct {
	Conn					*net.PacketConn
	ConnectionIDLength			*int
	ConnectionIDGenerator			*quic.ConnectionIDGenerator
	StatelessResetKey			*quic.StatelessResetKey
	TokenGeneratorKey			*handshake.TokenProtectorKey
	MaxTokenAge				*time.Duration
	DisableVersionNegotiationPackets	*bool
	VerifySourceAddress			*func(net.Addr) bool
	ConnContext				*func(context.Context, *quic.ClientInfo) (context.Context, error)
	Tracer					*logging.Tracer
	mutex					*sync.Mutex
	handlers				*map[protocol.ConnectionID]quic.packetHandler
	resetTokens				*map[protocol.StatelessResetToken]quic.packetHandler
	initOnce				*sync.Once
	initErr					*error
	connIDLen				*int
	connIDGenerator				*quic.ConnectionIDGenerator
	statelessResetter			*interface{}
	server					*interface{}
	conn					*interface{}
	closeQueue				*chan quic.closePacket
	statelessResetQueue			*chan quic.receivedPacket
	listening				*chan struct {}
	closeErr				*error
	createdConn				*bool
	isSingleUse				*bool
	readingNonQUICPackets			*atomic.Bool
	nonQUICPackets				*chan quic.receivedPacket
	logger					*utils.Logger
}

type quic_Transport struct {
	Conn					*net.PacketConn
	ConnectionIDLength			*int
	ConnectionIDGenerator			*quic.ConnectionIDGenerator
	StatelessResetKey			*quic.StatelessResetKey
	TokenGeneratorKey			*handshake.TokenProtectorKey
	MaxTokenAge				*time.Duration
	DisableVersionNegotiationPackets	*bool
	VerifySourceAddress			*func(net.Addr) bool
	ConnContext				*func(context.Context, *quic.ClientInfo) (context.Context, error)
	Tracer					*logging.Tracer
	mutex					*sync.Mutex
	handlers				*map[protocol.ConnectionID]quic.packetHandler
	resetTokens				*map[protocol.StatelessResetToken]quic.packetHandler
	initOnce				*sync.Once
	initErr					*error
	connIDLen				*int
	connIDGenerator				*quic.ConnectionIDGenerator
	statelessResetter			*interface{}
	server					*interface{}
	conn					*interface{}
	closeQueue				*chan quic.closePacket
	statelessResetQueue			*chan quic.receivedPacket
	listening				*chan struct {}
	closeErr				*error
	createdConn				*bool
	isSingleUse				*bool
	readingNonQUICPackets			*atomic.Bool
	nonQUICPackets				*chan quic.receivedPacket
	logger					*utils.Logger
}

type quic_UTransport struct {
	Transport	*quic.Transport
	QUICSpec	*quic.QUICSpec
}

type quic_UTransport struct {
	Transport	*quic.Transport
	QUICSpec	*quic.QUICSpec
}

type quic_ackFrameSource interface {
}

type quic_ackFrameSource interface {
}

type quic_baseCryptoStream struct {
	queue		*interface{}
	highestOffset	*protocol.ByteCount
	finished	*bool
	writeOffset	*protocol.ByteCount
	writeBuf	*[]uint8
}

type quic_baseCryptoStream struct {
	queue		*interface{}
	highestOffset	*protocol.ByteCount
	finished	*bool
	writeOffset	*protocol.ByteCount
	writeBuf	*[]uint8
}

type quic_baseServer struct {
	tr				*interface{}
	disableVersionNegotiation	*bool
	acceptEarlyConns		*bool
	tlsConf				*tls.Config
	config				*quic.Config
	conn				*interface{}
	tokenGenerator			*handshake.TokenGenerator
	maxTokenAge			*time.Duration
	connIDGenerator			*quic.ConnectionIDGenerator
	statelessResetter		*interface{}
	onClose				*func()
	receivedPackets			*chan quic.receivedPacket
	nextZeroRTTCleanup		*time.Time
	zeroRTTQueues			*map[protocol.ConnectionID]*quic.zeroRTTQueue
	connContext			*func(context.Context, *quic.ClientInfo) (context.Context, error)
	newConn				*func(context.Context, context.CancelCauseFunc, quic.sendConn, quic.connRunner, protocol.ConnectionID, *protocol.ConnectionID, protocol.ConnectionID, protocol.ConnectionID, protocol.ConnectionID, quic.ConnectionIDGenerator, *quic.statelessResetter, *quic.Config, *tls.Config, *handshake.TokenGenerator, bool, time.Duration, *logging.ConnectionTracer, utils.Logger, protocol.Version) *quic.wrappedConn
	closeMx				*sync.Mutex
	errorChan			*chan struct {}
	stopAccepting			*chan struct {}
	closeErr			*error
	running				*chan struct {}
	versionNegotiationQueue		*chan quic.receivedPacket
	invalidTokenQueue		*chan quic.rejectedPacket
	connectionRefusedQueue		*chan quic.rejectedPacket
	retryQueue			*chan quic.rejectedPacket
	handshakingCount		*sync.WaitGroup
	verifySourceAddress		*func(net.Addr) bool
	connQueue			*chan *quic.Conn
	tracer				*logging.Tracer
	logger				*utils.Logger
}

type quic_baseServer struct {
	tr				*interface{}
	disableVersionNegotiation	*bool
	acceptEarlyConns		*bool
	tlsConf				*tls.Config
	config				*quic.Config
	conn				*interface{}
	tokenGenerator			*handshake.TokenGenerator
	maxTokenAge			*time.Duration
	connIDGenerator			*quic.ConnectionIDGenerator
	statelessResetter		*interface{}
	onClose				*func()
	receivedPackets			*chan quic.receivedPacket
	nextZeroRTTCleanup		*time.Time
	zeroRTTQueues			*map[protocol.ConnectionID]*quic.zeroRTTQueue
	connContext			*func(context.Context, *quic.ClientInfo) (context.Context, error)
	newConn				*func(context.Context, context.CancelCauseFunc, quic.sendConn, quic.connRunner, protocol.ConnectionID, *protocol.ConnectionID, protocol.ConnectionID, protocol.ConnectionID, protocol.ConnectionID, quic.ConnectionIDGenerator, *quic.statelessResetter, *quic.Config, *tls.Config, *handshake.TokenGenerator, bool, time.Duration, *logging.ConnectionTracer, utils.Logger, protocol.Version) *quic.wrappedConn
	closeMx				*sync.Mutex
	errorChan			*chan struct {}
	stopAccepting			*chan struct {}
	closeErr			*error
	running				*chan struct {}
	versionNegotiationQueue		*chan quic.receivedPacket
	invalidTokenQueue		*chan quic.rejectedPacket
	connectionRefusedQueue		*chan quic.rejectedPacket
	retryQueue			*chan quic.rejectedPacket
	handshakingCount		*sync.WaitGroup
	verifySourceAddress		*func(net.Addr) bool
	connQueue			*chan *quic.Conn
	tracer				*logging.Tracer
	logger				*utils.Logger
}

type quic_basicConn struct {
	PacketConn	*net.PacketConn
	supportsDF	*bool
}

type quic_basicConn struct {
	PacketConn	*net.PacketConn
	supportsDF	*bool
}

type quic_batchConn interface {
}

type quic_batchConn interface {
}

type quic_byteInterval struct {
	Start	*protocol.ByteCount
	End	*protocol.ByteCount
}

type quic_byteInterval struct {
	Start	*protocol.ByteCount
	End	*protocol.ByteCount
}

type quic_clientHelloCut struct {
	start	*protocol.ByteCount
	end	*protocol.ByteCount
}

type quic_clientHelloCut struct {
	start	*protocol.ByteCount
	end	*protocol.ByteCount
}

type quic_closeError struct {
	err		*error
	immediate	*bool
}

type quic_closeError struct {
	err		*error
	immediate	*bool
}

type quic_closePacket struct {
	payload	*[]uint8
	addr	*net.Addr
	info	*interface{}
}

type quic_closePacket struct {
	payload	*[]uint8
	addr	*net.Addr
	info	*interface{}
}

type quic_closedLocalConn struct {
	counter		*atomic.Uint32
	logger		*utils.Logger
	sendPacket	*func(net.Addr, quic.packetInfo)
}

type quic_closedLocalConn struct {
	counter		*atomic.Uint32
	logger		*utils.Logger
	sendPacket	*func(net.Addr, quic.packetInfo)
}

type quic_closedRemoteConn struct {
}

type quic_closedRemoteConn struct {
}

type quic_coalescedPacket struct {
	buffer		*interface{}
	longHdrPackets	*[]*quic.longHeaderPacket
	shortHdrPacket	*interface{}
}

type quic_coalescedPacket struct {
	buffer		*interface{}
	longHdrPackets	*[]*quic.longHeaderPacket
	shortHdrPacket	*interface{}
}

type quic_connCapabilities struct {
	DF	*bool
	GSO	*bool
	ECN	*bool
}

type quic_connCapabilities struct {
	DF	*bool
	GSO	*bool
	ECN	*bool
}

type quic_connIDGenerator struct {
	generator		*quic.ConnectionIDGenerator
	highestSeq		*uint64
	connRunners		*interface{}
	activeSrcConnIDs	*map[uint64]protocol.ConnectionID
	connIDsToRetire		*[]quic.connIDToRetire
	initialClientDestConnID	*protocol.ConnectionID
	statelessResetter	*interface{}
	queueControlFrame	*func(wire.Frame)
}

type quic_connIDGenerator struct {
	generator		*quic.ConnectionIDGenerator
	highestSeq		*uint64
	connRunners		*interface{}
	activeSrcConnIDs	*map[uint64]protocol.ConnectionID
	connIDsToRetire		*[]quic.connIDToRetire
	initialClientDestConnID	*protocol.ConnectionID
	statelessResetter	*interface{}
	queueControlFrame	*func(wire.Frame)
}

type quic_connIDManager struct {
	queue				*[]quic.newConnID
	highestProbingID		*uint64
	pathProbing			*map[quic.pathID]quic.newConnID
	handshakeComplete		*bool
	activeSequenceNumber		*uint64
	highestRetired			*uint64
	activeConnectionID		*protocol.ConnectionID
	activeStatelessResetToken	*protocol.StatelessResetToken
	rand				*utils.Rand
	packetsSinceLastChange		*uint32
	packetsPerConnectionID		*uint32
	addStatelessResetToken		*func(protocol.StatelessResetToken)
	removeStatelessResetToken	*func(protocol.StatelessResetToken)
	queueControlFrame		*func(wire.Frame)
	closed				*bool
	connectionIDLimit		*uint64
}

type quic_connIDManager struct {
	queue				*[]quic.newConnID
	highestProbingID		*uint64
	pathProbing			*map[quic.pathID]quic.newConnID
	handshakeComplete		*bool
	activeSequenceNumber		*uint64
	highestRetired			*uint64
	activeConnectionID		*protocol.ConnectionID
	activeStatelessResetToken	*protocol.StatelessResetToken
	rand				*utils.Rand
	packetsSinceLastChange		*uint32
	packetsPerConnectionID		*uint32
	addStatelessResetToken		*func(protocol.StatelessResetToken)
	removeStatelessResetToken	*func(protocol.StatelessResetToken)
	queueControlFrame		*func(wire.Frame)
	closed				*bool
	connectionIDLimit		*uint64
}

type quic_connIDToRetire struct {
	t	*time.Time
	connID	*protocol.ConnectionID
}

type quic_connIDToRetire struct {
	t	*time.Time
	connID	*protocol.ConnectionID
}

type quic_connRunner interface {
}

type quic_connRunner interface {
}

type quic_connRunnerCallbacks struct {
	AddConnectionID		*func(protocol.ConnectionID)
	RemoveConnectionID	*func(protocol.ConnectionID)
	ReplaceWithClosed	*func([]protocol.ConnectionID, []uint8, time.Duration)
}

type quic_connRunnerCallbacks struct {
	AddConnectionID		*func(protocol.ConnectionID)
	RemoveConnectionID	*func(protocol.ConnectionID)
	ReplaceWithClosed	*func([]protocol.ConnectionID, []uint8, time.Duration)
}

type quic_connRunners map[interface{}]*interface{}

type quic_connRunners map[interface{}]*interface{}

type quic_connTestHooks struct {
	run			*func() error
	earlyConnReady		*func() <-chan struct {}
	context			*func() context.Context
	handshakeComplete	*func() <-chan struct {}
	closeWithTransportError	*func(qerr.TransportErrorCode)
	destroy			*func(error)
	handlePacket		*func(quic.receivedPacket)
}

type quic_connTestHooks struct {
	run			*func() error
	earlyConnReady		*func() <-chan struct {}
	context			*func() context.Context
	handshakeComplete	*func() <-chan struct {}
	closeWithTransportError	*func(qerr.TransportErrorCode)
	destroy			*func(error)
	handlePacket		*func(quic.receivedPacket)
}

type quic_connTracingCtxKey struct {
}

type quic_connTracingCtxKey struct {
}

type quic_connectionTimer struct {
	timer	*utils.Timer
	last	*time.Time
}

type quic_connectionTimer struct {
	timer	*utils.Timer
	last	*time.Time
}

type quic_cryptoStream struct {
	baseCryptoStream *interface{}
}

type quic_cryptoStream struct {
	baseCryptoStream *interface{}
}

type quic_cryptoStreamHandler interface {
}

type quic_cryptoStreamHandler interface {
}

type quic_cryptoStreamManager struct {
	initialStream	*interface{}
	handshakeStream	*interface{}
	oneRTTStream	*interface{}
}

type quic_cryptoStreamManager struct {
	initialStream	*interface{}
	handshakeStream	*interface{}
	oneRTTStream	*interface{}
}

type quic_datagramQueue struct {
	sendMx		*sync.Mutex
	sendQueue	*wire.DatagramFrame
	sent		*chan struct {}
	rcvMx		*sync.Mutex
	rcvQueue	*[][]uint8
	rcvd		*chan struct {}
	closeErr	*error
	closed		*chan struct {}
	hasData		*func()
	logger		*utils.Logger
}

type quic_datagramQueue struct {
	sendMx		*sync.Mutex
	sendQueue	*wire.DatagramFrame
	sent		*chan struct {}
	rcvMx		*sync.Mutex
	rcvQueue	*[][]uint8
	rcvd		*chan struct {}
	closeErr	*error
	closed		*chan struct {}
	hasData		*func()
	logger		*utils.Logger
}

type quic_deadlineError struct {
}

type quic_deadlineError struct {
}

type quic_emptyHandler struct {
}

type quic_emptyHandler struct {
}

type quic_errCloseForRecreating struct {
	nextPacketNumber	*protocol.PacketNumber
	nextVersion		*protocol.Version
}

type quic_errCloseForRecreating struct {
	nextPacketNumber	*protocol.PacketNumber
	nextVersion		*protocol.Version
}

type quic_errServerClosed struct {
}

type quic_errServerClosed struct {
}

type quic_errTransportClosed struct {
	err *error
}

type quic_errTransportClosed struct {
	err *error
}

type quic_frameSorter struct {
	queue	*map[protocol.ByteCount]quic.frameSorterEntry
	readPos	*protocol.ByteCount
	gaps	*interface{}
}

type quic_frameSorter struct {
	queue	*map[protocol.ByteCount]quic.frameSorterEntry
	readPos	*protocol.ByteCount
	gaps	*interface{}
}

type quic_frameSorterEntry struct {
	Data	*[]uint8
	DoneCb	*func()
}

type quic_frameSorterEntry struct {
	Data	*[]uint8
	DoneCb	*func()
}

type quic_frameSource interface {
}

type quic_frameSource interface {
}

type quic_framer struct {
	mutex				*sync.Mutex
	activeStreams			*map[protocol.StreamID]quic.streamFrameGetter
	streamQueue			*protocol.StreamID
	streamsWithControlFrames	*map[protocol.StreamID]quic.streamControlFrameGetter
	controlFrameMutex		*sync.Mutex
	controlFrames			*[]wire.Frame
	pathResponses			*[]*wire.PathResponseFrame
	connFlowController		*flowcontrol.ConnectionFlowController
	queuedTooManyControlFrames	*bool
}

type quic_framer struct {
	mutex				*sync.Mutex
	activeStreams			*map[protocol.StreamID]quic.streamFrameGetter
	streamQueue			*protocol.StreamID
	streamsWithControlFrames	*map[protocol.StreamID]quic.streamControlFrameGetter
	controlFrameMutex		*sync.Mutex
	controlFrames			*[]wire.Frame
	pathResponses			*[]*wire.PathResponseFrame
	connFlowController		*flowcontrol.ConnectionFlowController
	queuedTooManyControlFrames	*bool
}

type quic_framesToRetransmit struct {
	crypto	*[]*wire.CryptoFrame
	other	*[]wire.Frame
}

type quic_framesToRetransmit struct {
	crypto	*[]*wire.CryptoFrame
	other	*[]wire.Frame
}

type quic_headerDecryptor interface {
}

type quic_headerDecryptor interface {
}

type quic_headerParseError struct {
	err *error
}

type quic_headerParseError struct {
	err *error
}

type quic_initialCryptoStream struct {
	baseCryptoStream	*interface{}
	scramble		*bool
	end			*protocol.ByteCount
	cuts			*[2]quic.clientHelloCut
}

type quic_initialCryptoStream struct {
	baseCryptoStream	*interface{}
	scramble		*bool
	end			*protocol.ByteCount
	cuts			*[2]quic.clientHelloCut
}

type quic_longHeaderPacket struct {
	header		*wire.ExtendedHeader
	ack		*wire.AckFrame
	frames		*[]ackhandler.Frame
	streamFrames	*[]ackhandler.StreamFrame
	length		*protocol.ByteCount
}

type quic_longHeaderPacket struct {
	header		*wire.ExtendedHeader
	ack		*wire.AckFrame
	frames		*[]ackhandler.Frame
	streamFrames	*[]ackhandler.StreamFrame
	length		*protocol.ByteCount
}

type quic_mtuDiscoverer interface {
}

type quic_mtuDiscoverer interface {
}

type quic_mtuFinder struct {
	lastProbeTime		*time.Time
	rttStats		*utils.RTTStats
	inFlight		*protocol.ByteCount
	min			*protocol.ByteCount
	lost			*[3]protocol.ByteCount
	lastProbeWasLost	*bool
	generation		*uint8
	tracer			*logging.ConnectionTracer
}

type quic_mtuFinder struct {
	lastProbeTime		*time.Time
	rttStats		*utils.RTTStats
	inFlight		*protocol.ByteCount
	min			*protocol.ByteCount
	lost			*[3]protocol.ByteCount
	lastProbeWasLost	*bool
	generation		*uint8
	tracer			*logging.ConnectionTracer
}

type quic_mtuFinderAckHandler struct {
	mtuFinder	*interface{}
	generation	*uint8
}

type quic_mtuFinderAckHandler struct {
	mtuFinder	*interface{}
	generation	*uint8
}

type quic_newConnID struct {
	SequenceNumber		*uint64
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type quic_newConnID struct {
	SequenceNumber		*uint64
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type quic_oobConn struct {
	OOBCapablePacketConn	*quic.OOBCapablePacketConn
	batchConn		*interface{}
	readPos			*uint8
	messages		*[]socket.Message
	buffers			*[8]*quic.packetBuffer
	cap			*interface{}
}

type quic_oobConn struct {
	OOBCapablePacketConn	*quic.OOBCapablePacketConn
	batchConn		*interface{}
	readPos			*uint8
	messages		*[]socket.Message
	buffers			*[8]*quic.packetBuffer
	cap			*interface{}
}

type quic_packer interface {
}

type quic_packer interface {
}

type quic_packetBuffer struct {
	Data		*[]uint8
	refCount	*int
}

type quic_packetBuffer struct {
	Data		*[]uint8
	refCount	*int
}

type quic_packetHandler interface {
}

type quic_packetHandler interface {
}

type quic_packetHandlerMap struct {
	Conn					*net.PacketConn
	ConnectionIDLength			*int
	ConnectionIDGenerator			*quic.ConnectionIDGenerator
	StatelessResetKey			*quic.StatelessResetKey
	TokenGeneratorKey			*handshake.TokenProtectorKey
	MaxTokenAge				*time.Duration
	DisableVersionNegotiationPackets	*bool
	VerifySourceAddress			*func(net.Addr) bool
	ConnContext				*func(context.Context, *quic.ClientInfo) (context.Context, error)
	Tracer					*logging.Tracer
	mutex					*sync.Mutex
	handlers				*map[protocol.ConnectionID]quic.packetHandler
	resetTokens				*map[protocol.StatelessResetToken]quic.packetHandler
	initOnce				*sync.Once
	initErr					*error
	connIDLen				*int
	connIDGenerator				*quic.ConnectionIDGenerator
	statelessResetter			*interface{}
	server					*interface{}
	conn					*interface{}
	closeQueue				*chan quic.closePacket
	statelessResetQueue			*chan quic.receivedPacket
	listening				*chan struct {}
	closeErr				*error
	createdConn				*bool
	isSingleUse				*bool
	readingNonQUICPackets			*atomic.Bool
	nonQUICPackets				*chan quic.receivedPacket
	logger					*utils.Logger
}

type quic_packetHandlerMap struct {
	Conn					*net.PacketConn
	ConnectionIDLength			*int
	ConnectionIDGenerator			*quic.ConnectionIDGenerator
	StatelessResetKey			*quic.StatelessResetKey
	TokenGeneratorKey			*handshake.TokenProtectorKey
	MaxTokenAge				*time.Duration
	DisableVersionNegotiationPackets	*bool
	VerifySourceAddress			*func(net.Addr) bool
	ConnContext				*func(context.Context, *quic.ClientInfo) (context.Context, error)
	Tracer					*logging.Tracer
	mutex					*sync.Mutex
	handlers				*map[protocol.ConnectionID]quic.packetHandler
	resetTokens				*map[protocol.StatelessResetToken]quic.packetHandler
	initOnce				*sync.Once
	initErr					*error
	connIDLen				*int
	connIDGenerator				*quic.ConnectionIDGenerator
	statelessResetter			*interface{}
	server					*interface{}
	conn					*interface{}
	closeQueue				*chan quic.closePacket
	statelessResetQueue			*chan quic.receivedPacket
	listening				*chan struct {}
	closeErr				*error
	createdConn				*bool
	isSingleUse				*bool
	readingNonQUICPackets			*atomic.Bool
	nonQUICPackets				*chan quic.receivedPacket
	logger					*utils.Logger
}

type quic_packetInfo struct {
	addr	*netip.Addr
	ifIndex	*uint32
}

type quic_packetInfo struct {
	addr	*netip.Addr
	ifIndex	*uint32
}

type quic_packetNumberManager interface {
}

type quic_packetNumberManager interface {
}

type quic_packetPacker struct {
	srcConnID		*protocol.ConnectionID
	getDestConnID		*func() protocol.ConnectionID
	perspective		*protocol.Perspective
	cryptoSetup		*interface{}
	initialStream		*interface{}
	handshakeStream		*interface{}
	token			*[]uint8
	pnManager		*interface{}
	framer			*interface{}
	acks			*interface{}
	datagramQueue		*interface{}
	retransmissionQueue	*interface{}
	rand			*rand.Rand
	numNonAckElicitingAcks	*int
}

type quic_packetPacker struct {
	srcConnID		*protocol.ConnectionID
	getDestConnID		*func() protocol.ConnectionID
	perspective		*protocol.Perspective
	cryptoSetup		*interface{}
	initialStream		*interface{}
	handshakeStream		*interface{}
	token			*[]uint8
	pnManager		*interface{}
	framer			*interface{}
	acks			*interface{}
	datagramQueue		*interface{}
	retransmissionQueue	*interface{}
	rand			*rand.Rand
	numNonAckElicitingAcks	*int
}

type quic_packetUnpacker struct {
	cs			*handshake.CryptoSetup
	shortHdrConnIDLen	*int
}

type quic_packetUnpacker struct {
	cs			*handshake.CryptoSetup
	shortHdrConnIDLen	*int
}

type quic_path struct {
	id		*interface{}
	addr		*net.Addr
	lastPacketTime	*time.Time
	pathChallenge	*[8]uint8
	validated	*bool
	rcvdNonProbing	*bool
}

type quic_path struct {
	id		*interface{}
	addr		*net.Addr
	lastPacketTime	*time.Time
	pathChallenge	*[8]uint8
	validated	*bool
	rcvdNonProbing	*bool
}

type quic_pathID int64

type quic_pathID int64

type quic_pathManager struct {
	nextPathID	*interface{}
	paths		*[]*quic.path
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	logger		*utils.Logger
}

type quic_pathManager struct {
	nextPathID	*interface{}
	paths		*[]*quic.path
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	logger		*utils.Logger
}

type quic_pathManagerAckHandler struct {
	nextPathID	*interface{}
	paths		*[]*quic.path
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	logger		*utils.Logger
}

type quic_pathManagerAckHandler struct {
	nextPathID	*interface{}
	paths		*[]*quic.path
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	logger		*utils.Logger
}

type quic_pathManagerOutgoing struct {
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	scheduleSending	*func()
	mx		*sync.Mutex
	activePath	*interface{}
	pathsToProbe	*[]quic.pathID
	paths		*map[quic.pathID]*quic.pathOutgoing
	nextPathID	*interface{}
	pathToSwitchTo	*interface{}
}

type quic_pathManagerOutgoing struct {
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	scheduleSending	*func()
	mx		*sync.Mutex
	activePath	*interface{}
	pathsToProbe	*[]quic.pathID
	paths		*map[quic.pathID]*quic.pathOutgoing
	nextPathID	*interface{}
	pathToSwitchTo	*interface{}
}

type quic_pathManagerOutgoingAckHandler struct {
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	scheduleSending	*func()
	mx		*sync.Mutex
	activePath	*interface{}
	pathsToProbe	*[]quic.pathID
	paths		*map[quic.pathID]*quic.pathOutgoing
	nextPathID	*interface{}
	pathToSwitchTo	*interface{}
}

type quic_pathManagerOutgoingAckHandler struct {
	getConnID	*func(quic.pathID) (protocol.ConnectionID, bool)
	retireConnID	*func(quic.pathID)
	scheduleSending	*func()
	mx		*sync.Mutex
	activePath	*interface{}
	pathsToProbe	*[]quic.pathID
	paths		*map[quic.pathID]*quic.pathOutgoing
	nextPathID	*interface{}
	pathToSwitchTo	*interface{}
}

type quic_pathOutgoing struct {
	pathChallenges	*[][8]uint8
	tr		*quic.Transport
	isValidated	*bool
	probeSent	*chan struct {}
	validated	*chan struct {}
	enablePath	*func()
}

type quic_pathOutgoing struct {
	pathChallenges	*[][8]uint8
	tr		*quic.Transport
	isValidated	*bool
	probeSent	*chan struct {}
	validated	*chan struct {}
	enablePath	*func()
}

type quic_queueEntry struct {
	buf	*interface{}
	gsoSize	*uint16
	ecn	*protocol.ECN
}

type quic_queueEntry struct {
	buf	*interface{}
	gsoSize	*uint16
	ecn	*protocol.ECN
}

type quic_rawConn interface {
}

type quic_rawConn interface {
}

type quic_receiveStreamFrameHandler interface {
}

type quic_receiveStreamFrameHandler interface {
}

type quic_receivedPacket struct {
	buffer		*interface{}
	remoteAddr	*net.Addr
	rcvTime		*time.Time
	data		*[]uint8
	ecn		*protocol.ECN
	info		*interface{}
}

type quic_receivedPacket struct {
	buffer		*interface{}
	remoteAddr	*net.Addr
	rcvTime		*time.Time
	data		*[]uint8
	ecn		*protocol.ECN
	info		*interface{}
}

type quic_rejectedPacket struct {
	receivedPacket	*interface{}
	hdr		*wire.Header
}

type quic_rejectedPacket struct {
	receivedPacket	*interface{}
	hdr		*wire.Header
}

type quic_remoteAddrInfo struct {
	addr	*net.Addr
	oob	*[]uint8
}

type quic_remoteAddrInfo struct {
	addr	*net.Addr
	oob	*[]uint8
}

type quic_retransmissionQueue struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueue struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueAppDataAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueAppDataAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueHandshakeAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueHandshakeAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueInitialAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_retransmissionQueueInitialAckHandler struct {
	initial		*interface{}
	handshake	*interface{}
	appData		*interface{}
}

type quic_sconn struct {
	rawConn			*interface{}
	localAddr		*net.Addr
	remoteAddrInfo		*interface{}
	logger			*utils.Logger
	gotGSOError		*bool
	wroteFirstPacket	*bool
}

type quic_sconn struct {
	rawConn			*interface{}
	localAddr		*net.Addr
	remoteAddrInfo		*interface{}
	logger			*utils.Logger
	gotGSOError		*bool
	wroteFirstPacket	*bool
}

type quic_sealer interface {
}

type quic_sealer interface {
}

type quic_sealingManager interface {
}

type quic_sealingManager interface {
}

type quic_sendConn interface {
}

type quic_sendConn interface {
}

type quic_sendQueue struct {
	queue		*chan quic.queueEntry
	closeCalled	*chan struct {}
	runStopped	*chan struct {}
	available	*chan struct {}
	conn		*interface{}
}

type quic_sendQueue struct {
	queue		*chan quic.queueEntry
	closeCalled	*chan struct {}
	runStopped	*chan struct {}
	available	*chan struct {}
	conn		*interface{}
}

type quic_sendStreamAckHandler struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_sendStreamAckHandler struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_sendStreamFrameHandler interface {
}

type quic_sendStreamFrameHandler interface {
}

type quic_sendStreamResetStreamHandler struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_sendStreamResetStreamHandler struct {
	mutex			*sync.Mutex
	numOutstandingFrames	*int64
	retransmissionQueue	*[]*wire.StreamFrame
	ctx			*context.Context
	ctxCancel		*context.CancelCauseFunc
	streamID		*protocol.StreamID
	sender			*interface{}
	reliableSize		*protocol.ByteCount
	writeOffset		*protocol.ByteCount
	shutdownErr		*error
	resetErr		*quic.StreamError
	queuedResetStreamFrame	*wire.ResetStreamFrame
	supportsResetStreamAt	*bool
	finishedWriting		*bool
	finSent			*bool
	cancellationFlagged	*bool
	completed		*bool
	dataForWriting		*[]uint8
	nextFrame		*wire.StreamFrame
	writeChan		*chan struct {}
	writeOnce		*chan struct {}
	deadline		*time.Time
	flowController		*flowcontrol.StreamFlowController
}

type quic_sender interface {
}

type quic_sender interface {
}

type quic_shortHeaderPacket struct {
	PacketNumber		*protocol.PacketNumber
	Frames			*[]ackhandler.Frame
	StreamFrames		*[]ackhandler.StreamFrame
	Ack			*wire.AckFrame
	Length			*protocol.ByteCount
	IsPathMTUProbePacket	*bool
	IsPathProbePacket	*bool
	DestConnID		*protocol.ConnectionID
	PacketNumberLen		*protocol.PacketNumberLen
	KeyPhase		*protocol.KeyPhaseBit
}

type quic_shortHeaderPacket struct {
	PacketNumber		*protocol.PacketNumber
	Frames			*[]ackhandler.Frame
	StreamFrames		*[]ackhandler.StreamFrame
	Ack			*wire.AckFrame
	Length			*protocol.ByteCount
	IsPathMTUProbePacket	*bool
	IsPathProbePacket	*bool
	DestConnID		*protocol.ConnectionID
	PacketNumberLen		*protocol.PacketNumberLen
	KeyPhase		*protocol.KeyPhaseBit
}

type quic_statelessResetter struct {
	mx	*sync.Mutex
	h	*hash.Hash
}

type quic_statelessResetter struct {
	mx	*sync.Mutex
	h	*hash.Hash
}

type quic_streamControlFrameGetter interface {
}

type quic_streamControlFrameGetter interface {
}

type quic_streamFrameGetter interface {
}

type quic_streamFrameGetter interface {
}

type quic_streamSender interface {
}

type quic_streamSender interface {
}

type quic_streamsMap struct {
	ctx			*context.Context
	perspective		*protocol.Perspective
	maxIncomingBidiStreams	*uint64
	maxIncomingUniStreams	*uint64
	sender			*interface{}
	queueControlFrame	*func(wire.Frame)
	newFlowController	*func(protocol.StreamID) flowcontrol.StreamFlowController
	mutex			*sync.Mutex
	outgoingBidiStreams	*uquic-go.Stream
	outgoingUniStreams	*uquic-go.SendStream
	incomingBidiStreams	*uquic-go.Stream
	incomingUniStreams	*uquic-go.ReceiveStream
	reset			*bool
	supportsResetStreamAt	*bool
}

type quic_streamsMap struct {
	ctx			*context.Context
	perspective		*protocol.Perspective
	maxIncomingBidiStreams	*uint64
	maxIncomingUniStreams	*uint64
	sender			*interface{}
	queueControlFrame	*func(wire.Frame)
	newFlowController	*func(protocol.StreamID) flowcontrol.StreamFlowController
	mutex			*sync.Mutex
	outgoingBidiStreams	*uquic-go.Stream
	outgoingUniStreams	*uquic-go.SendStream
	incomingBidiStreams	*uquic-go.Stream
	incomingUniStreams	*uquic-go.ReceiveStream
	reset			*bool
	supportsResetStreamAt	*bool
}

type quic_uPacketPacker struct {
	packetPacker	*interface{}
	uSpec		*quic.QUICSpec
}

type quic_uPacketPacker struct {
	packetPacker	*interface{}
	uSpec		*quic.QUICSpec
}

type quic_uniStreamSender struct {
	streamSender			*interface{}
	onStreamCompletedImpl		*func()
	onHasStreamControlFrameImpl	*func(protocol.StreamID, quic.streamControlFrameGetter)
}

type quic_uniStreamSender struct {
	streamSender			*interface{}
	onStreamCompletedImpl		*func()
	onHasStreamControlFrameImpl	*func(protocol.StreamID, quic.streamControlFrameGetter)
}

type quic_unpackedPacket struct {
	hdr		*wire.ExtendedHeader
	encryptionLevel	*protocol.EncryptionLevel
	data		*[]uint8
}

type quic_unpackedPacket struct {
	hdr		*wire.ExtendedHeader
	encryptionLevel	*protocol.EncryptionLevel
	data		*[]uint8
}

type quic_unpacker interface {
}

type quic_unpacker interface {
}

type quic_wrappedConn struct {
	testHooks	*interface{}
	Conn		*quic.Conn
}

type quic_wrappedConn struct {
	testHooks	*interface{}
	Conn		*quic.Conn
}

type quic_zeroRTTQueue struct {
	packets		*[]quic.receivedPacket
	expiration	*time.Time
}

type quic_zeroRTTQueue struct {
	packets		*[]quic.receivedPacket
	expiration	*time.Time
}

type quicvarint_Reader interface {
}

type quicvarint_Reader interface {
}

type quicvarint_byteReader struct {
	Reader *io.Reader
}

type quicvarint_byteReader struct {
	Reader *io.Reader
}

type rand_PCG struct {
	hi	*uint64
	lo	*uint64
}

type rand_PCG struct {
	hi	*uint64
	lo	*uint64
}

type rand_Rand struct {
	src *rand.Source
}

type rand_Rand struct {
	src *rand.Source
}

type rand_Rand struct {
	src	*rand.Source
	s64	*rand.Source64
	readVal	*int64
	readPos	*int8
}

type rand_Rand struct {
	src	*rand.Source
	s64	*rand.Source64
	readVal	*int64
	readPos	*int8
}

type rand_Source interface {
}

type rand_Source interface {
}

type rand_Source interface {
}

type rand_Source interface {
}

type rand_Source64 interface {
}

type rand_Source64 interface {
}

type rand_lockedSource struct {
	lk	*sync.Mutex
	s	*interface{}
}

type rand_lockedSource struct {
	lk	*sync.Mutex
	s	*interface{}
}

type rand_reader struct {
	DefaultReader *drbg.DefaultReader
}

type rand_reader struct {
	DefaultReader *drbg.DefaultReader
}

type rand_rngSource struct {
	tap	*int
	feed	*int
	vec	*[607]int64
}

type rand_rngSource struct {
	tap	*int
	feed	*int
	vec	*[607]int64
}

type rand_runtimeSource struct {
	mu *sync.Mutex
}

type rand_runtimeSource struct {
	mu *sync.Mutex
}

type rand_runtimeSource struct {
}

type rand_runtimeSource struct {
}

type rc4_Cipher struct {
	s	*[256]uint32
	i	*uint8
	j	*uint8
}

type rc4_Cipher struct {
	s	*[256]uint32
	i	*uint8
	j	*uint8
}

type rc4_KeySizeError int

type rc4_KeySizeError int

type reflectlite_Type interface {
}

type reflectlite_Type interface {
}

type reflectlite_ValueError struct {
	Method	*string
	Kind	*abi.Kind
}

type reflectlite_ValueError struct {
	Method	*string
	Kind	*abi.Kind
}

type reflectlite_rtype struct {
	Type *abi.Type
}

type reflectlite_rtype struct {
	Type *abi.Type
}

type rsa_CRTValue struct {
	Exp	*big.Int
	Coeff	*big.Int
	R	*big.Int
}

type rsa_CRTValue struct {
	Exp	*big.Int
	Coeff	*big.Int
	R	*big.Int
}

type rsa_PSSOptions struct {
	SaltLength	*int
	Hash		*crypto.Hash
}

type rsa_PSSOptions struct {
	SaltLength	*int
	Hash		*crypto.Hash
}

type rsa_PrecomputedValues struct {
	Dp		*big.Int
	Dq		*big.Int
	Qinv		*big.Int
	CRTValues	*[]rsa.CRTValue
	fips		*rsa.PrivateKey
}

type rsa_PrecomputedValues struct {
	Dp		*big.Int
	Dq		*big.Int
	Qinv		*big.Int
	CRTValues	*[]rsa.CRTValue
	fips		*rsa.PrivateKey
}

type rsa_PrivateKey struct {
	pub		*rsa.PublicKey
	d		*bigmod.Nat
	p		*bigmod.Modulus
	q		*bigmod.Modulus
	dP		*[]uint8
	dQ		*[]uint8
	qInv		*bigmod.Nat
	fipsApproved	*bool
}

type rsa_PrivateKey struct {
	pub		*rsa.PublicKey
	d		*bigmod.Nat
	p		*bigmod.Modulus
	q		*bigmod.Modulus
	dP		*[]uint8
	dQ		*[]uint8
	qInv		*bigmod.Nat
	fipsApproved	*bool
}

type rsa_PrivateKey struct {
	PublicKey	*rsa.PublicKey
	D		*big.Int
	Primes		*[]*big.Int
	Precomputed	*rsa.PrecomputedValues
}

type rsa_PrivateKey struct {
	PublicKey	*rsa.PublicKey
	D		*big.Int
	Primes		*[]*big.Int
	Precomputed	*rsa.PrecomputedValues
}

type rsa_PublicKey struct {
	N	*bigmod.Modulus
	E	*int
}

type rsa_PublicKey struct {
	N	*bigmod.Modulus
	E	*int
}

type rsa_PublicKey struct {
	N	*big.Int
	E	*int
}

type rsa_PublicKey struct {
	N	*big.Int
	E	*int
}

type serrors_Comparer interface {
}

type serrors_Comparer interface {
}

type serrors_String string

type serrors_String string

type serrors_Wrapped interface {
}

type serrors_Wrapped interface {
}

type serrors_sentinelError struct {
	eString	*serrors.String
	args	*[]interface {}
}

type serrors_sentinelError struct {
	eString	*serrors.String
	args	*[]interface {}
}

type serrors_wrapped struct {
	error		*error
	cause		*error
	stackFunc	*func() string
}

type serrors_wrapped struct {
	error		*error
	cause		*error
	stackFunc	*func() string
}

type sha1_digest struct {
	h	*[5]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
}

type sha1_digest struct {
	h	*[5]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
}

type sha256_Digest struct {
	h	*[8]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
	is224	*bool
}

type sha256_Digest struct {
	h	*[8]uint32
	x	*[64]uint8
	nx	*int
	len	*uint64
	is224	*bool
}

type sha3_Digest struct {
	a		*[200]uint8
	n		*int
	rate		*int
	dsbyte		*uint8
	outputLen	*int
	state		*interface{}
}

type sha3_Digest struct {
	a		*[200]uint8
	n		*int
	rate		*int
	dsbyte		*uint8
	outputLen	*int
	state		*interface{}
}

type sha3_SHA3 struct {
	s *sha3.Digest
}

type sha3_SHA3 struct {
	s *sha3.Digest
}

type sha3_SHAKE struct {
	d		*sha3.Digest
	initBlock	*[]uint8
}

type sha3_SHAKE struct {
	s *sha3.SHAKE
}

type sha3_SHAKE struct {
	s *sha3.SHAKE
}

type sha3_SHAKE struct {
	d		*sha3.Digest
	initBlock	*[]uint8
}

type sha3_ShakeHash interface {
}

type sha3_ShakeHash interface {
}

type sha3_State struct {
	a		*[25]uint64
	rate		*int
	bufo		*int
	bufe		*int
	dsbyte		*uint8
	storage		*interface{}
	outputLen	*int
	state		*interface{}
	turbo		*bool
}

type sha3_State struct {
	a		*[25]uint64
	rate		*int
	bufo		*int
	bufe		*int
	dsbyte		*uint8
	storage		*interface{}
	outputLen	*int
	state		*interface{}
	turbo		*bool
}

type sha3_shakeWrapper struct {
	SHAKE		*sha3.SHAKE
	outputLen	*int
	squeezing	*bool
	newSHAKE	*func() *sha3.SHAKE
}

type sha3_shakeWrapper struct {
	SHAKE		*sha3.SHAKE
	outputLen	*int
	squeezing	*bool
	newSHAKE	*func() *sha3.SHAKE
}

type sha3_spongeDirection int

type sha3_spongeDirection int

type sha3_spongeDirection int

type sha3_spongeDirection int

type sha3_storageBuf [168]*uint8

type sha3_storageBuf [168]*uint8

type sha512_Digest struct {
	h	*[8]uint64
	x	*[128]uint8
	nx	*int
	len	*uint64
	size	*int
}

type sha512_Digest struct {
	h	*[8]uint64
	x	*[128]uint8
	nx	*int
	len	*uint64
	size	*int
}

type sign_PrivateKey interface {
}

type sign_PrivateKey interface {
}

type sign_PublicKey interface {
}

type sign_PublicKey interface {
}

type sign_Scheme interface {
}

type sign_Scheme interface {
}

type sign_SignatureOpts struct {
	Context *string
}

type sign_SignatureOpts struct {
	Context *string
}

type singleflight_Group struct {
	mu	*sync.Mutex
	m	*map[string]*singleflight.call
}

type singleflight_Group struct {
	mu	*sync.Mutex
	m	*map[string]*singleflight.call
}

type singleflight_Result struct {
	Val	*interface {}
	Err	*error
	Shared	*bool
}

type singleflight_Result struct {
	Val	*interface {}
	Err	*error
	Shared	*bool
}

type singleflight_call struct {
	wg	*sync.WaitGroup
	val	*interface {}
	err	*error
	dups	*int
	chans	*[]chan<- singleflight.Result
}

type singleflight_call struct {
	wg	*sync.WaitGroup
	val	*interface {}
	err	*error
	dups	*int
	chans	*[]chan<- singleflight.Result
}

type slog_Attr struct {
	Key	*string
	Value	*slog.Value
}

type slog_Attr struct {
	Key	*string
	Value	*slog.Value
}

type slog_Handler interface {
}

type slog_Handler interface {
}

type slog_HandlerOptions struct {
	AddSource	*bool
	Level		*slog.Leveler
	ReplaceAttr	*func([]string, slog.Attr) slog.Attr
}

type slog_HandlerOptions struct {
	AddSource	*bool
	Level		*slog.Leveler
	ReplaceAttr	*func([]string, slog.Attr) slog.Attr
}

type slog_Kind int

type slog_Kind int

type slog_Level int

type slog_Level int

type slog_Leveler interface {
}

type slog_Leveler interface {
}

type slog_LogValuer interface {
}

type slog_LogValuer interface {
}

type slog_Logger struct {
	handler *slog.Handler
}

type slog_Logger struct {
	handler *slog.Handler
}

type slog_Record struct {
	Time	*time.Time
	Message	*string
	Level	*slog.Level
	PC	*uintptr
	front	*[5]slog.Attr
	nFront	*int
	back	*[]slog.Attr
}

type slog_Record struct {
	Time	*time.Time
	Message	*string
	Level	*slog.Level
	PC	*uintptr
	front	*[5]slog.Attr
	nFront	*int
	back	*[]slog.Attr
}

type slog_Source struct {
	Function	*string
	File		*string
	Line		*int
}

type slog_Source struct {
	Function	*string
	File		*string
	Line		*int
}

type slog_Value struct {
	_	*[0]func()
	num	*uint64
	any	*interface {}
}

type slog_Value struct {
	_	*[0]func()
	num	*uint64
	any	*interface {}
}

type slog_commonHandler struct {
	json			*bool
	opts			*slog.HandlerOptions
	preformattedAttrs	*[]uint8
	groupPrefix		*string
	groups			*[]string
	nOpenGroups		*int
	mu			*sync.Mutex
	w			*io.Writer
}

type slog_commonHandler struct {
	json			*bool
	opts			*slog.HandlerOptions
	preformattedAttrs	*[]uint8
	groupPrefix		*string
	groups			*[]string
	nOpenGroups		*int
	mu			*sync.Mutex
	w			*io.Writer
}

type slog_defaultHandler struct {
	ch	*interface{}
	output	*func(uintptr, []uint8) error
}

type slog_defaultHandler struct {
	ch	*interface{}
	output	*func(uintptr, []uint8) error
}

type slog_kind int

type slog_kind int

type slog_timeTime struct {
	wall	*uint64
	ext	*int64
	loc	*time.Location
}

type slog_timeTime struct {
	wall	*uint64
	ext	*int64
	loc	*time.Location
}

type socket_Conn struct {
	network	*string
	c	*syscall.RawConn
}

type socket_Conn struct {
	network	*string
	c	*syscall.RawConn
}

type socket_Message struct {
	Buffers	*[][]uint8
	OOB	*[]uint8
	Addr	*net.Addr
	N	*int
	NN	*int
	Flags	*int
}

type socket_Message struct {
	Buffers	*[][]uint8
	OOB	*[]uint8
	Addr	*net.Addr
	N	*int
	NN	*int
	Flags	*int
}

type socket_iovec struct {
	Base	*uint8
	Len	*uint32
}

type socket_iovec struct {
	Base	*uint8
	Len	*uint32
}

type socket_ipConn interface {
}

type socket_ipConn interface {
}

type socket_mmsgTmps struct {
	packer		*interface{}
	syscaller	*interface{}
}

type socket_mmsgTmps struct {
	packer		*interface{}
	syscaller	*interface{}
}

type socket_mmsghdr struct {
	Hdr	*interface{}
	Len	*uint32
}

type socket_mmsghdr struct {
	Hdr	*interface{}
	Len	*uint32
}

type socket_mmsghdrs []*interface{}

type socket_mmsghdrs []*interface{}

type socket_mmsghdrsPacker struct {
	hs		*interface{}
	sockaddrs	*[]uint8
	vs		*[]socket.iovec
}

type socket_mmsghdrsPacker struct {
	hs		*interface{}
	sockaddrs	*[]uint8
	vs		*[]socket.iovec
}

type socket_msghdr struct {
	Name		*uint8
	Namelen		*uint32
	Iov		*interface{}
	Iovlen		*uint32
	Control		*uint8
	Controllen	*uint32
	Flags		*int32
}

type socket_msghdr struct {
	Name		*uint8
	Namelen		*uint32
	Iov		*interface{}
	Iovlen		*uint32
	Control		*uint8
	Controllen	*uint32
	Flags		*int32
}

type socket_syscaller struct {
	n		*int
	operr		*error
	hs		*interface{}
	flags		*int
	boundRecvmmsgF	*func(uintptr) bool
	boundSendmmsgF	*func(uintptr) bool
}

type socket_syscaller struct {
	n		*int
	operr		*error
	hs		*interface{}
	flags		*int
	boundRecvmmsgF	*func(uintptr) bool
	boundSendmmsgF	*func(uintptr) bool
}

type socket_tcpConn interface {
}

type socket_tcpConn interface {
}

type socket_udpConn interface {
}

type socket_udpConn interface {
}

type socks_Addr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type socks_Addr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type socks_AuthMethod int

type socks_AuthMethod int

type socks_Command int

type socks_Command int

type socks_Conn struct {
	Conn		*net.Conn
	boundAddr	*net.Addr
}

type socks_Conn struct {
	Conn		*net.Conn
	boundAddr	*net.Addr
}

type socks_Dialer struct {
	cmd		*socks.Command
	proxyNetwork	*string
	proxyAddress	*string
	ProxyDial	*func(context.Context, string, string) (net.Conn, error)
	AuthMethods	*[]socks.AuthMethod
	Authenticate	*func(context.Context, io.ReadWriter, socks.AuthMethod) error
}

type socks_Dialer struct {
	cmd		*socks.Command
	proxyNetwork	*string
	proxyAddress	*string
	ProxyDial	*func(context.Context, string, string) (net.Conn, error)
	AuthMethods	*[]socks.AuthMethod
	Authenticate	*func(context.Context, io.ReadWriter, socks.AuthMethod) error
}

type socks_UsernamePassword struct {
	Username	*string
	Password	*string
}

type socks_UsernamePassword struct {
	Username	*string
	Password	*string
}

type socks4_request struct {
	Host	*string
	Port	*int
	IP	*net.IP
	Is4a	*bool
	err	*error
	buf	*bytes.Buffer
}

type socks4_request struct {
	Host	*string
	Port	*int
	IP	*net.IP
	Is4a	*bool
	err	*error
	buf	*bytes.Buffer
}

type socks4_socks4 struct {
	url	*url.URL
	dialer	*proxy.Dialer
}

type socks4_socks4 struct {
	url	*url.URL
	dialer	*proxy.Dialer
}

type syntax_EmptyOp uint8

type syntax_EmptyOp uint8

type syntax_Error struct {
	Code	*syntax.ErrorCode
	Expr	*string
}

type syntax_Error struct {
	Code	*syntax.ErrorCode
	Expr	*string
}

type syntax_ErrorCode string

type syntax_ErrorCode string

type syntax_Flags uint16

type syntax_Flags uint16

type syntax_Inst struct {
	Op	*syntax.InstOp
	Out	*uint32
	Arg	*uint32
	Rune	*[]int32
}

type syntax_Inst struct {
	Op	*syntax.InstOp
	Out	*uint32
	Arg	*uint32
	Rune	*[]int32
}

type syntax_InstOp uint8

type syntax_InstOp uint8

type syntax_Op uint8

type syntax_Op uint8

type syntax_Prog struct {
	Inst	*[]syntax.Inst
	Start	*int
	NumCap	*int
}

type syntax_Prog struct {
	Inst	*[]syntax.Inst
	Start	*int
	NumCap	*int
}

type syntax_Regexp struct {
	Op	*syntax.Op
	Flags	*syntax.Flags
	Sub	*[]*syntax.Regexp
	Sub0	*[1]*syntax.Regexp
	Rune	*[]int32
	Rune0	*[2]int32
	Min	*int
	Max	*int
	Cap	*int
	Name	*string
}

type syntax_Regexp struct {
	Op	*syntax.Op
	Flags	*syntax.Flags
	Sub	*[]*syntax.Regexp
	Sub0	*[1]*syntax.Regexp
	Rune	*[]int32
	Rune0	*[2]int32
	Min	*int
	Max	*int
	Cap	*int
	Name	*string
}

type syntax_charGroup struct {
	sign	*int
	class	*[]int32
}

type syntax_charGroup struct {
	sign	*int
	class	*[]int32
}

type syntax_parser struct {
	flags		*syntax.Flags
	stack		*[]*syntax.Regexp
	free		*syntax.Regexp
	numCap		*int
	wholeRegexp	*string
	tmpClass	*[]int32
	numRegexp	*int
	numRunes	*int
	repeats		*int64
	height		*map[*syntax.Regexp]int
	size		*map[*syntax.Regexp]int64
}

type syntax_parser struct {
	flags		*syntax.Flags
	stack		*[]*syntax.Regexp
	free		*syntax.Regexp
	numCap		*int
	wholeRegexp	*string
	tmpClass	*[]int32
	numRegexp	*int
	numRunes	*int
	repeats		*int64
	height		*map[*syntax.Regexp]int
	size		*map[*syntax.Regexp]int64
}

type syntax_ranges struct {
	p *[]int32
}

type syntax_ranges struct {
	p *[]int32
}

type sys_NotInHeap struct {
	_ *interface{}
}

type sys_NotInHeap struct {
	_ *interface{}
}

type sys_nih struct {
}

type sys_nih struct {
}

type textproto_MIMEHeader map[interface{}]*string

type textproto_MIMEHeader map[interface{}]*string

type textproto_ProtocolError string

type textproto_ProtocolError string

type internal_FlushAfterChunkWriter struct {
	Writer *bufio.Writer
}

type internal_FlushAfterChunkWriter struct {
	Writer *bufio.Writer
}

type internal_FlushAfterChunkWriter struct {
	Writer *bufio.Writer
}

type internal_FlushAfterChunkWriter struct {
	Writer *bufio.Writer
}

type internal_Mat [3]*internal.Vec

type internal_Mat [8]*internal.VecL

type internal_Mat [4]*internal.VecL

type internal_Mat [4]*internal.VecL

type internal_Mat [8]*internal.VecL

type internal_Mat [3]*internal.Vec

type internal_Mat [4]*internal.VecL

type internal_Mat [6]*internal.VecL

type internal_Mat [6]*internal.VecL

type internal_Mat [6]*internal.VecL

type internal_Mat [4]*internal.VecL

type internal_Mat [6]*internal.VecL

type internal_Mat [8]*internal.VecL

type internal_Mat [8]*internal.VecL

type internal_PrivateKey struct {
	sh *internal.Vec
}

type internal_PrivateKey struct {
	sh *internal.Vec
}

type internal_PublicKey struct {
	rho	*[32]uint8
	th	*internal.Vec
	aT	*internal.Mat
}

type internal_PublicKey struct {
	rho	*[32]uint8
	th	*internal.Vec
	aT	*internal.Mat
}

type internal_Vec [3]*common.Poly

type internal_Vec [3]*common.Poly

type internal_VecK [8]*dilithium.Poly

type internal_VecK [4]*dilithium.Poly

type internal_VecK [6]*dilithium.Poly

type internal_VecK [4]*dilithium.Poly

type internal_VecK [4]*dilithium.Poly

type internal_VecK [4]*dilithium.Poly

type internal_VecK [6]*dilithium.Poly

type internal_VecK [6]*dilithium.Poly

type internal_VecK [8]*dilithium.Poly

type internal_VecK [8]*dilithium.Poly

type internal_VecK [6]*dilithium.Poly

type internal_VecK [8]*dilithium.Poly

type internal_VecL [5]*dilithium.Poly

type internal_VecL [5]*dilithium.Poly

type internal_VecL [4]*dilithium.Poly

type internal_VecL [4]*dilithium.Poly

type internal_VecL [5]*dilithium.Poly

type internal_VecL [7]*dilithium.Poly

type internal_VecL [7]*dilithium.Poly

type internal_VecL [7]*dilithium.Poly

type internal_VecL [4]*dilithium.Poly

type internal_VecL [5]*dilithium.Poly

type internal_VecL [4]*dilithium.Poly

type internal_VecL [7]*dilithium.Poly

type internal_chunkedReader struct {
	r		*bufio.Reader
	n		*uint64
	err		*error
	buf		*[2]uint8
	checkEnd	*bool
	excess		*int64
}

type internal_chunkedReader struct {
	r		*bufio.Reader
	n		*uint64
	err		*error
	buf		*[2]uint8
	checkEnd	*bool
	excess		*int64
}

type internal_chunkedReader struct {
	r		*bufio.Reader
	n		*uint64
	err		*error
	buf		*[2]uint8
	checkEnd	*bool
}

type internal_chunkedReader struct {
	r		*bufio.Reader
	n		*uint64
	err		*error
	buf		*[2]uint8
	checkEnd	*bool
}

type internal_chunkedWriter struct {
	Wire *io.Writer
}

type internal_chunkedWriter struct {
	Wire *io.Writer
}

type internal_chunkedWriter struct {
	Wire *io.Writer
}

type internal_chunkedWriter struct {
	Wire *io.Writer
}

type client_Client struct {
	conn		*net.Conn
	registry	*handlers.Registry
}

type client_Client struct {
	conn		*net.Conn
	registry	*handlers.Registry
}

type flooders_SillyPacket struct {
	TaskID		*uint32
	ID		*uint32
	Duration	*uint32
	Threads		*uint32
	Targets		*[]string
	Options		*map[uint32][]uint8
}

type flooders_SillyPacket struct {
	TaskID		*uint32
	ID		*uint32
	Duration	*uint32
	Threads		*uint32
	Targets		*[]string
	Options		*map[uint32][]uint8
}

type http_Client struct {
	Transport	*http.RoundTripper
	CheckRedirect	*func(*http.Request, []*http.Request) error
	Jar		*http.CookieJar
	Timeout		*time.Duration
}

type http_Client struct {
	Transport	*http.RoundTripper
	CheckRedirect	*func(*http.Request, []*http.Request) error
	Jar		*http.CookieJar
	Timeout		*time.Duration
}

type http_ConnState int

type http_ConnState int

type http_ConnState int

type http_ConnState int

type http_ConnState int

type http_ConnState int

type http_Cookie struct {
	Name		*string
	Value		*string
	Quoted		*bool
	Path		*string
	Domain		*string
	Expires		*time.Time
	RawExpires	*string
	MaxAge		*int
	Secure		*bool
	HttpOnly	*bool
	SameSite	*http.SameSite
	Partitioned	*bool
	Raw		*string
	Unparsed	*[]string
}

type http_Cookie struct {
	Name		*string
	Value		*string
	Quoted		*bool
	Path		*string
	Domain		*string
	Expires		*time.Time
	RawExpires	*string
	MaxAge		*int
	Secure		*bool
	HttpOnly	*bool
	SameSite	*http.SameSite
	Partitioned	*bool
	Raw		*string
	Unparsed	*[]string
}

type http_Cookie struct {
	Name		*string
	Value		*string
	Path		*string
	Domain		*string
	Expires		*time.Time
	RawExpires	*string
	MaxAge		*int
	Secure		*bool
	HttpOnly	*bool
	SameSite	*http.SameSite
	Raw		*string
	Unparsed	*[]string
}

type http_Cookie struct {
	Name		*string
	Value		*string
	Path		*string
	Domain		*string
	Expires		*time.Time
	RawExpires	*string
	MaxAge		*int
	Secure		*bool
	HttpOnly	*bool
	SameSite	*http.SameSite
	Raw		*string
	Unparsed	*[]string
}

type http_CookieJar interface {
}

type http_CookieJar interface {
}

type http_CookieJar interface {
}

type http_CookieJar interface {
}

type http_HTTP2Config struct {
	MaxConcurrentStreams		*int
	MaxDecoderHeaderTableSize	*int
	MaxEncoderHeaderTableSize	*int
	MaxReadFrameSize		*int
	MaxReceiveBufferPerConnection	*int
	MaxReceiveBufferPerStream	*int
	SendPingTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	PermitProhibitedCipherSuites	*bool
	CountError			*func(string)
}

type http_HTTP2Config struct {
	MaxConcurrentStreams		*int
	MaxDecoderHeaderTableSize	*int
	MaxEncoderHeaderTableSize	*int
	MaxReadFrameSize		*int
	MaxReceiveBufferPerConnection	*int
	MaxReceiveBufferPerStream	*int
	SendPingTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	PermitProhibitedCipherSuites	*bool
	CountError			*func(string)
}

type http_Header map[interface{}]*string

type http_Header map[interface{}]*string

type http_Header map[interface{}]*string

type http_Header map[interface{}]*string

type http_Header map[interface{}]*string

type http_Header map[interface{}]*string

type http_HeaderKeyValues struct {
	Key	*string
	Values	*[]string
}

type http_HeaderKeyValues struct {
	Key	*string
	Values	*[]string
}

type http_Protocols struct {
	bits *uint8
}

type http_Protocols struct {
	bits *uint8
}

type http_Request struct {
	Method			*string
	URL			*url.URL
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	SensitiveHeaders	*[]string
	Body			*io.ReadCloser
	GetBody			*func() (io.ReadCloser, error)
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Host			*string
	Form			*url.Values
	PostForm		*url.Values
	MultipartForm		*multipart.Form
	Trailer			*http.Header
	RemoteAddr		*string
	RequestURI		*string
	TLS			*tls.ConnectionState
	TLSConn			*net.Conn
	Cancel			*<-chan struct {}
	Response		*http.Response
	ctx			*context.Context
}

type http_Request struct {
	Method			*string
	URL			*url.URL
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	SensitiveHeaders	*[]string
	Body			*io.ReadCloser
	GetBody			*func() (io.ReadCloser, error)
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Host			*string
	Form			*url.Values
	PostForm		*url.Values
	MultipartForm		*multipart.Form
	Trailer			*http.Header
	RemoteAddr		*string
	RequestURI		*string
	TLS			*tls.ConnectionState
	TLSConn			*net.Conn
	Cancel			*<-chan struct {}
	Response		*http.Response
	ctx			*context.Context
}

type http_Request struct {
	Method			*string
	URL			*url.URL
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	GetBody			*func() (io.ReadCloser, error)
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Host			*string
	Form			*url.Values
	PostForm		*url.Values
	MultipartForm		*multipart.Form
	Trailer			*http.Header
	RemoteAddr		*string
	RequestURI		*string
	TLS			*tls.ConnectionState
	Cancel			*<-chan struct {}
	Response		*http.Response
	Pattern			*string
	ctx			*context.Context
	pat			*interface{}
	matches			*[]string
	otherValues		*map[string]string
}

type http_Request struct {
	Method			*string
	URL			*url.URL
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	GetBody			*func() (io.ReadCloser, error)
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Host			*string
	Form			*url.Values
	PostForm		*url.Values
	MultipartForm		*multipart.Form
	Trailer			*http.Header
	RemoteAddr		*string
	RequestURI		*string
	TLS			*tls.ConnectionState
	Cancel			*<-chan struct {}
	Response		*http.Response
	Pattern			*string
	ctx			*context.Context
	pat			*interface{}
	matches			*[]string
	otherValues		*map[string]string
}

type http_Response struct {
	Status			*string
	StatusCode		*int
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Uncompressed		*bool
	Trailer			*http.Header
	Request			*http.Request
	TLS			*tls.ConnectionState
}

type http_Response struct {
	Status			*string
	StatusCode		*int
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Uncompressed		*bool
	Trailer			*http.Header
	Request			*http.Request
	TLS			*tls.ConnectionState
}

type http_Response struct {
	Status			*string
	StatusCode		*int
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Uncompressed		*bool
	Trailer			*http.Header
	Request			*http.Request
	TLS			*tls.ConnectionState
}

type http_Response struct {
	Status			*string
	StatusCode		*int
	Proto			*string
	ProtoMajor		*int
	ProtoMinor		*int
	Header			*http.Header
	Body			*io.ReadCloser
	ContentLength		*int64
	TransferEncoding	*[]string
	Close			*bool
	Uncompressed		*bool
	Trailer			*http.Header
	Request			*http.Request
	TLS			*tls.ConnectionState
}

type http_RoundTripper interface {
}

type http_RoundTripper interface {
}

type http_RoundTripper interface {
}

type http_RoundTripper interface {
}

type http_SameSite int

type http_SameSite int

type http_SameSite int

type http_SameSite int

type http_Transport struct {
	idleMu			*sync.Mutex
	closeIdle		*bool
	idleConn		*map[http.connectMethodKey][]*http.persistConn
	idleConnWait		*map[http.connectMethodKey]http.wantConnQueue
	idleLRU			*interface{}
	reqMu			*sync.Mutex
	reqCanceler		*map[*http.Request]context.CancelCauseFunc
	altMu			*sync.Mutex
	altProto		*atomic.Value
	connsPerHostMu		*sync.Mutex
	connsPerHost		*map[http.connectMethodKey]int
	connsPerHostWait	*map[http.connectMethodKey]http.wantConnQueue
	dialsInProgress		*interface{}
	Proxy			*func(*http.Request) (*url.URL, error)
	OnProxyConnectResponse	*func(context.Context, *url.URL, *http.Request, *http.Response) error
	DialContext		*func(context.Context, string, string) (net.Conn, error)
	Dial			*func(string, string) (net.Conn, error)
	DialTLSContext		*func(context.Context, string, string) (net.Conn, error)
	DialTLS			*func(string, string) (net.Conn, error)
	TLSClientConfig		*tls.Config
	TLSHandshakeTimeout	*time.Duration
	DisableKeepAlives	*bool
	DisableCompression	*bool
	MaxIdleConns		*int
	MaxIdleConnsPerHost	*int
	MaxConnsPerHost		*int
	IdleConnTimeout		*time.Duration
	ResponseHeaderTimeout	*time.Duration
	ExpectContinueTimeout	*time.Duration
	TLSNextProto		*map[string]func(string, *tls.Conn) http.RoundTripper
	ProxyConnectHeader	*http.Header
	GetProxyConnectHeader	*func(context.Context, *url.URL, string) (http.Header, error)
	MaxResponseHeaderBytes	*int64
	WriteBufferSize		*int
	ReadBufferSize		*int
	nextProtoOnce		*sync.Once
	h2transport		*interface{}
	tlsNextProtoWasNil	*bool
	ForceAttemptHTTP2	*bool
	HTTP2			*http.HTTP2Config
	Protocols		*http.Protocols
}

type http_Transport struct {
	idleMu			*sync.Mutex
	closeIdle		*bool
	idleConn		*map[http.connectMethodKey][]*http.persistConn
	idleConnWait		*map[http.connectMethodKey]http.wantConnQueue
	idleLRU			*interface{}
	reqMu			*sync.Mutex
	reqCanceler		*map[http.cancelKey]func(error)
	altMu			*sync.Mutex
	altProto		*atomic.Value
	connsPerHostMu		*sync.Mutex
	connsPerHost		*map[http.connectMethodKey]int
	connsPerHostWait	*map[http.connectMethodKey]http.wantConnQueue
	Proxy			*func(*http.Request) (*url.URL, error)
	DialContext		*func(context.Context, string, string) (net.Conn, error)
	Dial			*func(string, string) (net.Conn, error)
	DialTLSContext		*func(context.Context, string, string) (net.Conn, error)
	DialTLS			*func(string, string) (net.Conn, error)
	TLSClientConfig		*tls.Config
	TLSHandshakeTimeout	*time.Duration
	DisableKeepAlives	*bool
	DisableCompression	*bool
	MaxIdleConns		*int
	MaxIdleConnsPerHost	*int
	MaxConnsPerHost		*int
	IdleConnTimeout		*time.Duration
	ResponseHeaderTimeout	*time.Duration
	ExpectContinueTimeout	*time.Duration
	TLSNextProto		*map[string]func(string, *tls.Conn) http.RoundTripper
	ProxyConnectHeader	*http.Header
	GetProxyConnectHeader	*func(context.Context, *url.URL, string) (http.Header, error)
	MaxResponseHeaderBytes	*int64
	WriteBufferSize		*int
	ReadBufferSize		*int
	nextProtoOnce		*sync.Once
	H2transport		*interface{}
	tlsNextProtoWasNil	*bool
	PseudoHeaderOrder	*[]string
	ConnectionFlow		*uint32
	ForceAttemptHTTP2	*bool
}

type http_Transport struct {
	idleMu			*sync.Mutex
	closeIdle		*bool
	idleConn		*map[http.connectMethodKey][]*http.persistConn
	idleConnWait		*map[http.connectMethodKey]http.wantConnQueue
	idleLRU			*interface{}
	reqMu			*sync.Mutex
	reqCanceler		*map[http.cancelKey]func(error)
	altMu			*sync.Mutex
	altProto		*atomic.Value
	connsPerHostMu		*sync.Mutex
	connsPerHost		*map[http.connectMethodKey]int
	connsPerHostWait	*map[http.connectMethodKey]http.wantConnQueue
	Proxy			*func(*http.Request) (*url.URL, error)
	DialContext		*func(context.Context, string, string) (net.Conn, error)
	Dial			*func(string, string) (net.Conn, error)
	DialTLSContext		*func(context.Context, string, string) (net.Conn, error)
	DialTLS			*func(string, string) (net.Conn, error)
	TLSClientConfig		*tls.Config
	TLSHandshakeTimeout	*time.Duration
	DisableKeepAlives	*bool
	DisableCompression	*bool
	MaxIdleConns		*int
	MaxIdleConnsPerHost	*int
	MaxConnsPerHost		*int
	IdleConnTimeout		*time.Duration
	ResponseHeaderTimeout	*time.Duration
	ExpectContinueTimeout	*time.Duration
	TLSNextProto		*map[string]func(string, *tls.Conn) http.RoundTripper
	ProxyConnectHeader	*http.Header
	GetProxyConnectHeader	*func(context.Context, *url.URL, string) (http.Header, error)
	MaxResponseHeaderBytes	*int64
	WriteBufferSize		*int
	ReadBufferSize		*int
	nextProtoOnce		*sync.Once
	H2transport		*interface{}
	tlsNextProtoWasNil	*bool
	PseudoHeaderOrder	*[]string
	ConnectionFlow		*uint32
	ForceAttemptHTTP2	*bool
}

type http_Transport struct {
	idleMu			*sync.Mutex
	closeIdle		*bool
	idleConn		*map[http.connectMethodKey][]*http.persistConn
	idleConnWait		*map[http.connectMethodKey]http.wantConnQueue
	idleLRU			*interface{}
	reqMu			*sync.Mutex
	reqCanceler		*map[*http.Request]context.CancelCauseFunc
	altMu			*sync.Mutex
	altProto		*atomic.Value
	connsPerHostMu		*sync.Mutex
	connsPerHost		*map[http.connectMethodKey]int
	connsPerHostWait	*map[http.connectMethodKey]http.wantConnQueue
	dialsInProgress		*interface{}
	Proxy			*func(*http.Request) (*url.URL, error)
	OnProxyConnectResponse	*func(context.Context, *url.URL, *http.Request, *http.Response) error
	DialContext		*func(context.Context, string, string) (net.Conn, error)
	Dial			*func(string, string) (net.Conn, error)
	DialTLSContext		*func(context.Context, string, string) (net.Conn, error)
	DialTLS			*func(string, string) (net.Conn, error)
	TLSClientConfig		*tls.Config
	TLSHandshakeTimeout	*time.Duration
	DisableKeepAlives	*bool
	DisableCompression	*bool
	MaxIdleConns		*int
	MaxIdleConnsPerHost	*int
	MaxConnsPerHost		*int
	IdleConnTimeout		*time.Duration
	ResponseHeaderTimeout	*time.Duration
	ExpectContinueTimeout	*time.Duration
	TLSNextProto		*map[string]func(string, *tls.Conn) http.RoundTripper
	ProxyConnectHeader	*http.Header
	GetProxyConnectHeader	*func(context.Context, *url.URL, string) (http.Header, error)
	MaxResponseHeaderBytes	*int64
	WriteBufferSize		*int
	ReadBufferSize		*int
	nextProtoOnce		*sync.Once
	h2transport		*interface{}
	tlsNextProtoWasNil	*bool
	ForceAttemptHTTP2	*bool
	HTTP2			*http.HTTP2Config
	Protocols		*http.Protocols
}

type http_body struct {
	src		*io.Reader
	hdr		*interface {}
	r		*bufio.Reader
	closing		*bool
	doEarlyClose	*bool
	mu		*sync.Mutex
	sawEOF		*bool
	closed		*bool
	earlyClose	*bool
	onHitEOF	*func()
}

type http_body struct {
	src		*io.Reader
	hdr		*interface {}
	r		*bufio.Reader
	closing		*bool
	doEarlyClose	*bool
	mu		*sync.Mutex
	sawEOF		*bool
	closed		*bool
	earlyClose	*bool
	onHitEOF	*func()
}

type http_body struct {
	src		*io.Reader
	hdr		*interface {}
	r		*bufio.Reader
	closing		*bool
	doEarlyClose	*bool
	mu		*sync.Mutex
	sawEOF		*bool
	closed		*bool
	earlyClose	*bool
	onHitEOF	*func()
}

type http_body struct {
	src		*io.Reader
	hdr		*interface {}
	r		*bufio.Reader
	closing		*bool
	doEarlyClose	*bool
	mu		*sync.Mutex
	sawEOF		*bool
	closed		*bool
	earlyClose	*bool
	onHitEOF	*func()
}

type http_bodyEOFSignal struct {
	body		*io.ReadCloser
	mu		*sync.Mutex
	closed		*bool
	rerr		*error
	fn		*func(error) error
	earlyCloseFn	*func() error
}

type http_bodyEOFSignal struct {
	body		*io.ReadCloser
	mu		*sync.Mutex
	closed		*bool
	rerr		*error
	fn		*func(error) error
	earlyCloseFn	*func() error
}

type http_bodyEOFSignal struct {
	body		*io.ReadCloser
	mu		*sync.Mutex
	closed		*bool
	rerr		*error
	fn		*func(error) error
	earlyCloseFn	*func() error
}

type http_bodyEOFSignal struct {
	body		*io.ReadCloser
	mu		*sync.Mutex
	closed		*bool
	rerr		*error
	fn		*func(error) error
	earlyCloseFn	*func() error
}

type http_bodyLocked struct {
	b *interface{}
}

type http_bodyLocked struct {
	b *interface{}
}

type http_bodyLocked struct {
	b *interface{}
}

type http_bodyLocked struct {
	b *interface{}
}

type http_brReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*brotli.Reader
	zerr	*error
}

type http_brReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*brotli.Reader
	zerr	*error
}

type http_bufioFlushWriter struct {
	w *io.Writer
}

type http_bufioFlushWriter struct {
	w *io.Writer
}

type http_bufioFlushWriter struct {
	w *io.Writer
}

type http_bufioFlushWriter struct {
	w *io.Writer
}

type http_byteReader struct {
	b	*uint8
	done	*bool
}

type http_byteReader struct {
	b	*uint8
	done	*bool
}

type http_byteReader struct {
	b	*uint8
	done	*bool
}

type http_byteReader struct {
	b	*uint8
	done	*bool
}

type http_cancelKey struct {
	req *http.Request
}

type http_cancelKey struct {
	req *http.Request
}

type http_cancelTimerBody struct {
	stop		*func()
	rc		*io.ReadCloser
	reqDidTimeout	*func() bool
}

type http_cancelTimerBody struct {
	stop		*func()
	rc		*io.ReadCloser
	reqDidTimeout	*func() bool
}

type http_canceler interface {
}

type http_canceler interface {
}

type http_connLRU struct {
	ll	*list.List
	m	*map[*http.persistConn]*list.Element
}

type http_connLRU struct {
	ll	*list.List
	m	*map[*http.persistConn]*list.Element
}

type http_connLRU struct {
	ll	*list.List
	m	*map[*http.persistConn]*list.Element
}

type http_connLRU struct {
	ll	*list.List
	m	*map[*http.persistConn]*list.Element
}

type http_connOrError struct {
	pc	*interface{}
	err	*error
	idleAt	*time.Time
}

type http_connOrError struct {
	pc	*interface{}
	err	*error
	idleAt	*time.Time
}

type http_connectMethod struct {
	_		*interface{}
	proxyURL	*url.URL
	targetScheme	*string
	targetAddr	*string
	onlyH1		*bool
}

type http_connectMethod struct {
	_		*interface{}
	proxyURL	*url.URL
	targetScheme	*string
	targetAddr	*string
	onlyH1		*bool
}

type http_connectMethod struct {
	_		*interface{}
	proxyURL	*url.URL
	targetScheme	*string
	targetAddr	*string
	onlyH1		*bool
}

type http_connectMethod struct {
	_		*interface{}
	proxyURL	*url.URL
	targetScheme	*string
	targetAddr	*string
	onlyH1		*bool
}

type http_connectMethodKey struct {
	proxy	*string
	scheme	*string
	addr	*string
	onlyH1	*bool
}

type http_connectMethodKey struct {
	proxy	*string
	scheme	*string
	addr	*string
	onlyH1	*bool
}

type http_connectMethodKey struct {
	proxy	*string
	scheme	*string
	addr	*string
	onlyH1	*bool
}

type http_connectMethodKey struct {
	proxy	*string
	scheme	*string
	addr	*string
	onlyH1	*bool
}

type http_deflateReader struct {
	_	*interface{}
	body	*io.ReadCloser
	r	*io.ReadCloser
	err	*error
}

type http_deflateReader struct {
	_	*interface{}
	body	*io.ReadCloser
	r	*io.ReadCloser
	err	*error
}

type http_erringRoundTripper interface {
}

type http_erringRoundTripper interface {
}

type http_erringRoundTripper interface {
}

type http_erringRoundTripper interface {
}

type http_errorReader struct {
	err *error
}

type http_errorReader struct {
	err *error
}

type http_errorReader struct {
	err *error
}

type http_errorReader struct {
	err *error
}

type http_fakeLocker struct {
}

type http_fakeLocker struct {
}

type http_fakeLocker struct {
}

type http_fakeLocker struct {
}

type http_finishAsyncByteRead struct {
	tw *interface{}
}

type http_finishAsyncByteRead struct {
	tw *interface{}
}

type http_finishAsyncByteRead struct {
	tw *interface{}
}

type http_finishAsyncByteRead struct {
	tw *interface{}
}

type http_gzipReader struct {
	_	*interface{}
	body	*interface{}
	zr	*gzip.Reader
	zerr	*error
}

type http_gzipReader struct {
	_	*interface{}
	body	*interface{}
	zr	*gzip.Reader
	zerr	*error
}

type http_gzipReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http_gzipReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http_h2Transport interface {
}

type http_h2Transport interface {
}

type http_h2Transport interface {
}

type http_h2Transport interface {
}

type http_headerSorter struct {
	kvs *[]http.keyValues
}

type http_headerSorter struct {
	kvs	*[]http.HeaderKeyValues
	order	*map[string]int
}

type http_headerSorter struct {
	kvs	*[]http.HeaderKeyValues
	order	*map[string]int
}

type http_headerSorter struct {
	kvs *[]http.keyValues
}

type http_http2ClientConn struct {
	br			*bufio.Reader
	bw			*bufio.Writer
	closed			*bool
	closing			*bool
	cond			*sync.Cond
	dialedAddr		*string
	flow			*interface{}
	fr			*interface{}
	freeBuf			*[][]uint8
	goAway			*interface{}
	goAwayDebug		*string
	hbuf			*bytes.Buffer
	henc			*hpack.Encoder
	highestPromiseID	*uint32
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
	inflow			*interface{}
	initialWindowSize	*uint32
	lastActive		*time.Time
	lastIdle		*time.Time
	maxConcurrentStreams	*uint32
	maxFrameSize		*uint32
	mu			*sync.Mutex
	nextStreamID		*uint32
	peerMaxHeaderListSize	*uint64
	pendingRequests		*int
	pings			*map[[8]uint8]chan struct {}
	readerDone		*chan struct {}
	readerErr		*error
	reused			*uint32
	singleUse		*bool
	streams			*map[uint32]*http.http2clientStream
	t			*interface{}
	tconn			*net.Conn
	tlsState		*tls.ConnectionState
	wantSettingsAck		*bool
	werr			*error
	wmu			*sync.Mutex
}

type http_http2ClientConn struct {
	t				*interface{}
	tconn				*net.Conn
	tlsState			*tls.ConnectionState
	atomicReused			*uint32
	singleUse			*bool
	getConnCalled			*bool
	readerDone			*chan struct {}
	readerErr			*error
	idleTimeout			*time.Duration
	idleTimer			*interface { C <-chan time.Time; Resettime.Duration) bool; Stop() bool }
	mu				*sync.Mutex
	cond				*sync.Cond
	flow				*interface{}
	inflow				*interface{}
	doNotReuse			*bool
	closing				*bool
	closed				*bool
	closedOnIdle			*bool
	seenSettings			*bool
	seenSettingsChan		*chan struct {}
	wantSettingsAck			*bool
	goAway				*interface{}
	goAwayDebug			*string
	streams				*map[uint32]*http.http2clientStream
	streamsReserved			*int
	nextStreamID			*uint32
	pendingRequests			*int
	pings				*map[[8]uint8]chan struct {}
	br				*bufio.Reader
	lastActive			*time.Time
	lastIdle			*time.Time
	maxFrameSize			*uint32
	maxConcurrentStreams		*uint32
	peerMaxHeaderListSize		*uint64
	peerMaxHeaderTableSize		*uint32
	initialWindowSize		*uint32
	initialStreamRecvWindowSize	*int32
	readIdleTimeout			*time.Duration
	pingTimeout			*time.Duration
	extendedConnectAllowed		*bool
	rstStreamPingsBlocked		*bool
	pendingResets			*int
	reqHeaderMu			*chan struct {}
	wmu				*sync.Mutex
	bw				*bufio.Writer
	fr				*interface{}
	werr				*error
	hbuf				*bytes.Buffer
	henc				*hpack.Encoder
}

type http_http2ClientConn struct {
	br			*bufio.Reader
	bw			*bufio.Writer
	closed			*bool
	closing			*bool
	cond			*sync.Cond
	dialedAddr		*string
	flow			*interface{}
	fr			*interface{}
	freeBuf			*[][]uint8
	goAway			*interface{}
	goAwayDebug		*string
	hbuf			*bytes.Buffer
	henc			*hpack.Encoder
	highestPromiseID	*uint32
	idleTimeout		*time.Duration
	idleTimer		*time.Timer
	inflow			*interface{}
	initialWindowSize	*uint32
	lastActive		*time.Time
	lastIdle		*time.Time
	maxConcurrentStreams	*uint32
	maxFrameSize		*uint32
	mu			*sync.Mutex
	nextStreamID		*uint32
	peerMaxHeaderListSize	*uint64
	pendingRequests		*int
	pings			*map[[8]uint8]chan struct {}
	readerDone		*chan struct {}
	readerErr		*error
	reused			*uint32
	singleUse		*bool
	streams			*map[uint32]*http.http2clientStream
	t			*interface{}
	tconn			*net.Conn
	tlsState		*tls.ConnectionState
	wantSettingsAck		*bool
	werr			*error
	wmu			*sync.Mutex
}

type http_http2ClientConn struct {
	t				*interface{}
	tconn				*net.Conn
	tlsState			*tls.ConnectionState
	atomicReused			*uint32
	singleUse			*bool
	getConnCalled			*bool
	readerDone			*chan struct {}
	readerErr			*error
	idleTimeout			*time.Duration
	idleTimer			*interface { C <-chan time.Time; Resettime.Duration) bool; Stop() bool }
	mu				*sync.Mutex
	cond				*sync.Cond
	flow				*interface{}
	inflow				*interface{}
	doNotReuse			*bool
	closing				*bool
	closed				*bool
	closedOnIdle			*bool
	seenSettings			*bool
	seenSettingsChan		*chan struct {}
	wantSettingsAck			*bool
	goAway				*interface{}
	goAwayDebug			*string
	streams				*map[uint32]*http.http2clientStream
	streamsReserved			*int
	nextStreamID			*uint32
	pendingRequests			*int
	pings				*map[[8]uint8]chan struct {}
	br				*bufio.Reader
	lastActive			*time.Time
	lastIdle			*time.Time
	maxFrameSize			*uint32
	maxConcurrentStreams		*uint32
	peerMaxHeaderListSize		*uint64
	peerMaxHeaderTableSize		*uint32
	initialWindowSize		*uint32
	initialStreamRecvWindowSize	*int32
	readIdleTimeout			*time.Duration
	pingTimeout			*time.Duration
	extendedConnectAllowed		*bool
	rstStreamPingsBlocked		*bool
	pendingResets			*int
	reqHeaderMu			*chan struct {}
	wmu				*sync.Mutex
	bw				*bufio.Writer
	fr				*interface{}
	werr				*error
	hbuf				*bytes.Buffer
	henc				*hpack.Encoder
}

type http_http2ClientConnPool interface {
}

type http_http2ClientConnPool interface {
}

type http_http2ClientConnPool interface {
}

type http_http2ClientConnPool interface {
}

type http_http2ConnectionError uint32

type http_http2ConnectionError uint32

type http_http2ConnectionError uint32

type http_http2ConnectionError uint32

type http_http2ContinuationFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
}

type http_http2ContinuationFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
}

type http_http2ContinuationFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
}

type http_http2ContinuationFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
}

type http_http2DataFrame struct {
	http2FrameHeader	*interface{}
	data			*[]uint8
}

type http_http2DataFrame struct {
	http2FrameHeader	*interface{}
	data			*[]uint8
}

type http_http2DataFrame struct {
	http2FrameHeader	*interface{}
	data			*[]uint8
}

type http_http2DataFrame struct {
	http2FrameHeader	*interface{}
	data			*[]uint8
}

type http_http2ErrCode uint32

type http_http2ErrCode uint32

type http_http2ErrCode uint32

type http_http2ErrCode uint32

type http_http2Flags uint8

type http_http2Flags uint8

type http_http2Flags uint8

type http_http2Flags uint8

type http_http2Frame interface {
}

type http_http2Frame interface {
}

type http_http2Frame interface {
}

type http_http2Frame interface {
}

type http_http2FrameHeader struct {
	valid		*bool
	Type		*interface{}
	Flags		*interface{}
	Length		*uint32
	StreamID	*uint32
}

type http_http2FrameHeader struct {
	Flags		*interface{}
	Length		*uint32
	StreamID	*uint32
	Type		*interface{}
	valid		*bool
}

type http_http2FrameHeader struct {
	valid		*bool
	Type		*interface{}
	Flags		*interface{}
	Length		*uint32
	StreamID	*uint32
}

type http_http2FrameHeader struct {
	Flags		*interface{}
	Length		*uint32
	StreamID	*uint32
	Type		*interface{}
	valid		*bool
}

type http_http2FrameType uint8

type http_http2FrameType uint8

type http_http2FrameType uint8

type http_http2FrameType uint8

type http_http2Framer struct {
	r			*io.Reader
	lastFrame		*interface{}
	errDetail		*error
	countError		*func(string)
	lastHeaderStream	*uint32
	maxReadSize		*uint32
	headerBuf		*[9]uint8
	getReadBuf		*func(uint32) []uint8
	readBuf			*[]uint8
	maxWriteSize		*uint32
	w			*io.Writer
	wbuf			*[]uint8
	AllowIllegalWrites	*bool
	AllowIllegalReads	*bool
	ReadMetaHeaders		*hpack.Decoder
	MaxHeaderListSize	*uint32
	logReads		*bool
	logWrites		*bool
	debugFramer		*interface{}
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	frameCache		*interface{}
}

type http_http2Framer struct {
	AllowIllegalReads	*bool
	AllowIllegalWrites	*bool
	debugFramer		*interface{}
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	errDetail		*error
	frameCache		*interface{}
	getReadBuf		*func(uint32) []uint8
	headerBuf		*[9]uint8
	lastFrame		*interface{}
	lastHeaderStream	*uint32
	logReads		*bool
	logWrites		*bool
	MaxHeaderListSize	*uint32
	maxReadSize		*uint32
	maxWriteSize		*uint32
	r			*io.Reader
	readBuf			*[]uint8
	ReadMetaHeaders		*hpack.Decoder
	w			*io.Writer
	wbuf			*[]uint8
}

type http_http2Framer struct {
	r			*io.Reader
	lastFrame		*interface{}
	errDetail		*error
	countError		*func(string)
	lastHeaderStream	*uint32
	maxReadSize		*uint32
	headerBuf		*[9]uint8
	getReadBuf		*func(uint32) []uint8
	readBuf			*[]uint8
	maxWriteSize		*uint32
	w			*io.Writer
	wbuf			*[]uint8
	AllowIllegalWrites	*bool
	AllowIllegalReads	*bool
	ReadMetaHeaders		*hpack.Decoder
	MaxHeaderListSize	*uint32
	logReads		*bool
	logWrites		*bool
	debugFramer		*interface{}
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	frameCache		*interface{}
}

type http_http2Framer struct {
	AllowIllegalReads	*bool
	AllowIllegalWrites	*bool
	debugFramer		*interface{}
	debugFramerBuf		*bytes.Buffer
	debugReadLoggerf	*func(string, ...interface {})
	debugWriteLoggerf	*func(string, ...interface {})
	errDetail		*error
	frameCache		*interface{}
	getReadBuf		*func(uint32) []uint8
	headerBuf		*[9]uint8
	lastFrame		*interface{}
	lastHeaderStream	*uint32
	logReads		*bool
	logWrites		*bool
	MaxHeaderListSize	*uint32
	maxReadSize		*uint32
	maxWriteSize		*uint32
	r			*io.Reader
	readBuf			*[]uint8
	ReadMetaHeaders		*hpack.Decoder
	w			*io.Writer
	wbuf			*[]uint8
}

type http_http2GoAwayError struct {
	LastStreamID	*uint32
	ErrCode		*interface{}
	DebugData	*string
}

type http_http2GoAwayError struct {
	DebugData	*string
	ErrCode		*interface{}
	LastStreamID	*uint32
}

type http_http2GoAwayError struct {
	LastStreamID	*uint32
	ErrCode		*interface{}
	DebugData	*string
}

type http_http2GoAwayError struct {
	DebugData	*string
	ErrCode		*interface{}
	LastStreamID	*uint32
}

type http_http2GoAwayFrame struct {
	http2FrameHeader	*interface{}
	LastStreamID		*uint32
	ErrCode			*interface{}
	debugData		*[]uint8
}

type http_http2GoAwayFrame struct {
	http2FrameHeader	*interface{}
	LastStreamID		*uint32
	ErrCode			*interface{}
	debugData		*[]uint8
}

type http_http2GoAwayFrame struct {
	http2FrameHeader	*interface{}
	debugData		*[]uint8
	ErrCode			*interface{}
	LastStreamID		*uint32
}

type http_http2GoAwayFrame struct {
	http2FrameHeader	*interface{}
	debugData		*[]uint8
	ErrCode			*interface{}
	LastStreamID		*uint32
}

type http_http2HeadersFrame struct {
	http2FrameHeader	*interface{}
	Priority		*interface{}
	headerFragBuf		*[]uint8
}

type http_http2HeadersFrame struct {
	http2FrameHeader	*interface{}
	Priority		*interface{}
	headerFragBuf		*[]uint8
}

type http_http2HeadersFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
	Priority		*interface{}
}

type http_http2HeadersFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
	Priority		*interface{}
}

type http_http2MetaHeadersFrame struct {
	http2HeadersFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2MetaHeadersFrame struct {
	http2HeadersFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2MetaHeadersFrame struct {
	http2HeadersFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2MetaHeadersFrame struct {
	http2HeadersFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2MetaPushPromiseFrame struct {
	http2PushPromiseFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2MetaPushPromiseFrame struct {
	http2PushPromiseFrame	*interface{}
	Fields			*[]hpack.HeaderField
	Truncated		*bool
}

type http_http2PingFrame struct {
	http2FrameHeader	*interface{}
	Data			*[8]uint8
}

type http_http2PingFrame struct {
	http2FrameHeader	*interface{}
	Data			*[8]uint8
}

type http_http2PingFrame struct {
	http2FrameHeader	*interface{}
	Data			*[8]uint8
}

type http_http2PingFrame struct {
	http2FrameHeader	*interface{}
	Data			*[8]uint8
}

type http_http2PriorityFrame struct {
	http2FrameHeader	*interface{}
	http2PriorityParam	*interface{}
}

type http_http2PriorityFrame struct {
	http2FrameHeader	*interface{}
	http2PriorityParam	*interface{}
}

type http_http2PriorityFrame struct {
	http2FrameHeader	*interface{}
	http2PriorityParam	*interface{}
}

type http_http2PriorityFrame struct {
	http2FrameHeader	*interface{}
	http2PriorityParam	*interface{}
}

type http_http2PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http_http2PriorityParam struct {
	Exclusive	*bool
	StreamDep	*uint32
	Weight		*uint8
}

type http_http2PriorityParam struct {
	Exclusive	*bool
	StreamDep	*uint32
	Weight		*uint8
}

type http_http2PriorityParam struct {
	StreamDep	*uint32
	Exclusive	*bool
	Weight		*uint8
}

type http_http2PushHandler interface {
}

type http_http2PushHandler interface {
}

type http_http2PushPromiseFrame struct {
	http2FrameHeader	*interface{}
	PromiseID		*uint32
	headerFragBuf		*[]uint8
}

type http_http2PushPromiseFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
	PromiseID		*uint32
}

type http_http2PushPromiseFrame struct {
	http2FrameHeader	*interface{}
	headerFragBuf		*[]uint8
	PromiseID		*uint32
}

type http_http2PushPromiseFrame struct {
	http2FrameHeader	*interface{}
	PromiseID		*uint32
	headerFragBuf		*[]uint8
}

type http_http2PushedRequest struct {
	OriginalRequestHeader	*http.Header
	OriginalRequestURL	*url.URL
	Promise			*http.Request
	pushedStream		*interface{}
}

type http_http2PushedRequest struct {
	OriginalRequestHeader	*http.Header
	OriginalRequestURL	*url.URL
	Promise			*http.Request
	pushedStream		*interface{}
}

type http_http2RSTStreamFrame struct {
	http2FrameHeader	*interface{}
	ErrCode			*interface{}
}

type http_http2RSTStreamFrame struct {
	http2FrameHeader	*interface{}
	ErrCode			*interface{}
}

type http_http2RSTStreamFrame struct {
	http2FrameHeader	*interface{}
	ErrCode			*interface{}
}

type http_http2RSTStreamFrame struct {
	http2FrameHeader	*interface{}
	ErrCode			*interface{}
}

type http_http2Setting struct {
	ID	*interface{}
	Val	*uint32
}

type http_http2Setting struct {
	ID	*interface{}
	Val	*uint32
}

type http_http2Setting struct {
	ID	*interface{}
	Val	*uint32
}

type http_http2Setting struct {
	ID	*interface{}
	Val	*uint32
}

type http_http2SettingID uint16

type http_http2SettingID uint16

type http_http2SettingID uint16

type http_http2SettingID uint16

type http_http2SettingID uint16

type http_http2SettingID uint16

type http_http2SettingsFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2SettingsFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2SettingsFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2SettingsFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2StreamError struct {
	Cause		*error
	Code		*interface{}
	StreamID	*uint32
}

type http_http2StreamError struct {
	StreamID	*uint32
	Code		*interface{}
	Cause		*error
}

type http_http2StreamError struct {
	StreamID	*uint32
	Code		*interface{}
	Cause		*error
}

type http_http2StreamError struct {
	Cause		*error
	Code		*interface{}
	StreamID	*uint32
}

type http_http2Transport struct {
	AllowHTTP			*bool
	ConnPool			*interface{}
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	DisableCompression		*bool
	HeaderTableSize			*uint32
	InitialWindowSize		*uint32
	MaxHeaderListSize		*uint32
	PingTimeout			*time.Duration
	PushHandler			*interface{}
	ReadIdleTimeout			*time.Duration
	Settings			*[]http.http2Setting
	StrictMaxConcurrentStreams	*bool
	t1				*http.Transport
	TLSClientConfig			*tls.Config
}

type http_http2Transport struct {
	DialTLSContext			*func(context.Context, string, string, *tls.Config) (net.Conn, error)
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	TLSClientConfig			*tls.Config
	ConnPool			*interface{}
	DisableCompression		*bool
	AllowHTTP			*bool
	MaxHeaderListSize		*uint32
	MaxReadFrameSize		*uint32
	MaxDecoderHeaderTableSize	*uint32
	MaxEncoderHeaderTableSize	*uint32
	StrictMaxConcurrentStreams	*bool
	IdleConnTimeout			*time.Duration
	ReadIdleTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	CountError			*func(string)
	t1				*http.Transport
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	http2transportTestHooks		*interface{}
}

type http_http2Transport struct {
	AllowHTTP			*bool
	ConnPool			*interface{}
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	DisableCompression		*bool
	HeaderTableSize			*uint32
	InitialWindowSize		*uint32
	MaxHeaderListSize		*uint32
	PingTimeout			*time.Duration
	PushHandler			*interface{}
	ReadIdleTimeout			*time.Duration
	Settings			*[]http.http2Setting
	StrictMaxConcurrentStreams	*bool
	t1				*http.Transport
	TLSClientConfig			*tls.Config
}

type http_http2Transport struct {
	DialTLSContext			*func(context.Context, string, string, *tls.Config) (net.Conn, error)
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	TLSClientConfig			*tls.Config
	ConnPool			*interface{}
	DisableCompression		*bool
	AllowHTTP			*bool
	MaxHeaderListSize		*uint32
	MaxReadFrameSize		*uint32
	MaxDecoderHeaderTableSize	*uint32
	MaxEncoderHeaderTableSize	*uint32
	StrictMaxConcurrentStreams	*bool
	IdleConnTimeout			*time.Duration
	ReadIdleTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	CountError			*func(string)
	t1				*http.Transport
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	http2transportTestHooks		*interface{}
}

type http_http2UnknownFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2UnknownFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2UnknownFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2UnknownFrame struct {
	http2FrameHeader	*interface{}
	p			*[]uint8
}

type http_http2WindowUpdateFrame struct {
	http2FrameHeader	*interface{}
	Increment		*uint32
}

type http_http2WindowUpdateFrame struct {
	http2FrameHeader	*interface{}
	Increment		*uint32
}

type http_http2WindowUpdateFrame struct {
	http2FrameHeader	*interface{}
	Increment		*uint32
}

type http_http2WindowUpdateFrame struct {
	http2FrameHeader	*interface{}
	Increment		*uint32
}

type http_http2addConnCall struct {
	_	*interface{}
	done	*chan struct {}
	err	*error
	p	*interface{}
}

type http_http2addConnCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	err	*error
}

type http_http2addConnCall struct {
	_	*interface{}
	p	*interface{}
	done	*chan struct {}
	err	*error
}

type http_http2addConnCall struct {
	_	*interface{}
	done	*chan struct {}
	err	*error
	p	*interface{}
}

type http_http2bodyWriterState struct {
	cs	*interface{}
	delay	*time.Duration
	fn	*func()
	fnonce	*sync.Once
	resc	*chan error
	timer	*time.Timer
}

type http_http2bodyWriterState struct {
	cs	*interface{}
	delay	*time.Duration
	fn	*func()
	fnonce	*sync.Once
	resc	*chan error
	timer	*time.Timer
}

type http_http2clientConnPool struct {
	addConnCalls	*map[string]*http.http2addConnCall
	conns		*map[string][]*http.http2ClientConn
	dialing		*map[string]*http.http2dialCall
	keys		*map[*http.http2ClientConn][]string
	mu		*sync.Mutex
	t		*interface{}
}

type http_http2clientConnPool struct {
	addConnCalls	*map[string]*http.http2addConnCall
	conns		*map[string][]*http.http2ClientConn
	dialing		*map[string]*http.http2dialCall
	keys		*map[*http.http2ClientConn][]string
	mu		*sync.Mutex
	t		*interface{}
}

type http_http2clientConnPool struct {
	t		*interface{}
	mu		*sync.Mutex
	conns		*map[string][]*http.http2ClientConn
	dialing		*map[string]*http.http2dialCall
	keys		*map[*http.http2ClientConn][]string
	addConnCalls	*map[string]*http.http2addConnCall
}

type http_http2clientConnPool struct {
	t		*interface{}
	mu		*sync.Mutex
	conns		*map[string][]*http.http2ClientConn
	dialing		*map[string]*http.http2dialCall
	keys		*map[*http.http2ClientConn][]string
	addConnCalls	*map[string]*http.http2addConnCall
}

type http_http2clientConnPoolIdleCloser interface {
}

type http_http2clientConnPoolIdleCloser interface {
}

type http_http2clientConnPoolIdleCloser interface {
}

type http_http2clientConnPoolIdleCloser interface {
}

type http_http2clientStream struct {
	cc			*interface{}
	ctx			*context.Context
	reqCancel		*<-chan struct {}
	trace			*httptrace.ClientTrace
	ID			*uint32
	bufPipe			*interface{}
	requestedGzip		*bool
	isHead			*bool
	abortOnce		*sync.Once
	abort			*chan struct {}
	abortErr		*error
	peerClosed		*chan struct {}
	donec			*chan struct {}
	on100			*chan struct {}
	respHeaderRecv		*chan struct {}
	res			*http.Response
	flow			*interface{}
	inflow			*interface{}
	bytesRemain		*int64
	readErr			*error
	reqBody			*io.ReadCloser
	reqBodyContentLength	*int64
	reqBodyClosed		*chan struct {}
	sentEndStream		*bool
	sentHeaders		*bool
	firstByte		*bool
	pastHeaders		*bool
	pastTrailers		*bool
	readClosed		*bool
	readAborted		*bool
	totalHeaderSize		*int64
	trailer			*http.Header
	resTrailer		*http.Header
}

type http_http2clientStream struct {
	bufPipe		*interface{}
	bytesRemain	*int64
	cc		*interface{}
	didReset	*bool
	done		*chan struct {}
	firstByte	*bool
	flow		*interface{}
	gotEndStream	*bool
	ID		*uint32
	inflow		*interface{}
	num1xx		*uint8
	on100		*func()
	pastHeaders	*bool
	pastTrailers	*bool
	peerReset	*chan struct {}
	readErr		*error
	req		*http.Request
	requestedGzip	*bool
	resc		*chan http.http2resAndError
	resetErr	*error
	resTrailer	*http.Header
	startedWrite	*bool
	stopReqBody	*error
	trace		*httptrace.ClientTrace
	trailer		*http.Header
}

type http_http2clientStream struct {
	cc			*interface{}
	ctx			*context.Context
	reqCancel		*<-chan struct {}
	trace			*httptrace.ClientTrace
	ID			*uint32
	bufPipe			*interface{}
	requestedGzip		*bool
	isHead			*bool
	abortOnce		*sync.Once
	abort			*chan struct {}
	abortErr		*error
	peerClosed		*chan struct {}
	donec			*chan struct {}
	on100			*chan struct {}
	respHeaderRecv		*chan struct {}
	res			*http.Response
	flow			*interface{}
	inflow			*interface{}
	bytesRemain		*int64
	readErr			*error
	reqBody			*io.ReadCloser
	reqBodyContentLength	*int64
	reqBodyClosed		*chan struct {}
	sentEndStream		*bool
	sentHeaders		*bool
	firstByte		*bool
	pastHeaders		*bool
	pastTrailers		*bool
	readClosed		*bool
	readAborted		*bool
	totalHeaderSize		*int64
	trailer			*http.Header
	resTrailer		*http.Header
}

type http_http2clientStream struct {
	bufPipe		*interface{}
	bytesRemain	*int64
	cc		*interface{}
	didReset	*bool
	done		*chan struct {}
	firstByte	*bool
	flow		*interface{}
	gotEndStream	*bool
	ID		*uint32
	inflow		*interface{}
	num1xx		*uint8
	on100		*func()
	pastHeaders	*bool
	pastTrailers	*bool
	peerReset	*chan struct {}
	readErr		*error
	req		*http.Request
	requestedGzip	*bool
	resc		*chan http.http2resAndError
	resetErr	*error
	resTrailer	*http.Header
	startedWrite	*bool
	stopReqBody	*error
	trace		*httptrace.ClientTrace
	trailer		*http.Header
}

type http_http2connError struct {
	Code	*interface{}
	Reason	*string
}

type http_http2connError struct {
	Code	*interface{}
	Reason	*string
}

type http_http2connError struct {
	Code	*interface{}
	Reason	*string
}

type http_http2connError struct {
	Code	*interface{}
	Reason	*string
}

type http_http2connectionStater interface {
}

type http_http2connectionStater interface {
}

type http_http2connectionStater interface {
}

type http_http2connectionStater interface {
}

type http_http2continuable interface {
}

type http_http2continuable interface {
}

type http_http2dataBuffer struct {
	chunks		*[][]uint8
	expected	*int64
	r		*int
	size		*int
	w		*int
}

type http_http2dataBuffer struct {
	chunks		*[][]uint8
	expected	*int64
	r		*int
	size		*int
	w		*int
}

type http_http2dataBuffer struct {
	chunks		*[][]uint8
	r		*int
	w		*int
	size		*int
	expected	*int64
}

type http_http2dataBuffer struct {
	chunks		*[][]uint8
	r		*int
	w		*int
	size		*int
	expected	*int64
}

type http_http2dialCall struct {
	_	*interface{}
	p	*interface{}
	ctx	*context.Context
	done	*chan struct {}
	res	*interface{}
	err	*error
}

type http_http2dialCall struct {
	_	*interface{}
	p	*interface{}
	ctx	*context.Context
	done	*chan struct {}
	res	*interface{}
	err	*error
}

type http_http2dialCall struct {
	_	*interface{}
	done	*chan struct {}
	err	*error
	p	*interface{}
	res	*interface{}
}

type http_http2dialCall struct {
	_	*interface{}
	done	*chan struct {}
	err	*error
	p	*interface{}
	res	*interface{}
}

type http_http2duplicatePseudoHeaderError string

type http_http2duplicatePseudoHeaderError string

type http_http2duplicatePseudoHeaderError string

type http_http2duplicatePseudoHeaderError string

type http_http2erringRoundTripper struct {
	err *error
}

type http_http2erringRoundTripper struct {
	err *error
}

type http_http2erringRoundTripper struct {
	err *error
}

type http_http2erringRoundTripper struct {
	err *error
}

type http_http2flow struct {
	_	*interface{}
	conn	*interface{}
	n	*int32
}

type http_http2flow struct {
	_	*interface{}
	conn	*interface{}
	n	*int32
}

type http_http2frameCache struct {
	dataFrame *interface{}
}

type http_http2frameCache struct {
	dataFrame *interface{}
}

type http_http2frameCache struct {
	dataFrame *interface{}
}

type http_http2frameCache struct {
	dataFrame *interface{}
}

type http_http2frameParser func()

type http_http2frameParser func()

type http_http2gzipReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http_http2gzipReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*gzip.Reader
	zerr	*error
}

type http_http2headerFieldNameError string

type http_http2headerFieldNameError string

type http_http2headerFieldNameError string

type http_http2headerFieldNameError string

type http_http2headerFieldValueError string

type http_http2headerFieldValueError string

type http_http2headerFieldValueError string

type http_http2headerFieldValueError string

type http_http2headersOrContinuation interface {
}

type http_http2headersOrContinuation interface {
}

type http_http2httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http_http2httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http_http2httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http_http2httpError struct {
	_	*interface{}
	msg	*string
	timeout	*bool
}

type http_http2incomparable [0]*func()

type http_http2incomparable [0]*func()

type http_http2incomparable [0]*func()

type http_http2incomparable [0]*func()

type http_http2inflow struct {
	avail	*int32
	unsent	*int32
}

type http_http2inflow struct {
	avail	*int32
	unsent	*int32
}

type http_http2metaFrame struct {
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http_http2metaFrame struct {
	Fields		*[]hpack.HeaderField
	Truncated	*bool
}

type http_http2missingBody struct {
}

type http_http2missingBody struct {
}

type http_http2noBodyReader struct {
}

type http_http2noBodyReader struct {
}

type http_http2noCachedConnError struct {
}

type http_http2noCachedConnError struct {
}

type http_http2noCachedConnError struct {
}

type http_http2noCachedConnError struct {
}

type http_http2noDialClientConnPool struct {
	http2clientConnPool *interface{}
}

type http_http2noDialClientConnPool struct {
	http2clientConnPool *interface{}
}

type http_http2noDialClientConnPool struct {
	http2clientConnPool *interface{}
}

type http_http2noDialClientConnPool struct {
	http2clientConnPool *interface{}
}

type http_http2noDialH2RoundTripper struct {
	http2Transport *interface{}
}

type http_http2noDialH2RoundTripper struct {
	http2Transport *interface{}
}

type http_http2noDialH2RoundTripper struct {
	http2Transport *interface{}
}

type http_http2noDialH2RoundTripper struct {
	http2Transport *interface{}
}

type http_http2outflow struct {
	_	*interface{}
	n	*int32
	conn	*interface{}
}

type http_http2outflow struct {
	_	*interface{}
	n	*int32
	conn	*interface{}
}

type http_http2pipe struct {
	b		*interface{}
	breakErr	*error
	c		*sync.Cond
	donec		*chan struct {}
	err		*error
	mu		*sync.Mutex
	readFn		*func()
	unread		*int
}

type http_http2pipe struct {
	mu		*sync.Mutex
	c		*sync.Cond
	b		*interface{}
	unread		*int
	err		*error
	breakErr	*error
	donec		*chan struct {}
	readFn		*func()
}

type http_http2pipe struct {
	b		*interface{}
	breakErr	*error
	c		*sync.Cond
	donec		*chan struct {}
	err		*error
	mu		*sync.Mutex
	readFn		*func()
	unread		*int
}

type http_http2pipe struct {
	mu		*sync.Mutex
	c		*sync.Cond
	b		*interface{}
	unread		*int
	err		*error
	breakErr	*error
	donec		*chan struct {}
	readFn		*func()
}

type http_http2pipeBuffer interface {
}

type http_http2pipeBuffer interface {
}

type http_http2pipeBuffer interface {
}

type http_http2pipeBuffer interface {
}

type http_http2pseudoHeaderError string

type http_http2pseudoHeaderError string

type http_http2pseudoHeaderError string

type http_http2pseudoHeaderError string

type http_http2resAndError struct {
	_	*interface{}
	err	*error
	res	*http.Response
}

type http_http2resAndError struct {
	_	*interface{}
	err	*error
	res	*http.Response
}

type http_http2serverMessage int

type http_http2serverMessage int

type http_http2serverMessage int

type http_http2serverMessage int

type http_http2serverMessage int

type http_http2serverMessage int

type http_http2stickyErrWriter struct {
	err	*error
	w	*io.Writer
}

type http_http2stickyErrWriter struct {
	group	*interface{}
	conn	*net.Conn
	timeout	*time.Duration
	err	*error
}

type http_http2stickyErrWriter struct {
	group	*interface{}
	conn	*net.Conn
	timeout	*time.Duration
	err	*error
}

type http_http2stickyErrWriter struct {
	err	*error
	w	*io.Writer
}

type http_http2synctestGroupInterface interface {
}

type http_http2synctestGroupInterface interface {
}

type http_http2timeTimer struct {
	Timer *time.Timer
}

type http_http2timeTimer struct {
	Timer *time.Timer
}

type http_http2transportResponseBody struct {
	cs *interface{}
}

type http_http2transportResponseBody struct {
	cs *interface{}
}

type http_http2transportResponseBody struct {
	cs *interface{}
}

type http_http2transportResponseBody struct {
	cs *interface{}
}

type http_http2transportTestHooks struct {
	newclientconn	*func(*http.http2ClientConn)
	group		*interface{}
}

type http_http2transportTestHooks struct {
	newclientconn	*func(*http.http2ClientConn)
	group		*interface{}
}

type http_http2unencryptedTransport struct {
	DialTLSContext			*func(context.Context, string, string, *tls.Config) (net.Conn, error)
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	TLSClientConfig			*tls.Config
	ConnPool			*interface{}
	DisableCompression		*bool
	AllowHTTP			*bool
	MaxHeaderListSize		*uint32
	MaxReadFrameSize		*uint32
	MaxDecoderHeaderTableSize	*uint32
	MaxEncoderHeaderTableSize	*uint32
	StrictMaxConcurrentStreams	*bool
	IdleConnTimeout			*time.Duration
	ReadIdleTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	CountError			*func(string)
	t1				*http.Transport
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	http2transportTestHooks		*interface{}
}

type http_http2unencryptedTransport struct {
	DialTLSContext			*func(context.Context, string, string, *tls.Config) (net.Conn, error)
	DialTLS				*func(string, string, *tls.Config) (net.Conn, error)
	TLSClientConfig			*tls.Config
	ConnPool			*interface{}
	DisableCompression		*bool
	AllowHTTP			*bool
	MaxHeaderListSize		*uint32
	MaxReadFrameSize		*uint32
	MaxDecoderHeaderTableSize	*uint32
	MaxEncoderHeaderTableSize	*uint32
	StrictMaxConcurrentStreams	*bool
	IdleConnTimeout			*time.Duration
	ReadIdleTimeout			*time.Duration
	PingTimeout			*time.Duration
	WriteByteTimeout		*time.Duration
	CountError			*func(string)
	t1				*http.Transport
	connPoolOnce			*sync.Once
	connPoolOrDef			*interface{}
	http2transportTestHooks		*interface{}
}

type http_httpError struct {
	err	*string
	timeout	*bool
}

type http_httpError struct {
	err	*string
	timeout	*bool
}

type http_incomparable [0]*func()

type http_incomparable [0]*func()

type http_incomparable [0]*func()

type http_incomparable [0]*func()

type http_keyValues struct {
	key	*string
	values	*[]string
}

type http_keyValues struct {
	key	*string
	values	*[]string
}

type http_noBody struct {
}

type http_noBody struct {
}

type http_noBody struct {
}

type http_noBody struct {
}

type http_nothingWrittenError struct {
	error *error
}

type http_nothingWrittenError struct {
	error *error
}

type http_nothingWrittenError struct {
	error *error
}

type http_nothingWrittenError struct {
	error *error
}

type http_pattern struct {
	str		*string
	method		*string
	host		*string
	segments	*[]http.segment
	loc		*string
}

type http_pattern struct {
	str		*string
	method		*string
	host		*string
	segments	*[]http.segment
	loc		*string
}

type http_persistConn struct {
	alt			*http.RoundTripper
	t			*http.Transport
	cacheKey		*interface{}
	conn			*net.Conn
	tlsState		*tls.ConnectionState
	br			*bufio.Reader
	bw			*bufio.Writer
	nwrite			*int64
	reqch			*chan http.requestAndChan
	writech			*chan http.writeRequest
	closech			*chan struct {}
	isProxy			*bool
	sawEOF			*bool
	readLimit		*int64
	writeErrCh		*chan error
	writeLoopDone		*chan struct {}
	idleAt			*time.Time
	idleTimer		*time.Timer
	mu			*sync.Mutex
	numExpectedResponses	*int
	closed			*error
	canceledErr		*error
	broken			*bool
	reused			*bool
	mutateHeaderFunc	*func(http.Header)
}

type http_persistConn struct {
	alt			*http.RoundTripper
	t			*http.Transport
	cacheKey		*interface{}
	conn			*net.Conn
	tlsState		*tls.ConnectionState
	br			*bufio.Reader
	bw			*bufio.Writer
	nwrite			*int64
	reqch			*chan http.requestAndChan
	writech			*chan http.writeRequest
	closech			*chan struct {}
	isProxy			*bool
	sawEOF			*bool
	readLimit		*int64
	writeErrCh		*chan error
	writeLoopDone		*chan struct {}
	idleAt			*time.Time
	idleTimer		*time.Timer
	mu			*sync.Mutex
	numExpectedResponses	*int
	closed			*error
	canceledErr		*error
	broken			*bool
	reused			*bool
	mutateHeaderFunc	*func(http.Header)
}

type http_persistConn struct {
	alt			*http.RoundTripper
	t			*http.Transport
	cacheKey		*interface{}
	conn			*net.Conn
	tlsState		*tls.ConnectionState
	br			*bufio.Reader
	bw			*bufio.Writer
	nwrite			*int64
	reqch			*chan http.requestAndChan
	writech			*chan http.writeRequest
	closech			*chan struct {}
	isProxy			*bool
	sawEOF			*bool
	readLimit		*int64
	writeErrCh		*chan error
	writeLoopDone		*chan struct {}
	idleAt			*time.Time
	idleTimer		*time.Timer
	mu			*sync.Mutex
	numExpectedResponses	*int
	closed			*error
	canceledErr		*error
	broken			*bool
	reused			*bool
	mutateHeaderFunc	*func(http.Header)
}

type http_persistConn struct {
	alt			*http.RoundTripper
	t			*http.Transport
	cacheKey		*interface{}
	conn			*net.Conn
	tlsState		*tls.ConnectionState
	br			*bufio.Reader
	bw			*bufio.Writer
	nwrite			*int64
	reqch			*chan http.requestAndChan
	writech			*chan http.writeRequest
	closech			*chan struct {}
	isProxy			*bool
	sawEOF			*bool
	readLimit		*int64
	writeErrCh		*chan error
	writeLoopDone		*chan struct {}
	idleAt			*time.Time
	idleTimer		*time.Timer
	mu			*sync.Mutex
	numExpectedResponses	*int
	closed			*error
	canceledErr		*error
	broken			*bool
	reused			*bool
	mutateHeaderFunc	*func(http.Header)
}

type http_persistConnWriter struct {
	pc *interface{}
}

type http_persistConnWriter struct {
	pc *interface{}
}

type http_persistConnWriter struct {
	pc *interface{}
}

type http_persistConnWriter struct {
	pc *interface{}
}

type http_readResult struct {
	_	*interface{}
	n	*int
	err	*error
	b	*uint8
}

type http_readResult struct {
	_	*interface{}
	n	*int
	err	*error
	b	*uint8
}

type http_readResult struct {
	_	*interface{}
	n	*int
	err	*error
	b	*uint8
}

type http_readResult struct {
	_	*interface{}
	n	*int
	err	*error
	b	*uint8
}

type http_readTrackingBody struct {
	ReadCloser	*io.ReadCloser
	didRead		*bool
	didClose	*bool
}

type http_readTrackingBody struct {
	ReadCloser	*io.ReadCloser
	didRead		*bool
	didClose	*bool
}

type http_readTrackingBody struct {
	ReadCloser	*io.ReadCloser
	didRead		*bool
	didClose	*bool
}

type http_readTrackingBody struct {
	ReadCloser	*io.ReadCloser
	didRead		*bool
	didClose	*bool
}

type http_readWriteCloserBody struct {
	_		*interface{}
	br		*bufio.Reader
	ReadWriteCloser	*io.ReadWriteCloser
}

type http_readWriteCloserBody struct {
	_		*interface{}
	br		*bufio.Reader
	ReadWriteCloser	*io.ReadWriteCloser
}

type http_readWriteCloserBody struct {
	_		*interface{}
	br		*bufio.Reader
	ReadWriteCloser	*io.ReadWriteCloser
}

type http_readWriteCloserBody struct {
	_		*interface{}
	br		*bufio.Reader
	ReadWriteCloser	*io.ReadWriteCloser
}

type http_requestAndChan struct {
	_		*interface{}
	treq		*interface{}
	ch		*chan http.responseAndError
	addedGzip	*bool
	continueCh	*chan<- struct {}
	callerGone	*<-chan struct {}
}

type http_requestAndChan struct {
	_		*interface{}
	req		*http.Request
	cancelKey	*interface{}
	ch		*chan http.responseAndError
	addedGzip	*bool
	continueCh	*chan<- struct {}
	callerGone	*<-chan struct {}
}

type http_requestAndChan struct {
	_		*interface{}
	treq		*interface{}
	ch		*chan http.responseAndError
	addedGzip	*bool
	continueCh	*chan<- struct {}
	callerGone	*<-chan struct {}
}

type http_requestAndChan struct {
	_		*interface{}
	req		*http.Request
	cancelKey	*interface{}
	ch		*chan http.responseAndError
	addedGzip	*bool
	continueCh	*chan<- struct {}
	callerGone	*<-chan struct {}
}

type http_requestBodyReadError struct {
	error *error
}

type http_requestBodyReadError struct {
	error *error
}

type http_requestBodyReadError struct {
	error *error
}

type http_requestBodyReadError struct {
	error *error
}

type http_responseAndError struct {
	_	*interface{}
	res	*http.Response
	err	*error
}

type http_responseAndError struct {
	_	*interface{}
	res	*http.Response
	err	*error
}

type http_responseAndError struct {
	_	*interface{}
	res	*http.Response
	err	*error
}

type http_responseAndError struct {
	_	*interface{}
	res	*http.Response
	err	*error
}

type http_segment struct {
	s	*string
	wild	*bool
	multi	*bool
}

type http_segment struct {
	s	*string
	wild	*bool
	multi	*bool
}

type http_socksAddr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type http_socksAddr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type http_socksAddr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type http_socksAddr struct {
	Name	*string
	IP	*net.IP
	Port	*int
}

type http_socksAuthMethod int

type http_socksAuthMethod int

type http_socksAuthMethod int

type http_socksAuthMethod int

type http_socksUsernamePassword struct {
	Username	*string
	Password	*string
}

type http_socksUsernamePassword struct {
	Username	*string
	Password	*string
}

type http_socksUsernamePassword struct {
	Username	*string
	Password	*string
}

type http_socksUsernamePassword struct {
	Username	*string
	Password	*string
}

type http_stringWriter struct {
	w *io.Writer
}

type http_stringWriter struct {
	w *io.Writer
}

type http_stringWriter struct {
	w *io.Writer
}

type http_stringWriter struct {
	w *io.Writer
}

type http_timeoutError struct {
	err *string
}

type http_timeoutError struct {
	err *string
}

type http_tlsHandshakeTimeoutError struct {
}

type http_tlsHandshakeTimeoutError struct {
}

type http_tlsHandshakeTimeoutError struct {
}

type http_tlsHandshakeTimeoutError struct {
}

type http_transferWriter struct {
	Method			*string
	Body			*io.Reader
	BodyCloser		*io.Closer
	ResponseToHEAD		*bool
	ContentLength		*int64
	Close			*bool
	TransferEncoding	*[]string
	Header			*http.Header
	Trailer			*http.Header
	IsResponse		*bool
	bodyReadError		*error
	FlushHeaders		*bool
	ByteReadCh		*chan http.readResult
}

type http_transferWriter struct {
	Method			*string
	Body			*io.Reader
	BodyCloser		*io.Closer
	ResponseToHEAD		*bool
	ContentLength		*int64
	Close			*bool
	TransferEncoding	*[]string
	Header			*http.Header
	Trailer			*http.Header
	IsResponse		*bool
	bodyReadError		*error
	FlushHeaders		*bool
	ByteReadCh		*chan http.readResult
}

type http_transferWriter struct {
	Method			*string
	Body			*io.Reader
	BodyCloser		*io.Closer
	ResponseToHEAD		*bool
	ContentLength		*int64
	Close			*bool
	TransferEncoding	*[]string
	Header			*http.Header
	Trailer			*http.Header
	IsResponse		*bool
	bodyReadError		*error
	FlushHeaders		*bool
	ByteReadCh		*chan http.readResult
}

type http_transferWriter struct {
	Method			*string
	Body			*io.Reader
	BodyCloser		*io.Closer
	ResponseToHEAD		*bool
	ContentLength		*int64
	Close			*bool
	TransferEncoding	*[]string
	Header			*http.Header
	Trailer			*http.Header
	IsResponse		*bool
	bodyReadError		*error
	FlushHeaders		*bool
	ByteReadCh		*chan http.readResult
}

type http_transportReadFromServerError struct {
	err *error
}

type http_transportReadFromServerError struct {
	err *error
}

type http_transportReadFromServerError struct {
	err *error
}

type http_transportReadFromServerError struct {
	err *error
}

type http_transportRequest struct {
	Request		*http.Request
	extra		*http.Header
	trace		*httptrace.ClientTrace
	cancelKey	*interface{}
	mu		*sync.Mutex
	err		*error
}

type http_transportRequest struct {
	Request	*http.Request
	extra	*http.Header
	trace	*httptrace.ClientTrace
	ctx	*context.Context
	cancel	*context.CancelCauseFunc
	mu	*sync.Mutex
	err	*error
}

type http_transportRequest struct {
	Request	*http.Request
	extra	*http.Header
	trace	*httptrace.ClientTrace
	ctx	*context.Context
	cancel	*context.CancelCauseFunc
	mu	*sync.Mutex
	err	*error
}

type http_transportRequest struct {
	Request		*http.Request
	extra		*http.Header
	trace		*httptrace.ClientTrace
	cancelKey	*interface{}
	mu		*sync.Mutex
	err		*error
}

type http_unencryptedNetConnInTLSConn struct {
	Conn	*net.Conn
	conn	*net.Conn
}

type http_unencryptedNetConnInTLSConn struct {
	Conn	*net.Conn
	conn	*net.Conn
}

type http_unsupportedTEError struct {
	err *string
}

type http_unsupportedTEError struct {
	err *string
}

type http_unsupportedTEError struct {
	err *string
}

type http_unsupportedTEError struct {
	err *string
}

type http_wantConn struct {
	cm		*interface{}
	key		*interface{}
	beforeDial	*func()
	afterDial	*func()
	mu		*sync.Mutex
	ctx		*context.Context
	cancelCtx	*context.CancelFunc
	done		*bool
	result		*chan http.connOrError
}

type http_wantConn struct {
	cm		*interface{}
	key		*interface{}
	ctx		*context.Context
	ready		*chan struct {}
	beforeDial	*func()
	afterDial	*func()
	mu		*sync.Mutex
	pc		*interface{}
	err		*error
}

type http_wantConn struct {
	cm		*interface{}
	key		*interface{}
	ctx		*context.Context
	ready		*chan struct {}
	beforeDial	*func()
	afterDial	*func()
	mu		*sync.Mutex
	pc		*interface{}
	err		*error
}

type http_wantConn struct {
	cm		*interface{}
	key		*interface{}
	beforeDial	*func()
	afterDial	*func()
	mu		*sync.Mutex
	ctx		*context.Context
	cancelCtx	*context.CancelFunc
	done		*bool
	result		*chan http.connOrError
}

type http_wantConnQueue struct {
	head	*[]*http.wantConn
	headPos	*int
	tail	*[]*http.wantConn
}

type http_wantConnQueue struct {
	head	*[]*http.wantConn
	headPos	*int
	tail	*[]*http.wantConn
}

type http_wantConnQueue struct {
	head	*[]*http.wantConn
	headPos	*int
	tail	*[]*http.wantConn
}

type http_wantConnQueue struct {
	head	*[]*http.wantConn
	headPos	*int
	tail	*[]*http.wantConn
}

type http_writeRequest struct {
	req		*interface{}
	ch		*chan<- error
	continueCh	*<-chan struct {}
}

type http_writeRequest struct {
	req		*interface{}
	ch		*chan<- error
	continueCh	*<-chan struct {}
}

type http_writeRequest struct {
	req		*interface{}
	ch		*chan<- error
	continueCh	*<-chan struct {}
}

type http_writeRequest struct {
	req		*interface{}
	ch		*chan<- error
	continueCh	*<-chan struct {}
}

type http_zlibDeflateReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*io.ReadCloser
	err	*error
}

type http_zlibDeflateReader struct {
	_	*interface{}
	body	*io.ReadCloser
	zr	*io.ReadCloser
	err	*error
}

type http_zstdReader struct {
	body	*io.ReadCloser
	zr	*zstd.Decoder
	zerr	*error
}

type http_zstdReader struct {
	body	*io.ReadCloser
	zr	*zstd.Decoder
	zerr	*error
}

type handlers_ExitHandler struct {
}

type handlers_ExitHandler struct {
}

type handlers_FloodHandler struct {
}

type handlers_FloodHandler struct {
}

type handlers_FloodKillHandler struct {
}

type handlers_FloodKillHandler struct {
}

type handlers_Handler func()

type handlers_Handler func()

type handlers_KeepAliveHandler struct {
	writer *handlers.MessageWriter
}

type handlers_KeepAliveHandler struct {
	writer *handlers.MessageWriter
}

type handlers_MessageWriter interface {
}

type handlers_MessageWriter interface {
}

type handlers_Registry struct {
	handlers *map[uint32]handlers.Handler
}

type handlers_Registry struct {
	handlers *map[uint32]handlers.Handler
}

type handlers_SillyPacket struct {
	TaskID	*uint32
	All	*bool
}

type handlers_SillyPacket struct {
	TaskID	*uint32
	All	*bool
}

type message_Message struct {
	Command		*uint32
	Length		*uint32
	DataChecksum	*uint32
	Magic		*uint32
	Payload		*bytebuf.Buffer
}

type message_Message struct {
	Command		*uint32
	Length		*uint32
	DataChecksum	*uint32
	Magic		*uint32
	Payload		*bytebuf.Buffer
}

type bytebuf_Buffer struct {
	buffer		*[]uint8
	position	*int
}

type bytebuf_Buffer struct {
	buffer		*[]uint8
	position	*int
}

type tls_ALPNExtension struct {
	AlpnProtocols *[]string
}

type tls_ALPNExtension struct {
	AlpnProtocols *[]string
}

type tls_ALPNExtension struct {
	AlpnProtocols *[]string
}

type tls_ALPNExtension struct {
	AlpnProtocols *[]string
}

type tls_ActiveConnectionIDLimit uint64

type tls_ActiveConnectionIDLimit uint64

type tls_AlertError uint8

type tls_AlertError uint8

type tls_AlertError uint8

type tls_AlertError uint8

type tls_AlertError uint8

type tls_AlertError uint8

type tls_ApplicationSettingsExtension struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtension struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtension struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtension struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtensionNew struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtensionNew struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtensionNew struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_ApplicationSettingsExtensionNew struct {
	applicationSettingsExtension	*interface{}
	SupportedProtocols		*[]string
}

type tls_CertCompressionAlgo uint16

type tls_CertCompressionAlgo uint16

type tls_CertCompressionAlgo uint16

type tls_CertCompressionAlgo uint16

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_Certificate struct {
	Certificate			*[][]uint8
	PrivateKey			*crypto.PrivateKey
	SupportedSignatureAlgorithms	*[]tls.SignatureScheme
	OCSPStaple			*[]uint8
	SignedCertificateTimestamps	*[][]uint8
	Leaf				*x509.Certificate
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestInfo struct {
	AcceptableCAs		*[][]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	Version			*uint16
	ctx			*context.Context
}

type tls_CertificateRequestMsgTLS13 struct {
	Raw					*[]uint8
	OcspStapling				*bool
	Scts					*bool
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	CertificateAuthorities			*[][]uint8
}

type tls_CertificateRequestMsgTLS13 struct {
	Raw					*[]uint8
	OcspStapling				*bool
	Scts					*bool
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	CertificateAuthorities			*[][]uint8
}

type tls_CertificateRequestMsgTLS13 struct {
	Raw					*[]uint8
	OcspStapling				*bool
	Scts					*bool
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	CertificateAuthorities			*[][]uint8
}

type tls_CertificateRequestMsgTLS13 struct {
	Raw					*[]uint8
	OcspStapling				*bool
	Scts					*bool
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	CertificateAuthorities			*[][]uint8
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CertificateVerificationError struct {
	UnverifiedCertificates	*[]*x509.Certificate
	Err			*error
}

type tls_CipherSuite struct {
	ID			*uint16
	Name			*string
	SupportedVersions	*[]uint16
	Insecure		*bool
}

type tls_CipherSuite struct {
	ID			*uint16
	Name			*string
	SupportedVersions	*[]uint16
	Insecure		*bool
}

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientAuthType int

type tls_ClientHelloBuildStatus int

type tls_ClientHelloBuildStatus int

type tls_ClientHelloBuildStatus int

type tls_ClientHelloBuildStatus int

type tls_ClientHelloID struct {
	Client	*string
	Version	*string
	Seed	*tls.PRNGSeed
	Weights	*tls.Weights
}

type tls_ClientHelloID struct {
	Client			*string
	RandomExtensionOrder	*bool
	Version			*string
	Seed			*tls.PRNGSeed
	Weights			*tls.Weights
	SpecFactory		*tls.ClientHelloSpecFactory
}

type tls_ClientHelloID struct {
	Client	*string
	Version	*string
	Seed	*tls.PRNGSeed
	Weights	*tls.Weights
}

type tls_ClientHelloID struct {
	Client			*string
	RandomExtensionOrder	*bool
	Version			*string
	Seed			*tls.PRNGSeed
	Weights			*tls.Weights
	SpecFactory		*tls.ClientHelloSpecFactory
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloInfo struct {
	CipherSuites		*[]uint16
	ServerName		*string
	SupportedCurves		*[]tls.CurveID
	SupportedPoints		*[]uint8
	SignatureSchemes	*[]tls.SignatureScheme
	SupportedProtos		*[]string
	SupportedVersions	*[]uint16
	Extensions		*[]uint16
	Conn			*net.Conn
	config			*tls.Config
	ctx			*context.Context
}

type tls_ClientHelloSpec struct {
	CipherSuites		*[]uint16
	CompressionMethods	*[]uint8
	Extensions		*[]tls.TLSExtension
	TLSVersMin		*uint16
	TLSVersMax		*uint16
	GetSessionID		*func([]uint8) [32]uint8
}

type tls_ClientHelloSpec struct {
	CipherSuites		*[]uint16
	CompressionMethods	*[]uint8
	Extensions		*[]tls.TLSExtension
	TLSVersMin		*uint16
	TLSVersMax		*uint16
	GetSessionID		*func([]uint8) [32]uint8
}

type tls_ClientHelloSpec struct {
	CipherSuites		*[]uint16
	CompressionMethods	*[]uint8
	Extensions		*[]tls.TLSExtension
	TLSVersMin		*uint16
	TLSVersMax		*uint16
	GetSessionID		*func([]uint8) [32]uint8
}

type tls_ClientHelloSpec struct {
	CipherSuites		*[]uint16
	CompressionMethods	*[]uint8
	Extensions		*[]tls.TLSExtension
	TLSVersMin		*uint16
	TLSVersMax		*uint16
	GetSessionID		*func([]uint8) [32]uint8
}

type tls_ClientHelloSpecFactory func()

type tls_ClientHelloSpecFactory func()

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionCache interface {
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_ClientSessionState struct {
	session *tls.SessionState
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
	ECHConfigs				*[]tls.ECHConfig
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
	ECHConfigs				*[]tls.ECHConfig
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
	ECHConfigs				*[]tls.ECHConfig
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	GetEncryptedClientHelloKeys		*func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error)
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	GetEncryptedClientHelloKeys		*func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error)
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
}

type tls_Config struct {
	Rand					*io.Reader
	Time					*func() time.Time
	Certificates				*[]tls.Certificate
	NameToCertificate			*map[string]*tls.Certificate
	GetCertificate				*func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate			*func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	GetConfigForClient			*func(*tls.ClientHelloInfo) (*tls.Config, error)
	VerifyPeerCertificate			*func([][]uint8, [][]*x509.Certificate) error
	VerifyConnection			*func(tls.ConnectionState) error
	RootCAs					*x509.CertPool
	NextProtos				*[]string
	ApplicationSettings			*map[string][]uint8
	ServerName				*string
	ClientAuth				*tls.ClientAuthType
	ClientCAs				*x509.CertPool
	InsecureSkipVerify			*bool
	InsecureSkipTimeVerify			*bool
	OmitEmptyPsk				*bool
	InsecureServerNameToVerify		*string
	PreferSkipResumptionOnNilExtension	*bool
	CipherSuites				*[]uint16
	PreferServerCipherSuites		*bool
	SessionTicketsDisabled			*bool
	SessionTicketKey			*[32]uint8
	ClientSessionCache			*tls.ClientSessionCache
	UnwrapSession				*func([]uint8, tls.ConnectionState) (*tls.SessionState, error)
	WrapSession				*func(tls.ConnectionState, *tls.SessionState) ([]uint8, error)
	MinVersion				*uint16
	MaxVersion				*uint16
	CurvePreferences			*[]tls.CurveID
	PQSignatureSchemesEnabled		*bool
	DynamicRecordSizingDisabled		*bool
	Renegotiation				*tls.RenegotiationSupport
	KeyLogWriter				*io.Writer
	EncryptedClientHelloConfigList		*[]uint8
	EncryptedClientHelloRejectionVerify	*func(tls.ConnectionState) error
	EncryptedClientHelloKeys		*[]tls.EncryptedClientHelloKey
	mutex					*sync.RWMutex
	sessionTicketKeys			*[]tls.ticketKey
	autoSessionTicketKeys			*[]tls.ticketKey
	ECHConfigs				*[]tls.ECHConfig
}

type tls_Conn struct {
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	peerSigAlg		*tls.SignatureScheme
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_Conn struct {
	ClientHello		*interface{}
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	utls			*interface{}
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_Conn struct {
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	peerSigAlg		*tls.SignatureScheme
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_Conn struct {
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	utls			*interface{}
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_Conn struct {
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	utls			*interface{}
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_Conn struct {
	ClientHello		*interface{}
	conn			*net.Conn
	isClient		*bool
	handshakeFn		*func(context.Context) error
	quic			*interface{}
	isHandshakeComplete	*atomic.Bool
	handshakeMutex		*sync.Mutex
	handshakeErr		*error
	vers			*uint16
	haveVers		*bool
	config			*tls.Config
	handshakes		*int
	extMasterSecret		*bool
	didResume		*bool
	didHRR			*bool
	cipherSuite		*uint16
	curveID			*tls.CurveID
	ocspResponse		*[]uint8
	scts			*[][]uint8
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	verifiedChains		*[][]*x509.Certificate
	serverName		*string
	secureRenegotiation	*bool
	ekm			*func(string, []uint8, int) ([]uint8, error)
	resumptionSecret	*[]uint8
	echAccepted		*bool
	ticketKeys		*[]tls.ticketKey
	clientFinishedIsFirst	*bool
	closeNotifyErr		*error
	closeNotifySent		*bool
	clientFinished		*[12]uint8
	serverFinished		*[12]uint8
	clientProtocol		*string
	utls			*interface{}
	in			*interface{}
	out			*interface{}
	rawInput		*bytes.Buffer
	input			*bytes.Reader
	hand			*bytes.Buffer
	buffering		*bool
	sendBuf			*[]uint8
	bytesSent		*int64
	packetsSent		*int64
	retryCount		*int
	activeCall		*atomic.Int32
	tmp			*[16]uint8
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
	ECHRetryConfigs			*[]tls.ECHConfig
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
	ECHRetryConfigs			*[]tls.ECHConfig
}

type tls_ConnectionState struct {
	Version					*uint16
	HandshakeComplete			*bool
	DidResume				*bool
	CipherSuite				*uint16
	CurveID					*tls.CurveID
	NegotiatedProtocol			*string
	NegotiatedProtocolIsMutual		*bool
	ServerName				*string
	PeerCertificates			*[]*x509.Certificate
	VerifiedChains				*[][]*x509.Certificate
	SignedCertificateTimestamps		*[][]uint8
	OCSPResponse				*[]uint8
	TLSUnique				*[]uint8
	ECHAccepted				*bool
	ekm					*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR			*bool
	testingOnlyPeerSignatureAlgorithm	*tls.SignatureScheme
}

type tls_ConnectionState struct {
	Version					*uint16
	HandshakeComplete			*bool
	DidResume				*bool
	CipherSuite				*uint16
	CurveID					*tls.CurveID
	NegotiatedProtocol			*string
	NegotiatedProtocolIsMutual		*bool
	ServerName				*string
	PeerCertificates			*[]*x509.Certificate
	VerifiedChains				*[][]*x509.Certificate
	SignedCertificateTimestamps		*[][]uint8
	OCSPResponse				*[]uint8
	TLSUnique				*[]uint8
	ECHAccepted				*bool
	ekm					*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR			*bool
	testingOnlyPeerSignatureAlgorithm	*tls.SignatureScheme
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
	ECHRetryConfigs			*[]tls.ECHConfig
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
	ECHRetryConfigs			*[]tls.ECHConfig
}

type tls_ConnectionState struct {
	Version				*uint16
	HandshakeComplete		*bool
	DidResume			*bool
	CipherSuite			*uint16
	NegotiatedProtocol		*string
	NegotiatedProtocolIsMutual	*bool
	PeerApplicationSettings		*[]uint8
	ServerName			*string
	PeerCertificates		*[]*x509.Certificate
	VerifiedChains			*[][]*x509.Certificate
	SignedCertificateTimestamps	*[][]uint8
	OCSPResponse			*[]uint8
	TLSUnique			*[]uint8
	ECHAccepted			*bool
	ekm				*func(string, []uint8, int) ([]uint8, error)
	testingOnlyDidHRR		*bool
	testingOnlyCurveID		*tls.CurveID
}

type tls_CookieExtension struct {
	Cookie *[]uint8
}

type tls_CookieExtension struct {
	Cookie *[]uint8
}

type tls_CookieExtension struct {
	Cookie *[]uint8
}

type tls_CookieExtension struct {
	Cookie *[]uint8
}

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_CurveID uint16

type tls_ECHConfig struct {
	Version		*uint16
	Length		*uint16
	Contents	*tls.ECHConfigContents
	raw		*[]uint8
}

type tls_ECHConfig struct {
	Version		*uint16
	Length		*uint16
	Contents	*tls.ECHConfigContents
	raw		*[]uint8
}

type tls_ECHConfig struct {
	Version		*uint16
	Length		*uint16
	Contents	*tls.ECHConfigContents
	raw		*[]uint8
}

type tls_ECHConfig struct {
	Version		*uint16
	Length		*uint16
	Contents	*tls.ECHConfigContents
	raw		*[]uint8
}

type tls_ECHConfigContents struct {
	KeyConfig		*tls.HPKEKeyConfig
	MaximumNameLength	*uint8
	PublicName		*[]uint8
	rawExtensions		*[]uint8
}

type tls_ECHConfigContents struct {
	KeyConfig		*tls.HPKEKeyConfig
	MaximumNameLength	*uint8
	PublicName		*[]uint8
	rawExtensions		*[]uint8
}

type tls_ECHConfigContents struct {
	KeyConfig		*tls.HPKEKeyConfig
	MaximumNameLength	*uint8
	PublicName		*[]uint8
	rawExtensions		*[]uint8
}

type tls_ECHConfigContents struct {
	KeyConfig		*tls.HPKEKeyConfig
	MaximumNameLength	*uint8
	PublicName		*[]uint8
	rawExtensions		*[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_ECHRejectionError struct {
	RetryConfigList *[]uint8
}

type tls_EncryptedClientHelloExtension interface {
}

type tls_EncryptedClientHelloExtension interface {
}

type tls_EncryptedClientHelloExtension interface {
}

type tls_EncryptedClientHelloExtension interface {
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_EncryptedClientHelloKey struct {
	Config		*[]uint8
	PrivateKey	*[]uint8
	SendAsRetry	*bool
}

type tls_ExtendedMasterSecretExtension struct {
}

type tls_ExtendedMasterSecretExtension struct {
}

type tls_ExtendedMasterSecretExtension struct {
}

type tls_ExtendedMasterSecretExtension struct {
}

type tls_FakeChannelIDExtension struct {
	OldExtensionID *bool
}

type tls_FakeChannelIDExtension struct {
	OldExtensionID *bool
}

type tls_FakeChannelIDExtension struct {
	OldExtensionID *bool
}

type tls_FakeChannelIDExtension struct {
	OldExtensionID *bool
}

type tls_FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_FakeQUICTransportParameter struct {
	Id	*uint64
	Val	*[]uint8
}

type tls_FakeQUICTransportParameter struct {
	Id	*uint64
	Val	*[]uint8
}

type tls_FakeRecordSizeLimitExtension struct {
	Limit *uint16
}

type tls_FakeRecordSizeLimitExtension struct {
	Limit *uint16
}

type tls_FakeRecordSizeLimitExtension struct {
	Limit *uint16
}

type tls_FakeRecordSizeLimitExtension struct {
	Limit *uint16
}

type tls_FinishedHash struct {
	Client		*hash.Hash
	Server		*hash.Hash
	ClientMD5	*hash.Hash
	ServerMD5	*hash.Hash
	Buffer		*[]uint8
	Version		*uint16
	Prfv2		*interface{}
	Prf		*interface{}
}

type tls_FinishedHash struct {
	Client		*hash.Hash
	Server		*hash.Hash
	ClientMD5	*hash.Hash
	ServerMD5	*hash.Hash
	Buffer		*[]uint8
	Version		*uint16
	Prfv2		*interface{}
	Prf		*interface{}
}

type tls_FinishedHash struct {
	Client		*hash.Hash
	Server		*hash.Hash
	ClientMD5	*hash.Hash
	ServerMD5	*hash.Hash
	Buffer		*[]uint8
	Version		*uint16
	Prfv2		*interface{}
	Prf		*interface{}
}

type tls_FinishedHash struct {
	Client		*hash.Hash
	Server		*hash.Hash
	ClientMD5	*hash.Hash
	ServerMD5	*hash.Hash
	Buffer		*[]uint8
	Version		*uint16
	Prfv2		*interface{}
	Prf		*interface{}
}

type tls_GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites		*[]tls.HPKESymmetricCipherSuite
	cipherSuite			*tls.HPKESymmetricCipherSuite
	CandidateConfigIds		*[]uint8
	configId			*uint8
	EncapsulatedKey			*[]uint8
	CandidatePayloadLens		*[]uint16
	payload				*[]uint8
	initOnce			*sync.Once
	UnimplementedECHExtension	*tls.UnimplementedECHExtension
}

type tls_GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites		*[]tls.HPKESymmetricCipherSuite
	cipherSuite			*tls.HPKESymmetricCipherSuite
	CandidateConfigIds		*[]uint8
	configId			*uint8
	EncapsulatedKey			*[]uint8
	CandidatePayloadLens		*[]uint16
	payload				*[]uint8
	initOnce			*sync.Once
	UnimplementedECHExtension	*tls.UnimplementedECHExtension
}

type tls_GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites		*[]tls.HPKESymmetricCipherSuite
	cipherSuite			*tls.HPKESymmetricCipherSuite
	CandidateConfigIds		*[]uint8
	configId			*uint8
	EncapsulatedKey			*[]uint8
	CandidatePayloadLens		*[]uint16
	payload				*[]uint8
	initOnce			*sync.Once
	UnimplementedECHExtension	*tls.UnimplementedECHExtension
}

type tls_GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites		*[]tls.HPKESymmetricCipherSuite
	cipherSuite			*tls.HPKESymmetricCipherSuite
	CandidateConfigIds		*[]uint8
	configId			*uint8
	EncapsulatedKey			*[]uint8
	CandidatePayloadLens		*[]uint16
	payload				*[]uint8
	initOnce			*sync.Once
	UnimplementedECHExtension	*tls.UnimplementedECHExtension
}

type tls_GREASETransportParameter struct {
	IdOverride	*uint64
	Length		*uint16
	ValueOverride	*[]uint8
}

type tls_GREASETransportParameter struct {
	IdOverride	*uint64
	Length		*uint16
	ValueOverride	*[]uint8
}

type tls_GenericExtension struct {
	Id	*uint16
	Data	*[]uint8
}

type tls_GenericExtension struct {
	Id	*uint16
	Data	*[]uint8
}

type tls_GenericExtension struct {
	Id	*uint16
	Data	*[]uint8
}

type tls_GenericExtension struct {
	Id	*uint16
	Data	*[]uint8
}

type tls_HPKEKeyConfig struct {
	ConfigId	*uint8
	KemId		*uint16
	PublicKey	*kem.PublicKey
	rawPublicKey	*[]uint8
	CipherSuites	*[]tls.HPKESymmetricCipherSuite
}

type tls_HPKEKeyConfig struct {
	ConfigId	*uint8
	KemId		*uint16
	PublicKey	*kem.PublicKey
	rawPublicKey	*[]uint8
	CipherSuites	*[]tls.HPKESymmetricCipherSuite
}

type tls_HPKEKeyConfig struct {
	ConfigId	*uint8
	KemId		*uint16
	PublicKey	*kem.PublicKey
	rawPublicKey	*[]uint8
	CipherSuites	*[]tls.HPKESymmetricCipherSuite
}

type tls_HPKEKeyConfig struct {
	ConfigId	*uint8
	KemId		*uint16
	PublicKey	*kem.PublicKey
	rawPublicKey	*[]uint8
	CipherSuites	*[]tls.HPKESymmetricCipherSuite
}

type tls_HPKESymmetricCipherSuite struct {
	KdfId	*uint16
	AeadId	*uint16
}

type tls_HPKESymmetricCipherSuite struct {
	KdfId	*uint16
	AeadId	*uint16
}

type tls_HPKESymmetricCipherSuite struct {
	KdfId	*uint16
	AeadId	*uint16
}

type tls_HPKESymmetricCipherSuite struct {
	KdfId	*uint16
	AeadId	*uint16
}

type tls_ISessionTicketExtension interface {
}

type tls_ISessionTicketExtension interface {
}

type tls_ISessionTicketExtension interface {
}

type tls_ISessionTicketExtension interface {
}

type tls_InitialMaxData uint64

type tls_InitialMaxData uint64

type tls_InitialMaxStreamDataBidiLocal uint64

type tls_InitialMaxStreamDataBidiLocal uint64

type tls_InitialMaxStreamDataBidiRemote uint64

type tls_InitialMaxStreamDataBidiRemote uint64

type tls_InitialMaxStreamDataUni uint64

type tls_InitialMaxStreamDataUni uint64

type tls_InitialMaxStreamsBidi uint64

type tls_InitialMaxStreamsBidi uint64

type tls_InitialMaxStreamsUni uint64

type tls_InitialMaxStreamsUni uint64

type tls_InitialSourceConnectionID []*uint8

type tls_InitialSourceConnectionID []*uint8

type tls_KemPrivateKey struct {
	SecretKey	*kem.PrivateKey
	CurveID		*tls.CurveID
}

type tls_KemPrivateKey struct {
	SecretKey	*kem.PrivateKey
	CurveID		*tls.CurveID
}

type tls_KemPrivateKey struct {
	SecretKey	*kem.PrivateKey
	CurveID		*tls.CurveID
}

type tls_KemPrivateKey struct {
	SecretKey	*kem.PrivateKey
	CurveID		*tls.CurveID
}

type tls_KeyShare struct {
	Group	*tls.CurveID
	Data	*[]uint8
}

type tls_KeyShare struct {
	Group	*tls.CurveID
	Data	*[]uint8
}

type tls_KeyShare struct {
	Group	*tls.CurveID
	Data	*[]uint8
}

type tls_KeyShare struct {
	Group	*tls.CurveID
	Data	*[]uint8
}

type tls_KeyShareExtension struct {
	KeyShares *[]tls.KeyShare
}

type tls_KeyShareExtension struct {
	KeyShares *[]tls.KeyShare
}

type tls_KeyShareExtension struct {
	KeyShares *[]tls.KeyShare
}

type tls_KeyShareExtension struct {
	KeyShares *[]tls.KeyShare
}

type tls_KeySharePrivateKeys struct {
	CurveID		*tls.CurveID
	Ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_KeySharePrivateKeys struct {
	CurveID		*tls.CurveID
	Ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_KeySharePrivateKeys struct {
	CurveID		*tls.CurveID
	Ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_KeySharePrivateKeys struct {
	CurveID		*tls.CurveID
	Ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_KeySharesParameters struct {
}

type tls_KeySharesParameters struct {
}

type tls_KeySharesParameters struct {
}

type tls_KeySharesParameters struct {
}

type tls_LoadSessionTrackerState int

type tls_LoadSessionTrackerState int

type tls_LoadSessionTrackerState int

type tls_LoadSessionTrackerState int

type tls_MaxAckDelay uint64

type tls_MaxAckDelay uint64

type tls_MaxDatagramFrameSize uint64

type tls_MaxDatagramFrameSize uint64

type tls_MaxIdleTimeout uint64

type tls_MaxIdleTimeout uint64

type tls_MaxUDPPayloadSize uint64

type tls_MaxUDPPayloadSize uint64

type tls_NPNExtension struct {
	NextProtos *[]string
}

type tls_NPNExtension struct {
	NextProtos *[]string
}

type tls_NPNExtension struct {
	NextProtos *[]string
}

type tls_NPNExtension struct {
	NextProtos *[]string
}

type tls_PRNGSeed [32]*uint8

type tls_PRNGSeed [32]*uint8

type tls_PRNGSeed [32]*uint8

type tls_PRNGSeed [32]*uint8

type tls_PSKKeyExchangeModesExtension struct {
	Modes *[]uint8
}

type tls_PSKKeyExchangeModesExtension struct {
	Modes *[]uint8
}

type tls_PSKKeyExchangeModesExtension struct {
	Modes *[]uint8
}

type tls_PSKKeyExchangeModesExtension struct {
	Modes *[]uint8
}

type tls_PreSharedKeyCommon struct {
	Identities	*[]tls.PskIdentity
	Binders		*[][]uint8
	BinderKey	*[]uint8
	EarlySecret	*[]uint8
	Session		*tls.SessionState
}

type tls_PreSharedKeyCommon struct {
	Identities	*[]tls.PskIdentity
	Binders		*[][]uint8
	BinderKey	*[]uint8
	EarlySecret	*[]uint8
	Session		*tls.SessionState
}

type tls_PreSharedKeyCommon struct {
	Identities	*[]tls.PskIdentity
	Binders		*[][]uint8
	BinderKey	*[]uint8
	EarlySecret	*[]uint8
	Session		*tls.SessionState
}

type tls_PreSharedKeyCommon struct {
	Identities	*[]tls.PskIdentity
	Binders		*[][]uint8
	BinderKey	*[]uint8
	EarlySecret	*[]uint8
	Session		*tls.SessionState
}

type tls_PreSharedKeyExtension interface {
}

type tls_PreSharedKeyExtension interface {
}

type tls_PreSharedKeyExtension interface {
}

type tls_PreSharedKeyExtension interface {
}

type tls_PskIdentity struct {
	Label			*[]uint8
	ObfuscatedTicketAge	*uint32
}

type tls_PskIdentity struct {
	Label			*[]uint8
	ObfuscatedTicketAge	*uint32
}

type tls_PskIdentity struct {
	Label			*[]uint8
	ObfuscatedTicketAge	*uint32
}

type tls_PskIdentity struct {
	Label			*[]uint8
	ObfuscatedTicketAge	*uint32
}

type tls_PubCipherSuite struct {
	Id	*uint16
	KeyLen	*int
	MacLen	*int
	IvLen	*int
	Ka	*func(uint16) tls.keyAgreement
	Flags	*int
	Cipher	*func([]uint8, []uint8, bool) interface {}
	Mac	*func([]uint8) hash.Hash
	Aead	*func([]uint8, []uint8) tls.aead
}

type tls_PubCipherSuite struct {
	Id	*uint16
	KeyLen	*int
	MacLen	*int
	IvLen	*int
	Ka	*func(uint16) tls.keyAgreement
	Flags	*int
	Cipher	*func([]uint8, []uint8, bool) interface {}
	Mac	*func([]uint8) hash.Hash
	Aead	*func([]uint8, []uint8) tls.aead
}

type tls_PubCipherSuite struct {
	Id	*uint16
	KeyLen	*int
	MacLen	*int
	IvLen	*int
	Ka	*func(uint16) tls.keyAgreement
	Flags	*int
	Cipher	*func([]uint8, []uint8, bool) interface {}
	Mac	*func([]uint8) hash.Hash
	Aead	*func([]uint8, []uint8) tls.aead
}

type tls_PubCipherSuite struct {
	Id	*uint16
	KeyLen	*int
	MacLen	*int
	IvLen	*int
	Ka	*func(uint16) tls.keyAgreement
	Flags	*int
	Cipher	*func([]uint8, []uint8, bool) interface {}
	Mac	*func([]uint8) hash.Hash
	Aead	*func([]uint8, []uint8) tls.aead
}

type tls_PubCipherSuiteTLS13 struct {
	Id	*uint16
	KeyLen	*int
	Aead	*func([]uint8, []uint8) tls.aead
	Hash	*crypto.Hash
}

type tls_PubCipherSuiteTLS13 struct {
	Id	*uint16
	KeyLen	*int
	Aead	*func([]uint8, []uint8) tls.aead
	Hash	*crypto.Hash
}

type tls_PubCipherSuiteTLS13 struct {
	Id	*uint16
	KeyLen	*int
	Aead	*func([]uint8, []uint8) tls.aead
	Hash	*crypto.Hash
}

type tls_PubCipherSuiteTLS13 struct {
	Id	*uint16
	KeyLen	*int
	Aead	*func([]uint8, []uint8) tls.aead
	Hash	*crypto.Hash
}

type tls_PubClientHandshakeState struct {
	C		*tls.Conn
	ServerHello	*tls.PubServerHelloMsg
	Hello		*tls.PubClientHelloMsg
	MasterSecret	*[]uint8
	Session		*tls.SessionState
	State12		*tls.TLS12OnlyState
	State13		*tls.TLS13OnlyState
	uconn		*tls.UConn
}

type tls_PubClientHandshakeState struct {
	C		*tls.Conn
	ServerHello	*tls.PubServerHelloMsg
	Hello		*tls.PubClientHelloMsg
	MasterSecret	*[]uint8
	Session		*tls.SessionState
	State12		*tls.TLS12OnlyState
	State13		*tls.TLS13OnlyState
	uconn		*tls.UConn
}

type tls_PubClientHandshakeState struct {
	C		*tls.Conn
	ServerHello	*tls.PubServerHelloMsg
	Hello		*tls.PubClientHelloMsg
	MasterSecret	*[]uint8
	Session		*tls.SessionState
	State12		*tls.TLS12OnlyState
	State13		*tls.TLS13OnlyState
	uconn		*tls.UConn
}

type tls_PubClientHandshakeState struct {
	C		*tls.Conn
	ServerHello	*tls.PubServerHelloMsg
	Hello		*tls.PubClientHelloMsg
	MasterSecret	*[]uint8
	Session		*tls.SessionState
	State12		*tls.TLS12OnlyState
	State13		*tls.TLS13OnlyState
	uconn		*tls.UConn
}

type tls_PubClientHelloMsg struct {
	Raw					*[]uint8
	Vers					*uint16
	Random					*[]uint8
	SessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	NextProtoNeg				*bool
	ServerName				*string
	OcspStapling				*bool
	Scts					*bool
	Ems					*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SecureRenegotiation			*[]uint8
	SecureRenegotiationSupported		*bool
	AlpnProtocols				*[]string
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SupportedVersions			*[]uint16
	Cookie					*[]uint8
	KeyShares				*[]tls.KeyShare
	EarlyData				*bool
	PskModes				*[]uint8
	PskIdentities				*[]tls.PskIdentity
	PskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	cachedPrivateHello			*interface{}
	encryptedClientHello			*[]uint8
}

type tls_PubClientHelloMsg struct {
	Raw					*[]uint8
	Vers					*uint16
	Random					*[]uint8
	SessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	NextProtoNeg				*bool
	ServerName				*string
	OcspStapling				*bool
	Scts					*bool
	Ems					*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SecureRenegotiation			*[]uint8
	SecureRenegotiationSupported		*bool
	AlpnProtocols				*[]string
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SupportedVersions			*[]uint16
	Cookie					*[]uint8
	KeyShares				*[]tls.KeyShare
	EarlyData				*bool
	PskModes				*[]uint8
	PskIdentities				*[]tls.PskIdentity
	PskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	cachedPrivateHello			*interface{}
	encryptedClientHello			*[]uint8
}

type tls_PubClientHelloMsg struct {
	Raw					*[]uint8
	Vers					*uint16
	Random					*[]uint8
	SessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	NextProtoNeg				*bool
	ServerName				*string
	OcspStapling				*bool
	Scts					*bool
	Ems					*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SecureRenegotiation			*[]uint8
	SecureRenegotiationSupported		*bool
	AlpnProtocols				*[]string
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SupportedVersions			*[]uint16
	Cookie					*[]uint8
	KeyShares				*[]tls.KeyShare
	EarlyData				*bool
	PskModes				*[]uint8
	PskIdentities				*[]tls.PskIdentity
	PskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	cachedPrivateHello			*interface{}
	encryptedClientHello			*[]uint8
}

type tls_PubClientHelloMsg struct {
	Raw					*[]uint8
	Vers					*uint16
	Random					*[]uint8
	SessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	NextProtoNeg				*bool
	ServerName				*string
	OcspStapling				*bool
	Scts					*bool
	Ems					*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SecureRenegotiation			*[]uint8
	SecureRenegotiationSupported		*bool
	AlpnProtocols				*[]string
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SupportedVersions			*[]uint16
	Cookie					*[]uint8
	KeyShares				*[]tls.KeyShare
	EarlyData				*bool
	PskModes				*[]uint8
	PskIdentities				*[]tls.PskIdentity
	PskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	cachedPrivateHello			*interface{}
	encryptedClientHello			*[]uint8
}

type tls_PubServerHelloMsg struct {
	Raw				*[]uint8
	Vers				*uint16
	Random				*[]uint8
	SessionId			*[]uint8
	CipherSuite			*uint16
	CompressionMethod		*uint8
	NextProtoNeg			*bool
	NextProtos			*[]string
	OcspStapling			*bool
	Scts				*[][]uint8
	ExtendedMasterSecret		*bool
	TicketSupported			*bool
	SecureRenegotiation		*[]uint8
	SecureRenegotiationSupported	*bool
	AlpnProtocol			*string
	SupportedVersion		*uint16
	ServerShare			*interface{}
	SelectedIdentityPresent		*bool
	SelectedIdentity		*uint16
	Cookie				*[]uint8
	SelectedGroup			*tls.CurveID
}

type tls_PubServerHelloMsg struct {
	Raw				*[]uint8
	Vers				*uint16
	Random				*[]uint8
	SessionId			*[]uint8
	CipherSuite			*uint16
	CompressionMethod		*uint8
	NextProtoNeg			*bool
	NextProtos			*[]string
	OcspStapling			*bool
	Scts				*[][]uint8
	ExtendedMasterSecret		*bool
	TicketSupported			*bool
	SecureRenegotiation		*[]uint8
	SecureRenegotiationSupported	*bool
	AlpnProtocol			*string
	SupportedVersion		*uint16
	ServerShare			*interface{}
	SelectedIdentityPresent		*bool
	SelectedIdentity		*uint16
	Cookie				*[]uint8
	SelectedGroup			*tls.CurveID
}

type tls_PubServerHelloMsg struct {
	Raw				*[]uint8
	Vers				*uint16
	Random				*[]uint8
	SessionId			*[]uint8
	CipherSuite			*uint16
	CompressionMethod		*uint8
	NextProtoNeg			*bool
	NextProtos			*[]string
	OcspStapling			*bool
	Scts				*[][]uint8
	ExtendedMasterSecret		*bool
	TicketSupported			*bool
	SecureRenegotiation		*[]uint8
	SecureRenegotiationSupported	*bool
	AlpnProtocol			*string
	SupportedVersion		*uint16
	ServerShare			*interface{}
	SelectedIdentityPresent		*bool
	SelectedIdentity		*uint16
	Cookie				*[]uint8
	SelectedGroup			*tls.CurveID
}

type tls_PubServerHelloMsg struct {
	Raw				*[]uint8
	Vers				*uint16
	Random				*[]uint8
	SessionId			*[]uint8
	CipherSuite			*uint16
	CompressionMethod		*uint8
	NextProtoNeg			*bool
	NextProtos			*[]string
	OcspStapling			*bool
	Scts				*[][]uint8
	ExtendedMasterSecret		*bool
	TicketSupported			*bool
	SecureRenegotiation		*[]uint8
	SecureRenegotiationSupported	*bool
	AlpnProtocol			*string
	SupportedVersion		*uint16
	ServerShare			*interface{}
	SelectedIdentityPresent		*bool
	SelectedIdentity		*uint16
	Cookie				*[]uint8
	SelectedGroup			*tls.CurveID
}

type tls_QUICConn struct {
	conn			*tls.Conn
	sessionTicketSent	*bool
}

type tls_QUICConn struct {
	conn			*tls.Conn
	sessionTicketSent	*bool
}

type tls_QUICEncryptionLevel int

type tls_QUICEncryptionLevel int

type tls_QUICEncryptionLevel int

type tls_QUICEncryptionLevel int

type tls_QUICEncryptionLevel int

type tls_QUICEncryptionLevel int

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEvent struct {
	Kind		*tls.QUICEventKind
	Level		*tls.QUICEncryptionLevel
	Data		*[]uint8
	Suite		*uint16
	SessionState	*tls.SessionState
}

type tls_QUICEventKind int

type tls_QUICEventKind int

type tls_QUICEventKind int

type tls_QUICEventKind int

type tls_QUICEventKind int

type tls_QUICEventKind int

type tls_QUICTransportParametersExtension struct {
	TransportParameters	*tls.TransportParameters
	marshalResult		*[]uint8
}

type tls_QUICTransportParametersExtension struct {
	TransportParameters	*tls.TransportParameters
	marshalResult		*[]uint8
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RecordHeaderError struct {
	Msg		*string
	RecordHeader	*[5]uint8
	Conn		*net.Conn
}

type tls_RenegotiationInfoExtension struct {
	Renegotiation		*tls.RenegotiationSupport
	RenegotiatedConnection	*[]uint8
}

type tls_RenegotiationInfoExtension struct {
	Renegotiation		*tls.RenegotiationSupport
	RenegotiatedConnection	*[]uint8
}

type tls_RenegotiationInfoExtension struct {
	Renegotiation		*tls.RenegotiationSupport
	RenegotiatedConnection	*[]uint8
}

type tls_RenegotiationInfoExtension struct {
	Renegotiation		*tls.RenegotiationSupport
	RenegotiatedConnection	*[]uint8
}

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_RenegotiationSupport int

type tls_SCTExtension struct {
}

type tls_SCTExtension struct {
}

type tls_SCTExtension struct {
}

type tls_SCTExtension struct {
}

type tls_SNIExtension struct {
	ServerName *string
}

type tls_SNIExtension struct {
	ServerName *string
}

type tls_SNIExtension struct {
	ServerName *string
}

type tls_SNIExtension struct {
	ServerName *string
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
	curveID			*tls.CurveID
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	activeCertHandles	*[]*tls.activeCert
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
}

type tls_SessionState struct {
	Extra			*[][]uint8
	EarlyData		*bool
	version			*uint16
	isClient		*bool
	cipherSuite		*uint16
	createdAt		*uint64
	secret			*[]uint8
	extMasterSecret		*bool
	peerCertificates	*[]*x509.Certificate
	ocspResponse		*[]uint8
	scts			*[][]uint8
	verifiedChains		*[][]*x509.Certificate
	alpnProtocol		*string
	useBy			*uint64
	ageAdd			*uint32
	ticket			*[]uint8
	curveID			*tls.CurveID
}

type tls_SessionTicketExtension struct {
	Session		*tls.SessionState
	Ticket		*[]uint8
	Initialized	*bool
}

type tls_SessionTicketExtension struct {
	Session		*tls.SessionState
	Ticket		*[]uint8
	Initialized	*bool
}

type tls_SessionTicketExtension struct {
	Session		*tls.SessionState
	Ticket		*[]uint8
	Initialized	*bool
}

type tls_SessionTicketExtension struct {
	Session		*tls.SessionState
	Ticket		*[]uint8
	Initialized	*bool
}

type tls_SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms *[]tls.SignatureScheme
}

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_SignatureScheme uint16

type tls_StatusRequestExtension struct {
}

type tls_StatusRequestExtension struct {
}

type tls_StatusRequestExtension struct {
}

type tls_StatusRequestExtension struct {
}

type tls_SupportedCurvesExtension struct {
	Curves *[]tls.CurveID
}

type tls_SupportedCurvesExtension struct {
	Curves *[]tls.CurveID
}

type tls_SupportedCurvesExtension struct {
	Curves *[]tls.CurveID
}

type tls_SupportedCurvesExtension struct {
	Curves *[]tls.CurveID
}

type tls_SupportedPointsExtension struct {
	SupportedPoints *[]uint8
}

type tls_SupportedPointsExtension struct {
	SupportedPoints *[]uint8
}

type tls_SupportedPointsExtension struct {
	SupportedPoints *[]uint8
}

type tls_SupportedPointsExtension struct {
	SupportedPoints *[]uint8
}

type tls_SupportedVersionsExtension struct {
	Versions *[]uint16
}

type tls_SupportedVersionsExtension struct {
	Versions *[]uint16
}

type tls_SupportedVersionsExtension struct {
	Versions *[]uint16
}

type tls_SupportedVersionsExtension struct {
	Versions *[]uint16
}

type tls_TLS12OnlyState struct {
	FinishedHash	*tls.FinishedHash
	Suite		*tls.PubCipherSuite
}

type tls_TLS12OnlyState struct {
	FinishedHash	*tls.FinishedHash
	Suite		*tls.PubCipherSuite
}

type tls_TLS12OnlyState struct {
	FinishedHash	*tls.FinishedHash
	Suite		*tls.PubCipherSuite
}

type tls_TLS12OnlyState struct {
	FinishedHash	*tls.FinishedHash
	Suite		*tls.PubCipherSuite
}

type tls_TLS13OnlyState struct {
	EcdheKey	*ecdh.PrivateKey
	KeySharesParams	*tls.KeySharesParameters
	KEMKey		*tls.KemPrivateKey
	KeyShareKeys	*tls.KeySharePrivateKeys
	Suite		*tls.PubCipherSuiteTLS13
	EarlySecret	*[]uint8
	BinderKey	*[]uint8
	CertReq		*tls.CertificateRequestMsgTLS13
	UsingPSK	*bool
	SentDummyCCS	*bool
	Transcript	*hash.Hash
	TrafficSecret	*[]uint8
}

type tls_TLS13OnlyState struct {
	EcdheKey	*ecdh.PrivateKey
	KeySharesParams	*tls.KeySharesParameters
	KEMKey		*tls.KemPrivateKey
	KeyShareKeys	*tls.KeySharePrivateKeys
	Suite		*tls.PubCipherSuiteTLS13
	EarlySecret	*[]uint8
	BinderKey	*[]uint8
	CertReq		*tls.CertificateRequestMsgTLS13
	UsingPSK	*bool
	SentDummyCCS	*bool
	Transcript	*hash.Hash
	TrafficSecret	*[]uint8
}

type tls_TLS13OnlyState struct {
	EcdheKey	*ecdh.PrivateKey
	KeySharesParams	*tls.KeySharesParameters
	KEMKey		*tls.KemPrivateKey
	KeyShareKeys	*tls.KeySharePrivateKeys
	Suite		*tls.PubCipherSuiteTLS13
	EarlySecret	*[]uint8
	BinderKey	*[]uint8
	CertReq		*tls.CertificateRequestMsgTLS13
	UsingPSK	*bool
	SentDummyCCS	*bool
	Transcript	*hash.Hash
	TrafficSecret	*[]uint8
}

type tls_TLS13OnlyState struct {
	EcdheKey	*ecdh.PrivateKey
	KeySharesParams	*tls.KeySharesParameters
	KEMKey		*tls.KemPrivateKey
	KeyShareKeys	*tls.KeySharePrivateKeys
	Suite		*tls.PubCipherSuiteTLS13
	EarlySecret	*[]uint8
	BinderKey	*[]uint8
	CertReq		*tls.CertificateRequestMsgTLS13
	UsingPSK	*bool
	SentDummyCCS	*bool
	Transcript	*hash.Hash
	TrafficSecret	*[]uint8
}

type tls_TLSExtension interface {
}

type tls_TLSExtension interface {
}

type tls_TLSExtension interface {
}

type tls_TLSExtension interface {
}

type tls_TransportParameter interface {
}

type tls_TransportParameter interface {
}

type tls_TransportParameters []*tls.TransportParameter

type tls_TransportParameters []*tls.TransportParameter

type tls_UConn struct {
	Conn				*tls.Conn
	Extensions			*[]tls.TLSExtension
	ClientHelloID			*tls.ClientHelloID
	sessionController		*interface{}
	clientHelloBuildStatus		*tls.ClientHelloBuildStatus
	clientHelloSpec			*tls.ClientHelloSpec
	HandshakeState			*tls.PubClientHandshakeState
	greaseSeed			*[5]uint16
	omitSNIExtension		*bool
	WithRandomTLSExtensionOrder	*bool
	WithForceHttp1			*bool
	WithDisableHttp3		*bool
	skipResumptionOnNilExtension	*bool
	certCompressionAlgs		*[]tls.CertCompressionAlgo
	ech				*tls.EncryptedClientHelloExtension
	echCtx				*interface{}
}

type tls_UConn struct {
	Conn				*tls.Conn
	Extensions			*[]tls.TLSExtension
	ClientHelloID			*tls.ClientHelloID
	sessionController		*interface{}
	clientHelloBuildStatus		*tls.ClientHelloBuildStatus
	clientHelloSpec			*tls.ClientHelloSpec
	HandshakeState			*tls.PubClientHandshakeState
	greaseSeed			*[5]uint16
	omitSNIExtension		*bool
	skipResumptionOnNilExtension	*bool
	certCompressionAlgs		*[]tls.CertCompressionAlgo
	ech				*tls.EncryptedClientHelloExtension
	echCtx				*interface{}
}

type tls_UConn struct {
	Conn				*tls.Conn
	Extensions			*[]tls.TLSExtension
	ClientHelloID			*tls.ClientHelloID
	sessionController		*interface{}
	clientHelloBuildStatus		*tls.ClientHelloBuildStatus
	clientHelloSpec			*tls.ClientHelloSpec
	HandshakeState			*tls.PubClientHandshakeState
	greaseSeed			*[5]uint16
	omitSNIExtension		*bool
	skipResumptionOnNilExtension	*bool
	certCompressionAlgs		*[]tls.CertCompressionAlgo
	ech				*tls.EncryptedClientHelloExtension
	echCtx				*interface{}
}

type tls_UConn struct {
	Conn				*tls.Conn
	Extensions			*[]tls.TLSExtension
	ClientHelloID			*tls.ClientHelloID
	sessionController		*interface{}
	clientHelloBuildStatus		*tls.ClientHelloBuildStatus
	clientHelloSpec			*tls.ClientHelloSpec
	HandshakeState			*tls.PubClientHandshakeState
	greaseSeed			*[5]uint16
	omitSNIExtension		*bool
	WithRandomTLSExtensionOrder	*bool
	WithForceHttp1			*bool
	WithDisableHttp3		*bool
	skipResumptionOnNilExtension	*bool
	certCompressionAlgs		*[]tls.CertCompressionAlgo
	ech				*tls.EncryptedClientHelloExtension
	echCtx				*interface{}
}

type tls_UQUICConn struct {
	conn			*tls.UConn
	sessionTicketSent	*bool
}

type tls_UQUICConn struct {
	conn			*tls.UConn
	sessionTicketSent	*bool
}

type tls_UnimplementedECHExtension struct {
}

type tls_UnimplementedECHExtension struct {
}

type tls_UnimplementedECHExtension struct {
}

type tls_UnimplementedECHExtension struct {
}

type tls_UnimplementedPreSharedKeyExtension struct {
}

type tls_UnimplementedPreSharedKeyExtension struct {
}

type tls_UnimplementedPreSharedKeyExtension struct {
}

type tls_UnimplementedPreSharedKeyExtension struct {
}

type tls_UtlsCompressCertExtension struct {
	Algorithms *[]tls.CertCompressionAlgo
}

type tls_UtlsCompressCertExtension struct {
	Algorithms *[]tls.CertCompressionAlgo
}

type tls_UtlsCompressCertExtension struct {
	Algorithms *[]tls.CertCompressionAlgo
}

type tls_UtlsCompressCertExtension struct {
	Algorithms *[]tls.CertCompressionAlgo
}

type tls_UtlsGREASEExtension struct {
	Value	*uint16
	Body	*[]uint8
}

type tls_UtlsGREASEExtension struct {
	Value	*uint16
	Body	*[]uint8
}

type tls_UtlsGREASEExtension struct {
	Value	*uint16
	Body	*[]uint8
}

type tls_UtlsGREASEExtension struct {
	Value	*uint16
	Body	*[]uint8
}

type tls_UtlsPaddingExtension struct {
	PaddingLen	*int
	WillPad		*bool
	GetPaddingLen	*func(int) (int, bool)
}

type tls_UtlsPaddingExtension struct {
	PaddingLen	*int
	WillPad		*bool
	GetPaddingLen	*func(int) (int, bool)
}

type tls_UtlsPaddingExtension struct {
	PaddingLen	*int
	WillPad		*bool
	GetPaddingLen	*func(int) (int, bool)
}

type tls_UtlsPaddingExtension struct {
	PaddingLen	*int
	WillPad		*bool
	GetPaddingLen	*func(int) (int, bool)
}

type tls_UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension	*tls.UnimplementedPreSharedKeyExtension
	PreSharedKeyCommon			*tls.PreSharedKeyCommon
	cipherSuite				*interface{}
	cachedLength				*int
	OmitEmptyPsk				*bool
}

type tls_UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension	*tls.UnimplementedPreSharedKeyExtension
	PreSharedKeyCommon			*tls.PreSharedKeyCommon
	cipherSuite				*interface{}
	cachedLength				*int
	OmitEmptyPsk				*bool
}

type tls_UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension	*tls.UnimplementedPreSharedKeyExtension
	PreSharedKeyCommon			*tls.PreSharedKeyCommon
	cipherSuite				*interface{}
	cachedLength				*int
	OmitEmptyPsk				*bool
}

type tls_UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension	*tls.UnimplementedPreSharedKeyExtension
	PreSharedKeyCommon			*tls.PreSharedKeyCommon
	cipherSuite				*interface{}
	cachedLength				*int
	OmitEmptyPsk				*bool
}

type tls_VersionInformation struct {
	ChoosenVersion		*uint32
	AvailableVersions	*[]uint32
	LegacyID		*bool
}

type tls_VersionInformation struct {
	ChoosenVersion		*uint32
	AvailableVersions	*[]uint32
	LegacyID		*bool
}

type tls_Weights struct {
	Extensions_Append_ALPN					*float64
	TLSVersMax_Set_VersionTLS13				*float64
	CipherSuites_Remove_RandomCiphers			*float64
	SigAndHashAlgos_Append_ECDSAWithSHA1			*float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512		*float64
	SigAndHashAlgos_Append_PSSWithSHA256			*float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512	*float64
	CurveIDs_Append_X25519					*float64
	CurveIDs_Append_CurveP521				*float64
	Extensions_Append_Padding				*float64
	Extensions_Append_Status				*float64
	Extensions_Append_SCT					*float64
	Extensions_Append_Reneg					*float64
	Extensions_Append_EMS					*float64
	FirstKeyShare_Set_CurveP256				*float64
	Extensions_Append_ALPS_Old				*float64
	Extensions_Append_ALPS					*float64
}

type tls_Weights struct {
	Extensions_Append_ALPN					*float64
	TLSVersMax_Set_VersionTLS13				*float64
	CipherSuites_Remove_RandomCiphers			*float64
	SigAndHashAlgos_Append_ECDSAWithSHA1			*float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512		*float64
	SigAndHashAlgos_Append_PSSWithSHA256			*float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512	*float64
	CurveIDs_Append_X25519					*float64
	CurveIDs_Append_CurveP521				*float64
	Extensions_Append_Padding				*float64
	Extensions_Append_Status				*float64
	Extensions_Append_SCT					*float64
	Extensions_Append_Reneg					*float64
	Extensions_Append_EMS					*float64
	FirstKeyShare_Set_CurveP256				*float64
	Extensions_Append_ALPS_Old				*float64
	Extensions_Append_ALPS					*float64
}

type tls_Weights struct {
	Extensions_Append_ALPN					*float64
	TLSVersMax_Set_VersionTLS13				*float64
	CipherSuites_Remove_RandomCiphers			*float64
	SigAndHashAlgos_Append_ECDSAWithSHA1			*float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512		*float64
	SigAndHashAlgos_Append_PSSWithSHA256			*float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512	*float64
	CurveIDs_Append_X25519					*float64
	CurveIDs_Append_CurveP521				*float64
	Extensions_Append_Padding				*float64
	Extensions_Append_Status				*float64
	Extensions_Append_SCT					*float64
	Extensions_Append_Reneg					*float64
	Extensions_Append_EMS					*float64
	FirstKeyShare_Set_CurveP256				*float64
	Extensions_Append_ALPS					*float64
}

type tls_Weights struct {
	Extensions_Append_ALPN					*float64
	TLSVersMax_Set_VersionTLS13				*float64
	CipherSuites_Remove_RandomCiphers			*float64
	SigAndHashAlgos_Append_ECDSAWithSHA1			*float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512		*float64
	SigAndHashAlgos_Append_PSSWithSHA256			*float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512	*float64
	CurveIDs_Append_X25519					*float64
	CurveIDs_Append_CurveP521				*float64
	Extensions_Append_Padding				*float64
	Extensions_Append_Status				*float64
	Extensions_Append_SCT					*float64
	Extensions_Append_Reneg					*float64
	Extensions_Append_EMS					*float64
	FirstKeyShare_Set_CurveP256				*float64
	Extensions_Append_ALPS					*float64
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_activeCert struct {
	cert *x509.Certificate
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_aead interface {
}

type tls_alert uint8

type tls_alert uint8

type tls_alert uint8

type tls_alert uint8

type tls_alert uint8

type tls_alert uint8

type tls_applicationSettingsExtension struct {
	codePoint *uint16
}

type tls_applicationSettingsExtension struct {
	codePoint *uint16
}

type tls_applicationSettingsExtension struct {
	codePoint *uint16
}

type tls_applicationSettingsExtension struct {
	codePoint *uint16
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_atLeastReader struct {
	R	*io.Reader
	N	*int64
}

type tls_binaryMarshaler interface {
}

type tls_binaryMarshaler interface {
}

type tls_binaryMarshaler interface {
}

type tls_binaryMarshaler interface {
}

type tls_binaryMarshaler interface {
}

type tls_binaryMarshaler interface {
}

type tls_cacheEntry struct {
	refs	*atomic.Int64
	cert	*x509.Certificate
}

type tls_cacheEntry struct {
	refs	*atomic.Int64
	cert	*x509.Certificate
}

type tls_cacheEntry struct {
	refs	*atomic.Int64
	cert	*x509.Certificate
}

type tls_cacheEntry struct {
	refs	*atomic.Int64
	cert	*x509.Certificate
}

type tls_cbcMode interface {
}

type tls_cbcMode interface {
}

type tls_cbcMode interface {
}

type tls_cbcMode interface {
}

type tls_cbcMode interface {
}

type tls_cbcMode interface {
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certCache struct {
	Map *sync.Map
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsg struct {
	certificates *[][]uint8
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateMsgTLS13 struct {
	certificate	*tls.Certificate
	ocspStapling	*bool
	scts		*bool
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsg struct {
	hasSignatureAlgorithm		*bool
	certificateTypes		*[]uint8
	supportedSignatureAlgorithms	*[]tls.SignatureScheme
	certificateAuthorities		*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateRequestMsgTLS13 struct {
	ocspStapling				*bool
	scts					*bool
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	certificateAuthorities			*[][]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateStatusMsg struct {
	response *[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_certificateVerifyMsg struct {
	hasSignatureAlgorithm	*bool
	signatureAlgorithm	*tls.SignatureScheme
	signature		*[]uint8
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuite struct {
	id	*uint16
	keyLen	*int
	macLen	*int
	ivLen	*int
	ka	*func(uint16) tls.keyAgreement
	flags	*int
	cipher	*func([]uint8, []uint8, bool) interface {}
	mac	*func([]uint8) hash.Hash
	aead	*func([]uint8, []uint8) tls.aead
}

type tls_cipherSuiteTLS13 struct {
	id	*uint16
	keyLen	*int
	aead	*func([]uint8, []uint8) tls.aead
	hash	*crypto.Hash
}

type tls_cipherSuiteTLS13 struct {
	id	*uint16
	keyLen	*int
	aead	*func([]uint8, []uint8) tls.aead
	hash	*crypto.Hash
}

type tls_cipherSuiteTLS13 struct {
	id	*uint16
	keyLen	*int
	aead	*func([]uint8, []uint8) tls.aead
	hash	*crypto.Hash
}

type tls_cipherSuiteTLS13 struct {
	id	*uint16
	keyLen	*int
	aead	*func([]uint8, []uint8) tls.aead
	hash	*crypto.Hash
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
	uconn		*tls.UConn
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
	uconn		*tls.UConn
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
	uconn		*tls.UConn
}

type tls_clientHandshakeState struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	suite		*interface{}
	finishedHash	*interface{}
	masterSecret	*[]uint8
	session		*tls.SessionState
	ticket		*[]uint8
	uconn		*tls.UConn
}

type tls_clientHandshakeStateTLS13 struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	keyShareKeys	*interface{}
	session		*tls.SessionState
	earlySecret	*tls13.EarlySecret
	binderKey	*[]uint8
	certReq		*interface{}
	usingPSK	*bool
	sentDummyCCS	*bool
	suite		*interface{}
	transcript	*hash.Hash
	masterSecret	*tls13.MasterSecret
	trafficSecret	*[]uint8
	echContext	*interface{}
	uconn		*tls.UConn
}

type tls_clientHandshakeStateTLS13 struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	keyShareKeys	*interface{}
	session		*tls.SessionState
	earlySecret	*tls13.EarlySecret
	binderKey	*[]uint8
	certReq		*interface{}
	usingPSK	*bool
	sentDummyCCS	*bool
	suite		*interface{}
	transcript	*hash.Hash
	masterSecret	*tls13.MasterSecret
	trafficSecret	*[]uint8
	echContext	*interface{}
	uconn		*tls.UConn
}

type tls_clientHandshakeStateTLS13 struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	keyShareKeys	*interface{}
	session		*tls.SessionState
	earlySecret	*tls13.EarlySecret
	binderKey	*[]uint8
	certReq		*interface{}
	usingPSK	*bool
	sentDummyCCS	*bool
	suite		*interface{}
	transcript	*hash.Hash
	masterSecret	*tls13.MasterSecret
	trafficSecret	*[]uint8
	echContext	*interface{}
	uconn		*tls.UConn
}

type tls_clientHandshakeStateTLS13 struct {
	c		*tls.Conn
	ctx		*context.Context
	serverHello	*interface{}
	hello		*interface{}
	keyShareKeys	*interface{}
	session		*tls.SessionState
	earlySecret	*tls13.EarlySecret
	binderKey	*[]uint8
	certReq		*interface{}
	usingPSK	*bool
	sentDummyCCS	*bool
	suite		*interface{}
	transcript	*hash.Hash
	masterSecret	*tls13.MasterSecret
	trafficSecret	*[]uint8
	echContext	*interface{}
	uconn		*tls.UConn
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
	nextProtoNeg				*bool
}

type tls_clientHelloMsg struct {
	Original				*[]uint8
	Vers					*uint16
	Random					*[]uint8
	sessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	ServerName				*string
	OcspStapling				*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SecureRenegotiationSupported		*bool
	SecureRenegotiation			*[]uint8
	ExtendedMasterSecret			*bool
	AlpnProtocols				*[]string
	scts					*bool
	SupportedVersions			*[]uint16
	cookie					*[]uint8
	KeyShares				*[]tls.keyShare
	EarlyData				*bool
	pskModes				*[]uint8
	PskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	EncryptedClientHello			*[]uint8
	Extensions				*[]uint16
	NextProtoNeg				*bool
	Raw					*[]uint8
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
	nextProtoNeg				*bool
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
	nextProtoNeg				*bool
}

type tls_clientHelloMsg struct {
	original				*[]uint8
	vers					*uint16
	random					*[]uint8
	sessionId				*[]uint8
	cipherSuites				*[]uint16
	compressionMethods			*[]uint8
	serverName				*string
	ocspStapling				*bool
	supportedCurves				*[]tls.CurveID
	supportedPoints				*[]uint8
	ticketSupported				*bool
	sessionTicket				*[]uint8
	supportedSignatureAlgorithms		*[]tls.SignatureScheme
	supportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	secureRenegotiationSupported		*bool
	secureRenegotiation			*[]uint8
	extendedMasterSecret			*bool
	alpnProtocols				*[]string
	scts					*bool
	supportedVersions			*[]uint16
	cookie					*[]uint8
	keyShares				*[]tls.keyShare
	earlyData				*bool
	pskModes				*[]uint8
	pskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	quicTransportParameters			*[]uint8
	encryptedClientHello			*[]uint8
	extensions				*[]uint16
	nextProtoNeg				*bool
}

type tls_clientHelloMsg struct {
	Original				*[]uint8
	Vers					*uint16
	Random					*[]uint8
	sessionId				*[]uint8
	CipherSuites				*[]uint16
	CompressionMethods			*[]uint8
	ServerName				*string
	OcspStapling				*bool
	SupportedCurves				*[]tls.CurveID
	SupportedPoints				*[]uint8
	TicketSupported				*bool
	SessionTicket				*[]uint8
	SupportedSignatureAlgorithms		*[]tls.SignatureScheme
	SupportedSignatureAlgorithmsCert	*[]tls.SignatureScheme
	SecureRenegotiationSupported		*bool
	SecureRenegotiation			*[]uint8
	ExtendedMasterSecret			*bool
	AlpnProtocols				*[]string
	scts					*bool
	SupportedVersions			*[]uint16
	cookie					*[]uint8
	KeyShares				*[]tls.keyShare
	EarlyData				*bool
	pskModes				*[]uint8
	PskIdentities				*[]tls.pskIdentity
	pskBinders				*[][]uint8
	QuicTransportParameters			*[]uint8
	EncryptedClientHello			*[]uint8
	Extensions				*[]uint16
	NextProtoNeg				*bool
	Raw					*[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_clientKeyExchangeMsg struct {
	ciphertext *[]uint8
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_constantTimeHash interface {
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_cthWrapper struct {
	h *interface{}
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_ecdheKeyAgreement struct {
	version			*uint16
	isRSA			*bool
	key			*ecdh.PrivateKey
	ckx			*interface{}
	preMasterSecret		*[]uint8
	curveID			*tls.CurveID
	signatureAlgorithm	*tls.SignatureScheme
}

type tls_ecdheKeyAgreement struct {
	version			*uint16
	isRSA			*bool
	key			*ecdh.PrivateKey
	ckx			*interface{}
	preMasterSecret		*[]uint8
	curveID			*tls.CurveID
	signatureAlgorithm	*tls.SignatureScheme
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_ecdheKeyAgreement struct {
	version		*uint16
	isRSA		*bool
	key		*ecdh.PrivateKey
	ckx		*interface{}
	preMasterSecret	*[]uint8
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echCipher struct {
	KDFID	*uint16
	AEADID	*uint16
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echClientContext struct {
	config		*interface{}
	hpkeContext	*hpke.Sender
	encapsulatedKey	*[]uint8
	innerHello	*interface{}
	innerTranscript	*hash.Hash
	kdfID		*uint16
	aeadID		*uint16
	echRejected	*bool
	retryConfigs	*[]uint8
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfig struct {
	raw			*[]uint8
	Version			*uint16
	Length			*uint16
	ConfigID		*uint8
	KemID			*uint16
	PublicKey		*[]uint8
	SymmetricCipherSuite	*[]tls.echCipher
	MaxNameLength		*uint8
	PublicName		*[]uint8
	Extensions		*[]tls.echExtension
}

type tls_echConfigErr struct {
	field *string
}

type tls_echConfigErr struct {
	field *string
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_echExtension struct {
	Type	*uint16
	Data	*[]uint8
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	utls			*interface{}
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	utls			*interface{}
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	serverNameAck		*bool
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	serverNameAck		*bool
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	utls			*interface{}
}

type tls_encryptedExtensionsMsg struct {
	alpnProtocol		*string
	quicTransportParameters	*[]uint8
	earlyData		*bool
	echRetryConfigs		*[]uint8
	utls			*interface{}
}

type tls_endOfEarlyDataMsg struct {
}

type tls_endOfEarlyDataMsg struct {
}

type tls_endOfEarlyDataMsg struct {
}

type tls_endOfEarlyDataMsg struct {
}

type tls_endOfEarlyDataMsg struct {
}

type tls_endOfEarlyDataMsg struct {
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedHash struct {
	client		*hash.Hash
	server		*hash.Hash
	clientMD5	*hash.Hash
	serverMD5	*hash.Hash
	buffer		*[]uint8
	version		*uint16
	prf		*interface{}
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_finishedMsg struct {
	verifyData *[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_halfConn struct {
	Mutex		*sync.Mutex
	err		*error
	version		*uint16
	cipher		*interface {}
	mac		*hash.Hash
	seq		*[8]uint8
	scratchBuf	*[13]uint8
	nextCipher	*interface {}
	nextMac		*hash.Hash
	level		*tls.QUICEncryptionLevel
	trafficSecret	*[]uint8
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessage interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_handshakeMessageWithOriginalBytes interface {
}

type tls_helloRequestMsg struct {
}

type tls_helloRequestMsg struct {
}

type tls_helloRequestMsg struct {
}

type tls_helloRequestMsg struct {
}

type tls_helloRequestMsg struct {
}

type tls_helloRequestMsg struct {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyAgreement interface {
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keyShare struct {
	group	*tls.CurveID
	data	*[]uint8
}

type tls_keySharePrivateKeys struct {
	curveID		*tls.CurveID
	ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_keySharePrivateKeys struct {
	curveID		*tls.CurveID
	ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_keySharePrivateKeys struct {
	curveID	*tls.CurveID
	ecdhe	*ecdh.PrivateKey
	mlkem	*mlkem.DecapsulationKey768
}

type tls_keySharePrivateKeys struct {
	curveID	*tls.CurveID
	ecdhe	*ecdh.PrivateKey
	mlkem	*mlkem.DecapsulationKey768
}

type tls_keySharePrivateKeys struct {
	curveID		*tls.CurveID
	ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_keySharePrivateKeys struct {
	curveID		*tls.CurveID
	ecdhe		*ecdh.PrivateKey
	mlkem		*mlkem.DecapsulationKey768
	mlkemEcdhe	*ecdh.PrivateKey
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_keyUpdateMsg struct {
	updateRequested *bool
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsg struct {
	ticket *[]uint8
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_newSessionTicketMsgTLS13 struct {
	lifetime	*uint32
	ageAdd		*uint32
	nonce		*[]uint8
	label		*[]uint8
	maxEarlyData	*uint32
}

type tls_permanentError struct {
	err *net.Error
}

type tls_permanentError struct {
	err *net.Error
}

type tls_permanentError struct {
	err *net.Error
}

type tls_permanentError struct {
	err *net.Error
}

type tls_permanentError struct {
	err *net.Error
}

type tls_permanentError struct {
	err *net.Error
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prefixNonceAEAD struct {
	nonce	*[12]uint8
	aead	*cipher.AEAD
}

type tls_prfFunc func()

type tls_prfFunc func()

type tls_prfFunc func()

type tls_prfFunc func()

type tls_prfFunc func()

type tls_prfFunc func()

type tls_prfFuncOld func()

type tls_prfFuncOld func()

type tls_prfFuncOld func()

type tls_prfFuncOld func()

type tls_prng struct {
	rand			*rand.Rand
	randomStreamMutex	*sync.Mutex
	randomStream		*sha3.ShakeHash
}

type tls_prng struct {
	rand			*rand.Rand
	randomStreamMutex	*sync.Mutex
	randomStream		*sha3.ShakeHash
}

type tls_prng struct {
	rand			*rand.Rand
	randomStreamMutex	*sync.Mutex
	randomStream		*sha3.ShakeHash
}

type tls_prng struct {
	rand			*rand.Rand
	randomStreamMutex	*sync.Mutex
	randomStream		*sha3.ShakeHash
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_pskIdentity struct {
	label			*[]uint8
	obfuscatedTicketAge	*uint32
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_quicState struct {
	events			*[]tls.QUICEvent
	nextEvent		*int
	eventArr		*[8]tls.QUICEvent
	started			*bool
	signalc			*chan struct {}
	blockedc		*chan struct {}
	cancelc			*<-chan struct {}
	cancel			*context.CancelFunc
	waitingForDrain		*bool
	readbuf			*[]uint8
	transportParams		*[]uint8
	enableSessionEvents	*bool
}

type tls_rawExtension struct {
	extType	*uint16
	data	*[]uint8
}

type tls_rawExtension struct {
	extType	*uint16
	data	*[]uint8
}

type tls_rawExtension struct {
	extType	*uint16
	data	*[]uint8
}

type tls_rawExtension struct {
	extType	*uint16
	data	*[]uint8
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_rsaKeyAgreement struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloDoneMsg struct {
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverHelloMsg struct {
	original			*[]uint8
	vers				*uint16
	random				*[]uint8
	sessionId			*[]uint8
	cipherSuite			*uint16
	compressionMethod		*uint8
	ocspStapling			*bool
	ticketSupported			*bool
	secureRenegotiationSupported	*bool
	secureRenegotiation		*[]uint8
	extendedMasterSecret		*bool
	alpnProtocol			*string
	scts				*[][]uint8
	supportedVersion		*uint16
	serverShare			*interface{}
	selectedIdentityPresent		*bool
	selectedIdentity		*uint16
	supportedPoints			*[]uint8
	encryptedClientHello		*[]uint8
	serverNameAck			*bool
	cookie				*[]uint8
	selectedGroup			*tls.CurveID
	nextProtoNeg			*bool
	nextProtos			*[]string
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_serverKeyExchangeMsg struct {
	key *[]uint8
}

type tls_sessionController struct {
	sessionTicketExt	*tls.ISessionTicketExtension
	pskExtension		*tls.PreSharedKeyExtension
	uconnRef		*tls.UConn
	state			*interface{}
	loadSessionTracker	*tls.LoadSessionTrackerState
	callingLoadSession	*bool
	locked			*bool
}

type tls_sessionController struct {
	sessionTicketExt	*tls.ISessionTicketExtension
	pskExtension		*tls.PreSharedKeyExtension
	uconnRef		*tls.UConn
	state			*interface{}
	loadSessionTracker	*tls.LoadSessionTrackerState
	callingLoadSession	*bool
	locked			*bool
}

type tls_sessionController struct {
	sessionTicketExt	*tls.ISessionTicketExtension
	pskExtension		*tls.PreSharedKeyExtension
	uconnRef		*tls.UConn
	state			*interface{}
	loadSessionTracker	*tls.LoadSessionTrackerState
	callingLoadSession	*bool
	locked			*bool
}

type tls_sessionController struct {
	sessionTicketExt	*tls.ISessionTicketExtension
	pskExtension		*tls.PreSharedKeyExtension
	uconnRef		*tls.UConn
	state			*interface{}
	loadSessionTracker	*tls.LoadSessionTrackerState
	callingLoadSession	*bool
	locked			*bool
}

type tls_sessionControllerState int

type tls_sessionControllerState int

type tls_sessionControllerState int

type tls_sessionControllerState int

type tls_sortableCipher struct {
	isObsolete	*bool
	randomTag	*int
	suite		*uint16
}

type tls_sortableCipher struct {
	isObsolete	*bool
	randomTag	*int
	suite		*uint16
}

type tls_sortableCipher struct {
	isObsolete	*bool
	randomTag	*int
	suite		*uint16
}

type tls_sortableCipher struct {
	isObsolete	*bool
	randomTag	*int
	suite		*uint16
}

type tls_sortableCiphers []*interface{}

type tls_sortableCiphers []*interface{}

type tls_sortableCiphers []*interface{}

type tls_sortableCiphers []*interface{}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_ticketKey struct {
	aesKey	*[16]uint8
	hmacKey	*[16]uint8
	created	*time.Time
}

type tls_transcriptHash interface {
}

type tls_transcriptHash interface {
}

type tls_transcriptHash interface {
}

type tls_transcriptHash interface {
}

type tls_transcriptHash interface {
}

type tls_transcriptHash interface {
}

type tls_utlsClientEncryptedExtensionsMsg struct {
	raw				*[]uint8
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	customExtension			*[]uint8
}

type tls_utlsClientEncryptedExtensionsMsg struct {
	raw				*[]uint8
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	customExtension			*[]uint8
}

type tls_utlsClientEncryptedExtensionsMsg struct {
	raw				*[]uint8
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	customExtension			*[]uint8
}

type tls_utlsClientEncryptedExtensionsMsg struct {
	raw				*[]uint8
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	customExtension			*[]uint8
}

type tls_utlsCompressedCertificateMsg struct {
	raw				*[]uint8
	algorithm			*uint16
	uncompressedLength		*uint32
	compressedCertificateMessage	*[]uint8
}

type tls_utlsCompressedCertificateMsg struct {
	raw				*[]uint8
	algorithm			*uint16
	uncompressedLength		*uint32
	compressedCertificateMessage	*[]uint8
}

type tls_utlsCompressedCertificateMsg struct {
	raw				*[]uint8
	algorithm			*uint16
	uncompressedLength		*uint32
	compressedCertificateMessage	*[]uint8
}

type tls_utlsCompressedCertificateMsg struct {
	raw				*[]uint8
	algorithm			*uint16
	uncompressedLength		*uint32
	compressedCertificateMessage	*[]uint8
}

type tls_utlsConnExtraFields struct {
	peerApplicationSettings		*[]uint8
	localApplicationSettings	*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	sessionController		*interface{}
}

type tls_utlsConnExtraFields struct {
	peerApplicationSettings		*[]uint8
	localApplicationSettings	*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	sessionController		*interface{}
}

type tls_utlsConnExtraFields struct {
	peerApplicationSettings		*[]uint8
	localApplicationSettings	*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	sessionController		*interface{}
}

type tls_utlsConnExtraFields struct {
	peerApplicationSettings		*[]uint8
	localApplicationSettings	*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	sessionController		*interface{}
}

type tls_utlsEncryptedExtensionsMsgExtraFields struct {
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	customExtension			*[]uint8
}

type tls_utlsEncryptedExtensionsMsgExtraFields struct {
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	customExtension			*[]uint8
}

type tls_utlsEncryptedExtensionsMsgExtraFields struct {
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	customExtension			*[]uint8
}

type tls_utlsEncryptedExtensionsMsgExtraFields struct {
	applicationSettings		*[]uint8
	applicationSettingsCodepoint	*uint16
	echRetryConfigs			*[]tls.ECHConfig
	customExtension			*[]uint8
}

type tls_weakCertCache struct {
	Map *sync.Map
}

type tls_weakCertCache struct {
	Map *sync.Map
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls_xorNonceAEAD struct {
	nonceMask	*[12]uint8
	aead		*cipher.AEAD
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_EarlySecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_ExporterMasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_HandshakeSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type tls13_MasterSecret struct {
	secret	*[]uint8
	hash	*func() hash.Hash
}

type unsafeheader_Slice struct {
	Data	*unsafe.Pointer
	Len	*int
	Cap	*int
}

type unsafeheader_Slice struct {
	Data	*unsafe.Pointer
	Len	*int
	Cap	*int
}

type url_Error struct {
	Op	*string
	URL	*string
	Err	*error
}

type url_Error struct {
	Op	*string
	URL	*string
	Err	*error
}

type url_EscapeError string

type url_EscapeError string

type url_InvalidHostError string

type url_InvalidHostError string

type url_URL struct {
	Scheme		*string
	Opaque		*string
	User		*url.Userinfo
	Host		*string
	Path		*string
	RawPath		*string
	OmitHost	*bool
	ForceQuery	*bool
	RawQuery	*string
	Fragment	*string
	RawFragment	*string
}

type url_URL struct {
	Scheme		*string
	Opaque		*string
	User		*url.Userinfo
	Host		*string
	Path		*string
	RawPath		*string
	OmitHost	*bool
	ForceQuery	*bool
	RawQuery	*string
	Fragment	*string
	RawFragment	*string
}

type url_Userinfo struct {
	username	*string
	password	*string
	passwordSet	*bool
}

type url_Userinfo struct {
	username	*string
	password	*string
	passwordSet	*bool
}

type url_Values map[interface{}]*string

type url_Values map[interface{}]*string

type utils_ConnectionStats struct {
	BytesSent	*atomic.Uint64
	PacketsSent	*atomic.Uint64
	BytesReceived	*atomic.Uint64
	PacketsReceived	*atomic.Uint64
	BytesLost	*atomic.Uint64
	PacketsLost	*atomic.Uint64
}

type utils_ConnectionStats struct {
	BytesSent	*atomic.Uint64
	PacketsSent	*atomic.Uint64
	BytesReceived	*atomic.Uint64
	PacketsReceived	*atomic.Uint64
	BytesLost	*atomic.Uint64
	PacketsLost	*atomic.Uint64
}

type utils_LogLevel uint8

type utils_LogLevel uint8

type utils_Logger interface {
}

type utils_Logger interface {
}

type utils_RTTStats struct {
	hasMeasurement	*bool
	minRTT		*atomic.Int64
	latestRTT	*atomic.Int64
	smoothedRTT	*atomic.Int64
	meanDeviation	*atomic.Int64
	maxAckDelay	*atomic.Int64
}

type utils_RTTStats struct {
	hasMeasurement	*bool
	minRTT		*atomic.Int64
	latestRTT	*atomic.Int64
	smoothedRTT	*atomic.Int64
	meanDeviation	*atomic.Int64
	maxAckDelay	*atomic.Int64
}

type utils_Rand struct {
	buf *[4]uint8
}

type utils_Rand struct {
	buf *[4]uint8
}

type utils_Timer struct {
	t		*time.Timer
	read		*bool
	deadline	*time.Time
}

type utils_Timer struct {
	t		*time.Timer
	read		*bool
	deadline	*time.Time
}

type utils_defaultLogger struct {
	prefix		*string
	logLevel	*utils.LogLevel
	timeFormat	*string
}

type utils_defaultLogger struct {
	prefix		*string
	logLevel	*utils.LogLevel
	timeFormat	*string
}

type utils_rewindReader struct {
	Reader	*io.Reader
	rr	*bytes.Reader
}

type utils_rewindReader struct {
	Reader	*io.Reader
	rr	*bytes.Reader
}

type websocket_BufferPool interface {
}

type websocket_BufferPool interface {
}

type websocket_Dialer struct {
	NetDial			*func(string, string) (net.Conn, error)
	NetDialContext		*func(context.Context, string, string) (net.Conn, error)
	NetDialTLSContext	*func(context.Context, string, string) (net.Conn, error)
	Proxy			*func(*http.Request) (*url.URL, error)
	TLSClientConfig		*tls.Config
	HandshakeTimeout	*time.Duration
	ReadBufferSize		*int
	WriteBufferSize		*int
	WriteBufferPool		*websocket.BufferPool
	Subprotocols		*[]string
	EnableCompression	*bool
	Jar			*http.CookieJar
}

type websocket_Dialer struct {
	NetDial			*func(string, string) (net.Conn, error)
	NetDialContext		*func(context.Context, string, string) (net.Conn, error)
	NetDialTLSContext	*func(context.Context, string, string) (net.Conn, error)
	Proxy			*func(*http.Request) (*url.URL, error)
	TLSClientConfig		*tls.Config
	HandshakeTimeout	*time.Duration
	ReadBufferSize		*int
	WriteBufferSize		*int
	WriteBufferPool		*websocket.BufferPool
	Subprotocols		*[]string
	EnableCompression	*bool
	Jar			*http.CookieJar
}

type websocket_httpProxyDialer struct {
	proxyURL	*url.URL
	forwardDial	*func(string, string) (net.Conn, error)
}

type websocket_httpProxyDialer struct {
	proxyURL	*url.URL
	forwardDial	*func(string, string) (net.Conn, error)
}

type websocket_proxy_Dialer interface {
}

type websocket_proxy_Dialer interface {
}

type wire_AckFrame struct {
	AckRanges	*[]wire.AckRange
	DelayTime	*time.Duration
	ECT0		*uint64
	ECT1		*uint64
	ECNCE		*uint64
}

type wire_AckFrame struct {
	AckRanges	*[]wire.AckRange
	DelayTime	*time.Duration
	ECT0		*uint64
	ECT1		*uint64
	ECNCE		*uint64
}

type wire_AckFrequencyFrame struct {
	SequenceNumber		*uint64
	AckElicitingThreshold	*uint64
	RequestMaxAckDelay	*time.Duration
	ReorderingThreshold	*protocol.PacketNumber
}

type wire_AckFrequencyFrame struct {
	SequenceNumber		*uint64
	AckElicitingThreshold	*uint64
	RequestMaxAckDelay	*time.Duration
	ReorderingThreshold	*protocol.PacketNumber
}

type wire_AckRange struct {
	Smallest	*protocol.PacketNumber
	Largest		*protocol.PacketNumber
}

type wire_AckRange struct {
	Smallest	*protocol.PacketNumber
	Largest		*protocol.PacketNumber
}

type wire_ConnectionCloseFrame struct {
	IsApplicationError	*bool
	ErrorCode		*uint64
	FrameType		*uint64
	ReasonPhrase		*string
}

type wire_ConnectionCloseFrame struct {
	IsApplicationError	*bool
	ErrorCode		*uint64
	FrameType		*uint64
	ReasonPhrase		*string
}

type wire_CryptoFrame struct {
	Offset	*protocol.ByteCount
	Data	*[]uint8
}

type wire_CryptoFrame struct {
	Offset	*protocol.ByteCount
	Data	*[]uint8
}

type wire_DataBlockedFrame struct {
	MaximumData *protocol.ByteCount
}

type wire_DataBlockedFrame struct {
	MaximumData *protocol.ByteCount
}

type wire_DatagramFrame struct {
	DataLenPresent	*bool
	Data		*[]uint8
}

type wire_DatagramFrame struct {
	DataLenPresent	*bool
	Data		*[]uint8
}

type wire_ExtendedHeader struct {
	Header		*wire.Header
	typeByte	*uint8
	KeyPhase	*protocol.KeyPhaseBit
	PacketNumberLen	*protocol.PacketNumberLen
	PacketNumber	*protocol.PacketNumber
	parsedLen	*protocol.ByteCount
}

type wire_ExtendedHeader struct {
	Header		*wire.Header
	typeByte	*uint8
	KeyPhase	*protocol.KeyPhaseBit
	PacketNumberLen	*protocol.PacketNumberLen
	PacketNumber	*protocol.PacketNumber
	parsedLen	*protocol.ByteCount
}

type wire_Frame interface {
}

type wire_Frame interface {
}

type wire_FrameParser struct {
	ackDelayExponent	*uint8
	supportsDatagrams	*bool
	supportsResetStreamAt	*bool
	supportsAckFrequency	*bool
	ackFrame		*wire.AckFrame
}

type wire_FrameParser struct {
	ackDelayExponent	*uint8
	supportsDatagrams	*bool
	supportsResetStreamAt	*bool
	supportsAckFrequency	*bool
	ackFrame		*wire.AckFrame
}

type wire_FrameType uint64

type wire_FrameType uint64

type wire_HandshakeDoneFrame struct {
}

type wire_HandshakeDoneFrame struct {
}

type wire_Header struct {
	typeByte		*uint8
	Type			*protocol.PacketType
	Version			*protocol.Version
	SrcConnectionID		*protocol.ConnectionID
	DestConnectionID	*protocol.ConnectionID
	Length			*protocol.ByteCount
	Token			*[]uint8
	parsedLen		*protocol.ByteCount
}

type wire_Header struct {
	typeByte		*uint8
	Type			*protocol.PacketType
	Version			*protocol.Version
	SrcConnectionID		*protocol.ConnectionID
	DestConnectionID	*protocol.ConnectionID
	Length			*protocol.ByteCount
	Token			*[]uint8
	parsedLen		*protocol.ByteCount
}

type wire_ImmediateAckFrame struct {
}

type wire_ImmediateAckFrame struct {
}

type wire_MaxDataFrame struct {
	MaximumData *protocol.ByteCount
}

type wire_MaxDataFrame struct {
	MaximumData *protocol.ByteCount
}

type wire_MaxStreamDataFrame struct {
	StreamID		*protocol.StreamID
	MaximumStreamData	*protocol.ByteCount
}

type wire_MaxStreamDataFrame struct {
	StreamID		*protocol.StreamID
	MaximumStreamData	*protocol.ByteCount
}

type wire_MaxStreamsFrame struct {
	Type		*protocol.StreamType
	MaxStreamNum	*protocol.StreamNum
}

type wire_MaxStreamsFrame struct {
	Type		*protocol.StreamType
	MaxStreamNum	*protocol.StreamNum
}

type wire_NewConnectionIDFrame struct {
	SequenceNumber		*uint64
	RetirePriorTo		*uint64
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type wire_NewConnectionIDFrame struct {
	SequenceNumber		*uint64
	RetirePriorTo		*uint64
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type wire_NewTokenFrame struct {
	Token *[]uint8
}

type wire_NewTokenFrame struct {
	Token *[]uint8
}

type wire_PathChallengeFrame struct {
	Data *[8]uint8
}

type wire_PathChallengeFrame struct {
	Data *[8]uint8
}

type wire_PathResponseFrame struct {
	Data *[8]uint8
}

type wire_PathResponseFrame struct {
	Data *[8]uint8
}

type wire_PingFrame struct {
}

type wire_PingFrame struct {
}

type wire_PreferredAddress struct {
	IPv4			*netip.AddrPort
	IPv6			*netip.AddrPort
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type wire_PreferredAddress struct {
	IPv4			*netip.AddrPort
	IPv6			*netip.AddrPort
	ConnectionID		*protocol.ConnectionID
	StatelessResetToken	*protocol.StatelessResetToken
}

type wire_ResetStreamFrame struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
	FinalSize	*protocol.ByteCount
	ReliableSize	*protocol.ByteCount
}

type wire_ResetStreamFrame struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
	FinalSize	*protocol.ByteCount
	ReliableSize	*protocol.ByteCount
}

type wire_RetireConnectionIDFrame struct {
	SequenceNumber *uint64
}

type wire_RetireConnectionIDFrame struct {
	SequenceNumber *uint64
}

type wire_StopSendingFrame struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
}

type wire_StopSendingFrame struct {
	StreamID	*protocol.StreamID
	ErrorCode	*qerr.StreamErrorCode
}

type wire_StreamDataBlockedFrame struct {
	StreamID		*protocol.StreamID
	MaximumStreamData	*protocol.ByteCount
}

type wire_StreamDataBlockedFrame struct {
	StreamID		*protocol.StreamID
	MaximumStreamData	*protocol.ByteCount
}

type wire_StreamFrame struct {
	StreamID	*protocol.StreamID
	Offset		*protocol.ByteCount
	Data		*[]uint8
	Fin		*bool
	DataLenPresent	*bool
	fromPool	*bool
}

type wire_StreamFrame struct {
	StreamID	*protocol.StreamID
	Offset		*protocol.ByteCount
	Data		*[]uint8
	Fin		*bool
	DataLenPresent	*bool
	fromPool	*bool
}

type wire_StreamsBlockedFrame struct {
	Type		*protocol.StreamType
	StreamLimit	*protocol.StreamNum
}

type wire_StreamsBlockedFrame struct {
	Type		*protocol.StreamType
	StreamLimit	*protocol.StreamNum
}

type wire_TransportParameters struct {
	InitialMaxStreamDataBidiLocal	*protocol.ByteCount
	InitialMaxStreamDataBidiRemote	*protocol.ByteCount
	InitialMaxStreamDataUni		*protocol.ByteCount
	InitialMaxData			*protocol.ByteCount
	MaxAckDelay			*time.Duration
	AckDelayExponent		*uint8
	DisableActiveMigration		*bool
	MaxUDPPayloadSize		*protocol.ByteCount
	MaxUniStreamNum			*protocol.StreamNum
	MaxBidiStreamNum		*protocol.StreamNum
	MaxIdleTimeout			*time.Duration
	PreferredAddress		*wire.PreferredAddress
	OriginalDestinationConnectionID	*protocol.ConnectionID
	InitialSourceConnectionID	*protocol.ConnectionID
	RetrySourceConnectionID		*protocol.ConnectionID
	StatelessResetToken		*protocol.StatelessResetToken
	ActiveConnectionIDLimit		*uint64
	MaxDatagramFrameSize		*protocol.ByteCount
	EnableResetStreamAt		*bool
	MinAckDelay			*time.Duration
	ClientOverride			*tls.TransportParameters
}

type wire_TransportParameters struct {
	InitialMaxStreamDataBidiLocal	*protocol.ByteCount
	InitialMaxStreamDataBidiRemote	*protocol.ByteCount
	InitialMaxStreamDataUni		*protocol.ByteCount
	InitialMaxData			*protocol.ByteCount
	MaxAckDelay			*time.Duration
	AckDelayExponent		*uint8
	DisableActiveMigration		*bool
	MaxUDPPayloadSize		*protocol.ByteCount
	MaxUniStreamNum			*protocol.StreamNum
	MaxBidiStreamNum		*protocol.StreamNum
	MaxIdleTimeout			*time.Duration
	PreferredAddress		*wire.PreferredAddress
	OriginalDestinationConnectionID	*protocol.ConnectionID
	InitialSourceConnectionID	*protocol.ConnectionID
	RetrySourceConnectionID		*protocol.ConnectionID
	StatelessResetToken		*protocol.StatelessResetToken
	ActiveConnectionIDLimit		*uint64
	MaxDatagramFrameSize		*protocol.ByteCount
	EnableResetStreamAt		*bool
	MinAckDelay			*time.Duration
	ClientOverride			*tls.TransportParameters
}

type wire_transportParameterID uint64

type wire_transportParameterID uint64

type x25519_Key [32]*uint8

type x25519_Key [32]*uint8

type x509_CertPool struct {
	byName		*map[string][]int
	lazyCerts	*[]x509.lazyCert
	haveSum		*map[x509.sum224]bool
	systemPool	*bool
}

type x509_CertPool struct {
	byName		*map[string][]int
	lazyCerts	*[]x509.lazyCert
	haveSum		*map[x509.sum224]bool
	systemPool	*bool
}

type x509_Certificate struct {
	Raw				*[]uint8
	RawTBSCertificate		*[]uint8
	RawSubjectPublicKeyInfo		*[]uint8
	RawSubject			*[]uint8
	RawIssuer			*[]uint8
	Signature			*[]uint8
	SignatureAlgorithm		*x509.SignatureAlgorithm
	PublicKeyAlgorithm		*x509.PublicKeyAlgorithm
	PublicKey			*interface {}
	Version				*int
	SerialNumber			*big.Int
	Issuer				*pkix.Name
	Subject				*pkix.Name
	NotBefore			*time.Time
	NotAfter			*time.Time
	KeyUsage			*x509.KeyUsage
	Extensions			*[]pkix.Extension
	ExtraExtensions			*[]pkix.Extension
	UnhandledCriticalExtensions	*[]asn1.ObjectIdentifier
	ExtKeyUsage			*[]x509.ExtKeyUsage
	UnknownExtKeyUsage		*[]asn1.ObjectIdentifier
	BasicConstraintsValid		*bool
	IsCA				*bool
	MaxPathLen			*int
	MaxPathLenZero			*bool
	SubjectKeyId			*[]uint8
	AuthorityKeyId			*[]uint8
	OCSPServer			*[]string
	IssuingCertificateURL		*[]string
	DNSNames			*[]string
	EmailAddresses			*[]string
	IPAddresses			*[]net.IP
	URIs				*[]*url.URL
	PermittedDNSDomainsCritical	*bool
	PermittedDNSDomains		*[]string
	ExcludedDNSDomains		*[]string
	PermittedIPRanges		*[]*net.IPNet
	ExcludedIPRanges		*[]*net.IPNet
	PermittedEmailAddresses		*[]string
	ExcludedEmailAddresses		*[]string
	PermittedURIDomains		*[]string
	ExcludedURIDomains		*[]string
	CRLDistributionPoints		*[]string
	PolicyIdentifiers		*[]asn1.ObjectIdentifier
	Policies			*[]x509.OID
	InhibitAnyPolicy		*int
	InhibitAnyPolicyZero		*bool
	InhibitPolicyMapping		*int
	InhibitPolicyMappingZero	*bool
	RequireExplicitPolicy		*int
	RequireExplicitPolicyZero	*bool
	PolicyMappings			*[]x509.PolicyMapping
}

type x509_Certificate struct {
	Raw				*[]uint8
	RawTBSCertificate		*[]uint8
	RawSubjectPublicKeyInfo		*[]uint8
	RawSubject			*[]uint8
	RawIssuer			*[]uint8
	Signature			*[]uint8
	SignatureAlgorithm		*x509.SignatureAlgorithm
	PublicKeyAlgorithm		*x509.PublicKeyAlgorithm
	PublicKey			*interface {}
	Version				*int
	SerialNumber			*big.Int
	Issuer				*pkix.Name
	Subject				*pkix.Name
	NotBefore			*time.Time
	NotAfter			*time.Time
	KeyUsage			*x509.KeyUsage
	Extensions			*[]pkix.Extension
	ExtraExtensions			*[]pkix.Extension
	UnhandledCriticalExtensions	*[]asn1.ObjectIdentifier
	ExtKeyUsage			*[]x509.ExtKeyUsage
	UnknownExtKeyUsage		*[]asn1.ObjectIdentifier
	BasicConstraintsValid		*bool
	IsCA				*bool
	MaxPathLen			*int
	MaxPathLenZero			*bool
	SubjectKeyId			*[]uint8
	AuthorityKeyId			*[]uint8
	OCSPServer			*[]string
	IssuingCertificateURL		*[]string
	DNSNames			*[]string
	EmailAddresses			*[]string
	IPAddresses			*[]net.IP
	URIs				*[]*url.URL
	PermittedDNSDomainsCritical	*bool
	PermittedDNSDomains		*[]string
	ExcludedDNSDomains		*[]string
	PermittedIPRanges		*[]*net.IPNet
	ExcludedIPRanges		*[]*net.IPNet
	PermittedEmailAddresses		*[]string
	ExcludedEmailAddresses		*[]string
	PermittedURIDomains		*[]string
	ExcludedURIDomains		*[]string
	CRLDistributionPoints		*[]string
	PolicyIdentifiers		*[]asn1.ObjectIdentifier
	Policies			*[]x509.OID
	InhibitAnyPolicy		*int
	InhibitAnyPolicyZero		*bool
	InhibitPolicyMapping		*int
	InhibitPolicyMappingZero	*bool
	RequireExplicitPolicy		*int
	RequireExplicitPolicyZero	*bool
	PolicyMappings			*[]x509.PolicyMapping
}

type x509_CertificateInvalidError struct {
	Cert	*x509.Certificate
	Reason	*x509.InvalidReason
	Detail	*string
}

type x509_CertificateInvalidError struct {
	Cert	*x509.Certificate
	Reason	*x509.InvalidReason
	Detail	*string
}

type x509_ConstraintViolationError struct {
}

type x509_ConstraintViolationError struct {
}

type x509_ExtKeyUsage int

type x509_ExtKeyUsage int

type x509_HostnameError struct {
	Certificate	*x509.Certificate
	Host		*string
}

type x509_HostnameError struct {
	Certificate	*x509.Certificate
	Host		*string
}

type x509_InsecureAlgorithmError int

type x509_InsecureAlgorithmError int

type x509_InvalidReason int

type x509_InvalidReason int

type x509_KeyUsage int

type x509_KeyUsage int

type x509_OID struct {
	der *[]uint8
}

type x509_OID struct {
	der *[]uint8
}

type x509_PolicyMapping struct {
	IssuerDomainPolicy	*x509.OID
	SubjectDomainPolicy	*x509.OID
}

type x509_PolicyMapping struct {
	IssuerDomainPolicy	*x509.OID
	SubjectDomainPolicy	*x509.OID
}

type x509_PublicKeyAlgorithm int

type x509_PublicKeyAlgorithm int

type x509_SignatureAlgorithm int

type x509_SignatureAlgorithm int

type x509_SystemRootsError struct {
	Err *error
}

type x509_SystemRootsError struct {
	Err *error
}

type x509_UnhandledCriticalExtension struct {
}

type x509_UnhandledCriticalExtension struct {
}

type x509_UnknownAuthorityError struct {
	Cert		*x509.Certificate
	hintErr		*error
	hintCert	*x509.Certificate
}

type x509_UnknownAuthorityError struct {
	Cert		*x509.Certificate
	hintErr		*error
	hintCert	*x509.Certificate
}

type x509_lazyCert struct {
	rawSubject	*[]uint8
	constraint	*func([]*x509.Certificate) error
	getCert		*func() (*x509.Certificate, error)
}

type x509_lazyCert struct {
	rawSubject	*[]uint8
	constraint	*func([]*x509.Certificate) error
	getCert		*func() (*x509.Certificate, error)
}

type x509_policyGraphNode struct {
	validPolicy		*x509.OID
	expectedPolicySet	*[]x509.OID
	parents			*map[*x509.policyGraphNode]bool
	children		*map[*x509.policyGraphNode]bool
}

type x509_policyGraphNode struct {
	validPolicy		*x509.OID
	expectedPolicySet	*[]x509.OID
	parents			*map[*x509.policyGraphNode]bool
	children		*map[*x509.policyGraphNode]bool
}

type x509_potentialParent struct {
	cert		*x509.Certificate
	constraint	*func([]*x509.Certificate) error
}

type x509_potentialParent struct {
	cert		*x509.Certificate
	constraint	*func([]*x509.Certificate) error
}

type x509_pssParameters struct {
	Hash		*pkix.AlgorithmIdentifier
	MGF		*pkix.AlgorithmIdentifier
	SaltLength	*int
	TrailerField	*int
}

type x509_pssParameters struct {
	Hash		*pkix.AlgorithmIdentifier
	MGF		*pkix.AlgorithmIdentifier
	SaltLength	*int
	TrailerField	*int
}

type x509_rfc2821Mailbox struct {
	local	*string
	domain	*string
}

type x509_rfc2821Mailbox struct {
	local	*string
	domain	*string
}

type x509_sum224 [28]*uint8

type x509_sum224 [28]*uint8

type xwing_PrivateKey struct {
	seed	*[32]uint8
	m	*mlkem768.PrivateKey
	x	*x25519.Key
	xpk	*x25519.Key
}

type xwing_PrivateKey struct {
	seed	*[32]uint8
	m	*mlkem768.PrivateKey
	x	*x25519.Key
	xpk	*x25519.Key
}

type xwing_PublicKey struct {
	m	*mlkem768.PublicKey
	x	*x25519.Key
}

type xwing_PublicKey struct {
	m	*mlkem768.PublicKey
	x	*x25519.Key
}

type xwing_scheme struct {
}

type xwing_scheme struct {
}

type xxhash_Digest struct {
	v1	*uint64
	v2	*uint64
	v3	*uint64
	v4	*uint64
	total	*uint64
	mem	*[32]uint8
	n	*int
}

type xxhash_Digest struct {
	v1	*uint64
	v2	*uint64
	v3	*uint64
	v4	*uint64
	total	*uint64
	mem	*[32]uint8
	n	*int
}

type zlib_reader struct {
	r		*flate.Reader
	decompressor	*io.ReadCloser
	digest		*hash.Hash32
	err		*error
	scratch		*[4]uint8
}

type zlib_reader struct {
	r		*flate.Reader
	decompressor	*io.ReadCloser
	digest		*hash.Hash32
	err		*error
	scratch		*[4]uint8
}

type zstd_Decoder struct {
	o		*interface{}
	decoders	*chan *zstd.blockDec
	current		*interface{}
	syncStream	*interface{}
	frame		*interface{}
	dicts		*map[uint32]*zstd.dict
	streamWg	*sync.WaitGroup
}

type zstd_Decoder struct {
	o		*interface{}
	decoders	*chan *zstd.blockDec
	current		*interface{}
	syncStream	*interface{}
	frame		*interface{}
	dicts		*map[uint32]*zstd.dict
	streamWg	*sync.WaitGroup
}

type zstd_baseOffset struct {
	baseLine	*uint32
	addBits		*uint8
}

type zstd_baseOffset struct {
	baseLine	*uint32
	addBits		*uint8
}

type zstd_bitReader struct {
	in		*[]uint8
	value		*uint64
	cursor		*int
	bitsRead	*uint8
}

type zstd_bitReader struct {
	in		*[]uint8
	value		*uint64
	cursor		*int
	bitsRead	*uint8
}

type zstd_blockDec struct {
	data		*[]uint8
	dataStorage	*[]uint8
	dst		*[]uint8
	literalBuf	*[]uint8
	WindowSize	*uint64
	err		*error
	checkCRC	*uint32
	hasCRC		*bool
	localFrame	*interface{}
	sequence	*[]zstd.seqVals
	async		*interface{}
	RLESize		*uint32
	Type		*interface{}
	Last		*bool
	lowMem		*bool
}

type zstd_blockDec struct {
	data		*[]uint8
	dataStorage	*[]uint8
	dst		*[]uint8
	literalBuf	*[]uint8
	WindowSize	*uint64
	err		*error
	checkCRC	*uint32
	hasCRC		*bool
	localFrame	*interface{}
	sequence	*[]zstd.seqVals
	async		*interface{}
	RLESize		*uint32
	Type		*interface{}
	Last		*bool
	lowMem		*bool
}

type zstd_blockType uint8

type zstd_blockType uint8

type zstd_byteBuf []*uint8

type zstd_byteBuf []*uint8

type zstd_byteBuffer interface {
}

type zstd_byteBuffer interface {
}

type zstd_byter interface {
}

type zstd_byter interface {
}

type zstd_decSymbol uint64

type zstd_decSymbol uint64

type zstd_decodeOutput struct {
	d	*interface{}
	b	*[]uint8
	err	*error
}

type zstd_decodeOutput struct {
	d	*interface{}
	b	*[]uint8
	err	*error
}

type zstd_decoderOptions struct {
	lowMem		*bool
	concurrent	*int
	maxDecodedSize	*uint64
	maxWindowSize	*uint64
	dicts		*[]*zstd.dict
	ignoreChecksum	*bool
	limitToCap	*bool
	decodeBufsBelow	*int
}

type zstd_decoderOptions struct {
	lowMem		*bool
	concurrent	*int
	maxDecodedSize	*uint64
	maxWindowSize	*uint64
	dicts		*[]*zstd.dict
	ignoreChecksum	*bool
	limitToCap	*bool
	decodeBufsBelow	*int
}

type zstd_decoderState struct {
	decodeOutput	*interface{}
	output		*chan zstd.decodeOutput
	cancel		*context.CancelFunc
	crc		*xxhash.Digest
	flushed		*bool
}

type zstd_decoderState struct {
	decodeOutput	*interface{}
	output		*chan zstd.decodeOutput
	cancel		*context.CancelFunc
	crc		*xxhash.Digest
	flushed		*bool
}

type zstd_dict struct {
	id	*uint32
	litEnc	*huff0.Scratch
	llDec	*interface{}
	ofDec	*interface{}
	mlDec	*interface{}
	offsets	*[3]int
	content	*[]uint8
}

type zstd_dict struct {
	id	*uint32
	litEnc	*huff0.Scratch
	llDec	*interface{}
	ofDec	*interface{}
	mlDec	*interface{}
	offsets	*[3]int
	content	*[]uint8
}

type zstd_frameDec struct {
	o			*interface{}
	crc			*xxhash.Digest
	WindowSize		*uint64
	history			*interface{}
	rawInput		*interface{}
	bBuf			*interface{}
	FrameContentSize	*uint64
	DictionaryID		*uint32
	HasCheckSum		*bool
	SingleSegment		*bool
}

type zstd_frameDec struct {
	o			*interface{}
	crc			*xxhash.Digest
	WindowSize		*uint64
	history			*interface{}
	rawInput		*interface{}
	bBuf			*interface{}
	FrameContentSize	*uint64
	DictionaryID		*uint32
	HasCheckSum		*bool
	SingleSegment		*bool
}

type zstd_fseDecoder struct {
	dt		*[512]zstd.decSymbol
	symbolLen	*uint16
	actualTableLog	*uint8
	maxBits		*uint8
	stateTable	*[256]uint16
	norm		*[256]int16
	preDefined	*bool
}

type zstd_fseDecoder struct {
	dt		*[512]zstd.decSymbol
	symbolLen	*uint16
	actualTableLog	*uint8
	maxBits		*uint8
	stateTable	*[256]uint16
	norm		*[256]int16
	preDefined	*bool
}

type zstd_fseState struct {
	dt	*[]zstd.decSymbol
	state	*interface{}
}

type zstd_fseState struct {
	dt	*[]zstd.decSymbol
	state	*interface{}
}

type zstd_history struct {
	huffTree		*huff0.Scratch
	decoders		*interface{}
	recentOffsets		*[3]int
	b			*[]uint8
	ignoreBuffer		*int
	windowSize		*int
	allocFrameBuffer	*int
	error			*bool
	dict			*interface{}
}

type zstd_history struct {
	huffTree		*huff0.Scratch
	decoders		*interface{}
	recentOffsets		*[3]int
	b			*[]uint8
	ignoreBuffer		*int
	windowSize		*int
	allocFrameBuffer	*int
	error			*bool
	dict			*interface{}
}

type zstd_readerWrapper struct {
	r	*io.Reader
	tmp	*[8]uint8
}

type zstd_readerWrapper struct {
	r	*io.Reader
	tmp	*[8]uint8
}

type zstd_seqVals struct {
	ll	*int
	ml	*int
	mo	*int
}

type zstd_seqVals struct {
	ll	*int
	ml	*int
	mo	*int
}

type zstd_sequenceDec struct {
	fse	*interface{}
	state	*interface{}
	repeat	*bool
}

type zstd_sequenceDec struct {
	fse	*interface{}
	state	*interface{}
	repeat	*bool
}

type zstd_sequenceDecs struct {
	litLengths	*interface{}
	offsets		*interface{}
	matchLengths	*interface{}
	prevOffset	*[3]int
	dict		*[]uint8
	literals	*[]uint8
	out		*[]uint8
	nSeqs		*int
	br		*interface{}
	seqSize		*int
	windowSize	*int
	maxBits		*uint8
	maxSyncLen	*uint64
}

type zstd_sequenceDecs struct {
	litLengths	*interface{}
	offsets		*interface{}
	matchLengths	*interface{}
	prevOffset	*[3]int
	dict		*[]uint8
	literals	*[]uint8
	out		*[]uint8
	nSeqs		*int
	br		*interface{}
	seqSize		*int
	windowSize	*int
	maxBits		*uint8
	maxSyncLen	*uint64
}

type zstd_symbolTransform struct {
	deltaNbBits	*uint32
	deltaFindState	*int16
	outBits		*uint8
}

type zstd_symbolTransform struct {
	deltaNbBits	*uint32
	deltaFindState	*int16
	outBits		*uint8
}

type zstd_tableIndex uint8

type zstd_tableIndex uint8

