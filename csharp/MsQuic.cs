// generated code do not edit

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Structmap.WebTransportFast.MsQuic
{
    public partial struct QUIC_HANDLE
    {
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_TLS_PROVIDER : uint
    {
        QUIC_TLS_PROVIDER_SCHANNEL = 0x0000,
        QUIC_TLS_PROVIDER_OPENSSL = 0x0001,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_EXECUTION_PROFILE : uint
    {
        QUIC_EXECUTION_PROFILE_LOW_LATENCY,
        QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,
        QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER,
        QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_LOAD_BALANCING_MODE : uint
    {
        QUIC_LOAD_BALANCING_DISABLED,
        QUIC_LOAD_BALANCING_SERVER_ID_IP,
        QUIC_LOAD_BALANCING_SERVER_ID_FIXED,
        QUIC_LOAD_BALANCING_COUNT,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_TLS_ALERT_CODES : uint
    {
        QUIC_TLS_ALERT_CODE_SUCCESS = 0xFFFF,
        QUIC_TLS_ALERT_CODE_UNEXPECTED_MESSAGE = 10,
        QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE = 42,
        QUIC_TLS_ALERT_CODE_UNSUPPORTED_CERTIFICATE = 43,
        QUIC_TLS_ALERT_CODE_CERTIFICATE_REVOKED = 44,
        QUIC_TLS_ALERT_CODE_CERTIFICATE_EXPIRED = 45,
        QUIC_TLS_ALERT_CODE_CERTIFICATE_UNKNOWN = 46,
        QUIC_TLS_ALERT_CODE_ILLEGAL_PARAMETER = 47,
        QUIC_TLS_ALERT_CODE_UNKNOWN_CA = 48,
        QUIC_TLS_ALERT_CODE_ACCESS_DENIED = 49,
        QUIC_TLS_ALERT_CODE_INSUFFICIENT_SECURITY = 71,
        QUIC_TLS_ALERT_CODE_INTERNAL_ERROR = 80,
        QUIC_TLS_ALERT_CODE_USER_CANCELED = 90,
        QUIC_TLS_ALERT_CODE_CERTIFICATE_REQUIRED = 116,
        QUIC_TLS_ALERT_CODE_MAX = 255,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CREDENTIAL_TYPE : uint
    {
        QUIC_CREDENTIAL_TYPE_NONE,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED,
        QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CREDENTIAL_FLAGS : uint
    {
        QUIC_CREDENTIAL_FLAG_NONE = 0x00000000,
        QUIC_CREDENTIAL_FLAG_CLIENT = 0x00000001,
        QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS = 0x00000002,
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION = 0x00000004,
        QUIC_CREDENTIAL_FLAG_ENABLE_OCSP = 0x00000008,
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED = 0x00000010,
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION = 0x00000020,
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION = 0x00000040,
        QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION = 0x00000080,
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT = 0x00000100,
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN = 0x00000200,
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400,
        QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK = 0x00000800,
        QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE = 0x00001000,
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES = 0x00002000,
        QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES = 0x00004000,
        QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS = 0x00008000,
        QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER = 0x00010000,
        QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL = 0x00020000,
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY = 0x00040000,
        QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE = 0x00080000,
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE = 0x00100000,
        QUIC_CREDENTIAL_FLAG_DISABLE_AIA = 0x00200000,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_ALLOWED_CIPHER_SUITE_FLAGS : uint
    {
        QUIC_ALLOWED_CIPHER_SUITE_NONE = 0x0,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 = 0x1,
        QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 = 0x2,
        QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 = 0x4,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CERTIFICATE_HASH_STORE_FLAGS : uint
    {
        QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE = 0x0000,
        QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE = 0x0001,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CONNECTION_SHUTDOWN_FLAGS : uint
    {
        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE = 0x0000,
        QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT = 0x0001,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_SERVER_RESUMPTION_LEVEL : uint
    {
        QUIC_SERVER_NO_RESUME,
        QUIC_SERVER_RESUME_ONLY,
        QUIC_SERVER_RESUME_AND_ZERORTT,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_SEND_RESUMPTION_FLAGS : uint
    {
        QUIC_SEND_RESUMPTION_FLAG_NONE = 0x0000,
        QUIC_SEND_RESUMPTION_FLAG_FINAL = 0x0001,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_STREAM_SCHEDULING_SCHEME : uint
    {
        QUIC_STREAM_SCHEDULING_SCHEME_FIFO = 0x0000,
        QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN = 0x0001,
        QUIC_STREAM_SCHEDULING_SCHEME_COUNT,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_STREAM_OPEN_FLAGS : uint
    {
        QUIC_STREAM_OPEN_FLAG_NONE = 0x0000,
        QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL = 0x0001,
        QUIC_STREAM_OPEN_FLAG_0_RTT = 0x0002,
        QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES = 0x0004,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_STREAM_START_FLAGS : uint
    {
        QUIC_STREAM_START_FLAG_NONE = 0x0000,
        QUIC_STREAM_START_FLAG_IMMEDIATE = 0x0001,
        QUIC_STREAM_START_FLAG_FAIL_BLOCKED = 0x0002,
        QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL = 0x0004,
        QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT = 0x0008,
        QUIC_STREAM_START_FLAG_PRIORITY_WORK = 0x0010,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_STREAM_SHUTDOWN_FLAGS : uint
    {
        QUIC_STREAM_SHUTDOWN_FLAG_NONE = 0x0000,
        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL = 0x0001,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND = 0x0002,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE = 0x0004,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 0x0006,
        QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE = 0x0008,
        QUIC_STREAM_SHUTDOWN_FLAG_INLINE = 0x0010,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_RECEIVE_FLAGS : uint
    {
        QUIC_RECEIVE_FLAG_NONE = 0x0000,
        QUIC_RECEIVE_FLAG_0_RTT = 0x0001,
        QUIC_RECEIVE_FLAG_FIN = 0x0002,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_SEND_FLAGS : uint
    {
        QUIC_SEND_FLAG_NONE = 0x0000,
        QUIC_SEND_FLAG_ALLOW_0_RTT = 0x0001,
        QUIC_SEND_FLAG_START = 0x0002,
        QUIC_SEND_FLAG_FIN = 0x0004,
        QUIC_SEND_FLAG_DGRAM_PRIORITY = 0x0008,
        QUIC_SEND_FLAG_DELAY_SEND = 0x0010,
        QUIC_SEND_FLAG_CANCEL_ON_LOSS = 0x0020,
        QUIC_SEND_FLAG_PRIORITY_WORK = 0x0040,
        QUIC_SEND_FLAG_CANCEL_ON_BLOCKED = 0x0080,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_DATAGRAM_SEND_STATE : uint
    {
        QUIC_DATAGRAM_SEND_UNKNOWN,
        QUIC_DATAGRAM_SEND_SENT,
        QUIC_DATAGRAM_SEND_LOST_SUSPECT,
        QUIC_DATAGRAM_SEND_LOST_DISCARDED,
        QUIC_DATAGRAM_SEND_ACKNOWLEDGED,
        QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS,
        QUIC_DATAGRAM_SEND_CANCELED,
    }

    public unsafe partial struct QUIC_REGISTRATION_CONFIG
    {
        [NativeTypeName("const char *")]
        public sbyte* AppName;

        public QUIC_EXECUTION_PROFILE ExecutionProfile;
    }

    public partial struct QUIC_CERTIFICATE_HASH
    {
        [NativeTypeName("uint8_t[20]")]
        public _ShaHash_e__FixedBuffer ShaHash;

        [InlineArray(20)]
        public partial struct _ShaHash_e__FixedBuffer
        {
            public byte e0;
        }
    }

    public partial struct QUIC_CERTIFICATE_HASH_STORE
    {
        public QUIC_CERTIFICATE_HASH_STORE_FLAGS Flags;

        [NativeTypeName("uint8_t[20]")]
        public _ShaHash_e__FixedBuffer ShaHash;

        [NativeTypeName("char[128]")]
        public _StoreName_e__FixedBuffer StoreName;

        [InlineArray(20)]
        public partial struct _ShaHash_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(128)]
        public partial struct _StoreName_e__FixedBuffer
        {
            public sbyte e0;
        }
    }

    public unsafe partial struct QUIC_CERTIFICATE_FILE
    {
        [NativeTypeName("const char *")]
        public sbyte* PrivateKeyFile;

        [NativeTypeName("const char *")]
        public sbyte* CertificateFile;
    }

    public unsafe partial struct QUIC_CERTIFICATE_FILE_PROTECTED
    {
        [NativeTypeName("const char *")]
        public sbyte* PrivateKeyFile;

        [NativeTypeName("const char *")]
        public sbyte* CertificateFile;

        [NativeTypeName("const char *")]
        public sbyte* PrivateKeyPassword;
    }

    public unsafe partial struct QUIC_CERTIFICATE_PKCS12
    {
        [NativeTypeName("const uint8_t *")]
        public byte* Asn1Blob;

        [NativeTypeName("uint32_t")]
        public uint Asn1BlobLength;

        [NativeTypeName("const char *")]
        public sbyte* PrivateKeyPassword;
    }

    public unsafe partial struct QUIC_CREDENTIAL_CONFIG
    {
        public QUIC_CREDENTIAL_TYPE Type;

        public QUIC_CREDENTIAL_FLAGS Flags;

        [NativeTypeName("__AnonymousRecord_msquic_L423_C5")]
        public _Anonymous_e__Union Anonymous;

        [NativeTypeName("const char *")]
        public sbyte* Principal;

        public void* Reserved;

        [NativeTypeName("QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, uint, void> AsyncHandler;

        public QUIC_ALLOWED_CIPHER_SUITE_FLAGS AllowedCipherSuites;

        [NativeTypeName("const char *")]
        public sbyte* CaCertificateFile;

        [UnscopedRef]
        public ref QUIC_CERTIFICATE_HASH* CertificateHash
        {
            get
            {
                return ref Anonymous.CertificateHash;
            }
        }

        [UnscopedRef]
        public ref QUIC_CERTIFICATE_HASH_STORE* CertificateHashStore
        {
            get
            {
                return ref Anonymous.CertificateHashStore;
            }
        }

        [UnscopedRef]
        public ref void* CertificateContext
        {
            get
            {
                return ref Anonymous.CertificateContext;
            }
        }

        [UnscopedRef]
        public ref QUIC_CERTIFICATE_FILE* CertificateFile
        {
            get
            {
                return ref Anonymous.CertificateFile;
            }
        }

        [UnscopedRef]
        public ref QUIC_CERTIFICATE_FILE_PROTECTED* CertificateFileProtected
        {
            get
            {
                return ref Anonymous.CertificateFileProtected;
            }
        }

        [UnscopedRef]
        public ref QUIC_CERTIFICATE_PKCS12* CertificatePkcs12
        {
            get
            {
                return ref Anonymous.CertificatePkcs12;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe partial struct _Anonymous_e__Union
        {
            [FieldOffset(0)]
            public QUIC_CERTIFICATE_HASH* CertificateHash;

            [FieldOffset(0)]
            public QUIC_CERTIFICATE_HASH_STORE* CertificateHashStore;

            [FieldOffset(0)]
            [NativeTypeName("QUIC_CERTIFICATE *")]
            public void* CertificateContext;

            [FieldOffset(0)]
            public QUIC_CERTIFICATE_FILE* CertificateFile;

            [FieldOffset(0)]
            public QUIC_CERTIFICATE_FILE_PROTECTED* CertificateFileProtected;

            [FieldOffset(0)]
            public QUIC_CERTIFICATE_PKCS12* CertificatePkcs12;
        }
    }

    public partial struct QUIC_TICKET_KEY_CONFIG
    {
        [NativeTypeName("uint8_t[16]")]
        public _Id_e__FixedBuffer Id;

        [NativeTypeName("uint8_t[64]")]
        public _Material_e__FixedBuffer Material;

        [NativeTypeName("uint8_t")]
        public byte MaterialLength;

        [InlineArray(16)]
        public partial struct _Id_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _Material_e__FixedBuffer
        {
            public byte e0;
        }
    }

    public unsafe partial struct QUIC_BUFFER
    {
        [NativeTypeName("uint32_t")]
        public uint Length;

        [NativeTypeName("uint8_t *")]
        public byte* Buffer;
    }

    public unsafe partial struct QUIC_NEW_CONNECTION_INFO
    {
        [NativeTypeName("uint32_t")]
        public uint QuicVersion;

        [NativeTypeName("const QUIC_ADDR *")]
        public IntPtr LocalAddress;

        [NativeTypeName("const QUIC_ADDR *")]
        public IntPtr RemoteAddress;

        [NativeTypeName("uint32_t")]
        public uint CryptoBufferLength;

        [NativeTypeName("uint16_t")]
        public ushort ClientAlpnListLength;

        [NativeTypeName("uint16_t")]
        public ushort ServerNameLength;

        [NativeTypeName("uint8_t")]
        public byte NegotiatedAlpnLength;

        [NativeTypeName("const uint8_t *")]
        public byte* CryptoBuffer;

        [NativeTypeName("const uint8_t *")]
        public byte* ClientAlpnList;

        [NativeTypeName("const uint8_t *")]
        public byte* NegotiatedAlpn;

        [NativeTypeName("const char *")]
        public sbyte* ServerName;
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_TLS_PROTOCOL_VERSION : uint
    {
        QUIC_TLS_PROTOCOL_UNKNOWN = 0,
        QUIC_TLS_PROTOCOL_1_3 = 0x3000,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CIPHER_ALGORITHM : uint
    {
        QUIC_CIPHER_ALGORITHM_NONE = 0,
        QUIC_CIPHER_ALGORITHM_AES_128 = 0x660E,
        QUIC_CIPHER_ALGORITHM_AES_256 = 0x6610,
        QUIC_CIPHER_ALGORITHM_CHACHA20 = 0x6612,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_HASH_ALGORITHM : uint
    {
        QUIC_HASH_ALGORITHM_NONE = 0,
        QUIC_HASH_ALGORITHM_SHA_256 = 0x800C,
        QUIC_HASH_ALGORITHM_SHA_384 = 0x800D,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_KEY_EXCHANGE_ALGORITHM : uint
    {
        QUIC_KEY_EXCHANGE_ALGORITHM_NONE = 0,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_TLS_GROUP : uint
    {
        QUIC_TLS_GROUP_UNKNOWN = 0,
        QUIC_TLS_GROUP_SECP256R1 = 23,
        QUIC_TLS_GROUP_SECP384R1 = 24,
        QUIC_TLS_GROUP_X25519 = 29,
        QUIC_TLS_GROUP_MLKEM512 = 512,
        QUIC_TLS_GROUP_MLKEM768 = 513,
        QUIC_TLS_GROUP_MLKEM1024 = 514,
        QUIC_TLS_GROUP_SECP256R1MLKEM768 = 4587,
        QUIC_TLS_GROUP_X25519MLKEM768 = 4588,
        QUIC_TLS_GROUP_SECP384R1MLKEM1024 = 4589,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CIPHER_SUITE : uint
    {
        QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256 = 0x1301,
        QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384 = 0x1302,
        QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CONGESTION_CONTROL_ALGORITHM : uint
    {
        QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC,
        QUIC_CONGESTION_CONTROL_ALGORITHM_MAX,
    }

    public partial struct QUIC_HANDSHAKE_INFO
    {
        public QUIC_TLS_PROTOCOL_VERSION TlsProtocolVersion;

        public QUIC_CIPHER_ALGORITHM CipherAlgorithm;

        [NativeTypeName("int32_t")]
        public int CipherStrength;

        public QUIC_HASH_ALGORITHM Hash;

        [NativeTypeName("int32_t")]
        public int HashStrength;

        public QUIC_KEY_EXCHANGE_ALGORITHM KeyExchangeAlgorithm;

        [NativeTypeName("int32_t")]
        public int KeyExchangeStrength;

        public QUIC_CIPHER_SUITE CipherSuite;

        public QUIC_TLS_GROUP TlsGroup;
    }

    public partial struct QUIC_STATISTICS
    {
        [NativeTypeName("uint64_t")]
        public ulong CorrelationId;

        public uint _bitfield;

        [NativeTypeName("uint32_t : 1")]
        public uint VersionNegotiation
        {
            readonly get
            {
                return _bitfield & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~0x1u) | (value & 0x1u);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint StatelessRetry
        {
            readonly get
            {
                return (_bitfield >> 1) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint ResumptionAttempted
        {
            readonly get
            {
                return (_bitfield >> 2) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint ResumptionSucceeded
        {
            readonly get
            {
                return (_bitfield >> 3) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 3)) | ((value & 0x1u) << 3);
            }
        }

        [NativeTypeName("uint32_t")]
        public uint Rtt;

        [NativeTypeName("uint32_t")]
        public uint MinRtt;

        [NativeTypeName("uint32_t")]
        public uint MaxRtt;

        [NativeTypeName("__AnonymousRecord_msquic_L562_C5")]
        public _Timing_e__Struct Timing;

        [NativeTypeName("__AnonymousRecord_msquic_L567_C5")]
        public _Handshake_e__Struct Handshake;

        [NativeTypeName("__AnonymousRecord_msquic_L572_C5")]
        public _Send_e__Struct Send;

        [NativeTypeName("__AnonymousRecord_msquic_L583_C5")]
        public _Recv_e__Struct Recv;

        [NativeTypeName("__AnonymousRecord_msquic_L593_C5")]
        public _Misc_e__Struct Misc;

        public partial struct _Timing_e__Struct
        {
            [NativeTypeName("uint64_t")]
            public ulong Start;

            [NativeTypeName("uint64_t")]
            public ulong InitialFlightEnd;

            [NativeTypeName("uint64_t")]
            public ulong HandshakeFlightEnd;
        }

        public partial struct _Handshake_e__Struct
        {
            [NativeTypeName("uint32_t")]
            public uint ClientFlight1Bytes;

            [NativeTypeName("uint32_t")]
            public uint ServerFlight1Bytes;

            [NativeTypeName("uint32_t")]
            public uint ClientFlight2Bytes;
        }

        public partial struct _Send_e__Struct
        {
            [NativeTypeName("uint16_t")]
            public ushort PathMtu;

            [NativeTypeName("uint64_t")]
            public ulong TotalPackets;

            [NativeTypeName("uint64_t")]
            public ulong RetransmittablePackets;

            [NativeTypeName("uint64_t")]
            public ulong SuspectedLostPackets;

            [NativeTypeName("uint64_t")]
            public ulong SpuriousLostPackets;

            [NativeTypeName("uint64_t")]
            public ulong TotalBytes;

            [NativeTypeName("uint64_t")]
            public ulong TotalStreamBytes;

            [NativeTypeName("uint32_t")]
            public uint CongestionCount;

            [NativeTypeName("uint32_t")]
            public uint PersistentCongestionCount;
        }

        public partial struct _Recv_e__Struct
        {
            [NativeTypeName("uint64_t")]
            public ulong TotalPackets;

            [NativeTypeName("uint64_t")]
            public ulong ReorderedPackets;

            [NativeTypeName("uint64_t")]
            public ulong DroppedPackets;

            [NativeTypeName("uint64_t")]
            public ulong DuplicatePackets;

            [NativeTypeName("uint64_t")]
            public ulong TotalBytes;

            [NativeTypeName("uint64_t")]
            public ulong TotalStreamBytes;

            [NativeTypeName("uint64_t")]
            public ulong DecryptionFailures;

            [NativeTypeName("uint64_t")]
            public ulong ValidAckFrames;
        }

        public partial struct _Misc_e__Struct
        {
            [NativeTypeName("uint32_t")]
            public uint KeyUpdateCount;
        }
    }

    public partial struct QUIC_STATISTICS_V2
    {
        [NativeTypeName("uint64_t")]
        public ulong CorrelationId;

        public uint _bitfield;

        [NativeTypeName("uint32_t : 1")]
        public uint VersionNegotiation
        {
            readonly get
            {
                return _bitfield & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~0x1u) | (value & 0x1u);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint StatelessRetry
        {
            readonly get
            {
                return (_bitfield >> 1) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint ResumptionAttempted
        {
            readonly get
            {
                return (_bitfield >> 2) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint ResumptionSucceeded
        {
            readonly get
            {
                return (_bitfield >> 3) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 3)) | ((value & 0x1u) << 3);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint GreaseBitNegotiated
        {
            readonly get
            {
                return (_bitfield >> 4) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 4)) | ((value & 0x1u) << 4);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint EcnCapable
        {
            readonly get
            {
                return (_bitfield >> 5) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 5)) | ((value & 0x1u) << 5);
            }
        }

        [NativeTypeName("uint32_t : 1")]
        public uint EncryptionOffloaded
        {
            readonly get
            {
                return (_bitfield >> 6) & 0x1u;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1u << 6)) | ((value & 0x1u) << 6);
            }
        }

        [NativeTypeName("uint32_t : 25")]
        public uint RESERVED
        {
            readonly get
            {
                return (_bitfield >> 7) & 0x1FFFFFFu;
            }

            set
            {
                _bitfield = (_bitfield & ~(0x1FFFFFFu << 7)) | ((value & 0x1FFFFFFu) << 7);
            }
        }

        [NativeTypeName("uint32_t")]
        public uint Rtt;

        [NativeTypeName("uint32_t")]
        public uint MinRtt;

        [NativeTypeName("uint32_t")]
        public uint MaxRtt;

        [NativeTypeName("uint64_t")]
        public ulong TimingStart;

        [NativeTypeName("uint64_t")]
        public ulong TimingInitialFlightEnd;

        [NativeTypeName("uint64_t")]
        public ulong TimingHandshakeFlightEnd;

        [NativeTypeName("uint32_t")]
        public uint HandshakeClientFlight1Bytes;

        [NativeTypeName("uint32_t")]
        public uint HandshakeServerFlight1Bytes;

        [NativeTypeName("uint32_t")]
        public uint HandshakeClientFlight2Bytes;

        [NativeTypeName("uint16_t")]
        public ushort SendPathMtu;

        [NativeTypeName("uint64_t")]
        public ulong SendTotalPackets;

        [NativeTypeName("uint64_t")]
        public ulong SendRetransmittablePackets;

        [NativeTypeName("uint64_t")]
        public ulong SendSuspectedLostPackets;

        [NativeTypeName("uint64_t")]
        public ulong SendSpuriousLostPackets;

        [NativeTypeName("uint64_t")]
        public ulong SendTotalBytes;

        [NativeTypeName("uint64_t")]
        public ulong SendTotalStreamBytes;

        [NativeTypeName("uint32_t")]
        public uint SendCongestionCount;

        [NativeTypeName("uint32_t")]
        public uint SendPersistentCongestionCount;

        [NativeTypeName("uint64_t")]
        public ulong RecvTotalPackets;

        [NativeTypeName("uint64_t")]
        public ulong RecvReorderedPackets;

        [NativeTypeName("uint64_t")]
        public ulong RecvDroppedPackets;

        [NativeTypeName("uint64_t")]
        public ulong RecvDuplicatePackets;

        [NativeTypeName("uint64_t")]
        public ulong RecvTotalBytes;

        [NativeTypeName("uint64_t")]
        public ulong RecvTotalStreamBytes;

        [NativeTypeName("uint64_t")]
        public ulong RecvDecryptionFailures;

        [NativeTypeName("uint64_t")]
        public ulong RecvValidAckFrames;

        [NativeTypeName("uint32_t")]
        public uint KeyUpdateCount;

        [NativeTypeName("uint32_t")]
        public uint SendCongestionWindow;

        [NativeTypeName("uint32_t")]
        public uint DestCidUpdateCount;

        [NativeTypeName("uint32_t")]
        public uint SendEcnCongestionCount;

        [NativeTypeName("uint8_t")]
        public byte HandshakeHopLimitTTL;

        [NativeTypeName("uint32_t")]
        public uint RttVariance;
    }

    public partial struct QUIC_NETWORK_STATISTICS
    {
        [NativeTypeName("uint32_t")]
        public uint BytesInFlight;

        [NativeTypeName("uint64_t")]
        public ulong PostedBytes;

        [NativeTypeName("uint64_t")]
        public ulong IdealBytes;

        [NativeTypeName("uint64_t")]
        public ulong SmoothedRTT;

        [NativeTypeName("uint32_t")]
        public uint CongestionWindow;

        [NativeTypeName("uint64_t")]
        public ulong Bandwidth;
    }

    public partial struct QUIC_LISTENER_STATISTICS
    {
        [NativeTypeName("uint64_t")]
        public ulong TotalAcceptedConnections;

        [NativeTypeName("uint64_t")]
        public ulong TotalRejectedConnections;

        [NativeTypeName("uint64_t")]
        public ulong BindingRecvDroppedPackets;
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_PERFORMANCE_COUNTERS : uint
    {
        QUIC_PERF_COUNTER_CONN_CREATED,
        QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL,
        QUIC_PERF_COUNTER_CONN_APP_REJECT,
        QUIC_PERF_COUNTER_CONN_RESUMED,
        QUIC_PERF_COUNTER_CONN_ACTIVE,
        QUIC_PERF_COUNTER_CONN_CONNECTED,
        QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS,
        QUIC_PERF_COUNTER_CONN_NO_ALPN,
        QUIC_PERF_COUNTER_STRM_ACTIVE,
        QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST,
        QUIC_PERF_COUNTER_PKTS_DROPPED,
        QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL,
        QUIC_PERF_COUNTER_UDP_RECV,
        QUIC_PERF_COUNTER_UDP_SEND,
        QUIC_PERF_COUNTER_UDP_RECV_BYTES,
        QUIC_PERF_COUNTER_UDP_SEND_BYTES,
        QUIC_PERF_COUNTER_UDP_RECV_EVENTS,
        QUIC_PERF_COUNTER_UDP_SEND_CALLS,
        QUIC_PERF_COUNTER_APP_SEND_BYTES,
        QUIC_PERF_COUNTER_APP_RECV_BYTES,
        QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH,
        QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH,
        QUIC_PERF_COUNTER_CONN_OPER_QUEUED,
        QUIC_PERF_COUNTER_CONN_OPER_COMPLETED,
        QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH,
        QUIC_PERF_COUNTER_WORK_OPER_QUEUED,
        QUIC_PERF_COUNTER_WORK_OPER_COMPLETED,
        QUIC_PERF_COUNTER_PATH_VALIDATED,
        QUIC_PERF_COUNTER_PATH_FAILURE,
        QUIC_PERF_COUNTER_SEND_STATELESS_RESET,
        QUIC_PERF_COUNTER_SEND_STATELESS_RETRY,
        QUIC_PERF_COUNTER_CONN_LOAD_REJECT,
        QUIC_PERF_COUNTER_LISTEN_QUEUE_DEPTH,
        QUIC_PERF_COUNTER_MAX,
    }

    public partial struct QUIC_GLOBAL_SETTINGS
    {
        [NativeTypeName("__AnonymousRecord_msquic_L740_C5")]
        public _Anonymous_e__Union Anonymous;

        [NativeTypeName("uint16_t")]
        public ushort RetryMemoryLimit;

        [NativeTypeName("uint16_t")]
        public ushort LoadBalancingMode;

        [NativeTypeName("uint32_t")]
        public uint FixedServerID;

        [UnscopedRef]
        public ref ulong IsSetFlags
        {
            get
            {
                return ref Anonymous.IsSetFlags;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._IsSet_e__Struct IsSet
        {
            get
            {
                return ref Anonymous.IsSet;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("uint64_t")]
            public ulong IsSetFlags;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L742_C9")]
            public _IsSet_e__Struct IsSet;

            public partial struct _IsSet_e__Struct
            {
                public ulong _bitfield;

                [NativeTypeName("uint64_t : 1")]
                public ulong RetryMemoryLimit
                {
                    readonly get
                    {
                        return _bitfield & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~0x1UL) | (value & 0x1UL);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong LoadBalancingMode
                {
                    readonly get
                    {
                        return (_bitfield >> 1) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 1)) | ((value & 0x1UL) << 1);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong FixedServerID
                {
                    readonly get
                    {
                        return (_bitfield >> 2) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 2)) | ((value & 0x1UL) << 2);
                    }
                }

                [NativeTypeName("uint64_t : 61")]
                public ulong RESERVED
                {
                    readonly get
                    {
                        return (_bitfield >> 3) & 0x1FFFFFFFUL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1FFFFFFFUL << 3)) | ((value & 0x1FFFFFFFUL) << 3);
                    }
                }
            }
        }
    }

    public partial struct QUIC_SETTINGS
    {
        [NativeTypeName("__AnonymousRecord_msquic_L756_C5")]
        public _Anonymous1_e__Union Anonymous1;

        [NativeTypeName("uint64_t")]
        public ulong MaxBytesPerKey;

        [NativeTypeName("uint64_t")]
        public ulong HandshakeIdleTimeoutMs;

        [NativeTypeName("uint64_t")]
        public ulong IdleTimeoutMs;

        [NativeTypeName("uint64_t")]
        public ulong MtuDiscoverySearchCompleteTimeoutUs;

        [NativeTypeName("uint32_t")]
        public uint TlsClientMaxSendBuffer;

        [NativeTypeName("uint32_t")]
        public uint TlsServerMaxSendBuffer;

        [NativeTypeName("uint32_t")]
        public uint StreamRecvWindowDefault;

        [NativeTypeName("uint32_t")]
        public uint StreamRecvBufferDefault;

        [NativeTypeName("uint32_t")]
        public uint ConnFlowControlWindow;

        [NativeTypeName("uint32_t")]
        public uint MaxWorkerQueueDelayUs;

        [NativeTypeName("uint32_t")]
        public uint MaxStatelessOperations;

        [NativeTypeName("uint32_t")]
        public uint InitialWindowPackets;

        [NativeTypeName("uint32_t")]
        public uint SendIdleTimeoutMs;

        [NativeTypeName("uint32_t")]
        public uint InitialRttMs;

        [NativeTypeName("uint32_t")]
        public uint MaxAckDelayMs;

        [NativeTypeName("uint32_t")]
        public uint DisconnectTimeoutMs;

        [NativeTypeName("uint32_t")]
        public uint KeepAliveIntervalMs;

        [NativeTypeName("uint16_t")]
        public ushort CongestionControlAlgorithm;

        [NativeTypeName("uint16_t")]
        public ushort PeerBidiStreamCount;

        [NativeTypeName("uint16_t")]
        public ushort PeerUnidiStreamCount;

        [NativeTypeName("uint16_t")]
        public ushort MaxBindingStatelessOperations;

        [NativeTypeName("uint16_t")]
        public ushort StatelessOperationExpirationMs;

        [NativeTypeName("uint16_t")]
        public ushort MinimumMtu;

        [NativeTypeName("uint16_t")]
        public ushort MaximumMtu;

        public byte _bitfield;

        [NativeTypeName("uint8_t : 1")]
        public byte SendBufferingEnabled
        {
            readonly get
            {
                return (byte)(_bitfield & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
            }
        }

        [NativeTypeName("uint8_t : 1")]
        public byte PacingEnabled
        {
            readonly get
            {
                return (byte)((_bitfield >> 1) & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1));
            }
        }

        [NativeTypeName("uint8_t : 1")]
        public byte MigrationEnabled
        {
            readonly get
            {
                return (byte)((_bitfield >> 2) & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2));
            }
        }

        [NativeTypeName("uint8_t : 1")]
        public byte DatagramReceiveEnabled
        {
            readonly get
            {
                return (byte)((_bitfield >> 3) & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x1u << 3)) | ((value & 0x1u) << 3));
            }
        }

        [NativeTypeName("uint8_t : 2")]
        public byte ServerResumptionLevel
        {
            readonly get
            {
                return (byte)((_bitfield >> 4) & 0x3u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x3u << 4)) | ((value & 0x3u) << 4));
            }
        }

        [NativeTypeName("uint8_t : 1")]
        public byte GreaseQuicBitEnabled
        {
            readonly get
            {
                return (byte)((_bitfield >> 6) & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x1u << 6)) | ((value & 0x1u) << 6));
            }
        }

        [NativeTypeName("uint8_t : 1")]
        public byte EcnEnabled
        {
            readonly get
            {
                return (byte)((_bitfield >> 7) & 0x1u);
            }

            set
            {
                _bitfield = (byte)((_bitfield & ~(0x1u << 7)) | ((value & 0x1u) << 7));
            }
        }

        [NativeTypeName("uint8_t")]
        public byte MaxOperationsPerDrain;

        [NativeTypeName("uint8_t")]
        public byte MtuDiscoveryMissingProbeCount;

        [NativeTypeName("uint32_t")]
        public uint DestCidUpdateIdleTimeoutMs;

        [NativeTypeName("__AnonymousRecord_msquic_L847_C5")]
        public _Anonymous2_e__Union Anonymous2;

        [NativeTypeName("uint32_t")]
        public uint StreamRecvWindowBidiLocalDefault;

        [NativeTypeName("uint32_t")]
        public uint StreamRecvWindowBidiRemoteDefault;

        [NativeTypeName("uint32_t")]
        public uint StreamRecvWindowUnidiDefault;

        [UnscopedRef]
        public ref ulong IsSetFlags
        {
            get
            {
                return ref Anonymous1.IsSetFlags;
            }
        }

        [UnscopedRef]
        public ref _Anonymous1_e__Union._IsSet_e__Struct IsSet
        {
            get
            {
                return ref Anonymous1.IsSet;
            }
        }

        [UnscopedRef]
        public ref ulong Flags
        {
            get
            {
                return ref Anonymous2.Flags;
            }
        }

        public ulong HyStartEnabled
        {
            readonly get
            {
                return Anonymous2.Anonymous.HyStartEnabled;
            }

            set
            {
                Anonymous2.Anonymous.HyStartEnabled = value;
            }
        }

        public ulong ReservedFlags
        {
            readonly get
            {
                return Anonymous2.Anonymous.ReservedFlags;
            }

            set
            {
                Anonymous2.Anonymous.ReservedFlags = value;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous1_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("uint64_t")]
            public ulong IsSetFlags;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L758_C9")]
            public _IsSet_e__Struct IsSet;

            public partial struct _IsSet_e__Struct
            {
                public ulong _bitfield;

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxBytesPerKey
                {
                    readonly get
                    {
                        return _bitfield & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~0x1UL) | (value & 0x1UL);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong HandshakeIdleTimeoutMs
                {
                    readonly get
                    {
                        return (_bitfield >> 1) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 1)) | ((value & 0x1UL) << 1);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong IdleTimeoutMs
                {
                    readonly get
                    {
                        return (_bitfield >> 2) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 2)) | ((value & 0x1UL) << 2);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MtuDiscoverySearchCompleteTimeoutUs
                {
                    readonly get
                    {
                        return (_bitfield >> 3) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 3)) | ((value & 0x1UL) << 3);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong TlsClientMaxSendBuffer
                {
                    readonly get
                    {
                        return (_bitfield >> 4) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 4)) | ((value & 0x1UL) << 4);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong TlsServerMaxSendBuffer
                {
                    readonly get
                    {
                        return (_bitfield >> 5) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 5)) | ((value & 0x1UL) << 5);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StreamRecvWindowDefault
                {
                    readonly get
                    {
                        return (_bitfield >> 6) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 6)) | ((value & 0x1UL) << 6);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StreamRecvBufferDefault
                {
                    readonly get
                    {
                        return (_bitfield >> 7) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 7)) | ((value & 0x1UL) << 7);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong ConnFlowControlWindow
                {
                    readonly get
                    {
                        return (_bitfield >> 8) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 8)) | ((value & 0x1UL) << 8);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxWorkerQueueDelayUs
                {
                    readonly get
                    {
                        return (_bitfield >> 9) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 9)) | ((value & 0x1UL) << 9);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxStatelessOperations
                {
                    readonly get
                    {
                        return (_bitfield >> 10) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 10)) | ((value & 0x1UL) << 10);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong InitialWindowPackets
                {
                    readonly get
                    {
                        return (_bitfield >> 11) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 11)) | ((value & 0x1UL) << 11);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong SendIdleTimeoutMs
                {
                    readonly get
                    {
                        return (_bitfield >> 12) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 12)) | ((value & 0x1UL) << 12);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong InitialRttMs
                {
                    readonly get
                    {
                        return (_bitfield >> 13) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 13)) | ((value & 0x1UL) << 13);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxAckDelayMs
                {
                    readonly get
                    {
                        return (_bitfield >> 14) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 14)) | ((value & 0x1UL) << 14);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong DisconnectTimeoutMs
                {
                    readonly get
                    {
                        return (_bitfield >> 15) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 15)) | ((value & 0x1UL) << 15);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong KeepAliveIntervalMs
                {
                    readonly get
                    {
                        return (_bitfield >> 16) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 16)) | ((value & 0x1UL) << 16);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong CongestionControlAlgorithm
                {
                    readonly get
                    {
                        return (_bitfield >> 17) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 17)) | ((value & 0x1UL) << 17);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong PeerBidiStreamCount
                {
                    readonly get
                    {
                        return (_bitfield >> 18) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 18)) | ((value & 0x1UL) << 18);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong PeerUnidiStreamCount
                {
                    readonly get
                    {
                        return (_bitfield >> 19) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 19)) | ((value & 0x1UL) << 19);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxBindingStatelessOperations
                {
                    readonly get
                    {
                        return (_bitfield >> 20) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 20)) | ((value & 0x1UL) << 20);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StatelessOperationExpirationMs
                {
                    readonly get
                    {
                        return (_bitfield >> 21) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 21)) | ((value & 0x1UL) << 21);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MinimumMtu
                {
                    readonly get
                    {
                        return (_bitfield >> 22) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 22)) | ((value & 0x1UL) << 22);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaximumMtu
                {
                    readonly get
                    {
                        return (_bitfield >> 23) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 23)) | ((value & 0x1UL) << 23);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong SendBufferingEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 24) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 24)) | ((value & 0x1UL) << 24);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong PacingEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 25) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 25)) | ((value & 0x1UL) << 25);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MigrationEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 26) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 26)) | ((value & 0x1UL) << 26);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong DatagramReceiveEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 27) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 27)) | ((value & 0x1UL) << 27);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong ServerResumptionLevel
                {
                    readonly get
                    {
                        return (_bitfield >> 28) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 28)) | ((value & 0x1UL) << 28);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MaxOperationsPerDrain
                {
                    readonly get
                    {
                        return (_bitfield >> 29) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 29)) | ((value & 0x1UL) << 29);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong MtuDiscoveryMissingProbeCount
                {
                    readonly get
                    {
                        return (_bitfield >> 30) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 30)) | ((value & 0x1UL) << 30);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong DestCidUpdateIdleTimeoutMs
                {
                    readonly get
                    {
                        return (_bitfield >> 31) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 31)) | ((value & 0x1UL) << 31);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong GreaseQuicBitEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 32) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 32)) | ((value & 0x1UL) << 32);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong EcnEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 33) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 33)) | ((value & 0x1UL) << 33);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong HyStartEnabled
                {
                    readonly get
                    {
                        return (_bitfield >> 34) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 34)) | ((value & 0x1UL) << 34);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StreamRecvWindowBidiLocalDefault
                {
                    readonly get
                    {
                        return (_bitfield >> 35) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 35)) | ((value & 0x1UL) << 35);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StreamRecvWindowBidiRemoteDefault
                {
                    readonly get
                    {
                        return (_bitfield >> 36) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 36)) | ((value & 0x1UL) << 36);
                    }
                }

                [NativeTypeName("uint64_t : 1")]
                public ulong StreamRecvWindowUnidiDefault
                {
                    readonly get
                    {
                        return (_bitfield >> 37) & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x1UL << 37)) | ((value & 0x1UL) << 37);
                    }
                }

                [NativeTypeName("uint64_t : 26")]
                public ulong RESERVED
                {
                    readonly get
                    {
                        return (_bitfield >> 38) & 0x3FFFFFFUL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x3FFFFFFUL << 38)) | ((value & 0x3FFFFFFUL) << 38);
                    }
                }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous2_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("uint64_t")]
            public ulong Flags;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L849_C9")]
            public _Anonymous_e__Struct Anonymous;

            public partial struct _Anonymous_e__Struct
            {
                public ulong _bitfield;

                [NativeTypeName("uint64_t : 1")]
                public ulong HyStartEnabled
                {
                    readonly get
                    {
                        return _bitfield & 0x1UL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~0x1UL) | (value & 0x1UL);
                    }
                }

                [NativeTypeName("uint64_t : 63")]
                public ulong ReservedFlags
                {
                    readonly get
                    {
                        return (_bitfield >> 1) & 0x7FFFFFFFUL;
                    }

                    set
                    {
                        _bitfield = (_bitfield & ~(0x7FFFFFFFUL << 1)) | ((value & 0x7FFFFFFFUL) << 1);
                    }
                }
            }
        }
    }

    public partial struct QUIC_TLS_SECRETS
    {
        [NativeTypeName("uint8_t")]
        public byte SecretLength;

        [NativeTypeName("__AnonymousRecord_msquic_L880_C5")]
        public _IsSet_e__Struct IsSet;

        [NativeTypeName("uint8_t[32]")]
        public _ClientRandom_e__FixedBuffer ClientRandom;

        [NativeTypeName("uint8_t[64]")]
        public _ClientEarlyTrafficSecret_e__FixedBuffer ClientEarlyTrafficSecret;

        [NativeTypeName("uint8_t[64]")]
        public _ClientHandshakeTrafficSecret_e__FixedBuffer ClientHandshakeTrafficSecret;

        [NativeTypeName("uint8_t[64]")]
        public _ServerHandshakeTrafficSecret_e__FixedBuffer ServerHandshakeTrafficSecret;

        [NativeTypeName("uint8_t[64]")]
        public _ClientTrafficSecret0_e__FixedBuffer ClientTrafficSecret0;

        [NativeTypeName("uint8_t[64]")]
        public _ServerTrafficSecret0_e__FixedBuffer ServerTrafficSecret0;

        public partial struct _IsSet_e__Struct
        {
            public byte _bitfield;

            [NativeTypeName("uint8_t : 1")]
            public byte ClientRandom
            {
                readonly get
                {
                    return (byte)(_bitfield & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                }
            }

            [NativeTypeName("uint8_t : 1")]
            public byte ClientEarlyTrafficSecret
            {
                readonly get
                {
                    return (byte)((_bitfield >> 1) & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1));
                }
            }

            [NativeTypeName("uint8_t : 1")]
            public byte ClientHandshakeTrafficSecret
            {
                readonly get
                {
                    return (byte)((_bitfield >> 2) & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2));
                }
            }

            [NativeTypeName("uint8_t : 1")]
            public byte ServerHandshakeTrafficSecret
            {
                readonly get
                {
                    return (byte)((_bitfield >> 3) & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~(0x1u << 3)) | ((value & 0x1u) << 3));
                }
            }

            [NativeTypeName("uint8_t : 1")]
            public byte ClientTrafficSecret0
            {
                readonly get
                {
                    return (byte)((_bitfield >> 4) & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~(0x1u << 4)) | ((value & 0x1u) << 4));
                }
            }

            [NativeTypeName("uint8_t : 1")]
            public byte ServerTrafficSecret0
            {
                readonly get
                {
                    return (byte)((_bitfield >> 5) & 0x1u);
                }

                set
                {
                    _bitfield = (byte)((_bitfield & ~(0x1u << 5)) | ((value & 0x1u) << 5));
                }
            }
        }

        [InlineArray(32)]
        public partial struct _ClientRandom_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _ClientEarlyTrafficSecret_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _ClientHandshakeTrafficSecret_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _ServerHandshakeTrafficSecret_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _ClientTrafficSecret0_e__FixedBuffer
        {
            public byte e0;
        }

        [InlineArray(64)]
        public partial struct _ServerTrafficSecret0_e__FixedBuffer
        {
            public byte e0;
        }
    }

    public partial struct QUIC_STREAM_STATISTICS
    {
        [NativeTypeName("uint64_t")]
        public ulong ConnBlockedBySchedulingUs;

        [NativeTypeName("uint64_t")]
        public ulong ConnBlockedByPacingUs;

        [NativeTypeName("uint64_t")]
        public ulong ConnBlockedByAmplificationProtUs;

        [NativeTypeName("uint64_t")]
        public ulong ConnBlockedByCongestionControlUs;

        [NativeTypeName("uint64_t")]
        public ulong ConnBlockedByFlowControlUs;

        [NativeTypeName("uint64_t")]
        public ulong StreamBlockedByIdFlowControlUs;

        [NativeTypeName("uint64_t")]
        public ulong StreamBlockedByFlowControlUs;

        [NativeTypeName("uint64_t")]
        public ulong StreamBlockedByAppUs;
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_AEAD_ALGORITHM_TYPE : uint
    {
        QUIC_AEAD_ALGORITHM_AES_128_GCM = 0,
        QUIC_AEAD_ALGORITHM_AES_256_GCM = 1,
    }

    public unsafe partial struct QUIC_STATELESS_RETRY_CONFIG
    {
        public QUIC_AEAD_ALGORITHM_TYPE Algorithm;

        [NativeTypeName("uint32_t")]
        public uint RotationMs;

        [NativeTypeName("uint32_t")]
        public uint SecretLength;

        [NativeTypeName("const uint8_t *")]
        public byte* Secret;
    }

    public unsafe partial struct QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W
    {
        [NativeTypeName("unsigned long")]
        public nuint Attribute;

        [NativeTypeName("unsigned long")]
        public nuint BufferLength;

        public void* Buffer;
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_LISTENER_EVENT_TYPE : uint
    {
        QUIC_LISTENER_EVENT_NEW_CONNECTION = 0,
        QUIC_LISTENER_EVENT_STOP_COMPLETE = 1,
        QUIC_LISTENER_EVENT_DOS_MODE_CHANGED = 2,
    }

    public partial struct QUIC_LISTENER_EVENT
    {
        public QUIC_LISTENER_EVENT_TYPE Type;

        [NativeTypeName("__AnonymousRecord_msquic_L1253_C5")]
        public _Anonymous_e__Union Anonymous;

        [UnscopedRef]
        public ref _Anonymous_e__Union._NEW_CONNECTION_e__Struct NEW_CONNECTION
        {
            get
            {
                return ref Anonymous.NEW_CONNECTION;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._STOP_COMPLETE_e__Struct STOP_COMPLETE
        {
            get
            {
                return ref Anonymous.STOP_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._DOS_MODE_CHANGED_e__Struct DOS_MODE_CHANGED
        {
            get
            {
                return ref Anonymous.DOS_MODE_CHANGED;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1254_C9")]
            public _NEW_CONNECTION_e__Struct NEW_CONNECTION;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1258_C9")]
            public _STOP_COMPLETE_e__Struct STOP_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1262_C9")]
            public _DOS_MODE_CHANGED_e__Struct DOS_MODE_CHANGED;

            public unsafe partial struct _NEW_CONNECTION_e__Struct
            {
                [NativeTypeName("const QUIC_NEW_CONNECTION_INFO *")]
                public QUIC_NEW_CONNECTION_INFO* Info;

                [NativeTypeName("HQUIC")]
                public QUIC_HANDLE* Connection;
            }

            public partial struct _STOP_COMPLETE_e__Struct
            {
                public byte _bitfield;

                [NativeTypeName("BOOLEAN : 1")]
                public byte AppCloseInProgress
                {
                    readonly get
                    {
                        return (byte)(_bitfield & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                    }
                }

                [NativeTypeName("BOOLEAN : 7")]
                public byte RESERVED
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 1) & 0x7Fu);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x7Fu << 1)) | ((value & 0x7Fu) << 1));
                    }
                }
            }

            public partial struct _DOS_MODE_CHANGED_e__Struct
            {
                public byte _bitfield;

                [NativeTypeName("BOOLEAN : 1")]
                public byte DosModeEnabled
                {
                    readonly get
                    {
                        return (byte)(_bitfield & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                    }
                }

                [NativeTypeName("BOOLEAN : 7")]
                public byte RESERVED
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 1) & 0x7Fu);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x7Fu << 1)) | ((value & 0x7Fu) << 1));
                    }
                }
            }
        }
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_CONNECTION_EVENT_TYPE : uint
    {
        QUIC_CONNECTION_EVENT_CONNECTED = 0,
        QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = 1,
        QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 2,
        QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = 3,
        QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = 4,
        QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = 5,
        QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 6,
        QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = 7,
        QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = 8,
        QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED = 9,
        QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED = 10,
        QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED = 11,
        QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = 12,
        QUIC_CONNECTION_EVENT_RESUMED = 13,
        QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = 14,
        QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = 15,
    }

    public partial struct QUIC_CONNECTION_EVENT
    {
        public QUIC_CONNECTION_EVENT_TYPE Type;

        [NativeTypeName("__AnonymousRecord_msquic_L1365_C5")]
        public _Anonymous_e__Union Anonymous;

        [UnscopedRef]
        public ref _Anonymous_e__Union._CONNECTED_e__Struct CONNECTED
        {
            get
            {
                return ref Anonymous.CONNECTED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SHUTDOWN_INITIATED_BY_TRANSPORT_e__Struct SHUTDOWN_INITIATED_BY_TRANSPORT
        {
            get
            {
                return ref Anonymous.SHUTDOWN_INITIATED_BY_TRANSPORT;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SHUTDOWN_INITIATED_BY_PEER_e__Struct SHUTDOWN_INITIATED_BY_PEER
        {
            get
            {
                return ref Anonymous.SHUTDOWN_INITIATED_BY_PEER;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SHUTDOWN_COMPLETE_e__Struct SHUTDOWN_COMPLETE
        {
            get
            {
                return ref Anonymous.SHUTDOWN_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._LOCAL_ADDRESS_CHANGED_e__Struct LOCAL_ADDRESS_CHANGED
        {
            get
            {
                return ref Anonymous.LOCAL_ADDRESS_CHANGED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_ADDRESS_CHANGED_e__Struct PEER_ADDRESS_CHANGED
        {
            get
            {
                return ref Anonymous.PEER_ADDRESS_CHANGED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_STREAM_STARTED_e__Struct PEER_STREAM_STARTED
        {
            get
            {
                return ref Anonymous.PEER_STREAM_STARTED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._STREAMS_AVAILABLE_e__Struct STREAMS_AVAILABLE
        {
            get
            {
                return ref Anonymous.STREAMS_AVAILABLE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_NEEDS_STREAMS_e__Struct PEER_NEEDS_STREAMS
        {
            get
            {
                return ref Anonymous.PEER_NEEDS_STREAMS;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._IDEAL_PROCESSOR_CHANGED_e__Struct IDEAL_PROCESSOR_CHANGED
        {
            get
            {
                return ref Anonymous.IDEAL_PROCESSOR_CHANGED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._DATAGRAM_STATE_CHANGED_e__Struct DATAGRAM_STATE_CHANGED
        {
            get
            {
                return ref Anonymous.DATAGRAM_STATE_CHANGED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._DATAGRAM_RECEIVED_e__Struct DATAGRAM_RECEIVED
        {
            get
            {
                return ref Anonymous.DATAGRAM_RECEIVED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._DATAGRAM_SEND_STATE_CHANGED_e__Struct DATAGRAM_SEND_STATE_CHANGED
        {
            get
            {
                return ref Anonymous.DATAGRAM_SEND_STATE_CHANGED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._RESUMED_e__Struct RESUMED
        {
            get
            {
                return ref Anonymous.RESUMED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._RESUMPTION_TICKET_RECEIVED_e__Struct RESUMPTION_TICKET_RECEIVED
        {
            get
            {
                return ref Anonymous.RESUMPTION_TICKET_RECEIVED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_CERTIFICATE_RECEIVED_e__Struct PEER_CERTIFICATE_RECEIVED
        {
            get
            {
                return ref Anonymous.PEER_CERTIFICATE_RECEIVED;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1366_C9")]
            public _CONNECTED_e__Struct CONNECTED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1373_C9")]
            public _SHUTDOWN_INITIATED_BY_TRANSPORT_e__Struct SHUTDOWN_INITIATED_BY_TRANSPORT;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1377_C9")]
            public _SHUTDOWN_INITIATED_BY_PEER_e__Struct SHUTDOWN_INITIATED_BY_PEER;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1380_C9")]
            public _SHUTDOWN_COMPLETE_e__Struct SHUTDOWN_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1385_C9")]
            public _LOCAL_ADDRESS_CHANGED_e__Struct LOCAL_ADDRESS_CHANGED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1388_C9")]
            public _PEER_ADDRESS_CHANGED_e__Struct PEER_ADDRESS_CHANGED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1391_C9")]
            public _PEER_STREAM_STARTED_e__Struct PEER_STREAM_STARTED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1395_C9")]
            public _STREAMS_AVAILABLE_e__Struct STREAMS_AVAILABLE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1399_C9")]
            public _PEER_NEEDS_STREAMS_e__Struct PEER_NEEDS_STREAMS;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1402_C9")]
            public _IDEAL_PROCESSOR_CHANGED_e__Struct IDEAL_PROCESSOR_CHANGED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1406_C9")]
            public _DATAGRAM_STATE_CHANGED_e__Struct DATAGRAM_STATE_CHANGED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1410_C9")]
            public _DATAGRAM_RECEIVED_e__Struct DATAGRAM_RECEIVED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1414_C9")]
            public _DATAGRAM_SEND_STATE_CHANGED_e__Struct DATAGRAM_SEND_STATE_CHANGED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1418_C9")]
            public _RESUMED_e__Struct RESUMED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1422_C9")]
            public _RESUMPTION_TICKET_RECEIVED_e__Struct RESUMPTION_TICKET_RECEIVED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1428_C9")]
            public _PEER_CERTIFICATE_RECEIVED_e__Struct PEER_CERTIFICATE_RECEIVED;

            public unsafe partial struct _CONNECTED_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte SessionResumed;

                [NativeTypeName("uint8_t")]
                public byte NegotiatedAlpnLength;

                [NativeTypeName("const uint8_t *")]
                public byte* NegotiatedAlpn;
            }

            public partial struct _SHUTDOWN_INITIATED_BY_TRANSPORT_e__Struct
            {
                [NativeTypeName("unsigned int")]
                public uint Status;

                [NativeTypeName("QUIC_UINT62")]
                public ulong ErrorCode;
            }

            public partial struct _SHUTDOWN_INITIATED_BY_PEER_e__Struct
            {
                [NativeTypeName("QUIC_UINT62")]
                public ulong ErrorCode;
            }

            public partial struct _SHUTDOWN_COMPLETE_e__Struct
            {
                public byte _bitfield;

                [NativeTypeName("BOOLEAN : 1")]
                public byte HandshakeCompleted
                {
                    readonly get
                    {
                        return (byte)(_bitfield & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                    }
                }

                [NativeTypeName("BOOLEAN : 1")]
                public byte PeerAcknowledgedShutdown
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 1) & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1));
                    }
                }

                [NativeTypeName("BOOLEAN : 1")]
                public byte AppCloseInProgress
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 2) & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2));
                    }
                }
            }

            public partial struct _LOCAL_ADDRESS_CHANGED_e__Struct
            {
                [NativeTypeName("const QUIC_ADDR *")]
                public IntPtr Address;
            }

            public partial struct _PEER_ADDRESS_CHANGED_e__Struct
            {
                [NativeTypeName("const QUIC_ADDR *")]
                public IntPtr Address;
            }

            public unsafe partial struct _PEER_STREAM_STARTED_e__Struct
            {
                [NativeTypeName("HQUIC")]
                public QUIC_HANDLE* Stream;

                public QUIC_STREAM_OPEN_FLAGS Flags;
            }

            public partial struct _STREAMS_AVAILABLE_e__Struct
            {
                [NativeTypeName("uint16_t")]
                public ushort BidirectionalCount;

                [NativeTypeName("uint16_t")]
                public ushort UnidirectionalCount;
            }

            public partial struct _PEER_NEEDS_STREAMS_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte Bidirectional;
            }

            public partial struct _IDEAL_PROCESSOR_CHANGED_e__Struct
            {
                [NativeTypeName("uint16_t")]
                public ushort IdealProcessor;

                [NativeTypeName("uint16_t")]
                public ushort PartitionIndex;
            }

            public partial struct _DATAGRAM_STATE_CHANGED_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte SendEnabled;

                [NativeTypeName("uint16_t")]
                public ushort MaxSendLength;
            }

            public unsafe partial struct _DATAGRAM_RECEIVED_e__Struct
            {
                [NativeTypeName("const QUIC_BUFFER *")]
                public QUIC_BUFFER* Buffer;

                public QUIC_RECEIVE_FLAGS Flags;
            }

            public unsafe partial struct _DATAGRAM_SEND_STATE_CHANGED_e__Struct
            {
                public void* ClientContext;

                public QUIC_DATAGRAM_SEND_STATE State;
            }

            public unsafe partial struct _RESUMED_e__Struct
            {
                [NativeTypeName("uint16_t")]
                public ushort ResumptionStateLength;

                [NativeTypeName("const uint8_t *")]
                public byte* ResumptionState;
            }

            public unsafe partial struct _RESUMPTION_TICKET_RECEIVED_e__Struct
            {
                [NativeTypeName("uint32_t")]
                public uint ResumptionTicketLength;

                [NativeTypeName("const uint8_t *")]
                public byte* ResumptionTicket;
            }

            public unsafe partial struct _PEER_CERTIFICATE_RECEIVED_e__Struct
            {
                [NativeTypeName("QUIC_CERTIFICATE *")]
                public void* Certificate;

                [NativeTypeName("uint32_t")]
                public uint DeferredErrorFlags;

                [NativeTypeName("unsigned int")]
                public uint DeferredStatus;

                [NativeTypeName("QUIC_CERTIFICATE_CHAIN *")]
                public void* Chain;
            }
        }
    }

    [NativeTypeName("unsigned int")]
    public enum QUIC_STREAM_EVENT_TYPE : uint
    {
        QUIC_STREAM_EVENT_START_COMPLETE = 0,
        QUIC_STREAM_EVENT_RECEIVE = 1,
        QUIC_STREAM_EVENT_SEND_COMPLETE = 2,
        QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN = 3,
        QUIC_STREAM_EVENT_PEER_SEND_ABORTED = 4,
        QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED = 5,
        QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE = 6,
        QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE = 7,
        QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = 8,
        QUIC_STREAM_EVENT_PEER_ACCEPTED = 9,
        QUIC_STREAM_EVENT_CANCEL_ON_LOSS = 10,
    }

    public partial struct QUIC_STREAM_EVENT
    {
        public QUIC_STREAM_EVENT_TYPE Type;

        [NativeTypeName("__AnonymousRecord_msquic_L1604_C5")]
        public _Anonymous_e__Union Anonymous;

        [UnscopedRef]
        public ref _Anonymous_e__Union._START_COMPLETE_e__Struct START_COMPLETE
        {
            get
            {
                return ref Anonymous.START_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._RECEIVE_e__Struct RECEIVE
        {
            get
            {
                return ref Anonymous.RECEIVE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SEND_COMPLETE_e__Struct SEND_COMPLETE
        {
            get
            {
                return ref Anonymous.SEND_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_SEND_ABORTED_e__Struct PEER_SEND_ABORTED
        {
            get
            {
                return ref Anonymous.PEER_SEND_ABORTED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._PEER_RECEIVE_ABORTED_e__Struct PEER_RECEIVE_ABORTED
        {
            get
            {
                return ref Anonymous.PEER_RECEIVE_ABORTED;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SEND_SHUTDOWN_COMPLETE_e__Struct SEND_SHUTDOWN_COMPLETE
        {
            get
            {
                return ref Anonymous.SEND_SHUTDOWN_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._SHUTDOWN_COMPLETE_e__Struct SHUTDOWN_COMPLETE
        {
            get
            {
                return ref Anonymous.SHUTDOWN_COMPLETE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._IDEAL_SEND_BUFFER_SIZE_e__Struct IDEAL_SEND_BUFFER_SIZE
        {
            get
            {
                return ref Anonymous.IDEAL_SEND_BUFFER_SIZE;
            }
        }

        [UnscopedRef]
        public ref _Anonymous_e__Union._CANCEL_ON_LOSS_e__Struct CANCEL_ON_LOSS
        {
            get
            {
                return ref Anonymous.CANCEL_ON_LOSS;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public partial struct _Anonymous_e__Union
        {
            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1605_C9")]
            public _START_COMPLETE_e__Struct START_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1611_C9")]
            public _RECEIVE_e__Struct RECEIVE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1620_C9")]
            public _SEND_COMPLETE_e__Struct SEND_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1624_C9")]
            public _PEER_SEND_ABORTED_e__Struct PEER_SEND_ABORTED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1627_C9")]
            public _PEER_RECEIVE_ABORTED_e__Struct PEER_RECEIVE_ABORTED;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1630_C9")]
            public _SEND_SHUTDOWN_COMPLETE_e__Struct SEND_SHUTDOWN_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1633_C9")]
            public _SHUTDOWN_COMPLETE_e__Struct SHUTDOWN_COMPLETE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1642_C9")]
            public _IDEAL_SEND_BUFFER_SIZE_e__Struct IDEAL_SEND_BUFFER_SIZE;

            [FieldOffset(0)]
            [NativeTypeName("__AnonymousRecord_msquic_L1645_C9")]
            public _CANCEL_ON_LOSS_e__Struct CANCEL_ON_LOSS;

            public partial struct _START_COMPLETE_e__Struct
            {
                [NativeTypeName("unsigned int")]
                public uint Status;

                [NativeTypeName("QUIC_UINT62")]
                public ulong ID;

                public byte _bitfield;

                [NativeTypeName("BOOLEAN : 1")]
                public byte PeerAccepted
                {
                    readonly get
                    {
                        return (byte)(_bitfield & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                    }
                }

                [NativeTypeName("BOOLEAN : 7")]
                public byte RESERVED
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 1) & 0x7Fu);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x7Fu << 1)) | ((value & 0x7Fu) << 1));
                    }
                }
            }

            public unsafe partial struct _RECEIVE_e__Struct
            {
                [NativeTypeName("uint64_t")]
                public ulong AbsoluteOffset;

                [NativeTypeName("uint64_t")]
                public ulong TotalBufferLength;

                [NativeTypeName("const QUIC_BUFFER *")]
                public QUIC_BUFFER* Buffers;

                [NativeTypeName("uint32_t")]
                public uint BufferCount;

                public QUIC_RECEIVE_FLAGS Flags;
            }

            public unsafe partial struct _SEND_COMPLETE_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte Canceled;

                public void* ClientContext;
            }

            public partial struct _PEER_SEND_ABORTED_e__Struct
            {
                [NativeTypeName("QUIC_UINT62")]
                public ulong ErrorCode;
            }

            public partial struct _PEER_RECEIVE_ABORTED_e__Struct
            {
                [NativeTypeName("QUIC_UINT62")]
                public ulong ErrorCode;
            }

            public partial struct _SEND_SHUTDOWN_COMPLETE_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte Graceful;
            }

            public partial struct _SHUTDOWN_COMPLETE_e__Struct
            {
                [NativeTypeName("BOOLEAN")]
                public byte ConnectionShutdown;

                public byte _bitfield;

                [NativeTypeName("BOOLEAN : 1")]
                public byte AppCloseInProgress
                {
                    readonly get
                    {
                        return (byte)(_bitfield & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~0x1u) | (value & 0x1u));
                    }
                }

                [NativeTypeName("BOOLEAN : 1")]
                public byte ConnectionShutdownByApp
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 1) & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x1u << 1)) | ((value & 0x1u) << 1));
                    }
                }

                [NativeTypeName("BOOLEAN : 1")]
                public byte ConnectionClosedRemotely
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 2) & 0x1u);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x1u << 2)) | ((value & 0x1u) << 2));
                    }
                }

                [NativeTypeName("BOOLEAN : 5")]
                public byte RESERVED
                {
                    readonly get
                    {
                        return (byte)((_bitfield >> 3) & 0x1Fu);
                    }

                    set
                    {
                        _bitfield = (byte)((_bitfield & ~(0x1Fu << 3)) | ((value & 0x1Fu) << 3));
                    }
                }

                [NativeTypeName("QUIC_UINT62")]
                public ulong ConnectionErrorCode;

                [NativeTypeName("unsigned int")]
                public uint ConnectionCloseStatus;
            }

            public partial struct _IDEAL_SEND_BUFFER_SIZE_e__Struct
            {
                [NativeTypeName("uint64_t")]
                public ulong ByteCount;
            }

            public partial struct _CANCEL_ON_LOSS_e__Struct
            {
                [NativeTypeName("QUIC_UINT62")]
                public ulong ErrorCode;
            }
        }
    }

    public unsafe partial struct QUIC_API_TABLE
    {
        [NativeTypeName("QUIC_SET_CONTEXT_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, void> SetContext;

        [NativeTypeName("QUIC_GET_CONTEXT_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*> GetContext;

        [NativeTypeName("QUIC_SET_CALLBACK_HANDLER_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, void*, void> SetCallbackHandler;

        [NativeTypeName("QUIC_SET_PARAM_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, uint, uint, void*, uint> SetParam;

        [NativeTypeName("QUIC_GET_PARAM_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, uint, uint*, void*, uint> GetParam;

        [NativeTypeName("QUIC_REGISTRATION_OPEN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_REGISTRATION_CONFIG*, QUIC_HANDLE**, uint> RegistrationOpen;

        [NativeTypeName("QUIC_REGISTRATION_CLOSE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> RegistrationClose;

        [NativeTypeName("QUIC_REGISTRATION_SHUTDOWN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_CONNECTION_SHUTDOWN_FLAGS, ulong, void> RegistrationShutdown;

        [NativeTypeName("QUIC_CONFIGURATION_OPEN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_BUFFER*, uint, QUIC_SETTINGS*, uint, void*, QUIC_HANDLE**, uint> ConfigurationOpen;

        [NativeTypeName("QUIC_CONFIGURATION_CLOSE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> ConfigurationClose;

        [NativeTypeName("QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_CREDENTIAL_CONFIG*, uint> ConfigurationLoadCredential;

        [NativeTypeName("QUIC_LISTENER_OPEN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_LISTENER_EVENT*, uint>, void*, QUIC_HANDLE**, uint> ListenerOpen;

        [NativeTypeName("QUIC_LISTENER_CLOSE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> ListenerClose;

        [NativeTypeName("QUIC_LISTENER_START_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_BUFFER*, uint, IntPtr, uint> ListenerStart;

        [NativeTypeName("QUIC_LISTENER_STOP_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> ListenerStop;

        [NativeTypeName("QUIC_CONNECTION_OPEN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_CONNECTION_EVENT*, uint>, void*, QUIC_HANDLE**, uint> ConnectionOpen;

        [NativeTypeName("QUIC_CONNECTION_CLOSE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> ConnectionClose;

        [NativeTypeName("QUIC_CONNECTION_SHUTDOWN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_CONNECTION_SHUTDOWN_FLAGS, ulong, void> ConnectionShutdown;

        [NativeTypeName("QUIC_CONNECTION_START_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_HANDLE*, byte, sbyte*, ushort, uint> ConnectionStart;

        [NativeTypeName("QUIC_CONNECTION_SET_CONFIGURATION_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_HANDLE*, uint> ConnectionSetConfiguration;

        [NativeTypeName("QUIC_CONNECTION_SEND_RESUMPTION_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_SEND_RESUMPTION_FLAGS, ushort, byte*, uint> ConnectionSendResumptionTicket;

        [NativeTypeName("QUIC_STREAM_OPEN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_STREAM_OPEN_FLAGS, delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_STREAM_EVENT*, uint>, void*, QUIC_HANDLE**, uint> StreamOpen;

        [NativeTypeName("QUIC_STREAM_CLOSE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void> StreamClose;

        [NativeTypeName("QUIC_STREAM_START_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_STREAM_START_FLAGS, uint> StreamStart;

        [NativeTypeName("QUIC_STREAM_SHUTDOWN_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_STREAM_SHUTDOWN_FLAGS, ulong, uint> StreamShutdown;

        [NativeTypeName("QUIC_STREAM_SEND_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_BUFFER*, uint, QUIC_SEND_FLAGS, void*, uint> StreamSend;

        [NativeTypeName("QUIC_STREAM_RECEIVE_COMPLETE_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, ulong, void> StreamReceiveComplete;

        [NativeTypeName("QUIC_STREAM_RECEIVE_SET_ENABLED_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, byte, uint> StreamReceiveSetEnabled;

        [NativeTypeName("QUIC_DATAGRAM_SEND_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, QUIC_BUFFER*, uint, QUIC_SEND_FLAGS, void*, uint> DatagramSend;

        [NativeTypeName("QUIC_CONNECTION_COMP_RESUMPTION_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, byte, uint> ConnectionResumptionTicketValidationComplete;

        [NativeTypeName("QUIC_CONNECTION_COMP_CERT_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, byte, QUIC_TLS_ALERT_CODES, uint> ConnectionCertificateValidationComplete;

        [NativeTypeName("QUIC_CONNECTION_OPEN_IN_PARTITION_FN")]
        public delegate* unmanaged[Cdecl]<QUIC_HANDLE*, ushort, delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_CONNECTION_EVENT*, uint>, void*, QUIC_HANDLE**, uint> ConnectionOpenInPartition;
    }

    public static unsafe partial class Methods
    {
        [DllImport("msquic", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [return: NativeTypeName("unsigned int")]
        public static extern uint MsQuicOpenVersion([NativeTypeName("uint32_t")] uint Version, [NativeTypeName("const void **")] void** QuicApi);

        [DllImport("msquic", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern void MsQuicClose([NativeTypeName("const void *")] void* QuicApi);
    }
}
