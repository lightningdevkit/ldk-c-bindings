#include <string.h>
namespace LDK {
// Forward declarations
class Str;
class BlindedRoute;
class BlindedHop;
class CounterpartyCommitmentSecrets;
class TxCreationKeys;
class ChannelPublicKeys;
class HTLCOutputInCommitment;
class ChannelTransactionParameters;
class CounterpartyChannelTransactionParameters;
class DirectedChannelTransactionParameters;
class HolderCommitmentTransaction;
class BuiltCommitmentTransaction;
class ClosingTransaction;
class TrustedClosingTransaction;
class CommitmentTransaction;
class TrustedCommitmentTransaction;
class ShutdownScript;
class InvalidShutdownScript;
class BackgroundProcessor;
class GossipSync;
class RouteHop;
class Route;
class RouteParameters;
class PaymentParameters;
class RouteHint;
class RouteHintHop;
class BroadcasterInterface;
class ConfirmationTarget;
class FeeEstimator;
class PaymentPurpose;
class ClosureReason;
class HTLCDestination;
class Event;
class MessageSendEvent;
class MessageSendEventsProvider;
class OnionMessageProvider;
class EventsProvider;
class EventHandler;
class BestBlock;
class AccessError;
class Access;
class Listen;
class Confirm;
class ChannelMonitorUpdateErr;
class Watch;
class Filter;
class WatchedOutput;
class Score;
class LockableScore;
class WriteableScore;
class MultiThreadedLockableScore;
class MultiThreadedScoreLock;
class ChannelUsage;
class FixedPenaltyScorer;
class ProbabilisticScorer;
class ProbabilisticScoringParameters;
class InitFeatures;
class NodeFeatures;
class ChannelFeatures;
class InvoiceFeatures;
class ChannelTypeFeatures;
class NodeId;
class NetworkGraph;
class ReadOnlyNetworkGraph;
class NetworkUpdate;
class P2PGossipSync;
class ChannelUpdateInfo;
class ChannelInfo;
class DirectedChannelInfo;
class EffectiveCapacity;
class RoutingFees;
class NodeAnnouncementInfo;
class NodeAlias;
class NodeInfo;
class DelayedPaymentOutputDescriptor;
class StaticPaymentOutputDescriptor;
class SpendableOutputDescriptor;
class BaseSign;
class Sign;
class Recipient;
class KeysInterface;
class InMemorySigner;
class KeysManager;
class PhantomKeysManager;
class FilesystemPersister;
class ChannelManager;
class ChainParameters;
class CounterpartyForwardingInfo;
class ChannelCounterparty;
class ChannelDetails;
class PaymentSendFailure;
class PhantomRouteHints;
class ChannelManagerReadArgs;
class ChannelHandshakeConfig;
class ChannelHandshakeLimits;
class ChannelConfig;
class UserConfig;
class APIError;
class BigSize;
class Hostname;
class OutPoint;
class CustomMessageReader;
class Type;
class InvoicePayer;
class Payer;
class Router;
class Retry;
class PaymentError;
class InFlightHtlcs;
class ParseError;
class ParseOrSemanticError;
class Invoice;
class SignedRawInvoice;
class RawInvoice;
class RawDataPart;
class PositiveTimestamp;
class SiPrefix;
class Currency;
class Sha256;
class Description;
class PayeePubKey;
class ExpiryTime;
class MinFinalCltvExpiry;
class Fallback;
class InvoiceSignature;
class PrivateRoute;
class CreationError;
class SemanticError;
class SignOrCreationError;
class ChannelMonitorUpdate;
class MonitorEvent;
class HTLCUpdate;
class Balance;
class ChannelMonitor;
class ExpandedKey;
class CustomMessageHandler;
class IgnoringMessageHandler;
class ErroringMessageHandler;
class MessageHandler;
class SocketDescriptor;
class PeerHandleError;
class PeerManager;
class OnionMessenger;
class Destination;
class SendError;
class RapidGossipSync;
class Persister;
class DecodeError;
class Init;
class ErrorMessage;
class WarningMessage;
class Ping;
class Pong;
class OpenChannel;
class AcceptChannel;
class FundingCreated;
class FundingSigned;
class ChannelReady;
class Shutdown;
class ClosingSignedFeeRange;
class ClosingSigned;
class UpdateAddHTLC;
class OnionMessage;
class UpdateFulfillHTLC;
class UpdateFailHTLC;
class UpdateFailMalformedHTLC;
class CommitmentSigned;
class RevokeAndACK;
class UpdateFee;
class DataLossProtect;
class ChannelReestablish;
class AnnouncementSignatures;
class NetAddress;
class UnsignedNodeAnnouncement;
class NodeAnnouncement;
class UnsignedChannelAnnouncement;
class ChannelAnnouncement;
class UnsignedChannelUpdate;
class ChannelUpdate;
class QueryChannelRange;
class ReplyChannelRange;
class QueryShortChannelIds;
class ReplyShortChannelIdsEnd;
class GossipTimestampFilter;
class ErrorAction;
class LightningError;
class CommitmentUpdate;
class ChannelMessageHandler;
class RoutingMessageHandler;
class OnionMessageHandler;
class GraphSyncError;
class DefaultRouter;
class Level;
class Record;
class Logger;
class FutureCallback;
class Future;
class MonitorUpdateId;
class Persist;
class LockedChannelMonitor;
class ChainMonitor;
class CVec_SpendableOutputDescriptorZ;
class CResult_LockedChannelMonitorNoneZ;
class CResult_PhantomRouteHintsDecodeErrorZ;
class COption_C2Tuple_u64u64ZZ;
class CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ;
class CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ;
class CResult_HTLCUpdateDecodeErrorZ;
class C2Tuple_SignatureCVec_SignatureZZ;
class CVec_C2Tuple_u32TxOutZZ;
class CResult_ChannelInfoDecodeErrorZ;
class COption_WriteableScoreZ;
class CResult_NoneSendErrorZ;
class CResult_FundingCreatedDecodeErrorZ;
class CResult_ChannelAnnouncementDecodeErrorZ;
class CResult_PositiveTimestampCreationErrorZ;
class CVec_OutPointZ;
class CResult_CVec_u8ZPeerHandleErrorZ;
class CResult_InvoiceFeaturesDecodeErrorZ;
class COption_NetworkUpdateZ;
class COption_u64Z;
class CResult_TxOutAccessErrorZ;
class CResult_TrustedClosingTransactionNoneZ;
class CResult_PaymentPreimageAPIErrorZ;
class CResult_ChannelMonitorUpdateDecodeErrorZ;
class CResult_RouteHintDecodeErrorZ;
class C2Tuple_PublicKeyTypeZ;
class CResult_NetAddressDecodeErrorZ;
class COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ;
class CResult_ChannelReestablishDecodeErrorZ;
class CVec_UpdateAddHTLCZ;
class CResult_CommitmentSignedDecodeErrorZ;
class COption_u32Z;
class CResult_InitFeaturesDecodeErrorZ;
class CResult_StaticPaymentOutputDescriptorDecodeErrorZ;
class CResult_PaymentIdPaymentSendFailureZ;
class CResult_OnionMessageDecodeErrorZ;
class CResult_CommitmentTransactionDecodeErrorZ;
class CResult_TransactionNoneZ;
class CResult_ClosingSignedFeeRangeDecodeErrorZ;
class CResult_PingDecodeErrorZ;
class CResult_UnsignedNodeAnnouncementDecodeErrorZ;
class CResult_ReplyChannelRangeDecodeErrorZ;
class CResult_GossipTimestampFilterDecodeErrorZ;
class CResult_InvoiceSignOrCreationErrorZ;
class CVec_TransactionOutputsZ;
class CResult_ErrorMessageDecodeErrorZ;
class CResult_OpenChannelDecodeErrorZ;
class CVec_CVec_u8ZZ;
class COption_FilterZ;
class CResult_SecretKeyErrorZ;
class CResult_ShutdownScriptDecodeErrorZ;
class CResult_ProbabilisticScorerDecodeErrorZ;
class CResult_QueryChannelRangeDecodeErrorZ;
class CResult_TxCreationKeysDecodeErrorZ;
class C2Tuple_usizeTransactionZ;
class CResult_ChannelFeaturesDecodeErrorZ;
class CVec_ChannelMonitorZ;
class CVec_TransactionZ;
class CResult_ChannelReadyDecodeErrorZ;
class CResult_RouteHopDecodeErrorZ;
class CResult_UpdateFeeDecodeErrorZ;
class CResult_NodeAnnouncementDecodeErrorZ;
class CVec_BalanceZ;
class CResult_HTLCOutputInCommitmentDecodeErrorZ;
class CResult_boolLightningErrorZ;
class CResult_TxCreationKeysErrorZ;
class COption_HTLCDestinationZ;
class CResult_NodeIdDecodeErrorZ;
class CResult_ShutdownScriptInvalidShutdownScriptZ;
class CResult_NodeAnnouncementInfoDecodeErrorZ;
class CResult_COption_NetworkUpdateZDecodeErrorZ;
class CResult_RecoverableSignatureNoneZ;
class C2Tuple_BlockHashChannelMonitorZ;
class C3Tuple_RawInvoice_u832InvoiceSignatureZ;
class CVec_UpdateFailMalformedHTLCZ;
class CResult_FundingSignedDecodeErrorZ;
class CResult_NetworkGraphDecodeErrorZ;
class CVec_RouteHopZ;
class CResult_NodeInfoDecodeErrorZ;
class CVec_NodeIdZ;
class CResult_RouteLightningErrorZ;
class CResult_ChannelPublicKeysDecodeErrorZ;
class CVec_u8Z;
class CVec_C2Tuple_BlockHashChannelMonitorZZ;
class CResult_NonePaymentSendFailureZ;
class CVec_ThirtyTwoBytesZ;
class CResult_ClosingSignedDecodeErrorZ;
class CVec_CResult_NoneAPIErrorZZ;
class CResult_HolderCommitmentTransactionDecodeErrorZ;
class CResult_CounterpartyCommitmentSecretsDecodeErrorZ;
class CResult_ChannelCounterpartyDecodeErrorZ;
class CResult_WarningMessageDecodeErrorZ;
class CResult_SignatureNoneZ;
class CVec_RouteHintHopZ;
class CResult_SecretKeyNoneZ;
class CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ;
class C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ;
class CResult_PaymentParametersDecodeErrorZ;
class CResult_PaymentPurposeDecodeErrorZ;
class CResult_InitDecodeErrorZ;
class CResult_OutPointDecodeErrorZ;
class CResult_BlindedRouteDecodeErrorZ;
class CVec_ChannelDetailsZ;
class CVec_MessageSendEventZ;
class CResult_SignDecodeErrorZ;
class COption_NetAddressZ;
class C2Tuple_OutPointScriptZ;
class CResult_RouteHintHopDecodeErrorZ;
class CResult_C2Tuple_SignatureSignatureZNoneZ;
class CResult_UpdateFailMalformedHTLCDecodeErrorZ;
class CResult_SharedSecretNoneZ;
class CVec_TxidZ;
class COption_AccessZ;
class CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ;
class CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ;
class CResult_PongDecodeErrorZ;
class CResult_CVec_CVec_u8ZZNoneZ;
class C2Tuple_SignatureSignatureZ;
class C2Tuple_PaymentHashPaymentSecretZ;
class C2Tuple_BlockHashChannelManagerZ;
class CResult_ChannelTransactionParametersDecodeErrorZ;
class CResult_AcceptChannelDecodeErrorZ;
class CVec_SignatureZ;
class CVec_u64Z;
class CResult_UnsignedChannelAnnouncementDecodeErrorZ;
class CResult_DelayedPaymentOutputDescriptorDecodeErrorZ;
class C2Tuple_PaymentHashPaymentIdZ;
class CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ;
class CResult_NoneErrorZ;
class CResult_COption_HTLCDestinationZDecodeErrorZ;
class CResult_InFlightHtlcsDecodeErrorZ;
class CResult_StringErrorZ;
class CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ;
class COption_EventZ;
class C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ;
class CResult_ChannelTypeFeaturesDecodeErrorZ;
class CResult_SiPrefixParseErrorZ;
class CVec_RouteHintZ;
class COption_u16Z;
class CResult_BlindedHopDecodeErrorZ;
class CVec_CVec_RouteHopZZ;
class CResult_TrustedCommitmentTransactionNoneZ;
class CResult_FixedPenaltyScorerDecodeErrorZ;
class CResult_NoneLightningErrorZ;
class CResult_NonePeerHandleErrorZ;
class CResult_COption_EventZDecodeErrorZ;
class CResult_CVec_SignatureZNoneZ;
class COption_CVec_NetAddressZZ;
class CResult__u832APIErrorZ;
class CResult_PaymentIdPaymentErrorZ;
class CResult_DescriptionCreationErrorZ;
class CResult_RoutingFeesDecodeErrorZ;
class CResult_PayeePubKeyErrorZ;
class CResult_COption_MonitorEventZDecodeErrorZ;
class C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ;
class CVec_C2Tuple_PublicKeyTypeZZ;
class CResult_InvoiceSemanticErrorZ;
class CResult_u32GraphSyncErrorZ;
class CResult_UpdateAddHTLCDecodeErrorZ;
class CResult_CounterpartyChannelTransactionParametersDecodeErrorZ;
class CResult_NoneAPIErrorZ;
class CVec_NetAddressZ;
class CResult_ChannelDetailsDecodeErrorZ;
class CVec_PublicKeyZ;
class CVec_C2Tuple_usizeTransactionZZ;
class CResult_QueryShortChannelIdsDecodeErrorZ;
class CVec_PhantomRouteHintsZ;
class COption_MonitorEventZ;
class C2Tuple_u64u64Z;
class COption_TypeZ;
class CResult_COption_TypeZDecodeErrorZ;
class C2Tuple_u32TxOutZ;
class CResult_UpdateFailHTLCDecodeErrorZ;
class CResult_InvoiceParseOrSemanticErrorZ;
class CResult_PaymentSecretNoneZ;
class CResult_ChannelConfigDecodeErrorZ;
class CVec_PrivateRouteZ;
class CResult_SpendableOutputDescriptorDecodeErrorZ;
class CResult_RevokeAndACKDecodeErrorZ;
class CResult_UnsignedChannelUpdateDecodeErrorZ;
class CResult_ShutdownDecodeErrorZ;
class CVec_EventZ;
class CResult_NoneSemanticErrorZ;
class CVec_MonitorEventZ;
class CVec_PaymentPreimageZ;
class CVec_C2Tuple_u32ScriptZZ;
class CResult_NoneChannelMonitorUpdateErrZ;
class CResult_COption_ClosureReasonZDecodeErrorZ;
class CResult_PublicKeyErrorZ;
class CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ;
class C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ;
class CResult_NoneNoneZ;
class CResult_RouteParametersDecodeErrorZ;
class COption_ClosureReasonZ;
class CResult_NodeAliasDecodeErrorZ;
class CVec_APIErrorZ;
class CResult_PrivateRouteCreationErrorZ;
class CResult_boolPeerHandleErrorZ;
class CVec_UpdateFulfillHTLCZ;
class CResult_BlindedRouteNoneZ;
class CResult_AnnouncementSignaturesDecodeErrorZ;
class CResult_UpdateFulfillHTLCDecodeErrorZ;
class CResult_ChannelUpdateDecodeErrorZ;
class CResult_NodeFeaturesDecodeErrorZ;
class CVec_u5Z;
class CResult_InMemorySignerDecodeErrorZ;
class CResult_PaymentSecretAPIErrorZ;
class CResult_CounterpartyForwardingInfoDecodeErrorZ;
class COption_ScalarZ;
class CResult_SignedRawInvoiceParseErrorZ;
class CResult_RouteDecodeErrorZ;
class CResult_BuiltCommitmentTransactionDecodeErrorZ;
class COption_NoneZ;
class CVec_TxOutZ;
class CResult_ChannelUpdateInfoDecodeErrorZ;
class C2Tuple_u32ScriptZ;
class CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ;
class CVec_UpdateFailHTLCZ;
class CResult_ReplyShortChannelIdsEndDecodeErrorZ;

class Str {
private:
	LDKStr self;
public:
	Str(const Str&) = delete;
	Str(Str&& o) : self(o.self) { memset(&o, 0, sizeof(Str)); }
	Str(LDKStr&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKStr)); }
	operator LDKStr() && { LDKStr res = self; memset(&self, 0, sizeof(LDKStr)); return res; }
	~Str() { Str_free(self); }
	Str& operator=(Str&& o) { Str_free(self); self = o.self; memset(&o, 0, sizeof(Str)); return *this; }
	LDKStr* operator &() { return &self; }
	LDKStr* operator ->() { return &self; }
	const LDKStr* operator &() const { return &self; }
	const LDKStr* operator ->() const { return &self; }
};
class BlindedRoute {
private:
	LDKBlindedRoute self;
public:
	BlindedRoute(const BlindedRoute&) = delete;
	BlindedRoute(BlindedRoute&& o) : self(o.self) { memset(&o, 0, sizeof(BlindedRoute)); }
	BlindedRoute(LDKBlindedRoute&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBlindedRoute)); }
	operator LDKBlindedRoute() && { LDKBlindedRoute res = self; memset(&self, 0, sizeof(LDKBlindedRoute)); return res; }
	~BlindedRoute() { BlindedRoute_free(self); }
	BlindedRoute& operator=(BlindedRoute&& o) { BlindedRoute_free(self); self = o.self; memset(&o, 0, sizeof(BlindedRoute)); return *this; }
	LDKBlindedRoute* operator &() { return &self; }
	LDKBlindedRoute* operator ->() { return &self; }
	const LDKBlindedRoute* operator &() const { return &self; }
	const LDKBlindedRoute* operator ->() const { return &self; }
};
class BlindedHop {
private:
	LDKBlindedHop self;
public:
	BlindedHop(const BlindedHop&) = delete;
	BlindedHop(BlindedHop&& o) : self(o.self) { memset(&o, 0, sizeof(BlindedHop)); }
	BlindedHop(LDKBlindedHop&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBlindedHop)); }
	operator LDKBlindedHop() && { LDKBlindedHop res = self; memset(&self, 0, sizeof(LDKBlindedHop)); return res; }
	~BlindedHop() { BlindedHop_free(self); }
	BlindedHop& operator=(BlindedHop&& o) { BlindedHop_free(self); self = o.self; memset(&o, 0, sizeof(BlindedHop)); return *this; }
	LDKBlindedHop* operator &() { return &self; }
	LDKBlindedHop* operator ->() { return &self; }
	const LDKBlindedHop* operator &() const { return &self; }
	const LDKBlindedHop* operator ->() const { return &self; }
};
class CounterpartyCommitmentSecrets {
private:
	LDKCounterpartyCommitmentSecrets self;
public:
	CounterpartyCommitmentSecrets(const CounterpartyCommitmentSecrets&) = delete;
	CounterpartyCommitmentSecrets(CounterpartyCommitmentSecrets&& o) : self(o.self) { memset(&o, 0, sizeof(CounterpartyCommitmentSecrets)); }
	CounterpartyCommitmentSecrets(LDKCounterpartyCommitmentSecrets&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCounterpartyCommitmentSecrets)); }
	operator LDKCounterpartyCommitmentSecrets() && { LDKCounterpartyCommitmentSecrets res = self; memset(&self, 0, sizeof(LDKCounterpartyCommitmentSecrets)); return res; }
	~CounterpartyCommitmentSecrets() { CounterpartyCommitmentSecrets_free(self); }
	CounterpartyCommitmentSecrets& operator=(CounterpartyCommitmentSecrets&& o) { CounterpartyCommitmentSecrets_free(self); self = o.self; memset(&o, 0, sizeof(CounterpartyCommitmentSecrets)); return *this; }
	LDKCounterpartyCommitmentSecrets* operator &() { return &self; }
	LDKCounterpartyCommitmentSecrets* operator ->() { return &self; }
	const LDKCounterpartyCommitmentSecrets* operator &() const { return &self; }
	const LDKCounterpartyCommitmentSecrets* operator ->() const { return &self; }
};
class TxCreationKeys {
private:
	LDKTxCreationKeys self;
public:
	TxCreationKeys(const TxCreationKeys&) = delete;
	TxCreationKeys(TxCreationKeys&& o) : self(o.self) { memset(&o, 0, sizeof(TxCreationKeys)); }
	TxCreationKeys(LDKTxCreationKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKTxCreationKeys)); }
	operator LDKTxCreationKeys() && { LDKTxCreationKeys res = self; memset(&self, 0, sizeof(LDKTxCreationKeys)); return res; }
	~TxCreationKeys() { TxCreationKeys_free(self); }
	TxCreationKeys& operator=(TxCreationKeys&& o) { TxCreationKeys_free(self); self = o.self; memset(&o, 0, sizeof(TxCreationKeys)); return *this; }
	LDKTxCreationKeys* operator &() { return &self; }
	LDKTxCreationKeys* operator ->() { return &self; }
	const LDKTxCreationKeys* operator &() const { return &self; }
	const LDKTxCreationKeys* operator ->() const { return &self; }
};
class ChannelPublicKeys {
private:
	LDKChannelPublicKeys self;
public:
	ChannelPublicKeys(const ChannelPublicKeys&) = delete;
	ChannelPublicKeys(ChannelPublicKeys&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelPublicKeys)); }
	ChannelPublicKeys(LDKChannelPublicKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelPublicKeys)); }
	operator LDKChannelPublicKeys() && { LDKChannelPublicKeys res = self; memset(&self, 0, sizeof(LDKChannelPublicKeys)); return res; }
	~ChannelPublicKeys() { ChannelPublicKeys_free(self); }
	ChannelPublicKeys& operator=(ChannelPublicKeys&& o) { ChannelPublicKeys_free(self); self = o.self; memset(&o, 0, sizeof(ChannelPublicKeys)); return *this; }
	LDKChannelPublicKeys* operator &() { return &self; }
	LDKChannelPublicKeys* operator ->() { return &self; }
	const LDKChannelPublicKeys* operator &() const { return &self; }
	const LDKChannelPublicKeys* operator ->() const { return &self; }
};
class HTLCOutputInCommitment {
private:
	LDKHTLCOutputInCommitment self;
public:
	HTLCOutputInCommitment(const HTLCOutputInCommitment&) = delete;
	HTLCOutputInCommitment(HTLCOutputInCommitment&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCOutputInCommitment)); }
	HTLCOutputInCommitment(LDKHTLCOutputInCommitment&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCOutputInCommitment)); }
	operator LDKHTLCOutputInCommitment() && { LDKHTLCOutputInCommitment res = self; memset(&self, 0, sizeof(LDKHTLCOutputInCommitment)); return res; }
	~HTLCOutputInCommitment() { HTLCOutputInCommitment_free(self); }
	HTLCOutputInCommitment& operator=(HTLCOutputInCommitment&& o) { HTLCOutputInCommitment_free(self); self = o.self; memset(&o, 0, sizeof(HTLCOutputInCommitment)); return *this; }
	LDKHTLCOutputInCommitment* operator &() { return &self; }
	LDKHTLCOutputInCommitment* operator ->() { return &self; }
	const LDKHTLCOutputInCommitment* operator &() const { return &self; }
	const LDKHTLCOutputInCommitment* operator ->() const { return &self; }
};
class ChannelTransactionParameters {
private:
	LDKChannelTransactionParameters self;
public:
	ChannelTransactionParameters(const ChannelTransactionParameters&) = delete;
	ChannelTransactionParameters(ChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelTransactionParameters)); }
	ChannelTransactionParameters(LDKChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelTransactionParameters)); }
	operator LDKChannelTransactionParameters() && { LDKChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKChannelTransactionParameters)); return res; }
	~ChannelTransactionParameters() { ChannelTransactionParameters_free(self); }
	ChannelTransactionParameters& operator=(ChannelTransactionParameters&& o) { ChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(ChannelTransactionParameters)); return *this; }
	LDKChannelTransactionParameters* operator &() { return &self; }
	LDKChannelTransactionParameters* operator ->() { return &self; }
	const LDKChannelTransactionParameters* operator &() const { return &self; }
	const LDKChannelTransactionParameters* operator ->() const { return &self; }
};
class CounterpartyChannelTransactionParameters {
private:
	LDKCounterpartyChannelTransactionParameters self;
public:
	CounterpartyChannelTransactionParameters(const CounterpartyChannelTransactionParameters&) = delete;
	CounterpartyChannelTransactionParameters(CounterpartyChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(CounterpartyChannelTransactionParameters)); }
	CounterpartyChannelTransactionParameters(LDKCounterpartyChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCounterpartyChannelTransactionParameters)); }
	operator LDKCounterpartyChannelTransactionParameters() && { LDKCounterpartyChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKCounterpartyChannelTransactionParameters)); return res; }
	~CounterpartyChannelTransactionParameters() { CounterpartyChannelTransactionParameters_free(self); }
	CounterpartyChannelTransactionParameters& operator=(CounterpartyChannelTransactionParameters&& o) { CounterpartyChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(CounterpartyChannelTransactionParameters)); return *this; }
	LDKCounterpartyChannelTransactionParameters* operator &() { return &self; }
	LDKCounterpartyChannelTransactionParameters* operator ->() { return &self; }
	const LDKCounterpartyChannelTransactionParameters* operator &() const { return &self; }
	const LDKCounterpartyChannelTransactionParameters* operator ->() const { return &self; }
};
class DirectedChannelTransactionParameters {
private:
	LDKDirectedChannelTransactionParameters self;
public:
	DirectedChannelTransactionParameters(const DirectedChannelTransactionParameters&) = delete;
	DirectedChannelTransactionParameters(DirectedChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(DirectedChannelTransactionParameters)); }
	DirectedChannelTransactionParameters(LDKDirectedChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDirectedChannelTransactionParameters)); }
	operator LDKDirectedChannelTransactionParameters() && { LDKDirectedChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKDirectedChannelTransactionParameters)); return res; }
	~DirectedChannelTransactionParameters() { DirectedChannelTransactionParameters_free(self); }
	DirectedChannelTransactionParameters& operator=(DirectedChannelTransactionParameters&& o) { DirectedChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(DirectedChannelTransactionParameters)); return *this; }
	LDKDirectedChannelTransactionParameters* operator &() { return &self; }
	LDKDirectedChannelTransactionParameters* operator ->() { return &self; }
	const LDKDirectedChannelTransactionParameters* operator &() const { return &self; }
	const LDKDirectedChannelTransactionParameters* operator ->() const { return &self; }
};
class HolderCommitmentTransaction {
private:
	LDKHolderCommitmentTransaction self;
public:
	HolderCommitmentTransaction(const HolderCommitmentTransaction&) = delete;
	HolderCommitmentTransaction(HolderCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(HolderCommitmentTransaction)); }
	HolderCommitmentTransaction(LDKHolderCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHolderCommitmentTransaction)); }
	operator LDKHolderCommitmentTransaction() && { LDKHolderCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKHolderCommitmentTransaction)); return res; }
	~HolderCommitmentTransaction() { HolderCommitmentTransaction_free(self); }
	HolderCommitmentTransaction& operator=(HolderCommitmentTransaction&& o) { HolderCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(HolderCommitmentTransaction)); return *this; }
	LDKHolderCommitmentTransaction* operator &() { return &self; }
	LDKHolderCommitmentTransaction* operator ->() { return &self; }
	const LDKHolderCommitmentTransaction* operator &() const { return &self; }
	const LDKHolderCommitmentTransaction* operator ->() const { return &self; }
};
class BuiltCommitmentTransaction {
private:
	LDKBuiltCommitmentTransaction self;
public:
	BuiltCommitmentTransaction(const BuiltCommitmentTransaction&) = delete;
	BuiltCommitmentTransaction(BuiltCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(BuiltCommitmentTransaction)); }
	BuiltCommitmentTransaction(LDKBuiltCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBuiltCommitmentTransaction)); }
	operator LDKBuiltCommitmentTransaction() && { LDKBuiltCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKBuiltCommitmentTransaction)); return res; }
	~BuiltCommitmentTransaction() { BuiltCommitmentTransaction_free(self); }
	BuiltCommitmentTransaction& operator=(BuiltCommitmentTransaction&& o) { BuiltCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(BuiltCommitmentTransaction)); return *this; }
	LDKBuiltCommitmentTransaction* operator &() { return &self; }
	LDKBuiltCommitmentTransaction* operator ->() { return &self; }
	const LDKBuiltCommitmentTransaction* operator &() const { return &self; }
	const LDKBuiltCommitmentTransaction* operator ->() const { return &self; }
};
class ClosingTransaction {
private:
	LDKClosingTransaction self;
public:
	ClosingTransaction(const ClosingTransaction&) = delete;
	ClosingTransaction(ClosingTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(ClosingTransaction)); }
	ClosingTransaction(LDKClosingTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKClosingTransaction)); }
	operator LDKClosingTransaction() && { LDKClosingTransaction res = self; memset(&self, 0, sizeof(LDKClosingTransaction)); return res; }
	~ClosingTransaction() { ClosingTransaction_free(self); }
	ClosingTransaction& operator=(ClosingTransaction&& o) { ClosingTransaction_free(self); self = o.self; memset(&o, 0, sizeof(ClosingTransaction)); return *this; }
	LDKClosingTransaction* operator &() { return &self; }
	LDKClosingTransaction* operator ->() { return &self; }
	const LDKClosingTransaction* operator &() const { return &self; }
	const LDKClosingTransaction* operator ->() const { return &self; }
};
class TrustedClosingTransaction {
private:
	LDKTrustedClosingTransaction self;
public:
	TrustedClosingTransaction(const TrustedClosingTransaction&) = delete;
	TrustedClosingTransaction(TrustedClosingTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(TrustedClosingTransaction)); }
	TrustedClosingTransaction(LDKTrustedClosingTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKTrustedClosingTransaction)); }
	operator LDKTrustedClosingTransaction() && { LDKTrustedClosingTransaction res = self; memset(&self, 0, sizeof(LDKTrustedClosingTransaction)); return res; }
	~TrustedClosingTransaction() { TrustedClosingTransaction_free(self); }
	TrustedClosingTransaction& operator=(TrustedClosingTransaction&& o) { TrustedClosingTransaction_free(self); self = o.self; memset(&o, 0, sizeof(TrustedClosingTransaction)); return *this; }
	LDKTrustedClosingTransaction* operator &() { return &self; }
	LDKTrustedClosingTransaction* operator ->() { return &self; }
	const LDKTrustedClosingTransaction* operator &() const { return &self; }
	const LDKTrustedClosingTransaction* operator ->() const { return &self; }
};
class CommitmentTransaction {
private:
	LDKCommitmentTransaction self;
public:
	CommitmentTransaction(const CommitmentTransaction&) = delete;
	CommitmentTransaction(CommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentTransaction)); }
	CommitmentTransaction(LDKCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentTransaction)); }
	operator LDKCommitmentTransaction() && { LDKCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKCommitmentTransaction)); return res; }
	~CommitmentTransaction() { CommitmentTransaction_free(self); }
	CommitmentTransaction& operator=(CommitmentTransaction&& o) { CommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentTransaction)); return *this; }
	LDKCommitmentTransaction* operator &() { return &self; }
	LDKCommitmentTransaction* operator ->() { return &self; }
	const LDKCommitmentTransaction* operator &() const { return &self; }
	const LDKCommitmentTransaction* operator ->() const { return &self; }
};
class TrustedCommitmentTransaction {
private:
	LDKTrustedCommitmentTransaction self;
public:
	TrustedCommitmentTransaction(const TrustedCommitmentTransaction&) = delete;
	TrustedCommitmentTransaction(TrustedCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(TrustedCommitmentTransaction)); }
	TrustedCommitmentTransaction(LDKTrustedCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKTrustedCommitmentTransaction)); }
	operator LDKTrustedCommitmentTransaction() && { LDKTrustedCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKTrustedCommitmentTransaction)); return res; }
	~TrustedCommitmentTransaction() { TrustedCommitmentTransaction_free(self); }
	TrustedCommitmentTransaction& operator=(TrustedCommitmentTransaction&& o) { TrustedCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(TrustedCommitmentTransaction)); return *this; }
	LDKTrustedCommitmentTransaction* operator &() { return &self; }
	LDKTrustedCommitmentTransaction* operator ->() { return &self; }
	const LDKTrustedCommitmentTransaction* operator &() const { return &self; }
	const LDKTrustedCommitmentTransaction* operator ->() const { return &self; }
};
class ShutdownScript {
private:
	LDKShutdownScript self;
public:
	ShutdownScript(const ShutdownScript&) = delete;
	ShutdownScript(ShutdownScript&& o) : self(o.self) { memset(&o, 0, sizeof(ShutdownScript)); }
	ShutdownScript(LDKShutdownScript&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKShutdownScript)); }
	operator LDKShutdownScript() && { LDKShutdownScript res = self; memset(&self, 0, sizeof(LDKShutdownScript)); return res; }
	~ShutdownScript() { ShutdownScript_free(self); }
	ShutdownScript& operator=(ShutdownScript&& o) { ShutdownScript_free(self); self = o.self; memset(&o, 0, sizeof(ShutdownScript)); return *this; }
	LDKShutdownScript* operator &() { return &self; }
	LDKShutdownScript* operator ->() { return &self; }
	const LDKShutdownScript* operator &() const { return &self; }
	const LDKShutdownScript* operator ->() const { return &self; }
};
class InvalidShutdownScript {
private:
	LDKInvalidShutdownScript self;
public:
	InvalidShutdownScript(const InvalidShutdownScript&) = delete;
	InvalidShutdownScript(InvalidShutdownScript&& o) : self(o.self) { memset(&o, 0, sizeof(InvalidShutdownScript)); }
	InvalidShutdownScript(LDKInvalidShutdownScript&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInvalidShutdownScript)); }
	operator LDKInvalidShutdownScript() && { LDKInvalidShutdownScript res = self; memset(&self, 0, sizeof(LDKInvalidShutdownScript)); return res; }
	~InvalidShutdownScript() { InvalidShutdownScript_free(self); }
	InvalidShutdownScript& operator=(InvalidShutdownScript&& o) { InvalidShutdownScript_free(self); self = o.self; memset(&o, 0, sizeof(InvalidShutdownScript)); return *this; }
	LDKInvalidShutdownScript* operator &() { return &self; }
	LDKInvalidShutdownScript* operator ->() { return &self; }
	const LDKInvalidShutdownScript* operator &() const { return &self; }
	const LDKInvalidShutdownScript* operator ->() const { return &self; }
};
class BackgroundProcessor {
private:
	LDKBackgroundProcessor self;
public:
	BackgroundProcessor(const BackgroundProcessor&) = delete;
	BackgroundProcessor(BackgroundProcessor&& o) : self(o.self) { memset(&o, 0, sizeof(BackgroundProcessor)); }
	BackgroundProcessor(LDKBackgroundProcessor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBackgroundProcessor)); }
	operator LDKBackgroundProcessor() && { LDKBackgroundProcessor res = self; memset(&self, 0, sizeof(LDKBackgroundProcessor)); return res; }
	~BackgroundProcessor() { BackgroundProcessor_free(self); }
	BackgroundProcessor& operator=(BackgroundProcessor&& o) { BackgroundProcessor_free(self); self = o.self; memset(&o, 0, sizeof(BackgroundProcessor)); return *this; }
	LDKBackgroundProcessor* operator &() { return &self; }
	LDKBackgroundProcessor* operator ->() { return &self; }
	const LDKBackgroundProcessor* operator &() const { return &self; }
	const LDKBackgroundProcessor* operator ->() const { return &self; }
};
class GossipSync {
private:
	LDKGossipSync self;
public:
	GossipSync(const GossipSync&) = delete;
	GossipSync(GossipSync&& o) : self(o.self) { memset(&o, 0, sizeof(GossipSync)); }
	GossipSync(LDKGossipSync&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKGossipSync)); }
	operator LDKGossipSync() && { LDKGossipSync res = self; memset(&self, 0, sizeof(LDKGossipSync)); return res; }
	~GossipSync() { GossipSync_free(self); }
	GossipSync& operator=(GossipSync&& o) { GossipSync_free(self); self = o.self; memset(&o, 0, sizeof(GossipSync)); return *this; }
	LDKGossipSync* operator &() { return &self; }
	LDKGossipSync* operator ->() { return &self; }
	const LDKGossipSync* operator &() const { return &self; }
	const LDKGossipSync* operator ->() const { return &self; }
};
class RouteHop {
private:
	LDKRouteHop self;
public:
	RouteHop(const RouteHop&) = delete;
	RouteHop(RouteHop&& o) : self(o.self) { memset(&o, 0, sizeof(RouteHop)); }
	RouteHop(LDKRouteHop&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteHop)); }
	operator LDKRouteHop() && { LDKRouteHop res = self; memset(&self, 0, sizeof(LDKRouteHop)); return res; }
	~RouteHop() { RouteHop_free(self); }
	RouteHop& operator=(RouteHop&& o) { RouteHop_free(self); self = o.self; memset(&o, 0, sizeof(RouteHop)); return *this; }
	LDKRouteHop* operator &() { return &self; }
	LDKRouteHop* operator ->() { return &self; }
	const LDKRouteHop* operator &() const { return &self; }
	const LDKRouteHop* operator ->() const { return &self; }
};
class Route {
private:
	LDKRoute self;
public:
	Route(const Route&) = delete;
	Route(Route&& o) : self(o.self) { memset(&o, 0, sizeof(Route)); }
	Route(LDKRoute&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoute)); }
	operator LDKRoute() && { LDKRoute res = self; memset(&self, 0, sizeof(LDKRoute)); return res; }
	~Route() { Route_free(self); }
	Route& operator=(Route&& o) { Route_free(self); self = o.self; memset(&o, 0, sizeof(Route)); return *this; }
	LDKRoute* operator &() { return &self; }
	LDKRoute* operator ->() { return &self; }
	const LDKRoute* operator &() const { return &self; }
	const LDKRoute* operator ->() const { return &self; }
};
class RouteParameters {
private:
	LDKRouteParameters self;
public:
	RouteParameters(const RouteParameters&) = delete;
	RouteParameters(RouteParameters&& o) : self(o.self) { memset(&o, 0, sizeof(RouteParameters)); }
	RouteParameters(LDKRouteParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteParameters)); }
	operator LDKRouteParameters() && { LDKRouteParameters res = self; memset(&self, 0, sizeof(LDKRouteParameters)); return res; }
	~RouteParameters() { RouteParameters_free(self); }
	RouteParameters& operator=(RouteParameters&& o) { RouteParameters_free(self); self = o.self; memset(&o, 0, sizeof(RouteParameters)); return *this; }
	LDKRouteParameters* operator &() { return &self; }
	LDKRouteParameters* operator ->() { return &self; }
	const LDKRouteParameters* operator &() const { return &self; }
	const LDKRouteParameters* operator ->() const { return &self; }
};
class PaymentParameters {
private:
	LDKPaymentParameters self;
public:
	PaymentParameters(const PaymentParameters&) = delete;
	PaymentParameters(PaymentParameters&& o) : self(o.self) { memset(&o, 0, sizeof(PaymentParameters)); }
	PaymentParameters(LDKPaymentParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPaymentParameters)); }
	operator LDKPaymentParameters() && { LDKPaymentParameters res = self; memset(&self, 0, sizeof(LDKPaymentParameters)); return res; }
	~PaymentParameters() { PaymentParameters_free(self); }
	PaymentParameters& operator=(PaymentParameters&& o) { PaymentParameters_free(self); self = o.self; memset(&o, 0, sizeof(PaymentParameters)); return *this; }
	LDKPaymentParameters* operator &() { return &self; }
	LDKPaymentParameters* operator ->() { return &self; }
	const LDKPaymentParameters* operator &() const { return &self; }
	const LDKPaymentParameters* operator ->() const { return &self; }
};
class RouteHint {
private:
	LDKRouteHint self;
public:
	RouteHint(const RouteHint&) = delete;
	RouteHint(RouteHint&& o) : self(o.self) { memset(&o, 0, sizeof(RouteHint)); }
	RouteHint(LDKRouteHint&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteHint)); }
	operator LDKRouteHint() && { LDKRouteHint res = self; memset(&self, 0, sizeof(LDKRouteHint)); return res; }
	~RouteHint() { RouteHint_free(self); }
	RouteHint& operator=(RouteHint&& o) { RouteHint_free(self); self = o.self; memset(&o, 0, sizeof(RouteHint)); return *this; }
	LDKRouteHint* operator &() { return &self; }
	LDKRouteHint* operator ->() { return &self; }
	const LDKRouteHint* operator &() const { return &self; }
	const LDKRouteHint* operator ->() const { return &self; }
};
class RouteHintHop {
private:
	LDKRouteHintHop self;
public:
	RouteHintHop(const RouteHintHop&) = delete;
	RouteHintHop(RouteHintHop&& o) : self(o.self) { memset(&o, 0, sizeof(RouteHintHop)); }
	RouteHintHop(LDKRouteHintHop&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteHintHop)); }
	operator LDKRouteHintHop() && { LDKRouteHintHop res = self; memset(&self, 0, sizeof(LDKRouteHintHop)); return res; }
	~RouteHintHop() { RouteHintHop_free(self); }
	RouteHintHop& operator=(RouteHintHop&& o) { RouteHintHop_free(self); self = o.self; memset(&o, 0, sizeof(RouteHintHop)); return *this; }
	LDKRouteHintHop* operator &() { return &self; }
	LDKRouteHintHop* operator ->() { return &self; }
	const LDKRouteHintHop* operator &() const { return &self; }
	const LDKRouteHintHop* operator ->() const { return &self; }
};
class BroadcasterInterface {
private:
	LDKBroadcasterInterface self;
public:
	BroadcasterInterface(const BroadcasterInterface&) = delete;
	BroadcasterInterface(BroadcasterInterface&& o) : self(o.self) { memset(&o, 0, sizeof(BroadcasterInterface)); }
	BroadcasterInterface(LDKBroadcasterInterface&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBroadcasterInterface)); }
	operator LDKBroadcasterInterface() && { LDKBroadcasterInterface res = self; memset(&self, 0, sizeof(LDKBroadcasterInterface)); return res; }
	~BroadcasterInterface() { BroadcasterInterface_free(self); }
	BroadcasterInterface& operator=(BroadcasterInterface&& o) { BroadcasterInterface_free(self); self = o.self; memset(&o, 0, sizeof(BroadcasterInterface)); return *this; }
	LDKBroadcasterInterface* operator &() { return &self; }
	LDKBroadcasterInterface* operator ->() { return &self; }
	const LDKBroadcasterInterface* operator &() const { return &self; }
	const LDKBroadcasterInterface* operator ->() const { return &self; }
	/**
	 *  Sends a transaction out to (hopefully) be mined.
	 */
	inline void broadcast_transaction(struct LDKTransaction tx);
};
class ConfirmationTarget {
private:
	LDKConfirmationTarget self;
public:
	ConfirmationTarget(const ConfirmationTarget&) = delete;
	ConfirmationTarget(ConfirmationTarget&& o) : self(o.self) { memset(&o, 0, sizeof(ConfirmationTarget)); }
	ConfirmationTarget(LDKConfirmationTarget&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKConfirmationTarget)); }
	operator LDKConfirmationTarget() && { LDKConfirmationTarget res = self; memset(&self, 0, sizeof(LDKConfirmationTarget)); return res; }
	ConfirmationTarget& operator=(ConfirmationTarget&& o) { self = o.self; memset(&o, 0, sizeof(ConfirmationTarget)); return *this; }
	LDKConfirmationTarget* operator &() { return &self; }
	LDKConfirmationTarget* operator ->() { return &self; }
	const LDKConfirmationTarget* operator &() const { return &self; }
	const LDKConfirmationTarget* operator ->() const { return &self; }
};
class FeeEstimator {
private:
	LDKFeeEstimator self;
public:
	FeeEstimator(const FeeEstimator&) = delete;
	FeeEstimator(FeeEstimator&& o) : self(o.self) { memset(&o, 0, sizeof(FeeEstimator)); }
	FeeEstimator(LDKFeeEstimator&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFeeEstimator)); }
	operator LDKFeeEstimator() && { LDKFeeEstimator res = self; memset(&self, 0, sizeof(LDKFeeEstimator)); return res; }
	~FeeEstimator() { FeeEstimator_free(self); }
	FeeEstimator& operator=(FeeEstimator&& o) { FeeEstimator_free(self); self = o.self; memset(&o, 0, sizeof(FeeEstimator)); return *this; }
	LDKFeeEstimator* operator &() { return &self; }
	LDKFeeEstimator* operator ->() { return &self; }
	const LDKFeeEstimator* operator &() const { return &self; }
	const LDKFeeEstimator* operator ->() const { return &self; }
	/**
	 *  Gets estimated satoshis of fee required per 1000 Weight-Units.
	 * 
	 *  LDK will wrap this method and ensure that the value returned is no smaller than 253
	 *  (ie 1 satoshi-per-byte rounded up to ensure later round-downs don't put us below 1 satoshi-per-byte).
	 * 
	 *  The following unit conversions can be used to convert to sats/KW:
	 *   * satoshis-per-byte * 250
	 *   * satoshis-per-kbyte / 4
	 */
	inline uint32_t get_est_sat_per_1000_weight(enum LDKConfirmationTarget confirmation_target);
};
class PaymentPurpose {
private:
	LDKPaymentPurpose self;
public:
	PaymentPurpose(const PaymentPurpose&) = delete;
	PaymentPurpose(PaymentPurpose&& o) : self(o.self) { memset(&o, 0, sizeof(PaymentPurpose)); }
	PaymentPurpose(LDKPaymentPurpose&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPaymentPurpose)); }
	operator LDKPaymentPurpose() && { LDKPaymentPurpose res = self; memset(&self, 0, sizeof(LDKPaymentPurpose)); return res; }
	~PaymentPurpose() { PaymentPurpose_free(self); }
	PaymentPurpose& operator=(PaymentPurpose&& o) { PaymentPurpose_free(self); self = o.self; memset(&o, 0, sizeof(PaymentPurpose)); return *this; }
	LDKPaymentPurpose* operator &() { return &self; }
	LDKPaymentPurpose* operator ->() { return &self; }
	const LDKPaymentPurpose* operator &() const { return &self; }
	const LDKPaymentPurpose* operator ->() const { return &self; }
};
class ClosureReason {
private:
	LDKClosureReason self;
public:
	ClosureReason(const ClosureReason&) = delete;
	ClosureReason(ClosureReason&& o) : self(o.self) { memset(&o, 0, sizeof(ClosureReason)); }
	ClosureReason(LDKClosureReason&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKClosureReason)); }
	operator LDKClosureReason() && { LDKClosureReason res = self; memset(&self, 0, sizeof(LDKClosureReason)); return res; }
	~ClosureReason() { ClosureReason_free(self); }
	ClosureReason& operator=(ClosureReason&& o) { ClosureReason_free(self); self = o.self; memset(&o, 0, sizeof(ClosureReason)); return *this; }
	LDKClosureReason* operator &() { return &self; }
	LDKClosureReason* operator ->() { return &self; }
	const LDKClosureReason* operator &() const { return &self; }
	const LDKClosureReason* operator ->() const { return &self; }
};
class HTLCDestination {
private:
	LDKHTLCDestination self;
public:
	HTLCDestination(const HTLCDestination&) = delete;
	HTLCDestination(HTLCDestination&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCDestination)); }
	HTLCDestination(LDKHTLCDestination&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCDestination)); }
	operator LDKHTLCDestination() && { LDKHTLCDestination res = self; memset(&self, 0, sizeof(LDKHTLCDestination)); return res; }
	~HTLCDestination() { HTLCDestination_free(self); }
	HTLCDestination& operator=(HTLCDestination&& o) { HTLCDestination_free(self); self = o.self; memset(&o, 0, sizeof(HTLCDestination)); return *this; }
	LDKHTLCDestination* operator &() { return &self; }
	LDKHTLCDestination* operator ->() { return &self; }
	const LDKHTLCDestination* operator &() const { return &self; }
	const LDKHTLCDestination* operator ->() const { return &self; }
};
class Event {
private:
	LDKEvent self;
public:
	Event(const Event&) = delete;
	Event(Event&& o) : self(o.self) { memset(&o, 0, sizeof(Event)); }
	Event(LDKEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEvent)); }
	operator LDKEvent() && { LDKEvent res = self; memset(&self, 0, sizeof(LDKEvent)); return res; }
	~Event() { Event_free(self); }
	Event& operator=(Event&& o) { Event_free(self); self = o.self; memset(&o, 0, sizeof(Event)); return *this; }
	LDKEvent* operator &() { return &self; }
	LDKEvent* operator ->() { return &self; }
	const LDKEvent* operator &() const { return &self; }
	const LDKEvent* operator ->() const { return &self; }
};
class MessageSendEvent {
private:
	LDKMessageSendEvent self;
public:
	MessageSendEvent(const MessageSendEvent&) = delete;
	MessageSendEvent(MessageSendEvent&& o) : self(o.self) { memset(&o, 0, sizeof(MessageSendEvent)); }
	MessageSendEvent(LDKMessageSendEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageSendEvent)); }
	operator LDKMessageSendEvent() && { LDKMessageSendEvent res = self; memset(&self, 0, sizeof(LDKMessageSendEvent)); return res; }
	~MessageSendEvent() { MessageSendEvent_free(self); }
	MessageSendEvent& operator=(MessageSendEvent&& o) { MessageSendEvent_free(self); self = o.self; memset(&o, 0, sizeof(MessageSendEvent)); return *this; }
	LDKMessageSendEvent* operator &() { return &self; }
	LDKMessageSendEvent* operator ->() { return &self; }
	const LDKMessageSendEvent* operator &() const { return &self; }
	const LDKMessageSendEvent* operator ->() const { return &self; }
};
class MessageSendEventsProvider {
private:
	LDKMessageSendEventsProvider self;
public:
	MessageSendEventsProvider(const MessageSendEventsProvider&) = delete;
	MessageSendEventsProvider(MessageSendEventsProvider&& o) : self(o.self) { memset(&o, 0, sizeof(MessageSendEventsProvider)); }
	MessageSendEventsProvider(LDKMessageSendEventsProvider&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageSendEventsProvider)); }
	operator LDKMessageSendEventsProvider() && { LDKMessageSendEventsProvider res = self; memset(&self, 0, sizeof(LDKMessageSendEventsProvider)); return res; }
	~MessageSendEventsProvider() { MessageSendEventsProvider_free(self); }
	MessageSendEventsProvider& operator=(MessageSendEventsProvider&& o) { MessageSendEventsProvider_free(self); self = o.self; memset(&o, 0, sizeof(MessageSendEventsProvider)); return *this; }
	LDKMessageSendEventsProvider* operator &() { return &self; }
	LDKMessageSendEventsProvider* operator ->() { return &self; }
	const LDKMessageSendEventsProvider* operator &() const { return &self; }
	const LDKMessageSendEventsProvider* operator ->() const { return &self; }
	/**
	 *  Gets the list of pending events which were generated by previous actions, clearing the list
	 *  in the process.
	 */
	inline LDK::CVec_MessageSendEventZ get_and_clear_pending_msg_events();
};
class OnionMessageProvider {
private:
	LDKOnionMessageProvider self;
public:
	OnionMessageProvider(const OnionMessageProvider&) = delete;
	OnionMessageProvider(OnionMessageProvider&& o) : self(o.self) { memset(&o, 0, sizeof(OnionMessageProvider)); }
	OnionMessageProvider(LDKOnionMessageProvider&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOnionMessageProvider)); }
	operator LDKOnionMessageProvider() && { LDKOnionMessageProvider res = self; memset(&self, 0, sizeof(LDKOnionMessageProvider)); return res; }
	~OnionMessageProvider() { OnionMessageProvider_free(self); }
	OnionMessageProvider& operator=(OnionMessageProvider&& o) { OnionMessageProvider_free(self); self = o.self; memset(&o, 0, sizeof(OnionMessageProvider)); return *this; }
	LDKOnionMessageProvider* operator &() { return &self; }
	LDKOnionMessageProvider* operator ->() { return &self; }
	const LDKOnionMessageProvider* operator &() const { return &self; }
	const LDKOnionMessageProvider* operator ->() const { return &self; }
	/**
	 *  Gets the next pending onion message for the peer with the given node id.
	 * 
	 *  Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
	 */
	inline LDK::OnionMessage next_onion_message_for_peer(struct LDKPublicKey peer_node_id);
};
class EventsProvider {
private:
	LDKEventsProvider self;
public:
	EventsProvider(const EventsProvider&) = delete;
	EventsProvider(EventsProvider&& o) : self(o.self) { memset(&o, 0, sizeof(EventsProvider)); }
	EventsProvider(LDKEventsProvider&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEventsProvider)); }
	operator LDKEventsProvider() && { LDKEventsProvider res = self; memset(&self, 0, sizeof(LDKEventsProvider)); return res; }
	~EventsProvider() { EventsProvider_free(self); }
	EventsProvider& operator=(EventsProvider&& o) { EventsProvider_free(self); self = o.self; memset(&o, 0, sizeof(EventsProvider)); return *this; }
	LDKEventsProvider* operator &() { return &self; }
	LDKEventsProvider* operator ->() { return &self; }
	const LDKEventsProvider* operator &() const { return &self; }
	const LDKEventsProvider* operator ->() const { return &self; }
	/**
	 *  Processes any events generated since the last call using the given event handler.
	 * 
	 *  See the trait-level documentation for requirements.
	 */
	inline void process_pending_events(struct LDKEventHandler handler);
};
class EventHandler {
private:
	LDKEventHandler self;
public:
	EventHandler(const EventHandler&) = delete;
	EventHandler(EventHandler&& o) : self(o.self) { memset(&o, 0, sizeof(EventHandler)); }
	EventHandler(LDKEventHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEventHandler)); }
	operator LDKEventHandler() && { LDKEventHandler res = self; memset(&self, 0, sizeof(LDKEventHandler)); return res; }
	~EventHandler() { EventHandler_free(self); }
	EventHandler& operator=(EventHandler&& o) { EventHandler_free(self); self = o.self; memset(&o, 0, sizeof(EventHandler)); return *this; }
	LDKEventHandler* operator &() { return &self; }
	LDKEventHandler* operator ->() { return &self; }
	const LDKEventHandler* operator &() const { return &self; }
	const LDKEventHandler* operator ->() const { return &self; }
	/**
	 *  Handles the given [`Event`].
	 * 
	 *  See [`EventsProvider`] for details that must be considered when implementing this method.
	 */
	inline void handle_event(const struct LDKEvent *NONNULL_PTR event);
};
class BestBlock {
private:
	LDKBestBlock self;
public:
	BestBlock(const BestBlock&) = delete;
	BestBlock(BestBlock&& o) : self(o.self) { memset(&o, 0, sizeof(BestBlock)); }
	BestBlock(LDKBestBlock&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBestBlock)); }
	operator LDKBestBlock() && { LDKBestBlock res = self; memset(&self, 0, sizeof(LDKBestBlock)); return res; }
	~BestBlock() { BestBlock_free(self); }
	BestBlock& operator=(BestBlock&& o) { BestBlock_free(self); self = o.self; memset(&o, 0, sizeof(BestBlock)); return *this; }
	LDKBestBlock* operator &() { return &self; }
	LDKBestBlock* operator ->() { return &self; }
	const LDKBestBlock* operator &() const { return &self; }
	const LDKBestBlock* operator ->() const { return &self; }
};
class AccessError {
private:
	LDKAccessError self;
public:
	AccessError(const AccessError&) = delete;
	AccessError(AccessError&& o) : self(o.self) { memset(&o, 0, sizeof(AccessError)); }
	AccessError(LDKAccessError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAccessError)); }
	operator LDKAccessError() && { LDKAccessError res = self; memset(&self, 0, sizeof(LDKAccessError)); return res; }
	AccessError& operator=(AccessError&& o) { self = o.self; memset(&o, 0, sizeof(AccessError)); return *this; }
	LDKAccessError* operator &() { return &self; }
	LDKAccessError* operator ->() { return &self; }
	const LDKAccessError* operator &() const { return &self; }
	const LDKAccessError* operator ->() const { return &self; }
};
class Access {
private:
	LDKAccess self;
public:
	Access(const Access&) = delete;
	Access(Access&& o) : self(o.self) { memset(&o, 0, sizeof(Access)); }
	Access(LDKAccess&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAccess)); }
	operator LDKAccess() && { LDKAccess res = self; memset(&self, 0, sizeof(LDKAccess)); return res; }
	~Access() { Access_free(self); }
	Access& operator=(Access&& o) { Access_free(self); self = o.self; memset(&o, 0, sizeof(Access)); return *this; }
	LDKAccess* operator &() { return &self; }
	LDKAccess* operator ->() { return &self; }
	const LDKAccess* operator &() const { return &self; }
	const LDKAccess* operator ->() const { return &self; }
	/**
	 *  Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	 *  Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	 *  is unknown.
	 * 
	 *  [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	 */
	inline LDK::CResult_TxOutAccessErrorZ get_utxo(const uint8_t (*genesis_hash)[32], uint64_t short_channel_id);
};
class Listen {
private:
	LDKListen self;
public:
	Listen(const Listen&) = delete;
	Listen(Listen&& o) : self(o.self) { memset(&o, 0, sizeof(Listen)); }
	Listen(LDKListen&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKListen)); }
	operator LDKListen() && { LDKListen res = self; memset(&self, 0, sizeof(LDKListen)); return res; }
	~Listen() { Listen_free(self); }
	Listen& operator=(Listen&& o) { Listen_free(self); self = o.self; memset(&o, 0, sizeof(Listen)); return *this; }
	LDKListen* operator &() { return &self; }
	LDKListen* operator ->() { return &self; }
	const LDKListen* operator &() const { return &self; }
	const LDKListen* operator ->() const { return &self; }
	/**
	 *  Notifies the listener that a block was added at the given height, with the transaction data
	 *  possibly filtered.
	 */
	inline void filtered_block_connected(const uint8_t (*header)[80], struct LDKCVec_C2Tuple_usizeTransactionZZ txdata, uint32_t height);
	/**
	 *  Notifies the listener that a block was added at the given height.
	 */
	inline void block_connected(struct LDKu8slice block, uint32_t height);
	/**
	 *  Notifies the listener that a block was removed at the given height.
	 */
	inline void block_disconnected(const uint8_t (*header)[80], uint32_t height);
};
class Confirm {
private:
	LDKConfirm self;
public:
	Confirm(const Confirm&) = delete;
	Confirm(Confirm&& o) : self(o.self) { memset(&o, 0, sizeof(Confirm)); }
	Confirm(LDKConfirm&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKConfirm)); }
	operator LDKConfirm() && { LDKConfirm res = self; memset(&self, 0, sizeof(LDKConfirm)); return res; }
	~Confirm() { Confirm_free(self); }
	Confirm& operator=(Confirm&& o) { Confirm_free(self); self = o.self; memset(&o, 0, sizeof(Confirm)); return *this; }
	LDKConfirm* operator &() { return &self; }
	LDKConfirm* operator ->() { return &self; }
	const LDKConfirm* operator &() const { return &self; }
	const LDKConfirm* operator ->() const { return &self; }
	/**
	 *  Processes transactions confirmed in a block with a given header and height.
	 * 
	 *  Should be called for any transactions registered by [`Filter::register_tx`] or any
	 *  transactions spending an output registered by [`Filter::register_output`]. Such transactions
	 *  appearing in the same block do not need to be included in the same call; instead, multiple
	 *  calls with additional transactions may be made so long as they are made in [chain order].
	 * 
	 *  May be called before or after [`best_block_updated`] for the corresponding block. However,
	 *  in the event of a chain reorganization, it must not be called with a `header` that is no
	 *  longer in the chain as of the last call to [`best_block_updated`].
	 * 
	 *  [chain order]: Confirm#order
	 *  [`best_block_updated`]: Self::best_block_updated
	 */
	inline void transactions_confirmed(const uint8_t (*header)[80], struct LDKCVec_C2Tuple_usizeTransactionZZ txdata, uint32_t height);
	/**
	 *  Processes a transaction that is no longer confirmed as result of a chain reorganization.
	 * 
	 *  Should be called for any transaction returned by [`get_relevant_txids`] if it has been
	 *  reorganized out of the best chain. Once called, the given transaction will not be returned
	 *  by [`get_relevant_txids`], unless it has been reconfirmed via [`transactions_confirmed`].
	 * 
	 *  [`get_relevant_txids`]: Self::get_relevant_txids
	 *  [`transactions_confirmed`]: Self::transactions_confirmed
	 */
	inline void transaction_unconfirmed(const uint8_t (*txid)[32]);
	/**
	 *  Processes an update to the best header connected at the given height.
	 * 
	 *  Should be called when a new header is available but may be skipped for intermediary blocks
	 *  if they become available at the same time.
	 */
	inline void best_block_updated(const uint8_t (*header)[80], uint32_t height);
	/**
	 *  Returns transactions that should be monitored for reorganization out of the chain.
	 * 
	 *  Will include any transactions passed to [`transactions_confirmed`] that have insufficient
	 *  confirmations to be safe from a chain reorganization. Will not include any transactions
	 *  passed to [`transaction_unconfirmed`], unless later reconfirmed.
	 * 
	 *  May be called to determine the subset of transactions that must still be monitored for
	 *  reorganization. Will be idempotent between calls but may change as a result of calls to the
	 *  other interface methods. Thus, this is useful to determine which transactions may need to be
	 *  given to [`transaction_unconfirmed`].
	 * 
	 *  [`transactions_confirmed`]: Self::transactions_confirmed
	 *  [`transaction_unconfirmed`]: Self::transaction_unconfirmed
	 */
	inline LDK::CVec_TxidZ get_relevant_txids();
};
class ChannelMonitorUpdateErr {
private:
	LDKChannelMonitorUpdateErr self;
public:
	ChannelMonitorUpdateErr(const ChannelMonitorUpdateErr&) = delete;
	ChannelMonitorUpdateErr(ChannelMonitorUpdateErr&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitorUpdateErr)); }
	ChannelMonitorUpdateErr(LDKChannelMonitorUpdateErr&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitorUpdateErr)); }
	operator LDKChannelMonitorUpdateErr() && { LDKChannelMonitorUpdateErr res = self; memset(&self, 0, sizeof(LDKChannelMonitorUpdateErr)); return res; }
	ChannelMonitorUpdateErr& operator=(ChannelMonitorUpdateErr&& o) { self = o.self; memset(&o, 0, sizeof(ChannelMonitorUpdateErr)); return *this; }
	LDKChannelMonitorUpdateErr* operator &() { return &self; }
	LDKChannelMonitorUpdateErr* operator ->() { return &self; }
	const LDKChannelMonitorUpdateErr* operator &() const { return &self; }
	const LDKChannelMonitorUpdateErr* operator ->() const { return &self; }
};
class Watch {
private:
	LDKWatch self;
public:
	Watch(const Watch&) = delete;
	Watch(Watch&& o) : self(o.self) { memset(&o, 0, sizeof(Watch)); }
	Watch(LDKWatch&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKWatch)); }
	operator LDKWatch() && { LDKWatch res = self; memset(&self, 0, sizeof(LDKWatch)); return res; }
	~Watch() { Watch_free(self); }
	Watch& operator=(Watch&& o) { Watch_free(self); self = o.self; memset(&o, 0, sizeof(Watch)); return *this; }
	LDKWatch* operator &() { return &self; }
	LDKWatch* operator ->() { return &self; }
	const LDKWatch* operator &() const { return &self; }
	const LDKWatch* operator ->() const { return &self; }
	/**
	 *  Watches a channel identified by `funding_txo` using `monitor`.
	 * 
	 *  Implementations are responsible for watching the chain for the funding transaction along
	 *  with any spends of outputs returned by [`get_outputs_to_watch`]. In practice, this means
	 *  calling [`block_connected`] and [`block_disconnected`] on the monitor.
	 * 
	 *  Note: this interface MUST error with `ChannelMonitorUpdateErr::PermanentFailure` if
	 *  the given `funding_txo` has previously been registered via `watch_channel`.
	 * 
	 *  [`get_outputs_to_watch`]: channelmonitor::ChannelMonitor::get_outputs_to_watch
	 *  [`block_connected`]: channelmonitor::ChannelMonitor::block_connected
	 *  [`block_disconnected`]: channelmonitor::ChannelMonitor::block_disconnected
	 */
	inline LDK::CResult_NoneChannelMonitorUpdateErrZ watch_channel(struct LDKOutPoint funding_txo, struct LDKChannelMonitor monitor);
	/**
	 *  Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	 * 
	 *  Implementations must call [`update_monitor`] with the given update. See
	 *  [`ChannelMonitorUpdateErr`] for invariants around returning an error.
	 * 
	 *  [`update_monitor`]: channelmonitor::ChannelMonitor::update_monitor
	 */
	inline LDK::CResult_NoneChannelMonitorUpdateErrZ update_channel(struct LDKOutPoint funding_txo, struct LDKChannelMonitorUpdate update);
	/**
	 *  Returns any monitor events since the last call. Subsequent calls must only return new
	 *  events.
	 * 
	 *  Note that after any block- or transaction-connection calls to a [`ChannelMonitor`], no
	 *  further events may be returned here until the [`ChannelMonitor`] has been fully persisted
	 *  to disk.
	 * 
	 *  For details on asynchronous [`ChannelMonitor`] updating and returning
	 *  [`MonitorEvent::UpdateCompleted`] here, see [`ChannelMonitorUpdateErr::TemporaryFailure`].
	 */
	inline LDK::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ release_pending_monitor_events();
};
class Filter {
private:
	LDKFilter self;
public:
	Filter(const Filter&) = delete;
	Filter(Filter&& o) : self(o.self) { memset(&o, 0, sizeof(Filter)); }
	Filter(LDKFilter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFilter)); }
	operator LDKFilter() && { LDKFilter res = self; memset(&self, 0, sizeof(LDKFilter)); return res; }
	~Filter() { Filter_free(self); }
	Filter& operator=(Filter&& o) { Filter_free(self); self = o.self; memset(&o, 0, sizeof(Filter)); return *this; }
	LDKFilter* operator &() { return &self; }
	LDKFilter* operator ->() { return &self; }
	const LDKFilter* operator &() const { return &self; }
	const LDKFilter* operator ->() const { return &self; }
	/**
	 *  Registers interest in a transaction with `txid` and having an output with `script_pubkey` as
	 *  a spending condition.
	 */
	inline void register_tx(const uint8_t (*txid)[32], struct LDKu8slice script_pubkey);
	/**
	 *  Registers interest in spends of a transaction output.
	 * 
	 *  Note that this method might be called during processing of a new block. You therefore need
	 *  to ensure that also dependent output spents within an already connected block are correctly
	 *  handled, e.g., by re-scanning the block in question whenever new outputs have been
	 *  registered mid-processing.
	 */
	inline void register_output(struct LDKWatchedOutput output);
};
class WatchedOutput {
private:
	LDKWatchedOutput self;
public:
	WatchedOutput(const WatchedOutput&) = delete;
	WatchedOutput(WatchedOutput&& o) : self(o.self) { memset(&o, 0, sizeof(WatchedOutput)); }
	WatchedOutput(LDKWatchedOutput&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKWatchedOutput)); }
	operator LDKWatchedOutput() && { LDKWatchedOutput res = self; memset(&self, 0, sizeof(LDKWatchedOutput)); return res; }
	~WatchedOutput() { WatchedOutput_free(self); }
	WatchedOutput& operator=(WatchedOutput&& o) { WatchedOutput_free(self); self = o.self; memset(&o, 0, sizeof(WatchedOutput)); return *this; }
	LDKWatchedOutput* operator &() { return &self; }
	LDKWatchedOutput* operator ->() { return &self; }
	const LDKWatchedOutput* operator &() const { return &self; }
	const LDKWatchedOutput* operator ->() const { return &self; }
};
class Score {
private:
	LDKScore self;
public:
	Score(const Score&) = delete;
	Score(Score&& o) : self(o.self) { memset(&o, 0, sizeof(Score)); }
	Score(LDKScore&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKScore)); }
	operator LDKScore() && { LDKScore res = self; memset(&self, 0, sizeof(LDKScore)); return res; }
	~Score() { Score_free(self); }
	Score& operator=(Score&& o) { Score_free(self); self = o.self; memset(&o, 0, sizeof(Score)); return *this; }
	LDKScore* operator &() { return &self; }
	LDKScore* operator ->() { return &self; }
	const LDKScore* operator &() const { return &self; }
	const LDKScore* operator ->() const { return &self; }
	/**
	 *  Returns the fee in msats willing to be paid to avoid routing `send_amt_msat` through the
	 *  given channel in the direction from `source` to `target`.
	 * 
	 *  The channel's capacity (less any other MPP parts that are also being considered for use in
	 *  the same payment) is given by `capacity_msat`. It may be determined from various sources
	 *  such as a chain data, network gossip, or invoice hints. For invoice hints, a capacity near
	 *  [`u64::max_value`] is given to indicate sufficient capacity for the invoice's full amount.
	 *  Thus, implementations should be overflow-safe.
	 */
	inline uint64_t channel_penalty_msat(uint64_t short_channel_id, const struct LDKNodeId *NONNULL_PTR source, const struct LDKNodeId *NONNULL_PTR target, struct LDKChannelUsage usage);
	/**
	 *  Handles updating channel penalties after failing to route through a channel.
	 */
	inline void payment_path_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id);
	/**
	 *  Handles updating channel penalties after successfully routing along a path.
	 */
	inline void payment_path_successful(struct LDKCVec_RouteHopZ path);
	/**
	 *  Handles updating channel penalties after a probe over the given path failed.
	 */
	inline void probe_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id);
	/**
	 *  Handles updating channel penalties after a probe over the given path succeeded.
	 */
	inline void probe_successful(struct LDKCVec_RouteHopZ path);
};
class LockableScore {
private:
	LDKLockableScore self;
public:
	LockableScore(const LockableScore&) = delete;
	LockableScore(LockableScore&& o) : self(o.self) { memset(&o, 0, sizeof(LockableScore)); }
	LockableScore(LDKLockableScore&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLockableScore)); }
	operator LDKLockableScore() && { LDKLockableScore res = self; memset(&self, 0, sizeof(LDKLockableScore)); return res; }
	~LockableScore() { LockableScore_free(self); }
	LockableScore& operator=(LockableScore&& o) { LockableScore_free(self); self = o.self; memset(&o, 0, sizeof(LockableScore)); return *this; }
	LDKLockableScore* operator &() { return &self; }
	LDKLockableScore* operator ->() { return &self; }
	const LDKLockableScore* operator &() const { return &self; }
	const LDKLockableScore* operator ->() const { return &self; }
	/**
	 *  Returns the locked scorer.
	 */
	inline LDK::Score lock();
};
class WriteableScore {
private:
	LDKWriteableScore self;
public:
	WriteableScore(const WriteableScore&) = delete;
	WriteableScore(WriteableScore&& o) : self(o.self) { memset(&o, 0, sizeof(WriteableScore)); }
	WriteableScore(LDKWriteableScore&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKWriteableScore)); }
	operator LDKWriteableScore() && { LDKWriteableScore res = self; memset(&self, 0, sizeof(LDKWriteableScore)); return res; }
	~WriteableScore() { WriteableScore_free(self); }
	WriteableScore& operator=(WriteableScore&& o) { WriteableScore_free(self); self = o.self; memset(&o, 0, sizeof(WriteableScore)); return *this; }
	LDKWriteableScore* operator &() { return &self; }
	LDKWriteableScore* operator ->() { return &self; }
	const LDKWriteableScore* operator &() const { return &self; }
	const LDKWriteableScore* operator ->() const { return &self; }
};
class MultiThreadedLockableScore {
private:
	LDKMultiThreadedLockableScore self;
public:
	MultiThreadedLockableScore(const MultiThreadedLockableScore&) = delete;
	MultiThreadedLockableScore(MultiThreadedLockableScore&& o) : self(o.self) { memset(&o, 0, sizeof(MultiThreadedLockableScore)); }
	MultiThreadedLockableScore(LDKMultiThreadedLockableScore&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMultiThreadedLockableScore)); }
	operator LDKMultiThreadedLockableScore() && { LDKMultiThreadedLockableScore res = self; memset(&self, 0, sizeof(LDKMultiThreadedLockableScore)); return res; }
	~MultiThreadedLockableScore() { MultiThreadedLockableScore_free(self); }
	MultiThreadedLockableScore& operator=(MultiThreadedLockableScore&& o) { MultiThreadedLockableScore_free(self); self = o.self; memset(&o, 0, sizeof(MultiThreadedLockableScore)); return *this; }
	LDKMultiThreadedLockableScore* operator &() { return &self; }
	LDKMultiThreadedLockableScore* operator ->() { return &self; }
	const LDKMultiThreadedLockableScore* operator &() const { return &self; }
	const LDKMultiThreadedLockableScore* operator ->() const { return &self; }
};
class MultiThreadedScoreLock {
private:
	LDKMultiThreadedScoreLock self;
public:
	MultiThreadedScoreLock(const MultiThreadedScoreLock&) = delete;
	MultiThreadedScoreLock(MultiThreadedScoreLock&& o) : self(o.self) { memset(&o, 0, sizeof(MultiThreadedScoreLock)); }
	MultiThreadedScoreLock(LDKMultiThreadedScoreLock&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMultiThreadedScoreLock)); }
	operator LDKMultiThreadedScoreLock() && { LDKMultiThreadedScoreLock res = self; memset(&self, 0, sizeof(LDKMultiThreadedScoreLock)); return res; }
	~MultiThreadedScoreLock() { MultiThreadedScoreLock_free(self); }
	MultiThreadedScoreLock& operator=(MultiThreadedScoreLock&& o) { MultiThreadedScoreLock_free(self); self = o.self; memset(&o, 0, sizeof(MultiThreadedScoreLock)); return *this; }
	LDKMultiThreadedScoreLock* operator &() { return &self; }
	LDKMultiThreadedScoreLock* operator ->() { return &self; }
	const LDKMultiThreadedScoreLock* operator &() const { return &self; }
	const LDKMultiThreadedScoreLock* operator ->() const { return &self; }
};
class ChannelUsage {
private:
	LDKChannelUsage self;
public:
	ChannelUsage(const ChannelUsage&) = delete;
	ChannelUsage(ChannelUsage&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelUsage)); }
	ChannelUsage(LDKChannelUsage&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelUsage)); }
	operator LDKChannelUsage() && { LDKChannelUsage res = self; memset(&self, 0, sizeof(LDKChannelUsage)); return res; }
	~ChannelUsage() { ChannelUsage_free(self); }
	ChannelUsage& operator=(ChannelUsage&& o) { ChannelUsage_free(self); self = o.self; memset(&o, 0, sizeof(ChannelUsage)); return *this; }
	LDKChannelUsage* operator &() { return &self; }
	LDKChannelUsage* operator ->() { return &self; }
	const LDKChannelUsage* operator &() const { return &self; }
	const LDKChannelUsage* operator ->() const { return &self; }
};
class FixedPenaltyScorer {
private:
	LDKFixedPenaltyScorer self;
public:
	FixedPenaltyScorer(const FixedPenaltyScorer&) = delete;
	FixedPenaltyScorer(FixedPenaltyScorer&& o) : self(o.self) { memset(&o, 0, sizeof(FixedPenaltyScorer)); }
	FixedPenaltyScorer(LDKFixedPenaltyScorer&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFixedPenaltyScorer)); }
	operator LDKFixedPenaltyScorer() && { LDKFixedPenaltyScorer res = self; memset(&self, 0, sizeof(LDKFixedPenaltyScorer)); return res; }
	~FixedPenaltyScorer() { FixedPenaltyScorer_free(self); }
	FixedPenaltyScorer& operator=(FixedPenaltyScorer&& o) { FixedPenaltyScorer_free(self); self = o.self; memset(&o, 0, sizeof(FixedPenaltyScorer)); return *this; }
	LDKFixedPenaltyScorer* operator &() { return &self; }
	LDKFixedPenaltyScorer* operator ->() { return &self; }
	const LDKFixedPenaltyScorer* operator &() const { return &self; }
	const LDKFixedPenaltyScorer* operator ->() const { return &self; }
};
class ProbabilisticScorer {
private:
	LDKProbabilisticScorer self;
public:
	ProbabilisticScorer(const ProbabilisticScorer&) = delete;
	ProbabilisticScorer(ProbabilisticScorer&& o) : self(o.self) { memset(&o, 0, sizeof(ProbabilisticScorer)); }
	ProbabilisticScorer(LDKProbabilisticScorer&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKProbabilisticScorer)); }
	operator LDKProbabilisticScorer() && { LDKProbabilisticScorer res = self; memset(&self, 0, sizeof(LDKProbabilisticScorer)); return res; }
	~ProbabilisticScorer() { ProbabilisticScorer_free(self); }
	ProbabilisticScorer& operator=(ProbabilisticScorer&& o) { ProbabilisticScorer_free(self); self = o.self; memset(&o, 0, sizeof(ProbabilisticScorer)); return *this; }
	LDKProbabilisticScorer* operator &() { return &self; }
	LDKProbabilisticScorer* operator ->() { return &self; }
	const LDKProbabilisticScorer* operator &() const { return &self; }
	const LDKProbabilisticScorer* operator ->() const { return &self; }
};
class ProbabilisticScoringParameters {
private:
	LDKProbabilisticScoringParameters self;
public:
	ProbabilisticScoringParameters(const ProbabilisticScoringParameters&) = delete;
	ProbabilisticScoringParameters(ProbabilisticScoringParameters&& o) : self(o.self) { memset(&o, 0, sizeof(ProbabilisticScoringParameters)); }
	ProbabilisticScoringParameters(LDKProbabilisticScoringParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKProbabilisticScoringParameters)); }
	operator LDKProbabilisticScoringParameters() && { LDKProbabilisticScoringParameters res = self; memset(&self, 0, sizeof(LDKProbabilisticScoringParameters)); return res; }
	~ProbabilisticScoringParameters() { ProbabilisticScoringParameters_free(self); }
	ProbabilisticScoringParameters& operator=(ProbabilisticScoringParameters&& o) { ProbabilisticScoringParameters_free(self); self = o.self; memset(&o, 0, sizeof(ProbabilisticScoringParameters)); return *this; }
	LDKProbabilisticScoringParameters* operator &() { return &self; }
	LDKProbabilisticScoringParameters* operator ->() { return &self; }
	const LDKProbabilisticScoringParameters* operator &() const { return &self; }
	const LDKProbabilisticScoringParameters* operator ->() const { return &self; }
};
class InitFeatures {
private:
	LDKInitFeatures self;
public:
	InitFeatures(const InitFeatures&) = delete;
	InitFeatures(InitFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(InitFeatures)); }
	InitFeatures(LDKInitFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInitFeatures)); }
	operator LDKInitFeatures() && { LDKInitFeatures res = self; memset(&self, 0, sizeof(LDKInitFeatures)); return res; }
	~InitFeatures() { InitFeatures_free(self); }
	InitFeatures& operator=(InitFeatures&& o) { InitFeatures_free(self); self = o.self; memset(&o, 0, sizeof(InitFeatures)); return *this; }
	LDKInitFeatures* operator &() { return &self; }
	LDKInitFeatures* operator ->() { return &self; }
	const LDKInitFeatures* operator &() const { return &self; }
	const LDKInitFeatures* operator ->() const { return &self; }
};
class NodeFeatures {
private:
	LDKNodeFeatures self;
public:
	NodeFeatures(const NodeFeatures&) = delete;
	NodeFeatures(NodeFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(NodeFeatures)); }
	NodeFeatures(LDKNodeFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeFeatures)); }
	operator LDKNodeFeatures() && { LDKNodeFeatures res = self; memset(&self, 0, sizeof(LDKNodeFeatures)); return res; }
	~NodeFeatures() { NodeFeatures_free(self); }
	NodeFeatures& operator=(NodeFeatures&& o) { NodeFeatures_free(self); self = o.self; memset(&o, 0, sizeof(NodeFeatures)); return *this; }
	LDKNodeFeatures* operator &() { return &self; }
	LDKNodeFeatures* operator ->() { return &self; }
	const LDKNodeFeatures* operator &() const { return &self; }
	const LDKNodeFeatures* operator ->() const { return &self; }
};
class ChannelFeatures {
private:
	LDKChannelFeatures self;
public:
	ChannelFeatures(const ChannelFeatures&) = delete;
	ChannelFeatures(ChannelFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelFeatures)); }
	ChannelFeatures(LDKChannelFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelFeatures)); }
	operator LDKChannelFeatures() && { LDKChannelFeatures res = self; memset(&self, 0, sizeof(LDKChannelFeatures)); return res; }
	~ChannelFeatures() { ChannelFeatures_free(self); }
	ChannelFeatures& operator=(ChannelFeatures&& o) { ChannelFeatures_free(self); self = o.self; memset(&o, 0, sizeof(ChannelFeatures)); return *this; }
	LDKChannelFeatures* operator &() { return &self; }
	LDKChannelFeatures* operator ->() { return &self; }
	const LDKChannelFeatures* operator &() const { return &self; }
	const LDKChannelFeatures* operator ->() const { return &self; }
};
class InvoiceFeatures {
private:
	LDKInvoiceFeatures self;
public:
	InvoiceFeatures(const InvoiceFeatures&) = delete;
	InvoiceFeatures(InvoiceFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(InvoiceFeatures)); }
	InvoiceFeatures(LDKInvoiceFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInvoiceFeatures)); }
	operator LDKInvoiceFeatures() && { LDKInvoiceFeatures res = self; memset(&self, 0, sizeof(LDKInvoiceFeatures)); return res; }
	~InvoiceFeatures() { InvoiceFeatures_free(self); }
	InvoiceFeatures& operator=(InvoiceFeatures&& o) { InvoiceFeatures_free(self); self = o.self; memset(&o, 0, sizeof(InvoiceFeatures)); return *this; }
	LDKInvoiceFeatures* operator &() { return &self; }
	LDKInvoiceFeatures* operator ->() { return &self; }
	const LDKInvoiceFeatures* operator &() const { return &self; }
	const LDKInvoiceFeatures* operator ->() const { return &self; }
};
class ChannelTypeFeatures {
private:
	LDKChannelTypeFeatures self;
public:
	ChannelTypeFeatures(const ChannelTypeFeatures&) = delete;
	ChannelTypeFeatures(ChannelTypeFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelTypeFeatures)); }
	ChannelTypeFeatures(LDKChannelTypeFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelTypeFeatures)); }
	operator LDKChannelTypeFeatures() && { LDKChannelTypeFeatures res = self; memset(&self, 0, sizeof(LDKChannelTypeFeatures)); return res; }
	~ChannelTypeFeatures() { ChannelTypeFeatures_free(self); }
	ChannelTypeFeatures& operator=(ChannelTypeFeatures&& o) { ChannelTypeFeatures_free(self); self = o.self; memset(&o, 0, sizeof(ChannelTypeFeatures)); return *this; }
	LDKChannelTypeFeatures* operator &() { return &self; }
	LDKChannelTypeFeatures* operator ->() { return &self; }
	const LDKChannelTypeFeatures* operator &() const { return &self; }
	const LDKChannelTypeFeatures* operator ->() const { return &self; }
};
class NodeId {
private:
	LDKNodeId self;
public:
	NodeId(const NodeId&) = delete;
	NodeId(NodeId&& o) : self(o.self) { memset(&o, 0, sizeof(NodeId)); }
	NodeId(LDKNodeId&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeId)); }
	operator LDKNodeId() && { LDKNodeId res = self; memset(&self, 0, sizeof(LDKNodeId)); return res; }
	~NodeId() { NodeId_free(self); }
	NodeId& operator=(NodeId&& o) { NodeId_free(self); self = o.self; memset(&o, 0, sizeof(NodeId)); return *this; }
	LDKNodeId* operator &() { return &self; }
	LDKNodeId* operator ->() { return &self; }
	const LDKNodeId* operator &() const { return &self; }
	const LDKNodeId* operator ->() const { return &self; }
};
class NetworkGraph {
private:
	LDKNetworkGraph self;
public:
	NetworkGraph(const NetworkGraph&) = delete;
	NetworkGraph(NetworkGraph&& o) : self(o.self) { memset(&o, 0, sizeof(NetworkGraph)); }
	NetworkGraph(LDKNetworkGraph&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetworkGraph)); }
	operator LDKNetworkGraph() && { LDKNetworkGraph res = self; memset(&self, 0, sizeof(LDKNetworkGraph)); return res; }
	~NetworkGraph() { NetworkGraph_free(self); }
	NetworkGraph& operator=(NetworkGraph&& o) { NetworkGraph_free(self); self = o.self; memset(&o, 0, sizeof(NetworkGraph)); return *this; }
	LDKNetworkGraph* operator &() { return &self; }
	LDKNetworkGraph* operator ->() { return &self; }
	const LDKNetworkGraph* operator &() const { return &self; }
	const LDKNetworkGraph* operator ->() const { return &self; }
};
class ReadOnlyNetworkGraph {
private:
	LDKReadOnlyNetworkGraph self;
public:
	ReadOnlyNetworkGraph(const ReadOnlyNetworkGraph&) = delete;
	ReadOnlyNetworkGraph(ReadOnlyNetworkGraph&& o) : self(o.self) { memset(&o, 0, sizeof(ReadOnlyNetworkGraph)); }
	ReadOnlyNetworkGraph(LDKReadOnlyNetworkGraph&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKReadOnlyNetworkGraph)); }
	operator LDKReadOnlyNetworkGraph() && { LDKReadOnlyNetworkGraph res = self; memset(&self, 0, sizeof(LDKReadOnlyNetworkGraph)); return res; }
	~ReadOnlyNetworkGraph() { ReadOnlyNetworkGraph_free(self); }
	ReadOnlyNetworkGraph& operator=(ReadOnlyNetworkGraph&& o) { ReadOnlyNetworkGraph_free(self); self = o.self; memset(&o, 0, sizeof(ReadOnlyNetworkGraph)); return *this; }
	LDKReadOnlyNetworkGraph* operator &() { return &self; }
	LDKReadOnlyNetworkGraph* operator ->() { return &self; }
	const LDKReadOnlyNetworkGraph* operator &() const { return &self; }
	const LDKReadOnlyNetworkGraph* operator ->() const { return &self; }
};
class NetworkUpdate {
private:
	LDKNetworkUpdate self;
public:
	NetworkUpdate(const NetworkUpdate&) = delete;
	NetworkUpdate(NetworkUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(NetworkUpdate)); }
	NetworkUpdate(LDKNetworkUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetworkUpdate)); }
	operator LDKNetworkUpdate() && { LDKNetworkUpdate res = self; memset(&self, 0, sizeof(LDKNetworkUpdate)); return res; }
	~NetworkUpdate() { NetworkUpdate_free(self); }
	NetworkUpdate& operator=(NetworkUpdate&& o) { NetworkUpdate_free(self); self = o.self; memset(&o, 0, sizeof(NetworkUpdate)); return *this; }
	LDKNetworkUpdate* operator &() { return &self; }
	LDKNetworkUpdate* operator ->() { return &self; }
	const LDKNetworkUpdate* operator &() const { return &self; }
	const LDKNetworkUpdate* operator ->() const { return &self; }
};
class P2PGossipSync {
private:
	LDKP2PGossipSync self;
public:
	P2PGossipSync(const P2PGossipSync&) = delete;
	P2PGossipSync(P2PGossipSync&& o) : self(o.self) { memset(&o, 0, sizeof(P2PGossipSync)); }
	P2PGossipSync(LDKP2PGossipSync&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKP2PGossipSync)); }
	operator LDKP2PGossipSync() && { LDKP2PGossipSync res = self; memset(&self, 0, sizeof(LDKP2PGossipSync)); return res; }
	~P2PGossipSync() { P2PGossipSync_free(self); }
	P2PGossipSync& operator=(P2PGossipSync&& o) { P2PGossipSync_free(self); self = o.self; memset(&o, 0, sizeof(P2PGossipSync)); return *this; }
	LDKP2PGossipSync* operator &() { return &self; }
	LDKP2PGossipSync* operator ->() { return &self; }
	const LDKP2PGossipSync* operator &() const { return &self; }
	const LDKP2PGossipSync* operator ->() const { return &self; }
};
class ChannelUpdateInfo {
private:
	LDKChannelUpdateInfo self;
public:
	ChannelUpdateInfo(const ChannelUpdateInfo&) = delete;
	ChannelUpdateInfo(ChannelUpdateInfo&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelUpdateInfo)); }
	ChannelUpdateInfo(LDKChannelUpdateInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelUpdateInfo)); }
	operator LDKChannelUpdateInfo() && { LDKChannelUpdateInfo res = self; memset(&self, 0, sizeof(LDKChannelUpdateInfo)); return res; }
	~ChannelUpdateInfo() { ChannelUpdateInfo_free(self); }
	ChannelUpdateInfo& operator=(ChannelUpdateInfo&& o) { ChannelUpdateInfo_free(self); self = o.self; memset(&o, 0, sizeof(ChannelUpdateInfo)); return *this; }
	LDKChannelUpdateInfo* operator &() { return &self; }
	LDKChannelUpdateInfo* operator ->() { return &self; }
	const LDKChannelUpdateInfo* operator &() const { return &self; }
	const LDKChannelUpdateInfo* operator ->() const { return &self; }
};
class ChannelInfo {
private:
	LDKChannelInfo self;
public:
	ChannelInfo(const ChannelInfo&) = delete;
	ChannelInfo(ChannelInfo&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelInfo)); }
	ChannelInfo(LDKChannelInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelInfo)); }
	operator LDKChannelInfo() && { LDKChannelInfo res = self; memset(&self, 0, sizeof(LDKChannelInfo)); return res; }
	~ChannelInfo() { ChannelInfo_free(self); }
	ChannelInfo& operator=(ChannelInfo&& o) { ChannelInfo_free(self); self = o.self; memset(&o, 0, sizeof(ChannelInfo)); return *this; }
	LDKChannelInfo* operator &() { return &self; }
	LDKChannelInfo* operator ->() { return &self; }
	const LDKChannelInfo* operator &() const { return &self; }
	const LDKChannelInfo* operator ->() const { return &self; }
};
class DirectedChannelInfo {
private:
	LDKDirectedChannelInfo self;
public:
	DirectedChannelInfo(const DirectedChannelInfo&) = delete;
	DirectedChannelInfo(DirectedChannelInfo&& o) : self(o.self) { memset(&o, 0, sizeof(DirectedChannelInfo)); }
	DirectedChannelInfo(LDKDirectedChannelInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDirectedChannelInfo)); }
	operator LDKDirectedChannelInfo() && { LDKDirectedChannelInfo res = self; memset(&self, 0, sizeof(LDKDirectedChannelInfo)); return res; }
	~DirectedChannelInfo() { DirectedChannelInfo_free(self); }
	DirectedChannelInfo& operator=(DirectedChannelInfo&& o) { DirectedChannelInfo_free(self); self = o.self; memset(&o, 0, sizeof(DirectedChannelInfo)); return *this; }
	LDKDirectedChannelInfo* operator &() { return &self; }
	LDKDirectedChannelInfo* operator ->() { return &self; }
	const LDKDirectedChannelInfo* operator &() const { return &self; }
	const LDKDirectedChannelInfo* operator ->() const { return &self; }
};
class EffectiveCapacity {
private:
	LDKEffectiveCapacity self;
public:
	EffectiveCapacity(const EffectiveCapacity&) = delete;
	EffectiveCapacity(EffectiveCapacity&& o) : self(o.self) { memset(&o, 0, sizeof(EffectiveCapacity)); }
	EffectiveCapacity(LDKEffectiveCapacity&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEffectiveCapacity)); }
	operator LDKEffectiveCapacity() && { LDKEffectiveCapacity res = self; memset(&self, 0, sizeof(LDKEffectiveCapacity)); return res; }
	~EffectiveCapacity() { EffectiveCapacity_free(self); }
	EffectiveCapacity& operator=(EffectiveCapacity&& o) { EffectiveCapacity_free(self); self = o.self; memset(&o, 0, sizeof(EffectiveCapacity)); return *this; }
	LDKEffectiveCapacity* operator &() { return &self; }
	LDKEffectiveCapacity* operator ->() { return &self; }
	const LDKEffectiveCapacity* operator &() const { return &self; }
	const LDKEffectiveCapacity* operator ->() const { return &self; }
};
class RoutingFees {
private:
	LDKRoutingFees self;
public:
	RoutingFees(const RoutingFees&) = delete;
	RoutingFees(RoutingFees&& o) : self(o.self) { memset(&o, 0, sizeof(RoutingFees)); }
	RoutingFees(LDKRoutingFees&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoutingFees)); }
	operator LDKRoutingFees() && { LDKRoutingFees res = self; memset(&self, 0, sizeof(LDKRoutingFees)); return res; }
	~RoutingFees() { RoutingFees_free(self); }
	RoutingFees& operator=(RoutingFees&& o) { RoutingFees_free(self); self = o.self; memset(&o, 0, sizeof(RoutingFees)); return *this; }
	LDKRoutingFees* operator &() { return &self; }
	LDKRoutingFees* operator ->() { return &self; }
	const LDKRoutingFees* operator &() const { return &self; }
	const LDKRoutingFees* operator ->() const { return &self; }
};
class NodeAnnouncementInfo {
private:
	LDKNodeAnnouncementInfo self;
public:
	NodeAnnouncementInfo(const NodeAnnouncementInfo&) = delete;
	NodeAnnouncementInfo(NodeAnnouncementInfo&& o) : self(o.self) { memset(&o, 0, sizeof(NodeAnnouncementInfo)); }
	NodeAnnouncementInfo(LDKNodeAnnouncementInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeAnnouncementInfo)); }
	operator LDKNodeAnnouncementInfo() && { LDKNodeAnnouncementInfo res = self; memset(&self, 0, sizeof(LDKNodeAnnouncementInfo)); return res; }
	~NodeAnnouncementInfo() { NodeAnnouncementInfo_free(self); }
	NodeAnnouncementInfo& operator=(NodeAnnouncementInfo&& o) { NodeAnnouncementInfo_free(self); self = o.self; memset(&o, 0, sizeof(NodeAnnouncementInfo)); return *this; }
	LDKNodeAnnouncementInfo* operator &() { return &self; }
	LDKNodeAnnouncementInfo* operator ->() { return &self; }
	const LDKNodeAnnouncementInfo* operator &() const { return &self; }
	const LDKNodeAnnouncementInfo* operator ->() const { return &self; }
};
class NodeAlias {
private:
	LDKNodeAlias self;
public:
	NodeAlias(const NodeAlias&) = delete;
	NodeAlias(NodeAlias&& o) : self(o.self) { memset(&o, 0, sizeof(NodeAlias)); }
	NodeAlias(LDKNodeAlias&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeAlias)); }
	operator LDKNodeAlias() && { LDKNodeAlias res = self; memset(&self, 0, sizeof(LDKNodeAlias)); return res; }
	~NodeAlias() { NodeAlias_free(self); }
	NodeAlias& operator=(NodeAlias&& o) { NodeAlias_free(self); self = o.self; memset(&o, 0, sizeof(NodeAlias)); return *this; }
	LDKNodeAlias* operator &() { return &self; }
	LDKNodeAlias* operator ->() { return &self; }
	const LDKNodeAlias* operator &() const { return &self; }
	const LDKNodeAlias* operator ->() const { return &self; }
};
class NodeInfo {
private:
	LDKNodeInfo self;
public:
	NodeInfo(const NodeInfo&) = delete;
	NodeInfo(NodeInfo&& o) : self(o.self) { memset(&o, 0, sizeof(NodeInfo)); }
	NodeInfo(LDKNodeInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeInfo)); }
	operator LDKNodeInfo() && { LDKNodeInfo res = self; memset(&self, 0, sizeof(LDKNodeInfo)); return res; }
	~NodeInfo() { NodeInfo_free(self); }
	NodeInfo& operator=(NodeInfo&& o) { NodeInfo_free(self); self = o.self; memset(&o, 0, sizeof(NodeInfo)); return *this; }
	LDKNodeInfo* operator &() { return &self; }
	LDKNodeInfo* operator ->() { return &self; }
	const LDKNodeInfo* operator &() const { return &self; }
	const LDKNodeInfo* operator ->() const { return &self; }
};
class DelayedPaymentOutputDescriptor {
private:
	LDKDelayedPaymentOutputDescriptor self;
public:
	DelayedPaymentOutputDescriptor(const DelayedPaymentOutputDescriptor&) = delete;
	DelayedPaymentOutputDescriptor(DelayedPaymentOutputDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(DelayedPaymentOutputDescriptor)); }
	DelayedPaymentOutputDescriptor(LDKDelayedPaymentOutputDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDelayedPaymentOutputDescriptor)); }
	operator LDKDelayedPaymentOutputDescriptor() && { LDKDelayedPaymentOutputDescriptor res = self; memset(&self, 0, sizeof(LDKDelayedPaymentOutputDescriptor)); return res; }
	~DelayedPaymentOutputDescriptor() { DelayedPaymentOutputDescriptor_free(self); }
	DelayedPaymentOutputDescriptor& operator=(DelayedPaymentOutputDescriptor&& o) { DelayedPaymentOutputDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(DelayedPaymentOutputDescriptor)); return *this; }
	LDKDelayedPaymentOutputDescriptor* operator &() { return &self; }
	LDKDelayedPaymentOutputDescriptor* operator ->() { return &self; }
	const LDKDelayedPaymentOutputDescriptor* operator &() const { return &self; }
	const LDKDelayedPaymentOutputDescriptor* operator ->() const { return &self; }
};
class StaticPaymentOutputDescriptor {
private:
	LDKStaticPaymentOutputDescriptor self;
public:
	StaticPaymentOutputDescriptor(const StaticPaymentOutputDescriptor&) = delete;
	StaticPaymentOutputDescriptor(StaticPaymentOutputDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(StaticPaymentOutputDescriptor)); }
	StaticPaymentOutputDescriptor(LDKStaticPaymentOutputDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKStaticPaymentOutputDescriptor)); }
	operator LDKStaticPaymentOutputDescriptor() && { LDKStaticPaymentOutputDescriptor res = self; memset(&self, 0, sizeof(LDKStaticPaymentOutputDescriptor)); return res; }
	~StaticPaymentOutputDescriptor() { StaticPaymentOutputDescriptor_free(self); }
	StaticPaymentOutputDescriptor& operator=(StaticPaymentOutputDescriptor&& o) { StaticPaymentOutputDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(StaticPaymentOutputDescriptor)); return *this; }
	LDKStaticPaymentOutputDescriptor* operator &() { return &self; }
	LDKStaticPaymentOutputDescriptor* operator ->() { return &self; }
	const LDKStaticPaymentOutputDescriptor* operator &() const { return &self; }
	const LDKStaticPaymentOutputDescriptor* operator ->() const { return &self; }
};
class SpendableOutputDescriptor {
private:
	LDKSpendableOutputDescriptor self;
public:
	SpendableOutputDescriptor(const SpendableOutputDescriptor&) = delete;
	SpendableOutputDescriptor(SpendableOutputDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(SpendableOutputDescriptor)); }
	SpendableOutputDescriptor(LDKSpendableOutputDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSpendableOutputDescriptor)); }
	operator LDKSpendableOutputDescriptor() && { LDKSpendableOutputDescriptor res = self; memset(&self, 0, sizeof(LDKSpendableOutputDescriptor)); return res; }
	~SpendableOutputDescriptor() { SpendableOutputDescriptor_free(self); }
	SpendableOutputDescriptor& operator=(SpendableOutputDescriptor&& o) { SpendableOutputDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(SpendableOutputDescriptor)); return *this; }
	LDKSpendableOutputDescriptor* operator &() { return &self; }
	LDKSpendableOutputDescriptor* operator ->() { return &self; }
	const LDKSpendableOutputDescriptor* operator &() const { return &self; }
	const LDKSpendableOutputDescriptor* operator ->() const { return &self; }
};
class BaseSign {
private:
	LDKBaseSign self;
public:
	BaseSign(const BaseSign&) = delete;
	BaseSign(BaseSign&& o) : self(o.self) { memset(&o, 0, sizeof(BaseSign)); }
	BaseSign(LDKBaseSign&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBaseSign)); }
	operator LDKBaseSign() && { LDKBaseSign res = self; memset(&self, 0, sizeof(LDKBaseSign)); return res; }
	~BaseSign() { BaseSign_free(self); }
	BaseSign& operator=(BaseSign&& o) { BaseSign_free(self); self = o.self; memset(&o, 0, sizeof(BaseSign)); return *this; }
	LDKBaseSign* operator &() { return &self; }
	LDKBaseSign* operator ->() { return &self; }
	const LDKBaseSign* operator &() const { return &self; }
	const LDKBaseSign* operator ->() const { return &self; }
	/**
	 *  Gets the per-commitment point for a specific commitment number
	 * 
	 *  Note that the commitment number starts at (1 << 48) - 1 and counts backwards.
	 */
	inline LDKPublicKey get_per_commitment_point(uint64_t idx);
	/**
	 *  Gets the commitment secret for a specific commitment number as part of the revocation process
	 * 
	 *  An external signer implementation should error here if the commitment was already signed
	 *  and should refuse to sign it in the future.
	 * 
	 *  May be called more than once for the same index.
	 * 
	 *  Note that the commitment number starts at (1 << 48) - 1 and counts backwards.
	 */
	inline LDKThirtyTwoBytes release_commitment_secret(uint64_t idx);
	/**
	 *  Validate the counterparty's signatures on the holder commitment transaction and HTLCs.
	 * 
	 *  This is required in order for the signer to make sure that releasing a commitment
	 *  secret won't leave us without a broadcastable holder transaction.
	 *  Policy checks should be implemented in this function, including checking the amount
	 *  sent to us and checking the HTLCs.
	 * 
	 *  The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	 *  A validating signer should ensure that an HTLC output is removed only when the matching
	 *  preimage is provided, or when the value to holder is restored.
	 * 
	 *  NOTE: all the relevant preimages will be provided, but there may also be additional
	 *  irrelevant or duplicate preimages.
	 */
	inline LDK::CResult_NoneNoneZ validate_holder_commitment(const struct LDKHolderCommitmentTransaction *NONNULL_PTR holder_tx, struct LDKCVec_PaymentPreimageZ preimages);
	/**
	 *  Gets an arbitrary identifier describing the set of keys which are provided back to you in
	 *  some SpendableOutputDescriptor types. This should be sufficient to identify this
	 *  Sign object uniquely and lookup or re-derive its keys.
	 */
	inline LDKThirtyTwoBytes channel_keys_id();
	/**
	 *  Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
	 * 
	 *  Note that if signing fails or is rejected, the channel will be force-closed.
	 * 
	 *  Policy checks should be implemented in this function, including checking the amount
	 *  sent to us and checking the HTLCs.
	 * 
	 *  The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	 *  A validating signer should ensure that an HTLC output is removed only when the matching
	 *  preimage is provided, or when the value to holder is restored.
	 * 
	 *  NOTE: all the relevant preimages will be provided, but there may also be additional
	 *  irrelevant or duplicate preimages.
	 */
	inline LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ sign_counterparty_commitment(const struct LDKCommitmentTransaction *NONNULL_PTR commitment_tx, struct LDKCVec_PaymentPreimageZ preimages);
	/**
	 *  Validate the counterparty's revocation.
	 * 
	 *  This is required in order for the signer to make sure that the state has moved
	 *  forward and it is safe to sign the next counterparty commitment.
	 */
	inline LDK::CResult_NoneNoneZ validate_counterparty_revocation(uint64_t idx, const uint8_t (*secret)[32]);
	/**
	 *  Create a signatures for a holder's commitment transaction and its claiming HTLC transactions.
	 *  This will only ever be called with a non-revoked commitment_tx.  This will be called with the
	 *  latest commitment_tx when we initiate a force-close.
	 *  This will be called with the previous latest, just to get claiming HTLC signatures, if we are
	 *  reacting to a ChannelMonitor replica that decided to broadcast before it had been updated to
	 *  the latest.
	 *  This may be called multiple times for the same transaction.
	 * 
	 *  An external signer implementation should check that the commitment has not been revoked.
	 * 
	 *  May return Err if key derivation fails.  Callers, such as ChannelMonitor, will panic in such a case.
	 */
	inline LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ sign_holder_commitment_and_htlcs(const struct LDKHolderCommitmentTransaction *NONNULL_PTR commitment_tx);
	/**
	 *  Create a signature for the given input in a transaction spending an HTLC transaction output
	 *  or a commitment transaction `to_local` output when our counterparty broadcasts an old state.
	 * 
	 *  A justice transaction may claim multiple outputs at the same time if timelocks are
	 *  similar, but only a signature for the input at index `input` should be signed for here.
	 *  It may be called multiple times for same output(s) if a fee-bump is needed with regards
	 *  to an upcoming timelock expiration.
	 * 
	 *  Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	 * 
	 *  per_commitment_key is revocation secret which was provided by our counterparty when they
	 *  revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	 *  not allow the spending of any funds by itself (you need our holder revocation_secret to do
	 *  so).
	 */
	inline LDK::CResult_SignatureNoneZ sign_justice_revoked_output(struct LDKTransaction justice_tx, uintptr_t input, uint64_t amount, const uint8_t (*per_commitment_key)[32]);
	/**
	 *  Create a signature for the given input in a transaction spending a commitment transaction
	 *  HTLC output when our counterparty broadcasts an old state.
	 * 
	 *  A justice transaction may claim multiple outputs at the same time if timelocks are
	 *  similar, but only a signature for the input at index `input` should be signed for here.
	 *  It may be called multiple times for same output(s) if a fee-bump is needed with regards
	 *  to an upcoming timelock expiration.
	 * 
	 *  Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	 * 
	 *  per_commitment_key is revocation secret which was provided by our counterparty when they
	 *  revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	 *  not allow the spending of any funds by itself (you need our holder revocation_secret to do
	 *  so).
	 * 
	 *  htlc holds HTLC elements (hash, timelock), thus changing the format of the witness script
	 *  (which is committed to in the BIP 143 signatures).
	 */
	inline LDK::CResult_SignatureNoneZ sign_justice_revoked_htlc(struct LDKTransaction justice_tx, uintptr_t input, uint64_t amount, const uint8_t (*per_commitment_key)[32], const struct LDKHTLCOutputInCommitment *NONNULL_PTR htlc);
	/**
	 *  Create a signature for a claiming transaction for a HTLC output on a counterparty's commitment
	 *  transaction, either offered or received.
	 * 
	 *  Such a transaction may claim multiples offered outputs at same time if we know the
	 *  preimage for each when we create it, but only the input at index `input` should be
	 *  signed for here. It may be called multiple times for same output(s) if a fee-bump is
	 *  needed with regards to an upcoming timelock expiration.
	 * 
	 *  Witness_script is either a offered or received script as defined in BOLT3 for HTLC
	 *  outputs.
	 * 
	 *  Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	 * 
	 *  Per_commitment_point is the dynamic point corresponding to the channel state
	 *  detected onchain. It has been generated by our counterparty and is used to derive
	 *  channel state keys, which are then included in the witness script and committed to in the
	 *  BIP 143 signature.
	 */
	inline LDK::CResult_SignatureNoneZ sign_counterparty_htlc_transaction(struct LDKTransaction htlc_tx, uintptr_t input, uint64_t amount, struct LDKPublicKey per_commitment_point, const struct LDKHTLCOutputInCommitment *NONNULL_PTR htlc);
	/**
	 *  Create a signature for a (proposed) closing transaction.
	 * 
	 *  Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	 *  chosen to forgo their output as dust.
	 */
	inline LDK::CResult_SignatureNoneZ sign_closing_transaction(const struct LDKClosingTransaction *NONNULL_PTR closing_tx);
	/**
	 *  Signs a channel announcement message with our funding key and our node secret key (aka
	 *  node_id or network_key), proving it comes from one of the channel participants.
	 * 
	 *  The first returned signature should be from our node secret key, the second from our
	 *  funding key.
	 * 
	 *  Note that if this fails or is rejected, the channel will not be publicly announced and
	 *  our counterparty may (though likely will not) close the channel on us for violating the
	 *  protocol.
	 */
	inline LDK::CResult_C2Tuple_SignatureSignatureZNoneZ sign_channel_announcement(const struct LDKUnsignedChannelAnnouncement *NONNULL_PTR msg);
	/**
	 *  Set the counterparty static channel data, including basepoints,
	 *  counterparty_selected/holder_selected_contest_delay and funding outpoint.
	 *  This is done as soon as the funding outpoint is known.  Since these are static channel data,
	 *  they MUST NOT be allowed to change to different values once set.
	 * 
	 *  channel_parameters.is_populated() MUST be true.
	 * 
	 *  We bind holder_selected_contest_delay late here for API convenience.
	 * 
	 *  Will be called before any signatures are applied.
	 */
	inline void ready_channel(const struct LDKChannelTransactionParameters *NONNULL_PTR channel_parameters);
};
class Sign {
private:
	LDKSign self;
public:
	Sign(const Sign&) = delete;
	Sign(Sign&& o) : self(o.self) { memset(&o, 0, sizeof(Sign)); }
	Sign(LDKSign&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSign)); }
	operator LDKSign() && { LDKSign res = self; memset(&self, 0, sizeof(LDKSign)); return res; }
	~Sign() { Sign_free(self); }
	Sign& operator=(Sign&& o) { Sign_free(self); self = o.self; memset(&o, 0, sizeof(Sign)); return *this; }
	LDKSign* operator &() { return &self; }
	LDKSign* operator ->() { return &self; }
	const LDKSign* operator &() const { return &self; }
	const LDKSign* operator ->() const { return &self; }
};
class Recipient {
private:
	LDKRecipient self;
public:
	Recipient(const Recipient&) = delete;
	Recipient(Recipient&& o) : self(o.self) { memset(&o, 0, sizeof(Recipient)); }
	Recipient(LDKRecipient&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRecipient)); }
	operator LDKRecipient() && { LDKRecipient res = self; memset(&self, 0, sizeof(LDKRecipient)); return res; }
	Recipient& operator=(Recipient&& o) { self = o.self; memset(&o, 0, sizeof(Recipient)); return *this; }
	LDKRecipient* operator &() { return &self; }
	LDKRecipient* operator ->() { return &self; }
	const LDKRecipient* operator &() const { return &self; }
	const LDKRecipient* operator ->() const { return &self; }
};
class KeysInterface {
private:
	LDKKeysInterface self;
public:
	KeysInterface(const KeysInterface&) = delete;
	KeysInterface(KeysInterface&& o) : self(o.self) { memset(&o, 0, sizeof(KeysInterface)); }
	KeysInterface(LDKKeysInterface&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKKeysInterface)); }
	operator LDKKeysInterface() && { LDKKeysInterface res = self; memset(&self, 0, sizeof(LDKKeysInterface)); return res; }
	~KeysInterface() { KeysInterface_free(self); }
	KeysInterface& operator=(KeysInterface&& o) { KeysInterface_free(self); self = o.self; memset(&o, 0, sizeof(KeysInterface)); return *this; }
	LDKKeysInterface* operator &() { return &self; }
	LDKKeysInterface* operator ->() { return &self; }
	const LDKKeysInterface* operator &() const { return &self; }
	const LDKKeysInterface* operator ->() const { return &self; }
	/**
	 *  Get node secret key based on the provided [`Recipient`].
	 * 
	 *  The node_id/network_key is the public key that corresponds to this secret key.
	 * 
	 *  This method must return the same value each time it is called with a given `Recipient`
	 *  parameter.
	 */
	inline LDK::CResult_SecretKeyNoneZ get_node_secret(enum LDKRecipient recipient);
	/**
	 *  Gets the ECDH shared secret of our [`node secret`] and `other_key`, multiplying by `tweak` if
	 *  one is provided. Note that this tweak can be applied to `other_key` instead of our node
	 *  secret, though this is less efficient.
	 * 
	 *  [`node secret`]: Self::get_node_secret
	 */
	inline LDK::CResult_SharedSecretNoneZ ecdh(enum LDKRecipient recipient, struct LDKPublicKey other_key, struct LDKCOption_ScalarZ tweak);
	/**
	 *  Get a script pubkey which we send funds to when claiming on-chain contestable outputs.
	 * 
	 *  This method should return a different value each time it is called, to avoid linking
	 *  on-chain funds across channels as controlled to the same user.
	 */
	inline LDK::CVec_u8Z get_destination_script();
	/**
	 *  Get a script pubkey which we will send funds to when closing a channel.
	 * 
	 *  This method should return a different value each time it is called, to avoid linking
	 *  on-chain funds across channels as controlled to the same user.
	 */
	inline LDK::ShutdownScript get_shutdown_scriptpubkey();
	/**
	 *  Get a new set of Sign for per-channel secrets. These MUST be unique even if you
	 *  restarted with some stale data!
	 * 
	 *  This method must return a different value each time it is called.
	 */
	inline LDK::Sign get_channel_signer(bool inbound, uint64_t channel_value_satoshis);
	/**
	 *  Gets a unique, cryptographically-secure, random 32 byte value. This is used for encrypting
	 *  onion packets and for temporary channel IDs. There is no requirement that these be
	 *  persisted anywhere, though they must be unique across restarts.
	 * 
	 *  This method must return a different value each time it is called.
	 */
	inline LDKThirtyTwoBytes get_secure_random_bytes();
	/**
	 *  Reads a `Signer` for this `KeysInterface` from the given input stream.
	 *  This is only called during deserialization of other objects which contain
	 *  `Sign`-implementing objects (ie `ChannelMonitor`s and `ChannelManager`s).
	 *  The bytes are exactly those which `<Self::Signer as Writeable>::write()` writes, and
	 *  contain no versioning scheme. You may wish to include your own version prefix and ensure
	 *  you've read all of the provided bytes to ensure no corruption occurred.
	 */
	inline LDK::CResult_SignDecodeErrorZ read_chan_signer(struct LDKu8slice reader);
	/**
	 *  Sign an invoice.
	 *  By parameterizing by the raw invoice bytes instead of the hash, we allow implementors of
	 *  this trait to parse the invoice and make sure they're signing what they expect, rather than
	 *  blindly signing the hash.
	 *  The hrp is ascii bytes, while the invoice data is base32.
	 * 
	 *  The secret key used to sign the invoice is dependent on the [`Recipient`].
	 */
	inline LDK::CResult_RecoverableSignatureNoneZ sign_invoice(struct LDKu8slice hrp_bytes, struct LDKCVec_u5Z invoice_data, enum LDKRecipient receipient);
	/**
	 *  Get secret key material as bytes for use in encrypting and decrypting inbound payment data.
	 * 
	 *  If the implementor of this trait supports [phantom node payments], then every node that is
	 *  intended to be included in the phantom invoice route hints must return the same value from
	 *  this method.
	 * 
	 *  This method must return the same value each time it is called.
	 * 
	 *  [phantom node payments]: PhantomKeysManager
	 */
	inline LDKThirtyTwoBytes get_inbound_payment_key_material();
};
class InMemorySigner {
private:
	LDKInMemorySigner self;
public:
	InMemorySigner(const InMemorySigner&) = delete;
	InMemorySigner(InMemorySigner&& o) : self(o.self) { memset(&o, 0, sizeof(InMemorySigner)); }
	InMemorySigner(LDKInMemorySigner&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInMemorySigner)); }
	operator LDKInMemorySigner() && { LDKInMemorySigner res = self; memset(&self, 0, sizeof(LDKInMemorySigner)); return res; }
	~InMemorySigner() { InMemorySigner_free(self); }
	InMemorySigner& operator=(InMemorySigner&& o) { InMemorySigner_free(self); self = o.self; memset(&o, 0, sizeof(InMemorySigner)); return *this; }
	LDKInMemorySigner* operator &() { return &self; }
	LDKInMemorySigner* operator ->() { return &self; }
	const LDKInMemorySigner* operator &() const { return &self; }
	const LDKInMemorySigner* operator ->() const { return &self; }
};
class KeysManager {
private:
	LDKKeysManager self;
public:
	KeysManager(const KeysManager&) = delete;
	KeysManager(KeysManager&& o) : self(o.self) { memset(&o, 0, sizeof(KeysManager)); }
	KeysManager(LDKKeysManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKKeysManager)); }
	operator LDKKeysManager() && { LDKKeysManager res = self; memset(&self, 0, sizeof(LDKKeysManager)); return res; }
	~KeysManager() { KeysManager_free(self); }
	KeysManager& operator=(KeysManager&& o) { KeysManager_free(self); self = o.self; memset(&o, 0, sizeof(KeysManager)); return *this; }
	LDKKeysManager* operator &() { return &self; }
	LDKKeysManager* operator ->() { return &self; }
	const LDKKeysManager* operator &() const { return &self; }
	const LDKKeysManager* operator ->() const { return &self; }
};
class PhantomKeysManager {
private:
	LDKPhantomKeysManager self;
public:
	PhantomKeysManager(const PhantomKeysManager&) = delete;
	PhantomKeysManager(PhantomKeysManager&& o) : self(o.self) { memset(&o, 0, sizeof(PhantomKeysManager)); }
	PhantomKeysManager(LDKPhantomKeysManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPhantomKeysManager)); }
	operator LDKPhantomKeysManager() && { LDKPhantomKeysManager res = self; memset(&self, 0, sizeof(LDKPhantomKeysManager)); return res; }
	~PhantomKeysManager() { PhantomKeysManager_free(self); }
	PhantomKeysManager& operator=(PhantomKeysManager&& o) { PhantomKeysManager_free(self); self = o.self; memset(&o, 0, sizeof(PhantomKeysManager)); return *this; }
	LDKPhantomKeysManager* operator &() { return &self; }
	LDKPhantomKeysManager* operator ->() { return &self; }
	const LDKPhantomKeysManager* operator &() const { return &self; }
	const LDKPhantomKeysManager* operator ->() const { return &self; }
};
class FilesystemPersister {
private:
	LDKFilesystemPersister self;
public:
	FilesystemPersister(const FilesystemPersister&) = delete;
	FilesystemPersister(FilesystemPersister&& o) : self(o.self) { memset(&o, 0, sizeof(FilesystemPersister)); }
	FilesystemPersister(LDKFilesystemPersister&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFilesystemPersister)); }
	operator LDKFilesystemPersister() && { LDKFilesystemPersister res = self; memset(&self, 0, sizeof(LDKFilesystemPersister)); return res; }
	~FilesystemPersister() { FilesystemPersister_free(self); }
	FilesystemPersister& operator=(FilesystemPersister&& o) { FilesystemPersister_free(self); self = o.self; memset(&o, 0, sizeof(FilesystemPersister)); return *this; }
	LDKFilesystemPersister* operator &() { return &self; }
	LDKFilesystemPersister* operator ->() { return &self; }
	const LDKFilesystemPersister* operator &() const { return &self; }
	const LDKFilesystemPersister* operator ->() const { return &self; }
};
class ChannelManager {
private:
	LDKChannelManager self;
public:
	ChannelManager(const ChannelManager&) = delete;
	ChannelManager(ChannelManager&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelManager)); }
	ChannelManager(LDKChannelManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelManager)); }
	operator LDKChannelManager() && { LDKChannelManager res = self; memset(&self, 0, sizeof(LDKChannelManager)); return res; }
	~ChannelManager() { ChannelManager_free(self); }
	ChannelManager& operator=(ChannelManager&& o) { ChannelManager_free(self); self = o.self; memset(&o, 0, sizeof(ChannelManager)); return *this; }
	LDKChannelManager* operator &() { return &self; }
	LDKChannelManager* operator ->() { return &self; }
	const LDKChannelManager* operator &() const { return &self; }
	const LDKChannelManager* operator ->() const { return &self; }
};
class ChainParameters {
private:
	LDKChainParameters self;
public:
	ChainParameters(const ChainParameters&) = delete;
	ChainParameters(ChainParameters&& o) : self(o.self) { memset(&o, 0, sizeof(ChainParameters)); }
	ChainParameters(LDKChainParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChainParameters)); }
	operator LDKChainParameters() && { LDKChainParameters res = self; memset(&self, 0, sizeof(LDKChainParameters)); return res; }
	~ChainParameters() { ChainParameters_free(self); }
	ChainParameters& operator=(ChainParameters&& o) { ChainParameters_free(self); self = o.self; memset(&o, 0, sizeof(ChainParameters)); return *this; }
	LDKChainParameters* operator &() { return &self; }
	LDKChainParameters* operator ->() { return &self; }
	const LDKChainParameters* operator &() const { return &self; }
	const LDKChainParameters* operator ->() const { return &self; }
};
class CounterpartyForwardingInfo {
private:
	LDKCounterpartyForwardingInfo self;
public:
	CounterpartyForwardingInfo(const CounterpartyForwardingInfo&) = delete;
	CounterpartyForwardingInfo(CounterpartyForwardingInfo&& o) : self(o.self) { memset(&o, 0, sizeof(CounterpartyForwardingInfo)); }
	CounterpartyForwardingInfo(LDKCounterpartyForwardingInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCounterpartyForwardingInfo)); }
	operator LDKCounterpartyForwardingInfo() && { LDKCounterpartyForwardingInfo res = self; memset(&self, 0, sizeof(LDKCounterpartyForwardingInfo)); return res; }
	~CounterpartyForwardingInfo() { CounterpartyForwardingInfo_free(self); }
	CounterpartyForwardingInfo& operator=(CounterpartyForwardingInfo&& o) { CounterpartyForwardingInfo_free(self); self = o.self; memset(&o, 0, sizeof(CounterpartyForwardingInfo)); return *this; }
	LDKCounterpartyForwardingInfo* operator &() { return &self; }
	LDKCounterpartyForwardingInfo* operator ->() { return &self; }
	const LDKCounterpartyForwardingInfo* operator &() const { return &self; }
	const LDKCounterpartyForwardingInfo* operator ->() const { return &self; }
};
class ChannelCounterparty {
private:
	LDKChannelCounterparty self;
public:
	ChannelCounterparty(const ChannelCounterparty&) = delete;
	ChannelCounterparty(ChannelCounterparty&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelCounterparty)); }
	ChannelCounterparty(LDKChannelCounterparty&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelCounterparty)); }
	operator LDKChannelCounterparty() && { LDKChannelCounterparty res = self; memset(&self, 0, sizeof(LDKChannelCounterparty)); return res; }
	~ChannelCounterparty() { ChannelCounterparty_free(self); }
	ChannelCounterparty& operator=(ChannelCounterparty&& o) { ChannelCounterparty_free(self); self = o.self; memset(&o, 0, sizeof(ChannelCounterparty)); return *this; }
	LDKChannelCounterparty* operator &() { return &self; }
	LDKChannelCounterparty* operator ->() { return &self; }
	const LDKChannelCounterparty* operator &() const { return &self; }
	const LDKChannelCounterparty* operator ->() const { return &self; }
};
class ChannelDetails {
private:
	LDKChannelDetails self;
public:
	ChannelDetails(const ChannelDetails&) = delete;
	ChannelDetails(ChannelDetails&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelDetails)); }
	ChannelDetails(LDKChannelDetails&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelDetails)); }
	operator LDKChannelDetails() && { LDKChannelDetails res = self; memset(&self, 0, sizeof(LDKChannelDetails)); return res; }
	~ChannelDetails() { ChannelDetails_free(self); }
	ChannelDetails& operator=(ChannelDetails&& o) { ChannelDetails_free(self); self = o.self; memset(&o, 0, sizeof(ChannelDetails)); return *this; }
	LDKChannelDetails* operator &() { return &self; }
	LDKChannelDetails* operator ->() { return &self; }
	const LDKChannelDetails* operator &() const { return &self; }
	const LDKChannelDetails* operator ->() const { return &self; }
};
class PaymentSendFailure {
private:
	LDKPaymentSendFailure self;
public:
	PaymentSendFailure(const PaymentSendFailure&) = delete;
	PaymentSendFailure(PaymentSendFailure&& o) : self(o.self) { memset(&o, 0, sizeof(PaymentSendFailure)); }
	PaymentSendFailure(LDKPaymentSendFailure&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPaymentSendFailure)); }
	operator LDKPaymentSendFailure() && { LDKPaymentSendFailure res = self; memset(&self, 0, sizeof(LDKPaymentSendFailure)); return res; }
	~PaymentSendFailure() { PaymentSendFailure_free(self); }
	PaymentSendFailure& operator=(PaymentSendFailure&& o) { PaymentSendFailure_free(self); self = o.self; memset(&o, 0, sizeof(PaymentSendFailure)); return *this; }
	LDKPaymentSendFailure* operator &() { return &self; }
	LDKPaymentSendFailure* operator ->() { return &self; }
	const LDKPaymentSendFailure* operator &() const { return &self; }
	const LDKPaymentSendFailure* operator ->() const { return &self; }
};
class PhantomRouteHints {
private:
	LDKPhantomRouteHints self;
public:
	PhantomRouteHints(const PhantomRouteHints&) = delete;
	PhantomRouteHints(PhantomRouteHints&& o) : self(o.self) { memset(&o, 0, sizeof(PhantomRouteHints)); }
	PhantomRouteHints(LDKPhantomRouteHints&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPhantomRouteHints)); }
	operator LDKPhantomRouteHints() && { LDKPhantomRouteHints res = self; memset(&self, 0, sizeof(LDKPhantomRouteHints)); return res; }
	~PhantomRouteHints() { PhantomRouteHints_free(self); }
	PhantomRouteHints& operator=(PhantomRouteHints&& o) { PhantomRouteHints_free(self); self = o.self; memset(&o, 0, sizeof(PhantomRouteHints)); return *this; }
	LDKPhantomRouteHints* operator &() { return &self; }
	LDKPhantomRouteHints* operator ->() { return &self; }
	const LDKPhantomRouteHints* operator &() const { return &self; }
	const LDKPhantomRouteHints* operator ->() const { return &self; }
};
class ChannelManagerReadArgs {
private:
	LDKChannelManagerReadArgs self;
public:
	ChannelManagerReadArgs(const ChannelManagerReadArgs&) = delete;
	ChannelManagerReadArgs(ChannelManagerReadArgs&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelManagerReadArgs)); }
	ChannelManagerReadArgs(LDKChannelManagerReadArgs&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelManagerReadArgs)); }
	operator LDKChannelManagerReadArgs() && { LDKChannelManagerReadArgs res = self; memset(&self, 0, sizeof(LDKChannelManagerReadArgs)); return res; }
	~ChannelManagerReadArgs() { ChannelManagerReadArgs_free(self); }
	ChannelManagerReadArgs& operator=(ChannelManagerReadArgs&& o) { ChannelManagerReadArgs_free(self); self = o.self; memset(&o, 0, sizeof(ChannelManagerReadArgs)); return *this; }
	LDKChannelManagerReadArgs* operator &() { return &self; }
	LDKChannelManagerReadArgs* operator ->() { return &self; }
	const LDKChannelManagerReadArgs* operator &() const { return &self; }
	const LDKChannelManagerReadArgs* operator ->() const { return &self; }
};
class ChannelHandshakeConfig {
private:
	LDKChannelHandshakeConfig self;
public:
	ChannelHandshakeConfig(const ChannelHandshakeConfig&) = delete;
	ChannelHandshakeConfig(ChannelHandshakeConfig&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelHandshakeConfig)); }
	ChannelHandshakeConfig(LDKChannelHandshakeConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelHandshakeConfig)); }
	operator LDKChannelHandshakeConfig() && { LDKChannelHandshakeConfig res = self; memset(&self, 0, sizeof(LDKChannelHandshakeConfig)); return res; }
	~ChannelHandshakeConfig() { ChannelHandshakeConfig_free(self); }
	ChannelHandshakeConfig& operator=(ChannelHandshakeConfig&& o) { ChannelHandshakeConfig_free(self); self = o.self; memset(&o, 0, sizeof(ChannelHandshakeConfig)); return *this; }
	LDKChannelHandshakeConfig* operator &() { return &self; }
	LDKChannelHandshakeConfig* operator ->() { return &self; }
	const LDKChannelHandshakeConfig* operator &() const { return &self; }
	const LDKChannelHandshakeConfig* operator ->() const { return &self; }
};
class ChannelHandshakeLimits {
private:
	LDKChannelHandshakeLimits self;
public:
	ChannelHandshakeLimits(const ChannelHandshakeLimits&) = delete;
	ChannelHandshakeLimits(ChannelHandshakeLimits&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelHandshakeLimits)); }
	ChannelHandshakeLimits(LDKChannelHandshakeLimits&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelHandshakeLimits)); }
	operator LDKChannelHandshakeLimits() && { LDKChannelHandshakeLimits res = self; memset(&self, 0, sizeof(LDKChannelHandshakeLimits)); return res; }
	~ChannelHandshakeLimits() { ChannelHandshakeLimits_free(self); }
	ChannelHandshakeLimits& operator=(ChannelHandshakeLimits&& o) { ChannelHandshakeLimits_free(self); self = o.self; memset(&o, 0, sizeof(ChannelHandshakeLimits)); return *this; }
	LDKChannelHandshakeLimits* operator &() { return &self; }
	LDKChannelHandshakeLimits* operator ->() { return &self; }
	const LDKChannelHandshakeLimits* operator &() const { return &self; }
	const LDKChannelHandshakeLimits* operator ->() const { return &self; }
};
class ChannelConfig {
private:
	LDKChannelConfig self;
public:
	ChannelConfig(const ChannelConfig&) = delete;
	ChannelConfig(ChannelConfig&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelConfig)); }
	ChannelConfig(LDKChannelConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelConfig)); }
	operator LDKChannelConfig() && { LDKChannelConfig res = self; memset(&self, 0, sizeof(LDKChannelConfig)); return res; }
	~ChannelConfig() { ChannelConfig_free(self); }
	ChannelConfig& operator=(ChannelConfig&& o) { ChannelConfig_free(self); self = o.self; memset(&o, 0, sizeof(ChannelConfig)); return *this; }
	LDKChannelConfig* operator &() { return &self; }
	LDKChannelConfig* operator ->() { return &self; }
	const LDKChannelConfig* operator &() const { return &self; }
	const LDKChannelConfig* operator ->() const { return &self; }
};
class UserConfig {
private:
	LDKUserConfig self;
public:
	UserConfig(const UserConfig&) = delete;
	UserConfig(UserConfig&& o) : self(o.self) { memset(&o, 0, sizeof(UserConfig)); }
	UserConfig(LDKUserConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUserConfig)); }
	operator LDKUserConfig() && { LDKUserConfig res = self; memset(&self, 0, sizeof(LDKUserConfig)); return res; }
	~UserConfig() { UserConfig_free(self); }
	UserConfig& operator=(UserConfig&& o) { UserConfig_free(self); self = o.self; memset(&o, 0, sizeof(UserConfig)); return *this; }
	LDKUserConfig* operator &() { return &self; }
	LDKUserConfig* operator ->() { return &self; }
	const LDKUserConfig* operator &() const { return &self; }
	const LDKUserConfig* operator ->() const { return &self; }
};
class APIError {
private:
	LDKAPIError self;
public:
	APIError(const APIError&) = delete;
	APIError(APIError&& o) : self(o.self) { memset(&o, 0, sizeof(APIError)); }
	APIError(LDKAPIError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAPIError)); }
	operator LDKAPIError() && { LDKAPIError res = self; memset(&self, 0, sizeof(LDKAPIError)); return res; }
	~APIError() { APIError_free(self); }
	APIError& operator=(APIError&& o) { APIError_free(self); self = o.self; memset(&o, 0, sizeof(APIError)); return *this; }
	LDKAPIError* operator &() { return &self; }
	LDKAPIError* operator ->() { return &self; }
	const LDKAPIError* operator &() const { return &self; }
	const LDKAPIError* operator ->() const { return &self; }
};
class BigSize {
private:
	LDKBigSize self;
public:
	BigSize(const BigSize&) = delete;
	BigSize(BigSize&& o) : self(o.self) { memset(&o, 0, sizeof(BigSize)); }
	BigSize(LDKBigSize&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBigSize)); }
	operator LDKBigSize() && { LDKBigSize res = self; memset(&self, 0, sizeof(LDKBigSize)); return res; }
	~BigSize() { BigSize_free(self); }
	BigSize& operator=(BigSize&& o) { BigSize_free(self); self = o.self; memset(&o, 0, sizeof(BigSize)); return *this; }
	LDKBigSize* operator &() { return &self; }
	LDKBigSize* operator ->() { return &self; }
	const LDKBigSize* operator &() const { return &self; }
	const LDKBigSize* operator ->() const { return &self; }
};
class Hostname {
private:
	LDKHostname self;
public:
	Hostname(const Hostname&) = delete;
	Hostname(Hostname&& o) : self(o.self) { memset(&o, 0, sizeof(Hostname)); }
	Hostname(LDKHostname&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHostname)); }
	operator LDKHostname() && { LDKHostname res = self; memset(&self, 0, sizeof(LDKHostname)); return res; }
	~Hostname() { Hostname_free(self); }
	Hostname& operator=(Hostname&& o) { Hostname_free(self); self = o.self; memset(&o, 0, sizeof(Hostname)); return *this; }
	LDKHostname* operator &() { return &self; }
	LDKHostname* operator ->() { return &self; }
	const LDKHostname* operator &() const { return &self; }
	const LDKHostname* operator ->() const { return &self; }
};
class OutPoint {
private:
	LDKOutPoint self;
public:
	OutPoint(const OutPoint&) = delete;
	OutPoint(OutPoint&& o) : self(o.self) { memset(&o, 0, sizeof(OutPoint)); }
	OutPoint(LDKOutPoint&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOutPoint)); }
	operator LDKOutPoint() && { LDKOutPoint res = self; memset(&self, 0, sizeof(LDKOutPoint)); return res; }
	~OutPoint() { OutPoint_free(self); }
	OutPoint& operator=(OutPoint&& o) { OutPoint_free(self); self = o.self; memset(&o, 0, sizeof(OutPoint)); return *this; }
	LDKOutPoint* operator &() { return &self; }
	LDKOutPoint* operator ->() { return &self; }
	const LDKOutPoint* operator &() const { return &self; }
	const LDKOutPoint* operator ->() const { return &self; }
};
class CustomMessageReader {
private:
	LDKCustomMessageReader self;
public:
	CustomMessageReader(const CustomMessageReader&) = delete;
	CustomMessageReader(CustomMessageReader&& o) : self(o.self) { memset(&o, 0, sizeof(CustomMessageReader)); }
	CustomMessageReader(LDKCustomMessageReader&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCustomMessageReader)); }
	operator LDKCustomMessageReader() && { LDKCustomMessageReader res = self; memset(&self, 0, sizeof(LDKCustomMessageReader)); return res; }
	~CustomMessageReader() { CustomMessageReader_free(self); }
	CustomMessageReader& operator=(CustomMessageReader&& o) { CustomMessageReader_free(self); self = o.self; memset(&o, 0, sizeof(CustomMessageReader)); return *this; }
	LDKCustomMessageReader* operator &() { return &self; }
	LDKCustomMessageReader* operator ->() { return &self; }
	const LDKCustomMessageReader* operator &() const { return &self; }
	const LDKCustomMessageReader* operator ->() const { return &self; }
	/**
	 *  Decodes a custom message to `CustomMessageType`. If the given message type is known to the
	 *  implementation and the message could be decoded, must return `Ok(Some(message))`. If the
	 *  message type is unknown to the implementation, must return `Ok(None)`. If a decoding error
	 *  occur, must return `Err(DecodeError::X)` where `X` details the encountered error.
	 */
	inline LDK::CResult_COption_TypeZDecodeErrorZ read(uint16_t message_type, struct LDKu8slice buffer);
};
class Type {
private:
	LDKType self;
public:
	Type(const Type&) = delete;
	Type(Type&& o) : self(o.self) { memset(&o, 0, sizeof(Type)); }
	Type(LDKType&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKType)); }
	operator LDKType() && { LDKType res = self; memset(&self, 0, sizeof(LDKType)); return res; }
	~Type() { Type_free(self); }
	Type& operator=(Type&& o) { Type_free(self); self = o.self; memset(&o, 0, sizeof(Type)); return *this; }
	LDKType* operator &() { return &self; }
	LDKType* operator ->() { return &self; }
	const LDKType* operator &() const { return &self; }
	const LDKType* operator ->() const { return &self; }
	/**
	 *  Returns the type identifying the message payload.
	 */
	inline uint16_t type_id();
	/**
	 * Return a human-readable "debug" string describing this object
	 */
	inline LDK::Str debug_str();
};
class InvoicePayer {
private:
	LDKInvoicePayer self;
public:
	InvoicePayer(const InvoicePayer&) = delete;
	InvoicePayer(InvoicePayer&& o) : self(o.self) { memset(&o, 0, sizeof(InvoicePayer)); }
	InvoicePayer(LDKInvoicePayer&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInvoicePayer)); }
	operator LDKInvoicePayer() && { LDKInvoicePayer res = self; memset(&self, 0, sizeof(LDKInvoicePayer)); return res; }
	~InvoicePayer() { InvoicePayer_free(self); }
	InvoicePayer& operator=(InvoicePayer&& o) { InvoicePayer_free(self); self = o.self; memset(&o, 0, sizeof(InvoicePayer)); return *this; }
	LDKInvoicePayer* operator &() { return &self; }
	LDKInvoicePayer* operator ->() { return &self; }
	const LDKInvoicePayer* operator &() const { return &self; }
	const LDKInvoicePayer* operator ->() const { return &self; }
};
class Payer {
private:
	LDKPayer self;
public:
	Payer(const Payer&) = delete;
	Payer(Payer&& o) : self(o.self) { memset(&o, 0, sizeof(Payer)); }
	Payer(LDKPayer&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPayer)); }
	operator LDKPayer() && { LDKPayer res = self; memset(&self, 0, sizeof(LDKPayer)); return res; }
	~Payer() { Payer_free(self); }
	Payer& operator=(Payer&& o) { Payer_free(self); self = o.self; memset(&o, 0, sizeof(Payer)); return *this; }
	LDKPayer* operator &() { return &self; }
	LDKPayer* operator ->() { return &self; }
	const LDKPayer* operator &() const { return &self; }
	const LDKPayer* operator ->() const { return &self; }
	/**
	 *  Returns the payer's node id.
	 */
	inline LDKPublicKey node_id();
	/**
	 *  Returns the payer's channels.
	 */
	inline LDK::CVec_ChannelDetailsZ first_hops();
	/**
	 *  Sends a payment over the Lightning Network using the given [`Route`].
	 * 
	 *  Note that payment_secret (or a relevant inner pointer) may be NULL or all-0s to represent None
	 */
	inline LDK::CResult_PaymentIdPaymentSendFailureZ send_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_hash, struct LDKThirtyTwoBytes payment_secret);
	/**
	 *  Sends a spontaneous payment over the Lightning Network using the given [`Route`].
	 */
	inline LDK::CResult_PaymentIdPaymentSendFailureZ send_spontaneous_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_preimage);
	/**
	 *  Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	 */
	inline LDK::CResult_NonePaymentSendFailureZ retry_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_id);
	/**
	 *  Signals that no further retries for the given payment will occur.
	 */
	inline void abandon_payment(struct LDKThirtyTwoBytes payment_id);
};
class Router {
private:
	LDKRouter self;
public:
	Router(const Router&) = delete;
	Router(Router&& o) : self(o.self) { memset(&o, 0, sizeof(Router)); }
	Router(LDKRouter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouter)); }
	operator LDKRouter() && { LDKRouter res = self; memset(&self, 0, sizeof(LDKRouter)); return res; }
	~Router() { Router_free(self); }
	Router& operator=(Router&& o) { Router_free(self); self = o.self; memset(&o, 0, sizeof(Router)); return *this; }
	LDKRouter* operator &() { return &self; }
	LDKRouter* operator ->() { return &self; }
	const LDKRouter* operator &() const { return &self; }
	const LDKRouter* operator ->() const { return &self; }
	/**
	 *  Finds a [`Route`] between `payer` and `payee` for a payment with the given values.
	 * 
	 *  Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
	 */
	inline LDK::CResult_RouteLightningErrorZ find_route(struct LDKPublicKey payer, const struct LDKRouteParameters *NONNULL_PTR route_params, const uint8_t (*payment_hash)[32], struct LDKCVec_ChannelDetailsZ *first_hops, struct LDKInFlightHtlcs inflight_htlcs);
	/**
	 *  Lets the router know that payment through a specific path has failed.
	 */
	inline void notify_payment_path_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id);
	/**
	 *  Lets the router know that payment through a specific path was successful.
	 */
	inline void notify_payment_path_successful(struct LDKCVec_RouteHopZ path);
	/**
	 *  Lets the router know that a payment probe was successful.
	 */
	inline void notify_payment_probe_successful(struct LDKCVec_RouteHopZ path);
	/**
	 *  Lets the router know that a payment probe failed.
	 */
	inline void notify_payment_probe_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id);
};
class Retry {
private:
	LDKRetry self;
public:
	Retry(const Retry&) = delete;
	Retry(Retry&& o) : self(o.self) { memset(&o, 0, sizeof(Retry)); }
	Retry(LDKRetry&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRetry)); }
	operator LDKRetry() && { LDKRetry res = self; memset(&self, 0, sizeof(LDKRetry)); return res; }
	~Retry() { Retry_free(self); }
	Retry& operator=(Retry&& o) { Retry_free(self); self = o.self; memset(&o, 0, sizeof(Retry)); return *this; }
	LDKRetry* operator &() { return &self; }
	LDKRetry* operator ->() { return &self; }
	const LDKRetry* operator &() const { return &self; }
	const LDKRetry* operator ->() const { return &self; }
};
class PaymentError {
private:
	LDKPaymentError self;
public:
	PaymentError(const PaymentError&) = delete;
	PaymentError(PaymentError&& o) : self(o.self) { memset(&o, 0, sizeof(PaymentError)); }
	PaymentError(LDKPaymentError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPaymentError)); }
	operator LDKPaymentError() && { LDKPaymentError res = self; memset(&self, 0, sizeof(LDKPaymentError)); return res; }
	~PaymentError() { PaymentError_free(self); }
	PaymentError& operator=(PaymentError&& o) { PaymentError_free(self); self = o.self; memset(&o, 0, sizeof(PaymentError)); return *this; }
	LDKPaymentError* operator &() { return &self; }
	LDKPaymentError* operator ->() { return &self; }
	const LDKPaymentError* operator &() const { return &self; }
	const LDKPaymentError* operator ->() const { return &self; }
};
class InFlightHtlcs {
private:
	LDKInFlightHtlcs self;
public:
	InFlightHtlcs(const InFlightHtlcs&) = delete;
	InFlightHtlcs(InFlightHtlcs&& o) : self(o.self) { memset(&o, 0, sizeof(InFlightHtlcs)); }
	InFlightHtlcs(LDKInFlightHtlcs&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInFlightHtlcs)); }
	operator LDKInFlightHtlcs() && { LDKInFlightHtlcs res = self; memset(&self, 0, sizeof(LDKInFlightHtlcs)); return res; }
	~InFlightHtlcs() { InFlightHtlcs_free(self); }
	InFlightHtlcs& operator=(InFlightHtlcs&& o) { InFlightHtlcs_free(self); self = o.self; memset(&o, 0, sizeof(InFlightHtlcs)); return *this; }
	LDKInFlightHtlcs* operator &() { return &self; }
	LDKInFlightHtlcs* operator ->() { return &self; }
	const LDKInFlightHtlcs* operator &() const { return &self; }
	const LDKInFlightHtlcs* operator ->() const { return &self; }
};
class ParseError {
private:
	LDKParseError self;
public:
	ParseError(const ParseError&) = delete;
	ParseError(ParseError&& o) : self(o.self) { memset(&o, 0, sizeof(ParseError)); }
	ParseError(LDKParseError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKParseError)); }
	operator LDKParseError() && { LDKParseError res = self; memset(&self, 0, sizeof(LDKParseError)); return res; }
	~ParseError() { ParseError_free(self); }
	ParseError& operator=(ParseError&& o) { ParseError_free(self); self = o.self; memset(&o, 0, sizeof(ParseError)); return *this; }
	LDKParseError* operator &() { return &self; }
	LDKParseError* operator ->() { return &self; }
	const LDKParseError* operator &() const { return &self; }
	const LDKParseError* operator ->() const { return &self; }
};
class ParseOrSemanticError {
private:
	LDKParseOrSemanticError self;
public:
	ParseOrSemanticError(const ParseOrSemanticError&) = delete;
	ParseOrSemanticError(ParseOrSemanticError&& o) : self(o.self) { memset(&o, 0, sizeof(ParseOrSemanticError)); }
	ParseOrSemanticError(LDKParseOrSemanticError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKParseOrSemanticError)); }
	operator LDKParseOrSemanticError() && { LDKParseOrSemanticError res = self; memset(&self, 0, sizeof(LDKParseOrSemanticError)); return res; }
	~ParseOrSemanticError() { ParseOrSemanticError_free(self); }
	ParseOrSemanticError& operator=(ParseOrSemanticError&& o) { ParseOrSemanticError_free(self); self = o.self; memset(&o, 0, sizeof(ParseOrSemanticError)); return *this; }
	LDKParseOrSemanticError* operator &() { return &self; }
	LDKParseOrSemanticError* operator ->() { return &self; }
	const LDKParseOrSemanticError* operator &() const { return &self; }
	const LDKParseOrSemanticError* operator ->() const { return &self; }
};
class Invoice {
private:
	LDKInvoice self;
public:
	Invoice(const Invoice&) = delete;
	Invoice(Invoice&& o) : self(o.self) { memset(&o, 0, sizeof(Invoice)); }
	Invoice(LDKInvoice&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInvoice)); }
	operator LDKInvoice() && { LDKInvoice res = self; memset(&self, 0, sizeof(LDKInvoice)); return res; }
	~Invoice() { Invoice_free(self); }
	Invoice& operator=(Invoice&& o) { Invoice_free(self); self = o.self; memset(&o, 0, sizeof(Invoice)); return *this; }
	LDKInvoice* operator &() { return &self; }
	LDKInvoice* operator ->() { return &self; }
	const LDKInvoice* operator &() const { return &self; }
	const LDKInvoice* operator ->() const { return &self; }
};
class SignedRawInvoice {
private:
	LDKSignedRawInvoice self;
public:
	SignedRawInvoice(const SignedRawInvoice&) = delete;
	SignedRawInvoice(SignedRawInvoice&& o) : self(o.self) { memset(&o, 0, sizeof(SignedRawInvoice)); }
	SignedRawInvoice(LDKSignedRawInvoice&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSignedRawInvoice)); }
	operator LDKSignedRawInvoice() && { LDKSignedRawInvoice res = self; memset(&self, 0, sizeof(LDKSignedRawInvoice)); return res; }
	~SignedRawInvoice() { SignedRawInvoice_free(self); }
	SignedRawInvoice& operator=(SignedRawInvoice&& o) { SignedRawInvoice_free(self); self = o.self; memset(&o, 0, sizeof(SignedRawInvoice)); return *this; }
	LDKSignedRawInvoice* operator &() { return &self; }
	LDKSignedRawInvoice* operator ->() { return &self; }
	const LDKSignedRawInvoice* operator &() const { return &self; }
	const LDKSignedRawInvoice* operator ->() const { return &self; }
};
class RawInvoice {
private:
	LDKRawInvoice self;
public:
	RawInvoice(const RawInvoice&) = delete;
	RawInvoice(RawInvoice&& o) : self(o.self) { memset(&o, 0, sizeof(RawInvoice)); }
	RawInvoice(LDKRawInvoice&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRawInvoice)); }
	operator LDKRawInvoice() && { LDKRawInvoice res = self; memset(&self, 0, sizeof(LDKRawInvoice)); return res; }
	~RawInvoice() { RawInvoice_free(self); }
	RawInvoice& operator=(RawInvoice&& o) { RawInvoice_free(self); self = o.self; memset(&o, 0, sizeof(RawInvoice)); return *this; }
	LDKRawInvoice* operator &() { return &self; }
	LDKRawInvoice* operator ->() { return &self; }
	const LDKRawInvoice* operator &() const { return &self; }
	const LDKRawInvoice* operator ->() const { return &self; }
};
class RawDataPart {
private:
	LDKRawDataPart self;
public:
	RawDataPart(const RawDataPart&) = delete;
	RawDataPart(RawDataPart&& o) : self(o.self) { memset(&o, 0, sizeof(RawDataPart)); }
	RawDataPart(LDKRawDataPart&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRawDataPart)); }
	operator LDKRawDataPart() && { LDKRawDataPart res = self; memset(&self, 0, sizeof(LDKRawDataPart)); return res; }
	~RawDataPart() { RawDataPart_free(self); }
	RawDataPart& operator=(RawDataPart&& o) { RawDataPart_free(self); self = o.self; memset(&o, 0, sizeof(RawDataPart)); return *this; }
	LDKRawDataPart* operator &() { return &self; }
	LDKRawDataPart* operator ->() { return &self; }
	const LDKRawDataPart* operator &() const { return &self; }
	const LDKRawDataPart* operator ->() const { return &self; }
};
class PositiveTimestamp {
private:
	LDKPositiveTimestamp self;
public:
	PositiveTimestamp(const PositiveTimestamp&) = delete;
	PositiveTimestamp(PositiveTimestamp&& o) : self(o.self) { memset(&o, 0, sizeof(PositiveTimestamp)); }
	PositiveTimestamp(LDKPositiveTimestamp&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPositiveTimestamp)); }
	operator LDKPositiveTimestamp() && { LDKPositiveTimestamp res = self; memset(&self, 0, sizeof(LDKPositiveTimestamp)); return res; }
	~PositiveTimestamp() { PositiveTimestamp_free(self); }
	PositiveTimestamp& operator=(PositiveTimestamp&& o) { PositiveTimestamp_free(self); self = o.self; memset(&o, 0, sizeof(PositiveTimestamp)); return *this; }
	LDKPositiveTimestamp* operator &() { return &self; }
	LDKPositiveTimestamp* operator ->() { return &self; }
	const LDKPositiveTimestamp* operator &() const { return &self; }
	const LDKPositiveTimestamp* operator ->() const { return &self; }
};
class SiPrefix {
private:
	LDKSiPrefix self;
public:
	SiPrefix(const SiPrefix&) = delete;
	SiPrefix(SiPrefix&& o) : self(o.self) { memset(&o, 0, sizeof(SiPrefix)); }
	SiPrefix(LDKSiPrefix&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSiPrefix)); }
	operator LDKSiPrefix() && { LDKSiPrefix res = self; memset(&self, 0, sizeof(LDKSiPrefix)); return res; }
	SiPrefix& operator=(SiPrefix&& o) { self = o.self; memset(&o, 0, sizeof(SiPrefix)); return *this; }
	LDKSiPrefix* operator &() { return &self; }
	LDKSiPrefix* operator ->() { return &self; }
	const LDKSiPrefix* operator &() const { return &self; }
	const LDKSiPrefix* operator ->() const { return &self; }
};
class Currency {
private:
	LDKCurrency self;
public:
	Currency(const Currency&) = delete;
	Currency(Currency&& o) : self(o.self) { memset(&o, 0, sizeof(Currency)); }
	Currency(LDKCurrency&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCurrency)); }
	operator LDKCurrency() && { LDKCurrency res = self; memset(&self, 0, sizeof(LDKCurrency)); return res; }
	Currency& operator=(Currency&& o) { self = o.self; memset(&o, 0, sizeof(Currency)); return *this; }
	LDKCurrency* operator &() { return &self; }
	LDKCurrency* operator ->() { return &self; }
	const LDKCurrency* operator &() const { return &self; }
	const LDKCurrency* operator ->() const { return &self; }
};
class Sha256 {
private:
	LDKSha256 self;
public:
	Sha256(const Sha256&) = delete;
	Sha256(Sha256&& o) : self(o.self) { memset(&o, 0, sizeof(Sha256)); }
	Sha256(LDKSha256&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSha256)); }
	operator LDKSha256() && { LDKSha256 res = self; memset(&self, 0, sizeof(LDKSha256)); return res; }
	~Sha256() { Sha256_free(self); }
	Sha256& operator=(Sha256&& o) { Sha256_free(self); self = o.self; memset(&o, 0, sizeof(Sha256)); return *this; }
	LDKSha256* operator &() { return &self; }
	LDKSha256* operator ->() { return &self; }
	const LDKSha256* operator &() const { return &self; }
	const LDKSha256* operator ->() const { return &self; }
};
class Description {
private:
	LDKDescription self;
public:
	Description(const Description&) = delete;
	Description(Description&& o) : self(o.self) { memset(&o, 0, sizeof(Description)); }
	Description(LDKDescription&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDescription)); }
	operator LDKDescription() && { LDKDescription res = self; memset(&self, 0, sizeof(LDKDescription)); return res; }
	~Description() { Description_free(self); }
	Description& operator=(Description&& o) { Description_free(self); self = o.self; memset(&o, 0, sizeof(Description)); return *this; }
	LDKDescription* operator &() { return &self; }
	LDKDescription* operator ->() { return &self; }
	const LDKDescription* operator &() const { return &self; }
	const LDKDescription* operator ->() const { return &self; }
};
class PayeePubKey {
private:
	LDKPayeePubKey self;
public:
	PayeePubKey(const PayeePubKey&) = delete;
	PayeePubKey(PayeePubKey&& o) : self(o.self) { memset(&o, 0, sizeof(PayeePubKey)); }
	PayeePubKey(LDKPayeePubKey&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPayeePubKey)); }
	operator LDKPayeePubKey() && { LDKPayeePubKey res = self; memset(&self, 0, sizeof(LDKPayeePubKey)); return res; }
	~PayeePubKey() { PayeePubKey_free(self); }
	PayeePubKey& operator=(PayeePubKey&& o) { PayeePubKey_free(self); self = o.self; memset(&o, 0, sizeof(PayeePubKey)); return *this; }
	LDKPayeePubKey* operator &() { return &self; }
	LDKPayeePubKey* operator ->() { return &self; }
	const LDKPayeePubKey* operator &() const { return &self; }
	const LDKPayeePubKey* operator ->() const { return &self; }
};
class ExpiryTime {
private:
	LDKExpiryTime self;
public:
	ExpiryTime(const ExpiryTime&) = delete;
	ExpiryTime(ExpiryTime&& o) : self(o.self) { memset(&o, 0, sizeof(ExpiryTime)); }
	ExpiryTime(LDKExpiryTime&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKExpiryTime)); }
	operator LDKExpiryTime() && { LDKExpiryTime res = self; memset(&self, 0, sizeof(LDKExpiryTime)); return res; }
	~ExpiryTime() { ExpiryTime_free(self); }
	ExpiryTime& operator=(ExpiryTime&& o) { ExpiryTime_free(self); self = o.self; memset(&o, 0, sizeof(ExpiryTime)); return *this; }
	LDKExpiryTime* operator &() { return &self; }
	LDKExpiryTime* operator ->() { return &self; }
	const LDKExpiryTime* operator &() const { return &self; }
	const LDKExpiryTime* operator ->() const { return &self; }
};
class MinFinalCltvExpiry {
private:
	LDKMinFinalCltvExpiry self;
public:
	MinFinalCltvExpiry(const MinFinalCltvExpiry&) = delete;
	MinFinalCltvExpiry(MinFinalCltvExpiry&& o) : self(o.self) { memset(&o, 0, sizeof(MinFinalCltvExpiry)); }
	MinFinalCltvExpiry(LDKMinFinalCltvExpiry&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMinFinalCltvExpiry)); }
	operator LDKMinFinalCltvExpiry() && { LDKMinFinalCltvExpiry res = self; memset(&self, 0, sizeof(LDKMinFinalCltvExpiry)); return res; }
	~MinFinalCltvExpiry() { MinFinalCltvExpiry_free(self); }
	MinFinalCltvExpiry& operator=(MinFinalCltvExpiry&& o) { MinFinalCltvExpiry_free(self); self = o.self; memset(&o, 0, sizeof(MinFinalCltvExpiry)); return *this; }
	LDKMinFinalCltvExpiry* operator &() { return &self; }
	LDKMinFinalCltvExpiry* operator ->() { return &self; }
	const LDKMinFinalCltvExpiry* operator &() const { return &self; }
	const LDKMinFinalCltvExpiry* operator ->() const { return &self; }
};
class Fallback {
private:
	LDKFallback self;
public:
	Fallback(const Fallback&) = delete;
	Fallback(Fallback&& o) : self(o.self) { memset(&o, 0, sizeof(Fallback)); }
	Fallback(LDKFallback&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFallback)); }
	operator LDKFallback() && { LDKFallback res = self; memset(&self, 0, sizeof(LDKFallback)); return res; }
	~Fallback() { Fallback_free(self); }
	Fallback& operator=(Fallback&& o) { Fallback_free(self); self = o.self; memset(&o, 0, sizeof(Fallback)); return *this; }
	LDKFallback* operator &() { return &self; }
	LDKFallback* operator ->() { return &self; }
	const LDKFallback* operator &() const { return &self; }
	const LDKFallback* operator ->() const { return &self; }
};
class InvoiceSignature {
private:
	LDKInvoiceSignature self;
public:
	InvoiceSignature(const InvoiceSignature&) = delete;
	InvoiceSignature(InvoiceSignature&& o) : self(o.self) { memset(&o, 0, sizeof(InvoiceSignature)); }
	InvoiceSignature(LDKInvoiceSignature&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInvoiceSignature)); }
	operator LDKInvoiceSignature() && { LDKInvoiceSignature res = self; memset(&self, 0, sizeof(LDKInvoiceSignature)); return res; }
	~InvoiceSignature() { InvoiceSignature_free(self); }
	InvoiceSignature& operator=(InvoiceSignature&& o) { InvoiceSignature_free(self); self = o.self; memset(&o, 0, sizeof(InvoiceSignature)); return *this; }
	LDKInvoiceSignature* operator &() { return &self; }
	LDKInvoiceSignature* operator ->() { return &self; }
	const LDKInvoiceSignature* operator &() const { return &self; }
	const LDKInvoiceSignature* operator ->() const { return &self; }
};
class PrivateRoute {
private:
	LDKPrivateRoute self;
public:
	PrivateRoute(const PrivateRoute&) = delete;
	PrivateRoute(PrivateRoute&& o) : self(o.self) { memset(&o, 0, sizeof(PrivateRoute)); }
	PrivateRoute(LDKPrivateRoute&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPrivateRoute)); }
	operator LDKPrivateRoute() && { LDKPrivateRoute res = self; memset(&self, 0, sizeof(LDKPrivateRoute)); return res; }
	~PrivateRoute() { PrivateRoute_free(self); }
	PrivateRoute& operator=(PrivateRoute&& o) { PrivateRoute_free(self); self = o.self; memset(&o, 0, sizeof(PrivateRoute)); return *this; }
	LDKPrivateRoute* operator &() { return &self; }
	LDKPrivateRoute* operator ->() { return &self; }
	const LDKPrivateRoute* operator &() const { return &self; }
	const LDKPrivateRoute* operator ->() const { return &self; }
};
class CreationError {
private:
	LDKCreationError self;
public:
	CreationError(const CreationError&) = delete;
	CreationError(CreationError&& o) : self(o.self) { memset(&o, 0, sizeof(CreationError)); }
	CreationError(LDKCreationError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCreationError)); }
	operator LDKCreationError() && { LDKCreationError res = self; memset(&self, 0, sizeof(LDKCreationError)); return res; }
	CreationError& operator=(CreationError&& o) { self = o.self; memset(&o, 0, sizeof(CreationError)); return *this; }
	LDKCreationError* operator &() { return &self; }
	LDKCreationError* operator ->() { return &self; }
	const LDKCreationError* operator &() const { return &self; }
	const LDKCreationError* operator ->() const { return &self; }
};
class SemanticError {
private:
	LDKSemanticError self;
public:
	SemanticError(const SemanticError&) = delete;
	SemanticError(SemanticError&& o) : self(o.self) { memset(&o, 0, sizeof(SemanticError)); }
	SemanticError(LDKSemanticError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSemanticError)); }
	operator LDKSemanticError() && { LDKSemanticError res = self; memset(&self, 0, sizeof(LDKSemanticError)); return res; }
	SemanticError& operator=(SemanticError&& o) { self = o.self; memset(&o, 0, sizeof(SemanticError)); return *this; }
	LDKSemanticError* operator &() { return &self; }
	LDKSemanticError* operator ->() { return &self; }
	const LDKSemanticError* operator &() const { return &self; }
	const LDKSemanticError* operator ->() const { return &self; }
};
class SignOrCreationError {
private:
	LDKSignOrCreationError self;
public:
	SignOrCreationError(const SignOrCreationError&) = delete;
	SignOrCreationError(SignOrCreationError&& o) : self(o.self) { memset(&o, 0, sizeof(SignOrCreationError)); }
	SignOrCreationError(LDKSignOrCreationError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSignOrCreationError)); }
	operator LDKSignOrCreationError() && { LDKSignOrCreationError res = self; memset(&self, 0, sizeof(LDKSignOrCreationError)); return res; }
	~SignOrCreationError() { SignOrCreationError_free(self); }
	SignOrCreationError& operator=(SignOrCreationError&& o) { SignOrCreationError_free(self); self = o.self; memset(&o, 0, sizeof(SignOrCreationError)); return *this; }
	LDKSignOrCreationError* operator &() { return &self; }
	LDKSignOrCreationError* operator ->() { return &self; }
	const LDKSignOrCreationError* operator &() const { return &self; }
	const LDKSignOrCreationError* operator ->() const { return &self; }
};
class ChannelMonitorUpdate {
private:
	LDKChannelMonitorUpdate self;
public:
	ChannelMonitorUpdate(const ChannelMonitorUpdate&) = delete;
	ChannelMonitorUpdate(ChannelMonitorUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitorUpdate)); }
	ChannelMonitorUpdate(LDKChannelMonitorUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitorUpdate)); }
	operator LDKChannelMonitorUpdate() && { LDKChannelMonitorUpdate res = self; memset(&self, 0, sizeof(LDKChannelMonitorUpdate)); return res; }
	~ChannelMonitorUpdate() { ChannelMonitorUpdate_free(self); }
	ChannelMonitorUpdate& operator=(ChannelMonitorUpdate&& o) { ChannelMonitorUpdate_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMonitorUpdate)); return *this; }
	LDKChannelMonitorUpdate* operator &() { return &self; }
	LDKChannelMonitorUpdate* operator ->() { return &self; }
	const LDKChannelMonitorUpdate* operator &() const { return &self; }
	const LDKChannelMonitorUpdate* operator ->() const { return &self; }
};
class MonitorEvent {
private:
	LDKMonitorEvent self;
public:
	MonitorEvent(const MonitorEvent&) = delete;
	MonitorEvent(MonitorEvent&& o) : self(o.self) { memset(&o, 0, sizeof(MonitorEvent)); }
	MonitorEvent(LDKMonitorEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMonitorEvent)); }
	operator LDKMonitorEvent() && { LDKMonitorEvent res = self; memset(&self, 0, sizeof(LDKMonitorEvent)); return res; }
	~MonitorEvent() { MonitorEvent_free(self); }
	MonitorEvent& operator=(MonitorEvent&& o) { MonitorEvent_free(self); self = o.self; memset(&o, 0, sizeof(MonitorEvent)); return *this; }
	LDKMonitorEvent* operator &() { return &self; }
	LDKMonitorEvent* operator ->() { return &self; }
	const LDKMonitorEvent* operator &() const { return &self; }
	const LDKMonitorEvent* operator ->() const { return &self; }
};
class HTLCUpdate {
private:
	LDKHTLCUpdate self;
public:
	HTLCUpdate(const HTLCUpdate&) = delete;
	HTLCUpdate(HTLCUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCUpdate)); }
	HTLCUpdate(LDKHTLCUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCUpdate)); }
	operator LDKHTLCUpdate() && { LDKHTLCUpdate res = self; memset(&self, 0, sizeof(LDKHTLCUpdate)); return res; }
	~HTLCUpdate() { HTLCUpdate_free(self); }
	HTLCUpdate& operator=(HTLCUpdate&& o) { HTLCUpdate_free(self); self = o.self; memset(&o, 0, sizeof(HTLCUpdate)); return *this; }
	LDKHTLCUpdate* operator &() { return &self; }
	LDKHTLCUpdate* operator ->() { return &self; }
	const LDKHTLCUpdate* operator &() const { return &self; }
	const LDKHTLCUpdate* operator ->() const { return &self; }
};
class Balance {
private:
	LDKBalance self;
public:
	Balance(const Balance&) = delete;
	Balance(Balance&& o) : self(o.self) { memset(&o, 0, sizeof(Balance)); }
	Balance(LDKBalance&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBalance)); }
	operator LDKBalance() && { LDKBalance res = self; memset(&self, 0, sizeof(LDKBalance)); return res; }
	~Balance() { Balance_free(self); }
	Balance& operator=(Balance&& o) { Balance_free(self); self = o.self; memset(&o, 0, sizeof(Balance)); return *this; }
	LDKBalance* operator &() { return &self; }
	LDKBalance* operator ->() { return &self; }
	const LDKBalance* operator &() const { return &self; }
	const LDKBalance* operator ->() const { return &self; }
};
class ChannelMonitor {
private:
	LDKChannelMonitor self;
public:
	ChannelMonitor(const ChannelMonitor&) = delete;
	ChannelMonitor(ChannelMonitor&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitor)); }
	ChannelMonitor(LDKChannelMonitor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitor)); }
	operator LDKChannelMonitor() && { LDKChannelMonitor res = self; memset(&self, 0, sizeof(LDKChannelMonitor)); return res; }
	~ChannelMonitor() { ChannelMonitor_free(self); }
	ChannelMonitor& operator=(ChannelMonitor&& o) { ChannelMonitor_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMonitor)); return *this; }
	LDKChannelMonitor* operator &() { return &self; }
	LDKChannelMonitor* operator ->() { return &self; }
	const LDKChannelMonitor* operator &() const { return &self; }
	const LDKChannelMonitor* operator ->() const { return &self; }
};
class ExpandedKey {
private:
	LDKExpandedKey self;
public:
	ExpandedKey(const ExpandedKey&) = delete;
	ExpandedKey(ExpandedKey&& o) : self(o.self) { memset(&o, 0, sizeof(ExpandedKey)); }
	ExpandedKey(LDKExpandedKey&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKExpandedKey)); }
	operator LDKExpandedKey() && { LDKExpandedKey res = self; memset(&self, 0, sizeof(LDKExpandedKey)); return res; }
	~ExpandedKey() { ExpandedKey_free(self); }
	ExpandedKey& operator=(ExpandedKey&& o) { ExpandedKey_free(self); self = o.self; memset(&o, 0, sizeof(ExpandedKey)); return *this; }
	LDKExpandedKey* operator &() { return &self; }
	LDKExpandedKey* operator ->() { return &self; }
	const LDKExpandedKey* operator &() const { return &self; }
	const LDKExpandedKey* operator ->() const { return &self; }
};
class CustomMessageHandler {
private:
	LDKCustomMessageHandler self;
public:
	CustomMessageHandler(const CustomMessageHandler&) = delete;
	CustomMessageHandler(CustomMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(CustomMessageHandler)); }
	CustomMessageHandler(LDKCustomMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCustomMessageHandler)); }
	operator LDKCustomMessageHandler() && { LDKCustomMessageHandler res = self; memset(&self, 0, sizeof(LDKCustomMessageHandler)); return res; }
	~CustomMessageHandler() { CustomMessageHandler_free(self); }
	CustomMessageHandler& operator=(CustomMessageHandler&& o) { CustomMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(CustomMessageHandler)); return *this; }
	LDKCustomMessageHandler* operator &() { return &self; }
	LDKCustomMessageHandler* operator ->() { return &self; }
	const LDKCustomMessageHandler* operator &() const { return &self; }
	const LDKCustomMessageHandler* operator ->() const { return &self; }
	/**
	 *  Called with the message type that was received and the buffer to be read.
	 *  Can return a `MessageHandlingError` if the message could not be handled.
	 */
	inline LDK::CResult_NoneLightningErrorZ handle_custom_message(struct LDKType msg, struct LDKPublicKey sender_node_id);
	/**
	 *  Gets the list of pending messages which were generated by the custom message
	 *  handler, clearing the list in the process. The first tuple element must
	 *  correspond to the intended recipients node ids. If no connection to one of the
	 *  specified node does not exist, the message is simply not sent to it.
	 */
	inline LDK::CVec_C2Tuple_PublicKeyTypeZZ get_and_clear_pending_msg();
};
class IgnoringMessageHandler {
private:
	LDKIgnoringMessageHandler self;
public:
	IgnoringMessageHandler(const IgnoringMessageHandler&) = delete;
	IgnoringMessageHandler(IgnoringMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(IgnoringMessageHandler)); }
	IgnoringMessageHandler(LDKIgnoringMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKIgnoringMessageHandler)); }
	operator LDKIgnoringMessageHandler() && { LDKIgnoringMessageHandler res = self; memset(&self, 0, sizeof(LDKIgnoringMessageHandler)); return res; }
	~IgnoringMessageHandler() { IgnoringMessageHandler_free(self); }
	IgnoringMessageHandler& operator=(IgnoringMessageHandler&& o) { IgnoringMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(IgnoringMessageHandler)); return *this; }
	LDKIgnoringMessageHandler* operator &() { return &self; }
	LDKIgnoringMessageHandler* operator ->() { return &self; }
	const LDKIgnoringMessageHandler* operator &() const { return &self; }
	const LDKIgnoringMessageHandler* operator ->() const { return &self; }
};
class ErroringMessageHandler {
private:
	LDKErroringMessageHandler self;
public:
	ErroringMessageHandler(const ErroringMessageHandler&) = delete;
	ErroringMessageHandler(ErroringMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(ErroringMessageHandler)); }
	ErroringMessageHandler(LDKErroringMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKErroringMessageHandler)); }
	operator LDKErroringMessageHandler() && { LDKErroringMessageHandler res = self; memset(&self, 0, sizeof(LDKErroringMessageHandler)); return res; }
	~ErroringMessageHandler() { ErroringMessageHandler_free(self); }
	ErroringMessageHandler& operator=(ErroringMessageHandler&& o) { ErroringMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(ErroringMessageHandler)); return *this; }
	LDKErroringMessageHandler* operator &() { return &self; }
	LDKErroringMessageHandler* operator ->() { return &self; }
	const LDKErroringMessageHandler* operator &() const { return &self; }
	const LDKErroringMessageHandler* operator ->() const { return &self; }
};
class MessageHandler {
private:
	LDKMessageHandler self;
public:
	MessageHandler(const MessageHandler&) = delete;
	MessageHandler(MessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(MessageHandler)); }
	MessageHandler(LDKMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageHandler)); }
	operator LDKMessageHandler() && { LDKMessageHandler res = self; memset(&self, 0, sizeof(LDKMessageHandler)); return res; }
	~MessageHandler() { MessageHandler_free(self); }
	MessageHandler& operator=(MessageHandler&& o) { MessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(MessageHandler)); return *this; }
	LDKMessageHandler* operator &() { return &self; }
	LDKMessageHandler* operator ->() { return &self; }
	const LDKMessageHandler* operator &() const { return &self; }
	const LDKMessageHandler* operator ->() const { return &self; }
};
class SocketDescriptor {
private:
	LDKSocketDescriptor self;
public:
	SocketDescriptor(const SocketDescriptor&) = delete;
	SocketDescriptor(SocketDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(SocketDescriptor)); }
	SocketDescriptor(LDKSocketDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSocketDescriptor)); }
	operator LDKSocketDescriptor() && { LDKSocketDescriptor res = self; memset(&self, 0, sizeof(LDKSocketDescriptor)); return res; }
	~SocketDescriptor() { SocketDescriptor_free(self); }
	SocketDescriptor& operator=(SocketDescriptor&& o) { SocketDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(SocketDescriptor)); return *this; }
	LDKSocketDescriptor* operator &() { return &self; }
	LDKSocketDescriptor* operator ->() { return &self; }
	const LDKSocketDescriptor* operator &() const { return &self; }
	const LDKSocketDescriptor* operator ->() const { return &self; }
	/**
	 *  Attempts to send some data from the given slice to the peer.
	 * 
	 *  Returns the amount of data which was sent, possibly 0 if the socket has since disconnected.
	 *  Note that in the disconnected case, [`PeerManager::socket_disconnected`] must still be
	 *  called and further write attempts may occur until that time.
	 * 
	 *  If the returned size is smaller than `data.len()`, a
	 *  [`PeerManager::write_buffer_space_avail`] call must be made the next time more data can be
	 *  written. Additionally, until a `send_data` event completes fully, no further
	 *  [`PeerManager::read_event`] calls should be made for the same peer! Because this is to
	 *  prevent denial-of-service issues, you should not read or buffer any data from the socket
	 *  until then.
	 * 
	 *  If a [`PeerManager::read_event`] call on this descriptor had previously returned true
	 *  (indicating that read events should be paused to prevent DoS in the send buffer),
	 *  `resume_read` may be set indicating that read events on this descriptor should resume. A
	 *  `resume_read` of false carries no meaning, and should not cause any action.
	 */
	inline uintptr_t send_data(struct LDKu8slice data, bool resume_read);
	/**
	 *  Disconnect the socket pointed to by this SocketDescriptor.
	 * 
	 *  You do *not* need to call [`PeerManager::socket_disconnected`] with this socket after this
	 *  call (doing so is a noop).
	 */
	inline void disconnect_socket();
	/** Checks if two objects are equal given this object's this_arg pointer and another object. */
	inline bool eq(const struct LDKSocketDescriptor *NONNULL_PTR other_arg);
	/**
	 * Calculate a succinct non-cryptographic hash for an object given its this_arg pointer.
	 * This is used, for example, for inclusion of this object in a hash map.
	 */
	inline uint64_t hash();
};
class PeerHandleError {
private:
	LDKPeerHandleError self;
public:
	PeerHandleError(const PeerHandleError&) = delete;
	PeerHandleError(PeerHandleError&& o) : self(o.self) { memset(&o, 0, sizeof(PeerHandleError)); }
	PeerHandleError(LDKPeerHandleError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPeerHandleError)); }
	operator LDKPeerHandleError() && { LDKPeerHandleError res = self; memset(&self, 0, sizeof(LDKPeerHandleError)); return res; }
	~PeerHandleError() { PeerHandleError_free(self); }
	PeerHandleError& operator=(PeerHandleError&& o) { PeerHandleError_free(self); self = o.self; memset(&o, 0, sizeof(PeerHandleError)); return *this; }
	LDKPeerHandleError* operator &() { return &self; }
	LDKPeerHandleError* operator ->() { return &self; }
	const LDKPeerHandleError* operator &() const { return &self; }
	const LDKPeerHandleError* operator ->() const { return &self; }
};
class PeerManager {
private:
	LDKPeerManager self;
public:
	PeerManager(const PeerManager&) = delete;
	PeerManager(PeerManager&& o) : self(o.self) { memset(&o, 0, sizeof(PeerManager)); }
	PeerManager(LDKPeerManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPeerManager)); }
	operator LDKPeerManager() && { LDKPeerManager res = self; memset(&self, 0, sizeof(LDKPeerManager)); return res; }
	~PeerManager() { PeerManager_free(self); }
	PeerManager& operator=(PeerManager&& o) { PeerManager_free(self); self = o.self; memset(&o, 0, sizeof(PeerManager)); return *this; }
	LDKPeerManager* operator &() { return &self; }
	LDKPeerManager* operator ->() { return &self; }
	const LDKPeerManager* operator &() const { return &self; }
	const LDKPeerManager* operator ->() const { return &self; }
};
class OnionMessenger {
private:
	LDKOnionMessenger self;
public:
	OnionMessenger(const OnionMessenger&) = delete;
	OnionMessenger(OnionMessenger&& o) : self(o.self) { memset(&o, 0, sizeof(OnionMessenger)); }
	OnionMessenger(LDKOnionMessenger&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOnionMessenger)); }
	operator LDKOnionMessenger() && { LDKOnionMessenger res = self; memset(&self, 0, sizeof(LDKOnionMessenger)); return res; }
	~OnionMessenger() { OnionMessenger_free(self); }
	OnionMessenger& operator=(OnionMessenger&& o) { OnionMessenger_free(self); self = o.self; memset(&o, 0, sizeof(OnionMessenger)); return *this; }
	LDKOnionMessenger* operator &() { return &self; }
	LDKOnionMessenger* operator ->() { return &self; }
	const LDKOnionMessenger* operator &() const { return &self; }
	const LDKOnionMessenger* operator ->() const { return &self; }
};
class Destination {
private:
	LDKDestination self;
public:
	Destination(const Destination&) = delete;
	Destination(Destination&& o) : self(o.self) { memset(&o, 0, sizeof(Destination)); }
	Destination(LDKDestination&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDestination)); }
	operator LDKDestination() && { LDKDestination res = self; memset(&self, 0, sizeof(LDKDestination)); return res; }
	~Destination() { Destination_free(self); }
	Destination& operator=(Destination&& o) { Destination_free(self); self = o.self; memset(&o, 0, sizeof(Destination)); return *this; }
	LDKDestination* operator &() { return &self; }
	LDKDestination* operator ->() { return &self; }
	const LDKDestination* operator &() const { return &self; }
	const LDKDestination* operator ->() const { return &self; }
};
class SendError {
private:
	LDKSendError self;
public:
	SendError(const SendError&) = delete;
	SendError(SendError&& o) : self(o.self) { memset(&o, 0, sizeof(SendError)); }
	SendError(LDKSendError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSendError)); }
	operator LDKSendError() && { LDKSendError res = self; memset(&self, 0, sizeof(LDKSendError)); return res; }
	~SendError() { SendError_free(self); }
	SendError& operator=(SendError&& o) { SendError_free(self); self = o.self; memset(&o, 0, sizeof(SendError)); return *this; }
	LDKSendError* operator &() { return &self; }
	LDKSendError* operator ->() { return &self; }
	const LDKSendError* operator &() const { return &self; }
	const LDKSendError* operator ->() const { return &self; }
};
class RapidGossipSync {
private:
	LDKRapidGossipSync self;
public:
	RapidGossipSync(const RapidGossipSync&) = delete;
	RapidGossipSync(RapidGossipSync&& o) : self(o.self) { memset(&o, 0, sizeof(RapidGossipSync)); }
	RapidGossipSync(LDKRapidGossipSync&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRapidGossipSync)); }
	operator LDKRapidGossipSync() && { LDKRapidGossipSync res = self; memset(&self, 0, sizeof(LDKRapidGossipSync)); return res; }
	~RapidGossipSync() { RapidGossipSync_free(self); }
	RapidGossipSync& operator=(RapidGossipSync&& o) { RapidGossipSync_free(self); self = o.self; memset(&o, 0, sizeof(RapidGossipSync)); return *this; }
	LDKRapidGossipSync* operator &() { return &self; }
	LDKRapidGossipSync* operator ->() { return &self; }
	const LDKRapidGossipSync* operator &() const { return &self; }
	const LDKRapidGossipSync* operator ->() const { return &self; }
};
class Persister {
private:
	LDKPersister self;
public:
	Persister(const Persister&) = delete;
	Persister(Persister&& o) : self(o.self) { memset(&o, 0, sizeof(Persister)); }
	Persister(LDKPersister&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPersister)); }
	operator LDKPersister() && { LDKPersister res = self; memset(&self, 0, sizeof(LDKPersister)); return res; }
	~Persister() { Persister_free(self); }
	Persister& operator=(Persister&& o) { Persister_free(self); self = o.self; memset(&o, 0, sizeof(Persister)); return *this; }
	LDKPersister* operator &() { return &self; }
	LDKPersister* operator ->() { return &self; }
	const LDKPersister* operator &() const { return &self; }
	const LDKPersister* operator ->() const { return &self; }
	/**
	 *  Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	 */
	inline LDK::CResult_NoneErrorZ persist_manager(const struct LDKChannelManager *NONNULL_PTR channel_manager);
	/**
	 *  Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	 */
	inline LDK::CResult_NoneErrorZ persist_graph(const struct LDKNetworkGraph *NONNULL_PTR network_graph);
	/**
	 *  Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	 */
	inline LDK::CResult_NoneErrorZ persist_scorer(const struct LDKWriteableScore *NONNULL_PTR scorer);
};
class DecodeError {
private:
	LDKDecodeError self;
public:
	DecodeError(const DecodeError&) = delete;
	DecodeError(DecodeError&& o) : self(o.self) { memset(&o, 0, sizeof(DecodeError)); }
	DecodeError(LDKDecodeError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDecodeError)); }
	operator LDKDecodeError() && { LDKDecodeError res = self; memset(&self, 0, sizeof(LDKDecodeError)); return res; }
	~DecodeError() { DecodeError_free(self); }
	DecodeError& operator=(DecodeError&& o) { DecodeError_free(self); self = o.self; memset(&o, 0, sizeof(DecodeError)); return *this; }
	LDKDecodeError* operator &() { return &self; }
	LDKDecodeError* operator ->() { return &self; }
	const LDKDecodeError* operator &() const { return &self; }
	const LDKDecodeError* operator ->() const { return &self; }
};
class Init {
private:
	LDKInit self;
public:
	Init(const Init&) = delete;
	Init(Init&& o) : self(o.self) { memset(&o, 0, sizeof(Init)); }
	Init(LDKInit&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInit)); }
	operator LDKInit() && { LDKInit res = self; memset(&self, 0, sizeof(LDKInit)); return res; }
	~Init() { Init_free(self); }
	Init& operator=(Init&& o) { Init_free(self); self = o.self; memset(&o, 0, sizeof(Init)); return *this; }
	LDKInit* operator &() { return &self; }
	LDKInit* operator ->() { return &self; }
	const LDKInit* operator &() const { return &self; }
	const LDKInit* operator ->() const { return &self; }
};
class ErrorMessage {
private:
	LDKErrorMessage self;
public:
	ErrorMessage(const ErrorMessage&) = delete;
	ErrorMessage(ErrorMessage&& o) : self(o.self) { memset(&o, 0, sizeof(ErrorMessage)); }
	ErrorMessage(LDKErrorMessage&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKErrorMessage)); }
	operator LDKErrorMessage() && { LDKErrorMessage res = self; memset(&self, 0, sizeof(LDKErrorMessage)); return res; }
	~ErrorMessage() { ErrorMessage_free(self); }
	ErrorMessage& operator=(ErrorMessage&& o) { ErrorMessage_free(self); self = o.self; memset(&o, 0, sizeof(ErrorMessage)); return *this; }
	LDKErrorMessage* operator &() { return &self; }
	LDKErrorMessage* operator ->() { return &self; }
	const LDKErrorMessage* operator &() const { return &self; }
	const LDKErrorMessage* operator ->() const { return &self; }
};
class WarningMessage {
private:
	LDKWarningMessage self;
public:
	WarningMessage(const WarningMessage&) = delete;
	WarningMessage(WarningMessage&& o) : self(o.self) { memset(&o, 0, sizeof(WarningMessage)); }
	WarningMessage(LDKWarningMessage&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKWarningMessage)); }
	operator LDKWarningMessage() && { LDKWarningMessage res = self; memset(&self, 0, sizeof(LDKWarningMessage)); return res; }
	~WarningMessage() { WarningMessage_free(self); }
	WarningMessage& operator=(WarningMessage&& o) { WarningMessage_free(self); self = o.self; memset(&o, 0, sizeof(WarningMessage)); return *this; }
	LDKWarningMessage* operator &() { return &self; }
	LDKWarningMessage* operator ->() { return &self; }
	const LDKWarningMessage* operator &() const { return &self; }
	const LDKWarningMessage* operator ->() const { return &self; }
};
class Ping {
private:
	LDKPing self;
public:
	Ping(const Ping&) = delete;
	Ping(Ping&& o) : self(o.self) { memset(&o, 0, sizeof(Ping)); }
	Ping(LDKPing&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPing)); }
	operator LDKPing() && { LDKPing res = self; memset(&self, 0, sizeof(LDKPing)); return res; }
	~Ping() { Ping_free(self); }
	Ping& operator=(Ping&& o) { Ping_free(self); self = o.self; memset(&o, 0, sizeof(Ping)); return *this; }
	LDKPing* operator &() { return &self; }
	LDKPing* operator ->() { return &self; }
	const LDKPing* operator &() const { return &self; }
	const LDKPing* operator ->() const { return &self; }
};
class Pong {
private:
	LDKPong self;
public:
	Pong(const Pong&) = delete;
	Pong(Pong&& o) : self(o.self) { memset(&o, 0, sizeof(Pong)); }
	Pong(LDKPong&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPong)); }
	operator LDKPong() && { LDKPong res = self; memset(&self, 0, sizeof(LDKPong)); return res; }
	~Pong() { Pong_free(self); }
	Pong& operator=(Pong&& o) { Pong_free(self); self = o.self; memset(&o, 0, sizeof(Pong)); return *this; }
	LDKPong* operator &() { return &self; }
	LDKPong* operator ->() { return &self; }
	const LDKPong* operator &() const { return &self; }
	const LDKPong* operator ->() const { return &self; }
};
class OpenChannel {
private:
	LDKOpenChannel self;
public:
	OpenChannel(const OpenChannel&) = delete;
	OpenChannel(OpenChannel&& o) : self(o.self) { memset(&o, 0, sizeof(OpenChannel)); }
	OpenChannel(LDKOpenChannel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOpenChannel)); }
	operator LDKOpenChannel() && { LDKOpenChannel res = self; memset(&self, 0, sizeof(LDKOpenChannel)); return res; }
	~OpenChannel() { OpenChannel_free(self); }
	OpenChannel& operator=(OpenChannel&& o) { OpenChannel_free(self); self = o.self; memset(&o, 0, sizeof(OpenChannel)); return *this; }
	LDKOpenChannel* operator &() { return &self; }
	LDKOpenChannel* operator ->() { return &self; }
	const LDKOpenChannel* operator &() const { return &self; }
	const LDKOpenChannel* operator ->() const { return &self; }
};
class AcceptChannel {
private:
	LDKAcceptChannel self;
public:
	AcceptChannel(const AcceptChannel&) = delete;
	AcceptChannel(AcceptChannel&& o) : self(o.self) { memset(&o, 0, sizeof(AcceptChannel)); }
	AcceptChannel(LDKAcceptChannel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAcceptChannel)); }
	operator LDKAcceptChannel() && { LDKAcceptChannel res = self; memset(&self, 0, sizeof(LDKAcceptChannel)); return res; }
	~AcceptChannel() { AcceptChannel_free(self); }
	AcceptChannel& operator=(AcceptChannel&& o) { AcceptChannel_free(self); self = o.self; memset(&o, 0, sizeof(AcceptChannel)); return *this; }
	LDKAcceptChannel* operator &() { return &self; }
	LDKAcceptChannel* operator ->() { return &self; }
	const LDKAcceptChannel* operator &() const { return &self; }
	const LDKAcceptChannel* operator ->() const { return &self; }
};
class FundingCreated {
private:
	LDKFundingCreated self;
public:
	FundingCreated(const FundingCreated&) = delete;
	FundingCreated(FundingCreated&& o) : self(o.self) { memset(&o, 0, sizeof(FundingCreated)); }
	FundingCreated(LDKFundingCreated&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFundingCreated)); }
	operator LDKFundingCreated() && { LDKFundingCreated res = self; memset(&self, 0, sizeof(LDKFundingCreated)); return res; }
	~FundingCreated() { FundingCreated_free(self); }
	FundingCreated& operator=(FundingCreated&& o) { FundingCreated_free(self); self = o.self; memset(&o, 0, sizeof(FundingCreated)); return *this; }
	LDKFundingCreated* operator &() { return &self; }
	LDKFundingCreated* operator ->() { return &self; }
	const LDKFundingCreated* operator &() const { return &self; }
	const LDKFundingCreated* operator ->() const { return &self; }
};
class FundingSigned {
private:
	LDKFundingSigned self;
public:
	FundingSigned(const FundingSigned&) = delete;
	FundingSigned(FundingSigned&& o) : self(o.self) { memset(&o, 0, sizeof(FundingSigned)); }
	FundingSigned(LDKFundingSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFundingSigned)); }
	operator LDKFundingSigned() && { LDKFundingSigned res = self; memset(&self, 0, sizeof(LDKFundingSigned)); return res; }
	~FundingSigned() { FundingSigned_free(self); }
	FundingSigned& operator=(FundingSigned&& o) { FundingSigned_free(self); self = o.self; memset(&o, 0, sizeof(FundingSigned)); return *this; }
	LDKFundingSigned* operator &() { return &self; }
	LDKFundingSigned* operator ->() { return &self; }
	const LDKFundingSigned* operator &() const { return &self; }
	const LDKFundingSigned* operator ->() const { return &self; }
};
class ChannelReady {
private:
	LDKChannelReady self;
public:
	ChannelReady(const ChannelReady&) = delete;
	ChannelReady(ChannelReady&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelReady)); }
	ChannelReady(LDKChannelReady&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelReady)); }
	operator LDKChannelReady() && { LDKChannelReady res = self; memset(&self, 0, sizeof(LDKChannelReady)); return res; }
	~ChannelReady() { ChannelReady_free(self); }
	ChannelReady& operator=(ChannelReady&& o) { ChannelReady_free(self); self = o.self; memset(&o, 0, sizeof(ChannelReady)); return *this; }
	LDKChannelReady* operator &() { return &self; }
	LDKChannelReady* operator ->() { return &self; }
	const LDKChannelReady* operator &() const { return &self; }
	const LDKChannelReady* operator ->() const { return &self; }
};
class Shutdown {
private:
	LDKShutdown self;
public:
	Shutdown(const Shutdown&) = delete;
	Shutdown(Shutdown&& o) : self(o.self) { memset(&o, 0, sizeof(Shutdown)); }
	Shutdown(LDKShutdown&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKShutdown)); }
	operator LDKShutdown() && { LDKShutdown res = self; memset(&self, 0, sizeof(LDKShutdown)); return res; }
	~Shutdown() { Shutdown_free(self); }
	Shutdown& operator=(Shutdown&& o) { Shutdown_free(self); self = o.self; memset(&o, 0, sizeof(Shutdown)); return *this; }
	LDKShutdown* operator &() { return &self; }
	LDKShutdown* operator ->() { return &self; }
	const LDKShutdown* operator &() const { return &self; }
	const LDKShutdown* operator ->() const { return &self; }
};
class ClosingSignedFeeRange {
private:
	LDKClosingSignedFeeRange self;
public:
	ClosingSignedFeeRange(const ClosingSignedFeeRange&) = delete;
	ClosingSignedFeeRange(ClosingSignedFeeRange&& o) : self(o.self) { memset(&o, 0, sizeof(ClosingSignedFeeRange)); }
	ClosingSignedFeeRange(LDKClosingSignedFeeRange&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKClosingSignedFeeRange)); }
	operator LDKClosingSignedFeeRange() && { LDKClosingSignedFeeRange res = self; memset(&self, 0, sizeof(LDKClosingSignedFeeRange)); return res; }
	~ClosingSignedFeeRange() { ClosingSignedFeeRange_free(self); }
	ClosingSignedFeeRange& operator=(ClosingSignedFeeRange&& o) { ClosingSignedFeeRange_free(self); self = o.self; memset(&o, 0, sizeof(ClosingSignedFeeRange)); return *this; }
	LDKClosingSignedFeeRange* operator &() { return &self; }
	LDKClosingSignedFeeRange* operator ->() { return &self; }
	const LDKClosingSignedFeeRange* operator &() const { return &self; }
	const LDKClosingSignedFeeRange* operator ->() const { return &self; }
};
class ClosingSigned {
private:
	LDKClosingSigned self;
public:
	ClosingSigned(const ClosingSigned&) = delete;
	ClosingSigned(ClosingSigned&& o) : self(o.self) { memset(&o, 0, sizeof(ClosingSigned)); }
	ClosingSigned(LDKClosingSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKClosingSigned)); }
	operator LDKClosingSigned() && { LDKClosingSigned res = self; memset(&self, 0, sizeof(LDKClosingSigned)); return res; }
	~ClosingSigned() { ClosingSigned_free(self); }
	ClosingSigned& operator=(ClosingSigned&& o) { ClosingSigned_free(self); self = o.self; memset(&o, 0, sizeof(ClosingSigned)); return *this; }
	LDKClosingSigned* operator &() { return &self; }
	LDKClosingSigned* operator ->() { return &self; }
	const LDKClosingSigned* operator &() const { return &self; }
	const LDKClosingSigned* operator ->() const { return &self; }
};
class UpdateAddHTLC {
private:
	LDKUpdateAddHTLC self;
public:
	UpdateAddHTLC(const UpdateAddHTLC&) = delete;
	UpdateAddHTLC(UpdateAddHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateAddHTLC)); }
	UpdateAddHTLC(LDKUpdateAddHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateAddHTLC)); }
	operator LDKUpdateAddHTLC() && { LDKUpdateAddHTLC res = self; memset(&self, 0, sizeof(LDKUpdateAddHTLC)); return res; }
	~UpdateAddHTLC() { UpdateAddHTLC_free(self); }
	UpdateAddHTLC& operator=(UpdateAddHTLC&& o) { UpdateAddHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateAddHTLC)); return *this; }
	LDKUpdateAddHTLC* operator &() { return &self; }
	LDKUpdateAddHTLC* operator ->() { return &self; }
	const LDKUpdateAddHTLC* operator &() const { return &self; }
	const LDKUpdateAddHTLC* operator ->() const { return &self; }
};
class OnionMessage {
private:
	LDKOnionMessage self;
public:
	OnionMessage(const OnionMessage&) = delete;
	OnionMessage(OnionMessage&& o) : self(o.self) { memset(&o, 0, sizeof(OnionMessage)); }
	OnionMessage(LDKOnionMessage&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOnionMessage)); }
	operator LDKOnionMessage() && { LDKOnionMessage res = self; memset(&self, 0, sizeof(LDKOnionMessage)); return res; }
	~OnionMessage() { OnionMessage_free(self); }
	OnionMessage& operator=(OnionMessage&& o) { OnionMessage_free(self); self = o.self; memset(&o, 0, sizeof(OnionMessage)); return *this; }
	LDKOnionMessage* operator &() { return &self; }
	LDKOnionMessage* operator ->() { return &self; }
	const LDKOnionMessage* operator &() const { return &self; }
	const LDKOnionMessage* operator ->() const { return &self; }
};
class UpdateFulfillHTLC {
private:
	LDKUpdateFulfillHTLC self;
public:
	UpdateFulfillHTLC(const UpdateFulfillHTLC&) = delete;
	UpdateFulfillHTLC(UpdateFulfillHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFulfillHTLC)); }
	UpdateFulfillHTLC(LDKUpdateFulfillHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFulfillHTLC)); }
	operator LDKUpdateFulfillHTLC() && { LDKUpdateFulfillHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFulfillHTLC)); return res; }
	~UpdateFulfillHTLC() { UpdateFulfillHTLC_free(self); }
	UpdateFulfillHTLC& operator=(UpdateFulfillHTLC&& o) { UpdateFulfillHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFulfillHTLC)); return *this; }
	LDKUpdateFulfillHTLC* operator &() { return &self; }
	LDKUpdateFulfillHTLC* operator ->() { return &self; }
	const LDKUpdateFulfillHTLC* operator &() const { return &self; }
	const LDKUpdateFulfillHTLC* operator ->() const { return &self; }
};
class UpdateFailHTLC {
private:
	LDKUpdateFailHTLC self;
public:
	UpdateFailHTLC(const UpdateFailHTLC&) = delete;
	UpdateFailHTLC(UpdateFailHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFailHTLC)); }
	UpdateFailHTLC(LDKUpdateFailHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFailHTLC)); }
	operator LDKUpdateFailHTLC() && { LDKUpdateFailHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFailHTLC)); return res; }
	~UpdateFailHTLC() { UpdateFailHTLC_free(self); }
	UpdateFailHTLC& operator=(UpdateFailHTLC&& o) { UpdateFailHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFailHTLC)); return *this; }
	LDKUpdateFailHTLC* operator &() { return &self; }
	LDKUpdateFailHTLC* operator ->() { return &self; }
	const LDKUpdateFailHTLC* operator &() const { return &self; }
	const LDKUpdateFailHTLC* operator ->() const { return &self; }
};
class UpdateFailMalformedHTLC {
private:
	LDKUpdateFailMalformedHTLC self;
public:
	UpdateFailMalformedHTLC(const UpdateFailMalformedHTLC&) = delete;
	UpdateFailMalformedHTLC(UpdateFailMalformedHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFailMalformedHTLC)); }
	UpdateFailMalformedHTLC(LDKUpdateFailMalformedHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFailMalformedHTLC)); }
	operator LDKUpdateFailMalformedHTLC() && { LDKUpdateFailMalformedHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFailMalformedHTLC)); return res; }
	~UpdateFailMalformedHTLC() { UpdateFailMalformedHTLC_free(self); }
	UpdateFailMalformedHTLC& operator=(UpdateFailMalformedHTLC&& o) { UpdateFailMalformedHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFailMalformedHTLC)); return *this; }
	LDKUpdateFailMalformedHTLC* operator &() { return &self; }
	LDKUpdateFailMalformedHTLC* operator ->() { return &self; }
	const LDKUpdateFailMalformedHTLC* operator &() const { return &self; }
	const LDKUpdateFailMalformedHTLC* operator ->() const { return &self; }
};
class CommitmentSigned {
private:
	LDKCommitmentSigned self;
public:
	CommitmentSigned(const CommitmentSigned&) = delete;
	CommitmentSigned(CommitmentSigned&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentSigned)); }
	CommitmentSigned(LDKCommitmentSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentSigned)); }
	operator LDKCommitmentSigned() && { LDKCommitmentSigned res = self; memset(&self, 0, sizeof(LDKCommitmentSigned)); return res; }
	~CommitmentSigned() { CommitmentSigned_free(self); }
	CommitmentSigned& operator=(CommitmentSigned&& o) { CommitmentSigned_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentSigned)); return *this; }
	LDKCommitmentSigned* operator &() { return &self; }
	LDKCommitmentSigned* operator ->() { return &self; }
	const LDKCommitmentSigned* operator &() const { return &self; }
	const LDKCommitmentSigned* operator ->() const { return &self; }
};
class RevokeAndACK {
private:
	LDKRevokeAndACK self;
public:
	RevokeAndACK(const RevokeAndACK&) = delete;
	RevokeAndACK(RevokeAndACK&& o) : self(o.self) { memset(&o, 0, sizeof(RevokeAndACK)); }
	RevokeAndACK(LDKRevokeAndACK&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRevokeAndACK)); }
	operator LDKRevokeAndACK() && { LDKRevokeAndACK res = self; memset(&self, 0, sizeof(LDKRevokeAndACK)); return res; }
	~RevokeAndACK() { RevokeAndACK_free(self); }
	RevokeAndACK& operator=(RevokeAndACK&& o) { RevokeAndACK_free(self); self = o.self; memset(&o, 0, sizeof(RevokeAndACK)); return *this; }
	LDKRevokeAndACK* operator &() { return &self; }
	LDKRevokeAndACK* operator ->() { return &self; }
	const LDKRevokeAndACK* operator &() const { return &self; }
	const LDKRevokeAndACK* operator ->() const { return &self; }
};
class UpdateFee {
private:
	LDKUpdateFee self;
public:
	UpdateFee(const UpdateFee&) = delete;
	UpdateFee(UpdateFee&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFee)); }
	UpdateFee(LDKUpdateFee&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFee)); }
	operator LDKUpdateFee() && { LDKUpdateFee res = self; memset(&self, 0, sizeof(LDKUpdateFee)); return res; }
	~UpdateFee() { UpdateFee_free(self); }
	UpdateFee& operator=(UpdateFee&& o) { UpdateFee_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFee)); return *this; }
	LDKUpdateFee* operator &() { return &self; }
	LDKUpdateFee* operator ->() { return &self; }
	const LDKUpdateFee* operator &() const { return &self; }
	const LDKUpdateFee* operator ->() const { return &self; }
};
class DataLossProtect {
private:
	LDKDataLossProtect self;
public:
	DataLossProtect(const DataLossProtect&) = delete;
	DataLossProtect(DataLossProtect&& o) : self(o.self) { memset(&o, 0, sizeof(DataLossProtect)); }
	DataLossProtect(LDKDataLossProtect&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDataLossProtect)); }
	operator LDKDataLossProtect() && { LDKDataLossProtect res = self; memset(&self, 0, sizeof(LDKDataLossProtect)); return res; }
	~DataLossProtect() { DataLossProtect_free(self); }
	DataLossProtect& operator=(DataLossProtect&& o) { DataLossProtect_free(self); self = o.self; memset(&o, 0, sizeof(DataLossProtect)); return *this; }
	LDKDataLossProtect* operator &() { return &self; }
	LDKDataLossProtect* operator ->() { return &self; }
	const LDKDataLossProtect* operator &() const { return &self; }
	const LDKDataLossProtect* operator ->() const { return &self; }
};
class ChannelReestablish {
private:
	LDKChannelReestablish self;
public:
	ChannelReestablish(const ChannelReestablish&) = delete;
	ChannelReestablish(ChannelReestablish&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelReestablish)); }
	ChannelReestablish(LDKChannelReestablish&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelReestablish)); }
	operator LDKChannelReestablish() && { LDKChannelReestablish res = self; memset(&self, 0, sizeof(LDKChannelReestablish)); return res; }
	~ChannelReestablish() { ChannelReestablish_free(self); }
	ChannelReestablish& operator=(ChannelReestablish&& o) { ChannelReestablish_free(self); self = o.self; memset(&o, 0, sizeof(ChannelReestablish)); return *this; }
	LDKChannelReestablish* operator &() { return &self; }
	LDKChannelReestablish* operator ->() { return &self; }
	const LDKChannelReestablish* operator &() const { return &self; }
	const LDKChannelReestablish* operator ->() const { return &self; }
};
class AnnouncementSignatures {
private:
	LDKAnnouncementSignatures self;
public:
	AnnouncementSignatures(const AnnouncementSignatures&) = delete;
	AnnouncementSignatures(AnnouncementSignatures&& o) : self(o.self) { memset(&o, 0, sizeof(AnnouncementSignatures)); }
	AnnouncementSignatures(LDKAnnouncementSignatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAnnouncementSignatures)); }
	operator LDKAnnouncementSignatures() && { LDKAnnouncementSignatures res = self; memset(&self, 0, sizeof(LDKAnnouncementSignatures)); return res; }
	~AnnouncementSignatures() { AnnouncementSignatures_free(self); }
	AnnouncementSignatures& operator=(AnnouncementSignatures&& o) { AnnouncementSignatures_free(self); self = o.self; memset(&o, 0, sizeof(AnnouncementSignatures)); return *this; }
	LDKAnnouncementSignatures* operator &() { return &self; }
	LDKAnnouncementSignatures* operator ->() { return &self; }
	const LDKAnnouncementSignatures* operator &() const { return &self; }
	const LDKAnnouncementSignatures* operator ->() const { return &self; }
};
class NetAddress {
private:
	LDKNetAddress self;
public:
	NetAddress(const NetAddress&) = delete;
	NetAddress(NetAddress&& o) : self(o.self) { memset(&o, 0, sizeof(NetAddress)); }
	NetAddress(LDKNetAddress&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetAddress)); }
	operator LDKNetAddress() && { LDKNetAddress res = self; memset(&self, 0, sizeof(LDKNetAddress)); return res; }
	~NetAddress() { NetAddress_free(self); }
	NetAddress& operator=(NetAddress&& o) { NetAddress_free(self); self = o.self; memset(&o, 0, sizeof(NetAddress)); return *this; }
	LDKNetAddress* operator &() { return &self; }
	LDKNetAddress* operator ->() { return &self; }
	const LDKNetAddress* operator &() const { return &self; }
	const LDKNetAddress* operator ->() const { return &self; }
};
class UnsignedNodeAnnouncement {
private:
	LDKUnsignedNodeAnnouncement self;
public:
	UnsignedNodeAnnouncement(const UnsignedNodeAnnouncement&) = delete;
	UnsignedNodeAnnouncement(UnsignedNodeAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedNodeAnnouncement)); }
	UnsignedNodeAnnouncement(LDKUnsignedNodeAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedNodeAnnouncement)); }
	operator LDKUnsignedNodeAnnouncement() && { LDKUnsignedNodeAnnouncement res = self; memset(&self, 0, sizeof(LDKUnsignedNodeAnnouncement)); return res; }
	~UnsignedNodeAnnouncement() { UnsignedNodeAnnouncement_free(self); }
	UnsignedNodeAnnouncement& operator=(UnsignedNodeAnnouncement&& o) { UnsignedNodeAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedNodeAnnouncement)); return *this; }
	LDKUnsignedNodeAnnouncement* operator &() { return &self; }
	LDKUnsignedNodeAnnouncement* operator ->() { return &self; }
	const LDKUnsignedNodeAnnouncement* operator &() const { return &self; }
	const LDKUnsignedNodeAnnouncement* operator ->() const { return &self; }
};
class NodeAnnouncement {
private:
	LDKNodeAnnouncement self;
public:
	NodeAnnouncement(const NodeAnnouncement&) = delete;
	NodeAnnouncement(NodeAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(NodeAnnouncement)); }
	NodeAnnouncement(LDKNodeAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeAnnouncement)); }
	operator LDKNodeAnnouncement() && { LDKNodeAnnouncement res = self; memset(&self, 0, sizeof(LDKNodeAnnouncement)); return res; }
	~NodeAnnouncement() { NodeAnnouncement_free(self); }
	NodeAnnouncement& operator=(NodeAnnouncement&& o) { NodeAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(NodeAnnouncement)); return *this; }
	LDKNodeAnnouncement* operator &() { return &self; }
	LDKNodeAnnouncement* operator ->() { return &self; }
	const LDKNodeAnnouncement* operator &() const { return &self; }
	const LDKNodeAnnouncement* operator ->() const { return &self; }
};
class UnsignedChannelAnnouncement {
private:
	LDKUnsignedChannelAnnouncement self;
public:
	UnsignedChannelAnnouncement(const UnsignedChannelAnnouncement&) = delete;
	UnsignedChannelAnnouncement(UnsignedChannelAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedChannelAnnouncement)); }
	UnsignedChannelAnnouncement(LDKUnsignedChannelAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedChannelAnnouncement)); }
	operator LDKUnsignedChannelAnnouncement() && { LDKUnsignedChannelAnnouncement res = self; memset(&self, 0, sizeof(LDKUnsignedChannelAnnouncement)); return res; }
	~UnsignedChannelAnnouncement() { UnsignedChannelAnnouncement_free(self); }
	UnsignedChannelAnnouncement& operator=(UnsignedChannelAnnouncement&& o) { UnsignedChannelAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedChannelAnnouncement)); return *this; }
	LDKUnsignedChannelAnnouncement* operator &() { return &self; }
	LDKUnsignedChannelAnnouncement* operator ->() { return &self; }
	const LDKUnsignedChannelAnnouncement* operator &() const { return &self; }
	const LDKUnsignedChannelAnnouncement* operator ->() const { return &self; }
};
class ChannelAnnouncement {
private:
	LDKChannelAnnouncement self;
public:
	ChannelAnnouncement(const ChannelAnnouncement&) = delete;
	ChannelAnnouncement(ChannelAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelAnnouncement)); }
	ChannelAnnouncement(LDKChannelAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelAnnouncement)); }
	operator LDKChannelAnnouncement() && { LDKChannelAnnouncement res = self; memset(&self, 0, sizeof(LDKChannelAnnouncement)); return res; }
	~ChannelAnnouncement() { ChannelAnnouncement_free(self); }
	ChannelAnnouncement& operator=(ChannelAnnouncement&& o) { ChannelAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(ChannelAnnouncement)); return *this; }
	LDKChannelAnnouncement* operator &() { return &self; }
	LDKChannelAnnouncement* operator ->() { return &self; }
	const LDKChannelAnnouncement* operator &() const { return &self; }
	const LDKChannelAnnouncement* operator ->() const { return &self; }
};
class UnsignedChannelUpdate {
private:
	LDKUnsignedChannelUpdate self;
public:
	UnsignedChannelUpdate(const UnsignedChannelUpdate&) = delete;
	UnsignedChannelUpdate(UnsignedChannelUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedChannelUpdate)); }
	UnsignedChannelUpdate(LDKUnsignedChannelUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedChannelUpdate)); }
	operator LDKUnsignedChannelUpdate() && { LDKUnsignedChannelUpdate res = self; memset(&self, 0, sizeof(LDKUnsignedChannelUpdate)); return res; }
	~UnsignedChannelUpdate() { UnsignedChannelUpdate_free(self); }
	UnsignedChannelUpdate& operator=(UnsignedChannelUpdate&& o) { UnsignedChannelUpdate_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedChannelUpdate)); return *this; }
	LDKUnsignedChannelUpdate* operator &() { return &self; }
	LDKUnsignedChannelUpdate* operator ->() { return &self; }
	const LDKUnsignedChannelUpdate* operator &() const { return &self; }
	const LDKUnsignedChannelUpdate* operator ->() const { return &self; }
};
class ChannelUpdate {
private:
	LDKChannelUpdate self;
public:
	ChannelUpdate(const ChannelUpdate&) = delete;
	ChannelUpdate(ChannelUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelUpdate)); }
	ChannelUpdate(LDKChannelUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelUpdate)); }
	operator LDKChannelUpdate() && { LDKChannelUpdate res = self; memset(&self, 0, sizeof(LDKChannelUpdate)); return res; }
	~ChannelUpdate() { ChannelUpdate_free(self); }
	ChannelUpdate& operator=(ChannelUpdate&& o) { ChannelUpdate_free(self); self = o.self; memset(&o, 0, sizeof(ChannelUpdate)); return *this; }
	LDKChannelUpdate* operator &() { return &self; }
	LDKChannelUpdate* operator ->() { return &self; }
	const LDKChannelUpdate* operator &() const { return &self; }
	const LDKChannelUpdate* operator ->() const { return &self; }
};
class QueryChannelRange {
private:
	LDKQueryChannelRange self;
public:
	QueryChannelRange(const QueryChannelRange&) = delete;
	QueryChannelRange(QueryChannelRange&& o) : self(o.self) { memset(&o, 0, sizeof(QueryChannelRange)); }
	QueryChannelRange(LDKQueryChannelRange&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKQueryChannelRange)); }
	operator LDKQueryChannelRange() && { LDKQueryChannelRange res = self; memset(&self, 0, sizeof(LDKQueryChannelRange)); return res; }
	~QueryChannelRange() { QueryChannelRange_free(self); }
	QueryChannelRange& operator=(QueryChannelRange&& o) { QueryChannelRange_free(self); self = o.self; memset(&o, 0, sizeof(QueryChannelRange)); return *this; }
	LDKQueryChannelRange* operator &() { return &self; }
	LDKQueryChannelRange* operator ->() { return &self; }
	const LDKQueryChannelRange* operator &() const { return &self; }
	const LDKQueryChannelRange* operator ->() const { return &self; }
};
class ReplyChannelRange {
private:
	LDKReplyChannelRange self;
public:
	ReplyChannelRange(const ReplyChannelRange&) = delete;
	ReplyChannelRange(ReplyChannelRange&& o) : self(o.self) { memset(&o, 0, sizeof(ReplyChannelRange)); }
	ReplyChannelRange(LDKReplyChannelRange&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKReplyChannelRange)); }
	operator LDKReplyChannelRange() && { LDKReplyChannelRange res = self; memset(&self, 0, sizeof(LDKReplyChannelRange)); return res; }
	~ReplyChannelRange() { ReplyChannelRange_free(self); }
	ReplyChannelRange& operator=(ReplyChannelRange&& o) { ReplyChannelRange_free(self); self = o.self; memset(&o, 0, sizeof(ReplyChannelRange)); return *this; }
	LDKReplyChannelRange* operator &() { return &self; }
	LDKReplyChannelRange* operator ->() { return &self; }
	const LDKReplyChannelRange* operator &() const { return &self; }
	const LDKReplyChannelRange* operator ->() const { return &self; }
};
class QueryShortChannelIds {
private:
	LDKQueryShortChannelIds self;
public:
	QueryShortChannelIds(const QueryShortChannelIds&) = delete;
	QueryShortChannelIds(QueryShortChannelIds&& o) : self(o.self) { memset(&o, 0, sizeof(QueryShortChannelIds)); }
	QueryShortChannelIds(LDKQueryShortChannelIds&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKQueryShortChannelIds)); }
	operator LDKQueryShortChannelIds() && { LDKQueryShortChannelIds res = self; memset(&self, 0, sizeof(LDKQueryShortChannelIds)); return res; }
	~QueryShortChannelIds() { QueryShortChannelIds_free(self); }
	QueryShortChannelIds& operator=(QueryShortChannelIds&& o) { QueryShortChannelIds_free(self); self = o.self; memset(&o, 0, sizeof(QueryShortChannelIds)); return *this; }
	LDKQueryShortChannelIds* operator &() { return &self; }
	LDKQueryShortChannelIds* operator ->() { return &self; }
	const LDKQueryShortChannelIds* operator &() const { return &self; }
	const LDKQueryShortChannelIds* operator ->() const { return &self; }
};
class ReplyShortChannelIdsEnd {
private:
	LDKReplyShortChannelIdsEnd self;
public:
	ReplyShortChannelIdsEnd(const ReplyShortChannelIdsEnd&) = delete;
	ReplyShortChannelIdsEnd(ReplyShortChannelIdsEnd&& o) : self(o.self) { memset(&o, 0, sizeof(ReplyShortChannelIdsEnd)); }
	ReplyShortChannelIdsEnd(LDKReplyShortChannelIdsEnd&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKReplyShortChannelIdsEnd)); }
	operator LDKReplyShortChannelIdsEnd() && { LDKReplyShortChannelIdsEnd res = self; memset(&self, 0, sizeof(LDKReplyShortChannelIdsEnd)); return res; }
	~ReplyShortChannelIdsEnd() { ReplyShortChannelIdsEnd_free(self); }
	ReplyShortChannelIdsEnd& operator=(ReplyShortChannelIdsEnd&& o) { ReplyShortChannelIdsEnd_free(self); self = o.self; memset(&o, 0, sizeof(ReplyShortChannelIdsEnd)); return *this; }
	LDKReplyShortChannelIdsEnd* operator &() { return &self; }
	LDKReplyShortChannelIdsEnd* operator ->() { return &self; }
	const LDKReplyShortChannelIdsEnd* operator &() const { return &self; }
	const LDKReplyShortChannelIdsEnd* operator ->() const { return &self; }
};
class GossipTimestampFilter {
private:
	LDKGossipTimestampFilter self;
public:
	GossipTimestampFilter(const GossipTimestampFilter&) = delete;
	GossipTimestampFilter(GossipTimestampFilter&& o) : self(o.self) { memset(&o, 0, sizeof(GossipTimestampFilter)); }
	GossipTimestampFilter(LDKGossipTimestampFilter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKGossipTimestampFilter)); }
	operator LDKGossipTimestampFilter() && { LDKGossipTimestampFilter res = self; memset(&self, 0, sizeof(LDKGossipTimestampFilter)); return res; }
	~GossipTimestampFilter() { GossipTimestampFilter_free(self); }
	GossipTimestampFilter& operator=(GossipTimestampFilter&& o) { GossipTimestampFilter_free(self); self = o.self; memset(&o, 0, sizeof(GossipTimestampFilter)); return *this; }
	LDKGossipTimestampFilter* operator &() { return &self; }
	LDKGossipTimestampFilter* operator ->() { return &self; }
	const LDKGossipTimestampFilter* operator &() const { return &self; }
	const LDKGossipTimestampFilter* operator ->() const { return &self; }
};
class ErrorAction {
private:
	LDKErrorAction self;
public:
	ErrorAction(const ErrorAction&) = delete;
	ErrorAction(ErrorAction&& o) : self(o.self) { memset(&o, 0, sizeof(ErrorAction)); }
	ErrorAction(LDKErrorAction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKErrorAction)); }
	operator LDKErrorAction() && { LDKErrorAction res = self; memset(&self, 0, sizeof(LDKErrorAction)); return res; }
	~ErrorAction() { ErrorAction_free(self); }
	ErrorAction& operator=(ErrorAction&& o) { ErrorAction_free(self); self = o.self; memset(&o, 0, sizeof(ErrorAction)); return *this; }
	LDKErrorAction* operator &() { return &self; }
	LDKErrorAction* operator ->() { return &self; }
	const LDKErrorAction* operator &() const { return &self; }
	const LDKErrorAction* operator ->() const { return &self; }
};
class LightningError {
private:
	LDKLightningError self;
public:
	LightningError(const LightningError&) = delete;
	LightningError(LightningError&& o) : self(o.self) { memset(&o, 0, sizeof(LightningError)); }
	LightningError(LDKLightningError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLightningError)); }
	operator LDKLightningError() && { LDKLightningError res = self; memset(&self, 0, sizeof(LDKLightningError)); return res; }
	~LightningError() { LightningError_free(self); }
	LightningError& operator=(LightningError&& o) { LightningError_free(self); self = o.self; memset(&o, 0, sizeof(LightningError)); return *this; }
	LDKLightningError* operator &() { return &self; }
	LDKLightningError* operator ->() { return &self; }
	const LDKLightningError* operator &() const { return &self; }
	const LDKLightningError* operator ->() const { return &self; }
};
class CommitmentUpdate {
private:
	LDKCommitmentUpdate self;
public:
	CommitmentUpdate(const CommitmentUpdate&) = delete;
	CommitmentUpdate(CommitmentUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentUpdate)); }
	CommitmentUpdate(LDKCommitmentUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentUpdate)); }
	operator LDKCommitmentUpdate() && { LDKCommitmentUpdate res = self; memset(&self, 0, sizeof(LDKCommitmentUpdate)); return res; }
	~CommitmentUpdate() { CommitmentUpdate_free(self); }
	CommitmentUpdate& operator=(CommitmentUpdate&& o) { CommitmentUpdate_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentUpdate)); return *this; }
	LDKCommitmentUpdate* operator &() { return &self; }
	LDKCommitmentUpdate* operator ->() { return &self; }
	const LDKCommitmentUpdate* operator &() const { return &self; }
	const LDKCommitmentUpdate* operator ->() const { return &self; }
};
class ChannelMessageHandler {
private:
	LDKChannelMessageHandler self;
public:
	ChannelMessageHandler(const ChannelMessageHandler&) = delete;
	ChannelMessageHandler(ChannelMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMessageHandler)); }
	ChannelMessageHandler(LDKChannelMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMessageHandler)); }
	operator LDKChannelMessageHandler() && { LDKChannelMessageHandler res = self; memset(&self, 0, sizeof(LDKChannelMessageHandler)); return res; }
	~ChannelMessageHandler() { ChannelMessageHandler_free(self); }
	ChannelMessageHandler& operator=(ChannelMessageHandler&& o) { ChannelMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMessageHandler)); return *this; }
	LDKChannelMessageHandler* operator &() { return &self; }
	LDKChannelMessageHandler* operator ->() { return &self; }
	const LDKChannelMessageHandler* operator &() const { return &self; }
	const LDKChannelMessageHandler* operator ->() const { return &self; }
	/**
	 *  Handle an incoming open_channel message from the given peer.
	 */
	inline void handle_open_channel(struct LDKPublicKey their_node_id, struct LDKInitFeatures their_features, const struct LDKOpenChannel *NONNULL_PTR msg);
	/**
	 *  Handle an incoming accept_channel message from the given peer.
	 */
	inline void handle_accept_channel(struct LDKPublicKey their_node_id, struct LDKInitFeatures their_features, const struct LDKAcceptChannel *NONNULL_PTR msg);
	/**
	 *  Handle an incoming funding_created message from the given peer.
	 */
	inline void handle_funding_created(struct LDKPublicKey their_node_id, const struct LDKFundingCreated *NONNULL_PTR msg);
	/**
	 *  Handle an incoming funding_signed message from the given peer.
	 */
	inline void handle_funding_signed(struct LDKPublicKey their_node_id, const struct LDKFundingSigned *NONNULL_PTR msg);
	/**
	 *  Handle an incoming channel_ready message from the given peer.
	 */
	inline void handle_channel_ready(struct LDKPublicKey their_node_id, const struct LDKChannelReady *NONNULL_PTR msg);
	/**
	 *  Handle an incoming shutdown message from the given peer.
	 */
	inline void handle_shutdown(struct LDKPublicKey their_node_id, const struct LDKInitFeatures *NONNULL_PTR their_features, const struct LDKShutdown *NONNULL_PTR msg);
	/**
	 *  Handle an incoming closing_signed message from the given peer.
	 */
	inline void handle_closing_signed(struct LDKPublicKey their_node_id, const struct LDKClosingSigned *NONNULL_PTR msg);
	/**
	 *  Handle an incoming update_add_htlc message from the given peer.
	 */
	inline void handle_update_add_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateAddHTLC *NONNULL_PTR msg);
	/**
	 *  Handle an incoming update_fulfill_htlc message from the given peer.
	 */
	inline void handle_update_fulfill_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFulfillHTLC *NONNULL_PTR msg);
	/**
	 *  Handle an incoming update_fail_htlc message from the given peer.
	 */
	inline void handle_update_fail_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFailHTLC *NONNULL_PTR msg);
	/**
	 *  Handle an incoming update_fail_malformed_htlc message from the given peer.
	 */
	inline void handle_update_fail_malformed_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFailMalformedHTLC *NONNULL_PTR msg);
	/**
	 *  Handle an incoming commitment_signed message from the given peer.
	 */
	inline void handle_commitment_signed(struct LDKPublicKey their_node_id, const struct LDKCommitmentSigned *NONNULL_PTR msg);
	/**
	 *  Handle an incoming revoke_and_ack message from the given peer.
	 */
	inline void handle_revoke_and_ack(struct LDKPublicKey their_node_id, const struct LDKRevokeAndACK *NONNULL_PTR msg);
	/**
	 *  Handle an incoming update_fee message from the given peer.
	 */
	inline void handle_update_fee(struct LDKPublicKey their_node_id, const struct LDKUpdateFee *NONNULL_PTR msg);
	/**
	 *  Handle an incoming announcement_signatures message from the given peer.
	 */
	inline void handle_announcement_signatures(struct LDKPublicKey their_node_id, const struct LDKAnnouncementSignatures *NONNULL_PTR msg);
	/**
	 *  Indicates a connection to the peer failed/an existing connection was lost. If no connection
	 *  is believed to be possible in the future (eg they're sending us messages we don't
	 *  understand or indicate they require unknown feature bits), no_connection_possible is set
	 *  and any outstanding channels should be failed.
	 */
	inline void peer_disconnected(struct LDKPublicKey their_node_id, bool no_connection_possible);
	/**
	 *  Handle a peer reconnecting, possibly generating channel_reestablish message(s).
	 */
	inline void peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR msg);
	/**
	 *  Handle an incoming channel_reestablish message from the given peer.
	 */
	inline void handle_channel_reestablish(struct LDKPublicKey their_node_id, const struct LDKChannelReestablish *NONNULL_PTR msg);
	/**
	 *  Handle an incoming channel update from the given peer.
	 */
	inline void handle_channel_update(struct LDKPublicKey their_node_id, const struct LDKChannelUpdate *NONNULL_PTR msg);
	/**
	 *  Handle an incoming error message from the given peer.
	 */
	inline void handle_error(struct LDKPublicKey their_node_id, const struct LDKErrorMessage *NONNULL_PTR msg);
	/**
	 *  Gets the node feature flags which this handler itself supports. All available handlers are
	 *  queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	 *  which are broadcasted in our [`NodeAnnouncement`] message.
	 */
	inline LDK::NodeFeatures provided_node_features();
	/**
	 *  Gets the init feature flags which should be sent to the given peer. All available handlers
	 *  are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	 *  which are sent in our [`Init`] message.
	 * 
	 *  Note that this method is called before [`Self::peer_connected`].
	 */
	inline LDK::InitFeatures provided_init_features(struct LDKPublicKey their_node_id);
};
class RoutingMessageHandler {
private:
	LDKRoutingMessageHandler self;
public:
	RoutingMessageHandler(const RoutingMessageHandler&) = delete;
	RoutingMessageHandler(RoutingMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(RoutingMessageHandler)); }
	RoutingMessageHandler(LDKRoutingMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoutingMessageHandler)); }
	operator LDKRoutingMessageHandler() && { LDKRoutingMessageHandler res = self; memset(&self, 0, sizeof(LDKRoutingMessageHandler)); return res; }
	~RoutingMessageHandler() { RoutingMessageHandler_free(self); }
	RoutingMessageHandler& operator=(RoutingMessageHandler&& o) { RoutingMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(RoutingMessageHandler)); return *this; }
	LDKRoutingMessageHandler* operator &() { return &self; }
	LDKRoutingMessageHandler* operator ->() { return &self; }
	const LDKRoutingMessageHandler* operator &() const { return &self; }
	const LDKRoutingMessageHandler* operator ->() const { return &self; }
	/**
	 *  Handle an incoming node_announcement message, returning true if it should be forwarded on,
	 *  false or returning an Err otherwise.
	 */
	inline LDK::CResult_boolLightningErrorZ handle_node_announcement(const struct LDKNodeAnnouncement *NONNULL_PTR msg);
	/**
	 *  Handle a channel_announcement message, returning true if it should be forwarded on, false
	 *  or returning an Err otherwise.
	 */
	inline LDK::CResult_boolLightningErrorZ handle_channel_announcement(const struct LDKChannelAnnouncement *NONNULL_PTR msg);
	/**
	 *  Handle an incoming channel_update message, returning true if it should be forwarded on,
	 *  false or returning an Err otherwise.
	 */
	inline LDK::CResult_boolLightningErrorZ handle_channel_update(const struct LDKChannelUpdate *NONNULL_PTR msg);
	/**
	 *  Gets channel announcements and updates required to dump our routing table to a remote node,
	 *  starting at the short_channel_id indicated by starting_point and including announcements
	 *  for a single channel.
	 */
	inline LDK::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ get_next_channel_announcement(uint64_t starting_point);
	/**
	 *  Gets a node announcement required to dump our routing table to a remote node, starting at
	 *  the node *after* the provided pubkey and including up to one announcement immediately
	 *  higher (as defined by <PublicKey as Ord>::cmp) than starting_point.
	 *  If None is provided for starting_point, we start at the first node.
	 * 
	 *  Note that starting_point (or a relevant inner pointer) may be NULL or all-0s to represent None
	 *  Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
	 */
	inline LDK::NodeAnnouncement get_next_node_announcement(struct LDKPublicKey starting_point);
	/**
	 *  Called when a connection is established with a peer. This can be used to
	 *  perform routing table synchronization using a strategy defined by the
	 *  implementor.
	 */
	inline void peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR init);
	/**
	 *  Handles the reply of a query we initiated to learn about channels
	 *  for a given range of blocks. We can expect to receive one or more
	 *  replies to a single query.
	 */
	inline LDK::CResult_NoneLightningErrorZ handle_reply_channel_range(struct LDKPublicKey their_node_id, struct LDKReplyChannelRange msg);
	/**
	 *  Handles the reply of a query we initiated asking for routing gossip
	 *  messages for a list of channels. We should receive this message when
	 *  a node has completed its best effort to send us the pertaining routing
	 *  gossip messages.
	 */
	inline LDK::CResult_NoneLightningErrorZ handle_reply_short_channel_ids_end(struct LDKPublicKey their_node_id, struct LDKReplyShortChannelIdsEnd msg);
	/**
	 *  Handles when a peer asks us to send a list of short_channel_ids
	 *  for the requested range of blocks.
	 */
	inline LDK::CResult_NoneLightningErrorZ handle_query_channel_range(struct LDKPublicKey their_node_id, struct LDKQueryChannelRange msg);
	/**
	 *  Handles when a peer asks us to send routing gossip messages for a
	 *  list of short_channel_ids.
	 */
	inline LDK::CResult_NoneLightningErrorZ handle_query_short_channel_ids(struct LDKPublicKey their_node_id, struct LDKQueryShortChannelIds msg);
	/**
	 *  Gets the node feature flags which this handler itself supports. All available handlers are
	 *  queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	 *  which are broadcasted in our [`NodeAnnouncement`] message.
	 */
	inline LDK::NodeFeatures provided_node_features();
	/**
	 *  Gets the init feature flags which should be sent to the given peer. All available handlers
	 *  are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	 *  which are sent in our [`Init`] message.
	 * 
	 *  Note that this method is called before [`Self::peer_connected`].
	 */
	inline LDK::InitFeatures provided_init_features(struct LDKPublicKey their_node_id);
};
class OnionMessageHandler {
private:
	LDKOnionMessageHandler self;
public:
	OnionMessageHandler(const OnionMessageHandler&) = delete;
	OnionMessageHandler(OnionMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(OnionMessageHandler)); }
	OnionMessageHandler(LDKOnionMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOnionMessageHandler)); }
	operator LDKOnionMessageHandler() && { LDKOnionMessageHandler res = self; memset(&self, 0, sizeof(LDKOnionMessageHandler)); return res; }
	~OnionMessageHandler() { OnionMessageHandler_free(self); }
	OnionMessageHandler& operator=(OnionMessageHandler&& o) { OnionMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(OnionMessageHandler)); return *this; }
	LDKOnionMessageHandler* operator &() { return &self; }
	LDKOnionMessageHandler* operator ->() { return &self; }
	const LDKOnionMessageHandler* operator &() const { return &self; }
	const LDKOnionMessageHandler* operator ->() const { return &self; }
	/**
	 *  Handle an incoming onion_message message from the given peer.
	 */
	inline void handle_onion_message(struct LDKPublicKey peer_node_id, const struct LDKOnionMessage *NONNULL_PTR msg);
	/**
	 *  Called when a connection is established with a peer. Can be used to track which peers
	 *  advertise onion message support and are online.
	 */
	inline void peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR init);
	/**
	 *  Indicates a connection to the peer failed/an existing connection was lost. Allows handlers to
	 *  drop and refuse to forward onion messages to this peer.
	 */
	inline void peer_disconnected(struct LDKPublicKey their_node_id, bool no_connection_possible);
	/**
	 *  Gets the node feature flags which this handler itself supports. All available handlers are
	 *  queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	 *  which are broadcasted in our [`NodeAnnouncement`] message.
	 */
	inline LDK::NodeFeatures provided_node_features();
	/**
	 *  Gets the init feature flags which should be sent to the given peer. All available handlers
	 *  are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	 *  which are sent in our [`Init`] message.
	 * 
	 *  Note that this method is called before [`Self::peer_connected`].
	 */
	inline LDK::InitFeatures provided_init_features(struct LDKPublicKey their_node_id);
};
class GraphSyncError {
private:
	LDKGraphSyncError self;
public:
	GraphSyncError(const GraphSyncError&) = delete;
	GraphSyncError(GraphSyncError&& o) : self(o.self) { memset(&o, 0, sizeof(GraphSyncError)); }
	GraphSyncError(LDKGraphSyncError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKGraphSyncError)); }
	operator LDKGraphSyncError() && { LDKGraphSyncError res = self; memset(&self, 0, sizeof(LDKGraphSyncError)); return res; }
	~GraphSyncError() { GraphSyncError_free(self); }
	GraphSyncError& operator=(GraphSyncError&& o) { GraphSyncError_free(self); self = o.self; memset(&o, 0, sizeof(GraphSyncError)); return *this; }
	LDKGraphSyncError* operator &() { return &self; }
	LDKGraphSyncError* operator ->() { return &self; }
	const LDKGraphSyncError* operator &() const { return &self; }
	const LDKGraphSyncError* operator ->() const { return &self; }
};
class DefaultRouter {
private:
	LDKDefaultRouter self;
public:
	DefaultRouter(const DefaultRouter&) = delete;
	DefaultRouter(DefaultRouter&& o) : self(o.self) { memset(&o, 0, sizeof(DefaultRouter)); }
	DefaultRouter(LDKDefaultRouter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDefaultRouter)); }
	operator LDKDefaultRouter() && { LDKDefaultRouter res = self; memset(&self, 0, sizeof(LDKDefaultRouter)); return res; }
	~DefaultRouter() { DefaultRouter_free(self); }
	DefaultRouter& operator=(DefaultRouter&& o) { DefaultRouter_free(self); self = o.self; memset(&o, 0, sizeof(DefaultRouter)); return *this; }
	LDKDefaultRouter* operator &() { return &self; }
	LDKDefaultRouter* operator ->() { return &self; }
	const LDKDefaultRouter* operator &() const { return &self; }
	const LDKDefaultRouter* operator ->() const { return &self; }
};
class Level {
private:
	LDKLevel self;
public:
	Level(const Level&) = delete;
	Level(Level&& o) : self(o.self) { memset(&o, 0, sizeof(Level)); }
	Level(LDKLevel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLevel)); }
	operator LDKLevel() && { LDKLevel res = self; memset(&self, 0, sizeof(LDKLevel)); return res; }
	Level& operator=(Level&& o) { self = o.self; memset(&o, 0, sizeof(Level)); return *this; }
	LDKLevel* operator &() { return &self; }
	LDKLevel* operator ->() { return &self; }
	const LDKLevel* operator &() const { return &self; }
	const LDKLevel* operator ->() const { return &self; }
};
class Record {
private:
	LDKRecord self;
public:
	Record(const Record&) = delete;
	Record(Record&& o) : self(o.self) { memset(&o, 0, sizeof(Record)); }
	Record(LDKRecord&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRecord)); }
	operator LDKRecord() && { LDKRecord res = self; memset(&self, 0, sizeof(LDKRecord)); return res; }
	~Record() { Record_free(self); }
	Record& operator=(Record&& o) { Record_free(self); self = o.self; memset(&o, 0, sizeof(Record)); return *this; }
	LDKRecord* operator &() { return &self; }
	LDKRecord* operator ->() { return &self; }
	const LDKRecord* operator &() const { return &self; }
	const LDKRecord* operator ->() const { return &self; }
};
class Logger {
private:
	LDKLogger self;
public:
	Logger(const Logger&) = delete;
	Logger(Logger&& o) : self(o.self) { memset(&o, 0, sizeof(Logger)); }
	Logger(LDKLogger&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLogger)); }
	operator LDKLogger() && { LDKLogger res = self; memset(&self, 0, sizeof(LDKLogger)); return res; }
	~Logger() { Logger_free(self); }
	Logger& operator=(Logger&& o) { Logger_free(self); self = o.self; memset(&o, 0, sizeof(Logger)); return *this; }
	LDKLogger* operator &() { return &self; }
	LDKLogger* operator ->() { return &self; }
	const LDKLogger* operator &() const { return &self; }
	const LDKLogger* operator ->() const { return &self; }
	/**
	 *  Logs the `Record`
	 */
	inline void log(const struct LDKRecord *NONNULL_PTR record);
};
class FutureCallback {
private:
	LDKFutureCallback self;
public:
	FutureCallback(const FutureCallback&) = delete;
	FutureCallback(FutureCallback&& o) : self(o.self) { memset(&o, 0, sizeof(FutureCallback)); }
	FutureCallback(LDKFutureCallback&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFutureCallback)); }
	operator LDKFutureCallback() && { LDKFutureCallback res = self; memset(&self, 0, sizeof(LDKFutureCallback)); return res; }
	~FutureCallback() { FutureCallback_free(self); }
	FutureCallback& operator=(FutureCallback&& o) { FutureCallback_free(self); self = o.self; memset(&o, 0, sizeof(FutureCallback)); return *this; }
	LDKFutureCallback* operator &() { return &self; }
	LDKFutureCallback* operator ->() { return &self; }
	const LDKFutureCallback* operator &() const { return &self; }
	const LDKFutureCallback* operator ->() const { return &self; }
	/**
	 *  The method which is called.
	 */
	inline void call();
};
class Future {
private:
	LDKFuture self;
public:
	Future(const Future&) = delete;
	Future(Future&& o) : self(o.self) { memset(&o, 0, sizeof(Future)); }
	Future(LDKFuture&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFuture)); }
	operator LDKFuture() && { LDKFuture res = self; memset(&self, 0, sizeof(LDKFuture)); return res; }
	~Future() { Future_free(self); }
	Future& operator=(Future&& o) { Future_free(self); self = o.self; memset(&o, 0, sizeof(Future)); return *this; }
	LDKFuture* operator &() { return &self; }
	LDKFuture* operator ->() { return &self; }
	const LDKFuture* operator &() const { return &self; }
	const LDKFuture* operator ->() const { return &self; }
};
class MonitorUpdateId {
private:
	LDKMonitorUpdateId self;
public:
	MonitorUpdateId(const MonitorUpdateId&) = delete;
	MonitorUpdateId(MonitorUpdateId&& o) : self(o.self) { memset(&o, 0, sizeof(MonitorUpdateId)); }
	MonitorUpdateId(LDKMonitorUpdateId&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMonitorUpdateId)); }
	operator LDKMonitorUpdateId() && { LDKMonitorUpdateId res = self; memset(&self, 0, sizeof(LDKMonitorUpdateId)); return res; }
	~MonitorUpdateId() { MonitorUpdateId_free(self); }
	MonitorUpdateId& operator=(MonitorUpdateId&& o) { MonitorUpdateId_free(self); self = o.self; memset(&o, 0, sizeof(MonitorUpdateId)); return *this; }
	LDKMonitorUpdateId* operator &() { return &self; }
	LDKMonitorUpdateId* operator ->() { return &self; }
	const LDKMonitorUpdateId* operator &() const { return &self; }
	const LDKMonitorUpdateId* operator ->() const { return &self; }
};
class Persist {
private:
	LDKPersist self;
public:
	Persist(const Persist&) = delete;
	Persist(Persist&& o) : self(o.self) { memset(&o, 0, sizeof(Persist)); }
	Persist(LDKPersist&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPersist)); }
	operator LDKPersist() && { LDKPersist res = self; memset(&self, 0, sizeof(LDKPersist)); return res; }
	~Persist() { Persist_free(self); }
	Persist& operator=(Persist&& o) { Persist_free(self); self = o.self; memset(&o, 0, sizeof(Persist)); return *this; }
	LDKPersist* operator &() { return &self; }
	LDKPersist* operator ->() { return &self; }
	const LDKPersist* operator &() const { return &self; }
	const LDKPersist* operator ->() const { return &self; }
	/**
	 *  Persist a new channel's data in response to a [`chain::Watch::watch_channel`] call. This is
	 *  called by [`ChannelManager`] for new channels, or may be called directly, e.g. on startup.
	 * 
	 *  The data can be stored any way you want, but the identifier provided by LDK is the
	 *  channel's outpoint (and it is up to you to maintain a correct mapping between the outpoint
	 *  and the stored channel data). Note that you **must** persist every new monitor to disk.
	 * 
	 *  The `update_id` is used to identify this call to [`ChainMonitor::channel_monitor_updated`],
	 *  if you return [`ChannelMonitorUpdateErr::TemporaryFailure`].
	 * 
	 *  See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`
	 *  and [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	 * 
	 *  [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	 *  [`Writeable::write`]: crate::util::ser::Writeable::write
	 */
	inline LDK::CResult_NoneChannelMonitorUpdateErrZ persist_new_channel(struct LDKOutPoint channel_id, const struct LDKChannelMonitor *NONNULL_PTR data, struct LDKMonitorUpdateId update_id);
	/**
	 *  Update one channel's data. The provided [`ChannelMonitor`] has already applied the given
	 *  update.
	 * 
	 *  Note that on every update, you **must** persist either the [`ChannelMonitorUpdate`] or the
	 *  updated monitor itself to disk/backups. See the [`Persist`] trait documentation for more
	 *  details.
	 * 
	 *  During blockchain synchronization operations, this may be called with no
	 *  [`ChannelMonitorUpdate`], in which case the full [`ChannelMonitor`] needs to be persisted.
	 *  Note that after the full [`ChannelMonitor`] is persisted any previous
	 *  [`ChannelMonitorUpdate`]s which were persisted should be discarded - they can no longer be
	 *  applied to the persisted [`ChannelMonitor`] as they were already applied.
	 * 
	 *  If an implementer chooses to persist the updates only, they need to make
	 *  sure that all the updates are applied to the `ChannelMonitors` *before*
	 *  the set of channel monitors is given to the `ChannelManager`
	 *  deserialization routine. See [`ChannelMonitor::update_monitor`] for
	 *  applying a monitor update to a monitor. If full `ChannelMonitors` are
	 *  persisted, then there is no need to persist individual updates.
	 * 
	 *  Note that there could be a performance tradeoff between persisting complete
	 *  channel monitors on every update vs. persisting only updates and applying
	 *  them in batches. The size of each monitor grows `O(number of state updates)`
	 *  whereas updates are small and `O(1)`.
	 * 
	 *  The `update_id` is used to identify this call to [`ChainMonitor::channel_monitor_updated`],
	 *  if you return [`ChannelMonitorUpdateErr::TemporaryFailure`].
	 * 
	 *  See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`,
	 *  [`Writeable::write`] on [`ChannelMonitorUpdate`] for writing out an update, and
	 *  [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	 * 
	 *  [`Writeable::write`]: crate::util::ser::Writeable::write
	 * 
	 *  Note that update (or a relevant inner pointer) may be NULL or all-0s to represent None
	 */
	inline LDK::CResult_NoneChannelMonitorUpdateErrZ update_persisted_channel(struct LDKOutPoint channel_id, const struct LDKChannelMonitorUpdate *NONNULL_PTR update, const struct LDKChannelMonitor *NONNULL_PTR data, struct LDKMonitorUpdateId update_id);
};
class LockedChannelMonitor {
private:
	LDKLockedChannelMonitor self;
public:
	LockedChannelMonitor(const LockedChannelMonitor&) = delete;
	LockedChannelMonitor(LockedChannelMonitor&& o) : self(o.self) { memset(&o, 0, sizeof(LockedChannelMonitor)); }
	LockedChannelMonitor(LDKLockedChannelMonitor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLockedChannelMonitor)); }
	operator LDKLockedChannelMonitor() && { LDKLockedChannelMonitor res = self; memset(&self, 0, sizeof(LDKLockedChannelMonitor)); return res; }
	~LockedChannelMonitor() { LockedChannelMonitor_free(self); }
	LockedChannelMonitor& operator=(LockedChannelMonitor&& o) { LockedChannelMonitor_free(self); self = o.self; memset(&o, 0, sizeof(LockedChannelMonitor)); return *this; }
	LDKLockedChannelMonitor* operator &() { return &self; }
	LDKLockedChannelMonitor* operator ->() { return &self; }
	const LDKLockedChannelMonitor* operator &() const { return &self; }
	const LDKLockedChannelMonitor* operator ->() const { return &self; }
};
class ChainMonitor {
private:
	LDKChainMonitor self;
public:
	ChainMonitor(const ChainMonitor&) = delete;
	ChainMonitor(ChainMonitor&& o) : self(o.self) { memset(&o, 0, sizeof(ChainMonitor)); }
	ChainMonitor(LDKChainMonitor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChainMonitor)); }
	operator LDKChainMonitor() && { LDKChainMonitor res = self; memset(&self, 0, sizeof(LDKChainMonitor)); return res; }
	~ChainMonitor() { ChainMonitor_free(self); }
	ChainMonitor& operator=(ChainMonitor&& o) { ChainMonitor_free(self); self = o.self; memset(&o, 0, sizeof(ChainMonitor)); return *this; }
	LDKChainMonitor* operator &() { return &self; }
	LDKChainMonitor* operator ->() { return &self; }
	const LDKChainMonitor* operator &() const { return &self; }
	const LDKChainMonitor* operator ->() const { return &self; }
};
class CVec_SpendableOutputDescriptorZ {
private:
	LDKCVec_SpendableOutputDescriptorZ self;
public:
	CVec_SpendableOutputDescriptorZ(const CVec_SpendableOutputDescriptorZ&) = delete;
	CVec_SpendableOutputDescriptorZ(CVec_SpendableOutputDescriptorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_SpendableOutputDescriptorZ)); }
	CVec_SpendableOutputDescriptorZ(LDKCVec_SpendableOutputDescriptorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_SpendableOutputDescriptorZ)); }
	operator LDKCVec_SpendableOutputDescriptorZ() && { LDKCVec_SpendableOutputDescriptorZ res = self; memset(&self, 0, sizeof(LDKCVec_SpendableOutputDescriptorZ)); return res; }
	~CVec_SpendableOutputDescriptorZ() { CVec_SpendableOutputDescriptorZ_free(self); }
	CVec_SpendableOutputDescriptorZ& operator=(CVec_SpendableOutputDescriptorZ&& o) { CVec_SpendableOutputDescriptorZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_SpendableOutputDescriptorZ)); return *this; }
	LDKCVec_SpendableOutputDescriptorZ* operator &() { return &self; }
	LDKCVec_SpendableOutputDescriptorZ* operator ->() { return &self; }
	const LDKCVec_SpendableOutputDescriptorZ* operator &() const { return &self; }
	const LDKCVec_SpendableOutputDescriptorZ* operator ->() const { return &self; }
};
class CResult_LockedChannelMonitorNoneZ {
private:
	LDKCResult_LockedChannelMonitorNoneZ self;
public:
	CResult_LockedChannelMonitorNoneZ(const CResult_LockedChannelMonitorNoneZ&) = delete;
	CResult_LockedChannelMonitorNoneZ(CResult_LockedChannelMonitorNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_LockedChannelMonitorNoneZ)); }
	CResult_LockedChannelMonitorNoneZ(LDKCResult_LockedChannelMonitorNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_LockedChannelMonitorNoneZ)); }
	operator LDKCResult_LockedChannelMonitorNoneZ() && { LDKCResult_LockedChannelMonitorNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_LockedChannelMonitorNoneZ)); return res; }
	~CResult_LockedChannelMonitorNoneZ() { CResult_LockedChannelMonitorNoneZ_free(self); }
	CResult_LockedChannelMonitorNoneZ& operator=(CResult_LockedChannelMonitorNoneZ&& o) { CResult_LockedChannelMonitorNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_LockedChannelMonitorNoneZ)); return *this; }
	LDKCResult_LockedChannelMonitorNoneZ* operator &() { return &self; }
	LDKCResult_LockedChannelMonitorNoneZ* operator ->() { return &self; }
	const LDKCResult_LockedChannelMonitorNoneZ* operator &() const { return &self; }
	const LDKCResult_LockedChannelMonitorNoneZ* operator ->() const { return &self; }
};
class CResult_PhantomRouteHintsDecodeErrorZ {
private:
	LDKCResult_PhantomRouteHintsDecodeErrorZ self;
public:
	CResult_PhantomRouteHintsDecodeErrorZ(const CResult_PhantomRouteHintsDecodeErrorZ&) = delete;
	CResult_PhantomRouteHintsDecodeErrorZ(CResult_PhantomRouteHintsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PhantomRouteHintsDecodeErrorZ)); }
	CResult_PhantomRouteHintsDecodeErrorZ(LDKCResult_PhantomRouteHintsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PhantomRouteHintsDecodeErrorZ)); }
	operator LDKCResult_PhantomRouteHintsDecodeErrorZ() && { LDKCResult_PhantomRouteHintsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PhantomRouteHintsDecodeErrorZ)); return res; }
	~CResult_PhantomRouteHintsDecodeErrorZ() { CResult_PhantomRouteHintsDecodeErrorZ_free(self); }
	CResult_PhantomRouteHintsDecodeErrorZ& operator=(CResult_PhantomRouteHintsDecodeErrorZ&& o) { CResult_PhantomRouteHintsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PhantomRouteHintsDecodeErrorZ)); return *this; }
	LDKCResult_PhantomRouteHintsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PhantomRouteHintsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PhantomRouteHintsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PhantomRouteHintsDecodeErrorZ* operator ->() const { return &self; }
};
class COption_C2Tuple_u64u64ZZ {
private:
	LDKCOption_C2Tuple_u64u64ZZ self;
public:
	COption_C2Tuple_u64u64ZZ(const COption_C2Tuple_u64u64ZZ&) = delete;
	COption_C2Tuple_u64u64ZZ(COption_C2Tuple_u64u64ZZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_C2Tuple_u64u64ZZ)); }
	COption_C2Tuple_u64u64ZZ(LDKCOption_C2Tuple_u64u64ZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_C2Tuple_u64u64ZZ)); }
	operator LDKCOption_C2Tuple_u64u64ZZ() && { LDKCOption_C2Tuple_u64u64ZZ res = self; memset(&self, 0, sizeof(LDKCOption_C2Tuple_u64u64ZZ)); return res; }
	~COption_C2Tuple_u64u64ZZ() { COption_C2Tuple_u64u64ZZ_free(self); }
	COption_C2Tuple_u64u64ZZ& operator=(COption_C2Tuple_u64u64ZZ&& o) { COption_C2Tuple_u64u64ZZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_C2Tuple_u64u64ZZ)); return *this; }
	LDKCOption_C2Tuple_u64u64ZZ* operator &() { return &self; }
	LDKCOption_C2Tuple_u64u64ZZ* operator ->() { return &self; }
	const LDKCOption_C2Tuple_u64u64ZZ* operator &() const { return &self; }
	const LDKCOption_C2Tuple_u64u64ZZ* operator ->() const { return &self; }
};
class CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
private:
	LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ self;
public:
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ(const CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ&) = delete;
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ(CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ)); }
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ(LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ)); }
	operator LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ() && { LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ)); return res; }
	~CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ() { CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_free(self); }
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ& operator=(CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ&& o) { CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ)); return *this; }
	LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ* operator &() { return &self; }
	LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ* operator ->() { return &self; }
	const LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ* operator &() const { return &self; }
	const LDKCResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
private:
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ self;
public:
	CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ(const CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ&) = delete;
	CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ(CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ)); }
	CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ)); }
	operator LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ() && { LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ)); return res; }
	~CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ() { CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ_free(self); }
	CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ& operator=(CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ&& o) { CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ)); return *this; }
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ* operator ->() const { return &self; }
};
class CResult_HTLCUpdateDecodeErrorZ {
private:
	LDKCResult_HTLCUpdateDecodeErrorZ self;
public:
	CResult_HTLCUpdateDecodeErrorZ(const CResult_HTLCUpdateDecodeErrorZ&) = delete;
	CResult_HTLCUpdateDecodeErrorZ(CResult_HTLCUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_HTLCUpdateDecodeErrorZ)); }
	CResult_HTLCUpdateDecodeErrorZ(LDKCResult_HTLCUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_HTLCUpdateDecodeErrorZ)); }
	operator LDKCResult_HTLCUpdateDecodeErrorZ() && { LDKCResult_HTLCUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_HTLCUpdateDecodeErrorZ)); return res; }
	~CResult_HTLCUpdateDecodeErrorZ() { CResult_HTLCUpdateDecodeErrorZ_free(self); }
	CResult_HTLCUpdateDecodeErrorZ& operator=(CResult_HTLCUpdateDecodeErrorZ&& o) { CResult_HTLCUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_HTLCUpdateDecodeErrorZ)); return *this; }
	LDKCResult_HTLCUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_HTLCUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_HTLCUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_HTLCUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_SignatureCVec_SignatureZZ {
private:
	LDKC2Tuple_SignatureCVec_SignatureZZ self;
public:
	C2Tuple_SignatureCVec_SignatureZZ(const C2Tuple_SignatureCVec_SignatureZZ&) = delete;
	C2Tuple_SignatureCVec_SignatureZZ(C2Tuple_SignatureCVec_SignatureZZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_SignatureCVec_SignatureZZ)); }
	C2Tuple_SignatureCVec_SignatureZZ(LDKC2Tuple_SignatureCVec_SignatureZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_SignatureCVec_SignatureZZ)); }
	operator LDKC2Tuple_SignatureCVec_SignatureZZ() && { LDKC2Tuple_SignatureCVec_SignatureZZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_SignatureCVec_SignatureZZ)); return res; }
	~C2Tuple_SignatureCVec_SignatureZZ() { C2Tuple_SignatureCVec_SignatureZZ_free(self); }
	C2Tuple_SignatureCVec_SignatureZZ& operator=(C2Tuple_SignatureCVec_SignatureZZ&& o) { C2Tuple_SignatureCVec_SignatureZZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_SignatureCVec_SignatureZZ)); return *this; }
	LDKC2Tuple_SignatureCVec_SignatureZZ* operator &() { return &self; }
	LDKC2Tuple_SignatureCVec_SignatureZZ* operator ->() { return &self; }
	const LDKC2Tuple_SignatureCVec_SignatureZZ* operator &() const { return &self; }
	const LDKC2Tuple_SignatureCVec_SignatureZZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_u32TxOutZZ {
private:
	LDKCVec_C2Tuple_u32TxOutZZ self;
public:
	CVec_C2Tuple_u32TxOutZZ(const CVec_C2Tuple_u32TxOutZZ&) = delete;
	CVec_C2Tuple_u32TxOutZZ(CVec_C2Tuple_u32TxOutZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_u32TxOutZZ)); }
	CVec_C2Tuple_u32TxOutZZ(LDKCVec_C2Tuple_u32TxOutZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_u32TxOutZZ)); }
	operator LDKCVec_C2Tuple_u32TxOutZZ() && { LDKCVec_C2Tuple_u32TxOutZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_u32TxOutZZ)); return res; }
	~CVec_C2Tuple_u32TxOutZZ() { CVec_C2Tuple_u32TxOutZZ_free(self); }
	CVec_C2Tuple_u32TxOutZZ& operator=(CVec_C2Tuple_u32TxOutZZ&& o) { CVec_C2Tuple_u32TxOutZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_u32TxOutZZ)); return *this; }
	LDKCVec_C2Tuple_u32TxOutZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_u32TxOutZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_u32TxOutZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_u32TxOutZZ* operator ->() const { return &self; }
};
class CResult_ChannelInfoDecodeErrorZ {
private:
	LDKCResult_ChannelInfoDecodeErrorZ self;
public:
	CResult_ChannelInfoDecodeErrorZ(const CResult_ChannelInfoDecodeErrorZ&) = delete;
	CResult_ChannelInfoDecodeErrorZ(CResult_ChannelInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelInfoDecodeErrorZ)); }
	CResult_ChannelInfoDecodeErrorZ(LDKCResult_ChannelInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelInfoDecodeErrorZ)); }
	operator LDKCResult_ChannelInfoDecodeErrorZ() && { LDKCResult_ChannelInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelInfoDecodeErrorZ)); return res; }
	~CResult_ChannelInfoDecodeErrorZ() { CResult_ChannelInfoDecodeErrorZ_free(self); }
	CResult_ChannelInfoDecodeErrorZ& operator=(CResult_ChannelInfoDecodeErrorZ&& o) { CResult_ChannelInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelInfoDecodeErrorZ)); return *this; }
	LDKCResult_ChannelInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelInfoDecodeErrorZ* operator ->() const { return &self; }
};
class COption_WriteableScoreZ {
private:
	LDKCOption_WriteableScoreZ self;
public:
	COption_WriteableScoreZ(const COption_WriteableScoreZ&) = delete;
	COption_WriteableScoreZ(COption_WriteableScoreZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_WriteableScoreZ)); }
	COption_WriteableScoreZ(LDKCOption_WriteableScoreZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_WriteableScoreZ)); }
	operator LDKCOption_WriteableScoreZ() && { LDKCOption_WriteableScoreZ res = self; memset(&self, 0, sizeof(LDKCOption_WriteableScoreZ)); return res; }
	~COption_WriteableScoreZ() { COption_WriteableScoreZ_free(self); }
	COption_WriteableScoreZ& operator=(COption_WriteableScoreZ&& o) { COption_WriteableScoreZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_WriteableScoreZ)); return *this; }
	LDKCOption_WriteableScoreZ* operator &() { return &self; }
	LDKCOption_WriteableScoreZ* operator ->() { return &self; }
	const LDKCOption_WriteableScoreZ* operator &() const { return &self; }
	const LDKCOption_WriteableScoreZ* operator ->() const { return &self; }
};
class CResult_NoneSendErrorZ {
private:
	LDKCResult_NoneSendErrorZ self;
public:
	CResult_NoneSendErrorZ(const CResult_NoneSendErrorZ&) = delete;
	CResult_NoneSendErrorZ(CResult_NoneSendErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneSendErrorZ)); }
	CResult_NoneSendErrorZ(LDKCResult_NoneSendErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneSendErrorZ)); }
	operator LDKCResult_NoneSendErrorZ() && { LDKCResult_NoneSendErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneSendErrorZ)); return res; }
	~CResult_NoneSendErrorZ() { CResult_NoneSendErrorZ_free(self); }
	CResult_NoneSendErrorZ& operator=(CResult_NoneSendErrorZ&& o) { CResult_NoneSendErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneSendErrorZ)); return *this; }
	LDKCResult_NoneSendErrorZ* operator &() { return &self; }
	LDKCResult_NoneSendErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneSendErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneSendErrorZ* operator ->() const { return &self; }
};
class CResult_FundingCreatedDecodeErrorZ {
private:
	LDKCResult_FundingCreatedDecodeErrorZ self;
public:
	CResult_FundingCreatedDecodeErrorZ(const CResult_FundingCreatedDecodeErrorZ&) = delete;
	CResult_FundingCreatedDecodeErrorZ(CResult_FundingCreatedDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_FundingCreatedDecodeErrorZ)); }
	CResult_FundingCreatedDecodeErrorZ(LDKCResult_FundingCreatedDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_FundingCreatedDecodeErrorZ)); }
	operator LDKCResult_FundingCreatedDecodeErrorZ() && { LDKCResult_FundingCreatedDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_FundingCreatedDecodeErrorZ)); return res; }
	~CResult_FundingCreatedDecodeErrorZ() { CResult_FundingCreatedDecodeErrorZ_free(self); }
	CResult_FundingCreatedDecodeErrorZ& operator=(CResult_FundingCreatedDecodeErrorZ&& o) { CResult_FundingCreatedDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_FundingCreatedDecodeErrorZ)); return *this; }
	LDKCResult_FundingCreatedDecodeErrorZ* operator &() { return &self; }
	LDKCResult_FundingCreatedDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_FundingCreatedDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_FundingCreatedDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelAnnouncementDecodeErrorZ {
private:
	LDKCResult_ChannelAnnouncementDecodeErrorZ self;
public:
	CResult_ChannelAnnouncementDecodeErrorZ(const CResult_ChannelAnnouncementDecodeErrorZ&) = delete;
	CResult_ChannelAnnouncementDecodeErrorZ(CResult_ChannelAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelAnnouncementDecodeErrorZ)); }
	CResult_ChannelAnnouncementDecodeErrorZ(LDKCResult_ChannelAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelAnnouncementDecodeErrorZ)); }
	operator LDKCResult_ChannelAnnouncementDecodeErrorZ() && { LDKCResult_ChannelAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelAnnouncementDecodeErrorZ)); return res; }
	~CResult_ChannelAnnouncementDecodeErrorZ() { CResult_ChannelAnnouncementDecodeErrorZ_free(self); }
	CResult_ChannelAnnouncementDecodeErrorZ& operator=(CResult_ChannelAnnouncementDecodeErrorZ&& o) { CResult_ChannelAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_ChannelAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PositiveTimestampCreationErrorZ {
private:
	LDKCResult_PositiveTimestampCreationErrorZ self;
public:
	CResult_PositiveTimestampCreationErrorZ(const CResult_PositiveTimestampCreationErrorZ&) = delete;
	CResult_PositiveTimestampCreationErrorZ(CResult_PositiveTimestampCreationErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PositiveTimestampCreationErrorZ)); }
	CResult_PositiveTimestampCreationErrorZ(LDKCResult_PositiveTimestampCreationErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PositiveTimestampCreationErrorZ)); }
	operator LDKCResult_PositiveTimestampCreationErrorZ() && { LDKCResult_PositiveTimestampCreationErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PositiveTimestampCreationErrorZ)); return res; }
	~CResult_PositiveTimestampCreationErrorZ() { CResult_PositiveTimestampCreationErrorZ_free(self); }
	CResult_PositiveTimestampCreationErrorZ& operator=(CResult_PositiveTimestampCreationErrorZ&& o) { CResult_PositiveTimestampCreationErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PositiveTimestampCreationErrorZ)); return *this; }
	LDKCResult_PositiveTimestampCreationErrorZ* operator &() { return &self; }
	LDKCResult_PositiveTimestampCreationErrorZ* operator ->() { return &self; }
	const LDKCResult_PositiveTimestampCreationErrorZ* operator &() const { return &self; }
	const LDKCResult_PositiveTimestampCreationErrorZ* operator ->() const { return &self; }
};
class CVec_OutPointZ {
private:
	LDKCVec_OutPointZ self;
public:
	CVec_OutPointZ(const CVec_OutPointZ&) = delete;
	CVec_OutPointZ(CVec_OutPointZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_OutPointZ)); }
	CVec_OutPointZ(LDKCVec_OutPointZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_OutPointZ)); }
	operator LDKCVec_OutPointZ() && { LDKCVec_OutPointZ res = self; memset(&self, 0, sizeof(LDKCVec_OutPointZ)); return res; }
	~CVec_OutPointZ() { CVec_OutPointZ_free(self); }
	CVec_OutPointZ& operator=(CVec_OutPointZ&& o) { CVec_OutPointZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_OutPointZ)); return *this; }
	LDKCVec_OutPointZ* operator &() { return &self; }
	LDKCVec_OutPointZ* operator ->() { return &self; }
	const LDKCVec_OutPointZ* operator &() const { return &self; }
	const LDKCVec_OutPointZ* operator ->() const { return &self; }
};
class CResult_CVec_u8ZPeerHandleErrorZ {
private:
	LDKCResult_CVec_u8ZPeerHandleErrorZ self;
public:
	CResult_CVec_u8ZPeerHandleErrorZ(const CResult_CVec_u8ZPeerHandleErrorZ&) = delete;
	CResult_CVec_u8ZPeerHandleErrorZ(CResult_CVec_u8ZPeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_u8ZPeerHandleErrorZ)); }
	CResult_CVec_u8ZPeerHandleErrorZ(LDKCResult_CVec_u8ZPeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_u8ZPeerHandleErrorZ)); }
	operator LDKCResult_CVec_u8ZPeerHandleErrorZ() && { LDKCResult_CVec_u8ZPeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_u8ZPeerHandleErrorZ)); return res; }
	~CResult_CVec_u8ZPeerHandleErrorZ() { CResult_CVec_u8ZPeerHandleErrorZ_free(self); }
	CResult_CVec_u8ZPeerHandleErrorZ& operator=(CResult_CVec_u8ZPeerHandleErrorZ&& o) { CResult_CVec_u8ZPeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_u8ZPeerHandleErrorZ)); return *this; }
	LDKCResult_CVec_u8ZPeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_CVec_u8ZPeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_CVec_u8ZPeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_CVec_u8ZPeerHandleErrorZ* operator ->() const { return &self; }
};
class CResult_InvoiceFeaturesDecodeErrorZ {
private:
	LDKCResult_InvoiceFeaturesDecodeErrorZ self;
public:
	CResult_InvoiceFeaturesDecodeErrorZ(const CResult_InvoiceFeaturesDecodeErrorZ&) = delete;
	CResult_InvoiceFeaturesDecodeErrorZ(CResult_InvoiceFeaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InvoiceFeaturesDecodeErrorZ)); }
	CResult_InvoiceFeaturesDecodeErrorZ(LDKCResult_InvoiceFeaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InvoiceFeaturesDecodeErrorZ)); }
	operator LDKCResult_InvoiceFeaturesDecodeErrorZ() && { LDKCResult_InvoiceFeaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InvoiceFeaturesDecodeErrorZ)); return res; }
	~CResult_InvoiceFeaturesDecodeErrorZ() { CResult_InvoiceFeaturesDecodeErrorZ_free(self); }
	CResult_InvoiceFeaturesDecodeErrorZ& operator=(CResult_InvoiceFeaturesDecodeErrorZ&& o) { CResult_InvoiceFeaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InvoiceFeaturesDecodeErrorZ)); return *this; }
	LDKCResult_InvoiceFeaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InvoiceFeaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InvoiceFeaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InvoiceFeaturesDecodeErrorZ* operator ->() const { return &self; }
};
class COption_NetworkUpdateZ {
private:
	LDKCOption_NetworkUpdateZ self;
public:
	COption_NetworkUpdateZ(const COption_NetworkUpdateZ&) = delete;
	COption_NetworkUpdateZ(COption_NetworkUpdateZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_NetworkUpdateZ)); }
	COption_NetworkUpdateZ(LDKCOption_NetworkUpdateZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_NetworkUpdateZ)); }
	operator LDKCOption_NetworkUpdateZ() && { LDKCOption_NetworkUpdateZ res = self; memset(&self, 0, sizeof(LDKCOption_NetworkUpdateZ)); return res; }
	~COption_NetworkUpdateZ() { COption_NetworkUpdateZ_free(self); }
	COption_NetworkUpdateZ& operator=(COption_NetworkUpdateZ&& o) { COption_NetworkUpdateZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_NetworkUpdateZ)); return *this; }
	LDKCOption_NetworkUpdateZ* operator &() { return &self; }
	LDKCOption_NetworkUpdateZ* operator ->() { return &self; }
	const LDKCOption_NetworkUpdateZ* operator &() const { return &self; }
	const LDKCOption_NetworkUpdateZ* operator ->() const { return &self; }
};
class COption_u64Z {
private:
	LDKCOption_u64Z self;
public:
	COption_u64Z(const COption_u64Z&) = delete;
	COption_u64Z(COption_u64Z&& o) : self(o.self) { memset(&o, 0, sizeof(COption_u64Z)); }
	COption_u64Z(LDKCOption_u64Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_u64Z)); }
	operator LDKCOption_u64Z() && { LDKCOption_u64Z res = self; memset(&self, 0, sizeof(LDKCOption_u64Z)); return res; }
	~COption_u64Z() { COption_u64Z_free(self); }
	COption_u64Z& operator=(COption_u64Z&& o) { COption_u64Z_free(self); self = o.self; memset(&o, 0, sizeof(COption_u64Z)); return *this; }
	LDKCOption_u64Z* operator &() { return &self; }
	LDKCOption_u64Z* operator ->() { return &self; }
	const LDKCOption_u64Z* operator &() const { return &self; }
	const LDKCOption_u64Z* operator ->() const { return &self; }
};
class CResult_TxOutAccessErrorZ {
private:
	LDKCResult_TxOutAccessErrorZ self;
public:
	CResult_TxOutAccessErrorZ(const CResult_TxOutAccessErrorZ&) = delete;
	CResult_TxOutAccessErrorZ(CResult_TxOutAccessErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TxOutAccessErrorZ)); }
	CResult_TxOutAccessErrorZ(LDKCResult_TxOutAccessErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TxOutAccessErrorZ)); }
	operator LDKCResult_TxOutAccessErrorZ() && { LDKCResult_TxOutAccessErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_TxOutAccessErrorZ)); return res; }
	~CResult_TxOutAccessErrorZ() { CResult_TxOutAccessErrorZ_free(self); }
	CResult_TxOutAccessErrorZ& operator=(CResult_TxOutAccessErrorZ&& o) { CResult_TxOutAccessErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TxOutAccessErrorZ)); return *this; }
	LDKCResult_TxOutAccessErrorZ* operator &() { return &self; }
	LDKCResult_TxOutAccessErrorZ* operator ->() { return &self; }
	const LDKCResult_TxOutAccessErrorZ* operator &() const { return &self; }
	const LDKCResult_TxOutAccessErrorZ* operator ->() const { return &self; }
};
class CResult_TrustedClosingTransactionNoneZ {
private:
	LDKCResult_TrustedClosingTransactionNoneZ self;
public:
	CResult_TrustedClosingTransactionNoneZ(const CResult_TrustedClosingTransactionNoneZ&) = delete;
	CResult_TrustedClosingTransactionNoneZ(CResult_TrustedClosingTransactionNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TrustedClosingTransactionNoneZ)); }
	CResult_TrustedClosingTransactionNoneZ(LDKCResult_TrustedClosingTransactionNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TrustedClosingTransactionNoneZ)); }
	operator LDKCResult_TrustedClosingTransactionNoneZ() && { LDKCResult_TrustedClosingTransactionNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_TrustedClosingTransactionNoneZ)); return res; }
	~CResult_TrustedClosingTransactionNoneZ() { CResult_TrustedClosingTransactionNoneZ_free(self); }
	CResult_TrustedClosingTransactionNoneZ& operator=(CResult_TrustedClosingTransactionNoneZ&& o) { CResult_TrustedClosingTransactionNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TrustedClosingTransactionNoneZ)); return *this; }
	LDKCResult_TrustedClosingTransactionNoneZ* operator &() { return &self; }
	LDKCResult_TrustedClosingTransactionNoneZ* operator ->() { return &self; }
	const LDKCResult_TrustedClosingTransactionNoneZ* operator &() const { return &self; }
	const LDKCResult_TrustedClosingTransactionNoneZ* operator ->() const { return &self; }
};
class CResult_PaymentPreimageAPIErrorZ {
private:
	LDKCResult_PaymentPreimageAPIErrorZ self;
public:
	CResult_PaymentPreimageAPIErrorZ(const CResult_PaymentPreimageAPIErrorZ&) = delete;
	CResult_PaymentPreimageAPIErrorZ(CResult_PaymentPreimageAPIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentPreimageAPIErrorZ)); }
	CResult_PaymentPreimageAPIErrorZ(LDKCResult_PaymentPreimageAPIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentPreimageAPIErrorZ)); }
	operator LDKCResult_PaymentPreimageAPIErrorZ() && { LDKCResult_PaymentPreimageAPIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentPreimageAPIErrorZ)); return res; }
	~CResult_PaymentPreimageAPIErrorZ() { CResult_PaymentPreimageAPIErrorZ_free(self); }
	CResult_PaymentPreimageAPIErrorZ& operator=(CResult_PaymentPreimageAPIErrorZ&& o) { CResult_PaymentPreimageAPIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentPreimageAPIErrorZ)); return *this; }
	LDKCResult_PaymentPreimageAPIErrorZ* operator &() { return &self; }
	LDKCResult_PaymentPreimageAPIErrorZ* operator ->() { return &self; }
	const LDKCResult_PaymentPreimageAPIErrorZ* operator &() const { return &self; }
	const LDKCResult_PaymentPreimageAPIErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelMonitorUpdateDecodeErrorZ {
private:
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ self;
public:
	CResult_ChannelMonitorUpdateDecodeErrorZ(const CResult_ChannelMonitorUpdateDecodeErrorZ&) = delete;
	CResult_ChannelMonitorUpdateDecodeErrorZ(CResult_ChannelMonitorUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelMonitorUpdateDecodeErrorZ)); }
	CResult_ChannelMonitorUpdateDecodeErrorZ(LDKCResult_ChannelMonitorUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelMonitorUpdateDecodeErrorZ)); }
	operator LDKCResult_ChannelMonitorUpdateDecodeErrorZ() && { LDKCResult_ChannelMonitorUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelMonitorUpdateDecodeErrorZ)); return res; }
	~CResult_ChannelMonitorUpdateDecodeErrorZ() { CResult_ChannelMonitorUpdateDecodeErrorZ_free(self); }
	CResult_ChannelMonitorUpdateDecodeErrorZ& operator=(CResult_ChannelMonitorUpdateDecodeErrorZ&& o) { CResult_ChannelMonitorUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelMonitorUpdateDecodeErrorZ)); return *this; }
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RouteHintDecodeErrorZ {
private:
	LDKCResult_RouteHintDecodeErrorZ self;
public:
	CResult_RouteHintDecodeErrorZ(const CResult_RouteHintDecodeErrorZ&) = delete;
	CResult_RouteHintDecodeErrorZ(CResult_RouteHintDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteHintDecodeErrorZ)); }
	CResult_RouteHintDecodeErrorZ(LDKCResult_RouteHintDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteHintDecodeErrorZ)); }
	operator LDKCResult_RouteHintDecodeErrorZ() && { LDKCResult_RouteHintDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteHintDecodeErrorZ)); return res; }
	~CResult_RouteHintDecodeErrorZ() { CResult_RouteHintDecodeErrorZ_free(self); }
	CResult_RouteHintDecodeErrorZ& operator=(CResult_RouteHintDecodeErrorZ&& o) { CResult_RouteHintDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteHintDecodeErrorZ)); return *this; }
	LDKCResult_RouteHintDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteHintDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteHintDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteHintDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_PublicKeyTypeZ {
private:
	LDKC2Tuple_PublicKeyTypeZ self;
public:
	C2Tuple_PublicKeyTypeZ(const C2Tuple_PublicKeyTypeZ&) = delete;
	C2Tuple_PublicKeyTypeZ(C2Tuple_PublicKeyTypeZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_PublicKeyTypeZ)); }
	C2Tuple_PublicKeyTypeZ(LDKC2Tuple_PublicKeyTypeZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_PublicKeyTypeZ)); }
	operator LDKC2Tuple_PublicKeyTypeZ() && { LDKC2Tuple_PublicKeyTypeZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_PublicKeyTypeZ)); return res; }
	~C2Tuple_PublicKeyTypeZ() { C2Tuple_PublicKeyTypeZ_free(self); }
	C2Tuple_PublicKeyTypeZ& operator=(C2Tuple_PublicKeyTypeZ&& o) { C2Tuple_PublicKeyTypeZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_PublicKeyTypeZ)); return *this; }
	LDKC2Tuple_PublicKeyTypeZ* operator &() { return &self; }
	LDKC2Tuple_PublicKeyTypeZ* operator ->() { return &self; }
	const LDKC2Tuple_PublicKeyTypeZ* operator &() const { return &self; }
	const LDKC2Tuple_PublicKeyTypeZ* operator ->() const { return &self; }
};
class CResult_NetAddressDecodeErrorZ {
private:
	LDKCResult_NetAddressDecodeErrorZ self;
public:
	CResult_NetAddressDecodeErrorZ(const CResult_NetAddressDecodeErrorZ&) = delete;
	CResult_NetAddressDecodeErrorZ(CResult_NetAddressDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NetAddressDecodeErrorZ)); }
	CResult_NetAddressDecodeErrorZ(LDKCResult_NetAddressDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NetAddressDecodeErrorZ)); }
	operator LDKCResult_NetAddressDecodeErrorZ() && { LDKCResult_NetAddressDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NetAddressDecodeErrorZ)); return res; }
	~CResult_NetAddressDecodeErrorZ() { CResult_NetAddressDecodeErrorZ_free(self); }
	CResult_NetAddressDecodeErrorZ& operator=(CResult_NetAddressDecodeErrorZ&& o) { CResult_NetAddressDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NetAddressDecodeErrorZ)); return *this; }
	LDKCResult_NetAddressDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NetAddressDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NetAddressDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NetAddressDecodeErrorZ* operator ->() const { return &self; }
};
class COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
private:
	LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ self;
public:
	COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(const COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&) = delete;
	COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); }
	COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); }
	operator LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ() && { LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ res = self; memset(&self, 0, sizeof(LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); return res; }
	~COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ() { COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(self); }
	COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ& operator=(COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& o) { COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); return *this; }
	LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator &() { return &self; }
	LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator ->() { return &self; }
	const LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator &() const { return &self; }
	const LDKCOption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator ->() const { return &self; }
};
class CResult_ChannelReestablishDecodeErrorZ {
private:
	LDKCResult_ChannelReestablishDecodeErrorZ self;
public:
	CResult_ChannelReestablishDecodeErrorZ(const CResult_ChannelReestablishDecodeErrorZ&) = delete;
	CResult_ChannelReestablishDecodeErrorZ(CResult_ChannelReestablishDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelReestablishDecodeErrorZ)); }
	CResult_ChannelReestablishDecodeErrorZ(LDKCResult_ChannelReestablishDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelReestablishDecodeErrorZ)); }
	operator LDKCResult_ChannelReestablishDecodeErrorZ() && { LDKCResult_ChannelReestablishDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelReestablishDecodeErrorZ)); return res; }
	~CResult_ChannelReestablishDecodeErrorZ() { CResult_ChannelReestablishDecodeErrorZ_free(self); }
	CResult_ChannelReestablishDecodeErrorZ& operator=(CResult_ChannelReestablishDecodeErrorZ&& o) { CResult_ChannelReestablishDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelReestablishDecodeErrorZ)); return *this; }
	LDKCResult_ChannelReestablishDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelReestablishDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelReestablishDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelReestablishDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_UpdateAddHTLCZ {
private:
	LDKCVec_UpdateAddHTLCZ self;
public:
	CVec_UpdateAddHTLCZ(const CVec_UpdateAddHTLCZ&) = delete;
	CVec_UpdateAddHTLCZ(CVec_UpdateAddHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateAddHTLCZ)); }
	CVec_UpdateAddHTLCZ(LDKCVec_UpdateAddHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateAddHTLCZ)); }
	operator LDKCVec_UpdateAddHTLCZ() && { LDKCVec_UpdateAddHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateAddHTLCZ)); return res; }
	~CVec_UpdateAddHTLCZ() { CVec_UpdateAddHTLCZ_free(self); }
	CVec_UpdateAddHTLCZ& operator=(CVec_UpdateAddHTLCZ&& o) { CVec_UpdateAddHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateAddHTLCZ)); return *this; }
	LDKCVec_UpdateAddHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateAddHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateAddHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateAddHTLCZ* operator ->() const { return &self; }
};
class CResult_CommitmentSignedDecodeErrorZ {
private:
	LDKCResult_CommitmentSignedDecodeErrorZ self;
public:
	CResult_CommitmentSignedDecodeErrorZ(const CResult_CommitmentSignedDecodeErrorZ&) = delete;
	CResult_CommitmentSignedDecodeErrorZ(CResult_CommitmentSignedDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CommitmentSignedDecodeErrorZ)); }
	CResult_CommitmentSignedDecodeErrorZ(LDKCResult_CommitmentSignedDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CommitmentSignedDecodeErrorZ)); }
	operator LDKCResult_CommitmentSignedDecodeErrorZ() && { LDKCResult_CommitmentSignedDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CommitmentSignedDecodeErrorZ)); return res; }
	~CResult_CommitmentSignedDecodeErrorZ() { CResult_CommitmentSignedDecodeErrorZ_free(self); }
	CResult_CommitmentSignedDecodeErrorZ& operator=(CResult_CommitmentSignedDecodeErrorZ&& o) { CResult_CommitmentSignedDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CommitmentSignedDecodeErrorZ)); return *this; }
	LDKCResult_CommitmentSignedDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CommitmentSignedDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CommitmentSignedDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CommitmentSignedDecodeErrorZ* operator ->() const { return &self; }
};
class COption_u32Z {
private:
	LDKCOption_u32Z self;
public:
	COption_u32Z(const COption_u32Z&) = delete;
	COption_u32Z(COption_u32Z&& o) : self(o.self) { memset(&o, 0, sizeof(COption_u32Z)); }
	COption_u32Z(LDKCOption_u32Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_u32Z)); }
	operator LDKCOption_u32Z() && { LDKCOption_u32Z res = self; memset(&self, 0, sizeof(LDKCOption_u32Z)); return res; }
	~COption_u32Z() { COption_u32Z_free(self); }
	COption_u32Z& operator=(COption_u32Z&& o) { COption_u32Z_free(self); self = o.self; memset(&o, 0, sizeof(COption_u32Z)); return *this; }
	LDKCOption_u32Z* operator &() { return &self; }
	LDKCOption_u32Z* operator ->() { return &self; }
	const LDKCOption_u32Z* operator &() const { return &self; }
	const LDKCOption_u32Z* operator ->() const { return &self; }
};
class CResult_InitFeaturesDecodeErrorZ {
private:
	LDKCResult_InitFeaturesDecodeErrorZ self;
public:
	CResult_InitFeaturesDecodeErrorZ(const CResult_InitFeaturesDecodeErrorZ&) = delete;
	CResult_InitFeaturesDecodeErrorZ(CResult_InitFeaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InitFeaturesDecodeErrorZ)); }
	CResult_InitFeaturesDecodeErrorZ(LDKCResult_InitFeaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InitFeaturesDecodeErrorZ)); }
	operator LDKCResult_InitFeaturesDecodeErrorZ() && { LDKCResult_InitFeaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InitFeaturesDecodeErrorZ)); return res; }
	~CResult_InitFeaturesDecodeErrorZ() { CResult_InitFeaturesDecodeErrorZ_free(self); }
	CResult_InitFeaturesDecodeErrorZ& operator=(CResult_InitFeaturesDecodeErrorZ&& o) { CResult_InitFeaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InitFeaturesDecodeErrorZ)); return *this; }
	LDKCResult_InitFeaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InitFeaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InitFeaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InitFeaturesDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
private:
	LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ self;
public:
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ(const CResult_StaticPaymentOutputDescriptorDecodeErrorZ&) = delete;
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ(CResult_StaticPaymentOutputDescriptorDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_StaticPaymentOutputDescriptorDecodeErrorZ)); }
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ(LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ)); }
	operator LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ() && { LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ)); return res; }
	~CResult_StaticPaymentOutputDescriptorDecodeErrorZ() { CResult_StaticPaymentOutputDescriptorDecodeErrorZ_free(self); }
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ& operator=(CResult_StaticPaymentOutputDescriptorDecodeErrorZ&& o) { CResult_StaticPaymentOutputDescriptorDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_StaticPaymentOutputDescriptorDecodeErrorZ)); return *this; }
	LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ* operator &() { return &self; }
	LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_StaticPaymentOutputDescriptorDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PaymentIdPaymentSendFailureZ {
private:
	LDKCResult_PaymentIdPaymentSendFailureZ self;
public:
	CResult_PaymentIdPaymentSendFailureZ(const CResult_PaymentIdPaymentSendFailureZ&) = delete;
	CResult_PaymentIdPaymentSendFailureZ(CResult_PaymentIdPaymentSendFailureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentIdPaymentSendFailureZ)); }
	CResult_PaymentIdPaymentSendFailureZ(LDKCResult_PaymentIdPaymentSendFailureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentIdPaymentSendFailureZ)); }
	operator LDKCResult_PaymentIdPaymentSendFailureZ() && { LDKCResult_PaymentIdPaymentSendFailureZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentIdPaymentSendFailureZ)); return res; }
	~CResult_PaymentIdPaymentSendFailureZ() { CResult_PaymentIdPaymentSendFailureZ_free(self); }
	CResult_PaymentIdPaymentSendFailureZ& operator=(CResult_PaymentIdPaymentSendFailureZ&& o) { CResult_PaymentIdPaymentSendFailureZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentIdPaymentSendFailureZ)); return *this; }
	LDKCResult_PaymentIdPaymentSendFailureZ* operator &() { return &self; }
	LDKCResult_PaymentIdPaymentSendFailureZ* operator ->() { return &self; }
	const LDKCResult_PaymentIdPaymentSendFailureZ* operator &() const { return &self; }
	const LDKCResult_PaymentIdPaymentSendFailureZ* operator ->() const { return &self; }
};
class CResult_OnionMessageDecodeErrorZ {
private:
	LDKCResult_OnionMessageDecodeErrorZ self;
public:
	CResult_OnionMessageDecodeErrorZ(const CResult_OnionMessageDecodeErrorZ&) = delete;
	CResult_OnionMessageDecodeErrorZ(CResult_OnionMessageDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_OnionMessageDecodeErrorZ)); }
	CResult_OnionMessageDecodeErrorZ(LDKCResult_OnionMessageDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_OnionMessageDecodeErrorZ)); }
	operator LDKCResult_OnionMessageDecodeErrorZ() && { LDKCResult_OnionMessageDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_OnionMessageDecodeErrorZ)); return res; }
	~CResult_OnionMessageDecodeErrorZ() { CResult_OnionMessageDecodeErrorZ_free(self); }
	CResult_OnionMessageDecodeErrorZ& operator=(CResult_OnionMessageDecodeErrorZ&& o) { CResult_OnionMessageDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_OnionMessageDecodeErrorZ)); return *this; }
	LDKCResult_OnionMessageDecodeErrorZ* operator &() { return &self; }
	LDKCResult_OnionMessageDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_OnionMessageDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_OnionMessageDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CommitmentTransactionDecodeErrorZ {
private:
	LDKCResult_CommitmentTransactionDecodeErrorZ self;
public:
	CResult_CommitmentTransactionDecodeErrorZ(const CResult_CommitmentTransactionDecodeErrorZ&) = delete;
	CResult_CommitmentTransactionDecodeErrorZ(CResult_CommitmentTransactionDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CommitmentTransactionDecodeErrorZ)); }
	CResult_CommitmentTransactionDecodeErrorZ(LDKCResult_CommitmentTransactionDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CommitmentTransactionDecodeErrorZ)); }
	operator LDKCResult_CommitmentTransactionDecodeErrorZ() && { LDKCResult_CommitmentTransactionDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CommitmentTransactionDecodeErrorZ)); return res; }
	~CResult_CommitmentTransactionDecodeErrorZ() { CResult_CommitmentTransactionDecodeErrorZ_free(self); }
	CResult_CommitmentTransactionDecodeErrorZ& operator=(CResult_CommitmentTransactionDecodeErrorZ&& o) { CResult_CommitmentTransactionDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CommitmentTransactionDecodeErrorZ)); return *this; }
	LDKCResult_CommitmentTransactionDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CommitmentTransactionDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CommitmentTransactionDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CommitmentTransactionDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_TransactionNoneZ {
private:
	LDKCResult_TransactionNoneZ self;
public:
	CResult_TransactionNoneZ(const CResult_TransactionNoneZ&) = delete;
	CResult_TransactionNoneZ(CResult_TransactionNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TransactionNoneZ)); }
	CResult_TransactionNoneZ(LDKCResult_TransactionNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TransactionNoneZ)); }
	operator LDKCResult_TransactionNoneZ() && { LDKCResult_TransactionNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_TransactionNoneZ)); return res; }
	~CResult_TransactionNoneZ() { CResult_TransactionNoneZ_free(self); }
	CResult_TransactionNoneZ& operator=(CResult_TransactionNoneZ&& o) { CResult_TransactionNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TransactionNoneZ)); return *this; }
	LDKCResult_TransactionNoneZ* operator &() { return &self; }
	LDKCResult_TransactionNoneZ* operator ->() { return &self; }
	const LDKCResult_TransactionNoneZ* operator &() const { return &self; }
	const LDKCResult_TransactionNoneZ* operator ->() const { return &self; }
};
class CResult_ClosingSignedFeeRangeDecodeErrorZ {
private:
	LDKCResult_ClosingSignedFeeRangeDecodeErrorZ self;
public:
	CResult_ClosingSignedFeeRangeDecodeErrorZ(const CResult_ClosingSignedFeeRangeDecodeErrorZ&) = delete;
	CResult_ClosingSignedFeeRangeDecodeErrorZ(CResult_ClosingSignedFeeRangeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ClosingSignedFeeRangeDecodeErrorZ)); }
	CResult_ClosingSignedFeeRangeDecodeErrorZ(LDKCResult_ClosingSignedFeeRangeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ClosingSignedFeeRangeDecodeErrorZ)); }
	operator LDKCResult_ClosingSignedFeeRangeDecodeErrorZ() && { LDKCResult_ClosingSignedFeeRangeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ClosingSignedFeeRangeDecodeErrorZ)); return res; }
	~CResult_ClosingSignedFeeRangeDecodeErrorZ() { CResult_ClosingSignedFeeRangeDecodeErrorZ_free(self); }
	CResult_ClosingSignedFeeRangeDecodeErrorZ& operator=(CResult_ClosingSignedFeeRangeDecodeErrorZ&& o) { CResult_ClosingSignedFeeRangeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ClosingSignedFeeRangeDecodeErrorZ)); return *this; }
	LDKCResult_ClosingSignedFeeRangeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ClosingSignedFeeRangeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ClosingSignedFeeRangeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ClosingSignedFeeRangeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PingDecodeErrorZ {
private:
	LDKCResult_PingDecodeErrorZ self;
public:
	CResult_PingDecodeErrorZ(const CResult_PingDecodeErrorZ&) = delete;
	CResult_PingDecodeErrorZ(CResult_PingDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PingDecodeErrorZ)); }
	CResult_PingDecodeErrorZ(LDKCResult_PingDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PingDecodeErrorZ)); }
	operator LDKCResult_PingDecodeErrorZ() && { LDKCResult_PingDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PingDecodeErrorZ)); return res; }
	~CResult_PingDecodeErrorZ() { CResult_PingDecodeErrorZ_free(self); }
	CResult_PingDecodeErrorZ& operator=(CResult_PingDecodeErrorZ&& o) { CResult_PingDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PingDecodeErrorZ)); return *this; }
	LDKCResult_PingDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PingDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PingDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PingDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_UnsignedNodeAnnouncementDecodeErrorZ {
private:
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ self;
public:
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(const CResult_UnsignedNodeAnnouncementDecodeErrorZ&) = delete;
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(CResult_UnsignedNodeAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedNodeAnnouncementDecodeErrorZ)); }
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ)); }
	operator LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ() && { LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ)); return res; }
	~CResult_UnsignedNodeAnnouncementDecodeErrorZ() { CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(self); }
	CResult_UnsignedNodeAnnouncementDecodeErrorZ& operator=(CResult_UnsignedNodeAnnouncementDecodeErrorZ&& o) { CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedNodeAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ReplyChannelRangeDecodeErrorZ {
private:
	LDKCResult_ReplyChannelRangeDecodeErrorZ self;
public:
	CResult_ReplyChannelRangeDecodeErrorZ(const CResult_ReplyChannelRangeDecodeErrorZ&) = delete;
	CResult_ReplyChannelRangeDecodeErrorZ(CResult_ReplyChannelRangeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ReplyChannelRangeDecodeErrorZ)); }
	CResult_ReplyChannelRangeDecodeErrorZ(LDKCResult_ReplyChannelRangeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ReplyChannelRangeDecodeErrorZ)); }
	operator LDKCResult_ReplyChannelRangeDecodeErrorZ() && { LDKCResult_ReplyChannelRangeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ReplyChannelRangeDecodeErrorZ)); return res; }
	~CResult_ReplyChannelRangeDecodeErrorZ() { CResult_ReplyChannelRangeDecodeErrorZ_free(self); }
	CResult_ReplyChannelRangeDecodeErrorZ& operator=(CResult_ReplyChannelRangeDecodeErrorZ&& o) { CResult_ReplyChannelRangeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ReplyChannelRangeDecodeErrorZ)); return *this; }
	LDKCResult_ReplyChannelRangeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ReplyChannelRangeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ReplyChannelRangeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ReplyChannelRangeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_GossipTimestampFilterDecodeErrorZ {
private:
	LDKCResult_GossipTimestampFilterDecodeErrorZ self;
public:
	CResult_GossipTimestampFilterDecodeErrorZ(const CResult_GossipTimestampFilterDecodeErrorZ&) = delete;
	CResult_GossipTimestampFilterDecodeErrorZ(CResult_GossipTimestampFilterDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_GossipTimestampFilterDecodeErrorZ)); }
	CResult_GossipTimestampFilterDecodeErrorZ(LDKCResult_GossipTimestampFilterDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_GossipTimestampFilterDecodeErrorZ)); }
	operator LDKCResult_GossipTimestampFilterDecodeErrorZ() && { LDKCResult_GossipTimestampFilterDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_GossipTimestampFilterDecodeErrorZ)); return res; }
	~CResult_GossipTimestampFilterDecodeErrorZ() { CResult_GossipTimestampFilterDecodeErrorZ_free(self); }
	CResult_GossipTimestampFilterDecodeErrorZ& operator=(CResult_GossipTimestampFilterDecodeErrorZ&& o) { CResult_GossipTimestampFilterDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_GossipTimestampFilterDecodeErrorZ)); return *this; }
	LDKCResult_GossipTimestampFilterDecodeErrorZ* operator &() { return &self; }
	LDKCResult_GossipTimestampFilterDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_GossipTimestampFilterDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_GossipTimestampFilterDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_InvoiceSignOrCreationErrorZ {
private:
	LDKCResult_InvoiceSignOrCreationErrorZ self;
public:
	CResult_InvoiceSignOrCreationErrorZ(const CResult_InvoiceSignOrCreationErrorZ&) = delete;
	CResult_InvoiceSignOrCreationErrorZ(CResult_InvoiceSignOrCreationErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InvoiceSignOrCreationErrorZ)); }
	CResult_InvoiceSignOrCreationErrorZ(LDKCResult_InvoiceSignOrCreationErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InvoiceSignOrCreationErrorZ)); }
	operator LDKCResult_InvoiceSignOrCreationErrorZ() && { LDKCResult_InvoiceSignOrCreationErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InvoiceSignOrCreationErrorZ)); return res; }
	~CResult_InvoiceSignOrCreationErrorZ() { CResult_InvoiceSignOrCreationErrorZ_free(self); }
	CResult_InvoiceSignOrCreationErrorZ& operator=(CResult_InvoiceSignOrCreationErrorZ&& o) { CResult_InvoiceSignOrCreationErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InvoiceSignOrCreationErrorZ)); return *this; }
	LDKCResult_InvoiceSignOrCreationErrorZ* operator &() { return &self; }
	LDKCResult_InvoiceSignOrCreationErrorZ* operator ->() { return &self; }
	const LDKCResult_InvoiceSignOrCreationErrorZ* operator &() const { return &self; }
	const LDKCResult_InvoiceSignOrCreationErrorZ* operator ->() const { return &self; }
};
class CVec_TransactionOutputsZ {
private:
	LDKCVec_TransactionOutputsZ self;
public:
	CVec_TransactionOutputsZ(const CVec_TransactionOutputsZ&) = delete;
	CVec_TransactionOutputsZ(CVec_TransactionOutputsZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_TransactionOutputsZ)); }
	CVec_TransactionOutputsZ(LDKCVec_TransactionOutputsZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_TransactionOutputsZ)); }
	operator LDKCVec_TransactionOutputsZ() && { LDKCVec_TransactionOutputsZ res = self; memset(&self, 0, sizeof(LDKCVec_TransactionOutputsZ)); return res; }
	~CVec_TransactionOutputsZ() { CVec_TransactionOutputsZ_free(self); }
	CVec_TransactionOutputsZ& operator=(CVec_TransactionOutputsZ&& o) { CVec_TransactionOutputsZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_TransactionOutputsZ)); return *this; }
	LDKCVec_TransactionOutputsZ* operator &() { return &self; }
	LDKCVec_TransactionOutputsZ* operator ->() { return &self; }
	const LDKCVec_TransactionOutputsZ* operator &() const { return &self; }
	const LDKCVec_TransactionOutputsZ* operator ->() const { return &self; }
};
class CResult_ErrorMessageDecodeErrorZ {
private:
	LDKCResult_ErrorMessageDecodeErrorZ self;
public:
	CResult_ErrorMessageDecodeErrorZ(const CResult_ErrorMessageDecodeErrorZ&) = delete;
	CResult_ErrorMessageDecodeErrorZ(CResult_ErrorMessageDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ErrorMessageDecodeErrorZ)); }
	CResult_ErrorMessageDecodeErrorZ(LDKCResult_ErrorMessageDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ErrorMessageDecodeErrorZ)); }
	operator LDKCResult_ErrorMessageDecodeErrorZ() && { LDKCResult_ErrorMessageDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ErrorMessageDecodeErrorZ)); return res; }
	~CResult_ErrorMessageDecodeErrorZ() { CResult_ErrorMessageDecodeErrorZ_free(self); }
	CResult_ErrorMessageDecodeErrorZ& operator=(CResult_ErrorMessageDecodeErrorZ&& o) { CResult_ErrorMessageDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ErrorMessageDecodeErrorZ)); return *this; }
	LDKCResult_ErrorMessageDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ErrorMessageDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ErrorMessageDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ErrorMessageDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_OpenChannelDecodeErrorZ {
private:
	LDKCResult_OpenChannelDecodeErrorZ self;
public:
	CResult_OpenChannelDecodeErrorZ(const CResult_OpenChannelDecodeErrorZ&) = delete;
	CResult_OpenChannelDecodeErrorZ(CResult_OpenChannelDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_OpenChannelDecodeErrorZ)); }
	CResult_OpenChannelDecodeErrorZ(LDKCResult_OpenChannelDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_OpenChannelDecodeErrorZ)); }
	operator LDKCResult_OpenChannelDecodeErrorZ() && { LDKCResult_OpenChannelDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_OpenChannelDecodeErrorZ)); return res; }
	~CResult_OpenChannelDecodeErrorZ() { CResult_OpenChannelDecodeErrorZ_free(self); }
	CResult_OpenChannelDecodeErrorZ& operator=(CResult_OpenChannelDecodeErrorZ&& o) { CResult_OpenChannelDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_OpenChannelDecodeErrorZ)); return *this; }
	LDKCResult_OpenChannelDecodeErrorZ* operator &() { return &self; }
	LDKCResult_OpenChannelDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_OpenChannelDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_OpenChannelDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_CVec_u8ZZ {
private:
	LDKCVec_CVec_u8ZZ self;
public:
	CVec_CVec_u8ZZ(const CVec_CVec_u8ZZ&) = delete;
	CVec_CVec_u8ZZ(CVec_CVec_u8ZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_CVec_u8ZZ)); }
	CVec_CVec_u8ZZ(LDKCVec_CVec_u8ZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_CVec_u8ZZ)); }
	operator LDKCVec_CVec_u8ZZ() && { LDKCVec_CVec_u8ZZ res = self; memset(&self, 0, sizeof(LDKCVec_CVec_u8ZZ)); return res; }
	~CVec_CVec_u8ZZ() { CVec_CVec_u8ZZ_free(self); }
	CVec_CVec_u8ZZ& operator=(CVec_CVec_u8ZZ&& o) { CVec_CVec_u8ZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_CVec_u8ZZ)); return *this; }
	LDKCVec_CVec_u8ZZ* operator &() { return &self; }
	LDKCVec_CVec_u8ZZ* operator ->() { return &self; }
	const LDKCVec_CVec_u8ZZ* operator &() const { return &self; }
	const LDKCVec_CVec_u8ZZ* operator ->() const { return &self; }
};
class COption_FilterZ {
private:
	LDKCOption_FilterZ self;
public:
	COption_FilterZ(const COption_FilterZ&) = delete;
	COption_FilterZ(COption_FilterZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_FilterZ)); }
	COption_FilterZ(LDKCOption_FilterZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_FilterZ)); }
	operator LDKCOption_FilterZ() && { LDKCOption_FilterZ res = self; memset(&self, 0, sizeof(LDKCOption_FilterZ)); return res; }
	~COption_FilterZ() { COption_FilterZ_free(self); }
	COption_FilterZ& operator=(COption_FilterZ&& o) { COption_FilterZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_FilterZ)); return *this; }
	LDKCOption_FilterZ* operator &() { return &self; }
	LDKCOption_FilterZ* operator ->() { return &self; }
	const LDKCOption_FilterZ* operator &() const { return &self; }
	const LDKCOption_FilterZ* operator ->() const { return &self; }
};
class CResult_SecretKeyErrorZ {
private:
	LDKCResult_SecretKeyErrorZ self;
public:
	CResult_SecretKeyErrorZ(const CResult_SecretKeyErrorZ&) = delete;
	CResult_SecretKeyErrorZ(CResult_SecretKeyErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SecretKeyErrorZ)); }
	CResult_SecretKeyErrorZ(LDKCResult_SecretKeyErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SecretKeyErrorZ)); }
	operator LDKCResult_SecretKeyErrorZ() && { LDKCResult_SecretKeyErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SecretKeyErrorZ)); return res; }
	~CResult_SecretKeyErrorZ() { CResult_SecretKeyErrorZ_free(self); }
	CResult_SecretKeyErrorZ& operator=(CResult_SecretKeyErrorZ&& o) { CResult_SecretKeyErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SecretKeyErrorZ)); return *this; }
	LDKCResult_SecretKeyErrorZ* operator &() { return &self; }
	LDKCResult_SecretKeyErrorZ* operator ->() { return &self; }
	const LDKCResult_SecretKeyErrorZ* operator &() const { return &self; }
	const LDKCResult_SecretKeyErrorZ* operator ->() const { return &self; }
};
class CResult_ShutdownScriptDecodeErrorZ {
private:
	LDKCResult_ShutdownScriptDecodeErrorZ self;
public:
	CResult_ShutdownScriptDecodeErrorZ(const CResult_ShutdownScriptDecodeErrorZ&) = delete;
	CResult_ShutdownScriptDecodeErrorZ(CResult_ShutdownScriptDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ShutdownScriptDecodeErrorZ)); }
	CResult_ShutdownScriptDecodeErrorZ(LDKCResult_ShutdownScriptDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ShutdownScriptDecodeErrorZ)); }
	operator LDKCResult_ShutdownScriptDecodeErrorZ() && { LDKCResult_ShutdownScriptDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ShutdownScriptDecodeErrorZ)); return res; }
	~CResult_ShutdownScriptDecodeErrorZ() { CResult_ShutdownScriptDecodeErrorZ_free(self); }
	CResult_ShutdownScriptDecodeErrorZ& operator=(CResult_ShutdownScriptDecodeErrorZ&& o) { CResult_ShutdownScriptDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ShutdownScriptDecodeErrorZ)); return *this; }
	LDKCResult_ShutdownScriptDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ShutdownScriptDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ShutdownScriptDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ShutdownScriptDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ProbabilisticScorerDecodeErrorZ {
private:
	LDKCResult_ProbabilisticScorerDecodeErrorZ self;
public:
	CResult_ProbabilisticScorerDecodeErrorZ(const CResult_ProbabilisticScorerDecodeErrorZ&) = delete;
	CResult_ProbabilisticScorerDecodeErrorZ(CResult_ProbabilisticScorerDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ProbabilisticScorerDecodeErrorZ)); }
	CResult_ProbabilisticScorerDecodeErrorZ(LDKCResult_ProbabilisticScorerDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ProbabilisticScorerDecodeErrorZ)); }
	operator LDKCResult_ProbabilisticScorerDecodeErrorZ() && { LDKCResult_ProbabilisticScorerDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ProbabilisticScorerDecodeErrorZ)); return res; }
	~CResult_ProbabilisticScorerDecodeErrorZ() { CResult_ProbabilisticScorerDecodeErrorZ_free(self); }
	CResult_ProbabilisticScorerDecodeErrorZ& operator=(CResult_ProbabilisticScorerDecodeErrorZ&& o) { CResult_ProbabilisticScorerDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ProbabilisticScorerDecodeErrorZ)); return *this; }
	LDKCResult_ProbabilisticScorerDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ProbabilisticScorerDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ProbabilisticScorerDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ProbabilisticScorerDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_QueryChannelRangeDecodeErrorZ {
private:
	LDKCResult_QueryChannelRangeDecodeErrorZ self;
public:
	CResult_QueryChannelRangeDecodeErrorZ(const CResult_QueryChannelRangeDecodeErrorZ&) = delete;
	CResult_QueryChannelRangeDecodeErrorZ(CResult_QueryChannelRangeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_QueryChannelRangeDecodeErrorZ)); }
	CResult_QueryChannelRangeDecodeErrorZ(LDKCResult_QueryChannelRangeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_QueryChannelRangeDecodeErrorZ)); }
	operator LDKCResult_QueryChannelRangeDecodeErrorZ() && { LDKCResult_QueryChannelRangeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_QueryChannelRangeDecodeErrorZ)); return res; }
	~CResult_QueryChannelRangeDecodeErrorZ() { CResult_QueryChannelRangeDecodeErrorZ_free(self); }
	CResult_QueryChannelRangeDecodeErrorZ& operator=(CResult_QueryChannelRangeDecodeErrorZ&& o) { CResult_QueryChannelRangeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_QueryChannelRangeDecodeErrorZ)); return *this; }
	LDKCResult_QueryChannelRangeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_QueryChannelRangeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_QueryChannelRangeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_QueryChannelRangeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_TxCreationKeysDecodeErrorZ {
private:
	LDKCResult_TxCreationKeysDecodeErrorZ self;
public:
	CResult_TxCreationKeysDecodeErrorZ(const CResult_TxCreationKeysDecodeErrorZ&) = delete;
	CResult_TxCreationKeysDecodeErrorZ(CResult_TxCreationKeysDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TxCreationKeysDecodeErrorZ)); }
	CResult_TxCreationKeysDecodeErrorZ(LDKCResult_TxCreationKeysDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TxCreationKeysDecodeErrorZ)); }
	operator LDKCResult_TxCreationKeysDecodeErrorZ() && { LDKCResult_TxCreationKeysDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_TxCreationKeysDecodeErrorZ)); return res; }
	~CResult_TxCreationKeysDecodeErrorZ() { CResult_TxCreationKeysDecodeErrorZ_free(self); }
	CResult_TxCreationKeysDecodeErrorZ& operator=(CResult_TxCreationKeysDecodeErrorZ&& o) { CResult_TxCreationKeysDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TxCreationKeysDecodeErrorZ)); return *this; }
	LDKCResult_TxCreationKeysDecodeErrorZ* operator &() { return &self; }
	LDKCResult_TxCreationKeysDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_TxCreationKeysDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_TxCreationKeysDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_usizeTransactionZ {
private:
	LDKC2Tuple_usizeTransactionZ self;
public:
	C2Tuple_usizeTransactionZ(const C2Tuple_usizeTransactionZ&) = delete;
	C2Tuple_usizeTransactionZ(C2Tuple_usizeTransactionZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_usizeTransactionZ)); }
	C2Tuple_usizeTransactionZ(LDKC2Tuple_usizeTransactionZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_usizeTransactionZ)); }
	operator LDKC2Tuple_usizeTransactionZ() && { LDKC2Tuple_usizeTransactionZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_usizeTransactionZ)); return res; }
	~C2Tuple_usizeTransactionZ() { C2Tuple_usizeTransactionZ_free(self); }
	C2Tuple_usizeTransactionZ& operator=(C2Tuple_usizeTransactionZ&& o) { C2Tuple_usizeTransactionZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_usizeTransactionZ)); return *this; }
	LDKC2Tuple_usizeTransactionZ* operator &() { return &self; }
	LDKC2Tuple_usizeTransactionZ* operator ->() { return &self; }
	const LDKC2Tuple_usizeTransactionZ* operator &() const { return &self; }
	const LDKC2Tuple_usizeTransactionZ* operator ->() const { return &self; }
};
class CResult_ChannelFeaturesDecodeErrorZ {
private:
	LDKCResult_ChannelFeaturesDecodeErrorZ self;
public:
	CResult_ChannelFeaturesDecodeErrorZ(const CResult_ChannelFeaturesDecodeErrorZ&) = delete;
	CResult_ChannelFeaturesDecodeErrorZ(CResult_ChannelFeaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelFeaturesDecodeErrorZ)); }
	CResult_ChannelFeaturesDecodeErrorZ(LDKCResult_ChannelFeaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelFeaturesDecodeErrorZ)); }
	operator LDKCResult_ChannelFeaturesDecodeErrorZ() && { LDKCResult_ChannelFeaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelFeaturesDecodeErrorZ)); return res; }
	~CResult_ChannelFeaturesDecodeErrorZ() { CResult_ChannelFeaturesDecodeErrorZ_free(self); }
	CResult_ChannelFeaturesDecodeErrorZ& operator=(CResult_ChannelFeaturesDecodeErrorZ&& o) { CResult_ChannelFeaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelFeaturesDecodeErrorZ)); return *this; }
	LDKCResult_ChannelFeaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelFeaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelFeaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelFeaturesDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_ChannelMonitorZ {
private:
	LDKCVec_ChannelMonitorZ self;
public:
	CVec_ChannelMonitorZ(const CVec_ChannelMonitorZ&) = delete;
	CVec_ChannelMonitorZ(CVec_ChannelMonitorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_ChannelMonitorZ)); }
	CVec_ChannelMonitorZ(LDKCVec_ChannelMonitorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_ChannelMonitorZ)); }
	operator LDKCVec_ChannelMonitorZ() && { LDKCVec_ChannelMonitorZ res = self; memset(&self, 0, sizeof(LDKCVec_ChannelMonitorZ)); return res; }
	~CVec_ChannelMonitorZ() { CVec_ChannelMonitorZ_free(self); }
	CVec_ChannelMonitorZ& operator=(CVec_ChannelMonitorZ&& o) { CVec_ChannelMonitorZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_ChannelMonitorZ)); return *this; }
	LDKCVec_ChannelMonitorZ* operator &() { return &self; }
	LDKCVec_ChannelMonitorZ* operator ->() { return &self; }
	const LDKCVec_ChannelMonitorZ* operator &() const { return &self; }
	const LDKCVec_ChannelMonitorZ* operator ->() const { return &self; }
};
class CVec_TransactionZ {
private:
	LDKCVec_TransactionZ self;
public:
	CVec_TransactionZ(const CVec_TransactionZ&) = delete;
	CVec_TransactionZ(CVec_TransactionZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_TransactionZ)); }
	CVec_TransactionZ(LDKCVec_TransactionZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_TransactionZ)); }
	operator LDKCVec_TransactionZ() && { LDKCVec_TransactionZ res = self; memset(&self, 0, sizeof(LDKCVec_TransactionZ)); return res; }
	~CVec_TransactionZ() { CVec_TransactionZ_free(self); }
	CVec_TransactionZ& operator=(CVec_TransactionZ&& o) { CVec_TransactionZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_TransactionZ)); return *this; }
	LDKCVec_TransactionZ* operator &() { return &self; }
	LDKCVec_TransactionZ* operator ->() { return &self; }
	const LDKCVec_TransactionZ* operator &() const { return &self; }
	const LDKCVec_TransactionZ* operator ->() const { return &self; }
};
class CResult_ChannelReadyDecodeErrorZ {
private:
	LDKCResult_ChannelReadyDecodeErrorZ self;
public:
	CResult_ChannelReadyDecodeErrorZ(const CResult_ChannelReadyDecodeErrorZ&) = delete;
	CResult_ChannelReadyDecodeErrorZ(CResult_ChannelReadyDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelReadyDecodeErrorZ)); }
	CResult_ChannelReadyDecodeErrorZ(LDKCResult_ChannelReadyDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelReadyDecodeErrorZ)); }
	operator LDKCResult_ChannelReadyDecodeErrorZ() && { LDKCResult_ChannelReadyDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelReadyDecodeErrorZ)); return res; }
	~CResult_ChannelReadyDecodeErrorZ() { CResult_ChannelReadyDecodeErrorZ_free(self); }
	CResult_ChannelReadyDecodeErrorZ& operator=(CResult_ChannelReadyDecodeErrorZ&& o) { CResult_ChannelReadyDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelReadyDecodeErrorZ)); return *this; }
	LDKCResult_ChannelReadyDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelReadyDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelReadyDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelReadyDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RouteHopDecodeErrorZ {
private:
	LDKCResult_RouteHopDecodeErrorZ self;
public:
	CResult_RouteHopDecodeErrorZ(const CResult_RouteHopDecodeErrorZ&) = delete;
	CResult_RouteHopDecodeErrorZ(CResult_RouteHopDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteHopDecodeErrorZ)); }
	CResult_RouteHopDecodeErrorZ(LDKCResult_RouteHopDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteHopDecodeErrorZ)); }
	operator LDKCResult_RouteHopDecodeErrorZ() && { LDKCResult_RouteHopDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteHopDecodeErrorZ)); return res; }
	~CResult_RouteHopDecodeErrorZ() { CResult_RouteHopDecodeErrorZ_free(self); }
	CResult_RouteHopDecodeErrorZ& operator=(CResult_RouteHopDecodeErrorZ&& o) { CResult_RouteHopDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteHopDecodeErrorZ)); return *this; }
	LDKCResult_RouteHopDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteHopDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteHopDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteHopDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_UpdateFeeDecodeErrorZ {
private:
	LDKCResult_UpdateFeeDecodeErrorZ self;
public:
	CResult_UpdateFeeDecodeErrorZ(const CResult_UpdateFeeDecodeErrorZ&) = delete;
	CResult_UpdateFeeDecodeErrorZ(CResult_UpdateFeeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UpdateFeeDecodeErrorZ)); }
	CResult_UpdateFeeDecodeErrorZ(LDKCResult_UpdateFeeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UpdateFeeDecodeErrorZ)); }
	operator LDKCResult_UpdateFeeDecodeErrorZ() && { LDKCResult_UpdateFeeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UpdateFeeDecodeErrorZ)); return res; }
	~CResult_UpdateFeeDecodeErrorZ() { CResult_UpdateFeeDecodeErrorZ_free(self); }
	CResult_UpdateFeeDecodeErrorZ& operator=(CResult_UpdateFeeDecodeErrorZ&& o) { CResult_UpdateFeeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UpdateFeeDecodeErrorZ)); return *this; }
	LDKCResult_UpdateFeeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UpdateFeeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UpdateFeeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UpdateFeeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NodeAnnouncementDecodeErrorZ {
private:
	LDKCResult_NodeAnnouncementDecodeErrorZ self;
public:
	CResult_NodeAnnouncementDecodeErrorZ(const CResult_NodeAnnouncementDecodeErrorZ&) = delete;
	CResult_NodeAnnouncementDecodeErrorZ(CResult_NodeAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeAnnouncementDecodeErrorZ)); }
	CResult_NodeAnnouncementDecodeErrorZ(LDKCResult_NodeAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeAnnouncementDecodeErrorZ)); }
	operator LDKCResult_NodeAnnouncementDecodeErrorZ() && { LDKCResult_NodeAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeAnnouncementDecodeErrorZ)); return res; }
	~CResult_NodeAnnouncementDecodeErrorZ() { CResult_NodeAnnouncementDecodeErrorZ_free(self); }
	CResult_NodeAnnouncementDecodeErrorZ& operator=(CResult_NodeAnnouncementDecodeErrorZ&& o) { CResult_NodeAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_NodeAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_BalanceZ {
private:
	LDKCVec_BalanceZ self;
public:
	CVec_BalanceZ(const CVec_BalanceZ&) = delete;
	CVec_BalanceZ(CVec_BalanceZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_BalanceZ)); }
	CVec_BalanceZ(LDKCVec_BalanceZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_BalanceZ)); }
	operator LDKCVec_BalanceZ() && { LDKCVec_BalanceZ res = self; memset(&self, 0, sizeof(LDKCVec_BalanceZ)); return res; }
	~CVec_BalanceZ() { CVec_BalanceZ_free(self); }
	CVec_BalanceZ& operator=(CVec_BalanceZ&& o) { CVec_BalanceZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_BalanceZ)); return *this; }
	LDKCVec_BalanceZ* operator &() { return &self; }
	LDKCVec_BalanceZ* operator ->() { return &self; }
	const LDKCVec_BalanceZ* operator &() const { return &self; }
	const LDKCVec_BalanceZ* operator ->() const { return &self; }
};
class CResult_HTLCOutputInCommitmentDecodeErrorZ {
private:
	LDKCResult_HTLCOutputInCommitmentDecodeErrorZ self;
public:
	CResult_HTLCOutputInCommitmentDecodeErrorZ(const CResult_HTLCOutputInCommitmentDecodeErrorZ&) = delete;
	CResult_HTLCOutputInCommitmentDecodeErrorZ(CResult_HTLCOutputInCommitmentDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_HTLCOutputInCommitmentDecodeErrorZ)); }
	CResult_HTLCOutputInCommitmentDecodeErrorZ(LDKCResult_HTLCOutputInCommitmentDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_HTLCOutputInCommitmentDecodeErrorZ)); }
	operator LDKCResult_HTLCOutputInCommitmentDecodeErrorZ() && { LDKCResult_HTLCOutputInCommitmentDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_HTLCOutputInCommitmentDecodeErrorZ)); return res; }
	~CResult_HTLCOutputInCommitmentDecodeErrorZ() { CResult_HTLCOutputInCommitmentDecodeErrorZ_free(self); }
	CResult_HTLCOutputInCommitmentDecodeErrorZ& operator=(CResult_HTLCOutputInCommitmentDecodeErrorZ&& o) { CResult_HTLCOutputInCommitmentDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_HTLCOutputInCommitmentDecodeErrorZ)); return *this; }
	LDKCResult_HTLCOutputInCommitmentDecodeErrorZ* operator &() { return &self; }
	LDKCResult_HTLCOutputInCommitmentDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_HTLCOutputInCommitmentDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_HTLCOutputInCommitmentDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_boolLightningErrorZ {
private:
	LDKCResult_boolLightningErrorZ self;
public:
	CResult_boolLightningErrorZ(const CResult_boolLightningErrorZ&) = delete;
	CResult_boolLightningErrorZ(CResult_boolLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_boolLightningErrorZ)); }
	CResult_boolLightningErrorZ(LDKCResult_boolLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_boolLightningErrorZ)); }
	operator LDKCResult_boolLightningErrorZ() && { LDKCResult_boolLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_boolLightningErrorZ)); return res; }
	~CResult_boolLightningErrorZ() { CResult_boolLightningErrorZ_free(self); }
	CResult_boolLightningErrorZ& operator=(CResult_boolLightningErrorZ&& o) { CResult_boolLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_boolLightningErrorZ)); return *this; }
	LDKCResult_boolLightningErrorZ* operator &() { return &self; }
	LDKCResult_boolLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_boolLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_boolLightningErrorZ* operator ->() const { return &self; }
};
class CResult_TxCreationKeysErrorZ {
private:
	LDKCResult_TxCreationKeysErrorZ self;
public:
	CResult_TxCreationKeysErrorZ(const CResult_TxCreationKeysErrorZ&) = delete;
	CResult_TxCreationKeysErrorZ(CResult_TxCreationKeysErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TxCreationKeysErrorZ)); }
	CResult_TxCreationKeysErrorZ(LDKCResult_TxCreationKeysErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TxCreationKeysErrorZ)); }
	operator LDKCResult_TxCreationKeysErrorZ() && { LDKCResult_TxCreationKeysErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_TxCreationKeysErrorZ)); return res; }
	~CResult_TxCreationKeysErrorZ() { CResult_TxCreationKeysErrorZ_free(self); }
	CResult_TxCreationKeysErrorZ& operator=(CResult_TxCreationKeysErrorZ&& o) { CResult_TxCreationKeysErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TxCreationKeysErrorZ)); return *this; }
	LDKCResult_TxCreationKeysErrorZ* operator &() { return &self; }
	LDKCResult_TxCreationKeysErrorZ* operator ->() { return &self; }
	const LDKCResult_TxCreationKeysErrorZ* operator &() const { return &self; }
	const LDKCResult_TxCreationKeysErrorZ* operator ->() const { return &self; }
};
class COption_HTLCDestinationZ {
private:
	LDKCOption_HTLCDestinationZ self;
public:
	COption_HTLCDestinationZ(const COption_HTLCDestinationZ&) = delete;
	COption_HTLCDestinationZ(COption_HTLCDestinationZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_HTLCDestinationZ)); }
	COption_HTLCDestinationZ(LDKCOption_HTLCDestinationZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_HTLCDestinationZ)); }
	operator LDKCOption_HTLCDestinationZ() && { LDKCOption_HTLCDestinationZ res = self; memset(&self, 0, sizeof(LDKCOption_HTLCDestinationZ)); return res; }
	~COption_HTLCDestinationZ() { COption_HTLCDestinationZ_free(self); }
	COption_HTLCDestinationZ& operator=(COption_HTLCDestinationZ&& o) { COption_HTLCDestinationZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_HTLCDestinationZ)); return *this; }
	LDKCOption_HTLCDestinationZ* operator &() { return &self; }
	LDKCOption_HTLCDestinationZ* operator ->() { return &self; }
	const LDKCOption_HTLCDestinationZ* operator &() const { return &self; }
	const LDKCOption_HTLCDestinationZ* operator ->() const { return &self; }
};
class CResult_NodeIdDecodeErrorZ {
private:
	LDKCResult_NodeIdDecodeErrorZ self;
public:
	CResult_NodeIdDecodeErrorZ(const CResult_NodeIdDecodeErrorZ&) = delete;
	CResult_NodeIdDecodeErrorZ(CResult_NodeIdDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeIdDecodeErrorZ)); }
	CResult_NodeIdDecodeErrorZ(LDKCResult_NodeIdDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeIdDecodeErrorZ)); }
	operator LDKCResult_NodeIdDecodeErrorZ() && { LDKCResult_NodeIdDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeIdDecodeErrorZ)); return res; }
	~CResult_NodeIdDecodeErrorZ() { CResult_NodeIdDecodeErrorZ_free(self); }
	CResult_NodeIdDecodeErrorZ& operator=(CResult_NodeIdDecodeErrorZ&& o) { CResult_NodeIdDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeIdDecodeErrorZ)); return *this; }
	LDKCResult_NodeIdDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeIdDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeIdDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeIdDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ShutdownScriptInvalidShutdownScriptZ {
private:
	LDKCResult_ShutdownScriptInvalidShutdownScriptZ self;
public:
	CResult_ShutdownScriptInvalidShutdownScriptZ(const CResult_ShutdownScriptInvalidShutdownScriptZ&) = delete;
	CResult_ShutdownScriptInvalidShutdownScriptZ(CResult_ShutdownScriptInvalidShutdownScriptZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ShutdownScriptInvalidShutdownScriptZ)); }
	CResult_ShutdownScriptInvalidShutdownScriptZ(LDKCResult_ShutdownScriptInvalidShutdownScriptZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ShutdownScriptInvalidShutdownScriptZ)); }
	operator LDKCResult_ShutdownScriptInvalidShutdownScriptZ() && { LDKCResult_ShutdownScriptInvalidShutdownScriptZ res = self; memset(&self, 0, sizeof(LDKCResult_ShutdownScriptInvalidShutdownScriptZ)); return res; }
	~CResult_ShutdownScriptInvalidShutdownScriptZ() { CResult_ShutdownScriptInvalidShutdownScriptZ_free(self); }
	CResult_ShutdownScriptInvalidShutdownScriptZ& operator=(CResult_ShutdownScriptInvalidShutdownScriptZ&& o) { CResult_ShutdownScriptInvalidShutdownScriptZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ShutdownScriptInvalidShutdownScriptZ)); return *this; }
	LDKCResult_ShutdownScriptInvalidShutdownScriptZ* operator &() { return &self; }
	LDKCResult_ShutdownScriptInvalidShutdownScriptZ* operator ->() { return &self; }
	const LDKCResult_ShutdownScriptInvalidShutdownScriptZ* operator &() const { return &self; }
	const LDKCResult_ShutdownScriptInvalidShutdownScriptZ* operator ->() const { return &self; }
};
class CResult_NodeAnnouncementInfoDecodeErrorZ {
private:
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ self;
public:
	CResult_NodeAnnouncementInfoDecodeErrorZ(const CResult_NodeAnnouncementInfoDecodeErrorZ&) = delete;
	CResult_NodeAnnouncementInfoDecodeErrorZ(CResult_NodeAnnouncementInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeAnnouncementInfoDecodeErrorZ)); }
	CResult_NodeAnnouncementInfoDecodeErrorZ(LDKCResult_NodeAnnouncementInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeAnnouncementInfoDecodeErrorZ)); }
	operator LDKCResult_NodeAnnouncementInfoDecodeErrorZ() && { LDKCResult_NodeAnnouncementInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeAnnouncementInfoDecodeErrorZ)); return res; }
	~CResult_NodeAnnouncementInfoDecodeErrorZ() { CResult_NodeAnnouncementInfoDecodeErrorZ_free(self); }
	CResult_NodeAnnouncementInfoDecodeErrorZ& operator=(CResult_NodeAnnouncementInfoDecodeErrorZ&& o) { CResult_NodeAnnouncementInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeAnnouncementInfoDecodeErrorZ)); return *this; }
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_COption_NetworkUpdateZDecodeErrorZ {
private:
	LDKCResult_COption_NetworkUpdateZDecodeErrorZ self;
public:
	CResult_COption_NetworkUpdateZDecodeErrorZ(const CResult_COption_NetworkUpdateZDecodeErrorZ&) = delete;
	CResult_COption_NetworkUpdateZDecodeErrorZ(CResult_COption_NetworkUpdateZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_NetworkUpdateZDecodeErrorZ)); }
	CResult_COption_NetworkUpdateZDecodeErrorZ(LDKCResult_COption_NetworkUpdateZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_NetworkUpdateZDecodeErrorZ)); }
	operator LDKCResult_COption_NetworkUpdateZDecodeErrorZ() && { LDKCResult_COption_NetworkUpdateZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_NetworkUpdateZDecodeErrorZ)); return res; }
	~CResult_COption_NetworkUpdateZDecodeErrorZ() { CResult_COption_NetworkUpdateZDecodeErrorZ_free(self); }
	CResult_COption_NetworkUpdateZDecodeErrorZ& operator=(CResult_COption_NetworkUpdateZDecodeErrorZ&& o) { CResult_COption_NetworkUpdateZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_NetworkUpdateZDecodeErrorZ)); return *this; }
	LDKCResult_COption_NetworkUpdateZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_NetworkUpdateZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_NetworkUpdateZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_NetworkUpdateZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RecoverableSignatureNoneZ {
private:
	LDKCResult_RecoverableSignatureNoneZ self;
public:
	CResult_RecoverableSignatureNoneZ(const CResult_RecoverableSignatureNoneZ&) = delete;
	CResult_RecoverableSignatureNoneZ(CResult_RecoverableSignatureNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RecoverableSignatureNoneZ)); }
	CResult_RecoverableSignatureNoneZ(LDKCResult_RecoverableSignatureNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RecoverableSignatureNoneZ)); }
	operator LDKCResult_RecoverableSignatureNoneZ() && { LDKCResult_RecoverableSignatureNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_RecoverableSignatureNoneZ)); return res; }
	~CResult_RecoverableSignatureNoneZ() { CResult_RecoverableSignatureNoneZ_free(self); }
	CResult_RecoverableSignatureNoneZ& operator=(CResult_RecoverableSignatureNoneZ&& o) { CResult_RecoverableSignatureNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RecoverableSignatureNoneZ)); return *this; }
	LDKCResult_RecoverableSignatureNoneZ* operator &() { return &self; }
	LDKCResult_RecoverableSignatureNoneZ* operator ->() { return &self; }
	const LDKCResult_RecoverableSignatureNoneZ* operator &() const { return &self; }
	const LDKCResult_RecoverableSignatureNoneZ* operator ->() const { return &self; }
};
class C2Tuple_BlockHashChannelMonitorZ {
private:
	LDKC2Tuple_BlockHashChannelMonitorZ self;
public:
	C2Tuple_BlockHashChannelMonitorZ(const C2Tuple_BlockHashChannelMonitorZ&) = delete;
	C2Tuple_BlockHashChannelMonitorZ(C2Tuple_BlockHashChannelMonitorZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_BlockHashChannelMonitorZ)); }
	C2Tuple_BlockHashChannelMonitorZ(LDKC2Tuple_BlockHashChannelMonitorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_BlockHashChannelMonitorZ)); }
	operator LDKC2Tuple_BlockHashChannelMonitorZ() && { LDKC2Tuple_BlockHashChannelMonitorZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_BlockHashChannelMonitorZ)); return res; }
	~C2Tuple_BlockHashChannelMonitorZ() { C2Tuple_BlockHashChannelMonitorZ_free(self); }
	C2Tuple_BlockHashChannelMonitorZ& operator=(C2Tuple_BlockHashChannelMonitorZ&& o) { C2Tuple_BlockHashChannelMonitorZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_BlockHashChannelMonitorZ)); return *this; }
	LDKC2Tuple_BlockHashChannelMonitorZ* operator &() { return &self; }
	LDKC2Tuple_BlockHashChannelMonitorZ* operator ->() { return &self; }
	const LDKC2Tuple_BlockHashChannelMonitorZ* operator &() const { return &self; }
	const LDKC2Tuple_BlockHashChannelMonitorZ* operator ->() const { return &self; }
};
class C3Tuple_RawInvoice_u832InvoiceSignatureZ {
private:
	LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ self;
public:
	C3Tuple_RawInvoice_u832InvoiceSignatureZ(const C3Tuple_RawInvoice_u832InvoiceSignatureZ&) = delete;
	C3Tuple_RawInvoice_u832InvoiceSignatureZ(C3Tuple_RawInvoice_u832InvoiceSignatureZ&& o) : self(o.self) { memset(&o, 0, sizeof(C3Tuple_RawInvoice_u832InvoiceSignatureZ)); }
	C3Tuple_RawInvoice_u832InvoiceSignatureZ(LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ)); }
	operator LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ() && { LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ res = self; memset(&self, 0, sizeof(LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ)); return res; }
	~C3Tuple_RawInvoice_u832InvoiceSignatureZ() { C3Tuple_RawInvoice_u832InvoiceSignatureZ_free(self); }
	C3Tuple_RawInvoice_u832InvoiceSignatureZ& operator=(C3Tuple_RawInvoice_u832InvoiceSignatureZ&& o) { C3Tuple_RawInvoice_u832InvoiceSignatureZ_free(self); self = o.self; memset(&o, 0, sizeof(C3Tuple_RawInvoice_u832InvoiceSignatureZ)); return *this; }
	LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ* operator &() { return &self; }
	LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ* operator ->() { return &self; }
	const LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ* operator &() const { return &self; }
	const LDKC3Tuple_RawInvoice_u832InvoiceSignatureZ* operator ->() const { return &self; }
};
class CVec_UpdateFailMalformedHTLCZ {
private:
	LDKCVec_UpdateFailMalformedHTLCZ self;
public:
	CVec_UpdateFailMalformedHTLCZ(const CVec_UpdateFailMalformedHTLCZ&) = delete;
	CVec_UpdateFailMalformedHTLCZ(CVec_UpdateFailMalformedHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFailMalformedHTLCZ)); }
	CVec_UpdateFailMalformedHTLCZ(LDKCVec_UpdateFailMalformedHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFailMalformedHTLCZ)); }
	operator LDKCVec_UpdateFailMalformedHTLCZ() && { LDKCVec_UpdateFailMalformedHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFailMalformedHTLCZ)); return res; }
	~CVec_UpdateFailMalformedHTLCZ() { CVec_UpdateFailMalformedHTLCZ_free(self); }
	CVec_UpdateFailMalformedHTLCZ& operator=(CVec_UpdateFailMalformedHTLCZ&& o) { CVec_UpdateFailMalformedHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFailMalformedHTLCZ)); return *this; }
	LDKCVec_UpdateFailMalformedHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFailMalformedHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFailMalformedHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFailMalformedHTLCZ* operator ->() const { return &self; }
};
class CResult_FundingSignedDecodeErrorZ {
private:
	LDKCResult_FundingSignedDecodeErrorZ self;
public:
	CResult_FundingSignedDecodeErrorZ(const CResult_FundingSignedDecodeErrorZ&) = delete;
	CResult_FundingSignedDecodeErrorZ(CResult_FundingSignedDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_FundingSignedDecodeErrorZ)); }
	CResult_FundingSignedDecodeErrorZ(LDKCResult_FundingSignedDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_FundingSignedDecodeErrorZ)); }
	operator LDKCResult_FundingSignedDecodeErrorZ() && { LDKCResult_FundingSignedDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_FundingSignedDecodeErrorZ)); return res; }
	~CResult_FundingSignedDecodeErrorZ() { CResult_FundingSignedDecodeErrorZ_free(self); }
	CResult_FundingSignedDecodeErrorZ& operator=(CResult_FundingSignedDecodeErrorZ&& o) { CResult_FundingSignedDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_FundingSignedDecodeErrorZ)); return *this; }
	LDKCResult_FundingSignedDecodeErrorZ* operator &() { return &self; }
	LDKCResult_FundingSignedDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_FundingSignedDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_FundingSignedDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NetworkGraphDecodeErrorZ {
private:
	LDKCResult_NetworkGraphDecodeErrorZ self;
public:
	CResult_NetworkGraphDecodeErrorZ(const CResult_NetworkGraphDecodeErrorZ&) = delete;
	CResult_NetworkGraphDecodeErrorZ(CResult_NetworkGraphDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NetworkGraphDecodeErrorZ)); }
	CResult_NetworkGraphDecodeErrorZ(LDKCResult_NetworkGraphDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NetworkGraphDecodeErrorZ)); }
	operator LDKCResult_NetworkGraphDecodeErrorZ() && { LDKCResult_NetworkGraphDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NetworkGraphDecodeErrorZ)); return res; }
	~CResult_NetworkGraphDecodeErrorZ() { CResult_NetworkGraphDecodeErrorZ_free(self); }
	CResult_NetworkGraphDecodeErrorZ& operator=(CResult_NetworkGraphDecodeErrorZ&& o) { CResult_NetworkGraphDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NetworkGraphDecodeErrorZ)); return *this; }
	LDKCResult_NetworkGraphDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NetworkGraphDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NetworkGraphDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NetworkGraphDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_RouteHopZ {
private:
	LDKCVec_RouteHopZ self;
public:
	CVec_RouteHopZ(const CVec_RouteHopZ&) = delete;
	CVec_RouteHopZ(CVec_RouteHopZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_RouteHopZ)); }
	CVec_RouteHopZ(LDKCVec_RouteHopZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_RouteHopZ)); }
	operator LDKCVec_RouteHopZ() && { LDKCVec_RouteHopZ res = self; memset(&self, 0, sizeof(LDKCVec_RouteHopZ)); return res; }
	~CVec_RouteHopZ() { CVec_RouteHopZ_free(self); }
	CVec_RouteHopZ& operator=(CVec_RouteHopZ&& o) { CVec_RouteHopZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_RouteHopZ)); return *this; }
	LDKCVec_RouteHopZ* operator &() { return &self; }
	LDKCVec_RouteHopZ* operator ->() { return &self; }
	const LDKCVec_RouteHopZ* operator &() const { return &self; }
	const LDKCVec_RouteHopZ* operator ->() const { return &self; }
};
class CResult_NodeInfoDecodeErrorZ {
private:
	LDKCResult_NodeInfoDecodeErrorZ self;
public:
	CResult_NodeInfoDecodeErrorZ(const CResult_NodeInfoDecodeErrorZ&) = delete;
	CResult_NodeInfoDecodeErrorZ(CResult_NodeInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeInfoDecodeErrorZ)); }
	CResult_NodeInfoDecodeErrorZ(LDKCResult_NodeInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeInfoDecodeErrorZ)); }
	operator LDKCResult_NodeInfoDecodeErrorZ() && { LDKCResult_NodeInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeInfoDecodeErrorZ)); return res; }
	~CResult_NodeInfoDecodeErrorZ() { CResult_NodeInfoDecodeErrorZ_free(self); }
	CResult_NodeInfoDecodeErrorZ& operator=(CResult_NodeInfoDecodeErrorZ&& o) { CResult_NodeInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeInfoDecodeErrorZ)); return *this; }
	LDKCResult_NodeInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeInfoDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_NodeIdZ {
private:
	LDKCVec_NodeIdZ self;
public:
	CVec_NodeIdZ(const CVec_NodeIdZ&) = delete;
	CVec_NodeIdZ(CVec_NodeIdZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_NodeIdZ)); }
	CVec_NodeIdZ(LDKCVec_NodeIdZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_NodeIdZ)); }
	operator LDKCVec_NodeIdZ() && { LDKCVec_NodeIdZ res = self; memset(&self, 0, sizeof(LDKCVec_NodeIdZ)); return res; }
	~CVec_NodeIdZ() { CVec_NodeIdZ_free(self); }
	CVec_NodeIdZ& operator=(CVec_NodeIdZ&& o) { CVec_NodeIdZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_NodeIdZ)); return *this; }
	LDKCVec_NodeIdZ* operator &() { return &self; }
	LDKCVec_NodeIdZ* operator ->() { return &self; }
	const LDKCVec_NodeIdZ* operator &() const { return &self; }
	const LDKCVec_NodeIdZ* operator ->() const { return &self; }
};
class CResult_RouteLightningErrorZ {
private:
	LDKCResult_RouteLightningErrorZ self;
public:
	CResult_RouteLightningErrorZ(const CResult_RouteLightningErrorZ&) = delete;
	CResult_RouteLightningErrorZ(CResult_RouteLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteLightningErrorZ)); }
	CResult_RouteLightningErrorZ(LDKCResult_RouteLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteLightningErrorZ)); }
	operator LDKCResult_RouteLightningErrorZ() && { LDKCResult_RouteLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteLightningErrorZ)); return res; }
	~CResult_RouteLightningErrorZ() { CResult_RouteLightningErrorZ_free(self); }
	CResult_RouteLightningErrorZ& operator=(CResult_RouteLightningErrorZ&& o) { CResult_RouteLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteLightningErrorZ)); return *this; }
	LDKCResult_RouteLightningErrorZ* operator &() { return &self; }
	LDKCResult_RouteLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteLightningErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelPublicKeysDecodeErrorZ {
private:
	LDKCResult_ChannelPublicKeysDecodeErrorZ self;
public:
	CResult_ChannelPublicKeysDecodeErrorZ(const CResult_ChannelPublicKeysDecodeErrorZ&) = delete;
	CResult_ChannelPublicKeysDecodeErrorZ(CResult_ChannelPublicKeysDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelPublicKeysDecodeErrorZ)); }
	CResult_ChannelPublicKeysDecodeErrorZ(LDKCResult_ChannelPublicKeysDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelPublicKeysDecodeErrorZ)); }
	operator LDKCResult_ChannelPublicKeysDecodeErrorZ() && { LDKCResult_ChannelPublicKeysDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelPublicKeysDecodeErrorZ)); return res; }
	~CResult_ChannelPublicKeysDecodeErrorZ() { CResult_ChannelPublicKeysDecodeErrorZ_free(self); }
	CResult_ChannelPublicKeysDecodeErrorZ& operator=(CResult_ChannelPublicKeysDecodeErrorZ&& o) { CResult_ChannelPublicKeysDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelPublicKeysDecodeErrorZ)); return *this; }
	LDKCResult_ChannelPublicKeysDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelPublicKeysDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelPublicKeysDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelPublicKeysDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_u8Z {
private:
	LDKCVec_u8Z self;
public:
	CVec_u8Z(const CVec_u8Z&) = delete;
	CVec_u8Z(CVec_u8Z&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_u8Z)); }
	CVec_u8Z(LDKCVec_u8Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_u8Z)); }
	operator LDKCVec_u8Z() && { LDKCVec_u8Z res = self; memset(&self, 0, sizeof(LDKCVec_u8Z)); return res; }
	~CVec_u8Z() { CVec_u8Z_free(self); }
	CVec_u8Z& operator=(CVec_u8Z&& o) { CVec_u8Z_free(self); self = o.self; memset(&o, 0, sizeof(CVec_u8Z)); return *this; }
	LDKCVec_u8Z* operator &() { return &self; }
	LDKCVec_u8Z* operator ->() { return &self; }
	const LDKCVec_u8Z* operator &() const { return &self; }
	const LDKCVec_u8Z* operator ->() const { return &self; }
};
class CVec_C2Tuple_BlockHashChannelMonitorZZ {
private:
	LDKCVec_C2Tuple_BlockHashChannelMonitorZZ self;
public:
	CVec_C2Tuple_BlockHashChannelMonitorZZ(const CVec_C2Tuple_BlockHashChannelMonitorZZ&) = delete;
	CVec_C2Tuple_BlockHashChannelMonitorZZ(CVec_C2Tuple_BlockHashChannelMonitorZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_BlockHashChannelMonitorZZ)); }
	CVec_C2Tuple_BlockHashChannelMonitorZZ(LDKCVec_C2Tuple_BlockHashChannelMonitorZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_BlockHashChannelMonitorZZ)); }
	operator LDKCVec_C2Tuple_BlockHashChannelMonitorZZ() && { LDKCVec_C2Tuple_BlockHashChannelMonitorZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_BlockHashChannelMonitorZZ)); return res; }
	~CVec_C2Tuple_BlockHashChannelMonitorZZ() { CVec_C2Tuple_BlockHashChannelMonitorZZ_free(self); }
	CVec_C2Tuple_BlockHashChannelMonitorZZ& operator=(CVec_C2Tuple_BlockHashChannelMonitorZZ&& o) { CVec_C2Tuple_BlockHashChannelMonitorZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_BlockHashChannelMonitorZZ)); return *this; }
	LDKCVec_C2Tuple_BlockHashChannelMonitorZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_BlockHashChannelMonitorZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_BlockHashChannelMonitorZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_BlockHashChannelMonitorZZ* operator ->() const { return &self; }
};
class CResult_NonePaymentSendFailureZ {
private:
	LDKCResult_NonePaymentSendFailureZ self;
public:
	CResult_NonePaymentSendFailureZ(const CResult_NonePaymentSendFailureZ&) = delete;
	CResult_NonePaymentSendFailureZ(CResult_NonePaymentSendFailureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NonePaymentSendFailureZ)); }
	CResult_NonePaymentSendFailureZ(LDKCResult_NonePaymentSendFailureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NonePaymentSendFailureZ)); }
	operator LDKCResult_NonePaymentSendFailureZ() && { LDKCResult_NonePaymentSendFailureZ res = self; memset(&self, 0, sizeof(LDKCResult_NonePaymentSendFailureZ)); return res; }
	~CResult_NonePaymentSendFailureZ() { CResult_NonePaymentSendFailureZ_free(self); }
	CResult_NonePaymentSendFailureZ& operator=(CResult_NonePaymentSendFailureZ&& o) { CResult_NonePaymentSendFailureZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NonePaymentSendFailureZ)); return *this; }
	LDKCResult_NonePaymentSendFailureZ* operator &() { return &self; }
	LDKCResult_NonePaymentSendFailureZ* operator ->() { return &self; }
	const LDKCResult_NonePaymentSendFailureZ* operator &() const { return &self; }
	const LDKCResult_NonePaymentSendFailureZ* operator ->() const { return &self; }
};
class CVec_ThirtyTwoBytesZ {
private:
	LDKCVec_ThirtyTwoBytesZ self;
public:
	CVec_ThirtyTwoBytesZ(const CVec_ThirtyTwoBytesZ&) = delete;
	CVec_ThirtyTwoBytesZ(CVec_ThirtyTwoBytesZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_ThirtyTwoBytesZ)); }
	CVec_ThirtyTwoBytesZ(LDKCVec_ThirtyTwoBytesZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_ThirtyTwoBytesZ)); }
	operator LDKCVec_ThirtyTwoBytesZ() && { LDKCVec_ThirtyTwoBytesZ res = self; memset(&self, 0, sizeof(LDKCVec_ThirtyTwoBytesZ)); return res; }
	~CVec_ThirtyTwoBytesZ() { CVec_ThirtyTwoBytesZ_free(self); }
	CVec_ThirtyTwoBytesZ& operator=(CVec_ThirtyTwoBytesZ&& o) { CVec_ThirtyTwoBytesZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_ThirtyTwoBytesZ)); return *this; }
	LDKCVec_ThirtyTwoBytesZ* operator &() { return &self; }
	LDKCVec_ThirtyTwoBytesZ* operator ->() { return &self; }
	const LDKCVec_ThirtyTwoBytesZ* operator &() const { return &self; }
	const LDKCVec_ThirtyTwoBytesZ* operator ->() const { return &self; }
};
class CResult_ClosingSignedDecodeErrorZ {
private:
	LDKCResult_ClosingSignedDecodeErrorZ self;
public:
	CResult_ClosingSignedDecodeErrorZ(const CResult_ClosingSignedDecodeErrorZ&) = delete;
	CResult_ClosingSignedDecodeErrorZ(CResult_ClosingSignedDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ClosingSignedDecodeErrorZ)); }
	CResult_ClosingSignedDecodeErrorZ(LDKCResult_ClosingSignedDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ClosingSignedDecodeErrorZ)); }
	operator LDKCResult_ClosingSignedDecodeErrorZ() && { LDKCResult_ClosingSignedDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ClosingSignedDecodeErrorZ)); return res; }
	~CResult_ClosingSignedDecodeErrorZ() { CResult_ClosingSignedDecodeErrorZ_free(self); }
	CResult_ClosingSignedDecodeErrorZ& operator=(CResult_ClosingSignedDecodeErrorZ&& o) { CResult_ClosingSignedDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ClosingSignedDecodeErrorZ)); return *this; }
	LDKCResult_ClosingSignedDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ClosingSignedDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ClosingSignedDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ClosingSignedDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_CResult_NoneAPIErrorZZ {
private:
	LDKCVec_CResult_NoneAPIErrorZZ self;
public:
	CVec_CResult_NoneAPIErrorZZ(const CVec_CResult_NoneAPIErrorZZ&) = delete;
	CVec_CResult_NoneAPIErrorZZ(CVec_CResult_NoneAPIErrorZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_CResult_NoneAPIErrorZZ)); }
	CVec_CResult_NoneAPIErrorZZ(LDKCVec_CResult_NoneAPIErrorZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_CResult_NoneAPIErrorZZ)); }
	operator LDKCVec_CResult_NoneAPIErrorZZ() && { LDKCVec_CResult_NoneAPIErrorZZ res = self; memset(&self, 0, sizeof(LDKCVec_CResult_NoneAPIErrorZZ)); return res; }
	~CVec_CResult_NoneAPIErrorZZ() { CVec_CResult_NoneAPIErrorZZ_free(self); }
	CVec_CResult_NoneAPIErrorZZ& operator=(CVec_CResult_NoneAPIErrorZZ&& o) { CVec_CResult_NoneAPIErrorZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_CResult_NoneAPIErrorZZ)); return *this; }
	LDKCVec_CResult_NoneAPIErrorZZ* operator &() { return &self; }
	LDKCVec_CResult_NoneAPIErrorZZ* operator ->() { return &self; }
	const LDKCVec_CResult_NoneAPIErrorZZ* operator &() const { return &self; }
	const LDKCVec_CResult_NoneAPIErrorZZ* operator ->() const { return &self; }
};
class CResult_HolderCommitmentTransactionDecodeErrorZ {
private:
	LDKCResult_HolderCommitmentTransactionDecodeErrorZ self;
public:
	CResult_HolderCommitmentTransactionDecodeErrorZ(const CResult_HolderCommitmentTransactionDecodeErrorZ&) = delete;
	CResult_HolderCommitmentTransactionDecodeErrorZ(CResult_HolderCommitmentTransactionDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_HolderCommitmentTransactionDecodeErrorZ)); }
	CResult_HolderCommitmentTransactionDecodeErrorZ(LDKCResult_HolderCommitmentTransactionDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_HolderCommitmentTransactionDecodeErrorZ)); }
	operator LDKCResult_HolderCommitmentTransactionDecodeErrorZ() && { LDKCResult_HolderCommitmentTransactionDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_HolderCommitmentTransactionDecodeErrorZ)); return res; }
	~CResult_HolderCommitmentTransactionDecodeErrorZ() { CResult_HolderCommitmentTransactionDecodeErrorZ_free(self); }
	CResult_HolderCommitmentTransactionDecodeErrorZ& operator=(CResult_HolderCommitmentTransactionDecodeErrorZ&& o) { CResult_HolderCommitmentTransactionDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_HolderCommitmentTransactionDecodeErrorZ)); return *this; }
	LDKCResult_HolderCommitmentTransactionDecodeErrorZ* operator &() { return &self; }
	LDKCResult_HolderCommitmentTransactionDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_HolderCommitmentTransactionDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_HolderCommitmentTransactionDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CounterpartyCommitmentSecretsDecodeErrorZ {
private:
	LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ self;
public:
	CResult_CounterpartyCommitmentSecretsDecodeErrorZ(const CResult_CounterpartyCommitmentSecretsDecodeErrorZ&) = delete;
	CResult_CounterpartyCommitmentSecretsDecodeErrorZ(CResult_CounterpartyCommitmentSecretsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CounterpartyCommitmentSecretsDecodeErrorZ)); }
	CResult_CounterpartyCommitmentSecretsDecodeErrorZ(LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ)); }
	operator LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ() && { LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ)); return res; }
	~CResult_CounterpartyCommitmentSecretsDecodeErrorZ() { CResult_CounterpartyCommitmentSecretsDecodeErrorZ_free(self); }
	CResult_CounterpartyCommitmentSecretsDecodeErrorZ& operator=(CResult_CounterpartyCommitmentSecretsDecodeErrorZ&& o) { CResult_CounterpartyCommitmentSecretsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CounterpartyCommitmentSecretsDecodeErrorZ)); return *this; }
	LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CounterpartyCommitmentSecretsDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelCounterpartyDecodeErrorZ {
private:
	LDKCResult_ChannelCounterpartyDecodeErrorZ self;
public:
	CResult_ChannelCounterpartyDecodeErrorZ(const CResult_ChannelCounterpartyDecodeErrorZ&) = delete;
	CResult_ChannelCounterpartyDecodeErrorZ(CResult_ChannelCounterpartyDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelCounterpartyDecodeErrorZ)); }
	CResult_ChannelCounterpartyDecodeErrorZ(LDKCResult_ChannelCounterpartyDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelCounterpartyDecodeErrorZ)); }
	operator LDKCResult_ChannelCounterpartyDecodeErrorZ() && { LDKCResult_ChannelCounterpartyDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelCounterpartyDecodeErrorZ)); return res; }
	~CResult_ChannelCounterpartyDecodeErrorZ() { CResult_ChannelCounterpartyDecodeErrorZ_free(self); }
	CResult_ChannelCounterpartyDecodeErrorZ& operator=(CResult_ChannelCounterpartyDecodeErrorZ&& o) { CResult_ChannelCounterpartyDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelCounterpartyDecodeErrorZ)); return *this; }
	LDKCResult_ChannelCounterpartyDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelCounterpartyDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelCounterpartyDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelCounterpartyDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_WarningMessageDecodeErrorZ {
private:
	LDKCResult_WarningMessageDecodeErrorZ self;
public:
	CResult_WarningMessageDecodeErrorZ(const CResult_WarningMessageDecodeErrorZ&) = delete;
	CResult_WarningMessageDecodeErrorZ(CResult_WarningMessageDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_WarningMessageDecodeErrorZ)); }
	CResult_WarningMessageDecodeErrorZ(LDKCResult_WarningMessageDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_WarningMessageDecodeErrorZ)); }
	operator LDKCResult_WarningMessageDecodeErrorZ() && { LDKCResult_WarningMessageDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_WarningMessageDecodeErrorZ)); return res; }
	~CResult_WarningMessageDecodeErrorZ() { CResult_WarningMessageDecodeErrorZ_free(self); }
	CResult_WarningMessageDecodeErrorZ& operator=(CResult_WarningMessageDecodeErrorZ&& o) { CResult_WarningMessageDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_WarningMessageDecodeErrorZ)); return *this; }
	LDKCResult_WarningMessageDecodeErrorZ* operator &() { return &self; }
	LDKCResult_WarningMessageDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_WarningMessageDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_WarningMessageDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_SignatureNoneZ {
private:
	LDKCResult_SignatureNoneZ self;
public:
	CResult_SignatureNoneZ(const CResult_SignatureNoneZ&) = delete;
	CResult_SignatureNoneZ(CResult_SignatureNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SignatureNoneZ)); }
	CResult_SignatureNoneZ(LDKCResult_SignatureNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SignatureNoneZ)); }
	operator LDKCResult_SignatureNoneZ() && { LDKCResult_SignatureNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_SignatureNoneZ)); return res; }
	~CResult_SignatureNoneZ() { CResult_SignatureNoneZ_free(self); }
	CResult_SignatureNoneZ& operator=(CResult_SignatureNoneZ&& o) { CResult_SignatureNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SignatureNoneZ)); return *this; }
	LDKCResult_SignatureNoneZ* operator &() { return &self; }
	LDKCResult_SignatureNoneZ* operator ->() { return &self; }
	const LDKCResult_SignatureNoneZ* operator &() const { return &self; }
	const LDKCResult_SignatureNoneZ* operator ->() const { return &self; }
};
class CVec_RouteHintHopZ {
private:
	LDKCVec_RouteHintHopZ self;
public:
	CVec_RouteHintHopZ(const CVec_RouteHintHopZ&) = delete;
	CVec_RouteHintHopZ(CVec_RouteHintHopZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_RouteHintHopZ)); }
	CVec_RouteHintHopZ(LDKCVec_RouteHintHopZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_RouteHintHopZ)); }
	operator LDKCVec_RouteHintHopZ() && { LDKCVec_RouteHintHopZ res = self; memset(&self, 0, sizeof(LDKCVec_RouteHintHopZ)); return res; }
	~CVec_RouteHintHopZ() { CVec_RouteHintHopZ_free(self); }
	CVec_RouteHintHopZ& operator=(CVec_RouteHintHopZ&& o) { CVec_RouteHintHopZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_RouteHintHopZ)); return *this; }
	LDKCVec_RouteHintHopZ* operator &() { return &self; }
	LDKCVec_RouteHintHopZ* operator ->() { return &self; }
	const LDKCVec_RouteHintHopZ* operator &() const { return &self; }
	const LDKCVec_RouteHintHopZ* operator ->() const { return &self; }
};
class CResult_SecretKeyNoneZ {
private:
	LDKCResult_SecretKeyNoneZ self;
public:
	CResult_SecretKeyNoneZ(const CResult_SecretKeyNoneZ&) = delete;
	CResult_SecretKeyNoneZ(CResult_SecretKeyNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SecretKeyNoneZ)); }
	CResult_SecretKeyNoneZ(LDKCResult_SecretKeyNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SecretKeyNoneZ)); }
	operator LDKCResult_SecretKeyNoneZ() && { LDKCResult_SecretKeyNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_SecretKeyNoneZ)); return res; }
	~CResult_SecretKeyNoneZ() { CResult_SecretKeyNoneZ_free(self); }
	CResult_SecretKeyNoneZ& operator=(CResult_SecretKeyNoneZ&& o) { CResult_SecretKeyNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SecretKeyNoneZ)); return *this; }
	LDKCResult_SecretKeyNoneZ* operator &() { return &self; }
	LDKCResult_SecretKeyNoneZ* operator ->() { return &self; }
	const LDKCResult_SecretKeyNoneZ* operator &() const { return &self; }
	const LDKCResult_SecretKeyNoneZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
private:
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ self;
public:
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ(const CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ&) = delete;
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ(CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ)); }
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ(LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ)); }
	operator LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ() && { LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ)); return res; }
	~CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ() { CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_free(self); }
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ& operator=(CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ&& o) { CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ)); return *this; }
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ* operator &() { return &self; }
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentSecretZNoneZ* operator ->() const { return &self; }
};
class C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
private:
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ self;
public:
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(const C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&) = delete;
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); }
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); }
	operator LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ() && { LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); return res; }
	~C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ() { C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(self); }
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ& operator=(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& o) { C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); return *this; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator &() { return &self; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator ->() { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator &() const { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator ->() const { return &self; }
};
class CResult_PaymentParametersDecodeErrorZ {
private:
	LDKCResult_PaymentParametersDecodeErrorZ self;
public:
	CResult_PaymentParametersDecodeErrorZ(const CResult_PaymentParametersDecodeErrorZ&) = delete;
	CResult_PaymentParametersDecodeErrorZ(CResult_PaymentParametersDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentParametersDecodeErrorZ)); }
	CResult_PaymentParametersDecodeErrorZ(LDKCResult_PaymentParametersDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentParametersDecodeErrorZ)); }
	operator LDKCResult_PaymentParametersDecodeErrorZ() && { LDKCResult_PaymentParametersDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentParametersDecodeErrorZ)); return res; }
	~CResult_PaymentParametersDecodeErrorZ() { CResult_PaymentParametersDecodeErrorZ_free(self); }
	CResult_PaymentParametersDecodeErrorZ& operator=(CResult_PaymentParametersDecodeErrorZ&& o) { CResult_PaymentParametersDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentParametersDecodeErrorZ)); return *this; }
	LDKCResult_PaymentParametersDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PaymentParametersDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PaymentParametersDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PaymentParametersDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PaymentPurposeDecodeErrorZ {
private:
	LDKCResult_PaymentPurposeDecodeErrorZ self;
public:
	CResult_PaymentPurposeDecodeErrorZ(const CResult_PaymentPurposeDecodeErrorZ&) = delete;
	CResult_PaymentPurposeDecodeErrorZ(CResult_PaymentPurposeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentPurposeDecodeErrorZ)); }
	CResult_PaymentPurposeDecodeErrorZ(LDKCResult_PaymentPurposeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentPurposeDecodeErrorZ)); }
	operator LDKCResult_PaymentPurposeDecodeErrorZ() && { LDKCResult_PaymentPurposeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentPurposeDecodeErrorZ)); return res; }
	~CResult_PaymentPurposeDecodeErrorZ() { CResult_PaymentPurposeDecodeErrorZ_free(self); }
	CResult_PaymentPurposeDecodeErrorZ& operator=(CResult_PaymentPurposeDecodeErrorZ&& o) { CResult_PaymentPurposeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentPurposeDecodeErrorZ)); return *this; }
	LDKCResult_PaymentPurposeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PaymentPurposeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PaymentPurposeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PaymentPurposeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_InitDecodeErrorZ {
private:
	LDKCResult_InitDecodeErrorZ self;
public:
	CResult_InitDecodeErrorZ(const CResult_InitDecodeErrorZ&) = delete;
	CResult_InitDecodeErrorZ(CResult_InitDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InitDecodeErrorZ)); }
	CResult_InitDecodeErrorZ(LDKCResult_InitDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InitDecodeErrorZ)); }
	operator LDKCResult_InitDecodeErrorZ() && { LDKCResult_InitDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InitDecodeErrorZ)); return res; }
	~CResult_InitDecodeErrorZ() { CResult_InitDecodeErrorZ_free(self); }
	CResult_InitDecodeErrorZ& operator=(CResult_InitDecodeErrorZ&& o) { CResult_InitDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InitDecodeErrorZ)); return *this; }
	LDKCResult_InitDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InitDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InitDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InitDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_OutPointDecodeErrorZ {
private:
	LDKCResult_OutPointDecodeErrorZ self;
public:
	CResult_OutPointDecodeErrorZ(const CResult_OutPointDecodeErrorZ&) = delete;
	CResult_OutPointDecodeErrorZ(CResult_OutPointDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_OutPointDecodeErrorZ)); }
	CResult_OutPointDecodeErrorZ(LDKCResult_OutPointDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_OutPointDecodeErrorZ)); }
	operator LDKCResult_OutPointDecodeErrorZ() && { LDKCResult_OutPointDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_OutPointDecodeErrorZ)); return res; }
	~CResult_OutPointDecodeErrorZ() { CResult_OutPointDecodeErrorZ_free(self); }
	CResult_OutPointDecodeErrorZ& operator=(CResult_OutPointDecodeErrorZ&& o) { CResult_OutPointDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_OutPointDecodeErrorZ)); return *this; }
	LDKCResult_OutPointDecodeErrorZ* operator &() { return &self; }
	LDKCResult_OutPointDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_OutPointDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_OutPointDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_BlindedRouteDecodeErrorZ {
private:
	LDKCResult_BlindedRouteDecodeErrorZ self;
public:
	CResult_BlindedRouteDecodeErrorZ(const CResult_BlindedRouteDecodeErrorZ&) = delete;
	CResult_BlindedRouteDecodeErrorZ(CResult_BlindedRouteDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_BlindedRouteDecodeErrorZ)); }
	CResult_BlindedRouteDecodeErrorZ(LDKCResult_BlindedRouteDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_BlindedRouteDecodeErrorZ)); }
	operator LDKCResult_BlindedRouteDecodeErrorZ() && { LDKCResult_BlindedRouteDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_BlindedRouteDecodeErrorZ)); return res; }
	~CResult_BlindedRouteDecodeErrorZ() { CResult_BlindedRouteDecodeErrorZ_free(self); }
	CResult_BlindedRouteDecodeErrorZ& operator=(CResult_BlindedRouteDecodeErrorZ&& o) { CResult_BlindedRouteDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_BlindedRouteDecodeErrorZ)); return *this; }
	LDKCResult_BlindedRouteDecodeErrorZ* operator &() { return &self; }
	LDKCResult_BlindedRouteDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_BlindedRouteDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_BlindedRouteDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_ChannelDetailsZ {
private:
	LDKCVec_ChannelDetailsZ self;
public:
	CVec_ChannelDetailsZ(const CVec_ChannelDetailsZ&) = delete;
	CVec_ChannelDetailsZ(CVec_ChannelDetailsZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_ChannelDetailsZ)); }
	CVec_ChannelDetailsZ(LDKCVec_ChannelDetailsZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_ChannelDetailsZ)); }
	operator LDKCVec_ChannelDetailsZ() && { LDKCVec_ChannelDetailsZ res = self; memset(&self, 0, sizeof(LDKCVec_ChannelDetailsZ)); return res; }
	~CVec_ChannelDetailsZ() { CVec_ChannelDetailsZ_free(self); }
	CVec_ChannelDetailsZ& operator=(CVec_ChannelDetailsZ&& o) { CVec_ChannelDetailsZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_ChannelDetailsZ)); return *this; }
	LDKCVec_ChannelDetailsZ* operator &() { return &self; }
	LDKCVec_ChannelDetailsZ* operator ->() { return &self; }
	const LDKCVec_ChannelDetailsZ* operator &() const { return &self; }
	const LDKCVec_ChannelDetailsZ* operator ->() const { return &self; }
};
class CVec_MessageSendEventZ {
private:
	LDKCVec_MessageSendEventZ self;
public:
	CVec_MessageSendEventZ(const CVec_MessageSendEventZ&) = delete;
	CVec_MessageSendEventZ(CVec_MessageSendEventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_MessageSendEventZ)); }
	CVec_MessageSendEventZ(LDKCVec_MessageSendEventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_MessageSendEventZ)); }
	operator LDKCVec_MessageSendEventZ() && { LDKCVec_MessageSendEventZ res = self; memset(&self, 0, sizeof(LDKCVec_MessageSendEventZ)); return res; }
	~CVec_MessageSendEventZ() { CVec_MessageSendEventZ_free(self); }
	CVec_MessageSendEventZ& operator=(CVec_MessageSendEventZ&& o) { CVec_MessageSendEventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_MessageSendEventZ)); return *this; }
	LDKCVec_MessageSendEventZ* operator &() { return &self; }
	LDKCVec_MessageSendEventZ* operator ->() { return &self; }
	const LDKCVec_MessageSendEventZ* operator &() const { return &self; }
	const LDKCVec_MessageSendEventZ* operator ->() const { return &self; }
};
class CResult_SignDecodeErrorZ {
private:
	LDKCResult_SignDecodeErrorZ self;
public:
	CResult_SignDecodeErrorZ(const CResult_SignDecodeErrorZ&) = delete;
	CResult_SignDecodeErrorZ(CResult_SignDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SignDecodeErrorZ)); }
	CResult_SignDecodeErrorZ(LDKCResult_SignDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SignDecodeErrorZ)); }
	operator LDKCResult_SignDecodeErrorZ() && { LDKCResult_SignDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SignDecodeErrorZ)); return res; }
	~CResult_SignDecodeErrorZ() { CResult_SignDecodeErrorZ_free(self); }
	CResult_SignDecodeErrorZ& operator=(CResult_SignDecodeErrorZ&& o) { CResult_SignDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SignDecodeErrorZ)); return *this; }
	LDKCResult_SignDecodeErrorZ* operator &() { return &self; }
	LDKCResult_SignDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_SignDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_SignDecodeErrorZ* operator ->() const { return &self; }
};
class COption_NetAddressZ {
private:
	LDKCOption_NetAddressZ self;
public:
	COption_NetAddressZ(const COption_NetAddressZ&) = delete;
	COption_NetAddressZ(COption_NetAddressZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_NetAddressZ)); }
	COption_NetAddressZ(LDKCOption_NetAddressZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_NetAddressZ)); }
	operator LDKCOption_NetAddressZ() && { LDKCOption_NetAddressZ res = self; memset(&self, 0, sizeof(LDKCOption_NetAddressZ)); return res; }
	~COption_NetAddressZ() { COption_NetAddressZ_free(self); }
	COption_NetAddressZ& operator=(COption_NetAddressZ&& o) { COption_NetAddressZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_NetAddressZ)); return *this; }
	LDKCOption_NetAddressZ* operator &() { return &self; }
	LDKCOption_NetAddressZ* operator ->() { return &self; }
	const LDKCOption_NetAddressZ* operator &() const { return &self; }
	const LDKCOption_NetAddressZ* operator ->() const { return &self; }
};
class C2Tuple_OutPointScriptZ {
private:
	LDKC2Tuple_OutPointScriptZ self;
public:
	C2Tuple_OutPointScriptZ(const C2Tuple_OutPointScriptZ&) = delete;
	C2Tuple_OutPointScriptZ(C2Tuple_OutPointScriptZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_OutPointScriptZ)); }
	C2Tuple_OutPointScriptZ(LDKC2Tuple_OutPointScriptZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_OutPointScriptZ)); }
	operator LDKC2Tuple_OutPointScriptZ() && { LDKC2Tuple_OutPointScriptZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_OutPointScriptZ)); return res; }
	~C2Tuple_OutPointScriptZ() { C2Tuple_OutPointScriptZ_free(self); }
	C2Tuple_OutPointScriptZ& operator=(C2Tuple_OutPointScriptZ&& o) { C2Tuple_OutPointScriptZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_OutPointScriptZ)); return *this; }
	LDKC2Tuple_OutPointScriptZ* operator &() { return &self; }
	LDKC2Tuple_OutPointScriptZ* operator ->() { return &self; }
	const LDKC2Tuple_OutPointScriptZ* operator &() const { return &self; }
	const LDKC2Tuple_OutPointScriptZ* operator ->() const { return &self; }
};
class CResult_RouteHintHopDecodeErrorZ {
private:
	LDKCResult_RouteHintHopDecodeErrorZ self;
public:
	CResult_RouteHintHopDecodeErrorZ(const CResult_RouteHintHopDecodeErrorZ&) = delete;
	CResult_RouteHintHopDecodeErrorZ(CResult_RouteHintHopDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteHintHopDecodeErrorZ)); }
	CResult_RouteHintHopDecodeErrorZ(LDKCResult_RouteHintHopDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteHintHopDecodeErrorZ)); }
	operator LDKCResult_RouteHintHopDecodeErrorZ() && { LDKCResult_RouteHintHopDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteHintHopDecodeErrorZ)); return res; }
	~CResult_RouteHintHopDecodeErrorZ() { CResult_RouteHintHopDecodeErrorZ_free(self); }
	CResult_RouteHintHopDecodeErrorZ& operator=(CResult_RouteHintHopDecodeErrorZ&& o) { CResult_RouteHintHopDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteHintHopDecodeErrorZ)); return *this; }
	LDKCResult_RouteHintHopDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteHintHopDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteHintHopDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteHintHopDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_SignatureSignatureZNoneZ {
private:
	LDKCResult_C2Tuple_SignatureSignatureZNoneZ self;
public:
	CResult_C2Tuple_SignatureSignatureZNoneZ(const CResult_C2Tuple_SignatureSignatureZNoneZ&) = delete;
	CResult_C2Tuple_SignatureSignatureZNoneZ(CResult_C2Tuple_SignatureSignatureZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_SignatureSignatureZNoneZ)); }
	CResult_C2Tuple_SignatureSignatureZNoneZ(LDKCResult_C2Tuple_SignatureSignatureZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_SignatureSignatureZNoneZ)); }
	operator LDKCResult_C2Tuple_SignatureSignatureZNoneZ() && { LDKCResult_C2Tuple_SignatureSignatureZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_SignatureSignatureZNoneZ)); return res; }
	~CResult_C2Tuple_SignatureSignatureZNoneZ() { CResult_C2Tuple_SignatureSignatureZNoneZ_free(self); }
	CResult_C2Tuple_SignatureSignatureZNoneZ& operator=(CResult_C2Tuple_SignatureSignatureZNoneZ&& o) { CResult_C2Tuple_SignatureSignatureZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_SignatureSignatureZNoneZ)); return *this; }
	LDKCResult_C2Tuple_SignatureSignatureZNoneZ* operator &() { return &self; }
	LDKCResult_C2Tuple_SignatureSignatureZNoneZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_SignatureSignatureZNoneZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_SignatureSignatureZNoneZ* operator ->() const { return &self; }
};
class CResult_UpdateFailMalformedHTLCDecodeErrorZ {
private:
	LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ self;
public:
	CResult_UpdateFailMalformedHTLCDecodeErrorZ(const CResult_UpdateFailMalformedHTLCDecodeErrorZ&) = delete;
	CResult_UpdateFailMalformedHTLCDecodeErrorZ(CResult_UpdateFailMalformedHTLCDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UpdateFailMalformedHTLCDecodeErrorZ)); }
	CResult_UpdateFailMalformedHTLCDecodeErrorZ(LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ)); }
	operator LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ() && { LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ)); return res; }
	~CResult_UpdateFailMalformedHTLCDecodeErrorZ() { CResult_UpdateFailMalformedHTLCDecodeErrorZ_free(self); }
	CResult_UpdateFailMalformedHTLCDecodeErrorZ& operator=(CResult_UpdateFailMalformedHTLCDecodeErrorZ&& o) { CResult_UpdateFailMalformedHTLCDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UpdateFailMalformedHTLCDecodeErrorZ)); return *this; }
	LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UpdateFailMalformedHTLCDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_SharedSecretNoneZ {
private:
	LDKCResult_SharedSecretNoneZ self;
public:
	CResult_SharedSecretNoneZ(const CResult_SharedSecretNoneZ&) = delete;
	CResult_SharedSecretNoneZ(CResult_SharedSecretNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SharedSecretNoneZ)); }
	CResult_SharedSecretNoneZ(LDKCResult_SharedSecretNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SharedSecretNoneZ)); }
	operator LDKCResult_SharedSecretNoneZ() && { LDKCResult_SharedSecretNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_SharedSecretNoneZ)); return res; }
	~CResult_SharedSecretNoneZ() { CResult_SharedSecretNoneZ_free(self); }
	CResult_SharedSecretNoneZ& operator=(CResult_SharedSecretNoneZ&& o) { CResult_SharedSecretNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SharedSecretNoneZ)); return *this; }
	LDKCResult_SharedSecretNoneZ* operator &() { return &self; }
	LDKCResult_SharedSecretNoneZ* operator ->() { return &self; }
	const LDKCResult_SharedSecretNoneZ* operator &() const { return &self; }
	const LDKCResult_SharedSecretNoneZ* operator ->() const { return &self; }
};
class CVec_TxidZ {
private:
	LDKCVec_TxidZ self;
public:
	CVec_TxidZ(const CVec_TxidZ&) = delete;
	CVec_TxidZ(CVec_TxidZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_TxidZ)); }
	CVec_TxidZ(LDKCVec_TxidZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_TxidZ)); }
	operator LDKCVec_TxidZ() && { LDKCVec_TxidZ res = self; memset(&self, 0, sizeof(LDKCVec_TxidZ)); return res; }
	~CVec_TxidZ() { CVec_TxidZ_free(self); }
	CVec_TxidZ& operator=(CVec_TxidZ&& o) { CVec_TxidZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_TxidZ)); return *this; }
	LDKCVec_TxidZ* operator &() { return &self; }
	LDKCVec_TxidZ* operator ->() { return &self; }
	const LDKCVec_TxidZ* operator &() const { return &self; }
	const LDKCVec_TxidZ* operator ->() const { return &self; }
};
class COption_AccessZ {
private:
	LDKCOption_AccessZ self;
public:
	COption_AccessZ(const COption_AccessZ&) = delete;
	COption_AccessZ(COption_AccessZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_AccessZ)); }
	COption_AccessZ(LDKCOption_AccessZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_AccessZ)); }
	operator LDKCOption_AccessZ() && { LDKCOption_AccessZ res = self; memset(&self, 0, sizeof(LDKCOption_AccessZ)); return res; }
	~COption_AccessZ() { COption_AccessZ_free(self); }
	COption_AccessZ& operator=(COption_AccessZ&& o) { COption_AccessZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_AccessZ)); return *this; }
	LDKCOption_AccessZ* operator &() { return &self; }
	LDKCOption_AccessZ* operator ->() { return &self; }
	const LDKCOption_AccessZ* operator &() const { return &self; }
	const LDKCOption_AccessZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
private:
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ self;
public:
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(const CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&) = delete;
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); }
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); }
	operator LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ() && { LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); return res; }
	~CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ() { CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(self); }
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ& operator=(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& o) { CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); return *this; }
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator &() { return &self; }
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
private:
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ self;
public:
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(const CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&) = delete;
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); }
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); }
	operator LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ() && { LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); return res; }
	~CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ() { CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(self); }
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ& operator=(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& o) { CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); return *this; }
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PongDecodeErrorZ {
private:
	LDKCResult_PongDecodeErrorZ self;
public:
	CResult_PongDecodeErrorZ(const CResult_PongDecodeErrorZ&) = delete;
	CResult_PongDecodeErrorZ(CResult_PongDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PongDecodeErrorZ)); }
	CResult_PongDecodeErrorZ(LDKCResult_PongDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PongDecodeErrorZ)); }
	operator LDKCResult_PongDecodeErrorZ() && { LDKCResult_PongDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PongDecodeErrorZ)); return res; }
	~CResult_PongDecodeErrorZ() { CResult_PongDecodeErrorZ_free(self); }
	CResult_PongDecodeErrorZ& operator=(CResult_PongDecodeErrorZ&& o) { CResult_PongDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PongDecodeErrorZ)); return *this; }
	LDKCResult_PongDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PongDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PongDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PongDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CVec_CVec_u8ZZNoneZ {
private:
	LDKCResult_CVec_CVec_u8ZZNoneZ self;
public:
	CResult_CVec_CVec_u8ZZNoneZ(const CResult_CVec_CVec_u8ZZNoneZ&) = delete;
	CResult_CVec_CVec_u8ZZNoneZ(CResult_CVec_CVec_u8ZZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_CVec_u8ZZNoneZ)); }
	CResult_CVec_CVec_u8ZZNoneZ(LDKCResult_CVec_CVec_u8ZZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_CVec_u8ZZNoneZ)); }
	operator LDKCResult_CVec_CVec_u8ZZNoneZ() && { LDKCResult_CVec_CVec_u8ZZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_CVec_u8ZZNoneZ)); return res; }
	~CResult_CVec_CVec_u8ZZNoneZ() { CResult_CVec_CVec_u8ZZNoneZ_free(self); }
	CResult_CVec_CVec_u8ZZNoneZ& operator=(CResult_CVec_CVec_u8ZZNoneZ&& o) { CResult_CVec_CVec_u8ZZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_CVec_u8ZZNoneZ)); return *this; }
	LDKCResult_CVec_CVec_u8ZZNoneZ* operator &() { return &self; }
	LDKCResult_CVec_CVec_u8ZZNoneZ* operator ->() { return &self; }
	const LDKCResult_CVec_CVec_u8ZZNoneZ* operator &() const { return &self; }
	const LDKCResult_CVec_CVec_u8ZZNoneZ* operator ->() const { return &self; }
};
class C2Tuple_SignatureSignatureZ {
private:
	LDKC2Tuple_SignatureSignatureZ self;
public:
	C2Tuple_SignatureSignatureZ(const C2Tuple_SignatureSignatureZ&) = delete;
	C2Tuple_SignatureSignatureZ(C2Tuple_SignatureSignatureZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_SignatureSignatureZ)); }
	C2Tuple_SignatureSignatureZ(LDKC2Tuple_SignatureSignatureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_SignatureSignatureZ)); }
	operator LDKC2Tuple_SignatureSignatureZ() && { LDKC2Tuple_SignatureSignatureZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_SignatureSignatureZ)); return res; }
	~C2Tuple_SignatureSignatureZ() { C2Tuple_SignatureSignatureZ_free(self); }
	C2Tuple_SignatureSignatureZ& operator=(C2Tuple_SignatureSignatureZ&& o) { C2Tuple_SignatureSignatureZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_SignatureSignatureZ)); return *this; }
	LDKC2Tuple_SignatureSignatureZ* operator &() { return &self; }
	LDKC2Tuple_SignatureSignatureZ* operator ->() { return &self; }
	const LDKC2Tuple_SignatureSignatureZ* operator &() const { return &self; }
	const LDKC2Tuple_SignatureSignatureZ* operator ->() const { return &self; }
};
class C2Tuple_PaymentHashPaymentSecretZ {
private:
	LDKC2Tuple_PaymentHashPaymentSecretZ self;
public:
	C2Tuple_PaymentHashPaymentSecretZ(const C2Tuple_PaymentHashPaymentSecretZ&) = delete;
	C2Tuple_PaymentHashPaymentSecretZ(C2Tuple_PaymentHashPaymentSecretZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_PaymentHashPaymentSecretZ)); }
	C2Tuple_PaymentHashPaymentSecretZ(LDKC2Tuple_PaymentHashPaymentSecretZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_PaymentHashPaymentSecretZ)); }
	operator LDKC2Tuple_PaymentHashPaymentSecretZ() && { LDKC2Tuple_PaymentHashPaymentSecretZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_PaymentHashPaymentSecretZ)); return res; }
	~C2Tuple_PaymentHashPaymentSecretZ() { C2Tuple_PaymentHashPaymentSecretZ_free(self); }
	C2Tuple_PaymentHashPaymentSecretZ& operator=(C2Tuple_PaymentHashPaymentSecretZ&& o) { C2Tuple_PaymentHashPaymentSecretZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_PaymentHashPaymentSecretZ)); return *this; }
	LDKC2Tuple_PaymentHashPaymentSecretZ* operator &() { return &self; }
	LDKC2Tuple_PaymentHashPaymentSecretZ* operator ->() { return &self; }
	const LDKC2Tuple_PaymentHashPaymentSecretZ* operator &() const { return &self; }
	const LDKC2Tuple_PaymentHashPaymentSecretZ* operator ->() const { return &self; }
};
class C2Tuple_BlockHashChannelManagerZ {
private:
	LDKC2Tuple_BlockHashChannelManagerZ self;
public:
	C2Tuple_BlockHashChannelManagerZ(const C2Tuple_BlockHashChannelManagerZ&) = delete;
	C2Tuple_BlockHashChannelManagerZ(C2Tuple_BlockHashChannelManagerZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_BlockHashChannelManagerZ)); }
	C2Tuple_BlockHashChannelManagerZ(LDKC2Tuple_BlockHashChannelManagerZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_BlockHashChannelManagerZ)); }
	operator LDKC2Tuple_BlockHashChannelManagerZ() && { LDKC2Tuple_BlockHashChannelManagerZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_BlockHashChannelManagerZ)); return res; }
	~C2Tuple_BlockHashChannelManagerZ() { C2Tuple_BlockHashChannelManagerZ_free(self); }
	C2Tuple_BlockHashChannelManagerZ& operator=(C2Tuple_BlockHashChannelManagerZ&& o) { C2Tuple_BlockHashChannelManagerZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_BlockHashChannelManagerZ)); return *this; }
	LDKC2Tuple_BlockHashChannelManagerZ* operator &() { return &self; }
	LDKC2Tuple_BlockHashChannelManagerZ* operator ->() { return &self; }
	const LDKC2Tuple_BlockHashChannelManagerZ* operator &() const { return &self; }
	const LDKC2Tuple_BlockHashChannelManagerZ* operator ->() const { return &self; }
};
class CResult_ChannelTransactionParametersDecodeErrorZ {
private:
	LDKCResult_ChannelTransactionParametersDecodeErrorZ self;
public:
	CResult_ChannelTransactionParametersDecodeErrorZ(const CResult_ChannelTransactionParametersDecodeErrorZ&) = delete;
	CResult_ChannelTransactionParametersDecodeErrorZ(CResult_ChannelTransactionParametersDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelTransactionParametersDecodeErrorZ)); }
	CResult_ChannelTransactionParametersDecodeErrorZ(LDKCResult_ChannelTransactionParametersDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelTransactionParametersDecodeErrorZ)); }
	operator LDKCResult_ChannelTransactionParametersDecodeErrorZ() && { LDKCResult_ChannelTransactionParametersDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelTransactionParametersDecodeErrorZ)); return res; }
	~CResult_ChannelTransactionParametersDecodeErrorZ() { CResult_ChannelTransactionParametersDecodeErrorZ_free(self); }
	CResult_ChannelTransactionParametersDecodeErrorZ& operator=(CResult_ChannelTransactionParametersDecodeErrorZ&& o) { CResult_ChannelTransactionParametersDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelTransactionParametersDecodeErrorZ)); return *this; }
	LDKCResult_ChannelTransactionParametersDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelTransactionParametersDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelTransactionParametersDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelTransactionParametersDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_AcceptChannelDecodeErrorZ {
private:
	LDKCResult_AcceptChannelDecodeErrorZ self;
public:
	CResult_AcceptChannelDecodeErrorZ(const CResult_AcceptChannelDecodeErrorZ&) = delete;
	CResult_AcceptChannelDecodeErrorZ(CResult_AcceptChannelDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_AcceptChannelDecodeErrorZ)); }
	CResult_AcceptChannelDecodeErrorZ(LDKCResult_AcceptChannelDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_AcceptChannelDecodeErrorZ)); }
	operator LDKCResult_AcceptChannelDecodeErrorZ() && { LDKCResult_AcceptChannelDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_AcceptChannelDecodeErrorZ)); return res; }
	~CResult_AcceptChannelDecodeErrorZ() { CResult_AcceptChannelDecodeErrorZ_free(self); }
	CResult_AcceptChannelDecodeErrorZ& operator=(CResult_AcceptChannelDecodeErrorZ&& o) { CResult_AcceptChannelDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_AcceptChannelDecodeErrorZ)); return *this; }
	LDKCResult_AcceptChannelDecodeErrorZ* operator &() { return &self; }
	LDKCResult_AcceptChannelDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_AcceptChannelDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_AcceptChannelDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_SignatureZ {
private:
	LDKCVec_SignatureZ self;
public:
	CVec_SignatureZ(const CVec_SignatureZ&) = delete;
	CVec_SignatureZ(CVec_SignatureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_SignatureZ)); }
	CVec_SignatureZ(LDKCVec_SignatureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_SignatureZ)); }
	operator LDKCVec_SignatureZ() && { LDKCVec_SignatureZ res = self; memset(&self, 0, sizeof(LDKCVec_SignatureZ)); return res; }
	~CVec_SignatureZ() { CVec_SignatureZ_free(self); }
	CVec_SignatureZ& operator=(CVec_SignatureZ&& o) { CVec_SignatureZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_SignatureZ)); return *this; }
	LDKCVec_SignatureZ* operator &() { return &self; }
	LDKCVec_SignatureZ* operator ->() { return &self; }
	const LDKCVec_SignatureZ* operator &() const { return &self; }
	const LDKCVec_SignatureZ* operator ->() const { return &self; }
};
class CVec_u64Z {
private:
	LDKCVec_u64Z self;
public:
	CVec_u64Z(const CVec_u64Z&) = delete;
	CVec_u64Z(CVec_u64Z&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_u64Z)); }
	CVec_u64Z(LDKCVec_u64Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_u64Z)); }
	operator LDKCVec_u64Z() && { LDKCVec_u64Z res = self; memset(&self, 0, sizeof(LDKCVec_u64Z)); return res; }
	~CVec_u64Z() { CVec_u64Z_free(self); }
	CVec_u64Z& operator=(CVec_u64Z&& o) { CVec_u64Z_free(self); self = o.self; memset(&o, 0, sizeof(CVec_u64Z)); return *this; }
	LDKCVec_u64Z* operator &() { return &self; }
	LDKCVec_u64Z* operator ->() { return &self; }
	const LDKCVec_u64Z* operator &() const { return &self; }
	const LDKCVec_u64Z* operator ->() const { return &self; }
};
class CResult_UnsignedChannelAnnouncementDecodeErrorZ {
private:
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ self;
public:
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(const CResult_UnsignedChannelAnnouncementDecodeErrorZ&) = delete;
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(CResult_UnsignedChannelAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedChannelAnnouncementDecodeErrorZ)); }
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ)); }
	operator LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ() && { LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ)); return res; }
	~CResult_UnsignedChannelAnnouncementDecodeErrorZ() { CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(self); }
	CResult_UnsignedChannelAnnouncementDecodeErrorZ& operator=(CResult_UnsignedChannelAnnouncementDecodeErrorZ&& o) { CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedChannelAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
private:
	LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ self;
public:
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ(const CResult_DelayedPaymentOutputDescriptorDecodeErrorZ&) = delete;
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ(CResult_DelayedPaymentOutputDescriptorDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_DelayedPaymentOutputDescriptorDecodeErrorZ)); }
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ(LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ)); }
	operator LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ() && { LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ)); return res; }
	~CResult_DelayedPaymentOutputDescriptorDecodeErrorZ() { CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_free(self); }
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ& operator=(CResult_DelayedPaymentOutputDescriptorDecodeErrorZ&& o) { CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_DelayedPaymentOutputDescriptorDecodeErrorZ)); return *this; }
	LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ* operator &() { return &self; }
	LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_DelayedPaymentOutputDescriptorDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_PaymentHashPaymentIdZ {
private:
	LDKC2Tuple_PaymentHashPaymentIdZ self;
public:
	C2Tuple_PaymentHashPaymentIdZ(const C2Tuple_PaymentHashPaymentIdZ&) = delete;
	C2Tuple_PaymentHashPaymentIdZ(C2Tuple_PaymentHashPaymentIdZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_PaymentHashPaymentIdZ)); }
	C2Tuple_PaymentHashPaymentIdZ(LDKC2Tuple_PaymentHashPaymentIdZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_PaymentHashPaymentIdZ)); }
	operator LDKC2Tuple_PaymentHashPaymentIdZ() && { LDKC2Tuple_PaymentHashPaymentIdZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_PaymentHashPaymentIdZ)); return res; }
	~C2Tuple_PaymentHashPaymentIdZ() { C2Tuple_PaymentHashPaymentIdZ_free(self); }
	C2Tuple_PaymentHashPaymentIdZ& operator=(C2Tuple_PaymentHashPaymentIdZ&& o) { C2Tuple_PaymentHashPaymentIdZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_PaymentHashPaymentIdZ)); return *this; }
	LDKC2Tuple_PaymentHashPaymentIdZ* operator &() { return &self; }
	LDKC2Tuple_PaymentHashPaymentIdZ* operator ->() { return &self; }
	const LDKC2Tuple_PaymentHashPaymentIdZ* operator &() const { return &self; }
	const LDKC2Tuple_PaymentHashPaymentIdZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
private:
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ self;
public:
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ(const CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ&) = delete;
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ(CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ)); }
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ(LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ)); }
	operator LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ() && { LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ)); return res; }
	~CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ() { CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_free(self); }
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ& operator=(CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ&& o) { CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ)); return *this; }
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ* operator &() { return &self; }
	LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ* operator ->() const { return &self; }
};
class CResult_NoneErrorZ {
private:
	LDKCResult_NoneErrorZ self;
public:
	CResult_NoneErrorZ(const CResult_NoneErrorZ&) = delete;
	CResult_NoneErrorZ(CResult_NoneErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneErrorZ)); }
	CResult_NoneErrorZ(LDKCResult_NoneErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneErrorZ)); }
	operator LDKCResult_NoneErrorZ() && { LDKCResult_NoneErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneErrorZ)); return res; }
	~CResult_NoneErrorZ() { CResult_NoneErrorZ_free(self); }
	CResult_NoneErrorZ& operator=(CResult_NoneErrorZ&& o) { CResult_NoneErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneErrorZ)); return *this; }
	LDKCResult_NoneErrorZ* operator &() { return &self; }
	LDKCResult_NoneErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneErrorZ* operator ->() const { return &self; }
};
class CResult_COption_HTLCDestinationZDecodeErrorZ {
private:
	LDKCResult_COption_HTLCDestinationZDecodeErrorZ self;
public:
	CResult_COption_HTLCDestinationZDecodeErrorZ(const CResult_COption_HTLCDestinationZDecodeErrorZ&) = delete;
	CResult_COption_HTLCDestinationZDecodeErrorZ(CResult_COption_HTLCDestinationZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_HTLCDestinationZDecodeErrorZ)); }
	CResult_COption_HTLCDestinationZDecodeErrorZ(LDKCResult_COption_HTLCDestinationZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_HTLCDestinationZDecodeErrorZ)); }
	operator LDKCResult_COption_HTLCDestinationZDecodeErrorZ() && { LDKCResult_COption_HTLCDestinationZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_HTLCDestinationZDecodeErrorZ)); return res; }
	~CResult_COption_HTLCDestinationZDecodeErrorZ() { CResult_COption_HTLCDestinationZDecodeErrorZ_free(self); }
	CResult_COption_HTLCDestinationZDecodeErrorZ& operator=(CResult_COption_HTLCDestinationZDecodeErrorZ&& o) { CResult_COption_HTLCDestinationZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_HTLCDestinationZDecodeErrorZ)); return *this; }
	LDKCResult_COption_HTLCDestinationZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_HTLCDestinationZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_HTLCDestinationZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_HTLCDestinationZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_InFlightHtlcsDecodeErrorZ {
private:
	LDKCResult_InFlightHtlcsDecodeErrorZ self;
public:
	CResult_InFlightHtlcsDecodeErrorZ(const CResult_InFlightHtlcsDecodeErrorZ&) = delete;
	CResult_InFlightHtlcsDecodeErrorZ(CResult_InFlightHtlcsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InFlightHtlcsDecodeErrorZ)); }
	CResult_InFlightHtlcsDecodeErrorZ(LDKCResult_InFlightHtlcsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InFlightHtlcsDecodeErrorZ)); }
	operator LDKCResult_InFlightHtlcsDecodeErrorZ() && { LDKCResult_InFlightHtlcsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InFlightHtlcsDecodeErrorZ)); return res; }
	~CResult_InFlightHtlcsDecodeErrorZ() { CResult_InFlightHtlcsDecodeErrorZ_free(self); }
	CResult_InFlightHtlcsDecodeErrorZ& operator=(CResult_InFlightHtlcsDecodeErrorZ&& o) { CResult_InFlightHtlcsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InFlightHtlcsDecodeErrorZ)); return *this; }
	LDKCResult_InFlightHtlcsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InFlightHtlcsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InFlightHtlcsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InFlightHtlcsDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_StringErrorZ {
private:
	LDKCResult_StringErrorZ self;
public:
	CResult_StringErrorZ(const CResult_StringErrorZ&) = delete;
	CResult_StringErrorZ(CResult_StringErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_StringErrorZ)); }
	CResult_StringErrorZ(LDKCResult_StringErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_StringErrorZ)); }
	operator LDKCResult_StringErrorZ() && { LDKCResult_StringErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_StringErrorZ)); return res; }
	~CResult_StringErrorZ() { CResult_StringErrorZ_free(self); }
	CResult_StringErrorZ& operator=(CResult_StringErrorZ&& o) { CResult_StringErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_StringErrorZ)); return *this; }
	LDKCResult_StringErrorZ* operator &() { return &self; }
	LDKCResult_StringErrorZ* operator ->() { return &self; }
	const LDKCResult_StringErrorZ* operator &() const { return &self; }
	const LDKCResult_StringErrorZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
private:
	LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ self;
public:
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ(const CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ&) = delete;
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ(CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ)); }
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ(LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ)); }
	operator LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ() && { LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ)); return res; }
	~CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ() { CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_free(self); }
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ& operator=(CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ&& o) { CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ)); return *this; }
	LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ* operator &() { return &self; }
	LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ* operator ->() const { return &self; }
};
class COption_EventZ {
private:
	LDKCOption_EventZ self;
public:
	COption_EventZ(const COption_EventZ&) = delete;
	COption_EventZ(COption_EventZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_EventZ)); }
	COption_EventZ(LDKCOption_EventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_EventZ)); }
	operator LDKCOption_EventZ() && { LDKCOption_EventZ res = self; memset(&self, 0, sizeof(LDKCOption_EventZ)); return res; }
	~COption_EventZ() { COption_EventZ_free(self); }
	COption_EventZ& operator=(COption_EventZ&& o) { COption_EventZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_EventZ)); return *this; }
	LDKCOption_EventZ* operator &() { return &self; }
	LDKCOption_EventZ* operator ->() { return &self; }
	const LDKCOption_EventZ* operator &() const { return &self; }
	const LDKCOption_EventZ* operator ->() const { return &self; }
};
class C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
private:
	LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ self;
public:
	C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ(const C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ&) = delete;
	C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ(C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ)); }
	C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ(LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ)); }
	operator LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ() && { LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ)); return res; }
	~C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ() { C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ_free(self); }
	C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ& operator=(C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ&& o) { C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ)); return *this; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ* operator &() { return &self; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ* operator ->() { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ* operator &() const { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ* operator ->() const { return &self; }
};
class CResult_ChannelTypeFeaturesDecodeErrorZ {
private:
	LDKCResult_ChannelTypeFeaturesDecodeErrorZ self;
public:
	CResult_ChannelTypeFeaturesDecodeErrorZ(const CResult_ChannelTypeFeaturesDecodeErrorZ&) = delete;
	CResult_ChannelTypeFeaturesDecodeErrorZ(CResult_ChannelTypeFeaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelTypeFeaturesDecodeErrorZ)); }
	CResult_ChannelTypeFeaturesDecodeErrorZ(LDKCResult_ChannelTypeFeaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelTypeFeaturesDecodeErrorZ)); }
	operator LDKCResult_ChannelTypeFeaturesDecodeErrorZ() && { LDKCResult_ChannelTypeFeaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelTypeFeaturesDecodeErrorZ)); return res; }
	~CResult_ChannelTypeFeaturesDecodeErrorZ() { CResult_ChannelTypeFeaturesDecodeErrorZ_free(self); }
	CResult_ChannelTypeFeaturesDecodeErrorZ& operator=(CResult_ChannelTypeFeaturesDecodeErrorZ&& o) { CResult_ChannelTypeFeaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelTypeFeaturesDecodeErrorZ)); return *this; }
	LDKCResult_ChannelTypeFeaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelTypeFeaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelTypeFeaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelTypeFeaturesDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_SiPrefixParseErrorZ {
private:
	LDKCResult_SiPrefixParseErrorZ self;
public:
	CResult_SiPrefixParseErrorZ(const CResult_SiPrefixParseErrorZ&) = delete;
	CResult_SiPrefixParseErrorZ(CResult_SiPrefixParseErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SiPrefixParseErrorZ)); }
	CResult_SiPrefixParseErrorZ(LDKCResult_SiPrefixParseErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SiPrefixParseErrorZ)); }
	operator LDKCResult_SiPrefixParseErrorZ() && { LDKCResult_SiPrefixParseErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SiPrefixParseErrorZ)); return res; }
	~CResult_SiPrefixParseErrorZ() { CResult_SiPrefixParseErrorZ_free(self); }
	CResult_SiPrefixParseErrorZ& operator=(CResult_SiPrefixParseErrorZ&& o) { CResult_SiPrefixParseErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SiPrefixParseErrorZ)); return *this; }
	LDKCResult_SiPrefixParseErrorZ* operator &() { return &self; }
	LDKCResult_SiPrefixParseErrorZ* operator ->() { return &self; }
	const LDKCResult_SiPrefixParseErrorZ* operator &() const { return &self; }
	const LDKCResult_SiPrefixParseErrorZ* operator ->() const { return &self; }
};
class CVec_RouteHintZ {
private:
	LDKCVec_RouteHintZ self;
public:
	CVec_RouteHintZ(const CVec_RouteHintZ&) = delete;
	CVec_RouteHintZ(CVec_RouteHintZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_RouteHintZ)); }
	CVec_RouteHintZ(LDKCVec_RouteHintZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_RouteHintZ)); }
	operator LDKCVec_RouteHintZ() && { LDKCVec_RouteHintZ res = self; memset(&self, 0, sizeof(LDKCVec_RouteHintZ)); return res; }
	~CVec_RouteHintZ() { CVec_RouteHintZ_free(self); }
	CVec_RouteHintZ& operator=(CVec_RouteHintZ&& o) { CVec_RouteHintZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_RouteHintZ)); return *this; }
	LDKCVec_RouteHintZ* operator &() { return &self; }
	LDKCVec_RouteHintZ* operator ->() { return &self; }
	const LDKCVec_RouteHintZ* operator &() const { return &self; }
	const LDKCVec_RouteHintZ* operator ->() const { return &self; }
};
class COption_u16Z {
private:
	LDKCOption_u16Z self;
public:
	COption_u16Z(const COption_u16Z&) = delete;
	COption_u16Z(COption_u16Z&& o) : self(o.self) { memset(&o, 0, sizeof(COption_u16Z)); }
	COption_u16Z(LDKCOption_u16Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_u16Z)); }
	operator LDKCOption_u16Z() && { LDKCOption_u16Z res = self; memset(&self, 0, sizeof(LDKCOption_u16Z)); return res; }
	~COption_u16Z() { COption_u16Z_free(self); }
	COption_u16Z& operator=(COption_u16Z&& o) { COption_u16Z_free(self); self = o.self; memset(&o, 0, sizeof(COption_u16Z)); return *this; }
	LDKCOption_u16Z* operator &() { return &self; }
	LDKCOption_u16Z* operator ->() { return &self; }
	const LDKCOption_u16Z* operator &() const { return &self; }
	const LDKCOption_u16Z* operator ->() const { return &self; }
};
class CResult_BlindedHopDecodeErrorZ {
private:
	LDKCResult_BlindedHopDecodeErrorZ self;
public:
	CResult_BlindedHopDecodeErrorZ(const CResult_BlindedHopDecodeErrorZ&) = delete;
	CResult_BlindedHopDecodeErrorZ(CResult_BlindedHopDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_BlindedHopDecodeErrorZ)); }
	CResult_BlindedHopDecodeErrorZ(LDKCResult_BlindedHopDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_BlindedHopDecodeErrorZ)); }
	operator LDKCResult_BlindedHopDecodeErrorZ() && { LDKCResult_BlindedHopDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_BlindedHopDecodeErrorZ)); return res; }
	~CResult_BlindedHopDecodeErrorZ() { CResult_BlindedHopDecodeErrorZ_free(self); }
	CResult_BlindedHopDecodeErrorZ& operator=(CResult_BlindedHopDecodeErrorZ&& o) { CResult_BlindedHopDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_BlindedHopDecodeErrorZ)); return *this; }
	LDKCResult_BlindedHopDecodeErrorZ* operator &() { return &self; }
	LDKCResult_BlindedHopDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_BlindedHopDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_BlindedHopDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_CVec_RouteHopZZ {
private:
	LDKCVec_CVec_RouteHopZZ self;
public:
	CVec_CVec_RouteHopZZ(const CVec_CVec_RouteHopZZ&) = delete;
	CVec_CVec_RouteHopZZ(CVec_CVec_RouteHopZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_CVec_RouteHopZZ)); }
	CVec_CVec_RouteHopZZ(LDKCVec_CVec_RouteHopZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_CVec_RouteHopZZ)); }
	operator LDKCVec_CVec_RouteHopZZ() && { LDKCVec_CVec_RouteHopZZ res = self; memset(&self, 0, sizeof(LDKCVec_CVec_RouteHopZZ)); return res; }
	~CVec_CVec_RouteHopZZ() { CVec_CVec_RouteHopZZ_free(self); }
	CVec_CVec_RouteHopZZ& operator=(CVec_CVec_RouteHopZZ&& o) { CVec_CVec_RouteHopZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_CVec_RouteHopZZ)); return *this; }
	LDKCVec_CVec_RouteHopZZ* operator &() { return &self; }
	LDKCVec_CVec_RouteHopZZ* operator ->() { return &self; }
	const LDKCVec_CVec_RouteHopZZ* operator &() const { return &self; }
	const LDKCVec_CVec_RouteHopZZ* operator ->() const { return &self; }
};
class CResult_TrustedCommitmentTransactionNoneZ {
private:
	LDKCResult_TrustedCommitmentTransactionNoneZ self;
public:
	CResult_TrustedCommitmentTransactionNoneZ(const CResult_TrustedCommitmentTransactionNoneZ&) = delete;
	CResult_TrustedCommitmentTransactionNoneZ(CResult_TrustedCommitmentTransactionNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TrustedCommitmentTransactionNoneZ)); }
	CResult_TrustedCommitmentTransactionNoneZ(LDKCResult_TrustedCommitmentTransactionNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TrustedCommitmentTransactionNoneZ)); }
	operator LDKCResult_TrustedCommitmentTransactionNoneZ() && { LDKCResult_TrustedCommitmentTransactionNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_TrustedCommitmentTransactionNoneZ)); return res; }
	~CResult_TrustedCommitmentTransactionNoneZ() { CResult_TrustedCommitmentTransactionNoneZ_free(self); }
	CResult_TrustedCommitmentTransactionNoneZ& operator=(CResult_TrustedCommitmentTransactionNoneZ&& o) { CResult_TrustedCommitmentTransactionNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TrustedCommitmentTransactionNoneZ)); return *this; }
	LDKCResult_TrustedCommitmentTransactionNoneZ* operator &() { return &self; }
	LDKCResult_TrustedCommitmentTransactionNoneZ* operator ->() { return &self; }
	const LDKCResult_TrustedCommitmentTransactionNoneZ* operator &() const { return &self; }
	const LDKCResult_TrustedCommitmentTransactionNoneZ* operator ->() const { return &self; }
};
class CResult_FixedPenaltyScorerDecodeErrorZ {
private:
	LDKCResult_FixedPenaltyScorerDecodeErrorZ self;
public:
	CResult_FixedPenaltyScorerDecodeErrorZ(const CResult_FixedPenaltyScorerDecodeErrorZ&) = delete;
	CResult_FixedPenaltyScorerDecodeErrorZ(CResult_FixedPenaltyScorerDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_FixedPenaltyScorerDecodeErrorZ)); }
	CResult_FixedPenaltyScorerDecodeErrorZ(LDKCResult_FixedPenaltyScorerDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_FixedPenaltyScorerDecodeErrorZ)); }
	operator LDKCResult_FixedPenaltyScorerDecodeErrorZ() && { LDKCResult_FixedPenaltyScorerDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_FixedPenaltyScorerDecodeErrorZ)); return res; }
	~CResult_FixedPenaltyScorerDecodeErrorZ() { CResult_FixedPenaltyScorerDecodeErrorZ_free(self); }
	CResult_FixedPenaltyScorerDecodeErrorZ& operator=(CResult_FixedPenaltyScorerDecodeErrorZ&& o) { CResult_FixedPenaltyScorerDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_FixedPenaltyScorerDecodeErrorZ)); return *this; }
	LDKCResult_FixedPenaltyScorerDecodeErrorZ* operator &() { return &self; }
	LDKCResult_FixedPenaltyScorerDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_FixedPenaltyScorerDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_FixedPenaltyScorerDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NoneLightningErrorZ {
private:
	LDKCResult_NoneLightningErrorZ self;
public:
	CResult_NoneLightningErrorZ(const CResult_NoneLightningErrorZ&) = delete;
	CResult_NoneLightningErrorZ(CResult_NoneLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneLightningErrorZ)); }
	CResult_NoneLightningErrorZ(LDKCResult_NoneLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneLightningErrorZ)); }
	operator LDKCResult_NoneLightningErrorZ() && { LDKCResult_NoneLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneLightningErrorZ)); return res; }
	~CResult_NoneLightningErrorZ() { CResult_NoneLightningErrorZ_free(self); }
	CResult_NoneLightningErrorZ& operator=(CResult_NoneLightningErrorZ&& o) { CResult_NoneLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneLightningErrorZ)); return *this; }
	LDKCResult_NoneLightningErrorZ* operator &() { return &self; }
	LDKCResult_NoneLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneLightningErrorZ* operator ->() const { return &self; }
};
class CResult_NonePeerHandleErrorZ {
private:
	LDKCResult_NonePeerHandleErrorZ self;
public:
	CResult_NonePeerHandleErrorZ(const CResult_NonePeerHandleErrorZ&) = delete;
	CResult_NonePeerHandleErrorZ(CResult_NonePeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NonePeerHandleErrorZ)); }
	CResult_NonePeerHandleErrorZ(LDKCResult_NonePeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NonePeerHandleErrorZ)); }
	operator LDKCResult_NonePeerHandleErrorZ() && { LDKCResult_NonePeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NonePeerHandleErrorZ)); return res; }
	~CResult_NonePeerHandleErrorZ() { CResult_NonePeerHandleErrorZ_free(self); }
	CResult_NonePeerHandleErrorZ& operator=(CResult_NonePeerHandleErrorZ&& o) { CResult_NonePeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NonePeerHandleErrorZ)); return *this; }
	LDKCResult_NonePeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_NonePeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_NonePeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_NonePeerHandleErrorZ* operator ->() const { return &self; }
};
class CResult_COption_EventZDecodeErrorZ {
private:
	LDKCResult_COption_EventZDecodeErrorZ self;
public:
	CResult_COption_EventZDecodeErrorZ(const CResult_COption_EventZDecodeErrorZ&) = delete;
	CResult_COption_EventZDecodeErrorZ(CResult_COption_EventZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_EventZDecodeErrorZ)); }
	CResult_COption_EventZDecodeErrorZ(LDKCResult_COption_EventZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_EventZDecodeErrorZ)); }
	operator LDKCResult_COption_EventZDecodeErrorZ() && { LDKCResult_COption_EventZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_EventZDecodeErrorZ)); return res; }
	~CResult_COption_EventZDecodeErrorZ() { CResult_COption_EventZDecodeErrorZ_free(self); }
	CResult_COption_EventZDecodeErrorZ& operator=(CResult_COption_EventZDecodeErrorZ&& o) { CResult_COption_EventZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_EventZDecodeErrorZ)); return *this; }
	LDKCResult_COption_EventZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_EventZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_EventZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_EventZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CVec_SignatureZNoneZ {
private:
	LDKCResult_CVec_SignatureZNoneZ self;
public:
	CResult_CVec_SignatureZNoneZ(const CResult_CVec_SignatureZNoneZ&) = delete;
	CResult_CVec_SignatureZNoneZ(CResult_CVec_SignatureZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_SignatureZNoneZ)); }
	CResult_CVec_SignatureZNoneZ(LDKCResult_CVec_SignatureZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_SignatureZNoneZ)); }
	operator LDKCResult_CVec_SignatureZNoneZ() && { LDKCResult_CVec_SignatureZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_SignatureZNoneZ)); return res; }
	~CResult_CVec_SignatureZNoneZ() { CResult_CVec_SignatureZNoneZ_free(self); }
	CResult_CVec_SignatureZNoneZ& operator=(CResult_CVec_SignatureZNoneZ&& o) { CResult_CVec_SignatureZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_SignatureZNoneZ)); return *this; }
	LDKCResult_CVec_SignatureZNoneZ* operator &() { return &self; }
	LDKCResult_CVec_SignatureZNoneZ* operator ->() { return &self; }
	const LDKCResult_CVec_SignatureZNoneZ* operator &() const { return &self; }
	const LDKCResult_CVec_SignatureZNoneZ* operator ->() const { return &self; }
};
class COption_CVec_NetAddressZZ {
private:
	LDKCOption_CVec_NetAddressZZ self;
public:
	COption_CVec_NetAddressZZ(const COption_CVec_NetAddressZZ&) = delete;
	COption_CVec_NetAddressZZ(COption_CVec_NetAddressZZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_CVec_NetAddressZZ)); }
	COption_CVec_NetAddressZZ(LDKCOption_CVec_NetAddressZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_CVec_NetAddressZZ)); }
	operator LDKCOption_CVec_NetAddressZZ() && { LDKCOption_CVec_NetAddressZZ res = self; memset(&self, 0, sizeof(LDKCOption_CVec_NetAddressZZ)); return res; }
	~COption_CVec_NetAddressZZ() { COption_CVec_NetAddressZZ_free(self); }
	COption_CVec_NetAddressZZ& operator=(COption_CVec_NetAddressZZ&& o) { COption_CVec_NetAddressZZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_CVec_NetAddressZZ)); return *this; }
	LDKCOption_CVec_NetAddressZZ* operator &() { return &self; }
	LDKCOption_CVec_NetAddressZZ* operator ->() { return &self; }
	const LDKCOption_CVec_NetAddressZZ* operator &() const { return &self; }
	const LDKCOption_CVec_NetAddressZZ* operator ->() const { return &self; }
};
class CResult__u832APIErrorZ {
private:
	LDKCResult__u832APIErrorZ self;
public:
	CResult__u832APIErrorZ(const CResult__u832APIErrorZ&) = delete;
	CResult__u832APIErrorZ(CResult__u832APIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult__u832APIErrorZ)); }
	CResult__u832APIErrorZ(LDKCResult__u832APIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult__u832APIErrorZ)); }
	operator LDKCResult__u832APIErrorZ() && { LDKCResult__u832APIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult__u832APIErrorZ)); return res; }
	~CResult__u832APIErrorZ() { CResult__u832APIErrorZ_free(self); }
	CResult__u832APIErrorZ& operator=(CResult__u832APIErrorZ&& o) { CResult__u832APIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult__u832APIErrorZ)); return *this; }
	LDKCResult__u832APIErrorZ* operator &() { return &self; }
	LDKCResult__u832APIErrorZ* operator ->() { return &self; }
	const LDKCResult__u832APIErrorZ* operator &() const { return &self; }
	const LDKCResult__u832APIErrorZ* operator ->() const { return &self; }
};
class CResult_PaymentIdPaymentErrorZ {
private:
	LDKCResult_PaymentIdPaymentErrorZ self;
public:
	CResult_PaymentIdPaymentErrorZ(const CResult_PaymentIdPaymentErrorZ&) = delete;
	CResult_PaymentIdPaymentErrorZ(CResult_PaymentIdPaymentErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentIdPaymentErrorZ)); }
	CResult_PaymentIdPaymentErrorZ(LDKCResult_PaymentIdPaymentErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentIdPaymentErrorZ)); }
	operator LDKCResult_PaymentIdPaymentErrorZ() && { LDKCResult_PaymentIdPaymentErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentIdPaymentErrorZ)); return res; }
	~CResult_PaymentIdPaymentErrorZ() { CResult_PaymentIdPaymentErrorZ_free(self); }
	CResult_PaymentIdPaymentErrorZ& operator=(CResult_PaymentIdPaymentErrorZ&& o) { CResult_PaymentIdPaymentErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentIdPaymentErrorZ)); return *this; }
	LDKCResult_PaymentIdPaymentErrorZ* operator &() { return &self; }
	LDKCResult_PaymentIdPaymentErrorZ* operator ->() { return &self; }
	const LDKCResult_PaymentIdPaymentErrorZ* operator &() const { return &self; }
	const LDKCResult_PaymentIdPaymentErrorZ* operator ->() const { return &self; }
};
class CResult_DescriptionCreationErrorZ {
private:
	LDKCResult_DescriptionCreationErrorZ self;
public:
	CResult_DescriptionCreationErrorZ(const CResult_DescriptionCreationErrorZ&) = delete;
	CResult_DescriptionCreationErrorZ(CResult_DescriptionCreationErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_DescriptionCreationErrorZ)); }
	CResult_DescriptionCreationErrorZ(LDKCResult_DescriptionCreationErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_DescriptionCreationErrorZ)); }
	operator LDKCResult_DescriptionCreationErrorZ() && { LDKCResult_DescriptionCreationErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_DescriptionCreationErrorZ)); return res; }
	~CResult_DescriptionCreationErrorZ() { CResult_DescriptionCreationErrorZ_free(self); }
	CResult_DescriptionCreationErrorZ& operator=(CResult_DescriptionCreationErrorZ&& o) { CResult_DescriptionCreationErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_DescriptionCreationErrorZ)); return *this; }
	LDKCResult_DescriptionCreationErrorZ* operator &() { return &self; }
	LDKCResult_DescriptionCreationErrorZ* operator ->() { return &self; }
	const LDKCResult_DescriptionCreationErrorZ* operator &() const { return &self; }
	const LDKCResult_DescriptionCreationErrorZ* operator ->() const { return &self; }
};
class CResult_RoutingFeesDecodeErrorZ {
private:
	LDKCResult_RoutingFeesDecodeErrorZ self;
public:
	CResult_RoutingFeesDecodeErrorZ(const CResult_RoutingFeesDecodeErrorZ&) = delete;
	CResult_RoutingFeesDecodeErrorZ(CResult_RoutingFeesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RoutingFeesDecodeErrorZ)); }
	CResult_RoutingFeesDecodeErrorZ(LDKCResult_RoutingFeesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RoutingFeesDecodeErrorZ)); }
	operator LDKCResult_RoutingFeesDecodeErrorZ() && { LDKCResult_RoutingFeesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RoutingFeesDecodeErrorZ)); return res; }
	~CResult_RoutingFeesDecodeErrorZ() { CResult_RoutingFeesDecodeErrorZ_free(self); }
	CResult_RoutingFeesDecodeErrorZ& operator=(CResult_RoutingFeesDecodeErrorZ&& o) { CResult_RoutingFeesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RoutingFeesDecodeErrorZ)); return *this; }
	LDKCResult_RoutingFeesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RoutingFeesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RoutingFeesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RoutingFeesDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PayeePubKeyErrorZ {
private:
	LDKCResult_PayeePubKeyErrorZ self;
public:
	CResult_PayeePubKeyErrorZ(const CResult_PayeePubKeyErrorZ&) = delete;
	CResult_PayeePubKeyErrorZ(CResult_PayeePubKeyErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PayeePubKeyErrorZ)); }
	CResult_PayeePubKeyErrorZ(LDKCResult_PayeePubKeyErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PayeePubKeyErrorZ)); }
	operator LDKCResult_PayeePubKeyErrorZ() && { LDKCResult_PayeePubKeyErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PayeePubKeyErrorZ)); return res; }
	~CResult_PayeePubKeyErrorZ() { CResult_PayeePubKeyErrorZ_free(self); }
	CResult_PayeePubKeyErrorZ& operator=(CResult_PayeePubKeyErrorZ&& o) { CResult_PayeePubKeyErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PayeePubKeyErrorZ)); return *this; }
	LDKCResult_PayeePubKeyErrorZ* operator &() { return &self; }
	LDKCResult_PayeePubKeyErrorZ* operator ->() { return &self; }
	const LDKCResult_PayeePubKeyErrorZ* operator &() const { return &self; }
	const LDKCResult_PayeePubKeyErrorZ* operator ->() const { return &self; }
};
class CResult_COption_MonitorEventZDecodeErrorZ {
private:
	LDKCResult_COption_MonitorEventZDecodeErrorZ self;
public:
	CResult_COption_MonitorEventZDecodeErrorZ(const CResult_COption_MonitorEventZDecodeErrorZ&) = delete;
	CResult_COption_MonitorEventZDecodeErrorZ(CResult_COption_MonitorEventZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_MonitorEventZDecodeErrorZ)); }
	CResult_COption_MonitorEventZDecodeErrorZ(LDKCResult_COption_MonitorEventZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_MonitorEventZDecodeErrorZ)); }
	operator LDKCResult_COption_MonitorEventZDecodeErrorZ() && { LDKCResult_COption_MonitorEventZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_MonitorEventZDecodeErrorZ)); return res; }
	~CResult_COption_MonitorEventZDecodeErrorZ() { CResult_COption_MonitorEventZDecodeErrorZ_free(self); }
	CResult_COption_MonitorEventZDecodeErrorZ& operator=(CResult_COption_MonitorEventZDecodeErrorZ&& o) { CResult_COption_MonitorEventZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_MonitorEventZDecodeErrorZ)); return *this; }
	LDKCResult_COption_MonitorEventZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_MonitorEventZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_MonitorEventZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_MonitorEventZDecodeErrorZ* operator ->() const { return &self; }
};
class C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ {
private:
	LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ self;
public:
	C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ(const C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ&) = delete;
	C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ(C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ&& o) : self(o.self) { memset(&o, 0, sizeof(C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ)); }
	C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ(LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ)); }
	operator LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ() && { LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ res = self; memset(&self, 0, sizeof(LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ)); return res; }
	~C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ() { C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ_free(self); }
	C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ& operator=(C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ&& o) { C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ_free(self); self = o.self; memset(&o, 0, sizeof(C3Tuple_OutPointCVec_MonitorEventZPublicKeyZ)); return *this; }
	LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ* operator &() { return &self; }
	LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ* operator ->() { return &self; }
	const LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ* operator &() const { return &self; }
	const LDKC3Tuple_OutPointCVec_MonitorEventZPublicKeyZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_PublicKeyTypeZZ {
private:
	LDKCVec_C2Tuple_PublicKeyTypeZZ self;
public:
	CVec_C2Tuple_PublicKeyTypeZZ(const CVec_C2Tuple_PublicKeyTypeZZ&) = delete;
	CVec_C2Tuple_PublicKeyTypeZZ(CVec_C2Tuple_PublicKeyTypeZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_PublicKeyTypeZZ)); }
	CVec_C2Tuple_PublicKeyTypeZZ(LDKCVec_C2Tuple_PublicKeyTypeZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_PublicKeyTypeZZ)); }
	operator LDKCVec_C2Tuple_PublicKeyTypeZZ() && { LDKCVec_C2Tuple_PublicKeyTypeZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_PublicKeyTypeZZ)); return res; }
	~CVec_C2Tuple_PublicKeyTypeZZ() { CVec_C2Tuple_PublicKeyTypeZZ_free(self); }
	CVec_C2Tuple_PublicKeyTypeZZ& operator=(CVec_C2Tuple_PublicKeyTypeZZ&& o) { CVec_C2Tuple_PublicKeyTypeZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_PublicKeyTypeZZ)); return *this; }
	LDKCVec_C2Tuple_PublicKeyTypeZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_PublicKeyTypeZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_PublicKeyTypeZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_PublicKeyTypeZZ* operator ->() const { return &self; }
};
class CResult_InvoiceSemanticErrorZ {
private:
	LDKCResult_InvoiceSemanticErrorZ self;
public:
	CResult_InvoiceSemanticErrorZ(const CResult_InvoiceSemanticErrorZ&) = delete;
	CResult_InvoiceSemanticErrorZ(CResult_InvoiceSemanticErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InvoiceSemanticErrorZ)); }
	CResult_InvoiceSemanticErrorZ(LDKCResult_InvoiceSemanticErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InvoiceSemanticErrorZ)); }
	operator LDKCResult_InvoiceSemanticErrorZ() && { LDKCResult_InvoiceSemanticErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InvoiceSemanticErrorZ)); return res; }
	~CResult_InvoiceSemanticErrorZ() { CResult_InvoiceSemanticErrorZ_free(self); }
	CResult_InvoiceSemanticErrorZ& operator=(CResult_InvoiceSemanticErrorZ&& o) { CResult_InvoiceSemanticErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InvoiceSemanticErrorZ)); return *this; }
	LDKCResult_InvoiceSemanticErrorZ* operator &() { return &self; }
	LDKCResult_InvoiceSemanticErrorZ* operator ->() { return &self; }
	const LDKCResult_InvoiceSemanticErrorZ* operator &() const { return &self; }
	const LDKCResult_InvoiceSemanticErrorZ* operator ->() const { return &self; }
};
class CResult_u32GraphSyncErrorZ {
private:
	LDKCResult_u32GraphSyncErrorZ self;
public:
	CResult_u32GraphSyncErrorZ(const CResult_u32GraphSyncErrorZ&) = delete;
	CResult_u32GraphSyncErrorZ(CResult_u32GraphSyncErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_u32GraphSyncErrorZ)); }
	CResult_u32GraphSyncErrorZ(LDKCResult_u32GraphSyncErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_u32GraphSyncErrorZ)); }
	operator LDKCResult_u32GraphSyncErrorZ() && { LDKCResult_u32GraphSyncErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_u32GraphSyncErrorZ)); return res; }
	~CResult_u32GraphSyncErrorZ() { CResult_u32GraphSyncErrorZ_free(self); }
	CResult_u32GraphSyncErrorZ& operator=(CResult_u32GraphSyncErrorZ&& o) { CResult_u32GraphSyncErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_u32GraphSyncErrorZ)); return *this; }
	LDKCResult_u32GraphSyncErrorZ* operator &() { return &self; }
	LDKCResult_u32GraphSyncErrorZ* operator ->() { return &self; }
	const LDKCResult_u32GraphSyncErrorZ* operator &() const { return &self; }
	const LDKCResult_u32GraphSyncErrorZ* operator ->() const { return &self; }
};
class CResult_UpdateAddHTLCDecodeErrorZ {
private:
	LDKCResult_UpdateAddHTLCDecodeErrorZ self;
public:
	CResult_UpdateAddHTLCDecodeErrorZ(const CResult_UpdateAddHTLCDecodeErrorZ&) = delete;
	CResult_UpdateAddHTLCDecodeErrorZ(CResult_UpdateAddHTLCDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UpdateAddHTLCDecodeErrorZ)); }
	CResult_UpdateAddHTLCDecodeErrorZ(LDKCResult_UpdateAddHTLCDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UpdateAddHTLCDecodeErrorZ)); }
	operator LDKCResult_UpdateAddHTLCDecodeErrorZ() && { LDKCResult_UpdateAddHTLCDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UpdateAddHTLCDecodeErrorZ)); return res; }
	~CResult_UpdateAddHTLCDecodeErrorZ() { CResult_UpdateAddHTLCDecodeErrorZ_free(self); }
	CResult_UpdateAddHTLCDecodeErrorZ& operator=(CResult_UpdateAddHTLCDecodeErrorZ&& o) { CResult_UpdateAddHTLCDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UpdateAddHTLCDecodeErrorZ)); return *this; }
	LDKCResult_UpdateAddHTLCDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UpdateAddHTLCDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UpdateAddHTLCDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UpdateAddHTLCDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
private:
	LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ self;
public:
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ(const CResult_CounterpartyChannelTransactionParametersDecodeErrorZ&) = delete;
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ(CResult_CounterpartyChannelTransactionParametersDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CounterpartyChannelTransactionParametersDecodeErrorZ)); }
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ(LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ)); }
	operator LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ() && { LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ)); return res; }
	~CResult_CounterpartyChannelTransactionParametersDecodeErrorZ() { CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_free(self); }
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ& operator=(CResult_CounterpartyChannelTransactionParametersDecodeErrorZ&& o) { CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CounterpartyChannelTransactionParametersDecodeErrorZ)); return *this; }
	LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CounterpartyChannelTransactionParametersDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NoneAPIErrorZ {
private:
	LDKCResult_NoneAPIErrorZ self;
public:
	CResult_NoneAPIErrorZ(const CResult_NoneAPIErrorZ&) = delete;
	CResult_NoneAPIErrorZ(CResult_NoneAPIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneAPIErrorZ)); }
	CResult_NoneAPIErrorZ(LDKCResult_NoneAPIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneAPIErrorZ)); }
	operator LDKCResult_NoneAPIErrorZ() && { LDKCResult_NoneAPIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneAPIErrorZ)); return res; }
	~CResult_NoneAPIErrorZ() { CResult_NoneAPIErrorZ_free(self); }
	CResult_NoneAPIErrorZ& operator=(CResult_NoneAPIErrorZ&& o) { CResult_NoneAPIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneAPIErrorZ)); return *this; }
	LDKCResult_NoneAPIErrorZ* operator &() { return &self; }
	LDKCResult_NoneAPIErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneAPIErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneAPIErrorZ* operator ->() const { return &self; }
};
class CVec_NetAddressZ {
private:
	LDKCVec_NetAddressZ self;
public:
	CVec_NetAddressZ(const CVec_NetAddressZ&) = delete;
	CVec_NetAddressZ(CVec_NetAddressZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_NetAddressZ)); }
	CVec_NetAddressZ(LDKCVec_NetAddressZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_NetAddressZ)); }
	operator LDKCVec_NetAddressZ() && { LDKCVec_NetAddressZ res = self; memset(&self, 0, sizeof(LDKCVec_NetAddressZ)); return res; }
	~CVec_NetAddressZ() { CVec_NetAddressZ_free(self); }
	CVec_NetAddressZ& operator=(CVec_NetAddressZ&& o) { CVec_NetAddressZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_NetAddressZ)); return *this; }
	LDKCVec_NetAddressZ* operator &() { return &self; }
	LDKCVec_NetAddressZ* operator ->() { return &self; }
	const LDKCVec_NetAddressZ* operator &() const { return &self; }
	const LDKCVec_NetAddressZ* operator ->() const { return &self; }
};
class CResult_ChannelDetailsDecodeErrorZ {
private:
	LDKCResult_ChannelDetailsDecodeErrorZ self;
public:
	CResult_ChannelDetailsDecodeErrorZ(const CResult_ChannelDetailsDecodeErrorZ&) = delete;
	CResult_ChannelDetailsDecodeErrorZ(CResult_ChannelDetailsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelDetailsDecodeErrorZ)); }
	CResult_ChannelDetailsDecodeErrorZ(LDKCResult_ChannelDetailsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelDetailsDecodeErrorZ)); }
	operator LDKCResult_ChannelDetailsDecodeErrorZ() && { LDKCResult_ChannelDetailsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelDetailsDecodeErrorZ)); return res; }
	~CResult_ChannelDetailsDecodeErrorZ() { CResult_ChannelDetailsDecodeErrorZ_free(self); }
	CResult_ChannelDetailsDecodeErrorZ& operator=(CResult_ChannelDetailsDecodeErrorZ&& o) { CResult_ChannelDetailsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelDetailsDecodeErrorZ)); return *this; }
	LDKCResult_ChannelDetailsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelDetailsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelDetailsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelDetailsDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_PublicKeyZ {
private:
	LDKCVec_PublicKeyZ self;
public:
	CVec_PublicKeyZ(const CVec_PublicKeyZ&) = delete;
	CVec_PublicKeyZ(CVec_PublicKeyZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_PublicKeyZ)); }
	CVec_PublicKeyZ(LDKCVec_PublicKeyZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_PublicKeyZ)); }
	operator LDKCVec_PublicKeyZ() && { LDKCVec_PublicKeyZ res = self; memset(&self, 0, sizeof(LDKCVec_PublicKeyZ)); return res; }
	~CVec_PublicKeyZ() { CVec_PublicKeyZ_free(self); }
	CVec_PublicKeyZ& operator=(CVec_PublicKeyZ&& o) { CVec_PublicKeyZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_PublicKeyZ)); return *this; }
	LDKCVec_PublicKeyZ* operator &() { return &self; }
	LDKCVec_PublicKeyZ* operator ->() { return &self; }
	const LDKCVec_PublicKeyZ* operator &() const { return &self; }
	const LDKCVec_PublicKeyZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_usizeTransactionZZ {
private:
	LDKCVec_C2Tuple_usizeTransactionZZ self;
public:
	CVec_C2Tuple_usizeTransactionZZ(const CVec_C2Tuple_usizeTransactionZZ&) = delete;
	CVec_C2Tuple_usizeTransactionZZ(CVec_C2Tuple_usizeTransactionZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_usizeTransactionZZ)); }
	CVec_C2Tuple_usizeTransactionZZ(LDKCVec_C2Tuple_usizeTransactionZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_usizeTransactionZZ)); }
	operator LDKCVec_C2Tuple_usizeTransactionZZ() && { LDKCVec_C2Tuple_usizeTransactionZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_usizeTransactionZZ)); return res; }
	~CVec_C2Tuple_usizeTransactionZZ() { CVec_C2Tuple_usizeTransactionZZ_free(self); }
	CVec_C2Tuple_usizeTransactionZZ& operator=(CVec_C2Tuple_usizeTransactionZZ&& o) { CVec_C2Tuple_usizeTransactionZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_usizeTransactionZZ)); return *this; }
	LDKCVec_C2Tuple_usizeTransactionZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_usizeTransactionZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_usizeTransactionZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_usizeTransactionZZ* operator ->() const { return &self; }
};
class CResult_QueryShortChannelIdsDecodeErrorZ {
private:
	LDKCResult_QueryShortChannelIdsDecodeErrorZ self;
public:
	CResult_QueryShortChannelIdsDecodeErrorZ(const CResult_QueryShortChannelIdsDecodeErrorZ&) = delete;
	CResult_QueryShortChannelIdsDecodeErrorZ(CResult_QueryShortChannelIdsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_QueryShortChannelIdsDecodeErrorZ)); }
	CResult_QueryShortChannelIdsDecodeErrorZ(LDKCResult_QueryShortChannelIdsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_QueryShortChannelIdsDecodeErrorZ)); }
	operator LDKCResult_QueryShortChannelIdsDecodeErrorZ() && { LDKCResult_QueryShortChannelIdsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_QueryShortChannelIdsDecodeErrorZ)); return res; }
	~CResult_QueryShortChannelIdsDecodeErrorZ() { CResult_QueryShortChannelIdsDecodeErrorZ_free(self); }
	CResult_QueryShortChannelIdsDecodeErrorZ& operator=(CResult_QueryShortChannelIdsDecodeErrorZ&& o) { CResult_QueryShortChannelIdsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_QueryShortChannelIdsDecodeErrorZ)); return *this; }
	LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_PhantomRouteHintsZ {
private:
	LDKCVec_PhantomRouteHintsZ self;
public:
	CVec_PhantomRouteHintsZ(const CVec_PhantomRouteHintsZ&) = delete;
	CVec_PhantomRouteHintsZ(CVec_PhantomRouteHintsZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_PhantomRouteHintsZ)); }
	CVec_PhantomRouteHintsZ(LDKCVec_PhantomRouteHintsZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_PhantomRouteHintsZ)); }
	operator LDKCVec_PhantomRouteHintsZ() && { LDKCVec_PhantomRouteHintsZ res = self; memset(&self, 0, sizeof(LDKCVec_PhantomRouteHintsZ)); return res; }
	~CVec_PhantomRouteHintsZ() { CVec_PhantomRouteHintsZ_free(self); }
	CVec_PhantomRouteHintsZ& operator=(CVec_PhantomRouteHintsZ&& o) { CVec_PhantomRouteHintsZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_PhantomRouteHintsZ)); return *this; }
	LDKCVec_PhantomRouteHintsZ* operator &() { return &self; }
	LDKCVec_PhantomRouteHintsZ* operator ->() { return &self; }
	const LDKCVec_PhantomRouteHintsZ* operator &() const { return &self; }
	const LDKCVec_PhantomRouteHintsZ* operator ->() const { return &self; }
};
class COption_MonitorEventZ {
private:
	LDKCOption_MonitorEventZ self;
public:
	COption_MonitorEventZ(const COption_MonitorEventZ&) = delete;
	COption_MonitorEventZ(COption_MonitorEventZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_MonitorEventZ)); }
	COption_MonitorEventZ(LDKCOption_MonitorEventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_MonitorEventZ)); }
	operator LDKCOption_MonitorEventZ() && { LDKCOption_MonitorEventZ res = self; memset(&self, 0, sizeof(LDKCOption_MonitorEventZ)); return res; }
	~COption_MonitorEventZ() { COption_MonitorEventZ_free(self); }
	COption_MonitorEventZ& operator=(COption_MonitorEventZ&& o) { COption_MonitorEventZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_MonitorEventZ)); return *this; }
	LDKCOption_MonitorEventZ* operator &() { return &self; }
	LDKCOption_MonitorEventZ* operator ->() { return &self; }
	const LDKCOption_MonitorEventZ* operator &() const { return &self; }
	const LDKCOption_MonitorEventZ* operator ->() const { return &self; }
};
class C2Tuple_u64u64Z {
private:
	LDKC2Tuple_u64u64Z self;
public:
	C2Tuple_u64u64Z(const C2Tuple_u64u64Z&) = delete;
	C2Tuple_u64u64Z(C2Tuple_u64u64Z&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_u64u64Z)); }
	C2Tuple_u64u64Z(LDKC2Tuple_u64u64Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_u64u64Z)); }
	operator LDKC2Tuple_u64u64Z() && { LDKC2Tuple_u64u64Z res = self; memset(&self, 0, sizeof(LDKC2Tuple_u64u64Z)); return res; }
	~C2Tuple_u64u64Z() { C2Tuple_u64u64Z_free(self); }
	C2Tuple_u64u64Z& operator=(C2Tuple_u64u64Z&& o) { C2Tuple_u64u64Z_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_u64u64Z)); return *this; }
	LDKC2Tuple_u64u64Z* operator &() { return &self; }
	LDKC2Tuple_u64u64Z* operator ->() { return &self; }
	const LDKC2Tuple_u64u64Z* operator &() const { return &self; }
	const LDKC2Tuple_u64u64Z* operator ->() const { return &self; }
};
class COption_TypeZ {
private:
	LDKCOption_TypeZ self;
public:
	COption_TypeZ(const COption_TypeZ&) = delete;
	COption_TypeZ(COption_TypeZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_TypeZ)); }
	COption_TypeZ(LDKCOption_TypeZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_TypeZ)); }
	operator LDKCOption_TypeZ() && { LDKCOption_TypeZ res = self; memset(&self, 0, sizeof(LDKCOption_TypeZ)); return res; }
	~COption_TypeZ() { COption_TypeZ_free(self); }
	COption_TypeZ& operator=(COption_TypeZ&& o) { COption_TypeZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_TypeZ)); return *this; }
	LDKCOption_TypeZ* operator &() { return &self; }
	LDKCOption_TypeZ* operator ->() { return &self; }
	const LDKCOption_TypeZ* operator &() const { return &self; }
	const LDKCOption_TypeZ* operator ->() const { return &self; }
};
class CResult_COption_TypeZDecodeErrorZ {
private:
	LDKCResult_COption_TypeZDecodeErrorZ self;
public:
	CResult_COption_TypeZDecodeErrorZ(const CResult_COption_TypeZDecodeErrorZ&) = delete;
	CResult_COption_TypeZDecodeErrorZ(CResult_COption_TypeZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_TypeZDecodeErrorZ)); }
	CResult_COption_TypeZDecodeErrorZ(LDKCResult_COption_TypeZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_TypeZDecodeErrorZ)); }
	operator LDKCResult_COption_TypeZDecodeErrorZ() && { LDKCResult_COption_TypeZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_TypeZDecodeErrorZ)); return res; }
	~CResult_COption_TypeZDecodeErrorZ() { CResult_COption_TypeZDecodeErrorZ_free(self); }
	CResult_COption_TypeZDecodeErrorZ& operator=(CResult_COption_TypeZDecodeErrorZ&& o) { CResult_COption_TypeZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_TypeZDecodeErrorZ)); return *this; }
	LDKCResult_COption_TypeZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_TypeZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_TypeZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_TypeZDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_u32TxOutZ {
private:
	LDKC2Tuple_u32TxOutZ self;
public:
	C2Tuple_u32TxOutZ(const C2Tuple_u32TxOutZ&) = delete;
	C2Tuple_u32TxOutZ(C2Tuple_u32TxOutZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_u32TxOutZ)); }
	C2Tuple_u32TxOutZ(LDKC2Tuple_u32TxOutZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_u32TxOutZ)); }
	operator LDKC2Tuple_u32TxOutZ() && { LDKC2Tuple_u32TxOutZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_u32TxOutZ)); return res; }
	~C2Tuple_u32TxOutZ() { C2Tuple_u32TxOutZ_free(self); }
	C2Tuple_u32TxOutZ& operator=(C2Tuple_u32TxOutZ&& o) { C2Tuple_u32TxOutZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_u32TxOutZ)); return *this; }
	LDKC2Tuple_u32TxOutZ* operator &() { return &self; }
	LDKC2Tuple_u32TxOutZ* operator ->() { return &self; }
	const LDKC2Tuple_u32TxOutZ* operator &() const { return &self; }
	const LDKC2Tuple_u32TxOutZ* operator ->() const { return &self; }
};
class CResult_UpdateFailHTLCDecodeErrorZ {
private:
	LDKCResult_UpdateFailHTLCDecodeErrorZ self;
public:
	CResult_UpdateFailHTLCDecodeErrorZ(const CResult_UpdateFailHTLCDecodeErrorZ&) = delete;
	CResult_UpdateFailHTLCDecodeErrorZ(CResult_UpdateFailHTLCDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UpdateFailHTLCDecodeErrorZ)); }
	CResult_UpdateFailHTLCDecodeErrorZ(LDKCResult_UpdateFailHTLCDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UpdateFailHTLCDecodeErrorZ)); }
	operator LDKCResult_UpdateFailHTLCDecodeErrorZ() && { LDKCResult_UpdateFailHTLCDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UpdateFailHTLCDecodeErrorZ)); return res; }
	~CResult_UpdateFailHTLCDecodeErrorZ() { CResult_UpdateFailHTLCDecodeErrorZ_free(self); }
	CResult_UpdateFailHTLCDecodeErrorZ& operator=(CResult_UpdateFailHTLCDecodeErrorZ&& o) { CResult_UpdateFailHTLCDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UpdateFailHTLCDecodeErrorZ)); return *this; }
	LDKCResult_UpdateFailHTLCDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UpdateFailHTLCDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UpdateFailHTLCDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UpdateFailHTLCDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_InvoiceParseOrSemanticErrorZ {
private:
	LDKCResult_InvoiceParseOrSemanticErrorZ self;
public:
	CResult_InvoiceParseOrSemanticErrorZ(const CResult_InvoiceParseOrSemanticErrorZ&) = delete;
	CResult_InvoiceParseOrSemanticErrorZ(CResult_InvoiceParseOrSemanticErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InvoiceParseOrSemanticErrorZ)); }
	CResult_InvoiceParseOrSemanticErrorZ(LDKCResult_InvoiceParseOrSemanticErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InvoiceParseOrSemanticErrorZ)); }
	operator LDKCResult_InvoiceParseOrSemanticErrorZ() && { LDKCResult_InvoiceParseOrSemanticErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InvoiceParseOrSemanticErrorZ)); return res; }
	~CResult_InvoiceParseOrSemanticErrorZ() { CResult_InvoiceParseOrSemanticErrorZ_free(self); }
	CResult_InvoiceParseOrSemanticErrorZ& operator=(CResult_InvoiceParseOrSemanticErrorZ&& o) { CResult_InvoiceParseOrSemanticErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InvoiceParseOrSemanticErrorZ)); return *this; }
	LDKCResult_InvoiceParseOrSemanticErrorZ* operator &() { return &self; }
	LDKCResult_InvoiceParseOrSemanticErrorZ* operator ->() { return &self; }
	const LDKCResult_InvoiceParseOrSemanticErrorZ* operator &() const { return &self; }
	const LDKCResult_InvoiceParseOrSemanticErrorZ* operator ->() const { return &self; }
};
class CResult_PaymentSecretNoneZ {
private:
	LDKCResult_PaymentSecretNoneZ self;
public:
	CResult_PaymentSecretNoneZ(const CResult_PaymentSecretNoneZ&) = delete;
	CResult_PaymentSecretNoneZ(CResult_PaymentSecretNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentSecretNoneZ)); }
	CResult_PaymentSecretNoneZ(LDKCResult_PaymentSecretNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentSecretNoneZ)); }
	operator LDKCResult_PaymentSecretNoneZ() && { LDKCResult_PaymentSecretNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentSecretNoneZ)); return res; }
	~CResult_PaymentSecretNoneZ() { CResult_PaymentSecretNoneZ_free(self); }
	CResult_PaymentSecretNoneZ& operator=(CResult_PaymentSecretNoneZ&& o) { CResult_PaymentSecretNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentSecretNoneZ)); return *this; }
	LDKCResult_PaymentSecretNoneZ* operator &() { return &self; }
	LDKCResult_PaymentSecretNoneZ* operator ->() { return &self; }
	const LDKCResult_PaymentSecretNoneZ* operator &() const { return &self; }
	const LDKCResult_PaymentSecretNoneZ* operator ->() const { return &self; }
};
class CResult_ChannelConfigDecodeErrorZ {
private:
	LDKCResult_ChannelConfigDecodeErrorZ self;
public:
	CResult_ChannelConfigDecodeErrorZ(const CResult_ChannelConfigDecodeErrorZ&) = delete;
	CResult_ChannelConfigDecodeErrorZ(CResult_ChannelConfigDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelConfigDecodeErrorZ)); }
	CResult_ChannelConfigDecodeErrorZ(LDKCResult_ChannelConfigDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelConfigDecodeErrorZ)); }
	operator LDKCResult_ChannelConfigDecodeErrorZ() && { LDKCResult_ChannelConfigDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelConfigDecodeErrorZ)); return res; }
	~CResult_ChannelConfigDecodeErrorZ() { CResult_ChannelConfigDecodeErrorZ_free(self); }
	CResult_ChannelConfigDecodeErrorZ& operator=(CResult_ChannelConfigDecodeErrorZ&& o) { CResult_ChannelConfigDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelConfigDecodeErrorZ)); return *this; }
	LDKCResult_ChannelConfigDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelConfigDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelConfigDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelConfigDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_PrivateRouteZ {
private:
	LDKCVec_PrivateRouteZ self;
public:
	CVec_PrivateRouteZ(const CVec_PrivateRouteZ&) = delete;
	CVec_PrivateRouteZ(CVec_PrivateRouteZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_PrivateRouteZ)); }
	CVec_PrivateRouteZ(LDKCVec_PrivateRouteZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_PrivateRouteZ)); }
	operator LDKCVec_PrivateRouteZ() && { LDKCVec_PrivateRouteZ res = self; memset(&self, 0, sizeof(LDKCVec_PrivateRouteZ)); return res; }
	~CVec_PrivateRouteZ() { CVec_PrivateRouteZ_free(self); }
	CVec_PrivateRouteZ& operator=(CVec_PrivateRouteZ&& o) { CVec_PrivateRouteZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_PrivateRouteZ)); return *this; }
	LDKCVec_PrivateRouteZ* operator &() { return &self; }
	LDKCVec_PrivateRouteZ* operator ->() { return &self; }
	const LDKCVec_PrivateRouteZ* operator &() const { return &self; }
	const LDKCVec_PrivateRouteZ* operator ->() const { return &self; }
};
class CResult_SpendableOutputDescriptorDecodeErrorZ {
private:
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ self;
public:
	CResult_SpendableOutputDescriptorDecodeErrorZ(const CResult_SpendableOutputDescriptorDecodeErrorZ&) = delete;
	CResult_SpendableOutputDescriptorDecodeErrorZ(CResult_SpendableOutputDescriptorDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SpendableOutputDescriptorDecodeErrorZ)); }
	CResult_SpendableOutputDescriptorDecodeErrorZ(LDKCResult_SpendableOutputDescriptorDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SpendableOutputDescriptorDecodeErrorZ)); }
	operator LDKCResult_SpendableOutputDescriptorDecodeErrorZ() && { LDKCResult_SpendableOutputDescriptorDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SpendableOutputDescriptorDecodeErrorZ)); return res; }
	~CResult_SpendableOutputDescriptorDecodeErrorZ() { CResult_SpendableOutputDescriptorDecodeErrorZ_free(self); }
	CResult_SpendableOutputDescriptorDecodeErrorZ& operator=(CResult_SpendableOutputDescriptorDecodeErrorZ&& o) { CResult_SpendableOutputDescriptorDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SpendableOutputDescriptorDecodeErrorZ)); return *this; }
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator &() { return &self; }
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RevokeAndACKDecodeErrorZ {
private:
	LDKCResult_RevokeAndACKDecodeErrorZ self;
public:
	CResult_RevokeAndACKDecodeErrorZ(const CResult_RevokeAndACKDecodeErrorZ&) = delete;
	CResult_RevokeAndACKDecodeErrorZ(CResult_RevokeAndACKDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RevokeAndACKDecodeErrorZ)); }
	CResult_RevokeAndACKDecodeErrorZ(LDKCResult_RevokeAndACKDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RevokeAndACKDecodeErrorZ)); }
	operator LDKCResult_RevokeAndACKDecodeErrorZ() && { LDKCResult_RevokeAndACKDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RevokeAndACKDecodeErrorZ)); return res; }
	~CResult_RevokeAndACKDecodeErrorZ() { CResult_RevokeAndACKDecodeErrorZ_free(self); }
	CResult_RevokeAndACKDecodeErrorZ& operator=(CResult_RevokeAndACKDecodeErrorZ&& o) { CResult_RevokeAndACKDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RevokeAndACKDecodeErrorZ)); return *this; }
	LDKCResult_RevokeAndACKDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RevokeAndACKDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RevokeAndACKDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RevokeAndACKDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_UnsignedChannelUpdateDecodeErrorZ {
private:
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ self;
public:
	CResult_UnsignedChannelUpdateDecodeErrorZ(const CResult_UnsignedChannelUpdateDecodeErrorZ&) = delete;
	CResult_UnsignedChannelUpdateDecodeErrorZ(CResult_UnsignedChannelUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedChannelUpdateDecodeErrorZ)); }
	CResult_UnsignedChannelUpdateDecodeErrorZ(LDKCResult_UnsignedChannelUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedChannelUpdateDecodeErrorZ)); }
	operator LDKCResult_UnsignedChannelUpdateDecodeErrorZ() && { LDKCResult_UnsignedChannelUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedChannelUpdateDecodeErrorZ)); return res; }
	~CResult_UnsignedChannelUpdateDecodeErrorZ() { CResult_UnsignedChannelUpdateDecodeErrorZ_free(self); }
	CResult_UnsignedChannelUpdateDecodeErrorZ& operator=(CResult_UnsignedChannelUpdateDecodeErrorZ&& o) { CResult_UnsignedChannelUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedChannelUpdateDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ShutdownDecodeErrorZ {
private:
	LDKCResult_ShutdownDecodeErrorZ self;
public:
	CResult_ShutdownDecodeErrorZ(const CResult_ShutdownDecodeErrorZ&) = delete;
	CResult_ShutdownDecodeErrorZ(CResult_ShutdownDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ShutdownDecodeErrorZ)); }
	CResult_ShutdownDecodeErrorZ(LDKCResult_ShutdownDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ShutdownDecodeErrorZ)); }
	operator LDKCResult_ShutdownDecodeErrorZ() && { LDKCResult_ShutdownDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ShutdownDecodeErrorZ)); return res; }
	~CResult_ShutdownDecodeErrorZ() { CResult_ShutdownDecodeErrorZ_free(self); }
	CResult_ShutdownDecodeErrorZ& operator=(CResult_ShutdownDecodeErrorZ&& o) { CResult_ShutdownDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ShutdownDecodeErrorZ)); return *this; }
	LDKCResult_ShutdownDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ShutdownDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ShutdownDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ShutdownDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_EventZ {
private:
	LDKCVec_EventZ self;
public:
	CVec_EventZ(const CVec_EventZ&) = delete;
	CVec_EventZ(CVec_EventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_EventZ)); }
	CVec_EventZ(LDKCVec_EventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_EventZ)); }
	operator LDKCVec_EventZ() && { LDKCVec_EventZ res = self; memset(&self, 0, sizeof(LDKCVec_EventZ)); return res; }
	~CVec_EventZ() { CVec_EventZ_free(self); }
	CVec_EventZ& operator=(CVec_EventZ&& o) { CVec_EventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_EventZ)); return *this; }
	LDKCVec_EventZ* operator &() { return &self; }
	LDKCVec_EventZ* operator ->() { return &self; }
	const LDKCVec_EventZ* operator &() const { return &self; }
	const LDKCVec_EventZ* operator ->() const { return &self; }
};
class CResult_NoneSemanticErrorZ {
private:
	LDKCResult_NoneSemanticErrorZ self;
public:
	CResult_NoneSemanticErrorZ(const CResult_NoneSemanticErrorZ&) = delete;
	CResult_NoneSemanticErrorZ(CResult_NoneSemanticErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneSemanticErrorZ)); }
	CResult_NoneSemanticErrorZ(LDKCResult_NoneSemanticErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneSemanticErrorZ)); }
	operator LDKCResult_NoneSemanticErrorZ() && { LDKCResult_NoneSemanticErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneSemanticErrorZ)); return res; }
	~CResult_NoneSemanticErrorZ() { CResult_NoneSemanticErrorZ_free(self); }
	CResult_NoneSemanticErrorZ& operator=(CResult_NoneSemanticErrorZ&& o) { CResult_NoneSemanticErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneSemanticErrorZ)); return *this; }
	LDKCResult_NoneSemanticErrorZ* operator &() { return &self; }
	LDKCResult_NoneSemanticErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneSemanticErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneSemanticErrorZ* operator ->() const { return &self; }
};
class CVec_MonitorEventZ {
private:
	LDKCVec_MonitorEventZ self;
public:
	CVec_MonitorEventZ(const CVec_MonitorEventZ&) = delete;
	CVec_MonitorEventZ(CVec_MonitorEventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_MonitorEventZ)); }
	CVec_MonitorEventZ(LDKCVec_MonitorEventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_MonitorEventZ)); }
	operator LDKCVec_MonitorEventZ() && { LDKCVec_MonitorEventZ res = self; memset(&self, 0, sizeof(LDKCVec_MonitorEventZ)); return res; }
	~CVec_MonitorEventZ() { CVec_MonitorEventZ_free(self); }
	CVec_MonitorEventZ& operator=(CVec_MonitorEventZ&& o) { CVec_MonitorEventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_MonitorEventZ)); return *this; }
	LDKCVec_MonitorEventZ* operator &() { return &self; }
	LDKCVec_MonitorEventZ* operator ->() { return &self; }
	const LDKCVec_MonitorEventZ* operator &() const { return &self; }
	const LDKCVec_MonitorEventZ* operator ->() const { return &self; }
};
class CVec_PaymentPreimageZ {
private:
	LDKCVec_PaymentPreimageZ self;
public:
	CVec_PaymentPreimageZ(const CVec_PaymentPreimageZ&) = delete;
	CVec_PaymentPreimageZ(CVec_PaymentPreimageZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_PaymentPreimageZ)); }
	CVec_PaymentPreimageZ(LDKCVec_PaymentPreimageZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_PaymentPreimageZ)); }
	operator LDKCVec_PaymentPreimageZ() && { LDKCVec_PaymentPreimageZ res = self; memset(&self, 0, sizeof(LDKCVec_PaymentPreimageZ)); return res; }
	~CVec_PaymentPreimageZ() { CVec_PaymentPreimageZ_free(self); }
	CVec_PaymentPreimageZ& operator=(CVec_PaymentPreimageZ&& o) { CVec_PaymentPreimageZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_PaymentPreimageZ)); return *this; }
	LDKCVec_PaymentPreimageZ* operator &() { return &self; }
	LDKCVec_PaymentPreimageZ* operator ->() { return &self; }
	const LDKCVec_PaymentPreimageZ* operator &() const { return &self; }
	const LDKCVec_PaymentPreimageZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_u32ScriptZZ {
private:
	LDKCVec_C2Tuple_u32ScriptZZ self;
public:
	CVec_C2Tuple_u32ScriptZZ(const CVec_C2Tuple_u32ScriptZZ&) = delete;
	CVec_C2Tuple_u32ScriptZZ(CVec_C2Tuple_u32ScriptZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_u32ScriptZZ)); }
	CVec_C2Tuple_u32ScriptZZ(LDKCVec_C2Tuple_u32ScriptZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_u32ScriptZZ)); }
	operator LDKCVec_C2Tuple_u32ScriptZZ() && { LDKCVec_C2Tuple_u32ScriptZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_u32ScriptZZ)); return res; }
	~CVec_C2Tuple_u32ScriptZZ() { CVec_C2Tuple_u32ScriptZZ_free(self); }
	CVec_C2Tuple_u32ScriptZZ& operator=(CVec_C2Tuple_u32ScriptZZ&& o) { CVec_C2Tuple_u32ScriptZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_u32ScriptZZ)); return *this; }
	LDKCVec_C2Tuple_u32ScriptZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_u32ScriptZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_u32ScriptZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_u32ScriptZZ* operator ->() const { return &self; }
};
class CResult_NoneChannelMonitorUpdateErrZ {
private:
	LDKCResult_NoneChannelMonitorUpdateErrZ self;
public:
	CResult_NoneChannelMonitorUpdateErrZ(const CResult_NoneChannelMonitorUpdateErrZ&) = delete;
	CResult_NoneChannelMonitorUpdateErrZ(CResult_NoneChannelMonitorUpdateErrZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneChannelMonitorUpdateErrZ)); }
	CResult_NoneChannelMonitorUpdateErrZ(LDKCResult_NoneChannelMonitorUpdateErrZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneChannelMonitorUpdateErrZ)); }
	operator LDKCResult_NoneChannelMonitorUpdateErrZ() && { LDKCResult_NoneChannelMonitorUpdateErrZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneChannelMonitorUpdateErrZ)); return res; }
	~CResult_NoneChannelMonitorUpdateErrZ() { CResult_NoneChannelMonitorUpdateErrZ_free(self); }
	CResult_NoneChannelMonitorUpdateErrZ& operator=(CResult_NoneChannelMonitorUpdateErrZ&& o) { CResult_NoneChannelMonitorUpdateErrZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneChannelMonitorUpdateErrZ)); return *this; }
	LDKCResult_NoneChannelMonitorUpdateErrZ* operator &() { return &self; }
	LDKCResult_NoneChannelMonitorUpdateErrZ* operator ->() { return &self; }
	const LDKCResult_NoneChannelMonitorUpdateErrZ* operator &() const { return &self; }
	const LDKCResult_NoneChannelMonitorUpdateErrZ* operator ->() const { return &self; }
};
class CResult_COption_ClosureReasonZDecodeErrorZ {
private:
	LDKCResult_COption_ClosureReasonZDecodeErrorZ self;
public:
	CResult_COption_ClosureReasonZDecodeErrorZ(const CResult_COption_ClosureReasonZDecodeErrorZ&) = delete;
	CResult_COption_ClosureReasonZDecodeErrorZ(CResult_COption_ClosureReasonZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_COption_ClosureReasonZDecodeErrorZ)); }
	CResult_COption_ClosureReasonZDecodeErrorZ(LDKCResult_COption_ClosureReasonZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_COption_ClosureReasonZDecodeErrorZ)); }
	operator LDKCResult_COption_ClosureReasonZDecodeErrorZ() && { LDKCResult_COption_ClosureReasonZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_COption_ClosureReasonZDecodeErrorZ)); return res; }
	~CResult_COption_ClosureReasonZDecodeErrorZ() { CResult_COption_ClosureReasonZDecodeErrorZ_free(self); }
	CResult_COption_ClosureReasonZDecodeErrorZ& operator=(CResult_COption_ClosureReasonZDecodeErrorZ&& o) { CResult_COption_ClosureReasonZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_COption_ClosureReasonZDecodeErrorZ)); return *this; }
	LDKCResult_COption_ClosureReasonZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_COption_ClosureReasonZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_COption_ClosureReasonZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_COption_ClosureReasonZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PublicKeyErrorZ {
private:
	LDKCResult_PublicKeyErrorZ self;
public:
	CResult_PublicKeyErrorZ(const CResult_PublicKeyErrorZ&) = delete;
	CResult_PublicKeyErrorZ(CResult_PublicKeyErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PublicKeyErrorZ)); }
	CResult_PublicKeyErrorZ(LDKCResult_PublicKeyErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PublicKeyErrorZ)); }
	operator LDKCResult_PublicKeyErrorZ() && { LDKCResult_PublicKeyErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PublicKeyErrorZ)); return res; }
	~CResult_PublicKeyErrorZ() { CResult_PublicKeyErrorZ_free(self); }
	CResult_PublicKeyErrorZ& operator=(CResult_PublicKeyErrorZ&& o) { CResult_PublicKeyErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PublicKeyErrorZ)); return *this; }
	LDKCResult_PublicKeyErrorZ* operator &() { return &self; }
	LDKCResult_PublicKeyErrorZ* operator ->() { return &self; }
	const LDKCResult_PublicKeyErrorZ* operator &() const { return &self; }
	const LDKCResult_PublicKeyErrorZ* operator ->() const { return &self; }
};
class CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ {
private:
	LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ self;
public:
	CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ(const CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ&) = delete;
	CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ(CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ)); }
	CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ(LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ)); }
	operator LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ() && { LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ res = self; memset(&self, 0, sizeof(LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ)); return res; }
	~CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ() { CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ_free(self); }
	CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ& operator=(CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ&& o) { CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ)); return *this; }
	LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ* operator &() { return &self; }
	LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ* operator ->() { return &self; }
	const LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ* operator &() const { return &self; }
	const LDKCVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ* operator ->() const { return &self; }
};
class C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
private:
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ self;
public:
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(const C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&) = delete;
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& o) : self(o.self) { memset(&o, 0, sizeof(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); }
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); }
	operator LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ() && { LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ res = self; memset(&self, 0, sizeof(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); return res; }
	~C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ() { C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(self); }
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ& operator=(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& o) { C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(self); self = o.self; memset(&o, 0, sizeof(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); return *this; }
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator &() { return &self; }
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator ->() { return &self; }
	const LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator &() const { return &self; }
	const LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator ->() const { return &self; }
};
class CResult_NoneNoneZ {
private:
	LDKCResult_NoneNoneZ self;
public:
	CResult_NoneNoneZ(const CResult_NoneNoneZ&) = delete;
	CResult_NoneNoneZ(CResult_NoneNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneNoneZ)); }
	CResult_NoneNoneZ(LDKCResult_NoneNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneNoneZ)); }
	operator LDKCResult_NoneNoneZ() && { LDKCResult_NoneNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneNoneZ)); return res; }
	~CResult_NoneNoneZ() { CResult_NoneNoneZ_free(self); }
	CResult_NoneNoneZ& operator=(CResult_NoneNoneZ&& o) { CResult_NoneNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneNoneZ)); return *this; }
	LDKCResult_NoneNoneZ* operator &() { return &self; }
	LDKCResult_NoneNoneZ* operator ->() { return &self; }
	const LDKCResult_NoneNoneZ* operator &() const { return &self; }
	const LDKCResult_NoneNoneZ* operator ->() const { return &self; }
};
class CResult_RouteParametersDecodeErrorZ {
private:
	LDKCResult_RouteParametersDecodeErrorZ self;
public:
	CResult_RouteParametersDecodeErrorZ(const CResult_RouteParametersDecodeErrorZ&) = delete;
	CResult_RouteParametersDecodeErrorZ(CResult_RouteParametersDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteParametersDecodeErrorZ)); }
	CResult_RouteParametersDecodeErrorZ(LDKCResult_RouteParametersDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteParametersDecodeErrorZ)); }
	operator LDKCResult_RouteParametersDecodeErrorZ() && { LDKCResult_RouteParametersDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteParametersDecodeErrorZ)); return res; }
	~CResult_RouteParametersDecodeErrorZ() { CResult_RouteParametersDecodeErrorZ_free(self); }
	CResult_RouteParametersDecodeErrorZ& operator=(CResult_RouteParametersDecodeErrorZ&& o) { CResult_RouteParametersDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteParametersDecodeErrorZ)); return *this; }
	LDKCResult_RouteParametersDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteParametersDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteParametersDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteParametersDecodeErrorZ* operator ->() const { return &self; }
};
class COption_ClosureReasonZ {
private:
	LDKCOption_ClosureReasonZ self;
public:
	COption_ClosureReasonZ(const COption_ClosureReasonZ&) = delete;
	COption_ClosureReasonZ(COption_ClosureReasonZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_ClosureReasonZ)); }
	COption_ClosureReasonZ(LDKCOption_ClosureReasonZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_ClosureReasonZ)); }
	operator LDKCOption_ClosureReasonZ() && { LDKCOption_ClosureReasonZ res = self; memset(&self, 0, sizeof(LDKCOption_ClosureReasonZ)); return res; }
	~COption_ClosureReasonZ() { COption_ClosureReasonZ_free(self); }
	COption_ClosureReasonZ& operator=(COption_ClosureReasonZ&& o) { COption_ClosureReasonZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_ClosureReasonZ)); return *this; }
	LDKCOption_ClosureReasonZ* operator &() { return &self; }
	LDKCOption_ClosureReasonZ* operator ->() { return &self; }
	const LDKCOption_ClosureReasonZ* operator &() const { return &self; }
	const LDKCOption_ClosureReasonZ* operator ->() const { return &self; }
};
class CResult_NodeAliasDecodeErrorZ {
private:
	LDKCResult_NodeAliasDecodeErrorZ self;
public:
	CResult_NodeAliasDecodeErrorZ(const CResult_NodeAliasDecodeErrorZ&) = delete;
	CResult_NodeAliasDecodeErrorZ(CResult_NodeAliasDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeAliasDecodeErrorZ)); }
	CResult_NodeAliasDecodeErrorZ(LDKCResult_NodeAliasDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeAliasDecodeErrorZ)); }
	operator LDKCResult_NodeAliasDecodeErrorZ() && { LDKCResult_NodeAliasDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeAliasDecodeErrorZ)); return res; }
	~CResult_NodeAliasDecodeErrorZ() { CResult_NodeAliasDecodeErrorZ_free(self); }
	CResult_NodeAliasDecodeErrorZ& operator=(CResult_NodeAliasDecodeErrorZ&& o) { CResult_NodeAliasDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeAliasDecodeErrorZ)); return *this; }
	LDKCResult_NodeAliasDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeAliasDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeAliasDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeAliasDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_APIErrorZ {
private:
	LDKCVec_APIErrorZ self;
public:
	CVec_APIErrorZ(const CVec_APIErrorZ&) = delete;
	CVec_APIErrorZ(CVec_APIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_APIErrorZ)); }
	CVec_APIErrorZ(LDKCVec_APIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_APIErrorZ)); }
	operator LDKCVec_APIErrorZ() && { LDKCVec_APIErrorZ res = self; memset(&self, 0, sizeof(LDKCVec_APIErrorZ)); return res; }
	~CVec_APIErrorZ() { CVec_APIErrorZ_free(self); }
	CVec_APIErrorZ& operator=(CVec_APIErrorZ&& o) { CVec_APIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_APIErrorZ)); return *this; }
	LDKCVec_APIErrorZ* operator &() { return &self; }
	LDKCVec_APIErrorZ* operator ->() { return &self; }
	const LDKCVec_APIErrorZ* operator &() const { return &self; }
	const LDKCVec_APIErrorZ* operator ->() const { return &self; }
};
class CResult_PrivateRouteCreationErrorZ {
private:
	LDKCResult_PrivateRouteCreationErrorZ self;
public:
	CResult_PrivateRouteCreationErrorZ(const CResult_PrivateRouteCreationErrorZ&) = delete;
	CResult_PrivateRouteCreationErrorZ(CResult_PrivateRouteCreationErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PrivateRouteCreationErrorZ)); }
	CResult_PrivateRouteCreationErrorZ(LDKCResult_PrivateRouteCreationErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PrivateRouteCreationErrorZ)); }
	operator LDKCResult_PrivateRouteCreationErrorZ() && { LDKCResult_PrivateRouteCreationErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PrivateRouteCreationErrorZ)); return res; }
	~CResult_PrivateRouteCreationErrorZ() { CResult_PrivateRouteCreationErrorZ_free(self); }
	CResult_PrivateRouteCreationErrorZ& operator=(CResult_PrivateRouteCreationErrorZ&& o) { CResult_PrivateRouteCreationErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PrivateRouteCreationErrorZ)); return *this; }
	LDKCResult_PrivateRouteCreationErrorZ* operator &() { return &self; }
	LDKCResult_PrivateRouteCreationErrorZ* operator ->() { return &self; }
	const LDKCResult_PrivateRouteCreationErrorZ* operator &() const { return &self; }
	const LDKCResult_PrivateRouteCreationErrorZ* operator ->() const { return &self; }
};
class CResult_boolPeerHandleErrorZ {
private:
	LDKCResult_boolPeerHandleErrorZ self;
public:
	CResult_boolPeerHandleErrorZ(const CResult_boolPeerHandleErrorZ&) = delete;
	CResult_boolPeerHandleErrorZ(CResult_boolPeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_boolPeerHandleErrorZ)); }
	CResult_boolPeerHandleErrorZ(LDKCResult_boolPeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_boolPeerHandleErrorZ)); }
	operator LDKCResult_boolPeerHandleErrorZ() && { LDKCResult_boolPeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_boolPeerHandleErrorZ)); return res; }
	~CResult_boolPeerHandleErrorZ() { CResult_boolPeerHandleErrorZ_free(self); }
	CResult_boolPeerHandleErrorZ& operator=(CResult_boolPeerHandleErrorZ&& o) { CResult_boolPeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_boolPeerHandleErrorZ)); return *this; }
	LDKCResult_boolPeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_boolPeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_boolPeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_boolPeerHandleErrorZ* operator ->() const { return &self; }
};
class CVec_UpdateFulfillHTLCZ {
private:
	LDKCVec_UpdateFulfillHTLCZ self;
public:
	CVec_UpdateFulfillHTLCZ(const CVec_UpdateFulfillHTLCZ&) = delete;
	CVec_UpdateFulfillHTLCZ(CVec_UpdateFulfillHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFulfillHTLCZ)); }
	CVec_UpdateFulfillHTLCZ(LDKCVec_UpdateFulfillHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFulfillHTLCZ)); }
	operator LDKCVec_UpdateFulfillHTLCZ() && { LDKCVec_UpdateFulfillHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFulfillHTLCZ)); return res; }
	~CVec_UpdateFulfillHTLCZ() { CVec_UpdateFulfillHTLCZ_free(self); }
	CVec_UpdateFulfillHTLCZ& operator=(CVec_UpdateFulfillHTLCZ&& o) { CVec_UpdateFulfillHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFulfillHTLCZ)); return *this; }
	LDKCVec_UpdateFulfillHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFulfillHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFulfillHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFulfillHTLCZ* operator ->() const { return &self; }
};
class CResult_BlindedRouteNoneZ {
private:
	LDKCResult_BlindedRouteNoneZ self;
public:
	CResult_BlindedRouteNoneZ(const CResult_BlindedRouteNoneZ&) = delete;
	CResult_BlindedRouteNoneZ(CResult_BlindedRouteNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_BlindedRouteNoneZ)); }
	CResult_BlindedRouteNoneZ(LDKCResult_BlindedRouteNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_BlindedRouteNoneZ)); }
	operator LDKCResult_BlindedRouteNoneZ() && { LDKCResult_BlindedRouteNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_BlindedRouteNoneZ)); return res; }
	~CResult_BlindedRouteNoneZ() { CResult_BlindedRouteNoneZ_free(self); }
	CResult_BlindedRouteNoneZ& operator=(CResult_BlindedRouteNoneZ&& o) { CResult_BlindedRouteNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_BlindedRouteNoneZ)); return *this; }
	LDKCResult_BlindedRouteNoneZ* operator &() { return &self; }
	LDKCResult_BlindedRouteNoneZ* operator ->() { return &self; }
	const LDKCResult_BlindedRouteNoneZ* operator &() const { return &self; }
	const LDKCResult_BlindedRouteNoneZ* operator ->() const { return &self; }
};
class CResult_AnnouncementSignaturesDecodeErrorZ {
private:
	LDKCResult_AnnouncementSignaturesDecodeErrorZ self;
public:
	CResult_AnnouncementSignaturesDecodeErrorZ(const CResult_AnnouncementSignaturesDecodeErrorZ&) = delete;
	CResult_AnnouncementSignaturesDecodeErrorZ(CResult_AnnouncementSignaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_AnnouncementSignaturesDecodeErrorZ)); }
	CResult_AnnouncementSignaturesDecodeErrorZ(LDKCResult_AnnouncementSignaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_AnnouncementSignaturesDecodeErrorZ)); }
	operator LDKCResult_AnnouncementSignaturesDecodeErrorZ() && { LDKCResult_AnnouncementSignaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_AnnouncementSignaturesDecodeErrorZ)); return res; }
	~CResult_AnnouncementSignaturesDecodeErrorZ() { CResult_AnnouncementSignaturesDecodeErrorZ_free(self); }
	CResult_AnnouncementSignaturesDecodeErrorZ& operator=(CResult_AnnouncementSignaturesDecodeErrorZ&& o) { CResult_AnnouncementSignaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_AnnouncementSignaturesDecodeErrorZ)); return *this; }
	LDKCResult_AnnouncementSignaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_AnnouncementSignaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_AnnouncementSignaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_AnnouncementSignaturesDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_UpdateFulfillHTLCDecodeErrorZ {
private:
	LDKCResult_UpdateFulfillHTLCDecodeErrorZ self;
public:
	CResult_UpdateFulfillHTLCDecodeErrorZ(const CResult_UpdateFulfillHTLCDecodeErrorZ&) = delete;
	CResult_UpdateFulfillHTLCDecodeErrorZ(CResult_UpdateFulfillHTLCDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UpdateFulfillHTLCDecodeErrorZ)); }
	CResult_UpdateFulfillHTLCDecodeErrorZ(LDKCResult_UpdateFulfillHTLCDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UpdateFulfillHTLCDecodeErrorZ)); }
	operator LDKCResult_UpdateFulfillHTLCDecodeErrorZ() && { LDKCResult_UpdateFulfillHTLCDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UpdateFulfillHTLCDecodeErrorZ)); return res; }
	~CResult_UpdateFulfillHTLCDecodeErrorZ() { CResult_UpdateFulfillHTLCDecodeErrorZ_free(self); }
	CResult_UpdateFulfillHTLCDecodeErrorZ& operator=(CResult_UpdateFulfillHTLCDecodeErrorZ&& o) { CResult_UpdateFulfillHTLCDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UpdateFulfillHTLCDecodeErrorZ)); return *this; }
	LDKCResult_UpdateFulfillHTLCDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UpdateFulfillHTLCDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UpdateFulfillHTLCDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UpdateFulfillHTLCDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelUpdateDecodeErrorZ {
private:
	LDKCResult_ChannelUpdateDecodeErrorZ self;
public:
	CResult_ChannelUpdateDecodeErrorZ(const CResult_ChannelUpdateDecodeErrorZ&) = delete;
	CResult_ChannelUpdateDecodeErrorZ(CResult_ChannelUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelUpdateDecodeErrorZ)); }
	CResult_ChannelUpdateDecodeErrorZ(LDKCResult_ChannelUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelUpdateDecodeErrorZ)); }
	operator LDKCResult_ChannelUpdateDecodeErrorZ() && { LDKCResult_ChannelUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelUpdateDecodeErrorZ)); return res; }
	~CResult_ChannelUpdateDecodeErrorZ() { CResult_ChannelUpdateDecodeErrorZ_free(self); }
	CResult_ChannelUpdateDecodeErrorZ& operator=(CResult_ChannelUpdateDecodeErrorZ&& o) { CResult_ChannelUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelUpdateDecodeErrorZ)); return *this; }
	LDKCResult_ChannelUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NodeFeaturesDecodeErrorZ {
private:
	LDKCResult_NodeFeaturesDecodeErrorZ self;
public:
	CResult_NodeFeaturesDecodeErrorZ(const CResult_NodeFeaturesDecodeErrorZ&) = delete;
	CResult_NodeFeaturesDecodeErrorZ(CResult_NodeFeaturesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeFeaturesDecodeErrorZ)); }
	CResult_NodeFeaturesDecodeErrorZ(LDKCResult_NodeFeaturesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeFeaturesDecodeErrorZ)); }
	operator LDKCResult_NodeFeaturesDecodeErrorZ() && { LDKCResult_NodeFeaturesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeFeaturesDecodeErrorZ)); return res; }
	~CResult_NodeFeaturesDecodeErrorZ() { CResult_NodeFeaturesDecodeErrorZ_free(self); }
	CResult_NodeFeaturesDecodeErrorZ& operator=(CResult_NodeFeaturesDecodeErrorZ&& o) { CResult_NodeFeaturesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeFeaturesDecodeErrorZ)); return *this; }
	LDKCResult_NodeFeaturesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeFeaturesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeFeaturesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeFeaturesDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_u5Z {
private:
	LDKCVec_u5Z self;
public:
	CVec_u5Z(const CVec_u5Z&) = delete;
	CVec_u5Z(CVec_u5Z&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_u5Z)); }
	CVec_u5Z(LDKCVec_u5Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_u5Z)); }
	operator LDKCVec_u5Z() && { LDKCVec_u5Z res = self; memset(&self, 0, sizeof(LDKCVec_u5Z)); return res; }
	~CVec_u5Z() { CVec_u5Z_free(self); }
	CVec_u5Z& operator=(CVec_u5Z&& o) { CVec_u5Z_free(self); self = o.self; memset(&o, 0, sizeof(CVec_u5Z)); return *this; }
	LDKCVec_u5Z* operator &() { return &self; }
	LDKCVec_u5Z* operator ->() { return &self; }
	const LDKCVec_u5Z* operator &() const { return &self; }
	const LDKCVec_u5Z* operator ->() const { return &self; }
};
class CResult_InMemorySignerDecodeErrorZ {
private:
	LDKCResult_InMemorySignerDecodeErrorZ self;
public:
	CResult_InMemorySignerDecodeErrorZ(const CResult_InMemorySignerDecodeErrorZ&) = delete;
	CResult_InMemorySignerDecodeErrorZ(CResult_InMemorySignerDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InMemorySignerDecodeErrorZ)); }
	CResult_InMemorySignerDecodeErrorZ(LDKCResult_InMemorySignerDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InMemorySignerDecodeErrorZ)); }
	operator LDKCResult_InMemorySignerDecodeErrorZ() && { LDKCResult_InMemorySignerDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InMemorySignerDecodeErrorZ)); return res; }
	~CResult_InMemorySignerDecodeErrorZ() { CResult_InMemorySignerDecodeErrorZ_free(self); }
	CResult_InMemorySignerDecodeErrorZ& operator=(CResult_InMemorySignerDecodeErrorZ&& o) { CResult_InMemorySignerDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InMemorySignerDecodeErrorZ)); return *this; }
	LDKCResult_InMemorySignerDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InMemorySignerDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InMemorySignerDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InMemorySignerDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PaymentSecretAPIErrorZ {
private:
	LDKCResult_PaymentSecretAPIErrorZ self;
public:
	CResult_PaymentSecretAPIErrorZ(const CResult_PaymentSecretAPIErrorZ&) = delete;
	CResult_PaymentSecretAPIErrorZ(CResult_PaymentSecretAPIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PaymentSecretAPIErrorZ)); }
	CResult_PaymentSecretAPIErrorZ(LDKCResult_PaymentSecretAPIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PaymentSecretAPIErrorZ)); }
	operator LDKCResult_PaymentSecretAPIErrorZ() && { LDKCResult_PaymentSecretAPIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PaymentSecretAPIErrorZ)); return res; }
	~CResult_PaymentSecretAPIErrorZ() { CResult_PaymentSecretAPIErrorZ_free(self); }
	CResult_PaymentSecretAPIErrorZ& operator=(CResult_PaymentSecretAPIErrorZ&& o) { CResult_PaymentSecretAPIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PaymentSecretAPIErrorZ)); return *this; }
	LDKCResult_PaymentSecretAPIErrorZ* operator &() { return &self; }
	LDKCResult_PaymentSecretAPIErrorZ* operator ->() { return &self; }
	const LDKCResult_PaymentSecretAPIErrorZ* operator &() const { return &self; }
	const LDKCResult_PaymentSecretAPIErrorZ* operator ->() const { return &self; }
};
class CResult_CounterpartyForwardingInfoDecodeErrorZ {
private:
	LDKCResult_CounterpartyForwardingInfoDecodeErrorZ self;
public:
	CResult_CounterpartyForwardingInfoDecodeErrorZ(const CResult_CounterpartyForwardingInfoDecodeErrorZ&) = delete;
	CResult_CounterpartyForwardingInfoDecodeErrorZ(CResult_CounterpartyForwardingInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CounterpartyForwardingInfoDecodeErrorZ)); }
	CResult_CounterpartyForwardingInfoDecodeErrorZ(LDKCResult_CounterpartyForwardingInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CounterpartyForwardingInfoDecodeErrorZ)); }
	operator LDKCResult_CounterpartyForwardingInfoDecodeErrorZ() && { LDKCResult_CounterpartyForwardingInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CounterpartyForwardingInfoDecodeErrorZ)); return res; }
	~CResult_CounterpartyForwardingInfoDecodeErrorZ() { CResult_CounterpartyForwardingInfoDecodeErrorZ_free(self); }
	CResult_CounterpartyForwardingInfoDecodeErrorZ& operator=(CResult_CounterpartyForwardingInfoDecodeErrorZ&& o) { CResult_CounterpartyForwardingInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CounterpartyForwardingInfoDecodeErrorZ)); return *this; }
	LDKCResult_CounterpartyForwardingInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CounterpartyForwardingInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CounterpartyForwardingInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CounterpartyForwardingInfoDecodeErrorZ* operator ->() const { return &self; }
};
class COption_ScalarZ {
private:
	LDKCOption_ScalarZ self;
public:
	COption_ScalarZ(const COption_ScalarZ&) = delete;
	COption_ScalarZ(COption_ScalarZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_ScalarZ)); }
	COption_ScalarZ(LDKCOption_ScalarZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_ScalarZ)); }
	operator LDKCOption_ScalarZ() && { LDKCOption_ScalarZ res = self; memset(&self, 0, sizeof(LDKCOption_ScalarZ)); return res; }
	~COption_ScalarZ() { COption_ScalarZ_free(self); }
	COption_ScalarZ& operator=(COption_ScalarZ&& o) { COption_ScalarZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_ScalarZ)); return *this; }
	LDKCOption_ScalarZ* operator &() { return &self; }
	LDKCOption_ScalarZ* operator ->() { return &self; }
	const LDKCOption_ScalarZ* operator &() const { return &self; }
	const LDKCOption_ScalarZ* operator ->() const { return &self; }
};
class CResult_SignedRawInvoiceParseErrorZ {
private:
	LDKCResult_SignedRawInvoiceParseErrorZ self;
public:
	CResult_SignedRawInvoiceParseErrorZ(const CResult_SignedRawInvoiceParseErrorZ&) = delete;
	CResult_SignedRawInvoiceParseErrorZ(CResult_SignedRawInvoiceParseErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SignedRawInvoiceParseErrorZ)); }
	CResult_SignedRawInvoiceParseErrorZ(LDKCResult_SignedRawInvoiceParseErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SignedRawInvoiceParseErrorZ)); }
	operator LDKCResult_SignedRawInvoiceParseErrorZ() && { LDKCResult_SignedRawInvoiceParseErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SignedRawInvoiceParseErrorZ)); return res; }
	~CResult_SignedRawInvoiceParseErrorZ() { CResult_SignedRawInvoiceParseErrorZ_free(self); }
	CResult_SignedRawInvoiceParseErrorZ& operator=(CResult_SignedRawInvoiceParseErrorZ&& o) { CResult_SignedRawInvoiceParseErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SignedRawInvoiceParseErrorZ)); return *this; }
	LDKCResult_SignedRawInvoiceParseErrorZ* operator &() { return &self; }
	LDKCResult_SignedRawInvoiceParseErrorZ* operator ->() { return &self; }
	const LDKCResult_SignedRawInvoiceParseErrorZ* operator &() const { return &self; }
	const LDKCResult_SignedRawInvoiceParseErrorZ* operator ->() const { return &self; }
};
class CResult_RouteDecodeErrorZ {
private:
	LDKCResult_RouteDecodeErrorZ self;
public:
	CResult_RouteDecodeErrorZ(const CResult_RouteDecodeErrorZ&) = delete;
	CResult_RouteDecodeErrorZ(CResult_RouteDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteDecodeErrorZ)); }
	CResult_RouteDecodeErrorZ(LDKCResult_RouteDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteDecodeErrorZ)); }
	operator LDKCResult_RouteDecodeErrorZ() && { LDKCResult_RouteDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteDecodeErrorZ)); return res; }
	~CResult_RouteDecodeErrorZ() { CResult_RouteDecodeErrorZ_free(self); }
	CResult_RouteDecodeErrorZ& operator=(CResult_RouteDecodeErrorZ&& o) { CResult_RouteDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteDecodeErrorZ)); return *this; }
	LDKCResult_RouteDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_BuiltCommitmentTransactionDecodeErrorZ {
private:
	LDKCResult_BuiltCommitmentTransactionDecodeErrorZ self;
public:
	CResult_BuiltCommitmentTransactionDecodeErrorZ(const CResult_BuiltCommitmentTransactionDecodeErrorZ&) = delete;
	CResult_BuiltCommitmentTransactionDecodeErrorZ(CResult_BuiltCommitmentTransactionDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_BuiltCommitmentTransactionDecodeErrorZ)); }
	CResult_BuiltCommitmentTransactionDecodeErrorZ(LDKCResult_BuiltCommitmentTransactionDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_BuiltCommitmentTransactionDecodeErrorZ)); }
	operator LDKCResult_BuiltCommitmentTransactionDecodeErrorZ() && { LDKCResult_BuiltCommitmentTransactionDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_BuiltCommitmentTransactionDecodeErrorZ)); return res; }
	~CResult_BuiltCommitmentTransactionDecodeErrorZ() { CResult_BuiltCommitmentTransactionDecodeErrorZ_free(self); }
	CResult_BuiltCommitmentTransactionDecodeErrorZ& operator=(CResult_BuiltCommitmentTransactionDecodeErrorZ&& o) { CResult_BuiltCommitmentTransactionDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_BuiltCommitmentTransactionDecodeErrorZ)); return *this; }
	LDKCResult_BuiltCommitmentTransactionDecodeErrorZ* operator &() { return &self; }
	LDKCResult_BuiltCommitmentTransactionDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_BuiltCommitmentTransactionDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_BuiltCommitmentTransactionDecodeErrorZ* operator ->() const { return &self; }
};
class COption_NoneZ {
private:
	LDKCOption_NoneZ self;
public:
	COption_NoneZ(const COption_NoneZ&) = delete;
	COption_NoneZ(COption_NoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(COption_NoneZ)); }
	COption_NoneZ(LDKCOption_NoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCOption_NoneZ)); }
	operator LDKCOption_NoneZ() && { LDKCOption_NoneZ res = self; memset(&self, 0, sizeof(LDKCOption_NoneZ)); return res; }
	~COption_NoneZ() { COption_NoneZ_free(self); }
	COption_NoneZ& operator=(COption_NoneZ&& o) { COption_NoneZ_free(self); self = o.self; memset(&o, 0, sizeof(COption_NoneZ)); return *this; }
	LDKCOption_NoneZ* operator &() { return &self; }
	LDKCOption_NoneZ* operator ->() { return &self; }
	const LDKCOption_NoneZ* operator &() const { return &self; }
	const LDKCOption_NoneZ* operator ->() const { return &self; }
};
class CVec_TxOutZ {
private:
	LDKCVec_TxOutZ self;
public:
	CVec_TxOutZ(const CVec_TxOutZ&) = delete;
	CVec_TxOutZ(CVec_TxOutZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_TxOutZ)); }
	CVec_TxOutZ(LDKCVec_TxOutZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_TxOutZ)); }
	operator LDKCVec_TxOutZ() && { LDKCVec_TxOutZ res = self; memset(&self, 0, sizeof(LDKCVec_TxOutZ)); return res; }
	~CVec_TxOutZ() { CVec_TxOutZ_free(self); }
	CVec_TxOutZ& operator=(CVec_TxOutZ&& o) { CVec_TxOutZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_TxOutZ)); return *this; }
	LDKCVec_TxOutZ* operator &() { return &self; }
	LDKCVec_TxOutZ* operator ->() { return &self; }
	const LDKCVec_TxOutZ* operator &() const { return &self; }
	const LDKCVec_TxOutZ* operator ->() const { return &self; }
};
class CResult_ChannelUpdateInfoDecodeErrorZ {
private:
	LDKCResult_ChannelUpdateInfoDecodeErrorZ self;
public:
	CResult_ChannelUpdateInfoDecodeErrorZ(const CResult_ChannelUpdateInfoDecodeErrorZ&) = delete;
	CResult_ChannelUpdateInfoDecodeErrorZ(CResult_ChannelUpdateInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelUpdateInfoDecodeErrorZ)); }
	CResult_ChannelUpdateInfoDecodeErrorZ(LDKCResult_ChannelUpdateInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelUpdateInfoDecodeErrorZ)); }
	operator LDKCResult_ChannelUpdateInfoDecodeErrorZ() && { LDKCResult_ChannelUpdateInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelUpdateInfoDecodeErrorZ)); return res; }
	~CResult_ChannelUpdateInfoDecodeErrorZ() { CResult_ChannelUpdateInfoDecodeErrorZ_free(self); }
	CResult_ChannelUpdateInfoDecodeErrorZ& operator=(CResult_ChannelUpdateInfoDecodeErrorZ&& o) { CResult_ChannelUpdateInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelUpdateInfoDecodeErrorZ)); return *this; }
	LDKCResult_ChannelUpdateInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelUpdateInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelUpdateInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelUpdateInfoDecodeErrorZ* operator ->() const { return &self; }
};
class C2Tuple_u32ScriptZ {
private:
	LDKC2Tuple_u32ScriptZ self;
public:
	C2Tuple_u32ScriptZ(const C2Tuple_u32ScriptZ&) = delete;
	C2Tuple_u32ScriptZ(C2Tuple_u32ScriptZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_u32ScriptZ)); }
	C2Tuple_u32ScriptZ(LDKC2Tuple_u32ScriptZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_u32ScriptZ)); }
	operator LDKC2Tuple_u32ScriptZ() && { LDKC2Tuple_u32ScriptZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_u32ScriptZ)); return res; }
	~C2Tuple_u32ScriptZ() { C2Tuple_u32ScriptZ_free(self); }
	C2Tuple_u32ScriptZ& operator=(C2Tuple_u32ScriptZ&& o) { C2Tuple_u32ScriptZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_u32ScriptZ)); return *this; }
	LDKC2Tuple_u32ScriptZ* operator &() { return &self; }
	LDKC2Tuple_u32ScriptZ* operator ->() { return &self; }
	const LDKC2Tuple_u32ScriptZ* operator &() const { return &self; }
	const LDKC2Tuple_u32ScriptZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
private:
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ self;
public:
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(const CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&) = delete;
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); }
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); }
	operator LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ() && { LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); return res; }
	~CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ() { CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(self); }
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ& operator=(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& o) { CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); return *this; }
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_UpdateFailHTLCZ {
private:
	LDKCVec_UpdateFailHTLCZ self;
public:
	CVec_UpdateFailHTLCZ(const CVec_UpdateFailHTLCZ&) = delete;
	CVec_UpdateFailHTLCZ(CVec_UpdateFailHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFailHTLCZ)); }
	CVec_UpdateFailHTLCZ(LDKCVec_UpdateFailHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFailHTLCZ)); }
	operator LDKCVec_UpdateFailHTLCZ() && { LDKCVec_UpdateFailHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFailHTLCZ)); return res; }
	~CVec_UpdateFailHTLCZ() { CVec_UpdateFailHTLCZ_free(self); }
	CVec_UpdateFailHTLCZ& operator=(CVec_UpdateFailHTLCZ&& o) { CVec_UpdateFailHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFailHTLCZ)); return *this; }
	LDKCVec_UpdateFailHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFailHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFailHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFailHTLCZ* operator ->() const { return &self; }
};
class CResult_ReplyShortChannelIdsEndDecodeErrorZ {
private:
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ self;
public:
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(const CResult_ReplyShortChannelIdsEndDecodeErrorZ&) = delete;
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(CResult_ReplyShortChannelIdsEndDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ReplyShortChannelIdsEndDecodeErrorZ)); }
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ)); }
	operator LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ() && { LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ)); return res; }
	~CResult_ReplyShortChannelIdsEndDecodeErrorZ() { CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(self); }
	CResult_ReplyShortChannelIdsEndDecodeErrorZ& operator=(CResult_ReplyShortChannelIdsEndDecodeErrorZ&& o) { CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ReplyShortChannelIdsEndDecodeErrorZ)); return *this; }
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator ->() const { return &self; }
};

inline void BroadcasterInterface::broadcast_transaction(struct LDKTransaction tx) {
	(self.broadcast_transaction)(self.this_arg, tx);
}
inline uint32_t FeeEstimator::get_est_sat_per_1000_weight(enum LDKConfirmationTarget confirmation_target) {
	uint32_t ret = (self.get_est_sat_per_1000_weight)(self.this_arg, confirmation_target);
	return ret;
}
inline LDK::CVec_MessageSendEventZ MessageSendEventsProvider::get_and_clear_pending_msg_events() {
	LDK::CVec_MessageSendEventZ ret = (self.get_and_clear_pending_msg_events)(self.this_arg);
	return ret;
}
inline LDK::OnionMessage OnionMessageProvider::next_onion_message_for_peer(struct LDKPublicKey peer_node_id) {
	LDK::OnionMessage ret = (self.next_onion_message_for_peer)(self.this_arg, peer_node_id);
	return ret;
}
inline void EventsProvider::process_pending_events(struct LDKEventHandler handler) {
	(self.process_pending_events)(self.this_arg, handler);
}
inline void EventHandler::handle_event(const struct LDKEvent *NONNULL_PTR event) {
	(self.handle_event)(self.this_arg, event);
}
inline LDK::CResult_TxOutAccessErrorZ Access::get_utxo(const uint8_t (*genesis_hash)[32], uint64_t short_channel_id) {
	LDK::CResult_TxOutAccessErrorZ ret = (self.get_utxo)(self.this_arg, genesis_hash, short_channel_id);
	return ret;
}
inline void Listen::filtered_block_connected(const uint8_t (*header)[80], struct LDKCVec_C2Tuple_usizeTransactionZZ txdata, uint32_t height) {
	(self.filtered_block_connected)(self.this_arg, header, txdata, height);
}
inline void Listen::block_connected(struct LDKu8slice block, uint32_t height) {
	(self.block_connected)(self.this_arg, block, height);
}
inline void Listen::block_disconnected(const uint8_t (*header)[80], uint32_t height) {
	(self.block_disconnected)(self.this_arg, header, height);
}
inline void Confirm::transactions_confirmed(const uint8_t (*header)[80], struct LDKCVec_C2Tuple_usizeTransactionZZ txdata, uint32_t height) {
	(self.transactions_confirmed)(self.this_arg, header, txdata, height);
}
inline void Confirm::transaction_unconfirmed(const uint8_t (*txid)[32]) {
	(self.transaction_unconfirmed)(self.this_arg, txid);
}
inline void Confirm::best_block_updated(const uint8_t (*header)[80], uint32_t height) {
	(self.best_block_updated)(self.this_arg, header, height);
}
inline LDK::CVec_TxidZ Confirm::get_relevant_txids() {
	LDK::CVec_TxidZ ret = (self.get_relevant_txids)(self.this_arg);
	return ret;
}
inline LDK::CResult_NoneChannelMonitorUpdateErrZ Watch::watch_channel(struct LDKOutPoint funding_txo, struct LDKChannelMonitor monitor) {
	LDK::CResult_NoneChannelMonitorUpdateErrZ ret = (self.watch_channel)(self.this_arg, funding_txo, monitor);
	return ret;
}
inline LDK::CResult_NoneChannelMonitorUpdateErrZ Watch::update_channel(struct LDKOutPoint funding_txo, struct LDKChannelMonitorUpdate update) {
	LDK::CResult_NoneChannelMonitorUpdateErrZ ret = (self.update_channel)(self.this_arg, funding_txo, update);
	return ret;
}
inline LDK::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ Watch::release_pending_monitor_events() {
	LDK::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ ret = (self.release_pending_monitor_events)(self.this_arg);
	return ret;
}
inline void Filter::register_tx(const uint8_t (*txid)[32], struct LDKu8slice script_pubkey) {
	(self.register_tx)(self.this_arg, txid, script_pubkey);
}
inline void Filter::register_output(struct LDKWatchedOutput output) {
	(self.register_output)(self.this_arg, output);
}
inline uint64_t Score::channel_penalty_msat(uint64_t short_channel_id, const struct LDKNodeId *NONNULL_PTR source, const struct LDKNodeId *NONNULL_PTR target, struct LDKChannelUsage usage) {
	uint64_t ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, source, target, usage);
	return ret;
}
inline void Score::payment_path_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id) {
	(self.payment_path_failed)(self.this_arg, path, short_channel_id);
}
inline void Score::payment_path_successful(struct LDKCVec_RouteHopZ path) {
	(self.payment_path_successful)(self.this_arg, path);
}
inline void Score::probe_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id) {
	(self.probe_failed)(self.this_arg, path, short_channel_id);
}
inline void Score::probe_successful(struct LDKCVec_RouteHopZ path) {
	(self.probe_successful)(self.this_arg, path);
}
inline LDK::Score LockableScore::lock() {
	LDK::Score ret = (self.lock)(self.this_arg);
	return ret;
}
inline LDKPublicKey BaseSign::get_per_commitment_point(uint64_t idx) {
	LDKPublicKey ret = (self.get_per_commitment_point)(self.this_arg, idx);
	return ret;
}
inline LDKThirtyTwoBytes BaseSign::release_commitment_secret(uint64_t idx) {
	LDKThirtyTwoBytes ret = (self.release_commitment_secret)(self.this_arg, idx);
	return ret;
}
inline LDK::CResult_NoneNoneZ BaseSign::validate_holder_commitment(const struct LDKHolderCommitmentTransaction *NONNULL_PTR holder_tx, struct LDKCVec_PaymentPreimageZ preimages) {
	LDK::CResult_NoneNoneZ ret = (self.validate_holder_commitment)(self.this_arg, holder_tx, preimages);
	return ret;
}
inline LDKThirtyTwoBytes BaseSign::channel_keys_id() {
	LDKThirtyTwoBytes ret = (self.channel_keys_id)(self.this_arg);
	return ret;
}
inline LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ BaseSign::sign_counterparty_commitment(const struct LDKCommitmentTransaction *NONNULL_PTR commitment_tx, struct LDKCVec_PaymentPreimageZ preimages) {
	LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ ret = (self.sign_counterparty_commitment)(self.this_arg, commitment_tx, preimages);
	return ret;
}
inline LDK::CResult_NoneNoneZ BaseSign::validate_counterparty_revocation(uint64_t idx, const uint8_t (*secret)[32]) {
	LDK::CResult_NoneNoneZ ret = (self.validate_counterparty_revocation)(self.this_arg, idx, secret);
	return ret;
}
inline LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ BaseSign::sign_holder_commitment_and_htlcs(const struct LDKHolderCommitmentTransaction *NONNULL_PTR commitment_tx) {
	LDK::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ ret = (self.sign_holder_commitment_and_htlcs)(self.this_arg, commitment_tx);
	return ret;
}
inline LDK::CResult_SignatureNoneZ BaseSign::sign_justice_revoked_output(struct LDKTransaction justice_tx, uintptr_t input, uint64_t amount, const uint8_t (*per_commitment_key)[32]) {
	LDK::CResult_SignatureNoneZ ret = (self.sign_justice_revoked_output)(self.this_arg, justice_tx, input, amount, per_commitment_key);
	return ret;
}
inline LDK::CResult_SignatureNoneZ BaseSign::sign_justice_revoked_htlc(struct LDKTransaction justice_tx, uintptr_t input, uint64_t amount, const uint8_t (*per_commitment_key)[32], const struct LDKHTLCOutputInCommitment *NONNULL_PTR htlc) {
	LDK::CResult_SignatureNoneZ ret = (self.sign_justice_revoked_htlc)(self.this_arg, justice_tx, input, amount, per_commitment_key, htlc);
	return ret;
}
inline LDK::CResult_SignatureNoneZ BaseSign::sign_counterparty_htlc_transaction(struct LDKTransaction htlc_tx, uintptr_t input, uint64_t amount, struct LDKPublicKey per_commitment_point, const struct LDKHTLCOutputInCommitment *NONNULL_PTR htlc) {
	LDK::CResult_SignatureNoneZ ret = (self.sign_counterparty_htlc_transaction)(self.this_arg, htlc_tx, input, amount, per_commitment_point, htlc);
	return ret;
}
inline LDK::CResult_SignatureNoneZ BaseSign::sign_closing_transaction(const struct LDKClosingTransaction *NONNULL_PTR closing_tx) {
	LDK::CResult_SignatureNoneZ ret = (self.sign_closing_transaction)(self.this_arg, closing_tx);
	return ret;
}
inline LDK::CResult_C2Tuple_SignatureSignatureZNoneZ BaseSign::sign_channel_announcement(const struct LDKUnsignedChannelAnnouncement *NONNULL_PTR msg) {
	LDK::CResult_C2Tuple_SignatureSignatureZNoneZ ret = (self.sign_channel_announcement)(self.this_arg, msg);
	return ret;
}
inline void BaseSign::ready_channel(const struct LDKChannelTransactionParameters *NONNULL_PTR channel_parameters) {
	(self.ready_channel)(self.this_arg, channel_parameters);
}
inline LDK::CResult_SecretKeyNoneZ KeysInterface::get_node_secret(enum LDKRecipient recipient) {
	LDK::CResult_SecretKeyNoneZ ret = (self.get_node_secret)(self.this_arg, recipient);
	return ret;
}
inline LDK::CResult_SharedSecretNoneZ KeysInterface::ecdh(enum LDKRecipient recipient, struct LDKPublicKey other_key, struct LDKCOption_ScalarZ tweak) {
	LDK::CResult_SharedSecretNoneZ ret = (self.ecdh)(self.this_arg, recipient, other_key, tweak);
	return ret;
}
inline LDK::CVec_u8Z KeysInterface::get_destination_script() {
	LDK::CVec_u8Z ret = (self.get_destination_script)(self.this_arg);
	return ret;
}
inline LDK::ShutdownScript KeysInterface::get_shutdown_scriptpubkey() {
	LDK::ShutdownScript ret = (self.get_shutdown_scriptpubkey)(self.this_arg);
	return ret;
}
inline LDK::Sign KeysInterface::get_channel_signer(bool inbound, uint64_t channel_value_satoshis) {
	LDK::Sign ret = (self.get_channel_signer)(self.this_arg, inbound, channel_value_satoshis);
	return ret;
}
inline LDKThirtyTwoBytes KeysInterface::get_secure_random_bytes() {
	LDKThirtyTwoBytes ret = (self.get_secure_random_bytes)(self.this_arg);
	return ret;
}
inline LDK::CResult_SignDecodeErrorZ KeysInterface::read_chan_signer(struct LDKu8slice reader) {
	LDK::CResult_SignDecodeErrorZ ret = (self.read_chan_signer)(self.this_arg, reader);
	return ret;
}
inline LDK::CResult_RecoverableSignatureNoneZ KeysInterface::sign_invoice(struct LDKu8slice hrp_bytes, struct LDKCVec_u5Z invoice_data, enum LDKRecipient receipient) {
	LDK::CResult_RecoverableSignatureNoneZ ret = (self.sign_invoice)(self.this_arg, hrp_bytes, invoice_data, receipient);
	return ret;
}
inline LDKThirtyTwoBytes KeysInterface::get_inbound_payment_key_material() {
	LDKThirtyTwoBytes ret = (self.get_inbound_payment_key_material)(self.this_arg);
	return ret;
}
inline LDK::CResult_COption_TypeZDecodeErrorZ CustomMessageReader::read(uint16_t message_type, struct LDKu8slice buffer) {
	LDK::CResult_COption_TypeZDecodeErrorZ ret = (self.read)(self.this_arg, message_type, buffer);
	return ret;
}
inline uint16_t Type::type_id() {
	uint16_t ret = (self.type_id)(self.this_arg);
	return ret;
}
inline LDK::Str Type::debug_str() {
	LDK::Str ret = (self.debug_str)(self.this_arg);
	return ret;
}
inline LDKPublicKey Payer::node_id() {
	LDKPublicKey ret = (self.node_id)(self.this_arg);
	return ret;
}
inline LDK::CVec_ChannelDetailsZ Payer::first_hops() {
	LDK::CVec_ChannelDetailsZ ret = (self.first_hops)(self.this_arg);
	return ret;
}
inline LDK::CResult_PaymentIdPaymentSendFailureZ Payer::send_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_hash, struct LDKThirtyTwoBytes payment_secret) {
	LDK::CResult_PaymentIdPaymentSendFailureZ ret = (self.send_payment)(self.this_arg, route, payment_hash, payment_secret);
	return ret;
}
inline LDK::CResult_PaymentIdPaymentSendFailureZ Payer::send_spontaneous_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_preimage) {
	LDK::CResult_PaymentIdPaymentSendFailureZ ret = (self.send_spontaneous_payment)(self.this_arg, route, payment_preimage);
	return ret;
}
inline LDK::CResult_NonePaymentSendFailureZ Payer::retry_payment(const struct LDKRoute *NONNULL_PTR route, struct LDKThirtyTwoBytes payment_id) {
	LDK::CResult_NonePaymentSendFailureZ ret = (self.retry_payment)(self.this_arg, route, payment_id);
	return ret;
}
inline void Payer::abandon_payment(struct LDKThirtyTwoBytes payment_id) {
	(self.abandon_payment)(self.this_arg, payment_id);
}
inline LDK::CResult_RouteLightningErrorZ Router::find_route(struct LDKPublicKey payer, const struct LDKRouteParameters *NONNULL_PTR route_params, const uint8_t (*payment_hash)[32], struct LDKCVec_ChannelDetailsZ *first_hops, struct LDKInFlightHtlcs inflight_htlcs) {
	LDK::CResult_RouteLightningErrorZ ret = (self.find_route)(self.this_arg, payer, route_params, payment_hash, first_hops, inflight_htlcs);
	return ret;
}
inline void Router::notify_payment_path_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id) {
	(self.notify_payment_path_failed)(self.this_arg, path, short_channel_id);
}
inline void Router::notify_payment_path_successful(struct LDKCVec_RouteHopZ path) {
	(self.notify_payment_path_successful)(self.this_arg, path);
}
inline void Router::notify_payment_probe_successful(struct LDKCVec_RouteHopZ path) {
	(self.notify_payment_probe_successful)(self.this_arg, path);
}
inline void Router::notify_payment_probe_failed(struct LDKCVec_RouteHopZ path, uint64_t short_channel_id) {
	(self.notify_payment_probe_failed)(self.this_arg, path, short_channel_id);
}
inline LDK::CResult_NoneLightningErrorZ CustomMessageHandler::handle_custom_message(struct LDKType msg, struct LDKPublicKey sender_node_id) {
	LDK::CResult_NoneLightningErrorZ ret = (self.handle_custom_message)(self.this_arg, msg, sender_node_id);
	return ret;
}
inline LDK::CVec_C2Tuple_PublicKeyTypeZZ CustomMessageHandler::get_and_clear_pending_msg() {
	LDK::CVec_C2Tuple_PublicKeyTypeZZ ret = (self.get_and_clear_pending_msg)(self.this_arg);
	return ret;
}
inline uintptr_t SocketDescriptor::send_data(struct LDKu8slice data, bool resume_read) {
	uintptr_t ret = (self.send_data)(self.this_arg, data, resume_read);
	return ret;
}
inline void SocketDescriptor::disconnect_socket() {
	(self.disconnect_socket)(self.this_arg);
}
inline bool SocketDescriptor::eq(const struct LDKSocketDescriptor *NONNULL_PTR other_arg) {
	bool ret = (self.eq)(self.this_arg, other_arg);
	return ret;
}
inline uint64_t SocketDescriptor::hash() {
	uint64_t ret = (self.hash)(self.this_arg);
	return ret;
}
inline LDK::CResult_NoneErrorZ Persister::persist_manager(const struct LDKChannelManager *NONNULL_PTR channel_manager) {
	LDK::CResult_NoneErrorZ ret = (self.persist_manager)(self.this_arg, channel_manager);
	return ret;
}
inline LDK::CResult_NoneErrorZ Persister::persist_graph(const struct LDKNetworkGraph *NONNULL_PTR network_graph) {
	LDK::CResult_NoneErrorZ ret = (self.persist_graph)(self.this_arg, network_graph);
	return ret;
}
inline LDK::CResult_NoneErrorZ Persister::persist_scorer(const struct LDKWriteableScore *NONNULL_PTR scorer) {
	LDK::CResult_NoneErrorZ ret = (self.persist_scorer)(self.this_arg, scorer);
	return ret;
}
inline void ChannelMessageHandler::handle_open_channel(struct LDKPublicKey their_node_id, struct LDKInitFeatures their_features, const struct LDKOpenChannel *NONNULL_PTR msg) {
	(self.handle_open_channel)(self.this_arg, their_node_id, their_features, msg);
}
inline void ChannelMessageHandler::handle_accept_channel(struct LDKPublicKey their_node_id, struct LDKInitFeatures their_features, const struct LDKAcceptChannel *NONNULL_PTR msg) {
	(self.handle_accept_channel)(self.this_arg, their_node_id, their_features, msg);
}
inline void ChannelMessageHandler::handle_funding_created(struct LDKPublicKey their_node_id, const struct LDKFundingCreated *NONNULL_PTR msg) {
	(self.handle_funding_created)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_funding_signed(struct LDKPublicKey their_node_id, const struct LDKFundingSigned *NONNULL_PTR msg) {
	(self.handle_funding_signed)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_channel_ready(struct LDKPublicKey their_node_id, const struct LDKChannelReady *NONNULL_PTR msg) {
	(self.handle_channel_ready)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_shutdown(struct LDKPublicKey their_node_id, const struct LDKInitFeatures *NONNULL_PTR their_features, const struct LDKShutdown *NONNULL_PTR msg) {
	(self.handle_shutdown)(self.this_arg, their_node_id, their_features, msg);
}
inline void ChannelMessageHandler::handle_closing_signed(struct LDKPublicKey their_node_id, const struct LDKClosingSigned *NONNULL_PTR msg) {
	(self.handle_closing_signed)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_update_add_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateAddHTLC *NONNULL_PTR msg) {
	(self.handle_update_add_htlc)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_update_fulfill_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFulfillHTLC *NONNULL_PTR msg) {
	(self.handle_update_fulfill_htlc)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_update_fail_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFailHTLC *NONNULL_PTR msg) {
	(self.handle_update_fail_htlc)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_update_fail_malformed_htlc(struct LDKPublicKey their_node_id, const struct LDKUpdateFailMalformedHTLC *NONNULL_PTR msg) {
	(self.handle_update_fail_malformed_htlc)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_commitment_signed(struct LDKPublicKey their_node_id, const struct LDKCommitmentSigned *NONNULL_PTR msg) {
	(self.handle_commitment_signed)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_revoke_and_ack(struct LDKPublicKey their_node_id, const struct LDKRevokeAndACK *NONNULL_PTR msg) {
	(self.handle_revoke_and_ack)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_update_fee(struct LDKPublicKey their_node_id, const struct LDKUpdateFee *NONNULL_PTR msg) {
	(self.handle_update_fee)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_announcement_signatures(struct LDKPublicKey their_node_id, const struct LDKAnnouncementSignatures *NONNULL_PTR msg) {
	(self.handle_announcement_signatures)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::peer_disconnected(struct LDKPublicKey their_node_id, bool no_connection_possible) {
	(self.peer_disconnected)(self.this_arg, their_node_id, no_connection_possible);
}
inline void ChannelMessageHandler::peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR msg) {
	(self.peer_connected)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_channel_reestablish(struct LDKPublicKey their_node_id, const struct LDKChannelReestablish *NONNULL_PTR msg) {
	(self.handle_channel_reestablish)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_channel_update(struct LDKPublicKey their_node_id, const struct LDKChannelUpdate *NONNULL_PTR msg) {
	(self.handle_channel_update)(self.this_arg, their_node_id, msg);
}
inline void ChannelMessageHandler::handle_error(struct LDKPublicKey their_node_id, const struct LDKErrorMessage *NONNULL_PTR msg) {
	(self.handle_error)(self.this_arg, their_node_id, msg);
}
inline LDK::NodeFeatures ChannelMessageHandler::provided_node_features() {
	LDK::NodeFeatures ret = (self.provided_node_features)(self.this_arg);
	return ret;
}
inline LDK::InitFeatures ChannelMessageHandler::provided_init_features(struct LDKPublicKey their_node_id) {
	LDK::InitFeatures ret = (self.provided_init_features)(self.this_arg, their_node_id);
	return ret;
}
inline LDK::CResult_boolLightningErrorZ RoutingMessageHandler::handle_node_announcement(const struct LDKNodeAnnouncement *NONNULL_PTR msg) {
	LDK::CResult_boolLightningErrorZ ret = (self.handle_node_announcement)(self.this_arg, msg);
	return ret;
}
inline LDK::CResult_boolLightningErrorZ RoutingMessageHandler::handle_channel_announcement(const struct LDKChannelAnnouncement *NONNULL_PTR msg) {
	LDK::CResult_boolLightningErrorZ ret = (self.handle_channel_announcement)(self.this_arg, msg);
	return ret;
}
inline LDK::CResult_boolLightningErrorZ RoutingMessageHandler::handle_channel_update(const struct LDKChannelUpdate *NONNULL_PTR msg) {
	LDK::CResult_boolLightningErrorZ ret = (self.handle_channel_update)(self.this_arg, msg);
	return ret;
}
inline LDK::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ RoutingMessageHandler::get_next_channel_announcement(uint64_t starting_point) {
	LDK::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ ret = (self.get_next_channel_announcement)(self.this_arg, starting_point);
	return ret;
}
inline LDK::NodeAnnouncement RoutingMessageHandler::get_next_node_announcement(struct LDKPublicKey starting_point) {
	LDK::NodeAnnouncement ret = (self.get_next_node_announcement)(self.this_arg, starting_point);
	return ret;
}
inline void RoutingMessageHandler::peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR init) {
	(self.peer_connected)(self.this_arg, their_node_id, init);
}
inline LDK::CResult_NoneLightningErrorZ RoutingMessageHandler::handle_reply_channel_range(struct LDKPublicKey their_node_id, struct LDKReplyChannelRange msg) {
	LDK::CResult_NoneLightningErrorZ ret = (self.handle_reply_channel_range)(self.this_arg, their_node_id, msg);
	return ret;
}
inline LDK::CResult_NoneLightningErrorZ RoutingMessageHandler::handle_reply_short_channel_ids_end(struct LDKPublicKey their_node_id, struct LDKReplyShortChannelIdsEnd msg) {
	LDK::CResult_NoneLightningErrorZ ret = (self.handle_reply_short_channel_ids_end)(self.this_arg, their_node_id, msg);
	return ret;
}
inline LDK::CResult_NoneLightningErrorZ RoutingMessageHandler::handle_query_channel_range(struct LDKPublicKey their_node_id, struct LDKQueryChannelRange msg) {
	LDK::CResult_NoneLightningErrorZ ret = (self.handle_query_channel_range)(self.this_arg, their_node_id, msg);
	return ret;
}
inline LDK::CResult_NoneLightningErrorZ RoutingMessageHandler::handle_query_short_channel_ids(struct LDKPublicKey their_node_id, struct LDKQueryShortChannelIds msg) {
	LDK::CResult_NoneLightningErrorZ ret = (self.handle_query_short_channel_ids)(self.this_arg, their_node_id, msg);
	return ret;
}
inline LDK::NodeFeatures RoutingMessageHandler::provided_node_features() {
	LDK::NodeFeatures ret = (self.provided_node_features)(self.this_arg);
	return ret;
}
inline LDK::InitFeatures RoutingMessageHandler::provided_init_features(struct LDKPublicKey their_node_id) {
	LDK::InitFeatures ret = (self.provided_init_features)(self.this_arg, their_node_id);
	return ret;
}
inline void OnionMessageHandler::handle_onion_message(struct LDKPublicKey peer_node_id, const struct LDKOnionMessage *NONNULL_PTR msg) {
	(self.handle_onion_message)(self.this_arg, peer_node_id, msg);
}
inline void OnionMessageHandler::peer_connected(struct LDKPublicKey their_node_id, const struct LDKInit *NONNULL_PTR init) {
	(self.peer_connected)(self.this_arg, their_node_id, init);
}
inline void OnionMessageHandler::peer_disconnected(struct LDKPublicKey their_node_id, bool no_connection_possible) {
	(self.peer_disconnected)(self.this_arg, their_node_id, no_connection_possible);
}
inline LDK::NodeFeatures OnionMessageHandler::provided_node_features() {
	LDK::NodeFeatures ret = (self.provided_node_features)(self.this_arg);
	return ret;
}
inline LDK::InitFeatures OnionMessageHandler::provided_init_features(struct LDKPublicKey their_node_id) {
	LDK::InitFeatures ret = (self.provided_init_features)(self.this_arg, their_node_id);
	return ret;
}
inline void Logger::log(const struct LDKRecord *NONNULL_PTR record) {
	(self.log)(self.this_arg, record);
}
inline void FutureCallback::call() {
	(self.call)(self.this_arg);
}
inline LDK::CResult_NoneChannelMonitorUpdateErrZ Persist::persist_new_channel(struct LDKOutPoint channel_id, const struct LDKChannelMonitor *NONNULL_PTR data, struct LDKMonitorUpdateId update_id) {
	LDK::CResult_NoneChannelMonitorUpdateErrZ ret = (self.persist_new_channel)(self.this_arg, channel_id, data, update_id);
	return ret;
}
inline LDK::CResult_NoneChannelMonitorUpdateErrZ Persist::update_persisted_channel(struct LDKOutPoint channel_id, const struct LDKChannelMonitorUpdate *NONNULL_PTR update, const struct LDKChannelMonitor *NONNULL_PTR data, struct LDKMonitorUpdateId update_id) {
	LDK::CResult_NoneChannelMonitorUpdateErrZ ret = (self.update_persisted_channel)(self.this_arg, channel_id, update, data, update_id);
	return ret;
}
}
