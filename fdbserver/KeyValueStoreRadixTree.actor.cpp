///*
// * KeyValueStoreRadixTree.actor.cpp
// *
// * This source file is part of the FoundationDB open source project
// *
// * Copyright 2013-2018 Apple Inc. and the FoundationDB project authors
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *     http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
//#include "flow/actorcompiler.h"
//#include "IKeyValueStore.h"
//#include "IDiskQueue.h"
//#include "flow/RadixTree.h"
//#include "flow/ActorCollection.h"
//#include "fdbclient/Notified.h"
//#include "fdbclient/SystemData.h"
//
//#define OP_DISK_OVERHEAD (sizeof(OpHeader) + 1)
//
//extern bool noUnseed;
//
//class KeyValueStoreRadixTree : public IKeyValueStore, NonCopyable {
//public:
//	KeyValueStoreRadixTree( IDiskQueue* log, UID id, int64_t memoryLimit, bool disableSnapshot, bool replaceContent, bool exactRecovery );
//
//	// IClosable
//	virtual Future<Void> getError() { return log->getError(); }
//	virtual Future<Void> onClosed() { return log->onClosed(); }
//	virtual void dispose() {
//		recovering.cancel();
//		log->dispose();
//		data.clear();
//		delete reserved_buffer;
//		delete this;
//	}
//	virtual void close() {
//		recovering.cancel();
//		log->close();
//		data.clear();
//		delete reserved_buffer;
//		delete this;
//	}
//
//	// IKeyValueStore
//	virtual KeyValueStoreType getType() { return KeyValueStoreType::MEMORY_RADIXTREE; }
//
//	int64_t getAvailableSize() {
//		int64_t residentSize =
//			data.sum_to(data.end()) +
//			queue.totalSize() +  // doesn't account for overhead in queue
//			transactionSize;
//        return memoryLimit - residentSize;
//	}
//
//	virtual StorageBytes getStorageBytes() {
//		StorageBytes diskQueueBytes = log->getStorageBytes();
//
//		// Try to bound how many in-memory bytes we might need to write to disk if we commit() now
//		int64_t uncommittedBytes = queue.totalSize() + transactionSize;
//
//		//Check that we have enough space in memory and on disk
//		int64_t freeSize = std::min(getAvailableSize(), diskQueueBytes.free / 4 - uncommittedBytes);
//		int64_t availableSize = std::min(getAvailableSize(), diskQueueBytes.available / 4 - uncommittedBytes);
//		int64_t totalSize = std::min(memoryLimit, diskQueueBytes.total / 4 - uncommittedBytes);
//
//		return StorageBytes(std::max((int64_t)0, freeSize), std::max((int64_t)0, totalSize), diskQueueBytes.used,
//		                    std::max((int64_t)0, availableSize));
//	}
//
//	virtual std::tuple<size_t, size_t, size_t> getSize() { return data.size(); }
//
//	void semiCommit() {
//		transactionSize += queue.totalSize();
//		if(transactionSize > 0.5 * committedDataSize) {
//			transactionIsLarge = true;
//			TraceEvent("KVSRtreeSwitchingToLargeTransactionMode", id).detail("TransactionSize", transactionSize).detail("DataSize", committedDataSize);
//			TEST(true); // KeyValueStoreMemory switching to large transaction mode
//			TEST(committedDataSize > 1e3); // KeyValueStoreMemory switching to large transaction mode with committed data
//		}
//
//		int64_t bytesWritten = commit_queue(queue, true);
//		committedWriteBytes += bytesWritten;
//	}
//
//	virtual void printData() {
//		printf("radix tree size %lu\n", std::get<0>(data.size()));
//		for (auto it = data.begin(); it != data.end(); ++it) {
//			StringRef key = it.getKey(reserved_buffer, 10000);
//			printf("key[%s : %d] value[%s : %d]\n", printable(key).c_str(), key.size(), printable(*it).c_str(),
//			       (*it).size());
//		}
//	}
//
//	virtual void set(KeyValueRef keyValue, const Arena* arena) {
//		//A commit that occurs with no available space returns Never, so we can throw out all modifications
//		if(getAvailableSize() <= 0)
//			return;
//
////		printf("insert: key[%s] value[%s] and larger %d? \n", printable(keyValue.key).c_str(), printable(keyValue.value).c_str(), transactionIsLarge);
//        if(transactionIsLarge) {
//			data.insert(keyValue.key, keyValue.value);
//		}
//		else {
//			queue.set(keyValue, arena);
//			if(recovering.isReady() && !disableSnapshot) {
//				semiCommit();
//			}
//		}
//		// printf("insert end: tree size[%lu]\n", std::get<0>(data.size()));
//	}
//
//	virtual void clear(KeyRangeRef range, const Arena* arena) {
//		//A commit that occurs with no available space returns Never, so we can throw out all modifications
//		if(getAvailableSize() <= 0)
//			return;
//
//		if(transactionIsLarge) {
//			data.erase(data.lower_bound(range.begin), data.lower_bound(range.end));
//		}
//		else {
//			queue.clear(range, arena);
//			if(recovering.isReady() && !disableSnapshot) {
//				semiCommit();
//			}
//		}
//    }
//
//	virtual Future<Void> commit(bool sequential) {
//		if(getAvailableSize() <= 0) {
//			if(g_network->isSimulated()) { //FIXME: known bug in simulation we are supressing
//				int unseed = noUnseed ? 0 : g_random->randomInt(0, 100001);
//				TraceEvent(SevWarnAlways, "KeyValueStoreRadixT_OutOfSpace", id);
//				TraceEvent("ElapsedTime").detail("SimTime", now()).detail("RealTime", 0)
//					.detail("RandomUnseed", unseed);
//				flushAndExit(0);
//			}
//			TraceEvent(SevError, "KeyValueStoreRadixT_OutOfSpace", id);
//			return Never();
//		}
//
//		if(recovering.isError()) throw recovering.getError();
//		if(!recovering.isReady())
//			return waitAndCommit(this, sequential);
//
//		if(!disableSnapshot && replaceContent && !firstCommitWithSnapshot) {
//			transactionSize += SERVER_KNOBS->REPLACE_CONTENTS_BYTES;
//			committedWriteBytes += SERVER_KNOBS->REPLACE_CONTENTS_BYTES;
//			semiCommit();
//		}
//
//		if(transactionIsLarge) {
//			fullSnapshot(data);
//
//			resetSnapshot = true;
//			committedWriteBytes = notifiedCommittedWriteBytes.get();
//			overheadWriteBytes = 0;
//
//			if(disableSnapshot) {
//				return Void();
//			}
//			log_op(OpCommit, StringRef(), StringRef());
//		}
//		else {
//			int64_t bytesWritten = commit_queue(queue, !disableSnapshot, sequential);
//
//			if(disableSnapshot) {
//				return Void();
//			}
//
//			if(bytesWritten > 0 || committedWriteBytes > notifiedCommittedWriteBytes.get()) {
//				committedWriteBytes += bytesWritten + overheadWriteBytes + OP_DISK_OVERHEAD; //OP_DISK_OVERHEAD is for the following log_op(OpCommit)
//				notifiedCommittedWriteBytes.set(committedWriteBytes); //This set will cause snapshot items to be written, so it must happen before the OpCommit
//				log_op(OpCommit, StringRef(), StringRef());
//				overheadWriteBytes = log->getCommitOverhead();
//			}
//		}
//		auto c = log->commit();
//
//		committedDataSize = data.sum_to(data.end());
//		transactionSize = 0;
//		transactionIsLarge = false;
//		firstCommitWithSnapshot = false;
//
//		addActor.send( commitAndUpdateVersions( this, c, previousSnapshotEnd ) );
//		return c;
//	}
//
//	virtual Future<Optional<Value>> readValue( KeyRef key, Optional<UID> debugID = Optional<UID>() ) {
//		if(recovering.isError()) throw recovering.getError();
//		if (!recovering.isReady()) return waitAndReadValue(this, key);
//
//		auto it = data.find(key);
//		if (it == data.end()) return Optional<Value>();
//		return Optional<Value>(*it);
//	}
//
//	virtual Future<Optional<Value>> readValuePrefix( KeyRef key, int maxLength, Optional<UID> debugID = Optional<UID>() ) {
//		if(recovering.isError()) throw recovering.getError();
//		if (!recovering.isReady()) return waitAndReadValuePrefix(this, key, maxLength);
//
//		auto it = data.find(key);
//		if (it == data.end()) return Optional<Value>();
//		auto val = *it;
//		if(maxLength < val.size()) {
//			return Optional<Value>(val.substr(0, maxLength));
//		}
//		else {
//			return Optional<Value>(val);
//		}
//	}
//
//	// If rowLimit>=0, reads first rows sorted ascending, otherwise reads last rows sorted descending
//	// The total size of the returned value (less the last entry) will be less than byteLimit
//	virtual Future<Standalone<VectorRef<KeyValueRef>>> readRange( KeyRangeRef keys, int rowLimit = 1<<30, int byteLimit = 1<<30 ) {
//		if(recovering.isError()) throw recovering.getError();
//		if (!recovering.isReady()) return waitAndReadRange(this, keys, rowLimit, byteLimit);
//
//		Standalone<VectorRef<KeyValueRef>> result;
//		if (rowLimit >= 0) {
//			auto it = data.lower_bound(keys.begin);
//			auto keyStart = it.getKey(reserved_buffer, 10000);
//			while (it!=data.end() && keyStart < keys.end && rowLimit && byteLimit>=0) {
//				byteLimit -= sizeof(KeyValueRef) + keyStart.size() + (*it).size();
//				result.push_back_deep( result.arena(), KeyValueRef(keyStart, (*it) ));
//				++it;
//				--rowLimit;
//				keyStart = it.getKey(reserved_buffer, 10000);
//			}
//		} else {
//			rowLimit = -rowLimit;
//			auto it = data.previous( data.lower_bound(keys.end) );
//			auto keyStart = it.getKey(reserved_buffer, 10000);
//			while (it!=data.end() && keyStart >= keys.begin && rowLimit && byteLimit>=0) {
//				byteLimit -= sizeof(KeyValueRef) + keyStart.size() + (*it).size();
//				result.push_back_deep( result.arena(), KeyValueRef(keyStart, (*it)) );
//				it = data.previous(it);
//				--rowLimit;
//				keyStart = it.getKey(reserved_buffer, 10000);
//			}
//		}
//		return result;
//	}
//
//	virtual void resyncLog() {
//		ASSERT( recovering.isReady() );
//		resetSnapshot = true;
//		log_op(OpSnapshotAbort, StringRef(), StringRef());
//	}
//
//	virtual void enableSnapshot() {
//		disableSnapshot = false;
//	}
//
//private:
//	enum OpType {
//		OpSet,
//		OpClear,
//		OpClearToEnd,
//		OpSnapshotItem,
//		OpSnapshotEnd,
//		OpSnapshotAbort, // terminate an in progress snapshot in order to start a full snapshot
//		OpCommit,        // only in log, not in queue
//		OpRollback       // only in log, not in queue
//	};
//
//	struct OpRef {
//		OpType op;
//		StringRef p1, p2;
//		OpRef() {}
//		OpRef(Arena& a, OpRef const& o) : op(o.op), p1(a,o.p1), p2(a,o.p2) {}
//		size_t expectedSize() {
//			return p1.expectedSize() + p2.expectedSize();
//		}
//	};
//	struct OpHeader {
//		int op;
//		int len1, len2;
//	};
//
//	struct OpQueue {
//		OpQueue() : numBytes(0) { }
//
//		int totalSize() const { return numBytes; }
//
//		void clear() {
//			numBytes = 0;
//			operations = Standalone<VectorRef<OpRef>>();
//			arenas.clear();
//		}
//
//		void rollback() {
//			clear();
//		}
//
//		void set( KeyValueRef keyValue, const Arena* arena = NULL ) {
//			queue_op(OpSet, keyValue.key, keyValue.value, arena);
//		}
//
//		void clear( KeyRangeRef range, const Arena* arena = NULL ) {
//			queue_op(OpClear, range.begin, range.end, arena);
//		}
//
//		void clear_to_end( StringRef fromKey, const Arena* arena = NULL ) {
//			queue_op(OpClearToEnd, fromKey, StringRef(), arena);
//		}
//
//		void queue_op( OpType op, StringRef p1, StringRef p2, const Arena* arena ) {
//			numBytes += p1.size() + p2.size() + sizeof(OpHeader) + sizeof(OpRef);
//
//			OpRef r; r.op = op; r.p1 = p1; r.p2 = p2;
//			if(arena == NULL) {
//				operations.push_back_deep( operations.arena(), r );
//			} else {
//				operations.push_back( operations.arena(), r );
//				arenas.push_back(*arena);
//			}
//		}
//
//		const OpRef* begin() {
//			return operations.begin();
//		}
//
//		const OpRef* end() {
//			return operations.end();
//		}
//
//		private:
//			Standalone<VectorRef<OpRef>> operations;
//			uint64_t numBytes;
//			std::vector<Arena> arenas;
//	};
//
//	UID id;
//
//	radix_tree data;
//	// reserved buffer for snapshot/fullsnapshot
//	uint8_t *reserved_buffer;
//
//	OpQueue queue; // mutations not yet commit()ted
//	IDiskQueue *log;
//	Future<Void> recovering, snapshotting;
//	int64_t committedWriteBytes;
//	int64_t overheadWriteBytes;
//	NotifiedVersion notifiedCommittedWriteBytes;
//	Key recoveredSnapshotKey; // After recovery, the next key in the currently uncompleted snapshot
//	IDiskQueue::location currentSnapshotEnd; //The end of the most recently completed snapshot (this snapshot cannot be discarded)
//	IDiskQueue::location previousSnapshotEnd; //The end of the second most recently completed snapshot (on commit, this snapshot can be discarded)
//	PromiseStream<Future<Void>> addActor;
//	Future<Void> commitActors;
//
//	int64_t committedDataSize;
//	int64_t transactionSize;
//	bool transactionIsLarge;
//
//	bool resetSnapshot; //Set to true after a fullSnapshot is performed.  This causes the regular snapshot mechanism to restart
//	bool disableSnapshot;
//	bool replaceContent;
//	bool firstCommitWithSnapshot;
//	int snapshotCount;
//
//	int64_t memoryLimit; //The upper limit on the memory used by the store (excluding, possibly, some clear operations)
//
//	int64_t commit_queue(OpQueue &ops, bool log, bool sequential = false) {
//		int64_t total = 0, count = 0;
//		IDiskQueue::location log_location = 0;
//
//		// DEBUG : check when sequential equals true
//		ASSERT(!sequential);
//
//		for(auto o = ops.begin(); o != ops.end(); ++o) {
//			++count;
//			total += o->p1.size() + o->p2.size() + OP_DISK_OVERHEAD;
//			if (o->op == OpSet) {
//				data.insert(o->p1, o->p2);
//				// printf("commit_queue : set key[%s] value[%s]\n", o->p1.toString().c_str(), o->p2.toString().c_str());
//			}
//			else if (o->op == OpClear) {
//				data.erase( data.lower_bound(o->p1), data.lower_bound(o->p2) );
//			}
//			else if (o->op == OpClearToEnd) {
//				data.erase( data.lower_bound(o->p1), data.end() );
//			}
//			else ASSERT(false);
//			if ( log )
//				log_location = log_op( o->op, o->p1, o->p2 );
//		}
//
//		bool ok = count < 1e6;
//		if( !ok ) {
//			TraceEvent(/*ok ? SevInfo : */SevWarnAlways, "KVSRadixTreeCommit_queue", id)
//				.detail("Bytes", total)
//				.detail("Log", log)
//				.detail("Ops", count)
//				.detail("LastLoggedLocation", log_location)
//				.detail("Details", count);
//		}
////		printf("commit_queue end: count[%lld]\n", count);
//
//		ops.clear();
//		return total;
//	}
//
//	IDiskQueue::location log_op(OpType op, StringRef v1, StringRef v2) {
//		OpHeader h = {(int)op, v1.size(), v2.size()};
//		log->push( StringRef((const uint8_t*)&h, sizeof(h)) );
//		log->push( v1 );
//		log->push( v2 );
//		return log->push( LiteralStringRef("\x01") ); // Changes here should be reflected in OP_DISK_OVERHEAD
//	}
//
//	ACTOR static Future<Void> recover( KeyValueStoreRadixTree* self, bool exactRecovery ) {
//		// 'uncommitted' variables track something that might be rolled back by an OpRollback, and are copied into permanent variables
//		// (in self) in OpCommit.  OpRollback does the reverse (copying the permanent versions over the uncommitted versions)
//		// the uncommitted and committed variables should be equal initially (to whatever makes sense if there are no committed transactions recovered)
//		state Key uncommittedNextKey = self->recoveredSnapshotKey;
//		state IDiskQueue::location uncommittedPrevSnapshotEnd = self->previousSnapshotEnd = self->log->getNextReadLocation();  // not really, but popping up to here does nothing
//		state IDiskQueue::location uncommittedSnapshotEnd = self->currentSnapshotEnd = uncommittedPrevSnapshotEnd;
//
//		state int zeroFillSize = 0;
//		state int dbgSnapshotItemCount=0;
//		state int dbgSnapshotEndCount=0;
//		state int dbgMutationCount=0;
//		state int dbgCommitCount=0;
//		state double startt = now();
//		state UID dbgid = self->id;
//
//		state Future<Void> loggingDelay = delay(1.0);
//
//		state OpQueue recoveryQueue;
//		state OpHeader h;
//
//		TraceEvent("KVSRadixTreeRecoveryStarted", self->id)
//			.detail("SnapshotEndLocation", uncommittedSnapshotEnd);
//
//		try {
//			loop {
//				Standalone<StringRef> data = wait( self->log->readNext( sizeof(OpHeader) ) );
//				if (data.size() != sizeof(OpHeader)) {
//					if (data.size()) {
//						TEST(true);  // zero fill partial header in KeyValueStoreMemory
//						memset(&h, 0, sizeof(OpHeader));
//						memcpy(&h, data.begin(), data.size());
//						zeroFillSize = sizeof(OpHeader)-data.size() + h.len1 + h.len2 + 1;
//					}
//					TraceEvent("KVSRadixTreeRecoveryComplete", self->id)
//						.detail("Reason", "Non-header sized data read")
//						.detail("DataSize", data.size())
//						.detail("ZeroFillSize", zeroFillSize)
//						.detail("SnapshotEndLocation", uncommittedSnapshotEnd)
//						.detail("NextReadLoc", self->log->getNextReadLocation());
//					break;
//				}
//				h = *(OpHeader*)data.begin();
//				Standalone<StringRef> data = wait( self->log->readNext( h.len1 + h.len2+1 ) );
//				if (data.size() != h.len1 + h.len2 + 1) {
//					zeroFillSize = h.len1 + h.len2 + 1 - data.size();
//					TraceEvent("KVSRadixTreeRecoveryComplete", self->id)
//						.detail("Reason", "data specified by header does not exist")
//						.detail("DataSize", data.size())
//						.detail("ZeroFillSize", zeroFillSize)
//						.detail("SnapshotEndLocation", uncommittedSnapshotEnd)
//						.detail("OpCode", h.op)
//						.detail("NextReadLoc", self->log->getNextReadLocation());
//					break;
//				}
//
//				if (data[data.size()-1]) {
//					StringRef p1 = data.substr(0, h.len1);
//					StringRef p2 = data.substr(h.len1, h.len2);
//
//					if (h.op == OpSnapshotItem) { // snapshot data item
//						/*if (p1 < uncommittedNextKey) {
//							TraceEvent(SevError, "RecSnapshotBack", self->id)
//								.detail("NextKey", printable(uncommittedNextKey))
//								.detail("P1", printable(p1))
//								.detail("Nextlocation", self->log->getNextReadLocation());
//						}
//						ASSERT( p1 >= uncommittedNextKey );*/
//						if( p1 >= uncommittedNextKey )
//							recoveryQueue.clear( KeyRangeRef(uncommittedNextKey, p1), &uncommittedNextKey.arena() ); //FIXME: Not sure what this line is for, is it necessary?
//						recoveryQueue.set( KeyValueRef(p1, p2), &data.arena() );
//						uncommittedNextKey = keyAfter(p1);
//						++dbgSnapshotItemCount;
////						printf("OpSnapshotItem : set key[%s] value[%s] and uncommittedNextKey[%s]\n", p1.toString().c_str(), p2.toString().c_str(), printable(uncommittedNextKey).c_str());
//					} else if (h.op == OpSnapshotEnd || h.op == OpSnapshotAbort) { // snapshot complete
//						TraceEvent("RecSnapshotEnd", self->id)
//							.detail("NextKey", printable(uncommittedNextKey))
//							.detail("Nextlocation", self->log->getNextReadLocation())
//							.detail("IsSnapshotEnd", h.op == OpSnapshotEnd);
//
//						if(h.op == OpSnapshotEnd) {
//							uncommittedPrevSnapshotEnd = uncommittedSnapshotEnd;
//							uncommittedSnapshotEnd = self->log->getNextReadLocation();
//							recoveryQueue.clear_to_end( uncommittedNextKey, &uncommittedNextKey.arena() );
//						}
//
//						uncommittedNextKey = Key();
//						++dbgSnapshotEndCount;
//					} else if (h.op == OpSet) { // set mutation
//						recoveryQueue.set( KeyValueRef(p1,p2), &data.arena() );
//						++dbgMutationCount;
////						printf("OpSet : set key[%s] value[%s] and dbgMutationCount[%d]\n", p1.toString().c_str(), p2.toString().c_str(), dbgMutationCount);
//					} else if (h.op == OpClear) { // clear mutation
//						recoveryQueue.clear( KeyRangeRef(p1,p2), &data.arena() );
//						++dbgMutationCount;
////						printf("OpClear\n");
//					} else if (h.op == OpClearToEnd) { //clear all data from begin key to end
//						recoveryQueue.clear_to_end( p1, &data.arena() );
////						printf("OpClearToEnd[%s]\n", p1.toString().c_str());
//					} else if (h.op == OpCommit) { // commit previous transaction
//						self->commit_queue(recoveryQueue, false);
//						++dbgCommitCount;
//						self->recoveredSnapshotKey = uncommittedNextKey;
//						self->previousSnapshotEnd = uncommittedPrevSnapshotEnd;
//						self->currentSnapshotEnd = uncommittedSnapshotEnd;
//					} else if (h.op == OpRollback) { // rollback previous transaction
//						recoveryQueue.rollback();
//						TraceEvent("KVSRadixTreeRecSnapshotRollback", self->id)
//							.detail("NextKey", printable(uncommittedNextKey));
//						uncommittedNextKey = self->recoveredSnapshotKey;
//						uncommittedPrevSnapshotEnd = self->previousSnapshotEnd;
//						uncommittedSnapshotEnd = self->currentSnapshotEnd;
//					} else
//						ASSERT(false);
//				} else {
//					TraceEvent("KVSRadixTreeRecoverySkippedZeroFill", self->id)
//						.detail("PayloadSize", data.size())
//						.detail("ExpectedSize", h.len1 + h.len2 + 1)
//						.detail("OpCode", h.op)
//						.detail("EndsAt", self->log->getNextReadLocation());
//				}
//
//				if (loggingDelay.isReady()) {
//					TraceEvent("KVSRadixTreeRecoveryLogSnap", self->id)
//						.detail("SnapshotItems", dbgSnapshotItemCount)
//						.detail("SnapshotEnd", dbgSnapshotEndCount)
//						.detail("Mutations", dbgMutationCount)
//						.detail("Commits", dbgCommitCount)
//						.detail("EndsAt", self->log->getNextReadLocation());
//					loggingDelay = delay(1.0);
//				}
//
//				Void _ = wait( yield() );
//			}
//
//			if (zeroFillSize) {
//				if( exactRecovery ) {
//					TraceEvent(SevError, "KVSRadixTreeExpectedExact", self->id);
//					ASSERT(false);
//				}
//
//				TEST( true );  // Fixing a partial commit at the end of the KeyValueStoreMemory log
//				for(int i=0; i<zeroFillSize; i++)
//					self->log->push( StringRef((const uint8_t*)"",1) );
//			}
//			//self->rollback(); not needed, since we are about to discard anything left in the recoveryQueue
//			//TraceEvent("KVSMemRecRollback", self->id).detail("QueueEmpty", data.size() == 0);
//			// make sure that before any new operations are added to the log that all uncommitted operations are "rolled back"
//			self->log_op( OpRollback, StringRef(), StringRef() );  // rollback previous transaction
//
//			self->committedDataSize = self->data.sum_to(self->data.end());
//
//			TraceEvent("KVSRadixTreeRecovered", self->id)
//				.detail("SnapshotItems", dbgSnapshotItemCount)
//				.detail("SnapshotEnd", dbgSnapshotEndCount)
//				.detail("Mutations", dbgMutationCount)
//				.detail("Commits", dbgCommitCount)
//				.detail("TimeTaken", now()-startt);
//
//			self->semiCommit();
//			return Void();
//		} catch( Error &e ) {
//			bool ok = e.code() == error_code_operation_cancelled || e.code() == error_code_file_not_found;
//			TraceEvent(ok ? SevInfo : SevError, "ErrorDuringRecovery", dbgid).error(e, true);
//			throw e;
//		}
//	}
//
//	//Snapshots an entire data set
//	void fullSnapshot(radix_tree& snapshotData) {
//		previousSnapshotEnd = log_op(OpSnapshotAbort, StringRef(), StringRef());
//		replaceContent = false;
//
//		//Clear everything since we are about to write the whole database
//		log_op(OpClearToEnd, allKeys.begin, StringRef());
//
//		int count = 0;
//		int64_t snapshotSize = 0;
//		for(auto kv = snapshotData.begin(); kv != snapshotData.end(); ++kv) {
//			auto key = kv.getKey(reserved_buffer, 10000);
//			log_op(OpSnapshotItem, key, *kv);
//			snapshotSize += key.size() + (*kv).size() + OP_DISK_OVERHEAD;
//			++count;
//		}
//
//		TraceEvent("FullSnapshotEnd", id)
//			.detail("PreviousSnapshotEndLoc", previousSnapshotEnd)
//			.detail("SnapshotSize", snapshotSize)
//			.detail("SnapshotElements", count);
//
//		currentSnapshotEnd = log_op(OpSnapshotEnd, StringRef(), StringRef());
//	}
//
//	ACTOR static Future<Void> snapshot( KeyValueStoreRadixTree* self ) {
//		Void _ = wait(self->recovering);
//
//		state Key nextKey = self->recoveredSnapshotKey;
//		state bool nextKeyAfter = false; //setting this to true is equilvent to setting nextKey = keyAfter(nextKey)
//		state uint64_t snapshotTotalWrittenBytes = 0;
//		state int lastDiff = 0;
//		state int snapItems = 0;
//		state uint64_t snapshotBytes = 0;
//
//		TraceEvent("KVSRadixTreeStartingSnapshot", self->id).detail("StartKey", printable(nextKey));
//
//		loop {
//			Void _ = wait( self->notifiedCommittedWriteBytes.whenAtLeast( snapshotTotalWrittenBytes + 1 ) );
//
//			if(self->resetSnapshot) {
//				nextKey = Key();
//				nextKeyAfter = false;
//				snapItems = 0;
//				snapshotBytes = 0;
//				self->resetSnapshot = false;
//			}
//
//			auto next = nextKeyAfter ? self->data.upper_bound(nextKey) : self->data.lower_bound(nextKey);
//			int diff = self->notifiedCommittedWriteBytes.get() - snapshotTotalWrittenBytes;
//			if( diff > lastDiff && diff > 5e7 )
//				TraceEvent(SevWarnAlways, "ManyWritesAtOnce", self->id)
//					.detail("CommittedWrites", self->notifiedCommittedWriteBytes.get())
//					.detail("SnapshotWrites", snapshotTotalWrittenBytes)
//					.detail("Diff", diff)
//					.detail("LastOperationWasASnapshot", nextKey == Key() && !nextKeyAfter);
//			lastDiff = diff;
//
//			if (next == self->data.end()) {
//				auto thisSnapshotEnd = self->log_op( OpSnapshotEnd, StringRef(), StringRef() );
//				TraceEvent("SnapshotEnd", self->id)
//					.detail("CurrentSnapshotEndLoc", self->currentSnapshotEnd)
//					.detail("PreviousSnapshotEndLoc", self->previousSnapshotEnd)
//					.detail("ThisSnapshotEnd", thisSnapshotEnd)
//					.detail("Items", snapItems)
//					.detail("CommittedWrites", self->notifiedCommittedWriteBytes.get())
//					.detail("SnapshotSize", snapshotBytes);
//
//				ASSERT(thisSnapshotEnd >= self->currentSnapshotEnd);
//				self->previousSnapshotEnd = self->currentSnapshotEnd;
//				self->currentSnapshotEnd = thisSnapshotEnd;
//
//				if(++self->snapshotCount == 2) {
//					self->replaceContent = false;
//				}
//				nextKey = Key();
//				nextKeyAfter = false;
//				snapItems = 0;
//
//				snapshotBytes = 0;
//
//				snapshotTotalWrittenBytes += OP_DISK_OVERHEAD;
//			} else {
//				// TODO: temp arena, hopefully will outof scope
//				state KeyRef key = next.getKey(self->reserved_buffer, 10000);
//				self->log_op( OpSnapshotItem, key, (*next));
//				nextKey = key;
//				nextKeyAfter = true;
//				snapItems++;
//				uint64_t opBytes = key.size() + (*next).size() + OP_DISK_OVERHEAD;
//				snapshotBytes += opBytes;
//				snapshotTotalWrittenBytes += opBytes;
//			}
//		}
//
//	}
//
//	ACTOR static Future<Optional<Value>> waitAndReadValue( KeyValueStoreRadixTree* self, Key key ) {
//		Void _ = wait( self->recovering );
//		return self->readValue(key).get();
//	}
//	ACTOR static Future<Optional<Value>> waitAndReadValuePrefix( KeyValueStoreRadixTree* self, Key key, int maxLength) {
//		Void _ = wait( self->recovering );
//		return self->readValuePrefix(key, maxLength).get();
//	}
//	ACTOR static Future<Standalone<VectorRef<KeyValueRef>>> waitAndReadRange( KeyValueStoreRadixTree* self, KeyRange keys, int rowLimit, int byteLimit ) {
//		Void _ = wait( self->recovering );
//		return self->readRange(keys, rowLimit, byteLimit).get();
//	}
//	ACTOR static Future<Void> waitAndCommit(KeyValueStoreRadixTree* self, bool sequential) {
//		Void _ = wait(self->recovering);
//		Void _ = wait(self->commit(sequential));
//		return Void();
//	}
//	ACTOR static Future<Void> commitAndUpdateVersions( KeyValueStoreRadixTree* self, Future<Void> commit, IDiskQueue::location location ) {
//		Void _ = wait( commit );
//		self->log->pop(location);
//		return Void();
//	}
//};
//
//KeyValueStoreRadixTree::KeyValueStoreRadixTree( IDiskQueue* log, UID id, int64_t memoryLimit, bool disableSnapshot, bool replaceContent, bool exactRecovery )
//	: log(log), id(id), previousSnapshotEnd(-1), currentSnapshotEnd(-1), resetSnapshot(false), memoryLimit(memoryLimit), committedWriteBytes(0), overheadWriteBytes(0),
//	  committedDataSize(0), transactionSize(0), transactionIsLarge(false), disableSnapshot(disableSnapshot), replaceContent(replaceContent), snapshotCount(0), firstCommitWithSnapshot(true)
//{
//	// create reserved buffer
//	this->reserved_buffer = new uint8_t[10000];
//	recovering = recover( this, exactRecovery );
//	snapshotting = snapshot( this );
//	commitActors = actorCollection( addActor.getFuture() );
//}
//
//IKeyValueStore* keyValueStoreRadixTree( std::string const& basename, UID logID, int64_t memoryLimit, std::string ext ) {
//	TraceEvent("KVSRadixTreeOpening", logID).detail("Basename", basename).detail("MemoryLimit", memoryLimit);
//	IDiskQueue *log = openDiskQueue( basename, ext, logID );
//	return new KeyValueStoreRadixTree( log, logID, memoryLimit, false, false, false );
//}
//
//
