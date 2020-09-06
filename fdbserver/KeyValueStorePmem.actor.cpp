/*
 * KeyValueStorePmem.actor.cpp
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2018 Apple Inc. and the FoundationDB project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fdbserver/IKeyValueStore.h"
#include "fdbserver/IDiskQueue.h"
#include "flow/PmemVector.h"
#include "flow/ActorCollection.h"
#include "fdbclient/Notified.h"
#include "fdbclient/SystemData.h"
#include "fdbrpc/simulator.h"
#include "flow/actorcompiler.h"  // This must be the last #include.

#define OP_DISK_OVERHEAD (sizeof(OpHeader) + 1)

inline bool operator<(const pmem::internal::string_t& lhs, const StringRef& rhs) {
    if (std::min((int)lhs.size(), rhs.size()) > 0) {
        int c = memcmp(lhs.data(), rhs.begin(), std::min((int)lhs.size(), rhs.size()));
        if (c != 0) return c < 0;
    }
    return lhs.size() < rhs.size();
}

inline bool operator >= ( const pmem::internal::string_t& lhs, const StringRef& rhs ) { return !(lhs<rhs); }

class KeyValueStorePmem : public IKeyValueStore, NonCopyable {
public:
	explicit KeyValueStorePmem(std::string const& basename, UID id, int64_t sizeLimit, std::string ext);
	~KeyValueStorePmem() = default;
	// IClosable
	virtual Future<Void> getError() { return delayed( log->getError() || error.getFuture() ); }
	virtual Future<Void> onClosed() { return log->onClosed(); }
	virtual void dispose() {
        doClose(this, true);
	}
	virtual void close() {
        doClose(this, false);
	}
    // IKeyValueStore
	virtual Future<Void> init() {
        return recovering;
	}

	virtual KeyValueStoreType getType() { return KeyValueStoreType::PMEM; }

	int64_t getAvailableSize() {
		int64_t residentSize = data.getAllocatedBytes();
		return sizeLimit - residentSize;
	}

	virtual StorageBytes getStorageBytes() {
		ASSERT(recovering.isReady());

		StorageBytes diskQueueBytes = log->getStorageBytes();
		// Try to bound how many in-memory bytes we might need to write to disk if we commit() now
		int64_t uncommittedBytes = transactionSize + queue.totalSize();
		// Check that we have enough space in memory and on disk
		int64_t freeSize = std::min(getAvailableSize(), diskQueueBytes.free / 4 - uncommittedBytes);
		int64_t availableSize = std::min(getAvailableSize(), diskQueueBytes.available / 4 - uncommittedBytes);
		int64_t totalSize = std::min(sizeLimit, diskQueueBytes.total / 4 - uncommittedBytes);

		return StorageBytes(std::max((int64_t)0, freeSize), std::max((int64_t)0, totalSize), diskQueueBytes.used,
		                    std::max((int64_t)0, availableSize));
	}

	virtual void set(KeyValueRef keyValue, const Arena* arena) {
		queue.set(keyValue, arena);
	}

	virtual void clear(KeyRangeRef range, const Arena* arena) { queue.clear(range, arena); }

	virtual Future<Optional<Value>> readValue( KeyRef key, Optional<UID> debugID = Optional<UID>() ) {
        return readValueImpl(this, key, debugID);
	}

    ACTOR static Future<Optional<Value>> readValueImpl(KeyValueStorePmem* self, Key key, Optional<UID> debugID = Optional<UID>()) {
        if (!self->checkpointing.isReady()) {
			wait(self->checkpointing);
		}

        auto it = self->data.find(key);
        if (it == self->data.end()) return Optional<Value>();

        StringRef val((uint8_t *)(it->value().data()), it->value().size());
        return Optional<Value>(val);
    }

	virtual Future<Optional<Value>> readValuePrefix( KeyRef key, int maxLength, Optional<UID> debugID = Optional<UID>() ) {
		return readValuePrefixImpl(this, key, maxLength, debugID);
	}

    ACTOR static Future<Optional<Value>> readValuePrefixImpl(KeyValueStorePmem* self, Key key, int maxLength, Optional<UID> debugID = Optional<UID>()) {
        if (!self->checkpointing.isReady())
            wait(self->checkpointing);

        auto it = self->data.find(key);
        if (it == self->data.end()) return Optional<Value>();

        StringRef val((uint8_t *)(it->value().data()), it->value().size());
        if(maxLength < val.size()) {
            return Optional<Value>(val.substr(0, maxLength));
        }
        else {
            return Optional<Value>(val);
        }
    }

	// If rowLimit>=0, reads first rows sorted ascending, otherwise reads last rows sorted descending
	// The total size of the returned value (less the last entry) will be less than byteLimit
	virtual Future<Standalone<RangeResultRef>> readRange( KeyRangeRef keys, int rowLimit = 1<<30, int byteLimit = 1<<30 ) {
        return readRangeImpl(this, keys, rowLimit, byteLimit);
	}

	ACTOR static Future<Standalone<RangeResultRef>> readRangeImpl(KeyValueStorePmem* self, KeyRange keys, int rowLimit,
	                                                              int byteLimit) {
		if (!self->checkpointing.isReady()) wait(self->checkpointing);

		Standalone<RangeResultRef> result;
		if (rowLimit == 0) {
			return result;
		}

		if (rowLimit > 0) {
			auto it = self->data.lower_bound(keys.begin);
			while (it != self->data.end() && it->key() < keys.end && rowLimit && byteLimit > 0) {
				StringRef key((uint8_t *)(it->key().data()), it->key().size());
                StringRef value((uint8_t *)(it->value().data()), it->value().size());

				byteLimit -= sizeof(KeyValueRef) + key.size() + value.size();
				result.push_back_deep(result.arena(), KeyValueRef(key, value));
				++it;
				--rowLimit;
			}
		} else {
			rowLimit = -rowLimit;
			auto it = self->data.lower_bound(keys.end);
			--it; // exclusive on the end
			while (it != self->data.end() && it->key() >= keys.begin && rowLimit && byteLimit > 0) {
                StringRef key((uint8_t *)(it->key().data()), it->key().size());
                StringRef value((uint8_t *)(it->value().data()), it->value().size());

				byteLimit -= sizeof(KeyValueRef) + key.size() + value.size();
				result.push_back_deep(result.arena(), KeyValueRef(key, value));
				--it;
				--rowLimit;
			}
		}

		result.more = rowLimit == 0 || byteLimit <= 0;
		if (result.more) {
			ASSERT(result.size() > 0);
			result.readThrough = result[result.size() - 1].key;
		}
		return result;
	}

	virtual Future<Void> commit(bool sequential) {
		if (getAvailableSize() <= 0) {
			TraceEvent(SevError, "KeyValueStoreMemory_OutOfSpace", id);
			return Never();
		}

		if (!checkpointing.isReady()) return waitAndCommit(this, sequential);

		for(auto o = queue.begin(); o != queue.end(); o++){
			log_op(o->op, o->p1, o->p2);
		}
		log_op(OpCommit, StringRef(), StringRef());
		auto c = log->commit();

        transactionSize = queue.totalSize();
        checkpointing = fullCheckpoint( this, c ) ;
        return c;
	}

private:
    enum OpType {
        OpSet,
        OpClear,
        OpClearToEnd,
        OpSnapshotEnd,
        OpSnapshotAbort, // terminate an in progress snapshot in order to start a full snapshot
        OpCommit,        // only in log, not in queue
        OpRollback       // only in log, not in queue
    };

    struct OpRef {
        OpType op;
        StringRef p1, p2;
        OpRef() {}
        OpRef(Arena& a, OpRef const& o) : op(o.op), p1(a,o.p1), p2(a,o.p2) {}
        size_t expectedSize() {
            return p1.expectedSize() + p2.expectedSize();
        }
    };
    struct OpHeader {
        int op;
        int len1, len2;
    };

    struct OpQueue {
        OpQueue() : numBytes(0) { }
        // deep copy constructor
		OpQueue(const OpQueue& other) : operations(other.operations.contents()), numBytes(other.numBytes) {
			for (auto it = other.arenas.begin(); it != other.arenas.end(); it++) arenas.emplace_back(*it);
		}

		int totalSize() const { return numBytes; }

		int size() const {return operations.size();}

        void clear() {
            numBytes = 0;
            operations = Standalone<VectorRef<OpRef>>();
            arenas.clear();
        }

        void rollback() {
            clear();
        }

        void set( KeyValueRef keyValue, const Arena* arena = NULL ) {
            queue_op(OpSet, keyValue.key, keyValue.value, arena);
        }

        void clear( KeyRangeRef range, const Arena* arena = NULL ) {
            queue_op(OpClear, range.begin, range.end, arena);
        }

        void clear_to_end( StringRef fromKey, const Arena* arena = NULL ) {
            queue_op(OpClearToEnd, fromKey, StringRef(), arena);
        }

        void queue_op( OpType op, StringRef p1, StringRef p2, const Arena* arena ) {
            numBytes += p1.size() + p2.size() + sizeof(OpHeader) + sizeof(OpRef);

            OpRef r; r.op = op; r.p1 = p1; r.p2 = p2;
            if(arena == NULL) {
                operations.push_back_deep( operations.arena(), r );
            } else {
                operations.push_back( operations.arena(), r );
                arenas.push_back(*arena);
            }
        }

        const OpRef* begin() {
            return operations.begin();
        }

        const OpRef* end() {
            return operations.end();
        }

        Standalone<VectorRef<OpRef>> operations;
        uint64_t numBytes;
        std::vector<Arena> arenas;
    };

    UID id;
    pmem::PmemVector data;
	std::string filename;
    int64_t sizeLimit; //The upper limit on the pmem used by the store (excluding, possibly, some clear operations)
    int64_t transactionSize;

	IDiskQueue *log;
    OpQueue queue; // mutations not yet commit()ted
	Future<Void> recovering;
	Future<Void> checkpointing;
	Promise<Void> error;

	Key recoveredSnapshotKey; // After recovery, the next key in the currently uncompleted snapshot
	IDiskQueue::location currentCheckpointEnd; //The end of the most recently completed checkpoint (this checkpoint can be discarded)
	IDiskQueue::location previousCheckpointEnd; //The end of the second most recently completed checkpoint (on commit, this checkpoint cannot be discarded)

	// private method to write operations into wal log
    IDiskQueue::location log_op(OpType op, StringRef v1, StringRef v2) {
		OpHeader h = { (int)op, v1.size(), v2.size() };
		log->push(StringRef((const uint8_t*)&h, sizeof(h)));
		log->push(v1);
		log->push(v2);
		return log->push(LiteralStringRef("\x01")); // Changes here should be reflected in OP_DISK_OVERHEAD
	}

	// private method to transfer all the mutations that are appended in the WAL file back into the pmem storage engine
    int64_t commit_queue(OpQueue &ops, bool log=false) {
        int64_t total = 0, count = 0;
        IDiskQueue::location log_location = 0;

        for(auto o = ops.begin(); o != ops.end(); ++o) {
            ++count;
            total += o->p1.size() + o->p2.size() + OP_DISK_OVERHEAD;
            if (o->op == OpSet) {
				data.insert(o->p1, o->p2);
            }
            else if (o->op == OpClear) {
                data.erase(o->p1, o->p2);
            }
            else ASSERT(false);
            if ( log )
                log_location = log_op( o->op, o->p1, o->p2 );
        }

        bool ok = count < 1e6;
        if( !ok ) {
            TraceEvent(/*ok ? SevInfo : */SevWarnAlways, "KVSPmemCommitQueue", id)
                .detail("Bytes", total)
                .detail("Log", log)
                .detail("Ops", count)
                .detail("LastLoggedLocation", log_location)
                .detail("Details", count);
        }
		ops.clear();
        std::cout << "commit queue "<< count << std::endl;
        return total;
    }

    ACTOR static Future<Void> fullCheckpoint( KeyValueStorePmem* self, Future<Void> commit ) {
		try {
			// deep copy whatever inside operation queue to a temp queue
			state OpQueue tempQueue(self->queue);
			self->queue.clear();
			wait(commit);

			self->commit_queue(tempQueue);
			auto thisCheckpointEnd = self->log_op(OpSnapshotEnd, StringRef(), StringRef());

			ASSERT(thisCheckpointEnd >= self->currentCheckpointEnd);
			self->previousCheckpointEnd = self->currentCheckpointEnd;
			self->currentCheckpointEnd = thisCheckpointEnd;
			self->log->pop(self->previousCheckpointEnd);
			self->transactionSize = 0;
			std::cout << "commit is done, in pmem storage engine " << self->data.size() << std::endl;
			return Void();
		} catch (Error& e) {
			if (e.code() != error_code_actor_cancelled && self->error.canBeSet()) {
				self->error.sendError(e);
			}
			throw e;
		}
    }

	ACTOR static Future<Void> recover( KeyValueStorePmem* self, bool exactRecovery ) {
        ASSERT(!self->recovering.isValid());
        loop {
            // 'uncommitted' variables track something that might be rolled back by an OpRollback, and are copied into permanent variables
            // (in self) in OpCommit.  OpRollback does the reverse (copying the permanent versions over the uncommitted versions)
            // the uncommitted and committed variables should be equal initially (to whatever makes sense if there are no committed transactions recovered)
            state Key uncommittedNextKey = self->recoveredSnapshotKey;
            state IDiskQueue::location uncommittedPrevSnapshotEnd = self->previousCheckpointEnd = self->log->getNextReadLocation();  // not really, but popping up to here does nothing
            state IDiskQueue::location uncommittedSnapshotEnd = self->currentCheckpointEnd = uncommittedPrevSnapshotEnd;

            state int zeroFillSize = 0;
            state int dbgSnapshotEndCount=0;
            state int dbgMutationCount=0;
            state int dbgCommitCount=0;
            state double startt = now();
            state UID dbgid = self->id;

            state Future<Void> loggingDelay = delay(1.0);

            state OpQueue recoveryQueue;
            state OpHeader h;

            TraceEvent("KVSPmemRecoveryStarted", self->id)
                .detail("SnapshotEndLocation", uncommittedSnapshotEnd);

            try {
                // initialized pmem container first
                bool forceCreate = !fileExists(self->filename);
				self->data.init(self->filename, self->sizeLimit, forceCreate);
                // recover from wal log
                loop {
                    {
                        Standalone<StringRef> data = wait( self->log->readNext( sizeof(OpHeader) ) );
                        if (data.size() != sizeof(OpHeader)) {
                            if (data.size()) {
                                TEST(true);  // zero fill partial header
                                memset(&h, 0, sizeof(OpHeader));
                                memcpy(&h, data.begin(), data.size());
                                zeroFillSize = sizeof(OpHeader)-data.size() + h.len1 + h.len2 + 1;
                            }
                            TraceEvent("KVSPmemRecoveryComplete", self->id)
                                .detail("Reason", "Non-header sized data read")
                                .detail("LogEntrySize", data.size())
                                .detail("ZeroFillSize", zeroFillSize)
                                .detail("SnapshotEndLocation", uncommittedSnapshotEnd)
                                .detail("NextReadLoc", self->log->getNextReadLocation());
                            break;
                        }
                        h = *(OpHeader*)data.begin();
                    }
                    Standalone<StringRef> data = wait( self->log->readNext( h.len1 + h.len2+1 ) );
                    if (data.size() != h.len1 + h.len2 + 1) {
                        zeroFillSize = h.len1 + h.len2 + 1 - data.size();
                        TraceEvent("KVSPmemRecoveryComplete", self->id)
                            .detail("Reason", "data specified by header does not exist")
                            .detail("LogEntrySize", data.size())
                            .detail("ZeroFillSize", zeroFillSize)
                            .detail("SnapshotEndLocation", uncommittedSnapshotEnd)
                            .detail("OpCode", h.op)
                            .detail("NextReadLoc", self->log->getNextReadLocation());
                        break;
                    }

                    if (data[data.size()-1]) {
                        StringRef p1 = data.substr(0, h.len1);
                        StringRef p2 = data.substr(h.len1, h.len2);

                        if (h.op == OpSnapshotEnd) { // snapshot complete
                            TraceEvent("RecSnapshotEnd", self->id)
                                .detail("Nextlocation", self->log->getNextReadLocation())
                                .detail("IsSnapshotEnd", h.op == OpSnapshotEnd);

                            uncommittedPrevSnapshotEnd = uncommittedSnapshotEnd;
                            uncommittedSnapshotEnd = self->log->getNextReadLocation();
                            ++dbgSnapshotEndCount;
                        } else if (h.op == OpSet) { // set mutation
                            recoveryQueue.set( KeyValueRef(p1,p2), &data.arena() );
                            ++dbgMutationCount;
                        } else if (h.op == OpClear) { // clear mutation
                            recoveryQueue.clear( KeyRangeRef(p1,p2), &data.arena() );
                            ++dbgMutationCount;
                        } else if (h.op == OpCommit) { // commit previous transaction
                            self->commit_queue(recoveryQueue);
                            ++dbgCommitCount;
                            self->previousCheckpointEnd = uncommittedPrevSnapshotEnd;
                            self->currentCheckpointEnd = uncommittedSnapshotEnd;
                        } else if (h.op == OpRollback) { // rollback previous transaction
                            recoveryQueue.rollback();
                            uncommittedPrevSnapshotEnd = self->previousCheckpointEnd;
                            uncommittedSnapshotEnd = self->currentCheckpointEnd;
                        } else
                            ASSERT(false);
                    } else {
                        TraceEvent("KVSPmemRecoverySkippedZeroFill", self->id)
                            .detail("PayloadSize", data.size())
                            .detail("ExpectedSize", h.len1 + h.len2 + 1)
                            .detail("OpCode", h.op)
                            .detail("EndsAt", self->log->getNextReadLocation());
                    }

                    if (loggingDelay.isReady()) {
                        TraceEvent("KVSPmemRecoveryLogSnap", self->id)
                            .detail("SnapshotEnd", dbgSnapshotEndCount)
                            .detail("Mutations", dbgMutationCount)
                            .detail("Commits", dbgCommitCount)
                            .detail("EndsAt", self->log->getNextReadLocation());
                        loggingDelay = delay(1.0);
                    }
				}

                if (zeroFillSize) {
                    if( exactRecovery ) {
                        TraceEvent(SevError, "KVSMemExpectedExact", self->id);
                        ASSERT(false);
                    }

                    TEST( true );  // Fixing a partial commit at the end of the KeyValueStoreMemory log
                    for(int i=0; i<zeroFillSize; i++)
                        self->log->push( StringRef((const uint8_t*)"",1) );
                }
                TraceEvent("KVSPmemRecovered", self->id)
                    .detail("SnapshotEnd", dbgSnapshotEndCount)
                    .detail("Mutations", dbgMutationCount)
                    .detail("Commits", dbgCommitCount)
                    .detail("TimeTaken", now()-startt)
				    .detail("KVStoreSize", self->data.size());

				std::cout << "recover is over " << self->data.size() << std::endl;
                return Void();
            } catch( Error &e ) {
                bool ok = e.code() == error_code_operation_cancelled || e.code() == error_code_file_not_found || e.code() == error_code_disk_adapter_reset;
                TraceEvent(ok ? SevInfo : SevError, "ErrorDuringRecovery", dbgid).error(e, true);
                if(e.code() != error_code_disk_adapter_reset) {
                    throw e;
                }
				// TODO: clear data container
                // self->data.clear();
            }
        }
	}

    ACTOR static void doClose( KeyValueStorePmem* self, bool deleteOnClose ) {
        state Error error = success();
        try {
            TraceEvent("KVClose", self->id).detail("Del", deleteOnClose).detail("Filename", self->filename);
			self->checkpointing.cancel();
			self->recovering.cancel();
            if (deleteOnClose) {
                wait( IAsyncFileSystem::filesystem()->incrementalDeleteFile( self->filename, true ) );
                self->log->dispose();
            } else {
				self->data.close();
                self->log->close();
			}
        } catch (Error& e) {
            TraceEvent(SevError, "KVDoCloseError", self->id)
                .error(e, true)
                .detail("Reason", e.code() == error_code_platform_error ? "could not delete database" : "unknown");
            error = e;
        }

        TraceEvent("KVClosed", self->id);
        if( error.code() != error_code_actor_cancelled ) {
            delete self;
        }
    }

    ACTOR static Future<Void> waitAndCommit(KeyValueStorePmem* self, bool sequential) {
		wait(self->checkpointing);
		wait(self->commit(sequential));
		return Void();
	}
};

KeyValueStorePmem::KeyValueStorePmem(std::string const& basename, UID id, int64_t sizeLimit, std::string ext)
  : id(id), previousCheckpointEnd(-1), currentCheckpointEnd(-1), sizeLimit(sizeLimit), transactionSize(0),
    checkpointing(Void()) {
	this->log = openDiskQueue(basename + "-", "wal", id, DiskQueueVersion::V1);
	this->filename = abspath(basename + "." + ext);
	this->recovering = recover(this, false);
}

IKeyValueStore* keyValueStorePmem(std::string const& basename, UID logID, int64_t sizeLimit, std::string ext) {
	TraceEvent("KVSPmemOpening", logID).detail("Basename", basename).detail("FileExtension", ext).detail("SizeLimit", sizeLimit);
	return new KeyValueStorePmem(basename, logID, sizeLimit, ext);
}
