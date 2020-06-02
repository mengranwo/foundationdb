/*
 * PmemVector.h
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2020 Apple Inc. and the FoundationDB project authors
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

#ifndef FLOW_PMEMVECTOR_H
#define FLOW_PMEMVECTOR_H
#pragma once

#include <iostream>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <typeinfo>

#include <libpmemobj++/pool.hpp>
#include <libpmemobj++/container/basic_string.hpp>
#include <libpmemobj++/experimental/radix_tree.hpp>
#include <libpmemobj++/persistent_ptr.hpp>
#include <libpmemobj++/transaction.hpp>

namespace pmem {
    namespace internal {
        using string_t = pmem::obj::experimental::inline_string;
        using kv_type_t = pmem::obj::experimental::radix_tree<string_t, string_t>;

        struct kv_container {
            /**
             * Keys and values are stored inside the radix tree container.
             */
            kv_type_t store;
        };
    } // namespace internal

    const std::string LAYOUT = "pmemkv";

    template <typename EngineData>
    class IPmemStore {
	public:
        IPmemStore() {
        }

        virtual ~IPmemStore() = default;

	    virtual void init(const std::string path, int64_t size, bool forceCreate) {
		    if (path.empty() || size == 0) {
			    throw std::runtime_error("Invalid path or size configuration");
		    } else {
			    pmem::obj::pool<Root> pop;
			    if (forceCreate) {
				    pop = pmem::obj::pool<Root>::create(path, LAYOUT, size, S_IRWXU);
			    } else {
				    pop = pmem::obj::pool<Root>::open(path, LAYOUT);
			    }

			    root_oid = pop.root()->ptr.raw_ptr();
			    pmpool = pop;
		    }
	    }

	    virtual inline size_t getAllocatedBytes() {
		    size_t result = 0;
		    pmemobj_ctl_get(pmpool.handle(), "stats.heap.run_allocated", &result);

		    return result;
	    }

	    virtual std::string getName() const = 0; // return underlying engine type
	    virtual int size() = 0;
        // TODO: come up with more public interfaces and inherit ICloseable?
	protected:
        struct Root {
            pmem::obj::persistent_ptr<EngineData> ptr; /* used when path is specified */
        };

        pmem::obj::pool_base pmpool;
        PMEMoid *root_oid;
    };

    class PmemVector : public IPmemStore<internal::kv_container> {
	public:
        using iterator = pmem::obj::experimental::radix_tree<internal::string_t, internal::string_t>::iterator;

        PmemVector() : IPmemStore(), container(nullptr) {
	    }
        ~PmemVector() = default;

        PmemVector(const PmemVector &) = delete;
        PmemVector &operator=(const PmemVector &) = delete;

	    void init(const std::string path, int64_t size, bool forceCreate);

	    inline void close() {
            pmpool.close();
	    }

        std::string getName() const {
            return "svector";
        }
        // lookups
        iterator find(const StringRef& key);
        iterator lower_bound(const StringRef& key);
        iterator upper_bound(const StringRef& key);
        // modifications
        std::pair<iterator, bool> insert(const StringRef& key, const StringRef& valuev, bool replaceExisting = true);
        void erase(const StringRef& begin, const StringRef& end);
	    // metadata
        int size() final; // total number of kv pairs
	    iterator begin();
	    iterator end();
	private:
        void recover();
        static pmem::obj::string_view convert(const StringRef &target) {
		    return {(char *)(target.begin()), (size_t)target.size()};
	    }
	    // member variable
        internal::kv_container *container;
    };

    // Helper method which throws an exception when called in a tx
    static inline void check_outside_tx() {
        if (pmemobj_tx_stage() != TX_STAGE_NONE)
            throw transaction_scope_error("Function called inside transaction scope.");
    }

    void PmemVector::init(const std::string path, int64_t size, bool forceCreate) {
	    try {
		    IPmemStore::init(path, size, forceCreate);
		    recover();
	    } catch (std::runtime_error& e) {
	        std::cout << e.what() << std::endl;
		    throw internal_error();
	    }
    }

    int PmemVector::size() {
        check_outside_tx();
	    return container->store.size();
    }

    PmemVector::iterator PmemVector::begin() {
	    return container->store.begin();
    }

    PmemVector::iterator PmemVector::end() {
	    return container->store.end();
    }

    PmemVector::iterator PmemVector::find(const StringRef &key) {
        check_outside_tx();
	    return container->store.find(convert(key));
    }

    PmemVector::iterator PmemVector::lower_bound(const StringRef &key) {
        check_outside_tx();
	    return container->store.lower_bound(convert(key));
    }

    PmemVector::iterator PmemVector::upper_bound(const StringRef &key) {
	    check_outside_tx();
	    return container->store.upper_bound(convert(key));
    }

    std::pair<PmemVector::iterator, bool> PmemVector::insert(const StringRef& key, const StringRef& value, bool replaceExisting) {
	    try {
		    check_outside_tx();
            std::pair<PmemVector::iterator, bool> result;

		    pmem::obj::transaction::run(pmpool, [&] {
			    auto it = container->store.find(convert(key));
                bool replaced = false;
			    if (it != end()) {
                    if (replaceExisting) {
					    it.assign_val(convert(value));
					    replaced = true;
				    }
                    result = std::make_pair(it, replaced);
			    } else {
                    result = container->store.emplace(convert(key), convert(value));
			    }
		    });
		    return result;
	    } catch (pmem::transaction_scope_error& e) {
		    Error err = internal_error();
		    TraceEvent(SevError, "ErrorInsertIntoPmem").error(err).detail("ErrorMsg", e.what());
		    throw err;
	    } catch (pmem::transaction_error& e) {
		    Error err = internal_error();
		    TraceEvent(SevError, "ErrorInsertIntoPmem").error(err).detail("ErrorMsg", e.what());
		    throw err;
	    }
    }

    void PmemVector::erase(const StringRef& lo, const StringRef& hi) {
	    try {
		    check_outside_tx();
		    // remove [first, last)
		    auto first = container->store.lower_bound(convert(lo));
		    auto last = container->store.lower_bound(convert(hi));
		    container->store.erase(first, last);
	    } catch (pmem::transaction_scope_error& e) {
            Error err = internal_error();
            TraceEvent(SevError, "ErrorEraseFromPmem").error(err).detail("ErrorMsg", e.what());
            throw err;
        } catch (pmem::transaction_error& e) {
            Error err = internal_error();
            TraceEvent(SevError, "ErrorEraseFromPmem").error(err).detail("ErrorMsg", e.what());
            throw err;
        }
    }

    void PmemVector::recover() {
        if (!OID_IS_NULL(*root_oid)) {
            container = (internal::kv_container *)pmemobj_direct(*root_oid);
        } else {
            pmem::obj::transaction::run(pmpool, [&] {
                pmem::obj::transaction::snapshot(root_oid);
                *root_oid = pmem::obj::make_persistent<internal::kv_container>().raw();
                container = (internal::kv_container *)pmemobj_direct(*root_oid);
            });
        }
    }
} // namespace pmem
#endif // FLOW_PMEMVECTOR_H
