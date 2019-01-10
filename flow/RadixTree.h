/*
 * RadixTree.h
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

#ifndef FLOW__RADIXTREE_H
#define FLOW__RADIXTREE_H
#pragma once

#include <cassert>
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include <functional>
#include <map>
#include <stdexcept>

#include "Arena.h"

// forward declaration
const int LEAF_BYTE = -1;
const int INLINE_KEY_SIZE = 12;
int m_height = 1;

template <typename K, class Compare = std::less<K> > class radix_tree;

template<typename K>
K radix_substr(const K &key, int begin, int num);

template <>
// explicit specialization for K = StringRef
StringRef radix_substr<StringRef>(const StringRef& key, int begin, int num) {
	int size = key.size();
    if (begin > size) {
        throw std::out_of_range("out of range in radix_substr<StringRef>");
    }
    if((begin + num) > size) {
        num = size - begin;
    }
    return key.substr(begin, num);
}

template<typename K>
K radix_join(const K &key1, const K &key2, Arena &arena);

template <>
StringRef radix_join<StringRef>(const StringRef& key1, const StringRef& key2, Arena& arena) {
	int rsize = key1.size() + key2.size();
    uint8_t* s = new (arena) uint8_t[ rsize ];

    memcpy(s, key1.begin(), key1.size());
    memcpy(s + key1.size(), key2.begin(), key2.size());

    return StringRef(s, rsize);
}

template<typename K>
int radix_length(const K &key);

template<>
inline int radix_length<StringRef>(const StringRef &key) {
    return key.size();
}

template<typename K>
K radix_constructStr(const K &key, int begin, int num, Arena &arena);

template <>
// explicit specialization for K = StringRef
StringRef radix_constructStr<StringRef>(const StringRef& key, int begin, int num, Arena& arena) {
	int size = key.size();
    if (begin > size) {
        throw std::out_of_range("out of range in radix_substr<StringRef>");
    }
    if((begin + num) > size) {
        num = size - begin;
    }
    return StringRef(arena, key.substr(begin, num));
}

template<typename K, typename Compare>
class radix_tree {
public:
    typedef K key_type;
    typedef std::size_t size_type;

private:
    struct node : FastAllocated<node> {
		// constructor for all kinds of node (root/internal/leaf)
		node() : m_is_leaf(0), m_is_inline(0), m_inline_length(0), m_depth(0), key(), arena(), m_parent(NULL) {}

		node(const node&) = delete; // delete
		node& operator=(const node& other) {
			m_is_leaf = other.m_is_leaf;
			m_is_inline = other.m_is_inline;
			m_inline_length = other.m_inline_length;
			m_depth = other.m_depth;
			memcpy(inlineKey, other.inlineKey, INLINE_KEY_SIZE);
			arena = other.arena;
			m_parent = other.m_parent;

			return *this;
		}

		void setData(const K& content, int start, int num) {
			bool isInline = num <= INLINE_KEY_SIZE;
			if (isInline) {
				memcpy(inlineKey, content.begin() + start, num);
				m_inline_length = num;
				if (!m_is_inline) arena = Arena();
			} else {
				Arena new_arena(num);
				key = radix_constructStr(content, start, num, new_arena);
				arena = new_arena;
			}

			m_is_inline = isInline;
		}

		K getData() {
			if (m_is_inline) {
				return K(&inlineKey[0], m_inline_length);
			} else {
				return key;
			}
		}

		inline int getDataSize() { return m_is_inline ? m_inline_length : radix_length(key); }

		inline uint8_t getFirstByte() { return m_is_inline ? inlineKey[0] : key[0]; }

		inline size_type getArenaSize() { return m_is_inline ? 0 : arena.getSize(); }

		uint32_t m_is_leaf : 1;
		uint32_t m_is_fixed : 1; // if true, then we have fixed number of children (3)
		uint32_t m_is_inline : 1;
		uint32_t m_inline_length : 4;
		// m_depth can be seen as common prefix length with your ancestors
		// for leaf node, m_depth == key.size()
		uint32_t m_depth : 25;
		// for internal node, data is the suffix, a substring that is different from your ancestors (key)
		union {
			uint8_t inlineKey[INLINE_KEY_SIZE];
			K key;
		};
		// for internal node, arena assign memory for key
		// for leaf node, rena assign memory for value
		Arena arena;
		node *m_parent;
    };

    struct internalNode : FastAllocated<internalNode> {
		internalNode() : base(), m_children(std::vector<std::pair<int16_t, node*>>()) {
			m_children.reserve(4);
			base.m_is_fixed = 0;
		}

		~internalNode() {
			for (auto it = 0; it < m_children.size(); ++it) {
				delete m_children[it].second;
			}
			m_children.clear();
		}

		node base;
		// ordered map by char, m_children.begin() return the smallest value
        std::vector<std::pair<int16_t, node *>> m_children;
    };

	struct internalNode4 : FastAllocated<internalNode4> {
		internalNode4() : base(), num_children(0) {
			base.m_is_fixed = 1;
			memset(keys, 0, sizeof(keys));
			memset(m_children, 0, sizeof(m_children));
		}

		~internalNode4() { num_children = 0; }

		node base;
		int16_t num_children;
		int16_t keys[3];
		node* m_children[3];
	};

public:
    class iterator : public std::iterator<std::forward_iterator_tag, std::pair<K, K>> {
	public:
		node* m_pointee;

		iterator() : m_pointee(NULL) {}
		iterator(const iterator& r) : m_pointee(r.m_pointee) {}
		iterator(node* p) : m_pointee(p) {}
		iterator& operator=(const iterator& r) { m_pointee = r.m_pointee; return *this; }
        ~iterator() = default;

		K operator*() const;
		K* operator->() const;
		const iterator& operator++();
		iterator operator++(int);
		const iterator& operator--();
		bool operator != (const iterator &lhs) const;
        bool operator == (const iterator &lhs) const;
        K key(uint8_t *content, int len) const;

	private:
		node* increment(node* target) const;
		node* decrement(node* target) const;
	};

	radix_tree() : m_size(0), m_node(0), inline_keys(0), total_bytes(0), m_root(NULL), m_predicate(Compare()) {}

	explicit radix_tree(Compare pred)
	  : m_size(0), m_node(0), inline_keys(0), total_bytes(0), m_root(NULL), m_predicate(pred) {}

	~radix_tree() { delete m_root; }

	radix_tree(const radix_tree& other) = delete; // delete
	radix_tree& operator=(const radix_tree other) = delete; // delete

	inline std::tuple<size_type, size_type, size_type> size() { return std::make_tuple(m_size, m_node, inline_keys); }

	inline int64_t getTreeHeight() { return m_height; }

	// Return the amount of memory used by an entry in the RadixTree
	static int getElementBytes(node* node) {
		int result = 0;
		if (node->m_is_leaf) {
			result = sizeof(node);
		} else if (node->m_is_fixed) {
			result = sizeof(internalNode4);
		} else {
			ASSERT(!node->m_is_fixed);
			result = sizeof(internalNode);
		}
		return result;
	}

	bool empty() const { return m_size == 0; }

	void clear() {
		delete (internalNode*)m_root;
		m_root = NULL;
		m_size = 0;
		m_node = 0;
		inline_keys = 0;
		total_bytes = 0;
	}
	// iterators
	iterator find(const K& key);
	iterator begin();
    iterator end();
    //modifications
	std::pair<iterator, bool> insert(const K& key, const K& val, bool replaceExisting = false);
	bool erase(node* child);
	void erase(iterator it);
	void erase(iterator begin, iterator end);
	// lookups
    iterator lower_bound(const K &key);
    iterator upper_bound(const K &key);
    // access
    int64_t sum_to(iterator to);
    iterator previous (iterator i);

private:
    size_type m_size;
    // number of nodes that has been created
    size_type m_node;
	// number of nodes with data.size() <= 12
	size_type inline_keys;
	int64_t total_bytes;
	node* m_root;
	Compare m_predicate;

	// modification
	void add_child(node* parent, node* child);
	void add_child_vector(node* parent, node* child);
	void add_child4(node* parent, node* child);
	void delete_child(node* parent, node* child);
	void delete_child_vector(node* parent, node* child);
	void delete_child4(node* parent, node* child);
	// access
	static int find_child(node* parent, int16_t ch); // return index
	static int child_size(node* parent); // how many children does parent node have
	static node* get_child(node* parent, int index); // return node pointer

	// direction 0 = left, 1 = right
	template <int reverse>
	static node* descend(node* i) {
		while (!i->m_is_leaf) {
			ASSERT(child_size(i) != 0);
			if (reverse) {
				i = get_child(i, child_size(i) - 1);
			} else {
				i = get_child(i, 0);
			}
		}
		return i;
	}

	node* find_node(const K& key, node* node, int depth);
	node* append(node* parent, const K& key, const K& val);
	node* prepend(node* node, const K& key, const K& val);
	iterator lower_bound(const K& key, node* node);
	iterator upper_bound(const K& key, node* node);
};

/////////////////////// iterator //////////////////////////
template <typename K, typename Compare>
void radix_tree<K, Compare>::add_child(node *parent, node *child){
	if (parent->m_is_fixed) {
		add_child4(parent, child);
	} else {
		add_child_vector(parent, child);
	}
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::add_child4(node* parent, node* child) {
	int16_t ch = child->m_is_leaf ? LEAF_BYTE : child->getFirstByte();
	internalNode4* parent_ref = (internalNode4*)parent;
	int i = 0;

	for (; i < parent_ref->num_children; ++i) {
		if (parent_ref->keys[i] >= ch) break;
	}

	if (!parent_ref->num_children) {
		// empty
		parent_ref->num_children++;
		parent_ref->keys[0] = ch;
		parent_ref->m_children[0] = child;
		// DEBUG
		total_bytes += getElementBytes(child) + child->getArenaSize();
	} else if (i >= 0 && i < parent_ref->num_children && parent_ref->keys[i] == ch) {
		// replace
		node* original = parent_ref->m_children[i];
		total_bytes -= (getElementBytes(original) + original->getArenaSize());
		parent_ref->m_children[i] = child;
		total_bytes += getElementBytes(child) + child->getArenaSize();
	} else if (parent_ref->num_children < 3) {
		// Shift to make room
		memmove(parent_ref->keys + i + 1, parent_ref->keys + i, (parent_ref->num_children - i) * sizeof(int16_t));
		memmove(parent_ref->m_children + i + 1, parent_ref->m_children + i,
		        (parent_ref->num_children - i) * sizeof(void*));

		// Insert element
		parent_ref->keys[i] = ch;
		parent_ref->m_children[i] = child;
		parent_ref->num_children++;
		// DEBUG
		total_bytes += getElementBytes(child) + child->getArenaSize();
	} else {
		ASSERT(parent_ref->num_children >= 3);
		// how many vector nodes do we have

		internalNode* new_node = new radix_tree<K, Compare>::internalNode();
		new_node->base = parent_ref->base; // equal operator
		ASSERT(!new_node->base.m_is_fixed);
		for (int index = 0; index < parent_ref->num_children; index++) {
			new_node->m_children.emplace_back(parent_ref->keys[index], parent_ref->m_children[index]);
			parent_ref->m_children[index]->m_parent = (node*)new_node;
		}
		// Insert element
		new_node->m_children.insert(new_node->m_children.begin() + i, std::make_pair(ch, child));
		child->m_parent = (node*)new_node;
		// update parent info
		add_child(new_node->base.m_parent, (node*)new_node);
		// DEBUG
		total_bytes += new_node->m_children.size() * sizeof(std::pair<int16_t, void*>) + getElementBytes(child) +
		               child->getArenaSize();
		delete parent_ref;
	}
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::add_child_vector(node* parent, node* child) {
	int16_t ch = child->m_is_leaf ? LEAF_BYTE : child->getFirstByte();
	internalNode* parent_ref = (internalNode*)parent;
	int i = 0;

	for (; i < parent_ref->m_children.size(); ++i) {
		if (parent_ref->m_children[i].first >= ch) break;
	}

	if (parent_ref->m_children.empty() || i == parent_ref->m_children.size() || parent_ref->m_children[i].first > ch) {
		parent_ref->m_children.insert(parent_ref->m_children.begin() + i, std::make_pair(ch, child));
		// DEBUG
		total_bytes += getElementBytes(child) + child->getArenaSize() + sizeof(std::pair<int16_t, void*>);
	} else {
		ASSERT(parent_ref->m_children[i].first == ch);
		// replace with the new child
		node* original = parent_ref->m_children[i].second;
		total_bytes -= (getElementBytes(original) + original->getArenaSize());
		parent_ref->m_children[i] = std::make_pair(ch, child); // replace with the new child
		total_bytes += getElementBytes(child) + child->getArenaSize();
	}
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::delete_child(radix_tree<K, Compare>::node* parent, radix_tree<K, Compare>::node* child) {
	if (parent->m_is_fixed) {
		delete_child4(parent, child);
	} else {
		delete_child_vector(parent, child);
	}
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::delete_child4(radix_tree<K, Compare>::node* parent, radix_tree<K, Compare>::node* child) {
	int16_t ch = child->m_is_leaf ? LEAF_BYTE : child->getFirstByte();
	internalNode4* parent_ref = (internalNode4*)parent;
	int i = 0;

	for (; i < parent_ref->num_children; i++) {
		if (parent_ref->keys[i] == ch) break;
	}
	ASSERT(i != parent_ref->num_children);
	memmove(parent_ref->keys + i, parent_ref->keys + i + 1, (parent_ref->num_children - 1 - i) * sizeof(int16_t));
	memmove(parent_ref->m_children + i, parent_ref->m_children + i + 1,
	        (parent_ref->num_children - 1 - i) * sizeof(void*));
	parent_ref->num_children--;
	total_bytes -= (getElementBytes(child) + child->getArenaSize());
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::delete_child_vector(radix_tree<K, Compare>::node* parent,
                                                 radix_tree<K, Compare>::node* child) {
	int16_t ch = child->m_is_leaf ? LEAF_BYTE : child->getFirstByte();
	internalNode* parent_ref = (internalNode*)parent;
	int i = 0;

    for(; i<parent_ref->m_children.size(); i++){
        if(parent_ref->m_children[i].first == ch)  break;
    }
    ASSERT(i != parent_ref->m_children.size());
    parent_ref->m_children.erase(parent_ref->m_children.begin() + i);
	total_bytes -= (getElementBytes(child) + child->getArenaSize() + sizeof(std::pair<int16_t, void*>));
	if (parent_ref->m_children.size() <= parent_ref->m_children.capacity() / 4) parent_ref->m_children.shrink_to_fit();
}

template <typename K, typename Compare>
int radix_tree<K, Compare>::find_child(radix_tree<K, Compare>::node* parent, int16_t ch) {
	int i = 0;
	if (parent->m_is_fixed) {
		internalNode4* parent_ref = (internalNode4*)parent;
		for (; i < parent_ref->num_children; ++i) {
			if (parent_ref->keys[i] == ch) return i;
		}
	} else {
		internalNode* parent_ref = (internalNode*)parent;
		for (; i != parent_ref->m_children.size(); ++i) {
			if (parent_ref->m_children[i].first == ch) return i;
		}
	}
	return i;
}

template <typename K, typename Compare>
int radix_tree<K, Compare>::child_size(radix_tree<K, Compare>::node* parent) {
	if (parent->m_is_fixed) {
		return ((internalNode4*)parent)->num_children;
	} else {
		return ((internalNode*)parent)->m_children.size();
	}
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::get_child(node* parent, int index) {
	if (parent->m_is_fixed) {
		ASSERT(index < ((internalNode4*)parent)->num_children);
		return ((internalNode4*)parent)->m_children[index];
	} else {
		return ((internalNode*)parent)->m_children[index].second;
	}
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::iterator::increment(node *target) const {
	radix_tree<K, Compare>::node* parent = target->m_parent;
	if (parent == NULL) return NULL;

	int index = target->m_is_leaf ? find_child(parent, LEAF_BYTE) : find_child(parent, target->getFirstByte());
	ASSERT(index != child_size(parent));
	++index;

	if (index == child_size(parent))
		return increment(target->m_parent);
	else
		return descend<0>(get_child(parent, index));
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::iterator::decrement(
    radix_tree<K, Compare>::node* target) const {
	radix_tree<K, Compare>::node* parent = target->m_parent;
	if (parent == NULL) return NULL;

	int index = target->m_is_leaf ? find_child(parent, LEAF_BYTE) : find_child(parent, target->getFirstByte());
	ASSERT(index != child_size(parent));

	if (index == 0)
		return decrement(target->m_parent);
	else {
		--index;
		return descend<1>(get_child(parent, index));
	}
}

template <typename K, typename Compare>
K radix_tree<K, Compare>::iterator::operator*() const {
	return m_pointee->getData();
}

template <typename K, typename Compare>
K* radix_tree<K, Compare>::iterator::operator->() const {
	return &m_pointee->getData();
}

template <typename K, typename Compare>
bool radix_tree<K, Compare>::iterator::operator!=(const radix_tree<K, Compare>::iterator &lhs) const {
    return m_pointee != lhs.m_pointee;
}

template <typename K, typename Compare>
bool radix_tree<K, Compare>::iterator::operator==(const radix_tree<K, Compare>::iterator &lhs) const {
    return m_pointee == lhs.m_pointee;
}

template <typename K, typename Compare>
const typename radix_tree<K, Compare>::iterator& radix_tree<K, Compare>::iterator::operator++() {
    if (m_pointee != NULL) // it is undefined behaviour to dereference iterator that is out of bounds...
        m_pointee = increment(m_pointee);
    return *this;
}

template <typename K, typename Compare>
const typename radix_tree<K, Compare>::iterator& radix_tree<K, Compare>::iterator::operator--() {
    if (m_pointee != NULL && m_pointee->m_is_leaf) {
        m_pointee = decrement(m_pointee);
    }
    return *this;
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::iterator::operator++(int) {
    radix_tree<K, Compare>::iterator copy(*this);
    ++(*this);
    return copy;
}

/*
 * reconstruct the key, using @param arena to allocate memory
 */
template <typename K, typename Compare>
K radix_tree<K, Compare>::iterator::key(uint8_t *content, int len) const {
    if(m_pointee == NULL)
        return K();

    ASSERT(m_pointee->m_is_leaf);
    memset(content, 0, len);

    auto node = m_pointee;
    int64_t pos = m_pointee->m_depth;
    while(true){
		if (!node->m_is_leaf) memcpy(content + pos, node->getData().begin(), node->getDataSize());
		node = node->m_parent;
		if (node == NULL || pos <= 0) break;
		pos -= node->m_is_leaf ? 0 : node->getDataSize();
	}
	return K(content, m_pointee->m_depth);
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::end() {
    return iterator(NULL);
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::begin() {
    typename radix_tree<K, Compare>::node *result;

    if (m_root == NULL || m_size == 0)
		return iterator(NULL);
	else {
		return descend<0>(m_root);
	}
}

/////////////////////// lookup //////////////////////////
template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::find(const K &key)
{
    if (m_root == NULL)
        return iterator(NULL);

    auto node = find_node(key, m_root, 0);
    // if the node is an internal node, return NULL
    if (! node->m_is_leaf)
        return iterator(NULL);

    return iterator(node);
}

/*
 * corner case : insert "apache, append", then search for "appends". find_node() will return internal node instead of the
 * leaf node with m_key == ""; if search for "ap", find_node() will return internal node with m_key = ap
 */
template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::find_node(const K &key, node* node, int depth) {
    if (node->m_is_leaf)
        return node;

    int len_key = radix_length(key) - depth;
	int size = child_size(node);

	for (int it = 0; it < size; ++it) {
		// printf("find_node: node key[%s], key address[%p], len_key[%d]\n", it->first.toString().c_str(), (void
		// *)it->first.begin(), len_key); empty string
		auto current = get_child(node, it);
		if (len_key == 0) {
			if (current->m_is_leaf)
				return current;
			else
				continue;
		}

		// they have at least one byte in common
		if (!current->m_is_leaf && key[depth] == current->getFirstByte()) {
			int len_node = current->getDataSize();
			K key_sub = radix_substr(key, depth, len_node);
			// if equal(this internal node), then keep searching, depth first
			if (key_sub == current->getData()) {
				return find_node(key, current, depth + len_node);
			} else {
				// return the match (which is the smallest match)
				// radix tree won't have siblings that share the same prefix
				return current;
			}
		}
	}

	return node;
}

/*
 * Returns the smallest node x such that *x>=key, or end()
 */
template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::lower_bound(const K &key) {
    if(m_root == NULL || m_size == 0)
        return iterator(NULL);
    return lower_bound(key, m_root);
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::lower_bound(const K &key, node *node){
    if(node == NULL || node->m_is_leaf)
        return iterator(node);

    iterator result(NULL);
	int size = child_size(node);

	for (int it = 0; it < size; ++it) {
		auto current = get_child(node, it);
		int len_key = radix_length(key) - current->m_depth;

		if (current->m_is_leaf && len_key == 0) {
			// when key == *node
			return iterator(current);
		} else if (!current->m_is_leaf) {
			K key_sub = radix_substr(key, current->m_depth, current->getDataSize());
			K node_data = current->getData();

			if (node_data == key_sub) {
				result = lower_bound(key, current);
			} else if (node_data > key_sub) {
				return descend<0>(current);
			}
		}
		if (result != end()) return result;
	}

	return result;
}

/*
 * Returns the smallest x such that *x>key, or end()
 */
template <typename  K, typename  Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::upper_bound(const K &key) {
    if(m_root == NULL || m_size == 0)
        return iterator(NULL);
    return upper_bound(key, m_root);
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::upper_bound(const K &key, node *node){
    if(node == NULL || node->m_is_leaf)
        return iterator(node);

    iterator result(NULL);
	int size = child_size(node);

	for (int it = 0; it < size; ++it) {
		auto current = get_child(node, it);
		if (!current->m_is_leaf) {
			K key_sub = radix_substr(key, current->m_depth, current->getDataSize());
			K node_data = current->getData();

			if (node_data == key_sub) {
				result = upper_bound(key, current);
			} else if (node_data > key_sub) {
				return descend<0>(current);
			}
		}
		if (result != end()) return result;
	}
	return result;
}

// Return the sum of getT(x) for begin()<=x<to
template <typename  K, typename  Compare>
int64_t radix_tree<K, Compare>::sum_to(iterator to) {
    if(to == end()) {
        return m_root ? total_bytes : 0;
    }
    else {
        throw std::invalid_argument("sum_to method only support end() input");
    }
}

template <typename K, typename Compare>
typename radix_tree<K, Compare>::iterator radix_tree<K, Compare>::previous(radix_tree<K, Compare>::iterator i) {
    if(i == end()){
        // for iterator == end(), find the largest element
		return descend<1>(m_root);
	} else if (i == begin()) {
		return iterator(NULL);
	} else {
		--i;
        return i;
	}
}

/////////////////////// modification //////////////////////////
/*
 * @param parent : direct parent of this newly inserted node
 * @param val : using val to create a newly inserted node
 */
template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::append(node* parent, const K& key, const K& val) {
	int depth;
	int len;
	typename radix_tree<K, Compare>::node *node_c, *node_cc;

	depth = parent->m_depth + parent->getDataSize();
	len = radix_length(key) - depth;

	if (len == 0) {
		node_c = new radix_tree<K, Compare>::node();
		m_node++;

		node_c->setData(val, 0, radix_length(val));
		node_c->m_depth = depth;
		node_c->m_parent = parent;
		node_c->m_is_leaf = 1;

		add_child(parent, node_c);
		// DEBUG
		if (val.size() <= INLINE_KEY_SIZE) inline_keys++;
		return node_c;
	} else {
		// create internal nodd
		node_c = (node*)new radix_tree<K, Compare>::internalNode4();
		m_node++;

		node_c->setData(key, depth, len);
		node_c->m_depth = depth;
		node_c->m_parent = parent;
		add_child(parent, node_c);

		// create leaf node
		node_cc = new radix_tree<K, Compare>::node();
		m_node++;

		node_cc->setData(val, 0, radix_length(val));
		node_cc->m_depth = radix_length(key);
		node_cc->m_parent = node_c;
		node_cc->m_is_leaf = 1;
		add_child(node_c, node_cc);
		// DEBUG
		if (val.size() <= INLINE_KEY_SIZE) inline_keys++;
		if (node_c->getDataSize() <= INLINE_KEY_SIZE) inline_keys++;
		return node_cc;
	}
}

/*
 * step one : find common substring of node->m_key and val(findnode() method has already guaranteed that they have something in common)
 * step two : split the existing node into two based on the common substring
 * step three : append newly inserted node to node_a
 *
 * @param node : split node
 * @param val : using val to create a newly inserted node
 */
template <typename K, typename Compare>
typename radix_tree<K, Compare>::node* radix_tree<K, Compare>::prepend(node* split, const K& key, const K& val) {
	int len1 = split->getDataSize();
	int len2 = radix_length(key) - split->m_depth;
	int count = 0;
	// deep copy original data using a temp_arena(becomes invalid once out)
	Arena temp_arena(split->getDataSize());
	K original_data(temp_arena, split->getData());

	for (; count < len1 && count < len2; count++) {
		if (!(original_data[count] == key[count + split->m_depth])) break;
	}
	ASSERT(count != 0);

	// create a new internal node
	node* node_a = (node*)new radix_tree<K, Compare>::internalNode4();
	m_node++;

	node_a->m_parent = split->m_parent;
	node_a->setData(original_data, 0, count);
	node_a->m_depth = split->m_depth;
	add_child(node_a->m_parent, node_a); // replace original node* with node_a*

	// modify original internal node
	// EXPERIMENT : create a new arena to replace with the original one, try to reduce memory usage
	// DEBUG
	if (count <= INLINE_KEY_SIZE) inline_keys++;
	if (split->getDataSize() > INLINE_KEY_SIZE && (len1 - count) <= INLINE_KEY_SIZE) inline_keys++;

	split->m_depth += count;
	split->m_parent = node_a;
	split->setData(original_data, count, len1 - count);
	add_child(node_a, split);
	return append(node_a, key, val);
}

template <typename K, typename Compare>
std::pair<typename radix_tree<K, Compare>::iterator, bool> radix_tree<K, Compare>::insert(const K& key, const K& val,
                                                                                          bool replaceExisting) {
	if (m_root == NULL) {
		m_root = (node*)new radix_tree<K, Compare>::internalNode();
		total_bytes += getElementBytes(m_root);
	}

	auto node = find_node(key, m_root, 0);
	if (node->m_is_leaf) {
		bool inserted = false;
		if(replaceExisting) {
			// DEBUG INFO
			if (node->getDataSize() <= INLINE_KEY_SIZE) inline_keys--;
			if (radix_length(val) <= INLINE_KEY_SIZE) inline_keys++;

			size_type old_metrics = node->getArenaSize();
			node->setData(val, 0, radix_length(val));
			// modify total bytes
			total_bytes = total_bytes - old_metrics + node->getArenaSize();
			inserted = true;
		}
		return std::pair<iterator, bool>(node, inserted);
	} else if (node == m_root) {
		m_size++;
		return std::pair<iterator, bool>(append(m_root, key, val), true);
	} else {
		m_size++;
		int len = node->getDataSize();
		K key_sub = radix_substr(key, node->m_depth, len);

		if (key_sub == node->getData()) {
			return std::pair<iterator, bool>(append(node, key, val), true);
		} else { // val is longer than node->m_key
			return std::pair<iterator, bool>(prepend(node, key, val), true);
		}
	}
}

template <typename K, typename Compare>
void radix_tree<K, Compare>::erase(iterator it) {
	erase(it.m_pointee);
}

template <typename K, typename Compare>
bool radix_tree<K, Compare>::erase(radix_tree<K, Compare>::node* child) {
	if (m_root == NULL) return false;
	ASSERT(child != NULL);

	if (!child->m_is_leaf) return false;

	radix_tree<K, Compare>::node *parent, *grandparent;

	parent = child->m_parent;
	delete_child(parent, child);
	// DEBUG
	if (child->getDataSize() <= INLINE_KEY_SIZE) inline_keys--;
	delete child;
	m_size--;
	m_node--;

	// the deleted node is the only one in radix tree
	if (parent == m_root) return true;

	if (child_size(parent) > 1) return true;

	// parent has only one child (leaf node), and that child has just been deleted
	if (child_size(parent) == 0) {
		grandparent = parent->m_parent;
		delete_child(grandparent, parent);

		// DEBUG
		if (parent->getDataSize() <= INLINE_KEY_SIZE) inline_keys--;
		parent->m_is_fixed ? delete (internalNode4*)parent : delete (internalNode*)parent;
		m_node--;
	} else {
		grandparent = parent;
	}

	if (grandparent == m_root) {
		return true;
	}
	// grandparent has only one child left, my parent's only sibling
	if (child_size(grandparent) == 1) {
		// merge grandparent with the uncle
		node* uncle = get_child(grandparent, 0);

		if (uncle->m_is_leaf) return true;

		// DEBUG
		if (uncle->getDataSize() <= INLINE_KEY_SIZE) inline_keys--;
		delete_child(grandparent, uncle);

		Arena temp_arena;
		K new_data = radix_join(grandparent->getData(), uncle->getData(), temp_arena);
		uncle->setData(new_data, 0, radix_length(new_data));
		uncle->m_depth = grandparent->m_depth;
		uncle->m_parent = grandparent->m_parent;
		// delete grandparent and replace with uncle
		add_child(grandparent->m_parent, uncle);
		// DEBUG
		if (uncle->getDataSize() <= INLINE_KEY_SIZE) inline_keys++;
		if (grandparent->getDataSize() <= INLINE_KEY_SIZE) inline_keys--;

		grandparent->m_is_fixed ? delete (internalNode4*)grandparent : delete (internalNode*)grandparent;
		m_node--;
	}
	return true;
}

// Erase the items in the indicated range.
template <typename K, typename Compare>
void radix_tree<K, Compare>::erase(radix_tree<K, Compare>::iterator begin,
                                   radix_tree<K, Compare>::iterator end) {
    std::vector<radix_tree<K, Compare>::node *> node_set;
    for(auto it = begin; it != end; ++it){
        node_set.push_back(it.m_pointee);
    }

    for(int i = 0; i <node_set.size(); ++i) {
        erase(node_set[i]);
    }
}

#endif