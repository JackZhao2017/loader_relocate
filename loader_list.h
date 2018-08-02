/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LOADER_LIST_H
#define __LOADER_LIST_H



#include "private/bionic_macros.h"

#define nullptr 0

template<typename T>
struct LoaderListEntry {
  LoaderListEntry<T>* next;
  T* element;
};

/*
 * Represents linked list of objects of type T
 */
template<typename T, typename Allocator>
class LoaderList {
 public:
  LoaderList() : head_(nullptr), tail_(nullptr) {}

  void push_front(T* const element) {
    // LoaderListEntry<T>* new_entry = Allocator::alloc();
    LoaderListEntry<T>* new_entry = NULL;
    new_entry->next = head_;
    new_entry->element = element;
    head_ = new_entry;
    if (tail_ == nullptr) {
      tail_ = new_entry;
    }
  }

  void push_back(T* const element) {
    // LoaderListEntry<T>* new_entry = Allocator::alloc();
    LoaderListEntry<T>* new_entry = NULL;
    new_entry->next = nullptr;
    new_entry->element = element;
    if (tail_ == nullptr) {
      tail_ = head_ = new_entry;
    } else {
      tail_->next = new_entry;
      tail_ = new_entry;
    }
  }

  T* pop_front() {
    if (head_ == nullptr) {
      return nullptr;
    }

    LoaderListEntry<T>* entry = head_;
    T* element = entry->element;
    head_ = entry->next;
   // Allocator::free(entry);

    if (head_ == nullptr) {
      tail_ = nullptr;
    }

    return element;
  }

  void clear() {
    while (head_ != nullptr) {
      LoaderListEntry<T>* p = head_;
      head_ = head_->next;
      //Allocator::free(p);
    }

    tail_ = nullptr;
  }

  template<typename F>
  void for_each(F&& action) {
    for (LoaderListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr) {
        action(e->element);
      }
    }
  }

  template<typename F>
  void remove_if(F&& predicate) {
    for (LoaderListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr && predicate(e->element)) {
        e->element = nullptr;
      }
    }
  }

  bool contains(const T* el) {
    for (LoaderListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr && e->element == el) {
        return true;
      }
    }
    return false;
  }

 private:
  LoaderListEntry<T>* head_;
  LoaderListEntry<T>* tail_;
  DISALLOW_COPY_AND_ASSIGN(LoaderList);
};


#endif // __LINKED_LIST_H
