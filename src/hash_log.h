// Copyright 2014 Matthias Maennich (matthias@maennich.net)
//           2016 SAP SE
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef NINJA_HASH_LOG_H_
#define NINJA_HASH_LOG_H_

#include <map>
#include <vector>
#include <string>

#include <stdio.h>

#ifdef _WIN32
#include "win32port.h"
#else
#include <stdint.h>
#endif

#include "hash_map.h"
#include "disk_interface.h"

struct Node;
struct Edge;
struct State;

struct HashLog {
  typedef FileHasher::Hash Hash;

  HashLog(FileHasher *hasher);
  ~HashLog();

  bool Load(const string& path, State* state, string* err);

  /// Check whether an edge's output hash matches the known hash of its inputs
  bool OutputHashClean(Node *output, Edge* edge, string* err);

  bool OpenForWrite(const string &path, string* err);
  void Close();

  /// Persist hashes (inputs and outputs) for a finished edge.
  bool RecordHashes(Edge* edge, DiskInterface* disk_interface, string* err);

  /// Recompact the hash log to reduce it to minimum size
  bool Recompact(const string &path, string* err);

  struct LogEntry {
    /// Unique id for each node so paths do not need to be stored for each
    /// record.  If the high bit is set the entry is followed by a path name
    /// otherwise the path should have been read earlier.
    unsigned id_;
    /// Timestamp when the hash was taken.
    TimeStamp mtime_;
    /// Hash when recording as an input.
    Hash input_hash_;
    /// Combined hash of all inputs when recoding as an output.
    Hash output_hash_;

    LogEntry() : id_(0), mtime_(0), input_hash_(0), output_hash_(0) {}
  };

 private:
  bool WriteEntry(Node *node, LogEntry *entry, string *err);

  bool HashIsClean(Node *node, bool is_input, Hash *acc, string *err);

  bool RecordHash(Node *node, bool is_input, Hash *acc, string *err);

  unsigned next_id_;

  FILE* file_;

  FileHasher *hasher_;

  typedef ExternalStringHashMap<LogEntry*>::Type Entries;

  Entries entries_;

  bool needs_recompaction_;
};

#endif //NINJA_HASH_LOG_H_
