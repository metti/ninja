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
struct ImplicitDepLoader;
struct BuildLogUser;

#if !defined(_MSC_VER) && (__cplusplus < 201103L)
namespace __gnu_cxx {
template<>
struct hash<Node*> {
  size_t operator()(Node* key) const {
    return hash<uintptr_t>()(reinterpret_cast<uintptr_t>(key));
  }
};
}
#endif

struct HashLog {
  typedef FileHasher::Hash Hash;

  explicit HashLog(FileHasher *hasher);
  ~HashLog();

  bool Load(const string& path, State* state, string* err);

  /// Check whether an edge's input and output hashes match previously
  /// recorded values.  The stat information on the inputs and outputs
  /// must be current for this to give the correct result.
  bool HashesAreClean(Node *output, Edge* edge, string* reason, string* err);

  bool OpenForWrite(const string &path, const BuildLogUser& user, string* err);
  void Close();

  /// Persist hashes (inputs and outputs) for a finished edge.
  bool RecordHashes(Edge* edge, DiskInterface* disk_interface, string* err,
                    const std::vector<Node*> &implicit_deps=std::vector<Node*>());

  /// Recompact the hash log to reduce it to minimum size
  bool Recompact(const string &path, const BuildLogUser& user, ImplicitDepLoader &dep_loader, string* err);
  /// Recompact the hash log to reduce it to minimum size only if needed
  /// A recompaction is done only if the hash_log is open for write
  bool RecompactIfNeeded(ImplicitDepLoader &dep_loader, string* err);

  struct HashRecord {
    /// The timestamp of the file when the hash was computed.  Hashes are only
    /// recomputed if the timestamp is different.
    TimeStamp mtime_;
    /// The hash value.
    Hash value_;

    HashRecord() : mtime_(-1), value_(0) {}
  };

  /// For NinjaMain::ToolHashes and testing.

  /// Retrieve the nodes for which there are hashes stored.
  vector<Node*> GetOutputs() const;
  /// Get the number of hashes known for a given output.
  size_t GetInputCount(Node *node) const;
  /// Get the hash of the input of the given output.
  HashRecord *GetInputHash(Node *output, Node *input) const;

 protected:
  struct IdHashRecord : HashRecord {
    /// Id of the node this hash is for.
    int id_;

    bool operator==(const IdHashRecord &other) const;
    bool operator<(const IdHashRecord &other) const;
    bool operator<(int id) const;

    IdHashRecord() : id_(-1) {}
  };

  /// Records for the inputs of a node.
  typedef vector<IdHashRecord> Inputs;

  /// Record for a node.
  /// If the node is seen as an input the HashRecord is populated.
  /// If the node is seen as an output the inputs are populated.
  struct NodeRecord : HashRecord {
    Inputs inputs_;
  };

  /// Get the id for the node.  Returns -1 if the node is unknown.
  int GetId(Node *node) const;
  /// Get the id for the node, creating and recording a new one if the node is
  /// unknown.  Returns -1 and sets err on error.
  int GetOrCreateId(Node *node, string* err);

  /// Get the record for the node.  Returns NULL if the node is unknown.
  NodeRecord *GetRecord(Node *node) const;
  NodeRecord *GetRecord(int id) const;
  /// Get the record for the node with the given id.  Creates a new record if
  /// one doesn't exist.
  NodeRecord *GetOrCreateRecord(int id, bool *is_new_entry=NULL);

  /// Compute the hash for the given node, using internal cache if available.
  HashRecord *ComputeHash(Node *node, int id, string* err);

  /// For testing.
  HashRecord *GetHash(Node *node) const;

  bool RecordHashes(Node *output, const Inputs& inputs, string* err);

  IdHashRecord *GetInputHash(NodeRecord *record, Node *input) const;

  /// Persist the id->path mapping.
  bool WriteId(int id, Node *node, string* err);
  /// Persist the record.
  bool WriteEntry(int id, NodeRecord* record, string* err);

  FILE* file_;

  FileHasher *hasher_;

#if (__cplusplus >= 201103L) || (_MSC_VER >= 1900)
  typedef std::unordered_map<Node*, int> Ids;
#else
  typedef hash_map<Node*, int> Ids;
#endif

  /// Node to id mapping.
  Ids ids_;
  /// Records indexed by node id.
  vector<NodeRecord*> hashes_;

  bool needs_recompaction_;
  const BuildLogUser* user_;
  string path_;
};

#endif //NINJA_HASH_LOG_H_
