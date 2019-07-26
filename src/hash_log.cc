// Copyright 2014 Matthias Maennich (matthias@maennich.net).
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

#include "hash_log.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <set>

#include "disk_interface.h"
#include "graph.h"
#include "state.h"
#include "hash_map.h"
#include "metrics.h"
#include "log_user.h"

/// The file banner in the persisted hash log.
static const char kFileSignature[] = "# ninjahash\n";
static const int kCurrentVersion = 6;
static const unsigned kMaxRecordSize = (1 << 19) - 1;

// TODO:  Do not hash files greater than a certain size (16kB?).
// TODO:  Command line argument, do not load hash log.
// TODO:  clang-format

bool HashLog::IdHashRecord::operator==(const IdHashRecord &other) const {
  return id_ == other.id_ && mtime_ == other.mtime_ && value_ == other.value_;
}

bool HashLog::IdHashRecord::operator<(const IdHashRecord &other) const {
  return id_ < other.id_;
}
bool HashLog::IdHashRecord::operator<(int id) const {
    return id_ < id;
}

HashLog::HashLog(FileHasher *hasher)
  : file_(NULL), hasher_(hasher), needs_recompaction_(false)
{}

HashLog::~HashLog() {
  Close();
}

void HashLog::Close() {
  if (file_)
    fclose(file_);
  file_ = NULL;
}

bool HashLog::Load(const std::string &path, State *state, std::string* err) {
  METRIC_RECORD(".ninja_hashes load");
  char buf[kMaxRecordSize + 1];
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) {
    if (errno == ENOENT)
      return true;
    err->assign(strerror(errno));
    return false;
  }

  bool valid_header = true;
  int version = 0;
  if (!fgets(buf, sizeof(buf), f) || fread(&version, 4, 1, f) < 1)
    valid_header = false;
  if (!valid_header || strcmp(buf, kFileSignature) != 0 ||
      version != kCurrentVersion) {
    if (version > 0 && version < kCurrentVersion)
      *err = "hash log version change; rebuilding";
    else
      *err = "bad hash log signature or version; starting over";
    fclose(f);
    unlink(path.c_str());
    // Don't report this as a failure.  An empty hash log just means
    // that we might rebuild stuff we do not really need to.
    return true;
  }

  long offset;
  bool read_failed = false;
  size_t total_record_count = 0;
  size_t unique_record_count = 0;

  for (;;) {
    offset = ftell(f);

    unsigned size;
    if (fread(&size, sizeof(unsigned), 1, f) < 1) {
      if (!feof(f))
        read_failed = true;
      break;
    }
    bool is_hash = (size >> 31) != 0;
    size = size & 0x7FFFFFFF;

    if (fread(buf, size, 1, f) < 1 || size > kMaxRecordSize) {
      read_failed = true;
      break;
    }

    if (is_hash) {
      uint8_t* hash_data = reinterpret_cast<uint8_t*>(buf);
      int id = *(reinterpret_cast<int*>(hash_data));
      hash_data += sizeof(int);
      int max_valid_id = ids_.size() - 1;

      if (id > max_valid_id) {
        read_failed = true;
        break;
      }

      // do some sanity checks
      size_t input_hashes_size = size - sizeof(int);
      size_t size_of_record = sizeof(int) + sizeof(TimeStamp) + sizeof(Hash);
      unsigned hash_count = input_hashes_size/size_of_record;
      if ((hash_count * size_of_record) != input_hashes_size) {
        read_failed = true;
        break;
      }

      if (hash_count == 0) {
        read_failed = true;
        break;
      }

      bool is_new_entry = false;
      NodeRecord *record = GetOrCreateRecord(id, &is_new_entry);
      // We count only the outputs. Later below we create entries in the hash
      // table for the inputs too, but we do not count them.
      ++total_record_count;
      if (is_new_entry)
        ++unique_record_count;

      Inputs &inputs = record->inputs_;
      inputs.resize(hash_count);

      for (unsigned i = 0; i < hash_count; ++i) {
        IdHashRecord &input = inputs[i];

        input.id_ = *(reinterpret_cast<int*>(hash_data));
        hash_data += sizeof(input.id_);
        input.mtime_ = *(reinterpret_cast<TimeStamp*>(hash_data));
        hash_data += sizeof(input.mtime_);
        input.value_ = *(reinterpret_cast<int*>(hash_data));
        hash_data += sizeof(input.value_);

        if (input.id_ > max_valid_id) {
          read_failed = true;
          break;
        }

        // Inputs must be sorted by id.
        if (i > 0 && input.id_ < inputs[i - 1].id_) {
          read_failed = true;
          break;
        }

        // Update the hash for this entry if the mtime is newer.
        HashRecord *hash = GetOrCreateRecord(input.id_);

        if (input.mtime_ > hash->mtime_)
          hash->value_ = input.value_;
      }
    } else {
      int path_size = size - 4;
      if (buf[path_size - 1] == '\0') --path_size;
      if (buf[path_size - 1] == '\0') --path_size;
      if (buf[path_size - 1] == '\0') --path_size;
      StringPiece subpath(buf, path_size);
      Node* node = state->GetNode(subpath, 0);
      unsigned checksum = *reinterpret_cast<unsigned*>(buf + size - 4);
      int expected_id = ~checksum;
      int id = ids_.size();

      if (expected_id != id) {
        read_failed = true;
        break;
      }

      ids_[node] = id;
    }
  }

  if (read_failed) {
    // An error occurred while loading; try to recover by truncating the
    // file to the last fully-read record.
    if (ferror(f)) {
      *err = strerror(ferror(f));
    } else {
      *err = "premature end of file";
    }
    fclose(f);

    if (!Truncate(path, offset, err))
      return false;

    // The truncate succeeded; we'll just report the load error as a
    // warning because the build can proceed.
    *err += "; recovering";
    return true;
  }

  fclose(f);

  // Rebuild the log if there are too many dead records.
  size_t kMinCompactionCount = 1000;
  size_t kCompactionRatio = 3;
  if (total_record_count > kMinCompactionCount &&
      total_record_count > unique_record_count * kCompactionRatio) {
    needs_recompaction_ = true;
  }

  return true;
}

bool HashLog::OpenForWrite(const std::string &path, const BuildLogUser& user,
                           std::string* err) {
  path_ = path;
  user_ = &user;
  file_ = fopen(path.c_str(), "ab");
  if (!file_) {
    *err = strerror(errno);
    return false;
  }
  // Set the buffer size to this and flush the file buffer after every record
  // to make sure records aren't written partially.
  setvbuf(file_, NULL, _IOFBF, kMaxRecordSize + 1);
  SetCloseOnExec(fileno(file_));

  // Opening a file in append mode doesn't set the file pointer to the file's
  // end on Windows. Do that explicitly.
  fseek(file_, 0, SEEK_END);

  if (ftell(file_) == 0) {
    if (fwrite(kFileSignature, sizeof(kFileSignature) - 1, 1, file_) < 1) {
      *err = strerror(errno);
      return false;
    }
    if (fwrite(&kCurrentVersion, sizeof(kCurrentVersion), 1, file_) < 1) {
      *err = strerror(errno);
      return false;
    }
  }
  if (fflush(file_) != 0) {
    *err = strerror(errno);
    return false;
  }
  return true;
}

bool HashLog::RecompactIfNeeded(ImplicitDepLoader &dep_loader, std::string* err) {
  if (!needs_recompaction_ || !user_)
    return true;

  // Open agian as Recompact will close the log
  // Should not really matter if we recompact after the build
  bool ret = Recompact(path_, *user_, dep_loader, err);
  return OpenForWrite(path_, *user_, err) && ret;
}

bool HashLog::Recompact(const std::string &path, const BuildLogUser& user,
                        ImplicitDepLoader &dep_loader, std::string* err) {
  Close();
  string temp_path = path + ".recompact";

  // OpenForWrite() opens for append.  Make sure it's not appending to a
  // left-over file from a previous recompaction attempt that crashed somehow.
  unlink(temp_path.c_str());

  HashLog new_log(NULL);
  if (!new_log.OpenForWrite(temp_path, user, err))
    return false;

  typedef set<IdHashRecord> OrderedInputs;

  // Iterate over current outputs.
  for (Ids::const_iterator i = ids_.begin(); i != ids_.end(); ++i) {
    Edge *edge = i->first->in_edge();

    // Skip nodes that do not use hashes.
    if (!edge || !edge->GetBindingBool("hash_input"))
      continue;

    // Skip over nodes that aren't outputs.
    NodeRecord *record = GetRecord(i->second);

    if (!record || record->inputs_.empty())
      continue;

    if (user.IsPathDead(i->first->path()))
      continue;

    if (edge->mark_ == Edge::VisitNone)
    {
        if (!dep_loader.LoadDeps(edge, err)) {
          if (!err->empty())
            Error("%s", err->c_str());
        }
    }

    OrderedInputs temp_inputs;

    // Extract known hashes for current inputs of recorded outputs.
    for (vector<Node*>::const_iterator j = edge->inputs_.begin();
        j != edge->inputs_.end() - edge->order_only_deps_; ++j) {
      // Get current hash.
      IdHashRecord *old_input = GetInputHash(record, *j);

      // Might be a new input.
      if (!old_input)
        continue;

      // Construct new record from old one.
      IdHashRecord new_input(*old_input);
      new_input.id_ = new_log.GetOrCreateId(*j, err);

      if (new_input.id_ == -1) {
        new_log.Close();
        return false;
      }

      temp_inputs.insert(new_input);

      // Also update the last input hash.
      HashRecord *hash = new_log.GetOrCreateRecord(new_input.id_);

      if (new_input.mtime_ > hash->mtime_)
        hash->value_ = new_input.value_;
    }

    Inputs new_inputs(temp_inputs.begin(), temp_inputs.end());

    if (!new_log.RecordHashes(i->first, new_inputs, err)) {
      new_log.Close();
      return false;
    }
  }
  new_log.Close();

  // new_log now has minimal ids_ and hashes_ so steal its data.
  ids_.swap(new_log.ids_);
  hashes_.swap(new_log.hashes_);

  if (unlink(path.c_str()) < 0) {
    *err = strerror(errno);
    return false;
  }

  if (rename(temp_path.c_str(), path.c_str()) < 0) {
    *err = strerror(errno);
    return false;
  }

  return true;
}

bool HashLog::HashesAreClean(Node *output, Edge* edge,  std::string* reason, std::string* err) {
  METRIC_RECORD("checking hashes");

  // Find the record for this output.
  NodeRecord *record = GetRecord(output);

  // Never seen this node.
  if (!record)
  {
    *reason = "Never seen this node";
    return false;
  }

  bool is_clean = true;
  bool should_rewrite = false;

  // N.B. it may happen that there are less inputs than were recorded
  // previously.  This case can be ignored because it can only be reached if
  // the changed set of inputs didn't change the command.

  // Since we have removed duplicates during generation of hash values in RecordHashes()
  // we also need to remove them here when we compare them
  set<Node*> input_nodes(edge->inputs_.begin(), edge->inputs_.end() - edge->order_only_deps_);
  // Look at all inputs and check if they have been seen before with the same
  // hash.
  for (set<Node*>::const_iterator i = input_nodes.begin();
       i != input_nodes.end(); ++i) {
    // Input does not exist or was not stat()ed.
    if (!(*i)->exists() || !(*i)->status_known()) {
      *reason = "Input does not exist or was not stat()ed";
      is_clean = false;
      break;
    }

    // Get the recorded hash.
    IdHashRecord *recorded_hash = GetInputHash(record, *i);

    // Never seen this node as an input for this output.
    if (!recorded_hash) {
      *reason = "Never seen this node as an input for this output";
      is_clean = false;
      break;
    }

    // mtime matches, assume it's clean.
    if ((*i)->mtime() == recorded_hash->mtime_)
      continue;

    // Get the current hash.
    HashRecord *hash = ComputeHash(*i, recorded_hash->id_, err);

    // Hashing failed.
    if (!hash)
    {
      *reason = "Hashing failed";
      return false;
    }

    // Hash is different.
    if (hash->value_ != recorded_hash->value_) {
      *reason = "Hash is different";
      is_clean = false;
      break;
    }

    // Hash is the same.  Continue checking updated the recorded mtime and
    // remember to rewrite the record later.
    recorded_hash->mtime_ = hash->mtime_;
    should_rewrite = true;
  }

  // At least one input was clean but had to be rehashed because of a different
  // mtime.  If the log is opened for writing rewrite the record so the hashing
  // can be skipped next time.
  if (should_rewrite && file_)
    if (!WriteEntry(GetId(output), record, err))
    {
      *reason = "Had to rehash because of different mtime";
      return false;
    }

  return is_clean;
}

HashLog::IdHashRecord* HashLog::GetInputHash(NodeRecord *record, Node *input) const {
  int id = GetId(input);

  if (id == -1)
    return NULL;

  // Do a binary search to find the input record for this id.
  Inputs::iterator start = record->inputs_.begin();
  Inputs::iterator end = record->inputs_.end();
  Inputs::iterator i = lower_bound(start, end, id);

  if (i != end && i->id_ == id)
    return &(*i);
  else
    return NULL;
}

HashLog::HashRecord *HashLog::GetInputHash(Node *output, Node *input) const {
  NodeRecord *record = GetRecord(output);

  if (!record)
    return NULL;
  else
    return GetInputHash(record, input);
}

HashLog::HashRecord* HashLog::ComputeHash(Node *node, int id, string* err) {
  HashRecord *hash = GetOrCreateRecord(id);

  if (node->mtime() != hash->mtime_) {
    if (hasher_->HashFile(node->path(), &hash->value_, err) != DiskInterface::Okay) {
      *err = "error hashing file: " + *err;
      return NULL;
    }

    hash->mtime_ = node->mtime();
  }

  return hash;
}

HashLog::HashRecord* HashLog::GetHash(Node *node) const {
  int id = GetId(node);

  if (id == -1)
    return NULL;

  int max_hash_id = hashes_.size() - 1;

  if (id > max_hash_id)
    return NULL;

  return hashes_[id];
}

HashLog::NodeRecord *HashLog::GetRecord(Node *node) const {
  int id = GetId(node);

  if (id == -1)
    return NULL;

  return GetRecord(id);
}

HashLog::NodeRecord *HashLog::GetRecord(int id) const {
  int max_id = hashes_.size() - 1;

  if (id > max_id)
    return NULL;

  return hashes_[id];
}

size_t HashLog::GetInputCount(Node *node) const {
  NodeRecord *record = GetRecord(node);

  if (record == NULL)
    return 0;
  else
    return record->inputs_.size();
}

int HashLog::GetId(Node *node) const {
  Ids::const_iterator i = ids_.find(node);

  if (i != ids_.end())
    return i->second;
  else
    return -1;
}

bool HashLog::RecordHashes(Edge* edge, DiskInterface *disk_interface,
                           std::string* err, const std::vector<Node*> &implicit_deps) {
  METRIC_RECORD("recording hashes");

  // Create an temporary, ordered map of input records.
  typedef set<IdHashRecord> OrderedInputs;
  OrderedInputs temp_inputs;

  // Since we do not have any guarantee that a node is not contained in edge->inputs_ as
  // well as implicit_deps we use a set to avoid duplicates
  set<Node*> input_nodes(edge->inputs_.begin(), edge->inputs_.end() - edge->order_only_deps_);
  input_nodes.insert(implicit_deps.begin(), implicit_deps.end());

  for (set<Node*>::const_iterator i = input_nodes.begin();
       i != input_nodes.end(); ++i) {
    IdHashRecord input;

    // Make sure the mtime is up to date.
    if (!(*i)->Stat(disk_interface, err))
      return false;

    // Input does not exist or was not stat()ed, ignore.
    if (!(*i)->exists() || !(*i)->status_known())
      continue;

    // Get the input id.
    input.id_ = GetOrCreateId(*i, err);

    if (input.id_ == -1)
      return false;

    // Get the input hash.
    HashRecord *hash = ComputeHash(*i, input.id_, err);

    if (!hash)
      return false;

    input.HashRecord::operator=(*hash);
    temp_inputs.insert(input);
  }

  Inputs inputs(temp_inputs.begin(), temp_inputs.end());

  // Record these inputs for all outputs.
  for (vector<Node*>::const_iterator i = edge->outputs_.begin(); i != edge->outputs_.end(); ++i) {
    if (!RecordHashes(*i, inputs, err))
      return false;
  }

  return true;
}

int HashLog::GetOrCreateId(Node *node, string* err) {
  int id = GetId(node);

  // Assign a new id.
  if (id == -1) {
    id = ids_.size();

    // Persist the id in the log.
    if (!WriteId(id, node, err)) {
      if (err->empty())
        err->assign(strerror(errno));
      return false;
    }

    ids_[node] = id;
  }

  return id;
}

bool HashLog::WriteId(int id, Node *node, string* err) {
  int path_size = node->path().size();
  int padding = (4 - path_size % 4) % 4;  // Pad path to 4 byte boundary.
  unsigned size = path_size + padding + 4;

  if (size > kMaxRecordSize) {
    err->assign(strerror(ERANGE));
    return false;
  }
  if (fwrite(&size, sizeof(unsigned), 1, file_) < 1)
    return false;
  if (fwrite(node->path().data(), path_size, 1, file_) < 1) {
    assert(node->path().size() > 0);
    return false;
  }
  if (padding && fwrite("\0\0", padding, 1, file_) < 1)
    return false;
  unsigned checksum = ~(unsigned)id;
  if (fwrite(&checksum, sizeof(unsigned), 1, file_) < 1)
    return false;
  if (fflush(file_) != 0)
    return false;

  return true;
}

HashLog::NodeRecord* HashLog::GetOrCreateRecord(int id, bool *is_new_entry) {
  int max_id = hashes_.size() - 1;

  if (id > max_id)
    hashes_.resize(id + 1);

  NodeRecord*& record = hashes_[id];

  if (record == NULL) {
    record = new NodeRecord;
    if (is_new_entry != NULL)
      *is_new_entry = true;
  } else {
      if (is_new_entry != NULL)
        *is_new_entry = false;
  }

  return record;
}

bool HashLog::RecordHashes(Node *output_node, const Inputs& new_inputs, string* err) {
  int id = GetOrCreateId(output_node, err);

  if (id == -1)
    return false;

  NodeRecord *record = GetOrCreateRecord(id);
  bool need_update = false;

  if (record->inputs_.size() == new_inputs.size())
    need_update = !equal(record->inputs_.begin(), record->inputs_.end(), new_inputs.begin());
  else
    need_update = true;

  if (!need_update)
    return true;

  record->inputs_ = new_inputs;

  return WriteEntry(id, record, err);
}

bool HashLog::WriteEntry(int id, NodeRecord *record, string* err) {
  // Do not store empty sets of inputs.
  if (record->inputs_.empty())
    return true;

  // N.B. The record might also have a valid mtime and hash but in that case it
  // is an input to another output and these values are persisted there.

  // size, output id and (id, mtime, hash) for each input
  unsigned size = sizeof(int) + (sizeof(int) + sizeof(TimeStamp) + sizeof(Hash))*record->inputs_.size();

  if (size > kMaxRecordSize) {
    err->assign(strerror(ERANGE));
    return false;
  }

  size |= 0x80000000;  // Hash record: set high bit.

  if (fwrite(&size, sizeof(size), 1, file_) < 1)
    return false;

  int int_id = id;

  if (fwrite(&int_id, sizeof(int_id), 1, file_) < 1)
    return false;

  for (Inputs::const_iterator it = record->inputs_.begin(); it != record->inputs_.end(); ++it) {
    int id_wr = it->id_;
    if (fwrite(&id_wr, sizeof(id_wr), 1, file_) < 1)
      return false;
    TimeStamp timestamp = it->mtime_;
    if (fwrite(&timestamp, sizeof(TimeStamp), 1, file_) < 1)
      return false;
    Hash hash = it->value_;
    if (fwrite(&hash, sizeof(hash), 1, file_) < 1)
      return false;
  }

  if (fflush(file_) != 0)
    return false;

  return true;
}

vector<Node*> HashLog::GetOutputs() const {
  vector<Node*> outputs;

  for (Ids::const_iterator i = ids_.begin(); i != ids_.end(); ++i) {
    NodeRecord *record = GetRecord(i->second);

    if (!record || record->inputs_.empty())
      continue;

    outputs.push_back(i->first);
  }

  return outputs;
}
