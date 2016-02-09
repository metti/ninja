// Copyright 2014 Matthias Maennich (matthias@maennich.net).
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

#include <iostream>
#include <algorithm>

#include "disk_interface.h"
#include "graph.h"
#include "state.h"
#include "hash_map.h"
#include "metrics.h"

/// The file banner in the persisted hash log.
static const char kFileSignature[] = "# ninjahashlog\n";
static const int kCurrentVersion = 6;
const unsigned kMaxPathSize = (1 << 19) - 1;

HashLog::HashLog(FileHasher *hasher)
  : next_id_(0), file_(NULL), hasher_(hasher), needs_recompaction_(false)
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
  char buf[kMaxPathSize + 1];
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
    if (version == 1)
      *err = "hash log version change; rebuilding";
    else
      *err = "bad hash log signature or version; starting over";
    fclose(f);
    unlink(path.c_str());
    // Don't report this as a failure.  An empty deps log will cause
    // us to rebuild the outputs anyway.
    return true;
  }

  long offset;
  bool read_failed = false;
  size_t total_entry_count = 0;

  // While reading we need a mapping from id to back to Node.
  map<int, Node*> ids;

  LogEntry *entry = new LogEntry;

  for (;;) {
    offset = ftell(f);

    // Read the entry.
    if (fread(entry, sizeof(*entry), 1, f) < 1) {
      if (!feof(f))
        read_failed = true;
      break;
    }

    bool has_path = (entry->id_ & 0x8000000) != 0;

    entry->id_ &= 0x7FFFFFFF;

    if (has_path) {
      // Read the path.
      unsigned path_size;

      if (fread(&path_size, sizeof(path_size), 1, f) < 1) {
        read_failed = true;
        break;
      }

      if (path_size > kMaxPathSize) {
        read_failed = true;
        errno = ERANGE;
        break;
      }

      if (fread(buf, path_size, 1, f) < 1) {
        read_failed = true;
        break;
      }

      // Strip padding.
      while (path_size > 0 && buf[path_size - 1] == '\0')
        --path_size;

      StringPiece path(buf, path_size);
      Node* node = state->GetNode(path, 0);
      ids[entry->id_] = node;
    }

    map<int, Node*>::iterator it = ids.find(entry->id_);

    if (it == ids.end()) {
      read_failed = true;
      errno = ERANGE;
      break;
    }

    ++total_entry_count;
    pair<Entries::iterator, bool> insert_result = entries_.insert(
        Entries::value_type(it->second->path(), NULL));

    if (insert_result.second) {
      // new entry
      insert_result.first->second = entry;
      entry = new LogEntry;
    } else {
      // overwrite existing entry
      *insert_result.first->second = *entry;
    }
  }

  delete entry;

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
  size_t kMinCompactionEntryCount = 1000;
  size_t kCompactionRatio = 3;
  if (total_entry_count > kMinCompactionEntryCount &&
      total_entry_count > entries_.size() * kCompactionRatio) {
    needs_recompaction_ = true;
  }

  // for (Entries::iterator it = entries_.begin(); it != entries_.end(); ++it)
  //   std::cout << it->first.AsString() << std::endl;

  return true;
}

bool HashLog::OpenForWrite(const std::string &path, std::string* err) {
  file_ = fopen(path.c_str(), "ab");
  if (!file_) {
    *err = strerror(errno);
    return false;
  }
  // Set the buffer size to this and flush the file buffer after every record
  // to make sure records aren't written partially.
  setvbuf(file_, NULL, _IOFBF, kMaxPathSize + 1);
  SetCloseOnExec(fileno(file_));

  // Opening a file in append mode doesn't set the file pointer to the file's
  // end on Windows. Do that explicitly.
  fseek(file_, 0, SEEK_END);

  if (ftell(file_) == 0) {
    // XXX: pad this to the LogEntry size
    if (fwrite(kFileSignature, sizeof(kFileSignature) - 1, 1, file_) < 1) {
      *err = strerror(errno);
      return false;
    }
    if (fwrite(&kCurrentVersion, 4, 1, file_) < 1) {
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

bool HashLog::Recompact(const std::string &path, std::string* err) {
  *err = "not implemented";
  return false;
}

bool HashLog::OutputHashClean(Node *output, Edge* edge, std::string* err) {
  METRIC_RECORD("checking hashes");
  Hash output_hash = 0;

  // Check if any inputs are updated.  Combine their hashes into the hash for
  // the output.
  for (vector<Node*>::const_iterator i = edge->inputs_.begin();
      i != edge->inputs_.end() - edge->order_only_deps_; ++i) {
    if (!HashIsClean(*i, true, &output_hash, err))
      return false;
  }

  return HashIsClean(output, false, &output_hash, err);
}

bool HashLog::RecordHashes(Edge* edge, DiskInterface *disk_interface, std::string* err) {
  METRIC_RECORD("recording hashes");
  Hash output_hash = 0;

  // Record hashes for inputs.  Combine their hashes into the hash for the
  // outputs.
  for (vector<Node*>::const_iterator i = edge->inputs_.begin();
      i != edge->inputs_.end() - edge->order_only_deps_; ++i) {
    if (!(*i)->Stat(disk_interface, err)) {
      *err = "error restatting in hash log: " + *err;
      return false;
    }

    if (!RecordHash(*i, true, &output_hash, err))
      return false;
  }

  // Record hashes for outputs.  Combine their hashes into a seed for the
  // outputs.
  for (vector<Node*>::const_iterator i = edge->outputs_.begin();
      i != edge->outputs_.end(); ++i) {
    if (!(*i)->Stat(disk_interface, err)) {
      *err = "error restatting in hash log: " + *err;
      return false;
    }

    if (!RecordHash(*i, false, &output_hash, err))
      return false;
  }

  return true;
}

/// Check if the node's hash matches the one recorded before.  If the node is
/// an input combine its actual hash it into the accumulator otherwise record the
/// accumulated hash of the inputs.  If the file is opened for writing and
/// the node changed record the new hash.
bool HashLog::HashIsClean(Node* node, bool is_input, Hash *acc, string *err) {
  // Stat should have happened before.
  if (!node->exists() || !node->status_known())
    return false;

  Entries::iterator it = entries_.find(node->path());

  // We do not know about this node yet.
  if (it == entries_.end())
    return false;

  Hash old_hash = is_input ? it->second->input_hash_ : it->second->output_hash_;

  if (it->second->mtime_ != node->mtime()) {
    if (is_input) {
      // Node is an input and it's mtime is newer.  Recompute and record hash.

      if (hasher_->HashFile(node->path(), &it->second->input_hash_, err) != DiskInterface::Okay) {
        *err = "error hashing file: " + *err;
        return false; 
      }
    } else {
      // Node is an output and it's mtime is newer.  Record the combined hash
      // of its inputs.
      it->second->output_hash_ = *acc;
    }

    it->second->mtime_ = node->mtime();

    // Log is opened for writing, go ahead and record the hash since we have it
    // already.
    if (file_ != NULL && !WriteEntry(node, it->second, err))
      return false;
  }

  Hash new_hash;

  if (is_input) {
    new_hash = it->second->input_hash_;
    *acc ^= it->second->input_hash_;
  } else {
    new_hash = it->second->output_hash_;
  }

  return old_hash == new_hash;
}

/// Record the node's hash.  If the node is an input combine its actual hash
/// it into the accumulator otherwise record the accumulated hash of the
/// inputs.
bool HashLog::RecordHash(Node *node, bool is_input, Hash *acc, string *err) {
  Entries::iterator it = entries_.find(node->path());
  LogEntry* entry;

  if (it != entries_.end())
    entry = it->second;
  else
    entry = new LogEntry;

  if (entry->mtime_ != node->mtime()) {
    entry->mtime_ = node->mtime();

    if (is_input) {
      if (hasher_->HashFile(node->path(), &entry->input_hash_, err) != DiskInterface::Okay) {
        *err = "hashing file: " + *err;
        return false; 
      }
    } else {
      entry->output_hash_ = *acc;
    }

    if (!WriteEntry(node, entry, err))
      return false;
  }

  if (it == entries_.end())
    entries_.insert(Entries::value_type(node->path(), entry));

  if (is_input)
    *acc ^= entry->input_hash_;

  return true;
}

static const char padding_data[sizeof(HashLog::LogEntry)] = {0};

bool HashLog::WriteEntry(Node *node, LogEntry *entry, string *err) {
  if (entry->id_ == 0)
    // We haven't seen this node before, record its path and give it an id and
    // mark it as having the path appended.
    entry->id_ = next_id_++ | 0x8000000;

  if (fwrite(entry, 1, sizeof(*entry), file_) < 1) {
      err->assign(strerror(errno));
      return false;
  }

  if (entry->id_ & 0x8000000) {
    const size_t entry_size = sizeof(LogEntry);
    unsigned path_size = node->path().size();

    // Pad path record to size of LogEntry.
    size_t padding_size = (entry_size - (sizeof(path_size) + path_size) % entry_size) % entry_size;
    unsigned record_size = path_size + padding_size;

    if (fwrite(&record_size, sizeof(record_size), 1, file_) < 1) {
      err->assign(strerror(errno));
      return false;
    }

    if (fwrite(node->path().data(), path_size, 1, file_) < 1) {
      err->assign(strerror(errno));
      return false;
    }

    if (padding_size > 0 && fwrite(padding_data, padding_size, 1, file_) < 1) {
      err->assign(strerror(errno));
      return false;
    }

    entry->id_ &= 0x7FFFFFFF;
  }

  if (fflush(file_) != 0) {
    err->assign(strerror(errno));
    return false;
  }

  return true;
}
