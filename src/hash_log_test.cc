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

#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <set>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif

#include "graph.h"
#include "deps_log.h"
#include "hash_log.h"
#include "log_user.h"
#include "test.h"

namespace {

const char kTestFilename[] = "HashLogTest-tempfile";

struct TestHashLog : HashLog {
  explicit TestHashLog(FileHasher *hasher) : HashLog(hasher) {}
  size_t GetOutputCount() const { return GetOutputs().size(); }

  // Expose members needed for the tests.
  using HashLog::GetHash;
  using HashLog::GetRecord;
};

typedef TestHashLog::HashRecord HashRecord;

struct HashLogTest : public testing::Test, public BuildLogUser {
  typedef HashLog::Hash Hash;

  HashLogTest() : log_(&disk_interface_) {}

  void cleanup() {
    unlink(kTestFilename);
  }

  virtual void SetUp() { cleanup(); };
  virtual void TearDown() { cleanup(); };

  virtual bool IsPathDead(StringPiece s) const { return false; }

  VirtualFileSystem disk_interface_;
  TestHashLog log_;
  State state_;
  string err;
  string result;
};

TEST_F(HashLogTest, BasicInOut) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  for (size_t i = 0; i < edge.inputs_.size(); ++i) {
    ASSERT_TRUE(edge.inputs_[i]->Stat(&disk_interface_, &err));
  }

  ASSERT_TRUE(output->Stat(&disk_interface_, &err));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Hashes are dirty before the first build.
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(0u, log_.GetOutputCount());

  // No files have been read.
  ASSERT_TRUE(disk_interface_.files_read_.empty());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());

  // Recording hashes should have read the three input files and nothing more.
  {
    const vector<string> &f = disk_interface_.files_read_;
    ASSERT_EQ(1u, count(f.begin(), f.end(), input1->path()));
    ASSERT_EQ(1u, count(f.begin(), f.end(), input2->path()));
    ASSERT_EQ(1u, count(f.begin(), f.end(), input3->path()));
    ASSERT_EQ(3u, f.size());
  }

  // The hash log should now contain entries for the inputs and the output.
  ASSERT_EQ(3u, log_.GetInputCount(output));

  for (size_t i = 0; i < edge.inputs_.size(); ++i) {
    Node *node = edge.inputs_[i];
    HashRecord *hash = log_.GetInputHash(output, node);
    ASSERT_TRUE(hash);
    ASSERT_EQ(node->mtime(), hash->mtime_);
    ASSERT_NE(0u, hash->value_);
  }

  // Now the hashes should be clean.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Update the first and third input's timestamp.
  disk_interface_.files_[input1->path()].mtime = disk_interface_.Tick();
  ASSERT_TRUE(input1->Stat(&disk_interface_, &err));
  ASSERT_TRUE(err.empty());
  disk_interface_.files_[input3->path()].mtime = disk_interface_.Tick();
  ASSERT_TRUE(input3->Stat(&disk_interface_, &err));
  ASSERT_TRUE(err.empty());

  disk_interface_.files_read_.clear();

  // Now the hashes should still be clean.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // This should have reread these two files.
  {
    const vector<string> &f = disk_interface_.files_read_;
    ASSERT_EQ(1u, count(f.begin(), f.end(), input1->path()));
    ASSERT_EQ(1u, count(f.begin(), f.end(), input3->path()));
    ASSERT_EQ(2u, f.size());
  }

  // mtimes should now be current.
  ASSERT_EQ(3u, log_.GetInputCount(output));

  for (size_t i = 0; i < edge.inputs_.size(); ++i) {
    Node *node = edge.inputs_[i];
    HashRecord *hash = log_.GetInputHash(output, node);
    ASSERT_TRUE(hash);
    ASSERT_EQ(node->mtime(), hash->mtime_);
    ASSERT_NE(0u, hash->value_);
  }

  disk_interface_.files_read_.clear();

  // Yet another check will still succeed but won't read any files.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_TRUE(disk_interface_.files_read_.empty());
}

TEST_F(HashLogTest, WriteRead) {
  // Create an edge with inputs and outputs.
  Edge edge;
  edge.outputs_.push_back(state_.GetNode(std::string("foo.o"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.cc"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.h"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("bar.h"), 0));

  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[0]->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[1]->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[2]->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(edge.outputs_[0]));

  // Close old log object.
  log_.Close();

  // Open log in new object.
  TestHashLog log2(&disk_interface_);

  ASSERT_TRUE(log2.Load(kTestFilename, &state_, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log2.GetOutputCount());
  ASSERT_EQ(3u, log2.GetInputCount(edge.outputs_[0]));

  // Files should still be known to be clean.
  ASSERT_TRUE(log2.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, CheckOnlyFirst) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(output));

  // Update the first and second input.
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo(int) {}"));
  ASSERT_TRUE(input1->Stat(&disk_interface_, &err));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo(int);"));
  ASSERT_TRUE(input2->Stat(&disk_interface_, &err));

  disk_interface_.files_read_.clear();

  // Hashes are now dirty.
  ASSERT_FALSE(log_.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(output));

  // Only the first input should have been read.
  ASSERT_EQ(1u, disk_interface_.files_read_.size());
  ASSERT_EQ(input1->path(), disk_interface_.files_read_[0]);

  // The first inputs's mtime should be cached.
  ASSERT_TRUE(log_.GetHash(input1))
  ASSERT_EQ(input1->mtime(), log_.GetHash(input1)->mtime_);

  // The second inputs's mtime should not be cached.
  ASSERT_TRUE(log_.GetHash(input2))
  ASSERT_NE(input2->mtime(), log_.GetHash(input2)->mtime_);

  // However, the output should not be updated for neither.
  ASSERT_TRUE(log_.GetInputHash(output, input1))
  ASSERT_NE(input1->mtime(), log_.GetInputHash(output, input1)->mtime_)
  ASSERT_TRUE(log_.GetInputHash(output, input2))
  ASSERT_NE(input2->mtime(), log_.GetInputHash(output, input2)->mtime_)
}

TEST_F(HashLogTest, SameInputs) {
  // Create an edge with inputs and outputs.
  Edge edge;
  edge.outputs_.push_back(state_.GetNode(std::string("foo.o"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.cc"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.h"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("bar.h"), 0));

  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[0]->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[1]->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[2]->path(), "void bar();"));

  // Create a second edge with the same inputs but a different output.
  Edge edge2;
  edge2.outputs_.push_back(state_.GetNode(std::string("foo-debug.o"), 0));
  edge2.inputs_ = edge.inputs_;

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes for the first edge.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  // Hashes are clean for the first edge.
  ASSERT_TRUE(log_.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Hashes are still dirty for the second edge.
  ASSERT_FALSE(log_.HashesAreClean(edge2.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes for the second edge.
  ASSERT_TRUE(log_.RecordHashes(&edge2, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  // Update an input's content.
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[2]->path(), "void bar(int);"));
  ASSERT_TRUE(edge.inputs_[2]->Stat(&disk_interface_, &err));

  // Hashes are dirty for both edges.
  ASSERT_FALSE(log_.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_FALSE(log_.HashesAreClean(edge2.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes for the first edge again.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  // Hashes are still dirty for the second edge.
  ASSERT_FALSE(log_.HashesAreClean(edge2.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, RepeatedInput) {
  // Create an edge with inputs and outputs.
  Edge edge;
  edge.outputs_.push_back(state_.GetNode(std::string("foo.o"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.cc"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("foo.h"), 0));
  edge.inputs_.push_back(state_.GetNode(std::string("bar.h"), 0));

  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[0]->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[1]->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[2]->path(), "void bar();"));

  // Append an input a second time.
  edge.inputs_.push_back(state_.GetNode(std::string("bar.h"), 0));

  // Open the log and record hashes.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  // Update the duplicated input's timestamp.
  disk_interface_.files_[edge.inputs_[2]->path()].mtime = disk_interface_.Tick();
  ASSERT_TRUE(edge.inputs_[2]->Stat(&disk_interface_, &err));
  ASSERT_TRUE(err.empty());

  disk_interface_.files_read_.clear();

  // Hashes should still be clean but the file should be reread.
  ASSERT_TRUE(log_.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, disk_interface_.files_read_.size());
  ASSERT_EQ(edge.inputs_[2]->path(), disk_interface_.files_read_[0]);

  // Update the duplicated input's content.
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(edge.inputs_[2]->path(), "void bar(int);"));

  // Hashes should be dirty now.
  ASSERT_TRUE(log_.HashesAreClean(edge.outputs_[0], &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, disk_interface_.files_read_.size());
  ASSERT_EQ(edge.inputs_[2]->path(), disk_interface_.files_read_[0]);
}

TEST_F(HashLogTest, NoInputs) {
  // Create an edge without inputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Edge edge;
  edge.outputs_.push_back(output);

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Hashes are dirty since the node is unknown.
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(0u, log_.GetOutputCount());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  // Nothing is recorded.
  ASSERT_EQ(0u, log_.GetOutputCount());

  // Hashes are clean since the node is now known.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, AddInput) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(2u, log_.GetInputCount(output));

  // Hashes are clean.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Add a new input.
  edge.inputs_.push_back(input3);

  // Hashes are dirty now.
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Record new hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(output));
}

TEST_F(HashLogTest, RemoveInput) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(output));

  // Hashes are clean.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Remove second input.
  edge.inputs_.erase(edge.inputs_.begin() + 1);

  // Hashes are clean, since we do not care about removed inputs.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  // Record new hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(2u, log_.GetInputCount(output));
}

TEST_F(HashLogTest, MissingInput) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);

  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes. A missing input is not an error it just gets ignored.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(2u, log_.GetInputCount(output));

  // Hashes are dirty.
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();

  // Record new hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(3u, log_.GetInputCount(output));

  // Hashes are clean
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, RemovedInputIsDirty) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes. A missing input is not an error it just gets ignored.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  // Hashes are clean.
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_TRUE(disk_interface_.RemoveFile(input1->path()) == 0);

  // HashesAreClean does not do a file stat itself (performance), but it is called inside
  // of RecomputeDirty
  ASSERT_TRUE(edge.inputs_[0]->Stat(&disk_interface_, &err));
  disk_interface_.files_read_.clear();
  // Hashes are dirty
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(0u, disk_interface_.files_read_.size());

  // Record new hashes.
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(1u, log_.GetOutputCount());
  ASSERT_EQ(2u, log_.GetInputCount(output));
  ASSERT_EQ(0u, disk_interface_.files_read_.size());

  // Hashes are dirty
  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, FinishedEgdeWithImplicitDeps) {

  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("bar.cc"), 0);
  Node *output1 = state_.GetNode(std::string("foo.o"), 0);
  Node *output2 = state_.GetNode(std::string("bar.o"), 0);

  Edge edge;
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.outputs_.push_back(output1);
  edge.outputs_.push_back(output2);

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void bar() {}"));
  disk_interface_.Tick();

  // On the initial compile rule execution, Ninja keeps a seperate container of implicit
  // input dependencies. We remove it from the inputs of the edge and add it later again
  Node* implicit_input_node = edge.inputs_.back();
  edge.inputs_.pop_back();

  // Create the container with implicit dependencies
  vector<Node*> implicit_input_nodes;
  implicit_input_nodes.push_back(implicit_input_node);

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  // Record hashes.
  log_.RecordHashes(&edge, &disk_interface_, &err, implicit_input_nodes);
  ASSERT_TRUE(err.empty());

  // Add the node again that we previously used as a implicit input dependency
  edge.inputs_.push_back(implicit_input_node);

  ASSERT_TRUE(log_.HashesAreClean(output1, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
  ASSERT_TRUE(log_.HashesAreClean(output2, &edge, &result, &err));
  ASSERT_TRUE(err.empty());
}

TEST_F(HashLogTest, HashFileSize) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);
  output->set_in_edge(&edge);
  BindingEnv bindings_;
  edge.env_ = &bindings_;
  edge.rule_ = &State::kPhonyRule;
  edge.env_->AddBinding(std::string("hash_input"), std::string("1"));

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  long expected_file_header_size = strlen("# ninjahash\n") + sizeof(int);
  FILE *file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  ASSERT_EQ(file_size, expected_file_header_size);
  fclose(file);

  ASSERT_FALSE(log_.HashesAreClean(output, &edge, &result, &err));

  // Recheck file size
  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  ASSERT_EQ(file_size, expected_file_header_size);
  fclose(file);

  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  fclose(file);
  size_t single_input_entry_size = sizeof(int) + sizeof(TimeStamp) + sizeof(FileHasher::Hash);
  size_t single_paths_entry_size = sizeof(unsigned) + sizeof(unsigned);

  int padding = (4 - output->path().size() % 4) % 4;
  size_t paths_size = output->path().size() + padding;
  for (size_t i = 0; i < edge.inputs_.size(); ++i) {
    padding = (4 - edge.inputs_[i]->path().size() % 4) % 4;
    paths_size += edge.inputs_[i]->path().size() + padding;
  }

  ASSERT_EQ((unsigned long)file_size,
            expected_file_header_size +
            sizeof(int) + sizeof(int) +
            3*single_input_entry_size +
            4*single_paths_entry_size +
            paths_size);

  // Rerecording the same hash should not increase the log size
  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  long file_size_new = ftell(file);
  fclose(file);
  ASSERT_EQ(file_size_new, file_size);

  // Recompacting, remove duplicates

  // Update the first and third input's timestamp.
  // This will append the enteries to the hash as the mtime changed and we use it
  disk_interface_.files_[input1->path()].mtime = disk_interface_.Tick();
  ASSERT_TRUE(input1->Stat(&disk_interface_, &err));
  ASSERT_TRUE(err.empty());
  disk_interface_.files_[input3->path()].mtime = disk_interface_.Tick();
  ASSERT_TRUE(input3->Stat(&disk_interface_, &err));
  ASSERT_TRUE(err.empty());

  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());

  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  file_size_new = ftell(file);
  fclose(file);
  ASSERT_GT(file_size_new, file_size);

  DepsLog deps_log_;
  ImplicitDepLoader dep_loader(&state_, &deps_log_,
                               &disk_interface_,
                               NULL);

  ASSERT_TRUE(log_.Recompact(kTestFilename, *this, dep_loader, &err));
  ASSERT_TRUE(err.empty());

  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  file_size_new = ftell(file);
  fclose(file);
  ASSERT_EQ(file_size_new, file_size);
}

TEST_F(HashLogTest, RecompactRemoveUnused) {
  // Create an edge with inputs and outputs.
  Node *output = state_.GetNode(std::string("foo.o"), 0);
  Node *input1 = state_.GetNode(std::string("foo.cc"), 0);
  Node *input2 = state_.GetNode(std::string("foo.h"), 0);
  Node *input3 = state_.GetNode(std::string("bar.h"), 0);
  Edge edge;
  edge.outputs_.push_back(output);
  edge.inputs_.push_back(input1);
  edge.inputs_.push_back(input2);
  edge.inputs_.push_back(input3);
  output->set_in_edge(&edge);
  BindingEnv bindings_;
  edge.env_ = &bindings_;
  edge.rule_ = &State::kPhonyRule;
  edge.env_->AddBinding(std::string("hash_input"), std::string("1"));

  ASSERT_TRUE(disk_interface_.WriteFile(input1->path(), "void foo() {}"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input2->path(), "void foo();"));
  disk_interface_.Tick();
  ASSERT_TRUE(disk_interface_.WriteFile(input3->path(), "void bar();"));

  // Open the log.
  ASSERT_TRUE(log_.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_TRUE(err.empty());

  ASSERT_TRUE(log_.RecordHashes(&edge, &disk_interface_, &err, std::vector<Node *>()));
  ASSERT_TRUE(err.empty());
  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_NE(log_.GetRecord(output), NULL);
  ASSERT_NE(log_.GetRecord(input1), NULL);
  ASSERT_NE(log_.GetRecord(input2), NULL);
  ASSERT_NE(log_.GetRecord(input3), NULL);

  FILE *file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fclose(file);

  // Remove second input.
  edge.inputs_.erase(edge.inputs_.begin() + 1);

  DepsLog deps_log_;
  ImplicitDepLoader dep_loader(&state_, &deps_log_,
                               &disk_interface_,
                               NULL);

  ASSERT_TRUE(log_.Recompact(kTestFilename, *this, dep_loader, &err));
  ASSERT_TRUE(err.empty());

  ASSERT_TRUE(log_.HashesAreClean(output, &edge, &result, &err));
  ASSERT_NE(log_.GetRecord(output), NULL);
  ASSERT_NE(log_.GetRecord(input1), NULL);
  ASSERT_EQ(log_.GetRecord(input2), NULL);
  ASSERT_NE(log_.GetRecord(input3), NULL);

  file = fopen(kTestFilename, "rb");
  fseek(file, 0, SEEK_END);
  long file_size_new = ftell(file);
  fclose(file);
  ASSERT_GT(file_size, file_size_new);
}

// test to be done:
// * check hashes without opening for write

}  // anonymous namespace
