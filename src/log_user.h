#ifndef LOG_USER_H_
#define LOG_USER_H_

#include "string_piece.h"

/// Can answer questions about the manifest for the BuildLog.
struct BuildLogUser {
  virtual ~BuildLogUser() {}
  /// Return if a given output is no longer part of the build manifest.
  /// This is only called during recompaction and doesn't have to be fast.
  virtual bool IsPathDead(StringPiece s) const = 0;
};

#endif // LOG_USER_H_
