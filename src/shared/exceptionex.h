/*
Userspace Virtual Filesystem

Copyright (C) 2015 Sebastian Herbord. All rights reserved.

This file is part of usvfs.

usvfs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

usvfs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "logging.h"
#include <boost/exception/all.hpp>
#include <stdexcept>

/*
namespace MyBoostFake
{
  struct error_base
  {
  };

  template <typename TagT, typename ValueT>
  struct error_info : error_base
  {
    typedef ValueT value_type;
    error_info(const ValueT&) {}
  };

  class exception : virtual std::exception
  {
  };

  template <class ExceptionT, class TagT, typename ValueT>
  const ExceptionT &operator<<(const ExceptionT &ex, const error_info<TagT, ValueT> &val) {
    return ex;
  }

  template <class InfoT, class ExceptionT>
  typename InfoT::value_type *get_error_info(const ExceptionT &ex) {
    static InfoT::value_type def;
    return &def;
  }

}

namespace MyBoost = MyBoostFake;
*/
namespace MyBoost = boost;

//#ifdef _MSC_VER
typedef MyBoost::error_info<struct tag_message, DWORD> ex_win_errcode;
//#endif // _MSC_VER
typedef MyBoost::error_info<struct tag_message, std::string> ex_msg;

struct std_boost_exception : virtual MyBoost::exception, virtual std::exception
{
  const char* what() const noexcept override {
    return MyBoost::diagnostic_information_what(*this);
  }
};

struct incompatibility_error : std_boost_exception {};
struct usage_error : std_boost_exception {};
struct data_error : std_boost_exception {};
struct file_not_found_error : std_boost_exception {};
struct timeout_error : std_boost_exception {};
struct unknown_error : std_boost_exception {};
struct node_missing_error : std_boost_exception {};



#define USVFS_THROW_EXCEPTION(x) BOOST_THROW_EXCEPTION(x)

#ifdef BOOST_NO_EXCEPTIONS
namespace boost
{
inline void throw_exception(const std::exception &e) {
  throw e;
}
}
#endif

void logExtInfo(const std::exception &e, LogLevel logLevel = LogLevel::Warning);


namespace usvfs::shared
{

class windows_error : public std::runtime_error {
public:
  windows_error(const std::string& message, int errorcode = GetLastError())
    : runtime_error(constructMessage(message, errorcode)), m_ErrorCode(errorcode)
  {}
  int getErrorCode() const { return m_ErrorCode; }
private:
  std::string constructMessage(const std::string& input, int errorcode);
private:
  int m_ErrorCode;
};


class guard
{
public:
  explicit guard(std::function<void ()> f)
    : m_f(std::move(f))
  {
  }

  ~guard()
  {
    if (m_f) {
      m_f();
    }
  }

  guard(const guard&);
  guard& operator=(const guard&);

private:
  std::function<void ()> m_f;
};

} // namespace

#define CONCATENATE_DIRECT(s1, s2) s1##s2
#define CONCATENATE(s1, s2) CONCATENATE_DIRECT(s1, s2)
#define ANONYMOUS_VARIABLE(str) CONCATENATE(str, __LINE__)
#define ON_BLOCK_EXIT(f) usvfs::shared::guard ANONYMOUS_VARIABLE(guard)(f)
