#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <functional>
#include <iomanip>
#include <memory>
#include <cstdint>
#include <codecvt>
#include <limits>
#include <algorithm>
#include <atomic>
#include <string>
#include <limits>
#include <type_traits>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <ios>
#include <sstream>
#include <vector>
#include <cassert>
#include <string>
#include <algorithm>
#include <string>
#include <memory>
#include <type_traits>
#include <exception>
#include <vector>
#include <limits>
#include <sstream>
#include <utility>

#ifndef NOMINMAX
  #define NOMINMAX
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <ShlObj.h>
#include <comutil.h>
#include <Psapi.h>

#include <boost/predef.h>
#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/interprocess/smart_ptr/shared_ptr.hpp>
#include <boost/interprocess/smart_ptr/weak_ptr.hpp>
#include <boost/interprocess/smart_ptr/deleter.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/managed_windows_shared_memory.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/container/scoped_allocator.hpp>
#include <boost/interprocess/offset_ptr.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/format.hpp>
#include <boost/type_traits.hpp>
#include <boost/static_assert.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/locale.hpp>

#include <fmt/ostr.h>
#include <spdlog.h>

namespace fs = boost::filesystem;
