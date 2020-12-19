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
#include "directory_tree.h"
#include "tree_container.h"

namespace usvfs::shared
{

fs::path::iterator nextIter(
  const fs::path::iterator &iter, const fs::path::iterator &end)
{
  fs::path::iterator next = iter;
  advanceIter(next, end);
  return next;
}

void advanceIter(
  fs::path::iterator &iter, const fs::path::iterator &end)
{
  ++iter;
  while (iter != end &&
         (iter->wstring() == L"/" || iter->wstring() == L"\\" || iter->wstring() == L"."))
    ++iter;
}


DecomposablePath::DecomposablePath(std::string_view s)
  : m_s(s), m_begin(0), m_end(0)
{
  m_end = nextSeparator(m_begin);
}

bool DecomposablePath::last() const
{
  return (m_end >= m_s.size());
}

void DecomposablePath::next()
{
  m_begin = m_end + 1;
  m_end = nextSeparator(m_begin);
}

std::string_view DecomposablePath::current() const
{
  return {m_s.data() + m_begin, m_end - m_begin};
}

std::size_t DecomposablePath::nextSeparator(std::size_t from) const
{
  while (from < m_s.size()) {
    if (m_s[from] == '/' || m_s[from] == '\\') {
      break;
    }

    ++from;
  }

  return from;
}

}  // namespace
