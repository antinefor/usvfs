#include <sharedparameters.h>
#include <usvfsparametersprivate.h>
#include <logging.h>
#include <boost/algorithm/string/predicate.hpp>
#include <spdlog.h>

namespace usvfs
{

ForcedLibrary::ForcedLibrary(
  const std::string& process, const std::string& path,
  const shared::VoidAllocatorT& alloc) :
  m_processName(process.begin(), process.end(), alloc),
  m_libraryPath(path.begin(), path.end(), alloc)
{
}

std::string ForcedLibrary::processName() const
{
  return {m_processName.begin(), m_processName.end()};
}

std::string ForcedLibrary::libraryPath() const
{
  return {m_libraryPath.begin(), m_libraryPath.end()};
}


SharedParameters::SharedParameters(const usvfsParameters& reference,
  const shared::VoidAllocatorT &allocator)
  : m_instanceName(reference.instanceName, allocator)
  , m_currentSHMName(reference.currentSHMName, allocator)
  , m_currentInverseSHMName(reference.currentInverseSHMName, allocator)
  , m_debugMode(reference.debugMode)
  , m_logLevel(reference.logLevel)
  , m_crashDumpsType(reference.crashDumpsType)
  , m_crashDumpsPath(reference.crashDumpsPath, allocator)
  , m_delayProcess(reference.delayProcessMs)
  , m_userCount(1)
  , m_processBlacklist(allocator)
  , m_processList(allocator)
  , m_forcedLibraries(allocator)
{
}

usvfsParameters SharedParameters::makeLocal() const
{
  return usvfsParameters(
    m_instanceName.c_str(),
    m_currentSHMName.c_str(),
    m_currentInverseSHMName.c_str(),
    m_debugMode, m_logLevel, m_crashDumpsType,
    m_crashDumpsPath.c_str(),
    m_delayProcess.count());
}

std::string SharedParameters::instanceName() const
{
  return {m_instanceName.begin(), m_instanceName.end()};
}

std::string SharedParameters::currentSHMName() const
{
  return {m_currentSHMName.begin(), m_currentSHMName.end()};
}

std::string SharedParameters::currentInverseSHMName() const
{
  return {m_currentInverseSHMName.begin(), m_currentInverseSHMName.end()};
}

void SharedParameters::setSHMNames(
  const std::string& current, const std::string& inverse)
{
  m_currentSHMName.assign(current.begin(), current.end());
  m_currentInverseSHMName.assign(inverse.begin(), inverse.end());
}

void SharedParameters::setDebugParameters(
  LogLevel level, CrashDumpsType dumpType, const std::string& dumpPath,
  std::chrono::milliseconds delayProcess)
{
  m_logLevel = level;
  m_crashDumpsType = dumpType;
  m_crashDumpsPath.assign(dumpPath.begin(), dumpPath.end());
  m_delayProcess = delayProcess;
}

std::size_t SharedParameters::userConnected()
{
  return ++m_userCount;
}

std::size_t SharedParameters::userDisconnected()
{
  return --m_userCount;
}

std::size_t SharedParameters::userCount()
{
  return m_userCount;
}

std::size_t SharedParameters::registeredProcessCount() const
{
  return m_processList.size();
}

std::vector<DWORD> SharedParameters::registeredProcesses() const
{
  return {m_processList.begin(), m_processList.end()};
}

void SharedParameters::registerProcess(DWORD pid)
{
  m_processList.insert(pid);
}

void SharedParameters::unregisterProcess(DWORD pid)
{
  auto itor = m_processList.find(pid);

  if (itor == m_processList.end()) {
    spdlog::get("usvfs")->error(
      "cannot unregister process {}, not in list", pid);

    return;
  }

  m_processList.erase(itor);
}

void SharedParameters::blacklistExecutable(const std::string& name)
{
  m_processBlacklist.insert(shared::StringT(
    name.begin(), name.end(), m_processBlacklist.get_allocator()));
}

void SharedParameters::clearExecutableBlacklist()
{
  m_processBlacklist.clear();
}

bool SharedParameters::executableBlacklisted(
  const std::string& appName, const std::string& cmdLine) const
{
  for (const shared::StringT& sitem : m_processBlacklist) {
    const auto item = "\\" + std::string(sitem.begin(), sitem.end());

    if (!appName.empty()) {
      if (boost::algorithm::iends_with(appName, item)) {
        spdlog::get("usvfs")->info("application {} is blacklisted", appName);
        return true;
      }
    }

    if (!cmdLine.empty()) {
      if (boost::algorithm::icontains(cmdLine, item)) {
        spdlog::get("usvfs")->info("command line {} is blacklisted", cmdLine);
        return true;
      }
    }
  }

  return false;
}

void SharedParameters::addForcedLibrary(
  const std::string& processName, const std::string& libraryPath)
{
  m_forcedLibraries.push_front(ForcedLibrary(
    processName, libraryPath, m_forcedLibraries.get_allocator()));
}

std::vector<std::string> SharedParameters::forcedLibraries(
  const std::string& processName)
{
  std::vector<std::string> v;

  for (const auto& lib : m_forcedLibraries) {
    if (boost::algorithm::iequals(processName, lib.processName())) {
      v.push_back(lib.libraryPath());
    }
  }

  return v;
}

void SharedParameters::clearForcedLibraries()
{
  m_forcedLibraries.clear();
}

} // namespace
