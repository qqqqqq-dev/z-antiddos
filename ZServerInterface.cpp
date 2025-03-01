#include <comdef.h>
#include <cstdio>
#include <ctime>
#include <map>
#include <mutex>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <set>
#include <string>
#include <vector>
#include <windows.h>

typedef unsigned int uint32;
typedef unsigned short uint16;

#define ZSERVERINTERFACE_VERSION 1

char logPath[MAX_PATH];
bool comInitialized = false;
bool firewallEnabled = false;

struct ServerInfo {
  std::wstring name;
  std::wstring path;
  std::wstring cmd;
  uint16 gamePort;
  std::string login; // Храним логин как строку ASCII
  uint32 serverId; // ID сервера, получаемый в OnServerAuthed
  std::map<uint32, uint32> playerIPs;
};

std::map<std::string, ServerInfo> servers; // login -> ServerInfo
std::mutex serversMutex;
std::mutex processedDisconnectsMutex;
std::mutex processedMutex;
std::set<std::pair<uint32, uint32>>
    processedDisconnects; // (serverID, playerID)

// Функция для создания консоли и файла
void CreateConsoleAndFile() {
  // Создание консоли
  if (AllocConsole()) {
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleTitleW(L"Z-ANTIDDOS SERVICE | (C) WELL DEV & ZLOFENIX | "
                     L"COMMUNITY VERSION 1.0");
    wprintf(L"Host your servers on wellcloud.io and get the professional "
            L"version of Z-ANTIDDOS for free\n\n");
    wprintf(
        L"With the professional version, the rules will be created not on "
        L"your machine, but at the wellcloud network level, which will "
        L"prevent your server's bandwith from being overloaded, ensuring you "
        L"stay online even during the strongest attacks\n\n");
  } else {
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    // wprintf(L"Using existing console...\n");
  }

  // Открытие файла для записи рядом с exe
  GetModuleFileNameA(NULL, logPath,
                     MAX_PATH); // Получаем путь к текущему исполняемому файлу
  char *lastSlash = strrchr(logPath, '\\');
  if (lastSlash) {
    *(lastSlash + 1) = 0; // Обрезаем путь до каталога
  }
  strcat(logPath, "Z-ANTIDDOS.log"); // Имя файла в том же каталоге

  FILE *file = fopen(logPath, "w"); // Открываем файл для записи
  if (file) {
    time_t now = time(0);
    struct tm *tstruct = localtime(&now); // Получаем текущее время

    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", tstruct);

    fprintf(file, "[%s] Z-ANTIDDOS service loaded\n", buf);
    fprintf(file, "[%s] Process ID: %u\n", buf, GetCurrentProcessId());
    fclose(file); // Закрываем файл
  } else {
    wprintf(L"Failed to open log file\n");
  }
}

std::mutex lockLog;
// Функция для логирования
void LogMessage(const char *fmt, ...) {
  va_list arg;
  va_start(arg, fmt);
  std::lock_guard<std::mutex> G(lockLog);
  FILE *file = fopen(logPath, "a"); // Открываем файл для добавления
  if (file) {
    time_t now = time(0);
    struct tm *tstruct = localtime(&now);

    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", tstruct);

    fprintf(file, "[%s] ", buf);
    vfprintf(file, fmt, arg);
    fprintf(file, "\n");
    fclose(file);
  }

  // Вывод в консоль
  vprintf(fmt, arg);
  printf("\n");
  va_end(arg);
}

// Инициализация COM
bool InitializeCOM() {
  if (comInitialized) {
    return true;
  }

  HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
  if (FAILED(hr)) {
    LogMessage("CoInitializeEx failed: 0x%08lx", hr);
    return false;
  }

  comInitialized = true;
  return true;
}

// Освобождение COM
void UninitializeCOM() {
  if (comInitialized) {
    CoUninitialize();
    comInitialized = false;
  }
}

bool IsFirewallEnabled() {
  LogMessage("Checking if Windows Firewall is enabled...");

  try {
    HKEY hKey;
    DWORD dwType;
    DWORD dwValue;
    DWORD dwSize = sizeof(DWORD);

    // Открываем ключ реестра, где хранится настройка брандмауэра
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Pa"
                      "rameters\\FirewallPolicy\\StandardProfile",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {

      // Читаем значение EnableFirewall
      if (RegQueryValueExA(hKey, "EnableFirewall", NULL, &dwType,
                           (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        bool enabled = (dwValue != 0);
        LogMessage("Windows Firewall is %s (registry check)",
                   enabled ? "enabled" : "disabled");
        return enabled;
      }
      RegCloseKey(hKey);
    }
  } catch (...) {
    LogMessage("Exception checking firewall in registry");
  }

  // Если реестр не помог, попробуем API брандмауэра с безопасными проверками
  try {
    // Инициализируем COM внутри этой функции
    // LogMessage("Initializing COM for firewall check");
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage("COM initialization failed: 0x%08lx", hr);
      return false;
    }

    // Создаем экземпляр NetFwMgr с дополнительными проверками
    // LogMessage("Creating NetFwMgr instance (safe mode)");
    INetFwMgr *fwMgr = NULL;
    hr = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwMgr), (void **)&fwMgr);

    if (SUCCEEDED(hr) && fwMgr != NULL) {
      // Получаем локальную политику
      INetFwPolicy *fwPolicy = NULL;
      hr = fwMgr->get_LocalPolicy(&fwPolicy);

      if (SUCCEEDED(hr) && fwPolicy != NULL) {
        // Получаем текущий профиль
        INetFwProfile *fwProfile = NULL;
        hr = fwPolicy->get_CurrentProfile(&fwProfile);

        if (SUCCEEDED(hr) && fwProfile != NULL) {
          // Проверяем, включен ли брандмауэр
          VARIANT_BOOL fwEnabled = VARIANT_FALSE;
          hr = fwProfile->get_FirewallEnabled(&fwEnabled);

          if (SUCCEEDED(hr)) {
            bool result = (fwEnabled == VARIANT_TRUE);
            LogMessage("Windows Firewall is %s (API check)",
                       result ? "enabled" : "disabled");

            // Освобождаем ресурсы
            fwProfile->Release();
            fwPolicy->Release();
            fwMgr->Release();
            CoUninitialize();

            return result;
          }

          if (fwProfile)
            fwProfile->Release();
        }

        if (fwPolicy)
          fwPolicy->Release();
      }

      if (fwMgr)
        fwMgr->Release();
    }

    // Освобождаем COM
    CoUninitialize();
  } catch (...) {
    LogMessage("Exception in IsFirewallEnabled() API check");
  }

  // Если все методы не сработали, предполагаем, что брандмауэр выключен
  LogMessage("Could not determine firewall status, assuming it's disabled");
  return false;
}

// Извлечение порта из командной строки сервера
uint16 ExtractGamePort(const std::wstring &cmd) {
  // LogMessage("Extracting game port from command: %S", cmd.c_str());

  // Ищем параметр -GamePort с последующим числом
  size_t pos = cmd.find(L"-GamePort");
  if (pos == std::wstring::npos) {
    LogMessage("GamePort parameter not found");
    return 0; // Порт не найден
  }

  // Ищем начало номера порта после "-GamePort"
  size_t startPos = pos + 9; // длина "-GamePort"

  // Пропускаем пробелы
  while (startPos < cmd.length() && iswspace(cmd[startPos])) {
    startPos++;
  }

  // Если достигнут конец строки, порт не найден
  if (startPos >= cmd.length()) {
    LogMessage("No port number after GamePort parameter");
    return 0;
  }

  // Читаем число порта
  std::wstring portStr;
  while (startPos < cmd.length() && iswdigit(cmd[startPos])) {
    portStr += cmd[startPos];
    startPos++;
  }

  // Преобразуем строку в число
  if (portStr.empty()) {
    LogMessage("Empty port number");
    return 0;
  }

  try {
    uint16 port = static_cast<uint16>(std::stoi(portStr));
    //   LogMessage("Extracted port: %d", port);
    return port;
  } catch (...) {
    LogMessage("Failed to convert port string to number");
    return 0;
  }
}

bool ClearAllowRulesForServer(const wchar_t *ruleName) {
  // LogMessage("Clearing all allow rules for server rule: %S", ruleName);

  if (!firewallEnabled) {
    LogMessage("Firewall is disabled, cannot clear rules");
    return false;
  }

  HRESULT hr = S_OK;
  bool result = false;
  INetFwPolicy2 *pNetFwPolicy2 = NULL;
  INetFwRules *pFwRules = NULL;

  try {
    // Инициализируем COM внутри этой функции
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage(
          "COM initialization failed in ClearAllowRulesForServer: 0x%08lx", hr);
      return false;
    }

    LogMessage("Creating NetFwPolicy2 instance...");
    // Создание экземпляра Firewall Policy
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void **)&pNetFwPolicy2);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx", hr);
      CoUninitialize();
      return false;
    }

    LogMessage("Getting rules collection...");
    // Получение коллекции правил
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
      LogMessage("get_Rules failed: 0x%08lx", hr);
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Шаблон для поиска правил
    std::wstring rulePattern = std::wstring(ruleName) + L"-Allow-";
    LogMessage("Looking for rules with pattern: %S", rulePattern.c_str());

    // Получаем все правила и ищем те, которые соответствуют шаблону
    std::vector<std::wstring> rulesToRemove;

    // Более надежный способ перебора правил
    INetFwRule *pRule = NULL;
    VARIANT_BOOL currentProfileOnly = VARIANT_FALSE;

    // Получаем количество правил
    LONG count = 0;
    hr = pFwRules->get_Count(&count);
    if (FAILED(hr)) {
      LogMessage("Failed to get rules count: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    LogMessage("Total firewall rules: %d", count);

    // Используем более простой подход с временным хранением имен
    IEnumVARIANT *pEnum = NULL;
    IUnknown *pUnk = NULL;
    VARIANT var;
    VariantInit(&var);

    // Получаем _NewEnum интерфейс
    hr = pFwRules->get__NewEnum(&pUnk);
    if (FAILED(hr) || !pUnk) {
      LogMessage("Failed to get _NewEnum interface: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    pUnk->Release();

    if (FAILED(hr) || !pEnum) {
      LogMessage("Failed to get IEnumVARIANT interface: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Перебираем правила и сохраняем имена тех, которые нужно удалить
    ULONG fetched = 0;
    int matchingRules = 0;

    while (pEnum->Next(1, &var, &fetched) == S_OK && fetched > 0) {
      if (var.vt == VT_DISPATCH) {
        INetFwRule *pRule = NULL;
        hr =
            var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void **)&pRule);

        if (SUCCEEDED(hr) && pRule) {
          BSTR name = NULL;
          hr = pRule->get_Name(&name);

          if (SUCCEEDED(hr) && name) {
            std::wstring nameStr(name);

            // Проверяем соответствие паттерну
            if (nameStr.find(rulePattern) == 0) {
              rulesToRemove.push_back(nameStr);
              matchingRules++;
              LogMessage("Found matching rule: %S", nameStr.c_str());
            }

            SysFreeString(name);
          }

          pRule->Release();
        }
      }

      VariantClear(&var);
    }

    pEnum->Release();

    LogMessage("Found %d rules matching pattern", matchingRules);

    // Удаляем найденные правила
    if (!rulesToRemove.empty()) {
      LogMessage("Removing %d matching rules", rulesToRemove.size());

      for (const auto &name : rulesToRemove) {
        BSTR bstrName = SysAllocString(name.c_str());

        if (bstrName) {
          hr = pFwRules->Remove(bstrName);

          if (SUCCEEDED(hr)) {
            LogMessage("Successfully removed rule: %S", name.c_str());
          } else {
            LogMessage("Failed to remove rule %S: 0x%08lx", name.c_str(), hr);
          }

          SysFreeString(bstrName);
        }
      }

      result = true;
    } else {
      LogMessage("No matching rules found to remove");
      result = true; // Считаем успех
    }

    // Освобождаем ресурсы
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
  } catch (const std::exception &ex) {
    LogMessage("Exception in ClearAllowRulesForServer: %s", ex.what());

    // Освобождаем ресурсы в случае исключения
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
    return false;
  } catch (...) {
    LogMessage("Unknown exception in ClearAllowRulesForServer()");

    // Освобождаем ресурсы в случае исключения
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
    return false;
  }

  return result;
}

// Функция CreateFirewallRule (полная)
bool CreateFirewallRule(const wchar_t *ruleName, uint16 port,
                        bool allowAll = false) {
  LogMessage("Creating firewall rule: %S for port %d (allowAll=%d)", ruleName,
             port, allowAll);

  if (!firewallEnabled) {
    LogMessage("Firewall is disabled, cannot create rule");
    return false;
  }

  HRESULT hr = S_OK;
  bool result = false;
  INetFwPolicy2 *pNetFwPolicy2 = NULL;
  INetFwRules *pFwRules = NULL;
  INetFwRule *pFwRule = NULL;

  try {
    // Инициализируем COM внутри этой функции
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage("COM initialization failed in CreateFirewallRule: 0x%08lx",
                 hr);
      return false;
    }

    LogMessage("Creating NetFwPolicy2 instance...");
    // Создание экземпляра Firewall Policy
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void **)&pNetFwPolicy2);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx", hr);
      CoUninitialize();
      return false;
    }

    LogMessage("Getting rules collection...");
    // Получение коллекции правил
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
      LogMessage("get_Rules failed: 0x%08lx", hr);
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    LogMessage("Creating new rule instance...");
    // Создание нового правила
    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwRule), (void **)&pFwRule);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwRule failed: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    LogMessage("Configuring rule...");
    // Настройка правила
    pFwRule->put_Name(_bstr_t(ruleName));
    pFwRule->put_Description(_bstr_t(L"Z-ANTIDDOS protection rule"));
    pFwRule->put_ApplicationName(NULL);
    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);

    // Преобразуем порт в строку
    std::wstring portStr = std::to_wstring(port);
    LogMessage("Setting port: %S", portStr.c_str());
    pFwRule->put_LocalPorts(_bstr_t(portStr.c_str()));

    pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
    pFwRule->put_Enabled(VARIANT_TRUE);

    // Устанавливаем действие (разрешить всем или запретить всем)
    if (allowAll) {
      LogMessage("Setting action to ALLOW");
      pFwRule->put_Action(NET_FW_ACTION_ALLOW);
      // Для правила "разрешить всем" устанавливаем RemoteAddresses в "*"
      pFwRule->put_RemoteAddresses(_bstr_t(L"*"));
    } else {
      LogMessage("Setting action to BLOCK");
      pFwRule->put_Action(NET_FW_ACTION_BLOCK);
      // Для правила "запретить всем" также устанавливаем RemoteAddresses в
      // "*"
      pFwRule->put_RemoteAddresses(_bstr_t(L"*"));
    }

    LogMessage("Adding rule to collection...");
    // Добавление правила в коллекцию
    hr = pFwRules->Add(pFwRule);
    if (FAILED(hr)) {
      LogMessage("Add rule failed: 0x%08lx", hr);
      if (pFwRule)
        pFwRule->Release();
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    LogMessage("%s firewall rule created for port %d",
               allowAll ? "Allow" : "Block", port);
    result = true;

    // Освобождение ресурсов
    if (pFwRule)
      pFwRule->Release();
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();
    CoUninitialize();
  } catch (...) {
    LogMessage("Exception in CreateFirewallRule()");
    // Освобождение ресурсов в случае исключения
    if (pFwRule)
      pFwRule->Release();
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();
    CoUninitialize();
    return false;
  }

  return result;
}

bool CleanupFirewallRules(uint16 gamePort, const wchar_t *serverName) {
  // LogMessage("Performing complete firewall rules cleanup for port %d",
  // gamePort);

  if (!firewallEnabled) {
    //    LogMessage("Firewall is disabled, skipping cleanup");
    return false;
  }

  try {
    // Создаем короткую аббревиатуру из имени сервера для правила
    std::wstring serverInitial = std::wstring(serverName).substr(0, 1);

    // Шаблоны имен правил для поиска и удаления
    std::vector<std::wstring> patterns = {
        L"Game-Block-Port" + std::to_wstring(gamePort),
        L"Game-" + serverInitial + L"-Port" + std::to_wstring(gamePort),
        L"Z-ANTIDDOS-" + std::wstring(serverName) + L"-" +
            std::to_wstring(gamePort),
        L"Z-ANTIDDOS-server-" + std::to_wstring(gamePort)};

    // Инициализируем COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage("COM initialization failed: 0x%08lx", hr);
      return false;
    }

    // Создаем экземпляр Firewall Policy
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void **)&pNetFwPolicy2);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx", hr);
      CoUninitialize();
      return false;
    }

    // Получаем коллекцию правил
    INetFwRules *pFwRules = NULL;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
      LogMessage("get_Rules failed: 0x%08lx", hr);
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Получаем все правила и обрабатываем те, что соответствуют шаблонам
    IEnumVARIANT *pEnum = NULL;
    IUnknown *pUnk = NULL;
    VARIANT var;
    VariantInit(&var);

    // Получаем интерфейс перечисления
    hr = pFwRules->get__NewEnum(&pUnk);
    if (FAILED(hr) || !pUnk) {
      LogMessage("Failed to get enumeration interface: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    pUnk->Release();

    if (FAILED(hr) || !pEnum) {
      LogMessage("Failed to get IEnumVARIANT: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Перебираем все правила и сохраняем имена тех, что подходят для удаления
    std::vector<std::wstring> rulesToRemove;
    ULONG fetched = 0;

    while (pEnum->Next(1, &var, &fetched) == S_OK && fetched > 0) {
      if (var.vt == VT_DISPATCH) {
        INetFwRule *pRule = NULL;
        hr =
            var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void **)&pRule);

        if (SUCCEEDED(hr) && pRule) {
          BSTR name = NULL;
          hr = pRule->get_Name(&name);

          if (SUCCEEDED(hr) && name) {
            std::wstring nameStr(name);

            // Проверяем соответствие любому из шаблонов
            for (const auto &pattern : patterns) {
              if (nameStr.find(pattern) != std::wstring::npos) {
                //    LogMessage("Found rule to remove: %S",
                //    nameStr.c_str());
                rulesToRemove.push_back(nameStr);
                break;
              }
            }

            // Также ищем правила "Allow" для этого порта
            if (nameStr.find(L"-Allow-") != std::wstring::npos &&
                nameStr.find(std::to_wstring(gamePort)) != std::wstring::npos) {
              //   LogMessage("Found allow rule to remove: %S",
              //   nameStr.c_str());
              rulesToRemove.push_back(nameStr);
            }

            SysFreeString(name);
          }

          pRule->Release();
        }
      }

      VariantClear(&var);
    }

    pEnum->Release();

    // Удаляем найденные правила
    if (!rulesToRemove.empty()) {
      //   LogMessage("Removing %d matching rules", rulesToRemove.size());

      for (const auto &name : rulesToRemove) {
        BSTR bstrName = SysAllocString(name.c_str());

        if (bstrName) {
          hr = pFwRules->Remove(bstrName);

          if (SUCCEEDED(hr)) {
            //       LogMessage("Successfully removed rule: %S",
            //       name.c_str());
          } else {
            LogMessage("Failed to remove rule %S: 0x%08lx", name.c_str(), hr);
          }

          SysFreeString(bstrName);
        }
      }
    } else {
      //  LogMessage("No matching rules found to remove");
    }

    // Освобождаем ресурсы
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
    return true;
  } catch (...) {
    LogMessage("Exception in CleanupFirewallRules");
    CoUninitialize();
    return false;
  }
}

// Вспомогательная функция для поиска и удаления IP из списка
bool FindAndRemoveIPFromList(const std::wstring &addresses,
                             const std::wstring &ipToRemove,
                             std::wstring &result) {
  // Проверяем различные варианты положения IP в списке

  // 1. IP в начале списка: "IP,..."
  if (addresses.substr(0, ipToRemove.length()) == ipToRemove &&
      addresses.length() > ipToRemove.length() &&
      addresses[ipToRemove.length()] == L',') {
    result = addresses.substr(ipToRemove.length() + 1);
    return true;
  }

  // 2. IP в конце списка: "...,IP"
  if (addresses.length() >= ipToRemove.length() + 1 &&
      addresses[addresses.length() - ipToRemove.length() - 1] == L',' &&
      addresses.substr(addresses.length() - ipToRemove.length()) ==
          ipToRemove) {
    result = addresses.substr(0, addresses.length() - ipToRemove.length() - 1);
    return true;
  }

  // 3. IP в середине списка: "...,IP,..."
  std::wstring pattern = L"," + ipToRemove + L",";
  size_t pos = addresses.find(pattern);
  if (pos != std::wstring::npos) {
    result = addresses.substr(0, pos + 1) +
             addresses.substr(pos + pattern.length() - 1);
    return true;
  }

  return false;
}

// Вспомогательная функция для очистки списка IP-адресов
void CleanupIPAddressList(std::wstring &addresses) {
  // Удаляем последовательные запятые
  size_t pos = addresses.find(L",,");
  while (pos != std::wstring::npos) {
    addresses.erase(pos, 1);
    pos = addresses.find(L",,", pos);
  }

  // Удаляем запятую в начале
  if (!addresses.empty() && addresses[0] == L',') {
    addresses.erase(0, 1);
  }

  // Удаляем запятую в конце
  if (!addresses.empty() && addresses[addresses.length() - 1] == L',') {
    addresses.erase(addresses.length() - 1, 1);
  }

  // Если список пустой, оставляем его пустым (не заменяем на wildcard)
  // Или если там только "*", тоже считаем его пустым
}

/// Обновленная AddIPToAllowRule для корректной обработки масок IP:
bool AddIPToAllowRule(const wchar_t *ruleName, uint32 ip, uint16 port) {
  // Преобразование IP в строку
  unsigned char *bytes = (unsigned char *)&ip;
  char ip_str[16];
  sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);

  // LogMessage("Adding IP %s to rule %S", ip_str, ruleName);

  if (!firewallEnabled) {
    //   LogMessage("Firewall is disabled, cannot update rule");
    return false;
  }

  HRESULT hr = S_OK;
  bool result = false;
  INetFwPolicy2 *pNetFwPolicy2 = NULL;
  INetFwRules *pFwRules = NULL;
  INetFwRule *pAllowRule = NULL;

  try {
    // Инициализируем COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage("COM initialization failed: 0x%08lx", hr);
      return false;
    }

    // Создаем экземпляр Firewall Policy
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void **)&pNetFwPolicy2);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx", hr);
      CoUninitialize();
      return false;
    }

    // Получаем коллекцию правил
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
      LogMessage("get_Rules failed: 0x%08lx", hr);
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Ищем правило по имени
    bool ruleExists = false;

    // Перебираем все правила и ищем наше
    IEnumVARIANT *pEnum = NULL;
    IUnknown *pUnk = NULL;
    VARIANT var;
    VariantInit(&var);

    hr = pFwRules->get__NewEnum(&pUnk);
    if (FAILED(hr) || !pUnk) {
      LogMessage("Failed to get _NewEnum interface: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    pUnk->Release();

    if (FAILED(hr) || !pEnum) {
      LogMessage("Failed to get IEnumVARIANT: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Ищем правило по имени
    ULONG fetched = 0;
    while (pEnum->Next(1, &var, &fetched) == S_OK && fetched > 0) {
      if (var.vt == VT_DISPATCH) {
        INetFwRule *pCurrentRule = NULL;
        hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                          (void **)&pCurrentRule);

        if (SUCCEEDED(hr) && pCurrentRule) {
          BSTR name = NULL;
          hr = pCurrentRule->get_Name(&name);

          if (SUCCEEDED(hr) && name) {
            if (wcscmp(name, ruleName) == 0) {
              // Нашли наше правило
              pAllowRule = pCurrentRule;
              ruleExists = true;
              SysFreeString(name);
              break;
            }
            SysFreeString(name);
          }

          if (pCurrentRule != pAllowRule) {
            pCurrentRule->Release();
          }
        }
      }
      VariantClear(&var);
    }

    pEnum->Release();

    if (ruleExists && pAllowRule) {
      // LogMessage("Found existing rule: %S", ruleName);

      // Получаем текущий список IP и добавляем новый
      BSTR currentRemoteAddresses = NULL;
      hr = pAllowRule->get_RemoteAddresses(&currentRemoteAddresses);

      if (SUCCEEDED(hr) && currentRemoteAddresses) {
        std::wstring remoteAddresses(currentRemoteAddresses);
        SysFreeString(currentRemoteAddresses);

        // Преобразуем IP в wstring
        wchar_t ipStrW[32];
        swprintf(ipStrW, 32, L"%u.%u.%u.%u", bytes[3], bytes[2], bytes[1],
                 bytes[0]);

        // Также проверяем формат с маской
        wchar_t ipWithMaskW[64];
        swprintf(ipWithMaskW, 64, L"%u.%u.%u.%u/255.255.255.255", bytes[3],
                 bytes[2], bytes[1], bytes[0]);

        // Проверяем, есть ли уже этот IP в любом формате
        bool ipAlreadyExists =
            (remoteAddresses.find(ipStrW) != std::wstring::npos) ||
            (remoteAddresses.find(ipWithMaskW) != std::wstring::npos);

        if (!ipAlreadyExists) {
          // Добавляем IP к списку через запятую
          if (remoteAddresses.compare(L"*") == 0) {
            // Если был "*", заменяем его на конкретный IP
            remoteAddresses = ipWithMaskW; // Используем IP с маской
          } else {
            remoteAddresses +=
                L"," + std::wstring(ipWithMaskW); // Используем IP с маской
          }

          // Обновляем правило новым списком IP
          BSTR newRemoteAddresses = SysAllocString(remoteAddresses.c_str());
          hr = pAllowRule->put_RemoteAddresses(newRemoteAddresses);
          SysFreeString(newRemoteAddresses);

          if (SUCCEEDED(hr)) {
            // LogMessage("IP %s added to rule", ip_str);
            result = true;
          } else {
            LogMessage("Failed to update remote addresses: 0x%08lx", hr);
          }
        } else {
          // LogMessage("IP %s already in rule", ip_str);
          result = true; // IP уже в списке
        }
      }

      pAllowRule->Release();
    } else {
      // Правило не существует, создаем новое
      // LogMessage("Rule %S does not exist, creating new allow rule",
      // ruleName);

      hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwRule), (void **)&pAllowRule);
      if (FAILED(hr)) {
        LogMessage("CoCreateInstance for INetFwRule failed: 0x%08lx", hr);
        if (pFwRules)
          pFwRules->Release();
        if (pNetFwPolicy2)
          pNetFwPolicy2->Release();
        CoUninitialize();
        return false;
      }

      // Настраиваем правило
      pAllowRule->put_Name(_bstr_t(ruleName));
      pAllowRule->put_Description(_bstr_t(L"Z-ANTIDDOS SERVICE"));
      pAllowRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);
      pAllowRule->put_LocalPorts(_bstr_t(std::to_wstring(port).c_str()));
      pAllowRule->put_Direction(NET_FW_RULE_DIR_IN);
      pAllowRule->put_Enabled(VARIANT_TRUE);
      pAllowRule->put_Action(NET_FW_ACTION_ALLOW);

      // Преобразуем IP в wstring с маской и устанавливаем как
      // RemoteAddresses
      wchar_t ipWithMaskW[64];
      swprintf(ipWithMaskW, 64, L"%u.%u.%u.%u/255.255.255.255", bytes[3],
               bytes[2], bytes[1], bytes[0]);
      pAllowRule->put_RemoteAddresses(_bstr_t(ipWithMaskW));

      // Устанавливаем высокий приоритет для правила разрешения
      pAllowRule->put_Profiles(NET_FW_PROFILE2_ALL);

      // Добавляем правило в коллекцию
      hr = pFwRules->Add(pAllowRule);
      if (FAILED(hr)) {
        LogMessage("Add rule failed: 0x%08lx", hr);
      } else {
        //   LogMessage("New allow rule created with IP %s", ip_str);
        result = true;
      }

      pAllowRule->Release();
    }

    // Освобождаем ресурсы
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
  } catch (...) {
    LogMessage("Exception in AddIPToAllowRule");
    if (pAllowRule)
      pAllowRule->Release();
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();
    CoUninitialize();
    return false;
  }

  return result;
}

bool RemoveIPFromAllowRule(const wchar_t *ruleName, uint32 ip) {
  // Преобразуем IP для логирования
  unsigned char *bytes = (unsigned char *)&ip;
  char ip_str[16];
  sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);

  // LogMessage("Removing IP %s from rule %S", ip_str, ruleName);

  if (!firewallEnabled) {
    //    LogMessage("Firewall is disabled, cannot update rule");
    return false;
  }

  HRESULT hr = S_OK;
  bool result = false;
  INetFwPolicy2 *pNetFwPolicy2 = NULL;
  INetFwRules *pFwRules = NULL;
  INetFwRule *pAllowRule = NULL;

  try {
    // Инициализируем COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
      LogMessage("COM initialization failed: 0x%08lx", hr);
      return false;
    }

    // Создаем экземпляр Firewall Policy
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void **)&pNetFwPolicy2);
    if (FAILED(hr)) {
      LogMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx", hr);
      CoUninitialize();
      return false;
    }

    // Получаем коллекцию правил
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
      LogMessage("get_Rules failed: 0x%08lx", hr);
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Ищем правило по имени
    bool ruleExists = false;

    // Перебираем все правила и ищем наше
    IEnumVARIANT *pEnum = NULL;
    IUnknown *pUnk = NULL;
    VARIANT var;
    VariantInit(&var);

    hr = pFwRules->get__NewEnum(&pUnk);
    if (FAILED(hr) || !pUnk) {
      LogMessage("Failed to get _NewEnum interface: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    pUnk->Release();

    if (FAILED(hr) || !pEnum) {
      LogMessage("Failed to get IEnumVARIANT: 0x%08lx", hr);
      if (pFwRules)
        pFwRules->Release();
      if (pNetFwPolicy2)
        pNetFwPolicy2->Release();
      CoUninitialize();
      return false;
    }

    // Ищем правило по имени
    ULONG fetched = 0;
    while (pEnum->Next(1, &var, &fetched) == S_OK && fetched > 0) {
      if (var.vt == VT_DISPATCH) {
        INetFwRule *pCurrentRule = NULL;
        hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                          (void **)&pCurrentRule);

        if (SUCCEEDED(hr) && pCurrentRule) {
          BSTR name = NULL;
          hr = pCurrentRule->get_Name(&name);

          if (SUCCEEDED(hr) && name) {
            if (wcscmp(name, ruleName) == 0) {
              // Нашли наше правило
              pAllowRule = pCurrentRule;
              ruleExists = true;
              SysFreeString(name);
              break;
            }
            SysFreeString(name);
          }

          if (pCurrentRule != pAllowRule) {
            pCurrentRule->Release();
          }
        }
      }
      VariantClear(&var);
    }

    pEnum->Release();

    if (ruleExists && pAllowRule) {
      // Получаем текущий список IP
      BSTR currentRemoteAddresses = NULL;
      hr = pAllowRule->get_RemoteAddresses(&currentRemoteAddresses);

      if (SUCCEEDED(hr) && currentRemoteAddresses) {
        std::wstring remoteAddresses(currentRemoteAddresses);
        SysFreeString(currentRemoteAddresses);

        // LogMessage("Current remote addresses in rule: %S",
        // remoteAddresses.c_str());

        // Генерируем различные варианты представления IP для поиска
        wchar_t ipStrW[32];
        swprintf(ipStrW, 32, L"%u.%u.%u.%u", bytes[3], bytes[2], bytes[1],
                 bytes[0]);
        std::wstring ipWStr(ipStrW);

        // Также проверяем формат с маской
        wchar_t ipWithMaskW[64];
        swprintf(ipWithMaskW, 64, L"%u.%u.%u.%u/255.255.255.255", bytes[3],
                 bytes[2], bytes[1], bytes[0]);
        std::wstring ipWithMaskWStr(ipWithMaskW);

        // Ищем IP во всех возможных форматах
        bool ipFound = false;
        std::wstring newRemoteAddresses = remoteAddresses;

        // Поиск IP в списке
        if (remoteAddresses == ipWStr || remoteAddresses == ipWithMaskWStr) {
          // IP единственный в списке
          // LogMessage("IP is the only one in the rule");
          ipFound = true;
          newRemoteAddresses = L""; // Пустая строка - будем удалять правило
        } else {
          // Проверяем различные варианты положения IP в списке

          // Проверка для IP без маски
          if (FindAndRemoveIPFromList(remoteAddresses, ipWStr,
                                      newRemoteAddresses)) {
            ipFound = true;
            //     LogMessage("Found and removed IP without mask");
          }
          // Проверка для IP с маской
          else if (FindAndRemoveIPFromList(remoteAddresses, ipWithMaskWStr,
                                           newRemoteAddresses)) {
            ipFound = true;
            //     LogMessage("Found and removed IP with mask");
          }
        }

        if (ipFound) {
          // Устраняем возможные проблемы с форматированием
          CleanupIPAddressList(newRemoteAddresses);

          // Проверяем, пуст ли список IP-адресов после удаления
          bool isEmpty =
              newRemoteAddresses.empty() || newRemoteAddresses == L"*";

          if (isEmpty) {
            //    LogMessage("No IPs left in rule, removing the
            //    rule");

            // Освобождаем правило перед удалением
            pAllowRule->Release();

            // Удаляем правило полностью
            BSTR bstrRuleNameToRemove = SysAllocString(ruleName);
            hr = pFwRules->Remove(bstrRuleNameToRemove);
            SysFreeString(bstrRuleNameToRemove);

            if (SUCCEEDED(hr)) {
              //     LogMessage("Rule %S removed successfully",
              //     ruleName);
              result = true;
            } else {
              LogMessage("Failed to remove rule: 0x%08lx", hr);
            }
          } else {
            //  LogMessage("New remote addresses: %S",
            //  newRemoteAddresses.c_str());

            // Обновляем правило
            BSTR newAddresses = SysAllocString(newRemoteAddresses.c_str());
            hr = pAllowRule->put_RemoteAddresses(newAddresses);
            SysFreeString(newAddresses);

            if (SUCCEEDED(hr)) {
              //     LogMessage("IP %s removed from rule %S",
              //     ip_str, ruleName);
              result = true;
            } else {
              LogMessage("Failed to update rule: 0x%08lx", hr);
            }

            if (pAllowRule)
              pAllowRule->Release();
          }
        } else {
          //   LogMessage("IP %s not found in rule %S, no need to
          //   remove", ip_str, ruleName);
          result = true; // Считаем успехом, так как IP и так нет
          if (pAllowRule)
            pAllowRule->Release();
        }
      } else {
        LogMessage("Failed to get remote addresses: 0x%08lx", hr);
        if (pAllowRule)
          pAllowRule->Release();
      }
    } else {
      //  LogMessage("Rule %S does not exist", ruleName);
      result = true; // Считаем успехом, так как правила нет
    }

    // Освобождаем ресурсы
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();

    CoUninitialize();
  } catch (...) {
    LogMessage("Exception in RemoveIPFromAllowRule");
    if (pAllowRule)
      pAllowRule->Release();
    if (pFwRules)
      pFwRules->Release();
    if (pNetFwPolicy2)
      pNetFwPolicy2->Release();
    CoUninitialize();
    return false;
  }

  return result;
}

// Генерация имени правила для сервера
std::wstring GenerateRuleName(const std::wstring &serverName, uint16 port) {
  return L"Z-ANTIDDOS-" + serverName + L"-" + std::to_wstring(port);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

struct ZServerInterfaceUser {
  virtual ~ZServerInterfaceUser() {}

  virtual void ReloadDLL() = 0;

  virtual void ServerList() = 0;
  virtual bool ServerAdd(const wchar_t *name, const wchar_t *path,
                         const wchar_t *cmd, bool autostart, bool kill,
                         bool restartalways) = 0;
  virtual bool ServerSet(const wchar_t *name, const wchar_t *path,
                         const wchar_t *cmd, bool autostart, bool kill,
                         bool restartalways) = 0;
  virtual bool ServerSetPath(const wchar_t *name, const wchar_t *path) = 0;
  virtual bool ServerSetCmd(const wchar_t *name, const wchar_t *cmd) = 0;
  virtual bool ServerSetAutostart(const wchar_t *name, bool autostart) = 0;
  virtual bool ServerSetKill(const wchar_t *name, bool kill) = 0;
  virtual bool ServerSetRestartAlways(const wchar_t *name,
                                      bool restartalways) = 0;
  virtual bool ServerDel(const wchar_t *name) = 0;
  virtual bool ServerStart(const wchar_t *name) = 0;
  virtual bool ServerStop(const wchar_t *name) = 0;
  virtual void ServerProcessList(const wchar_t *name) = 0;
};

ZServerInterfaceUser *zsi;

// Интерфейсы ТОЧНО как в коде разработчика
struct ZServerInterfaceListener {
  virtual ~ZServerInterfaceListener() {}

  virtual void OnLoaded() {
    // LogMessage("OnLoaded called");

    // Проверяем, включен ли брандмауэр Windows
    try {
      firewallEnabled = IsFirewallEnabled();
      if (!firewallEnabled) {
        LogMessage("WARNING: Windows Firewall is disabled!");
        LogMessage("WARNING: Z-ANTIDDOS service is disabled!");
        // Здесь можно добавить код для уведомления пользователя
      } else {
        LogMessage("Windows Firewall is enabled!");
        LogMessage("Z-ANTIDDOS service is active!");
      }
    } catch (...) {
      LogMessage("Exception checking firewall status");
    }

    // Тестируем метод ServerList
    try {
      // LogMessage("Attempting to call ServerList");
      zsi->ServerList();
      // LogMessage("[TEST] Called successfully");
    } catch (...) {
      LogMessage("[TEST] Exception calling");
    }
  }

  virtual void OnEmuConnected() {
    // LogMessage("OnEmuConnected called");
  }

  virtual void OnEmuAuthed() {
    //  LogMessage("OnEmuAuthed called");
  }

  virtual void OnEmuDisconnected() {
    //  LogMessage("OnEmuDisconnected called");
  }

  virtual void OnServerStarted(const wchar_t *name) {
    // LogMessage("Server %S started", name);

    if (!firewallEnabled) {
      //   LogMessage("Windows Firewall is disabled, skipping firewall rule
      //   creation");
      return;
    }

    try {
      // Находим информацию о сервере по имени
      std::lock_guard<std::mutex> guard(serversMutex);

      // Находим сервер по имени
      ServerInfo *serverInfo = nullptr;
      for (auto &pair : servers) {
        if (pair.second.name == name) {
          serverInfo = &pair.second;
          break;
        }
      }

      if (!serverInfo) {
        LogMessage("Server %S not found in server list", name);
        return;
      }

      if (serverInfo->gamePort == 0) {
        LogMessage("Game port not found for server %S", name);
        return;
      }

      // 1. Очищаем все старые правила
      if (!CleanupFirewallRules(serverInfo->gamePort, name)) {
        LogMessage("Warning: Failed to cleanup old firewall rules");
      }

      // 2. Создаем разрешающее правило для уже подключенных игроков (если
      // есть)
      if (!serverInfo->playerIPs.empty()) {
        std::wstring serverInitial = std::wstring(name).substr(0, 1);
        std::wstring allowRuleName = L"Game-" + serverInitial + L"-Port" +
                                     std::to_wstring(serverInfo->gamePort);

        // Добавляем первый IP
        auto firstPlayer = serverInfo->playerIPs.begin();
        if (firstPlayer != serverInfo->playerIPs.end()) {
          unsigned char *bytes = (unsigned char *)&firstPlayer->second;
          char ip_str[16];
          sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1],
                  bytes[0]);

          LogMessage("Adding first IP %s to allow rule", ip_str);
          AddIPToAllowRule(allowRuleName.c_str(), firstPlayer->second,
                           serverInfo->gamePort);

          // Добавляем остальные IP
          auto it = firstPlayer;
          it++;
          for (; it != serverInfo->playerIPs.end(); ++it) {
            bytes = (unsigned char *)&it->second;
            sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1],
                    bytes[0]);

            LogMessage("Adding IP %s to allow rule", ip_str);
            AddIPToAllowRule(allowRuleName.c_str(), it->second,
                             serverInfo->gamePort);
          }
        }
      }

      // LogMessage("Firewall rules setup completed for server %S", name);
    } catch (...) {
      LogMessage("Exception in OnServerStarted");
    }
  }

  virtual void OnServerCrashed(const wchar_t *name) {
    // LogMessage("Server %S crashed", name);
  }

  virtual void OnServerStopped(const wchar_t *name, uint32 code) {
    // LogMessage("Server %S stopped", name, code);
  }

  virtual void OnServerRemoved(const wchar_t *name) {
    // LogMessage("OnServerRemoved called %S", name);
  }

  // Обновленная функция OnServerData с улучшенным управлением серверами
  virtual void OnServerData(const wchar_t *name, const wchar_t *path,
                            const wchar_t *cmd, bool autostart, bool kill,
                            bool restartalways, uint32 *pids, uint32 npids) {
    // LogMessage("OnServerData called name [%S] path [%S] cmd [%S] autostart %u
    // kill %u restartalways %u pids %u",
    //            name, path, cmd, autostart, kill, restartalways, npids);

    try {
      // Извлекаем порт игры из командной строки
      uint16 gamePort = ExtractGamePort(cmd);
      // LogMessage("Extracted game port: %d", gamePort);

      // Извлекаем логин из командной строки
      std::wstring cmdStr(cmd);
      std::string login;

      // Ищем параметр -zlogin в командной строке
      size_t loginPos = cmdStr.find(L"-zlogin");
      if (loginPos != std::wstring::npos) {
        size_t startPos = loginPos + 8; // длина "-zlogin "
        // Пропускаем пробелы
        while (startPos < cmdStr.length() && iswspace(cmdStr[startPos])) {
          startPos++;
        }
        // Читаем логин до следующего пробела или конца строки
        std::wstring loginW;
        while (startPos < cmdStr.length() && !iswspace(cmdStr[startPos])) {
          loginW += cmdStr[startPos];
          startPos++;
        }
        login = WStringToString(loginW);
      }

      if (login.empty()) {
        // Если логин не найден, используем имя сервера
        login = WStringToString(name);
        LogMessage("No login found in command line, using server name: %s",
                   login.c_str());
      } else {
        //   LogMessage("Extracted login from command: %s", login.c_str());
      }

      // Сохраняем информацию о сервере, используя логин как ключ
      std::lock_guard<std::mutex> guard(serversMutex);

      // Проверяем, существует ли уже сервер с таким логином
      auto it = servers.find(login);
      if (it != servers.end()) {
        // Обновляем информацию о существующем сервере
        it->second.name = name;
        it->second.path = path;
        it->second.cmd = cmd;
        it->second.gamePort = gamePort;
        LogMessage("Updated server %s with name %S and port %d", login.c_str(),
                   name, gamePort);
      } else {
        // Создаем новую запись
        ServerInfo &server = servers[login];
        server.name = name;
        server.path = path;
        server.cmd = cmd;
        server.gamePort = gamePort;
        server.login = login;

        LogMessage("Registered new server with login %s, name %S, and port %d",
                   login.c_str(), name, gamePort);
      }
    } catch (...) {
      LogMessage("Exception in OnServerData");
    }
  }

  // Функция для извлечения логина из командной строки
  std::wstring ExtractLoginFromCmd(const wchar_t *cmd) {
    std::wstring cmdStr(cmd);
    std::wstring loginPrefix = L"-login=";
    size_t pos = cmdStr.find(loginPrefix);

    if (pos != std::wstring::npos) {
      pos += loginPrefix.length();
      size_t endPos = cmdStr.find(L" ", pos);
      if (endPos != std::wstring::npos) {
        return cmdStr.substr(pos, endPos - pos);
      } else {
        return cmdStr.substr(pos);
      }
    }

    return L"";
  }

  // Вспомогательная функция для конвертации wstring в string
  std::string WStringToString(const std::wstring &wstr) {
    if (wstr.empty())
      return "";

    int size_needed =
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed,
                        NULL, NULL);

    // Удаляем завершающий нулевой символ
    if (!strTo.empty() && strTo.back() == 0) {
      strTo.pop_back();
    }

    return strTo;
  }

  // Вспомогательная функция для конвертации string в wstring
  std::wstring StringToWString(const std::string &str) {
    if (str.empty())
      return L"";

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstrTo[0], size_needed);

    // Удаляем завершающий нулевой символ
    if (!wstrTo.empty() && wstrTo.back() == 0) {
      wstrTo.pop_back();
    }

    return wstrTo;
  }

  virtual void OnServerList(bool done) {
    //  LogMessage("OnServerList called %u", done);
  }

  // Обновленная функция OnServerAuthed
  virtual void OnServerAuthed(uint32 id, const char *login) {
    // LogMessage("OnServerAuthed called %u %s", id, login);

    try {
      std::lock_guard<std::mutex> guard(serversMutex);

      // Ищем сервер по логину напрямую
      auto it = servers.find(login);
      if (it != servers.end()) {
        // Сохраняем id сервера для дальнейшего использования
        it->second.serverId = id;
        LogMessage("Server %s authenticated with ID %u", login, id);
      } else {
        // Если сервер не найден, создаем временную запись
        ServerInfo &server = servers[login];
        server.login = login;
        server.serverId = id;
        server.name =
            StringToWString(login); // Конвертируем логин в wstring для имени
        LogMessage("Created temporary record for server %s with ID %u", login,
                   id);
      }
    } catch (...) {
      LogMessage("Exception in OnServerAuthed");
    }
  }

  virtual void OnServerProcessList(const wchar_t *name, uint32 *pids,
                                   uint32 npids) {
    //  LogMessage("OnServerProcessList called %S %u", name, npids);
  }

  // Обновленная функция OnPlayerConnecting с оптимизированным управлением
  // IP-адресами
  virtual void OnPlayerConnecting(uint32 srvid, uint32 id, const char *name,
                                  uint32 ip, uint16 port) {
    // Преобразование IP из uint32 в строку с точечной нотацией
    char ip_str[16];
    unsigned char *bytes = (unsigned char *)&ip;
    sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);

    // LogMessage("OnPlayerConnecting called %u %u %s %s (%08X) %u",
    //           srvid, id, name, ip_str, ip, port);

    if (!firewallEnabled) {
      return;
    }

    try {
      std::string serverLogin;
      ServerInfo *serverInfo = nullptr;

      {
        std::lock_guard<std::mutex> guard(serversMutex);

        // Ищем сервер по ID
        for (auto &pair : servers) {
          if (pair.second.serverId == srvid) {
            serverLogin = pair.first;
            serverInfo = &pair.second;
            //     LogMessage("Found server with login %s by ID %u",
            //     serverLogin.c_str(), srvid);
            break;
          }
        }

        // Если не нашли по ID, попробуем найти сервер с портом, совпадающим с
        // портом игрока
        if (!serverInfo) {
          for (auto &pair : servers) {
            if (pair.second.gamePort == port) {
              serverLogin = pair.first;
              serverInfo = &pair.second;
              //      LogMessage("Found server with login %s by port
              //      %u", serverLogin.c_str(), port);
              break;
            }
          }
        }

        if (!serverInfo) {
          LogMessage("No server found for player connection (ID: %u, IP: %s)",
                     id, ip_str);
          return;
        }

        // Сохраняем информацию о подключении игрока
        serverInfo->playerIPs[id] = ip;
      }

      // Генерируем имя правила для разрешения
      std::wstring serverInitial = serverInfo->name.substr(0, 1);
      std::wstring allowRuleName = L"Game-" + serverInitial + L"-Port" +
                                   std::to_wstring(serverInfo->gamePort);

      // Добавляем IP игрока в правило разрешения
      LogMessage("Adding IP %s for server %S", ip_str,
                 serverInfo->name.c_str());
      AddIPToAllowRule(allowRuleName.c_str(), ip, serverInfo->gamePort);
    } catch (...) {
      LogMessage("Exception in OnPlayerConnecting");
    }
  }

  virtual void OnPlayerConnected(uint32 srvid, uint32 id) {
    // LogMessage("OnPlayerConnected called %u %u", srvid, id);
  }

  virtual void OnPlayerDisconnected(uint32 srvid, uint32 id) {
    // LogMessage("OnPlayerDisconnected called %u %u", srvid, id);

    if (!firewallEnabled) {
      return;
    }

    try {
      // Создаем ключ для отслеживания обработанных отключений
      std::pair<uint32, uint32> disconnectKey(srvid, id);

      // Проверка, обрабатывали ли мы уже это отключение
      {
        std::lock_guard<std::mutex> guardProcessed(processedMutex);
        if (processedDisconnects.find(disconnectKey) !=
            processedDisconnects.end()) {
          //    LogMessage("Disconnect for server %u player %u already
          //    processed", srvid, id);
          return; // Уже обработали это отключение
        }
        // Отмечаем, что обрабатываем это отключение
        processedDisconnects.insert(disconnectKey);

        // Ограничиваем размер множества обработанных отключений
        if (processedDisconnects.size() > 1000) {
          processedDisconnects.erase(processedDisconnects.begin());
        }
      }

      uint32 playerIP = 0;        // Сохраним IP игрока здесь
      std::wstring allowRuleName; // И имя правила здесь

      {
        std::lock_guard<std::mutex> guard(serversMutex);

        ServerInfo *serverInfo = nullptr;
        std::string serverLogin;

        // Ищем сервер по ID
        for (auto &pair : servers) {
          if (pair.second.serverId == srvid) {
            serverLogin = pair.first;
            serverInfo = &pair.second;
            //      LogMessage("Found server with login %s by ID %u for
            //      disconnect", serverLogin.c_str(), srvid);
            break;
          }
        }

        if (!serverInfo) {
          LogMessage("No server found for player disconnect (Server ID: "
                     "%u, Player ID: %u)",
                     srvid, id);
          return;
        }

        // Ищем IP игрока в сохраненном списке
        auto playerIt = serverInfo->playerIPs.find(id);
        if (playerIt == serverInfo->playerIPs.end()) {
          //    LogMessage("Player ID %u not found in player IPs map for
          //    server %S",
          //             id, serverInfo->name.c_str());
          return;
        }

        // Сохраняем IP игрока перед удалением
        playerIP = playerIt->second;

        // Преобразование IP в строку для логирования
        unsigned char *bytes = (unsigned char *)&playerIP;
        char ip_str[16];
        sprintf(ip_str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);

        // Генерируем имя правила для удаления
        std::wstring serverInitial = serverInfo->name.substr(0, 1);
        allowRuleName = L"Game-" + serverInitial + L"-Port" +
                        std::to_wstring(serverInfo->gamePort);

        // Удаляем IP игрока из правила
        LogMessage("Removing IP %s for server %S", ip_str,
                   serverInfo->name.c_str());

        // Удаляем игрока из списка
        serverInfo->playerIPs.erase(playerIt);

        // Разблокируем мьютекс перед вызовом RemoveIPFromAllowRule,
        // чтобы другие потоки могли получить доступ к серверам
      }

      // Теперь вызываем RemoveIPFromAllowRule без удерживания мьютекса
      RemoveIPFromAllowRule(allowRuleName.c_str(), playerIP);
    } catch (...) {
      LogMessage("Exception in OnPlayerDisconnected");
    }
  }

  // Функция для генерации имени правила фаервола
  std::wstring GenerateRuleName(const std::wstring &serverName,
                                uint16 gamePort) {
    wchar_t buffer[256];
    swprintf(buffer, sizeof(buffer) / sizeof(wchar_t), L"Game-%s-Port%u",
             serverName.c_str(), gamePort);
    return buffer;
  }
};

#pragma GCC diagnostic pop

// DllMain для инициализации и очистки
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    // Инициализация при загрузке DLL
    CreateConsoleAndFile();
    // LogMessage("DLL loaded");
    //  Инициализация COM при загрузке DLL
    InitializeCOM();
    break;

  case DLL_PROCESS_DETACH:
    // Очистка при выгрузке DLL
    // LogMessage("DLL unloaded");
    // Освобождение COM при выгрузке DLL
    UninitializeCOM();
    break;
  }
  return TRUE;
}

extern "C" __declspec(dllexport) uint32 ZServerInterfaceVersion() {
  // LogMessage("ZServerInterfaceVersion called");
  return ZSERVERINTERFACE_VERSION;
}

extern "C" __declspec(dllexport) ZServerInterfaceListener *
ZServerInterfaceInit(void *reserved, ZServerInterfaceUser *zsi) {
  // LogMessage("ZServerInterfaceInit called");

  // Создаем статический объект, чтобы он не был уничтожен
  static ZServerInterfaceListener *listener = nullptr;

  // Если объект уже создан, используем его
  if (listener) {
    //   LogMessage("Returning existing ZServerInterfaceListener");
    return listener;
  }

  // Проверяем переданный указатель
  if (zsi == nullptr) {
    LogMessage("WARNING: Interface is NULL");
  } else {
    // LogMessage("Interface is valid");
    // LogMessage("ZServerInterfaceUser is valid");
    ::zsi = zsi;
  }

  // Создаем новый объект ZServerInterfaceListener
  listener = new ZServerInterfaceListener();
  //  LogMessage("Created new ZServerInterfaceListener");

  return listener;
}
