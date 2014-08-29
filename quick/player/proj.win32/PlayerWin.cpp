﻿
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='Win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='X86' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "stdafx.h"
#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <Commdlg.h>
#include <Shlobj.h>
#include <winnls.h>
#include <shobjidl.h>
#include <objbase.h>
#include <objidl.h>
#include <shlguid.h>
#include <shellapi.h>

// for mac address
#include <WinSock2.h>
#include <Iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib")

#include "PlayerWin.h"

#include "glfw3.h"
#include "glfw3native.h"

#include "CCLuaEngine.h"
#include "PlayerLuaCore.h"

int APIENTRY _tWinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPTSTR    lpCmdLine,
                       int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    auto player = player::PlayerWin::create();
    return player->run();
}

PLAYER_NS_BEGIN

PlayerWin::PlayerWin()
: _app(nullptr)
, _hwnd(NULL)
, _hwndConsole(NULL)
, _writeDebugLogFile(nullptr)
, _messageBoxService(nullptr)
, _menuService(nullptr)
, _editboxService(nullptr)
, _taskService(nullptr)
{
}

PlayerWin::~PlayerWin()
{
    CC_SAFE_DELETE(_menuService);
    CC_SAFE_DELETE(_messageBoxService);
    CC_SAFE_DELETE(_fileDialogService);
    CC_SAFE_DELETE(_app);
    if (_writeDebugLogFile)
    {
        fclose(_writeDebugLogFile);
    }
}

PlayerWin *PlayerWin::create()
{
    return new PlayerWin();
}

PlayerFileDialogServiceProtocol *PlayerWin::getFileDialogService()
{
    return _fileDialogService;
}

PlayerMessageBoxServiceProtocol *PlayerWin::getMessageBoxService()
{
    return _messageBoxService;
}

PlayerMenuServiceProtocol *PlayerWin::getMenuService()
{
    return _menuService;
}

PlayerEditBoxServiceProtocol *PlayerWin::getEditBoxService()
{
    return _editboxService;
}

PlayerTaskServiceProtocol *PlayerWin::getTaskService()
{
    return _taskService;
}

void PlayerWin::quit()
{
	Director::getInstance()->end();
}

void PlayerWin::relaunch()
{
	openNewPlayer();
	quit();
}

void PlayerWin::openNewPlayer()
{
	openNewPlayerWithProjectConfig(_project);
}

void PlayerWin::openNewPlayerWithProjectConfig(ProjectConfig config)
{
	static long taskid = 100;
	stringstream buf;
	buf << taskid++;

	auto task = getTaskService()->createTask(buf.str(), getApplicationExePath(), config.makeCommandLine());
	task->run();
}

void PlayerWin::openProjectWithProjectConfig(ProjectConfig config)
{
	openNewPlayerWithProjectConfig(config);
	quit();
}

void PlayerWin::loadLuaConfig()
{
	LuaEngine* pEngine = LuaEngine::getInstance();
	ScriptEngineManager::getInstance()->setScriptEngine(pEngine);

	// load player lua core
	luaopen_PlayerLuaCore(pEngine->getLuaStack()->getLuaState());

	// set env
	string quickRootPath = SimulatorConfig::getInstance()->getQuickCocos2dxRootPath();
	quickRootPath = convertPathFormatToUnixStyle(quickRootPath);

	string env = "__G_QUICK_V3_ROOT__=\"";
	env.append(quickRootPath);
	env.append("\"");
	pEngine->executeString(env.c_str());

	// set user home dir
	lua_pushstring(pEngine->getLuaStack()->getLuaState(), getUserDocumentPath().c_str());
	lua_setglobal(pEngine->getLuaStack()->getLuaState(), "__USER_HOME__");

	//
	// ugly: Add the opening project to the "Open Recents" list
	//
	lua_pushstring(pEngine->getLuaStack()->getLuaState(), _project.getProjectDir().c_str());
	lua_setglobal(pEngine->getLuaStack()->getLuaState(), "__PLAYER_OPEN_TITLE__");

	lua_pushstring(pEngine->getLuaStack()->getLuaState(), _project.makeCommandLine().c_str());
	lua_setglobal(pEngine->getLuaStack()->getLuaState(), "__PLAYER_OPEN_COMMAND__");


	// set guid
	string uid = getUserGUID();
	lua_pushstring(pEngine->getLuaStack()->getLuaState(), uid.c_str());
	lua_setglobal(pEngine->getLuaStack()->getLuaState(), "__G_QUICK_GUID__");

	// load player.lua
	quickRootPath.append("quick/player/src/player.lua");
	pEngine->getLuaStack()->executeScriptFile(quickRootPath.c_str());
}

void PlayerWin::registerKeyboardEvent()
{
	auto eventDispatcher = cocos2d::Director::getInstance()->getEventDispatcher();
	auto keyEvent = cocos2d::EventListenerKeyboard::create();
	keyEvent->onKeyReleased = [](EventKeyboard::KeyCode key, Event*) {
		auto event = EventCustom("APP.EVENT");
		stringstream data;
		data << "{\"name\":\"keyReleased\",\"data\":" << (int)key << "}";
		event.setDataString(data.str());
		Director::getInstance()->getEventDispatcher()->dispatchEvent(&event);
	};
	eventDispatcher->addEventListenerWithFixedPriority(keyEvent, 1);	
}

int PlayerWin::run()
{
    INITCOMMONCONTROLSEX InitCtrls;
    InitCtrls.dwSize = sizeof(InitCtrls);
    InitCtrls.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&InitCtrls);

    // set QUICK_V3_ROOT
    const char *QUICK_V3_ROOT = getenv("QUICK_V3_ROOT");
    if (!QUICK_V3_ROOT || strlen(QUICK_V3_ROOT) == 0)
    {
        MessageBox("Please run \"setup_win.bat\", set quick-cocos2d-x root path.", "quick-cocos2d-x player error");
        return 1;
    }
    SimulatorConfig::getInstance()->setQuickCocos2dxRootPath(QUICK_V3_ROOT);

    // load project config from command line args
    vector<string> args;
    for (int i = 0; i < __argc; ++i)
    {
        wstring ws(__wargv[i]);
        string s;
        s.assign(ws.begin(), ws.end());
        args.push_back(s);
    }
    _project.parseCommandLine(args);

	if (_project.getProjectDir().length() <= 0)
	{
		_project.resetToWelcome();
	}

    // create the application instance
    _app = new AppDelegate();
    _app->setProjectConfig(_project);

    // set window icon
    HICON icon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_PLAYER));

    // create console window
    if (_project.isShowConsole())
    {
        AllocConsole();
        _hwndConsole = GetConsoleWindow();
        if (_hwndConsole != NULL)
        {
            SendMessage(_hwndConsole, WM_SETICON, ICON_BIG, (LPARAM)icon);
            SendMessage(_hwndConsole, WM_SETICON, ICON_SMALL, (LPARAM)icon);

            ShowWindow(_hwndConsole, SW_SHOW);
            BringWindowToTop(_hwndConsole);
            freopen("CONOUT$", "wt", stdout);
            freopen("CONOUT$", "wt", stderr);

            HMENU hmenu = GetSystemMenu(_hwndConsole, FALSE);
            if (hmenu != NULL) DeleteMenu(hmenu, SC_CLOSE, MF_BYCOMMAND);
        }
    }

    // set environments
    SetCurrentDirectoryA(_project.getProjectDir().c_str());
    FileUtils::getInstance()->setSearchRootPath(_project.getProjectDir().c_str());
    FileUtils::getInstance()->setWritablePath(_project.getWritableRealPath().c_str());

    // check screen DPI
    HDC screen = GetDC(0);
    int dpi = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(0, screen);

    // set scale with DPI
    //  96 DPI = 100 % scaling
    // 120 DPI = 125 % scaling
    // 144 DPI = 150 % scaling
    // 192 DPI = 200 % scaling
    // http://msdn.microsoft.com/en-us/library/windows/desktop/dn469266%28v=vs.85%29.aspx#dpi_and_the_desktop_scaling_factor
    //
    // enable DPI-Aware with DeclareDPIAware.manifest
    // http://msdn.microsoft.com/en-us/library/windows/desktop/dn469266%28v=vs.85%29.aspx#declaring_dpi_awareness
    float screenScale = 1.0f;
    if (dpi >= 120 && dpi < 144)
    {
        screenScale = 1.25f;
    }
    else if (dpi >= 144 && dpi < 192)
    {
        screenScale = 1.5f;
    }
    else if (dpi >= 192)
    {
        screenScale = 2.0f;
    }
    CCLOG("SCREEN DPI = %d, SCREEN SCALE = %0.2f", dpi, screenScale);

    // create opengl view
    Size frameSize = _project.getFrameSize();
    float frameScale = 1.0f;
    if (_project.isRetinaDisplay())
    {
        frameSize.width *= screenScale;
        frameSize.height *= screenScale;
    }
    else
    {
        frameScale = screenScale;
    }

    const Rect frameRect = Rect(0, 0, frameSize.width, frameSize.height);
    const bool isResize = _project.isResizeWindow();
    auto glview = GLView::createWithRect("quick-cocos2d-x", frameRect, frameScale, isResize, false, true);
    _hwnd = glfwGetWin32Window(glview->getWindow());
    SendMessage(_hwnd, WM_SETICON, ICON_BIG, (LPARAM)icon);
    SendMessage(_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)icon);
    FreeResource(icon);

    auto director = Director::getInstance();
    director->setOpenGLView(glview);
    director->setScreenScale(screenScale);

    // init player services
    initServices();

	loadLuaConfig();
	registerKeyboardEvent();

    // register event handlers
    auto eventDispatcher = director->getEventDispatcher();
    eventDispatcher->addCustomEventListener("APP.WINDOW_CLOSE_EVENT", CC_CALLBACK_1(PlayerWin::onWindowClose, this));
    eventDispatcher->addCustomEventListener("APP.WINDOW_RESIZE_EVENT", CC_CALLBACK_1(PlayerWin::onWindowResize, this));
	eventDispatcher->addCustomEventListener("APP.VIEW_SCALE", CC_CALLBACK_1(PlayerWin::onWindowScale, this));

    // prepare
    _project.dump();
    auto app = Application::getInstance();

    HWND hwnd = _hwnd;
    HWND hwndConsole = _hwndConsole;
    const ProjectConfig &project = _project;
    director->getScheduler()->schedule([hwnd, hwndConsole, project](float dt) {
        CC_UNUSED_PARAM(dt);
        ShowWindow(hwnd, SW_RESTORE);
        GLFWwindow *window = Director::getInstance()->getOpenGLView()->getWindow();
        glfwShowWindow(window);
    }, this, 0.0f, 0, 0.001f, false, "SHOW_WINDOW_CALLBACK");

    if (project.isAppMenu() && GetMenu(hwnd))
    {
        // update window size
        RECT rect;
        GetWindowRect(_hwnd, &rect);
        MoveWindow(_hwnd, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top + GetSystemMetrics(SM_CYMENU), FALSE);
    }
    ShowWindow(_hwnd, SW_MINIMIZE);

    // startup message loop
    return app->run();
}

// services
void PlayerWin::initServices()
{
    CCASSERT(_menuService == nullptr, "CAN'T INITIALIZATION SERVICES MORE THAN ONCE");
    _menuService = new PlayerMenuServiceWin(_hwnd);
    _messageBoxService = new PlayerMessageBoxServiceWin(_hwnd);
    _fileDialogService = new PlayerFileDialogServiceWin(_hwnd);
    _editboxService = new PlayerEditBoxServiceWin(_hwnd);
    _taskService = new PlayerTaskServiceWin(_hwnd);

    if (!_project.isAppMenu())
    {
        // remove menu
        SetMenu(_hwnd, NULL);
    }
}

// event handlers
void PlayerWin::onWindowClose(EventCustom* event)
{
    CCLOG("APP.WINDOW_CLOSE_EVENT");

    // If script set event's result to "cancel", ignore window close event
    EventCustom forwardEvent("APP.EVENT");
    stringstream buf;
    buf << "{\"name\":\"close\"}";
    forwardEvent.setDataString(buf.str());
    Director::getInstance()->getEventDispatcher()->dispatchEvent(&forwardEvent);
    if (forwardEvent.getResult().compare("cancel") != 0)
    {
        glfwSetWindowShouldClose(Director::getInstance()->getOpenGLView()->getWindow(), 1);
    }
}

void PlayerWin::onWindowResize(EventCustom* event)
{
}

void PlayerWin::onWindowScale(EventCustom* event)
{
	float scale = atof(event->getDataString().c_str());
	cocos2d::Director::getInstance()->getOpenGLView()->setFrameZoomFactor(scale);
}

// debug log
void PlayerWin::writeDebugLog(const char *log)
{

}


//
// D:\aaa\bbb\ccc\ddd\abc.txt --> D:/aaa/bbb/ccc/ddd/abc.txt
//
std::string PlayerWin::convertPathFormatToUnixStyle(const std::string& path)
{
	std::string ret = path;
	int len = ret.length();
	for (int i = 0; i < len; ++i)
	{
		if (ret[i] == '\\')
		{
			ret[i] = '/';
		}
	}
	return ret;
}

//
// @return: C:/Users/win8/Documents/
//
 std::string PlayerWin::getUserDocumentPath()
{
	TCHAR filePath[MAX_PATH];
	SHGetSpecialFolderPath(NULL, filePath, CSIDL_PERSONAL, FALSE);
	int length = 2 * wcslen(filePath);
	char* tempstring = new char[length + 1];
	wcstombs(tempstring, filePath, length + 1);
	string userDocumentPath(tempstring);
	free(tempstring);

	userDocumentPath = convertPathFormatToUnixStyle(userDocumentPath);
	userDocumentPath.append("/");

	return userDocumentPath;
}

//
// convert Unicode/LocalCode TCHAR to Utf8 char
//
 char* PlayerWin::convertTCharToUtf8(const TCHAR* src)
{
#ifdef UNICODE
	WCHAR* tmp = (WCHAR*)src;
	size_t size = wcslen(src) * 3 + 1;
	char* dest = new char[size];
	memset(dest, 0, size);
	WideCharToMultiByte(CP_UTF8, 0, tmp, -1, dest, size, NULL, NULL);
	return dest;
#else
	char* tmp = (char*)src;
	uint32 size = strlen(tmp) + 1;
	WCHAR* dest = new WCHAR[size];
	memset(dest, 0, sizeof(WCHAR)*size);
	MultiByteToWideChar(CP_ACP, 0, src, -1, dest, (int)size); // convert local code to unicode.

	size = wcslen(dest) * 3 + 1;
	char* dest2 = new char[size];
	memset(dest2, 0, size);
	WideCharToMultiByte(CP_UTF8, 0, dest, -1, dest2, size, NULL, NULL); // convert unicode to utf8.
	delete[] dest;
	return dest2;
#endif
}

//
std::string PlayerWin::getApplicationExePath()
{
	TCHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	std::u16string u16ApplicationName;
	char *applicationExePath = convertTCharToUtf8(szFileName);
	std::string path(applicationExePath);
	CC_SAFE_FREE(applicationExePath);

	return path;
}

//
static bool getMacAddress(string& macstring)
{
	bool ret = false;
	ULONG ipInfoLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO *)malloc(ipInfoLen);
	if (adapterInfo == NULL)
	{
		return false;
	}

	if (GetAdaptersInfo(adapterInfo, &ipInfoLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(adapterInfo);
		adapterInfo = (IP_ADAPTER_INFO *)malloc(ipInfoLen);
		if (adapterInfo == NULL)
		{
			return false;
		}
	}

	if (GetAdaptersInfo(adapterInfo, &ipInfoLen) == NO_ERROR)
	{
		for (PIP_ADAPTER_INFO pAdapter = adapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
			{
				continue;
			}

			if (pAdapter->AddressLength != 6)
			{
				continue;
			}

			char buf32[32];
			sprintf(buf32, "%02X-%02X-%02X-%02X-%02X-%02X",
				int(pAdapter->Address[0]),
				int(pAdapter->Address[1]),
				int(pAdapter->Address[2]),
				int(pAdapter->Address[3]),
				int(pAdapter->Address[4]),
				int(pAdapter->Address[5]));
			macstring = buf32;
			ret = true;
			break;
		}
	}

	free(adapterInfo);
	return ret;
}

std::string PlayerWin::getUserGUID()
{
	if (_userGUID.length() <= 0)
	{
		if (!getMacAddress(_userGUID))
		{
			_userGUID = "guid-fixed-1234567890";
		}
	}

	return _userGUID;
}

PLAYER_NS_END
