#pragma once

#include "stdafx.h"
#include "Resource.h"
#include "cocos2d.h"
#include "AppDelegate.h"
#include "ProjectConfig/ProjectConfig.h"
#include "ProjectConfig/SimulatorConfig.h"

#include "PlayerMacros.h"
#include "PlayerProtocol.h"
#include "PlayerMenuServiceWin.h"
#include "PlayerMessageBoxServiceWin.h"
#include "PlayerFileDialogServiceWin.h"
#include "PlayerEditBoxServiceWin.h"
#include "PlayerTaskServiceWin.h"

PLAYER_NS_BEGIN

class CC_DLL PlayerWin : public PlayerProtocol, public cocos2d::Ref
{
public:
    static PlayerWin *create();
    virtual ~PlayerWin();
    int run();

    virtual PlayerFileDialogServiceProtocol *getFileDialogService();
    virtual PlayerMessageBoxServiceProtocol *getMessageBoxService();
    virtual PlayerMenuServiceProtocol *getMenuService();
    virtual PlayerEditBoxServiceProtocol *getEditBoxService();
    virtual PlayerTaskServiceProtocol *getTaskService();

protected:
    PlayerWin();

    ProjectConfig _project;
    HWND _hwnd;
    HWND _hwndConsole;
    AppDelegate *_app;
    FILE *_writeDebugLogFile;

    PlayerMenuServiceWin *_menuService;
    PlayerMessageBoxServiceWin *_messageBoxService;
    PlayerFileDialogServiceWin *_fileDialogService;
    PlayerEditBoxServiceWin *_editboxService;

    // services
    void initServices();

    // event handlers
    void onWindowClose(EventCustom* event);
    void onWindowResize(EventCustom* event);

    // debug log
    void writeDebugLog(const char *log);
};


PLAYER_NS_END
