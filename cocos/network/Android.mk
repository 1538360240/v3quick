LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := cocos_network_static

LOCAL_MODULE_FILENAME := libnetwork

LOCAL_SRC_FILES := WebSocket.cpp

LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/..

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. \
					$(LOCAL_PATH)/.. \
                    $(LOCAL_PATH)/../platform/android \
				    $(QUICK_V3_LIB)

LOCAL_CFLAGS += -Wno-psabi
LOCAL_EXPORT_CFLAGS += -Wno-psabi

ifeq ($(QUICK_WEBSOCKET_ENABLED),1)
LOCAL_WHOLE_STATIC_LIBRARIES += libwebsockets_static
endif

include $(BUILD_STATIC_LIBRARY)

ifeq ($(QUICK_WEBSOCKET_ENABLED),1)
$(call import-module,websockets/prebuilt/android)
endif
