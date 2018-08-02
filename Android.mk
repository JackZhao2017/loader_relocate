root_path := $(call my-dir)
LOCAL_PATH := $(root_path)


include $(CLEAR_VARS)


LOCAL_MODULE :=loader.so

LOCAL_MODULE_FILENAME:=libloader

LOCAL_C_INCLUDES:=$(LOCAL_PATH)/

LOCAL_SRC_FILES := $(LOCAL_PATH)/loader.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/linker_allocator.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader_soinfo.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader_phdr.cpp


include $(BUILD_SHARED_LIBRARY)








# include $(CLEAR_VARS)

# LOCAL_MODULE    :=pre-load
# LOCAL_SRC_FILES :=$(LOCAL_PATH)/libs/armeabi-v7a/libloader.so

# include $(PREBUILT_SHARED_LIBRARY)




# include $(CLEAR_VARS)

# LOCAL_MODULE := main.out

# LOCAL_SRC_FILES := $(LOCAL_PATH)/main.cpp

# LOCAL_C_INCLUDES :=$(LOCAL_PATH)/
# LOCAL_SHARED_LIBRARIES := pre-load


# include $(BUILD_EXECUTABLE)




