root_path := $(call my-dir)
LOCAL_PATH := $(root_path)


include $(CLEAR_VARS)


LOCAL_MODULE :=firstshared.so

LOCAL_MODULE_FILENAME:=libfirstshared

LOCAL_C_INCLUDES:=$(LOCAL_PATH)/



LOCAL_SRC_FILES := $(LOCAL_PATH)/linker_allocator.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader_soinfo.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader_phdr.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader_addr.cpp
LOCAL_SRC_FILES += $(LOCAL_PATH)/loader.cpp

include $(BUILD_SHARED_LIBRARY)



# include $(CLEAR_VARS)


# LOCAL_MODULE :=addr.out

# LOCAL_C_INCLUDES:=$(LOCAL_PATH)/

# LOCAL_SRC_FILES := $(LOCAL_PATH)/loader_addr.cpp

# include $(BUILD_EXECUTABLE)



