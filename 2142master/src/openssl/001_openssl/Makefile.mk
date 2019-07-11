
include $(PWD)/mk/defaults.mk

.DEFAULT_GOAL := all

CURDIR := $(shell pwd)
THISGOAL := $(shell basename $$(pwd))
FANCYGOAL := $(shell echo $$(basename $$(pwd))|sed -e 's/^.*_//')

BUILD_TGT := $(foreach tgts,$(BUILD_OS_TARGETS),$(shell echo $(BUILD_DIR_3)/$(OS).$(tgts)/$(THISGOAL)) )
STAGING_TGT := $(foreach tgts,$(BUILD_OS_TARGETS),$(shell echo $(STAGING_DIR)/$(OS).$(tgts)/))

all: subdirs $(BUILD_TGT)

.PHONY: subdirs $(BUILD_TGT)

subdirs: $(BUILD_TGT)

# Set according configure target arch
#  $(1) is build directory
#  $(2) is arch to build
define ConfigMakeForTGT/android
	$(verbose)if [ ! -e "$(1)/libcrypto.a" ] || [ ! -e "$(1)/libssl.a" ];then \
		echo "       $(FANCYGOAL)-$(OS)-$(2) building.";\
		export SYSTEM="android";\
		export ANDROID_SYSROOT="$(ANDROID_NDK_ROOT)/platforms/$(ANDROID_API)/$(_ANDROID_ARCH)";\
		export ANDROID_TOOLCHAIN="$(ANDROID_NDK_ROOT)/toolchains/$(_ANDROID_EABI)/prebuilt/$(ANDROID_HOST)/bin";\
		export ANDROID_DEV="$(ANDROID_NDK_ROOT)/platforms/$(ANDROID_API)/$(_ANDROID_ARCH)/usr";\
		export SYSROOT="$(ANDROID_NDK_ROOT)/platforms/$(ANDROID_API)/$(_ANDROID_ARCH)/usr";\
		export NDK_SYSROOT="$$ANDROID_SYSROOT";\
		export ANDROID_NDK_SYSROOT="$$ANDROID_SYSROOT";\
		export HOSTCC=gcc;\
		export CROSS_COMPILE="$(CROSS_COMPILE)";\
		export PATH=$$ANDROID_TOOLCHAIN:$$PATH;\
		export xCFLAGS="-DDSO_DLFCN -DHAVE_DLFCN_H -mandroid -I$$ANDROID_DEV/include -B$$ANDROID_DEV/$$xLIB -O3 -fomit-frame-pointer -Wall \
			$(gEXTRA_CFLAGS)";\
		export CFLAGS="$(gEXTRA_CFLAGS)";\
		export LFLAGS="$(gEXTRA_LFLAGS)";\
		cd "$(1)";\
		./Configure no-asm $(configure_platform) $$xCFLAGS $(MOVOUTPUT);\
		$(MAKE) $(SILENT) build_libcrypto $(MOVOUTPUT);\
		$(MAKE) $(SILENT) build_libssl $(MOVOUTPUT);\
		if [ ! -e "$(1)/libcrypto.a" ] || [ ! -e "$(1)/libssl.a" ];then\
			echo "       $(FANCYGOAL)-$(OS)-$(2) libcrypto.a or libssl.a not found. Some error occured.";\
			exit 1;\
		else \
			echo "       $(FANCYGOAL)-$(OS)-$(2) done building";\
		fi;\
	else\
		echo "       $(FANCYGOAL)-$(OS)-$(2) already built.";\
	fi
	
endef

define ConfigMakeForTGT/linux
	$(verbose)if [ ! -e "$(1)/libcrypto.a" ] || [ ! -e "$(1)/libssl.a" ];then \
		echo "       $(FANCYGOAL)-$(OS)-$(2) building.";\
		cd "$(1)";\
		./config $(MOVOUTPUT);\
		$(MAKE) $(SILENT) build_libcrypto $(MOVOUTPUT);\
		$(MAKE) $(SILENT) build_libssl $(MOVOUTPUT);\
		if [ ! -e "$(1)/libcrypto.a" ] || [ ! -e "$(1)/libssl.a" ];then\
			echo "       $(FANCYGOAL)-$(OS)-$(2) libcrypto.a or libssl.a not found. Some error occured.";\
			exit 1;\
		else \
			echo "       $(FANCYGOAL)-$(OS)-$(2) done building";\
		fi;\
	else\
		echo "       $(FANCYGOAL)-$(OS)-$(2) already built.";\
	fi
	
endef

define PrepareBuildInstall3
	$(eval CURTGT="$(subst $(OS).,,$(subst /$(THISGOAL),,$(subst $(BUILD_DIR_3)/,,$(1)))"))
	$(verbose)echo "     $(FANCYGOAL)-$(OS)-$(CURTGT)";
	$(verbose)if [ ! -e "$(1)/.prepared" ];then \
		echo "       $(FANCYGOAL)-$(OS)-$(CURTGT) preparing.";\
		if [ ! -d "$(1)" ];then\
			mkdir -p $(1);\
		fi;\
		cd "$(1)";\
			(cd $(CURDIR)/src; find . -type f) | while read F; do\
				mkdir -p `dirname $$F`;\
				[ -e "$$F" ] && rm -f $$F; ln -s $(CURDIR)/src/$$F $$F;\
			done;\
		touch "$(1)/.prepared";\
		echo "       $(FANCYGOAL)-$(OS)-$(CURTGT) done preparing";\
		$(MAKE) -f Makefile.org $(SILENT) clean $(MOVOUTPUT);\
	else\
		echo "       $(FANCYGOAL)-$(OS)-$(CURTGT) already prepared.";\
	fi
	$(call PREPARE_VARS/$(OS), $(CURTGT))
	$(call ConfigMakeForTGT/$(OS),$(1),$(CURTGT))
	$(verbose)echo "       $(FANCYGOAL)-$(OS)-$(CURTGT) installing to staging.";
	$(call STAGING_INSTALL/lib,$(1)/libcrypto.a,$(OS).$(CURTGT))
	$(call STAGING_INSTALL/lib,$(1)/libssl.a,$(OS).$(CURTGT))
	$(verbose)find $(1)/include/ -follow -type l -delete;
	$(call STAGING_INSTALL/include,$(1)/include/*,$(OS).$(CURTGT))
	$(verbose)echo "       $(FANCYGOAL)-$(OS)-$(CURTGT) installation done.";
	$(verbose)echo "     $(FANCYGOAL)-$(OS)-$(CURTGT) all done";
endef

$(BUILD_TGT):
	$(call PrepareBuildInstall3,$@)

