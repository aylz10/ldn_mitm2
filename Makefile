KIPS := ldn_mitm
NROS := ldnmitm_config

SUBFOLDERS := Atmosphere-libs/libstratosphere $(KIPS) $(NROS) overlay

OUTDIR		:=	out
SD_ROOT     :=  $(OUTDIR)/sd
NRO_DIR     :=  $(SD_ROOT)/switch/ldnmitm_config
TITLE_DIR   :=  $(SD_ROOT)/atmosphere/contents/4200000000000010
OVERLAY_DIR :=  $(SD_ROOT)/switch/.overlays

ATMOSPHERE_PATCH := docs/atmosphere-libs-mitm-domain-id-collision.patch

# libstratosphere miscompiles under gcc >= 16 (the console wedges when an LDN
# session ends). Build with devkitA64 r29.2 / gcc 15.2.0.
GCC_PREFIX := $(if $(PREFIX),$(PREFIX),aarch64-none-elf-)
GCC_MAJOR := $(shell ($(GCC_PREFIX)gcc -dumpversion 2>/dev/null || $(DEVKITPRO)/devkitA64/bin/aarch64-none-elf-gcc -dumpversion 2>/dev/null) | cut -d. -f1)
ifeq ($(shell test "$(GCC_MAJOR)" -ge 16 2>/dev/null && echo yes),yes)
$(warning ==========================================================)
$(warning gcc $(GCC_MAJOR) detected. libstratosphere miscompiles with)
$(warning gcc >= 16 - LDN sessions freeze the console when they end.)
$(warning Use devkitA64 r29.2 / gcc 15.2.0.)
$(warning ==========================================================)
endif

all: PACK

clean: $(SUBFOLDERS)
	@ rm -rf $(OUTDIR)

$(SUBFOLDERS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

atmosphere-patch:
	@ if git -C Atmosphere-libs apply --check -R ../$(ATMOSPHERE_PATCH) 2>/dev/null; then \
		echo "Atmosphere-libs patch already applied"; \
	else \
		echo "Applying $(ATMOSPHERE_PATCH)"; \
		git -C Atmosphere-libs apply ../$(ATMOSPHERE_PATCH); \
	fi

ifeq (,$(filter clean,$(MAKECMDGOALS)))
Atmosphere-libs/libstratosphere: atmosphere-patch
endif

$(KIPS): Atmosphere-libs/libstratosphere

#---------------------------------------------------------------------------------
PACK: $(SUBFOLDERS)
	@ mkdir -p $(NRO_DIR)
	@ mkdir -p $(TITLE_DIR)/flags
	@ mkdir -p $(OVERLAY_DIR)
	@ cp ldnmitm_config/ldnmitm_config.nro $(NRO_DIR)/ldnmitm_config.nro
	@ cp ldn_mitm/ldn_mitm.nsp $(TITLE_DIR)/exefs.nsp
	@ cp overlay/overlay.ovl $(OVERLAY_DIR)/ldnmitm_config.ovl
	@ cp ldn_mitm/res/toolbox.json $(TITLE_DIR)/toolbox.json
	@ touch $(TITLE_DIR)/flags/boot2.flag
#---------------------------------------------------------------------------------

.PHONY: all clean PACK atmosphere-patch $(SUBFOLDERS)
