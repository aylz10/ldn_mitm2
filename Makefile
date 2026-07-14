KIPS := ldn_mitm
NROS := ldnmitm_config

SUBFOLDERS := Atmosphere-libs/libstratosphere $(KIPS) $(NROS) overlay

TOPTARGETS := all clean

OUTDIR		:=	out
SD_ROOT     :=  $(OUTDIR)/sd
NRO_DIR     :=  $(SD_ROOT)/switch/ldnmitm_config
TITLE_DIR   :=  $(SD_ROOT)/atmosphere/contents/4200000000000010
OVERLAY_DIR :=  $(SD_ROOT)/switch/.overlays

ATMOSPHERE_PATCH := docs/atmosphere-libs-mitm-domain-id-collision.patch

$(TOPTARGETS): PACK

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

.PHONY: $(TOPTARGETS) $(SUBFOLDERS)
