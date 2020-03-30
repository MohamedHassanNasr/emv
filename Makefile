ROOTDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
OBJDIR := $(CURDIR)/build


SRCS = native/main.cpp native/mbedtls/bignum.c native/mbedtls/sha1.c
OBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(patsubst %.c, $(OBJDIR)/%.o, $(SRCS)))

CFLAGS := $(CFLAGS) -DHAVE_LOG -I. -I./json/include -I./native/mbedtls -I./mock -I./native -g -Werror -Wall
CPPFLAGS := $(CFLAGS) -std=c++17
DEPFLAGS = -MT $(OBJDIR)/$*.o -MD -MP -MF $(OBJDIR)/$*.d

$(OBJDIR)/emv: $(OBJS)
	@echo "LD $@"
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -pthread -o $@ $^

msc-offline: 
	$(OBJDIR)/emv --mock ./mock/mock-msc-offline.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MChip1.json ./cfg/cfg_PPS_Perf_MC.json ./cfg/cfg_visa.json

ms:
	$(OBJDIR)/emv --mock ./mock/mock-msc-ms-mode.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MStripe1.json

visa-offline:
	$(OBJDIR)/emv --mock ./mock/mock-visa-offline.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MChip1.json ./cfg/cfg_PPS_Perf_MC.json ./cfg/cfg_visa.json

visa-express-mode:
	$(OBJDIR)/emv --mock ./mock/mock-visa-offline.json --express --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_visa.json

visa-online:
	$(OBJDIR)/emv --mock ./mock/mock-visa-online.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_visa.json ./cfg/cfg_test_cert_override.json

msc-online:
	$(OBJDIR)/emv --mock ./mock/mock-msc-online.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_mc.json  ./cfg/cfg_test_cert_override.json
 
nfc-test-card:
	$(OBJDIR)/emv --ip 192.168.178.35 --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MChip1.json ./cfg/cfg_PPS_Perf_MC.json ./cfg/cfg_visa.json ./cfg/cfg_test_cert_override.json
 
$(OBJDIR)/%.o: $(ROOTDIR)/%.cpp $(OBJDIR)/%.d
	@echo "CXX $<"
	@mkdir -p $(dir $@)
	$(CXX) -c $(DEPFLAGS) $(CPPFLAGS) -o $@ -c $< $(INCLUDES)

$(OBJDIR)/%.o: $(ROOTDIR)/%.c $(OBJDIR)/%.d
	@echo "CC $<"
	@mkdir -p $(dir $@)
	$(CC) -c $(DEPFLAGS) $(CFLAGS) -g -o $@ -c $< $(INCLUDES)

$(OBJDIR):
	@mkdir -p $@

$(OBJDIR)/%.d: ;
.PRECIOUS: $(OBJDIR)/%.d

-include $(patsubst %.o, %.d, $(OBJS))

clean:
	rm -rf ${OBJDIR}/*

$(OBJDIR)/%.d: ;
.PRECIOUS: $(OBJDIR)/%.d
-include $(patsubst %.o, %.d, $(OBJECTS))

