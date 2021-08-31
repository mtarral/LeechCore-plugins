#include <stdbool.h>

#include <leechcore_device.h>
#include <libmicrovmi.h>

#define PLUGIN_URL_SCHEME "microvmi"

static VOID DeviceMicrovmi_ReadContigious(PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
  // read contigious physical memory
  PLC_CONTEXT ctxLC = ctxRC->ctxLC;
  void* driver = ctxLC->hDevice;
  uint64_t bytes_read = 0;
  if (!microvmi_read_physical(driver, ctxRC->paBase, ctxRC->pb, ctxRC->cb, &bytes_read)) {
    lcprintfvvv(ctxLC, "Failed to read physical memory at 0x%llx\n", ctxRC->paBase);
  }
  ctxRC->cbRead = (DWORD)bytes_read;
}

static VOID DeviceMicrovmi_Close(_Inout_ PLC_CONTEXT ctxLC)
{
  // close driver
  void* driver = ctxLC->hDevice;
  microvmi_destroy(driver);
}

_Success_(return)
EXPORTED_FUNCTION BOOL LcPluginCreate(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
  lcprintfv(ctxLC, "MICROVMI: Initializing\n");
  // safety checks
	if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
	if(ctxLC->version != LC_CONTEXT_VERSION) { return false; }
  
  // TODO: handle init args
  // check URL scheme
  if (strncmp(ctxLC->Config.szDevice, PLUGIN_URL_SCHEME, strlen(PLUGIN_URL_SCHEME))) {
    // no match, quit
    return false;
  }

  // TODO: init libmicrovmi
  microvmi_envlogger_init();
  const char* init_error = NULL;
  DriverInitParamsFFI init_params = {
    .common = {
      .vm_name = "win10"
    },
    .kvm = {
      .tag = UnixSocket,
      .unix_socket.path = "/tmp/introspector",
    }
  };
  void* microvmi_driver = microvmi_init(NULL, &init_params, &init_error);
  if (!microvmi_driver) {
    lcprintf(ctxLC, "Device Microvmi initialization failed: %s.\n", init_error);
    rs_cstring_free((char*)init_error);
    return false;
  }

  // assign context
  ctxLC->hDevice = (HANDLE)microvmi_driver;

  // setup config
  ctxLC->Config.fVolatile = true;
  // set callback functions
  ctxLC->pfnReadContigious = DeviceMicrovmi_ReadContigious;
  ctxLC->pfnClose = DeviceMicrovmi_Close;
  // status
  lcprintfv(ctxLC, "MICROVMI: initialized.\n");
}
