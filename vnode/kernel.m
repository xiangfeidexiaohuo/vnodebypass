#include "kernel.h"
#include <dlfcn.h>
#include <sys/sysctl.h>
#include "fishhook.h"

typedef char io_string_t[512];
typedef UInt32        IOOptionBits;
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;
CFTypeRef
IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
extern const mach_port_t kIOMainPortDefault;
io_registry_entry_t
IORegistryEntryFromPath(mach_port_t, const io_string_t);

//set offset
#define kCFCoreFoundationVersionNumber_iOS_15_0 (1854)
#define kCFCoreFoundationVersionNumber_iOS_15_2 (1856.105)

uint32_t off_p_pid = 0;
uint32_t off_p_pfd = 0;
uint32_t off_fd_ofiles = 0;
uint32_t off_fp_fglob = 0;
uint32_t off_fg_data = 0;
uint32_t off_vnode_iocount = 0;
uint32_t off_vnode_usecount = 0;
uint32_t off_vnode_vflags = 0;

static void *libjb = NULL;
uint64_t ourproc = 0;
unsigned long long t1sz_boot = 0;
static bool did_jbdInitPPLRW = false;

const char* get_kernversion(void) {
    char kern_version[512] = {};
    size_t size = sizeof(kern_version);
    sysctlbyname("kern.version", &kern_version, &size, NULL, 0);
    
    return strdup(kern_version);;
}

int offset_init() {	
	if(isArm64e()) {
		if(strstr(get_kernversion(), "T8120") != NULL || strstr(get_kernversion(), "T8103") != NULL || strstr(get_kernversion(), "T8112") != NULL)
        	t1sz_boot = 17;
    	else
        	t1sz_boot = 25;
	} else {
		t1sz_boot = 0;
	}

	if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_2) {
		// ios 15.2 ~ 16.x
		printf("iOS 15.2+ offset selected!!!\n");
		off_p_pid = 0x68; //proc_pid v
        off_p_pfd = 0xf8;
        off_fd_ofiles = 0x0; //?
        off_fp_fglob = 0x10;
        off_fg_data = 0x38; //_fg_get_vnode + 10, LDR X0, [X0,#0x38]
        off_vnode_iocount = 0x64; //vnode_iocount v
        off_vnode_usecount = 0x60; //vnode_usecount v
        off_vnode_vflags = 0x54; //_vnode_isvroot, _vnode_issystem, _vnode_isswap... LDR W8, [X0,#0x54] v
		return 0;
	}

	if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        // ios 15.0-15.1.1
        printf("iOS 15.0-15.1.1 offset selected!!!\n");
        off_p_pid = 0x68; //proc_pid v
        off_p_pfd = 0x100;  //
        off_fd_ofiles = 0x0; //?
        off_fp_fglob = 0x10;
        off_fg_data = 0x38; //_fg_get_vnode + 10, LDR X0, [X0,#0x38]
        off_vnode_iocount = 0x64; //vnode_iocount v
        off_vnode_usecount = 0x60; //vnode_usecount v
        off_vnode_vflags = 0x54; //_vnode_isvroot, _vnode_issystem, _vnode_isswap... LDR W8, [X0,#0x54] v

        return 0;
    }

	return -1;
}

bool isArm64e(void) {
	cpu_subtype_t subtype;
    size_t cpusz = sizeof(cpu_subtype_t);
    sysctlbyname("hw.cpusubtype", &subtype, &cpusz, NULL, 0);
	return (subtype == 2/*CPU_SUBTYPE_ARM64E*/);
}

uint64_t unsign_kptr(uint64_t pac_kaddr) {
	if(t1sz_boot == 0) {
		return pac_kaddr;
	}

    if ((pac_kaddr & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
        return pac_kaddr;
    }
    if(t1sz_boot != 0) {
        return pac_kaddr |= ~((1ULL << (64U - t1sz_boot)) - 1U);
    }
    return pac_kaddr;
}

void kwrite64(uint64_t va, uint64_t v) {
	void *libjb_kwrite64 = dlsym(libjb, "kwrite64");
	int (*kwrite64_)(uint64_t va, uint64_t v) = libjb_kwrite64;
	kwrite64_(va, v);
}

void kwrite32(uint64_t va, uint32_t v) {
	void *libjb_kwrite32 = dlsym(libjb, "kwrite32");
	int (*kwrite32_)(uint64_t va, uint32_t v) = libjb_kwrite32;
	kwrite32_(va, v);
}

uint64_t kread64(uint64_t va) {
	void *libjb_kread64 = dlsym(libjb, "kread64");
	uint64_t (*kread64_)(uint64_t va) = libjb_kread64;
	return kread64_(va);
}

uint64_t proc_find(pid_t pidToFind) {
	void *libjb_procfind = dlsym(libjb, "proc_find");
	uint64_t (*proc_find_)(pid_t pidToFind) = libjb_procfind;
	return proc_find_(pidToFind);
}

uint32_t kread32(uint64_t va) {
	void *libjb_kread32 = dlsym(libjb, "kread32");
	uint32_t (*kread32_)(uint64_t va) = libjb_kread32;
	return kread32_(va);
}

//get vnode
uint64_t getVnodeAtPath(const char* filename) {
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = proc_find(getpid());

    uint64_t filedesc_pac = kread64(proc + off_p_pfd);
    uint64_t filedesc = unsign_kptr(filedesc_pac);
    uint64_t openedfile = kread64(filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(openedfile + off_fp_fglob);
    uint64_t fileglob = unsign_kptr(fileglob_pac);
    uint64_t vnode_pac = kread64(fileglob + off_fg_data);
    uint64_t vnode = unsign_kptr(vnode_pac);
    
    close(file_index);
    
    return vnode;
}

//hide and show file using vnode
#define VISSHADOW 0x008000
void hide_path(uint64_t vnode){
	uint32_t v_flags = kread32(vnode + off_vnode_vflags);
	kwrite32(vnode + off_vnode_vflags, (v_flags | VISSHADOW));
}

void show_path(uint64_t vnode){
	uint32_t v_flags = kread32(vnode + off_vnode_vflags);
	kwrite32(vnode + off_vnode_vflags, (v_flags &= ~VISSHADOW));
}

uid_t (*orig_getuid)(void);
static uid_t hook_getuid(void) {
	if(did_jbdInitPPLRW) return orig_getuid();
	return 0;
}

int init_kernel(void) {

  	printf("======= init_kernel =======\n");
	libjb = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
	if(!did_jbdInitPPLRW) {
		//hook getuid to 0, bypass protection when calling jbdInitPPLRW
		rebind_symbols((struct rebinding[1]){{"getuid", (void *)hook_getuid, (void **)&orig_getuid}}, 1);

		void *libjb_jbdInitPPLRW = dlsym(libjb, "jbdInitPPLRW");
		int (*jbdInitPPLRW)(void) = libjb_jbdInitPPLRW;
		int ret = jbdInitPPLRW();
		//NSLog(@"[vnodeDEBUG] jbdInitPPLRW ret: %d\n", ret);
		if(ret != 0) {
			return 1;
		}
		
	}
	did_jbdInitPPLRW = true;

	ourproc = proc_find(getpid());
	//NSLog(@"[vnodeDEBUG] ourproc: 0x%llx\n", ourproc);
	if(ourproc == 0) {
		return 1;
	}

	kern_return_t err = offset_init();
	if (err) {
		printf("offset init failed: %d\n", err);
		return 1;
	}

	return 0;
}

NSData *bootManifestHash(void)
{
  io_registry_entry_t registryEntry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
  if (registryEntry) {
    return (__bridge NSData *)IORegistryEntryCreateCFProperty(registryEntry, CFSTR("boot-manifest-hash"), NULL, 0);
  }
  return nil;
}

NSString *hexStringFromData(NSData* data) {
    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
    if (!dataBuffer) return [NSString string];

    NSUInteger dataLength = [data length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (int i = 0; i < dataLength; ++i) {
        [hexString appendFormat:@"%02lX", (unsigned long)dataBuffer[i]];
    }

    return hexString;
}

NSString *getActivePrebootPath(void)
{
    return [@"/private/preboot" stringByAppendingPathComponent:hexStringFromData(bootManifestHash())];
}

//https://github.com/opa334/Dopamine/blob/2.x/Application/Dopamine/Jailbreak/DOEnvironmentManager.m#L56C1-L85C10
NSString *locateJailbreakRoot(void)
{
  NSString *activePrebootPath = getActivePrebootPath();
  
  NSString *randomizedJailbreakPath;
  
  // First attempt at finding jailbreak root, look for Dopamine 2.x path
  for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
      if (subItem.length == 15 && [subItem hasPrefix:@"dopamine-"]) {
          randomizedJailbreakPath = [activePrebootPath stringByAppendingPathComponent:subItem];
          return randomizedJailbreakPath;
      }
  }
  return nil;
}

uint64_t proc_ucred(uint64_t proc) {
	void *libjb_proc_ucred = dlsym(libjb, "proc_ucred");
	uint64_t (*proc_ucred_)(uint64_t proc) = libjb_proc_ucred;
	return proc_ucred_(proc);
}

NSString *NSJBRootPath(NSString *relativePath) {
	void *libjb_NSJBRootPath = dlsym(libjb, "NSJBRootPath");
	NSString* (*NSJBRootPath_)(NSString* relativePath) = libjb_NSJBRootPath;
	return NSJBRootPath_(relativePath);
}

int get_root_by_krw(void) {
	libjb = dlopen([NSString stringWithFormat:@"%@/procursus/basebin/libjailbreak.dylib", locateJailbreakRoot()].UTF8String, RTLD_NOW);
	if(!did_jbdInitPPLRW) {
		//hook getuid to 0, bypass protection when calling jbdInitPPLRW
		rebind_symbols((struct rebinding[1]){{"getuid", (void *)hook_getuid, (void **)&orig_getuid}}, 1);

		void *libjb_jbdInitPPLRW = dlsym(libjb, "jbdInitPPLRW");
		int (*jbdInitPPLRW)(void) = libjb_jbdInitPPLRW;
		int ret = jbdInitPPLRW();
		if(ret != 0) {
			//NSLog(@"[vnodeDEBUG] jbdInitPPLRW ret: %d", ret);
			return 1;
		}
		
	}
	did_jbdInitPPLRW = true;

	ourproc = proc_find(getpid());
	uint64_t ucred = proc_ucred(ourproc);

	//https://github.com/opa334/Dopamine/blob/2.x/BaseBin/libjailbreak/src/info.c#L111
	 // Get uid 0
	 uint32_t ucred_cr_posix = 0x18;
    //kwrite32(ourproc + 0x3C, 0);	//kwrite32(proc + koffsetof(proc, svuid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x8, 0);	//kwrite32(ucred + koffsetof(ucred, svuid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x4, 0);	//kwrite32(ucred + koffsetof(ucred, ruid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x0, 0);	//kwrite32(ucred + koffsetof(ucred, uid), 0);
    
    // Get gid 0
    //kwrite32(ourproc + 0x48, 0);	//kwrite32(proc + koffsetof(proc, svgid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x50, 0);	//kwrite32(ucred + koffsetof(ucred, rgid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x54, 0);	//kwrite32(ucred + koffsetof(ucred, svgid), 0);
    kwrite32(ucred + ucred_cr_posix + 0x10, 0);	//kwrite32(ucred + koffsetof(ucred, groups), 0);

	return 0;
}