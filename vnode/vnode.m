#include "vnode.h"
#include "SVC_Caller.h"
#include "kernel.h"
#import <spawn.h>

__attribute__((constructor)) void initVnodeMemPath() {
  vnodeMemPath =
      [NSString stringWithFormat:@"/tmp/%@.txt", NSProcessInfo.processInfo.processName].UTF8String;
}


void initPath() {
  hidePathList = [NSArray
      arrayWithContentsOfFile:[NSString stringWithFormat:@"/var/jb/usr/share/%@/hidePathList.plist",
                                                         NSProcessInfo.processInfo.processName]];
  if (hidePathList == nil) goto exit;
  for (id path in hidePathList) {
    if (![path isKindOfClass:[NSString class]]) goto exit;
  }
  return;
exit:
  printf("hidePathList.plist is broken, please reinstall vnodebypass!\n");
  exit(1);
}

void saveVnode() {
  if (access(vnodeMemPath, F_OK) == 0) {
    printf("Already exist /tmp/vnodeMem.txt, Please vnode recovery first!\n");
    return;
  }

  initPath();


  if (init_kernel() == 1) {
    printf("Failed init_kernel\n");
    return;
  }

  FILE *fp = fopen(vnodeMemPath, "w");

  int hideCount = (int)[hidePathList count];
  uint64_t vnodeArray[hideCount];

  for (int i = 0; i < hideCount; i++) {
    const char *hidePath = [[hidePathList objectAtIndex:i] UTF8String];
    if(access(hidePath, R_OK) != 0) continue;
    vnodeArray[i] = getVnodeAtPath(hidePath);
    printf("hidePath: %s, vnode[%d]: 0x%" PRIX64 "\n", hidePath, i, vnodeArray[i]);
    kwrite32(vnodeArray[i] + off_vnode_usecount, kread32(vnodeArray[i] + off_vnode_usecount) + 1);
    kwrite32(vnodeArray[i] + off_vnode_iocount, kread32(vnodeArray[i] + off_vnode_iocount) + 1);
    printf("vnode_usecount: 0x%" PRIX32 ", vnode_iocount: 0x%" PRIX32 "\n",
           kread32(vnodeArray[i] + off_vnode_usecount),
           kread32(vnodeArray[i] + off_vnode_iocount));
    fprintf(fp, "0x%" PRIX64 "\n", vnodeArray[i]);
  }
  fclose(fp);

  printf("Saved vnode to /tmp/vnodeMem.txt\nMake sure vnode recovery to prevent kernel panic!\n");
}

void hideVnode() {
  if (init_kernel() == 1) {
    printf("Failed init_kernel\n");
    return;
  }
  if (access(vnodeMemPath, F_OK) == 0) {
    FILE *fp = fopen(vnodeMemPath, "r");
    uint64_t savedVnode;
    int i = 0;
    while (!feof(fp)) {
      if (fscanf(fp, "0x%" PRIX64 "\n", &savedVnode) == 1) {
        printf("Saved vnode[%d] = 0x%" PRIX64 "\n", i, savedVnode);
        hide_path(savedVnode);
      }
      i++;
    }
  }

  printf("Hide file!\n");
  unlink("/var/jb");
}

void revertVnode() {
  symlink([NSString stringWithFormat:@"%@/procursus", locateJailbreakRoot()].UTF8String, "/var/jb");
  if (init_kernel() == 1) {
    printf("Failed init_kernel\n");
    return;
  }
  if (access(vnodeMemPath, F_OK) == 0) {
    FILE *fp = fopen(vnodeMemPath, "r");
    uint64_t savedVnode;
    int i = 0;
    while (!feof(fp)) {
      if (fscanf(fp, "0x%" PRIX64 "\n", &savedVnode) == 1) {
        printf("Saved vnode[%d] = 0x%" PRIX64 "\n", i, savedVnode);
        show_path(savedVnode);
      }
      i++;
    }
  }

  printf("Show file!\n");
}

void recoveryVnode() {
  if (init_kernel() == 1) {
    printf("Failed init_kernel\n");
    return;
  }
  if (access(vnodeMemPath, F_OK) == 0) {
    FILE *fp = fopen(vnodeMemPath, "r");
    uint64_t savedVnode;
    int i = 0;
    while (!feof(fp)) {
      if (fscanf(fp, "0x%" PRIX64 "\n", &savedVnode) == 1) {
        if(kread32(savedVnode + off_vnode_iocount) > 0)
          kwrite32(savedVnode + off_vnode_iocount, kread32(savedVnode + off_vnode_iocount) - 1);
        if(kread32(savedVnode + off_vnode_usecount) > 0)
          kwrite32(savedVnode + off_vnode_usecount,
                       kread32(savedVnode + off_vnode_usecount) - 1);
        printf("Saved vnode[%d] = 0x%" PRIX64 "\n", i, savedVnode);
        printf("vnode_usecount: 0x%" PRIX32 ", vnode_iocount: 0x%" PRIX32 "\n",
               kread32(savedVnode + off_vnode_usecount),
               kread32(savedVnode + off_vnode_iocount));
      }
      i++;
    }
    remove(vnodeMemPath);
  }
  printf("Recovered vnode! No more kernel panic when you shutdown.\n");
}

void checkFile() {
  initPath();
  int hideCount = (int)[hidePathList count];
  for (int i = 0; i < hideCount; i++) {
    const char *hidePath = [[hidePathList objectAtIndex:i] UTF8String];
    int ret = 0;
    ret = SVC_Access(hidePath);
    printf("hidePath: %s, errno: %d\n", hidePath, ret);
  }
  printf("Done check file!\n");
}

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

int rerunAsRoot(void) {
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
  posix_spawnattr_set_persona_uid_np(&attr, 0);
  posix_spawnattr_set_persona_gid_np(&attr, 0);

  const char* filepath = [NSString stringWithFormat:@"%@/procursus/usr/bin/%@", locateJailbreakRoot(), NSProcessInfo.processInfo.processName].UTF8String;

  char *_argv[] = { (char*)NSProcessInfo.processInfo.processName.UTF8String, "-r", NULL };

  int pid = 0;
  int ret = posix_spawnp(&pid, filepath, NULL, &attr, _argv, NULL);
  //NSLog(@"[vbmodule] posix_spawnp filepath: %s, ret: %d", filepath, ret);
  if (ret) {
    // fprintf(stderr, "failed to exec %s: %s\n", _file, strerror(errno));
    return 1;
  }
  // waitUntilDone(pid);
  int status;
  waitpid(pid, &status, 0);
  // NSLog(@"[vnode] child_pid: %d", child_pid);
  return 0;
}
