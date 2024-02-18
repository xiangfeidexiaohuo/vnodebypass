#import "RootViewController.h"
#import <spawn.h>
#import "../vnode/vnode.h"
#import "../vnode/kernel.h"
#import "../vnode/fishhook.h"
#import "dlfcn.h"


#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

@interface RootViewController ()
@end

// int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred) {
//   void* libjb = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
//   void *libjb_jbclient_root_steal_ucred = dlsym(libjb, "jbclient_root_steal_ucred");
// 	uint64_t (*jbclient_root_steal_ucred_)(uint64_t ucredToSteal, uint64_t *orgUcred) = libjb_jbclient_root_steal_ucred;
// 	return jbclient_root_steal_ucred_(ucredToSteal, orgUcred);
// }

// int exec_cmd_root(const char *binary, ...) {
//   void* libjb = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
//   void *libjb_exec_cmd_root = dlsym(libjb, "exec_cmd_root");
// 	uint64_t (*exec_cmd_root_)(const char *binary, ...) = libjb_exec_cmd_root;
// 	return exec_cmd_root_(binary, ...);
// }

void waitUntilDone(pid_t pid){
  siginfo_t info;
  while (waitid(P_PID, pid, &info, WEXITED | WSTOPPED | WCONTINUED) == -1) {
    if (errno != EINTR) {
      break;
    }
  }

  if (info.si_code == CLD_EXITED) {
    // int exit_status = info.si_status;
  } else if (info.si_code == CLD_KILLED) {
    // int signal_number = info.si_status;
  }
}

int run_as_root(const char* _file, const char** _argv) {
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
  posix_spawnattr_set_persona_uid_np(&attr, 0);
  posix_spawnattr_set_persona_gid_np(&attr, 0);

  int pid = 0;
  int ret = posix_spawnp(&pid, _file, NULL, &attr, (char *const *)_argv, NULL);
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

@implementation RootViewController

- (void)loadView {
  [super loadView];

  self.view.backgroundColor = UIColor.blackColor;
}

- (void)viewDidLoad {
  [super viewDidLoad];

  // NSLog(@"[vnode] locateJailbreakRoot: %@", locateJailbreakRoot());

  

  _titleLabel =
      [[UILabel alloc] initWithFrame:CGRectMake(0, 50, UIScreen.mainScreen.bounds.size.width, 100)];
  _titleLabel.text = @"vnodebypass";
  _titleLabel.textAlignment = NSTextAlignmentCenter;
  _titleLabel.textColor = UIColor.whiteColor;
  _titleLabel.font = [UIFont systemFontOfSize:40];
  [self.view addSubview:_titleLabel];

  _subtitleLabel = [[UILabel alloc]
      initWithFrame:CGRectMake(0, 100, UIScreen.mainScreen.bounds.size.width, 100)];
  _subtitleLabel.text = @"USE IT AT YOUR OWN RISK!";
  _subtitleLabel.textAlignment = NSTextAlignmentCenter;
  _subtitleLabel.textColor = UIColor.whiteColor;
  _subtitleLabel.font = [UIFont systemFontOfSize:20];
  [self.view addSubview:_subtitleLabel];

  _button = [UIButton buttonWithType:UIButtonTypeSystem];
  _button.frame = CGRectMake(UIScreen.mainScreen.bounds.size.width / 2 - 30,
                             UIScreen.mainScreen.bounds.size.height / 2 - 25, 60, 50);
  [_button setTitle:access("/var/jb/bin/bash", F_OK) == 0 ? @"Enable" : @"Disable"
           forState:UIControlStateNormal];
  [_button addTarget:self
                action:@selector(buttonPressed:)
      forControlEvents:UIControlEventTouchUpInside];
  [self.view addSubview:_button];
}

- (void)buttonPressed:(UIButton *)sender {
  BOOL disabled = access("/var/jb/bin/bash", F_OK) == 0;
  
  NSString *launchPath = [NSString stringWithFormat:@"%@/procursus/usr/bin/%@", locateJailbreakRoot(), NSProcessInfo.processInfo.processName];
  // NSLog(@"[vnode] launchPath: %@", launchPath);

  if(disabled) {
    const char* args[] = {NSProcessInfo.processInfo.processName.UTF8String, "-s", NULL};
    run_as_root(launchPath.UTF8String, args);

    const char* args2[] = {NSProcessInfo.processInfo.processName.UTF8String, "-h", NULL};
    run_as_root(launchPath.UTF8String, args2);
  } else {
    const char* args[] = {NSProcessInfo.processInfo.processName.UTF8String, "-r", NULL};
    run_as_root(launchPath.UTF8String, args);

    const char* args2[] = {NSProcessInfo.processInfo.processName.UTF8String, "-R", NULL};
    run_as_root(launchPath.UTF8String, args2);
  }

  NSString *title = access("/var/jb/bin/bash", F_OK) == 0 ? @"Enable" : @"Disable";
  NSString *successTitle = (access("/var/jb/bin/bash", F_OK) == 0) == disabled ? @"Failed" : @"Success";
  [_button setTitle:successTitle forState:UIControlStateNormal];
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    sleep(1);
    dispatch_async(dispatch_get_main_queue(), ^{
      [_button setTitle:title forState:UIControlStateNormal];
    });
  });
}

@end
